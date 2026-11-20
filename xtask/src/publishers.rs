//! The owner's registry of third-party plugin publishers (`docs/design/publishers.md`,
//! "Подключение издателя"): `publishers/<name>/publisher.toml`, one file per publisher,
//! merged by the owner only. Once it has an entry, `cargo xtask tuf update` makes two
//! things of it for the top-level targets of `tuf/v1`, and `cargo xtask tuf check`
//! verifies the signed repository against them:
//!
//! - [`Registry::delegations`], the `delegations` member of the top-level targets: a role
//!   `pub-<name>` for each active publisher, with its keys and threshold, the paths
//!   `plugins/<name>/*/*` and `terminating: true`, in the order of the names;
//! - [`Registry::publishers_json`], the target `publishers.json`: every publisher, active,
//!   retired or revoked, with its id prefix, modules, bundles, superseded ports and the
//!   versions the owner revoked.
//!
//! The schema is strict (unknown keys and states are refused) and so are the rules: the
//! name is a [`PublisherName`] and the name of its directory; the id prefix is a reverse
//! domain ending in `.`, never nested in another publisher's or the project's own; modules
//! and bundles are valid names, not built-in, not the core's, not another publisher's (in
//! any case) and not served by a port of the owner's indexes unless that port is in
//! `supersedes`; keys are distinct across publishers and are no key of a root; `display` is
//! not the project's name. A retired publisher keeps its prefix, modules, bundles and ports;
//! a revoked one keeps its prefix only.
//!
//! `revoke_all = "<date>"` and the move to `retired` are settled by `tuf update` into
//! explicit `[[revoked_versions]]` of the file ([`Registry::settle`]), so `publishers.json`
//! stays a function of the files.
//!
//! The same directory holds [`builders::FILE_NAME`], the builder images a publisher's
//! release may be built with, and [`sdk_revisions::FILE_NAME`], the released SDK commits its
//! sources may depend on.

pub mod builders;
pub mod sdk_revisions;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::catalog::{PublisherPolicy, Standing};
use oncl_update::tuf::ed25519::verify_threshold;
use oncl_update::tuf::{
    Envelope, KeyId, Limits, PathPattern, Profile, PublicKey, PublisherName, RoleKeys, RoleName,
    Root, Targets,
};
use oncl_update::{Index, Version};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Where the registry is, from the workspace root.
pub const PUBLISHERS_DIR: &str = "publishers";

/// The file of one publisher, in its directory.
pub const FILE_NAME: &str = "publisher.toml";

/// The target path of the rules of the publishers in the top-level targets.
pub const TARGET: &str = "publishers.json";

/// The `schema` of `publishers.json`.
pub const SCHEMA: u32 = 1;

/// The most publishers, of every state, `publishers.json` lists (Р37).
pub const MAX_PUBLISHERS: usize = PublisherPolicy::MAX_PUBLISHERS;

/// The most revoked versions `publishers.json` lists, all publishers together (Р37).
pub const MAX_REVOKED_VERSIONS: usize = PublisherPolicy::MAX_REVOKED_VERSIONS;

/// The largest `publishers.json` (Р37): what the client reads.
pub const MAX_JSON_LEN: usize = PublisherPolicy::MAX_LEN;

/// The largest `publisher.toml` read.
const MAX_FILE_LEN: u64 = 1 << 20;

/// The prefix of the project's own plugin ids: no publisher's prefix is nested with it.
const PROJECT_PREFIX: &str = "io.github.arynyklas.openncalayer.";

/// The longest plugin id or id prefix, in bytes (as in a plugin's manifest).
const MAX_ID: usize = 64;

/// The longest translation of `display`, in characters.
const MAX_DISPLAY: usize = 128;

/// The longest URL or contact line.
const MAX_URL: usize = 2048;

/// The most `binary_files` a publisher lists.
const MAX_BINARY_FILES: usize = 256;

/// Whether a publisher's plugins are offered (`docs/design/publishers.md`, "Состояния
/// издателя"). Any other value of `state` is refused: a typo never reaches a signature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Delegated to: its role is in the top-level targets.
    #[default]
    Active,
    /// No new versions: not delegated to any more, installed plugins keep working unless
    /// their versions are revoked. Its prefix, modules, bundles and ports stay its own.
    Retired,
    /// Not delegated to any more; its prefix stays reserved, and clients switch its plugins
    /// off.
    Revoked,
}

impl State {
    /// `active`, `retired` or `revoked`.
    pub fn as_str(self) -> &'static str {
        match self {
            State::Active => "active",
            State::Retired => "retired",
            State::Revoked => "revoked",
        }
    }
}

/// A publisher's name in the three interface languages.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Display {
    /// Russian.
    pub ru: String,
    /// Kazakh.
    pub kk: String,
    /// English.
    pub en: String,
}

/// A version of a publisher's plugin that the owner revoked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedVersion {
    /// The plugin, under the publisher's prefix.
    pub id: String,
    /// The version.
    pub version: Version,
    /// When, `YYYY-MM-DD`.
    pub date: String,
}

/// One publisher, as its file says, every rule of its own checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publisher {
    /// Its name, and the name of its directory.
    pub name: PublisherName,
    /// Active, retired or revoked.
    pub state: State,
    /// When it was revoked, `YYYY-MM-DD`: exactly for a revoked publisher.
    pub revoked: Option<String>,
    /// `YYYY-MM-DD`: revoke every version its role had in git on that date. `tuf update`
    /// settles it into `revoked_versions` and takes it out of the file ([`Registry::settle`]).
    pub revoke_all: Option<String>,
    /// Its name for people.
    pub display: Display,
    /// The prefix of its plugin ids, ending in `.`.
    pub id_prefix: String,
    /// The module names its plugins may serve.
    pub modules: Vec<String>,
    /// The bundles of the original its plugins may replace (`replaces.symname`).
    pub bundles: Vec<String>,
    /// The GitHub accounts that may open its release pull requests.
    pub github: Vec<String>,
    /// Its website.
    pub homepage: Option<String>,
    /// Where security reports go.
    pub contact: Option<String>,
    /// How many of its keys sign a role file.
    pub threshold: u32,
    /// Its keys.
    pub keys: Vec<PublicKey>,
    /// The ports of the owner it replaces: port id to its own plugin id.
    pub supersedes: BTreeMap<String, String>,
    /// The versions the owner revoked.
    pub revoked_versions: Vec<RevokedVersion>,
    /// The files of its source archives (`src/…`) that may be binary and larger than 64 KiB
    /// (check 18 of a release pull request).
    pub binary_files: Vec<String>,
}

impl Publisher {
    /// Its delegated role.
    pub fn role(&self) -> RoleName {
        RoleName::of(&self.name)
    }

    /// Whether it is delegated to.
    pub fn is_active(&self) -> bool {
        self.state == State::Active
    }

    /// Whether its prefix, modules, bundles and ports are its own: unless it is revoked.
    pub fn keeps_rules(&self) -> bool {
        self.state != State::Revoked
    }

    /// Whether `id` is under its prefix.
    pub fn covers(&self, id: &str) -> bool {
        id.starts_with(&self.id_prefix)
    }

    /// Whether the owner may revoke versions of `id` for it: a plugin id under its prefix.
    /// [`Registry::settle`] and `tuf check` use the same filter.
    pub fn may_revoke(&self, id: &str) -> bool {
        self.covers(id) && is_plugin_id(id)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPublisher {
    name: String,
    #[serde(default)]
    state: State,
    #[serde(default)]
    revoked: Option<String>,
    #[serde(default)]
    revoke_all: Option<String>,
    display: Display,
    id_prefix: String,
    #[serde(default)]
    modules: Vec<String>,
    #[serde(default)]
    bundles: Vec<String>,
    #[serde(default)]
    github: Vec<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    contact: Option<String>,
    #[serde(default = "one")]
    threshold: u32,
    #[serde(default)]
    keys: Vec<RawKey>,
    #[serde(default)]
    supersedes: BTreeMap<String, String>,
    #[serde(default)]
    revoked_versions: Vec<RawRevokedVersion>,
    #[serde(default)]
    binary_files: Vec<String>,
}

fn one() -> u32 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKey {
    public: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRevokedVersion {
    id: String,
    version: String,
    date: String,
}

/// `^[a-z0-9][a-z0-9.-]{1,62}[a-z0-9]$` with at least one dot, no empty label: a plugin id.
fn is_plugin_id(id: &str) -> bool {
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = id.as_bytes();
    let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    (3..=MAX_ID).contains(&bytes.len())
        && edge(first)
        && edge(last)
        && bytes.iter().all(|&b| edge(b) || b == b'.' || b == b'-')
        && bytes.contains(&b'.')
        && !id.contains("..")
}

/// A plugin id followed by `.`: `kz.ecc.`.
fn is_id_prefix(prefix: &str) -> bool {
    prefix.len() <= MAX_ID && prefix.strip_suffix('.').is_some_and(is_plugin_id)
}

/// A GitHub login: 1 to 39 letters, digits and single hyphens, not at either end.
fn is_github_login(login: &str) -> bool {
    (1..=39).contains(&login.len())
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !login.starts_with('-')
        && !login.ends_with('-')
        && !login.contains("--")
}

/// `YYYY-MM-DD`, a real date.
fn is_date(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    let [year, month, day] = parts.as_slice() else {
        return false;
    };
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    if !(digits(year, 4) && digits(month, 2) && digits(day, 2)) {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (year.parse::<i32>(), month.parse::<u8>(), day.parse())
    else {
        return false;
    };
    time::Month::try_from(month)
        .ok()
        .and_then(|month| time::Date::from_calendar_date(year, month, day).ok())
        .is_some()
}

/// `https://` and more, without white space, control characters or credentials.
fn is_https_url(url: &str) -> bool {
    url.len() <= MAX_URL
        && url.strip_prefix("https://").is_some_and(|rest| {
            !rest.is_empty()
                && !rest.contains('@')
                && rest.chars().all(|c| !c.is_whitespace() && !c.is_control())
        })
}

fn text_ok(text: &str, max: usize) -> bool {
    let count = text.chars().count();
    (1..=max).contains(&count) && !text.chars().any(char::is_control) && text.trim() == text
}

/// Every item once.
fn distinct<'a>(items: impl IntoIterator<Item = &'a String>, what: &str) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            bail!("{what} {item:?} is listed twice");
        }
    }
    Ok(())
}

/// Reads one publisher's file, its own rules checked. `dir_name` is the name of its
/// directory.
///
/// # Errors
///
/// If the TOML does not parse or breaks a rule (see the module's description).
pub fn parse_publisher(text: &str, dir_name: &str) -> anyhow::Result<Publisher> {
    let raw: RawPublisher = toml::from_str(text).context("not a valid publisher.toml")?;
    let name = PublisherName::parse(&raw.name).map_err(|e| anyhow::anyhow!("name: {e}"))?;
    if name.as_str() != dir_name {
        bail!("the name {name} is not the name of its directory {dir_name:?}");
    }
    for (lang, text) in [
        ("ru", &raw.display.ru),
        ("kk", &raw.display.kk),
        ("en", &raw.display.en),
    ] {
        if !text_ok(text, MAX_DISPLAY) {
            bail!(
                "display.{lang} must be 1 to {MAX_DISPLAY} characters without control \
                 characters or surrounding space"
            );
        }
        if text.to_lowercase().contains("openncalayer") {
            bail!("display.{lang} names OpenNCALayer: a publisher is not the project");
        }
    }
    if !is_id_prefix(&raw.id_prefix) {
        bail!(
            "id_prefix {:?} is not a reverse domain ending in '.' (kz.example.)",
            raw.id_prefix
        );
    }
    if raw.id_prefix.starts_with(PROJECT_PREFIX) || PROJECT_PREFIX.starts_with(&raw.id_prefix) {
        bail!(
            "id_prefix {:?} is nested with the project's own {PROJECT_PREFIX}",
            raw.id_prefix
        );
    }
    match (raw.state, &raw.revoked) {
        (State::Active | State::Retired, None) => {}
        (state @ (State::Active | State::Retired), Some(_)) => {
            bail!("revoked is set, but the state is {}", state.as_str())
        }
        (State::Revoked, Some(date)) if is_date(date) => {}
        (State::Revoked, _) => bail!("a revoked publisher needs revoked = \"YYYY-MM-DD\""),
    }
    match (raw.state, &raw.revoke_all) {
        (_, None) => {}
        (State::Revoked, Some(_)) => bail!(
            "revoke_all is set, but the publisher is revoked: every plugin of a revoked \
             publisher is off already"
        ),
        (State::Active | State::Retired, Some(date)) if is_date(date) => {}
        (State::Active | State::Retired, Some(date)) => {
            bail!("revoke_all {date:?} is not YYYY-MM-DD")
        }
    }
    let mut keys = Vec::with_capacity(raw.keys.len());
    for key in &raw.keys {
        let public = PublicKey::from_hex(&key.public)
            .with_context(|| format!("keys: {:?} is not 64 lowercase hex digits", key.public))?;
        if keys.contains(&public) {
            bail!("keys: the key {} is listed twice", public.key_id());
        }
        keys.push(public);
    }
    if raw.state == State::Active {
        if keys.is_empty() {
            bail!("an active publisher needs at least one key ([[keys]] public = \"<hex>\")");
        }
        if raw.modules.is_empty() {
            bail!("an active publisher needs at least one module");
        }
        if raw.github.is_empty() {
            bail!("an active publisher needs at least one GitHub account (github)");
        }
    }
    if !(1..=keys.len().max(1)).contains(&(raw.threshold as usize)) {
        bail!(
            "threshold {} is not between 1 and the {} keys",
            raw.threshold,
            keys.len()
        );
    }
    for module in &raw.modules {
        if !oncl_plugin::is_symbolic_name(module) {
            bail!("module {module:?} is not a valid module name");
        }
    }
    distinct(&raw.modules, "module")?;
    for bundle in &raw.bundles {
        if !oncl_plugin::is_symbolic_name(bundle) {
            bail!("bundle {bundle:?} is not a valid symbolic name");
        }
    }
    distinct(&raw.bundles, "bundle")?;
    for login in &raw.github {
        if !is_github_login(login) {
            bail!("github {login:?} is not a GitHub account name");
        }
    }
    distinct(&raw.github, "github account")?;
    if let Some(url) = &raw.homepage
        && !is_https_url(url)
    {
        bail!("homepage {url:?} is not an https:// URL without credentials");
    }
    if let Some(contact) = &raw.contact
        && !text_ok(contact, MAX_URL)
    {
        bail!("contact must be one line of 1 to {MAX_URL} characters");
    }
    let mut replacing = BTreeSet::new();
    for (port, plugin) in &raw.supersedes {
        if !is_plugin_id(port) || !port.starts_with(PROJECT_PREFIX) {
            bail!("supersedes: {port:?} is not a port of the project ({PROJECT_PREFIX}…)");
        }
        if port.starts_with(oncl_plugin::BUILTIN_ID_PREFIX) {
            bail!("supersedes: {port} is a built-in module, not a port");
        }
        if !is_plugin_id(plugin) || !plugin.starts_with(&raw.id_prefix) {
            bail!(
                "supersedes: {plugin:?} is not a plugin id under {}",
                raw.id_prefix
            );
        }
        if !replacing.insert(plugin) {
            bail!("supersedes: {plugin} replaces more than one port");
        }
    }
    let mut revoked_versions = Vec::with_capacity(raw.revoked_versions.len());
    let mut seen = BTreeSet::new();
    for entry in &raw.revoked_versions {
        if !is_plugin_id(&entry.id) || !entry.id.starts_with(&raw.id_prefix) {
            bail!(
                "revoked_versions: {:?} is not a plugin id under {}",
                entry.id,
                raw.id_prefix
            );
        }
        let version = Version::parse(&entry.version).with_context(|| {
            format!(
                "revoked_versions: {} {:?} is not a semver version",
                entry.id, entry.version
            )
        })?;
        if !is_date(&entry.date) {
            bail!(
                "revoked_versions: {} {}: date {:?} is not YYYY-MM-DD",
                entry.id,
                version,
                entry.date
            );
        }
        if !seen.insert((entry.id.clone(), version.clone())) {
            bail!("revoked_versions: {} {} is listed twice", entry.id, version);
        }
        revoked_versions.push(RevokedVersion {
            id: entry.id.clone(),
            version,
            date: entry.date.clone(),
        });
    }
    if raw.binary_files.len() > MAX_BINARY_FILES {
        bail!("binary_files: more than {MAX_BINARY_FILES} files");
    }
    for path in &raw.binary_files {
        let under = path.strip_prefix("src/").filter(|rest| !rest.is_empty());
        if !under.is_some_and(|rest| oncl_pack::source::check_dir_path(rest).is_ok()) {
            bail!("binary_files: {path:?} is not the path of a file of a source archive (src/…)");
        }
    }
    distinct(&raw.binary_files, "binary file")?;
    Ok(Publisher {
        name,
        state: raw.state,
        revoked: raw.revoked,
        revoke_all: raw.revoke_all,
        display: raw.display,
        id_prefix: raw.id_prefix,
        modules: raw.modules,
        bundles: raw.bundles,
        github: raw.github,
        homepage: raw.homepage,
        contact: raw.contact,
        threshold: raw.threshold,
        keys,
        supersedes: raw.supersedes,
        revoked_versions,
        binary_files: raw.binary_files,
    })
}

/// Every publisher, by name, the rules between them checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    publishers: BTreeMap<PublisherName, Publisher>,
}

impl Registry {
    /// The registry in `dir` (`publishers/`): every directory in it is a publisher with its
    /// `publisher.toml`; the only other entry allowed is a `README.md` file. No directory is
    /// an empty registry.
    ///
    /// # Errors
    ///
    /// If a directory cannot be read, an entry is neither a publisher's directory,
    /// `README.md`, [`builders::FILE_NAME`] nor [`sdk_revisions::FILE_NAME`], a publisher's
    /// file is missing or breaks a rule,
    /// or the publishers break a rule between them ([`Registry::new`]).
    pub fn read(dir: &Path) -> anyhow::Result<Registry> {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Registry::default());
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        let mut publishers = Vec::new();
        let mut paths: Vec<_> = entries
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<_, _>>()
            .with_context(|| format!("reading {}", dir.display()))?;
        paths.sort();
        for path in paths {
            if !path.is_dir() {
                if path.file_name().is_some_and(|n| {
                    n == "README.md" || n == builders::FILE_NAME || n == sdk_revisions::FILE_NAME
                }) && path.is_file()
                {
                    continue;
                }
                bail!(
                    "{} is not a publisher's directory: {} holds only those, README.md, {} and {}",
                    path.display(),
                    dir.display(),
                    builders::FILE_NAME,
                    sdk_revisions::FILE_NAME
                );
            }
            let dir_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let file = path.join(FILE_NAME);
            let size = fs::metadata(&file)
                .with_context(|| format!("reading {}", file.display()))?
                .len();
            if size > MAX_FILE_LEN {
                bail!("{} is larger than {MAX_FILE_LEN} bytes", file.display());
            }
            let text =
                fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            publishers.push(
                parse_publisher(&text, &dir_name).with_context(|| format!("{}", file.display()))?,
            );
        }
        Registry::new(publishers)
    }

    /// The registry of `publishers`, the rules between them checked: names, prefixes,
    /// modules, bundles, superseded ports and keys distinct (modules and bundles in any
    /// case, as the client compares them), prefixes not nested, modules not built-in and
    /// bundles not the core's, at most [`MAX_PUBLISHERS`] publishers,
    /// [`MAX_REVOKED_VERSIONS`] revoked versions and [`Limits::max_delegations`] active
    /// publishers. A retired publisher's modules, bundles and ports count as its own.
    ///
    /// # Errors
    ///
    /// The first rule broken.
    pub fn new(publishers: Vec<Publisher>) -> anyhow::Result<Registry> {
        if publishers.len() > MAX_PUBLISHERS {
            bail!(
                "{} publishers: publishers.json lists at most {MAX_PUBLISHERS}",
                publishers.len()
            );
        }
        let revoked: usize = publishers
            .iter()
            .filter(|p| p.keeps_rules())
            .map(|p| p.revoked_versions.len())
            .sum();
        if revoked > MAX_REVOKED_VERSIONS {
            bail!(
                "{revoked} revoked versions: publishers.json lists at most \
                 {MAX_REVOKED_VERSIONS}, all publishers together"
            );
        }
        let max_active = Limits::default().max_delegations as usize;
        let active = publishers.iter().filter(|p| p.is_active()).count();
        if active > max_active {
            bail!("{active} active publishers: clients follow at most {max_active} roles");
        }
        let builtin = crate::index::builtin_modules()?;
        let mut by_name = BTreeMap::new();
        let mut module_owner: BTreeMap<String, &PublisherName> = BTreeMap::new();
        let mut bundle_owner: BTreeMap<String, &PublisherName> = BTreeMap::new();
        let mut port_owner: BTreeMap<&str, &PublisherName> = BTreeMap::new();
        let mut key_owner: BTreeMap<KeyId, &PublisherName> = BTreeMap::new();
        for (i, p) in publishers.iter().enumerate() {
            for other in &publishers[..i] {
                if other.name == p.name {
                    bail!("the publisher {} is there twice", p.name);
                }
                if p.id_prefix.starts_with(&other.id_prefix)
                    || other.id_prefix.starts_with(&p.id_prefix)
                {
                    bail!(
                        "the id prefixes of {} ({}) and {} ({}) are nested",
                        other.name,
                        other.id_prefix,
                        p.name,
                        p.id_prefix
                    );
                }
            }
            for key in &p.keys {
                if let Some(owner) = key_owner.insert(key.key_id(), &p.name) {
                    bail!(
                        "the key {} is a key of both {owner} and {}: one key, one role",
                        key.key_id(),
                        p.name
                    );
                }
            }
            if !p.keeps_rules() {
                continue;
            }
            for module in &p.modules {
                if builtin.iter().any(|b| b.eq_ignore_ascii_case(module)) {
                    bail!("{}: {module} is a built-in module", p.name);
                }
                if let Some(owner) = module_owner.insert(module.to_ascii_lowercase(), &p.name) {
                    bail!(
                        "the module {module} is claimed by both {owner} and {}",
                        p.name
                    );
                }
            }
            for bundle in &p.bundles {
                if oncl_builtin_accessory::CORE_BUNDLES
                    .iter()
                    .any(|(symname, _)| symname == bundle)
                {
                    bail!("{}: the bundle {bundle} is the core's", p.name);
                }
                if let Some(owner) = bundle_owner.insert(bundle.to_ascii_lowercase(), &p.name) {
                    bail!(
                        "the bundle {bundle} is claimed by both {owner} and {}",
                        p.name
                    );
                }
            }
            for port in p.supersedes.keys() {
                if let Some(owner) = port_owner.insert(port, &p.name) {
                    bail!(
                        "the port {port} is superseded by both {owner} and {}",
                        p.name
                    );
                }
            }
        }
        for p in publishers {
            by_name.insert(p.name.clone(), p);
        }
        Ok(Registry {
            publishers: by_name,
        })
    }

    /// Every publisher, by name.
    pub fn publishers(&self) -> impl Iterator<Item = &Publisher> {
        self.publishers.values()
    }

    /// Whether there is no publisher: then the top-level targets have neither
    /// `delegations` nor `publishers.json`, as before the first publisher.
    pub fn is_empty(&self) -> bool {
        self.publishers.is_empty()
    }

    /// The active publishers, by name.
    pub fn active(&self) -> impl Iterator<Item = &Publisher> {
        self.publishers().filter(|p| p.is_active())
    }

    /// The publisher `name`.
    pub fn get(&self, name: &PublisherName) -> Option<&Publisher> {
        self.publishers.get(name)
    }

    /// No publisher's key is a key of one of `roots` (`(what, root)`): one key, one role.
    ///
    /// # Errors
    ///
    /// The first key that is.
    pub fn check_roots(&self, roots: &[(&str, &Root)]) -> anyhow::Result<()> {
        for p in self.publishers() {
            for key in &p.keys {
                for (what, root) in roots {
                    if root.keys.contains_key(&key.key_id()) {
                        bail!(
                            "the key {} of {} is a key of {what} (root {})",
                            key.key_id(),
                            p.name,
                            root.version
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Р24: the newest role file of every active publisher in the repository `dir` is
    /// signed by a threshold of the keys its `publisher.toml` keeps. A rotation removes the
    /// old key only after the role was re-signed with the new one: otherwise the clients
    /// would get a delegation their newest role does not verify under. A publisher without
    /// a role file yet passes.
    ///
    /// # Errors
    ///
    /// Every publisher whose newest role file falls short, or a role file that cannot be
    /// read.
    pub fn check_newest_roles(&self, dir: &Path) -> anyhow::Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }
        let newest = crate::tuf::repo::Listing::read(dir)?.newest_roles();
        let mut short = Vec::new();
        for p in self.active() {
            let role = p.role();
            let Some(version) = newest.get(&role) else {
                continue;
            };
            let what = oncl_update::tuf::layout::delegated_path(*version, &role);
            let bytes = fs::read(dir.join(&what)).with_context(|| format!("reading {what}"))?;
            let envelope = Envelope::parse(&bytes, Limits::default().delegated, &what)
                .map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
            let keys: BTreeMap<KeyId, PublicKey> =
                p.keys.iter().map(|k| (k.key_id(), *k)).collect();
            let role_keys = RoleKeys {
                keyids: keys.keys().copied().collect(),
                threshold: p.threshold,
            };
            if let Err(e) = verify_threshold(&envelope, &role_keys, &keys, &what) {
                short.push(format!(
                    "publishers/{}: {e}: the newest role file is not signed by a threshold of \
                     the keys publisher.toml keeps; the publisher re-signs the role with the \
                     new key before the old key is removed (Р24)",
                    p.name
                ));
            }
        }
        if short.is_empty() {
            Ok(())
        } else {
            bail!("{}", short.join("\n"))
        }
    }

    /// Р28: every publisher of the signed `publishers.json` `earlier` is still in the
    /// registry, with the same name and id prefix. Entries are kept for good: a publisher
    /// missing from the file is unavailable to the clients, never revoked.
    ///
    /// # Errors
    ///
    /// If `earlier` cannot be read, or lists a publisher that went or whose prefix changed.
    pub fn keeps(&self, earlier: &[u8]) -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct Earlier {
            publishers: Vec<Entry>,
        }
        #[derive(Deserialize)]
        struct Entry {
            name: String,
            id_prefix: String,
        }
        let earlier: Earlier = serde_json::from_slice(earlier)
            .with_context(|| format!("{TARGET} does not read as one"))?;
        let mut broken = Vec::new();
        for entry in &earlier.publishers {
            let now = PublisherName::parse(&entry.name)
                .ok()
                .and_then(|name| self.publishers.get(&name));
            match now {
                None => broken.push(format!("{} is gone", entry.name)),
                Some(p) if p.id_prefix != entry.id_prefix => broken.push(format!(
                    "{} has the id_prefix {} instead of {}",
                    entry.name, p.id_prefix, entry.id_prefix
                )),
                Some(_) => {}
            }
        }
        if broken.is_empty() {
            Ok(())
        } else {
            bail!(
                "{}: an entry of publishers/ is never removed, and its name and id_prefix never \
                 change (Р28)",
                broken.join("; ")
            )
        }
    }

    /// The owner's `indexes` against the publishers: no plugin of an index is under a
    /// publisher's prefix, no module or bundle an active or retired publisher claims is
    /// served by a port unless the publisher supersedes that port, and every port an active
    /// publisher supersedes is a plugin of some index (its plugin id is under the
    /// publisher's prefix: [`parse_publisher`]).
    ///
    /// # Errors
    ///
    /// The first conflict.
    pub fn check_indexes(&self, indexes: &[Index]) -> anyhow::Result<()> {
        for index in indexes {
            for port in &index.plugins {
                for p in self.publishers() {
                    if p.covers(&port.id) {
                        bail!(
                            "the {} index has the plugin {} under the prefix {} of {}",
                            index.channel,
                            port.id,
                            p.id_prefix,
                            p.name
                        );
                    }
                }
                for p in self.publishers().filter(|p| p.keeps_rules()) {
                    if p.supersedes.contains_key(&port.id) {
                        continue;
                    }
                    if let Some(module) = port
                        .modules
                        .iter()
                        .find(|m| p.modules.iter().any(|own| own.eq_ignore_ascii_case(m)))
                    {
                        bail!(
                            "{} claims the module {module}, which the port {} serves (only a \
                             port in its supersedes may share it)",
                            p.name,
                            port.id
                        );
                    }
                    if let Some(replaces) = &port.replaces
                        && p.bundles
                            .iter()
                            .any(|own| own.eq_ignore_ascii_case(&replaces.symname))
                    {
                        bail!(
                            "{} claims the bundle {}, which the port {} replaces (only a port \
                             in its supersedes may share it)",
                            p.name,
                            replaces.symname,
                            port.id
                        );
                    }
                }
            }
        }
        for p in self.active() {
            for port in p.supersedes.keys() {
                let listed = indexes
                    .iter()
                    .any(|index| index.plugins.iter().any(|plugin| plugin.id == *port));
                if !listed {
                    bail!(
                        "{} supersedes {port}, which is no plugin of the owner's indexes",
                        p.name
                    );
                }
            }
        }
        Ok(())
    }

    /// The `delegations` member of the top-level targets: every active publisher's role, by
    /// name. A retired or revoked publisher has none.
    pub fn delegations(&self) -> Value {
        let mut keys = Map::new();
        let mut roles = Vec::new();
        for p in self.active() {
            let mut keyids = Vec::with_capacity(p.keys.len());
            for key in &p.keys {
                let id = key.key_id().to_hex();
                keys.insert(id.clone(), key.to_value());
                keyids.push(Value::String(id));
            }
            roles.push(json!({
                "name": p.role().as_str(),
                "keyids": keyids,
                "threshold": p.threshold,
                "paths": [PathPattern::of(&p.name).to_string()],
                "terminating": true,
            }));
        }
        json!({"keys": keys, "roles": roles})
    }

    /// `publishers.json`: canonical JSON and a newline, read back as the client reads it.
    ///
    /// # Errors
    ///
    /// If it would be larger than [`MAX_JSON_LEN`], or the client would not read it whole.
    pub fn publishers_json(&self) -> anyhow::Result<Vec<u8>> {
        let entries: Vec<Value> = self.publishers().map(entry).collect();
        let value = json!({"schema": SCHEMA, "publishers": entries});
        let mut bytes = oncl_update::tuf::canonical::to_vec(&value)
            .map_err(|e| anyhow::anyhow!("publishers.json: {e}"))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_JSON_LEN {
            bail!(
                "publishers.json would be {} bytes, more than {MAX_JSON_LEN}",
                bytes.len()
            );
        }
        let policy = PublisherPolicy::from_json(&bytes)
            .map_err(|e| anyhow::anyhow!("the client would not read publishers.json: {e}"))?;
        if let Some(p) = policy
            .publishers()
            .iter()
            .find(|p| matches!(p.standing(), Standing::Unknown { .. }))
        {
            bail!(
                "publishers.json gives {} a state the client does not know",
                p.name()
            );
        }
        Ok(bytes)
    }

    /// What `tuf update` writes into the files of `dir` (`publishers/`) before it signs,
    /// so that `publishers.json` stays a function of them (`docs/design/publishers.md`,
    /// "Подключение издателя"):
    ///
    /// - a retired publisher whose role `delegated` still names (the move to `retired`):
    ///   every target of the newest file of its role in the repository `repo` marked
    ///   `revoked: true` becomes an owner's revoked version dated `today`, so that the
    ///   publisher's own revocations outlive its role;
    /// - `revoke_all = "<date>"`: every target of every file of the publisher's role in git
    ///   at the last commit on or before that date (first parents of `HEAD`) becomes a
    ///   revoked version of that date, and the line goes. A shallow clone is refused, and so
    ///   is a date that finds nothing while the role has files: a revocation never silently
    ///   revokes nothing.
    ///
    /// Only versions [`Publisher::may_revoke`] are added, and none already revoked. A date
    /// (`revoke_all`, `revoked`, `revoked_versions`) after `today` (UTC) is refused. Nothing
    /// is written here.
    ///
    /// # Errors
    ///
    /// If a file cannot be read, a date is in the future, git cannot answer for
    /// `revoke_all` (or the clone is shallow), `revoke_all` finds no version of a role that
    /// has files, or the result does not read back as the file it should be.
    pub fn settle(
        &self,
        dir: &Path,
        repo: &Path,
        delegated: &BTreeSet<RoleName>,
        today: &str,
    ) -> anyhow::Result<Vec<Settled>> {
        let newest = if repo.is_dir() {
            crate::tuf::repo::Listing::read(repo)?.newest_roles()
        } else {
            BTreeMap::new()
        };
        let mut settled = Vec::new();
        for p in self.publishers() {
            let mut dates = p
                .revoke_all
                .iter()
                .chain(p.revoked.iter())
                .chain(p.revoked_versions.iter().map(|r| &r.date));
            if let Some(date) = dates.find(|d| d.as_str() > today) {
                bail!(
                    "publishers/{}: the date {date} is after today ({today}, UTC): a revocation \
                     is dated when it is made",
                    p.name
                );
            }
            let role = p.role();
            let mut added: Vec<RevokedVersion> = Vec::new();
            let mut why = Vec::new();
            let mut add = |id: String, version: Version, date: &str| {
                let known = |list: &[RevokedVersion]| {
                    list.iter().any(|r| r.id == id && r.version == version)
                };
                if p.may_revoke(&id) && !known(&p.revoked_versions) && !known(&added) {
                    added.push(RevokedVersion {
                        id,
                        version,
                        date: date.to_owned(),
                    });
                }
            };
            if p.state == State::Retired
                && delegated.contains(&role)
                && let Some(version) = newest.get(&role)
            {
                let what = oncl_update::tuf::layout::delegated_path(*version, &role);
                let bytes =
                    fs::read(repo.join(&what)).with_context(|| format!("reading {what}"))?;
                for (id, version, revoked) in role_entries(&bytes, &what)? {
                    if revoked {
                        add(id, version, today);
                    }
                }
                why.push(format!(
                    "retired: the versions {what} revokes are revoked by the owner"
                ));
            }
            if let Some(date) = &p.revoke_all {
                let files = role_files_at(repo, &role, date)?;
                let mut found = 0;
                for (what, bytes) in files {
                    for (id, version, _) in role_entries(&bytes, &what)? {
                        found += 1;
                        add(id, version, date);
                    }
                }
                if found == 0 && newest.contains_key(&role) {
                    bail!(
                        "publishers/{}: revoke_all = \"{date}\" finds no version of {role} in \
                         git on that date, but the role has files: check the date (the commit \
                         that added them is later?) and write the versions in revoked_versions \
                         if need be",
                        p.name
                    );
                }
                why.push(format!(
                    "revoke_all = \"{date}\": every version of {role} in git on that date"
                ));
            }
            if added.is_empty() && p.revoke_all.is_none() {
                continue;
            }
            let path = dir.join(p.name.as_str()).join(FILE_NAME);
            let before =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let after = settled_text(&before, &added);
            let back = parse_publisher(&after, p.name.as_str()).with_context(|| {
                format!(
                    "{} could not be settled: write its revoked_versions by hand",
                    path.display()
                )
            })?;
            if back.revoke_all.is_some()
                || back.revoked_versions.len() != p.revoked_versions.len() + added.len()
            {
                bail!(
                    "{} could not be settled: write its revoked_versions by hand and remove \
                     revoke_all",
                    path.display()
                );
            }
            settled.push(Settled {
                name: p.name.clone(),
                path,
                before,
                after,
                added,
                why: why.join("; "),
            });
        }
        Ok(settled)
    }
}

/// A `publisher.toml` that [`Registry::settle`] rewrites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settled {
    /// The publisher.
    pub name: PublisherName,
    /// The file.
    pub path: PathBuf,
    /// Its text now.
    pub before: String,
    /// Its text settled: the versions added, `revoke_all` gone.
    pub after: String,
    /// The versions added to `revoked_versions`.
    pub added: Vec<RevokedVersion>,
    /// Why, for the owner.
    pub why: String,
}

/// `text` without its `revoke_all` line and with a `[[revoked_versions]]` table for each of
/// `added` at the end. The line is a key of the top table, so it is looked for only before
/// the first table header.
fn settled_text(text: &str, added: &[RevokedVersion]) -> String {
    let mut out = String::with_capacity(text.len() + added.len() * 96);
    let mut top = true;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            top = false;
        }
        let is_revoke_all = trimmed
            .strip_prefix("revoke_all")
            .is_some_and(|rest| rest.trim_start().starts_with('='));
        if !(top && is_revoke_all) {
            out.push_str(line);
        }
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for r in added {
        out.push_str(&format!(
            "\n[[revoked_versions]]\nid = \"{}\"\nversion = \"{}\"\ndate = \"{}\"\n",
            r.id, r.version, r.date
        ));
    }
    out
}

/// The targets of the role file `bytes` (`what`, for errors): plugin id and version from
/// the path `plugins/<name>/<id>/<version>.onclp`, and whether the entry says
/// `revoked: true`. A path of another form, or a version that is not semver, is no plugin
/// release (the client skips it) and is left out.
///
/// # Errors
///
/// If the file is not a role file the client could read.
pub fn role_entries(bytes: &[u8], what: &str) -> anyhow::Result<Vec<(String, Version, bool)>> {
    let envelope = Envelope::parse(bytes, Limits::default().delegated, what)
        .map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    // A role delegates no further: the profile that refuses `delegations` reads it.
    let targets = Targets::from_signed(&envelope.signed, Profile::Legacy)
        .map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    let mut entries = Vec::new();
    for (path, target) in &targets.targets {
        let mut parts = path.as_str().split('/');
        let (Some("plugins"), Some(_), Some(id), Some(file), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        let Ok(version) = Version::parse(file.strip_suffix(".onclp").unwrap_or(file)) else {
            continue;
        };
        let revoked = target
            .custom
            .as_ref()
            .and_then(|custom| custom.get("oncl"))
            .and_then(|oncl| oncl.get("revoked"))
            .and_then(Value::as_bool)
            == Some(true);
        entries.push((id.to_owned(), version, revoked));
    }
    Ok(entries)
}

/// The files of `role` in the repository `repo` at the last git commit on or before the
/// end of `date` (UTC): `(path, bytes)`. None before the first commit.
fn role_files_at(
    repo: &Path,
    role: &RoleName,
    date: &str,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let (git_dir, _) = crate::index::existing_ancestor(repo)?;
    let shallow = crate::index::git(&git_dir, &["rev-parse", "--is-shallow-repository"])?;
    if !shallow.status.success() || String::from_utf8_lossy(&shallow.stdout).trim() != "false" {
        bail!(
            "revoke_all needs the whole git history of {}: this clone is shallow or not a git \
             repository (`git fetch --unshallow`)",
            repo.display()
        );
    }
    let before = format!("--before={date} 23:59:59 +0000");
    let found = crate::index::git(
        &git_dir,
        &["rev-list", "-1", "--first-parent", &before, "HEAD"],
    )?;
    if !found.status.success() {
        bail!(
            "revoke_all needs the git history of {}: git rev-list: {}",
            repo.display(),
            String::from_utf8_lossy(&found.stderr).trim()
        );
    }
    let rev = String::from_utf8_lossy(&found.stdout).trim().to_owned();
    if rev.is_empty() {
        return Ok(Vec::new());
    }
    let files = crate::tuf::check::base_files(repo, &rev)?;
    Ok(files
        .into_iter()
        .filter(|(path, _)| {
            matches!(
                crate::tuf::repo::classify(path),
                crate::tuf::repo::Kind::Delegated { role: ref r, .. } if r == role
            )
        })
        .collect())
}

/// A publisher's entry in `publishers.json`.
fn entry(p: &Publisher) -> Value {
    let display = json!({"ru": p.display.ru, "kk": p.display.kk, "en": p.display.en});
    match p.state {
        State::Revoked => json!({
            "name": p.name.as_str(),
            "state": "revoked",
            "display": display,
            "id_prefix": p.id_prefix,
            "revoked": p.revoked,
        }),
        State::Active | State::Retired => {
            let revoked: Vec<Value> = p
                .revoked_versions
                .iter()
                .map(|r| json!({"id": r.id, "version": r.version.to_string(), "date": r.date}))
                .collect();
            let mut value = json!({
                "name": p.name.as_str(),
                "state": p.state.as_str(),
                "display": display,
                "id_prefix": p.id_prefix,
                "modules": p.modules,
                "bundles": p.bundles,
                "supersedes": p.supersedes,
                "revoked_versions": revoked,
            });
            if let (Some(url), Some(members)) = (&p.homepage, value.as_object_mut()) {
                members.insert("homepage".to_owned(), Value::String(url.clone()));
            }
            value
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_hex(n: u8) -> String {
        oncl_update::tuf::SigningKey::from_seed(&[n; 32])
            .unwrap()
            .public()
            .to_hex()
    }

    fn toml_of(name: &str, prefix: &str, module: &str, key: u8) -> String {
        format!(
            "name = \"{name}\"\n\
             display = {{ ru = \"Ру\", kk = \"Қа\", en = \"En\" }}\n\
             id_prefix = \"{prefix}\"\n\
             modules = [\"{module}\"]\n\
             bundles = []\n\
             github = [\"{name}-release\"]\n\
             keys = [{{ public = \"{}\" }}]\n",
            key_hex(key)
        )
    }

    fn publisher(name: &str, prefix: &str, module: &str, key: u8) -> Publisher {
        parse_publisher(&toml_of(name, prefix, module, key), name).unwrap()
    }

    #[test]
    fn a_publisher_file_is_read_with_its_defaults() {
        let p = publisher("ecc", "kz.ecc.", "kz.ecc.market.Signer", 7);
        assert_eq!(p.state, State::Active);
        assert_eq!(p.threshold, 1);
        assert_eq!(p.role().as_str(), "pub-ecc");
        assert!(p.covers("kz.ecc.market"));
        assert!(!p.covers("kz.eccx.market"));
    }

    #[test]
    fn a_publisher_file_breaking_a_rule_is_refused() {
        let good = toml_of("ecc", "kz.ecc.", "kz.ecc.Signer", 7);
        let cases: Vec<(String, &str, &str)> = vec![
            (good.clone(), "other", "name of its directory"),
            (
                good.replace("name = \"ecc\"", "name = \"root\""),
                "root",
                "name",
            ),
            (good.replace("kz.ecc.", "kz.ecc"), "ecc", "id_prefix"),
            (
                good.replace("kz.ecc.", "io.github.arynyklas.openncalayer.x."),
                "ecc",
                "nested",
            ),
            (good.replace("kz.ecc.", "io.github."), "ecc", "nested"),
            (
                good.replace("en = \"En\"", "en = \"OpenNCALayer\""),
                "ecc",
                "names",
            ),
            (good.clone() + "unknown = 1\n", "ecc", "not a valid"),
            (good.clone() + "threshold = 2\n", "ecc", "threshold"),
            (
                good.replace("[\"kz.ecc.Signer\"]", "[\"a b\"]"),
                "ecc",
                "module",
            ),
            (good.replace("ecc-release", "-bad"), "ecc", "github"),
            (
                good.clone() + "homepage = \"http://ecc.kz/\"\n",
                "ecc",
                "homepage",
            ),
            (
                good.clone() + "state = \"revoked\"\n",
                "ecc",
                "revoked = \"YYYY-MM-DD\"",
            ),
            (
                good.clone() + "revoked = \"2027-01-01\"\n",
                "ecc",
                "state is active",
            ),
            (
                good.clone()
                    + "[supersedes]\n\"io.github.arynyklas.openncalayer.port.x\" = \"kz.other.x\"\n",
                "ecc",
                "supersedes",
            ),
            (
                good.clone()
                    + "[supersedes]\n\"io.github.arynyklas.openncalayer.port.x\" = \"kz.ecc.x\"\n\"io.github.arynyklas.openncalayer.port.y\" = \"kz.ecc.x\"\n",
                "ecc",
                "more than one port",
            ),
            (
                good.clone()
                    + "[[revoked_versions]]\nid = \"kz.ecc.x\"\nversion = \"1.0\"\ndate = \"2027-01-01\"\n",
                "ecc",
                "semver",
            ),
            (
                good.clone()
                    + "[[revoked_versions]]\nid = \"kz.ecc.x\"\nversion = \"1.0.0\"\ndate = \"2027-02-30\"\n",
                "ecc",
                "YYYY-MM-DD",
            ),
            (
                good.clone()
                    + "[[revoked_versions]]\nid = \"kz.other.x\"\nversion = \"1.0.0\"\ndate = \"2027-01-01\"\n",
                "ecc",
                "under kz.ecc.",
            ),
            (good.clone() + "state = \"suspended\"\n", "ecc", "suspended"),
            (
                good.clone() + "state = \"retired\"\nrevoked = \"2027-01-01\"\n",
                "ecc",
                "state is retired",
            ),
            (
                good.clone() + "revoke_all = \"2027-13-01\"\n",
                "ecc",
                "revoke_all",
            ),
            (
                good.clone()
                    + "state = \"revoked\"\nrevoked = \"2027-01-01\"\nrevoke_all = \"2027-01-01\"\n",
                "ecc",
                "revoke_all is set",
            ),
        ];
        for (text, dir, expected) in cases {
            let err = format!("{:#}", parse_publisher(&text, dir).unwrap_err());
            assert!(err.contains(expected), "{expected}: {err}\n{text}");
        }
    }

    #[test]
    fn publishers_that_overlap_are_refused() {
        let a = publisher("aaa", "kz.a.", "kz.a.M", 1);
        let nested = publisher("bbb", "kz.a.b.", "kz.b.M", 2);
        let err = Registry::new(vec![a.clone(), nested]).unwrap_err();
        assert!(err.to_string().contains("nested"), "{err}");
        let same_module = publisher("bbb", "kz.b.", "kz.a.M", 2);
        let err = Registry::new(vec![a.clone(), same_module]).unwrap_err();
        assert!(err.to_string().contains("claimed by both"), "{err}");
        let same_key = publisher("bbb", "kz.b.", "kz.b.M", 1);
        let err = Registry::new(vec![a.clone(), same_key]).unwrap_err();
        assert!(err.to_string().contains("one key, one role"), "{err}");
        let builtin = crate::index::builtin_modules().unwrap();
        let taken = publisher("bbb", "kz.b.", &builtin[0], 2);
        let err = Registry::new(vec![taken]).unwrap_err();
        assert!(err.to_string().contains("built-in"), "{err}");
    }

    #[test]
    fn a_retired_publisher_keeps_its_rules_and_loses_its_role() {
        let mut a = publisher("aaa", "kz.a.", "kz.a.M", 1);
        a.state = State::Retired;
        // Its module stays its own, in any case, as the client compares modules.
        let taker = publisher("bbb", "kz.b.", "KZ.A.M", 2);
        let err = Registry::new(vec![a.clone(), taker]).unwrap_err();
        assert!(err.to_string().contains("claimed by both"), "{err}");
        let registry = Registry::new(vec![a]).unwrap();
        assert_eq!(registry.delegations()["roles"], json!([]));
        let json: Value = serde_json::from_slice(&registry.publishers_json().unwrap()).unwrap();
        assert_eq!(json["publishers"][0]["state"], "retired");
        assert_eq!(json["publishers"][0]["modules"], json!(["kz.a.M"]));
    }

    #[test]
    fn publishers_json_keeps_the_limits_of_the_client() {
        let mut a = publisher("aaa", "kz.a.", "kz.a.M", 1);
        a.revoked_versions = (0..=MAX_REVOKED_VERSIONS)
            .map(|n| RevokedVersion {
                id: "kz.a.tool".to_owned(),
                version: Version::new(1, 0, n as u64),
                date: "2027-01-01".to_owned(),
            })
            .collect();
        let err = Registry::new(vec![a.clone()]).unwrap_err();
        assert!(err.to_string().contains("revoked versions"), "{err}");
        a.revoked_versions.pop();
        let bytes = Registry::new(vec![a]).unwrap().publishers_json().unwrap();
        assert!(bytes.len() <= MAX_JSON_LEN);
    }

    #[test]
    fn a_settled_file_loses_revoke_all_and_gains_the_versions() {
        let text = toml_of("ecc", "kz.ecc.", "kz.ecc.Signer", 7).replace(
            "bundles = []\n",
            "bundles = []\nrevoke_all = \"2027-04-01\" # the leak\n",
        );
        let before = parse_publisher(&text, "ecc").unwrap();
        assert_eq!(before.revoke_all.as_deref(), Some("2027-04-01"));
        let added = [RevokedVersion {
            id: "kz.ecc.market".to_owned(),
            version: Version::new(1, 2, 0),
            date: "2027-04-01".to_owned(),
        }];
        let after = parse_publisher(&settled_text(&text, &added), "ecc").unwrap();
        assert_eq!(after.revoke_all, None);
        assert_eq!(after.revoked_versions, added);
        assert_eq!(after.keys, before.keys);
    }

    #[test]
    fn the_delegations_and_publishers_json_list_what_the_files_say() {
        let a = publisher("aaa", "kz.a.", "kz.a.M", 1);
        let mut b = publisher("bbb", "kz.b.", "kz.b.M", 2);
        b.state = State::Revoked;
        b.revoked = Some("2027-03-01".to_owned());
        let registry = Registry::new(vec![b, a]).unwrap();
        let delegations = registry.delegations();
        let roles = delegations["roles"].as_array().unwrap();
        assert_eq!(roles.len(), 1, "a revoked publisher is not delegated to");
        assert_eq!(roles[0]["name"], "pub-aaa");
        assert_eq!(roles[0]["paths"], json!(["plugins/aaa/*/*"]));
        assert_eq!(roles[0]["terminating"], true);
        assert_eq!(delegations["keys"].as_object().unwrap().len(), 1);
        let json: Value = serde_json::from_slice(&registry.publishers_json().unwrap()).unwrap();
        assert_eq!(json["schema"], 1);
        let names: Vec<&str> = json["publishers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["aaa", "bbb"]);
        assert_eq!(json["publishers"][1]["state"], "revoked");
        assert_eq!(json["publishers"][1]["revoked"], "2027-03-01");
        assert!(json["publishers"][1].get("modules").is_none());
        // The bytes are a function of the files.
        assert_eq!(
            registry.publishers_json().unwrap(),
            Registry::new(registry.publishers().cloned().collect())
                .unwrap()
                .publishers_json()
                .unwrap()
        );
    }

    #[test]
    fn a_port_shares_its_modules_only_with_the_publisher_that_supersedes_it() {
        let mut p = publisher("ecc", "kz.ecc.", "kz.ecc.Signer", 1);
        let registry = Registry::new(vec![p.clone()]).unwrap();
        let index: Index = serde_json::from_value(json!({
            "schema": 1, "channel": "stable", "seq": 1,
            "generated": "2026-09-20T00:00:00Z", "expires": "2026-10-20T00:00:00Z",
            "core": [],
            "plugins": [{
                "id": "io.github.arynyklas.openncalayer.port.market",
                "version": "1.0.0",
                "url": "https://example.invalid/p.onclp", "size": 1, "sha256": "00".repeat(32),
                "min_core": "0.1.0",
                "modules": ["kz.ecc.Signer"],
                "name": {"ru": "x", "kk": "x", "en": "x"},
                "rollout": 100,
                "revoked": false
            }]
        }))
        .unwrap();
        let err = registry
            .check_indexes(std::slice::from_ref(&index))
            .unwrap_err();
        assert!(err.to_string().contains("serves"), "{err}");
        p.supersedes.insert(
            "io.github.arynyklas.openncalayer.port.market".to_owned(),
            "kz.ecc.market".to_owned(),
        );
        Registry::new(vec![p.clone()])
            .unwrap()
            .check_indexes(std::slice::from_ref(&index))
            .unwrap();
        // A port that no index has cannot be superseded.
        p.supersedes.insert(
            "io.github.arynyklas.openncalayer.port.gone".to_owned(),
            "kz.ecc.gone".to_owned(),
        );
        let err = Registry::new(vec![p])
            .unwrap()
            .check_indexes(&[index])
            .unwrap_err();
        assert!(
            err.to_string().contains("no plugin of the owner's indexes"),
            "{err}"
        );
    }

    #[test]
    fn the_registry_directory_holds_publishers_a_readme_and_the_builders_only() {
        let dir = tempfile::tempdir().unwrap();
        let ecc = dir.path().join("ecc");
        fs::create_dir_all(&ecc).unwrap();
        fs::write(
            ecc.join(FILE_NAME),
            toml_of("ecc", "kz.ecc.", "kz.ecc.Signer", 7),
        )
        .unwrap();
        fs::write(dir.path().join("README.md"), "the publishers").unwrap();
        fs::write(dir.path().join(builders::FILE_NAME), "").unwrap();
        let registry = Registry::read(dir.path()).unwrap();
        assert_eq!(registry.publishers().count(), 1);
        fs::write(dir.path().join("ecc.toml"), "name = \"ecc\"").unwrap();
        let err = Registry::read(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("not a publisher's directory"),
            "{err}"
        );
    }
}
