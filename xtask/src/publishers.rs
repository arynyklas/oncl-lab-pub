//! The owner's registry of third-party plugin publishers (`docs/design/publishers.md`,
//! "Подключение издателя"): `publishers/<name>/publisher.toml`, one file per publisher,
//! merged by the owner only. `cargo xtask tuf update` makes two things of it for `tuf/v2`,
//! and `cargo xtask tuf check` verifies the signed repository against them:
//!
//! - [`Registry::delegations`], the `delegations` member of the top-level targets: a role
//!   `pub-<name>` for each active publisher, with its keys and threshold, the paths
//!   `plugins/<name>/*/*` and `terminating: true`, in the order of the names;
//! - [`Registry::publishers_json`], the target `publishers.json`: every publisher, active or
//!   revoked, with its id prefix, modules, bundles, superseded ports and the versions the
//!   owner revoked.
//!
//! The schema is strict (unknown keys are refused) and so are the rules: the name is a
//! [`PublisherName`] and the name of its directory; the id prefix is a reverse domain ending
//! in `.`, never nested in another publisher's or the project's own; modules and bundles are
//! valid names, not built-in, not the core's, not another publisher's and not served by a
//! port of the owner's indexes unless that port is in `supersedes`; keys are distinct across
//! publishers and are no key of a root; `display` is not the project's name.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, bail};
use oncl_update::tuf::{KeyId, Limits, PathPattern, PublicKey, PublisherName, RoleName, Root};
use oncl_update::{Index, Version};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Where the registry is, from the workspace root.
pub const PUBLISHERS_DIR: &str = "publishers";

/// The file of one publisher, in its directory.
pub const FILE_NAME: &str = "publisher.toml";

/// The target path of the rules of the publishers in `tuf/v2`.
pub const TARGET: &str = "publishers.json";

/// The `schema` of `publishers.json`.
pub const SCHEMA: u32 = 1;

/// The most publishers, active and revoked, `publishers.json` lists.
pub const MAX_PUBLISHERS: usize = 128;

/// The largest `publishers.json`.
pub const MAX_JSON_LEN: usize = 64 << 10;

/// The largest `publisher.toml` read.
const MAX_FILE_LEN: u64 = 64 << 10;

/// The prefix of the project's own plugin ids: no publisher's prefix is nested with it.
const PROJECT_PREFIX: &str = "io.github.arynyklas.openncalayer.";

/// The longest plugin id or id prefix, in bytes (as in a plugin's manifest).
const MAX_ID: usize = 64;

/// The longest translation of `display`, in characters.
const MAX_DISPLAY: usize = 128;

/// The longest URL or contact line.
const MAX_URL: usize = 2048;

/// Whether a publisher's plugins are offered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Delegated to: its role is in the top-level targets.
    #[default]
    Active,
    /// Not delegated to any more; its prefix stays reserved, and clients switch its plugins
    /// off.
    Revoked,
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
    /// Active or revoked.
    pub state: State,
    /// When it was revoked, `YYYY-MM-DD`: exactly for a revoked publisher.
    pub revoked: Option<String>,
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

    /// Whether `id` is under its prefix.
    pub fn covers(&self, id: &str) -> bool {
        id.starts_with(&self.id_prefix)
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
        (State::Active, None) => {}
        (State::Active, Some(_)) => bail!("revoked is set, but the state is active"),
        (State::Revoked, Some(date)) if is_date(date) => {}
        (State::Revoked, _) => bail!("a revoked publisher needs revoked = \"YYYY-MM-DD\""),
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
    Ok(Publisher {
        name,
        state: raw.state,
        revoked: raw.revoked,
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
    /// If a directory cannot be read, an entry is neither a publisher's directory nor
    /// `README.md`, a publisher's file is missing or breaks a rule, or the publishers break a
    /// rule between them ([`Registry::new`]).
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
                if path.file_name().is_some_and(|n| n == "README.md") && path.is_file() {
                    continue;
                }
                bail!(
                    "{} is not a publisher's directory: {} holds only those and README.md",
                    path.display(),
                    dir.display()
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
    /// modules, bundles, superseded ports and keys distinct, prefixes not nested, modules
    /// not built-in and bundles not the core's, at most [`MAX_PUBLISHERS`] publishers and
    /// [`Limits::max_delegations`] active ones.
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
        let max_active = Limits::default().max_delegations as usize;
        let active = publishers.iter().filter(|p| p.is_active()).count();
        if active > max_active {
            bail!("{active} active publishers: clients follow at most {max_active} roles");
        }
        let builtin = crate::index::builtin_modules()?;
        let mut by_name = BTreeMap::new();
        let mut module_owner: BTreeMap<&str, &PublisherName> = BTreeMap::new();
        let mut bundle_owner: BTreeMap<&str, &PublisherName> = BTreeMap::new();
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
            if !p.is_active() {
                continue;
            }
            for module in &p.modules {
                if builtin.contains(module) {
                    bail!("{}: {module} is a built-in module", p.name);
                }
                if let Some(owner) = module_owner.insert(module, &p.name) {
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
                if let Some(owner) = bundle_owner.insert(bundle, &p.name) {
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

    /// The owner's `indexes` against the active publishers: no plugin of an index is under a
    /// publisher's prefix, no module or bundle a publisher claims is served by a port unless
    /// the publisher supersedes that port, and every port a publisher supersedes is a plugin
    /// of some index (its plugin id is under the publisher's prefix: [`parse_publisher`]).
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
                for p in self.active() {
                    if p.supersedes.contains_key(&port.id) {
                        continue;
                    }
                    if let Some(module) = port.modules.iter().find(|m| p.modules.contains(m)) {
                        bail!(
                            "{} claims the module {module}, which the port {} serves (only a \
                             port in its supersedes may share it)",
                            p.name,
                            port.id
                        );
                    }
                    if let Some(replaces) = &port.replaces
                        && p.bundles.contains(&replaces.symname)
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

    /// The `delegations` member of the top-level targets of `tuf/v2`: every active
    /// publisher's role, by name.
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

    /// `publishers.json`: canonical JSON and a newline.
    ///
    /// # Errors
    ///
    /// If it would be larger than [`MAX_JSON_LEN`].
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
        Ok(bytes)
    }
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
        State::Active => {
            let revoked: Vec<Value> = p
                .revoked_versions
                .iter()
                .map(|r| json!({"id": r.id, "version": r.version.to_string(), "date": r.date}))
                .collect();
            let mut value = json!({
                "name": p.name.as_str(),
                "state": "active",
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
    fn the_registry_directory_holds_publishers_and_a_readme_only() {
        let dir = tempfile::tempdir().unwrap();
        let ecc = dir.path().join("ecc");
        fs::create_dir_all(&ecc).unwrap();
        fs::write(
            ecc.join(FILE_NAME),
            toml_of("ecc", "kz.ecc.", "kz.ecc.Signer", 7),
        )
        .unwrap();
        fs::write(dir.path().join("README.md"), "the publishers").unwrap();
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
