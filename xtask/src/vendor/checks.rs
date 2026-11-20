//! The checks of a publisher's release pull request (`docs/design/publishers.md`, «Проверки»
//! and «Проверки PR издателя»), each a pure function over data: the paths the pull request
//! changes, the bytes of its role file, what the base (`main`) says ([`Base`]), a source
//! archive's files. Each returns its [`Finding`]s, none when it holds; [`super::pr`] reads
//! the data from git and the network and runs them in order.
//!
//! The rules the client applies to a target are the client's own code
//! ([`PublisherRelease::parse`], [`ReleaseSource::parse`], [`Capabilities`] from
//! `custom.oncl.capabilities`): CI and client agree by construction, and CI adds what only it
//! can know (unknown members, the builder list, licences, history, the catalog after the
//! merge).

use std::collections::{BTreeMap, BTreeSet};

use oncl_pack::source::Tree;
use oncl_plugin::Capabilities;
use oncl_update::catalog::{
    EntryRejection, PROJECT_PREFIX, PublisherRelease, PublisherTarget, ReleaseSource, mirror_url,
};
use oncl_update::index::Index;
use oncl_update::tuf::ed25519::verify_threshold;
use oncl_update::tuf::{
    Delegations, Envelope, Profile, PublisherName, RoleName, Target, TargetPath, Targets,
};
use oncl_update::{Channel, Version};
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use super::git::{Change, ChangeKind};
use super::licenses::{self, Reading};
use super::{
    Layout, MAX_EXPIRY_DAYS, MAX_NEW_PACKAGES, MAX_PLAIN_BINARY, MAX_ROLE_FILE, MAX_TARGETS,
    MIN_EXPIRY_DAYS, RELEASE_INTERVAL,
};
use crate::publishers::builders::Builders;
use crate::publishers::sdk_revisions::SdkRevisions;
use crate::publishers::{Publisher, Registry};

/// One way the pull request breaks check [`Finding::check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The check's number.
    pub check: u8,
    /// What is wrong.
    pub message: String,
}

/// A [`Finding`] of check `check`.
pub fn finding(check: u8, message: impl Into<String>) -> Finding {
    Finding {
        check,
        message: message.into(),
    }
}

/// The newest file of a publisher's role on the base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleAt {
    /// Its version.
    pub version: u64,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

/// What the base (`main`) says, read and verified before any check.
#[derive(Clone, Debug)]
pub struct Base {
    /// The registry of the publishers (`publishers/`).
    pub registry: Registry,
    /// The builder images (`publishers/builders.toml`).
    pub builders: Builders,
    /// The `delegations` of the newest top-level targets, verified by the client's code.
    pub delegations: Option<Delegations>,
    /// The owner's indexes.
    pub indexes: Vec<Index>,
    /// The newest role file of each publisher that has one.
    pub roles: BTreeMap<PublisherName, RoleAt>,
    /// The modules built into the core: no plugin serves them.
    pub builtin_modules: Vec<String>,
    /// The git sources a lock file may name (check 17).
    pub git_sources: GitSources,
}

/// The git sources a lock file may name besides crates.io (check 17).
#[derive(Clone, Debug, Default)]
pub struct GitSources {
    /// The repositories of `deny.toml` (`allow-git`), at any commit.
    pub allowed: Vec<String>,
    /// The released SDK commits of this repository (`publishers/sdk-revisions.toml`): only
    /// the crates of the SDK, only at these commits.
    pub sdk: SdkRevisions,
}

/// This repository: a lock file may name it as the git source of the SDK's crates, at a
/// released commit (check 17, Р44).
pub const OWN_REPOSITORY: &str = "https://github.com/arynyklas/OpenNCALayer";

/// The registry sources a lock file may name: crates.io, as git index or sparse.
const REGISTRIES: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// The role file a pull request adds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleFile {
    /// Its path in the repository.
    pub path: String,
    /// Its version, from the file name.
    pub version: u64,
    /// The publisher.
    pub publisher: PublisherName,
}

/// Check 1, the paths: exactly one change, a new regular file
/// `<tuf>/metadata/<V>.pub-<publisher>.json`.
///
/// # Errors
///
/// The findings of check 1.
pub fn role_path(changes: &[Change], layout: &Layout) -> Result<RoleFile, Vec<Finding>> {
    let [change] = changes else {
        let paths: Vec<&str> = changes.iter().take(8).map(|c| c.path.as_str()).collect();
        return Err(vec![finding(
            1,
            format!(
                "the pull request changes {} paths ({}): a release changes exactly one, its new \
                 role file",
                changes.len(),
                paths.join(", ")
            ),
        )]);
    };
    let mut findings = Vec::new();
    if change.kind != ChangeKind::Added {
        findings.push(finding(
            1,
            format!(
                "{} is {:?}, not a new file: role files are never edited, removed or renamed",
                change.path, change.kind
            ),
        ));
    }
    if change.new_mode != "100644" {
        findings.push(finding(
            1,
            format!(
                "{} has mode {}, not a regular file (100644)",
                change.path, change.new_mode
            ),
        ));
    }
    let prefix = format!("{}/metadata/", layout.tuf);
    let parsed = change
        .path
        .strip_prefix(&prefix)
        .and_then(|name| name.strip_suffix(".json"))
        .and_then(|stem| stem.split_once('.'))
        .and_then(|(version, role)| {
            let valid = !version.is_empty()
                && version.bytes().all(|b| b.is_ascii_digit())
                && !version.starts_with('0');
            let version: u64 = version.parse().ok().filter(|_| valid)?;
            let role = RoleName::parse(role).ok()?;
            Some((version, role.publisher()))
        });
    match parsed {
        Some((version, publisher)) if findings.is_empty() => Ok(RoleFile {
            path: change.path.clone(),
            version,
            publisher,
        }),
        Some(_) => Err(findings),
        None => {
            findings.push(finding(
                1,
                format!(
                    "{} is not {prefix}<version>.pub-<publisher>.json",
                    change.path
                ),
            ));
            Err(findings)
        }
    }
}

/// Check 1, the rest: the file is at most [`MAX_ROLE_FILE`] bytes and its publisher active in
/// the registry and delegated to by the newest top-level targets on the base.
pub fn role_admitted(base: &Base, role: &RoleFile, len: u64) -> Vec<Finding> {
    let mut findings = Vec::new();
    if len > MAX_ROLE_FILE {
        findings.push(finding(
            1,
            format!("{} is {len} bytes, more than {MAX_ROLE_FILE}", role.path),
        ));
    }
    match base.registry.get(&role.publisher) {
        None => findings.push(finding(
            1,
            format!("{} is no publisher of publishers/", role.publisher),
        )),
        Some(p) if !p.is_active() => findings.push(finding(
            1,
            format!("{} is {}, not active", role.publisher, p.state.as_str()),
        )),
        Some(_) => {}
    }
    let name = RoleName::of(&role.publisher);
    let delegated = base
        .delegations
        .as_ref()
        .and_then(|d| d.role(&name))
        .is_some_and(|r| r.is_ok());
    if !delegated {
        findings.push(finding(
            1,
            format!("the newest top-level targets on main do not delegate to {name}"),
        ));
    }
    findings
}

/// Check 2: `author` is one of the publisher's `github` accounts (GitHub logins are
/// case-insensitive).
pub fn author_listed(publisher: &Publisher, author: &str) -> Vec<Finding> {
    if publisher
        .github
        .iter()
        .any(|login| login.eq_ignore_ascii_case(author))
    {
        Vec::new()
    } else {
        vec![finding(
            2,
            format!(
                "{author} is not in github of publishers/{}/publisher.toml",
                publisher.name
            ),
        )]
    }
}

/// Check 3: the file's version is exactly one more than the newest of the role on the base
/// (1 for the first).
pub fn next_version(previous: Option<u64>, role: &RoleFile) -> Vec<Finding> {
    let wanted = previous.map_or(1, |v| v + 1);
    if role.version == wanted {
        Vec::new()
    } else {
        vec![finding(
            3,
            format!(
                "{} is version {}, but the next version of the role is {wanted}",
                role.path, role.version
            ),
        )]
    }
}

/// Check 4: the file reads as the client reads it (canonical JSON, no key twice, `_type`
/// `targets`, no `delegations`), its targets are under the role's paths, and a threshold of
/// the keys the base delegates the role to signed it. Its `version` against its name is
/// check 3.
///
/// # Errors
///
/// The findings of checks 3 and 4.
pub fn signed_role(
    bytes: &[u8],
    role: &RoleFile,
    delegations: Option<&Delegations>,
) -> Result<Targets, Vec<Finding>> {
    let envelope = Envelope::parse(bytes, MAX_ROLE_FILE, &role.path)
        .map_err(|e| vec![finding(4, format!("{}: {e}", role.path))])?;
    let targets = Targets::from_signed(&envelope.signed, Profile::Legacy)
        .map_err(|e| vec![finding(4, format!("{}: {e}", role.path))])?;
    let mut findings = Vec::new();
    if targets.version != role.version {
        findings.push(finding(
            3,
            format!(
                "{} says version {}, its name {}",
                role.path, targets.version, role.version
            ),
        ));
    }
    let name = RoleName::of(&role.publisher);
    match delegations.and_then(|d| Some((d, d.role(&name)?.ok()?))) {
        Some((delegations, delegated)) => {
            if let Err(e) =
                verify_threshold(&envelope, delegated.keys(), delegations.keys(), &role.path)
            {
                findings.push(finding(4, e.to_string()));
            }
            // The client refuses the whole role for one target outside its paths.
            for path in targets.targets.keys() {
                if !delegated.pattern().matches(path) {
                    findings.push(finding(
                        4,
                        format!("{path} is outside the role's paths {}", delegated.pattern()),
                    ));
                }
            }
        }
        None => findings.push(finding(
            4,
            format!("no delegation of {name} to verify with"),
        )),
    }
    if findings.is_empty() {
        Ok(targets)
    } else {
        Err(findings)
    }
}

/// Check 5: `expires` is between `now` + [`MIN_EXPIRY_DAYS`] and `now` +
/// [`MAX_EXPIRY_DAYS`].
pub fn expiry(expires: OffsetDateTime, now: OffsetDateTime) -> Vec<Finding> {
    let earliest = now + time::Duration::days(MIN_EXPIRY_DAYS);
    let latest = now + time::Duration::days(MAX_EXPIRY_DAYS);
    if (earliest..=latest).contains(&expires) {
        Vec::new()
    } else {
        vec![finding(
            5,
            format!(
                "the role expires {expires}: it must be {MIN_EXPIRY_DAYS} to {MAX_EXPIRY_DAYS} \
                 days after the check ({now})"
            ),
        )]
    }
}

/// `custom.oncl` of a publisher's target, with nothing the format does not have.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Read for its shape: the client's reader gives the values.
struct StrictEntry {
    schema: u64,
    id: String,
    version: String,
    url: String,
    source: Value,
    channel: String,
    min_core: String,
    modules: Vec<String>,
    #[serde(default)]
    replaces: Option<StrictReplaces>,
    name: StrictName,
    capabilities: Value,
    rollout: u8,
    #[serde(default)]
    revoked: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StrictReplaces {
    symname: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StrictName {
    ru: String,
    kk: String,
    en: String,
}

/// `custom.oncl.source`, with nothing the format does not have.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StrictSource {
    archive_sha256: String,
    archive_length: u64,
    fetch: String,
    path: String,
    license: String,
    builder: String,
    #[serde(default)]
    vcs: Option<StrictVcs>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StrictVcs {
    url: String,
    rev: String,
}

/// `custom.oncl` of `target`.
fn oncl(target: &Target) -> Option<&Value> {
    target.custom.as_ref()?.get("oncl")
}

/// What the role's targets are, as far as checks 6, 12 and 23 read them.
#[derive(Clone, Debug, Default)]
pub struct Entries {
    /// Each target the client would take, by path.
    pub releases: BTreeMap<TargetPath, PublisherRelease>,
    /// The findings of checks 6, 12 and 23.
    pub findings: Vec<Finding>,
}

/// Checks 6, 12 and 23 over every target of the role: the client's own reading
/// ([`PublisherRelease::parse`]), no member the format does not have, the publisher's prefix,
/// modules and bundles, no built-in module, capabilities by the rules of a manifest,
/// `min_core` at least [`super::MIN_CORE`], at most [`MAX_TARGETS`] targets and
/// [`MAX_NEW_PACKAGES`] of them new (`new`); for the new ones `source` by its table, its
/// builder on the base and its licence OSI (12); `url` the copy in the project's Releases
/// (23).
pub fn entries(
    publisher: &Publisher,
    targets: &Targets,
    new: &BTreeSet<TargetPath>,
    builders: &Builders,
    builtin_modules: &[String],
) -> Entries {
    let mut out = Entries::default();
    let name = &publisher.name;
    if targets.targets.len() > MAX_TARGETS {
        out.findings.push(finding(
            6,
            format!(
                "the role lists {} targets, more than {MAX_TARGETS}",
                targets.targets.len()
            ),
        ));
    }
    if new.len() > MAX_NEW_PACKAGES {
        out.findings.push(finding(
            6,
            format!(
                "the pull request adds {} packages, more than {MAX_NEW_PACKAGES}",
                new.len()
            ),
        ));
    }
    let min_core = super::min_core();
    for (path, target) in &targets.targets {
        let at = |check: u8, message: String| finding(check, format!("{path}: {message}"));
        let Some(entry) = oncl(target) else {
            out.findings
                .push(at(6, "the target has no custom.oncl".to_owned()));
            continue;
        };
        if let Err(e) = StrictEntry::deserialize(entry) {
            out.findings
                .push(at(6, format!("custom.oncl is not of the format: {e}")));
        }
        if target.length == 0 || target.length > oncl_plugin::MAX_PACKAGE {
            out.findings.push(at(
                6,
                format!(
                    "the package is {} bytes, not 1 to {}",
                    target.length,
                    oncl_plugin::MAX_PACKAGE
                ),
            ));
        }
        // The address of the copy (23), computed from the signed fields alone.
        let place = PublisherTarget::parse(path).filter(|p| p.publisher == *name);
        let wanted = place
            .as_ref()
            .map(|p| mirror_url(name, &p.id, &p.version, &target.sha256));
        if let Some(wanted) = &wanted
            && entry.get("url").and_then(Value::as_str) != Some(wanted.as_str())
        {
            out.findings.push(at(23, format!("url is not {wanted}")));
        }
        if new.contains(path) {
            out.findings
                .extend(source_rules(entry.get("source"), builders, path));
        }
        // The client's reading, with the address as it should be: what else would it refuse?
        let release = match (PublisherRelease::parse(name, path, target), &wanted) {
            (Err(EntryRejection::NotMirrored), Some(wanted)) => {
                let mut fixed = target.clone();
                if let Some(oncl) = fixed
                    .custom
                    .as_mut()
                    .and_then(|c| c.get_mut("oncl"))
                    .and_then(Value::as_object_mut)
                {
                    oncl.insert("url".to_owned(), Value::String(wanted.clone()));
                }
                PublisherRelease::parse(name, path, &fixed)
            }
            (other, _) => other,
        };
        let release = match release {
            Ok(release) => release,
            Err(EntryRejection::Source(e)) => {
                // Check 12 reports it for a new target; an old one went in with it.
                if !new.contains(path) {
                    out.findings
                        .push(at(6, format!("the client would leave it out: {e}")));
                }
                continue;
            }
            Err(e) => {
                out.findings
                    .push(at(6, format!("the client would leave it out: {e}")));
                continue;
            }
        };
        out.findings.extend(
            publisher_rules(publisher, &release, builtin_modules, &min_core)
                .into_iter()
                .map(|m| at(6, m)),
        );
        out.releases.insert(path.clone(), release);
    }
    out
}

/// The rules of «Как он собирается» that need the publisher: its prefix, modules and bundles,
/// no built-in module, capabilities by the rules of a manifest, `min_core`.
fn publisher_rules(
    publisher: &Publisher,
    release: &PublisherRelease,
    builtin_modules: &[String],
    min_core: &Version,
) -> Vec<String> {
    let r = release.release();
    let mut problems = Vec::new();
    if !(publisher.covers(&r.id) && r.id.len() > publisher.id_prefix.len()) {
        problems.push(format!(
            "the id {} is not under the prefix {}",
            r.id, publisher.id_prefix
        ));
    }
    if r.id.starts_with(PROJECT_PREFIX) {
        problems.push(format!("the id {} is under the project's prefix", r.id));
    }
    for module in &r.modules {
        if !publisher.modules.contains(module) {
            problems.push(format!("the module {module} is not one of the publisher's"));
        }
        if builtin_modules
            .iter()
            .any(|b| b.eq_ignore_ascii_case(module))
        {
            problems.push(format!("the module {module} is built into the core"));
        }
    }
    if let Some(replaces) = &r.replaces
        && !publisher.bundles.contains(&replaces.symname)
    {
        problems.push(format!(
            "replaces.symname {} is not one of the publisher's bundles",
            replaces.symname
        ));
    }
    match r.capabilities.as_ref().map(Capabilities::try_from) {
        Some(Ok(_)) => {}
        Some(Err(e)) => problems.push(format!(
            "capabilities do not read as a manifest's [capabilities]: {e}"
        )),
        None => problems.push("capabilities are missing".to_owned()),
    }
    if r.min_core < *min_core {
        problems.push(format!(
            "min_core {} is older than {min_core}, the first core with the publishers' catalog",
            r.min_core
        ));
    }
    problems
}

/// 64 lowercase hex digits of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Check 12 for one new target: `source` by the client's rules ([`ReleaseSource::parse`])
/// and with no member the format does not have, its builder in `publishers/builders.toml` on
/// the base, its licence OSI.
pub fn source_rules(
    source: Option<&Value>,
    builders: &Builders,
    path: &TargetPath,
) -> Vec<Finding> {
    let at = |message: String| finding(12, format!("{path}: {message}"));
    let parsed = match ReleaseSource::parse(source) {
        Ok(parsed) => parsed,
        Err(e) => return vec![at(e.to_string())],
    };
    let mut findings = Vec::new();
    if let Some(source) = source
        && let Err(e) = StrictSource::deserialize(source)
    {
        findings.push(at(format!("source is not of the format: {e}")));
    }
    // The path reaches command lines of the rebuild: letters, digits, `.`, `_` and `-` only.
    let plain = parsed.path.split('/').all(|segment| {
        segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    });
    if !plain || parsed.path.starts_with('-') {
        findings.push(at(format!(
            "source.path {:?} has a character other than A-Z a-z 0-9 . _ - in a segment",
            parsed.path
        )));
    }
    let builder = format!("sha256:{}", hex(&parsed.builder.0));
    if builders.get(&builder).is_none() {
        findings.push(at(format!(
            "source.builder {builder} is not in publishers/builders.toml on main"
        )));
    }
    if let Err(e) = licenses::check_osi(&parsed.license, Reading::Strict) {
        findings.push(at(format!("source.license: {e}")));
    }
    findings
}

/// The modules and bundles a role file's targets serve, leniently: what the client would
/// take of them does not matter here, only what they claim.
fn claims(bytes: &[u8]) -> (Vec<String>, Vec<String>) {
    let Ok(envelope) = Envelope::parse(bytes, MAX_ROLE_FILE, "role") else {
        return (Vec::new(), Vec::new());
    };
    let Ok(targets) = Targets::from_signed(&envelope.signed, Profile::Delegating) else {
        return (Vec::new(), Vec::new());
    };
    let mut modules = Vec::new();
    let mut bundles = Vec::new();
    for target in targets.targets.values() {
        let Some(entry) = oncl(target) else {
            continue;
        };
        for module in entry["modules"].as_array().into_iter().flatten() {
            if let Some(m) = module.as_str() {
                modules.push(m.to_owned());
            }
        }
        if let Some(symname) = entry["replaces"]["symname"].as_str() {
            bundles.push(symname.to_owned());
        }
    }
    (modules, bundles)
}

/// Check 7: after the merge, each module and bundle of the role is served by no port of the
/// owner's indexes (unless the publisher supersedes that port) and by no target of another
/// publisher's newest role (but a revoked one's); modules and bundles compare without case.
/// No index has a plugin of the role's ids.
pub fn catalog(
    base: &Base,
    publisher: &Publisher,
    releases: &BTreeMap<TargetPath, PublisherRelease>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut others: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    for index in &base.indexes {
        for port in &index.plugins {
            if publisher.supersedes.contains_key(&port.id) {
                continue;
            }
            let bundles = port.replaces.iter().map(|r| r.symname.clone()).collect();
            others.push((
                format!("the port {} of the {} index", port.id, index.channel),
                port.modules.clone(),
                bundles,
            ));
        }
    }
    for (name, role) in &base.roles {
        // A revoked publisher keeps its prefix only: its modules and bundles are free.
        let revoked = base.registry.get(name).is_some_and(|p| !p.keeps_rules());
        if *name == publisher.name || revoked {
            continue;
        }
        let (modules, bundles) = claims(&role.bytes);
        others.push((format!("the role of {name}"), modules, bundles));
    }
    for (path, release) in releases {
        let r = release.release();
        for (who, modules, bundles) in &others {
            if let Some(m) = r
                .modules
                .iter()
                .find(|m| modules.iter().any(|o| o.eq_ignore_ascii_case(m)))
            {
                findings.push(finding(
                    7,
                    format!("{path}: the module {m} is served by {who}"),
                ));
            }
            if let Some(replaces) = &r.replaces
                && bundles
                    .iter()
                    .any(|b| b.eq_ignore_ascii_case(&replaces.symname))
            {
                findings.push(finding(
                    7,
                    format!(
                        "{path}: the bundle {} is stood for by {who}",
                        replaces.symname
                    ),
                ));
            }
        }
        for index in &base.indexes {
            if index.plugins.iter().any(|p| p.id == r.id) {
                findings.push(finding(
                    7,
                    format!(
                        "{path}: the {} index has the plugin {}",
                        index.channel, r.id
                    ),
                ));
            }
        }
    }
    findings
}

/// The members of `custom.oncl` a later role version may change (check 8).
const MUTABLE: [&str; 4] = ["rollout", "name", "revoked", "channel"];

fn channel_of(target: &Target) -> Option<Channel> {
    serde_json::from_value(oncl(target)?.get("channel")?.clone()).ok()
}

fn revoked(target: &Target) -> bool {
    oncl(target)
        .and_then(|o| o.get("revoked"))
        .and_then(Value::as_bool)
        == Some(true)
}

/// Checks 8 and 24 against the role's newest file on the base, `previous` (none for the first
/// release): a target that was there keeps its package, address, source and the rest but for
/// [`MUTABLE`], and its channel only widens (`beta` to `stable`); `source` unchanged is check
/// 24. A target leaves only if it is not revoked by the publisher or the owner and a newer,
/// unrevoked version of the same plugin is in the role on the same or a wider channel.
pub fn history(previous: Option<&Targets>, new: &Targets, publisher: &Publisher) -> Vec<Finding> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for (path, old) in &previous.targets {
        let Some(now) = new.targets.get(path) else {
            findings.extend(removal(path, old, new, publisher));
            continue;
        };
        if old.length != now.length || old.sha256 != now.sha256 {
            findings.push(finding(
                8,
                format!("{path}: the package's length or sha256 changed"),
            ));
        }
        let (Some(was), Some(is)) = (oncl(old), oncl(now)) else {
            if oncl(old) != oncl(now) {
                findings.push(finding(8, format!("{path}: custom.oncl changed")));
            }
            continue;
        };
        if was.get("source") != is.get("source") {
            findings.push(finding(24, format!("{path}: source changed")));
        }
        let keys: BTreeSet<&String> = was
            .as_object()
            .into_iter()
            .flat_map(|o| o.keys())
            .chain(is.as_object().into_iter().flat_map(|o| o.keys()))
            .collect();
        for key in keys {
            if key == "source" || MUTABLE.contains(&key.as_str()) {
                continue;
            }
            if was.get(key) != is.get(key) {
                findings.push(finding(8, format!("{path}: {key} changed")));
            }
        }
        if channel_of(old) == Some(Channel::Stable) && channel_of(now) == Some(Channel::Beta) {
            findings.push(finding(
                8,
                format!("{path}: the channel went from stable back to beta"),
            ));
        }
    }
    findings
}

/// Whether the target `path` of the previous role may leave (check 8).
fn removal(path: &TargetPath, old: &Target, new: &Targets, publisher: &Publisher) -> Vec<Finding> {
    let refuse = |why: &str| vec![finding(8, format!("{path} was removed, but {why}"))];
    let Some(place) = PublisherTarget::parse(path) else {
        return Vec::new();
    };
    if revoked(old) {
        return refuse("it is revoked: revoked versions stay in the role");
    }
    if publisher
        .revoked_versions
        .iter()
        .any(|r| r.id == place.id.as_str() && r.version == place.version)
    {
        return refuse("the owner revoked it: revoked versions stay in the role");
    }
    let old_channel = channel_of(old).unwrap_or(Channel::Beta);
    let replaced = new.targets.iter().any(|(p, t)| {
        let Some(other) = PublisherTarget::parse(p) else {
            return false;
        };
        let wide_enough = match (old_channel, channel_of(t)) {
            (Channel::Beta, Some(_)) | (Channel::Stable, Some(Channel::Stable)) => true,
            (_, None) | (Channel::Stable, Some(Channel::Beta)) => false,
        };
        other.id == place.id && other.version > place.version && !revoked(t) && wide_enough
    });
    if replaced {
        Vec::new()
    } else {
        refuse(
            "no newer unrevoked version of the plugin on the same or a wider channel is in the \
             role",
        )
    }
}

/// Check 9 (Р19): the last commit of the base that touched the publisher's role files, at
/// `last` (none: the first release), is at least [`RELEASE_INTERVAL`] before `now`.
pub fn frequency(last: Option<OffsetDateTime>, now: OffsetDateTime) -> Vec<Finding> {
    match last {
        Some(last) if now - last < RELEASE_INTERVAL => vec![finding(
            9,
            format!(
                "the publisher's last release on main is of {last}: one release an hour at most"
            ),
        )],
        _ => Vec::new(),
    }
}

/// Check 13 on a downloaded archive: its length and sha256 are the signed ones.
pub fn download(bytes: &[u8], source: &ReleaseSource, path: &TargetPath) -> Vec<Finding> {
    let mut findings = Vec::new();
    if bytes.len() as u64 != source.archive_length {
        findings.push(finding(
            13,
            format!(
                "{path}: the archive is {} bytes, the role says {}",
                bytes.len(),
                source.archive_length
            ),
        ));
    }
    let sha256 = oncl_pack::sha256_hex(bytes);
    let signed = hex(&source.archive_sha256.0);
    if sha256 != signed {
        findings.push(finding(
            13,
            format!("{path}: the archive's sha256 is {sha256}, the role says {signed}"),
        ));
    }
    findings
}

/// Check 14: the archive is canonical (read strictly and packed again, the same bytes); its
/// files.
///
/// # Errors
///
/// The finding of check 14.
pub fn canonical(bytes: &[u8], path: &TargetPath) -> Result<Tree, Finding> {
    Tree::from_archive(bytes).map_err(|e| finding(14, format!("{path}: {e}")))
}

/// The directories from `src/` down to the crate at `crate_path`: `""`, then each one below.
fn ancestors(crate_path: &str) -> Vec<String> {
    let mut dirs = vec![String::new()];
    let mut at = String::new();
    for part in crate_path.split('/').filter(|p| !p.is_empty()) {
        if !at.is_empty() {
            at.push('/');
        }
        at.push_str(part);
        dirs.push(at.clone());
    }
    dirs
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

fn toml_of(tree: &Tree, path: &str) -> Option<toml::Value> {
    let file = tree.get(path)?;
    toml::from_str(std::str::from_utf8(&file.data).ok()?).ok()
}

/// The directory of the workspace of the crate at `crate_path`: the nearest one from the crate
/// up with a `Cargo.lock`.
fn workspace_dir(tree: &Tree, crate_path: &str) -> Option<String> {
    ancestors(crate_path)
        .into_iter()
        .rev()
        .find(|dir| tree.get(&join(dir, "Cargo.lock")).is_some())
}

/// The crate's `license`: its own, or its workspace's with `license.workspace = true`.
pub fn crate_license(tree: &Tree, crate_path: &str) -> Option<String> {
    let manifest = toml_of(tree, &join(crate_path, "Cargo.toml"))?;
    match manifest.get("package")?.get("license")? {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Table(t) if t.get("workspace") == Some(&toml::Value::Boolean(true)) => {
            let root = toml_of(tree, &join(&workspace_dir(tree, crate_path)?, "Cargo.toml"))?;
            root.get("workspace")?
                .get("package")?
                .get("license")?
                .as_str()
                .map(str::to_owned)
        }
        _ => None,
    }
}

/// The sha256 of the `Cargo.lock` of the crate's workspace.
pub fn lock_sha256(tree: &Tree, crate_path: &str) -> Option<String> {
    let dir = workspace_dir(tree, crate_path)?;
    let file = tree.get(&join(&dir, "Cargo.lock"))?;
    Some(oncl_pack::sha256_hex(&file.data))
}

/// Check 15: the crate's `Cargo.toml` and `plugin.toml`, the `Cargo.lock` of its workspace
/// and a licence file at the top of `src/` are there, and the crate's `license` (its own or
/// its workspace's) is `source.license`.
pub fn crate_files(tree: &Tree, source: &ReleaseSource, path: &TargetPath) -> Vec<Finding> {
    let at = |message: String| finding(15, format!("{path}: {message}"));
    let crate_path = source.path.as_str();
    let mut findings = Vec::new();
    for name in ["Cargo.toml", "plugin.toml"] {
        if tree.get(&join(crate_path, name)).is_none() {
            findings.push(at(format!(
                "src/{} is not in the archive",
                join(crate_path, name)
            )));
        }
    }
    if workspace_dir(tree, crate_path).is_none() {
        findings.push(at("no Cargo.lock from the crate up to src/".to_owned()));
    }
    let licence_file = tree.files().any(|(p, _)| {
        !p.contains('/') && {
            let upper = p.to_ascii_uppercase();
            ["LICENSE", "LICENCE", "COPYING"]
                .iter()
                .any(|stem| upper.starts_with(stem))
        }
    });
    if !licence_file {
        findings.push(at(
            "no licence file (LICENSE*, LICENCE*, COPYING*) in src/".to_owned()
        ));
    }
    let has_manifest = tree.get(&join(crate_path, "Cargo.toml")).is_some();
    match crate_license(tree, crate_path) {
        Some(license) if license == source.license => {}
        Some(license) => findings.push(at(format!(
            "the crate's license is {license:?}, source.license {:?}",
            source.license
        ))),
        None if has_manifest => {
            findings.push(at("the crate's Cargo.toml has no license".to_owned()));
        }
        None => {}
    }
    findings
}

/// Check 16: no `.cargo/config` or `.cargo/config.toml` in `src/` or in a directory on the way
/// to the crate.
pub fn cargo_config(tree: &Tree, crate_path: &str, path: &TargetPath) -> Vec<Finding> {
    ancestors(crate_path)
        .iter()
        .flat_map(|dir| [join(dir, ".cargo/config"), join(dir, ".cargo/config.toml")])
        .filter(|config| tree.get(config).is_some())
        .map(|config| {
            finding(
                16,
                format!("{path}: src/{config} could change the sources or the build"),
            )
        })
        .collect()
}

/// Why the crate `name` from `source` (a lock file's or `cargo metadata`'s) breaks check
/// 17, if it does. Allowed: crates.io; a crate of the SDK ([`crate::sdk_delivery::CHAIN`])
/// from exactly `git+`[`OWN_REPOSITORY`]`?tag=…` or `?rev=…` at a commit of
/// [`GitSources::sdk`] (only the locked commit counts: a tag can move); any crate from a
/// repository of [`GitSources::allowed`] with its commit.
pub fn source_finding(name: &str, source: &str, sources: &GitSources) -> Option<String> {
    if REGISTRIES.contains(&source) {
        return None;
    }
    let refused = || {
        format!(
            "{name} comes from {source}: crates.io, the released SDK from {OWN_REPOSITORY} and \
             the git repositories of deny.toml (with a commit) only"
        )
    };
    let Some((url, commit)) = source
        .strip_prefix("git+")
        .and_then(|rest| rest.rsplit_once('#'))
    else {
        return Some(refused());
    };
    let (url, query) = url.split_once('?').unwrap_or((url, ""));
    let bare = url.strip_suffix(".git").unwrap_or(url);
    if bare.eq_ignore_ascii_case(OWN_REPOSITORY) {
        return sdk_finding(name, source, url, query, commit, &sources.sdk);
    }
    let commit_ok = (commit.len() == 40 || commit.len() == 64)
        && commit
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let listed = sources
        .allowed
        .iter()
        .any(|a| bare.eq_ignore_ascii_case(a.strip_suffix(".git").unwrap_or(a)));
    (!(commit_ok && listed)).then(refused)
}

/// Check 17 for a crate from this repository: `name` is a crate of the SDK, `url` is exactly
/// [`OWN_REPOSITORY`], the reference a tag or a revision (a branch moves) and `commit` one of
/// `sdk`.
fn sdk_finding(
    name: &str,
    source: &str,
    url: &str,
    query: &str,
    commit: &str,
    sdk: &SdkRevisions,
) -> Option<String> {
    let why = if !crate::sdk_delivery::CHAIN.contains(&name) {
        format!(
            "{name} is not a crate of the SDK ({})",
            crate::sdk_delivery::CHAIN.join(", ")
        )
    } else if url != OWN_REPOSITORY {
        format!("the SDK's address is exactly {OWN_REPOSITORY}")
    } else if !query
        .split_once('=')
        .is_some_and(|(key, value)| matches!(key, "tag" | "rev") && !value.is_empty())
        || query.contains('&')
    {
        "the SDK is named by its release tag (`tag = \"v<version>\"`) or `rev`, not a branch"
            .to_owned()
    } else if sdk.by_commit(commit).is_none() {
        format!(
            "{commit} is not the commit of a released SDK tag (publishers/sdk-revisions.toml on \
             main)"
        )
    } else {
        return None;
    };
    Some(format!("{name} comes from {source}: {why}"))
}

/// `dir` and the relative `path` joined and normalized, `None` if it leaves `src/`.
fn resolve(dir: &str, path: &str) -> Option<String> {
    if path.starts_with('/') || path.contains('\\') || path.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

/// The `path` of every dependency table of a manifest (`[dependencies]`, `[dev-dependencies]`,
/// `[build-dependencies]`, their `[target.*]` forms, `[workspace.dependencies]`, `[patch.*]`,
/// `[replace]`) and `package.workspace`.
fn manifest_paths(manifest: &toml::Value) -> Vec<String> {
    fn deps(table: Option<&toml::Value>, out: &mut Vec<String>) {
        for (_, dep) in table.and_then(toml::Value::as_table).into_iter().flatten() {
            if let Some(path) = dep.get("path").and_then(toml::Value::as_str) {
                out.push(path.to_owned());
            }
        }
    }
    let mut out = Vec::new();
    for kind in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "dev_dependencies",
        "build_dependencies",
    ] {
        deps(manifest.get(kind), &mut out);
        for (_, target) in manifest
            .get("target")
            .and_then(toml::Value::as_table)
            .into_iter()
            .flatten()
        {
            deps(target.get(kind), &mut out);
        }
    }
    deps(
        manifest
            .get("workspace")
            .and_then(|w| w.get("dependencies")),
        &mut out,
    );
    deps(manifest.get("replace"), &mut out);
    for (_, patch) in manifest
        .get("patch")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
    {
        deps(Some(patch), &mut out);
    }
    if let Some(workspace) = manifest
        .get("package")
        .and_then(|p| p.get("workspace"))
        .and_then(toml::Value::as_str)
    {
        out.push(workspace.to_owned());
    }
    out
}

/// Check 17: every `Cargo.lock` of the archive (the one Cargo uses may be any of them)
/// names only the sources [`source_finding`] allows; every `Cargo.toml` reads, and every
/// `path` in it stays inside `src/`.
pub fn lock_sources(tree: &Tree, sources: &GitSources, path: &TargetPath) -> Vec<Finding> {
    let at = |message: String| finding(17, format!("{path}: {message}"));
    let mut findings = Vec::new();
    for (lock, _) in tree.files() {
        if !(lock == "Cargo.lock" || lock.ends_with("/Cargo.lock")) {
            continue;
        }
        let Some(lock_file) = toml_of(tree, lock) else {
            findings.push(at(format!("src/{lock} is not a lock file")));
            continue;
        };
        for package in lock_file
            .get("package")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or("?");
            if let Some(source) = package.get("source").and_then(toml::Value::as_str) {
                findings.extend(
                    source_finding(name, source, sources).map(|m| at(format!("src/{lock}: {m}"))),
                );
            }
        }
    }
    for (file, _) in tree.files() {
        if !(file == "Cargo.toml" || file.ends_with("/Cargo.toml")) {
            continue;
        }
        let dir = file.rsplit_once('/').map_or("", |(d, _)| d);
        let Some(manifest) = toml_of(tree, file) else {
            findings.push(at(format!("src/{file} does not read as TOML")));
            continue;
        };
        for dep in manifest_paths(&manifest) {
            if resolve(dir, &dep).is_none() {
                findings.push(at(format!(
                    "src/{file} names the path {dep:?}, which leaves src/"
                )));
            }
        }
    }
    findings
}

/// What `data` is if it starts like an executable, an object archive or a compressed one.
fn signature(data: &[u8]) -> Option<&'static str> {
    let pe = data.starts_with(b"MZ") && data.len() >= 0x40 && {
        let at = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        data.get(at..at.saturating_add(4)) == Some(b"PE\0\0")
    };
    if pe {
        return Some("PE");
    }
    let forms: [(&[u8], &'static str); 12] = [
        (b"\0asm", "WebAssembly"),
        (b"\x7fELF", "ELF"),
        (b"\xfe\xed\xfa\xce", "Mach-O"),
        (b"\xfe\xed\xfa\xcf", "Mach-O"),
        (b"\xce\xfa\xed\xfe", "Mach-O"),
        (b"\xcf\xfa\xed\xfe", "Mach-O"),
        (b"\xca\xfe\xba\xbe", "Mach-O universal"),
        (b"!<arch>\n", "ar"),
        (b"PK\x03\x04", "zip"),
        (b"PK\x05\x06", "zip"),
        (b"PK\x07\x08", "zip"),
        (b"\x1f\x8b", "gzip"),
    ];
    forms
        .iter()
        .find(|(magic, _)| data.starts_with(magic))
        .map(|(_, kind)| *kind)
}

/// Check 18: no WebAssembly, executable, object archive, zip, gzip or `.onclp` file; other
/// binary files (a NUL byte, or not UTF-8) above [`MAX_PLAIN_BINARY`] only if the publisher
/// lists them in `binary_files`.
pub fn binaries(tree: &Tree, binary_files: &[String], path: &TargetPath) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (file, data) in tree.files() {
        let full = format!("src/{file}");
        if let Some(kind) = signature(&data.data) {
            findings.push(finding(18, format!("{path}: {full} is a {kind} file")));
            continue;
        }
        if file.to_ascii_lowercase().ends_with(".onclp") {
            findings.push(finding(18, format!("{path}: {full} is a plugin package")));
            continue;
        }
        let binary = data.data.contains(&0) || std::str::from_utf8(&data.data).is_err();
        if binary && data.data.len() > MAX_PLAIN_BINARY && !binary_files.contains(&full) {
            findings.push(finding(
                18,
                format!(
                    "{path}: {full} is a binary file of {} bytes, not in binary_files",
                    data.data.len()
                ),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests;

/// What `tuf check` warns of (never an error: a rule change applies to new versions only):
/// the checks 6, 12 and 23 that the newest role file of each active publisher in `roles`
/// breaks under the rules of today, with `publishers` the registry directory.
pub fn role_rule_warnings(
    publishers: &std::path::Path,
    roles: &BTreeMap<RoleName, crate::tuf::check::RoleFile>,
) -> Vec<String> {
    let Ok(registry) = Registry::read(publishers) else {
        return Vec::new();
    };
    let builders = Builders::read(&publishers.join(crate::publishers::builders::FILE_NAME))
        .unwrap_or_default();
    let builtin = crate::index::builtin_modules().unwrap_or_default();
    let mut warnings = Vec::new();
    for publisher in registry.active() {
        let Some(role) = roles.get(&publisher.role()) else {
            continue;
        };
        let targets = Envelope::parse(&role.file, MAX_ROLE_FILE, "role")
            .ok()
            .and_then(|e| Targets::from_signed(&e.signed, Profile::Legacy).ok());
        let Some(targets) = targets else {
            warnings.push(format!(
                "{} {}: the role does not read as a publisher's",
                publisher.role(),
                role.version
            ));
            continue;
        };
        let mut findings =
            entries(publisher, &targets, &BTreeSet::new(), &builders, &builtin).findings;
        for (path, target) in &targets.targets {
            let source = oncl(target).and_then(|o| o.get("source"));
            findings.extend(source_rules(source, &builders, path));
        }
        for f in findings {
            warnings.push(format!(
                "{} {}: check {}: {} (today's rules; the release stands)",
                publisher.role(),
                role.version,
                f.check,
                f.message
            ));
        }
    }
    warnings
}
