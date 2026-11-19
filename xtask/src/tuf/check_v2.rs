//! `cargo xtask tuf check` of `tuf/v2` (`docs/design/publishers.md`, "xtask"): the
//! repository verified offline by the client's own code in the delegating profile, plus what
//! only the operator's tree can say.
//!
//! The repository goes through three stages ([`Stage`]): the committed tree (no snapshot, no
//! timestamp: the snapshot of `tuf/v2` is signed online when Pages is published), the copy
//! for publication after `tuf snapshot`, and the published copy after `tuf timestamp`. What
//! is verified:
//!
//! 1. the files are only those of the layout ([`super::repo::Layout::V2`]), and the snapshot
//!    and the timestamp are there or not as the stage says;
//! 2. the trust anchor is byte for byte `metadata/<its version>.root.json`;
//! 3. the chain of roots, by the client; the newest top-level targets against the final
//!    root, with its delegations; every target it lists there with its length and hash;
//! 4. every role entry of the delegations keeps the profile and no key of a role is a key of
//!    the root; the newest file of each delegated role is verified by the client
//!    ([`TufClient::verify_cached_role`], or [`TufClient::delegated`] once published):
//!    signed by a threshold of the delegation's keys, its version, no delegations, every
//!    target inside its paths. Every version of every role is there, from 1, and every role
//!    was delegated to by some committed targets;
//! 5. with a snapshot, the guard of the online snapshot: it lists the top-level targets and
//!    the newest file of every role that ever had one (a revoked publisher's too) with its
//!    length and hash, and no older snapshot in the directory lists a file it drops or a
//!    version it lowers (section 5.5.5 of the specification: the client would take it for a
//!    rollback);
//! 6. the targets are the indexes of `updates/v1` and `publishers.json`; `publishers.json`
//!    and the delegations are exactly what `tuf update` makes of `publishers/`;
//! 7. against `--base`: no committed file changed or went, no version went back;
//! 8. expiry: the root and the top-level targets as in `tuf/v1`; the online snapshot and
//!    timestamp only when expired; a publisher's role only as a warning.
//!
//! [`cross`] compares the two repositories: they share no key but the targets key, and list
//! the same indexes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::Context;
use oncl_update::tuf::ed25519::verify_role;
use oncl_update::tuf::model::TARGETS_META;
use oncl_update::tuf::{
    DelegationError, Delegations, Digest, Envelope, KeyId, Limits, MemoryStore, Profile, Role,
    RoleName, RoleState, Root, Snapshot, Targets, Timestamp, TrustState, TufClient, TufError,
    layout,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use super::check::{
    self, Expiry, base_files, compare_base, compare_indexes, expiry_finding, malformed, parse_file,
    problem,
};
use super::repo::{DirFetcher, Layout, Listing};
use super::{MAX_TARGET, Problem, show_time};
use crate::publishers::{self, Registry};

/// How far the publication of a `tuf/v2` directory has gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The committed tree: no snapshot and no timestamp.
    Tree,
    /// A copy for publication after `tuf snapshot`: a snapshot, no timestamp.
    Snapshotted,
    /// A copy for publication after `tuf timestamp`, or the published site: both.
    Published,
}

/// What is verified.
pub struct Options<'a> {
    /// The repository directory.
    pub dir: &'a Path,
    /// The directory of the indexes (`updates/v1`): the index targets must be exactly them.
    /// `None` does not compare.
    pub index: Option<&'a Path>,
    /// The registry of the publishers (`publishers/`): `publishers.json` and the delegations
    /// must be what `tuf update` makes of it. `None` does not compare.
    pub publishers: Option<&'a Path>,
    /// The trust anchor file; `None` takes `<dir>/metadata/1.root.json`.
    pub anchor: Option<&'a Path>,
    /// The time to judge expiry at.
    pub now: OffsetDateTime,
    /// What the directory must have.
    pub stage: Stage,
    /// What counts as expiring.
    pub expiry: Expiry,
    /// The git revision whose repository this one must extend.
    pub base: Option<&'a str>,
}

/// The newest file of a delegated role in the directory.
#[derive(Clone, Debug)]
pub struct RoleFile {
    /// Its version.
    pub version: u64,
    /// Its bytes.
    pub file: Vec<u8>,
    /// Whether the newest top-level targets delegate to the role.
    pub delegated: bool,
    /// When it expires, if it can be read.
    pub expires: Option<OffsetDateTime>,
}

/// The metadata the client trusts.
#[derive(Clone, Debug)]
pub struct Verified {
    /// The root in force.
    pub root: Root,
    /// Every root of the chain, from version 1.
    pub roots: Vec<Root>,
    /// The newest top-level targets.
    pub targets: Targets,
    /// Its file.
    pub targets_file: Vec<u8>,
    /// Its `delegations` member, as signed.
    pub delegations: Value,
    /// The newest snapshot, if there is one.
    pub snapshot: Option<Snapshot>,
    /// The timestamp, if there is one.
    pub timestamp: Option<Timestamp>,
    /// The newest file of every role that has one.
    pub roles: BTreeMap<RoleName, RoleFile>,
}

/// What a check found.
#[derive(Debug, Default)]
pub struct Report {
    /// What is wrong.
    pub problems: Vec<Problem>,
    /// What is worth knowing.
    pub warnings: Vec<Problem>,
    /// What the repository is, for the operator.
    pub notes: Vec<String>,
    /// The metadata the client trusts, if the verification got that far.
    pub verified: Option<Verified>,
}

/// The result of [`check`].
#[derive(Debug)]
pub enum Outcome {
    /// There is no directory, and the base had none: the state before the ceremony of
    /// `tuf/v2`.
    NoRepository,
    /// A repository was checked.
    Checked(Box<Report>),
}

/// Checks the `tuf/v2` repository of `options` (see the module's description).
///
/// # Errors
///
/// If a file or directory cannot be read, or git cannot answer for `--base`: the findings
/// about the repository itself are in the [`Report`].
pub fn check(options: &Options) -> anyhow::Result<Outcome> {
    let mut report = Report::default();
    let base = match options.base {
        Some(rev) => Some(base_files(options.dir, rev)?),
        None => None,
    };
    if !options.dir.is_dir() {
        if base.as_ref().is_some_and(|b| !b.is_empty()) {
            report.problems.push(problem(
                "repository-removed",
                format!(
                    "{} is gone, but the base has it: clients would lose their updates",
                    options.dir.display()
                ),
            ));
            return Ok(Outcome::Checked(Box::new(report)));
        }
        return Ok(Outcome::NoRepository);
    }
    let anchor = match options.anchor {
        Some(file) => fs::read(file)
            .with_context(|| format!("reading the trust anchor {}", file.display()))?,
        None => match fs::read(options.dir.join(layout::root_path(1))) {
            Ok(bytes) => bytes,
            Err(e) => {
                report.problems.push(problem(
                    "no-root",
                    format!("reading metadata/1.root.json: {e}"),
                ));
                return Ok(Outcome::Checked(Box::new(report)));
            }
        },
    };
    if options.anchor.is_some() {
        match Envelope::parse(&anchor, Limits::default().root, "the trust anchor")
            .and_then(|env| Root::from_signed(&env.signed))
        {
            Ok(root) => {
                let committed = fs::read(options.dir.join(layout::root_path(root.version)));
                if committed.ok().as_deref() != Some(anchor.as_slice()) {
                    report.problems.push(problem(
                        "anchor-mismatch",
                        format!(
                            "the trust anchor is not metadata/{}.root.json byte for byte",
                            root.version
                        ),
                    ));
                }
            }
            Err(e) => report.problems.push(problem(
                "anchor",
                format!("the trust anchor is not a root: {e}"),
            )),
        }
    }

    let listing = Listing::read_layout(options.dir, Layout::V2)?;
    let verified = verify(
        options.dir,
        &anchor,
        options.now,
        options.stage,
        &mut report.problems,
    )?;
    match verified {
        Err(p) => report.problems.push(p),
        Ok(verified) => {
            notes(&verified, options.now, &mut report.notes);
            let (findings, role_warnings) =
                expiry_findings(&verified, options.now, &options.expiry);
            if options.expiry.fail {
                report.problems.extend(findings);
            } else {
                report.warnings.extend(findings);
            }
            report.warnings.extend(role_warnings);
            if let Some(index) = options.index {
                compare_indexes(
                    index,
                    &verified.targets,
                    &[publishers::TARGET],
                    &mut report.problems,
                );
            }
            if let Some(dir) = options.publishers {
                compare_publishers(dir, options.index, &verified, &mut report.problems);
            }
            report.verified = Some(verified);
        }
    }
    if let Some(base) = &base {
        compare_base(
            options.dir,
            &listing,
            base,
            Layout::V2,
            &mut report.problems,
        );
    }
    Ok(Outcome::Checked(Box::new(report)))
}

fn notes(verified: &Verified, now: OffsetDateTime, notes: &mut Vec<String>) {
    let version = |v: Option<u64>| v.map_or_else(|| "absent".to_owned(), |v| v.to_string());
    notes.push(format!(
        "root {}, targets {}, snapshot {}, timestamp {}",
        verified.root.version,
        verified.targets.version,
        version(verified.snapshot.as_ref().map(|s| s.version)),
        version(verified.timestamp.as_ref().map(|t| t.version)),
    ));
    for (role, version, expires) in expiries(verified) {
        notes.push(format!(
            "{role} {version} expires {} (in {} days)",
            show_time(expires),
            (expires - now).whole_days()
        ));
    }
    for (name, role) in &verified.roles {
        let state = if role.delegated {
            "delegated"
        } else {
            "not delegated (revoked)"
        };
        notes.push(format!("{name} {}, {state}", role.version));
    }
}

/// The expiries of the top-level files, `(role, version, expires)`.
fn expiries(verified: &Verified) -> Vec<(Role, u64, OffsetDateTime)> {
    let mut all = vec![
        (Role::Root, verified.root.version, verified.root.expires),
        (
            Role::Targets,
            verified.targets.version,
            verified.targets.expires,
        ),
    ];
    if let Some(s) = &verified.snapshot {
        all.push((Role::Snapshot, s.version, s.expires));
    }
    if let Some(t) = &verified.timestamp {
        all.push((Role::Timestamp, t.version, t.expires));
    }
    all
}

/// The expired and expiring metadata of `verified` at `now`, and the expired and expiring
/// roles of the publishers (always warnings: a publisher's role never stops the
/// publication).
pub fn expiry_findings(
    verified: &Verified,
    now: OffsetDateTime,
    policy: &Expiry,
) -> (Vec<Problem>, Vec<Problem>) {
    let top = expiries(verified)
        .into_iter()
        .filter_map(|(role, version, expires)| {
            // The snapshot and the timestamp of `tuf/v2` are signed online, for a week.
            let min = match role {
                Role::Root => Some(policy.min_root_days),
                Role::Targets => Some(policy.min_days),
                Role::Snapshot | Role::Timestamp => None,
            };
            expiry_finding(
                ("expired", "expiring"),
                &role.to_string(),
                version,
                expires,
                now,
                min,
            )
        })
        .collect();
    let roles = verified
        .roles
        .iter()
        .filter(|(_, role)| role.delegated)
        .filter_map(|(name, role)| {
            expiry_finding(
                ("role-expired", "role-expiring"),
                name.as_str(),
                role.version,
                role.expires?,
                now,
                Some(policy.min_days),
            )
        })
        .collect();
    (top, roles)
}

/// The file `path`, or `None` if it is larger than `limit` bytes (no more than one byte
/// past the limit is read).
fn read_capped(path: &Path, limit: u64) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let mut body = Vec::new();
    fs::File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut body)?;
    Ok((body.len() as u64 <= limit).then_some(body))
}

/// The newest file of each role in `listing`, with its expiry as written (not verified).
fn role_files(
    dir: &Path,
    listing: &Listing,
    delegations: &Delegations,
) -> Result<BTreeMap<RoleName, RoleFile>, Problem> {
    let limit = Limits::default().delegated;
    let mut roles = BTreeMap::new();
    for (name, version) in listing.newest_roles() {
        let path = layout::delegated_path(version, &name);
        let file = read_capped(&dir.join(&path), limit)
            .map_err(|e| problem("unreadable", format!("reading {path}: {e}")))?
            .ok_or_else(|| {
                problem(
                    "too-large",
                    format!("{path} is larger than the {limit} bytes a client reads of a role"),
                )
            })?;
        let expires = Envelope::parse(&file, limit, &path)
            .ok()
            .and_then(|env| Targets::from_signed(&env.signed, Profile::Legacy).ok())
            .map(|t| t.expires);
        let delegated = delegations.role(&name).is_some();
        roles.insert(
            name,
            RoleFile {
                version,
                file,
                delegated,
                expires,
            },
        );
    }
    Ok(roles)
}

/// Verifies the `tuf/v2` repository in `dir` from `anchor` (the bytes of a root file), as
/// [`check::verify`] does for `tuf/v1` (see the module's description). The findings that do
/// not stop the verification are added to `problems`; one that does is its `Err`.
///
/// # Errors
///
/// If a directory cannot be read.
pub fn verify(
    dir: &Path,
    anchor: &[u8],
    now: OffsetDateTime,
    stage: Stage,
    problems: &mut Vec<Problem>,
) -> anyhow::Result<Result<Verified, Problem>> {
    let listing = Listing::read_layout(dir, Layout::V2)?;
    for stray in &listing.strays {
        problems.push(problem(
            "stray-file",
            format!("{stray} is not a file of the repository"),
        ));
    }
    match (stage, listing.timestamp, listing.snapshots.is_empty()) {
        (Stage::Tree, true, _) => problems.push(problem(
            "timestamp-committed",
            "metadata/timestamp.json is in the tree: it is made when Pages is published and \
             must never be committed",
        )),
        (Stage::Snapshotted, true, _) => problems.push(problem(
            "unexpected-timestamp",
            "metadata/timestamp.json is there before the snapshot was checked",
        )),
        (Stage::Published, false, _) => problems.push(problem(
            "no-timestamp",
            "metadata/timestamp.json is not there: it is made by `cargo xtask tuf timestamp \
             --repo v2` when Pages is published",
        )),
        _ => {}
    }
    match (stage, listing.snapshots.is_empty()) {
        (Stage::Tree, false) => problems.push(problem(
            "snapshot-committed",
            "a snapshot is in the tree: the snapshot of tuf/v2 is signed by CI when Pages is \
             published (`cargo xtask tuf snapshot`) and is never committed",
        )),
        (Stage::Snapshotted | Stage::Published, true) => {
            return Ok(Err(problem(
                "no-snapshot",
                "there is no metadata/<N>.snapshot.json: it is made by `cargo xtask tuf \
                 snapshot`",
            )));
        }
        _ => {}
    }
    Ok(verify_inner(dir, anchor, now, stage, &listing, problems))
}

fn verify_inner(
    dir: &Path,
    anchor: &[u8],
    now: OffsetDateTime,
    stage: Stage,
    listing: &Listing,
    problems: &mut Vec<Problem>,
) -> Result<Verified, Problem> {
    let limits = Limits::default();
    let (last_root, last_targets, last_snapshot) = listing.highest();
    if last_root == 0 {
        return Err(problem("no-root", "there is no metadata/<N>.root.json"));
    }
    if !listing.roots.iter().copied().eq(1..=last_root) {
        return Err(problem(
            "root-gap",
            format!(
                "the root versions are {:?}: every version from 1 to the last must be there",
                listing.roots
            ),
        ));
    }
    if last_targets == 0 {
        return Err(problem(
            "no-targets",
            "there is no metadata/<N>.targets.json",
        ));
    }
    for (role, versions) in &listing.delegated {
        let newest = versions.last().copied().unwrap_or(0);
        if !versions.iter().copied().eq(1..=newest) {
            problems.push(problem(
                "role-gap",
                format!(
                    "the versions of {role} are {versions:?}: every version from 1 to the last \
                     must be there"
                ),
            ));
        }
    }

    // The newest files read as they are, for their expiry.
    let root_path = layout::root_path(last_root);
    let root_file = parse_file(dir, &root_path, limits.root)?;
    let top_root = Root::from_signed(&root_file.signed).map_err(|e| malformed(&root_path, &e))?;
    let targets_path = layout::targets_path(last_targets);
    let targets_bytes = fs::read(dir.join(&targets_path))
        .map_err(|e| problem("unreadable", format!("reading {targets_path}: {e}")))?;
    let targets_file = Envelope::parse(&targets_bytes, limits.targets, &targets_path)
        .map_err(|e| malformed(&targets_path, &e))?;
    let top_targets = Targets::from_signed(&targets_file.signed, Profile::Delegating)
        .map_err(|e| malformed(&targets_path, &e))?;
    // Clients keep the member unread with the targets; `tuf/v2` must have one, readable.
    let top_delegations = top_targets
        .delegations()
        .map_err(|e| malformed(&targets_path, &e))?
        .ok_or_else(|| {
            problem(
                "delegations-missing",
                format!("{targets_path} has no delegations member"),
            )
        })?;
    let delegations = targets_file
        .signed
        .get("delegations")
        .cloned()
        .unwrap_or(Value::Null);
    let top_snapshot = if last_snapshot == 0 {
        None
    } else {
        let path = layout::snapshot_path(last_snapshot);
        let file = parse_file(dir, &path, limits.snapshot)?;
        Some(Snapshot::from_signed(&file.signed).map_err(|e| malformed(&path, &e))?)
    };
    let top_timestamp = if listing.timestamp {
        let file = parse_file(dir, layout::TIMESTAMP_PATH, limits.timestamp)?;
        Some(
            Timestamp::from_signed(&file.signed)
                .map_err(|e| malformed(layout::TIMESTAMP_PATH, &e))?,
        )
    } else {
        None
    };
    let roles = role_files(dir, listing, &top_delegations)?;
    let earliest = [
        Some(top_root.expires),
        Some(top_targets.expires),
        top_snapshot.as_ref().map(|s| s.expires),
        top_timestamp.as_ref().map(|t| t.expires),
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(top_root.expires);
    let client_now = now.min(earliest - Duration::seconds(1));
    // The roles are verified with a clock inside their own validity too: a publisher's
    // expired role is a warning, not a failure of the repository.
    let roles_now = roles
        .values()
        .filter(|r| r.delegated)
        .filter_map(|r| r.expires)
        .map(|e| e - Duration::seconds(1))
        .fold(client_now, OffsetDateTime::min);

    // The delegations: every entry keeps the profile, no key of a role is a key of the root.
    for entry in top_delegations.roles() {
        match entry {
            Err(refused) => problems.push(problem(
                "delegation-refused",
                format!(
                    "{targets_path}: the delegation to {} breaks the profile: {}",
                    refused.name, refused.error
                ),
            )),
            Ok(role) => {
                if let Some(id) = role
                    .keys()
                    .keyids
                    .iter()
                    .find(|id| top_root.keys.contains_key(id))
                {
                    problems.push(problem(
                        "key-reused",
                        format!("the key {id} of {} is a key of the root", role.name()),
                    ));
                }
            }
        }
    }

    let published = stage == Stage::Published;
    let fetcher = if published {
        DirFetcher::new(dir)
    } else {
        DirFetcher::new(dir).without_timestamp()
    };
    let mut client = TufClient::new(anchor, &fetcher, MemoryStore::default(), limits)
        .map_err(|e| problem("anchor", format!("the trust anchor is not usable: {e}")))?
        .with_profile(Profile::Delegating);
    let (root, roots_state) = match client.refresh(client_now) {
        Ok(trusted) if published => {
            if trusted.snapshot().version != last_snapshot {
                return Err(problem(
                    "stale-snapshot",
                    format!(
                        "the timestamp lists snapshot {}, but snapshot {last_snapshot} is the \
                         newest in the repository",
                        trusted.snapshot().version
                    ),
                ));
            }
            if trusted.targets().version != last_targets {
                return Err(problem(
                    "stale-targets",
                    format!(
                        "the snapshot lists targets {}, but targets {last_targets} is in the \
                         repository",
                        trusted.targets().version
                    ),
                ));
            }
            for path in trusted.targets().targets.keys() {
                client
                    .download_target(&trusted, path.as_str(), MAX_TARGET, client_now)
                    .map_err(|e| target_problem(path.as_str(), e))?;
            }
            let delegated = client.delegated(&trusted, roles_now).map_err(|e| {
                problem("client", format!("the client cannot follow the roles: {e}"))
            })?;
            for (name, result) in delegated.roles() {
                match result {
                    Ok(_) => {}
                    Err(TufError::Delegation {
                        error: DelegationError::NotInSnapshot,
                        ..
                    }) if !roles.contains_key(name) => {}
                    Err(e) => problems.push(role_problem(name, e)),
                }
            }
            (trusted.root().clone(), client.store().state.clone())
        }
        Ok(_) => {
            return Err(problem(
                "client",
                "the repository answered a timestamp that was hidden from it",
            ));
        }
        Err(TufError::NotFound(path)) if !published && path == layout::TIMESTAMP_PATH => {
            let state = client.store().state.clone();
            let root = match state.roots.last() {
                Some(file) => {
                    Root::from_signed(&file.signed).map_err(|e| malformed("the final root", &e))?
                }
                None => {
                    let env = Envelope::parse(anchor, limits.root, "the trust anchor")
                        .map_err(|e| malformed("the trust anchor", &e))?;
                    Root::from_signed(&env.signed).map_err(|e| malformed("the trust anchor", &e))?
                }
            };
            (root, state)
        }
        Err(e) => {
            return Err(problem(
                "client",
                format!("the client refuses the repository: {e}"),
            ));
        }
    };
    if root.version != last_root {
        return Err(problem(
            "client",
            format!(
                "the client stopped at root {}, root {last_root} is in the repository",
                root.version
            ),
        ));
    }
    let roots = chain(dir, last_root)?;

    if !published {
        // The newest targets against the final root, and the files they list.
        verify_role(&targets_file, &root, Role::Targets, &targets_path)
            .map_err(|e| malformed(&targets_path, &e))?;
        if top_targets.version != last_targets {
            return Err(problem(
                "version-mismatch",
                format!("{targets_path} is of version {}", top_targets.version),
            ));
        }
        for (path, target) in &top_targets.targets {
            let stored = layout::target_file_path(path, &target.sha256);
            match fs::read(dir.join(&stored)) {
                Ok(bytes)
                    if bytes.len() as u64 == target.length
                        && Digest::of(&bytes) == target.sha256 => {}
                Ok(_) => {
                    return Err(problem(
                        "hash-mismatch",
                        format!("{stored} is not the file the targets list for {path}"),
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(problem(
                        "missing-file",
                        format!("{stored} (the target {path}) is not in the repository"),
                    ));
                }
                Err(e) => return Err(problem("unreadable", format!("reading {stored}: {e}"))),
            }
        }
        // The newest file of every delegated role, by the client, offline.
        for (name, role) in roles.iter().filter(|(_, r)| r.delegated) {
            let mut state = TrustState {
                targets: Some(last_targets),
                targets_file: Some(targets_file.clone()),
                ..roots_state.clone()
            };
            state.delegated.insert(
                name.clone(),
                RoleState {
                    version: role.version,
                    sha256: Digest::of(&role.file),
                },
            );
            let store = MemoryStore {
                state,
                ..MemoryStore::default()
            };
            let offline = TufClient::new(anchor, &fetcher, store, limits)
                .map_err(|e| problem("anchor", format!("the trust anchor is not usable: {e}")))?
                .with_profile(Profile::Delegating);
            let role_now = role
                .expires
                .map_or(client_now, |e| client_now.min(e - Duration::seconds(1)));
            if let Err(e) = offline.verify_cached_role(name, &role.file, role_now) {
                problems.push(role_problem(name, &e));
            }
        }
    }

    // The roles were delegated to, once at least.
    let mut ever_delegated = BTreeSet::new();
    let mut listed = BTreeSet::new();
    for version in &listing.targets {
        let path = layout::targets_path(*version);
        let targets = if *version == last_targets {
            top_targets.clone()
        } else {
            match parse_file(dir, &path, limits.targets).and_then(|file| {
                Targets::from_signed(&file.signed, Profile::Delegating)
                    .map_err(|e| malformed(&path, &e))
            }) {
                Ok(t) => t,
                Err(p) => {
                    problems.push(p);
                    continue;
                }
            }
        };
        match targets.delegations() {
            Ok(Some(delegations)) => {
                for entry in delegations.roles() {
                    ever_delegated.insert(match entry {
                        Ok(role) => role.name().clone(),
                        Err(refused) => refused.name.clone(),
                    });
                }
            }
            Ok(None) => problems.push(problem(
                "delegations-missing",
                format!("{path} has no delegations member"),
            )),
            Err(e) => problems.push(malformed(&path, &e)),
        }
        for (target, entry) in &targets.targets {
            listed.insert(layout::target_file_path(target, &entry.sha256));
        }
    }
    for role in listing.delegated.keys() {
        if !ever_delegated.contains(role) {
            problems.push(problem(
                "role-not-delegated",
                format!("{role} has files, but no committed targets ever delegated to it"),
            ));
        }
    }
    for stored in listing.target_files.difference(&listed) {
        problems.push(problem(
            "stray-file",
            format!("{stored} is listed by no targets file"),
        ));
    }

    if let Some(snapshot) = &top_snapshot {
        if !published {
            verify_snapshot(dir, &root, snapshot, last_snapshot, last_targets)?;
        }
        problems.extend(snapshot_guard(
            dir,
            listing,
            snapshot,
            &targets_bytes,
            &roles,
        ));
    }

    Ok(Verified {
        root,
        roots,
        targets: top_targets,
        targets_file: targets_bytes,
        delegations,
        snapshot: top_snapshot,
        timestamp: top_timestamp,
        roles,
    })
}

/// Every root of the directory, from version 1 to `last` (the client verified them as a
/// chain).
fn chain(dir: &Path, last: u64) -> Result<Vec<Root>, Problem> {
    (1..=last)
        .map(|version| {
            let path = layout::root_path(version);
            let file = parse_file(dir, &path, Limits::default().root)?;
            Root::from_signed(&file.signed).map_err(|e| malformed(&path, &e))
        })
        .collect()
}

fn target_problem(path: &str, e: TufError) -> Problem {
    match e {
        TufError::NotFound(_) => problem("missing-file", format!("{path}: {e}")),
        TufError::Hash { .. } | TufError::Length { .. } => {
            problem("hash-mismatch", format!("{path}: {e}"))
        }
        e => problem("client", format!("the client cannot read {path}: {e}")),
    }
}

fn role_problem(name: &RoleName, e: &TufError) -> Problem {
    problem(
        "role",
        format!("the client does not trust the newest file of {name}: {e}"),
    )
}

/// The newest snapshot against `root` and the newest targets: signed by the snapshot keys,
/// its own version, listing the targets with their length and hash.
fn verify_snapshot(
    dir: &Path,
    root: &Root,
    snapshot: &Snapshot,
    last_snapshot: u64,
    last_targets: u64,
) -> Result<(), Problem> {
    let path = layout::snapshot_path(last_snapshot);
    let file = parse_file(dir, &path, Limits::default().snapshot)?;
    verify_role(&file, root, Role::Snapshot, &path).map_err(|e| malformed(&path, &e))?;
    if snapshot.version != last_snapshot {
        return Err(problem(
            "version-mismatch",
            format!("{path} is of version {}", snapshot.version),
        ));
    }
    if snapshot.targets().version != last_targets {
        return Err(problem(
            "stale-targets",
            format!(
                "snapshot {last_snapshot} lists targets {}, but targets {last_targets} is in \
                 the repository",
                snapshot.targets().version
            ),
        ));
    }
    Ok(())
}

/// The guard of the online snapshot (see the module's description, step 5).
pub fn snapshot_guard(
    dir: &Path,
    listing: &Listing,
    snapshot: &Snapshot,
    targets_file: &[u8],
    roles: &BTreeMap<RoleName, RoleFile>,
) -> Vec<Problem> {
    let mut problems = Vec::new();
    let what = format!("snapshot {}", snapshot.version);
    let same = |meta: &oncl_update::tuf::MetaFile, bytes: &[u8]| {
        meta.length == Some(bytes.len() as u64) && meta.sha256 == Some(Digest::of(bytes))
    };
    if !same(snapshot.targets(), targets_file) {
        problems.push(problem(
            "hash-mismatch",
            format!("{what} does not list the length and sha256 of the newest targets"),
        ));
    }
    for (name, role) in roles {
        let meta_name = name.meta_name();
        match snapshot.meta.get(&meta_name) {
            None => problems.push(problem(
                "snapshot-role-missing",
                format!(
                    "{what} does not list {meta_name}: clients that saw it would take the \
                     snapshot for a rollback"
                ),
            )),
            Some(meta) if meta.version != role.version => problems.push(problem(
                "snapshot-role-stale",
                format!(
                    "{what} lists {meta_name} version {}, the newest file is version {}",
                    meta.version, role.version
                ),
            )),
            Some(meta) if !same(meta, &role.file) => problems.push(problem(
                "hash-mismatch",
                format!(
                    "{what} does not list the length and sha256 of {}",
                    layout::delegated_path(role.version, name)
                ),
            )),
            Some(_) => {}
        }
    }
    for (meta_name, meta) in &snapshot.meta {
        if meta_name == TARGETS_META {
            continue;
        }
        let known = meta_name
            .strip_suffix(".json")
            .and_then(|role| RoleName::parse(role).ok())
            .is_some_and(|role| roles.contains_key(&role));
        if !known {
            problems.push(problem(
                "missing-file",
                format!("{what} lists {meta_name}, which is no role file of the repository"),
            ));
        }
        if meta.length.is_none() || meta.sha256.is_none() {
            problems.push(problem(
                "snapshot-meta-incomplete",
                format!("{what} lists {meta_name} without its length and sha256"),
            ));
        }
    }
    // An older snapshot kept beside the newest (the one published before): nothing it
    // listed is dropped or goes back.
    for version in listing.snapshots.range(..snapshot.version) {
        let path = layout::snapshot_path(*version);
        let older = match parse_file(dir, &path, Limits::default().snapshot)
            .and_then(|file| Snapshot::from_signed(&file.signed).map_err(|e| malformed(&path, &e)))
        {
            Ok(older) => older,
            Err(p) => {
                problems.push(p);
                continue;
            }
        };
        problems.extend(rollback(&older, snapshot));
    }
    problems
}

/// What `new` drops or lowers of what `old` listed.
pub fn rollback(old: &Snapshot, new: &Snapshot) -> Vec<Problem> {
    old.meta
        .iter()
        .filter_map(|(name, before)| match new.meta.get(name) {
            None => Some(problem(
                "snapshot-rollback",
                format!(
                    "snapshot {} drops {name}, which snapshot {} listed",
                    new.version, old.version
                ),
            )),
            Some(now) if now.version < before.version => Some(problem(
                "snapshot-rollback",
                format!(
                    "snapshot {} lists {name} version {}, snapshot {} listed version {}",
                    new.version, now.version, old.version, before.version
                ),
            )),
            Some(_) => None,
        })
        .collect()
}

/// `publishers.json` and the delegations of the newest targets against what `tuf update`
/// makes of the registry in `dir`.
fn compare_publishers(
    dir: &Path,
    index: Option<&Path>,
    verified: &Verified,
    problems: &mut Vec<Problem>,
) {
    let registry = match Registry::read(dir) {
        Ok(registry) => registry,
        Err(e) => {
            problems.push(problem("publishers-invalid", format!("{e:#}")));
            return;
        }
    };
    let roots: Vec<(&str, &Root)> = verified.roots.iter().map(|r| ("tuf/v2", r)).collect();
    if let Err(e) = registry.check_roots(&roots) {
        problems.push(problem("publishers-invalid", format!("{e:#}")));
    }
    if let Some(index) = index {
        match super::update::read_indexes(index).and_then(|files| {
            files
                .iter()
                .map(|(_, bytes)| oncl_update::Index::from_json(bytes).map_err(Into::into))
                .collect::<anyhow::Result<Vec<_>>>()
        }) {
            Ok(indexes) => {
                if let Err(e) = registry.check_indexes(&indexes) {
                    problems.push(problem("publishers-invalid", format!("{e:#}")));
                }
            }
            Err(e) => problems.push(problem("unreadable", format!("{e:#}"))),
        }
    }
    match registry.publishers_json() {
        Ok(bytes) => match verified.targets.targets.get(publishers::TARGET) {
            Some(t) if t.length == bytes.len() as u64 && t.sha256 == Digest::of(&bytes) => {}
            Some(_) => problems.push(problem(
                "publishers-mismatch",
                format!(
                    "the targets list another {} than {} makes: run `cargo xtask tuf update`",
                    publishers::TARGET,
                    dir.display()
                ),
            )),
            None => problems.push(problem(
                "publishers-not-listed",
                format!(
                    "the targets do not list {}: run `cargo xtask tuf update`",
                    publishers::TARGET
                ),
            )),
        },
        Err(e) => problems.push(problem("publishers-invalid", format!("{e:#}"))),
    }
    if verified.delegations != registry.delegations() {
        problems.push(problem(
            "delegations-mismatch",
            format!(
                "the delegations of targets {} are not what {} makes: run `cargo xtask tuf \
                 update`",
                verified.targets.version,
                dir.display()
            ),
        ));
    }
}

/// The roles each key of `roots` served, over every root of the chain.
fn roles_of_keys(roots: &[Root]) -> BTreeMap<KeyId, BTreeSet<Role>> {
    let mut roles: BTreeMap<KeyId, BTreeSet<Role>> = BTreeMap::new();
    for root in roots {
        for role in [Role::Root, Role::Timestamp, Role::Snapshot, Role::Targets] {
            for id in &root.role(role).keyids {
                roles.entry(*id).or_default().insert(role);
            }
        }
    }
    roles
}

/// The keys the chains of roots `v1` and `v2` share (every root of each, not only the ones
/// in force): the only key both may have is one that served as a targets key, and as
/// nothing else, in both. Any other key of both is a `shared-key` problem: a snapshot or
/// timestamp of one repository would be accepted by the clients of the other.
pub fn shared_keys(v1: &[Root], v2: &[Root]) -> Vec<Problem> {
    let v1_roles = roles_of_keys(v1);
    let v2_roles = roles_of_keys(v2);
    let targets_only = BTreeSet::from([Role::Targets]);
    let names = |roles: &BTreeSet<Role>| {
        roles
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    v1_roles
        .iter()
        .filter_map(|(id, in_v1)| {
            let in_v2 = v2_roles.get(id)?;
            (*in_v1 != targets_only || *in_v2 != targets_only).then(|| {
                problem(
                    "shared-key",
                    format!(
                        "the key {id} is a {} key of tuf/v1 and a {} key of tuf/v2: the two \
                         chains share only the targets key, as targets in both",
                        names(in_v1),
                        names(in_v2)
                    ),
                )
            })
        })
        .collect()
}

/// `tuf/v1` against `tuf/v2`: the chains of roots share no key but the targets key
/// ([`shared_keys`], over `v1_roots`, every root of `tuf/v1`, and `v2.roots`), no
/// publisher's key is a key of any root of either, and the index targets are the same files.
/// Returns the problems and the warnings.
pub fn cross(
    v1: &check::Verified,
    v1_roots: &[Root],
    v2: &Verified,
) -> (Vec<Problem>, Vec<Problem>) {
    let mut problems = shared_keys(v1_roots, &v2.roots);
    let mut warnings = Vec::new();
    let targets_ids = |root: &Root| -> BTreeSet<KeyId> {
        root.role(Role::Targets).keyids.iter().copied().collect()
    };
    if targets_ids(&v1.root) != targets_ids(&v2.root) {
        warnings.push(problem(
            "targets-key-differs",
            format!(
                "root {} of tuf/v1 and root {} of tuf/v2 have other targets keys: the two \
                 repositories share it (`cargo xtask tuf root --repo v2` follows tuf/v1)",
                v1.root.version, v2.root.version
            ),
        ));
    }
    if let Some(Value::Object(keys)) = v2.delegations.get("keys") {
        let root_keys = roles_of_keys(v1_roots);
        let v2_keys = roles_of_keys(&v2.roots);
        for id in keys.keys().filter_map(|id| KeyId::from_hex(id)) {
            for (repo, of) in [("tuf/v1", &root_keys), ("tuf/v2", &v2_keys)] {
                if of.contains_key(&id) {
                    problems.push(problem(
                        "shared-key",
                        format!("the publishers' key {id} is a key of a root of {repo}"),
                    ));
                }
            }
        }
    }
    let indexes = |targets: &Targets| -> BTreeMap<String, (u64, Digest)> {
        targets
            .targets
            .iter()
            .filter(|(path, _)| path.as_str().starts_with("indexes/"))
            .map(|(path, t)| (path.as_str().to_owned(), (t.length, t.sha256)))
            .collect()
    };
    if indexes(&v1.targets) != indexes(&v2.targets) {
        problems.push(problem(
            "index-diverged",
            format!(
                "targets {} of tuf/v1 and targets {} of tuf/v2 list other indexes: run `cargo \
                 xtask tuf update`",
                v1.targets.version, v2.targets.version
            ),
        ));
    }
    (problems, warnings)
}
