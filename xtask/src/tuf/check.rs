//! `cargo xtask tuf check`: the repository `tuf/v1`, verified offline by the client's own
//! code in the profile of the clients from 0.1.2 ([`Profile::Delegating`]), plus what only
//! the operator's tree can say (the targets are the indexes of `updates/v1` and what
//! `publishers/` makes, nothing is stray, history is never rewritten).
//!
//! The repository goes through three stages ([`Stage`]): the committed tree (no timestamp;
//! with the snapshot offline, the owner's snapshot over the newest targets; with the
//! snapshot online, no snapshot signed by the snapshot key in force), the copy for
//! publication with its newest snapshot and no timestamp (after `tuf snapshot` when the
//! snapshot is online), and the published copy after `tuf timestamp`. What is verified, in
//! this order:
//!
//! 1. the files are only those of the layout ([`super::repo`]), and the snapshot and the
//!    timestamp are there or not as the stage says;
//! 2. the trust anchor is byte for byte `metadata/<its version>.root.json`;
//! 3. the client ([`TufClient`]) starts at the anchor and follows every root and, **with**
//!    a timestamp, the timestamp, snapshot, targets, every target and every delegated role,
//!    exactly as an installed program would. **Without** one the client still checks the
//!    chain of roots, and the newest targets, the files they list, the newest file of every
//!    delegated role ([`TufClient::verify_cached_role`]) and, unless the stage has none, the
//!    newest snapshot are verified here against the final root with the client's code;
//! 4. every role entry of the delegations keeps the profile and no key of a role is a key of
//!    the root; every version of every role is there, from 1, every role was delegated to by
//!    some committed targets, and once a targets file has the `delegations` member, every
//!    later one has it;
//! 5. the snapshot lists the newest targets and the newest file of every role that ever had
//!    one (a retired or revoked publisher's too) with its length and hash, and no older
//!    snapshot in the directory lists a file it drops or a version it lowers (section 5.5.5
//!    of the specification: the client would take it for a rollback);
//! 6. the targets are the indexes of `updates/v1`, byte for byte, and `publishers.json` and
//!    the delegations are what `tuf update` makes of `publishers/`; no entry of
//!    `publishers/` was removed or renamed (Р28), against every signed `publishers.json` and
//!    `--base`;
//! 7. against `--base`: no committed file was changed or removed, no version went back;
//! 8. expiry: what is expired or expires within `--min-days` (root: `--min-root-days`) is a
//!    warning, an error with `--fail-on-expiring`; the online snapshot and the timestamp only
//!    when expired; a publisher's role only as a warning.
//!
//! A note says whether the clients released before delegations (0.1.0, 0.1.1:
//! [`Profile::Legacy`]) still read the repository.
//!
//! The clock of step 3 is held inside the validity of the files, so that signatures and the
//! chain are verified even when something has expired; expiry is step 8's business.
//!
//! The report is lines `tuf check: error[<code>]: <message>` and `tuf check: warning[<code>]:
//! <message>`; the codes are listed in `docs/dev/release.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, bail};
use oncl_update::Channel;
use oncl_update::catalog::{PublisherPolicy, Standing};
use oncl_update::tuf::build;
use oncl_update::tuf::ed25519::verify_role;
use oncl_update::tuf::model::TARGETS_META;
use oncl_update::tuf::{
    DelegationError, Delegations, Digest, Envelope, Limits, MemoryStore, MetaFile, Profile, Role,
    RoleName, RoleState, Root, Snapshot, Targets, Timestamp, TrustState, TufClient, TufError,
    layout,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use super::repo::{self, DirFetcher, Kind, Listing, SnapshotMode};
use super::{MAX_TARGET, Problem, show_time};
use crate::publishers::{self, Registry, State};

/// How far the publication of a directory has gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The committed tree: no timestamp.
    Tree,
    /// A copy for publication with its newest snapshot (after `tuf snapshot` when the
    /// snapshot is online), before `tuf timestamp`: no timestamp.
    Snapshotted,
    /// A copy for publication after `tuf timestamp`, or the published site.
    Published,
}

/// When metadata counts as expiring.
#[derive(Clone, Copy, Debug)]
pub struct Expiry {
    /// Targets, an offline snapshot and a publisher's role with fewer days left than this
    /// are expiring.
    pub min_days: i64,
    /// The same for the root.
    pub min_root_days: i64,
    /// Whether expired and expiring metadata is an error (the publishing and scheduled
    /// paths) and not a warning (pull requests).
    pub fail: bool,
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
    /// The trust anchor file (`crates/oncl-update/keys/root.json`); `None` takes
    /// `<dir>/metadata/1.root.json`.
    pub anchor: Option<&'a Path>,
    /// The time to judge expiry at.
    pub now: OffsetDateTime,
    /// What the directory must have.
    pub stage: Stage,
    /// Who signs the snapshot (`tuf/v1.toml`).
    pub mode: SnapshotMode,
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
    /// Its `delegations` member, as signed, if it has one.
    pub delegations: Option<Value>,
    /// Whether the clients released before delegations (0.1.0, 0.1.1) read the newest
    /// targets.
    pub legacy_reads: bool,
    /// The newest snapshot, if the stage verifies one.
    pub snapshot: Option<Snapshot>,
    /// The timestamp, if there is one.
    pub timestamp: Option<Timestamp>,
    /// The newest file of every role that has one.
    pub roles: BTreeMap<RoleName, RoleFile>,
}

impl Verified {
    /// The expiries of the top-level files, `(role, version, expires)`.
    pub fn expiries(&self) -> Vec<(Role, u64, OffsetDateTime)> {
        let mut all = vec![
            (Role::Root, self.root.version, self.root.expires),
            (Role::Targets, self.targets.version, self.targets.expires),
        ];
        if let Some(s) = &self.snapshot {
            all.push((Role::Snapshot, s.version, s.expires));
        }
        if let Some(t) = &self.timestamp {
            all.push((Role::Timestamp, t.version, t.expires));
        }
        all
    }
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
    /// There is no directory and no anchor: the state before the owner's ceremony.
    NoRepository,
    /// A repository was checked.
    Checked(Box<Report>),
}

pub(super) fn problem(code: &'static str, message: impl Into<String>) -> Problem {
    Problem::new(code, message)
}

pub(super) fn malformed(what: &str, e: &TufError) -> Problem {
    match e {
        TufError::Signature { .. } => problem("signature", format!("{what}: {e}")),
        _ => problem("malformed", format!("{what}: {e}")),
    }
}

/// The file `path` of `dir`, parsed (not verified).
pub(super) fn parse_file(dir: &Path, path: &str, limit: u64) -> Result<Envelope, Problem> {
    let bytes = fs::read(dir.join(path))
        .map_err(|e| problem("unreadable", format!("reading {path}: {e}")))?;
    Envelope::parse(&bytes, limit, path).map_err(|e| malformed(path, &e))
}

/// Checks the repository of `options` (see the module's description).
///
/// # Errors
///
/// If a file or directory cannot be read, or git cannot answer for `--base`: the findings
/// about the repository itself are in the [`Report`].
pub fn check(options: &Options) -> anyhow::Result<Outcome> {
    let mut report = Report::default();
    let have_dir = options.dir.is_dir();
    let anchor_file = options.anchor.filter(|a| a.is_file());
    let base = match options.base {
        Some(rev) => Some(base_files(options.dir, rev)?),
        None => None,
    };
    if !have_dir && anchor_file.is_none() && options.anchor.is_some() {
        let had = base.as_ref().is_some_and(|b| !b.is_empty());
        if !had {
            return Ok(Outcome::NoRepository);
        }
        report.problems.push(problem(
            "repository-removed",
            format!(
                "{} is gone, but the base has a repository: clients would lose their updates",
                options.dir.display()
            ),
        ));
        return Ok(Outcome::Checked(Box::new(report)));
    }
    if !have_dir {
        report.problems.push(problem(
            "repository-missing",
            format!("{} is not a directory", options.dir.display()),
        ));
        return Ok(Outcome::Checked(Box::new(report)));
    }
    let anchor_bytes = match (options.anchor, anchor_file) {
        (Some(_), Some(file)) => fs::read(file)
            .with_context(|| format!("reading the trust anchor {}", file.display()))?,
        (Some(path), None) => {
            report.problems.push(problem(
                "anchor-missing",
                format!(
                    "the trust anchor {} is not there: clients would not trust the repository",
                    path.display()
                ),
            ));
            return Ok(Outcome::Checked(Box::new(report)));
        }
        (None, _) => match fs::read(options.dir.join(layout::root_path(1))) {
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

    // The anchor is one of the repository's own roots.
    match Envelope::parse(&anchor_bytes, Limits::default().root, "the trust anchor")
        .and_then(|env| Root::from_signed(&env.signed))
    {
        Ok(root) => {
            let committed = fs::read(options.dir.join(layout::root_path(root.version)));
            if committed.ok().as_deref() != Some(anchor_bytes.as_slice()) {
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

    let listing = Listing::read(options.dir)?;
    let verified = verify(
        options.dir,
        &anchor_bytes,
        options.now,
        options.stage,
        options.mode,
        &mut report.problems,
    )?;
    match verified {
        Err(p) => report.problems.push(p),
        Ok(verified) => {
            notes(&verified, options.now, &mut report.notes);
            let (findings, role_warnings) =
                expiry_findings(&verified, options.now, &options.expiry, options.mode);
            if options.expiry.fail {
                report.problems.extend(findings);
            } else {
                report.warnings.extend(findings);
            }
            report.warnings.extend(role_warnings);
            report.warnings.extend(size_warning(&verified));
            if let Some(index) = options.index {
                compare_indexes(
                    index,
                    &verified.targets,
                    &[publishers::TARGET],
                    &mut report.problems,
                );
            }
            if let Some(dir) = options.publishers {
                compare_publishers(
                    dir,
                    options.dir,
                    options.index,
                    &listing,
                    &verified,
                    &mut report.problems,
                );
                // Today's rules over the newest roles: a warning, the releases stand.
                report.warnings.extend(
                    crate::vendor::checks::role_rule_warnings(dir, &verified.roles)
                        .into_iter()
                        .map(|m| problem("publisher-rules", m)),
                );
            }
            report.verified = Some(verified);
        }
    }
    if let Some(base) = &base {
        compare_base(options.dir, &listing, base, &mut report.problems);
    }
    if let (Some(rev), Some(dir)) = (options.base, options.publishers) {
        compare_publishers_base(dir, rev, &mut report.problems)?;
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
    for (role, version, expires) in verified.expiries() {
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
            "not delegated (retired or revoked)"
        };
        notes.push(format!("{name} {}, {state}", role.version));
    }
    notes.push(if verified.legacy_reads {
        "clients 0.1.0 and 0.1.1 read this repository (its targets have no delegations)".to_owned()
    } else {
        "clients 0.1.0 and 0.1.1 do not read this repository: its targets have delegations, \
         they stop updating (Р16)"
            .to_owned()
    });
}

/// The expired and expiring metadata of `verified` at `now`, and the expired and expiring
/// roles of the publishers (always warnings: a publisher's role never stops the
/// publication).
pub fn expiry_findings(
    verified: &Verified,
    now: OffsetDateTime,
    policy: &Expiry,
    mode: SnapshotMode,
) -> (Vec<Problem>, Vec<Problem>) {
    let top = verified
        .expiries()
        .into_iter()
        .filter_map(|(role, version, expires)| {
            // The online snapshot and the timestamp are signed for a week on every
            // publication: only an expired one is worth saying.
            let min = match (role, mode) {
                (Role::Root, _) => Some(policy.min_root_days),
                (Role::Targets, _) | (Role::Snapshot, SnapshotMode::Offline) => {
                    Some(policy.min_days)
                }
                (Role::Snapshot, SnapshotMode::Online) | (Role::Timestamp, _) => None,
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

/// The share of the client's limit on the top-level targets past which [`check`] warns: the
/// delegations of every publisher share the limit with the targets.
const TARGETS_WARN_SHARE: (u64, u64) = (3, 4);

/// A warning when the newest targets near the limit the client reads.
fn size_warning(verified: &Verified) -> Option<Problem> {
    let limit = Limits::default().targets;
    let len = verified.targets_file.len() as u64;
    (len * TARGETS_WARN_SHARE.1 > limit * TARGETS_WARN_SHARE.0).then(|| {
        problem(
            "targets-large",
            format!(
                "{} is {len} bytes of the {limit} a client reads: the delegations share the \
                 limit with the targets, and a larger file stops every update",
                layout::targets_path(verified.targets.version)
            ),
        )
    })
}

/// Whether the file `what` of `version` has expired at `now` (`codes.0`), or has fewer than
/// `min` days left (`codes.1`; never with `min` `None`).
pub(super) fn expiry_finding(
    codes: (&'static str, &'static str),
    what: &str,
    version: u64,
    expires: OffsetDateTime,
    now: OffsetDateTime,
    min: Option<i64>,
) -> Option<Problem> {
    let left = expires - now;
    let days = left.whole_days();
    let when = show_time(expires);
    if left <= Duration::ZERO {
        return Some(problem(
            codes.0,
            format!("{what} {version} expired at {when}"),
        ));
    }
    let min = min?;
    (left < Duration::days(min)).then(|| {
        problem(
            codes.1,
            format!("{what} {version} expires at {when}, in {days} days (less than {min})"),
        )
    })
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
    delegations: Option<&Delegations>,
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
        let delegated = delegations.is_some_and(|d| d.role(&name).is_some());
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

/// Verifies the repository in `dir` from `anchor` (the bytes of a root file) as the client
/// does (see the module's description). The findings that do not stop the verification
/// (stray files, a committed timestamp) are added to `problems`; one that does is its
/// `Err`. `now` is held inside the validity of the files for the client.
///
/// # Errors
///
/// If a directory cannot be read.
pub fn verify(
    dir: &Path,
    anchor: &[u8],
    now: OffsetDateTime,
    stage: Stage,
    mode: SnapshotMode,
    problems: &mut Vec<Problem>,
) -> anyhow::Result<Result<Verified, Problem>> {
    let listing = Listing::read(dir)?;
    for stray in &listing.strays {
        problems.push(problem(
            "stray-file",
            format!("{stray} is not a file of the repository"),
        ));
    }
    match (stage, listing.timestamp) {
        (Stage::Tree, true) => problems.push(problem(
            "timestamp-committed",
            "metadata/timestamp.json is in the tree: it is made when Pages is published and \
             must never be committed",
        )),
        (Stage::Snapshotted, true) => problems.push(problem(
            "unexpected-timestamp",
            "metadata/timestamp.json is there before the snapshot was checked",
        )),
        (Stage::Published, false) => {
            return Ok(Err(problem(
                "no-timestamp",
                "metadata/timestamp.json is not there: it is made by `cargo xtask tuf \
                 timestamp` when Pages is published",
            )));
        }
        _ => {}
    }
    Ok(verify_inner(
        dir, anchor, now, stage, mode, &listing, problems,
    ))
}

fn verify_inner(
    dir: &Path,
    anchor: &[u8],
    now: OffsetDateTime,
    stage: Stage,
    mode: SnapshotMode,
    listing: &Listing,
    problems: &mut Vec<Problem>,
) -> Result<Verified, Problem> {
    let limits = Limits::default();
    let (last_root, last_targets, last_snapshot) = listing.highest();
    // The committed tree of an online snapshot has the owner's old snapshots only: the one in
    // force is made by CI when Pages is published.
    let with_snapshot = !(stage == Stage::Tree && mode == SnapshotMode::Online);
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
    if with_snapshot && last_snapshot == 0 {
        return Err(problem(
            "no-snapshot",
            match mode {
                SnapshotMode::Offline => {
                    "there is no metadata/<N>.snapshot.json: `cargo xtask tuf update` signs it"
                }
                SnapshotMode::Online => {
                    "there is no metadata/<N>.snapshot.json: `cargo xtask tuf snapshot` signs it"
                }
            },
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

    // The newest files read as they are, for their expiry and for what the verification
    // below must arrive at.
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
    let legacy_reads = Targets::from_signed(&targets_file.signed, Profile::Legacy).is_ok();
    // The clients keep the member unread with the targets; the owner's never is unreadable.
    let top_delegations = top_targets
        .delegations()
        .map_err(|e| malformed(&targets_path, &e))?;
    let delegations = targets_file.signed.get("delegations").cloned();
    let top_snapshot = if with_snapshot {
        let path = layout::snapshot_path(last_snapshot);
        let file = parse_file(dir, &path, limits.snapshot)?;
        Some(Snapshot::from_signed(&file.signed).map_err(|e| malformed(&path, &e))?)
    } else {
        None
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
    let roles = role_files(dir, listing, top_delegations.as_ref())?;
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
    for entry in top_delegations.iter().flat_map(Delegations::roles) {
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
    if !with_snapshot {
        // The snapshot is signed by CI: none in the tree may carry the key in force.
        for version in &listing.snapshots {
            let path = layout::snapshot_path(*version);
            match parse_file(dir, &path, limits.snapshot) {
                Ok(file) => {
                    if verify_role(&file, &root, Role::Snapshot, &path).is_ok() {
                        problems.push(problem(
                            "snapshot-committed",
                            format!(
                                "{path} is signed by the snapshot key of root {}: the snapshot \
                                 is online, CI signs it when Pages is published (`cargo xtask \
                                 tuf snapshot`) and it is never committed",
                                root.version
                            ),
                        ));
                    }
                }
                Err(p) => problems.push(p),
            }
        }
    }

    // The roles were delegated to, once at least; the member, once there, stays.
    let mut ever_delegated = BTreeSet::new();
    let mut listed = BTreeSet::new();
    let mut had_member: Option<u64> = None;
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
        let member = match targets.delegations() {
            Ok(Some(delegations)) => {
                for entry in delegations.roles() {
                    ever_delegated.insert(match entry {
                        Ok(role) => role.name().clone(),
                        Err(refused) => refused.name.clone(),
                    });
                }
                true
            }
            Ok(None) => false,
            Err(e) => {
                problems.push(malformed(&path, &e));
                true
            }
        };
        match (had_member, member) {
            (None, true) => had_member = Some(*version),
            (Some(first), false) => problems.push(problem(
                "delegations-dropped",
                format!(
                    "{path} has no delegations member, but targets {first} had one: once \
                     there, it stays (entries of publishers/ are never removed)"
                ),
            )),
            _ => {}
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
        legacy_reads,
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
/// its own version, listing the newest targets.
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

/// The guard of the snapshot (see the module's description, step 5).
pub fn snapshot_guard(
    dir: &Path,
    listing: &Listing,
    snapshot: &Snapshot,
    targets_file: &[u8],
    roles: &BTreeMap<RoleName, RoleFile>,
) -> Vec<Problem> {
    let mut problems = Vec::new();
    let what = format!("snapshot {}", snapshot.version);
    let same = |meta: &MetaFile, bytes: &[u8]| {
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
    // An older snapshot in the directory (the owner's committed ones, the one published
    // before): nothing it listed is dropped or goes back.
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
/// makes of the registry in `dir`, the newest role of each active publisher in the
/// repository `repo` against the keys the registry keeps (Р24), and the registry against
/// every signed `publishers.json` of the tree (Р28).
fn compare_publishers(
    dir: &Path,
    repo: &Path,
    index: Option<&Path>,
    listing: &Listing,
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
    let roots: Vec<(&str, &Root)> = verified.roots.iter().map(|r| ("tuf/v1", r)).collect();
    if let Err(e) = registry.check_roots(&roots) {
        problems.push(problem("publishers-invalid", format!("{e:#}")));
    }
    if let Err(e) = registry.check_newest_roles(repo) {
        problems.push(problem("role-key-removed", format!("{e:#}")));
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
    // Р28: no entry ever signed has gone or changed its prefix.
    let mut gone = BTreeSet::new();
    for stored in &listing.target_files {
        if repo::classify(stored) != Kind::Publishers {
            continue;
        }
        let checked = fs::read(repo.join(stored))
            .map_err(anyhow::Error::from)
            .and_then(|bytes| registry.keeps(&bytes));
        if let Err(e) = checked {
            gone.insert(format!("{stored}: {e:#}"));
        }
    }
    problems.extend(
        gone.into_iter()
            .map(|message| problem("publisher-removed", message)),
    );
    for p in registry.publishers() {
        if let Some(date) = &p.revoke_all {
            problems.push(problem(
                "revoke-all-pending",
                format!(
                    "publishers/{}: revoke_all = \"{date}\" is not settled into \
                     revoked_versions: run `cargo xtask tuf update`",
                    p.name
                ),
            ));
        }
        let role = p.role();
        if p.state == State::Retired
            && let Some(file) = verified.roles.get(&role)
            && let Ok(entries) =
                publishers::role_entries(&file.file, &layout::delegated_path(file.version, &role))
        {
            let missing: Vec<String> = entries
                .into_iter()
                .filter(|(id, version, revoked)| {
                    *revoked
                        && p.may_revoke(id)
                        && !p
                            .revoked_versions
                            .iter()
                            .any(|r| r.id == *id && r.version == *version)
                })
                .map(|(id, version, _)| format!("{id} {version}"))
                .collect();
            if !missing.is_empty() {
                problems.push(problem(
                    "retired-revocations-missing",
                    format!(
                        "publishers/{}: retired, but the versions its role revoked are not in \
                         its revoked_versions ({}): `cargo xtask tuf update` moves them there",
                        p.name,
                        missing.join(", ")
                    ),
                ));
            }
        }
    }
    // The signed `publishers.json`, as the client reads it.
    if let Some((path, target)) = verified
        .targets
        .targets
        .iter()
        .find(|(path, _)| path.as_str() == publishers::TARGET)
    {
        let stored = layout::target_file_path(path, &target.sha256);
        match fs::read(repo.join(&stored)) {
            Ok(bytes) => match PublisherPolicy::from_json(&bytes) {
                Ok(policy) => {
                    for p in policy.publishers() {
                        if let Standing::Unknown { state, .. } = p.standing() {
                            problems.push(problem(
                                "publishers-invalid",
                                format!(
                                    "{stored}: {} has the state {state:?}: only active, \
                                     retired and revoked are signed",
                                    p.name()
                                ),
                            ));
                        }
                    }
                }
                Err(e) => problems.push(problem(
                    "publishers-invalid",
                    format!("{stored}: the client does not read it: {e}"),
                )),
            },
            Err(e) => problems.push(problem("unreadable", format!("reading {stored}: {e}"))),
        }
    }
    // What `tuf update` makes of the registry.
    let listed = verified.targets.targets.get(publishers::TARGET);
    if registry.is_empty() {
        if listed.is_some() {
            problems.push(problem(
                "publishers-mismatch",
                format!(
                    "the targets list {}, but {} has no publisher",
                    publishers::TARGET,
                    dir.display()
                ),
            ));
        }
        if verified.delegations.is_some() {
            problems.push(problem(
                "delegations-mismatch",
                format!(
                    "targets {} has delegations, but {} has no publisher",
                    verified.targets.version,
                    dir.display()
                ),
            ));
        }
        return;
    }
    match registry.publishers_json() {
        Ok(bytes) => match listed {
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
    if verified.delegations.as_ref() != Some(&registry.delegations()) {
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

/// The name and id prefix of a `publisher.toml`, read loosely (an old file may not follow
/// today's schema).
fn name_and_prefix(text: &[u8]) -> Option<(String, String)> {
    let value: toml::Value = toml::from_str(std::str::from_utf8(text).ok()?).ok()?;
    let field = |key: &str| {
        value
            .get(key)
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
    };
    Some((field("name")?, field("id_prefix")?))
}

/// Р28 against `--base`: every `publishers/<name>/publisher.toml` of the base is still there,
/// with its name and id prefix.
fn compare_publishers_base(
    dir: &Path,
    rev: &str,
    problems: &mut Vec<Problem>,
) -> anyhow::Result<()> {
    for (path, bytes) in base_files(dir, rev)? {
        let mut parts = path.split('/');
        let (Some(_), Some(publishers::FILE_NAME), None) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        match fs::read(dir.join(&path)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => problems.push(problem(
                "publisher-removed",
                format!(
                    "publishers/{path} is in the base and gone: an entry of publishers/ is never \
                     removed (Р28)"
                ),
            )),
            Err(e) => problems.push(problem(
                "unreadable",
                format!("reading publishers/{path}: {e}"),
            )),
            Ok(now) => {
                if let (Some(then), Some(now)) = (name_and_prefix(&bytes), name_and_prefix(&now))
                    && then != now
                {
                    problems.push(problem(
                        "publisher-removed",
                        format!(
                            "publishers/{path}: name and id_prefix were {} and {}, now {} and \
                             {}: they never change (Р28)",
                            then.0, then.1, now.0, now.1
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The root in force in `dir`: the client follows the chain of roots from `anchor` (the
/// bytes of a root file) and stops where the timestamp would be asked for.
///
/// # Errors
///
/// If the roots are not a chain from the anchor, or the last one has expired at `now`.
pub fn final_root(dir: &Path, anchor: &[u8], now: OffsetDateTime) -> anyhow::Result<Root> {
    let limits = Limits::default();
    let fetcher = DirFetcher::new(dir).without_timestamp();
    let mut client = TufClient::new(anchor, &fetcher, MemoryStore::default(), limits)
        .map_err(|e| anyhow::anyhow!("the trust anchor is not usable: {e}"))?;
    match client.refresh(now) {
        Err(TufError::NotFound(path)) if path == layout::TIMESTAMP_PATH => {}
        Err(e @ TufError::Expired { .. }) => bail!(
            "the roots of {} are a chain, but the last one is not valid: {e} (a root is \
             renewed with `cargo xtask tuf root`)",
            dir.display()
        ),
        Err(e) => bail!(
            "the roots of {} are not a chain from the trust anchor: {e}",
            dir.display()
        ),
        Ok(_) => bail!("the repository answered a timestamp that was hidden from it"),
    }
    let env = match client.store().state.roots.last() {
        Some(file) => file.clone(),
        None => Envelope::parse(anchor, limits.root, "the trust anchor")
            .map_err(|e| anyhow::anyhow!("the trust anchor: {e}"))?,
    };
    Root::from_signed(&env.signed).map_err(|e| anyhow::anyhow!("the final root: {e}"))
}

/// Every root of the repository `dir`, from its own root version 1 to the root in force,
/// as the client follows the chain, with a clock at the start of time: the keys each named,
/// whether or not it has expired.
///
/// # Errors
///
/// If `dir` has no root version 1, or its roots are not a chain.
pub fn committed_chain(dir: &Path) -> anyhow::Result<Vec<Root>> {
    let limits = Limits::default();
    let anchor = repo::read(dir, &layout::root_path(1))?;
    let fetcher = DirFetcher::new(dir).without_timestamp();
    let mut client = TufClient::new(&anchor, &fetcher, MemoryStore::default(), limits)
        .map_err(|e| anyhow::anyhow!("{}: root version 1 is not usable: {e}", dir.display()))?;
    match client.refresh(OffsetDateTime::UNIX_EPOCH + Duration::seconds(1)) {
        Err(TufError::NotFound(path)) if path == layout::TIMESTAMP_PATH => {}
        Err(e) => bail!("the roots of {} are not a chain: {e}", dir.display()),
        Ok(_) => bail!("the repository answered a timestamp that was hidden from it"),
    }
    let first = Envelope::parse(&anchor, limits.root, "root version 1")
        .map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))?;
    std::iter::once(&first)
        .chain(client.store().state.roots.iter())
        .map(|file| Root::from_signed(&file.signed).map_err(|e| anyhow::anyhow!("{e}")))
        .collect()
}

/// The keys and threshold of `role` in `root`, as a root to build names them.
///
/// # Errors
///
/// If the root lists a key id of the role without its key (a root the client reads never
/// does).
pub fn role_def(root: &Root, role: Role) -> anyhow::Result<build::RoleDef> {
    let keys = root.role(role);
    Ok(build::RoleDef {
        keys: keys
            .keyids
            .iter()
            .map(|id| {
                root.keys.get(id).copied().with_context(|| {
                    format!(
                        "root {} lists the {role} key {id} without the key",
                        root.version
                    )
                })
            })
            .collect::<anyhow::Result<_>>()?,
        threshold: keys.threshold,
    })
}

/// The index files in `index` against the targets: the same files, byte for byte. Targets
/// other than the indexes and `extra` are unexpected.
pub(super) fn compare_indexes(
    index: &Path,
    targets: &Targets,
    extra: &[&str],
    problems: &mut Vec<Problem>,
) {
    let mut expected = BTreeSet::new();
    for channel in Channel::ALL {
        let target = format!("indexes/{}.json", channel.as_str());
        let file = index.join(format!("{}.json", channel.as_str()));
        let listed = targets.targets.get(target.as_str());
        expected.insert(target.clone());
        match (fs::read(&file), listed) {
            (Ok(bytes), Some(t)) => {
                if bytes.len() as u64 != t.length || Digest::of(&bytes) != t.sha256 {
                    problems.push(problem(
                        "index-mismatch",
                        format!(
                            "{target} is not {}: run `cargo xtask tuf update`",
                            file.display()
                        ),
                    ));
                }
            }
            (Ok(_), None) => problems.push(problem(
                "index-not-listed",
                format!(
                    "{} is not a target ({target}): run `cargo xtask tuf update`",
                    file.display()
                ),
            )),
            (Err(e), Some(_)) if e.kind() == std::io::ErrorKind::NotFound => {
                problems.push(problem(
                    "index-missing",
                    format!(
                        "the targets list {target}, but {} does not exist",
                        file.display()
                    ),
                ));
            }
            (Err(e), _) if e.kind() == std::io::ErrorKind::NotFound => {}
            (Err(e), _) => problems.push(problem(
                "unreadable",
                format!("reading {}: {e}", file.display()),
            )),
        }
    }
    for target in targets.targets.keys() {
        if !expected.contains(target.as_str()) && !extra.contains(&target.as_str()) {
            problems.push(problem(
                "unexpected-target",
                format!("{target} is not an update index"),
            ));
        }
    }
}

/// The files at the git revision `rev` below `dir`'s place in it: relative path to bytes.
/// Empty if the revision has none.
///
/// # Errors
///
/// If `rev` is not in the git repository of `dir`, or git fails.
pub(crate) fn base_files(dir: &Path, rev: &str) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let (repo, below) = crate::index::existing_ancestor(dir)?;
    let commit = format!("{rev}^{{commit}}");
    if !crate::index::git(&repo, &["rev-parse", "--verify", "--quiet", &commit])?
        .status
        .success()
    {
        bail!(
            "the base revision {rev} is not in the repository of {}",
            dir.display()
        );
    }
    let spec = format!("./{below}");
    let listed = crate::index::git(
        &repo,
        &["ls-tree", "-r", "-z", "--name-only", rev, "--", &spec],
    )?;
    if !listed.status.success() {
        bail!(
            "git ls-tree {rev}: {}",
            String::from_utf8_lossy(&listed.stderr).trim()
        );
    }
    let mut files = BTreeMap::new();
    for name in listed.stdout.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let name = String::from_utf8_lossy(name).into_owned();
        let Some(relative) = name.strip_prefix(&below) else {
            continue;
        };
        let object = format!("{rev}:./{name}");
        let blob = crate::index::git(&repo, &["cat-file", "blob", &object])?;
        if !blob.status.success() {
            bail!(
                "git cat-file blob {object}: {}",
                String::from_utf8_lossy(&blob.stderr).trim()
            );
        }
        files.insert(relative.to_owned(), blob.stdout);
    }
    Ok(files)
}

/// The tree in `dir` against the repository at the base: history is kept for good, a
/// delegated role's version never goes back either, and a new version of one is a version
/// bump.
fn compare_base(
    dir: &Path,
    listing: &Listing,
    base: &BTreeMap<String, Vec<u8>>,
    problems: &mut Vec<Problem>,
) {
    for (path, bytes) in base {
        if is_timestamp(path) {
            continue;
        }
        match fs::read(dir.join(path)) {
            Ok(now) if now == *bytes => {}
            Ok(_) => problems.push(problem(
                "file-modified",
                format!("{path} differs from the base: published metadata and targets never change"),
            )),
            Err(_) => problems.push(problem(
                "file-removed",
                format!("{path} is in the base and gone: published metadata and targets are kept for good"),
            )),
        }
    }
    let base_listing = Listing::of(base.keys().cloned());
    let (br, bt, bs) = base_listing.highest();
    let (r, t, s) = listing.highest();
    for (what, now, then) in [("root", r, br), ("targets", t, bt), ("snapshot", s, bs)] {
        if now < then {
            problems.push(problem(
                "version-rollback",
                format!("the newest {what} is version {now}, the base has {then}"),
            ));
        }
    }
    let base_roles = base_listing.newest_roles();
    let roles = listing.newest_roles();
    for (role, then) in &base_roles {
        let now = roles.get(role).copied().unwrap_or(0);
        if now < *then {
            problems.push(problem(
                "version-rollback",
                format!("the newest {role} is version {now}, the base has {then}"),
            ));
        }
    }
    let base_names: BTreeSet<&String> = base.keys().filter(|p| !is_timestamp(p)).collect();
    let now_names: BTreeSet<&String> = listing.all.iter().filter(|p| !is_timestamp(p)).collect();
    if base_names != now_names && (r, t, s) == (br, bt, bs) && roles == base_roles {
        problems.push(problem(
            "no-version-bump",
            "files were added but no version is higher than the base's",
        ));
    }
}

fn is_timestamp(path: &str) -> bool {
    repo::classify(path) == Kind::Timestamp
}
