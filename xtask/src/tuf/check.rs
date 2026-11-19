//! `cargo xtask tuf check`: the whole repository, verified offline by the client's own code
//! over a directory, plus what only the operator's tree can say (the targets are the indexes
//! in `updates/v1`, nothing is stray, history is never rewritten).
//!
//! What it verifies, in this order:
//!
//! 1. the files in the directory are only those of the layout ([`super::repo`]);
//! 2. the trust anchor is byte for byte `metadata/<its version>.root.json`;
//! 3. the client ([`oncl_update::tuf::TufClient`]) starts at the anchor, follows every root
//!    and, **with** a timestamp, the timestamp, snapshot, targets and every target, exactly
//!    as an installed program would. **Without** one (the committed tree: the timestamp is
//!    made when Pages is published) the client still checks the chain of roots, and the
//!    newest snapshot and targets are verified here against the final root with the
//!    client's [`verify_role`];
//! 4. every file the newest targets list is there with its length and hash, and every file
//!    in `targets/` is listed by some committed targets;
//! 5. the targets are the indexes of `updates/v1`, byte for byte;
//! 6. against `--base`: no committed file was changed or removed, no version went back;
//! 7. expiry: what is expired or expires within `--min-days` (root: `--min-root-days`) is a
//!    warning, an error with `--fail-on-expiring`.
//!
//! The clock of step 3 is held inside the validity of the files, so that signatures and the
//! chain are verified even when something has expired; expiry is step 7's business.
//!
//! The report is lines `tuf check: error[<code>]: <message>` and `tuf check: warning[<code>]:
//! <message>`; the codes are listed in `docs/dev/release.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, bail};
use oncl_update::Channel;
use oncl_update::tuf::build;
use oncl_update::tuf::ed25519::verify_role;
use oncl_update::tuf::{
    Digest, Envelope, Limits, MemoryStore, Profile, Role, Root, Snapshot, Targets, Timestamp,
    TufClient, TufError, layout,
};
use time::{Duration, OffsetDateTime};

use super::repo::{DirFetcher, Kind, Layout, Listing};
use super::{MAX_TARGET, Problem, show_time};

/// Whether the repository has a timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampMode {
    /// It must be there and is verified: a repository about to be published, or published.
    Required,
    /// It must not be there: the committed tree.
    Absent,
}

/// When metadata counts as expiring.
#[derive(Clone, Copy, Debug)]
pub struct Expiry {
    /// Targets and snapshot with fewer days left than this are expiring.
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
    /// The directory of the indexes (`updates/v1`): the targets must be exactly them. `None`
    /// does not compare.
    pub index: Option<&'a Path>,
    /// The trust anchor file (`crates/oncl-update/keys/root.json`); `None` takes
    /// `<dir>/metadata/1.root.json`.
    pub anchor: Option<&'a Path>,
    /// The time to judge expiry at.
    pub now: OffsetDateTime,
    /// The timestamp.
    pub timestamp: TimestampMode,
    /// What counts as expiring.
    pub expiry: Expiry,
    /// The git revision whose repository this one must extend.
    pub base: Option<&'a str>,
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

/// The metadata the client trusts: what [`verify`] returns when nothing stops it.
#[derive(Clone, Debug)]
pub struct Verified {
    /// The root in force.
    pub root: Root,
    /// The newest targets.
    pub targets: Targets,
    /// The newest snapshot.
    pub snapshot: Snapshot,
    /// The timestamp, if there is one.
    pub timestamp: Option<Timestamp>,
}

impl Verified {
    /// The expiries to judge, `(role, version, expires)`.
    pub fn expiries(&self) -> Vec<(Role, u64, OffsetDateTime)> {
        let mut all = vec![
            (Role::Root, self.root.version, self.root.expires),
            (Role::Targets, self.targets.version, self.targets.expires),
            (Role::Snapshot, self.snapshot.version, self.snapshot.expires),
        ];
        if let Some(t) = &self.timestamp {
            all.push((Role::Timestamp, t.version, t.expires));
        }
        all
    }
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

/// The newest file of a kind, parsed (not verified).
pub(super) fn parse_file(dir: &Path, path: &str, limit: u64) -> Result<Envelope, Problem> {
    let bytes = fs::read(dir.join(path))
        .map_err(|e| problem("unreadable", format!("reading {path}: {e}")))?;
    Envelope::parse(&bytes, limit, path).map_err(|e| malformed(path, &e))
}

/// Verifies the repository in `dir` as the client does (see the module's description), from
/// the trust anchor `anchor` (the bytes of a root file). The findings that do not stop the
/// verification (stray files, a committed timestamp) are added to `problems`; one that does
/// is its `Err`. `now` is held inside the validity of the files for the client (see the
/// module's description).
///
/// # Errors
///
/// If a directory cannot be read.
pub fn verify(
    dir: &Path,
    anchor: &[u8],
    now: OffsetDateTime,
    mode: TimestampMode,
    problems: &mut Vec<Problem>,
) -> anyhow::Result<Result<Verified, Problem>> {
    let listing = Listing::read(dir)?;
    for stray in &listing.strays {
        problems.push(problem(
            "stray-file",
            format!("{stray} is not a file of the repository"),
        ));
    }
    if listing.timestamp && mode == TimestampMode::Absent {
        problems.push(problem(
            "timestamp-committed",
            "metadata/timestamp.json is in the tree: it is made when Pages is published and \
             must never be committed",
        ));
    }
    Ok(verify_inner(dir, anchor, now, mode, &listing, problems))
}

fn verify_inner(
    dir: &Path,
    anchor: &[u8],
    now: OffsetDateTime,
    mode: TimestampMode,
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
    if last_snapshot == 0 {
        return Err(problem(
            "no-snapshot",
            "there is no metadata/<N>.snapshot.json",
        ));
    }
    if last_targets == 0 {
        return Err(problem(
            "no-targets",
            "there is no metadata/<N>.targets.json",
        ));
    }

    // The newest files read as they are, for their expiry and for what the verification
    // below must arrive at.
    let root_path = layout::root_path(last_root);
    let root_file = parse_file(dir, &root_path, limits.root)?;
    let top_root = Root::from_signed(&root_file.signed).map_err(|e| malformed(&root_path, &e))?;
    let snapshot_path = layout::snapshot_path(last_snapshot);
    let snapshot_file = parse_file(dir, &snapshot_path, limits.snapshot)?;
    let top_snapshot =
        Snapshot::from_signed(&snapshot_file.signed).map_err(|e| malformed(&snapshot_path, &e))?;
    let targets_path = layout::targets_path(last_targets);
    let targets_file = parse_file(dir, &targets_path, limits.targets)?;
    let top_targets = Targets::from_signed(&targets_file.signed, Profile::Legacy)
        .map_err(|e| malformed(&targets_path, &e))?;
    let top_timestamp = if listing.timestamp {
        let file = parse_file(dir, layout::TIMESTAMP_PATH, limits.timestamp)?;
        Some(
            Timestamp::from_signed(&file.signed)
                .map_err(|e| malformed(layout::TIMESTAMP_PATH, &e))?,
        )
    } else {
        None
    };
    let earliest = [
        Some(top_root.expires),
        Some(top_snapshot.expires),
        Some(top_targets.expires),
        top_timestamp.as_ref().map(|t| t.expires),
    ]
    .into_iter()
    .flatten()
    .min()
    .expect("the root is there");
    let client_now = now.min(earliest - Duration::seconds(1));

    let fetcher = DirFetcher::new(dir);
    // What the clients released before delegations read: `tuf/v1` must stay readable by them.
    let mut client = TufClient::new(anchor, &fetcher, MemoryStore::default(), limits)
        .map_err(|e| problem("anchor", format!("the trust anchor is not usable: {e}")))?
        .with_profile(Profile::Legacy);
    let verified = match client.refresh(client_now) {
        Ok(trusted) => {
            if trusted.snapshot().version != last_snapshot {
                return Err(problem(
                    "stale-snapshot",
                    format!(
                        "the timestamp lists snapshot {}, but snapshot {last_snapshot} is in \
                         the repository",
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
                    .map_err(|e| match e {
                        TufError::NotFound(_) => problem("missing-file", format!("{path}: {e}")),
                        TufError::Hash { .. } | TufError::Length { .. } => {
                            problem("hash-mismatch", format!("{path}: {e}"))
                        }
                        e => problem("client", format!("the client cannot read {path}: {e}")),
                    })?;
            }
            Verified {
                root: trusted.root().clone(),
                targets: trusted.targets().clone(),
                snapshot: trusted.snapshot().clone(),
                timestamp: Some(trusted.timestamp().clone()),
            }
        }
        Err(TufError::NotFound(path)) if path == layout::TIMESTAMP_PATH => {
            if mode == TimestampMode::Required {
                return Err(problem(
                    "no-timestamp",
                    "metadata/timestamp.json is not there: it is made by `cargo xtask tuf \
                     timestamp` when Pages is published",
                ));
            }
            // The chain of roots held; the rest is verified here, against the final root.
            let state = &client.store().state;
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
            if root.version != last_root {
                return Err(problem(
                    "client",
                    format!(
                        "the client stopped at root {}, root {last_root} is in the repository",
                        root.version
                    ),
                ));
            }
            lower(dir, &root, last_snapshot, last_targets)?
        }
        Err(e) => {
            return Err(problem(
                "client",
                format!("the client refuses the repository: {e}"),
            ));
        }
    };

    // Every file of `targets/` is listed by some committed targets.
    let mut listed = BTreeSet::new();
    for version in &listing.targets {
        let targets = if *version == last_targets {
            top_targets.clone()
        } else {
            let path = layout::targets_path(*version);
            match parse_file(dir, &path, limits.targets).and_then(|file| {
                Targets::from_signed(&file.signed, Profile::Legacy)
                    .map_err(|e| malformed(&path, &e))
            }) {
                Ok(t) => t,
                Err(p) => {
                    problems.push(p);
                    continue;
                }
            }
        };
        for (target, entry) in &targets.targets {
            listed.insert(layout::target_file_path(target, &entry.sha256));
        }
    }
    for stored in listing.target_files.difference(&listed) {
        problems.push(problem(
            "stray-file",
            format!("{stored} is listed by no targets file"),
        ));
    }
    Ok(Verified {
        timestamp: top_timestamp,
        ..verified
    })
}

/// The newest snapshot and targets, verified against `root`, and the files the targets list.
fn lower(
    dir: &Path,
    root: &Root,
    last_snapshot: u64,
    last_targets: u64,
) -> Result<Verified, Problem> {
    let limits = Limits::default();
    let snapshot_path = layout::snapshot_path(last_snapshot);
    let file = parse_file(dir, &snapshot_path, limits.snapshot)?;
    verify_role(&file, root, Role::Snapshot, &snapshot_path)
        .map_err(|e| malformed(&snapshot_path, &e))?;
    let snapshot =
        Snapshot::from_signed(&file.signed).map_err(|e| malformed(&snapshot_path, &e))?;
    if snapshot.version != last_snapshot {
        return Err(problem(
            "version-mismatch",
            format!("{snapshot_path} is of version {}", snapshot.version),
        ));
    }
    let listed = snapshot.targets();
    if listed.version != last_targets {
        return Err(problem(
            "stale-targets",
            format!(
                "snapshot {last_snapshot} lists targets {}, but targets {last_targets} is in \
                 the repository",
                listed.version
            ),
        ));
    }
    let targets_path = layout::targets_path(last_targets);
    let bytes = fs::read(dir.join(&targets_path))
        .map_err(|e| problem("unreadable", format!("reading {targets_path}: {e}")))?;
    if listed.length.is_some_and(|l| l != bytes.len() as u64)
        || listed.sha256.is_some_and(|h| h != Digest::of(&bytes))
    {
        return Err(problem(
            "hash-mismatch",
            format!("{targets_path} is not the file snapshot {last_snapshot} lists"),
        ));
    }
    let file = Envelope::parse(&bytes, limits.targets, &targets_path)
        .map_err(|e| malformed(&targets_path, &e))?;
    verify_role(&file, root, Role::Targets, &targets_path)
        .map_err(|e| malformed(&targets_path, &e))?;
    let targets = Targets::from_signed(&file.signed, Profile::Legacy)
        .map_err(|e| malformed(&targets_path, &e))?;
    if targets.version != last_targets {
        return Err(problem(
            "version-mismatch",
            format!("{targets_path} is of version {}", targets.version),
        ));
    }
    for (path, target) in &targets.targets {
        let stored = layout::target_file_path(path, &target.sha256);
        let bytes = match fs::read(dir.join(&stored)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(problem(
                    "missing-file",
                    format!("{stored} (the target {path}) is not in the repository"),
                ));
            }
            Err(e) => return Err(problem("unreadable", format!("reading {stored}: {e}"))),
        };
        if bytes.len() as u64 != target.length || Digest::of(&bytes) != target.sha256 {
            return Err(problem(
                "hash-mismatch",
                format!("{stored} is not the file the targets list for {path}"),
            ));
        }
    }
    Ok(Verified {
        root: root.clone(),
        targets,
        snapshot,
        timestamp: None,
    })
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

/// The root in force in the repository `dir`, followed from its own root version 1 with a
/// clock at the start of time: the keys it names, whether or not it has expired.
///
/// # Errors
///
/// If `dir` has no root version 1, or its roots are not a chain.
pub fn committed_root(dir: &Path) -> anyhow::Result<Root> {
    let anchor = super::repo::read(dir, &layout::root_path(1))?;
    final_root(
        dir,
        &anchor,
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(1),
    )
}

/// Every root of the repository `dir`, from its own root version 1 to the root in force,
/// as the client follows the chain (with a clock at the start of time, as
/// [`committed_root`]).
///
/// # Errors
///
/// If `dir` has no root version 1, or its roots are not a chain.
pub fn committed_chain(dir: &Path) -> anyhow::Result<Vec<Root>> {
    let limits = Limits::default();
    let anchor = super::repo::read(dir, &layout::root_path(1))?;
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

/// The expired and expiring metadata of `verified` at `now`.
pub fn expiry_findings(verified: &Verified, now: OffsetDateTime, policy: &Expiry) -> Vec<Problem> {
    verified
        .expiries()
        .into_iter()
        .filter_map(|(role, version, expires)| {
            let min = match role {
                Role::Root => Some(policy.min_root_days),
                Role::Targets | Role::Snapshot => Some(policy.min_days),
                Role::Timestamp => None,
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
        .collect()
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

/// The files of the repository at the git revision `rev`, below `dir`'s place in it:
/// relative path to bytes. Empty if the revision has none.
pub(super) fn base_files(dir: &Path, rev: &str) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
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

/// The tree in `dir` against the repository of `layout` at `rev`: history is kept for good.
/// In `tuf/v2` a delegated role's version never goes back either, and a new version of one
/// is a version bump.
pub(super) fn compare_base(
    dir: &Path,
    listing: &Listing,
    base: &BTreeMap<String, Vec<u8>>,
    layout: Layout,
    problems: &mut Vec<Problem>,
) {
    for (path, bytes) in base {
        if classify_is_timestamp(path) {
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
    let base_listing = Listing::of_layout(base.keys().cloned(), layout);
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
    let base_names: BTreeSet<&String> = base.keys().filter(|p| !classify_is_timestamp(p)).collect();
    let now_names: BTreeSet<&String> = listing
        .all
        .iter()
        .filter(|p| !classify_is_timestamp(p))
        .collect();
    if base_names != now_names && (r, t, s) == (br, bt, bs) && roles == base_roles {
        problems.push(problem(
            "no-version-bump",
            "files were added but no version is higher than the base's",
        ));
    }
}

fn classify_is_timestamp(path: &str) -> bool {
    super::repo::classify(path) == Kind::Timestamp
}

/// Checks the repository of `options`.
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
        options.timestamp,
        &mut report.problems,
    )?;
    match verified {
        Err(p) => report.problems.push(p),
        Ok(verified) => {
            report.notes.push(format!(
                "root {}, targets {}, snapshot {}, timestamp {}",
                verified.root.version,
                verified.targets.version,
                verified.snapshot.version,
                verified
                    .timestamp
                    .as_ref()
                    .map_or_else(|| "absent".to_owned(), |t| t.version.to_string())
            ));
            for (role, version, expires) in verified.expiries() {
                report.notes.push(format!(
                    "{role} {version} expires {} (in {} days)",
                    show_time(expires),
                    (expires - options.now).whole_days()
                ));
            }
            let findings = expiry_findings(&verified, options.now, &options.expiry);
            if options.expiry.fail {
                report.problems.extend(findings);
            } else {
                report.warnings.extend(findings);
            }
            if let Some(index) = options.index {
                compare_indexes(index, &verified.targets, &[], &mut report.problems);
            }
            report.verified = Some(verified);
        }
    }
    if let Some(base) = &base {
        compare_base(
            options.dir,
            &listing,
            base,
            Layout::V1,
            &mut report.problems,
        );
    }
    Ok(Outcome::Checked(Box::new(report)))
}
