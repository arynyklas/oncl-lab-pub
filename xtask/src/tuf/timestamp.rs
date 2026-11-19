//! `cargo xtask tuf timestamp`: the one file CI signs on every publication of Pages, with
//! the online key (`docs/design/tuf.md`). It is made in the copy of the repository that
//! goes into the site artifact, never in the committed tree.
//!
//! Before signing, the copy is verified with the client's code as it stands before the
//! timestamp ([`super::check`], [`Stage::Snapshotted`]): the newest snapshot, the owner's
//! while the snapshot is offline or the one `tuf snapshot` signed once it is online, must be
//! signed by the keys of the root in force and agree with the targets, the target files and
//! the publishers' roles. CI can only vouch for a snapshot that holds. It refuses a
//! snapshot, targets or root that has expired or expires within a day: a timestamp over
//! them would be a promise that cannot be kept, and the owner has to refresh them first.
//! After signing, the result is verified again with the timestamp, as the client does,
//! the publishers' roles included.
//!
//! The timestamp's `version` is the Unix time of signing and it expires 7 days later.
//! The key is read, never printed.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::build;
use oncl_update::tuf::{Role, layout};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::check::{self, Expiry, Stage};
use super::repo::SnapshotMode;
use super::{
    ONLINE_SNAPSHOT_DAYS, SNAPSHOT_DAYS, TIMESTAMP_DAYS, expiry, keystore, remove_created, repo,
    show_time, whole_seconds,
};

/// Where an online key is.
#[derive(Clone, Debug)]
pub enum KeySource {
    /// The environment variable of this name (the GitHub secret `TUF_TIMESTAMP_KEY` or
    /// `TUF_SNAPSHOT_KEY`).
    Env(String),
    /// A key file.
    File(PathBuf),
}

/// What [`timestamp`] does.
pub struct Options<'a> {
    /// The repository directory (a copy for publication).
    pub out: &'a Path,
    /// The trust anchor the client embeds (`crates/oncl-update/keys/root.json`): the
    /// repository is verified from it, not from its own first root.
    pub anchor: &'a Path,
    /// The indexes of the tree (`updates/v1`): the targets must be exactly them.
    pub index: &'a Path,
    /// The registry of the publishers (`publishers/`).
    pub publishers: &'a Path,
    /// Who signs the snapshot (`tuf/v1.toml`): how long the snapshot is valid.
    pub mode: SnapshotMode,
    /// The key.
    pub key: &'a KeySource,
    /// The signing time.
    pub now: OffsetDateTime,
}

/// What [`timestamp`] made.
#[derive(Debug)]
pub struct Signed {
    /// The file.
    pub path: PathBuf,
    /// Its version (Unix seconds).
    pub version: u64,
    /// The snapshot it lists.
    pub snapshot: u64,
    /// When it expires.
    pub expires: OffsetDateTime,
}

/// The online key in `source`.
///
/// # Errors
///
/// If it is not there, or is not an online key's line.
pub fn load_key(source: &KeySource) -> anyhow::Result<oncl_update::tuf::SigningKey> {
    let text = match source {
        KeySource::Env(name) => Zeroizing::new(std::env::var(name).map_err(|_| {
            anyhow::anyhow!("the environment variable {name} is not set (or is not text)")
        })?),
        KeySource::File(path) => Zeroizing::new(
            fs::read_to_string(path)
                .with_context(|| format!("reading the key file {}", path.display()))?,
        ),
    };
    keystore::parse_seed(&text)
}

/// Signs the timestamp of the repository in `options.out`.
///
/// # Errors
///
/// If the repository does not verify, expires within a day, already has a timestamp, the
/// key is missing, malformed or not the timestamp key of the root in force, or the result
/// does not verify (then nothing stays written).
pub fn timestamp(options: &Options) -> anyhow::Result<Signed> {
    let target = options.out.join(layout::TIMESTAMP_PATH);
    if target.exists() {
        bail!(
            "{} exists already; refusing to overwrite it",
            target.display()
        );
    }
    // Nothing is signed over a repository the client would refuse, or that is not the
    // owner's: the chain from the embedded anchor, signatures, versions, hashes of every
    // file, the targets against the indexes, and at least a day of validity left.
    let report = check::check(&check::Options {
        dir: options.out,
        index: Some(options.index),
        publishers: Some(options.publishers),
        anchor: Some(options.anchor),
        now: options.now,
        stage: Stage::Snapshotted,
        mode: options.mode,
        expiry: Expiry {
            min_days: 1,
            min_root_days: 1,
            fail: true,
        },
        base: None,
    })?;
    let (verified, snapshot) = match report {
        check::Outcome::NoRepository => bail!(
            "there is no repository in {} and no trust anchor {}: no timestamp is signed",
            options.out.display(),
            options.anchor.display()
        ),
        check::Outcome::Checked(report) => match report.verified {
            Some(v) if report.problems.is_empty() => match v.snapshot.clone() {
                Some(snapshot) => (v, snapshot),
                None => bail!("the repository has no snapshot: no timestamp is signed"),
            },
            _ => bail!(
                "the repository does not verify, no timestamp is signed:\n{}\n(an expired or \
                 nearly expired snapshot or targets: the owner runs `cargo xtask tuf update \
                 --refresh` and merges it; an expired root: `cargo xtask tuf root`)",
                list(&report.problems)
            ),
        },
    };
    let anchor = fs::read(options.anchor)
        .with_context(|| format!("reading the trust anchor {}", options.anchor.display()))?;
    let now = whole_seconds(options.now);
    // A clock before the snapshot was signed is not a clock to date a timestamp by.
    let days = match options.mode {
        SnapshotMode::Offline => SNAPSHOT_DAYS,
        SnapshotMode::Online => ONLINE_SNAPSHOT_DAYS,
    };
    let signed_at = snapshot.expires - Duration::days(days);
    if now + Duration::days(1) < signed_at {
        bail!(
            "the clock ({}) is before snapshot {} was signed (about {}): not signing",
            show_time(now),
            snapshot.version,
            show_time(signed_at)
        );
    }
    let key = load_key(options.key)?;
    let allowed = &verified.root.role(Role::Timestamp).keyids;
    if !allowed.contains(&key.key_id()) {
        bail!(
            "the key {} is not a timestamp key of root {} (it lists {}): the key was rotated, \
             or the secret holds another key",
            key.key_id(),
            verified.root.version,
            allowed
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let version = u64::try_from(now.unix_timestamp()).context("the clock is before 1970")?;
    let snapshot_file = repo::read(options.out, &layout::snapshot_path(snapshot.version))?;
    let expires = expiry(now, TIMESTAMP_DAYS);
    let signed = build::timestamp(version, expires, snapshot.version, &snapshot_file)
        .map_err(|e| anyhow::anyhow!("making the timestamp: {e}"))?;
    let file =
        build::sign(&signed, &[&key]).map_err(|e| anyhow::anyhow!("signing the timestamp: {e}"))?;
    let path = repo::write_new(options.out, layout::TIMESTAMP_PATH, &file)?;

    let mut after = Vec::new();
    let again = check::verify(
        options.out,
        &anchor,
        now,
        Stage::Published,
        options.mode,
        &mut after,
    );
    let ok = matches!(&again, Ok(Ok(_))) && after.is_empty();
    if !ok {
        let cleanup = remove_created(std::slice::from_ref(&path));
        let why = match again {
            Ok(Err(p)) => p.to_string(),
            Ok(Ok(_)) => list(&after),
            Err(e) => format!("{e:#}"),
        };
        bail!("the repository does not verify with the new timestamp (removed{cleanup}): {why}");
    }
    Ok(Signed {
        path,
        version,
        snapshot: snapshot.version,
        expires,
    })
}

fn list(problems: &[super::Problem]) -> String {
    problems
        .iter()
        .map(|p| format!("  {p}"))
        .collect::<Vec<_>>()
        .join("\n")
}
