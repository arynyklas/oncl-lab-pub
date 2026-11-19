//! `cargo xtask tuf timestamp`: the one file CI signs, with the online key, when Pages is
//! published (`docs/design/tuf.md`). It is made in the copy of the repository that goes into
//! the site artifact, never in the committed tree.
//!
//! Before signing, the repository is verified with the client's code as a tree without a
//! timestamp ([`super::check`]): the snapshot must be signed by the keys of the root in
//! force and agree with the targets and the target files. CI can only vouch for a snapshot
//! the owner has signed. It refuses a snapshot, targets or root that has expired or expires
//! within a day: a timestamp over them would be a promise that cannot be kept, and the
//! owner has to refresh them first. After signing, the result is verified again with the
//! timestamp, as the client does.
//!
//! The timestamp's `version` is the Unix time of signing and it expires 7 days later.
//! The key is read, never printed.
//!
//! [`timestamp_v2`] does the same for the copy of `tuf/v2`, after `tuf snapshot` signed its
//! snapshot ([`super::snapshot`]): the copy is verified with the snapshot first
//! ([`Stage::Snapshotted`]), and once more with the timestamp, as the client of `tuf/v2`
//! reads it, its publishers' roles included.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::build;
use oncl_update::tuf::{Role, layout};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::check::{self, Expiry, TimestampMode};
use super::check_v2::{self, Stage};
use super::{
    SNAPSHOT_DAYS, TIMESTAMP_DAYS, V2_SNAPSHOT_DAYS, expiry, keystore, remove_created, repo,
    show_time, whole_seconds,
};

/// Where the timestamp key is.
#[derive(Clone, Debug)]
pub enum KeySource {
    /// The environment variable of this name (the GitHub secret `TUF_TIMESTAMP_KEY`).
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
        anchor: Some(options.anchor),
        now: options.now,
        timestamp: TimestampMode::Absent,
        expiry: Expiry {
            min_days: 1,
            min_root_days: 1,
            fail: true,
        },
        base: None,
    })?;
    let verified = match report {
        check::Outcome::NoRepository => bail!(
            "there is no repository in {} and no trust anchor {}: no timestamp is signed",
            options.out.display(),
            options.anchor.display()
        ),
        check::Outcome::Checked(report) => match report.verified {
            Some(v) if report.problems.is_empty() => v,
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
    // A clock before the snapshot was signed (it is valid for SNAPSHOT_DAYS) is not a clock
    // to date a timestamp by.
    let signed_at = verified.snapshot.expires - Duration::days(SNAPSHOT_DAYS);
    if now + Duration::days(1) < signed_at {
        bail!(
            "the clock ({}) is before snapshot {} was signed (about {}): not signing",
            show_time(now),
            verified.snapshot.version,
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
    let snapshot_file = repo::read(
        options.out,
        &layout::snapshot_path(verified.snapshot.version),
    )?;
    let expires = expiry(now, TIMESTAMP_DAYS);
    let signed = build::timestamp(version, expires, verified.snapshot.version, &snapshot_file)
        .map_err(|e| anyhow::anyhow!("making the timestamp: {e}"))?;
    let file =
        build::sign(&signed, &[&key]).map_err(|e| anyhow::anyhow!("signing the timestamp: {e}"))?;
    let path = repo::write_new(options.out, layout::TIMESTAMP_PATH, &file)?;

    let mut after = Vec::new();
    let again = check::verify(
        options.out,
        &anchor,
        now,
        TimestampMode::Required,
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
        snapshot: verified.snapshot.version,
        expires,
    })
}

/// What [`timestamp_v2`] does.
pub struct V2Options<'a> {
    /// The repository directory (a copy of `tuf/v2` for publication, with its snapshot).
    pub out: &'a Path,
    /// The trust anchor of `tuf/v2` the copy is verified from.
    pub anchor: &'a Path,
    /// The indexes of the tree (`updates/v1`).
    pub index: &'a Path,
    /// The registry of the publishers (`publishers/`).
    pub publishers: &'a Path,
    /// The key.
    pub key: &'a KeySource,
    /// The signing time.
    pub now: OffsetDateTime,
}

/// Signs the timestamp of the copy of `tuf/v2` in `options.out` (see the module's
/// description).
///
/// # Errors
///
/// As [`timestamp`].
pub fn timestamp_v2(options: &V2Options) -> anyhow::Result<Signed> {
    let target = options.out.join(layout::TIMESTAMP_PATH);
    if target.exists() {
        bail!(
            "{} exists already; refusing to overwrite it",
            target.display()
        );
    }
    let report = check_v2::check(&check_v2::Options {
        dir: options.out,
        index: Some(options.index),
        publishers: Some(options.publishers),
        anchor: Some(options.anchor),
        now: options.now,
        stage: Stage::Snapshotted,
        expiry: Expiry {
            min_days: 1,
            min_root_days: 1,
            fail: true,
        },
        base: None,
    })?;
    let (verified, snapshot) = match report {
        check_v2::Outcome::NoRepository => bail!(
            "there is no tuf/v2 in {}: no timestamp is signed",
            options.out.display()
        ),
        check_v2::Outcome::Checked(report) => match report.verified {
            Some(v) if report.problems.is_empty() => match v.snapshot.clone() {
                Some(snapshot) => (v, snapshot),
                None => bail!("tuf/v2 has no snapshot: run `cargo xtask tuf snapshot` first"),
            },
            _ => bail!(
                "tuf/v2 does not verify, no timestamp is signed:\n{}",
                list(&report.problems)
            ),
        },
    };
    let anchor = fs::read(options.anchor)
        .with_context(|| format!("reading the trust anchor {}", options.anchor.display()))?;
    let now = whole_seconds(options.now);
    let signed_at = snapshot.expires - Duration::days(V2_SNAPSHOT_DAYS);
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
            "the key {} is not a timestamp key of root {} of tuf/v2 (it lists {}): the key was \
             rotated, or the secret holds another key",
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
    let again = check_v2::verify(options.out, &anchor, now, Stage::Published, &mut after);
    let ok = matches!(&again, Ok(Ok(_))) && after.is_empty();
    if !ok {
        let cleanup = remove_created(std::slice::from_ref(&path));
        let why = match again {
            Ok(Err(p)) => p.to_string(),
            Ok(Ok(_)) => list(&after),
            Err(e) => format!("{e:#}"),
        };
        bail!("tuf/v2 does not verify with the new timestamp (removed{cleanup}): {why}");
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
