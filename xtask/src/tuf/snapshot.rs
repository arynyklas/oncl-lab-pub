//! `cargo xtask tuf snapshot`: the snapshot of `tuf/v1` CI signs with the online snapshot
//! key when Pages is published, once the snapshot is online (`snapshot = "online"` in
//! `tuf/v1.toml`; `docs/design/publishers.md`, "Онлайн-снимок", Р8). It is made in the copy
//! of `tuf/v1` that goes into the site artifact, never in the committed tree. While the
//! snapshot is offline the owner signs it with `tuf update`, and this refuses.
//!
//! Before signing, the copy is verified as the committed tree with the client's code
//! ([`super::check`], [`Stage::Tree`]): the chain of roots, the top-level targets signed by
//! the owner, the indexes and `publishers.json` exactly those of the tree, and the newest
//! file of every delegated role signed by its publisher's keys. A snapshot is never signed
//! over a file that was not verified; a retired or revoked publisher's last file is listed
//! as it is (no client reads it: there is no delegation to it any more).
//!
//! The snapshot lists the newest top-level targets and the newest file of every role that
//! ever had one, each with its version, length and sha256. Its version is the Unix time of
//! signing, or one more than the previous snapshot's; it expires 7 days later.
//!
//! The previous snapshot is the one the published `timestamp.json` names, read with a
//! [`Fetcher`] over the published site: verified by the timestamp and snapshot keys of the
//! root in force or of the root it replaced (the first online snapshot extends the owner's
//! last offline one, signed by the key the rotation replaced), its version no more than a day
//! ahead of the clock, then the guard of section 5.5.5 of the specification:
//! the new snapshot drops nothing it listed and lowers no version (a client would take it
//! for a rollback, and every update would stop). It is also written into the copy, so that
//! a client whose cached `timestamp.json` still names it finds it. If the published site
//! cannot be read or does not verify, nothing is signed and there is no way around it
//! (Р25): the owner repairs it by hand (`docs/dev/release.md`). The new snapshot is verified
//! once more with the previous one beside it ([`Stage::Snapshotted`]); if it does not hold,
//! what was written is removed again.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::build;
use oncl_update::tuf::ed25519::verify_role;
use oncl_update::tuf::{
    Digest, Envelope, Fetcher, Limits, Response, Role, Root, Snapshot, Timestamp, layout,
};
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::check::{self, Expiry, Stage};
use super::repo::SnapshotMode;
use super::timestamp::{KeySource, load_key};
use super::{
    ONLINE_SNAPSHOT_DAYS, Problem, expiry, next_version, remove_created, repo, whole_seconds,
};

/// What [`snapshot`] does.
pub struct Options<'a> {
    /// The repository directory (a copy of `tuf/v1` for publication).
    pub out: &'a Path,
    /// The trust anchor the copy is verified from (`crates/oncl-update/keys/root.json`).
    pub anchor: &'a Path,
    /// The indexes of the tree (`updates/v1`).
    pub index: &'a Path,
    /// The registry of the publishers (`publishers/`).
    pub publishers: &'a Path,
    /// Who signs the snapshot (`tuf/v1.toml`): this signs only an online one.
    pub mode: SnapshotMode,
    /// The key.
    pub key: &'a KeySource,
    /// The signing time.
    pub now: OffsetDateTime,
}

/// What [`snapshot`] made.
#[derive(Debug)]
pub struct Signed {
    /// The file.
    pub path: PathBuf,
    /// Its version.
    pub version: u64,
    /// The targets it lists.
    pub targets: u64,
    /// How many role files it lists.
    pub roles: usize,
    /// The previous snapshot, written beside it: its version and file.
    pub previous: (u64, PathBuf),
    /// When it expires.
    pub expires: OffsetDateTime,
}

/// How far ahead of the clock, in seconds, the version of the published snapshot may be.
const MAX_AHEAD: u64 = 86_400;

fn list(problems: &[Problem]) -> String {
    problems
        .iter()
        .map(|p| format!("  {p}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `file` is signed by a threshold of the keys of `role` of one of `roots`.
fn signed_by_any(file: &Envelope, roots: &[Root], role: Role, what: &str) -> anyhow::Result<()> {
    if roots
        .iter()
        .any(|root| verify_role(file, root, role, what).is_ok())
    {
        Ok(())
    } else {
        bail!("{what} is not signed by the {role} keys of the root in force or the one it replaced")
    }
}

/// The snapshot the published `timestamp.json` of `fetcher` names, and its file.
///
/// # Errors
///
/// If the site cannot be read, has no timestamp, or the timestamp or the snapshot is not
/// signed by the keys of one of `roots` or does not match what the timestamp lists.
pub fn previous_snapshot(
    fetcher: &dyn Fetcher,
    roots: &[Root],
) -> anyhow::Result<(Snapshot, Vec<u8>)> {
    let limits = Limits::default();
    let body = match fetcher
        .fetch(layout::TIMESTAMP_PATH, limits.timestamp)
        .map_err(|e| anyhow::anyhow!("the published timestamp: {e}"))?
    {
        Response::NotFound => bail!(
            "the published repository has no timestamp: a new snapshot always extends the \
             published one, and there is no way around it (Р25); repair the site by hand \
             (docs/dev/release.md)"
        ),
        Response::Body(body) => body,
    };
    let file = Envelope::parse(&body, limits.timestamp, "the published timestamp")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    signed_by_any(&file, roots, Role::Timestamp, "the published timestamp")?;
    let timestamp = Timestamp::from_signed(&file.signed).map_err(|e| anyhow::anyhow!("{e}"))?;
    let listed = &timestamp.snapshot;
    let path = layout::snapshot_path(listed.version);
    let max = listed
        .length
        .unwrap_or(limits.snapshot)
        .min(limits.snapshot);
    let body = match fetcher
        .fetch(&path, max)
        .map_err(|e| anyhow::anyhow!("the published {path}: {e}"))?
    {
        Response::NotFound => bail!(
            "the published timestamp names snapshot {}, which is not published",
            listed.version
        ),
        Response::Body(body) => body,
    };
    if listed.length.is_some_and(|l| l != body.len() as u64)
        || listed.sha256.is_some_and(|h| h != Digest::of(&body))
    {
        bail!("the published {path} is not the file the published timestamp lists");
    }
    let file =
        Envelope::parse(&body, limits.snapshot, &path).map_err(|e| anyhow::anyhow!("{e}"))?;
    signed_by_any(
        &file,
        roots,
        Role::Snapshot,
        &format!("the published {path}"),
    )?;
    let snapshot = Snapshot::from_signed(&file.signed).map_err(|e| anyhow::anyhow!("{e}"))?;
    if snapshot.version != listed.version {
        bail!("the published {path} is of version {}", snapshot.version);
    }
    Ok((snapshot, body))
}

/// What a snapshot lists of a file: version, length and sha256.
pub(super) fn meta_entry(version: u64, file: &[u8]) -> Value {
    json!({
        "version": version,
        "length": file.len(),
        "hashes": {"sha256": Digest::of(file).to_hex()},
    })
}

/// Signs the snapshot of the copy of `tuf/v1` in `options.out` (see the module's
/// description); `previous` reads the published site.
///
/// # Errors
///
/// If the snapshot is offline, the copy does not verify or expires within a day, has a
/// snapshot signed by the key in force or a timestamp already, the key is missing,
/// malformed or not the snapshot key of the root in force, the previous snapshot cannot be
/// read or verified, the new one would drop or lower what it listed, or the result does not
/// verify (then nothing stays written).
pub fn snapshot(options: &Options, previous: &dyn Fetcher) -> anyhow::Result<Signed> {
    if options.mode == SnapshotMode::Offline {
        bail!(
            "the snapshot is offline (tuf/v1.toml): the owner signs it with `cargo xtask tuf \
             update`; it goes online with `cargo xtask tuf root --rotate-snapshot --online`"
        );
    }
    let check_at = |stage, now, expiry| {
        check::check(&check::Options {
            dir: options.out,
            index: Some(options.index),
            publishers: Some(options.publishers),
            anchor: Some(options.anchor),
            now,
            stage,
            mode: options.mode,
            expiry,
            base: None,
        })
    };
    let report = check_at(
        Stage::Tree,
        options.now,
        Expiry {
            min_days: 1,
            min_root_days: 1,
            fail: true,
        },
    )?;
    let verified = match report {
        check::Outcome::NoRepository => {
            bail!(
                "there is no repository in {}: no snapshot is signed",
                options.out.display()
            )
        }
        check::Outcome::Checked(report) => match report.verified {
            Some(v) if report.problems.is_empty() => v,
            _ => bail!(
                "the repository does not verify, no snapshot is signed:\n{}\n(an expired or \
                 nearly expired targets: the owner runs `cargo xtask tuf update --refresh` and \
                 merges it; an expired root: `cargo xtask tuf root`)",
                list(&report.problems)
            ),
        },
    };
    let key = load_key(options.key)?;
    let allowed = &verified.root.role(Role::Snapshot).keyids;
    if !allowed.contains(&key.key_id()) {
        bail!(
            "the key {} is not a snapshot key of root {} (it lists {}): the key was rotated, \
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
    // The published snapshot is signed by the root in force, or (the first after a rotation)
    // by the root it replaced: never by an older one.
    let recent = &verified.roots[verified.roots.len().saturating_sub(2)..];
    let (previous, previous_bytes) = previous_snapshot(previous, recent)?;

    let now = whole_seconds(options.now);
    let unix = u64::try_from(now.unix_timestamp()).context("the clock is before 1970")?;
    // Versions are Unix seconds, one more per publication within a second: one far ahead of
    // the clock is a wrong clock or a forged file, and would be carried on for good.
    if previous.version > unix.saturating_add(MAX_AHEAD) {
        bail!(
            "the published snapshot is of version {}, more than a day ahead of the clock \
             ({unix}): not extending it; repair the site by hand (docs/dev/release.md)",
            previous.version
        );
    }
    let version = unix.max(next_version("published snapshot", previous.version)?);
    let expires = expiry(now, ONLINE_SNAPSHOT_DAYS);
    let mut signed = build::snapshot(
        version,
        expires,
        verified.targets.version,
        &verified.targets_file,
    )
    .map_err(|e| anyhow::anyhow!("making the snapshot: {e}"))?;
    let Some(meta) = signed.get_mut("meta").and_then(Value::as_object_mut) else {
        bail!("the snapshot made has no meta");
    };
    for (name, role) in &verified.roles {
        meta.insert(name.meta_name(), meta_entry(role.version, &role.file));
    }
    let made = Snapshot::from_signed(&signed).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut problems = check::rollback(&previous, &made);
    for (name, before) in &previous.meta {
        let Some(now) = made.meta.get(name) else {
            continue;
        };
        let differs = before.length.is_some_and(|l| now.length != Some(l))
            || before.sha256.is_some_and(|h| now.sha256 != Some(h));
        if now.version == before.version && differs {
            problems.push(Problem::new(
                "published-differs",
                format!(
                    "the published snapshot {} lists another {name} of version {} than the \
                     tree has: published files never change",
                    previous.version, before.version
                ),
            ));
        }
    }
    if !problems.is_empty() {
        bail!(
            "the new snapshot would not extend the published one, no snapshot is signed:\n{}",
            list(&problems)
        );
    }
    let file =
        build::sign(&signed, &[&key]).map_err(|e| anyhow::anyhow!("signing the snapshot: {e}"))?;

    let mut created = Vec::new();
    let previous_path = options.out.join(layout::snapshot_path(previous.version));
    let written = (|| -> anyhow::Result<()> {
        if previous_path.exists() {
            if fs::read(&previous_path)
                .with_context(|| format!("reading {}", previous_path.display()))?
                != previous_bytes
            {
                bail!(
                    "{} exists and is not the published snapshot",
                    previous_path.display()
                );
            }
        } else {
            created.push(repo::write_new(
                options.out,
                &layout::snapshot_path(previous.version),
                &previous_bytes,
            )?);
        }
        created.push(repo::write_new(
            options.out,
            &layout::snapshot_path(version),
            &file,
        )?);
        Ok(())
    })();
    let verdict = written.and_then(|()| {
        match check_at(
            Stage::Snapshotted,
            now,
            Expiry {
                min_days: 0,
                min_root_days: 0,
                fail: false,
            },
        )? {
            check::Outcome::Checked(report) if report.problems.is_empty() => Ok(()),
            check::Outcome::Checked(report) => bail!(
                "the repository does not verify with the new snapshot (removed): {}",
                list(&report.problems)
            ),
            check::Outcome::NoRepository => bail!("the repository vanished"),
        }
    });
    if let Err(e) = verdict {
        let cleanup = remove_created(&created);
        return Err(e.context(format!("the files written were removed{cleanup}")));
    }
    Ok(Signed {
        path: options.out.join(layout::snapshot_path(version)),
        version,
        targets: verified.targets.version,
        roles: verified.roles.len(),
        previous: (previous.version, previous_path),
        expires,
    })
}
