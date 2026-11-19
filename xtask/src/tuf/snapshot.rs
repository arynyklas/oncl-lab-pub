//! `cargo xtask tuf snapshot`: the snapshot of `tuf/v2`, which CI signs with the online
//! snapshot key when Pages is published (`docs/design/publishers.md`, "Онлайн-снимок v2",
//! Р8). It is made in the copy of `tuf/v2` that goes into the site artifact, never in the
//! committed tree.
//!
//! Before signing, the copy is verified as the committed tree with the client's code
//! ([`super::check_v2`], [`Stage::Tree`]): the chain of roots, the top-level targets signed
//! by the owner, the indexes and `publishers.json` exactly those of the tree, and the newest
//! file of every delegated role signed by its publisher's keys. A snapshot is never signed
//! over a file that was not verified; a revoked publisher's last file is listed as it is
//! (no client reads it: there is no delegation to it any more).
//!
//! The snapshot lists the newest top-level targets and the newest file of every role that
//! ever had one, each with its version, length and sha256. Its version is the Unix time of
//! signing, or one more than the previous snapshot's; it expires 7 days later.
//!
//! The previous snapshot is the one the published `timestamp.json` names, read with a
//! [`Fetcher`] over the published site: verified by the timestamp and snapshot keys of a
//! root of the chain, then the guard of section 5.5.5 of the specification: the new
//! snapshot drops nothing it listed and lowers no version (a client would take it for a
//! rollback, and every update of `tuf/v2` would stop). It is also written into the copy, so
//! that a client whose cached `timestamp.json` still names it finds it. The new snapshot is
//! verified once more with the previous one beside it ([`Stage::Snapshotted`]); if it does
//! not hold, what was written is removed again. A published site without a timestamp is an
//! error: only the first publication ([`Previous::FirstPublication`]) extends nothing.

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

use super::check::Expiry;
use super::check_v2::{self, Stage};
use super::timestamp::{KeySource, load_key};
use super::{Problem, V2_SNAPSHOT_DAYS, expiry, next_version, remove_created, repo, whole_seconds};

/// What [`snapshot`] does.
pub struct Options<'a> {
    /// The repository directory (a copy of `tuf/v2` for publication).
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
    pub previous: Option<(u64, PathBuf)>,
    /// When it expires.
    pub expires: OffsetDateTime,
}

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
        bail!("{what} is not signed by the {role} keys of any root of tuf/v2")
    }
}

/// What the new snapshot extends.
#[derive(Clone, Copy)]
pub enum Previous<'a> {
    /// The published `tuf/v2`, read with this fetcher: its timestamp must be there.
    Published(&'a dyn Fetcher),
    /// Nothing: the first publication of `tuf/v2` (`--first-publication`).
    FirstPublication,
}

/// The snapshot the published `timestamp.json` of `fetcher` names, and its file.
///
/// # Errors
///
/// If the site cannot be read, has no timestamp (a 404: run with `--first-publication` for
/// the first publication), or the timestamp or the snapshot is not one of `roots`' keys or
/// does not match what the timestamp lists.
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
            "the published tuf/v2 has no timestamp: a snapshot that extends nothing is \
             signed only for the first publication (`--first-publication`)"
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
fn meta_entry(version: u64, file: &[u8]) -> Value {
    json!({
        "version": version,
        "length": file.len(),
        "hashes": {"sha256": Digest::of(file).to_hex()},
    })
}

/// Signs the snapshot of the copy of `tuf/v2` in `options.out` (see the module's
/// description); `previous` reads the published site.
///
/// # Errors
///
/// If the copy does not verify or expires within a day, has a snapshot or a timestamp
/// already, the key is missing, malformed or not the snapshot key of the root in force, the
/// previous snapshot cannot be read or verified, the new one would drop or lower what it
/// listed, or the result does not verify (then nothing stays written).
pub fn snapshot(options: &Options, previous: Previous<'_>) -> anyhow::Result<Signed> {
    let report = check_v2::check(&check_v2::Options {
        dir: options.out,
        index: Some(options.index),
        publishers: Some(options.publishers),
        anchor: Some(options.anchor),
        now: options.now,
        stage: Stage::Tree,
        expiry: Expiry {
            min_days: 1,
            min_root_days: 1,
            fail: true,
        },
        base: None,
    })?;
    let verified = match report {
        check_v2::Outcome::NoRepository => {
            bail!(
                "there is no tuf/v2 in {}: no snapshot is signed",
                options.out.display()
            )
        }
        check_v2::Outcome::Checked(report) => match report.verified {
            Some(v) if report.problems.is_empty() => v,
            _ => bail!(
                "tuf/v2 does not verify, no snapshot is signed:\n{}\n(an expired or nearly \
                 expired targets: the owner runs `cargo xtask tuf update --refresh` and merges \
                 it; an expired root: `cargo xtask tuf root --repo v2`)",
                list(&report.problems)
            ),
        },
    };
    let key = load_key(options.key)?;
    let allowed = &verified.root.role(Role::Snapshot).keyids;
    if !allowed.contains(&key.key_id()) {
        bail!(
            "the key {} is not a snapshot key of root {} of tuf/v2 (it lists {}): the key was \
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
    let previous = match previous {
        Previous::Published(fetcher) => Some(previous_snapshot(fetcher, &verified.roots)?),
        Previous::FirstPublication => None,
    };

    let now = whole_seconds(options.now);
    let unix = u64::try_from(now.unix_timestamp()).context("the clock is before 1970")?;
    let version = match &previous {
        Some((p, _)) => unix.max(next_version("published snapshot", p.version)?),
        None => unix,
    };
    let expires = expiry(now, V2_SNAPSHOT_DAYS);
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
    if let Some((p, _)) = &previous {
        let mut problems = check_v2::rollback(p, &made);
        for (name, before) in &p.meta {
            if let Some(now) = made.meta.get(name)
                && now.version == before.version
                && (now.length != before.length || now.sha256 != before.sha256)
            {
                problems.push(Problem::new(
                    "published-differs",
                    format!(
                        "the published snapshot {} lists another {name} of version {} than \
                         the tree has: published files never change",
                        p.version, now.version
                    ),
                ));
            }
        }
        if !problems.is_empty() {
            bail!(
                "the new snapshot would not extend the published one, no snapshot is \
                 signed:\n{}",
                list(&problems)
            );
        }
    }
    let file =
        build::sign(&signed, &[&key]).map_err(|e| anyhow::anyhow!("signing the snapshot: {e}"))?;

    let mut created = Vec::new();
    let written = (|| -> anyhow::Result<Option<(u64, PathBuf)>> {
        let mut kept = None;
        if let Some((p, bytes)) = &previous {
            let path = layout::snapshot_path(p.version);
            let full = options.out.join(&path);
            if full.exists() {
                if fs::read(&full).with_context(|| format!("reading {}", full.display()))? != *bytes
                {
                    bail!(
                        "{} exists and is not the published snapshot",
                        full.display()
                    );
                }
            } else {
                created.push(repo::write_new(options.out, &path, bytes)?);
            }
            kept = Some((p.version, full));
        }
        created.push(repo::write_new(
            options.out,
            &layout::snapshot_path(version),
            &file,
        )?);
        Ok(kept)
    })();
    let verdict = written.and_then(|kept| {
        let report = check_v2::check(&check_v2::Options {
            dir: options.out,
            index: Some(options.index),
            publishers: Some(options.publishers),
            anchor: Some(options.anchor),
            now,
            stage: Stage::Snapshotted,
            expiry: Expiry {
                min_days: 0,
                min_root_days: 0,
                fail: false,
            },
            base: None,
        })?;
        match report {
            check_v2::Outcome::Checked(report) if report.problems.is_empty() => Ok(kept),
            check_v2::Outcome::Checked(report) => bail!(
                "tuf/v2 does not verify with the new snapshot (removed): {}",
                list(&report.problems)
            ),
            check_v2::Outcome::NoRepository => bail!("tuf/v2 vanished"),
        }
    });
    let kept = match verdict {
        Ok(kept) => kept,
        Err(e) => {
            let cleanup = remove_created(&created);
            return Err(e.context(format!("the files written were removed{cleanup}")));
        }
    };
    Ok(Signed {
        path: options.out.join(layout::snapshot_path(version)),
        version,
        targets: verified.targets.version,
        roles: verified.roles.len(),
        previous: kept,
        expires,
    })
}
