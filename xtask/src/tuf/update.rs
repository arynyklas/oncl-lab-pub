//! `cargo xtask tuf update`: new targets and snapshot over the update indexes, signed with the
//! owner's keys.
//!
//! The indexes (`updates/v1/{stable,beta}.json`) are copied byte for byte to
//! `targets/indexes/<sha256>.<channel>.json` and listed by `metadata/<N+1>.targets.json`,
//! which `metadata/<N+1>.snapshot.json` lists. Versions only grow, by one over the highest
//! committed. The timestamp is not touched: CI signs it when Pages is published.
//!
//! A run with nothing to change writes nothing (so the owner is not asked for a passphrase
//! either): the indexes are the committed targets, and the committed targets and snapshot
//! are signed by the keys of the root in force. `refresh` signs new versions anyway, with
//! the same targets: the monthly job that pushes the expiry forward. After a rotation of the
//! targets or snapshot key the committed files are not signed by the keys in force, which is
//! "something to change" too.
//!
//! The result is verified before the run ends, with the client's code ([`super::check`]);
//! if it does not hold, what was written is removed again.
//!
//! [`update_v2`] does the same for `tuf/v2` (`docs/design/publishers.md`, "xtask"): its
//! top-level targets list the same indexes and `publishers.json`, and delegate to the active
//! publishers, both made of `publishers/` ([`crate::publishers`]), signed with the targets
//! key both repositories share. It writes no snapshot: CI signs that one online
//! ([`super::snapshot`]). [`update_both`] updates `tuf/v1` and then `tuf/v2`, asks the
//! passphrase once, verifies the two together ([`super::check_v2::cross`]), and leaves
//! nothing written in either if one fails.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::build;
use oncl_update::tuf::ed25519::verify_role;
use oncl_update::tuf::{
    Digest, Envelope, Limits, Profile, Role, Root, SigningKey, Snapshot, Targets, layout,
};
use oncl_update::{Channel, Index, MAX_INDEX_LEN};
use time::OffsetDateTime;

use super::check::{self, Expiry, TimestampMode};
use super::check_v2::{self, Stage};
use super::keystore::{self, Unlock};
use super::repo::{self, Layout, Listing};
use super::{PassphraseSource, SNAPSHOT_DAYS, TARGETS_DAYS, expiry, next_version, remove_created};
use crate::publishers::{self, Registry};

/// What [`update`] does.
pub struct Options<'a> {
    /// The directory of the secret keys.
    pub keys: &'a Path,
    /// The directory of the indexes (`updates/v1`).
    pub index: &'a Path,
    /// The repository directory (`tuf/v1`).
    pub out: &'a Path,
    /// Sign new versions even if nothing changed.
    pub refresh: bool,
    /// The signing time.
    pub now: OffsetDateTime,
    /// Where the passphrase of the keys comes from.
    pub passphrase: &'a PassphraseSource,
}

/// What [`update`] did.
#[derive(Debug)]
pub enum Outcome {
    /// Nothing to change: the committed targets and snapshot already are the indexes.
    UpToDate {
        /// The targets version in force.
        targets: u64,
        /// The snapshot version in force.
        snapshot: u64,
    },
    /// New versions were written.
    Written(Written),
}

/// The new versions.
#[derive(Debug)]
pub struct Written {
    /// Why.
    pub reason: String,
    /// The new targets version.
    pub targets: u64,
    /// The new snapshot version.
    pub snapshot: u64,
    /// When both expire.
    pub expires: OffsetDateTime,
    /// The files made, with the metadata last.
    pub files: Vec<PathBuf>,
}

/// The indexes in `dir` as targets: `(target path, bytes)`, valid indexes of the channel
/// their file name says.
///
/// # Errors
///
/// If one is not readable, too large or not a valid index of its channel.
pub fn read_indexes(dir: &Path) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    for channel in Channel::ALL {
        let path = dir.join(format!("{}.json", channel.as_str()));
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        if bytes.len() as u64 > MAX_INDEX_LEN {
            bail!("{} is larger than {MAX_INDEX_LEN} bytes", path.display());
        }
        let index =
            Index::from_json(&bytes).with_context(|| format!("reading {}", path.display()))?;
        if index.channel != channel {
            bail!(
                "{} is an index of the {} channel",
                path.display(),
                index.channel
            );
        }
        files.push((format!("indexes/{}.json", channel.as_str()), bytes));
    }
    Ok(files)
}

fn read_targets(dir: &Path, version: u64) -> anyhow::Result<(Envelope, Targets)> {
    let path = layout::targets_path(version);
    let bytes = repo::read(dir, &path)?;
    let env = Envelope::parse(&bytes, Limits::default().targets, &path)
        .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    let targets = Targets::from_signed(&env.signed, Profile::Legacy)
        .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    Ok((env, targets))
}

fn read_snapshot(dir: &Path, version: u64) -> anyhow::Result<(Envelope, Snapshot)> {
    let path = layout::snapshot_path(version);
    let bytes = repo::read(dir, &path)?;
    let env = Envelope::parse(&bytes, Limits::default().snapshot, &path)
        .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    let snapshot =
        Snapshot::from_signed(&env.signed).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    Ok((env, snapshot))
}

/// The signing keys of `role` of `root` in the key directory `dir`, at least its threshold.
fn signers(
    dir: &Path,
    root: &Root,
    role: Role,
    unlock: &mut Unlock,
) -> anyhow::Result<Vec<SigningKey>> {
    let keys = keystore::find_keys(dir, role, &root.role(role).keyids, unlock)?;
    if keys.len() < root.role(role).threshold as usize {
        bail!(
            "root {} needs {} {role} keys to sign, {} are in {}",
            root.version,
            root.role(role).threshold,
            keys.len(),
            dir.display()
        );
    }
    Ok(keys)
}

/// Signs new targets and snapshot over the indexes (see the module's description).
///
/// # Errors
///
/// If the repository or the indexes are not usable, the keys cannot be opened, or the result
/// does not verify (then nothing stays written).
pub fn update(options: &Options) -> anyhow::Result<Outcome> {
    let mut unlock = Unlock::new(options.passphrase.clone(), "Passphrase of the TUF keys: ");
    update_with(options, &mut unlock)
}

/// [`update`], with the passphrase asked once for both repositories.
fn update_with(options: &Options, unlock: &mut Unlock) -> anyhow::Result<Outcome> {
    let anchor = repo::read(options.out, &layout::root_path(1))
        .context("the repository has no root version 1: run `cargo xtask tuf init` first")?;
    let root = check::final_root(options.out, &anchor, options.now)?;
    let listing = Listing::read(options.out)?;
    let (_, last_targets, last_snapshot) = listing.highest();

    let indexes = read_indexes(options.index)?;
    if indexes.is_empty() {
        bail!("there is no update index in {}", options.index.display());
    }
    let wanted: BTreeMap<&str, (u64, Digest)> = indexes
        .iter()
        .map(|(path, bytes)| (path.as_str(), (bytes.len() as u64, Digest::of(bytes))))
        .collect();

    // What there is to do.
    let mut reasons: Vec<String> = Vec::new();
    if last_targets == 0 || last_snapshot == 0 {
        reasons.push("the repository has no targets and snapshot yet".to_owned());
    } else {
        let (targets_env, targets) = read_targets(options.out, last_targets)?;
        for path in targets.targets.keys() {
            if !wanted.contains_key(path.as_str()) {
                bail!(
                    "the targets list {path}, but its index file is not in {}: clients of that \
                     channel would be left without updates",
                    options.index.display()
                );
            }
        }
        let listed: BTreeMap<&str, (u64, Digest)> = targets
            .targets
            .iter()
            .map(|(path, t)| (path.as_str(), (t.length, t.sha256)))
            .collect();
        if listed != wanted {
            let changed: Vec<&str> = wanted
                .iter()
                .filter(|(path, entry)| listed.get(*path) != Some(entry))
                .map(|(path, _)| *path)
                .collect();
            reasons.push(format!("the indexes changed: {}", changed.join(", ")));
        }
        let (snapshot_env, snapshot) = read_snapshot(options.out, last_snapshot)?;
        let keys_ok = verify_role(&targets_env, &root, Role::Targets, "the targets").is_ok()
            && verify_role(&snapshot_env, &root, Role::Snapshot, "the snapshot").is_ok();
        if !keys_ok {
            reasons.push(format!(
                "targets {last_targets} and snapshot {last_snapshot} are not signed by the keys \
                 of root {} (a key was rotated)",
                root.version
            ));
        }
        if snapshot.targets().version != last_targets {
            reasons.push(format!(
                "snapshot {last_snapshot} lists targets {}, not {last_targets}",
                snapshot.targets().version
            ));
        }
    }
    if reasons.is_empty() && options.refresh {
        reasons.push("refresh: new expiry, same targets".to_owned());
    }
    if reasons.is_empty() {
        return Ok(Outcome::UpToDate {
            targets: last_targets,
            snapshot: last_snapshot,
        });
    }

    // The keys of the roles in force.
    let targets_keys = signers(options.keys, &root, Role::Targets, unlock)?;
    let snapshot_keys = signers(options.keys, &root, Role::Snapshot, unlock)?;

    let targets_version = next_version("targets", last_targets)?;
    let snapshot_version = next_version("snapshot", last_snapshot)?;
    let expires = expiry(options.now, TARGETS_DAYS.min(SNAPSHOT_DAYS));
    let refs: Vec<(&str, &[u8])> = indexes
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    let signed = build::targets(targets_version, expiry(options.now, TARGETS_DAYS), &refs)
        .map_err(|e| anyhow::anyhow!("making the targets: {e}"))?;
    let targets_file = build::sign(&signed, &targets_keys.iter().collect::<Vec<_>>())
        .map_err(|e| anyhow::anyhow!("signing the targets: {e}"))?;
    let signed = build::snapshot(
        snapshot_version,
        expiry(options.now, SNAPSHOT_DAYS),
        targets_version,
        &targets_file,
    )
    .map_err(|e| anyhow::anyhow!("making the snapshot: {e}"))?;
    let snapshot_file = build::sign(&signed, &snapshot_keys.iter().collect::<Vec<_>>())
        .map_err(|e| anyhow::anyhow!("signing the snapshot: {e}"))?;
    let stored =
        build::target_files(&refs).map_err(|e| anyhow::anyhow!("laying out the targets: {e}"))?;

    // Write: the targets files (content-addressed: one that is there already must be the
    // same bytes), then the metadata. A failure removes what this run made.
    let mut created: Vec<PathBuf> = Vec::new();
    let written = (|| -> anyhow::Result<()> {
        write_stored(options.out, &stored, &mut created)?;
        created.push(repo::write_new(
            options.out,
            &layout::targets_path(targets_version),
            &targets_file,
        )?);
        created.push(repo::write_new(
            options.out,
            &layout::snapshot_path(snapshot_version),
            &snapshot_file,
        )?);
        Ok(())
    })();
    let verdict = written.and_then(|()| {
        let report = check::check(&check::Options {
            dir: options.out,
            index: Some(options.index),
            anchor: None,
            now: options.now,
            timestamp: TimestampMode::Absent,
            expiry: Expiry {
                min_days: 0,
                min_root_days: 0,
                fail: false,
            },
            base: None,
        })?;
        match report {
            check::Outcome::Checked(report) if report.problems.is_empty() => Ok(()),
            check::Outcome::Checked(report) => bail!(
                "the repository does not verify after the update:\n{}",
                report
                    .problems
                    .iter()
                    .map(|p| format!("  {p}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            check::Outcome::NoRepository => bail!("the repository vanished"),
        }
    });
    if let Err(e) = verdict {
        let cleanup = remove_created(&created);
        return Err(e.context(format!("nothing was left written{cleanup}")));
    }
    Ok(Outcome::Written(Written {
        reason: reasons.join("; "),
        targets: targets_version,
        snapshot: snapshot_version,
        expires,
        files: created,
    }))
}

/// Writes the target files `stored` (`(path, content)`) into the repository `out`, adding the
/// files made to `created`. A file that is there already must have the same bytes: its name
/// is its hash.
fn write_stored(
    out: &Path,
    stored: &[(String, Vec<u8>)],
    created: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    for (path, content) in stored {
        let full = out.join(path);
        if full.exists() {
            if fs::read(&full).with_context(|| format!("reading {}", full.display()))? != *content {
                bail!(
                    "{} exists and is not the file its name says",
                    full.display()
                );
            }
            continue;
        }
        created.push(repo::write_new(out, path, content)?);
    }
    Ok(())
}

fn list(problems: &[super::Problem]) -> String {
    problems
        .iter()
        .map(|p| format!("  {p}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// What [`update_v2`] does.
pub struct V2Options<'a> {
    /// The directory of the secret keys.
    pub keys: &'a Path,
    /// The directory of the indexes (`updates/v1`).
    pub index: &'a Path,
    /// The repository directory (`tuf/v2`).
    pub out: &'a Path,
    /// `tuf/v1`, if there is one: no publisher's key may be a key of its root either.
    pub v1: Option<&'a Path>,
    /// The registry of the publishers (`publishers/`).
    pub publishers: &'a Path,
    /// Sign a new version even if nothing changed.
    pub refresh: bool,
    /// The signing time.
    pub now: OffsetDateTime,
    /// Where the passphrase of the keys comes from.
    pub passphrase: &'a PassphraseSource,
}

/// What [`update_v2`] did.
#[derive(Debug)]
pub enum V2Outcome {
    /// Nothing to change: the committed targets already are the indexes and the publishers.
    UpToDate {
        /// The targets version in force.
        targets: u64,
    },
    /// A new version was written.
    Written(V2Written),
}

/// The new targets of `tuf/v2`.
#[derive(Debug)]
pub struct V2Written {
    /// Why.
    pub reason: String,
    /// The new targets version.
    pub targets: u64,
    /// How many publishers it delegates to.
    pub delegated: usize,
    /// When it expires.
    pub expires: OffsetDateTime,
    /// The files made, with the metadata last.
    pub files: Vec<PathBuf>,
}

/// Signs new top-level targets of `tuf/v2` over the indexes and the publishers (see the
/// module's description).
///
/// # Errors
///
/// If the repository, the indexes or the registry of the publishers are not usable, the
/// targets key cannot be opened, or the result does not verify (then nothing stays
/// written).
pub fn update_v2(options: &V2Options) -> anyhow::Result<V2Outcome> {
    let mut unlock = Unlock::new(options.passphrase.clone(), "Passphrase of the TUF keys: ");
    update_v2_with(options, &mut unlock)
}

/// What `tuf/v2`'s next targets are made of, every input checked: the root in force, the
/// target files (the indexes and `publishers.json`) and the delegations.
struct V2Inputs {
    root: Root,
    files: Vec<(String, Vec<u8>)>,
    delegations: serde_json::Value,
}

/// Reads and checks what `tuf/v2`'s next targets are made of: its chain of roots, the
/// indexes, the registry of the publishers against the indexes and against every root of
/// both chains. Nothing is written.
fn v2_inputs(options: &V2Options) -> anyhow::Result<V2Inputs> {
    let anchor = repo::read(options.out, &layout::root_path(1))
        .context("tuf/v2 has no root version 1: run `cargo xtask tuf init --repo v2` first")?;
    let root = check::final_root(options.out, &anchor, options.now)?;
    let indexes = read_indexes(options.index)?;
    if indexes.is_empty() {
        bail!("there is no update index in {}", options.index.display());
    }
    let parsed = indexes
        .iter()
        .map(|(_, bytes)| Index::from_json(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let registry = Registry::read(options.publishers)?;
    let v2_chain = check::committed_chain(options.out)?;
    let v1_chain = match options.v1 {
        Some(v1) if v1.join(layout::root_path(1)).is_file() => check::committed_chain(v1)?,
        _ => Vec::new(),
    };
    let roots: Vec<(&str, &Root)> = v2_chain
        .iter()
        .map(|r| ("tuf/v2", r))
        .chain(v1_chain.iter().map(|r| ("tuf/v1", r)))
        .collect();
    registry.check_roots(&roots)?;
    registry.check_indexes(&parsed)?;
    let delegations = registry.delegations();
    let mut files = indexes;
    files.push((publishers::TARGET.to_owned(), registry.publishers_json()?));
    Ok(V2Inputs {
        root,
        files,
        delegations,
    })
}

fn update_v2_with(options: &V2Options, unlock: &mut Unlock) -> anyhow::Result<V2Outcome> {
    let V2Inputs {
        root,
        files,
        delegations,
    } = v2_inputs(options)?;
    let listing = Listing::read_layout(options.out, Layout::V2)?;
    let (_, last_targets, _) = listing.highest();
    let wanted: BTreeMap<&str, (u64, Digest)> = files
        .iter()
        .map(|(path, bytes)| (path.as_str(), (bytes.len() as u64, Digest::of(bytes))))
        .collect();

    // What there is to do.
    let mut reasons: Vec<String> = Vec::new();
    if last_targets == 0 {
        reasons.push("tuf/v2 has no targets yet".to_owned());
    } else {
        let path = layout::targets_path(last_targets);
        let bytes = repo::read(options.out, &path)?;
        let env = Envelope::parse(&bytes, Limits::default().targets, &path)
            .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        let targets = Targets::from_signed(&env.signed, Profile::Delegating)
            .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        for path in targets.targets.keys() {
            if path.as_str().starts_with("indexes/") && !wanted.contains_key(path.as_str()) {
                bail!(
                    "the targets of tuf/v2 list {path}, but its index file is not in {}: \
                     clients of that channel would be left without updates",
                    options.index.display()
                );
            }
        }
        let listed: BTreeMap<&str, (u64, Digest)> = targets
            .targets
            .iter()
            .map(|(path, t)| (path.as_str(), (t.length, t.sha256)))
            .collect();
        if listed != wanted {
            let changed: Vec<&str> = wanted
                .iter()
                .filter(|(path, entry)| listed.get(*path) != Some(entry))
                .map(|(path, _)| *path)
                .collect();
            reasons.push(format!("the targets changed: {}", changed.join(", ")));
        }
        if env.signed.get("delegations") != Some(&delegations) {
            reasons.push("the delegations to the publishers changed".to_owned());
        }
        if verify_role(&env, &root, Role::Targets, "the targets").is_err() {
            reasons.push(format!(
                "targets {last_targets} of tuf/v2 is not signed by the keys of its root {} (a \
                 key was rotated)",
                root.version
            ));
        }
    }
    if reasons.is_empty() && options.refresh {
        reasons.push("refresh: new expiry, same targets".to_owned());
    }
    if reasons.is_empty() {
        return Ok(V2Outcome::UpToDate {
            targets: last_targets,
        });
    }

    let targets_keys = signers(options.keys, &root, Role::Targets, unlock)?;
    let version = next_version("targets of tuf/v2", last_targets)?;
    let expires = expiry(options.now, TARGETS_DAYS);
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    let mut signed = build::targets(version, expires, &refs)
        .map_err(|e| anyhow::anyhow!("making the targets: {e}"))?;
    let Some(members) = signed.as_object_mut() else {
        bail!("the targets made are not an object");
    };
    members.insert("delegations".to_owned(), delegations);
    // What the client of `tuf/v2` reads, every delegation keeping the profile.
    let made = Targets::from_signed(&signed, Profile::Delegating)
        .map_err(|e| anyhow::anyhow!("the targets made do not read back: {e}"))?;
    let delegated = match made
        .delegations()
        .map_err(|e| anyhow::anyhow!("the delegations made do not read back: {e}"))?
    {
        Some(d) => {
            if let Some(Err(refused)) = d.roles().iter().find(|r| r.is_err()) {
                bail!(
                    "the delegation to {} breaks the profile: {}",
                    refused.name,
                    refused.error
                );
            }
            d.roles().len()
        }
        None => bail!("the targets made have no delegations"),
    };
    let targets_file = build::sign(&signed, &targets_keys.iter().collect::<Vec<_>>())
        .map_err(|e| anyhow::anyhow!("signing the targets: {e}"))?;
    let stored =
        build::target_files(&refs).map_err(|e| anyhow::anyhow!("laying out the targets: {e}"))?;

    let mut created: Vec<PathBuf> = Vec::new();
    let written = write_stored(options.out, &stored, &mut created).and_then(|()| {
        created.push(repo::write_new(
            options.out,
            &layout::targets_path(version),
            &targets_file,
        )?);
        Ok(())
    });
    let verdict = written.and_then(|()| {
        match check_v2::check(&check_v2::Options {
            dir: options.out,
            index: Some(options.index),
            publishers: Some(options.publishers),
            anchor: None,
            now: options.now,
            stage: Stage::Tree,
            expiry: Expiry {
                min_days: 0,
                min_root_days: 0,
                fail: false,
            },
            base: None,
        })? {
            check_v2::Outcome::Checked(report) if report.problems.is_empty() => Ok(()),
            check_v2::Outcome::Checked(report) => bail!(
                "tuf/v2 does not verify after the update:\n{}",
                list(&report.problems)
            ),
            check_v2::Outcome::NoRepository => bail!("tuf/v2 vanished"),
        }
    });
    if let Err(e) = verdict {
        let cleanup = remove_created(&created);
        return Err(e.context(format!("nothing was left written in tuf/v2{cleanup}")));
    }
    Ok(V2Outcome::Written(V2Written {
        reason: reasons.join("; "),
        targets: version,
        delegated,
        expires,
        files: created,
    }))
}

/// What [`update_both`] does.
pub struct BothOptions<'a> {
    /// The directory of the secret keys (of both repositories).
    pub keys: &'a Path,
    /// The directory of the indexes (`updates/v1`).
    pub index: &'a Path,
    /// `tuf/v1`.
    pub v1: &'a Path,
    /// `tuf/v2`; updated only if it has its root version 1.
    pub v2: &'a Path,
    /// The registry of the publishers (`publishers/`).
    pub publishers: &'a Path,
    /// Sign new versions even if nothing changed.
    pub refresh: bool,
    /// The signing time.
    pub now: OffsetDateTime,
    /// Where the passphrase of the keys comes from (asked once).
    pub passphrase: &'a PassphraseSource,
}

/// What [`update_both`] did.
#[derive(Debug)]
pub struct Both {
    /// `tuf/v1`.
    pub v1: Outcome,
    /// `tuf/v2`, if there is one.
    pub v2: Option<V2Outcome>,
}

/// [`update`] of `tuf/v1`, then [`update_v2`] of `tuf/v2` if it exists, then both verified
/// together ([`check_v2::cross`]). If anything fails, nothing this run wrote stays in either.
///
/// # Errors
///
/// The errors of [`update`] and [`update_v2`], and the problems [`check_v2::cross`] finds.
pub fn update_both(options: &BothOptions) -> anyhow::Result<Both> {
    let v2_options = V2Options {
        keys: options.keys,
        index: options.index,
        out: options.v2,
        v1: Some(options.v1),
        publishers: options.publishers,
        refresh: options.refresh,
        now: options.now,
        passphrase: options.passphrase,
    };
    let has_v2 = options.v2.join(layout::root_path(1)).is_file();
    // What tuf/v2 is made of is checked before anything is written in tuf/v1.
    if has_v2 {
        v2_inputs(&v2_options).context("tuf/v2 cannot be updated: nothing was written")?;
    }
    let mut unlock = Unlock::new(options.passphrase.clone(), "Passphrase of the TUF keys: ");
    let v1 = update_with(
        &Options {
            keys: options.keys,
            index: options.index,
            out: options.v1,
            refresh: options.refresh,
            now: options.now,
            passphrase: options.passphrase,
        },
        &mut unlock,
    )?;
    if !has_v2 {
        return Ok(Both { v1, v2: None });
    }
    let mut created: Vec<PathBuf> = match &v1 {
        Outcome::Written(w) => w.files.clone(),
        Outcome::UpToDate { .. } => Vec::new(),
    };
    let v2 = update_v2_with(&v2_options, &mut unlock);
    let together = v2.and_then(|v2| {
        if let V2Outcome::Written(w) = &v2 {
            created.extend(w.files.iter().cloned());
        }
        let problems = cross_check(options)?;
        if !problems.is_empty() {
            bail!(
                "tuf/v1 and tuf/v2 do not agree after the update:\n{}",
                list(&problems)
            );
        }
        Ok(v2)
    });
    match together {
        Ok(v2) => Ok(Both { v1, v2: Some(v2) }),
        Err(e) => {
            let cleanup = remove_created(&created);
            Err(e.context(format!(
                "nothing this run wrote was left in tuf/v1 or tuf/v2{cleanup}"
            )))
        }
    }
}

/// Both repositories verified as committed trees, and [`check_v2::cross`] over them.
fn cross_check(options: &BothOptions) -> anyhow::Result<Vec<super::Problem>> {
    let expiry = Expiry {
        min_days: 0,
        min_root_days: 0,
        fail: false,
    };
    let v1 = match check::check(&check::Options {
        dir: options.v1,
        index: Some(options.index),
        anchor: None,
        now: options.now,
        timestamp: TimestampMode::Absent,
        expiry,
        base: None,
    })? {
        check::Outcome::Checked(report) => report,
        check::Outcome::NoRepository => bail!("tuf/v1 vanished"),
    };
    let v2 = match check_v2::check(&check_v2::Options {
        dir: options.v2,
        index: Some(options.index),
        publishers: Some(options.publishers),
        anchor: None,
        now: options.now,
        stage: Stage::Tree,
        expiry,
        base: None,
    })? {
        check_v2::Outcome::Checked(report) => report,
        check_v2::Outcome::NoRepository => bail!("tuf/v2 vanished"),
    };
    let mut problems = v1.problems;
    problems.extend(v2.problems);
    if let (Some(a), Some(b)) = (&v1.verified, &v2.verified) {
        let v1_roots = check::committed_chain(options.v1)?;
        problems.extend(check_v2::cross(a, &v1_roots, b).0);
    }
    Ok(problems)
}
