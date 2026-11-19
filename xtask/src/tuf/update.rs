//! `cargo xtask tuf update`: new top-level targets (and, while the snapshot is offline, a new
//! snapshot) over the update indexes and the publishers, signed with the owner's keys.
//!
//! The indexes (`updates/v1/{stable,beta}.json`) are copied byte for byte to
//! `targets/indexes/<sha256>.<channel>.json` and listed by `metadata/<N+1>.targets.json`.
//! Once `publishers/` has an entry ([`crate::publishers`]), the targets also list
//! `publishers.json` and delegate to the active publishers (`docs/design/publishers.md`,
//! "Делегирование в верхнем targets"); without one they have neither, as for the clients
//! released before delegations. While the snapshot is offline (`tuf/v1.toml`),
//! `metadata/<N+1>.snapshot.json` lists the new targets and the newest file of every
//! publisher's role; once it is online, CI signs it ([`super::snapshot`]) and this writes
//! none. Versions only grow, by one over the highest committed. The timestamp is not
//! touched: CI signs it when Pages is published.
//!
//! Before anything is signed, `publishers/` is settled ([`Registry::settle`]): a publisher
//! moved to `retired` keeps the revocations of its role, and `revoke_all` becomes explicit
//! revoked versions, written into its `publisher.toml`. Then the registry is checked against
//! the roots, the indexes, the newest role files (Р24: a publisher's key goes only after the
//! role is re-signed without it) and every signed `publishers.json` (Р28: no entry goes).
//!
//! A run with nothing to change writes nothing (so the owner is not asked for a passphrase
//! either). `refresh` signs new versions anyway, with the same targets: the monthly job that
//! pushes the expiry forward. After a rotation of the targets key, or of the snapshot key
//! while the snapshot is offline, the committed files are not signed by the keys in force,
//! which is "something to change" too.
//!
//! The result is verified before the run ends, with the client's code ([`super::check`]);
//! if it does not hold, what was written is removed again and the publishers' files are
//! restored.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::build;
use oncl_update::tuf::ed25519::verify_role;
use oncl_update::tuf::{
    Digest, Envelope, Limits, Profile, Role, RoleName, Root, SigningKey, Snapshot, Targets, layout,
};
use oncl_update::{Channel, Index, MAX_INDEX_LEN};
use serde_json::Value;
use time::OffsetDateTime;

use super::check::{self, Expiry, Stage};
use super::keystore::{self, Unlock};
use super::repo::{self, Kind, Listing, SnapshotMode};
use super::snapshot::meta_entry;
use super::{PassphraseSource, SNAPSHOT_DAYS, TARGETS_DAYS, expiry, next_version, remove_created};
use crate::publishers::{self, Registry, Settled, parse_publisher};

/// What [`update`] does.
pub struct Options<'a> {
    /// The directory of the secret keys.
    pub keys: &'a Path,
    /// The directory of the indexes (`updates/v1`).
    pub index: &'a Path,
    /// The repository directory (`tuf/v1`).
    pub out: &'a Path,
    /// The registry of the publishers (`publishers/`).
    pub publishers: &'a Path,
    /// Who signs the snapshot (`tuf/v1.toml`).
    pub mode: SnapshotMode,
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
    /// Nothing to change: the committed targets (and offline snapshot) already are the
    /// indexes and the publishers.
    UpToDate {
        /// The targets version in force.
        targets: u64,
        /// The offline snapshot version in force; `None` when the snapshot is online.
        snapshot: Option<u64>,
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
    /// The new snapshot version; `None` when the snapshot is online.
    pub snapshot: Option<u64>,
    /// How many publishers the targets delegate to; `None` without `delegations`.
    pub delegated: Option<usize>,
    /// When the targets (and the snapshot) expire.
    pub expires: OffsetDateTime,
    /// The files made, with the metadata last.
    pub files: Vec<PathBuf>,
    /// The `publisher.toml` files settled ([`Registry::settle`]), with the versions each
    /// gained.
    pub settled: Vec<Settled>,
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
    let targets = Targets::from_signed(&env.signed, Profile::Delegating)
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

/// `now` as a date in UTC, `YYYY-MM-DD`.
fn day(now: OffsetDateTime) -> String {
    let date = now.to_offset(time::UtcOffset::UTC).date();
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// The registry of `options.publishers` settled ([`Registry::settle`]) against the
/// repository and its newest targets `current`: the registry as it will be, and the files
/// to rewrite.
fn settled_registry(
    options: &Options,
    current: Option<&Targets>,
) -> anyhow::Result<(Registry, Vec<Settled>)> {
    let registry = Registry::read(options.publishers)?;
    let delegated: BTreeSet<RoleName> = match current.map(Targets::delegations).transpose() {
        Ok(found) => found
            .flatten()
            .iter()
            .flat_map(|d| d.roles())
            .filter_map(|role| role.as_ref().ok().map(|r| r.name().clone()))
            .collect(),
        Err(e) => bail!("the committed targets have delegations that do not read: {e}"),
    };
    let settled = registry.settle(
        options.publishers,
        options.out,
        &delegated,
        &day(options.now),
    )?;
    if settled.is_empty() {
        return Ok((registry, settled));
    }
    let mut all: BTreeMap<_, _> = registry
        .publishers()
        .map(|p| (p.name.clone(), p.clone()))
        .collect();
    for s in &settled {
        all.insert(
            s.name.clone(),
            parse_publisher(&s.after, s.name.as_str())
                .with_context(|| format!("{}", s.path.display()))?,
        );
    }
    Ok((Registry::new(all.into_values().collect())?, settled))
}

/// Signs new targets (and snapshot) over the indexes and the publishers (see the module's
/// description).
///
/// # Errors
///
/// If the repository, the indexes or the registry of the publishers are not usable, the
/// keys cannot be opened, or the result does not verify (then nothing stays written).
pub fn update(options: &Options) -> anyhow::Result<Outcome> {
    let offline = options.mode == SnapshotMode::Offline;
    let anchor = repo::read(options.out, &layout::root_path(1))
        .context("the repository has no root version 1: run `cargo xtask tuf init` first")?;
    let root = check::final_root(options.out, &anchor, options.now)?;
    let chain = check::committed_chain(options.out)?;
    let listing = Listing::read(options.out)?;
    let (_, last_targets, last_snapshot) = listing.highest();

    let indexes = read_indexes(options.index)?;
    if indexes.is_empty() {
        bail!("there is no update index in {}", options.index.display());
    }
    let parsed = indexes
        .iter()
        .map(|(_, bytes)| Index::from_json(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let current = if last_targets == 0 {
        None
    } else {
        Some(read_targets(options.out, last_targets)?)
    };

    // The publishers, settled and checked before anything is signed.
    let (registry, settled) = settled_registry(options, current.as_ref().map(|(_, t)| t))?;
    let roots: Vec<(&str, &Root)> = chain.iter().map(|r| ("tuf/v1", r)).collect();
    registry.check_roots(&roots)?;
    registry.check_indexes(&parsed)?;
    registry.check_newest_roles(options.out)?;
    for stored in &listing.target_files {
        if repo::classify(stored) == Kind::Publishers {
            registry
                .keeps(&repo::read(options.out, stored)?)
                .with_context(|| format!("{stored} names it"))?;
        }
    }
    let had_member = current
        .as_ref()
        .is_some_and(|(env, _)| env.signed.get("delegations").is_some());
    let (delegations, publishers_json) = if registry.is_empty() {
        if had_member {
            bail!(
                "targets {last_targets} delegate to publishers, but {} has none: an entry of \
                 publishers/ is never removed (Р28)",
                options.publishers.display()
            );
        }
        (None, None)
    } else {
        if !had_member && offline {
            bail!(
                "the first publisher waits for the online snapshot: while tuf/v1.toml says \
                 offline, every release of a publisher would wait for the owner's snapshot \
                 (docs/design/publishers.md, Р35); move the snapshot key into CI first \
                 (`cargo xtask tuf root --rotate-snapshot --online`)"
            );
        }
        (
            Some(registry.delegations()),
            Some(registry.publishers_json()?),
        )
    };
    let mut files = indexes;
    if let Some(json) = publishers_json {
        files.push((publishers::TARGET.to_owned(), json));
    }
    let wanted: BTreeMap<&str, (u64, Digest)> = files
        .iter()
        .map(|(path, bytes)| (path.as_str(), (bytes.len() as u64, Digest::of(bytes))))
        .collect();
    // The newest file of every role, for an offline snapshot.
    let mut roles: BTreeMap<RoleName, (u64, Vec<u8>)> = BTreeMap::new();
    if offline {
        for (name, version) in listing.newest_roles() {
            let bytes = repo::read(options.out, &layout::delegated_path(version, &name))?;
            roles.insert(name, (version, bytes));
        }
    }

    // What there is to do.
    let mut reasons: Vec<String> = Vec::new();
    match &current {
        None => reasons.push("the repository has no targets yet".to_owned()),
        Some((env, targets)) => {
            for path in targets.targets.keys() {
                if path.as_str().starts_with("indexes/") && !wanted.contains_key(path.as_str()) {
                    bail!(
                        "the targets list {path}, but its index file is not in {}: clients of \
                         that channel would be left without updates",
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
                let mut changed: Vec<&str> = wanted
                    .iter()
                    .filter(|(path, entry)| listed.get(*path) != Some(entry))
                    .map(|(path, _)| *path)
                    .collect();
                changed.extend(listed.keys().filter(|path| !wanted.contains_key(*path)));
                reasons.push(format!("the targets changed: {}", changed.join(", ")));
            }
            if env.signed.get("delegations") != delegations.as_ref() {
                reasons.push("the delegations to the publishers changed".to_owned());
            }
            if verify_role(env, &root, Role::Targets, "the targets").is_err() {
                reasons.push(format!(
                    "targets {last_targets} is not signed by the keys of root {} (a key was \
                     rotated)",
                    root.version
                ));
            }
        }
    }
    if offline {
        if last_snapshot == 0 {
            reasons.push("the repository has no snapshot yet".to_owned());
        } else {
            let (env, snapshot) = read_snapshot(options.out, last_snapshot)?;
            if verify_role(&env, &root, Role::Snapshot, "the snapshot").is_err() {
                reasons.push(format!(
                    "snapshot {last_snapshot} is not signed by the keys of root {} (a key was \
                     rotated)",
                    root.version
                ));
            }
            if snapshot.targets().version != last_targets {
                reasons.push(format!(
                    "snapshot {last_snapshot} lists targets {}, not {last_targets}",
                    snapshot.targets().version
                ));
            }
            for (name, (version, bytes)) in &roles {
                let meta = snapshot.meta.get(&name.meta_name());
                let same = meta.is_some_and(|m| {
                    m.version == *version
                        && m.length == Some(bytes.len() as u64)
                        && m.sha256 == Some(Digest::of(bytes))
                });
                if !same {
                    reasons.push(format!(
                        "snapshot {last_snapshot} does not list {name} {version}"
                    ));
                }
            }
        }
    }
    for s in &settled {
        reasons.push(format!("publishers/{}: {}", s.name, s.why));
    }
    if reasons.is_empty() && options.refresh {
        reasons.push("refresh: new expiry, same targets".to_owned());
    }
    if reasons.is_empty() {
        return Ok(Outcome::UpToDate {
            targets: last_targets,
            snapshot: offline.then_some(last_snapshot),
        });
    }

    // The keys of the roles in force.
    let mut unlock = Unlock::new(options.passphrase.clone(), "Passphrase of the TUF keys: ");
    let targets_keys = signers(options.keys, &root, Role::Targets, &mut unlock)?;
    let snapshot_keys = if offline {
        signers(options.keys, &root, Role::Snapshot, &mut unlock)?
    } else {
        Vec::new()
    };

    let targets_version = next_version("targets", last_targets)?;
    let expires = expiry(options.now, TARGETS_DAYS);
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    let mut signed = build::targets(targets_version, expires, &refs)
        .map_err(|e| anyhow::anyhow!("making the targets: {e}"))?;
    let delegated = match delegations {
        None => None,
        Some(delegations) => {
            let Some(members) = signed.as_object_mut() else {
                bail!("the targets made are not an object");
            };
            members.insert("delegations".to_owned(), delegations);
            // What the clients read, every delegation keeping the profile.
            let made = Targets::from_signed(&signed, Profile::Delegating)
                .map_err(|e| anyhow::anyhow!("the targets made do not read back: {e}"))?;
            let Some(read) = made
                .delegations()
                .map_err(|e| anyhow::anyhow!("the delegations made do not read back: {e}"))?
            else {
                bail!("the targets made have no delegations");
            };
            if let Some(Err(refused)) = read.roles().iter().find(|r| r.is_err()) {
                bail!(
                    "the delegation to {} breaks the profile: {}",
                    refused.name,
                    refused.error
                );
            }
            Some(read.roles().len())
        }
    };
    let targets_file = build::sign(&signed, &targets_keys.iter().collect::<Vec<_>>())
        .map_err(|e| anyhow::anyhow!("signing the targets: {e}"))?;
    let snapshot = if offline {
        let version = next_version("snapshot", last_snapshot)?;
        let mut signed = build::snapshot(
            version,
            expiry(options.now, SNAPSHOT_DAYS),
            targets_version,
            &targets_file,
        )
        .map_err(|e| anyhow::anyhow!("making the snapshot: {e}"))?;
        let Some(meta) = signed.get_mut("meta").and_then(Value::as_object_mut) else {
            bail!("the snapshot made has no meta");
        };
        for (name, (role_version, bytes)) in &roles {
            meta.insert(name.meta_name(), meta_entry(*role_version, bytes));
        }
        let file = build::sign(&signed, &snapshot_keys.iter().collect::<Vec<_>>())
            .map_err(|e| anyhow::anyhow!("signing the snapshot: {e}"))?;
        Some((version, file))
    } else {
        None
    };
    let stored =
        build::target_files(&refs).map_err(|e| anyhow::anyhow!("laying out the targets: {e}"))?;

    // Write: the settled publishers, the targets files (content-addressed: one that is
    // there already must be the same bytes), then the metadata. A failure undoes the run.
    let mut created: Vec<PathBuf> = Vec::new();
    let mut rewritten: Vec<&Settled> = Vec::new();
    let written = (|| -> anyhow::Result<()> {
        for s in &settled {
            rewritten.push(s);
            replace(&s.path, &s.after)?;
        }
        write_stored(options.out, &stored, &mut created)?;
        created.push(repo::write_new(
            options.out,
            &layout::targets_path(targets_version),
            &targets_file,
        )?);
        if let Some((version, file)) = &snapshot {
            created.push(repo::write_new(
                options.out,
                &layout::snapshot_path(*version),
                file,
            )?);
        }
        Ok(())
    })();
    let verdict = written.and_then(|()| {
        let report = check::check(&check::Options {
            dir: options.out,
            index: Some(options.index),
            publishers: Some(options.publishers),
            anchor: None,
            now: options.now,
            stage: Stage::Tree,
            mode: options.mode,
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
        let mut cleanup = remove_created(&created);
        for s in rewritten {
            if let Err(e) = replace(&s.path, &s.before) {
                cleanup.push_str(&format!(
                    "; could not restore: {} ({e:#})",
                    s.path.display()
                ));
            }
        }
        return Err(e.context(format!("nothing was left written{cleanup}")));
    }
    Ok(Outcome::Written(Written {
        reason: reasons.join("; "),
        targets: targets_version,
        snapshot: snapshot.map(|(version, _)| version),
        delegated,
        expires,
        files: created,
        settled,
    }))
}

/// Replaces the file `path` with `text`: written beside it, then renamed over it, so that it
/// is never left half written.
fn replace(path: &Path, text: &str) -> anyhow::Result<()> {
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    fs::write(&temp, text).with_context(|| format!("writing {}", temp.display()))?;
    fs::rename(&temp, path).with_context(|| format!("replacing {}", path.display()))
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
