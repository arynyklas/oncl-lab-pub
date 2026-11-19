//! `cargo xtask tuf root`: the next root, version N+1: a renewal (the root expires after 365
//! days) or a rotation of the key of any role (`docs/design/tuf.md`, "Ротация и
//! компрометация").
//!
//! The new root is signed by the keys of the root in force (the threshold of its root role)
//! and, when the root key itself is rotated, also by the new root key: a client needs both
//! for each new version. New keys are written next to the old ones as `<role>.v<N>.key`; the
//! old files stay (the old root key is what signed this root; keep it until the chain is
//! published). Roles that are not rotated keep their keys and thresholds; a rotated role
//! gets one new key with threshold 1.
//!
//! A new root that rotates the targets key, or the snapshot key while the snapshot is
//! offline, leaves the committed targets and snapshot signed by keys no longer in force:
//! `tuf update` notices and signs new versions (`--refresh` is not needed). A new timestamp
//! key is for the GitHub secret.
//!
//! `online` moves the snapshot key into CI (`docs/design/publishers.md`, "Онлайн-снимок",
//! Р8): it goes with `rotate_snapshot`, the new snapshot key is an online line for the
//! secret `TUF_SNAPSHOT_KEY`, and `tuf/v1.toml` is written with `snapshot = "online"`.
//! Once the snapshot is online, every new snapshot key is such a line.
//!
//! Everything is made in memory, the new keys are written, then the root; the chain of
//! roots is verified with the client's code, and the root and the new keys are removed
//! again if it does not hold.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::build::{self, RoleDef, RootDef};
use oncl_update::tuf::{KeyId, Role, SigningKey, layout};
use time::{Duration, OffsetDateTime};

use super::check;
use super::keystore::{self, Unlock};
use super::repo::{self, SnapshotMode};
use super::{PassphraseSource, ROOT_DAYS, expiry, next_version, remove_created};

/// What [`root`] does.
pub struct Options<'a> {
    /// The directory of the secret keys.
    pub keys: &'a Path,
    /// The repository directory (`tuf/v1`).
    pub out: &'a Path,
    /// The file of its snapshot mode (`tuf/v1.toml`).
    pub config: &'a Path,
    /// Replace the root key.
    pub rotate_root: bool,
    /// Replace the targets key.
    pub rotate_targets: bool,
    /// Replace the snapshot key.
    pub rotate_snapshot: bool,
    /// Replace the timestamp key.
    pub rotate_timestamp: bool,
    /// Make the new snapshot key an online key and the snapshot online (with
    /// `rotate_snapshot`).
    pub online: bool,
    /// The signing time.
    pub now: OffsetDateTime,
    /// Where the passphrase of the keys comes from (the old keys are opened with it, and
    /// the new encrypted ones made with it).
    pub passphrase: &'a PassphraseSource,
}

/// What [`root`] made.
#[derive(Debug)]
pub struct Rotated {
    /// The new root version.
    pub version: u64,
    /// `metadata/<N>.root.json`.
    pub root: PathBuf,
    /// When it expires.
    pub expires: OffsetDateTime,
    /// The new keys: role, id and file.
    pub new_keys: Vec<(Role, KeyId, PathBuf)>,
    /// The snapshot mode after the new root.
    pub mode: SnapshotMode,
    /// The file of the snapshot mode, if this run wrote it (`online` moved the snapshot
    /// online).
    pub config: Option<PathBuf>,
}

/// Makes the next root (see the module's description).
///
/// # Errors
///
/// If `online` comes without `rotate_snapshot`, the repository is not a chain of roots, the
/// keys of the root in force cannot be found or opened, a new key file exists, or the new
/// chain does not verify (the root and the new keys are then removed again).
pub fn root(options: &Options) -> anyhow::Result<Rotated> {
    if options.online && !options.rotate_snapshot {
        bail!(
            "--online moves the snapshot key into CI: it goes with --rotate-snapshot, which \
             makes that key"
        );
    }
    let before = repo::read_mode(options.config)?;
    let mode = if options.online {
        SnapshotMode::Online
    } else {
        before
    };
    let anchor = repo::read(options.out, &layout::root_path(1))
        .context("the repository has no root version 1: run `cargo xtask tuf init` first")?;
    // The root in force may have expired: renewing it is what this is for, so the chain is
    // followed with a clock at the start of time (signatures and thresholds are what it
    // verifies; the expiry of the root in force is the owner's to see).
    let old = check::final_root(
        options.out,
        &anchor,
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(1),
    )?;
    let version = next_version("root", old.version)?;

    let rotated = [
        (Role::Root, options.rotate_root),
        (Role::Targets, options.rotate_targets),
        (Role::Snapshot, options.rotate_snapshot),
        (Role::Timestamp, options.rotate_timestamp),
    ];
    // What may refuse comes before anything is made.
    for (role, rotate) in rotated {
        if rotate {
            keystore::key_path(options.keys, &keystore::file_name(role, Some(version)))?;
        }
    }
    let target = options.out.join(layout::root_path(version));
    if target.exists() {
        bail!(
            "{} exists already; refusing to overwrite it",
            target.display()
        );
    }

    let mut unlock = Unlock::new(options.passphrase.clone(), "Passphrase of the TUF keys: ");
    let old_signers = {
        let keys = keystore::find_keys(options.keys, Role::Root, &old.root.keyids, &mut unlock)?;
        let need = old.root.threshold as usize;
        if keys.len() < need {
            bail!(
                "root {} needs {need} root keys to sign the next one, {} are in {}",
                old.version,
                keys.len(),
                options.keys.display()
            );
        }
        keys.into_iter().take(need).collect::<Vec<_>>()
    };

    // New keys, in memory.
    let mut fresh: Vec<(Role, SigningKey, zeroize::Zeroizing<String>)> = Vec::new();
    for (role, rotate) in rotated {
        if !rotate {
            continue;
        }
        let (key, text) = if keystore::is_online(mode, role) {
            keystore::generate_seed()?
        } else {
            keystore::generate_encrypted(role, unlock.passphrase()?)?
        };
        fresh.push((role, key, text));
    }
    let role_def = |role: Role| -> anyhow::Result<RoleDef> {
        if let Some((_, key, _)) = fresh.iter().find(|(r, _, _)| *r == role) {
            return Ok(RoleDef {
                keys: vec![key.public()],
                threshold: 1,
            });
        }
        check::role_def(&old, role)
    };
    let def = RootDef {
        root: role_def(Role::Root)?,
        timestamp: role_def(Role::Timestamp)?,
        snapshot: role_def(Role::Snapshot)?,
        targets: role_def(Role::Targets)?,
    };
    let expires = expiry(options.now, ROOT_DAYS);
    let signed =
        build::root(version, expires, &def).map_err(|e| anyhow::anyhow!("making the root: {e}"))?;
    let old_refs: Vec<&SigningKey> = old_signers.iter().collect();
    let mut file =
        build::sign(&signed, &old_refs).map_err(|e| anyhow::anyhow!("signing the root: {e}"))?;
    if let Some((_, new_root_key, _)) = fresh.iter().find(|(r, _, _)| *r == Role::Root) {
        file = build::add_signatures(&file, &[new_root_key])
            .map_err(|e| anyhow::anyhow!("signing the root with the new root key: {e}"))?;
    }

    let mut new_keys = Vec::new();
    for (role, key, text) in &fresh {
        let path = keystore::write_key_file(
            options.keys,
            &keystore::file_name(*role, Some(version)),
            text,
        )?;
        new_keys.push((*role, key.key_id(), path));
    }
    let path = repo::write_new(options.out, &layout::root_path(version), &file)?;
    let verified = check::final_root(
        options.out,
        &anchor,
        options.now.min(expires - Duration::seconds(1)),
    );
    let checked = match verified {
        Ok(r) if r.version == version => Ok(()),
        Ok(r) => Err(anyhow::anyhow!("the chain ends at root {}", r.version)),
        Err(e) => Err(e),
    };
    // The snapshot goes online with the root that names its online key, in the same change.
    let config = checked.and_then(|()| {
        if mode == before {
            return Ok(None);
        }
        std::fs::write(options.config, repo::mode_file(mode))
            .with_context(|| format!("writing {}", options.config.display()))?;
        Ok(Some(options.config.to_owned()))
    });
    let config = match config {
        Ok(config) => config,
        Err(e) => {
            // The new keys go with the root: a retry must not meet them as existing files.
            let mut made = vec![path.clone()];
            made.extend(new_keys.iter().map(|(_, _, file)| file.clone()));
            let cleanup = remove_created(&made);
            bail!(
                "the chain of roots does not verify with root {version}, or the snapshot mode \
                 could not be written (the root and the new key files were removed{cleanup}): \
                 {e:#}"
            );
        }
    };
    Ok(Rotated {
        version,
        root: path,
        expires,
        new_keys,
        mode,
        config,
    })
}
