//! `cargo xtask tuf init`: the owner's ceremony. Makes the keys of the four roles and root
//! version 1, signed by the root key, and a copy of it as the client's trust anchor.
//!
//! [`init_v2`] is the ceremony of `tuf/v2` (`docs/design/publishers.md`, "Онлайн-снимок
//! v2"): a new root key (encrypted), online snapshot and timestamp keys (one line each, for
//! the GitHub secrets `TUF_V2_SNAPSHOT_KEY` and `TUF_V2_TIMESTAMP_KEY`), and the targets key
//! of `tuf/v1`'s root in force, which the two repositories share; no secret of `tuf/v1` is
//! needed.
//!
//! Nothing existing is overwritten, and everything is made in memory before the first file
//! is written. The files are a function of the keys and `now`.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::build::{self, RoleDef, RootDef};
use oncl_update::tuf::{KeyId, Limits, MemoryStore, Role, TufClient, layout};

use super::keystore;
use super::repo::{self, DirFetcher, Layout};
use super::{PassphraseSource, ROOT_DAYS, expiry};
use super::{check, check_v2};

/// What [`init`] does.
pub struct Options<'a> {
    /// Where the secret keys are written, outside the repository (or git-ignored).
    pub keys: &'a Path,
    /// The repository directory (`tuf/v1`).
    pub out: &'a Path,
    /// The trust anchor file the client embeds.
    pub anchor: &'a Path,
    /// The signing time.
    pub now: time::OffsetDateTime,
    /// Where the passphrase of the encrypted keys comes from (asked twice when prompted).
    pub passphrase: &'a PassphraseSource,
}

/// What [`init`] made.
#[derive(Debug)]
pub struct Initialized {
    /// The key ids, by what they are for: `root`, `targets`, `snapshot`,
    /// `timestamp`.
    pub key_ids: Vec<(&'static str, KeyId)>,
    /// The secret key files.
    pub key_files: Vec<PathBuf>,
    /// `metadata/1.root.json` in the repository.
    pub root: PathBuf,
    /// The trust anchor.
    pub anchor: PathBuf,
}

/// Makes the keys and root version 1.
///
/// # Errors
///
/// If any file to write exists already, a key file would be committable, or writing fails.
pub fn init(options: &Options) -> anyhow::Result<Initialized> {
    // Everything that may refuse comes before anything is made or written.
    let names: Vec<(&'static str, String)> = vec![
        ("root", keystore::file_name(Role::Root, None)),
        ("targets", keystore::file_name(Role::Targets, None)),
        ("snapshot", keystore::file_name(Role::Snapshot, None)),
        ("timestamp", keystore::file_name(Role::Timestamp, None)),
    ];
    for (_, name) in &names {
        keystore::key_path(options.keys, name)?;
    }
    let root_path = layout::root_path(1);
    for existing in [options.out.join(&root_path), options.anchor.to_owned()] {
        if existing.exists() {
            bail!(
                "{} exists already; refusing to overwrite it",
                existing.display()
            );
        }
    }

    let passphrase = options.passphrase.get_new("Passphrase of the new keys: ")?;
    let (root_key, root_text) = keystore::generate_encrypted(Role::Root, &passphrase)?;
    let (targets_key, targets_text) = keystore::generate_encrypted(Role::Targets, &passphrase)?;
    let (snapshot_key, snapshot_text) = keystore::generate_encrypted(Role::Snapshot, &passphrase)?;
    let (timestamp_key, timestamp_line) = keystore::generate_seed()?;
    let def = RootDef {
        root: RoleDef {
            keys: vec![root_key.public()],
            threshold: 1,
        },
        timestamp: RoleDef {
            keys: vec![timestamp_key.public()],
            threshold: 1,
        },
        snapshot: RoleDef {
            keys: vec![snapshot_key.public()],
            threshold: 1,
        },
        targets: RoleDef {
            keys: vec![targets_key.public()],
            threshold: 1,
        },
    };
    let signed = build::root(1, expiry(options.now, ROOT_DAYS), &def)
        .map_err(|e| anyhow::anyhow!("making the root: {e}"))?;
    let file =
        build::sign(&signed, &[&root_key]).map_err(|e| anyhow::anyhow!("signing the root: {e}"))?;
    // What the client will do with the anchor: read it and check its own signature.
    TufClient::new(
        &file,
        DirFetcher::new(options.out),
        MemoryStore::default(),
        Limits::default(),
    )
    .map_err(|e| anyhow::anyhow!("the root just made is not usable as an anchor: {e}"))?;

    let mut key_files = Vec::new();
    let key_ids = vec![
        ("root", root_key.key_id()),
        ("targets", targets_key.key_id()),
        ("snapshot", snapshot_key.key_id()),
        ("timestamp", timestamp_key.key_id()),
    ];
    key_files.push(keystore::write_key_file(
        options.keys,
        &names[0].1,
        &root_text,
    )?);
    key_files.push(keystore::write_key_file(
        options.keys,
        &names[1].1,
        &targets_text,
    )?);
    key_files.push(keystore::write_key_file(
        options.keys,
        &names[2].1,
        &snapshot_text,
    )?);
    key_files.push(keystore::write_key_file(
        options.keys,
        &names[3].1,
        &timestamp_line,
    )?);

    let root = repo::write_new(options.out, &root_path, &file)
        .context("the keys are written; the repository is not")?;
    if let Some(parent) = options.anchor.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    crate::files::write_new(options.anchor, &file, false)
        .context("the keys and the root are written; the trust anchor is not")?;
    Ok(Initialized {
        key_ids,
        key_files,
        root,
        anchor: options.anchor.to_owned(),
    })
}

/// What [`init_v2`] does.
pub struct V2Options<'a> {
    /// Where the secret keys are written, outside the repository (or git-ignored); the
    /// directory of the keys of `tuf/v1` will do.
    pub keys: &'a Path,
    /// The repository directory (`tuf/v2`).
    pub out: &'a Path,
    /// `tuf/v1`, whose root in force names the shared targets key.
    pub v1: &'a Path,
    /// A copy of root version 1 to write as a trust anchor, if any.
    pub anchor: Option<&'a Path>,
    /// The signing time.
    pub now: time::OffsetDateTime,
    /// Where the passphrase of the encrypted root key comes from (asked twice when
    /// prompted).
    pub passphrase: &'a PassphraseSource,
}

/// Makes the keys of `tuf/v2` and its root version 1 (see the module's description).
///
/// # Errors
///
/// If `tuf/v1` has no chain of roots, any file to write exists already, a key file would be
/// committable, or writing fails.
pub fn init_v2(options: &V2Options) -> anyhow::Result<Initialized> {
    let v1_chain = check::committed_chain(options.v1)
        .context("tuf/v2 shares the targets key of tuf/v1: tuf/v1 must be there first")?;
    let Some(v1_root) = v1_chain.last() else {
        bail!("tuf/v1 has no root");
    };
    let names = [Role::Root, Role::Snapshot, Role::Timestamp]
        .map(|role| keystore::file_name_in(Layout::V2, role, None));
    for name in &names {
        keystore::key_path(options.keys, name)?;
    }
    let root_path = layout::root_path(1);
    let mut existing = vec![options.out.join(&root_path)];
    existing.extend(options.anchor.map(Path::to_owned));
    for path in existing {
        if path.exists() {
            bail!(
                "{} exists already; refusing to overwrite it",
                path.display()
            );
        }
    }

    let passphrase = options
        .passphrase
        .get_new("Passphrase of the new root key: ")?;
    let (root_key, root_text) = keystore::generate_encrypted(Role::Root, &passphrase)?;
    let (snapshot_key, snapshot_line) = keystore::generate_seed()?;
    let (timestamp_key, timestamp_line) = keystore::generate_seed()?;
    let targets = v1_root.role(Role::Targets);
    let def = RootDef {
        root: RoleDef {
            keys: vec![root_key.public()],
            threshold: 1,
        },
        timestamp: RoleDef {
            keys: vec![timestamp_key.public()],
            threshold: 1,
        },
        snapshot: RoleDef {
            keys: vec![snapshot_key.public()],
            threshold: 1,
        },
        targets: check::role_def(v1_root, Role::Targets)?,
    };
    let signed = build::root(1, expiry(options.now, ROOT_DAYS), &def)
        .map_err(|e| anyhow::anyhow!("making the root: {e}"))?;
    // No key of any root of tuf/v1 serves tuf/v2, but the targets key, as targets in both.
    let new_root = oncl_update::tuf::Root::from_signed(&signed)
        .map_err(|e| anyhow::anyhow!("the root made does not read back: {e}"))?;
    let shared = check_v2::shared_keys(&v1_chain, std::slice::from_ref(&new_root));
    if !shared.is_empty() {
        bail!(
            "the root of tuf/v2 would share keys with tuf/v1: {}",
            shared
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let file =
        build::sign(&signed, &[&root_key]).map_err(|e| anyhow::anyhow!("signing the root: {e}"))?;
    TufClient::new(
        &file,
        DirFetcher::new(options.out),
        MemoryStore::default(),
        Limits::default(),
    )
    .map_err(|e| anyhow::anyhow!("the root just made is not usable as an anchor: {e}"))?;

    let mut key_ids = vec![
        ("root", root_key.key_id()),
        ("snapshot (online)", snapshot_key.key_id()),
        ("timestamp (online)", timestamp_key.key_id()),
    ];
    key_ids.extend(targets.keyids.iter().map(|id| ("targets (of tuf/v1)", *id)));
    let mut key_files = Vec::new();
    for (name, text) in names
        .iter()
        .zip([&root_text, &snapshot_line, &timestamp_line])
    {
        key_files.push(keystore::write_key_file(options.keys, name, text)?);
    }
    let root = repo::write_new(options.out, &root_path, &file)
        .context("the keys are written; the repository is not")?;
    let anchor = match options.anchor {
        Some(anchor) => {
            if let Some(parent) = anchor.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            crate::files::write_new(anchor, &file, false)
                .context("the keys and the root are written; the trust anchor is not")?;
            anchor.to_owned()
        }
        None => root.clone(),
    };
    Ok(Initialized {
        key_ids,
        key_files,
        root,
        anchor,
    })
}
