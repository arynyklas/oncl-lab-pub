//! `cargo xtask tuf init`: the owner's ceremony. Makes the keys of the four roles and root
//! version 1, signed by the root key, and a copy of it as the client's trust anchor. The
//! snapshot starts offline (no `tuf/v1.toml`).
//!
//! Nothing existing is overwritten, and everything is made in memory before the first file
//! is written. The files are a function of the keys and `now`.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::build::{self, RoleDef, RootDef};
use oncl_update::tuf::{KeyId, Limits, MemoryStore, Role, TufClient, layout};

use super::keystore;
use super::repo::{self, DirFetcher};
use super::{PassphraseSource, ROOT_DAYS, expiry};

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
