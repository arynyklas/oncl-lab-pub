//! LAB ONLY (throwaway test repository of the publisher-catalog gate, never in OpenNCALayer):
//! the G12 fixtures `cargo xtask` refuses to write, and a snapshot and timestamp signed over
//! them. Runs on a publication copy of `tuf/v1`, never on the committed tree.
//!
//! - `foreign-role`: the next version of a publisher's role, signed by a fresh key that no
//!   delegation names (the client: "a publisher's role is refused" / "a kept publisher's role
//!   does not hold").
//! - `bad-delegations`: the next top-level targets, signed by the real targets key, whose
//!   `delegations` member cannot be read ("cannot read the publishers' delegations; every
//!   publisher is unavailable"); the indexes stay listed, so the core keeps updating.
//! - `sign`: snapshot and timestamp of the copy, without the checks of `tuf snapshot` and
//!   `tuf timestamp` (they refuse the fixtures, and later the repair over them): the previous
//!   published snapshot is kept beside, its meta carried over, every newest file listed, no
//!   version lowered.
//!
//! `cargo run -p xtask --example lab_forge -- <command> …`

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use oncl_update::tuf::build;
use oncl_update::tuf::layout;
use oncl_update::tuf::{Envelope, RoleName, SigningKey};
use serde_json::{Value, json};
use sha2::Digest as _;
use time::OffsetDateTime;
use xtask::tuf::keystore;
use xtask::tuf::repo::Listing;

const MAX_FILE: u64 = 16 << 20;
const SEED_PREFIX: &str = "oncl-tuf-ed25519-seed-v1:";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// The next version of ROLE in the copy, signed by a key nobody delegated to.
    ForeignRole {
        #[arg(long)]
        copy: PathBuf,
        /// `pub-<publisher>`.
        #[arg(long)]
        role: String,
        #[arg(long, default_value_t = 14)]
        days: i64,
    },
    /// The next top-level targets of the copy with an unreadable `delegations`.
    BadDelegations {
        #[arg(long)]
        copy: PathBuf,
        /// The targets key (encrypted, or a seed line).
        #[arg(long)]
        targets_key: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long, default_value_t = 30)]
        days: i64,
    },
    /// Snapshot and timestamp of the copy.
    Sign {
        #[arg(long)]
        copy: PathBuf,
        /// The `tuf/v1` published last (a local mirror: the gh-pages clone), if any.
        #[arg(long)]
        previous: Option<PathBuf>,
        #[arg(long)]
        snapshot_key: PathBuf,
        #[arg(long)]
        timestamp_key: PathBuf,
        /// For an encrypted (offline) snapshot key.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long, default_value_t = 7)]
        snapshot_days: i64,
        #[arg(long, default_value_t = 7)]
        timestamp_days: i64,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::ForeignRole { copy, role, days } => foreign_role(&copy, &role, days),
        Command::BadDelegations {
            copy,
            targets_key,
            passphrase_file,
            days,
        } => bad_delegations(&copy, &targets_key, passphrase_file.as_deref(), days),
        Command::Sign {
            copy,
            previous,
            snapshot_key,
            timestamp_key,
            passphrase_file,
            snapshot_days,
            timestamp_days,
        } => sign(
            &copy,
            previous.as_deref(),
            &snapshot_key,
            &timestamp_key,
            passphrase_file.as_deref(),
            snapshot_days,
            timestamp_days,
        ),
    }
}

fn now() -> OffsetDateTime {
    xtask::tuf::whole_seconds(OffsetDateTime::now_utc())
}

/// `YYYY-MM-DDTHH:MM:SSZ`, as the repository writes `expires`.
fn expires(days: i64) -> String {
    let t = now() + time::Duration::days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn meta_entry(version: u64, file: &[u8]) -> Value {
    json!({
        "version": version,
        "length": file.len(),
        "hashes": {"sha256": hex(&sha2::Sha256::digest(file))},
    })
}

fn read_signed(path: &Path) -> anyhow::Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let envelope = Envelope::parse(&bytes, MAX_FILE, "a metadata file")
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(envelope.signed)
}

fn write_file(dir: &Path, rel: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let path = dir.join(rel);
    fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
    println!("lab_forge: wrote {}", path.display());
    Ok(())
}

fn set_version(signed: &mut Value, version: u64, expires: String) -> anyhow::Result<()> {
    let Some(map) = signed.as_object_mut() else {
        bail!("signed is not an object");
    };
    map.insert("version".into(), json!(version));
    map.insert("expires".into(), json!(expires));
    Ok(())
}

/// A key file: a seed line, or an encrypted key and its passphrase.
fn load_key(path: &Path, passphrase_file: Option<&Path>) -> anyhow::Result<SigningKey> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if text.trim_start().starts_with(SEED_PREFIX) {
        return keystore::parse_seed(&text);
    }
    let Some(file) = passphrase_file else {
        bail!("{} is encrypted: --passphrase-file", path.display());
    };
    let pass = fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    keystore::load_encrypted(path, pass.lines().next().unwrap_or_default())
}

fn foreign_role(copy: &Path, role: &str, days: i64) -> anyhow::Result<()> {
    let role = RoleName::parse(role).map_err(|e| anyhow::anyhow!("{role}: {e}"))?;
    let listing = Listing::read(copy)?;
    let Some(&newest) = listing.newest_roles().get(&role) else {
        bail!("{} has no file of {role}", copy.display());
    };
    let mut signed = read_signed(&copy.join(layout::delegated_path(newest, &role)))?;
    set_version(&mut signed, newest + 1, expires(days))?;
    let (key, _) = keystore::generate_seed()?;
    println!("lab_forge: {role} {} signed by the foreign key {}", newest + 1, key.key_id().to_hex());
    let file = build::sign(&signed, &[&key]).map_err(|e| anyhow::anyhow!("{e}"))?;
    write_file(copy, &layout::delegated_path(newest + 1, &role), &file)
}

fn bad_delegations(
    copy: &Path,
    key: &Path,
    passphrase_file: Option<&Path>,
    days: i64,
) -> anyhow::Result<()> {
    let (_, targets, _) = Listing::read(copy)?.highest();
    if targets == 0 {
        bail!("{} has no targets", copy.display());
    }
    let mut signed = read_signed(&copy.join(layout::targets_path(targets)))?;
    set_version(&mut signed, targets + 1, expires(days))?;
    signed
        .as_object_mut()
        .context("targets")?
        .insert("delegations".into(), json!({"keys": "lab-g12: unreadable", "roles": 1}));
    let key = load_key(key, passphrase_file)?;
    let file = build::sign(&signed, &[&key]).map_err(|e| anyhow::anyhow!("{e}"))?;
    write_file(copy, &layout::targets_path(targets + 1), &file)
}

fn sign(
    copy: &Path,
    previous: Option<&Path>,
    snapshot_key: &Path,
    timestamp_key: &Path,
    passphrase_file: Option<&Path>,
    snapshot_days: i64,
    timestamp_days: i64,
) -> anyhow::Result<()> {
    // The snapshot published last: kept beside the new one; its meta carried over.
    let mut prev: Option<(u64, Value, u64)> = None;
    if let Some(dir) = previous.filter(|d| d.join(layout::TIMESTAMP_PATH).is_file()) {
        let ts = read_signed(&dir.join(layout::TIMESTAMP_PATH))?;
        let version = ts["meta"]["snapshot.json"]["version"]
            .as_u64()
            .context("the published timestamp lists no snapshot version")?;
        let ts_version = ts["version"].as_u64().unwrap_or(0);
        let rel = layout::snapshot_path(version);
        let bytes = fs::read(dir.join(&rel)).with_context(|| format!("reading the published {rel}"))?;
        if !copy.join(&rel).exists() {
            write_file(copy, &rel, &bytes)?;
        }
        prev = Some((version, read_signed(&dir.join(&rel))?, ts_version));
    }
    let listing = Listing::read(copy)?;
    let (_, targets, newest_snapshot) = listing.highest();
    if targets == 0 {
        bail!("{} has no targets", copy.display());
    }
    let base = match &prev {
        Some((_, signed, _)) => signed.clone(),
        None if newest_snapshot > 0 => read_signed(&copy.join(layout::snapshot_path(newest_snapshot)))?,
        None => json!({"_type": "snapshot", "spec_version": "1.0.31", "meta": {}}),
    };
    let mut signed = base;
    let meta = signed
        .get_mut("meta")
        .and_then(Value::as_object_mut)
        .context("the snapshot has no meta")?;
    let targets_file = fs::read(copy.join(layout::targets_path(targets)))?;
    let mut lowered = Vec::new();
    let mut put = |name: String, version: u64, file: &[u8]| {
        if let Some(old) = meta.get(&name).and_then(|e| e["version"].as_u64()) {
            if old > version {
                lowered.push(format!("{name} {old} -> {version}"));
            }
        }
        meta.insert(name, meta_entry(version, file));
    };
    put("targets.json".into(), targets, &targets_file);
    for (role, version) in listing.newest_roles() {
        let file = fs::read(copy.join(layout::delegated_path(version, &role)))?;
        put(format!("{role}.json"), version, &file);
    }
    if !lowered.is_empty() {
        bail!("the new snapshot would lower {} (bump the tree first)", lowered.join(", "));
    }
    let unix = u64::try_from(now().unix_timestamp()).unwrap_or(0);
    let prev_version = prev.as_ref().map_or(0, |p| p.0).max(newest_snapshot);
    let version = unix.max(prev_version + 1);
    set_version(&mut signed, version, expires(snapshot_days))?;
    let key = load_key(snapshot_key, passphrase_file)?;
    let snapshot_file = build::sign(&signed, &[&key]).map_err(|e| anyhow::anyhow!("{e}"))?;
    write_file(copy, &layout::snapshot_path(version), &snapshot_file)?;

    let ts_version = unix.max(prev.as_ref().map_or(0, |p| p.2) + 1);
    let ts_expires = now() + time::Duration::days(timestamp_days);
    let ts = build::timestamp(ts_version, ts_expires, version, &snapshot_file)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let key = load_key(timestamp_key, None)?;
    let file = build::sign(&ts, &[&key]).map_err(|e| anyhow::anyhow!("{e}"))?;
    write_file(copy, layout::TIMESTAMP_PATH, &file)?;
    println!("lab_forge: snapshot {version} (targets {targets}), timestamp {ts_version}");
    Ok(())
}
