//! The secret keys of the repository, on the owner's machine.
//!
//! - `root`, `targets` and `snapshot` keys are **encrypted**: a minisign secret key file
//!   (scrypt over the passphrase, a checksum that
//!   a wrong passphrase fails). A minisign secret key is an Ed25519 key pair; its 64-byte
//!   `sk` is the 32-byte seed followed by the public key, so decrypting it gives the seed
//!   `ring` builds the signing key from ([`oncl_update::tuf::SigningKey::from_seed`]), and
//!   the public key in the file must be the one the seed gives. The untrusted comment line
//!   names the role and the key id, only to pick the file; the key id that counts is the
//!   one computed from the decrypted seed.
//! - the `timestamp` key is **not** encrypted, one line `oncl-tuf-ed25519-seed-v1:<64 hex>`:
//!   it is pasted into the GitHub secret `TUF_TIMESTAMP_KEY` (an environment secret CI uses
//!   unattended), so a passphrase would protect nothing. Once the snapshot is online
//!   ([`SnapshotMode::Online`]) the `snapshot` key is such a line too (`TUF_SNAPSHOT_KEY`,
//!   `docs/design/publishers.md`, Р8).
//!
//! A key is picked by its id, never by its file name.
//!
//! Key files are written only where git would not commit them and never
//! over an existing file.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use minisign::{KeyPair, SecretKey};
use oncl_update::tuf::{KeyId, Role, SigningKey};
use zeroize::Zeroizing;

use super::PassphraseSource;
use super::repo::SnapshotMode;

/// The length of a serialized minisign secret key: signature algorithm, KDF algorithm,
/// checksum algorithm (2 bytes each), KDF salt (32), scrypt ops and memory limits (8 each),
/// key number (8), `sk` (64), checksum (32).
const MINISIGN_KEY_LEN: usize = 6 + 32 + 8 + 8 + 8 + 64 + 32;
/// Where `sk` (seed, then public key) starts in a serialized minisign secret key.
const SK_OFFSET: usize = 6 + 32 + 8 + 8 + 8;

/// The prefix of the line of an unencrypted seed.
const SEED_PREFIX: &str = "oncl-tuf-ed25519-seed-v1:";

/// The file name of a role's key: `<role>.key`, or `<role>.v<N>.key` for the key made by the
/// root of version `N`.
pub fn file_name(role: Role, root_version: Option<u64>) -> String {
    match root_version {
        Some(v) => format!("{}.v{v}.key", role.name()),
        None => format!("{}.key", role.name()),
    }
}

/// Whether the key of `role` is an online key: one unencrypted line that CI signs with
/// ([`generate_seed`]). The snapshot key is one once the snapshot is online.
pub fn is_online(mode: SnapshotMode, role: Role) -> bool {
    match (mode, role) {
        (_, Role::Timestamp) | (SnapshotMode::Online, Role::Snapshot) => true,
        (_, Role::Root | Role::Targets) | (SnapshotMode::Offline, Role::Snapshot) => false,
    }
}

fn unhex_32(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    // `from_str_radix` also takes a sign: only hex digits are a seed.
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// The shortest passphrase new keys are encrypted with. The key derivation is minisign's
/// fixed, light scrypt: the length of the passphrase is what protects a stolen key file.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// A new encrypted key: the signing key and the text of its file.
///
/// # Errors
///
/// If the passphrase is shorter than [`MIN_PASSPHRASE_CHARS`], or the key cannot be
/// generated or encrypted.
pub fn generate_encrypted(
    role: Role,
    passphrase: &str,
) -> anyhow::Result<(SigningKey, Zeroizing<String>)> {
    generate_encrypted_as(role.name(), passphrase)
}

/// [`generate_encrypted`] for the key labelled `label` in its file's comment: a top-level
/// role's name, or a publisher's role `pub-<name>`.
///
/// # Errors
///
/// As [`generate_encrypted`].
pub fn generate_encrypted_as(
    label: &str,
    passphrase: &str,
) -> anyhow::Result<(SigningKey, Zeroizing<String>)> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        bail!("the passphrase of new keys must have at least {MIN_PASSPHRASE_CHARS} characters");
    }
    let pair = KeyPair::generate_encrypted_keypair(Some(passphrase.to_owned()))
        .context("generating the key")?;
    // The comment is not part of what the passphrase protects, so the box is made twice: to
    // read the seed back (the key id is of the seed), then with the comment that says which.
    let plain = pair.sk.to_box(None).context("encoding the key")?;
    let decrypted = SecretKey::from_box(plain, Some(passphrase.to_owned()))
        .context("decrypting the new key")?;
    let key = signing_key_of(&decrypted)?;
    let comment = format!("oncl-tuf-key role={label} keyid={}", key.key_id());
    let text = pair
        .sk
        .to_box(Some(&comment))
        .context("encoding the key")?
        .into_string();
    Ok((key, Zeroizing::new(text)))
}

/// The Ed25519 key inside a decrypted minisign secret key.
fn signing_key_of(secret: &SecretKey) -> anyhow::Result<SigningKey> {
    let bytes = Zeroizing::new(secret.to_bytes());
    if bytes.len() != MINISIGN_KEY_LEN {
        bail!("the secret key has an unexpected length");
    }
    let sk = &bytes[SK_OFFSET..SK_OFFSET + 64];
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&sk[..32]);
    let key = SigningKey::from_seed(&seed).map_err(|e| anyhow::anyhow!("{e}"))?;
    if key.public().as_bytes() != &sk[32..] {
        bail!(
            "the public key in the secret key file is not the one of its seed: the file is damaged"
        );
    }
    Ok(key)
}

/// Reads the encrypted key file `path`.
///
/// # Errors
///
/// If the file cannot be read, is not a minisign secret key, or the passphrase is wrong.
pub fn load_encrypted(path: &Path, passphrase: &str) -> anyhow::Result<SigningKey> {
    let secret = SecretKey::from_file(path, Some(passphrase.to_owned())).with_context(|| {
        format!(
            "reading the key {} (a wrong passphrase fails here too)",
            path.display()
        )
    })?;
    signing_key_of(&secret).with_context(|| format!("reading the key {}", path.display()))
}

/// A new unencrypted key: the signing key and the line of its file.
///
/// # Errors
///
/// If the system's random generator fails.
pub fn generate_seed() -> anyhow::Result<(SigningKey, Zeroizing<String>)> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|e| anyhow::anyhow!("the random generator: {e}"))?;
    let key = SigningKey::from_seed(&seed).map_err(|e| anyhow::anyhow!("{e}"))?;
    // One buffer of the final size, so that no copy of the digits is left behind.
    let mut line = Zeroizing::new(String::with_capacity(SEED_PREFIX.len() + 65));
    line.push_str(SEED_PREFIX);
    for byte in seed.iter() {
        let _ = write!(*line, "{byte:02x}");
    }
    line.push('\n');
    Ok((key, line))
}

/// The key of a line [`generate_seed`] wrote (surrounding white space is ignored: a secret
/// made with `gh secret set < file` has the newline).
///
/// # Errors
///
/// If it is not such a line.
pub fn parse_seed(text: &str) -> anyhow::Result<SigningKey> {
    let hex = text
        .trim()
        .strip_prefix(SEED_PREFIX)
        .context("the online key is not an `oncl-tuf-ed25519-seed-v1:<hex>` line")?;
    let seed = unhex_32(hex).context("the online key is not 64 hex digits")?;
    SigningKey::from_seed(&seed).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Writes the key file `name` in `dir`: never over an existing file, and not where git
/// would commit it. The directory is made.
///
/// # Errors
///
/// If the file exists, git could commit it, or it cannot be written.
pub fn write_key_file(dir: &Path, name: &str, text: &str) -> anyhow::Result<PathBuf> {
    let path = key_path(dir, name)?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    crate::files::write_new(&path, text.as_bytes(), true)?;
    Ok(path)
}

/// The path of the key file `name` in `dir`, after the checks [`write_key_file`] makes: it
/// does not exist and git would not commit it.
///
/// # Errors
///
/// As [`write_key_file`].
pub fn key_path(dir: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let path = dir.join(name);
    if path.exists() {
        bail!(
            "{} exists already; refusing to overwrite it",
            path.display()
        );
    }
    crate::files::refuse_committable(&path)?;
    Ok(path)
}

/// The passphrase, asked for once and only when a key is encrypted.
pub struct Unlock {
    source: PassphraseSource,
    prompt: &'static str,
    cached: Option<Zeroizing<String>>,
}

impl Unlock {
    /// Unlocking with `source`.
    pub fn new(source: PassphraseSource, prompt: &'static str) -> Unlock {
        Unlock {
            source,
            prompt,
            cached: None,
        }
    }

    /// The passphrase.
    ///
    /// # Errors
    ///
    /// If it cannot be read.
    pub fn passphrase(&mut self) -> anyhow::Result<&str> {
        if self.cached.is_none() {
            self.cached = Some(self.source.get(self.prompt)?);
        }
        Ok(self.cached.as_deref().map_or("", String::as_str))
    }
}

/// What the first line of a key file says it is (untrusted: only to choose a file).
fn comment_of(text: &str) -> Option<(String, KeyId)> {
    let line = text.lines().next()?.strip_prefix("untrusted comment:")?;
    let mut role = None;
    let mut keyid = None;
    for word in line.split_whitespace() {
        if let Some(r) = word.strip_prefix("role=") {
            role = Some(r.to_owned());
        } else if let Some(k) = word.strip_prefix("keyid=") {
            keyid = KeyId::from_hex(k);
        }
    }
    Some((role?, keyid?))
}

/// The signing keys of `role` among the key files of `dir` whose ids are in `wanted` (the
/// ids the root in force lists for the role). Encrypted files are opened with `unlock`; a
/// file whose decrypted key is not the one its comment names is an error.
///
/// # Errors
///
/// If no file holds a wanted key, or a file cannot be opened.
pub fn find_keys(
    dir: &Path,
    role: Role,
    wanted: &[KeyId],
    unlock: &mut Unlock,
) -> anyhow::Result<Vec<SigningKey>> {
    let online = matches!(role, Role::Timestamp | Role::Snapshot);
    let found = find_labelled(dir, role.name(), online, wanted, unlock)?;
    if found.is_empty() {
        let ids: Vec<String> = wanted.iter().map(ToString::to_string).collect();
        bail!(
            "no key file in {} holds the {} key of the root in force (key id {}): the keys \
             may have been rotated, or are kept elsewhere",
            dir.display(),
            role,
            ids.join(" or ")
        );
    }
    Ok(found)
}

/// The encrypted keys labelled `label` (a publisher's role, `pub-<name>`) among the key files
/// of `dir` whose ids are in `wanted`, opened with `unlock`; none found is an empty list.
///
/// # Errors
///
/// If the directory or a wanted file cannot be read, or a file holds another key than its
/// comment names.
pub fn find_encrypted_keys(
    dir: &Path,
    label: &str,
    wanted: &[KeyId],
    unlock: &mut Unlock,
) -> anyhow::Result<Vec<SigningKey>> {
    find_labelled(dir, label, false, wanted, unlock)
}

/// The keys labelled `label` in `dir` whose ids are in `wanted`: encrypted files, and with
/// `online` the unencrypted seed lines too.
fn find_labelled(
    dir: &Path,
    label: &str,
    online: bool,
    wanted: &[KeyId],
    unlock: &mut Unlock,
) -> anyhow::Result<Vec<SigningKey>> {
    let mut found: Vec<SigningKey> = Vec::new();
    let mut seen = BTreeSet::new();
    let entries = fs::read_dir(dir)
        .with_context(|| format!("reading the key directory {}", dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "key") && p.is_file())
        .collect();
    paths.sort();
    for path in paths {
        let Ok(text) = fs::read_to_string(&path).map(Zeroizing::new) else {
            continue;
        };
        let key = if online && text.trim_start().starts_with(SEED_PREFIX) {
            let key = parse_seed(&text).with_context(|| format!("reading {}", path.display()))?;
            if !wanted.contains(&key.key_id()) {
                continue;
            }
            key
        } else if let Some((name, id)) = comment_of(&text) {
            if name != label || !wanted.contains(&id) {
                continue;
            }
            let key = load_encrypted(&path, unlock.passphrase()?)?;
            if key.key_id() != id {
                bail!(
                    "{} is labelled with key {id} but holds another key: refusing to use it",
                    path.display()
                );
            }
            key
        } else {
            continue;
        };
        if seen.insert(key.key_id()) {
            found.push(key);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_passphrase_makes_no_key_and_a_seed_has_only_hex_digits() {
        assert!(generate_encrypted(Role::Root, "eleven char").is_err());
        let signed = format!("{SEED_PREFIX}+{}", "a".repeat(63));
        assert!(parse_seed(&signed).is_err());
        assert!(parse_seed(&format!("{SEED_PREFIX}{}", "A".repeat(64))).is_ok());
    }

    #[test]
    fn an_encrypted_key_round_trips_and_a_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (key, text) = generate_encrypted(Role::Targets, "correct horse").unwrap();
        let path = dir.path().join("targets.key");
        fs::write(&path, text.as_bytes()).unwrap();
        // The seed read back signs as the generated key does, and is the key the comment names.
        let loaded = load_encrypted(&path, "correct horse").unwrap();
        assert_eq!(loaded.key_id(), key.key_id());
        assert_eq!(loaded.sign(b"x"), key.sign(b"x"));
        let (role, id) = comment_of(&text).unwrap();
        assert_eq!((role.as_str(), id), ("targets", key.key_id()));
        let err = load_encrypted(&path, "incorrect horse").unwrap_err();
        assert!(format!("{err:#}").contains("reading the key"), "{err:#}");
    }

    #[test]
    fn the_seed_line_round_trips_with_and_without_the_newline() {
        let (key, line) = generate_seed().unwrap();
        assert!(line.ends_with('\n') && line.lines().count() == 1);
        assert_eq!(parse_seed(&line).unwrap().key_id(), key.key_id());
        assert_eq!(parse_seed(line.trim_end()).unwrap().key_id(), key.key_id());
        // `gh secret set < file` and PowerShell's `Get-Content -Raw` keep the line end.
        let crlf = format!("{}\r\n", line.trim_end());
        assert_eq!(parse_seed(&crlf).unwrap().key_id(), key.key_id());
        assert!(parse_seed("oncl-tuf-ed25519-seed-v1:abcd").is_err());
        assert!(parse_seed(&"ab".repeat(32)).is_err());
    }

    #[test]
    fn key_files_are_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        write_key_file(dir.path(), "a.key", "one").unwrap();
        let err = write_key_file(dir.path(), "a.key", "two").unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"), "{err}");
        assert_eq!(fs::read_to_string(dir.path().join("a.key")).unwrap(), "one");
    }
}
