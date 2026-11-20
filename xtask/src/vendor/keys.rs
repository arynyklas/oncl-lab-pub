//! A publisher's keys and signatures (`docs/design/publishers.md`, «Команды издателя»):
//! `vendor keygen` (an Ed25519 key in an encrypted file, as `tuf init` writes the owner's,
//! labelled with the role `pub-<name>`), `vendor sign` (the next version of the role from the
//! draft, signed by the keys of a directory) and `vendor cosign` (more signatures, for a
//! threshold above 1). Keys live outside the working tree; a file git would commit is
//! refused.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::model::SPEC_VERSION;
use oncl_update::tuf::{
    Envelope, KeyId, PathPattern, Profile, PublicKey, PublisherName, RoleName, SigningKey,
    TargetPath, Targets, build, layout,
};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{MAX_EXPIRY_DAYS, MAX_ROLE_FILE, MIN_EXPIRY_DAYS};
use crate::publishers::Publisher;
use crate::tuf::keystore::{self, Unlock};
use crate::tuf::repo::{self, Listing};

/// The file name of a key of `publisher`: `pub-<name>-<first 16 hex of the key id>.key`.
pub fn key_file_name(publisher: &PublisherName, id: &KeyId) -> String {
    let hex = id.to_hex();
    format!("pub-{publisher}-{}.key", &hex[..16])
}

/// A new key of `publisher`, encrypted with `passphrase`, written into `out`.
///
/// # Errors
///
/// The passphrase is too short, the file would be committable or exists, or writing fails.
pub fn keygen(
    publisher: &PublisherName,
    out: &Path,
    passphrase: &str,
) -> anyhow::Result<(PathBuf, PublicKey)> {
    let role = RoleName::of(publisher);
    let (key, text) = keystore::generate_encrypted_as(role.as_str(), passphrase)?;
    let name = key_file_name(publisher, &key.key_id());
    let path = keystore::write_key_file(out, &name, &text)?;
    Ok((path, key.public()))
}

/// The keys of `publisher` among the key files of `dir`.
///
/// # Errors
///
/// None is there, or a file cannot be opened.
pub fn publisher_keys(
    dir: &Path,
    publisher: &Publisher,
    unlock: &mut Unlock,
) -> anyhow::Result<Vec<SigningKey>> {
    let wanted: Vec<KeyId> = publisher.keys.iter().map(PublicKey::key_id).collect();
    let keys = keystore::find_encrypted_keys(dir, publisher.role().as_str(), &wanted, unlock)?;
    if keys.is_empty() {
        bail!(
            "no key file in {} holds a key of publishers/{}/publisher.toml",
            dir.display(),
            publisher.name
        );
    }
    Ok(keys)
}

/// `expires` as the metadata writes it: RFC 3339, UTC, whole seconds.
fn format_expires(expires: OffsetDateTime) -> anyhow::Result<String> {
    Ok(crate::tuf::whole_seconds(expires).format(&Rfc3339)?)
}

/// What [`sign`] wrote.
#[derive(Debug)]
pub struct Signed {
    /// The file.
    pub path: PathBuf,
    /// Its version.
    pub version: u64,
    /// How many keys signed it.
    pub signatures: usize,
    /// How many must.
    pub threshold: u32,
}

/// The `signed` part of version `version` of `publisher`'s role over `targets`, expiring at
/// `expires`, read back as the client reads it, every target under the role's paths.
///
/// # Errors
///
/// The client would not read it.
pub fn role_signed(
    publisher: &PublisherName,
    version: u64,
    expires: OffsetDateTime,
    targets: &Map<String, Value>,
) -> anyhow::Result<Value> {
    let signed = json!({
        "_type": "targets",
        "spec_version": SPEC_VERSION,
        "version": version,
        "expires": format_expires(expires)?,
        "targets": targets,
    });
    let read = Targets::from_signed(&signed, Profile::Legacy)
        .map_err(|e| anyhow::anyhow!("the client would not read the role: {e}"))?;
    let pattern = PathPattern::of(publisher);
    if let Some(path) = read.targets.keys().find(|p| !pattern.matches(p)) {
        bail!("{path} is outside the role's paths {pattern}");
    }
    Ok(signed)
}

/// Writes the next version of `publisher`'s role into the repository `tuf` (`tuf/v1`):
/// `targets` (the draft, started from version `base` of the role), expiring `days` days after
/// `now`, signed by `keys`.
///
/// # Errors
///
/// The role moved on since the draft was started, `days` is outside 14 to 180, a key is not
/// the publisher's, the file is too large or exists, or writing fails.
pub fn sign(
    tuf: &Path,
    publisher: &Publisher,
    base: Option<u64>,
    targets: &Map<String, Value>,
    now: OffsetDateTime,
    days: i64,
    keys: &[SigningKey],
) -> anyhow::Result<Signed> {
    if !(MIN_EXPIRY_DAYS..=MAX_EXPIRY_DAYS).contains(&days) {
        bail!(
            "--expires-days {days}: a role is valid {MIN_EXPIRY_DAYS} to {MAX_EXPIRY_DAYS} days \
             (CI wants at least {MIN_EXPIRY_DAYS} days left when it checks)"
        );
    }
    let role = publisher.role();
    let newest = Listing::read(tuf)?.newest_roles().get(&role).copied();
    if newest != base {
        bail!(
            "the draft was started from version {} of {role}, but the repository has {}: start \
             the draft again (remove target/vendor/{}/role.json) from the newest version",
            base.map_or_else(|| "none".to_owned(), |v| v.to_string()),
            newest.map_or_else(|| "none".to_owned(), |v| v.to_string()),
            publisher.name
        );
    }
    let ids: Vec<KeyId> = publisher.keys.iter().map(PublicKey::key_id).collect();
    if let Some(key) = keys.iter().find(|k| !ids.contains(&k.key_id())) {
        bail!(
            "the key {} is not one of publishers/{}/publisher.toml",
            key.key_id(),
            publisher.name
        );
    }
    let version = newest.map_or(1, |v| v + 1);
    let signed = role_signed(
        &publisher.name,
        version,
        now + time::Duration::days(days),
        targets,
    )?;
    let refs: Vec<&SigningKey> = keys.iter().collect();
    let bytes = build::sign(&signed, &refs).map_err(|e| anyhow::anyhow!("{e}"))?;
    if bytes.len() as u64 > MAX_ROLE_FILE {
        bail!(
            "the role would be {} bytes, more than {MAX_ROLE_FILE}: prune old versions",
            bytes.len()
        );
    }
    let path = repo::write_new(tuf, &layout::delegated_path(version, &role), &bytes)?;
    Ok(Signed {
        path,
        version,
        signatures: keys.len(),
        threshold: publisher.threshold,
    })
}

/// The role a file `<V>.pub-<name>.json` is of.
///
/// # Errors
///
/// The name is not of that form.
pub fn role_of_file(file: &Path) -> anyhow::Result<RoleName> {
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no file name", file.display()))?;
    name.strip_suffix(".json")
        .and_then(|stem| stem.split_once('.'))
        .and_then(|(_, role)| RoleName::parse(role).ok())
        .with_context(|| format!("{name} is not <version>.pub-<publisher>.json"))
}

/// Adds the signatures of `keys` to the role file `file` (another key holder's turn, for a
/// threshold above 1): how many keys of `publisher` signed it now.
///
/// # Errors
///
/// The file is not a role file of the publisher, a key is not the publisher's, or writing
/// fails.
pub fn cosign(file: &Path, publisher: &Publisher, keys: &[SigningKey]) -> anyhow::Result<usize> {
    let role = role_of_file(file)?;
    if role != publisher.role() {
        bail!(
            "{} is a file of {role}, not of {}",
            file.display(),
            publisher.role()
        );
    }
    let ids: Vec<KeyId> = publisher.keys.iter().map(PublicKey::key_id).collect();
    if let Some(key) = keys.iter().find(|k| !ids.contains(&k.key_id())) {
        bail!(
            "the key {} is not one of publishers/{}/publisher.toml",
            key.key_id(),
            publisher.name
        );
    }
    let bytes = oncl_pack::read_limited(file, MAX_ROLE_FILE)?;
    let refs: Vec<&SigningKey> = keys.iter().collect();
    let signed = build::add_signatures(&bytes, &refs).map_err(|e| anyhow::anyhow!("{e}"))?;
    let envelope = Envelope::parse(&signed, MAX_ROLE_FILE, &file.display().to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let count = envelope
        .signatures
        .iter()
        .filter(|s| KeyId::from_hex(&s.keyid).is_some_and(|id| ids.contains(&id)))
        .count();
    fs::write(file, &signed).with_context(|| format!("writing {}", file.display()))?;
    Ok(count)
}

/// The targets of the newest file of `publisher`'s role in the repository `tuf`, and its
/// version; none before the first release.
///
/// # Errors
///
/// The file cannot be read as the client reads a role.
pub fn newest_targets(
    tuf: &Path,
    publisher: &PublisherName,
) -> anyhow::Result<Option<(u64, Map<String, Value>)>> {
    let role = RoleName::of(publisher);
    let Some(version) = Listing::read(tuf)?.newest_roles().get(&role).copied() else {
        return Ok(None);
    };
    let path = layout::delegated_path(version, &role);
    let bytes = repo::read(tuf, &path)?;
    let envelope =
        Envelope::parse(&bytes, MAX_ROLE_FILE, &path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let targets = envelope.signed["targets"]
        .as_object()
        .cloned()
        .with_context(|| format!("{path} has no targets"))?;
    // Every path a target path: what the client reads.
    for path in targets.keys() {
        TargetPath::parse(path).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(Some((version, targets)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_role_outside_its_paths_or_of_a_wrong_form_is_not_signed() {
        let name = PublisherName::parse("ecc").unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let mut targets = Map::new();
        targets.insert(
            "plugins/ecc/kz.ecc.a/1.0.0.onclp".into(),
            json!({"length": 1, "hashes": {"sha256": "a".repeat(64)}}),
        );
        role_signed(&name, 1, now, &targets).unwrap();
        targets.insert(
            "plugins/other/kz.ecc.a/1.0.0.onclp".into(),
            json!({"length": 1, "hashes": {"sha256": "a".repeat(64)}}),
        );
        let err = role_signed(&name, 1, now, &targets).unwrap_err();
        assert!(
            format!("{err:#}").contains("outside the role's paths"),
            "{err:#}"
        );
    }

    #[test]
    fn a_key_file_is_named_after_its_publisher_and_key() {
        let key = SigningKey::from_seed(&[7; 32]).unwrap();
        let name = key_file_name(&PublisherName::parse("ecc").unwrap(), &key.key_id());
        assert!(
            name.starts_with("pub-ecc-") && name.ends_with(".key") && name.len() == 28,
            "{name}"
        );
        let role = role_of_file(Path::new("tuf/v1/metadata/3.pub-ecc.json")).unwrap();
        assert_eq!(role.as_str(), "pub-ecc");
        assert!(role_of_file(Path::new("3.targets.json")).is_err());
    }
}
