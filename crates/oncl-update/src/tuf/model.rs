//! The metadata files of TUF (specification section 4): the signed envelope that keeps the
//! exact JSON that was signed, and typed views of the four roles that read it strictly.
//!
//! A metadata file is `{"signatures": [{"keyid", "sig"}…], "signed": {…}}`. [`Envelope`]
//! holds `signed` as the [`serde_json::Value`] that was read, never as a struct that would
//! drop the members this client does not know: a signature covers all of them, and the
//! typed views ([`Root`], [`Timestamp`], [`Snapshot`], [`Targets`]) are read from that value
//! only after the signature has held.
//!
//! The subset this client reads, anything else is refused:
//!
//! - `spec_version` is `1.x`; `_type` is the role's name; `version` is at least 1;
//!   `expires` is `YYYY-MM-DDTHH:MM:SSZ`;
//! - keys are Ed25519 ([`super::keys`]); a key's id is recomputed; no key serves two roles;
//! - `consistent_snapshot` is `true`;
//! - hashes are sha256 only;
//! - in the [`Profile::Legacy`] profile targets have no `delegations` (not even an empty
//!   one); in [`Profile::Delegating`] the top-level targets may have one, kept unread
//!   ([`Targets::delegations`] reads it into [`Delegations`]);
//! - a target path is a [`TargetPath`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Digest as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::canonical;
use super::delegation::Delegations;
use super::error::{Role, TufError};
use super::keys::{KeyId, PublicKey};
use super::names::TargetPath;

/// The `spec_version` this client writes.
pub const SPEC_VERSION: &str = "1.0.31";

/// A sha256 sum.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(#[serde(with = "crate::hex::array")] pub [u8; 32]);

impl Digest {
    /// The sha256 of `data`.
    pub fn of(data: &[u8]) -> Digest {
        Digest(sha2::Sha256::digest(data).into())
    }

    /// 64 lowercase hex digits.
    pub fn to_hex(self) -> String {
        crate::hex::encode(&self.0)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

/// One signature of a metadata file: by the key of id `keyid`, `sig` the 64 bytes of the
/// Ed25519 signature as lowercase hex. Neither is checked on reading: a signature that
/// names no trusted key, or does not verify, counts for nothing (see
/// [`super::ed25519::count_valid`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// The id of the signing key.
    pub keyid: String,
    /// The signature.
    pub sig: String,
}

/// A metadata file: `signed`, as read, and the signatures over its canonical form.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// What was signed: any JSON; its canonical form is what the signatures cover.
    pub signed: Value,
    /// The signatures.
    pub signatures: Vec<Signature>,
}

impl Envelope {
    /// Reads a file of at most `limit` bytes with the strict parser ([`canonical::parse`]).
    /// The file need not be in canonical form (a signer may pretty-print); `what` names it
    /// in errors.
    ///
    /// # Errors
    ///
    /// The errors of [`canonical::parse`], and [`TufError::Malformed`] if the JSON is not
    /// `{"signed": …, "signatures": […]}`.
    pub fn parse(bytes: &[u8], limit: u64, what: &str) -> Result<Envelope, TufError> {
        let value = canonical::parse(bytes, limit, what)?;
        serde_json::from_value(value).map_err(|e| TufError::malformed(what, e.to_string()))
    }

    /// The canonical form of `signed`: the bytes every signature is over.
    ///
    /// # Errors
    ///
    /// [`TufError::Float`] or [`TufError::TooDeep`] ([`canonical::to_vec`]).
    pub fn canonical_signed(&self) -> Result<Vec<u8>, TufError> {
        canonical::to_vec(&self.signed)
    }

    /// The file: the whole envelope in canonical form (keys sorted, no whitespace) and one
    /// `\n` after it, the signatures sorted by key id; so the same envelope is always the
    /// same bytes. The `\n` is part of the file: its length and sha256 are what a snapshot
    /// or timestamp lists.
    ///
    /// # Errors
    ///
    /// [`TufError::Float`] or [`TufError::TooDeep`] ([`canonical::to_vec`]).
    pub fn to_file(&self) -> Result<Vec<u8>, TufError> {
        let mut signatures = self.signatures.clone();
        signatures.sort_by(|a, b| a.keyid.cmp(&b.keyid).then_with(|| a.sig.cmp(&b.sig)));
        let signatures = serde_json::to_value(&signatures)
            .map_err(|e| TufError::malformed("signatures", e.to_string()))?;
        let mut members = Map::new();
        members.insert("signatures".to_owned(), signatures);
        members.insert("signed".to_owned(), self.signed.clone());
        let mut file = canonical::to_vec(&Value::Object(members))?;
        file.push(b'\n');
        Ok(file)
    }
}

/// The keys and the threshold of a role in a root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleKeys {
    /// The ids of the role's keys: distinct, and all in the root's `keys`.
    pub keyids: Vec<KeyId>,
    /// How many distinct keys must sign: at least 1, at most `keyids.len()`.
    pub threshold: u32,
}

impl RoleKeys {
    /// Whether `other` trusts the same keys with the same threshold (the order of `keyids`
    /// does not matter).
    pub fn same_as(&self, other: &RoleKeys) -> bool {
        self.threshold == other.threshold
            && self.keyids.iter().collect::<BTreeSet<_>>()
                == other.keyids.iter().collect::<BTreeSet<_>>()
    }
}

/// `root.json`: the keys of every role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    /// The version, 1 for the first root and one more for each next.
    pub version: u64,
    /// When the root stops being trusted.
    pub expires: OffsetDateTime,
    /// Every key, by its id (recomputed on reading).
    pub keys: BTreeMap<KeyId, PublicKey>,
    /// Who signs roots.
    pub root: RoleKeys,
    /// Who signs the timestamp.
    pub timestamp: RoleKeys,
    /// Who signs the snapshot.
    pub snapshot: RoleKeys,
    /// Who signs the targets.
    pub targets: RoleKeys,
}

impl Root {
    /// Reads the `signed` of a root.
    ///
    /// # Errors
    ///
    /// [`TufError::Malformed`] for a field missing or of the wrong type, a role listing a
    /// key the root does not have or a key twice, a threshold of 0 or above the number of
    /// keys; [`TufError::Unsupported`] for a spec version other than 1.x, a key type,
    /// scheme or hash other than Ed25519 or sha256, `consistent_snapshot` other than
    /// `true`, a role besides the four; [`TufError::BadKeyId`] for a key listed under
    /// another id than the hash of its key object.
    pub fn from_signed(signed: &Value) -> Result<Root, TufError> {
        let (members, header) = header(signed, Role::Root)?;
        match members.get("consistent_snapshot") {
            Some(Value::Bool(true)) => {}
            Some(Value::Bool(false)) | None => {
                return Err(TufError::Unsupported(
                    "a root without consistent_snapshot: true".to_owned(),
                ));
            }
            Some(_) => {
                return Err(TufError::malformed(
                    "root",
                    "consistent_snapshot is not a boolean",
                ));
            }
        }
        let mut keys = BTreeMap::new();
        for (claimed, key) in object(field(members, "keys", "root")?, "keys")? {
            let id = KeyId::from_hex(claimed)
                .ok_or_else(|| TufError::malformed("keys", "a key id is not 64 hex digits"))?;
            let key = PublicKey::from_value(key)?;
            let actual = key.key_id();
            if actual != id {
                return Err(TufError::BadKeyId {
                    claimed: claimed.clone(),
                    actual: actual.to_hex(),
                });
            }
            keys.insert(id, key);
        }
        let roles = object(field(members, "roles", "root")?, "roles")?;
        if let Some(other) = roles
            .keys()
            .find(|name| !matches!(name.as_str(), "root" | "timestamp" | "snapshot" | "targets"))
        {
            return Err(TufError::Unsupported(format!(
                "the role {other:?} in a root"
            )));
        }
        let role = |role: Role| -> Result<RoleKeys, TufError> {
            let what = format!("role {role}");
            let entry = roles
                .get(role.name())
                .ok_or_else(|| TufError::malformed("roles", format!("no {role} role")))?;
            let entry = object(entry, &what)?;
            let mut keyids = Vec::new();
            for id in array(field(entry, "keyids", &what)?, "keyids")? {
                let id = id
                    .as_str()
                    .and_then(KeyId::from_hex)
                    .ok_or_else(|| TufError::malformed(&what, "a key id is not 64 hex digits"))?;
                if !keys.contains_key(&id) {
                    return Err(TufError::malformed(
                        &what,
                        format!("the key {id} is not in keys"),
                    ));
                }
                if keyids.contains(&id) {
                    return Err(TufError::malformed(
                        &what,
                        format!("the key {id} is listed twice"),
                    ));
                }
                keyids.push(id);
            }
            let threshold = uint(entry, "threshold", &what)?;
            if threshold < 1 || threshold > keyids.len() as u64 {
                return Err(TufError::malformed(
                    &what,
                    format!("threshold {threshold} of {} keys", keyids.len()),
                ));
            }
            Ok(RoleKeys {
                keyids,
                threshold: threshold as u32,
            })
        };
        let root = Root {
            version: header.version,
            expires: header.expires,
            root: role(Role::Root)?,
            timestamp: role(Role::Timestamp)?,
            snapshot: role(Role::Snapshot)?,
            targets: role(Role::Targets)?,
            keys,
        };
        // No key serves two roles: the timestamp key is the one that is online, and it
        // must give no right to sign targets, snapshots or roots.
        let mut served_by = BTreeMap::new();
        for role in [Role::Root, Role::Timestamp, Role::Snapshot, Role::Targets] {
            for id in &root.role(role).keyids {
                if let Some(other) = served_by.insert(id, role) {
                    return Err(TufError::malformed(
                        "roles",
                        format!("the key {id} serves both the {other} and the {role} role"),
                    ));
                }
            }
        }
        Ok(root)
    }

    /// The keys and threshold of `role`.
    pub fn role(&self, role: Role) -> &RoleKeys {
        match role {
            Role::Root => &self.root,
            Role::Timestamp => &self.timestamp,
            Role::Snapshot => &self.snapshot,
            Role::Targets => &self.targets,
        }
    }

    /// Whether `new` (a later root) trusts other keys or another threshold than `self` for
    /// the timestamp, snapshot or targets role: the case in which the versions trusted
    /// before are forgotten ([`super::TufClient::refresh`]).
    pub fn rotates(&self, new: &Root) -> bool {
        [Role::Timestamp, Role::Snapshot, Role::Targets]
            .into_iter()
            .any(|role| !self.role(role).same_as(new.role(role)))
    }
}

/// What a role lists of another role's file: `snapshot.json` in the timestamp, `targets.json`
/// in the snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaFile {
    /// The version of the file.
    pub version: u64,
    /// Its size in bytes, if listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    /// Its sha256, if listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Digest>,
}

impl MetaFile {
    fn from_value(value: &Value, what: &str) -> Result<MetaFile, TufError> {
        let members = object(value, what)?;
        let version = uint(members, "version", what)?;
        if version < 1 {
            return Err(TufError::malformed(what, "version 0"));
        }
        let length = members
            .contains_key("length")
            .then(|| uint(members, "length", what))
            .transpose()?;
        let sha256 = members
            .get("hashes")
            .map(|hashes| hashes_of(hashes, what))
            .transpose()?;
        Ok(MetaFile {
            version,
            length,
            sha256,
        })
    }
}

/// `timestamp.json`: the version of the snapshot, and its size and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    /// The version.
    pub version: u64,
    /// When the timestamp stops being trusted.
    pub expires: OffsetDateTime,
    /// `meta["snapshot.json"]`.
    pub snapshot: MetaFile,
}

impl Timestamp {
    /// Reads the `signed` of a timestamp; the errors are those of [`Root::from_signed`].
    pub fn from_signed(signed: &Value) -> Result<Timestamp, TufError> {
        let (members, header) = header(signed, Role::Timestamp)?;
        let meta = object(field(members, "meta", "timestamp")?, "meta")?;
        let snapshot = meta
            .get("snapshot.json")
            .ok_or_else(|| TufError::malformed("timestamp", "meta has no snapshot.json"))?;
        Ok(Timestamp {
            version: header.version,
            expires: header.expires,
            snapshot: MetaFile::from_value(snapshot, "meta of snapshot.json")?,
        })
    }
}

/// `snapshot.json`: the version of every targets file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The version.
    pub version: u64,
    /// When the snapshot stops being trusted.
    pub expires: OffsetDateTime,
    /// `meta`: by file name (`targets.json`).
    pub meta: BTreeMap<String, MetaFile>,
}

/// The name the top-level targets file is listed under in a snapshot.
pub const TARGETS_META: &str = "targets.json";

impl Snapshot {
    /// Reads the `signed` of a snapshot; the errors are those of [`Root::from_signed`], and
    /// [`TufError::Malformed`] for a meta without `targets.json`.
    pub fn from_signed(signed: &Value) -> Result<Snapshot, TufError> {
        let (members, header) = header(signed, Role::Snapshot)?;
        let mut meta = BTreeMap::new();
        for (name, entry) in object(field(members, "meta", "snapshot")?, "meta")? {
            meta.insert(
                name.clone(),
                MetaFile::from_value(entry, &format!("meta of {name}"))?,
            );
        }
        if !meta.contains_key(TARGETS_META) {
            return Err(TufError::malformed("snapshot", "meta has no targets.json"));
        }
        Ok(Snapshot {
            version: header.version,
            expires: header.expires,
            meta,
        })
    }

    /// What the snapshot lists for `targets.json`.
    pub fn targets(&self) -> &MetaFile {
        &self.meta[TARGETS_META]
    }
}

/// One file of the repository, as the targets metadata lists it.
#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    /// The size in bytes.
    pub length: u64,
    /// The sha256.
    pub sha256: Digest,
    /// The `custom` member, as signed.
    pub custom: Option<Value>,
}

/// How the client reads a repository's top-level targets: the `delegations` member is the
/// only difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    /// The clients released before delegations (0.1.0, 0.1.1): a top-level targets with a
    /// `delegations` member, even an empty one, is refused. Kept to tell whether they still
    /// read a repository.
    Legacy,
    /// Every client from 0.1.2: `delegations` is optional and is not read with the targets
    /// ([`Targets::delegations`] reads it, for the plugin catalog only), so the program's
    /// updates never depend on it.
    Delegating,
}

/// `targets.json`, or a delegated role's file: the files of the repository.
#[derive(Clone, Debug, PartialEq)]
pub struct Targets {
    /// The version.
    pub version: u64,
    /// When the targets stop being trusted.
    pub expires: OffsetDateTime,
    /// The files, by target path.
    pub targets: BTreeMap<TargetPath, Target>,
    /// The `delegations` member as signed, unread (`None` without one, always in
    /// [`Profile::Legacy`]).
    delegations: Option<Value>,
}

impl Targets {
    /// Reads the `signed` of a targets file in `profile`; the errors are those of
    /// [`Root::from_signed`], and in [`Profile::Legacy`] [`TufError::Unsupported`] for a
    /// `delegations` member. In [`Profile::Delegating`] that member is not read here.
    pub fn from_signed(signed: &Value, profile: Profile) -> Result<Targets, TufError> {
        let (members, header) = header(signed, Role::Targets)?;
        let delegations = match (profile, members.get("delegations")) {
            (_, None) => None,
            (Profile::Legacy, Some(_)) => {
                return Err(TufError::Unsupported(
                    "delegations in targets metadata".to_owned(),
                ));
            }
            (Profile::Delegating, Some(delegations)) => Some(delegations.clone()),
        };
        let mut targets = BTreeMap::new();
        for (path, entry) in object(field(members, "targets", "targets")?, "targets")? {
            let path = TargetPath::parse(path)
                .map_err(|e| TufError::malformed("targets", e.to_string()))?;
            let what = format!("target {path}");
            let entry = object(entry, &what)?;
            let hashes = field(entry, "hashes", &what)?;
            targets.insert(
                path,
                Target {
                    length: uint(entry, "length", &what)?,
                    sha256: hashes_of(hashes, &what)?,
                    custom: entry.get("custom").cloned(),
                },
            );
        }
        Ok(Targets {
            version: header.version,
            expires: header.expires,
            targets,
            delegations,
        })
    }

    /// The delegations, read now: `Ok(None)` without the member. A member that cannot be
    /// read is an error here, for the plugin catalog, never for the targets.
    ///
    /// # Errors
    ///
    /// [`TufError::Malformed`] for a field missing or of the wrong type, a key id that is not
    /// 64 hex digits, a role name that is not a [`RoleName`](super::names::RoleName) or is
    /// listed twice; [`TufError::BadKeyId`] for a key under another id than its hash;
    /// [`TufError::Unsupported`] for a key that is not Ed25519.
    pub fn delegations(&self) -> Result<Option<Delegations>, TufError> {
        self.delegations
            .as_ref()
            .map(Delegations::from_value)
            .transpose()
    }
}

/// `Ok` if `expires` is after `now`, the fixed time the update started at.
///
/// # Errors
///
/// [`TufError::Expired`] otherwise.
pub fn ensure_fresh(
    role: Role,
    expires: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), TufError> {
    if expires > now {
        Ok(())
    } else {
        Err(TufError::Expired { role, expires })
    }
}

/// `expires` as the metadata spells it: `YYYY-MM-DDTHH:MM:SSZ`, UTC, whole seconds.
///
/// # Errors
///
/// [`TufError::Malformed`] for a year outside 0000–9999 (its form cannot be written).
pub fn format_expires(expires: OffsetDateTime) -> Result<String, TufError> {
    let utc = expires.to_offset(time::UtcOffset::UTC);
    if !(0..=9999).contains(&utc.year()) {
        return Err(TufError::malformed(
            "expires",
            "the year is not four digits",
        ));
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    ))
}

fn parse_expires(text: &str) -> Result<OffsetDateTime, TufError> {
    let bad = || TufError::malformed("expires", format!("{text:?} is not YYYY-MM-DDTHH:MM:SSZ"));
    // The shape first: RFC 3339 alone also allows lowercase letters, fractions and offsets.
    let shape = b"dddd-dd-ddTdd:dd:ddZ";
    let ok = text.len() == shape.len()
        && text.bytes().zip(shape).all(|(b, s)| match s {
            b'd' => b.is_ascii_digit(),
            _ => b == *s,
        });
    if !ok {
        return Err(bad());
    }
    OffsetDateTime::parse(text, &Rfc3339).map_err(|_| bad())
}

struct Header {
    version: u64,
    expires: OffsetDateTime,
}

/// The members of a role's `signed`, and its `_type`, `spec_version`, `version` and
/// `expires`, checked.
fn header(signed: &Value, role: Role) -> Result<(&Map<String, Value>, Header), TufError> {
    let what = role.name();
    let members = object(signed, what)?;
    let kind = string(members, "_type", what)?;
    if kind != what {
        return Err(TufError::malformed(
            what,
            format!("_type is {kind:?}, not {what:?}"),
        ));
    }
    let spec = string(members, "spec_version", what)?;
    let parts: Vec<&str> = spec.split('.').collect();
    if !(2..=3).contains(&parts.len())
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(TufError::malformed(what, format!("spec_version {spec:?}")));
    }
    if parts[0] != "1" {
        return Err(TufError::Unsupported(format!("spec_version {spec}")));
    }
    let version = uint(members, "version", what)?;
    if version < 1 {
        return Err(TufError::malformed(what, "version 0"));
    }
    let expires = parse_expires(string(members, "expires", what)?)?;
    Ok((members, Header { version, expires }))
}

pub(super) fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, TufError> {
    value
        .as_object()
        .ok_or_else(|| TufError::malformed(what, "not an object"))
}

pub(super) fn array<'a>(value: &'a Value, what: &str) -> Result<&'a Vec<Value>, TufError> {
    value
        .as_array()
        .ok_or_else(|| TufError::malformed(what, "not an array"))
}

pub(super) fn field<'a>(
    members: &'a Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<&'a Value, TufError> {
    members
        .get(name)
        .ok_or_else(|| TufError::malformed(what, format!("{name} is missing")))
}

fn string<'a>(
    members: &'a Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<&'a str, TufError> {
    field(members, name, what)?
        .as_str()
        .ok_or_else(|| TufError::malformed(what, format!("{name} is not a string")))
}

pub(super) fn uint(members: &Map<String, Value>, name: &str, what: &str) -> Result<u64, TufError> {
    field(members, name, what)?
        .as_u64()
        .ok_or_else(|| TufError::malformed(what, format!("{name} is not a non-negative integer")))
}

/// The sha256 of a `hashes` object: exactly `{"sha256": <64 lowercase hex digits>}`.
fn hashes_of(value: &Value, what: &str) -> Result<Digest, TufError> {
    let hashes = object(value, what)?;
    if let Some(other) = hashes.keys().find(|algorithm| *algorithm != "sha256") {
        return Err(TufError::Unsupported(format!(
            "the hash algorithm {other:?}"
        )));
    }
    let sum = hashes
        .get("sha256")
        .and_then(Value::as_str)
        .and_then(crate::hex::decode::<32>)
        .ok_or_else(|| {
            TufError::malformed(what, "hashes has no sha256 of 64 lowercase hex digits")
        })?;
    Ok(Digest(sum))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::macros::datetime;

    fn key(n: u8) -> (String, Value) {
        let key = PublicKey::from_bytes([n; 32]);
        (key.key_id().to_hex(), key.to_value())
    }

    /// Keys 1 to 6 are in the root; 1 signs roots, 2 the timestamp, 3 and 4 (both needed)
    /// the snapshot, 5 the targets; 6 serves no role.
    fn root_value() -> Value {
        let keys: Vec<(String, Value)> = (1..=6).map(key).collect();
        let id = |n: usize| keys[n - 1].0.clone();
        json!({
            "_type": "root",
            "spec_version": "1.0.31",
            "consistent_snapshot": true,
            "version": 3,
            "expires": "2027-11-15T00:00:00Z",
            "keys": keys.iter().cloned().collect::<serde_json::Map<_, _>>(),
            "roles": {
                "root": {"keyids": [id(1)], "threshold": 1},
                "timestamp": {"keyids": [id(2)], "threshold": 1},
                "snapshot": {"keyids": [id(3), id(4)], "threshold": 2},
                "targets": {"keyids": [id(5)], "threshold": 1},
            },
        })
    }

    fn edited(mut v: Value, edit: impl FnOnce(&mut Value)) -> Value {
        edit(&mut v);
        v
    }

    #[test]
    fn a_root_is_read() {
        let root = Root::from_signed(&root_value()).unwrap();
        assert_eq!(root.version, 3);
        assert_eq!(root.expires, datetime!(2027-11-15 0:00 UTC));
        assert_eq!(root.keys.len(), 6);
        assert_eq!(root.snapshot.threshold, 2);
        assert_eq!(root.snapshot.keyids.len(), 2);
        assert!(root.root.same_as(&root.root));
        assert!(!root.root.same_as(&root.snapshot));
        // Unknown members are ignored here (and covered by the signature).
        Root::from_signed(&edited(root_value(), |v| v["extra"] = json!({"x": 1}))).unwrap();
        // Spec versions 1.x.
        for spec in ["1.0.0", "1.0.37", "1.9", "1.0.31"] {
            Root::from_signed(&edited(root_value(), |v| v["spec_version"] = json!(spec))).unwrap();
        }
    }

    #[test]
    fn a_root_that_breaks_a_rule_is_refused() {
        let (a, _) = key(1);
        let (c, kc) = key(9);
        type Edit = Box<dyn Fn(&mut Value)>;
        let unsupported: Vec<(&str, Edit)> = vec![
            ("spec 2", Box::new(|v| v["spec_version"] = json!("2.0.0"))),
            ("spec 0", Box::new(|v| v["spec_version"] = json!("0.9.0"))),
            (
                "no consistent_snapshot",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("consistent_snapshot");
                }),
            ),
            (
                "consistent_snapshot false",
                Box::new(|v| v["consistent_snapshot"] = json!(false)),
            ),
            (
                "rsa key",
                Box::new({
                    let a = a.clone();
                    move |v| v["keys"][&a]["keytype"] = json!("rsa")
                }),
            ),
            (
                "other scheme",
                Box::new({
                    let a = a.clone();
                    move |v| v["keys"][&a]["scheme"] = json!("ecdsa-sha2-nistp256")
                }),
            ),
            (
                "an extra role",
                Box::new(|v| v["roles"]["mirrors"] = json!({"keyids": [], "threshold": 1})),
            ),
        ];
        for (name, edit) in unsupported {
            assert!(
                matches!(
                    Root::from_signed(&edited(root_value(), |v| edit(v))),
                    Err(TufError::Unsupported(_))
                ),
                "{name}"
            );
        }
        let malformed: Vec<(&str, Edit)> = vec![
            ("wrong _type", Box::new(|v| v["_type"] = json!("targets"))),
            (
                "no _type",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("_type");
                }),
            ),
            ("spec shape", Box::new(|v| v["spec_version"] = json!("1"))),
            (
                "spec letters",
                Box::new(|v| v["spec_version"] = json!("1.x.0")),
            ),
            ("version 0", Box::new(|v| v["version"] = json!(0))),
            ("negative version", Box::new(|v| v["version"] = json!(-1))),
            ("version string", Box::new(|v| v["version"] = json!("3"))),
            (
                "consistent_snapshot string",
                Box::new(|v| v["consistent_snapshot"] = json!("true")),
            ),
            (
                "threshold 0",
                Box::new(|v| v["roles"]["root"]["threshold"] = json!(0)),
            ),
            (
                "threshold above keys",
                Box::new(|v| v["roles"]["root"]["threshold"] = json!(2)),
            ),
            (
                "negative threshold",
                Box::new(|v| v["roles"]["root"]["threshold"] = json!(-1)),
            ),
            (
                "duplicate keyid",
                Box::new({
                    let a = a.clone();
                    move |v| v["roles"]["snapshot"]["keyids"] = json!([a.clone(), a.clone()])
                }),
            ),
            (
                "unknown keyid",
                Box::new({
                    let c = c.clone();
                    move |v| v["roles"]["root"]["keyids"] = json!([c.clone()])
                }),
            ),
            (
                "missing role",
                Box::new(|v| {
                    v["roles"].as_object_mut().unwrap().remove("targets");
                }),
            ),
            (
                "keyid not hex",
                Box::new(|v| v["roles"]["root"]["keyids"] = json!(["xyz"])),
            ),
            (
                "key id upper case",
                Box::new({
                    let a = a.clone();
                    move |v| v["roles"]["root"]["keyids"] = json!([a.to_uppercase()])
                }),
            ),
            (
                "key id not hex in keys",
                Box::new({
                    let kc = kc.clone();
                    move |v| v["keys"]["not-hex"] = kc.clone()
                }),
            ),
            (
                "expires fraction",
                Box::new(|v| v["expires"] = json!("2027-11-15T00:00:00.5Z")),
            ),
            (
                "expires offset",
                Box::new(|v| v["expires"] = json!("2027-11-15T01:00:00+01:00")),
            ),
            (
                "expires lowercase",
                Box::new(|v| v["expires"] = json!("2027-11-15t00:00:00z")),
            ),
            (
                "expires date",
                Box::new(|v| v["expires"] = json!("2027-13-15T00:00:00Z")),
            ),
            (
                "expires number",
                Box::new(|v| v["expires"] = json!(1_800_000_000)),
            ),
        ];
        for (name, edit) in malformed {
            let result = Root::from_signed(&edited(root_value(), |v| edit(v)));
            assert!(
                matches!(result, Err(TufError::Malformed { .. })),
                "{name}: {result:?}"
            );
        }
    }

    #[test]
    fn a_key_listed_under_another_id_is_refused() {
        let (a, _) = key(1);
        let (c, kc) = key(9);
        // The key of `a` under the id of another key.
        let v = edited(root_value(), |v| {
            let keys = v["keys"].as_object_mut().unwrap();
            keys.remove(&a);
            keys.insert(a.clone(), kc.clone());
        });
        match Root::from_signed(&v) {
            Err(TufError::BadKeyId { claimed, actual }) => {
                assert_eq!(claimed, a);
                assert_eq!(actual, c);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rotation_is_a_change_of_the_keys_or_threshold_of_the_lower_roles() {
        let root = Root::from_signed(&root_value()).unwrap();
        assert!(!root.rotates(&root));
        let id = |n: u8| key(n).0;
        // A new root version that only changes the root role's keys is not a rotation.
        let v = edited(root_value(), |v| {
            v["roles"]["root"]["keyids"] = json!([id(1), id(6)])
        });
        assert!(!root.rotates(&Root::from_signed(&v).unwrap()));
        // The order of keyids is not a rotation, another threshold is.
        let v = edited(root_value(), |v| {
            v["roles"]["snapshot"]["keyids"] = json!([id(4), id(3)])
        });
        assert!(!root.rotates(&Root::from_signed(&v).unwrap()));
        let v = edited(root_value(), |v| {
            v["roles"]["snapshot"]["threshold"] = json!(1)
        });
        assert!(root.rotates(&Root::from_signed(&v).unwrap()));
        let v = edited(root_value(), |v| {
            v["roles"]["timestamp"]["keyids"] = json!([id(6)])
        });
        assert!(root.rotates(&Root::from_signed(&v).unwrap()));
        let v = edited(root_value(), |v| {
            v["roles"]["targets"]["keyids"] = json!([id(6)])
        });
        assert!(root.rotates(&Root::from_signed(&v).unwrap()));
    }

    #[test]
    fn a_key_may_serve_only_one_role() {
        let id = |n: u8| key(n).0;
        // Every pair of roles, in both directions: the key of one listed in the other.
        let roles = ["root", "timestamp", "snapshot", "targets"];
        for (i, from) in roles.iter().enumerate() {
            for (j, to) in roles.iter().enumerate() {
                if i == j {
                    continue;
                }
                let borrowed = root_value()["roles"][from]["keyids"][0].clone();
                let mut v = root_value();
                // `to` lists the key of `from` as its only key (threshold 1).
                v["roles"][to] = json!({"keyids": [borrowed], "threshold": 1});
                let e = Root::from_signed(&v).unwrap_err();
                assert!(
                    matches!(&e, TufError::Malformed { why, .. } if why.contains("serves both")),
                    "{from} -> {to}: {e:?}"
                );
            }
        }
        // The same key twice in one role is its own error.
        let v = edited(root_value(), |v| {
            v["roles"]["snapshot"]["keyids"] = json!([id(3), id(3)])
        });
        assert!(matches!(
            Root::from_signed(&v),
            Err(TufError::Malformed { why, .. }) if why.contains("twice")
        ));
    }

    #[test]
    fn the_typed_views_read_only_their_own_role() {
        // A signed snapshot offered as a timestamp (and every other pair) is not one.
        let signed = |kind: &str| {
            json!({"_type": kind, "spec_version": "1.0.31", "version": 1,
                "expires": "2027-11-15T00:00:00Z",
                "meta": {"snapshot.json": {"version": 1}, "targets.json": {"version": 1}},
                "targets": {}, "keys": {}, "roles": {}, "consistent_snapshot": true})
        };
        type View = fn(&Value) -> Result<(), TufError>;
        let views: [(&str, View); 4] = [
            ("root", |v| Root::from_signed(v).map(drop)),
            ("timestamp", |v| Timestamp::from_signed(v).map(drop)),
            ("snapshot", |v| Snapshot::from_signed(v).map(drop)),
            ("targets", |v| {
                Targets::from_signed(v, Profile::Legacy).map(drop)
            }),
        ];
        for (offered, _) in views {
            for (read_as, read) in views {
                if offered == read_as {
                    continue;
                }
                let e = read(&signed(offered)).unwrap_err();
                assert!(
                    matches!(&e, TufError::Malformed { why, .. } if why.contains("_type")),
                    "{offered} read as {read_as}: {e:?}"
                );
            }
        }
        // (A timestamp, snapshot or targets that is right passes its own view.)
        Timestamp::from_signed(&signed("timestamp")).unwrap();
        Snapshot::from_signed(&signed("snapshot")).unwrap();
        Targets::from_signed(&signed("targets"), Profile::Legacy).unwrap();
    }

    fn hash(n: u8) -> String {
        crate::hex::encode(&[n; 32])
    }

    #[test]
    fn timestamp_snapshot_and_targets_are_read() {
        let ts = Timestamp::from_signed(&json!({
            "_type": "timestamp", "spec_version": "1.0.31", "version": 9,
            "expires": "2026-11-22T00:00:00Z",
            "meta": {"snapshot.json": {"version": 4, "length": 100, "hashes": {"sha256": hash(1)}}},
        }))
        .unwrap();
        assert_eq!(ts.version, 9);
        assert_eq!(
            ts.snapshot,
            MetaFile {
                version: 4,
                length: Some(100),
                sha256: Some(Digest([1; 32]))
            }
        );
        // length and hashes are optional.
        let ts = Timestamp::from_signed(&json!({
            "_type": "timestamp", "spec_version": "1.0.31", "version": 9,
            "expires": "2026-11-22T00:00:00Z", "meta": {"snapshot.json": {"version": 4}},
        }))
        .unwrap();
        assert_eq!((ts.snapshot.length, ts.snapshot.sha256), (None, None));

        let snap = Snapshot::from_signed(&json!({
            "_type": "snapshot", "spec_version": "1.0.31", "version": 4,
            "expires": "2026-12-15T00:00:00Z",
            "meta": {"targets.json": {"version": 2, "length": 5, "hashes": {"sha256": hash(2)}}},
        }))
        .unwrap();
        assert_eq!(snap.targets().version, 2);

        let targets = Targets::from_signed(
            &json!({
                "_type": "targets", "spec_version": "1.0.31", "version": 2,
                "expires": "2026-12-15T00:00:00Z",
                "targets": {"indexes/stable.json": {
                    "length": 77, "hashes": {"sha256": hash(3)}, "custom": {"a": 1}}},
            }),
            Profile::Legacy,
        )
        .unwrap();
        let target = &targets.targets["indexes/stable.json"];
        assert_eq!((target.length, target.sha256), (77, Digest([3; 32])));
        assert_eq!(target.custom, Some(json!({"a": 1})));
    }

    #[test]
    fn metadata_rules_are_enforced() {
        let ts = |meta: Value| {
            Timestamp::from_signed(&json!({
                "_type": "timestamp", "spec_version": "1.0.31", "version": 1,
                "expires": "2026-11-22T00:00:00Z", "meta": meta,
            }))
        };
        assert!(matches!(ts(json!({})), Err(TufError::Malformed { .. })));
        assert!(matches!(
            ts(json!({"snapshot.json": {"version": 0}})),
            Err(TufError::Malformed { .. })
        ));
        // Any hash algorithm but sha256 is refused, also next to a sha256.
        for hashes in [
            json!({"sha512": "00"}),
            json!({"sha256": hash(1), "sha512": "00"}),
            json!({"md5": "00"}),
        ] {
            assert!(
                matches!(
                    ts(json!({"snapshot.json": {"version": 1, "hashes": hashes}})),
                    Err(TufError::Unsupported(_))
                ),
                "{hashes}"
            );
        }
        for hashes in [
            json!({}),
            json!({"sha256": "00"}),
            json!({"sha256": hash(0xab).to_uppercase()}),
            json!([]),
        ] {
            assert!(
                matches!(
                    ts(json!({"snapshot.json": {"version": 1, "hashes": hashes}})),
                    Err(TufError::Malformed { .. })
                ),
                "{hashes}"
            );
        }
        assert!(matches!(
            Snapshot::from_signed(&json!({
                "_type": "snapshot", "spec_version": "1.0.31", "version": 1,
                "expires": "2026-11-22T00:00:00Z",
                "meta": {"other.json": {"version": 1}},
            })),
            Err(TufError::Malformed { .. })
        ));
    }

    #[test]
    fn delegations_and_bad_target_paths_are_refused() {
        let targets = |extra: Value, path: &str| {
            let mut v = json!({
                "_type": "targets", "spec_version": "1.0.31", "version": 1,
                "expires": "2026-11-22T00:00:00Z",
                "targets": {path: {"length": 1, "hashes": {"sha256": hash(1)}}},
            });
            if let Some(extra) = extra.as_object() {
                v.as_object_mut().unwrap().extend(extra.clone());
            }
            Targets::from_signed(&v, Profile::Legacy)
        };
        targets(json!({}), "indexes/stable.json").unwrap();
        targets(json!({}), "a/b-c_d+e.1").unwrap();
        for delegations in [json!({"keys": {}, "roles": []}), json!({}), Value::Null] {
            assert!(
                matches!(
                    targets(json!({"delegations": delegations}), "a"),
                    Err(TufError::Unsupported(m)) if m.contains("delegations")
                ),
                "{delegations}"
            );
        }
        for path in [
            "", "/a", "a/", "a//b", "./a", "a/../b", "..", "a\\b", "a b", "a%2fb", "é", "a:b",
        ] {
            assert!(
                matches!(targets(json!({}), path), Err(TufError::Malformed { .. })),
                "{path:?}"
            );
        }
        assert!(TargetPath::parse(&"a".repeat(513)).is_err());
        assert!(TargetPath::parse(&"a".repeat(512)).is_ok());
    }

    #[test]
    fn expiry_is_strictly_after_now() {
        let t = datetime!(2026-11-15 12:00 UTC);
        ensure_fresh(Role::Timestamp, t + time::Duration::seconds(1), t).unwrap();
        for expires in [t, t - time::Duration::seconds(1)] {
            assert!(matches!(
                ensure_fresh(Role::Timestamp, expires, t),
                Err(TufError::Expired {
                    role: Role::Timestamp,
                    ..
                })
            ));
        }
        assert_eq!(format_expires(t).unwrap(), "2026-11-15T12:00:00Z");
        assert_eq!(parse_expires("2026-11-15T12:00:00Z").unwrap(), t);
        // Another offset and nanoseconds are written as UTC whole seconds.
        let odd = datetime!(2026-11-15 15:00:00.9 +3);
        assert_eq!(format_expires(odd).unwrap(), "2026-11-15T12:00:00Z");
    }

    #[test]
    fn the_envelope_keeps_what_was_signed_and_writes_canonical_files() {
        let text = r#" { "signatures" : [ {"sig":"bb","keyid":"b"}, {"keyid":"a","sig":"aa"} ],
            "signed" : {"z": 1, "unknown": {"b": [1, 2], "a": null}} } "#;
        let env = Envelope::parse(text.as_bytes(), 1000, "t").unwrap();
        assert_eq!(
            String::from_utf8(env.canonical_signed().unwrap()).unwrap(),
            r#"{"unknown":{"a":null,"b":[1,2]},"z":1}"#
        );
        assert_eq!(
            String::from_utf8(env.to_file().unwrap()).unwrap(),
            "{\"signatures\":[{\"keyid\":\"a\",\"sig\":\"aa\"},{\"keyid\":\"b\",\"sig\":\"bb\"}],\"signed\":{\"unknown\":{\"a\":null,\"b\":[1,2]},\"z\":1}}\n"
        );
        // The file written reads back as the same envelope.
        let again = Envelope::parse(&env.to_file().unwrap(), 1000, "t").unwrap();
        assert_eq!(again.signed, env.signed);

        for bad in [
            r#"{"signed": {}}"#,
            r#"{"signatures": []}"#,
            r#"{"signed": {}, "signatures": [], "x": 1}"#,
            r#"{"signed": {}, "signatures": [{"keyid": "a"}]}"#,
            r#"[]"#,
        ] {
            assert!(
                matches!(
                    Envelope::parse(bad.as_bytes(), 1000, "t"),
                    Err(TufError::Malformed { .. })
                ),
                "{bad}"
            );
        }
    }
}
