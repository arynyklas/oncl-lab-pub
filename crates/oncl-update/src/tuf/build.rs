//! Making a repository: the `signed` part of each role, signing, and the file names of
//! consistent snapshots. The tools that publish (`cargo xtask`) use this; the client does
//! not. Each function makes what the client of this module reads, with the same canonical
//! code and the same model: what is built is read back by [`Root::from_signed`] and its
//! siblings before it is returned.
//!
//! A repository is made in steps, each by the key of its role (and the roles' keys need not
//! be in one place: only a signed file travels from step to step):
//!
//! 1. [`targets`] over the files of the repository, signed by the targets key
//!    ([`sign`]); the files themselves are in [`target_files`] under their hash names;
//! 2. [`snapshot`] over the targets file as signed, by the snapshot key;
//! 3. [`timestamp`] over the snapshot file as signed, by the timestamp key.
//!
//! A [`root`] is signed with [`sign`] by the keys of the root before it and then by the
//! keys it names itself ([`add_signatures`]): a client needs both for each new version.
//!
//! The files are deterministic: the same `signed` and keys always give the same bytes (the
//! envelope in canonical JSON, signatures sorted by key id, Ed25519 being deterministic,
//! then one `\n`), which is also what a snapshot's and a timestamp's hashes and lengths are
//! of.

use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::client::Limits;
use super::ed25519::SigningKey;
use super::error::{Role, TufError};
use super::keys::PublicKey;
use super::layout;
use super::model::{
    Digest, Envelope, Profile, Root, SPEC_VERSION, Snapshot, TARGETS_META, Targets, Timestamp,
    format_expires,
};
use super::names::TargetPath;

/// The largest file [`add_signatures`] reads.
const MAX_FILE_LEN: u64 = 4 << 20;

/// The keys of a role and its threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleDef {
    /// The public keys: distinct.
    pub keys: Vec<PublicKey>,
    /// How many must sign: 1 to `keys.len()`.
    pub threshold: u32,
}

/// The four roles of a root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootDef {
    /// Who signs roots.
    pub root: RoleDef,
    /// Who signs the timestamp.
    pub timestamp: RoleDef,
    /// Who signs the snapshot.
    pub snapshot: RoleDef,
    /// Who signs the targets.
    pub targets: RoleDef,
}

/// The `signed` of a root: `version` (1 for the first, then the one before plus one),
/// expiring at `expires` (whole seconds, UTC), with the keys of `def`. No key may serve two
/// roles (the client refuses a root where one does).
///
/// # Errors
///
/// [`TufError::Malformed`] for a role without keys, a threshold of 0 or above the number of
/// its keys, a key twice in a role or in two roles, a version of 0.
pub fn root(version: u64, expires: OffsetDateTime, def: &RootDef) -> Result<Value, TufError> {
    let roles = [
        (Role::Root, &def.root),
        (Role::Timestamp, &def.timestamp),
        (Role::Snapshot, &def.snapshot),
        (Role::Targets, &def.targets),
    ];
    let mut keys = Map::new();
    let mut role_members = Map::new();
    for (role, role_def) in roles {
        let mut keyids = Vec::new();
        for key in &role_def.keys {
            let id = key.key_id();
            keys.insert(id.to_hex(), key.to_value());
            keyids.push(Value::String(id.to_hex()));
        }
        role_members.insert(
            role.name().to_owned(),
            json!({"keyids": keyids, "threshold": role_def.threshold}),
        );
    }
    let signed = json!({
        "_type": "root",
        "spec_version": SPEC_VERSION,
        "consistent_snapshot": true,
        "version": version,
        "expires": format_expires(expires)?,
        "keys": keys,
        "roles": role_members,
    });
    Root::from_signed(&signed)?;
    Ok(signed)
}

/// The `signed` of a targets file over `files`, `(target path, content)`: each listed by
/// its length and sha256. Paths are distinct and valid ([`TargetPath`]); there are no
/// delegations ([`Profile::Legacy`]).
///
/// # Errors
///
/// [`TufError::Malformed`] for a path that is invalid or listed twice, a version of 0.
pub fn targets(
    version: u64,
    expires: OffsetDateTime,
    files: &[(&str, &[u8])],
) -> Result<Value, TufError> {
    let mut listed = Map::new();
    for (path, content) in files {
        let entry = json!({
            "length": content.len(),
            "hashes": {"sha256": Digest::of(content).to_hex()},
        });
        if listed.insert((*path).to_owned(), entry).is_some() {
            return Err(TufError::malformed(
                "targets",
                format!("{path} is listed twice"),
            ));
        }
    }
    let signed = json!({
        "_type": "targets",
        "spec_version": SPEC_VERSION,
        "version": version,
        "expires": format_expires(expires)?,
        "targets": listed,
    });
    Targets::from_signed(&signed, Profile::Legacy)?;
    Ok(signed)
}

/// What a snapshot or a timestamp lists of the file below it: version, length and sha256 of
/// the file as signed.
fn meta_entry(version: u64, file: &[u8]) -> Value {
    json!({
        "version": version,
        "length": file.len(),
        "hashes": {"sha256": Digest::of(file).to_hex()},
    })
}

/// The `signed` of a snapshot listing the targets file `targets_file` (the bytes of the
/// signed file, [`sign`]'s result) as version `targets_version`.
///
/// # Errors
///
/// [`TufError::Malformed`] for a version of 0.
pub fn snapshot(
    version: u64,
    expires: OffsetDateTime,
    targets_version: u64,
    targets_file: &[u8],
) -> Result<Value, TufError> {
    let signed = json!({
        "_type": "snapshot",
        "spec_version": SPEC_VERSION,
        "version": version,
        "expires": format_expires(expires)?,
        "meta": {TARGETS_META: meta_entry(targets_version, targets_file)},
    });
    Snapshot::from_signed(&signed)?;
    Ok(signed)
}

/// The `signed` of a timestamp listing the snapshot file `snapshot_file` (the bytes of the
/// signed file) as version `snapshot_version`. `version` is the caller's: the repository
/// publishes the Unix time of signing, which grows without any state kept.
///
/// # Errors
///
/// [`TufError::Malformed`] for a version of 0.
pub fn timestamp(
    version: u64,
    expires: OffsetDateTime,
    snapshot_version: u64,
    snapshot_file: &[u8],
) -> Result<Value, TufError> {
    let signed = json!({
        "_type": "timestamp",
        "spec_version": SPEC_VERSION,
        "version": version,
        "expires": format_expires(expires)?,
        "meta": {"snapshot.json": meta_entry(snapshot_version, snapshot_file)},
    });
    Timestamp::from_signed(&signed)?;
    Ok(signed)
}

/// The file made of `signed` and its signatures by `keys` (each key once). A root,
/// timestamp, snapshot or targets file larger than the client's default limit for it
/// ([`Limits::default`]) is refused: the client would never read it.
///
/// `signed` may be any JSON that has a canonical form, also with members this client does not
/// read: they are signed as they are.
///
/// # Errors
///
/// [`TufError::Float`] or [`TufError::TooDeep`] if `signed` has no canonical form;
/// [`TufError::TooLarge`] for a file over the client's limit.
pub fn sign(signed: &Value, keys: &[&SigningKey]) -> Result<Vec<u8>, TufError> {
    let envelope = Envelope {
        signed: signed.clone(),
        signatures: Vec::new(),
    };
    sign_envelope(envelope, keys)
}

/// `file` with the signatures of `keys` added to its own (a key that signed it already has
/// its signature replaced, so no key is listed twice): the second signature a root needs, or
/// a threshold signed in turns.
///
/// # Errors
///
/// The errors of [`Envelope::parse`]; [`TufError::TooLarge`] as for [`sign`].
pub fn add_signatures(file: &[u8], keys: &[&SigningKey]) -> Result<Vec<u8>, TufError> {
    let envelope = Envelope::parse(file, MAX_FILE_LEN, "the file to sign")?;
    sign_envelope(envelope, keys)
}

fn sign_envelope(mut envelope: Envelope, keys: &[&SigningKey]) -> Result<Vec<u8>, TufError> {
    let message = envelope.canonical_signed()?;
    for key in keys {
        let signature = key.signature(&message);
        envelope.signatures.retain(|s| s.keyid != signature.keyid);
        envelope.signatures.push(signature);
    }
    let file = envelope.to_file()?;
    let limits = Limits::default();
    let kind = envelope.signed.get("_type").and_then(Value::as_str);
    let limit = match kind {
        Some("root") => limits.root,
        Some("timestamp") => limits.timestamp,
        Some("snapshot") => limits.snapshot,
        Some("targets") => limits.targets,
        _ => return Ok(file),
    };
    if file.len() as u64 > limit {
        return Err(TufError::TooLarge {
            what: format!("the {} file", kind.unwrap_or_default()),
            limit,
        });
    }
    Ok(file)
}

/// The files of the repository as the consistent snapshot layout stores them: for each
/// `(target path, content)` the path under the repository
/// ([`layout::target_file_path`]) and the content.
///
/// # Errors
///
/// [`TufError::Malformed`] for an invalid target path.
pub fn target_files(files: &[(&str, &[u8])]) -> Result<Vec<(String, Vec<u8>)>, TufError> {
    files
        .iter()
        .map(|(path, content)| {
            let path = TargetPath::parse(path)
                .map_err(|e| TufError::malformed("targets", e.to_string()))?;
            Ok((
                layout::target_file_path(&path, &Digest::of(content)),
                content.to_vec(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const EXPIRES: OffsetDateTime = datetime!(2027-01-01 0:00 UTC);

    fn key(n: u8) -> SigningKey {
        SigningKey::from_seed(&[n; 32]).unwrap()
    }

    fn def(roles: [(&SigningKey, u32); 4]) -> RootDef {
        let role = |(k, threshold): (&SigningKey, u32)| RoleDef {
            keys: vec![k.public()],
            threshold,
        };
        RootDef {
            root: role(roles[0]),
            timestamp: role(roles[1]),
            snapshot: role(roles[2]),
            targets: role(roles[3]),
        }
    }

    #[test]
    fn a_root_is_built_and_read_back() {
        let keys: Vec<_> = (1..=4).map(key).collect();
        let d = def([(&keys[0], 1), (&keys[1], 1), (&keys[2], 1), (&keys[3], 1)]);
        let signed = root(1, EXPIRES, &d).unwrap();
        let read = Root::from_signed(&signed).unwrap();
        assert_eq!(read.version, 1);
        assert_eq!(read.expires, EXPIRES);
        assert_eq!(read.keys.len(), 4);
        assert_eq!(read.timestamp.keyids, [keys[1].key_id()]);
        // The same input is the same bytes.
        assert_eq!(
            sign(&signed, &[&keys[0]]).unwrap(),
            sign(&root(1, EXPIRES, &d).unwrap(), &[&keys[0]]).unwrap()
        );
        assert!(sign(&signed, &[&keys[0]]).unwrap().ends_with(b"}\n"));
    }

    #[test]
    fn a_root_that_would_be_refused_is_not_built() {
        let keys: Vec<_> = (1..=5).map(key).collect();
        let good = def([(&keys[0], 1), (&keys[1], 1), (&keys[2], 1), (&keys[3], 1)]);
        let refuse = |d: RootDef, version: u64| {
            matches!(root(version, EXPIRES, &d), Err(TufError::Malformed { .. }))
        };
        // A key serving two roles (owner policy: the four keys are distinct).
        let mut shared = good.clone();
        shared.snapshot = shared.timestamp.clone();
        assert!(refuse(shared, 1));
        // A key twice in a role.
        let mut twice = good.clone();
        twice.root.keys = vec![keys[0].public(), keys[0].public()];
        assert!(refuse(twice, 1));
        let mut none = good.clone();
        none.targets.keys.clear();
        assert!(refuse(none, 1));
        let mut zero = good.clone();
        zero.targets.threshold = 0;
        assert!(refuse(zero, 1));
        let mut over = good.clone();
        over.targets.threshold = 2;
        assert!(refuse(over, 1));
        assert!(refuse(good.clone(), 0));
        let mut two_of_two = good;
        two_of_two.root = RoleDef {
            keys: vec![keys[0].public(), keys[4].public()],
            threshold: 2,
        };
        root(1, EXPIRES, &two_of_two).unwrap();
    }

    #[test]
    fn targets_snapshot_and_timestamp_list_what_is_below_them() {
        let files: &[(&str, &[u8])] = &[
            ("indexes/stable.json", b"{}\n"),
            ("indexes/beta.json", b"[]"),
        ];
        let targets_signed = targets(3, EXPIRES, files).unwrap();
        let read = Targets::from_signed(&targets_signed, Profile::Legacy).unwrap();
        assert_eq!(read.targets["indexes/beta.json"].length, 2);
        assert_eq!(read.targets["indexes/beta.json"].sha256, Digest::of(b"[]"));

        let k = key(9);
        let targets_file = sign(&targets_signed, &[&k]).unwrap();
        let snapshot_signed = snapshot(5, EXPIRES, 3, &targets_file).unwrap();
        let meta = Snapshot::from_signed(&snapshot_signed).unwrap().meta[TARGETS_META].clone();
        assert_eq!(meta.version, 3);
        assert_eq!(meta.length, Some(targets_file.len() as u64));
        assert_eq!(meta.sha256, Some(Digest::of(&targets_file)));

        let snapshot_file = sign(&snapshot_signed, &[&k]).unwrap();
        let timestamp_signed = timestamp(1_800_000_000, EXPIRES, 5, &snapshot_file).unwrap();
        let ts = Timestamp::from_signed(&timestamp_signed).unwrap();
        assert_eq!((ts.version, ts.snapshot.version), (1_800_000_000, 5));
        assert_eq!(ts.snapshot.sha256, Some(Digest::of(&snapshot_file)));

        assert!(matches!(
            targets(1, EXPIRES, &[("a", b"x"), ("a", b"y")]),
            Err(TufError::Malformed { .. })
        ));
        assert!(matches!(
            targets(1, EXPIRES, &[("../a", b"x")]),
            Err(TufError::Malformed { .. })
        ));
        assert!(matches!(
            snapshot(0, EXPIRES, 1, b""),
            Err(TufError::Malformed { .. })
        ));
        assert!(matches!(
            timestamp(0, EXPIRES, 1, b""),
            Err(TufError::Malformed { .. })
        ));
    }

    #[test]
    fn target_files_are_named_by_their_hash() {
        let files: &[(&str, &[u8])] = &[("indexes/stable.json", b"abc")];
        let stored = target_files(files).unwrap();
        assert_eq!(
            stored,
            [(
                "targets/indexes/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.stable.json"
                    .to_owned(),
                b"abc".to_vec()
            )]
        );
        assert!(target_files(&[("/abs", b"")]).is_err());
    }

    #[test]
    fn signatures_are_added_once_per_key() {
        let (a, b) = (key(1), key(2));
        let signed = json!({"x": 1, "future": {"field": [true]}});
        let by_a = sign(&signed, &[&a]).unwrap();
        let both = add_signatures(&by_a, &[&b]).unwrap();
        let env = Envelope::parse(&both, 10_000, "f").unwrap();
        assert_eq!(env.signatures.len(), 2);
        // Signing again by the same key replaces its signature.
        let again = add_signatures(&both, &[&a, &b]).unwrap();
        assert_eq!(again, both);
        assert_eq!(
            sign(&signed, &[&b, &a]).unwrap(),
            both,
            "the order of keys does not matter"
        );
        // The signed part is untouched, unknown members included.
        assert_eq!(env.signed, signed);
        assert!(add_signatures(b"{", &[&a]).is_err());
        assert!(matches!(
            sign(&json!({"f": serde_json::Number::from_f64(0.5)}), &[&a]),
            Err(TufError::Float)
        ));
    }
}
