//! Public keys and their ids: what a root lists and a signature names. The operations that
//! need a signature algorithm (`verify`, signing, generating keys) are in [`super::ed25519`];
//! nothing here depends on it, so `build.rs` can check the embedded root with this code.
//!
//! The only key type is Ed25519: `keytype` and `scheme` are both `ed25519`, and the public
//! key is its 32 bytes as 64 lowercase hex digits.
//!
//! A key's id (`keyid`) is the lowercase hex sha256 of the canonical JSON
//! ([`super::canonical`]) of the key object `{"keytype", "scheme", "keyval": {"public"}}`.
//! A client recomputes it for every key of a root and refuses a root that names a key under
//! another id: a signature names its key by id, and the id must not be a label the signer of
//! the root chose.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Digest as _;

use super::canonical;
use super::error::TufError;

/// `keytype` of an Ed25519 key.
pub const KEY_TYPE: &str = "ed25519";
/// `scheme` of an Ed25519 key.
pub const SCHEME: &str = "ed25519";

/// The id of a key: the sha256 of its canonical key object.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(#[serde(with = "crate::hex::array")] [u8; 32]);

impl KeyId {
    /// The id `hex` spells; `None` unless it is 64 lowercase hex digits.
    pub fn from_hex(hex: &str) -> Option<KeyId> {
        crate::hex::decode(hex).map(KeyId)
    }

    /// 64 lowercase hex digits.
    pub fn to_hex(self) -> String {
        crate::hex::encode(&self.0)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({self})")
    }
}

/// An Ed25519 public key: always exactly 32 bytes, so no length is ever a parameter.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// The key of these 32 bytes. Whether they are a point of the curve is found out when
    /// a signature is verified against them.
    pub fn from_bytes(bytes: [u8; 32]) -> PublicKey {
        PublicKey(bytes)
    }

    /// The 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key `hex` spells; `None` unless it is 64 lowercase hex digits.
    pub fn from_hex(hex: &str) -> Option<PublicKey> {
        crate::hex::decode(hex).map(PublicKey)
    }

    /// 64 lowercase hex digits.
    pub fn to_hex(self) -> String {
        crate::hex::encode(&self.0)
    }

    /// The key object of a root's `keys`.
    pub fn to_value(self) -> Value {
        let mut keyval = Map::new();
        keyval.insert("public".to_owned(), Value::String(self.to_hex()));
        let mut key = Map::new();
        key.insert("keytype".to_owned(), Value::String(KEY_TYPE.to_owned()));
        key.insert("scheme".to_owned(), Value::String(SCHEME.to_owned()));
        key.insert("keyval".to_owned(), Value::Object(keyval));
        Value::Object(key)
    }

    /// Reads a key object. It has exactly the members `keytype`, `scheme` and `keyval`,
    /// which has exactly `public`: an extra member would be one the key's id does not
    /// cover.
    ///
    /// # Errors
    ///
    /// [`TufError::Unsupported`] for a `keytype` or `scheme` other than `ed25519`;
    /// [`TufError::Malformed`] for anything else that is not such an object.
    pub fn from_value(value: &Value) -> Result<PublicKey, TufError> {
        let bad = |why: &str| TufError::malformed("key", why);
        let key = value.as_object().ok_or_else(|| bad("not an object"))?;
        if key.len() != 3 {
            return Err(bad("members other than keytype, scheme and keyval"));
        }
        let text = |name: &str| {
            key.get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| bad(&format!("{name} is missing or not a string")))
        };
        let (keytype, scheme) = (text("keytype")?, text("scheme")?);
        if keytype != KEY_TYPE {
            return Err(TufError::Unsupported(format!("key type {keytype:?}")));
        }
        if scheme != SCHEME {
            return Err(TufError::Unsupported(format!("key scheme {scheme:?}")));
        }
        let keyval = key
            .get("keyval")
            .and_then(Value::as_object)
            .ok_or_else(|| bad("keyval is missing or not an object"))?;
        let public = keyval
            .get("public")
            .and_then(Value::as_str)
            .filter(|_| keyval.len() == 1)
            .ok_or_else(|| bad("keyval is not exactly {\"public\": <string>}"))?;
        PublicKey::from_hex(public).ok_or_else(|| bad("public is not 64 lowercase hex digits"))
    }

    /// The key's id.
    pub fn key_id(&self) -> KeyId {
        let canonical = canonical::to_vec(&self.to_value())
            .expect("a key object is strings in objects, always canonical");
        KeyId(sha2::Sha256::digest(canonical).into())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_key_id_is_the_sha256_of_the_canonical_key_object() {
        let key = PublicKey::from_bytes([7; 32]);
        let object = format!(
            r#"{{"keytype":"ed25519","keyval":{{"public":"{}"}},"scheme":"ed25519"}}"#,
            "07".repeat(32)
        );
        let expected: [u8; 32] = sha2::Sha256::digest(object.as_bytes()).into();
        assert_eq!(key.key_id(), KeyId(expected));
        assert_eq!(key.key_id().to_hex(), crate::hex::encode(&expected));
        assert_ne!(key.key_id(), PublicKey::from_bytes([8; 32]).key_id());
        assert_eq!(KeyId::from_hex(&key.key_id().to_hex()), Some(key.key_id()));
        assert_eq!(KeyId::from_hex(&key.key_id().to_hex().to_uppercase()), None);
    }

    #[test]
    fn a_key_object_round_trips_and_is_read_strictly() {
        let key = PublicKey::from_bytes(std::array::from_fn(|i| i as u8));
        assert_eq!(PublicKey::from_value(&key.to_value()).unwrap(), key);

        let public = key.to_hex();
        let with = |edit: &dyn Fn(&mut Value)| {
            let mut v = key.to_value();
            edit(&mut v);
            PublicKey::from_value(&v)
        };
        assert!(matches!(
            with(&|v| v["keytype"] = json!("rsa")),
            Err(TufError::Unsupported(_))
        ));
        assert!(matches!(
            with(&|v| v["scheme"] = json!("rsassa-pss-sha256")),
            Err(TufError::Unsupported(_))
        ));
        for edit in [
            (&|v: &mut Value| v["extra"] = json!(1)) as &dyn Fn(&mut Value),
            &|v| v["keyval"]["extra"] = json!(1),
            &|v| v["keyval"]["public"] = json!(public.to_uppercase()),
            &|v| v["keyval"]["public"] = json!(&public[2..]),
            &|v| v["keyval"]["public"] = json!(7),
            &|v| *v = json!("key"),
            &|v| {
                v.as_object_mut().unwrap().remove("scheme");
            },
        ] {
            assert!(
                matches!(with(edit), Err(TufError::Malformed { .. })),
                "{:?}",
                with(edit)
            );
        }
    }
}
