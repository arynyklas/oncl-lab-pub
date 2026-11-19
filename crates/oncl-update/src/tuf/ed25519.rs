//! Ed25519 through `ring`: verifying signatures, counting them toward a threshold, and the
//! signing keys the repository tools use.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use zeroize::Zeroizing;

use super::error::{Role, TufError};
use super::keys::{KeyId, PublicKey};
use super::model::{Envelope, RoleKeys, Root, Signature};

/// The length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Whether `signature` is `key`'s Ed25519 signature of `message`.
pub fn verify(key: &PublicKey, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
    UnparsedPublicKey::new(&ED25519, key.as_bytes())
        .verify(message, signature)
        .is_ok()
}

/// How many of the keys of `role` (looked up in `keys`) made a valid signature of `message`
/// among `signatures`, each key counted once: a signature by a key that is not the role's,
/// one whose `keyid` or `sig` is not lowercase hex of the right length, one that does not
/// verify, and a second signature by a key already counted all count for nothing.
pub fn count_valid(
    message: &[u8],
    signatures: &[Signature],
    role: &RoleKeys,
    keys: &BTreeMap<KeyId, PublicKey>,
) -> usize {
    let mut counted = BTreeSet::new();
    for signature in signatures {
        let Some(id) = KeyId::from_hex(&signature.keyid) else {
            continue;
        };
        if !role.keyids.contains(&id) || counted.contains(&id) {
            continue;
        }
        let (Some(key), Some(sig)) = (
            keys.get(&id),
            crate::hex::decode::<SIGNATURE_LEN>(&signature.sig),
        ) else {
            continue;
        };
        if verify(key, message, &sig) {
            counted.insert(id);
        }
    }
    counted.len()
}

/// Checks that `envelope` is signed by a threshold of the keys `role` names in `root`. `what`
/// names the file and whose keys are asked, for the error.
///
/// # Errors
///
/// [`TufError::Signature`] if fewer distinct keys signed than the threshold;
/// [`TufError::Float`] or [`TufError::TooDeep`] if `signed` has no canonical form.
pub fn verify_role(
    envelope: &Envelope,
    root: &Root,
    role: Role,
    what: &str,
) -> Result<(), TufError> {
    verify_threshold(envelope, root.role(role), &root.keys, what)
}

/// Checks that `envelope` is signed by a threshold of the keys `role` names, looked up in
/// `keys`: those of a root, or of the delegations of a targets file. `what` names the file
/// and whose keys are asked, for the error.
///
/// # Errors
///
/// As [`verify_role`].
pub fn verify_threshold(
    envelope: &Envelope,
    role: &RoleKeys,
    keys: &BTreeMap<KeyId, PublicKey>,
    what: &str,
) -> Result<(), TufError> {
    let message = envelope.canonical_signed()?;
    let valid = count_valid(&message, &envelope.signatures, role, keys);
    if valid < role.threshold as usize {
        return Err(TufError::Signature {
            what: what.to_owned(),
            valid,
            threshold: role.threshold,
        });
    }
    Ok(())
}

/// An Ed25519 key pair that signs metadata.
pub struct SigningKey {
    pair: Ed25519KeyPair,
    public: PublicKey,
}

impl SigningKey {
    /// A new random key and its PKCS#8 encoding (the form [`SigningKey::from_pkcs8`] reads;
    /// the caller stores it, protected). The copy returned is wiped when dropped.
    ///
    /// # Errors
    ///
    /// [`TufError::Key`] if the system's random generator fails.
    pub fn generate() -> Result<(SigningKey, Zeroizing<Vec<u8>>), TufError> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| TufError::Key("the system random generator failed".to_owned()))?;
        let key = SigningKey::from_pkcs8(pkcs8.as_ref())?;
        Ok((key, Zeroizing::new(pkcs8.as_ref().to_vec())))
    }

    /// The key of a PKCS#8 v2 document (with the public key), as [`SigningKey::generate`]
    /// writes it.
    ///
    /// # Errors
    ///
    /// [`TufError::Key`] if `pkcs8` is not an Ed25519 key.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<SigningKey, TufError> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|e| TufError::Key(format!("not an Ed25519 PKCS#8 key: {e}")))?;
        Ok(SigningKey::of(pair))
    }

    /// The key of a 32-byte seed.
    ///
    /// # Errors
    ///
    /// [`TufError::Key`] if ring refuses the seed.
    pub fn from_seed(seed: &[u8; 32]) -> Result<SigningKey, TufError> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|e| TufError::Key(format!("not an Ed25519 seed: {e}")))?;
        Ok(SigningKey::of(pair))
    }

    fn of(pair: Ed25519KeyPair) -> SigningKey {
        let mut public = [0u8; 32];
        public.copy_from_slice(pair.public_key().as_ref());
        SigningKey {
            pair,
            public: PublicKey::from_bytes(public),
        }
    }

    /// The public key.
    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// The public key's id.
    pub fn key_id(&self) -> KeyId {
        self.public.key_id()
    }

    /// The signature of `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        let mut out = [0u8; SIGNATURE_LEN];
        out.copy_from_slice(self.pair.sign(message).as_ref());
        out
    }

    /// The signature of `message` as an entry of a file's `signatures`.
    pub fn signature(&self, message: &[u8]) -> Signature {
        Signature {
            keyid: self.key_id().to_hex(),
            sig: crate::hex::encode(&self.sign(message)),
        }
    }
}

impl fmt::Debug for SigningKey {
    /// The public key only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({})", self.key_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_seed(&[n; 32]).unwrap()
    }

    fn role_of(keys: &[&SigningKey], threshold: u32) -> (RoleKeys, BTreeMap<KeyId, PublicKey>) {
        (
            RoleKeys {
                keyids: keys.iter().map(|k| k.key_id()).collect(),
                threshold,
            },
            keys.iter().map(|k| (k.key_id(), k.public())).collect(),
        )
    }

    #[test]
    fn signatures_verify_against_their_key_and_message_only() {
        let (a, b) = (key(1), key(2));
        let sig = a.sign(b"message");
        assert!(verify(&a.public(), b"message", &sig));
        assert!(!verify(&a.public(), b"messagE", &sig));
        assert!(!verify(&b.public(), b"message", &sig));
        let mut flipped = sig;
        flipped[10] ^= 1;
        assert!(!verify(&a.public(), b"message", &flipped));
        // Ed25519 is deterministic: the same bytes every time.
        assert_eq!(a.sign(b"message"), sig);
    }

    #[test]
    fn generated_keys_round_trip_through_pkcs8() {
        let (key, pkcs8) = SigningKey::generate().unwrap();
        let again = SigningKey::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(again.public(), key.public());
        assert!(verify(&key.public(), b"m", &again.sign(b"m")));
        assert!(matches!(
            SigningKey::from_pkcs8(&pkcs8[..40]),
            Err(TufError::Key(_))
        ));
        assert!(matches!(SigningKey::from_pkcs8(b""), Err(TufError::Key(_))));
        // The debug form names the key by its id, nothing secret.
        assert_eq!(format!("{key:?}"), format!("SigningKey({})", key.key_id()));
        let (other, _) = SigningKey::generate().unwrap();
        assert_ne!(other.public(), key.public());
    }

    #[test]
    fn only_distinct_trusted_keys_count_toward_the_threshold() {
        let (a, b, c) = (key(1), key(2), key(3));
        let (role, keys) = role_of(&[&a, &b], 2);
        let msg = b"signed";

        assert_eq!(
            count_valid(msg, &[a.signature(msg), b.signature(msg)], &role, &keys),
            2
        );
        // One key twice (the same signature, or two valid ones: Ed25519 gives one) counts once.
        assert_eq!(
            count_valid(msg, &[a.signature(msg), a.signature(msg)], &role, &keys),
            1
        );
        // A key outside the role counts for nothing, even if the root knows it.
        let mut known = keys.clone();
        known.insert(c.key_id(), c.public());
        assert_eq!(
            count_valid(msg, &[a.signature(msg), c.signature(msg)], &role, &known),
            1
        );
        // A bad signature, an unparsable one and a made-up key id count for nothing.
        let mut bad = b.signature(msg);
        let first = if bad.sig.starts_with('0') { "1" } else { "0" };
        bad.sig.replace_range(..1, first);
        let garbage = Signature {
            keyid: b.key_id().to_hex(),
            sig: "zz".to_owned(),
        };
        let nobody = Signature {
            keyid: "ff".repeat(32),
            sig: a.signature(msg).sig,
        };
        let shouty = Signature {
            keyid: a.key_id().to_hex().to_uppercase(),
            sig: a.signature(msg).sig,
        };
        assert_eq!(
            count_valid(
                msg,
                &[bad, garbage, nobody, shouty, a.signature(msg)],
                &role,
                &keys
            ),
            1
        );
        assert_eq!(
            count_valid(
                b"other",
                &[a.signature(msg), b.signature(msg)],
                &role,
                &keys
            ),
            0
        );
    }
}
