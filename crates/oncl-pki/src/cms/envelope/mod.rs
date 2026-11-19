//! CMS encryption and decryption with RSA recipients: `EnvelopedData` (RFC 5652) and
//! `AuthEnvelopedData` (RFC 5083) for one or several recipients chosen by certificate.
//!
//! # Profiles
//!
//! | [`EnvelopeProfile`] | structure | key transport | content cipher | integrity |
//! |---|---|---|---|---|
//! | `RsaOaepSha256Aes256Gcm` | `AuthEnvelopedData` | RSAES-OAEP, SHA-256, MGF1-SHA-256 | AES-256-GCM, 128-bit tag | authenticated |
//! | `RsaOaepSha256Aes256Cbc` | `EnvelopedData` | RSAES-OAEP, SHA-256, MGF1-SHA-256 | AES-256-CBC | **none** |
//!
//! [`encrypt`] makes only these two. [`decrypt`] reads them and, because they are what other
//! software produces, also AES-128/192-CBC, AES-128/192-GCM and OAEP with a label. What it
//! reads is checked, never guessed: any other algorithm is an
//! [`EnvelopeError::UnsupportedProfile`], and nothing is silently replaced by another
//! algorithm.
//!
//! RSAES-PKCS1-v1_5 key transport and DES-EDE3-CBC (what the Kalkan provider of NCALayer
//! writes, and the only RSA envelope it writes that it can read back) are **legacy**: refused
//! unless [`DecryptOptions::allow_legacy`] is set, never produced. RSAES-PKCS1-v1_5 is
//! vulnerable to padding oracles by construction; the decryption follows RFC 3218 (a failed
//! unwrap continues with a random key, so the failure shows only as a content failure), but
//! the unauthenticated content that goes with it is not authenticated, whatever the oracle.
//!
//! # No KZ GOST profile
//!
//! There is no GOST (KZ GOST 34.310-2004 / 34.10-2015) profile: none is proven. The Kalkan
//! provider has no key agreement and no GOST content cipher in its CMS layer, so no
//! independent oracle writes or reads such an envelope (`docs/dev/platform-interop.md`,
//! `fixtures/platform/envelope/profiles.toml`). A GOST recipient certificate is refused with a
//! named reason; no Russian OID is substituted.
//!
//! # Integrity and staging
//!
//! [`EnvelopeReport::integrity`] says whether the content was authenticated. Only a verified
//! GCM tag makes it [`Integrity::Authenticated`]; an `EnvelopedData` envelope (CBC) is
//! [`Integrity::Unauthenticated`] and the caller must not treat its plaintext as
//! tamper-evident.
//!
//! The plaintext goes to a [`StagingSink`] as it is decrypted, in bounded pieces; with GCM the
//! tag is the last element of the message, so those pieces are **provisional** until
//! [`decrypt`] returns `Ok`. On any error [`StagingSink::discard`] has been called: nothing of
//! a failed or unauthenticated-so-far message may be published. The caller publishes (renames
//! the staged file to its final name) only after `Ok`.
//!
//! This is weaker than "no plaintext leaves before the tag is verified", and says so: the
//! library does write unverified plaintext into the sink it is given (a 1 GiB message
//! cannot be held in memory until its tag at the end is read). The guarantee holds only if
//! the sink is a real staging area: a temporary file in an owner-only directory that nothing
//! else reads and that is renamed to its final name after `Ok`, or deleted by `discard`. The
//! library has no file sink of its own yet; a caller that passes anything else (a network
//! stream, a visible file) releases unauthenticated plaintext.
//!
//! # Memory
//!
//! Both directions work on a 64 KiB window. The only structures kept whole are the header
//! (recipient infos, at most 4 MiB). A 64-bit plaintext length is fine; AES-GCM is limited to
//! `2^36 - 32` bytes by the mode ([`EnvelopeError::TooLarge`]).
//!
//! # Encoding
//!
//! With a known plaintext length ([`EncryptSpec::plaintext_len`]) the output is definite-length
//! DER. Without it the container is written with indefinite lengths (BER, as OpenSSL's
//! streaming mode does) and the ciphertext as OCTET STRING segments. [`decrypt`] reads both,
//! and constructed-segment BER from other writers.

mod cipher;
mod wire;

use super::asn1::{IssuerAndSerialNumber, der_set_contents};
use crate::ber;
use crate::cert::Certificate;
use crate::key::{KeyError, PrivateKey, PublicKey};
use cipher::{CHUNK, CipherError, Decryptor, Encryptor, GCM_MAX_BYTES};
use der::asn1::{Any, Int, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Sequence, Tagged};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use spki::AlgorithmIdentifierOwned;
use std::io::{Read, Write};
use wire::{Header, Parser};
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage};
use zeroize::Zeroizing;

/// A recipient limit: a recipient list is read whole.
pub const MAX_RECIPIENTS: usize = 1024;
/// RSA recipient key size bounds, as for the private side ([`crate::key`]).
const RSA_BITS: std::ops::RangeInclusive<usize> = 2048..=8192;

const ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
/// id-ct-authEnvelopedData (RFC 5083).
const AUTH_ENVELOPED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.23");
const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// id-RSAES-OAEP (RFC 8017 appendix A.2.1).
const RSAES_OAEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const P_SPECIFIED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.9");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const AES128_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
const AES192_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.22");
const AES256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");
const AES128_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.6");
const AES192_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.26");
const AES256_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");
const DES_EDE3_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.3.7");
const EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
const ANY_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");

/// The envelopes [`encrypt`] makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeProfile {
    /// `AuthEnvelopedData`, RSAES-OAEP (SHA-256, MGF1-SHA-256), AES-256-GCM: authenticated.
    RsaOaepSha256Aes256Gcm,
    /// `EnvelopedData`, RSAES-OAEP (SHA-256, MGF1-SHA-256), AES-256-CBC: **not**
    /// authenticated.
    RsaOaepSha256Aes256Cbc,
}

impl EnvelopeProfile {
    /// Whether the profile authenticates the content.
    pub fn integrity(self) -> Integrity {
        match self {
            EnvelopeProfile::RsaOaepSha256Aes256Gcm => Integrity::Authenticated,
            EnvelopeProfile::RsaOaepSha256Aes256Cbc => Integrity::Unauthenticated,
        }
    }
}

/// Whether the content of an envelope was authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integrity {
    /// An authentication tag over the whole content verified.
    Authenticated,
    /// The content cipher has no authentication: modification is not detected.
    Unauthenticated,
}

/// The CMS structure of an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Structure {
    /// `EnvelopedData`.
    Enveloped,
    /// `AuthEnvelopedData`.
    AuthEnveloped,
}

/// How the content-encryption key reached the recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyTransport {
    /// RSAES-OAEP with SHA-256 and MGF1-SHA-256.
    RsaOaepSha256,
    /// RSAES-PKCS1-v1_5 (legacy; [`DecryptOptions::allow_legacy`]).
    RsaPkcs1V15,
}

/// The content cipher of an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentCipher {
    /// AES-CBC with a 128/192/256-bit key (`bits`).
    AesCbc {
        /// Key size in bits.
        bits: u16,
    },
    /// AES-GCM with a 128/192/256-bit key (`bits`).
    AesGcm {
        /// Key size in bits.
        bits: u16,
    },
    /// DES-EDE3-CBC (legacy; [`DecryptOptions::allow_legacy`]).
    DesEde3Cbc,
}

/// What [`decrypt`] established about a message it decrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeReport {
    /// The CMS structure.
    pub structure: Structure,
    /// The key transport of the recipient that was used.
    pub key_transport: KeyTransport,
    /// The content cipher.
    pub content_cipher: ContentCipher,
    /// Whether the content was authenticated.
    pub integrity: Integrity,
    /// The named profile the message is in, if it is one of [`EnvelopeProfile`].
    pub profile: Option<EnvelopeProfile>,
    /// `true` when a legacy algorithm was accepted (opt-in).
    pub legacy: bool,
    /// The content type of the plaintext (`id-data` unless the sender said otherwise).
    pub content_type: ObjectIdentifier,
    /// Recipient infos in the message (of every type).
    pub recipient_count: usize,
    /// Index of the recipient info that was used.
    pub recipient_index: usize,
    /// Plaintext bytes written to the staging sink.
    pub plaintext_len: u64,
}

/// What [`encrypt`] wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptReport {
    /// The profile used.
    pub profile: EnvelopeProfile,
    /// Number of recipients.
    pub recipients: usize,
    /// Plaintext bytes read.
    pub plaintext_len: u64,
}

/// What to encrypt and for whom.
#[derive(Clone, Copy, Debug)]
pub struct EncryptSpec<'a> {
    /// The profile.
    pub profile: EnvelopeProfile,
    /// Recipient certificates, each checked for use in encryption ([`CertProblem`]).
    pub recipients: &'a [&'a Certificate],
    /// The exact plaintext length when known: the output is then definite-length DER and
    /// the reader must deliver exactly that many bytes ([`EnvelopeError::LengthMismatch`]).
    pub plaintext_len: Option<u64>,
}

/// What [`decrypt`] accepts besides the named profiles.
#[derive(Clone, Copy, Debug, Default)]
pub struct DecryptOptions {
    /// Accept RSAES-PKCS1-v1_5 key transport and DES-EDE3-CBC content: foreign legacy data.
    /// Off by default; never enable it for data from an untrusted network peer.
    pub allow_legacy: bool,
}

/// Where decrypted plaintext is staged until [`decrypt`] returns `Ok`.
///
/// `write_chunk` gets the plaintext in order; `discard` is called when decryption fails and
/// must drop everything written (truncate and remove the staging file). The sink must not
/// publish the data under a final name by itself.
pub trait StagingSink {
    /// Appends plaintext.
    ///
    /// # Errors
    ///
    /// Any I/O error; decryption stops with [`EnvelopeError::Sink`].
    fn write_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// Drops everything written so far.
    fn discard(&mut self);
}

impl StagingSink for Vec<u8> {
    fn write_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }

    fn discard(&mut self) {
        self.clear();
    }
}

/// Why a certificate is not usable as an encryption recipient.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CertProblem {
    /// The key is GOST: no KZ GOST envelope profile is proven, so none is offered.
    #[error("GOST key {0}: no KZ GOST CMS envelope profile is proven")]
    GostKey(String),
    /// The key is not an RSA key.
    #[error("key algorithm {0} is not supported for encryption")]
    UnsupportedKey(String),
    /// The RSA modulus is outside 2048..=8192 bits or the key is malformed.
    #[error("RSA key size or encoding is not acceptable")]
    KeySize,
    /// A key usage extension is present and lacks keyEncipherment.
    #[error("key usage does not allow keyEncipherment")]
    KeyUsage,
    /// An extended key usage extension is present and names neither emailProtection nor
    /// anyExtendedKeyUsage.
    #[error("extended key usage does not allow encryption (emailProtection)")]
    ExtendedKeyUsage,
    /// A key usage or extended key usage extension does not parse.
    #[error("key usage extension is malformed")]
    MalformedExtension,
}

/// Error of [`encrypt`] and [`decrypt`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// No recipient certificate was given.
    #[error("no recipient certificate given")]
    NoRecipients,
    /// More recipients than [`MAX_RECIPIENTS`].
    #[error("more than {MAX_RECIPIENTS} recipients")]
    TooManyRecipients,
    /// A recipient certificate (by index) is not suitable.
    #[error("recipient certificate {index}: {problem}")]
    UnsuitableCertificate {
        /// Index in the recipient list.
        index: usize,
        /// Why.
        problem: CertProblem,
    },
    /// The envelope uses an algorithm or structure that is not supported: what.
    #[error("unsupported envelope profile: {0}")]
    UnsupportedProfile(String),
    /// The envelope is not valid CMS.
    #[error("malformed envelope: {0}")]
    Malformed(String),
    /// The envelope ends before it is complete.
    #[error("the envelope is truncated")]
    Truncated,
    /// No recipient info of the envelope is addressed to the certificate.
    #[error("no recipient of the envelope matches the certificate")]
    NoMatchingRecipient,
    /// The private key is not the key of the certificate.
    #[error("the private key does not belong to the certificate")]
    KeyMismatch,
    /// The content-encryption key or the content could not be decrypted (wrong key, damaged
    /// message, bad padding): one error for all, so it is no oracle.
    #[error("decryption failed")]
    DecryptionFailed,
    /// The authentication tag does not verify: the message was changed or is not for this
    /// key.
    #[error("authentication tag does not verify")]
    AuthenticationFailed,
    /// The message is longer than the cipher mode allows.
    #[error("message too long for the content cipher")]
    TooLarge,
    /// The reader did not deliver the declared plaintext length.
    #[error("plaintext length differs from the declared length")]
    LengthMismatch,
    /// The operating system random generator failed.
    #[error("random generator failure")]
    Random,
    /// RSAES-OAEP encryption of the content-encryption key for a recipient failed: why. A
    /// key that passed the certificate checks does not normally do this.
    #[error("encrypting the content-encryption key for recipient {index}: {reason}")]
    KeyTransport {
        /// Index in the recipient list.
        index: usize,
        /// What the RSA implementation said.
        reason: String,
    },
    /// The input could not be read: why.
    #[error("reading the input: {0}")]
    Source(String),
    /// The output or the staging sink could not be written: why.
    #[error("writing the output: {0}")]
    Sink(String),
}

impl From<der::Error> for EnvelopeError {
    fn from(e: der::Error) -> Self {
        EnvelopeError::Malformed(e.to_string())
    }
}

impl From<CipherError> for EnvelopeError {
    fn from(e: CipherError) -> Self {
        match e {
            CipherError::BadPadding => EnvelopeError::DecryptionFailed,
            CipherError::BadTag => EnvelopeError::AuthenticationFailed,
            CipherError::TooLong => EnvelopeError::TooLarge,
        }
    }
}

// ---------------------------------------------------------------- ASN.1

/// `KeyTransRecipientInfo` (RFC 5652 6.2.1); `rid` is the raw `RecipientIdentifier` CHOICE.
#[derive(Clone, Debug, Sequence)]
struct KeyTransRecipientInfo {
    version: u8,
    rid: Any,
    key_encryption_algorithm: AlgorithmIdentifierOwned,
    encrypted_key: OctetString,
}

/// `RSAES-OAEP-params` (RFC 8017 A.2.1): every field optional, SHA-1 defaults.
#[derive(Clone, Debug, Default, Sequence)]
struct OaepParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    p_source: Option<AlgorithmIdentifierOwned>,
}

/// `GCMParameters` (RFC 5084): `aes-ICVlen` defaults to 12.
#[derive(Clone, Debug, Sequence)]
struct GcmParameters {
    nonce: OctetString,
    #[asn1(default = "default_icv_len")]
    icv_len: u8,
}

fn default_icv_len() -> u8 {
    12
}

fn sha256_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: SHA256,
        parameters: None,
    }
}

/// The `keyEncryptionAlgorithm` of every recipient info [`encrypt`] makes.
fn oaep_sha256_algorithm() -> Result<AlgorithmIdentifierOwned, EnvelopeError> {
    let mgf1_hash = sha256_alg().to_der()?;
    let params = OaepParams {
        hash: Some(sha256_alg()),
        mask_gen: Some(AlgorithmIdentifierOwned {
            oid: MGF1,
            parameters: Some(Any::from_der(&mgf1_hash)?),
        }),
        p_source: None,
    }
    .to_der()?;
    Ok(AlgorithmIdentifierOwned {
        oid: RSAES_OAEP,
        parameters: Some(Any::from_der(&params)?),
    })
}

fn decode_raw<'a, T: Decode<'a>>(der: &'a [u8]) -> Result<T, EnvelopeError> {
    T::from_der(der).map_err(|e| EnvelopeError::Malformed(e.to_string()))
}

/// A header structure as DER.
fn to_der(raw: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    ber::to_der(raw).map_err(|e| EnvelopeError::Malformed(e.to_string()))
}

// ---------------------------------------------------------------- certificates

/// The RSA public key of `cert` if the certificate may receive an envelope.
fn recipient_key(cert: &Certificate) -> Result<rsa::RsaPublicKey, CertProblem> {
    let tbs = cert.tbs_certificate();
    let spki = tbs.subject_public_key_info();
    let oid = spki.algorithm.oid;
    if oid != RSA_ENCRYPTION {
        let name = oid.to_string();
        return Err(if oid.to_string().starts_with("1.2.398.3.10.1.") {
            CertProblem::GostKey(name)
        } else {
            CertProblem::UnsupportedKey(name)
        });
    }
    match tbs.get_extension::<KeyUsage>() {
        Ok(Some((_, usage))) if !usage.key_encipherment() => return Err(CertProblem::KeyUsage),
        Ok(_) => {}
        Err(_) => return Err(CertProblem::MalformedExtension),
    }
    match tbs.get_extension::<ExtendedKeyUsage>() {
        Ok(Some((_, usage)))
            if !usage
                .0
                .iter()
                .any(|oid| *oid == EMAIL_PROTECTION || *oid == ANY_EXTENDED_KEY_USAGE) =>
        {
            return Err(CertProblem::ExtendedKeyUsage);
        }
        Ok(_) => {}
        Err(_) => return Err(CertProblem::MalformedExtension),
    }
    let bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or(CertProblem::KeySize)?;
    let key = rsa::RsaPublicKey::from_pkcs1_der(bits).map_err(|_| CertProblem::KeySize)?;
    if !RSA_BITS.contains(&key.n().bits()) || key.e().bits() > 33 {
        return Err(CertProblem::KeySize);
    }
    Ok(key)
}

/// Whether the `RecipientIdentifier` `rid` names `cert`.
fn rid_matches(rid: &Any, cert: &Certificate) -> Result<bool, EnvelopeError> {
    let tbs = cert.tbs_certificate();
    match rid.tag() {
        der::Tag::Sequence => {
            let sid: IssuerAndSerialNumber = rid.decode_as()?;
            Ok(sid.issuer == *tbs.issuer()
                && sid.serial_number.as_bytes() == tbs.serial_number().as_bytes())
        }
        // [0] IMPLICIT SubjectKeyIdentifier.
        der::Tag::ContextSpecific {
            constructed: false,
            number,
        } if number.value() == 0 => {
            let ski = tbs
                .get_extension::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
                .map_err(|e| EnvelopeError::Malformed(e.to_string()))?;
            Ok(ski.is_some_and(|(_, ski)| ski.0.as_bytes() == rid.value()))
        }
        other => Err(EnvelopeError::Malformed(format!(
            "recipient identifier of type {other}"
        ))),
    }
}

// ---------------------------------------------------------------- encryption

fn random(buf: &mut [u8]) -> Result<(), EnvelopeError> {
    getrandom::fill(buf).map_err(|_| EnvelopeError::Random)
}

fn sink_error(e: std::io::Error) -> EnvelopeError {
    EnvelopeError::Sink(e.to_string())
}

/// Reads until `buf` is full or the source ends; returns the bytes read.
fn read_full<R: Read>(input: &mut R, buf: &mut [u8]) -> Result<usize, EnvelopeError> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(EnvelopeError::Source(e.to_string())),
        }
    }
    Ok(filled)
}

/// Encrypts the bytes of `input` for the recipients of `spec`, writing the CMS to `out`.
///
/// Every recipient certificate must pass the encryption checks ([`CertProblem`]); trust in
/// the certificate (path, validity, revocation) is the caller's business
/// ([`crate::validation`]). Nothing of the plaintext is kept; memory is bounded by a 64 KiB
/// window and the recipient infos. On an error `out` may hold a partial message: discard it.
///
/// # Errors
///
/// [`EnvelopeError`]: no or too many recipients, an unsuitable certificate, a length
/// mismatch, a failing reader or writer, a message beyond the GCM limit.
pub fn encrypt<R: Read, W: Write>(
    spec: &EncryptSpec<'_>,
    mut input: R,
    mut out: W,
) -> Result<EncryptReport, EnvelopeError> {
    if spec.recipients.is_empty() {
        return Err(EnvelopeError::NoRecipients);
    }
    if spec.recipients.len() > MAX_RECIPIENTS {
        return Err(EnvelopeError::TooManyRecipients);
    }
    let authenticated = spec.profile == EnvelopeProfile::RsaOaepSha256Aes256Gcm;
    // A declared length that cannot be framed (the lengths below are sums of it) or that
    // the mode cannot carry under one key and nonce.
    let too_long = |n: u64| n > 1 << 62 || (authenticated && n > GCM_MAX_BYTES);
    if spec.plaintext_len.is_some_and(too_long) {
        return Err(EnvelopeError::TooLarge);
    }
    let mut keys = Vec::with_capacity(spec.recipients.len());
    for (index, cert) in spec.recipients.iter().enumerate() {
        keys.push(
            recipient_key(cert)
                .map_err(|problem| EnvelopeError::UnsuitableCertificate { index, problem })?,
        );
    }

    let mut cek = Zeroizing::new([0u8; 32]);
    random(&mut cek[..])?;
    let (mut encryptor, algorithm): (Box<dyn Encryptor>, AlgorithmIdentifierOwned) =
        if authenticated {
            let mut nonce = [0u8; 12];
            random(&mut nonce)?;
            let params = GcmParameters {
                nonce: OctetString::new(nonce.to_vec())?,
                icv_len: 16,
            }
            .to_der()?;
            (
                Box::new(cipher::Gcm::new(&cek[..], &nonce).expect("a 256-bit AES key")),
                AlgorithmIdentifierOwned {
                    oid: AES256_GCM,
                    parameters: Some(Any::from_der(&params)?),
                },
            )
        } else {
            let mut iv = [0u8; 16];
            random(&mut iv)?;
            let params = OctetString::new(iv.to_vec())?.to_der()?;
            (
                cipher::aes_cbc_encryptor(&cek[..], &iv)
                    .expect("a 256-bit AES key and a 128-bit IV"),
                AlgorithmIdentifierOwned {
                    oid: AES256_CBC,
                    parameters: Some(Any::from_der(&params)?),
                },
            )
        };

    // Recipient infos.
    let key_algorithm = oaep_sha256_algorithm()?;
    let mut infos = Vec::with_capacity(keys.len());
    for (index, (cert, key)) in spec.recipients.iter().zip(&keys).enumerate() {
        let tbs = cert.tbs_certificate();
        let rid = IssuerAndSerialNumber {
            issuer: tbs.issuer().clone(),
            serial_number: Int::new(tbs.serial_number().as_bytes())?,
        }
        .to_der()?;
        let wrapped = key
            .encrypt(
                &mut crate::keygen::OsRng,
                rsa::Oaep::new::<rsa::sha2::Sha256>(),
                &cek[..],
            )
            .map_err(|e| EnvelopeError::KeyTransport {
                index,
                reason: e.to_string(),
            })?;
        infos.push(
            KeyTransRecipientInfo {
                version: 0,
                rid: Any::from_der(&rid)?,
                key_encryption_algorithm: key_algorithm.clone(),
                encrypted_key: OctetString::new(wrapped)?,
            }
            .to_der()?,
        );
    }
    let recipient_infos = wire::tlv(wire::SET, &der_set_contents(infos));

    // Layout: everything before the encrypted content, and what follows it.
    let content_type = DATA.to_der()?;
    let algorithm = algorithm.to_der()?;
    let mut encrypted_info_head = content_type;
    encrypted_info_head.extend_from_slice(&algorithm);
    let version = [0x02, 0x01, 0x00];
    let outer_oid = if authenticated {
        AUTH_ENVELOPED_DATA
    } else {
        ENVELOPED_DATA
    }
    .to_der()?;
    let mac_len: u64 = if authenticated { 2 + 16 } else { 0 };

    let ciphertext_len = spec
        .plaintext_len
        .map(|n| if authenticated { n } else { (n / 16 + 1) * 16 });
    let (content_header, content_trailer): (Vec<u8>, &[u8]) = match ciphertext_len {
        Some(len) => (wire::header(wire::CONTEXT_0_PRIMITIVE, Some(len)), &[]),
        None => (wire::header(wire::CONTEXT_0_CONSTRUCTED, None), &[0, 0]),
    };
    let sequence = |content: Option<u64>| wire::header(wire::SEQUENCE, content);
    let trailer: &[u8] = if ciphertext_len.is_some() {
        &[]
    } else {
        &[0, 0]
    };
    let (ci, ctx0, enveloped, encrypted_info) = match ciphertext_len {
        Some(cl) => {
            let eci = encrypted_info_head.len() as u64 + content_header.len() as u64 + cl;
            let ed = version.len() as u64
                + recipient_infos.len() as u64
                + wire::header_len(eci)
                + eci
                + mac_len;
            let c0 = wire::header_len(ed) + ed;
            let ci = outer_oid.len() as u64 + wire::header_len(c0) + c0;
            (
                sequence(Some(ci)),
                wire::header(wire::CONTEXT_0_CONSTRUCTED, Some(c0)),
                sequence(Some(ed)),
                sequence(Some(eci)),
            )
        }
        None => (
            sequence(None),
            wire::header(wire::CONTEXT_0_CONSTRUCTED, None),
            sequence(None),
            sequence(None),
        ),
    };
    let write = |out: &mut W, bytes: &[u8]| out.write_all(bytes).map_err(sink_error);
    write(&mut out, &ci)?;
    write(&mut out, &outer_oid)?;
    write(&mut out, &ctx0)?;
    write(&mut out, &enveloped)?;
    write(&mut out, &version)?;
    write(&mut out, &recipient_infos)?;
    write(&mut out, &encrypted_info)?;
    write(&mut out, &encrypted_info_head)?;
    write(&mut out, &content_header)?;

    let mut plain = vec![0u8; CHUNK];
    let mut sealed = Vec::with_capacity(CHUNK + 32);
    let mut total = 0u64;
    let mut written = 0u64;
    let definite = ciphertext_len.is_some();
    let emit = |out: &mut W, bytes: &[u8], written: &mut u64| -> Result<(), EnvelopeError> {
        if bytes.is_empty() {
            return Ok(());
        }
        *written += bytes.len() as u64;
        if !definite {
            write(
                out,
                &wire::header(wire::OCTET_STRING, Some(bytes.len() as u64)),
            )?;
        }
        write(out, bytes)
    };
    loop {
        let n = read_full(&mut input, &mut plain)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if spec.plaintext_len.is_some_and(|expected| total > expected) {
            return Err(EnvelopeError::LengthMismatch);
        }
        if authenticated && total > GCM_MAX_BYTES {
            return Err(EnvelopeError::TooLarge);
        }
        sealed.clear();
        encryptor.update(&plain[..n], &mut sealed)?;
        emit(&mut out, &sealed, &mut written)?;
        if n < plain.len() {
            break;
        }
    }
    if spec.plaintext_len.is_some_and(|expected| total != expected) {
        return Err(EnvelopeError::LengthMismatch);
    }
    sealed.clear();
    let tag = encryptor.finish(&mut sealed)?;
    emit(&mut out, &sealed, &mut written)?;
    if ciphertext_len.is_some_and(|expected| written != expected) {
        return Err(EnvelopeError::LengthMismatch);
    }
    write(&mut out, content_trailer)?; // end of the encrypted content
    write(&mut out, trailer)?; // end of EncryptedContentInfo
    if let Some(tag) = tag {
        write(&mut out, &wire::tlv(wire::OCTET_STRING, &tag))?;
    }
    write(&mut out, trailer)?; // end of the (Auth)EnvelopedData
    write(&mut out, trailer)?; // end of the explicit [0]
    write(&mut out, trailer)?; // end of the ContentInfo
    out.flush().map_err(sink_error)?;
    Ok(EncryptReport {
        profile: spec.profile,
        recipients: spec.recipients.len(),
        plaintext_len: total,
    })
}

// ---------------------------------------------------------------- decryption

/// The content cipher of a message, as its `contentEncryptionAlgorithm` names it.
#[derive(Clone, Copy, Debug)]
enum Cipher {
    AesCbc { bits: u16 },
    AesGcm { bits: u16, icv_len: usize },
    DesEde3Cbc,
}

impl Cipher {
    fn key_len(self) -> usize {
        match self {
            Cipher::AesCbc { bits } | Cipher::AesGcm { bits, .. } => usize::from(bits / 8),
            Cipher::DesEde3Cbc => 24,
        }
    }

    fn report(self) -> ContentCipher {
        match self {
            Cipher::AesCbc { bits } => ContentCipher::AesCbc { bits },
            Cipher::AesGcm { bits, .. } => ContentCipher::AesGcm { bits },
            Cipher::DesEde3Cbc => ContentCipher::DesEde3Cbc,
        }
    }
}

fn parse_cipher(
    alg: &AlgorithmIdentifierOwned,
    structure: Structure,
    options: &DecryptOptions,
) -> Result<(Cipher, Vec<u8>), EnvelopeError> {
    let params = alg
        .parameters
        .as_ref()
        .ok_or_else(|| EnvelopeError::Malformed("content cipher has no parameters".into()))?;
    let cipher = match alg.oid {
        o if o == AES128_CBC => Cipher::AesCbc { bits: 128 },
        o if o == AES192_CBC => Cipher::AesCbc { bits: 192 },
        o if o == AES256_CBC => Cipher::AesCbc { bits: 256 },
        o if o == AES128_GCM => Cipher::AesGcm {
            bits: 128,
            icv_len: 0,
        },
        o if o == AES192_GCM => Cipher::AesGcm {
            bits: 192,
            icv_len: 0,
        },
        o if o == AES256_GCM => Cipher::AesGcm {
            bits: 256,
            icv_len: 0,
        },
        o if o == DES_EDE3_CBC => Cipher::DesEde3Cbc,
        o => {
            return Err(EnvelopeError::UnsupportedProfile(format!(
                "content encryption algorithm {o}"
            )));
        }
    };
    match (structure, cipher) {
        (Structure::AuthEnveloped, Cipher::AesGcm { .. }) => {}
        (Structure::AuthEnveloped, _) => {
            return Err(EnvelopeError::UnsupportedProfile(format!(
                "AuthEnvelopedData with content cipher {}",
                alg.oid
            )));
        }
        (Structure::Enveloped, Cipher::AesGcm { .. }) => {
            return Err(EnvelopeError::UnsupportedProfile(
                "AES-GCM inside EnvelopedData (RFC 5084 requires AuthEnvelopedData)".into(),
            ));
        }
        (Structure::Enveloped, _) => {}
    }
    if cipher.key_len() == 24 && matches!(cipher, Cipher::DesEde3Cbc) && !options.allow_legacy {
        return Err(EnvelopeError::UnsupportedProfile(
            "DES-EDE3-CBC is a legacy content cipher (DecryptOptions::allow_legacy)".into(),
        ));
    }
    match cipher {
        Cipher::AesGcm { bits, .. } => {
            let params: GcmParameters = params.decode_as()?;
            let icv_len = usize::from(params.icv_len);
            if params.nonce.as_bytes().len() != 12 {
                return Err(EnvelopeError::UnsupportedProfile(
                    "AES-GCM nonce other than 96 bits".into(),
                ));
            }
            if !(12..=16).contains(&icv_len) {
                return Err(EnvelopeError::UnsupportedProfile(format!(
                    "AES-GCM tag length {icv_len}"
                )));
            }
            Ok((
                Cipher::AesGcm { bits, icv_len },
                params.nonce.as_bytes().to_vec(),
            ))
        }
        Cipher::AesCbc { .. } | Cipher::DesEde3Cbc => {
            let iv: OctetString = params.decode_as()?;
            let expected = if matches!(cipher, Cipher::DesEde3Cbc) {
                8
            } else {
                16
            };
            if iv.as_bytes().len() != expected {
                return Err(EnvelopeError::Malformed(
                    "CBC initialization vector length".into(),
                ));
            }
            Ok((cipher, iv.as_bytes().to_vec()))
        }
    }
}

/// The OAEP label if `params` are exactly SHA-256 / MGF1-SHA-256, else the reason not.
fn oaep_label(params: Option<&Any>) -> Result<Vec<u8>, EnvelopeError> {
    let params: OaepParams = match params {
        Some(any) => any.decode_as()?,
        None => OaepParams::default(),
    };
    let unsupported = |what: &str| {
        Err(EnvelopeError::UnsupportedProfile(format!(
            "RSAES-OAEP {what}"
        )))
    };
    let is_sha256 = |alg: &AlgorithmIdentifierOwned| {
        alg.oid == SHA256
            && alg
                .parameters
                .as_ref()
                .is_none_or(|p| p.tag() == der::Tag::Null)
    };
    match &params.hash {
        Some(hash) if is_sha256(hash) => {}
        Some(hash) => return unsupported(&format!("hash {}", hash.oid)),
        None => return unsupported("hash SHA-1 (the default)"),
    }
    match &params.mask_gen {
        Some(mgf) if mgf.oid == MGF1 => {
            let inner: Option<AlgorithmIdentifierOwned> =
                mgf.parameters.as_ref().map(Any::decode_as).transpose()?;
            if !inner.as_ref().is_some_and(is_sha256) {
                return unsupported("MGF1 with a hash other than SHA-256");
            }
        }
        Some(mgf) => return unsupported(&format!("mask generation {}", mgf.oid)),
        None => return unsupported("MGF1-SHA-1 (the default)"),
    }
    match &params.p_source {
        None => Ok(Vec::new()),
        Some(source) if source.oid == P_SPECIFIED => {
            let label: OctetString = source
                .parameters
                .as_ref()
                .ok_or_else(|| EnvelopeError::Malformed("pSpecified without a label".into()))?
                .decode_as()?;
            Ok(label.into_bytes().into())
        }
        Some(source) => unsupported(&format!("label source {}", source.oid)),
    }
}

/// What [`decrypt`] needs to unwrap a key.
struct Unwrapper<'a> {
    key: &'a PrivateKey,
    options: &'a DecryptOptions,
    key_len: usize,
}

impl Unwrapper<'_> {
    fn unwrap(
        &self,
        info: &KeyTransRecipientInfo,
    ) -> Result<(Zeroizing<Vec<u8>>, KeyTransport), EnvelopeError> {
        let alg = &info.key_encryption_algorithm;
        let wrapped = info.encrypted_key.as_bytes();
        if alg.oid == RSAES_OAEP {
            let label = oaep_label(alg.parameters.as_ref())?;
            let cek = self
                .key
                .decrypt_oaep_sha256(wrapped, &label)
                .map_err(key_error)?;
            if cek.len() != self.key_len {
                return Err(EnvelopeError::DecryptionFailed);
            }
            return Ok((Zeroizing::new(cek), KeyTransport::RsaOaepSha256));
        }
        if alg.oid == RSA_ENCRYPTION {
            if !self.options.allow_legacy {
                return Err(EnvelopeError::UnsupportedProfile(
                    "RSAES-PKCS1-v1_5 key transport is a legacy profile (DecryptOptions::allow_legacy)"
                        .into(),
                ));
            }
            // RFC 3218 2.3.2: a failure continues with a random key, so that it surfaces
            // only when the content does not decrypt.
            let cek = match self.key.decrypt_pkcs1_v15(wrapped) {
                Ok(cek) if cek.len() == self.key_len => cek,
                Ok(_) | Err(KeyError::DecryptionFailed) => {
                    let mut random_key = vec![0u8; self.key_len];
                    random(&mut random_key)?;
                    random_key
                }
                Err(other) => return Err(key_error(other)),
            };
            return Ok((Zeroizing::new(cek), KeyTransport::RsaPkcs1V15));
        }
        Err(EnvelopeError::UnsupportedProfile(format!(
            "key encryption algorithm {}",
            alg.oid
        )))
    }
}

fn key_error(error: KeyError) -> EnvelopeError {
    match error {
        KeyError::DecryptionFailed => EnvelopeError::DecryptionFailed,
        KeyError::UnsupportedAlgorithm => {
            EnvelopeError::UnsupportedProfile("the private key is not an RSA key".into())
        }
        other => EnvelopeError::Source(other.to_string()),
    }
}

/// Decrypts the CMS envelope read from `input` for `recipient` (a certificate named by the
/// message) and its private `key`, staging the plaintext in `stage`.
///
/// See the [module documentation](self) for the profiles, the staging contract and the
/// integrity statement. In short: on `Ok` the plaintext in `stage` is complete and
/// [`EnvelopeReport::integrity`] tells whether it is authenticated; on `Err`
/// [`StagingSink::discard`] has been called and nothing may be published. With an
/// authenticated profile an error is returned if even one bit of the ciphertext or tag
/// differs.
///
/// # Errors
///
/// [`EnvelopeError`]: [`KeyMismatch`](EnvelopeError::KeyMismatch) when `key` is not the key
/// of `recipient`; [`NoMatchingRecipient`](EnvelopeError::NoMatchingRecipient);
/// [`UnsupportedProfile`](EnvelopeError::UnsupportedProfile) for algorithms outside the
/// profiles (and legacy ones without the opt-in); [`DecryptionFailed`](EnvelopeError::DecryptionFailed),
/// [`AuthenticationFailed`](EnvelopeError::AuthenticationFailed), malformed or truncated
/// input, trailing data after the message, reader and sink failures.
pub fn decrypt<R: Read, S: StagingSink>(
    input: R,
    recipient: &Certificate,
    key: &PrivateKey,
    options: &DecryptOptions,
    stage: &mut S,
) -> Result<EnvelopeReport, EnvelopeError> {
    let result = decrypt_inner(input, recipient, key, options, stage);
    if result.is_err() {
        stage.discard();
    }
    result
}

fn expect(parser: &mut Parser<impl Read>, tag: u8, what: &str) -> Result<Header, EnvelopeError> {
    let header = parser.header()?;
    if header.tag != tag {
        return Err(EnvelopeError::Malformed(format!(
            "{what}: unexpected element {:#04x}",
            header.tag
        )));
    }
    Ok(header)
}

fn decrypt_inner<R: Read, S: StagingSink>(
    input: R,
    recipient: &Certificate,
    key: &PrivateKey,
    options: &DecryptOptions,
    stage: &mut S,
) -> Result<EnvelopeReport, EnvelopeError> {
    let spki = recipient.tbs_certificate().subject_public_key_info();
    let public = PublicKey::from_spki(spki)
        .map_err(|e| EnvelopeError::Malformed(format!("recipient certificate key: {e}")))?;
    if public != key.public_key() {
        return Err(EnvelopeError::KeyMismatch);
    }

    let mut parser = Parser::new(input, CHUNK);
    let header = expect(&mut parser, wire::SEQUENCE, "ContentInfo")?;
    parser.enter(header)?;
    let content_type: ObjectIdentifier = decode_raw(&to_der(&parser.raw_element()?)?)?;
    let structure = if content_type == ENVELOPED_DATA {
        Structure::Enveloped
    } else if content_type == AUTH_ENVELOPED_DATA {
        Structure::AuthEnveloped
    } else {
        return Err(EnvelopeError::Malformed(format!(
            "content type {content_type} is not envelopedData or authEnvelopedData"
        )));
    };
    let header = expect(&mut parser, wire::CONTEXT_0_CONSTRUCTED, "content")?;
    parser.enter(header)?;
    let header = expect(&mut parser, wire::SEQUENCE, "EnvelopedData")?;
    parser.enter(header)?;
    let version: u8 = decode_raw(&to_der(&parser.raw_element()?)?)?;
    let version_ok = match structure {
        Structure::Enveloped => matches!(version, 0 | 2 | 3 | 4),
        Structure::AuthEnveloped => version == 0,
    };
    if !version_ok {
        return Err(EnvelopeError::UnsupportedProfile(format!(
            "CMS version {version}"
        )));
    }
    let mut header = parser.header()?;
    if header.tag == wire::CONTEXT_0_CONSTRUCTED {
        // originatorInfo: certificates and CRLs of the originator; nothing here uses them.
        parser.skip(header)?;
        header = parser.header()?;
    }
    if header.tag != wire::SET {
        return Err(EnvelopeError::Malformed("recipientInfos is missing".into()));
    }
    parser.enter(header)?;
    let mut infos: Vec<Vec<u8>> = Vec::new();
    let mut info_bytes = 0usize;
    while !parser.at_end()? {
        if infos.len() == MAX_RECIPIENTS {
            return Err(EnvelopeError::TooManyRecipients);
        }
        let raw = to_der(&parser.raw_element()?)?;
        info_bytes += raw.len();
        if info_bytes > wire::MAX_RAW {
            return Err(EnvelopeError::Malformed(
                "recipientInfos are too large".into(),
            ));
        }
        infos.push(raw);
    }
    parser.leave()?;
    if infos.is_empty() {
        return Err(EnvelopeError::Malformed("no recipient infos".into()));
    }

    let header = expect(&mut parser, wire::SEQUENCE, "EncryptedContentInfo")?;
    parser.enter(header)?;
    let inner_type: ObjectIdentifier = decode_raw(&to_der(&parser.raw_element()?)?)?;
    let algorithm: AlgorithmIdentifierOwned = decode_raw(&to_der(&parser.raw_element()?)?)?;
    let (cipher, iv) = parse_cipher(&algorithm, structure, options)?;
    if parser.at_end()? {
        return Err(EnvelopeError::Malformed(
            "the encrypted content is missing".into(),
        ));
    }
    let content = parser.header()?;
    if content.tag != wire::CONTEXT_0_PRIMITIVE && content.tag != wire::CONTEXT_0_CONSTRUCTED {
        return Err(EnvelopeError::Malformed(
            "encryptedContent is not [0]".into(),
        ));
    }

    // The content-encryption key: from the first recipient info for this certificate that
    // decrypts.
    let unwrapper = Unwrapper {
        key,
        options,
        key_len: cipher.key_len(),
    };
    let mut selected = None;
    let mut unsupported_kinds = Vec::new();
    let mut failure = None;
    for (index, raw) in infos.iter().enumerate() {
        if raw[0] != wire::SEQUENCE {
            unsupported_kinds.push(match raw[0] {
                0xA1 => "KeyAgreeRecipientInfo",
                0xA2 => "KEKRecipientInfo",
                0xA3 => "PasswordRecipientInfo",
                0xA4 => "OtherRecipientInfo",
                _ => "an unknown recipient info",
            });
            continue;
        }
        let info: KeyTransRecipientInfo = decode_raw(raw)?;
        if !matches!(info.version, 0 | 2) {
            return Err(EnvelopeError::Malformed(
                "KeyTransRecipientInfo version".into(),
            ));
        }
        if !rid_matches(&info.rid, recipient)? {
            continue;
        }
        match unwrapper.unwrap(&info) {
            Ok(unwrapped) => {
                selected = Some((index, unwrapped));
                break;
            }
            Err(error @ EnvelopeError::UnsupportedProfile(_)) => return Err(error),
            Err(error) => failure = Some(error),
        }
    }
    let (recipient_index, (cek, key_transport)) = match selected {
        Some(selected) => selected,
        None => {
            return Err(match failure {
                Some(failure) => failure,
                None if !unsupported_kinds.is_empty() => {
                    EnvelopeError::UnsupportedProfile(format!(
                        "no key transport recipient matches the certificate, the message has {}",
                        unsupported_kinds.join(", ")
                    ))
                }
                None => EnvelopeError::NoMatchingRecipient,
            });
        }
    };

    let mut decryptor: Box<dyn Decryptor> = match cipher {
        Cipher::AesCbc { .. } => cipher::aes_cbc_decryptor(&cek, &iv),
        Cipher::AesGcm { .. } => {
            let nonce: [u8; 12] = iv
                .as_slice()
                .try_into()
                .expect("a 96-bit nonce was checked");
            cipher::Gcm::new(&cek, &nonce).map(|gcm| Box::new(gcm) as Box<dyn Decryptor>)
        }
        Cipher::DesEde3Cbc => cipher::des_ede3_cbc_decryptor(&cek, &iv),
    }
    .ok_or(EnvelopeError::DecryptionFailed)?;

    let mut plain = Vec::with_capacity(CHUNK + 32);
    let mut plaintext_len = 0u64;
    let mut forward = |piece: &[u8]| -> Result<(), EnvelopeError> {
        plain.clear();
        decryptor.update(piece, &mut plain)?;
        plaintext_len += plain.len() as u64;
        stage.write_chunk(&plain).map_err(sink_error)
    };
    parser.stream_octets(content, &mut forward)?;
    plain.clear();
    parser.leave()?; // EncryptedContentInfo

    let mut tag = None;
    if structure == Structure::AuthEnveloped {
        let raw = parser.raw_element()?;
        if raw[0] == 0xA1 {
            return Err(EnvelopeError::UnsupportedProfile(
                "AuthEnvelopedData with authenticated attributes".into(),
            ));
        }
        if raw[0] != wire::OCTET_STRING {
            return Err(EnvelopeError::Malformed("the MAC is missing".into()));
        }
        let mac: OctetString = decode_raw(&to_der(&raw)?)?;
        let Cipher::AesGcm { icv_len, .. } = cipher else {
            unreachable!("AuthEnvelopedData is GCM only")
        };
        if mac.as_bytes().len() != icv_len {
            return Err(EnvelopeError::Malformed(
                "the MAC length differs from the declared tag length".into(),
            ));
        }
        tag = Some(mac.into_bytes());
    }
    // Unprotected / unauthenticated attributes are not interpreted.
    while let Some(header) = parser.next()? {
        parser.skip(header)?;
    }
    parser.leave()?; // the (Auth)EnvelopedData
    parser.leave()?; // [0]
    parser.leave()?; // ContentInfo
    if !parser.at_eof()? {
        return Err(EnvelopeError::Malformed(
            "trailing data after the message".into(),
        ));
    }

    decryptor.finish(&mut plain, tag.as_deref())?;
    if !plain.is_empty() {
        plaintext_len += plain.len() as u64;
        stage.write_chunk(&plain).map_err(sink_error)?;
    }
    let integrity = match structure {
        Structure::AuthEnveloped => Integrity::Authenticated,
        Structure::Enveloped => Integrity::Unauthenticated,
    };
    let legacy = key_transport == KeyTransport::RsaPkcs1V15 || matches!(cipher, Cipher::DesEde3Cbc);
    let profile = match (structure, key_transport, cipher) {
        (
            Structure::AuthEnveloped,
            KeyTransport::RsaOaepSha256,
            Cipher::AesGcm {
                bits: 256,
                icv_len: 16,
            },
        ) => Some(EnvelopeProfile::RsaOaepSha256Aes256Gcm),
        (Structure::Enveloped, KeyTransport::RsaOaepSha256, Cipher::AesCbc { bits: 256 }) => {
            Some(EnvelopeProfile::RsaOaepSha256Aes256Cbc)
        }
        _ => None,
    };
    Ok(EnvelopeReport {
        structure,
        key_transport,
        content_cipher: cipher.report(),
        integrity,
        profile,
        legacy,
        content_type: inner_type,
        recipient_count: infos.len(),
        recipient_index,
        plaintext_len,
    })
}
