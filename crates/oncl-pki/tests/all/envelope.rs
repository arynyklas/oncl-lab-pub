//! CMS encryption and decryption (`oncl_pki::cms::envelope`): the profiles, recipients and
//! certificates, tampering, truncation and the legacy opt-in. Synthetic keys only. The
//! independent judges (OpenSSL, the local-only Kalkan oracle) are the rows `envelope-*` of
//! `cargo xtask platform-interop`; what is checked here is what needs no other tool.

use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use oncl_pki::cert::Certificate;
use oncl_pki::cms::envelope::{
    CertProblem, ContentCipher, DecryptOptions, EncryptSpec, EnvelopeError, EnvelopeProfile,
    EnvelopeReport, Integrity, KeyTransport, StagingSink, Structure, decrypt, encrypt,
};
use oncl_pki::key::PrivateKey;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_testkit::{fixture, read, synthetic};
use rsa::pkcs1::DecodeRsaPublicKey;
use spki::AlgorithmIdentifierOwned;
use std::io::Read;
use std::str::FromStr;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::name::Name;

const GCM: EnvelopeProfile = EnvelopeProfile::RsaOaepSha256Aes256Gcm;
const CBC: EnvelopeProfile = EnvelopeProfile::RsaOaepSha256Aes256Cbc;
const CHUNK: usize = 64 * 1024;
const EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

fn entry(name: &str) -> KeyEntry {
    let fixture = synthetic(name);
    load(&read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0)
}

fn oid(text: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(text)
}

fn extension(id: &str, value: Vec<u8>) -> Extension {
    Extension {
        extn_id: oid(id),
        critical: false,
        extn_value: OctetString::new(value).unwrap(),
    }
}

/// A recipient certificate for `key`, signed by the synthetic RSA signer.
fn certificate(
    key: &PrivateKey,
    common_name: &str,
    serial: u8,
    usage: Option<KeyUsages>,
    purposes: Option<&[&str]>,
) -> Certificate {
    let issuer = entry("user-rsa-sign");
    let mut spec = TestCertSpec::from_cert(&issuer.cert);
    spec.subject = Name::from_str(&format!("CN={common_name}")).unwrap();
    spec.public_key = key.public_key().to_spki();
    spec.serial = vec![serial];
    spec.extensions.clear();
    if let Some(usage) = usage {
        spec.extensions.push(extension(
            "2.5.29.15",
            KeyUsage(usage.into()).to_der().unwrap(),
        ));
    }
    if let Some(purposes) = purposes {
        let purposes = purposes.iter().map(|p| oid(p)).collect();
        spec.extensions.push(extension(
            "2.5.29.37",
            ExtendedKeyUsage(purposes).to_der().unwrap(),
        ));
    }
    issue_cert(&issuer, spec)
}

/// A recipient: its key and an encryption certificate.
struct Recipient {
    key: PrivateKey,
    cert: Certificate,
}

fn recipient_a() -> Recipient {
    let key = entry("user-rsa-sign").key;
    let cert = certificate(
        &key,
        "Recipient A",
        0x11,
        Some(KeyUsages::KeyEncipherment),
        Some(&[EMAIL_PROTECTION]),
    );
    Recipient { key, cert }
}

fn other_key() -> PrivateKey {
    PrivateKey::from_pkcs8_der(&read(fixture("openssl/rsa.pk8.der")), None).unwrap()
}

fn recipient_b() -> Recipient {
    let key = other_key();
    let cert = certificate(
        &key,
        "Recipient B",
        0x12,
        Some(KeyUsages::KeyEncipherment),
        None,
    );
    Recipient { key, cert }
}

/// Deterministic, non-repeating-looking bytes.
fn data(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn seal(
    profile: EnvelopeProfile,
    recipients: &[&Certificate],
    plaintext: &[u8],
    known_length: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    let report = encrypt(
        &EncryptSpec {
            profile,
            recipients,
            plaintext_len: known_length.then_some(plaintext.len() as u64),
        },
        plaintext,
        &mut out,
    )
    .unwrap();
    assert_eq!(report.plaintext_len, plaintext.len() as u64);
    assert_eq!(report.recipients, recipients.len());
    out
}

/// A staging sink that records what happened to it.
#[derive(Default)]
struct Recorder {
    bytes: Vec<u8>,
    writes: usize,
    discards: usize,
}

impl StagingSink for Recorder {
    fn write_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.writes += 1;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn discard(&mut self) {
        self.discards += 1;
        self.bytes.clear();
    }
}

fn open(
    message: &[u8],
    who: &Recipient,
    options: &DecryptOptions,
) -> (Result<EnvelopeReport, EnvelopeError>, Recorder) {
    let mut stage = Recorder::default();
    let result = decrypt(message, &who.cert, &who.key, options, &mut stage);
    (result, stage)
}

fn open_ok(message: &[u8], who: &Recipient) -> (EnvelopeReport, Vec<u8>) {
    let (result, stage) = open(message, who, &DecryptOptions::default());
    assert_eq!(
        stage.discards, 0,
        "a decryption that succeeds discards nothing"
    );
    (result.unwrap(), stage.bytes)
}

#[test]
fn gcm_profile_round_trips_and_is_reported_authenticated() {
    // Break caught: a profile that reports the wrong integrity, a chunk boundary that
    // loses or repeats bytes, an envelope that does not round-trip at a size boundary.
    let a = recipient_a();
    for len in [0, 1, 15, 16, 17, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 5] {
        let plaintext = data(len);
        for known in [true, false] {
            let message = seal(GCM, &[&a.cert], &plaintext, known);
            let (report, decrypted) = open_ok(&message, &a);
            assert_eq!(decrypted, plaintext, "{len} bytes, known length: {known}");
            assert_eq!(report.structure, Structure::AuthEnveloped);
            assert_eq!(report.integrity, Integrity::Authenticated);
            assert_eq!(report.profile, Some(GCM));
            assert_eq!(report.key_transport, KeyTransport::RsaOaepSha256);
            assert_eq!(report.content_cipher, ContentCipher::AesGcm { bits: 256 });
            assert!(!report.legacy);
            assert_eq!(report.plaintext_len, len as u64);
            assert_eq!(report.recipient_count, 1);
        }
    }
}

#[test]
fn cbc_profile_round_trips_and_is_reported_unauthenticated() {
    // Break caught: PKCS#7 padding errors at block boundaries; CBC claimed as authenticated.
    let a = recipient_a();
    for len in [
        0,
        1,
        15,
        16,
        17,
        31,
        32,
        CHUNK - 1,
        CHUNK,
        CHUNK + 1,
        2 * CHUNK + 16,
    ] {
        let plaintext = data(len);
        for known in [true, false] {
            let message = seal(CBC, &[&a.cert], &plaintext, known);
            let (report, decrypted) = open_ok(&message, &a);
            assert_eq!(decrypted, plaintext, "{len} bytes, known length: {known}");
            assert_eq!(report.structure, Structure::Enveloped);
            assert_eq!(report.integrity, Integrity::Unauthenticated);
            assert_eq!(report.profile, Some(CBC));
            assert_eq!(report.content_cipher, ContentCipher::AesCbc { bits: 256 });
        }
    }
}

#[test]
fn a_known_length_is_definite_der_and_an_unknown_one_is_indefinite_ber() {
    // Break caught: lengths computed wrongly (a strict DER reader rejects the message), or
    // an indefinite container that a BER reader cannot close.
    let a = recipient_a();
    for profile in [GCM, CBC] {
        let plaintext = data(1000);
        let definite = seal(profile, &[&a.cert], &plaintext, true);
        assert_eq!(oncl_pki::ber::to_der(&definite).unwrap(), definite);
        let indefinite = seal(profile, &[&a.cert], &plaintext, false);
        assert_eq!(
            indefinite[1], 0x80,
            "outer ContentInfo has an indefinite length"
        );
        assert_eq!(&indefinite[indefinite.len() - 2..], &[0, 0]);
        let der = oncl_pki::ber::to_der(&indefinite).unwrap();
        assert_ne!(der, indefinite);
        // The same message, normalized, still decrypts.
        let (_, decrypted) = open_ok(&der, &a);
        assert_eq!(decrypted, plaintext);
    }
}

#[test]
fn every_recipient_decrypts_and_a_stranger_does_not() {
    // Break caught: only the first recipient served; a recipient list that matches by
    // position instead of by certificate.
    let (a, b) = (recipient_a(), recipient_b());
    let key = other_key();
    let stranger = Recipient {
        cert: certificate(
            &key,
            "Stranger",
            0x13,
            Some(KeyUsages::KeyEncipherment),
            None,
        ),
        key,
    };
    let plaintext = data(5000);
    for profile in [GCM, CBC] {
        let message = seal(profile, &[&a.cert, &b.cert], &plaintext, true);
        for who in [&a, &b] {
            let (report, decrypted) = open_ok(&message, who);
            assert_eq!(decrypted, plaintext);
            assert_eq!(report.recipient_count, 2);
        }
        // Same key as B but another certificate (serial, name): no recipient info names it.
        let (result, stage) = open(&message, &stranger, &DecryptOptions::default());
        assert_eq!(result.unwrap_err(), EnvelopeError::NoMatchingRecipient);
        assert!(stage.bytes.is_empty());
    }
}

#[test]
fn each_message_is_fresh() {
    // Break caught: a fixed CEK/IV/nonce (the same plaintext must not give the same bytes).
    let (a, b) = (recipient_a(), recipient_b());
    let plaintext = data(64);
    let first = seal(GCM, &[&a.cert, &b.cert], &plaintext, true);
    let second = seal(GCM, &[&a.cert, &b.cert], &plaintext, true);
    assert_ne!(first, second);
    let tail = |m: &[u8]| m[m.len() - 18 - plaintext.len()..m.len() - 18].to_vec();
    assert_ne!(tail(&first), tail(&second));
}

#[test]
fn a_private_key_that_is_not_the_certificates_is_refused_before_anything_is_read() {
    // Break caught: decrypting with a mismatched pair, or a failure that depends on the
    // message.
    let (a, b) = (recipient_a(), recipient_b());
    let message = seal(GCM, &[&a.cert], b"secret", true);
    let mixed = Recipient {
        cert: a.cert.clone(),
        key: b.key,
    };
    let (result, stage) = open(&message, &mixed, &DecryptOptions::default());
    assert_eq!(result.unwrap_err(), EnvelopeError::KeyMismatch);
    assert_eq!(stage.writes, 0);
}

/// Offset of the first byte of the first 256-byte OCTET STRING of `message`: the RSA
/// ciphertext of the first recipient info.
fn wrapped_key_offset(message: &[u8]) -> usize {
    message
        .windows(4)
        .position(|w| w == [0x04, 0x82, 0x01, 0x00])
        .expect("a 256-byte OCTET STRING")
        + 4
}

#[test]
fn a_corrupted_wrapped_key_is_one_undifferentiated_failure() {
    // Break caught: telling "bad padding" from "wrong key" (an RSA oracle), or plaintext
    // after a failed unwrap.
    let a = recipient_a();
    let message = seal(GCM, &[&a.cert], &data(300), true);
    let marker = wrapped_key_offset(&message);
    for offset in [0, 100, 255] {
        let mut damaged = message.clone();
        damaged[marker + offset] ^= 0x40;
        let (result, stage) = open(&damaged, &a, &DecryptOptions::default());
        assert_eq!(result.unwrap_err(), EnvelopeError::DecryptionFailed);
        assert!(stage.bytes.is_empty());
        assert_eq!(stage.writes, 0, "nothing was decrypted without a key");
    }
}

#[test]
fn authenticated_profile_releases_no_plaintext_when_a_bit_changes() {
    // Break caught: plaintext handed out before the tag is verified, a tag that is not
    // compared, or a modification that goes unnoticed in a chunk or in the tag.
    let a = recipient_a();
    let plaintext = data(3 * CHUNK + 100);
    let message = seal(GCM, &[&a.cert], &plaintext, true);
    let end = message.len();
    let ciphertext_start = end - 18 - plaintext.len();
    let positions = [
        ciphertext_start,
        ciphertext_start + CHUNK,
        ciphertext_start + plaintext.len() - 1,
        end - 16, // first tag byte
        end - 1,  // last tag byte
    ];
    for position in positions {
        let mut damaged = message.clone();
        damaged[position] ^= 0x01;
        let (result, stage) = open(&damaged, &a, &DecryptOptions::default());
        assert_eq!(
            result.unwrap_err(),
            EnvelopeError::AuthenticationFailed,
            "byte {position}"
        );
        assert!(
            stage.bytes.is_empty(),
            "nothing survives in the staging sink"
        );
        assert_eq!(stage.discards, 1);
    }
    // The staging contract is real: the plaintext did reach the sink, provisionally.
    let mut damaged = message.clone();
    damaged[end - 1] ^= 0x01;
    let (_, stage) = open(&damaged, &a, &DecryptOptions::default());
    assert!(
        stage.writes > 0 && stage.discards == 1,
        "the sink was written and then discarded"
    );
}

#[test]
fn unauthenticated_profile_never_claims_authentication() {
    // Break caught: CBC reported as authenticated. A change in a middle block is NOT
    // detected (that is what "unauthenticated" means); the report must say so.
    let a = recipient_a();
    let plaintext = data(64);
    let message = seal(CBC, &[&a.cert], &plaintext, true);
    let mut damaged = message.clone();
    let len = damaged.len();
    damaged[len - 40] ^= 0x01; // inside the first ciphertext block
    let (report, decrypted) = open_ok(&damaged, &a);
    assert_eq!(report.integrity, Integrity::Unauthenticated);
    assert_ne!(decrypted, plaintext);
}

#[test]
fn a_truncated_message_never_decrypts() {
    // Break caught: a reader that accepts a message cut anywhere (a prefix that happens to
    // parse), or leaves plaintext behind.
    let (a, b) = (recipient_a(), recipient_b());
    for profile in [GCM, CBC] {
        for known in [true, false] {
            let message = seal(profile, &[&a.cert, &b.cert], &data(150), known);
            for cut in 0..message.len() {
                let (result, stage) = open(&message[..cut], &a, &DecryptOptions::default());
                let error = result.expect_err(&format!("{cut} of {} bytes", message.len()));
                assert!(
                    matches!(
                        error,
                        EnvelopeError::Truncated | EnvelopeError::Malformed(_)
                    ),
                    "cut at {cut}: {error:?}"
                );
                assert!(stage.bytes.is_empty());
            }
        }
    }
}

#[test]
fn bytes_after_the_message_are_refused() {
    // Break caught: a message with appended data accepted.
    let a = recipient_a();
    let mut message = seal(GCM, &[&a.cert], b"payload", true);
    message.push(0);
    let (result, stage) = open(&message, &a, &DecryptOptions::default());
    assert!(matches!(result.unwrap_err(), EnvelopeError::Malformed(_)));
    assert!(stage.bytes.is_empty());
}

#[test]
fn certificates_that_are_not_for_encryption_are_refused_with_the_reason() {
    // Break caught: a signing certificate used for encryption because its owner matches;
    // a GOST certificate silently handled; usage extensions ignored.
    let a = recipient_a();
    let signing = entry("user-rsa-sign");
    let refused = |cert: &Certificate| {
        let mut out = Vec::new();
        encrypt(
            &EncryptSpec {
                profile: GCM,
                recipients: &[&a.cert, cert],
                plaintext_len: None,
            },
            &b"x"[..],
            &mut out,
        )
        .unwrap_err()
    };
    // The synthetic signing certificate: digitalSignature + nonRepudiation only.
    assert_eq!(
        refused(&signing.cert),
        EnvelopeError::UnsuitableCertificate {
            index: 1,
            problem: CertProblem::KeyUsage
        }
    );
    // Key usage allows it, the extended key usage does not.
    let key = a.key.clone();
    let tls_only = certificate(
        &key,
        "Client",
        0x21,
        Some(KeyUsages::KeyEncipherment),
        Some(&[CLIENT_AUTH]),
    );
    assert_eq!(
        refused(&tls_only),
        EnvelopeError::UnsuitableCertificate {
            index: 1,
            problem: CertProblem::ExtendedKeyUsage
        }
    );
    // Key agreement is not key transport.
    let agreement = certificate(&key, "Agree", 0x22, Some(KeyUsages::KeyAgreement), None);
    assert_eq!(
        refused(&agreement),
        EnvelopeError::UnsuitableCertificate {
            index: 1,
            problem: CertProblem::KeyUsage
        }
    );
    // GOST: no proven KZ profile, so none is offered; the reason names the key.
    for name in ["user-gost2015-sign", "user-gost2004-sign"] {
        let gost = entry(name);
        let gost_cert = certificate(
            &gost.key,
            "Gost",
            0x23,
            Some(KeyUsages::KeyEncipherment),
            None,
        );
        let EnvelopeError::UnsuitableCertificate {
            index: 1,
            problem: CertProblem::GostKey(oid),
        } = refused(&gost_cert)
        else {
            panic!("{name}: GOST recipient accepted or wrongly described")
        };
        assert!(oid.starts_with("1.2.398.3.10.1."), "{oid}");
    }
    // A certificate with no usage extensions at all is allowed (RFC 5280: all usages).
    let plain = certificate(&key, "Plain", 0x24, None, None);
    let message = seal(GCM, &[&plain], b"ok", true);
    let (_, decrypted) = open_ok(&message, &Recipient { key, cert: plain });
    assert_eq!(decrypted, b"ok");
}

#[test]
fn recipient_list_limits() {
    let a = recipient_a();
    let mut out = Vec::new();
    fn spec<'a>(recipients: &'a [&'a Certificate]) -> EncryptSpec<'a> {
        EncryptSpec {
            profile: GCM,
            recipients,
            plaintext_len: None,
        }
    }
    assert_eq!(
        encrypt(&spec(&[]), &b""[..], &mut out).unwrap_err(),
        EnvelopeError::NoRecipients
    );
    let many = vec![&a.cert; 1025];
    assert_eq!(
        encrypt(&spec(&many), &b""[..], &mut out).unwrap_err(),
        EnvelopeError::TooManyRecipients
    );
}

#[test]
fn a_declared_length_must_be_the_real_one() {
    // Break caught: a header that promises a length the stream does not keep (the message
    // would be silently corrupt).
    let a = recipient_a();
    for (declared, actual) in [(10u64, 9usize), (10, 11), (0, 1)] {
        let mut out = Vec::new();
        let error = encrypt(
            &EncryptSpec {
                profile: CBC,
                recipients: &[&a.cert],
                plaintext_len: Some(declared),
            },
            &data(actual)[..],
            &mut out,
        )
        .unwrap_err();
        assert_eq!(
            error,
            EnvelopeError::LengthMismatch,
            "{declared} vs {actual}"
        );
    }
}

#[test]
fn reader_and_writer_failures_are_typed() {
    struct Failing(usize);
    impl Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::other("disk gone"));
            }
            let n = buf.len().min(self.0);
            buf[..n].fill(7);
            self.0 -= n;
            Ok(n)
        }
    }
    let a = recipient_a();
    let spec = EncryptSpec {
        profile: GCM,
        recipients: &[&a.cert],
        plaintext_len: None,
    };
    let error = encrypt(&spec, Failing(CHUNK + 5), Vec::new()).unwrap_err();
    assert_eq!(error, EnvelopeError::Source("disk gone".into()));

    struct FullSink;
    impl StagingSink for FullSink {
        fn write_chunk(&mut self, _: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("no space"))
        }
        fn discard(&mut self) {}
    }
    let message = seal(GCM, &[&a.cert], b"abc", true);
    let result = decrypt(
        &message[..],
        &a.cert,
        &a.key,
        &DecryptOptions::default(),
        &mut FullSink,
    );
    assert_eq!(result.unwrap_err(), EnvelopeError::Sink("no space".into()));
}

// ------------------------------------------------------------ foreign and legacy profiles

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

fn recipient_info(
    cert: &Certificate,
    algorithm: &AlgorithmIdentifierOwned,
    wrapped: &[u8],
) -> Vec<u8> {
    let tbs = cert.tbs_certificate();
    let mut rid = tbs.issuer().to_der().unwrap();
    rid.extend(tlv(0x02, tbs.serial_number().as_bytes()));
    let mut body = vec![0x02, 0x01, 0x00];
    body.extend(tlv(0x30, &rid));
    body.extend(algorithm.to_der().unwrap());
    body.extend(tlv(0x04, wrapped));
    tlv(0x30, &body)
}

fn algorithm(id: &str, params: Option<Vec<u8>>) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oid(id),
        parameters: params.map(|p| Any::from_der(&p).unwrap()),
    }
}

fn enveloped_data(
    infos: &[Vec<u8>],
    content: &AlgorithmIdentifierOwned,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut eci = oid("1.2.840.113549.1.7.1").to_der().unwrap();
    eci.extend(content.to_der().unwrap());
    eci.extend(tlv(0x80, ciphertext));
    let mut body = vec![0x02, 0x01, 0x00];
    body.extend(tlv(0x31, &infos.concat()));
    body.extend(tlv(0x30, &eci));
    let mut outer = oid("1.2.840.113549.1.7.3").to_der().unwrap();
    outer.extend(tlv(0xA0, &tlv(0x30, &body)));
    tlv(0x30, &outer)
}

/// A deterministic RNG for the padding of a test-only RSAES-PKCS1-v1_5 encryption.
struct Counter(u8);

impl Counter {
    fn next_byte(&mut self) -> u8 {
        self.0 = self.0.wrapping_add(1).max(1);
        self.0
    }
}

impl rsa::rand_core::RngCore for Counter {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([self.next_byte(); 4])
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([self.next_byte(); 8])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.iter_mut().for_each(|b| *b = self.next_byte());
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for Counter {}

/// What Kalkan writes for an RSA recipient: `rsaEncryption` key transport (PKCS#1 v1.5,
/// NULL parameters) and DES-EDE3-CBC, built here from the public key and the cipher crates.
fn legacy_message(who: &Recipient, plaintext: &[u8]) -> Vec<u8> {
    let oncl_pki::key::PublicKey::Rsa(der) = who.key.public_key() else {
        panic!("RSA fixture")
    };
    let public = rsa::RsaPublicKey::from_pkcs1_der(&der).unwrap();
    let cek = [0x5a_u8; 24];
    let iv = [0x33_u8; 8];
    let wrapped = public
        .encrypt(&mut Counter(0), rsa::Pkcs1v15Encrypt, &cek)
        .unwrap();
    let ciphertext = cbc::Encryptor::<des::TdesEde3>::new_from_slices(&cek, &iv)
        .unwrap()
        .encrypt_padded_vec::<Pkcs7>(plaintext);
    let info = recipient_info(
        &who.cert,
        &algorithm("1.2.840.113549.1.1.1", Some(vec![5, 0])),
        &wrapped,
    );
    let params = OctetString::new(iv.to_vec()).unwrap().to_der().unwrap();
    enveloped_data(
        &[info],
        &algorithm("1.2.840.113549.3.7", Some(params)),
        &ciphertext,
    )
}

#[test]
fn legacy_pkcs1_v15_and_3des_are_refused_unless_opted_in() {
    // Break caught: RSAES-PKCS1-v1_5 / 3DES accepted as a default; the opt-in not reaching
    // the cipher; a legacy message reported as a named (non-legacy) profile.
    let a = recipient_a();
    let plaintext = data(777);
    let message = legacy_message(&a, &plaintext);

    let (result, stage) = open(&message, &a, &DecryptOptions::default());
    let EnvelopeError::UnsupportedProfile(why) = result.unwrap_err() else {
        panic!("not refused as an unsupported profile")
    };
    assert!(why.contains("allow_legacy"), "{why}");
    assert!(stage.bytes.is_empty());

    let (result, stage) = open(&message, &a, &DecryptOptions { allow_legacy: true });
    let report = result.unwrap();
    assert_eq!(stage.bytes, plaintext);
    assert!(report.legacy);
    assert_eq!(report.profile, None);
    assert_eq!(report.key_transport, KeyTransport::RsaPkcs1V15);
    assert_eq!(report.content_cipher, ContentCipher::DesEde3Cbc);
    assert_eq!(report.integrity, Integrity::Unauthenticated);
}

#[test]
fn a_failed_pkcs1_v15_unwrap_does_not_reveal_itself() {
    // Break caught: a distinct error for "padding invalid" (a Bleichenbacher oracle). RFC
    // 3218: the failure surfaces only as bad content; here it is the same error as any
    // other undecryptable message, or (rarely, with a random key) padding that happens to
    // parse and yields garbage, never the plaintext.
    let a = recipient_a();
    let plaintext = data(100);
    let message = legacy_message(&a, &plaintext);
    let at = wrapped_key_offset(&message);
    let mut damaged = message.clone();
    damaged[at + 7] ^= 0x80;
    let (result, stage) = open(&damaged, &a, &DecryptOptions { allow_legacy: true });
    match result {
        Err(error) => {
            assert_eq!(error, EnvelopeError::DecryptionFailed);
            assert!(stage.bytes.is_empty());
        }
        Ok(_) => assert_ne!(stage.bytes, plaintext),
    }
}

#[test]
fn unsupported_algorithms_are_named_never_replaced() {
    // Break caught: an algorithm the reader does not implement decrypted with another one.
    let a = recipient_a();
    let wrapped = vec![0x42; 256];
    let iv = OctetString::new(vec![9; 16]).unwrap().to_der().unwrap();
    let aes256_cbc = algorithm("2.16.840.1.101.3.4.1.42", Some(iv.clone()));
    let oaep = |params: Option<Vec<u8>>| algorithm("1.2.840.113549.1.1.7", params);
    let sha512 = || algorithm("2.16.840.1.101.3.4.2.3", None).to_der().unwrap();
    let sha256 = || algorithm("2.16.840.1.101.3.4.2.1", None).to_der().unwrap();
    let mgf1 = |hash: Vec<u8>| {
        let mut body = oid("1.2.840.113549.1.1.8").to_der().unwrap();
        body.extend(hash);
        tlv(0x30, &body)
    };
    let oaep_params = |hash: Vec<u8>, mask: Vec<u8>| {
        let mut body = tlv(0xA0, &hash);
        body.extend(tlv(0xA1, &mask));
        tlv(0x30, &body)
    };
    let sha256_oaep = || oaep(Some(oaep_params(sha256(), mgf1(sha256()))));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // OAEP with no parameters means SHA-1.
        (
            "hash SHA-1",
            enveloped_data(
                &[recipient_info(&a.cert, &oaep(None), &wrapped)],
                &aes256_cbc,
                &[0; 32],
            ),
        ),
        (
            "hash 2.16.840.1.101.3.4.2.3",
            enveloped_data(
                &[recipient_info(
                    &a.cert,
                    &oaep(Some(oaep_params(sha512(), mgf1(sha512())))),
                    &wrapped,
                )],
                &aes256_cbc,
                &[0; 32],
            ),
        ),
        (
            "MGF1 with a hash other than SHA-256",
            enveloped_data(
                &[recipient_info(
                    &a.cert,
                    &oaep(Some(oaep_params(sha256(), mgf1(sha512())))),
                    &wrapped,
                )],
                &aes256_cbc,
                &[0; 32],
            ),
        ),
        (
            "key encryption algorithm 1.2.398.3.10.1.4.1.2",
            enveloped_data(
                &[recipient_info(
                    &a.cert,
                    &algorithm("1.2.398.3.10.1.4.1.2", None),
                    &wrapped,
                )],
                &aes256_cbc,
                &[0; 32],
            ),
        ),
        (
            "content encryption algorithm 1.2.398.3.10.1.2.1",
            enveloped_data(
                &[recipient_info(&a.cert, &sha256_oaep(), &wrapped)],
                &algorithm("1.2.398.3.10.1.2.1", Some(iv.clone())),
                &[0; 32],
            ),
        ),
        (
            "AES-GCM inside EnvelopedData",
            enveloped_data(
                &[recipient_info(&a.cert, &sha256_oaep(), &wrapped)],
                &algorithm("2.16.840.1.101.3.4.1.46", Some(iv.clone())),
                &[0; 32],
            ),
        ),
    ];
    for (needle, message) in cases {
        let (result, stage) = open(&message, &a, &DecryptOptions { allow_legacy: true });
        let EnvelopeError::UnsupportedProfile(why) = result.unwrap_err() else {
            panic!("{needle}: not an unsupported-profile error")
        };
        assert!(why.contains(needle), "{needle}: {why}");
        assert!(stage.bytes.is_empty());
    }
}

#[test]
fn a_key_agreement_recipient_is_reported_as_such_not_as_a_missing_recipient() {
    // Break caught: a GOST (key agreement) envelope reported as "not for you": the message
    // may well be for the key, in a profile this crate does not implement.
    let a = recipient_a();
    let kari = tlv(0xA1, &[0x02, 0x01, 0x03]);
    let iv = OctetString::new(vec![9; 16]).unwrap().to_der().unwrap();
    let message = enveloped_data(
        &[kari],
        &algorithm("2.16.840.1.101.3.4.1.42", Some(iv)),
        &[0; 32],
    );
    let (result, _) = open(&message, &a, &DecryptOptions::default());
    let EnvelopeError::UnsupportedProfile(why) = result.unwrap_err() else {
        panic!("not an unsupported-profile error")
    };
    assert!(why.contains("KeyAgreeRecipientInfo"), "{why}");
}

#[test]
fn a_message_of_another_content_type_is_not_an_envelope() {
    let a = recipient_a();
    let signed = {
        let mut body = oid("1.2.840.113549.1.7.2").to_der().unwrap();
        body.extend(tlv(0xA0, &tlv(0x30, &[])));
        tlv(0x30, &body)
    };
    let (result, _) = open(&signed, &a, &DecryptOptions::default());
    assert!(matches!(result.unwrap_err(), EnvelopeError::Malformed(_)));
}

#[test]
fn gcm_keystream_continues_across_chunks() {
    // Break caught: a counter that restarts at a chunk (the same keystream applied to two
    // chunks: the ciphertext of two equal plaintext chunks would then be equal).
    let a = recipient_a();
    let plaintext = vec![0u8; 2 * CHUNK];
    let message = seal(GCM, &[&a.cert], &plaintext, true);
    let end = message.len() - 18;
    let ciphertext = &message[end - plaintext.len()..end];
    assert_ne!(&ciphertext[..CHUNK], &ciphertext[CHUNK..]);
    assert_ne!(&ciphertext[..16], &ciphertext[16..32]);
}

#[test]
fn a_length_that_cannot_be_framed_or_encrypted_under_one_nonce_is_refused_up_front() {
    // Break caught: an overflow while the header lengths are summed (a panic or a header
    // that lies), or a GCM message beyond 2^36 - 32 bytes under one nonce.
    let a = recipient_a();
    for (profile, declared) in [
        (CBC, u64::MAX),
        (CBC, (1 << 62) + 1),
        (GCM, u64::MAX),
        (GCM, (1 << 36) - 31),
    ] {
        let mut out = Vec::new();
        let error = encrypt(
            &EncryptSpec {
                profile,
                recipients: &[&a.cert],
                plaintext_len: Some(declared),
            },
            &b""[..],
            &mut out,
        )
        .unwrap_err();
        assert_eq!(error, EnvelopeError::TooLarge, "{profile:?} {declared}");
        assert!(out.is_empty(), "nothing is written before the refusal");
    }
}
