//! CMS encryption and decryption (`oncl_pki::cms::envelope`), judged by tools that are not
//! ours: OpenSSL (`openssl cms`) in both directions for the RSA profiles, and the local-only
//! Kalkan oracle for what the Kalkan provider can and cannot do. The library is called
//! directly (the CLI has no encryption command): the rows judge the library's bytes.
//!
//! There is no KZ GOST row that succeeds, on purpose: Kalkan has no GOST key agreement and
//! no GOST content cipher in its CMS layer, so no independent tool writes or reads such an
//! envelope and no GOST profile is claimed (`fixtures/platform/envelope/profiles.toml`).
//! `envelope-kalkan-gost-refused` keeps that evidence reproducible.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, ensure};
use der::Encode;
use der::asn1::{ObjectIdentifier, OctetString};
use oncl_pki::cert::Certificate;
use oncl_pki::cms::envelope::{
    CertProblem, DecryptOptions, EncryptSpec, EnvelopeError, EnvelopeProfile, EnvelopeReport,
    Integrity, KeyTransport, decrypt, encrypt,
};
use oncl_pki::key::PrivateKey;
use oncl_pki::keygen::{self, KeySpec};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::name::Name;

use super::super::kalkan;
use super::super::oncl::path_str;
use super::super::world::Profile;
use super::super::{Case, Ctx, Observed};
use super::common::grade;

const GCM: EnvelopeProfile = EnvelopeProfile::RsaOaepSha256Aes256Gcm;
const CBC: EnvelopeProfile = EnvelopeProfile::RsaOaepSha256Aes256Cbc;
/// OpenSSL's key options for RSAES-OAEP with SHA-256 and MGF1-SHA-256.
const OAEP: [&str; 6] = [
    "-keyopt",
    "rsa_padding_mode:oaep",
    "-keyopt",
    "rsa_oaep_md:sha256",
    "-keyopt",
    "rsa_mgf1_md:sha256",
];

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("envelope-openssl-opens-ours-rsa-oaep", openssl_opens_ours),
        Case::new("envelope-ours-opens-openssl-rsa-oaep", ours_opens_openssl),
        Case::new(
            "envelope-ours-opens-openssl-rsa-pkcs1-legacy",
            ours_opens_openssl_legacy,
        ),
        Case::new(
            "envelope-ours-opens-kalkan-rsa-3des-legacy",
            ours_opens_kalkan,
        ),
        Case::new("envelope-kalkan-gost-refused", kalkan_gost_refused),
    ]
}

/// Sizes that cross the 64 KiB window and the block sizes.
fn sizes() -> [usize; 4] {
    [0, 1, 65_537, 3 << 20]
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

/// A recipient with its files for the other tools.
struct Recipient {
    key: PrivateKey,
    cert: Certificate,
    cert_der: PathBuf,
    cert_pem: PathBuf,
    key_pem: PathBuf,
    pkcs8: PathBuf,
}

fn extension(id: &str, value: Vec<u8>) -> Extension {
    Extension {
        extn_id: ObjectIdentifier::new_unwrap(id),
        critical: false,
        extn_value: OctetString::new(value).expect("extension value"),
    }
}

/// The encryption certificate of `key` under the matrix's root: keyEncipherment and the
/// emailProtection purpose.
fn encryption_cert(
    ctx: &Ctx,
    key: &PrivateKey,
    name: &str,
    serial: u8,
) -> anyhow::Result<Certificate> {
    let template = &ctx.world.signer(Profile::Rsa).entry.cert;
    let mut spec = TestCertSpec::from_cert(template);
    spec.subject = Name::from_str(&format!("CN={name}")).map_err(|e| anyhow::anyhow!("{e}"))?;
    spec.public_key = key.public_key().to_spki();
    spec.serial = vec![0x71, 5, serial];
    spec.extensions = vec![
        extension(
            "2.5.29.15",
            KeyUsage(KeyUsages::KeyEncipherment.into()).to_der()?,
        ),
        extension(
            "2.5.29.37",
            ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4")]).to_der()?,
        ),
    ];
    Ok(issue_cert(&ctx.world.root_entry, spec))
}

fn recipient(ctx: &Ctx, name: &str, serial: u8) -> anyhow::Result<Recipient> {
    let key = keygen::generate(KeySpec::RsaSha256(2048)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let cert = encryption_cert(ctx, &key, name, serial)?;
    let pkcs8 = key.to_pkcs8_der().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let cert_der = cert.to_der()?;
    Ok(Recipient {
        cert_der: ctx.write(&format!("{name}.cer"), &cert_der)?,
        cert_pem: ctx.write(
            &format!("{name}.pem"),
            oncl_pki::pem::encode("CERTIFICATE", &cert_der).as_bytes(),
        )?,
        key_pem: ctx.write(
            &format!("{name}.key.pem"),
            oncl_pki::pem::encode("PRIVATE KEY", &pkcs8).as_bytes(),
        )?,
        pkcs8: ctx.write(&format!("{name}.pk8"), &pkcs8)?,
        key,
        cert,
    })
}

fn ours_encrypt(
    profile: EnvelopeProfile,
    recipients: &[&Recipient],
    plaintext: &[u8],
    known_length: bool,
) -> anyhow::Result<Vec<u8>> {
    let certs: Vec<&Certificate> = recipients.iter().map(|r| &r.cert).collect();
    let mut out = Vec::new();
    encrypt(
        &EncryptSpec {
            profile,
            recipients: &certs,
            plaintext_len: known_length.then_some(plaintext.len() as u64),
        },
        plaintext,
        &mut out,
    )
    .map_err(|e| anyhow::anyhow!("oncl encrypt: {e}"))?;
    Ok(out)
}

fn ours_decrypt(
    message: &[u8],
    who: &Recipient,
    allow_legacy: bool,
) -> Result<(EnvelopeReport, Vec<u8>), EnvelopeError> {
    let mut stage = Vec::new();
    let report = decrypt(
        message,
        &who.cert,
        &who.key,
        &DecryptOptions { allow_legacy },
        &mut stage,
    )?;
    Ok((report, stage))
}

/// OpenSSL's `cms -decrypt` of a DER message: the plaintext, or `None` when it refuses.
fn openssl_decrypt(ctx: &Ctx, message: &[u8], who: &Recipient) -> anyhow::Result<Option<Vec<u8>>> {
    let input = ctx.write("openssl-in.der", message)?;
    let output = ctx.file("openssl-out.bin");
    let _ = std::fs::remove_file(&output);
    let out = ctx.openssl(&[
        "cms".to_owned(),
        "-decrypt".into(),
        "-inform".into(),
        "DER".into(),
        "-in".into(),
        path_str(&input)?.into(),
        "-recip".into(),
        path_str(&who.cert_pem)?.into(),
        "-inkey".into(),
        path_str(&who.key_pem)?.into(),
        "-out".into(),
        path_str(&output)?.into(),
    ])?;
    if !out.ok() {
        return Ok(None);
    }
    Ok(Some(
        std::fs::read(&output).context("openssl cms -decrypt output")?,
    ))
}

/// OpenSSL's `cms -encrypt` of `plaintext` for each recipient, as DER.
fn openssl_encrypt(
    ctx: &Ctx,
    cipher: &str,
    oaep: bool,
    stream: bool,
    plaintext: &[u8],
    recipients: &[&Recipient],
) -> anyhow::Result<Vec<u8>> {
    let input = ctx.write("openssl-plain.bin", plaintext)?;
    let output = ctx.file("openssl-enc.der");
    let mut args: Vec<String> = vec![
        "cms".into(),
        "-encrypt".into(),
        "-binary".into(),
        format!("-{cipher}"),
        "-outform".into(),
        "DER".into(),
        "-in".into(),
        path_str(&input)?.into(),
        "-out".into(),
        path_str(&output)?.into(),
    ];
    if stream {
        args.push("-stream".into());
    }
    for who in recipients {
        if oaep {
            // The key options belong to the `-recip` they follow.
            args.push("-recip".into());
            args.push(path_str(&who.cert_pem)?.into());
            args.extend(OAEP.iter().map(|s| (*s).to_owned()));
        } else {
            args.push(path_str(&who.cert_pem)?.into());
        }
    }
    let out = ctx.openssl(&args)?;
    ensure!(out.ok(), "openssl cms -encrypt {cipher}: {}", out.brief());
    std::fs::read(&output).context("openssl cms -encrypt output")
}

fn flip(message: &[u8], at: usize) -> Vec<u8> {
    let mut damaged = message.to_vec();
    damaged[at] ^= 1;
    damaged
}

/// `oncl` encrypts (both profiles, known and unknown length, several sizes, two recipients)
/// and OpenSSL decrypts with each recipient's key; a changed tag or ciphertext byte of the
/// GCM profile is refused by OpenSSL too.
fn openssl_opens_ours(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let a = recipient(ctx, "a", 1)?;
    let b = recipient(ctx, "b", 2)?;
    let mut messages = 0;
    for profile in [GCM, CBC] {
        for known in [true, false] {
            for size in sizes() {
                let plaintext = data(size);
                let message = ours_encrypt(profile, &[&a, &b], &plaintext, known)?;
                for who in [&a, &b] {
                    let opened = openssl_decrypt(ctx, &message, who)?;
                    ensure!(
                        opened.as_deref() == Some(plaintext.as_slice()),
                        "OpenSSL did not return the plaintext of {profile:?} (known length: \
                         {known}, {size} bytes)"
                    );
                }
                messages += 1;
                if profile == GCM && known && size > 0 {
                    for at in [message.len() - 1, message.len() - 18 - size / 2] {
                        ensure!(
                            openssl_decrypt(ctx, &flip(&message, at), &a)?.is_none(),
                            "OpenSSL accepted a GCM envelope changed at byte {at}"
                        );
                    }
                }
            }
        }
    }
    Ok(Observed {
        grade: grade(&[
            ("ours", "encrypted".to_owned()),
            ("openssl-gcm", "ok/2-recipients".to_owned()),
            ("openssl-cbc", "ok/2-recipients".to_owned()),
            ("tamper-gcm", "rejected".to_owned()),
        ]),
        ours: format!("{messages} messages encrypted"),
        oracle: "openssl cms -decrypt returned every plaintext".to_owned(),
        detail: String::new(),
    })
}

/// OpenSSL encrypts with RSAES-OAEP (SHA-256) for two recipients (AES-128/192/256-CBC,
/// AES-128/256-GCM, DER and `-stream` BER) and `oncl` decrypts with the default options.
fn ours_opens_openssl(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let a = recipient(ctx, "a", 1)?;
    let b = recipient(ctx, "b", 2)?;
    let mut opened = 0;
    for cipher in [
        "aes-128-cbc",
        "aes-192-cbc",
        "aes-256-cbc",
        "aes-128-gcm",
        "aes-256-gcm",
    ] {
        for stream in [false, true] {
            for size in sizes() {
                // OpenSSL 3.0's own limitation: `-stream` with GCM fails on an empty input
                // (exit 6) before it writes anything: nothing to judge.
                if stream && size == 0 && cipher.ends_with("gcm") {
                    continue;
                }
                let plaintext = data(size);
                let message = openssl_encrypt(ctx, cipher, true, stream, &plaintext, &[&a, &b])?;
                for who in [&a, &b] {
                    let (report, bytes) = ours_decrypt(&message, who, false)
                        .map_err(|e| anyhow::anyhow!("oncl decrypt of OpenSSL {cipher}: {e}"))?;
                    ensure!(
                        bytes == plaintext,
                        "oncl returned other bytes for OpenSSL {cipher} (stream: {stream}, {size} bytes)"
                    );
                    let expected = if cipher.ends_with("gcm") {
                        Integrity::Authenticated
                    } else {
                        Integrity::Unauthenticated
                    };
                    ensure!(
                        report.integrity == expected && !report.legacy,
                        "{cipher}: reported {report:?}"
                    );
                }
                opened += 1;
            }
        }
    }
    // A damaged tag of OpenSSL's own GCM message is refused and leaves nothing staged.
    let plaintext = data(5000);
    let message = openssl_encrypt(ctx, "aes-256-gcm", true, false, &plaintext, &[&a])?;
    let mut stage = Vec::new();
    let refused = decrypt(
        &flip(&message, message.len() - 1)[..],
        &a.cert,
        &a.key,
        &DecryptOptions::default(),
        &mut stage,
    );
    ensure!(
        refused == Err(EnvelopeError::AuthenticationFailed) && stage.is_empty(),
        "a damaged OpenSSL GCM envelope: {refused:?}, {} bytes staged",
        stage.len()
    );
    Ok(Observed {
        grade: grade(&[
            ("openssl", "encrypted".to_owned()),
            ("ours-cbc", "ok/unauthenticated".to_owned()),
            ("ours-gcm", "ok/authenticated".to_owned()),
            ("tamper-gcm", "rejected".to_owned()),
        ]),
        ours: format!("{opened} OpenSSL messages decrypted"),
        oracle: "openssl cms -encrypt with rsa_padding_mode:oaep, SHA-256".to_owned(),
        detail: String::new(),
    })
}

/// OpenSSL's default key transport is RSAES-PKCS1-v1_5: `oncl` refuses it unless the caller
/// opts into legacy profiles, and then decrypts it (and says it is legacy).
fn ours_opens_openssl_legacy(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let a = recipient(ctx, "a", 1)?;
    let plaintext = data(70_000);
    for cipher in ["aes-256-cbc", "aes-256-gcm"] {
        let message = openssl_encrypt(ctx, cipher, false, false, &plaintext, &[&a])?;
        let refused = ours_decrypt(&message, &a, false);
        ensure!(
            matches!(&refused, Err(EnvelopeError::UnsupportedProfile(why)) if why.contains("allow_legacy")),
            "{cipher}: PKCS#1 v1.5 not refused by default: {refused:?}"
        );
        let (report, bytes) = ours_decrypt(&message, &a, true)
            .map_err(|e| anyhow::anyhow!("legacy decrypt of OpenSSL {cipher}: {e}"))?;
        ensure!(bytes == plaintext, "{cipher}: other bytes");
        ensure!(
            report.legacy && report.key_transport == KeyTransport::RsaPkcs1V15,
            "{cipher}: {report:?}"
        );
    }
    Ok(Observed {
        grade: grade(&[
            ("ours-default", "UnsupportedProfile".to_owned()),
            ("ours-legacy", "ok".to_owned()),
        ]),
        ours: "refused by default, decrypted with allow_legacy".to_owned(),
        oracle: "openssl cms -encrypt (rsaEncryption key transport)".to_owned(),
        detail: String::new(),
    })
}

/// Kalkan (`CMSEnvelopedDataGenerator`) makes an EnvelopedData (RSA key transport,
/// DES-EDE3-CBC); `oncl` refuses it by default and decrypts it as legacy. Kalkan reads its
/// own message but not ours (it has neither RSAES-OAEP nor AuthEnvelopedData).
fn ours_opens_kalkan(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let a = recipient(ctx, "a", 1)?;
    let plaintext = data(3 << 20);
    let plain_path = ctx.write("kalkan-plain.bin", &plaintext)?;
    let envelope = ctx.file("kalkan-envelope.der");
    let made = ctx.java_json(&[
        "envelope-make",
        path_str(&a.cert_der)?,
        path_str(&plain_path)?,
        path_str(&envelope)?,
    ])?;
    ensure!(
        kalkan::verdict(&made),
        "Kalkan could not make an RSA envelope: {made}"
    );
    let message = std::fs::read(&envelope)?;
    let back = ctx.file("kalkan-own.bin");
    let own = ctx.java_json(&[
        "envelope-open",
        path_str(&a.pkcs8)?,
        path_str(&envelope)?,
        path_str(&back)?,
    ])?;
    ensure!(
        kalkan::verdict(&own) && std::fs::read(&back)? == plaintext,
        "Kalkan did not read its own envelope: {own}"
    );
    let default = ours_decrypt(&message, &a, false);
    ensure!(
        matches!(&default, Err(EnvelopeError::UnsupportedProfile(_))),
        "Kalkan's legacy envelope not refused by default: {default:?}"
    );
    let (report, bytes) = ours_decrypt(&message, &a, true)
        .map_err(|e| anyhow::anyhow!("oncl decrypt of Kalkan's envelope: {e}"))?;
    ensure!(
        bytes == plaintext,
        "oncl decrypted other bytes than Kalkan encrypted"
    );
    ensure!(
        report.legacy
            && report.profile.is_none()
            && report.integrity == Integrity::Unauthenticated
            && report.key_transport == KeyTransport::RsaPkcs1V15,
        "{report:?}"
    );
    let mut refused = Vec::new();
    for profile in [GCM, CBC] {
        let ours = ctx.write(
            "ours.der",
            &ours_encrypt(profile, &[&a], &plaintext[..1000], true)?,
        )?;
        let answer = ctx.java_json(&[
            "envelope-open",
            path_str(&a.pkcs8)?,
            path_str(&ours)?,
            path_str(&ctx.file("kalkan-ours.bin"))?,
        ])?;
        refused.push(if kalkan::verdict(&answer) {
            "opened"
        } else {
            "refused"
        });
    }
    Ok(Observed {
        grade: grade(&[
            ("kalkan-makes", "ok".to_owned()),
            ("kalkan-opens-own", "ok".to_owned()),
            ("ours-default", "UnsupportedProfile".to_owned()),
            ("ours-legacy", "ok/rsa-pkcs1+des-ede3".to_owned()),
            ("kalkan-opens-ours", refused.join("+")),
        ]),
        ours: "decrypted Kalkan's envelope as legacy".to_owned(),
        oracle: "kalkan CMSEnvelopedDataGenerator / RecipientInformation".to_owned(),
        detail: String::new(),
    })
}

/// The evidence behind "no KZ GOST profile": Kalkan makes an envelope for an RSA certificate
/// and cannot for a GOST 2015-512 or GOST 2004 certificate; `oncl` refuses a GOST recipient
/// with the reason.
fn kalkan_gost_refused(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let rsa = recipient(ctx, "a", 1)?;
    let plain = ctx.write("gost-plain.bin", &data(1000))?;
    let out = ctx.file("gost-envelope.der");
    let rsa_answer = ctx.java_json(&[
        "envelope-make",
        path_str(&rsa.cert_der)?,
        path_str(&plain)?,
        path_str(&out)?,
    ])?;
    ensure!(
        kalkan::verdict(&rsa_answer),
        "the control (an RSA recipient) failed: {rsa_answer}"
    );
    let mut parts = vec![("kalkan-rsa", "ok".to_owned())];
    for (profile, label) in [
        (Profile::Gost2015, "gost2015"),
        (Profile::Gost2004, "gost2004"),
    ] {
        let signer = ctx.world.signer(profile);
        let _ = std::fs::remove_file(&out);
        let answer = ctx.java_json(&[
            "envelope-make",
            path_str(&signer.cert_der)?,
            path_str(&plain)?,
            path_str(&out)?,
        ])?;
        ensure!(
            !kalkan::verdict(&answer) && !out.exists(),
            "Kalkan made an envelope for a {label} certificate: {answer}"
        );
        parts.push((
            if profile == Profile::Gost2015 {
                "kalkan-gost2015"
            } else {
                "kalkan-gost2004"
            },
            "refused".to_owned(),
        ));
        // Ours: the same key with an encryption certificate is refused with its reason.
        let key = signer.entry.key.clone();
        let cert = encryption_cert(ctx, &key, label, 9)?;
        let refused = encrypt(
            &EncryptSpec {
                profile: GCM,
                recipients: &[&cert],
                plaintext_len: None,
            },
            &b"x"[..],
            Vec::new(),
        );
        ensure!(
            matches!(
                &refused,
                Err(EnvelopeError::UnsuitableCertificate {
                    problem: CertProblem::GostKey(_),
                    ..
                })
            ),
            "{label}: oncl did not refuse the GOST recipient: {refused:?}"
        );
    }
    parts.push(("ours-gost", "refused/GostKey".to_owned()));
    Ok(Observed {
        grade: grade(&parts),
        ours: "GOST recipients refused with a named reason".to_owned(),
        oracle: "kalkan CMSEnvelopedDataGenerator.addKeyTransRecipient".to_owned(),
        detail: String::new(),
    })
}
