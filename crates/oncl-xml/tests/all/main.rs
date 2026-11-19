//! The integration tests of `oncl-xml` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.
//!
//! Binaries of their own: `signed_intake` and `xades_large_crl` each install their own
//! `#[global_allocator]`, and a binary has one.

// The XAdES PKI of `xades_unsigned_layout`; `xades_large_crl` declares its own copy.
#[cfg(feature = "testing")]
#[path = "../support/xades_pki.rs"]
mod xades_pki;

mod indexed_xml;
mod legacy_output_admission;
mod stream_c14n;
mod stream_sign;
mod stream_verify;
mod wsse;
#[cfg(feature = "testing")]
mod xades;
#[cfg(feature = "testing")]
mod xades_levels;
#[cfg(feature = "testing")]
mod xades_unsigned_layout;
mod xml_add_preflight;
mod xml_spec;
mod xmldsig;
