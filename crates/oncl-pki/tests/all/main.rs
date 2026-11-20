//! The integration tests of `oncl-pki` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.
//!
//! `cms_stream` and `metadata_intake` stay binaries of their own: each installs its own
//! `#[global_allocator]`, and a binary has one.

mod ber;
#[cfg(feature = "testing")]
mod cades;
mod cert_verify;
mod cms;
#[cfg(feature = "testing")]
mod cms_report;
#[cfg(feature = "testing")]
mod cms_signer;
mod cms_spec;
#[cfg(feature = "testing")]
mod cms_stream_sign;
mod configuration_budget;
#[cfg(feature = "testing")]
mod crl;
mod csr;
mod digest_signatures;
#[cfg(feature = "testing")]
mod envelope;
#[cfg(feature = "testing")]
mod evidence;
mod frozen_input;
mod info;
mod input_spool;
mod jks;
#[cfg(feature = "testing")]
mod keystore;
#[cfg(feature = "testing")]
mod ocsp;
mod pkcs12;
#[cfg(feature = "testing")]
mod pkix;
mod private_fs;
mod provisional_input;
mod spki;
mod token_key;
#[cfg(feature = "testing")]
mod tsp;
mod wire_capture;
mod xml_output;
