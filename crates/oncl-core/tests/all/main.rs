//! The integration tests of `oncl-core` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.
//!
//! Binaries of their own: `batch`, `cms_stream_admission`, `large_crl`, `plugin_access`,
//! `plugin_manual` and `validation_memory` each install their own `#[global_allocator]`, and a
//! binary has one; `plugin_ports_manual` is run alone by `cargo xtask plugin-ports-manual`,
//! which passes the user's filters to it as they are.

// The probe's fixtures, one copy for the plugin modules; they name the batch fixture
// `crate::plugin_crypto`.
#[cfg(all(
    feature = "plugins",
    feature = "tokens",
    any(feature = "testing", feature = "xml")
))]
#[path = "../../examples/sdk_probe/batch_fixture.rs"]
pub(crate) mod plugin_crypto;
#[cfg(all(
    feature = "plugins",
    feature = "tokens",
    any(feature = "testing", feature = "xml")
))]
#[path = "../../examples/sdk_probe/plugin_fixture.rs"]
mod plugin_fixture;
#[cfg(all(
    feature = "plugins",
    feature = "tokens",
    any(feature = "testing", feature = "xml")
))]
#[path = "../../examples/sdk_probe/plugin_xml_fixture.rs"]
mod plugin_xml_fixture;

mod activity;
mod admission;
mod cades;
mod cades_limits;
mod cms_stream;
mod cms_stream_sign;
mod examples;
mod inspect;
mod io_limits;
#[cfg(feature = "jose")]
mod jose;
#[cfg(feature = "tokens")]
mod key_sources;
#[cfg(feature = "pdf")]
mod pdf;
#[cfg(all(feature = "plugins", feature = "tokens", feature = "testing"))]
mod plugin_approval;
#[cfg(all(feature = "plugins", feature = "tokens", feature = "testing"))]
mod plugin_ticket;
#[cfg(all(feature = "plugins", feature = "tokens", feature = "xml"))]
mod plugin_xml;
mod resource_edges;
mod timestamp;
mod validation_policy;
#[cfg(feature = "xml")]
mod xml;
