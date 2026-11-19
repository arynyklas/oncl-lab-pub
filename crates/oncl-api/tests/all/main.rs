//! The integration tests of `oncl-api` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.

#[cfg(feature = "server")]
mod private_support;

#[cfg(feature = "server")]
mod batch_route;
mod client;
#[cfg(feature = "server")]
mod http_operations;
#[cfg(feature = "server")]
mod multipart_admission;
#[cfg(feature = "server")]
mod plugin_grants;
#[cfg(feature = "server")]
mod private_operations;
#[cfg(feature = "server")]
mod streaming;
mod subcode;
#[cfg(feature = "server")]
mod upload_deadline;
