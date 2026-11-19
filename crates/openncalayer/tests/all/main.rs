//! The integration tests of `openncalayer` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.
//!
//! A binary of its own: `bridge` points `XDG_RUNTIME_DIR` of its process at a private
//! directory, which the endpoints of the other files' daemons must not see change under them.

mod e2e;
#[cfg(all(windows, feature = "e2e-prompter"))]
mod maintenance_e2e;
mod nm;
#[cfg(feature = "e2e-prompter")]
mod plugins;
#[cfg(feature = "e2e-prompter")]
mod ports_e2e;
mod ports_heavy_e2e;
#[cfg(all(feature = "e2e-prompter", feature = "token-emulator"))]
mod tokens;
