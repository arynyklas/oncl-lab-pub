//! The integration tests of `oncl-token` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.
//!
//! Binaries of their own: `wipe` installs its own `#[global_allocator]`, and a binary has
//! one; `vpcd` is run alone by CI against a card served to vpcd (`--test vpcd`).

#[cfg(feature = "emulator")]
mod common;

#[cfg(feature = "emulator")]
mod akey;
#[cfg(feature = "emulator")]
mod emulator;
#[cfg(feature = "emulator")]
mod etoken5110;
#[cfg(feature = "emulator")]
mod etoken72k;
#[cfg(feature = "emulator")]
mod jacarta;
#[cfg(feature = "emulator")]
mod kaztoken;
#[cfg(feature = "emulator")]
mod kzid;
#[cfg(feature = "emulator")]
mod service;
mod transport;
