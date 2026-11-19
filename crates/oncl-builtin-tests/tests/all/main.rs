//! The integration tests of `oncl-builtin-tests` as one test binary: one link of the crate,
//! its dependencies and the embedded guests instead of one per file. A test is
//! `<file>::<test>`.
//!
//! Binaries of their own: `call_heap` installs its own `#[global_allocator]`, and a binary
//! has one; `applet_process` and `commonutils_process` test state that belongs to the
//! process; `limits` and `bench` are run alone by CI (`--test limits` on 32-bit,
//! `--test bench` in the scheduled benchmarks).

mod accessory;
mod applet;
mod applet_tokens;
mod basics_essentials;
mod basics_sign;
mod basics_tokens;
mod basics_validation;
mod commonutils;
mod commonutils_tokens;
mod large_data;
mod markers;
mod panics;
