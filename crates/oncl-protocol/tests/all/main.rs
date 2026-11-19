//! The integration tests of `oncl-protocol` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.
//!
//! A binary of its own: `orgjson_memory` installs its own `#[global_allocator]`, and a
//! binary has one.

mod envelope;
mod invoker;
mod javab64;
mod javamap;
mod legacy;
mod orgjson;
