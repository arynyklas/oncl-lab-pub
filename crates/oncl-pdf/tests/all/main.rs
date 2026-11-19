//! The integration tests of `oncl-pdf` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.
//!
//! A binary of its own: `ades` installs its own `#[global_allocator]`, and a binary has one.

mod budget;
mod dense;
mod sign;
mod surcharge;
mod verify;
