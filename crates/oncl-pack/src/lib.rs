//! OpenNCALayer's plugin builder (`oncl-pack`), the reference build of publishers' plugins
//! (docs/design/publishers.md, «Сборщик» and «Архив исходников»):
//!
//! - [`source`]: the canonical source archive (`<id>-<version>.src.tar.gz`) made from a
//!   directory or a git revision, and its strict reading, which refuses any archive
//!   `oncl-pack source` would not have written byte for byte;
//! - [`pack`]: one plugin crate built for core Wasm and packaged as `.onclp`, the logic
//!   `cargo xtask plugin pack` uses for the ports too;
//! - [`builder`]: the reference build from an archive, as the builder image runs it: the
//!   archive unpacked at fixed paths, the environment cleared, the profile forced, two builds
//!   in clean target directories compared, and the rebuild of a published package.
//!
//! The builder image (`xtask/assets/plugin-builder/Dockerfile`) runs the `oncl-pack` binary
//! of this crate; that image, by its digest in `publishers/builders.toml`, is the reference:
//! builds of the same archive elsewhere are not promised to give the same bytes.

pub mod builder;
pub mod pack;
pub mod source;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail};
use semver::Version;
use sha2::{Digest, Sha256};

/// The file name of the package of plugin `id` at `version`: `<id>-<version>.onclp`.
pub fn package_file_name(id: &str, version: &Version) -> String {
    format!("{id}-{version}.{}", oncl_plugin::PACKAGE_EXT)
}

/// The SHA-256 of `bytes`, as 64 lowercase hexadecimal digits.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// The bytes of the file at `path`, refused above `limit` bytes without reading further.
///
/// # Errors
///
/// The file cannot be read, or it is longer than `limit`.
pub fn read_limited(path: &Path, limit: u64) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > limit {
        bail!("{} exceeds {limit} bytes", path.display());
    }
    Ok(bytes)
}
