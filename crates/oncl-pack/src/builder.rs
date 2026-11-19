//! The reference build of a plugin from its canonical source archive, as the builder image
//! runs it (docs/design/publishers.md, «Сборщик»):
//!
//! 1. [`prepare`]: the archive is read strictly (it must be canonical), the crate directory
//!    checked (its `Cargo.toml` and `plugin.toml` are there, no `.cargo/config*` on the way to
//!    it) and the archive unpacked into `<work>/src`;
//! 2. [`fetch`], with the network: `cargo fetch --locked` into the Cargo home, which runs no
//!    code of the sources; a git dependency (the SDK from OpenNCALayer's repository) is cloned
//!    whole into `$CARGO_HOME/git`, at most [`MAX_GIT_FETCH`] bytes;
//! 3. [`build`], only without the network (on Linux it refuses to start while any interface
//!    but `lo` exists): `--frozen`, the environment cleared but for [`KEPT_VARS`] (`env -i`),
//!    `SOURCE_DATE_EPOCH` fixed, the profile forced ([`pack::FORCED_PROFILE`]), the paths of
//!    the build remapped; twice, each in a target directory and a `TMPDIR` it creates (and
//!    refuses to find already there), and the two packages compared. Both builds run in the
//!    one container and share the Cargo home, which the caller mounts read-only;
//! 4. [`verify`], likewise without the network, after [`fetch`] in a container of its own:
//!    one build compared with a published package's SHA-256.
//!
//! In the image the paths are fixed (`/build/src`, `/build/target`, `/cargo`), and the image
//! has no rustup, so a `rust-toolchain.toml` of the sources is never read.

use std::ffi::OsString;
use std::fs;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use crate::pack::{self, Build, Mode, Packed};
use crate::source::{self, Tree};
use crate::{read_limited, sha256_hex};

/// `SOURCE_DATE_EPOCH` of every reference build: 1980-01-01, the time of the package's and
/// the archive's entries (a commit time may not exist: the sources need not come from git).
pub const SOURCE_DATE_EPOCH: &str = "315532800";

/// The work directory in the builder image.
pub const WORK: &str = "/build";

/// The variables of the caller's environment a reference build keeps; every other one is
/// cleared. In the image they are the image's own (`PATH`, `HOME`, `CARGO_HOME`); the rustup
/// ones only matter outside it, where `RUSTUP_TOOLCHAIN` keeps the sources' toolchain file
/// from choosing the compiler.
pub const KEPT_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    #[cfg(windows)]
    "SYSTEMROOT",
    #[cfg(windows)]
    "TEMP",
    #[cfg(windows)]
    "TMP",
];

/// The most bytes one [`fetch`] may add under `$CARGO_HOME/git`, the repositories and
/// checkouts of the git dependencies. OpenNCALayer's repository at `v0.1.2`, the SDK's
/// source, takes about 43 MB there (17.6 MB of history, 25 MB of checkout).
pub const MAX_GIT_FETCH: u64 = 256 << 20;

/// The names of the Cargo configuration files Cargo would read from the sources.
const CARGO_CONFIGS: [&str; 2] = [".cargo/config", ".cargo/config.toml"];

/// An archive unpacked for a build.
#[derive(Debug, Clone)]
pub struct Prepared {
    work: PathBuf,
    src: PathBuf,
    crate_dir: PathBuf,
    /// The SHA-256 of the archive.
    pub archive_sha256: String,
}

impl Prepared {
    /// The crate's directory.
    pub fn crate_dir(&self) -> &Path {
        &self.crate_dir
    }

    /// The whole environment Cargo and rustc get: [`KEPT_VARS`] that are set,
    /// `SOURCE_DATE_EPOCH` and, on Unix, `TMPDIR` in `<work>/<tmp>`, created here and so empty
    /// (the image's root file system is read-only).
    fn env(&self, tmp: &str) -> anyhow::Result<Vec<(OsString, OsString)>> {
        let mut env: Vec<(OsString, OsString)> = KEPT_VARS
            .iter()
            .filter_map(|&key| std::env::var_os(key).map(|value| (key.into(), value)))
            .collect();
        if !env.iter().any(|(key, _)| key == "CARGO_HOME") {
            bail!("CARGO_HOME is not set: the build reads the crates `oncl-pack fetch` put there");
        }
        env.push(("SOURCE_DATE_EPOCH".into(), SOURCE_DATE_EPOCH.into()));
        // No incremental state whatever the sources' profiles say.
        env.push(("CARGO_INCREMENTAL".into(), "0".into()));
        if cfg!(unix) {
            let tmp = self.work.join(tmp);
            fs::create_dir(&tmp)
                .with_context(|| format!("creating {} (it must not exist yet)", tmp.display()))?;
            env.push(("TMPDIR".into(), tmp.into_os_string()));
        }
        Ok(env)
    }
}

/// Reads the archive at `archive`, checks the crate at `crate_path` (relative to `src/`,
/// `""` for `src/` itself) and unpacks the archive into `<work>/src`, which must not exist.
///
/// # Errors
///
/// The archive is unreadable, too large or not canonical; the crate's `Cargo.toml` or
/// `plugin.toml` is missing; a `.cargo/config*` is in `src/` or on the way to the crate;
/// the work directory cannot be written.
pub fn prepare(archive: &Path, crate_path: &str, work: &Path) -> anyhow::Result<Prepared> {
    source::check_dir_path(crate_path).context("the crate path")?;
    let bytes = read_limited(archive, source::MAX_ARCHIVE)?;
    let tree =
        Tree::from_archive(&bytes).with_context(|| format!("reading {}", archive.display()))?;
    check_crate(&tree, crate_path)?;
    let work = std::path::absolute(work)?;
    fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    let src = work.join("src");
    tree.unpack(&src)
        .context("unpacking the archive (the work directory must be fresh)")?;
    let crate_dir = if crate_path.is_empty() {
        src.clone()
    } else {
        src.join(crate_path)
    };
    Ok(Prepared {
        work,
        src,
        crate_dir,
        archive_sha256: sha256_hex(&bytes),
    })
}

fn check_crate(tree: &Tree, crate_path: &str) -> anyhow::Result<()> {
    let under = |name: &str| {
        if crate_path.is_empty() {
            name.to_owned()
        } else {
            format!("{crate_path}/{name}")
        }
    };
    for name in ["Cargo.toml", "plugin.toml"] {
        if tree.get(&under(name)).is_none() {
            bail!("the archive has no src/{}", under(name));
        }
    }
    // `src/`, every directory on the way to the crate, and the crate's.
    let mut dirs = vec![""];
    dirs.extend(
        crate_path
            .match_indices('/')
            .map(|(at, _)| &crate_path[..at])
            .chain((!crate_path.is_empty()).then_some(crate_path)),
    );
    for dir in dirs {
        for config in CARGO_CONFIGS {
            let path = if dir.is_empty() {
                config.to_owned()
            } else {
                format!("{dir}/{config}")
            };
            if tree.get(&path).is_some() {
                bail!(
                    "the archive has src/{path}: a Cargo configuration in the sources could \
                     change where crates come from and how they build"
                );
            }
        }
    }
    Ok(())
}

/// Downloads the crates the crate's lock file names into the Cargo home
/// (`cargo fetch --locked`); this runs no code of the sources.
///
/// # Errors
///
/// No `CARGO_HOME`, Cargo fails (a lock file that is missing or out of date, no network),
/// or the git dependencies took more than [`MAX_GIT_FETCH`] bytes.
pub fn fetch(prepared: &Prepared) -> anyhow::Result<()> {
    let env = prepared.env("tmp-fetch")?;
    let git = env
        .iter()
        .find(|(key, _)| key == "CARGO_HOME")
        .map(|(_, home)| Path::new(home).join("git"))
        .context("CARGO_HOME is not set")?;
    let before = tree_size(&git)?;
    let status = std::process::Command::new("cargo")
        .env_clear()
        .envs(env)
        .args(["fetch", "--locked", "--manifest-path"])
        .arg(prepared.crate_dir.join("Cargo.toml"))
        .status()
        .context("running cargo fetch")?;
    if !status.success() {
        bail!("cargo fetch failed ({status})");
    }
    let added = tree_size(&git)?.saturating_sub(before);
    if added > MAX_GIT_FETCH {
        bail!(
            "the git dependencies take {added} bytes in {}, more than {MAX_GIT_FETCH}",
            git.display()
        );
    }
    Ok(())
}

/// The bytes of the regular files under `dir`, links not followed; 0 if it does not exist.
fn tree_size(dir: &Path) -> anyhow::Result<u64> {
    let mut total = 0u64;
    let mut dirs = vec![dir.to_owned()];
    while let Some(dir) = dirs.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
            // `DirEntry::metadata` does not follow a link.
            let meta = entry
                .metadata()
                .with_context(|| format!("reading {}", entry.path().display()))?;
            if meta.is_dir() {
                dirs.push(entry.path());
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    Ok(total)
}

/// One reference build in `<work>/<target>` with its temporary files in `<work>/tmp-<target>`,
/// both created here and so empty: nothing an earlier build left reaches this one. The target
/// directory and every path of the sources are remapped to fixed names, so two target
/// directories give the same bytes.
fn build_once(
    prepared: &Prepared,
    jobs: Option<NonZeroU32>,
    target: &str,
) -> anyhow::Result<Packed> {
    let target_dir = prepared.work.join(target);
    fs::create_dir(&target_dir)
        .with_context(|| format!("creating {} (it must not exist yet)", target_dir.display()))?;
    let mode = Mode::Reference {
        env: prepared.env(&format!("tmp-{target}"))?,
        jobs,
    };
    pack::pack(&Build {
        crate_dir: &prepared.crate_dir,
        target_dir: &target_dir,
        remaps: vec![
            (target_dir.clone(), "/target"),
            (prepared.src.clone(), "/workspace"),
            (prepared.crate_dir.clone(), "/plugin"),
        ],
        mode: &mode,
    })
    .map_err(|e| {
        e.context(
            "the reference build failed (were the crates fetched first with `oncl-pack fetch`?)",
        )
    })
}

/// Refuses to build where the network is reachable: the build runs the sources' build
/// scripts and procedural macros, so it belongs in a container started with
/// `--network=none`, whose only interface is `lo`. Checked on Linux, through
/// `/sys/class/net`; elsewhere (not the reference build) it is the caller's to ensure.
fn require_offline() -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    let interfaces = match fs::read_dir("/sys/class/net") {
        Ok(entries) => entries
            .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()
            .context("reading /sys/class/net")?,
        Err(e) => return Err(e).context("reading /sys/class/net"),
    };
    let other: Vec<&String> = interfaces.iter().filter(|name| *name != "lo").collect();
    if !other.is_empty() {
        bail!(
            "the network is on (interfaces {other:?}): the build runs code of the sources, so \
             it runs only in a container without the network (`docker run --network=none`)"
        );
    }
    Ok(())
}

/// Builds the package twice, in two clean target directories, and returns it if both
/// builds gave the same bytes.
///
/// # Errors
///
/// A build fails, or the two builds differ: something in the sources or their crates does
/// not build reproducibly.
pub fn build(prepared: &Prepared, jobs: Option<NonZeroU32>) -> anyhow::Result<Packed> {
    require_offline()?;
    let first = build_once(prepared, jobs, "target")?;
    let second = build_once(prepared, jobs, "target-again")?;
    if first.bytes != second.bytes {
        bail!(
            "two builds of the same sources differ ({} and {}): the plugin does not build \
             reproducibly",
            sha256_hex(&first.bytes),
            sha256_hex(&second.bytes)
        );
    }
    Ok(first)
}

/// Builds the package once and compares its SHA-256 with `expected` (64 hex digits, any
/// case).
///
/// # Errors
///
/// The build fails, or it gives other bytes than `expected`.
pub fn verify(
    prepared: &Prepared,
    expected: &str,
    jobs: Option<NonZeroU32>,
) -> anyhow::Result<Packed> {
    let expected = expected.to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{expected:?} is not a SHA-256 (64 hexadecimal digits)");
    }
    require_offline()?;
    let packed = build_once(prepared, jobs, "target")?;
    let built = sha256_hex(&packed.bytes);
    if built != expected {
        bail!(
            "the rebuild of {} differs from the package: expected sha256 {expected}, built {built}",
            packed.file_name()
        );
    }
    Ok(packed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_size_counts_the_files_below_and_nothing_for_no_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(tree_size(&dir.path().join("git")).unwrap(), 0);
        let git = dir.path().join("git");
        fs::create_dir_all(git.join("db/a")).unwrap();
        fs::create_dir_all(git.join("checkouts/a/0123456")).unwrap();
        fs::write(git.join("db/a/pack"), [0; 1000]).unwrap();
        fs::write(git.join("checkouts/a/0123456/Cargo.toml"), [0; 24]).unwrap();
        assert_eq!(tree_size(&git).unwrap(), 1024);
    }
}
