//! One `cdylib` Rust crate built for core Wasm and packaged as a deterministic `.onclp`, by
//! the checks the daemon makes before an installation: the logic of `cargo xtask plugin pack`
//! ([`Mode::Workspace`]) and of the reference builder ([`Mode::Reference`]).

use std::ffi::{OsStr, OsString};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use oncl_pdk::abi::Import;
use oncl_plugin::{MAX_MANIFEST, MAX_WASM, Manifest, Package};
use serde_json::Value;

use crate::read_limited;

/// The target every plugin is built for.
pub const TARGET: &str = "wasm32-unknown-unknown";

/// The profile settings the reference build forces over the crate's own `release` profile
/// (`opt-level`, `lto` and `panic` stay the publisher's): one code generation unit, no
/// incremental state, no debug information, and no symbol names (`strip`), whose mangled
/// hashes may still carry the paths of the build (docs/design/publishers.md, «Сборщик»).
pub const FORCED_PROFILE: [&str; 4] = [
    "profile.release.codegen-units=1",
    "profile.release.incremental=false",
    "profile.release.debug=false",
    "profile.release.strip=true",
];

/// The rustc flags the reference build appends after the remaps: a crate's per-package
/// profile overrides (`[profile.release.package.*]`) win over [`FORCED_PROFILE`], but these
/// come after the profile's flags on rustc's command line, and for `-C` the last one wins.
pub const FORCED_RUSTC: [&str; 3] = ["-Ccodegen-units=1", "-Cdebuginfo=0", "-Cstrip=symbols"];

/// How Cargo runs.
#[derive(Debug, Clone)]
pub enum Mode {
    /// `cargo xtask plugin pack`: the caller's environment without `RUSTFLAGS`, the toolchain
    /// rustup picks for the crate, `--locked`, the crate's own profile.
    Workspace,
    /// The reference build: only `env` reaches Cargo and rustc (as after `env -i`),
    /// `--frozen` (the crates were fetched before, the network is off), and
    /// [`FORCED_PROFILE`].
    Reference {
        /// The whole environment of the build.
        env: Vec<(OsString, OsString)>,
        /// Cargo's `--jobs`, so the build keeps to the machine's limits; the bytes do not
        /// depend on it.
        jobs: Option<NonZeroU32>,
    },
}

impl Mode {
    fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(program);
        match self {
            // Flags meant for the host build are not the plugin's.
            Self::Workspace => {
                command.env_remove("RUSTFLAGS");
            }
            Self::Reference { env, .. } => {
                command.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
            }
        }
        command
    }

    fn cargo(&self) -> Command {
        match self {
            Self::Workspace => {
                self.command(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            }
            Self::Reference { .. } => self.command("cargo"),
        }
    }

    fn cargo_home(&self) -> anyhow::Result<PathBuf> {
        match self {
            Self::Workspace => match std::env::var_os("CARGO_HOME") {
                Some(home) => Ok(PathBuf::from(home)),
                None => Ok(std::env::home_dir()
                    .context("the home directory is unknown")?
                    .join(".cargo")),
            },
            Self::Reference { env, .. } => env
                .iter()
                .find(|(key, _)| key == "CARGO_HOME")
                .map(|(_, home)| PathBuf::from(home))
                .context("the reference build needs CARGO_HOME"),
        }
    }
}

/// One build.
#[derive(Debug, Clone)]
pub struct Build<'a> {
    /// The crate's directory (its `Cargo.toml` and `plugin.toml`).
    pub crate_dir: &'a Path,
    /// Cargo's target directory.
    pub target_dir: &'a Path,
    /// The directories whose paths are replaced in the module by fixed names, after the
    /// Cargo home (`/cargo`) and the toolchain (`/rustc`), which come first. rustc applies the
    /// last matching one, so the more specific directories come later.
    pub remaps: Vec<(PathBuf, &'static str)>,
    /// How Cargo runs.
    pub mode: &'a Mode,
}

/// A package built.
#[derive(Debug, Clone)]
pub struct Packed {
    /// Its checked manifest.
    pub manifest: Manifest,
    /// The `.onclp` bytes.
    pub bytes: Vec<u8>,
}

impl Packed {
    /// `<id>-<version>.onclp`.
    pub fn file_name(&self) -> String {
        crate::package_file_name(&self.manifest.id, &self.manifest.version)
    }
}

/// Builds the crate and packages its manifest and module.
///
/// The manifest version must match Cargo's package version. The finished archive and the
/// Wasm ABI are checked by the same code the daemon uses before an installation.
///
/// # Errors
///
/// An invalid crate or manifest, a failed build, an unsupported Wasm module or I/O error.
pub fn pack(build: &Build) -> anyhow::Result<Packed> {
    let directory = build.crate_dir;
    let mode = build.mode;
    let cargo_manifest = directory
        .join("Cargo.toml")
        .canonicalize()
        .with_context(|| format!("finding {}/Cargo.toml", directory.display()))?;
    // What Cargo is given: absolute, but not the verbatim (`\\?\`) form `canonicalize` gives on
    // Windows, with which Cargo fails to inherit a member's `workspace.dependencies` (as the
    // ports' shared crates do).
    let cargo_manifest_arg = std::path::absolute(directory.join("Cargo.toml"))
        .with_context(|| format!("finding {}/Cargo.toml", directory.display()))?;
    let manifest_bytes = read_limited(&directory.join("plugin.toml"), MAX_MANIFEST)?;
    let manifest_text = std::str::from_utf8(&manifest_bytes).context("plugin.toml is not UTF-8")?;
    let manifest = Manifest::from_toml(manifest_text)?;
    let mut metadata = mode.cargo();
    metadata.args([
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
        "--manifest-path",
    ]);
    metadata.arg(&cargo_manifest_arg);
    if let Mode::Reference { .. } = mode {
        metadata.arg("--frozen");
    }
    let metadata = metadata.output().context("running cargo metadata")?;
    if !metadata.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&metadata.stderr)
        );
    }
    let metadata: Value =
        serde_json::from_slice(&metadata.stdout).context("reading cargo metadata")?;
    let package = metadata["packages"]
        .as_array()
        .context("Cargo returned no packages")?
        .iter()
        .find(|p| {
            p["manifest_path"].as_str().is_some_and(|path| {
                Path::new(path)
                    .canonicalize()
                    .is_ok_and(|path| path == cargo_manifest)
            })
        })
        .context("the requested package is absent from cargo metadata")?;
    check_version(
        &manifest,
        package["version"]
            .as_str()
            .context("Cargo returned no package version")?,
    )?;
    let targets = package["targets"]
        .as_array()
        .context("Cargo returned no targets")?;
    let mut libraries = targets.iter().filter(|t| {
        t["crate_types"]
            .as_array()
            .is_some_and(|types| types.iter().any(|kind| kind == "cdylib"))
    });
    let target = libraries
        .next()
        .context("the plugin crate must have a cdylib target")?;
    if libraries.next().is_some() {
        bail!("the plugin crate must have exactly one cdylib target");
    }
    // Cargo names a library's artifact after the target with `-` made `_`.
    let target_name = target["name"]
        .as_str()
        .context("Cargo returned no target name")?
        .replace('-', "_");
    let mut cargo = mode.cargo();
    cargo
        .args(["build", "--release", "--target", TARGET, "--manifest-path"])
        .arg(&cargo_manifest_arg)
        .arg("--target-dir")
        .arg(build.target_dir)
        // The package is published, so the paths of the machine that built it (source files
        // named in panic locations) are replaced by fixed names.
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags(build)?);
    match mode {
        Mode::Workspace => {
            cargo.arg("--locked");
        }
        Mode::Reference { jobs, .. } => {
            cargo.arg("--frozen");
            for setting in FORCED_PROFILE {
                cargo.args(["--config", setting]);
            }
            if let Some(jobs) = jobs {
                cargo.arg("--jobs").arg(jobs.to_string());
            }
        }
    }
    let status = cargo
        .status()
        .with_context(|| format!("building the plugin for {TARGET}"))?;
    if !status.success() {
        bail!("the plugin build failed ({status})");
    }
    let wasm = read_limited(
        &build
            .target_dir
            .join(TARGET)
            .join("release")
            .join(format!("{target_name}.wasm")),
        MAX_WASM,
    )?;
    let compiled = oncl_plugin::Engine::new()
        .compile(&manifest, &wasm)
        .context("checking the plugin ABI")?;
    check_min_core(&manifest, compiled.imports())?;
    let bytes = oncl_plugin::archive(&manifest_bytes, &wasm)?;
    Package::read(&bytes).context("checking the packaged plugin")?;
    Ok(Packed { manifest, bytes })
}

/// `CARGO_ENCODED_RUSTFLAGS`: the remaps, then in the reference build [`FORCED_RUSTC`].
fn rustflags(build: &Build) -> anyhow::Result<String> {
    let mut flags = remap_flags(build)?;
    if let Mode::Reference { .. } = build.mode {
        for flag in FORCED_RUSTC {
            flags.push('\u{1f}');
            flags.push_str(flag);
        }
    }
    Ok(flags)
}

/// `--remap-path-prefix` flags (separated by 0x1f, as `CARGO_ENCODED_RUSTFLAGS` takes them)
/// for the directories whose paths end up in a module: the Cargo home (registry sources),
/// the toolchain, then [`Build::remaps`].
fn remap_flags(build: &Build) -> anyhow::Result<String> {
    // The toolchain rustup would pick for the crate (`cargo xtask plugin pack`); the
    // reference build asks outside the sources, so no toolchain file of theirs is seen even
    // where rustup is installed.
    let dir = match build.mode {
        Mode::Workspace => build.crate_dir,
        Mode::Reference { .. } => build.target_dir,
    };
    let sysroot = build
        .mode
        .command("rustc")
        .args(["--print", "sysroot"])
        .current_dir(dir)
        .output()
        .context("asking rustc for its sysroot")?;
    if !sysroot.status.success() {
        bail!("rustc --print sysroot failed");
    }
    let sysroot = PathBuf::from(
        String::from_utf8(sysroot.stdout)
            .context("the sysroot is not UTF-8")?
            .trim(),
    );
    let mut flags = Vec::new();
    for (from, to) in [
        (std::path::absolute(build.mode.cargo_home()?)?, "/cargo"),
        (sysroot, "/rustc"),
    ]
    .into_iter()
    .chain(build.remaps.iter().cloned())
    {
        let from = std::path::absolute(from)?;
        let from = from.to_str().context("a build path is not UTF-8")?;
        flags.push(format!("--remap-path-prefix={from}={to}"));
    }
    Ok(flags.join("\u{1f}"))
}

fn check_version(manifest: &Manifest, cargo_version: &str) -> anyhow::Result<()> {
    if manifest.version.to_string() != cargo_version {
        bail!(
            "plugin.toml version {} differs from Cargo version {cargo_version}",
            manifest.version
        );
    }
    Ok(())
}

/// A core older than the newest of `imports` (their [`Import::since`]) cannot load the
/// plugin: its `min_core` must be at least that.
///
/// # Errors
///
/// `min_core` is below the `since` of an import, which the message names.
pub fn check_min_core(manifest: &Manifest, imports: &[Import]) -> anyhow::Result<()> {
    if let Some(newest) = imports.iter().max_by_key(|import| import.since())
        && manifest.min_core < newest.since()
    {
        bail!(
            "plugin.toml min_core {} is below {}, where the host function {} appeared",
            manifest.min_core,
            newest.since(),
            newest.name()
        );
    }
    Ok(())
}
