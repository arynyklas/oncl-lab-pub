//! The reference build of a publisher's package in the builder image, as the publisher runs
//! it (`vendor build`), as CI's rebuild job runs it (checks 19 and 20) and as anyone checks a
//! published release (`vendor verify`) (`docs/design/publishers.md`, «Сборщик»):
//!
//! 1. `oncl-pack fetch` in a container with the network: the archive unpacked into a work
//!    volume, its crates into a Cargo volume; no code of the sources runs;
//! 2. `cargo metadata` in a container without the network over the same volumes, read-only:
//!    the crates of the module and their licences (check 20, `THIRD-PARTY.txt`);
//! 3. `oncl-pack build` (two builds compared) or `oncl-pack verify` in a container started
//!    with `--network=none`, the root file system and the Cargo volume read-only, no
//!    capabilities, an unprivileged user, limits on CPUs, memory and processes, a fresh work
//!    volume and no host directory writable;
//! 4. the package taken out with `docker cp` after the container ended: exactly one regular
//!    file, not a link, at most `MAX_PACKAGE` bytes, hashed here. Nothing the container
//!    printed is believed.
//!
//! The commands are built by pure functions ([`fetch_args`], [`metadata_args`],
//! [`build_args`], [`verify_args`]) and checked by tests; [`run`] runs them with a deadline.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use oncl_pack::source::Tree;
use serde_json::Value;

use super::licenses::{self, WasmCrate};
use super::verdict::Checks;

/// The user of the builder image.
pub const USER: &str = "10001:10001";

/// Where the archive is mounted in a container (read-only).
const INPUT: &str = "/in";

/// The archive's file name inside [`INPUT`].
const ARCHIVE: &str = "source.src.tar.gz";

/// How long the fetch of the crates and the metadata may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// The container engine: `docker`, or `podman` with `ONCL_CONTAINER=podman`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Engine(pub String);

impl Engine {
    /// `ONCL_CONTAINER`, else `docker`.
    pub fn from_env() -> Engine {
        Engine(std::env::var("ONCL_CONTAINER").unwrap_or_else(|_| "docker".to_owned()))
    }

    fn command(&self) -> Command {
        Command::new(&self.0)
    }
}

/// The limits and hardening every container of a build keeps to.
pub fn hardening() -> Vec<String> {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get().min(8));
    [
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        USER,
        "--cpus",
        &cpus.to_string(),
        "--memory",
        "8g",
        "--pids-limit",
        "4096",
    ]
    .map(str::to_owned)
    .into()
}

fn volume(name: &str, at: &str, read_only: bool) -> String {
    let mut spec = format!("type=volume,src={name},dst={at}");
    if read_only {
        spec.push_str(",readonly");
    }
    spec
}

fn input(dir: &Path) -> String {
    format!("type=bind,src={},dst={INPUT},readonly", dir.display())
}

/// What one build works on: the image by digest, the volumes, the archive's directory and
/// the crate.
#[derive(Clone, Debug)]
pub struct Job<'a> {
    /// The image, `ghcr.io/arynyklas/oncl-plugin-builder@sha256:…`.
    pub image: &'a str,
    /// The Cargo volume.
    pub cargo: &'a str,
    /// The work volume of the fetch and the metadata.
    pub work: &'a str,
    /// The host directory holding [`ARCHIVE`], mounted read-only.
    pub input: &'a Path,
    /// The crate directory under `src/` (`source.path`).
    pub crate_path: &'a str,
}

/// `run` of the fetch: with the network, the Cargo and work volumes writable.
pub fn fetch_args(job: &Job, name: &str) -> Vec<String> {
    let mut args = vec!["run".to_owned(), "--name".to_owned(), name.to_owned()];
    args.extend(hardening());
    args.extend([
        "--mount".to_owned(),
        volume(job.cargo, "/cargo", false),
        "--mount".to_owned(),
        volume(job.work, "/build", false),
        "--mount".to_owned(),
        input(job.input),
        job.image.to_owned(),
        "fetch".to_owned(),
        "--source".to_owned(),
        format!("{INPUT}/{ARCHIVE}"),
        format!("--path={}", job.crate_path),
    ]);
    args
}

/// `run` of `cargo metadata` over the fetched sources: without the network, both volumes
/// read-only.
pub fn metadata_args(job: &Job, name: &str) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
        "--network=none".to_owned(),
    ];
    args.extend(hardening());
    args.extend([
        "--mount".to_owned(),
        volume(job.cargo, "/cargo", true),
        "--mount".to_owned(),
        volume(job.work, "/build", true),
        "--entrypoint".to_owned(),
        "cargo".to_owned(),
        job.image.to_owned(),
        "metadata".to_owned(),
        "--format-version".to_owned(),
        "1".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
        "--filter-platform".to_owned(),
        oncl_pack::pack::TARGET.to_owned(),
        "--manifest-path".to_owned(),
        manifest_path(job.crate_path),
    ]);
    args
}

/// The crate's `Cargo.toml` in the container.
pub fn manifest_path(crate_path: &str) -> String {
    if crate_path.is_empty() {
        "/build/src/Cargo.toml".to_owned()
    } else {
        format!("/build/src/{crate_path}/Cargo.toml")
    }
}

/// `run` of `oncl-pack build`: without the network, the Cargo volume read-only, a fresh
/// anonymous work volume.
pub fn build_args(job: &Job, name: &str, jobs: Option<u32>) -> Vec<String> {
    let mut args = sandboxed(job, name);
    args.extend([
        "build".to_owned(),
        "--source".to_owned(),
        format!("{INPUT}/{ARCHIVE}"),
        format!("--path={}", job.crate_path),
        "--out".to_owned(),
        "/build/out".to_owned(),
    ]);
    if let Some(jobs) = jobs {
        args.extend(["--jobs".to_owned(), jobs.to_string()]);
    }
    args
}

/// `run` of `oncl-pack verify` against `sha256`, as [`build_args`].
pub fn verify_args(job: &Job, name: &str, sha256: &str) -> Vec<String> {
    let mut args = sandboxed(job, name);
    args.extend([
        "verify".to_owned(),
        "--source".to_owned(),
        format!("{INPUT}/{ARCHIVE}"),
        format!("--path={}", job.crate_path),
        "--sha256".to_owned(),
        sha256.to_owned(),
    ]);
    args
}

fn sandboxed(job: &Job, name: &str) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
        "--network=none".to_owned(),
    ];
    args.extend(hardening());
    args.extend([
        "--mount".to_owned(),
        volume(job.cargo, "/cargo", true),
        "--mount".to_owned(),
        "type=volume,dst=/build".to_owned(),
        "--mount".to_owned(),
        input(job.input),
        job.image.to_owned(),
    ]);
    args
}

/// What a container run gave.
#[derive(Debug)]
pub struct Ran {
    /// Whether it exited with 0.
    pub success: bool,
    /// Its standard output.
    pub stdout: Vec<u8>,
    /// Its standard error.
    pub stderr: Vec<u8>,
}

/// Runs `engine args` (a `run --name name …`) within `timeout`; past it the container is
/// killed. The stopped container is left for the caller to copy from and remove.
///
/// # Errors
///
/// The engine cannot be started, or the deadline passed.
pub fn run(engine: &Engine, args: &[String], name: &str, timeout: Duration) -> anyhow::Result<Ran> {
    let mut child = engine
        .command()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", engine.0))?;
    let mut stdout = child.stdout.take().context("no stdout")?;
    let mut stderr = child.stderr.take().context("no stderr")?;
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > timeout {
            let _ = engine.command().args(["kill", name]).output();
            let _ = child.kill();
            let _ = child.wait();
            bail!("{name} did not finish within {} s", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    Ok(Ran {
        success: status.success(),
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// A named volume, removed when dropped.
struct Volume<'e> {
    engine: &'e Engine,
    name: String,
}

impl<'e> Volume<'e> {
    fn new(engine: &'e Engine, name: String) -> anyhow::Result<Volume<'e>> {
        let output = engine
            .command()
            .args(["volume", "create", &name])
            .output()
            .with_context(|| format!("starting {}", engine.0))?;
        if !output.status.success() {
            bail!(
                "{} volume create failed: {}",
                engine.0,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(Volume { engine, name })
    }
}

impl Drop for Volume<'_> {
    fn drop(&mut self) {
        let _ = self
            .engine
            .command()
            .args(["volume", "rm", "-f", &self.name])
            .output();
    }
}

/// A container, removed with its anonymous volumes when dropped.
struct Container<'e> {
    engine: &'e Engine,
    name: String,
}

impl Drop for Container<'_> {
    fn drop(&mut self) {
        let _ = self
            .engine
            .command()
            .args(["rm", "-f", "-v", &self.name])
            .output();
    }
}

/// A name no other run of this process or another uses.
fn unique(step: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!("oncl-vendor-{}-{nanos:09}-{step}", std::process::id())
}

/// The one package in `dir` (the build's `out`, copied out of the container): exactly one
/// regular file, not a link, named `*.onclp`, at most `MAX_PACKAGE` bytes. Its name and
/// bytes.
///
/// # Errors
///
/// Anything else in `dir`.
pub fn collect_package(dir: &Path) -> anyhow::Result<(String, Vec<u8>)> {
    // The container may have made `out` a link to anywhere on the host.
    if !fs::symlink_metadata(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .file_type()
        .is_dir()
    {
        bail!("{} is not a directory", dir.display());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    entries.sort();
    let [path] = entries.as_slice() else {
        bail!(
            "the build left {} entries in out, not exactly one package",
            entries.len()
        );
    };
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| n.ends_with(".onclp") && !n.starts_with('.'))
        .with_context(|| format!("{} is not named <id>-<version>.onclp", path.display()))?
        .to_owned();
    let bytes = oncl_pack::read_limited(path, oncl_plugin::MAX_PACKAGE)?;
    Ok((name, bytes))
}

/// What the rebuild of one archive gave.
#[derive(Debug, Default)]
pub struct Rebuilt {
    /// Checks 19 and 20.
    pub checks: Checks,
    /// The package's file name and bytes, if the build succeeded.
    pub package: Option<(String, Vec<u8>)>,
    /// The crates of the module, if `cargo metadata` read them.
    pub crates: Vec<WasmCrate>,
    /// Their licence files.
    pub licences: licenses::LicenceTexts,
}

/// The tail of a container's standard error, for a message.
fn tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text.lines().rev().take(12).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

/// `docker create` of a container over the Cargo volume, never started: its files are copied
/// out with `docker cp`, nothing of the sources runs.
pub fn holder_args(image: &str, cargo: &str, name: &str) -> Vec<String> {
    let mut args = vec![
        "create".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
        "--network=none".to_owned(),
    ];
    args.extend(hardening());
    args.extend([
        "--mount".to_owned(),
        volume(cargo, "/cargo", true),
        image.to_owned(),
    ]);
    args
}

/// The licence files of each crate of the module: a crate of the sources from the archive
/// `tree`, a fetched one from its directory in the Cargo volume, copied out of a container
/// that never starts. A crate anywhere else gets none (and fails check 20).
fn collect_texts(
    engine: &Engine,
    image: &str,
    cargo: &str,
    crates: &[WasmCrate],
    tree: &Tree,
    work: &Path,
) -> anyhow::Result<licenses::LicenceTexts> {
    let mut texts = licenses::LicenceTexts::new();
    let holder = Container {
        engine,
        name: unique("licences"),
    };
    let created = engine
        .command()
        .args(holder_args(image, cargo, &holder.name))
        .output()
        .with_context(|| format!("starting {}", engine.0))?;
    if !created.status.success() {
        bail!(
            "{} create failed: {}",
            engine.0,
            String::from_utf8_lossy(&created.stderr).trim()
        );
    }
    for (n, c) in crates.iter().enumerate() {
        let dir = c.manifest_path.rsplit_once('/').map_or("", |(d, _)| d);
        let plain = !dir.split('/').any(|s| s == ".." || s == ".");
        let files = if let Some(rel) = dir.strip_prefix("/build/src").filter(|_| plain) {
            licenses::tree_licence_files(tree, rel)
        } else if dir.starts_with("/cargo/") && plain {
            let host = work.join("licences").join(n.to_string());
            fs::create_dir_all(host.parent().unwrap_or(work))?;
            let cp = engine
                .command()
                .args(["cp", &format!("{}:{dir}", holder.name)])
                .arg(&host)
                .output()
                .with_context(|| format!("starting {}", engine.0))?;
            if cp.status.success() && fs::symlink_metadata(&host)?.is_dir() {
                licenses::licence_files(&host)?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        texts.insert((c.name.clone(), c.version.clone()), files);
    }
    Ok(texts)
}

/// The largest bare repository check 25 copies out of its container (shallow: one revision).
pub const MAX_VCS_REPO: u64 = 256 << 20;

/// Whether `name` may be check 25's network by its name alone: not a built-in or another
/// container's namespace (`host`, `bridge`, `default`, `none`, `container:…`, `ns:…`,
/// `slirp4netns`, `pasta`), a plain name.
///
/// # Errors
///
/// Why it is refused.
pub fn network_name(name: &str) -> Result<(), String> {
    let builtin = [
        "host",
        "bridge",
        "default",
        "none",
        "slirp4netns",
        "pasta",
        "private",
    ];
    if name.contains(':') || builtin.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(format!(
            "--network {name} is a built-in or shared network: use the egress-only bridge of \
             docs/dev/publishers.md («Сеть проверки 25»)"
        ));
    }
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(format!("--network {name:?} is not a network name"));
    }
    Ok(())
}

/// Checks `name` ([`network_name`]) and that the engine has it as a user-defined bridge.
///
/// # Errors
///
/// It is refused, missing or of another driver.
pub fn check_network(engine: &Engine, name: &str) -> anyhow::Result<()> {
    network_name(name).map_err(|e| anyhow::anyhow!(e))?;
    let out = engine
        .command()
        .args(["network", "inspect", "--format", "{{.Driver}}", name])
        .output()
        .with_context(|| format!("starting {}", engine.0))?;
    let driver = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if !out.status.success() || driver != "bridge" {
        bail!("--network {name} is not a user-defined bridge network (driver {driver:?})");
    }
    Ok(())
}

/// The bytes of the regular files under `dir`, links not followed.
fn tree_size(dir: &Path) -> std::io::Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            total += tree_size(&entry.path())?;
        } else if kind.is_file() {
            total += entry.metadata()?.len();
        }
    }
    Ok(total)
}

/// The git configuration of check 25's fetch: `https` only, no redirect, no credential.
const GIT_SANDBOX: [&str; 10] = [
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "http.followRedirects=false",
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
];

/// `run` of `git` in `image` on `network` (check 25): unprivileged, read-only, its only
/// writable place the volume `work` at `/build`, `git_args` after the sandbox
/// configuration.
pub fn git_args(
    image: &str,
    network: &str,
    work: &str,
    name: &str,
    git_args: &[&str],
) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
        format!("--network={network}"),
    ];
    args.extend(hardening());
    args.extend(
        [
            "--mount",
            &volume(work, "/build", false),
            "--env",
            "GIT_TERMINAL_PROMPT=0",
            "--env",
            "GIT_CONFIG_NOSYSTEM=1",
            "--env",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "--entrypoint",
            "git",
            image,
        ]
        .map(str::to_owned),
    );
    args.extend(GIT_SANDBOX.map(str::to_owned));
    args.extend(git_args.iter().map(|a| (*a).to_owned()));
    args
}

/// Fetches `rev` of `url` in a container of `image` on `network` into a new bare repository,
/// copied out to `dest` once the container ended (check 25).
///
/// # Errors
///
/// The engine fails, git fails or runs out of `timeout`.
pub fn git_fetch(
    engine: &Engine,
    image: &str,
    network: &str,
    url: &str,
    rev: &str,
    dest: &Path,
    timeout: Duration,
) -> anyhow::Result<()> {
    let format = if rev.len() == 64 {
        "--object-format=sha256"
    } else {
        "--object-format=sha1"
    };
    let work = Volume::new(engine, unique("vcs"))?;
    let init = Container {
        engine,
        name: unique("vcs-init"),
    };
    let ran = run(
        engine,
        &git_args(
            image,
            "none",
            &work.name,
            &init.name,
            &["init", "-q", "--bare", format, "/build/vcs.git"],
        ),
        &init.name,
        timeout,
    )?;
    if !ran.success {
        bail!("git init: {}", tail(&ran.stderr));
    }
    let fetch = Container {
        engine,
        name: unique("vcs-fetch"),
    };
    let ran = run(
        engine,
        &git_args(
            image,
            network,
            &work.name,
            &fetch.name,
            &[
                "-C",
                "/build/vcs.git",
                "fetch",
                "-q",
                "--no-tags",
                "--depth=1",
                url,
                rev,
            ],
        ),
        &fetch.name,
        timeout,
    )?;
    if !ran.success {
        bail!("git fetch {url} {rev}: {}", tail(&ran.stderr));
    }
    let cp = engine
        .command()
        .args(["cp", &format!("{}:/build/vcs.git", fetch.name)])
        .arg(dest)
        .output()
        .with_context(|| format!("starting {}", engine.0))?;
    if !cp.status.success() {
        bail!(
            "{} cp of the repository failed: {}",
            engine.0,
            String::from_utf8_lossy(&cp.stderr).trim()
        );
    }
    if !fs::symlink_metadata(dest)?.is_dir() {
        bail!("the copied repository is not a directory");
    }
    // `Tree::from_git` then keeps to the archive's own limits (MAX_UNPACKED, MAX_ENTRIES).
    let size = tree_size(dest)?;
    if size > MAX_VCS_REPO {
        bail!("the repository of one revision is {size} bytes, more than {MAX_VCS_REPO}");
    }
    Ok(())
}

/// Puts `archive` alone into a fresh directory under `work`, as the containers' input.
fn stage(archive: &Path, work: &Path) -> anyhow::Result<PathBuf> {
    let input = work.join("in");
    fs::create_dir_all(&input)?;
    fs::copy(archive, input.join(ARCHIVE))
        .with_context(|| format!("copying {}", archive.display()))?;
    Ok(input)
}

/// The fetch and the metadata of `archive`'s crate in `image`: the Cargo volume to build
/// with, and the crates of the module (or why not, check 20). Every package `cargo metadata`
/// resolves comes from crates.io or `allowed_git` (check 17 again, on what Cargo itself read).
fn prepare<'e>(
    engine: &'e Engine,
    image: &str,
    input: &Path,
    crate_path: &str,
    allowed_git: &[String],
    checks: &mut Checks,
) -> anyhow::Result<(Volume<'e>, Option<Vec<WasmCrate>>)> {
    let cargo = Volume::new(engine, unique("cargo"))?;
    let work = Volume::new(engine, unique("work"))?;
    let job = Job {
        image,
        cargo: &cargo.name,
        work: &work.name,
        input,
        crate_path,
    };
    let fetch = Container {
        engine,
        name: unique("fetch"),
    };
    let ran = run(
        engine,
        &fetch_args(&job, &fetch.name),
        &fetch.name,
        FETCH_TIMEOUT,
    )?;
    if !ran.success {
        checks.fail(
            19,
            format!("oncl-pack fetch failed:\n{}", tail(&ran.stderr)),
        );
        return Ok((cargo, None));
    }
    let metadata = Container {
        engine,
        name: unique("metadata"),
    };
    let ran = run(
        engine,
        &metadata_args(&job, &metadata.name),
        &metadata.name,
        FETCH_TIMEOUT,
    )?;
    if !ran.success {
        checks.fail(20, format!("cargo metadata failed:\n{}", tail(&ran.stderr)));
        return Ok((cargo, None));
    }
    let metadata = match serde_json::from_slice::<Value>(&ran.stdout) {
        Ok(metadata) => metadata,
        Err(e) => {
            checks.fail(20, format!("cargo metadata printed no JSON: {e}"));
            return Ok((cargo, None));
        }
    };
    for package in metadata["packages"].as_array().into_iter().flatten() {
        if let Some(source) = package["source"].as_str() {
            let name = package["name"].as_str().unwrap_or("?");
            if let Some(why) = super::checks::source_finding(name, source, allowed_git) {
                checks.fail(17, format!("cargo metadata: {why}"));
            }
        }
    }
    if !checks.failed(17) {
        checks.pass(17);
    }
    match licenses::wasm_crates(&metadata, &manifest_path(crate_path)) {
        Ok(crates) => {
            checks.record(20, licenses::check_crates(&crates));
            Ok((cargo, Some(crates)))
        }
        Err(e) => {
            checks.fail(20, format!("{e:#}"));
            Ok((cargo, None))
        }
    }
}

/// Rebuilds the package of `archive` (the crate at `crate_path`) in `image`, using `work` (a
/// directory of the host) for the input and the copied output: checks 19 and 20.
///
/// # Errors
///
/// The engine cannot be run or a file of `work` cannot be written: no outcome at all.
pub fn rebuild(
    engine: &Engine,
    image: &str,
    archive: &Path,
    crate_path: &str,
    allowed_git: &[String],
    jobs: Option<u32>,
    work: &Path,
) -> anyhow::Result<Rebuilt> {
    let mut out = Rebuilt::default();
    let input = stage(archive, work)?;
    let (cargo, crates) = prepare(
        engine,
        image,
        &input,
        crate_path,
        allowed_git,
        &mut out.checks,
    )?;
    out.crates = crates.unwrap_or_default();
    if !out.crates.is_empty() {
        let tree = Tree::from_archive(&oncl_pack::read_limited(
            archive,
            oncl_pack::source::MAX_ARCHIVE,
        )?)
        .map_err(|e| anyhow::anyhow!("{}: {e}", archive.display()))?;
        out.licences = collect_texts(engine, image, &cargo.name, &out.crates, &tree, work)?;
        if let Err(problems) = licenses::check_texts(&out.crates, &out.licences) {
            for p in problems {
                out.checks.fail(20, p);
            }
        }
    }
    if !out.checks.failures().is_empty() {
        out.checks
            .skip(19, "the sources or their licences failed a check");
        return Ok(out);
    }
    let job = Job {
        image,
        cargo: &cargo.name,
        work: "",
        input: &input,
        crate_path,
    };
    let build = Container {
        engine,
        name: unique("build"),
    };
    let ran = run(
        engine,
        &build_args(&job, &build.name, jobs),
        &build.name,
        super::REBUILD_TIMEOUT,
    );
    let ran = match ran {
        Ok(ran) => ran,
        Err(e) => {
            out.checks.fail(19, format!("{e:#}"));
            return Ok(out);
        }
    };
    if !ran.success {
        out.checks.fail(
            19,
            format!("oncl-pack build failed:\n{}", tail(&ran.stderr)),
        );
        return Ok(out);
    }
    let copied = work.join("out");
    let cp = engine
        .command()
        .args(["cp", &format!("{}:/build/out", build.name)])
        .arg(&copied)
        .output()
        .with_context(|| format!("starting {}", engine.0))?;
    if !cp.status.success() {
        out.checks.fail(
            19,
            format!(
                "{} cp of the package failed: {}",
                engine.0,
                String::from_utf8_lossy(&cp.stderr).trim()
            ),
        );
        return Ok(out);
    }
    match collect_package(&copied) {
        Ok(package) => {
            out.checks.pass(19);
            out.package = Some(package);
        }
        Err(e) => out.checks.fail(19, format!("{e:#}")),
    }
    Ok(out)
}

/// Rebuilds the package of `archive` in `image` and compares it with `sha256` (`oncl-pack
/// verify`): whether the same bytes came out.
///
/// # Errors
///
/// The engine cannot be run, the crates cannot be fetched, or the rebuild differs or fails.
pub fn verify(
    engine: &Engine,
    image: &str,
    archive: &Path,
    crate_path: &str,
    sha256: &str,
    work: &Path,
) -> anyhow::Result<()> {
    let input = stage(archive, work)?;
    let mut checks = Checks::new();
    // Anyone checks a published release: its sources were judged when it was taken in.
    let (cargo, _) = prepare(engine, image, &input, crate_path, &[], &mut checks)?;
    if checks.failed(19) {
        bail!("{:?}", checks.to_vec());
    }
    let job = Job {
        image,
        cargo: &cargo.name,
        work: "",
        input: &input,
        crate_path,
    };
    let container = Container {
        engine,
        name: unique("verify"),
    };
    let ran = run(
        engine,
        &verify_args(&job, &container.name, sha256),
        &container.name,
        super::REBUILD_TIMEOUT,
    )?;
    if !ran.success {
        bail!(
            "the rebuild did not give the package {sha256}:\n{}",
            tail(&ran.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(input: &Path) -> Job<'_> {
        Job {
            image: "ghcr.io/arynyklas/oncl-plugin-builder@sha256:abc",
            cargo: "cargo-v",
            work: "work-v",
            input,
            crate_path: "crates/market",
        }
    }

    #[test]
    fn the_build_runs_without_the_network_by_digest_and_unprivileged() {
        let dir = Path::new("/tmp/in");
        let args = build_args(&job(dir), "b", Some(8));
        let joined = args.join(" ");
        for wanted in [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "no-new-privileges",
            "--user 10001:10001",
            "type=volume,src=cargo-v,dst=/cargo,readonly",
            "type=volume,dst=/build",
            "dst=/in,readonly",
            "@sha256:abc build --source /in/source.src.tar.gz --path=crates/market --out /build/out --jobs 8",
        ] {
            assert!(joined.contains(wanted), "{wanted}: {joined}");
        }
        // No host directory is writable: the only bind mount is the input, read-only.
        assert_eq!(joined.matches("type=bind").count(), 1, "{joined}");
        let verify = verify_args(&job(dir), "v", "00").join(" ");
        assert!(
            verify.contains("--network=none") && verify.contains("verify --source"),
            "{verify}"
        );
        let metadata = metadata_args(&job(dir), "m").join(" ");
        for wanted in [
            "--network=none",
            "type=volume,src=work-v,dst=/build,readonly",
            "--entrypoint cargo",
            "metadata --format-version 1 --locked --offline --filter-platform wasm32-unknown-unknown",
            "--manifest-path /build/src/crates/market/Cargo.toml",
        ] {
            assert!(metadata.contains(wanted), "{wanted}: {metadata}");
        }
        // The fetch alone has the network, and runs no code of the sources.
        let fetch = fetch_args(&job(dir), "f").join(" ");
        assert!(
            !fetch.contains("--network=none") && fetch.contains(" fetch --source"),
            "{fetch}"
        );
    }

    #[test]
    fn check_25_runs_on_a_named_user_network_only() {
        network_name("oncl-vcs").unwrap();
        network_name("oncl_vcs.1").unwrap();
        for refused in [
            "host",
            "bridge",
            "Default",
            "none",
            "slirp4netns",
            "pasta",
            "private",
            "container:runner",
            "ns:/proc/1/ns/net",
            "slirp4netns:allow_host_loopback=true",
            "",
            "a b",
        ] {
            assert!(network_name(refused).is_err(), "{refused}");
        }
        // A name that passes still has to be a user-defined bridge the engine knows.
        assert!(check_network(&Engine("no-such-engine".into()), "oncl-vcs").is_err());
    }

    #[test]
    fn licence_copies_and_the_git_sandbox_run_nothing_of_the_sources() {
        let holder = holder_args("img@sha256:abc", "cargo-v", "h").join(" ");
        assert!(
            holder.starts_with("create --name h --network=none"),
            "{holder}"
        );
        assert!(
            holder.contains("type=volume,src=cargo-v,dst=/cargo,readonly"),
            "{holder}"
        );
        let git = git_args(
            "img@sha256:abc",
            "oncl-vcs",
            "work-v",
            "g",
            &["fetch", "https://example.com/r.git", "abc"],
        )
        .join(" ");
        for wanted in [
            "--network=oncl-vcs",
            "--read-only",
            "--cap-drop=ALL",
            "--user 10001:10001",
            "--entrypoint git img@sha256:abc",
            "protocol.allow=never",
            "protocol.https.allow=always",
            "http.followRedirects=false",
            "credential.helper=",
            "GIT_TERMINAL_PROMPT=0",
        ] {
            assert!(git.contains(wanted), "{wanted}: {git}");
        }
        assert!(!git.contains("type=bind"), "{git}");
    }

    #[test]
    fn the_output_is_exactly_one_regular_package() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();
        assert!(collect_package(&out).is_err(), "empty");
        fs::write(out.join("kz.a.b-1.0.0.onclp"), b"zip").unwrap();
        let (name, bytes) = collect_package(&out).unwrap();
        assert_eq!(
            (name.as_str(), bytes.as_slice()),
            ("kz.a.b-1.0.0.onclp", &b"zip"[..])
        );
        fs::write(out.join("extra.txt"), b"x").unwrap();
        let err = collect_package(&out).unwrap_err();
        assert!(format!("{err:#}").contains("2 entries"), "{err:#}");
        fs::remove_file(out.join("extra.txt")).unwrap();
        fs::remove_file(out.join("kz.a.b-1.0.0.onclp")).unwrap();
        fs::create_dir(out.join("kz.a.b-1.0.0.onclp")).unwrap();
        assert!(collect_package(&out).is_err(), "a directory");
    }
}
