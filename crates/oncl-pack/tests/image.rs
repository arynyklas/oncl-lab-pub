//! The builder image (`xtask/assets/plugin-builder/Dockerfile`) end to end, with a port of
//! this repository as the sources: the canonical archive of `HEAD` (without the repository's
//! `.cargo/config.toml`, its aliases and Windows flags, which the builder refuses in sources),
//! `oncl-pack fetch` with the network, then two independent `oncl-pack build` runs in fresh
//! containers without the network give the same `.onclp` bytes, and `oncl-pack verify`
//! accepts that package and refuses it with one byte changed.
//!
//! Ignored by default: it needs Docker (or Podman, `ONCL_CONTAINER=podman`), builds the image
//! from `HEAD` unless `ONCL_BUILDER_IMAGE` names one already built, and takes minutes. Run it
//! with
//!
//! ```sh
//! cargo test -p oncl-pack --test image -- --ignored --nocapture
//! ```
//!
//! It prints the image size and the time of each step.

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use oncl_pack::sha256_hex;
use oncl_pack::source::Tree;

/// The port built: a small one, with the ports' shared crates and the PDK as path
/// dependencies.
const PORT: &str = "plugins/eot";
/// The limits every container keeps to: at most 8 CPUs (fewer on a smaller host), 8 GiB and
/// 4096 processes.
fn limits() -> Vec<String> {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get().min(8));
    [
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

fn engine() -> String {
    std::env::var("ONCL_CONTAINER").unwrap_or_else(|_| "docker".into())
}

fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn timed<T>(what: &str, step: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let result = step();
    eprintln!("{what}: {:.1} s", start.elapsed().as_secs_f64());
    result
}

/// The image of `HEAD` (`git archive` as the build context, so nothing uncommitted).
fn image(root: &Path) -> String {
    if let Ok(image) = std::env::var("ONCL_BUILDER_IMAGE") {
        return image;
    }
    let tag = "oncl-plugin-builder:test";
    timed("image build", || {
        let mut archive = Command::new("git")
            .current_dir(root)
            .args(["archive", "--format=tar", "HEAD"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let status = Command::new(engine())
            .args(["build", "-f", "xtask/assets/plugin-builder/Dockerfile"])
            .args(["--build-arg", "CARGO_BUILD_JOBS=8", "-t", tag, "-"])
            .stdin(archive.stdout.take().unwrap())
            .status()
            .unwrap();
        assert!(archive.wait().unwrap().success());
        assert!(status.success(), "the image build failed");
    });
    tag.to_owned()
}

fn mount(host: &Path, at: &str, read_only: bool) -> String {
    let mut spec = format!("type=bind,src={},dst={at}", host.display());
    if read_only {
        spec.push_str(",readonly");
    }
    spec
}

/// A volume that is removed when dropped.
struct Volume(String);

impl Volume {
    fn new(name: &str) -> Self {
        let name = format!("oncl-pack-test-{}-{name}", std::process::id());
        run(Command::new(engine()).args(["volume", "create", &name]));
        Self(name)
    }

    fn at(&self, path: &str) -> String {
        format!("type=volume,src={},dst={path}", self.0)
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        let _ = Command::new(engine())
            .args(["volume", "rm", "-f", &self.0])
            .output();
    }
}

/// `<engine> run` as the reference build runs: without the network, the root file system
/// read-only, no capabilities, the Cargo home `cargo` read-only, the inputs read-only at
/// `/in`; the caller adds the name or `--rm`, the work volume, the image and `oncl-pack`'s
/// arguments. Nothing of the host is writable: the package stays in the work volume.
fn sandboxed(cargo: &Volume, input: &Path) -> Command {
    let mut command = Command::new(engine());
    command
        .args(["run", "--network=none", "--read-only", "--cap-drop=ALL"])
        .args(["--security-opt", "no-new-privileges"])
        .args(limits())
        .args(["--mount", &format!("{},readonly", cargo.at("/cargo"))])
        .args(["--mount", &mount(input, "/in", true)]);
    command
}

/// Removes a stopped container with its anonymous volumes when dropped.
struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new(engine())
            .args(["rm", "-f", "-v", &self.0])
            .output();
    }
}

#[test]
#[ignore = "needs Docker or Podman and builds the builder image (minutes)"]
fn two_builds_in_the_image_give_the_same_package_and_verify_checks_it() {
    let root = oncl_testkit::workspace_root();
    let image = image(&root);
    let size =
        run(Command::new(engine()).args(["image", "inspect", "--format", "{{.Size}}", &image]));
    eprintln!(
        "image {image}: {} bytes",
        String::from_utf8_lossy(&size.stdout).trim()
    );

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in");
    fs::create_dir(&input).unwrap();
    let archive = timed("source archive of HEAD", || {
        let mut sources = Tree::new();
        for (path, file) in Tree::from_git(&root, "HEAD").unwrap().files() {
            if !path.starts_with(".cargo/") {
                sources.insert(path, file.clone()).unwrap();
            }
        }
        sources.to_archive().unwrap()
    });
    fs::write(input.join("port.src.tar.gz"), &archive).unwrap();
    eprintln!(
        "archive: {} bytes, sha256 {}",
        archive.len(),
        sha256_hex(&archive)
    );
    let source = ["--source", "/in/port.src.tar.gz", "--path", PORT];

    let cargo = Volume::new("cargo");
    timed("fetch (network)", || {
        let work = Volume::new("fetch");
        run(Command::new(engine())
            .args(["run", "--rm", "--read-only", "--cap-drop=ALL"])
            .args(["--security-opt", "no-new-privileges"])
            .args(limits())
            .args(["--mount", &cargo.at("/cargo")])
            .args(["--mount", &work.at("/build")])
            .args(["--mount", &mount(&input, "/in", true)])
            .arg(&image)
            .arg("fetch")
            .args(source));
    });

    // The network check: a build where an interface other than `lo` exists does not start.
    let work = Volume::new("networked");
    let output = Command::new(engine())
        .args(["run", "--rm", "--read-only", "--cap-drop=ALL"])
        .args(["--mount", &format!("{},readonly", cargo.at("/cargo"))])
        .args(["--mount", &work.at("/build")])
        .args(["--mount", &mount(&input, "/in", true)])
        .arg(&image)
        .arg("build")
        .args(source)
        .args(["--out", "/build/out"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() && stderr.contains("the network is on"),
        "{stderr}"
    );
    drop(work);

    let mut packages = Vec::new();
    for run_name in ["first", "second"] {
        let work = Volume::new(run_name);
        let container = Container(format!("oncl-pack-test-{}-{run_name}", std::process::id()));
        timed(
            &format!("build, {run_name} container (two builds inside)"),
            || {
                run(sandboxed(&cargo, &input)
                    .args(["--name", &container.0])
                    .args(["--mount", &work.at("/build")])
                    .arg(&image)
                    .arg("build")
                    .args(source)
                    .args(["--out", "/build/out", "--jobs", "8"]));
            },
        );
        // Collected after the container exited, and hashed here: nothing it printed is used.
        let out = dir.path().join(run_name);
        run(Command::new(engine()).args([
            "cp",
            &format!("{}:/build/out", container.0),
            &out.display().to_string(),
        ]));
        let files: Vec<_> = fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "one package: {files:?}");
        assert!(fs::symlink_metadata(&files[0]).unwrap().is_file());
        packages.push((files[0].clone(), fs::read(&files[0]).unwrap()));
    }
    let (first, second) = (&packages[0], &packages[1]);
    assert_eq!(first.0.file_name(), second.0.file_name());
    assert!(first.1 == second.1, "two independent builds differ");
    eprintln!(
        "{}: {} bytes, sha256 {}",
        first.0.file_name().unwrap().to_string_lossy(),
        first.1.len(),
        sha256_hex(&first.1)
    );
    let package = oncl_plugin::Package::read(&first.1).unwrap();
    assert!(
        package.manifest.id.ends_with(".port.eot"),
        "{}",
        package.manifest.id
    );

    fs::copy(&first.0, input.join("published.onclp")).unwrap();
    let mut tampered = first.1.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;
    fs::write(input.join("tampered.onclp"), &tampered).unwrap();
    for (package, same) in [("published", true), ("tampered", false)] {
        let work = Volume::new(&format!("verify-{package}"));
        let output = timed(&format!("verify {package}"), || {
            sandboxed(&cargo, &input)
                .arg("--rm")
                .args(["--mount", &work.at("/build")])
                .arg(&image)
                .arg("verify")
                .args(source)
                .args(["--package", &format!("/in/{package}.onclp")])
                .output()
                .unwrap()
        });
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.success(), same, "verify {package}: {stderr}");
        if !same {
            assert!(stderr.contains("differs from the package"), "{stderr}");
        }
    }
}
