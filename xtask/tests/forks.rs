//! The forks named in `[patch.crates-io]` are the ones the lock file uses.
//!
//! An upgrade of a patched crate leaves its `[patch.crates-io]` entry unused (cargo only
//! warns) and brings the crates.io package back: Slint's winit backend would import
//! `SystemParametersInfoForDpi` again, which Windows 7 does not have, Velopack would use an
//! Update.exe taken from a package rebuilt from a delta before anything checks it, and the
//! framing observer of `multer` would be missing.

use oncl_testkit::workspace_root;

fn read_table(path: &str) -> toml::Table {
    std::fs::read_to_string(workspace_root().join(path))
        .unwrap()
        .parse()
        .unwrap()
}

/// `(version, source)` of every locked package `name`.
fn locked(lock: &toml::Table, name: &str) -> Vec<(String, Option<String>)> {
    lock["package"]
        .as_array()
        .expect("[[package]] in Cargo.lock")
        .iter()
        .filter(|p| p["name"].as_str() == Some(name))
        .map(|p| {
            (
                p["version"].as_str().unwrap().to_owned(),
                p.get("source").and_then(|s| s.as_str()).map(str::to_owned),
            )
        })
        .collect()
}

/// The git source Cargo.lock records for a dependency pinned by `rev` in the manifest.
fn pinned_source(spec: &toml::Value) -> String {
    let git = spec["git"].as_str().expect("a git dependency");
    let rev = spec["rev"].as_str().expect("pinned by rev");
    assert_eq!(rev.len(), 40, "rev must be a full commit hash: {rev}");
    format!("git+{git}?rev={rev}#{rev}")
}

#[test]
fn every_patched_crate_is_locked_from_its_pinned_fork() {
    let manifest = read_table("Cargo.toml");
    let lock = read_table("Cargo.lock");
    let patches = manifest["patch"]["crates-io"]
        .as_table()
        .expect("[patch.crates-io]");
    assert_eq!(
        patches.keys().map(String::as_str).collect::<Vec<_>>(),
        ["i-slint-backend-winit", "velopack"]
    );
    for (name, spec) in patches {
        let source = pinned_source(spec);
        let packages = locked(&lock, name);
        let forked: Vec<_> = packages
            .iter()
            .filter(|(_, s)| s.as_deref() == Some(&source))
            .collect();
        assert_eq!(
            forked.len(),
            1,
            "{name} is not locked from {source}: {packages:?}"
        );
        for (version, source) in &packages {
            assert!(
                !(source
                    .as_deref()
                    .is_some_and(|s| s.starts_with("registry+"))
                    && *version == forked[0].0),
                "{name} {version} also comes from a registry: update the fork"
            );
        }
    }
}

#[test]
fn multer_is_locked_from_its_pinned_fork() {
    let manifest = read_table("Cargo.toml");
    let lock = read_table("Cargo.lock");
    let dependencies = &manifest["workspace"]["dependencies"];
    let source = pinned_source(&dependencies["multer"]);
    let multer = locked(&lock, "multer");
    assert_eq!(
        multer.len(),
        1,
        "exactly one multer must be locked, from {source}: {multer:?}"
    );
    assert_eq!(
        multer[0].1.as_deref(),
        Some(source.as_str()),
        "multer is not locked from {source}"
    );
}

#[test]
fn locked_winit_backend_is_slints_version() {
    let lock = read_table("Cargo.lock");
    let backend = locked(&lock, "i-slint-backend-winit");
    let core = locked(&lock, "i-slint-core");
    assert_eq!(backend.len(), 1);
    assert_eq!(core.len(), 1);
    assert_eq!(
        backend[0].0, core[0].0,
        "the patched backend is not Slint's version"
    );
}

#[test]
fn locked_velopack_is_the_version_the_workspace_asks_for() {
    let manifest = read_table("Cargo.toml");
    let lock = read_table("Cargo.lock");
    let wanted = manifest["workspace"]["dependencies"]["velopack"]["version"]
        .as_str()
        .unwrap();
    let velopack = locked(&lock, "velopack");
    assert_eq!(velopack.len(), 1, "{velopack:?}");
    assert_eq!(velopack[0].0, wanted);
}

#[test]
fn rustcrypto_streebog_and_hmac_come_from_crates_io() {
    // The secret-input Streebog and HMAC are code of `oncl-gost`; a git source here would
    // mean a fork is back, and SDK consumers would need a `[patch.crates-io]` again.
    let lock = read_table("Cargo.lock");
    for name in ["hmac", "streebog"] {
        let packages = locked(&lock, name);
        assert!(!packages.is_empty(), "{name} is not locked");
        for (version, source) in &packages {
            assert!(
                source
                    .as_deref()
                    .is_some_and(|s| s.starts_with("registry+")),
                "{name} {version} does not come from a registry: {source:?}"
            );
        }
    }
}
