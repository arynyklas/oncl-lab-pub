//! The builder image's Dockerfile pins what it is made of: the base image by digest, the Rust
//! release of the workspace (`rust-toolchain.toml`), and each toolchain tarball by SHA-256.

use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(oncl_testkit::workspace_root().join(path))
        .unwrap()
        .replace("\r\n", "\n")
}

/// The default of `ARG <name>=…`.
fn arg<'a>(dockerfile: &'a str, name: &str) -> &'a str {
    let prefix = format!("ARG {name}=");
    dockerfile
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no ARG {name}"))
}

#[test]
fn the_image_is_pinned_and_has_the_workspace_toolchain() {
    let dockerfile = read("xtask/assets/plugin-builder/Dockerfile");
    let base = arg(&dockerfile, "BASE_IMAGE");
    let (_, digest) = base
        .split_once("@sha256:")
        .expect("the base image by digest");
    assert!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "{base}"
    );
    for line in dockerfile.lines().filter(|l| l.starts_with("FROM ")) {
        let image = line.split_whitespace().nth(1).unwrap();
        assert!(
            image == "${BASE_IMAGE}" || ["toolchain", "runtime"].contains(&image),
            "every stage starts from the pinned base: {line}"
        );
    }
    let toolchain = read("rust-toolchain.toml");
    let channel = toolchain
        .lines()
        .find_map(|line| line.strip_prefix("channel = "))
        .unwrap()
        .trim_matches('"');
    assert_eq!(arg(&dockerfile, "RUST_VERSION"), channel);
    for name in [
        "RUSTC_SHA256",
        "CARGO_SHA256",
        "STD_HOST_SHA256",
        "STD_WASM_SHA256",
    ] {
        let hash = arg(&dockerfile, name);
        assert!(
            hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "{name}"
        );
    }
    assert!(
        dockerfile.contains("sha256sum -c"),
        "the tarballs are checked"
    );
    assert!(
        dockerfile.contains("RUN --network=none cargo build --frozen"),
        "oncl-pack builds without the network"
    );
}
