//! Gives xtask's integration-test executables the installer entry's application manifest
//! (the same file `oncl-winget-setup` embeds): `tests/winget_setup.rs` uses its own test
//! executable as a stand-in entry, and `package winget-setup` refuses an entry without an
//! `asInvoker` manifest (finding F1). Gives the `cargo xtask` executable the 8 MiB main
//! thread stack it has on Linux: Windows' default 1 MiB is not enough for the debug build of
//! clap's parser of all its subcommands.

use std::env;
use std::path::Path;

fn main() {
    let manifest = "../crates/oncl-winget-setup/windows/oncl-winget-setup.manifest";
    println!("cargo:rerun-if-changed={manifest}");
    println!("cargo:rerun-if-changed=build.rs");
    let windows_msvc = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows")
        && env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "msvc");
    if !windows_msvc {
        return;
    }
    let dir = env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let path = Path::new(&dir).join(manifest);
    println!("cargo:rustc-link-arg-bins=/STACK:8388608");
    println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-tests=/MANIFESTUAC:NO");
    println!(
        "cargo:rustc-link-arg-tests=/MANIFESTINPUT:{}",
        path.display()
    );
}
