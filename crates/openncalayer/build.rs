//! Gives the program the git commit it is built from (`ONCL_GIT_COMMIT`, `unknown` outside
//! a git checkout, `dev` in a debug build), for the About window, embeds the built-in modules'
//! WebAssembly (`$OUT_DIR/builtins.rs`): taken from `ONCL_BUILTINS_DIR` if it is set, else
//! built, and on Windows embeds the application manifest ([`embed_manifest`]).

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    embed_manifest();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if let Err(e) = oncl_builtins_build::embed(&workspace) {
        panic!("the built-in modules: {e}");
    }
    // Only a release build says its commit: watching HEAD reruns this script, and so
    // recompiles the crate and relinks its tests, after every commit and checkout.
    if std::env::var("PROFILE").is_ok_and(|profile| profile == "release") {
        stamp_commit();
    } else {
        println!("cargo:rustc-env=ONCL_GIT_COMMIT=dev");
    }
}

/// `ONCL_GIT_COMMIT` from git, and the files a commit, checkout or reset changes to rerun on.
fn stamp_commit() {
    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=ONCL_GIT_COMMIT={commit}");
    // A commit, checkout or reset moves HEAD or the branch it names, and is written to
    // HEAD's reflog even when the branch's ref is packed.
    let mut watched = vec![
        "HEAD".to_owned(),
        "logs/HEAD".to_owned(),
        "packed-refs".to_owned(),
    ];
    watched.extend(git(&["symbolic-ref", "-q", "HEAD"]));
    for name in watched {
        if let Some(path) = git(&["rev-parse", "--git-path", &name])
            && Path::new(&path).exists()
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

/// The program stays a console program (shells wait for it and get its output and exit
/// code), and its manifest asks Windows 11 24H2 and later not to allocate a console when
/// nothing started it from one (`consoleAllocationPolicy` `detached`): the Start menu
/// shortcut, the autostart entry and Velopack's restart start it without a console window.
/// Older Windows ignore the setting. The MSVC linker writes the `RT_MANIFEST` resource
/// itself (`/MANIFEST:EMBED`) and adds the default `asInvoker` trust info.
fn embed_manifest() {
    let manifest = "windows/openncalayer.manifest";
    println!("cargo:rerun-if-changed={manifest}");
    let windows_msvc = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "msvc");
    if !windows_msvc {
        return;
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(manifest);
    let bin = "openncalayer";
    println!("cargo:rustc-link-arg-bin={bin}=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bin={bin}=/MANIFESTINPUT:{}",
        path.display()
    );
}

/// The trimmed output of `git <args>`, if it succeeds.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (out.status.success() && !text.is_empty()).then(|| text.to_owned())
}
