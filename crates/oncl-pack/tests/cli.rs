//! `oncl-pack source` and `oncl-pack check` as the binary runs them.

use std::fs;
use std::process::{Command, Output};

fn oncl_pack(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oncl-pack"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn source_writes_an_archive_check_accepts_and_a_changed_byte_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sources = dir.path().join("sources");
    fs::create_dir_all(sources.join("crates/p")).unwrap();
    fs::write(sources.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(sources.join("crates/p/plugin.toml"), "id = \"x\"\n").unwrap();
    let archive = dir.path().join("p.src.tar.gz");
    let made = oncl_pack(&[
        "source".as_ref(),
        "--dir".as_ref(),
        sources.as_os_str(),
        "--out".as_ref(),
        archive.as_os_str(),
    ]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let bytes = fs::read(&archive).unwrap();
    let sha256 = oncl_pack::sha256_hex(&bytes);
    assert!(String::from_utf8_lossy(&made.stdout).starts_with(&format!("{sha256}  ")));

    let checked = oncl_pack(&["check".as_ref(), archive.as_os_str()]);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(
        String::from_utf8_lossy(&checked.stdout)
            .starts_with(&format!("{sha256}  {}  ", bytes.len()))
    );

    let mut changed = bytes;
    changed[4] ^= 1;
    fs::write(&archive, &changed).unwrap();
    let refused = oncl_pack(&["check".as_ref(), archive.as_os_str()]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("not canonical"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

#[test]
fn source_takes_a_directory_or_a_git_revision() {
    for args in [
        &["source", "--out", "x"][..],
        &[
            "source", "--dir", "a", "--git", "b", "--rev", "c", "--out", "x",
        ],
        &["source", "--git", "b", "--out", "x"],
    ] {
        let args: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_ref()).collect();
        let output = oncl_pack(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
}
