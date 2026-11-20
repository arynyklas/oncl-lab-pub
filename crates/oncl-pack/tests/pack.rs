//! The checks of a plugin package and of the crate a reference build is asked for, before
//! anything is built.

use std::fs;
use std::path::Path;

use oncl_pack::builder;
use oncl_pack::source::{File, Tree};

fn error_text(result: anyhow::Result<impl std::fmt::Debug>) -> String {
    format!("{:#}", result.unwrap_err())
}

#[test]
fn min_core_must_cover_the_imports() {
    let manifest = |min_core: &str| {
        oncl_plugin::Manifest::from_toml(&oncl_testkit::plugin::example_manifest().replace(
            "min_core = \"0.1.0-alpha.3\"",
            &format!("min_core = \"{min_core}\""),
        ))
        .unwrap()
    };
    let wasm = fs::read(oncl_testkit::plugin::example_wasm()).unwrap();
    let compiled = oncl_plugin::Engine::new()
        .compile(&manifest("0.1.0-alpha.3"), &wasm)
        .unwrap();
    assert!(!compiled.imports().is_empty());
    let check = oncl_pack::pack::check_min_core;
    check(&manifest("0.1.0-alpha.3"), compiled.imports()).unwrap();
    check(&manifest("1.0.0"), compiled.imports()).unwrap();
    let error = error_text(check(&manifest("0.1.0-alpha.2"), compiled.imports()));
    assert!(
        error.contains("min_core 0.1.0-alpha.2 is below 0.1.0-alpha.3"),
        "{error}"
    );
    // A module importing nothing needs no particular core.
    check(&manifest("0.0.1"), &[]).unwrap();
}

/// An archive of a crate at `crates/p` with `extra` files, written to `dir/a.src.tar.gz`.
fn archive(dir: &Path, extra: &[&str]) -> std::path::PathBuf {
    let mut tree = Tree::new();
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/p/Cargo.toml",
        "crates/p/plugin.toml",
    ]
    .iter()
    .chain(extra)
    {
        tree.insert(
            path,
            File {
                executable: false,
                data: format!("# {path}\n").into_bytes(),
            },
        )
        .unwrap();
    }
    let path = dir.join("a.src.tar.gz");
    fs::write(&path, tree.to_archive().unwrap()).unwrap();
    path
}

#[test]
fn prepare_unpacks_a_canonical_archive_into_a_fresh_work_directory() {
    let dir = tempfile::tempdir().unwrap();
    let source = archive(dir.path(), &["crates/p/src/lib.rs"]);
    let work = dir.path().join("work");
    let prepared = builder::prepare(&source, "crates/p", &work).unwrap();
    assert_eq!(
        prepared.crate_dir(),
        std::path::absolute(work.join("src/crates/p")).unwrap()
    );
    assert_eq!(
        fs::read_to_string(work.join("src/crates/p/src/lib.rs")).unwrap(),
        "# crates/p/src/lib.rs\n"
    );
    assert_eq!(
        prepared.archive_sha256,
        oncl_pack::sha256_hex(&fs::read(&source).unwrap())
    );
    let again = error_text(builder::prepare(&source, "crates/p", &work));
    assert!(
        again.contains("the work directory must be fresh"),
        "{again}"
    );
}

#[test]
fn prepare_refuses_a_crate_it_cannot_build_from_the_archive_alone() {
    let dir = tempfile::tempdir().unwrap();
    let cases: [(&[&str], &str, &str); 6] = [
        (
            &[],
            "crates/q",
            "the archive has no src/crates/q/Cargo.toml",
        ),
        (&[], "crates", "the archive has no src/crates/Cargo.toml"),
        (&[], "../p", "the crate path"),
        (
            &[".cargo/config.toml"],
            "crates/p",
            "src/.cargo/config.toml: a Cargo configuration",
        ),
        (
            &["crates/.cargo/config"],
            "crates/p",
            "src/crates/.cargo/config: a Cargo configuration",
        ),
        (
            &["crates/p/.cargo/config.toml"],
            "crates/p",
            "src/crates/p/.cargo/config.toml: a Cargo configuration",
        ),
    ];
    for (n, (extra, crate_path, expected)) in cases.into_iter().enumerate() {
        let case = dir.path().join(n.to_string());
        fs::create_dir(&case).unwrap();
        let source = archive(&case, extra);
        let error = error_text(builder::prepare(&source, crate_path, &case.join("work")));
        assert!(error.contains(expected), "{crate_path} {extra:?}: {error}");
        assert!(!case.join("work/src").exists(), "nothing unpacked");
    }
    // A `.cargo` directory elsewhere is not on the way to the crate.
    let case = dir.path().join("elsewhere");
    fs::create_dir(&case).unwrap();
    let source = archive(&case, &["other/.cargo/config.toml"]);
    builder::prepare(&source, "crates/p", &case.join("work")).unwrap();
}

#[test]
fn prepare_refuses_an_archive_that_is_not_canonical() {
    let dir = tempfile::tempdir().unwrap();
    let source = archive(dir.path(), &[]);
    let mut bytes = fs::read(&source).unwrap();
    bytes[4] = 1;
    fs::write(&source, &bytes).unwrap();
    let error = error_text(builder::prepare(
        &source,
        "crates/p",
        &dir.path().join("work"),
    ));
    assert!(error.contains("not canonical"), "{error}");
}

#[test]
fn verify_wants_a_sha256() {
    let dir = tempfile::tempdir().unwrap();
    let source = archive(dir.path(), &[]);
    let prepared = builder::prepare(&source, "crates/p", &dir.path().join("work")).unwrap();
    let error = error_text(builder::verify(&prepared, "abc", None));
    assert!(error.contains("is not a SHA-256"), "{error}");
}
