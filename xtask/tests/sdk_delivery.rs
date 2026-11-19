//! Guards of the SDK delivery evidence (docs/dev/sdk.md): no network, no builds, only
//! `cargo metadata` / `cargo tree` of the real workspace.
use std::collections::{BTreeSet, HashMap};

use xtask::licenses::{Package, PackagesMissing};
use xtask::sdk_delivery::{
    CHAIN, chain_problems, closure_report, inventory_is_current, licenses, pick_packages,
};

#[test]
fn publishable_crates_are_exactly_the_chain_in_dependency_order() {
    let problems = chain_problems(&oncl_testkit::workspace_root()).unwrap();
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(CHAIN.last(), Some(&"oncl-core"));
}

/// The value of `result`, or `None` (with a note) when the other platforms' packages are not
/// in the local cargo registry on a developer's machine; in CI (`CI` set, after `cargo fetch
/// --locked`) that fails, as does any other error. Like `licenses_fresh.rs`.
fn unless_packages_missing<T>(what: &str, result: anyhow::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(e) if e.is::<PackagesMissing>() && std::env::var_os("CI").is_none() => {
            eprintln!("{what} not checked (skipped): {e}");
            None
        }
        Err(e) => panic!("{e:#}"),
    }
}

#[test]
fn sdk_closures_contain_no_ui_desktop_updater_server_or_runtime_crate() {
    // `closure_report` fails naming the offending crates of any feature set.
    let Some(report) = unless_packages_missing(
        "the SDK closure report",
        closure_report(&oncl_testkit::workspace_root()),
    ) else {
        return;
    };
    assert!(report.contains("| minimal |"), "{report}");
    assert!(report.contains("| full |"), "{report}");
}

#[test]
fn committed_inventory_is_current_and_a_stale_copy_is_detected() {
    // A stale copy is detected, whatever the registry holds.
    let sample = "aes 0.9.0 MIT\nsha2 0.11.0 MIT OR Apache-2.0\n";
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("THIRD-PARTY.txt");
    std::fs::write(&copy, sample).unwrap();
    assert!(inventory_is_current(&copy, sample));
    std::fs::write(&copy, sample.replacen("aes ", "aes-stale ", 1)).unwrap();
    assert!(!inventory_is_current(&copy, sample));
    assert!(!inventory_is_current(
        &dir.path().join("absent.txt"),
        sample
    ));

    let root = oncl_testkit::workspace_root();
    let Some(expected) = unless_packages_missing("the SDK licence inventory", licenses(&root))
    else {
        return;
    };
    let committed = root.join(xtask::sdk_delivery::LICENSES_OUTPUT);
    assert!(
        inventory_is_current(&committed, &expected),
        "{} is stale: run `cargo xtask sdk licenses`",
        xtask::sdk_delivery::LICENSES_OUTPUT
    );
}

#[test]
fn a_closure_crate_missing_from_the_registry_is_an_error_naming_it() {
    let package = |name: &str| Package {
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        authors: vec![],
        license: Some("MIT".to_owned()),
        license_file: None,
        repository: None,
        dir: std::path::PathBuf::new(),
    };
    let key = |name: &str| (name.to_owned(), "1.0.0".to_owned());
    let wanted: BTreeSet<_> = [key("present"), key("gone"), key("oncl-core")].into();
    let packages: HashMap<_, _> = [(key("present"), package("present"))].into();
    let error = pick_packages(wanted.clone(), packages.clone()).unwrap_err();
    assert!(error.to_string().contains("gone 1.0.0"), "{error}");
    assert!(!error.to_string().contains("oncl-core"), "{error}");

    let mut complete = packages;
    complete.insert(key("gone"), package("gone"));
    assert_eq!(pick_packages(wanted, complete).unwrap().len(), 2);
}
