//! Each check of a release pull request on a minimal fixture that passes and on fixtures that
//! fail it, with synthetic keys.

use std::io::{Read as _, Write as _};

use oncl_pack::source::File;
use oncl_update::tuf::{SigningKey, build};
use serde_json::{Map, json};
use time::Duration;

use super::*;
use crate::publishers::parse_publisher;
use crate::vendor::keys;
use crate::vendor::mirror;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[60 + n; 32]).unwrap()
}

fn builder() -> String {
    format!("sha256:{}", "b".repeat(64))
}

fn publisher_toml(name: &str, n: u8) -> String {
    format!(
        "name = \"{name}\"\n\
         display = {{ ru = \"{name} ру\", kk = \"{name} қа\", en = \"{name} en\" }}\n\
         id_prefix = \"kz.{name}.\"\n\
         modules = [\"kz.{name}.Signer\"]\n\
         bundles = [\"kz.{name}.bundle\"]\n\
         github = [\"{name}-release\"]\n\
         binary_files = [\"src/fonts/big.ttf\"]\n\
         [[keys]]\n\
         public = \"{}\"\n",
        key(n).public().to_hex()
    )
}

fn publisher(name: &str, n: u8) -> Publisher {
    parse_publisher(&publisher_toml(name, n), name).unwrap()
}

fn builders() -> Builders {
    Builders::parse(&format!(
        "[[builder]]\ndigest = \"{}\"\ncommit = \"{}\"\nrust = \"1.99.1\"\nadded = 2026-11-19\n",
        builder(),
        "c".repeat(40)
    ))
    .unwrap()
}

fn delegations(publishers: &[&Publisher]) -> Delegations {
    let registry = Registry::new(publishers.iter().map(|p| (*p).clone()).collect()).unwrap();
    let signed = json!({
        "_type": "targets",
        "spec_version": "1.0.31",
        "version": 1,
        "expires": "2100-01-01T00:00:00Z",
        "targets": {},
        "delegations": registry.delegations(),
    });
    Targets::from_signed(&signed, Profile::Delegating)
        .unwrap()
        .delegations()
        .unwrap()
        .unwrap()
}

fn base(publishers: &[&Publisher]) -> Base {
    Base {
        registry: Registry::new(publishers.iter().map(|p| (*p).clone()).collect()).unwrap(),
        builders: builders(),
        delegations: Some(delegations(publishers)),
        indexes: Vec::new(),
        roles: BTreeMap::new(),
        builtin_modules: vec!["kz.gov.Builtin".to_owned()],
        allowed_git: vec!["https://github.com/arynyklas/slint".to_owned()],
    }
}

fn tp(path: &str) -> TargetPath {
    TargetPath::parse(path).unwrap()
}

/// The source of a package of the crate `crates/p`.
fn crate_tree() -> Tree {
    tree(&[
        ("LICENSE", b"MIT License\n"),
        (
            "Cargo.toml",
            b"[workspace]\nmembers = [\"crates/p\"]\n[workspace.package]\nlicense = \"MIT\"\n",
        ),
        (
            "Cargo.lock",
            b"version = 4\n\n[[package]]\nname = \"p\"\nversion = \"1.0.0\"\n\n\
              [[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
              source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
              [[package]]\nname = \"slint\"\nversion = \"1.0.0\"\n\
              source = \"git+https://github.com/arynyklas/slint?rev=x#0123456789abcdef0123456789abcdef01234567\"\n",
        ),
        (
            "crates/p/Cargo.toml",
            b"[package]\nname = \"p\"\nversion = \"1.0.0\"\nlicense.workspace = true\n\
              [dependencies]\nshared = { path = \"../shared\" }\n",
        ),
        ("crates/p/plugin.toml", manifest("kz.ecc.market", "1.0.0").as_bytes()),
        ("crates/p/src/lib.rs", b"// the plugin\n"),
        ("crates/shared/Cargo.toml", b"[package]\nname = \"shared\"\n"),
        ("fonts/small.ttf", &[0, 1, 2, 3]),
    ])
}

fn tree(files: &[(&str, &[u8])]) -> Tree {
    let mut tree = Tree::new();
    for (path, data) in files {
        tree.insert(
            path,
            File {
                executable: false,
                data: data.to_vec(),
            },
        )
        .unwrap();
    }
    tree
}

fn manifest(id: &str, version: &str) -> String {
    format!(
        "id = \"{id}\"\nversion = \"{version}\"\nmin_core = \"0.1.3\"\n\
         modules = [\"kz.ecc.Signer\"]\n\n\
         [name]\nru = \"Маркет\"\nkk = \"Маркет\"\nen = \"Market\"\n\n\
         [capabilities]\nkeys = true\n"
    )
}

/// A package of `manifest` and an empty module.
fn package(manifest: &str) -> Vec<u8> {
    oncl_plugin::archive(manifest.as_bytes(), b"\0asm\x01\0\0\0").unwrap()
}

/// A valid target of `ecc` for `package`, built from `archive`.
fn target(id: &str, version: &str, package: &[u8], archive: &[u8]) -> Value {
    let name = PublisherName::parse("ecc").unwrap();
    let sha256 = oncl_update::tuf::Digest::of(package);
    let url = mirror_url(
        &name,
        &oncl_update::catalog::PluginId::parse(id).unwrap(),
        &Version::parse(version).unwrap(),
        &sha256,
    );
    json!({
        "length": package.len(),
        "hashes": {"sha256": sha256.to_hex()},
        "custom": {"oncl": {
            "schema": 1,
            "id": id,
            "version": version,
            "url": url,
            "source": {
                "archive_sha256": oncl_pack::sha256_hex(archive),
                "archive_length": archive.len(),
                "fetch": "https://downloads.ecc.example/a.src.tar.gz",
                "path": "crates/p",
                "license": "MIT",
                "builder": builder(),
            },
            "channel": "stable",
            "min_core": "0.1.3",
            "modules": ["kz.ecc.Signer"],
            "name": {"ru": "Маркет", "kk": "Маркет", "en": "Market"},
            "capabilities": {"keys": true},
            "rollout": 100,
            "revoked": false,
        }},
    })
}

fn one(path: &str, target: Value) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(path.to_owned(), target);
    map
}

fn targets(map: &Map<String, Value>) -> Targets {
    let signed = keys::role_signed(
        &PublisherName::parse("ecc").unwrap(),
        1,
        now() + Duration::days(90),
        map,
    )
    .unwrap();
    Targets::from_signed(&signed, Profile::Legacy).unwrap()
}

const PATH: &str = "plugins/ecc/kz.ecc.market/1.0.0.onclp";

fn archive() -> Vec<u8> {
    crate_tree().to_archive().unwrap()
}

fn good() -> Map<String, Value> {
    one(
        PATH,
        target(
            "kz.ecc.market",
            "1.0.0",
            &package(&manifest("kz.ecc.market", "1.0.0")),
            &archive(),
        ),
    )
}

fn checks_of(findings: &[Finding]) -> Vec<u8> {
    let mut ids: Vec<u8> = findings.iter().map(|f| f.check).collect();
    ids.dedup();
    ids
}

fn change(kind: ChangeKind, mode: &str, path: &str) -> Change {
    Change {
        kind,
        old_mode: "000000".to_owned(),
        new_mode: mode.to_owned(),
        path: path.to_owned(),
    }
}

#[test]
fn check_1_takes_exactly_one_new_regular_role_file() {
    let layout = Layout::REPO;
    let path = "tuf/v1/metadata/3.pub-ecc.json";
    let role = role_path(&[change(ChangeKind::Added, "100644", path)], &layout).unwrap();
    assert_eq!((role.version, role.publisher.as_str()), (3, "ecc"));
    let refused: Vec<Vec<Change>> = vec![
        vec![],
        vec![
            change(ChangeKind::Added, "100644", path),
            change(
                ChangeKind::Modified,
                "100644",
                ".github/workflows/publisher-pr.yml",
            ),
        ],
        vec![change(ChangeKind::Modified, "100644", path)],
        vec![change(ChangeKind::Deleted, "000000", path)],
        vec![change(ChangeKind::Added, "100755", path)],
        vec![change(ChangeKind::Added, "120000", path)],
        vec![change(
            ChangeKind::Added,
            "100644",
            "tuf/v1/metadata/03.pub-ecc.json",
        )],
        vec![change(
            ChangeKind::Added,
            "100644",
            "tuf/v1/metadata/3.targets.json",
        )],
        vec![change(
            ChangeKind::Added,
            "100644",
            "tuf/v1/metadata/3.pub-openncalayer.json",
        )],
        vec![change(
            ChangeKind::Added,
            "100644",
            "tuf/v1/metadata/../3.pub-ecc.json",
        )],
        vec![change(
            ChangeKind::Added,
            "100644",
            "publishers/ecc/publisher.toml",
        )],
    ];
    for changes in refused {
        let findings = role_path(&changes, &layout).unwrap_err();
        assert_eq!(checks_of(&findings), [1], "{changes:?}");
    }
}

#[test]
fn check_1_wants_an_active_delegated_publisher_and_a_small_file() {
    let ecc = publisher("ecc", 0);
    let b = base(&[&ecc]);
    let role = RoleFile {
        path: "tuf/v1/metadata/1.pub-ecc.json".into(),
        version: 1,
        publisher: ecc.name.clone(),
    };
    assert!(role_admitted(&b, &role, 1000).is_empty());
    assert_eq!(checks_of(&role_admitted(&b, &role, MAX_ROLE_FILE + 1)), [1]);
    let mut retired = ecc.clone();
    retired.state = crate::publishers::State::Retired;
    let mut b2 = base(&[&ecc]);
    b2.registry = Registry::new(vec![retired]).unwrap();
    assert_eq!(checks_of(&role_admitted(&b2, &role, 10)), [1]);
    let mut b3 = base(&[&ecc]);
    b3.delegations = None;
    assert_eq!(checks_of(&role_admitted(&b3, &role, 10)), [1]);
}

#[test]
fn check_2_wants_an_author_of_the_publishers_github() {
    let ecc = publisher("ecc", 0);
    assert!(author_listed(&ecc, "ECC-Release").is_empty());
    assert_eq!(checks_of(&author_listed(&ecc, "mallory")), [2]);
}

#[test]
fn check_3_wants_the_next_version_exactly() {
    let role = |version| RoleFile {
        path: format!("tuf/v1/metadata/{version}.pub-ecc.json"),
        version,
        publisher: PublisherName::parse("ecc").unwrap(),
    };
    assert!(next_version(None, &role(1)).is_empty());
    assert!(next_version(Some(4), &role(5)).is_empty());
    assert_eq!(checks_of(&next_version(Some(4), &role(7))), [3]);
    assert_eq!(checks_of(&next_version(Some(4), &role(4))), [3]);
    assert_eq!(checks_of(&next_version(None, &role(2))), [3]);
}

fn signed(map: &Map<String, Value>, version: u64, signer: &SigningKey) -> Vec<u8> {
    let value = keys::role_signed(
        &PublisherName::parse("ecc").unwrap(),
        version,
        now() + Duration::days(90),
        map,
    )
    .unwrap();
    build::sign(&value, &[signer]).unwrap()
}

#[test]
fn check_4_wants_the_delegated_keys_and_the_clients_reading() {
    let ecc = publisher("ecc", 0);
    let acme = publisher("acme", 1);
    let d = delegations(&[&ecc, &acme]);
    let role = RoleFile {
        path: "tuf/v1/metadata/1.pub-ecc.json".into(),
        version: 1,
        publisher: ecc.name.clone(),
    };
    signed_role(&signed(&good(), 1, &key(0)), &role, Some(&d)).unwrap();
    // Another publisher's key, a key of no one.
    for other in [key(1), key(9)] {
        let err = signed_role(&signed(&good(), 1, &other), &role, Some(&d)).unwrap_err();
        assert_eq!(checks_of(&err), [4]);
    }
    // A key twice: the client's strict parser refuses the file.
    let bytes = signed(&good(), 1, &key(0));
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.contains("\"_type\":\"targets\""), "{text}");
    let twice = text.replacen(
        "\"_type\":\"targets\"",
        "\"_type\":\"targets\",\"_type\":\"targets\"",
        1,
    );
    assert_eq!(
        checks_of(&signed_role(twice.as_bytes(), &role, Some(&d)).unwrap_err()),
        [4]
    );
    // Delegations inside a role; a target outside its paths.
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["signed"]["delegations"] = json!({"keys": {}, "roles": []});
    let nested = build::sign(&value["signed"], &[&key(0)]).unwrap();
    assert_eq!(
        checks_of(&signed_role(&nested, &role, Some(&d)).unwrap_err()),
        [4]
    );
    let mut outside = good();
    let t = outside.remove(PATH).unwrap();
    outside.insert("plugins/acme/kz.ecc.market/1.0.0.onclp".into(), t);
    let signed_value = json!({
        "_type": "targets", "spec_version": "1.0.31", "version": 1,
        "expires": "2026-12-20T00:00:00Z", "targets": outside,
    });
    let outside = build::sign(&signed_value, &[&key(0)]).unwrap();
    assert_eq!(
        checks_of(&signed_role(&outside, &role, Some(&d)).unwrap_err()),
        [4]
    );
    // The version inside is not the name's: check 3.
    let mismatch = signed(&good(), 2, &key(0));
    assert_eq!(
        checks_of(&signed_role(&mismatch, &role, Some(&d)).unwrap_err()),
        [3]
    );
}

#[test]
fn check_5_wants_14_to_180_days() {
    assert!(expiry(now() + Duration::days(90), now()).is_empty());
    assert!(expiry(now() + Duration::days(14), now()).is_empty());
    assert_eq!(checks_of(&expiry(now() + Duration::days(13), now())), [5]);
    assert_eq!(checks_of(&expiry(now() + Duration::days(181), now())), [5]);
}

fn entries_of(map: &Map<String, Value>) -> Entries {
    let new: BTreeSet<TargetPath> = map.keys().map(|p| tp(p)).collect();
    entries(
        &publisher("ecc", 0),
        &targets(map),
        &new,
        &builders(),
        &["kz.gov.Builtin".to_owned()],
    )
}

fn edited(edit: impl FnOnce(&mut Value)) -> Map<String, Value> {
    let mut map = good();
    edit(map.get_mut(PATH).unwrap());
    map
}

#[test]
fn check_6_reads_each_entry_as_the_client_and_more_strictly() {
    let found = entries_of(&good());
    assert!(found.findings.is_empty(), "{:?}", found.findings);
    assert_eq!(found.releases.len(), 1);
    let refused: Vec<(&str, Map<String, Value>)> = vec![
        (
            "an unknown member",
            edited(|t| t["custom"]["oncl"]["extra"] = json!(1)),
        ),
        (
            "another publisher's module",
            edited(|t| t["custom"]["oncl"]["modules"] = json!(["kz.acme.Signer"])),
        ),
        (
            "no module",
            edited(|t| t["custom"]["oncl"]["modules"] = json!([])),
        ),
        (
            "an old core",
            edited(|t| t["custom"]["oncl"]["min_core"] = json!("0.1.2")),
        ),
        (
            "a bundle not its own",
            edited(|t| {
                t["custom"]["oncl"]["replaces"] = json!({"symname": "kz.other", "version": "1"})
            }),
        ),
        (
            "built-in capabilities",
            edited(|t| t["custom"]["oncl"]["capabilities"] = json!({"builtin": true})),
        ),
        (
            "unreadable capabilities",
            edited(|t| t["custom"]["oncl"]["capabilities"] = json!({"http": ["ftp://x/"]})),
        ),
        (
            "no capabilities",
            edited(|t| {
                t["custom"]["oncl"]
                    .as_object_mut()
                    .unwrap()
                    .remove("capabilities");
            }),
        ),
        (
            "a stable pre-release",
            edited(|t| t["custom"]["oncl"]["version"] = json!("1.0.0-rc.1")),
        ),
        (
            "a rollout over 100",
            edited(|t| t["custom"]["oncl"]["rollout"] = json!(101)),
        ),
        (
            "no custom.oncl",
            edited(|t| {
                t.as_object_mut().unwrap().remove("custom");
            }),
        ),
        (
            "a schema not 1",
            edited(|t| t["custom"]["oncl"]["schema"] = json!(2)),
        ),
    ];
    for (what, map) in refused {
        let found = entries_of(&map);
        assert!(
            checks_of(&found.findings).contains(&6),
            "{what}: {:?}",
            found.findings
        );
    }
    // A version with build metadata in the path.
    let mut plus = Map::new();
    let pkg = package(&manifest("kz.ecc.market", "1.0.0"));
    plus.insert(
        "plugins/ecc/kz.ecc.market/1.0.0+b1.onclp".into(),
        target("kz.ecc.market", "1.0.0+b1", &pkg, &archive()),
    );
    assert_eq!(checks_of(&entries_of(&plus).findings), [6]);
    // Nine new packages.
    let mut nine = Map::new();
    for n in 0..9 {
        let version = format!("1.0.{n}");
        let pkg = package(&manifest("kz.ecc.market", &version));
        nine.insert(
            format!("plugins/ecc/kz.ecc.market/{version}.onclp"),
            target("kz.ecc.market", &version, &pkg, &archive()),
        );
    }
    let found = entries_of(&nine);
    assert_eq!(checks_of(&found.findings), [6], "{:?}", found.findings);
}

#[test]
fn check_12_wants_the_source_table_a_listed_builder_and_an_osi_licence() {
    let path = tp(PATH);
    let source = |edit: &dyn Fn(&mut Value)| {
        let mut t = good()[PATH].clone();
        edit(&mut t);
        t["custom"]["oncl"]["source"].clone()
    };
    assert!(source_rules(Some(&source(&|_| {})), &builders(), &path).is_empty());
    let refused: Vec<(&str, Value)> = vec![
        ("no source", Value::Null),
        (
            "an unknown builder",
            source(&|t| {
                t["custom"]["oncl"]["source"]["builder"] =
                    json!(format!("sha256:{}", "e".repeat(64)))
            }),
        ),
        (
            "a licence not OSI",
            source(&|t| t["custom"]["oncl"]["source"]["license"] = json!("BUSL-1.1")),
        ),
        (
            "an unknown member",
            source(&|t| t["custom"]["oncl"]["source"]["extra"] = json!(1)),
        ),
        (
            "fetch over http",
            source(&|t| {
                t["custom"]["oncl"]["source"]["fetch"] = json!("http://downloads.ecc.example/a")
            }),
        ),
        (
            "a path with ..",
            source(&|t| t["custom"]["oncl"]["source"]["path"] = json!("../x")),
        ),
        (
            "a path with shell characters",
            source(&|t| t["custom"]["oncl"]["source"]["path"] = json!("crates/m;$(id)")),
        ),
        (
            "a path starting with -",
            source(&|t| t["custom"]["oncl"]["source"]["path"] = json!("-x")),
        ),
        (
            "an archive over 64 MiB",
            source(&|t| t["custom"]["oncl"]["source"]["archive_length"] = json!(65 << 20)),
        ),
        (
            "a bad vcs rev",
            source(&|t| {
                t["custom"]["oncl"]["source"]["vcs"] =
                    json!({"url": "https://git.example/x.git", "rev": "abc"})
            }),
        ),
    ];
    for (what, value) in refused {
        let found = source_rules(Some(&value).filter(|v| !v.is_null()), &builders(), &path);
        assert_eq!(checks_of(&found), [12], "{what}: {found:?}");
    }
    // Through `entries`, for a new target only.
    let bad = edited(|t| t["custom"]["oncl"]["source"]["license"] = json!("BUSL-1.1"));
    assert_eq!(checks_of(&entries_of(&bad).findings), [12]);
}

#[test]
fn check_23_wants_the_url_of_the_copy() {
    let other = format!(
        "{}pub-ecc-{}/kz.ecc.market-1.0.0.onclp",
        oncl_update::catalog::MIRROR_BASE,
        "0".repeat(64)
    );
    for url in [
        "https://downloads.ecc.example/kz.ecc.market-1.0.0.onclp".to_owned(),
        other,
    ] {
        let found = entries_of(&edited(|t| t["custom"]["oncl"]["url"] = json!(url)));
        assert_eq!(
            checks_of(&found.findings),
            [23],
            "{url}: {:?}",
            found.findings
        );
        // The client's other rules still ran: the entry is otherwise good.
        assert_eq!(found.releases.len(), 1);
    }
}

fn index_with(module: &str) -> Index {
    Index::from_json(
        json!({
            "schema": 1, "channel": "stable", "seq": 1,
            "generated": "2026-09-20T00:00:00Z", "expires": "2026-10-20T00:00:00Z",
            "core": [],
            "plugins": [{
                "id": "io.github.arynyklas.openncalayer.port.x",
                "version": "1.0.0",
                "url": "https://github.com/arynyklas/OpenNCALayer/releases/download/plugins-20260101/x.onclp",
                "sha256": "a".repeat(64),
                "size": 10,
                "min_core": "0.1.0",
                "modules": [module],
                "name": {"ru": "x", "kk": "x", "en": "x"},
                "rollout": 100,
            }],
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap()
}

#[test]
fn check_7_keeps_modules_and_bundles_unique_in_the_catalog() {
    let ecc = publisher("ecc", 0);
    let found = entries_of(&good());
    let mut b = base(&[&ecc]);
    b.indexes = vec![index_with("kz.other.Module")];
    assert!(catalog(&b, &ecc, &found.releases).is_empty());
    // A port serves the module (in another case).
    b.indexes = vec![index_with("KZ.ECC.SIGNER")];
    assert_eq!(checks_of(&catalog(&b, &ecc, &found.releases)), [7]);
    // ...unless the publisher supersedes the port.
    let mut superseding = ecc.clone();
    superseding.supersedes.insert(
        "io.github.arynyklas.openncalayer.port.x".into(),
        "kz.ecc.market".into(),
    );
    assert!(catalog(&b, &superseding, &found.releases).is_empty());
    // Another publisher's newest role claims it.
    let mut b = base(&[&ecc]);
    let mut theirs = good();
    let t = theirs.remove(PATH).unwrap();
    theirs.insert("plugins/acme/kz.acme.x/1.0.0.onclp".into(), t);
    let value = json!({
        "_type": "targets", "spec_version": "1.0.31", "version": 1,
        "expires": "2026-12-20T00:00:00Z", "targets": theirs,
    });
    b.roles.insert(
        PublisherName::parse("acme").unwrap(),
        RoleAt {
            version: 1,
            bytes: build::sign(&value, &[&key(1)]).unwrap(),
        },
    );
    assert_eq!(checks_of(&catalog(&b, &ecc, &found.releases)), [7]);
    // A revoked publisher keeps its prefix only: its role claims nothing any more.
    let revoked = parse_publisher(
        &publisher_toml("acme", 1).replace(
            "id_prefix",
            "state = \"revoked\"\nrevoked = \"2026-09-01\"\nid_prefix",
        ),
        "acme",
    )
    .unwrap();
    b.registry = Registry::new(vec![ecc.clone(), revoked]).unwrap();
    assert!(catalog(&b, &ecc, &found.releases).is_empty());
}

#[test]
fn checks_8_and_24_keep_what_was_released() {
    let ecc = publisher("ecc", 0);
    let before = targets(&edited(|t| t["custom"]["oncl"]["channel"] = json!("beta")));
    // What may change: rollout, name, revoked, beta to stable.
    let after = targets(&edited(|t| {
        t["custom"]["oncl"]["rollout"] = json!(10);
        t["custom"]["oncl"]["revoked"] = json!(true);
        t["custom"]["oncl"]["name"]["en"] = json!("Market 2");
    }));
    assert!(history(Some(&before), &after, &ecc).is_empty());
    assert!(history(None, &after, &ecc).is_empty());
    let stable = targets(&good());
    let cases: Vec<(&str, Targets, Targets, u8)> = vec![
        (
            "the length",
            before.clone(),
            targets(&edited(|t| t["length"] = json!(5))),
            8,
        ),
        (
            "the url",
            before.clone(),
            targets(&edited(|t| {
                t["custom"]["oncl"]["url"] = json!("https://x.example/a")
            })),
            8,
        ),
        (
            "the modules",
            before.clone(),
            targets(&edited(|t| {
                t["custom"]["oncl"]["modules"] = json!(["kz.ecc.Other"])
            })),
            8,
        ),
        (
            "the capabilities",
            before.clone(),
            targets(&edited(|t| {
                t["custom"]["oncl"]["capabilities"] = json!({"keys": false})
            })),
            8,
        ),
        ("stable back to beta", stable.clone(), before.clone(), 8),
        (
            "the source",
            before.clone(),
            targets(&edited(|t| {
                t["custom"]["oncl"]["source"]["fetch"] = json!("https://elsewhere.example/a")
            })),
            24,
        ),
    ];
    for (what, old, new, check) in cases {
        let found = history(Some(&old), &new, &ecc);
        assert_eq!(checks_of(&found), [check], "{what}: {found:?}");
    }
}

#[test]
fn check_8_lets_a_version_go_only_for_a_newer_unrevoked_one() {
    let ecc = publisher("ecc", 0);
    let pkg2 = package(&manifest("kz.ecc.market", "1.1.0"));
    let newer = target("kz.ecc.market", "1.1.0", &pkg2, &archive());
    let both = {
        let mut m = good();
        m.insert(
            "plugins/ecc/kz.ecc.market/1.1.0.onclp".into(),
            newer.clone(),
        );
        targets(&m)
    };
    let only_newer = targets(&one("plugins/ecc/kz.ecc.market/1.1.0.onclp", newer.clone()));
    assert!(history(Some(&both), &only_newer, &ecc).is_empty());
    // Nothing newer stays.
    let empty = targets(&Map::new());
    assert_eq!(checks_of(&history(Some(&both), &empty, &ecc)), [8]);
    // The newer one is beta only, the old one stable.
    let mut beta = newer.clone();
    beta["custom"]["oncl"]["channel"] = json!("beta");
    let only_beta = targets(&one("plugins/ecc/kz.ecc.market/1.1.0.onclp", beta));
    assert_eq!(checks_of(&history(Some(&both), &only_beta, &ecc)), [8]);
    // The old one is revoked by the publisher, or by the owner.
    let revoked = {
        let mut m = edited(|t| t["custom"]["oncl"]["revoked"] = json!(true));
        m.insert(
            "plugins/ecc/kz.ecc.market/1.1.0.onclp".into(),
            newer.clone(),
        );
        targets(&m)
    };
    assert_eq!(checks_of(&history(Some(&revoked), &only_newer, &ecc)), [8]);
    let mut owner = ecc.clone();
    owner
        .revoked_versions
        .push(crate::publishers::RevokedVersion {
            id: "kz.ecc.market".into(),
            version: Version::new(1, 0, 0),
            date: "2026-09-01".into(),
        });
    assert_eq!(checks_of(&history(Some(&both), &only_newer, &owner)), [8]);
}

#[test]
fn check_9_wants_an_hour_since_the_last_release() {
    assert!(frequency(None, now()).is_empty());
    assert!(frequency(Some(now() - Duration::minutes(61)), now()).is_empty());
    assert_eq!(
        checks_of(&frequency(Some(now() - Duration::minutes(59)), now())),
        [9]
    );
}

fn source() -> ReleaseSource {
    ReleaseSource::parse(Some(&good()[PATH]["custom"]["oncl"]["source"])).unwrap()
}

#[test]
fn check_13_wants_the_signed_length_and_sha256() {
    let path = tp(PATH);
    assert!(download(&archive(), &source(), &path).is_empty());
    let mut other = archive();
    other[10] ^= 1;
    assert_eq!(checks_of(&download(&other, &source(), &path)), [13]);
    assert_eq!(
        checks_of(&download(&archive()[1..], &source(), &path)),
        [13]
    );
}

#[test]
fn check_14_wants_the_canonical_archive() {
    let path = tp(PATH);
    canonical(&archive(), &path).unwrap();
    // The same tar, compressed by another gzip: not what `oncl-pack source` writes.
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(archive().as_slice())
        .read_to_end(&mut tar)
        .unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    let other = gz.finish().unwrap();
    assert_eq!(canonical(&other, &path).unwrap_err().check, 14);
    assert_eq!(canonical(b"not a gzip", &path).unwrap_err().check, 14);
}

fn without(tree: &Tree, path: &str) -> Tree {
    let mut out = Tree::new();
    for (p, f) in tree.files().filter(|(p, _)| *p != path) {
        out.insert(p, f.clone()).unwrap();
    }
    out
}

fn with(tree: &Tree, path: &str, data: &[u8]) -> Tree {
    let mut out = without(tree, path);
    out.insert(
        path,
        File {
            executable: false,
            data: data.to_vec(),
        },
    )
    .unwrap();
    out
}

#[test]
fn check_15_wants_the_crate_its_lock_file_and_licence() {
    let path = tp(PATH);
    let t = crate_tree();
    assert!(crate_files(&t, &source(), &path).is_empty());
    for (what, broken) in [
        ("no plugin.toml", without(&t, "crates/p/plugin.toml")),
        ("no Cargo.lock", without(&t, "Cargo.lock")),
        ("no licence file", without(&t, "LICENSE")),
        (
            "another licence",
            with(
                &t,
                "crates/p/Cargo.toml",
                b"[package]\nname = \"p\"\nlicense = \"Apache-2.0\"\n",
            ),
        ),
    ] {
        assert_eq!(
            checks_of(&crate_files(&broken, &source(), &path)),
            [15],
            "{what}"
        );
    }
}

#[test]
fn check_16_refuses_cargo_configuration_on_the_way_to_the_crate() {
    let path = tp(PATH);
    let t = crate_tree();
    assert!(cargo_config(&t, "crates/p", &path).is_empty());
    for config in [
        ".cargo/config.toml",
        "crates/.cargo/config",
        "crates/p/.cargo/config.toml",
    ] {
        let broken = with(&t, config, b"[source.crates-io]\nreplace-with = \"x\"\n");
        assert_eq!(
            checks_of(&cargo_config(&broken, "crates/p", &path)),
            [16],
            "{config}"
        );
    }
    // Elsewhere it is not read.
    let elsewhere = with(&t, "tools/.cargo/config.toml", b"");
    assert!(cargo_config(&elsewhere, "crates/p", &path).is_empty());
}

#[test]
fn check_17_wants_crates_io_and_listed_git_with_a_commit_and_paths_inside() {
    let path = tp(PATH);
    let allowed = vec!["https://github.com/arynyklas/slint".to_owned()];
    let t = crate_tree();
    assert!(lock_sources(&t, &allowed, &path).is_empty());
    let lock = |source: &str| {
        format!(
            "version = 4\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nsource = \"{source}\"\n"
        )
    };
    for source in [
        "git+https://github.com/evil/slint#0123456789abcdef0123456789abcdef01234567",
        "git+https://github.com/arynyklas/slint?branch=main",
        "registry+https://my-registry.example/index",
        "sparse+https://my-registry.example/",
    ] {
        let broken = with(&t, "Cargo.lock", lock(source).as_bytes());
        assert_eq!(
            checks_of(&lock_sources(&broken, &allowed, &path)),
            [17],
            "{source}"
        );
        // A clean lock beside the crate does not hide a bad one elsewhere: every lock counts.
        let beside = with(&broken, "crates/p/Cargo.lock", b"version = 4\n");
        assert_eq!(checks_of(&lock_sources(&beside, &allowed, &path)), [17]);
    }
    let own = lock(
        "git+https://github.com/arynyklas/OpenNCALayer?rev=a#0123456789abcdef0123456789abcdef01234567",
    );
    assert!(lock_sources(&with(&t, "Cargo.lock", own.as_bytes()), &allowed, &path).is_empty());
    let outside = with(
        &t,
        "crates/p/Cargo.toml",
        b"[package]\nname = \"p\"\nlicense = \"MIT\"\n[dependencies]\nx = { path = \"../../../outside\" }\n",
    );
    assert_eq!(checks_of(&lock_sources(&outside, &allowed, &path)), [17]);
    let unreadable = with(&t, "crates/q/Cargo.toml", b"[package\n");
    assert_eq!(checks_of(&lock_sources(&unreadable, &allowed, &path)), [17]);
}

#[test]
fn check_18_refuses_built_code_and_unlisted_large_binaries() {
    let path = tp(PATH);
    let ecc = publisher("ecc", 0);
    let t = crate_tree();
    assert!(binaries(&t, &ecc.binary_files, &path).is_empty());
    let big = vec![0u8; MAX_PLAIN_BINARY + 1];
    assert!(binaries(&with(&t, "fonts/big.ttf", &big), &ecc.binary_files, &path).is_empty());
    let mut pe = vec![0u8; 0x80];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c] = 0x40;
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    for (file, data) in [
        ("fonts/other.ttf", big.clone()),
        ("prebuilt/plugin.wasm", b"\0asm\x01\0\0\0".to_vec()),
        ("prebuilt/tool", b"\x7fELF\x02\x01".to_vec()),
        ("prebuilt/tool.exe", pe),
        ("prebuilt/lib.a", b"!<arch>\nx".to_vec()),
        ("prebuilt/x.zip", b"PK\x03\x04".to_vec()),
        ("prebuilt/x.gz", b"\x1f\x8b\x08".to_vec()),
        ("prebuilt/kz.ecc.market-1.0.0.onclp", b"text".to_vec()),
    ] {
        let broken = with(&t, file, &data);
        assert_eq!(
            checks_of(&binaries(&broken, &ecc.binary_files, &path)),
            [18],
            "{file}"
        );
    }
}

#[test]
fn checks_21_and_22_compare_the_rebuilt_package_with_the_entry_and_the_sources() {
    let path = tp(PATH);
    let found = entries_of(&good());
    let release = &found.releases[&path];
    let t = targets(&good());
    let target = &t.targets[&path];
    let pkg = package(&manifest("kz.ecc.market", "1.0.0"));
    let tree = crate_tree();
    assert!(mirror::rebuilt_bytes(&pkg, target, &path).is_empty());
    assert!(mirror::rebuilt_package(&pkg, release, &tree, "crates/p", &path).is_empty());
    // Other bytes: 21.
    let other = package(&format!(
        "{}# rebuilt\n",
        manifest("kz.ecc.market", "1.0.0")
    ));
    assert_eq!(
        checks_of(&mirror::rebuilt_bytes(&other, target, &path)),
        [21]
    );
    // A manifest with more capabilities than the entry, or not the archive's: 22.
    let more = package(
        &manifest("kz.ecc.market", "1.0.0").replace("keys = true", "keys = true\ndialogs = true"),
    );
    assert_eq!(
        checks_of(&mirror::rebuilt_package(
            &more, release, &tree, "crates/p", &path
        )),
        [22]
    );
    assert_eq!(
        checks_of(&mirror::rebuilt_package(
            &other, release, &tree, "crates/p", &path
        )),
        [22]
    );
    let moved = package(&manifest("kz.ecc.other", "1.0.0"));
    assert_eq!(
        checks_of(&mirror::rebuilt_package(
            &moved, release, &tree, "crates/p", &path
        )),
        [22]
    );
    assert_eq!(
        checks_of(&mirror::rebuilt_package(
            b"not a zip",
            release,
            &tree,
            "crates/p",
            &path
        )),
        [22]
    );
}
