//! `<data>/plugins/`: installed packages checked against their sums, the state file
//! replaced when damaged, and the catalog kept and checked again against the TUF state.

use oncl_plugin::{Package, Source, Store, StoreError};
use oncl_testkit::plugin::{example_package, example_package_with};
use oncl_update::tuf::testing::Repo;
use oncl_update::tuf::{FileStore, MemoryFetcher, TufClient};
use oncl_update::{Channel, Index, Version};
use time::{Duration, OffsetDateTime};

const ID: &str = "io.github.arynyklas.openncalayer.example";

fn example() -> (Package, Vec<u8>) {
    let bytes = example_package();
    (Package::read(&bytes).unwrap(), bytes)
}

fn package_file(dir: &std::path::Path, version: &str) -> std::path::PathBuf {
    dir.join("plugins/packages")
        .join(format!("{ID}-{version}.onclp"))
}

#[test]
fn install_then_load_package() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store
        .install(&package, &bytes, Source::Catalog, None)
        .unwrap();

    let state = store.state();
    let installed = &state.plugins[ID];
    assert_eq!(installed.version, package.manifest.version);
    assert_eq!(installed.sha256.0, package.sha256);
    assert_eq!(installed.source, Source::Catalog);
    assert!(installed.enabled && !installed.withdrawn);
    assert!(package_file(dir.path(), "0.1.0").is_file());

    let loaded = store.load_package(ID).unwrap();
    assert_eq!(loaded.manifest, package.manifest);
    assert_eq!(loaded.sha256, package.sha256);
    // The state is on disk: another store reads it.
    let again = Store::open(dir.path()).unwrap();
    assert_eq!(again.state(), state);
    assert!(again.load_package(ID).is_ok());
    assert!(matches!(
        again.load_package("kz.example.none"),
        Err(StoreError::NotInstalled(_))
    ));
    // Bytes that are not the package's file are refused.
    let err = store
        .install(&package, &bytes[..bytes.len() - 1], Source::Local, None)
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn tampered_package_is_not_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store
        .install(&package, &bytes, Source::Local, None)
        .unwrap();
    let file = package_file(dir.path(), "0.1.0");
    let mut changed = std::fs::read(&file).unwrap();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    std::fs::write(&file, &changed).unwrap();
    assert!(matches!(store.load_package(ID), Err(StoreError::Tampered)));
    std::fs::remove_file(&file).unwrap();
    assert!(matches!(store.load_package(ID), Err(StoreError::Io(_))));
}

#[test]
fn corrupt_state_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let first = Store::open(dir.path()).unwrap().state();
    // A fresh state is saved at once: its install id is kept.
    assert_eq!(Store::open(dir.path()).unwrap().state(), first);
    let path = dir.path().join("plugins/state.json");
    std::fs::write(&path, b"{not json").unwrap();
    let store = Store::open(dir.path()).unwrap();
    assert!(store.state().plugins.is_empty());
    assert_ne!(store.state().install_id, first.install_id);
    // Replaced on disk.
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved["install_id"].as_str().unwrap().len(), 32);
    // A state that cannot be read for another reason is an error: a directory in its place.
    let other = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(other.path().join("plugins/state.json")).unwrap();
    assert!(Store::open(other.path()).is_err());
}

#[test]
fn remove_deletes_package() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store
        .install(&package, &bytes, Source::Catalog, None)
        .unwrap();
    store.set_enabled(ID, false).unwrap();
    store.set_withdrawn(ID, true).unwrap();
    let installed = store.state().plugins[ID].clone();
    assert!(!installed.enabled && installed.withdrawn);
    // Installed again: still off, no longer withdrawn.
    store
        .install(&package, &bytes, Source::Catalog, None)
        .unwrap();
    let installed = store.state().plugins[ID].clone();
    assert!(!installed.enabled && !installed.withdrawn);

    store.remove(ID).unwrap();
    assert!(!store.state().plugins.contains_key(ID));
    assert!(!package_file(dir.path(), "0.1.0").exists());
    assert_eq!(
        store.remove(ID).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        store.set_enabled(ID, true).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    store.mark_bad(ID, &Version::new(0, 1, 0)).unwrap();
    assert!(store.state().bad[ID].contains(&Version::new(0, 1, 0)));
}

#[test]
fn an_update_replaces_the_old_package_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store
        .install(&package, &bytes, Source::Catalog, None)
        .unwrap();
    let newer =
        example_package_with(|m| m.replacen("version = \"0.1.0\"", "version = \"0.2.0\"", 1));
    store
        .install(
            &Package::read(&newer).unwrap(),
            &newer,
            Source::Catalog,
            None,
        )
        .unwrap();
    assert_eq!(store.state().plugins[ID].version, Version::new(0, 2, 0));
    assert!(!package_file(dir.path(), "0.1.0").exists());
    assert!(package_file(dir.path(), "0.2.0").is_file());
    assert_eq!(
        store.load_package(ID).unwrap().manifest.version,
        Version::new(0, 2, 0)
    );
}

/// An empty index of the beta channel, `seq`, made at `generated`.
fn index(seq: u64, generated: OffsetDateTime) -> Vec<u8> {
    serde_json::to_vec(&Index {
        schema: 1,
        channel: Channel::Beta,
        seq,
        generated,
        expires: generated + Duration::days(7),
        core: Vec::new(),
        extension: None,
        plugins: Vec::new(),
    })
    .unwrap()
}

type Client = TufClient<MemoryFetcher, FileStore>;

/// A client of `repo` with the TUF state in `tuf_dir` (the one a refresh and the store's
/// checks share).
fn client(repo: &Repo, tuf_dir: &std::path::Path) -> Client {
    repo.client(repo.fetcher(), FileStore::in_data_dir(tuf_dir))
}

/// The beta index as the TUF client downloads it from `repo`.
fn downloaded(client: &mut Client, now: OffsetDateTime) -> Vec<u8> {
    let trusted = client.refresh(now).unwrap();
    client
        .download_target(&trusted, &Channel::Beta.target_path(), 1 << 20, now)
        .unwrap()
}

/// What the store asks to vouch for the kept bytes: the TUF client, offline.
fn check(
    client: &Client,
    now: OffsetDateTime,
) -> impl FnOnce(&[u8]) -> Result<OffsetDateTime, String> + '_ {
    move |bytes| {
        client
            .verify_cached_target(&Channel::Beta.target_path(), bytes, now)
            .map_err(|e| e.to_string())
    }
}

#[test]
fn catalog_roundtrip_is_checked_against_the_saved_targets_and_expires_with_them() {
    let dir = tempfile::tempdir().unwrap();
    let tuf = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let mut repo = Repo::new();
    let now = repo.signed_at;
    repo.publish(Channel::Beta, &index(5, now - Duration::hours(1)));
    let mut client = client(&repo, tuf.path());
    assert!(
        store
            .load_catalog(Channel::Beta, check(&client, now))
            .is_none()
    );

    let bytes = downloaded(&mut client, now);
    store.save_catalog(Channel::Beta, &bytes).unwrap();
    assert_eq!(store.state().last_seq[&Channel::Beta], 5);
    let kept = store
        .load_catalog(Channel::Beta, check(&client, now))
        .unwrap();
    assert_eq!(kept.index.seq, 5);
    // It holds as long as the targets that list it: 30 days.
    assert_eq!(kept.valid_until, now + Duration::days(30));
    assert!(
        store
            .load_catalog(Channel::Beta, check(&client, now + Duration::days(29)))
            .is_some()
    );
    assert!(
        store
            .load_catalog(Channel::Beta, check(&client, now + Duration::days(31)))
            .is_none(),
        "expired targets"
    );
    // Another channel has none kept.
    assert!(store.load_catalog(Channel::Stable, |_| Ok(now)).is_none());
}

#[test]
fn a_kept_index_that_no_longer_matches_the_verified_targets_is_not_used() {
    let dir = tempfile::tempdir().unwrap();
    let tuf = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let mut repo = Repo::new();
    let now = repo.signed_at;
    repo.publish(Channel::Beta, &index(5, now));
    let mut client = client(&repo, tuf.path());
    let bytes = downloaded(&mut client, now);
    store.save_catalog(Channel::Beta, &bytes).unwrap();
    assert!(
        store
            .load_catalog(Channel::Beta, check(&client, now))
            .is_some()
    );

    let path = dir.path().join("plugins/catalog/beta.json");
    // Altered on disk, however little (still a valid index).
    let altered = index(6, now);
    std::fs::write(&path, &altered).unwrap();
    assert!(
        store
            .load_catalog(Channel::Beta, check(&client, now))
            .is_none()
    );
    let mut padded = bytes.clone();
    padded.push(b' ');
    std::fs::write(&path, &padded).unwrap();
    assert!(
        store
            .load_catalog(Channel::Beta, check(&client, now))
            .is_none()
    );

    // The repository publishes a newer index and the client takes it: the old file, put
    // back, is not what the targets list any more, though it was once.
    std::fs::write(&path, &bytes).unwrap();
    repo.publish(Channel::Beta, &index(7, now));
    let mut newer = TufClient::new(
        repo.anchor(),
        repo.fetcher(),
        FileStore::in_data_dir(tuf.path()),
        oncl_update::tuf::Limits::default(),
    )
    .unwrap();
    let fresh = downloaded(&mut newer, now);
    assert!(
        store
            .load_catalog(Channel::Beta, check(&newer, now))
            .is_none()
    );
    store.save_catalog(Channel::Beta, &fresh).unwrap();
    assert_eq!(store.state().last_seq[&Channel::Beta], 7);
    assert_eq!(
        store
            .load_catalog(Channel::Beta, check(&newer, now))
            .unwrap()
            .index
            .seq,
        7
    );
}

#[test]
fn a_kept_index_is_still_held_to_its_channel_and_last_seq() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let now = OffsetDateTime::now_utc();
    store.save_catalog(Channel::Beta, &index(7, now)).unwrap();
    let valid = |_: &[u8]| Ok(now + Duration::days(1));
    assert_eq!(
        store.load_catalog(Channel::Beta, valid).unwrap().index.seq,
        7
    );
    // An older index put back (the check, here, vouches for anything) is a rollback.
    let path = dir.path().join("plugins/catalog/beta.json");
    std::fs::write(&path, index(6, now)).unwrap();
    assert!(store.load_catalog(Channel::Beta, valid).is_none());
    // An index of the other channel under this one's name.
    let mut other: serde_json::Value = serde_json::from_slice(&index(9, now)).unwrap();
    other["channel"] = "stable".into();
    std::fs::write(&path, serde_json::to_vec(&other).unwrap()).unwrap();
    assert!(store.load_catalog(Channel::Beta, valid).is_none());
    // The check says no.
    std::fs::write(&path, index(8, now)).unwrap();
    assert!(
        store
            .load_catalog(Channel::Beta, |_| Err("expired".into()))
            .is_none()
    );
    // What is not an index cannot be saved.
    assert_eq!(
        store
            .save_catalog(Channel::Beta, b"nope")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
}

fn ecc() -> oncl_update::tuf::PublisherName {
    oncl_update::tuf::PublisherName::parse("ecc").unwrap()
}

fn role(name: &str) -> oncl_update::tuf::RoleName {
    oncl_update::tuf::RoleName::parse(name).unwrap()
}

#[test]
fn installed_without_publisher_reads_as_none() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("plugins")).unwrap();
    std::fs::write(
        dir.path().join("plugins/state.json"),
        format!(
            r#"{{"install_id": "000102030405060708090a0b0c0d0e0f",
                "plugins": {{"{ID}": {{"version": "0.1.0", "sha256": "{}",
                "source": "catalog", "enabled": true}}}}}}"#,
            "00".repeat(32)
        ),
    )
    .unwrap();
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.state().plugins[ID].publisher, None);
}

#[test]
fn a_recorded_publisher_this_version_does_not_accept_is_dropped_not_the_state() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("plugins")).unwrap();
    let sum = "00".repeat(32);
    let installed = |publisher: &str| {
        format!(
            r#"{{"version": "0.1.0", "sha256": "{sum}", "source": "catalog", "enabled": true,
                "publisher": {publisher}}}"#
        )
    };
    std::fs::write(
        dir.path().join("plugins/state.json"),
        format!(
            r#"{{"install_id": "000102030405060708090a0b0c0d0e0f", "last_seq": {{"beta": 3}},
                "plugins": {{"kz.ecc.market": {}, "kz.reserved.tool": {}, "kz.odd.tool": {},
                "kz.null.tool": {}}},
                "bad": {{"kz.ecc.market": ["0.0.9"]}}}}"#,
            installed("\"ecc\""),
            installed("\"root\""),
            installed("7"),
            installed("null"),
        ),
    )
    .unwrap();
    let store = Store::open(dir.path()).unwrap();
    let state = store.state();
    assert_eq!(
        state.install_id,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    assert_eq!(state.last_seq[&Channel::Beta], 3);
    assert_eq!(state.bad["kz.ecc.market"].len(), 1);
    assert_eq!(state.plugins.len(), 4);
    assert_eq!(state.plugins["kz.ecc.market"].publisher, Some(ecc()));
    for id in ["kz.reserved.tool", "kz.odd.tool", "kz.null.tool"] {
        assert_eq!(state.plugins[id].publisher, None, "{id}");
        assert!(state.plugins[id].enabled, "{id}");
    }
}

#[test]
fn publisher_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store
        .install(&package, &bytes, Source::Catalog, Some(&ecc()))
        .unwrap();
    assert_eq!(store.state().plugins[ID].publisher, Some(ecc()));
    let text = std::fs::read_to_string(dir.path().join("plugins/state.json")).unwrap();
    assert!(text.contains("\"publisher\": \"ecc\""), "{text}");
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.state().plugins[ID].publisher, Some(ecc()));
    store.set_publisher(ID, None).unwrap();
    let text = std::fs::read_to_string(dir.path().join("plugins/state.json")).unwrap();
    assert!(!text.contains("publisher"), "{text}");
    store.set_publisher(ID, Some(ecc())).unwrap();
    assert_eq!(store.state().plugins[ID].publisher, Some(ecc()));
    // Installed again without a publisher (a file the user chose): none recorded.
    store
        .install(&package, &bytes, Source::Local, None)
        .unwrap();
    assert_eq!(store.state().plugins[ID].publisher, None);
    assert_eq!(
        store
            .set_publisher("kz.ecc.absent", Some(ecc()))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn state_of_0_1_1_reads_with_empty_declined() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("plugins")).unwrap();
    std::fs::write(
        dir.path().join("plugins/state.json"),
        r#"{"install_id": "000102030405060708090a0b0c0d0e0f", "last_seq": {"beta": 3},
            "plugins": {}, "bad": {}}"#,
    )
    .unwrap();
    let store = Store::open(dir.path()).unwrap();
    assert!(store.state().declined_replacements.is_empty());
    store
        .set_declined_replacement("a.port", Some("kz.ecc.market"))
        .unwrap();
    assert_eq!(
        store.state().declined_replacements["a.port"],
        "kz.ecc.market"
    );
    store.set_declined_replacement("a.port", None).unwrap();
    let text = std::fs::read_to_string(dir.path().join("plugins/state.json")).unwrap();
    assert!(!text.contains("declined_replacements"), "{text}");
}

/// A port replaced by a publisher's plugin (Р11): one save records the plugin, on or off as
/// the port was, and forgets the port, its settings, its package and its declined offer.
#[test]
fn a_port_is_replaced_by_a_publishers_plugin() {
    const MARKET: &str = "kz.acme.market";
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (port, port_bytes) = example();
    store
        .install(&port, &port_bytes, Source::Catalog, None)
        .unwrap();
    store.set_enabled(ID, false).unwrap();
    store.set_declined_replacement(ID, Some(MARKET)).unwrap();
    std::fs::create_dir_all(store.settings_dir()).unwrap();
    std::fs::write(store.settings_path(ID), b"{}").unwrap();
    let bytes = example_package_with(|m| m.replace(ID, MARKET));
    let market = Package::read(&bytes).unwrap();
    let acme = oncl_update::tuf::PublisherName::parse("acme").unwrap();

    // Not the package's file, the port itself, or no port: nothing changes.
    let short = &bytes[..bytes.len() - 1];
    let err = store.replace(ID, &market, short, Some(&acme)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    let err = store
        .replace(ID, &port, &port_bytes, Some(&acme))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    let err = store
        .replace("kz.none", &market, &bytes, Some(&acme))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(store.state().plugins.contains_key(ID));

    store.replace(ID, &market, &bytes, Some(&acme)).unwrap();
    let state = Store::open(dir.path()).unwrap().state();
    assert!(!state.plugins.contains_key(ID));
    assert!(state.declined_replacements.is_empty());
    let installed = &state.plugins[MARKET];
    assert_eq!(installed.source, Source::Catalog);
    assert_eq!(installed.publisher.as_ref(), Some(&acme));
    assert!(!installed.enabled && !installed.withdrawn);
    assert!(store.load_package(MARKET).is_ok());
    assert!(!package_file(dir.path(), "0.1.0").exists());
    assert!(!store.settings_path(ID).exists());
    // A replacement installed already is never installed again over another port.
    store
        .install(&port, &port_bytes, Source::Catalog, None)
        .unwrap();
    let err = store.replace(ID, &market, &bytes, Some(&acme)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(store.state().plugins.contains_key(ID));
}

/// The state cannot be saved: the port stays installed with its files, and the
/// replacement's package written for it is gone again.
#[test]
fn a_replacement_not_saved_leaves_the_port_as_it_was() {
    const MARKET: &str = "kz.acme.market";
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (port, port_bytes) = example();
    store
        .install(&port, &port_bytes, Source::Catalog, None)
        .unwrap();
    let bytes = example_package_with(|m| m.replace(ID, MARKET));
    let market = Package::read(&bytes).unwrap();
    // The state file is a directory now: no save succeeds.
    let state_file = dir.path().join("plugins/state.json");
    std::fs::remove_file(&state_file).unwrap();
    std::fs::create_dir(&state_file).unwrap();
    std::fs::write(state_file.join("keep"), b"x").unwrap();
    assert!(store.replace(ID, &market, &bytes, None).is_err());
    let state = store.state();
    assert!(state.plugins.contains_key(ID) && !state.plugins.contains_key(MARKET));
    assert!(package_file(dir.path(), "0.1.0").is_file());
    let market_file = dir
        .path()
        .join("plugins/packages/kz.acme.market-0.1.0.onclp");
    assert!(!market_file.exists());
}

/// Files a crash left behind (a port replaced, a plugin removed) go once they are older than
/// `PRUNE_AFTER`; the installed plugins' files, the built-in modules' settings and a fresh
/// orphan (another process may be installing it) stay.
#[test]
fn files_no_plugin_owns_are_pruned() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store
        .install(&package, &bytes, Source::Catalog, None)
        .unwrap();
    let long_ago = std::time::SystemTime::now() - Store::PRUNE_AFTER * 2;
    let old = |path: &std::path::Path| {
        std::fs::write(path, b"old").unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
    };
    let packages = dir.path().join("plugins/packages");
    let orphan = packages.join("kz.gone.port-1.0.0.onclp");
    old(&orphan);
    let fresh = packages.join("kz.new.plugin-1.0.0.onclp");
    std::fs::write(&fresh, b"new").unwrap();
    let unrelated = packages.join("notes.txt");
    old(&unrelated);
    std::fs::create_dir_all(store.settings_dir()).unwrap();
    old(&store.settings_path(ID));
    old(&store.settings_path("kz.gone.port"));
    let fresh_settings = store.settings_path("kz.new.plugin");
    std::fs::write(&fresh_settings, b"{}").unwrap();
    let builtin = store.settings_path("io.github.arynyklas.openncalayer.builtin.basics");
    old(&builtin);
    store.prune_files();
    assert!(!orphan.exists() && !store.settings_path("kz.gone.port").exists());
    assert!(
        fresh.is_file() && fresh_settings.is_file(),
        "a fresh file stays"
    );
    assert!(package_file(dir.path(), "0.1.0").is_file());
    assert!(store.settings_path(ID).is_file() && builtin.is_file() && unrelated.is_file());
}

#[test]
fn removing_a_port_forgets_its_declined_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store
        .install(&package, &bytes, Source::Catalog, None)
        .unwrap();
    store
        .set_declined_replacement(ID, Some("kz.acme.market"))
        .unwrap();
    store.remove(ID).unwrap();
    assert!(store.state().declined_replacements.is_empty());
}

/// The state as 0.1.1 reads it: its structs, frozen, without the fields of later versions.
mod v0_1_1 {
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(serde::Deserialize)]
    pub struct StoreState {
        pub install_id: String,
        #[serde(default)]
        pub last_seq: BTreeMap<String, u64>,
        #[serde(default)]
        pub plugins: BTreeMap<String, Installed>,
        #[serde(default)]
        pub bad: BTreeMap<String, BTreeSet<String>>,
    }

    #[derive(serde::Deserialize)]
    pub struct Installed {
        pub version: String,
        pub sha256: String,
        pub source: String,
        pub enabled: bool,
        #[serde(default)]
        pub withdrawn: bool,
    }
}

#[test]
fn a_state_with_publishers_still_reads_as_0_1_1_reads_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store
        .install(&package, &bytes, Source::Catalog, Some(&ecc()))
        .unwrap();
    store
        .set_declined_replacement(ID, Some("kz.ecc.market"))
        .unwrap();
    let text = std::fs::read(dir.path().join("plugins/state.json")).unwrap();
    let old: v0_1_1::StoreState = serde_json::from_slice(&text).unwrap();
    assert_eq!(old.install_id.len(), 32);
    assert!(old.last_seq.is_empty() && old.bad.is_empty());
    let installed = &old.plugins[ID];
    assert_eq!(installed.version, "0.1.0");
    assert_eq!(installed.sha256.len(), 64);
    assert_eq!(installed.source, "catalog");
    assert!(installed.enabled && !installed.withdrawn);
}

#[test]
fn kept_role_and_publishers_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let until = OffsetDateTime::now_utc() + Duration::days(1);
    assert!(store.load_publishers(|_| Ok(until)).is_none());
    assert!(store.load_role(&role("pub-ecc"), <[u8]>::to_vec).is_none());
    store.save_publishers(b"{\"publishers\":[]}").unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("plugins/catalog/publishers.json")).unwrap(),
        b"{\"publishers\":[]}"
    );
    assert_eq!(
        store.load_publishers(|bytes| {
            assert_eq!(bytes, b"{\"publishers\":[]}");
            Ok(until)
        }),
        Some((b"{\"publishers\":[]}".to_vec(), until))
    );
    // Bytes the TUF client no longer vouches for are not used.
    assert!(store.load_publishers(|_| Err("no".to_owned())).is_none());
    store.save_role(&role("pub-other"), b"other").unwrap();
    store.save_role(&role("pub-ecc"), b"ecc").unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("plugins/catalog/roles/pub-ecc.json")).unwrap(),
        b"ecc"
    );
    assert_eq!(
        store.load_role(&role("pub-ecc"), <[u8]>::to_vec),
        Some(b"ecc".to_vec())
    );
    assert_eq!(
        store.load_role(&role("pub-other"), <[u8]>::to_vec),
        Some(b"other".to_vec())
    );
    // Saved again: replaced.
    store.save_role(&role("pub-ecc"), b"ecc 2").unwrap();
    assert_eq!(
        store.load_role(&role("pub-ecc"), <[u8]>::to_vec),
        Some(b"ecc 2".to_vec())
    );
    // Longer than any role the client keeps: not read.
    store
        .save_role(&role("pub-big"), &vec![b' '; (128 << 10) + 1])
        .unwrap();
    assert!(store.load_role(&role("pub-big"), <[u8]>::to_vec).is_none());
}

#[test]
fn prune_roles_removes_only_undelegated() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    // Nothing kept yet: nothing to do.
    store
        .prune_roles(&std::collections::BTreeSet::new())
        .unwrap();
    store.save_role(&role("pub-ecc"), b"ecc").unwrap();
    store.save_role(&role("pub-gone"), b"gone").unwrap();
    let roles = dir.path().join("plugins/catalog/roles");
    std::fs::write(roles.join("targets.json"), b"x").unwrap();
    // A role being saved by another write right now.
    std::fs::write(roles.join("pub-gone.json.123-4.tmp"), b"gone").unwrap();
    store.save_publishers(b"{}").unwrap();
    store
        .prune_roles(&std::collections::BTreeSet::from([role("pub-ecc")]))
        .unwrap();
    assert!(store.load_role(&role("pub-ecc"), |_| ()).is_some());
    assert!(store.load_role(&role("pub-gone"), |_| ()).is_none());
    assert!(!roles.join("pub-gone.json").exists());
    assert!(!roles.join("targets.json").exists());
    // `publishers.json` is not a role's file.
    assert!(dir.path().join("plugins/catalog/publishers.json").is_file());
    assert!(roles.join("pub-gone.json.123-4.tmp").is_file());
}
