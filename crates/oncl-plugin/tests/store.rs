//! `<data>/plugins/`: installed packages checked against their sums, the state file
//! replaced when damaged, and the catalog kept and checked again against the TUF state.

mod common;

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
    store.install(&package, &bytes, Source::Catalog).unwrap();

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
        .install(&package, &bytes[..bytes.len() - 1], Source::Local)
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn tampered_package_is_not_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store.install(&package, &bytes, Source::Local).unwrap();
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
    store.install(&package, &bytes, Source::Catalog).unwrap();
    store.set_enabled(ID, false).unwrap();
    store.set_withdrawn(ID, true).unwrap();
    let installed = store.state().plugins[ID].clone();
    assert!(!installed.enabled && installed.withdrawn);
    // Installed again: still off, no longer withdrawn.
    store.install(&package, &bytes, Source::Catalog).unwrap();
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
    store.install(&package, &bytes, Source::Catalog).unwrap();
    let newer =
        example_package_with(|m| m.replacen("version = \"0.1.0\"", "version = \"0.2.0\"", 1));
    store
        .install(&Package::read(&newer).unwrap(), &newer, Source::Catalog)
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
