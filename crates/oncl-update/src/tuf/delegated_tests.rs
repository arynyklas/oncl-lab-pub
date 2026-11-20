//! [`TufClient::delegated`] against repositories of the delegating profile made here: the
//! bounds the python-tuf vectors do not reach (the most roles followed, a threshold of two
//! keys met, a store that cannot be written, a rotation that forgets the roles' versions).

use serde_json::{Map, Value, json};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use super::build::{self, RoleDef, RootDef};
use super::layout;
use super::model::{Digest, SPEC_VERSION, format_expires};
use super::*;

const T0: OffsetDateTime = datetime!(2026-11-15 12:00 UTC);

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

fn one(key: &SigningKey) -> RoleDef {
    RoleDef {
        keys: vec![key.public()],
        threshold: 1,
    }
}

/// The keys of the top-level roles.
struct Top {
    root: SigningKey,
    timestamp: SigningKey,
    snapshot: SigningKey,
    targets: SigningKey,
}

fn top(base: u8) -> Top {
    Top {
        root: key(base),
        timestamp: key(base + 1),
        snapshot: key(base + 2),
        targets: key(base + 3),
    }
}

fn root_file(version: u64, k: &Top, signers: &[&SigningKey]) -> Vec<u8> {
    let def = RootDef {
        root: one(&k.root),
        timestamp: one(&k.timestamp),
        snapshot: one(&k.snapshot),
        targets: one(&k.targets),
    };
    build::sign(
        &build::root(version, T0 + Duration::days(365), &def).unwrap(),
        signers,
    )
    .unwrap()
}

/// A publisher: its name, the keys of its delegation and threshold, the keys that sign.
struct Publisher {
    name: String,
    keys: Vec<SigningKey>,
    threshold: u64,
    signers: Vec<SigningKey>,
    /// How many targets its role lists.
    targets: usize,
    /// The snapshot lists its role's file by version only.
    unhashed: bool,
}

fn publisher(name: &str, seed: u8) -> Publisher {
    Publisher {
        name: name.to_owned(),
        keys: vec![key(seed)],
        threshold: 1,
        signers: vec![key(seed)],
        targets: 1,
        unhashed: false,
    }
}

fn meta(version: u64, file: &[u8]) -> Value {
    json!({"version": version, "length": file.len(), "hashes": {"sha256": Digest::of(file).to_hex()}})
}

/// Publishes targets `version` delegating to `publishers` (each role version `version`),
/// with snapshot and timestamp, into `repo`.
fn publish(repo: &MemoryFetcher, k: &Top, version: u64, publishers: &[Publisher]) {
    let expires = format_expires(T0 + Duration::days(30)).unwrap();
    let mut keys = Map::new();
    let mut roles = Vec::new();
    let mut snapshot_meta = Map::new();
    for p in publishers {
        for key in &p.keys {
            keys.insert(key.public().key_id().to_hex(), key.public().to_value());
        }
        roles.push(json!({
            "name": format!("pub-{}", p.name),
            "keyids": p.keys.iter().map(|k| k.public().key_id().to_hex()).collect::<Vec<_>>(),
            "threshold": p.threshold,
            "paths": [format!("plugins/{}/*/*", p.name)],
            "terminating": true,
        }));
        let targets: Map<String, Value> = (0..p.targets)
            .map(|n| {
                (
                    format!("plugins/{}/x{n}/1.0.0.onclp", p.name),
                    json!({"length": 1, "hashes": {"sha256": Digest::of(b"x").to_hex()}}),
                )
            })
            .collect();
        let role = json!({
            "_type": "targets", "spec_version": SPEC_VERSION, "version": version,
            "expires": expires, "targets": targets,
        });
        let signers: Vec<&SigningKey> = p.signers.iter().collect();
        let file = build::sign(&role, &signers).unwrap();
        let name = RoleName::parse(&format!("pub-{}", p.name)).unwrap();
        let listed = if p.unhashed {
            json!({ "version": version })
        } else {
            meta(version, &file)
        };
        snapshot_meta.insert(name.meta_name(), listed);
        repo.put(layout::delegated_path(version, &name), file);
    }
    let targets = json!({
        "_type": "targets", "spec_version": SPEC_VERSION, "version": version,
        "expires": expires, "targets": {},
        "delegations": {"keys": keys, "roles": roles},
    });
    let targets = build::sign(&targets, &[&k.targets]).unwrap();
    snapshot_meta.insert("targets.json".to_owned(), meta(version, &targets));
    repo.put(layout::targets_path(version), targets);
    let snapshot = json!({
        "_type": "snapshot", "spec_version": SPEC_VERSION, "version": version,
        "expires": expires, "meta": snapshot_meta,
    });
    let snapshot = build::sign(&snapshot, &[&k.snapshot]).unwrap();
    let timestamp = build::timestamp(version, T0 + Duration::days(7), version, &snapshot).unwrap();
    repo.put(layout::snapshot_path(version), snapshot);
    repo.put(
        layout::TIMESTAMP_PATH,
        build::sign(&timestamp, &[&k.timestamp]).unwrap(),
    );
}

fn repository(k: &Top, publishers: &[Publisher]) -> (MemoryFetcher, Vec<u8>) {
    let repo = MemoryFetcher::new();
    let anchor = root_file(1, k, &[&k.root]);
    repo.put(layout::root_path(1), anchor.clone());
    publish(&repo, k, 1, publishers);
    (repo, anchor)
}

fn client<'a, S: Store>(
    anchor: &[u8],
    repo: &'a MemoryFetcher,
    store: S,
) -> TufClient<&'a MemoryFetcher, S> {
    TufClient::new(anchor, repo, store, Limits::default())
        .unwrap()
        .with_profile(Profile::Delegating)
}

fn role(name: &str) -> RoleName {
    RoleName::parse(name).unwrap()
}

#[test]
fn the_roles_after_the_most_followed_are_not_trusted() {
    let k = top(1);
    let names: Vec<String> = (0..33).map(|n| format!("p{n:02}x")).collect();
    let publishers: Vec<Publisher> = names
        .iter()
        .zip(100u8..)
        .map(|(name, seed)| publisher(name, seed))
        .collect();
    let (repo, anchor) = repository(&k, &publishers);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    let delegated = c.delegated(&trusted, T0).unwrap();
    let roles: Vec<_> = delegated.roles().collect();
    assert_eq!(roles.len(), 33);
    assert!(roles[..32].iter().all(|(_, role)| role.is_ok()));
    assert!(matches!(
        roles[32].1,
        Err(TufError::Delegation {
            error: DelegationError::TooMany { max: 32 },
            ..
        })
    ));
    assert_eq!(c.store().state.delegated.len(), 32);
}

#[test]
fn a_threshold_of_two_keys_is_met_by_both() {
    let k = top(1);
    let mut both = publisher("two", 50);
    both.keys = vec![key(50), key(51)];
    both.threshold = 2;
    both.signers = vec![key(50), key(51)];
    let (repo, anchor) = repository(&k, &[both]);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    let delegated = c.delegated(&trusted, T0).unwrap();
    assert!(matches!(delegated.role(&role("pub-two")), Some(Ok(_))));
}

/// A store that reads but cannot write.
struct ReadOnly(MemoryStore);

impl Store for ReadOnly {
    fn load(&self) -> Result<TrustState, TufError> {
        self.0.load()
    }

    fn save(&mut self, _: &TrustState) -> Result<TrustState, TufError> {
        Err(std::io::Error::other("read-only").into())
    }

    fn overwrite(&mut self, _: &TrustState) -> Result<(), TufError> {
        Err(std::io::Error::other("read-only").into())
    }
}

#[test]
fn a_store_that_cannot_be_written_fails_the_whole_step() {
    let k = top(1);
    let (repo, anchor) = repository(&k, &[publisher("ecc", 50)]);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    let state = c.store().state.clone();
    let mut c = client(&anchor, &repo, ReadOnly(MemoryStore { state, saves: 0 }));
    assert!(matches!(c.delegated(&trusted, T0), Err(TufError::Store(_))));
}

#[test]
fn a_saved_role_version_above_the_listed_one_is_a_rollback() {
    let k = top(1);
    let (repo, anchor) = repository(&k, &[publisher("ecc", 50)]);
    let mut store = MemoryStore::default();
    store.state.delegated.insert(
        role("pub-ecc"),
        RoleState {
            version: 5,
            sha256: Digest([0; 32]),
        },
    );
    let mut c = client(&anchor, &repo, store);
    let trusted = c.refresh(T0).unwrap();
    let delegated = c.delegated(&trusted, T0).unwrap();
    assert!(matches!(
        delegated.role(&role("pub-ecc")),
        Some(Err(TufError::Delegation {
            error: DelegationError::Rollback {
                found: 1,
                trusted: 5
            },
            ..
        }))
    ));
    // The version saved is not lowered.
    assert_eq!(c.store().state.delegated[&role("pub-ecc")].version, 5);
}

#[test]
fn a_rotation_of_the_keys_forgets_the_role_versions() {
    let k = top(1);
    let (repo, anchor) = repository(&k, &[publisher("ecc", 50)]);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    c.delegated(&trusted, T0).unwrap();
    assert_eq!(c.store().state.delegated.len(), 1);
    // Root 2 rotates every key but the root's.
    let mut rotated = top(20);
    rotated.root = key(1);
    repo.put(layout::root_path(2), root_file(2, &rotated, &[&k.root]));
    publish(&repo, &rotated, 2, &[publisher("ecc", 50)]);
    let trusted = c.refresh(T0).unwrap();
    assert!(c.store().state.delegated.is_empty());
    c.delegated(&trusted, T0).unwrap();
    assert_eq!(c.store().state.delegated[&role("pub-ecc")].version, 2);
}

const INDEX: &str = "indexes/stable.json";
const INDEX_BODY: &[u8] = b"[]";

/// A repository whose targets list the index [`INDEX`] and have `delegations`, if any, as
/// their member, whatever it is; the snapshot lists the targets by version only.
fn plain_repository(k: &Top, delegations: Option<Value>) -> (MemoryFetcher, Vec<u8>) {
    plain_repository_listing(k, delegations, |_| json!({"version": 1}))
}

/// [`plain_repository`], the snapshot listing the targets file as `listing` of its bytes says.
fn plain_repository_listing(
    k: &Top,
    delegations: Option<Value>,
    listing: impl Fn(&[u8]) -> Value,
) -> (MemoryFetcher, Vec<u8>) {
    let repo = MemoryFetcher::new();
    let anchor = root_file(1, k, &[&k.root]);
    repo.put(layout::root_path(1), anchor.clone());
    let files: [(&str, &[u8]); 1] = [(INDEX, INDEX_BODY)];
    let mut targets = build::targets(1, T0 + Duration::days(30), &files).unwrap();
    if let Some(delegations) = delegations {
        targets["delegations"] = delegations;
    }
    let targets = build::sign(&targets, &[&k.targets]).unwrap();
    let snapshot = json!({
        "_type": "snapshot", "spec_version": SPEC_VERSION, "version": 1,
        "expires": format_expires(T0 + Duration::days(30)).unwrap(),
        "meta": {"targets.json": listing(&targets)},
    });
    let snapshot = build::sign(&snapshot, &[&k.snapshot]).unwrap();
    let timestamp = build::timestamp(1, T0 + Duration::days(7), 1, &snapshot).unwrap();
    for (path, content) in build::target_files(&files).unwrap() {
        repo.put(path, content);
    }
    repo.put(layout::targets_path(1), targets);
    repo.put(layout::snapshot_path(1), snapshot);
    repo.put(
        layout::TIMESTAMP_PATH,
        build::sign(&timestamp, &[&k.timestamp]).unwrap(),
    );
    (repo, anchor)
}

#[test]
fn the_legacy_profile_delegates_to_no_role() {
    let k = top(1);
    let (repo, anchor) = plain_repository(&k, None);
    let mut c = TufClient::new(&anchor, &repo, MemoryStore::default(), Limits::default())
        .unwrap()
        .with_profile(Profile::Legacy);
    let trusted = c.refresh(T0).unwrap();
    assert_eq!(c.delegated(&trusted, T0).unwrap().roles().count(), 0);
    assert!(c.store().state.delegated.is_empty());
}

#[test]
fn the_default_profile_is_the_delegating_one() {
    let k = top(1);
    let (repo, anchor) = plain_repository(&k, None);
    let c = TufClient::new(&anchor, &repo, MemoryStore::default(), Limits::default()).unwrap();
    assert_eq!(c.profile(), Profile::Delegating);
}

#[test]
fn the_delegating_profile_refuses_targets_other_than_the_snapshot_lists() {
    let k = top(1);
    let digest = |file: &[u8]| Digest::of(file).to_hex();
    // One byte more than the file: its length is not the one listed.
    let (repo, anchor) = plain_repository_listing(
        &k,
        Some(json!({})),
        |file| json!({"version": 1, "length": file.len() + 1, "hashes": {"sha256": digest(file)}}),
    );
    let e = client(&anchor, &repo, MemoryStore::default())
        .refresh(T0)
        .unwrap_err();
    assert!(matches!(e, TufError::Length { .. }), "{e:?}");
    // The right length, another sha256.
    let (repo, anchor) = plain_repository_listing(
        &k,
        Some(json!({})),
        |file| json!({"version": 1, "length": file.len(), "hashes": {"sha256": digest(b"other")}}),
    );
    let e = client(&anchor, &repo, MemoryStore::default())
        .refresh(T0)
        .unwrap_err();
    assert!(matches!(e, TufError::Hash { .. }), "{e:?}");
    // Listed exactly, the same file is trusted.
    let (repo, anchor) = plain_repository_listing(
        &k,
        Some(json!({})),
        |file| json!({"version": 1, "length": file.len(), "hashes": {"sha256": digest(file)}}),
    );
    client(&anchor, &repo, MemoryStore::default())
        .refresh(T0)
        .unwrap();
}

#[test]
fn no_delegations_means_no_publishers() {
    let k = top(1);
    let (repo, anchor) = plain_repository(&k, None);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    assert_eq!(c.delegated(&trusted, T0).unwrap().roles().count(), 0);
    assert!(c.store().state.delegated.is_empty());
    let e = c
        .verify_cached_role(&role("pub-ecc"), b"{}", T0)
        .unwrap_err();
    assert!(
        matches!(
            e,
            TufError::Delegation {
                error: DelegationError::NotDelegated,
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn the_program_updates_through_targets_whose_delegations_it_cannot_read() {
    let k = top(1);
    let (repo, anchor) = plain_repository(&k, Some(json!({"keys": {}, "roles": 7})));
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    let index = c.download_target(&trusted, INDEX, 1 << 20, T0).unwrap();
    assert_eq!(index, INDEX_BODY);
    c.verify_cached_target(INDEX, &index, T0).unwrap();
    let e = c.delegated(&trusted, T0).unwrap_err();
    assert!(matches!(e, TufError::Malformed { .. }), "{e:?}");
    assert!(c.store().state.delegated.is_empty());
    let e = c
        .verify_cached_role(&role("pub-ecc"), b"{}", T0)
        .unwrap_err();
    assert!(matches!(e, TufError::Malformed { .. }), "{e:?}");
}

#[test]
fn a_role_listed_without_length_and_sha256_is_refused() {
    let k = top(1);
    let mut unhashed = publisher("bare", 60);
    unhashed.unhashed = true;
    let (repo, anchor) = repository(&k, &[publisher("ecc", 50), unhashed]);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    let delegated = c.delegated(&trusted, T0).unwrap();
    assert!(delegated.role(&role("pub-ecc")).unwrap().is_ok());
    assert!(matches!(
        delegated.role(&role("pub-bare")),
        Some(Err(TufError::Delegation {
            error: DelegationError::Unhashed,
            ..
        }))
    ));
    assert!(!c.store().state.delegated.contains_key(&role("pub-bare")));
}

#[test]
fn a_role_of_more_targets_than_the_limit_is_not_trusted() {
    let k = top(1);
    let mut at_limit = publisher("full", 50);
    at_limit.targets = 256;
    let mut over = publisher("over", 60);
    over.targets = 257;
    let (repo, anchor) = repository(&k, &[at_limit, over]);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    let delegated = c.delegated(&trusted, T0).unwrap();
    assert_eq!(
        delegated
            .role(&role("pub-full"))
            .unwrap()
            .unwrap()
            .targets()
            .len(),
        256
    );
    assert!(matches!(
        delegated.role(&role("pub-over")),
        Some(Err(TufError::Delegation {
            error: DelegationError::TooManyTargets { max: 256 },
            ..
        }))
    ));
}

#[test]
fn a_second_validly_signed_file_of_the_accepted_version_is_refused_offline() {
    let k = top(1);
    let (repo, anchor) = repository(&k, &[publisher("ecc", 50)]);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    let delegated = c.delegated(&trusted, T0).unwrap();
    let accepted = delegated.role(&role("pub-ecc")).unwrap().unwrap();
    c.verify_cached_role(&role("pub-ecc"), accepted.file(), T0)
        .unwrap();
    // The same version, signed by the publisher's key, listing another target.
    let other = json!({
        "_type": "targets", "spec_version": SPEC_VERSION, "version": accepted.version(),
        "expires": format_expires(T0 + Duration::days(30)).unwrap(),
        "targets": {"plugins/ecc/y/9.0.0.onclp":
            {"length": 1, "hashes": {"sha256": Digest::of(b"y").to_hex()}}},
    });
    let other = build::sign(&other, &[&key(50)]).unwrap();
    let e = c
        .verify_cached_role(&role("pub-ecc"), &other, T0)
        .unwrap_err();
    assert!(matches!(e, TufError::Hash { .. }), "{e:?}");
}

#[test]
fn the_saved_top_level_targets_are_checked_again_offline_with_their_delegations() {
    let k = top(1);
    let (repo, anchor) = repository(&k, &[publisher("ecc", 50)]);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    assert!(
        c.verify_cached_top_level(T0).unwrap().is_none(),
        "none saved"
    );
    c.refresh(T0).unwrap();
    let (targets, valid_until) = c.verify_cached_top_level(T0).unwrap().unwrap();
    assert_eq!(valid_until, T0 + Duration::days(30));
    let delegations = targets.delegations().unwrap().unwrap();
    assert_eq!(delegations.roles().len(), 1);
    // Expired: refused.
    let e = c
        .verify_cached_top_level(T0 + Duration::days(31))
        .unwrap_err();
    assert!(matches!(e, TufError::Expired { .. }), "{e:?}");
}

#[test]
fn a_kept_role_holds_offline_only_at_the_version_the_snapshot_lists() {
    let k = top(1);
    let (repo, anchor) = repository(&k, &[publisher("ecc", 50)]);
    let mut c = client(&anchor, &repo, MemoryStore::default());
    let trusted = c.refresh(T0).unwrap();
    let delegated = c.delegated(&trusted, T0).unwrap();
    let kept = delegated
        .role(&role("pub-ecc"))
        .unwrap()
        .unwrap()
        .file()
        .to_vec();
    c.verify_cached_current_role(&role("pub-ecc"), &kept, T0)
        .unwrap();
    // Version 2 is signed by a key the delegation does not name: refused online, and the
    // version 1 kept no longer holds offline either.
    let mut forged = publisher("ecc", 50);
    forged.signers = vec![key(51)];
    publish(&repo, &k, 2, &[forged]);
    let trusted = c.refresh(T0).unwrap();
    assert!(
        c.delegated(&trusted, T0)
            .unwrap()
            .role(&role("pub-ecc"))
            .unwrap()
            .is_err()
    );
    // The plain check (the maintainer's tools) still takes the version accepted.
    c.verify_cached_role(&role("pub-ecc"), &kept, T0).unwrap();
    let e = c
        .verify_cached_current_role(&role("pub-ecc"), &kept, T0)
        .unwrap_err();
    assert!(
        matches!(
            e,
            TufError::Delegation {
                error: DelegationError::NotAccepted,
                ..
            }
        ),
        "{e:?}"
    );
}
