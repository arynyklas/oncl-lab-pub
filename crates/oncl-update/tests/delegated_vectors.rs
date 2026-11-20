//! The delegated repositories python-tuf read (`tests/fixtures/tuf/delegated-*`, see the
//! README): a repository of two publishers, `pub-alpha` and `pub-beta`, as `tuf/v1` is laid
//! out once it delegates, and one mutation of it per vector. These tests read the files with
//! the model alone: the top-level targets in the delegating profile, and each role's file
//! against the keys its delegation names.

use std::path::{Path, PathBuf};

use oncl_update::tuf::ed25519::{count_valid, verify_role};
use oncl_update::tuf::{
    DelegatedRole, DelegationError, Delegations, Envelope, Limits, Profile, RefusedRole, Role,
    RoleName, Root, Snapshot, Targets, Timestamp, TufError, layout,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tuf")
}

fn file(vector: &str, path: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(vector).join(path)).unwrap()
}

fn envelope(vector: &str, path: &str) -> Envelope {
    Envelope::parse(&file(vector, path), Limits::default().targets, path).unwrap()
}

fn role(name: &str) -> RoleName {
    RoleName::parse(name).unwrap()
}

/// The root every delegated vector is anchored at.
fn root() -> Root {
    Root::from_signed(&envelope("delegated-valid", "metadata/1.root.json").signed).unwrap()
}

/// The snapshot the vector's timestamp names.
fn snapshot(vector: &str) -> Snapshot {
    let timestamp =
        Timestamp::from_signed(&envelope(vector, layout::TIMESTAMP_PATH).signed).unwrap();
    let path = layout::snapshot_path(timestamp.snapshot.version);
    Snapshot::from_signed(&envelope(vector, &path).signed).unwrap()
}

/// The vector's top-level targets, the version its snapshot lists, read in `profile`.
fn targets(vector: &str, profile: Profile) -> Result<Targets, TufError> {
    let path = layout::targets_path(snapshot(vector).targets().version);
    Targets::from_signed(&envelope(vector, &path).signed, profile)
}

fn delegations(vector: &str) -> Delegations {
    targets(vector, Profile::Delegating)
        .unwrap()
        .delegations()
        .unwrap()
        .unwrap()
}

fn accepted<'a>(delegations: &'a Delegations, name: &str) -> &'a DelegatedRole {
    match delegations.role(&role(name)) {
        Some(Ok(role)) => role,
        other => panic!("{name}: {other:?}"),
    }
}

/// Whether the file the snapshot lists for `name` is signed by a threshold of the keys of
/// its delegation.
fn signed_by_its_delegation(vector: &str, name: &str) -> bool {
    let delegations = delegations(vector);
    let delegated = accepted(&delegations, name);
    let listed = &snapshot(vector).meta[&delegated.name().meta_name()];
    let file = envelope(
        vector,
        &layout::delegated_path(listed.version, delegated.name()),
    );
    let message = file.canonical_signed().unwrap();
    let valid = count_valid(
        &message,
        &file.signatures,
        delegated.keys(),
        delegations.keys(),
    );
    valid >= delegated.keys().threshold as usize
}

const VECTORS_OF_TWO_ROLES: [&str; 11] = [
    "delegated-valid",
    "delegated-bad-signature",
    "delegated-threshold-not-met",
    "delegated-version-mismatch",
    "delegated-hash-mismatch",
    "delegated-expired",
    "delegated-not-in-snapshot",
    "delegated-path-outside",
    "delegated-nested",
    "delegated-key-reuse",
    "delegated-glob-depth",
];

#[test]
fn the_legacy_profile_refuses_the_top_level_targets_of_every_delegated_vector() {
    for vector in VECTORS_OF_TWO_ROLES {
        assert!(
            matches!(
                targets(vector, Profile::Legacy),
                Err(TufError::Unsupported(_))
            ),
            "{vector}"
        );
    }
}

#[test]
fn both_roles_keep_the_profile_where_the_attack_is_not_in_the_delegation() {
    for vector in VECTORS_OF_TWO_ROLES {
        let delegations = delegations(vector);
        let names: Vec<&str> = delegations
            .roles()
            .iter()
            .map(|role| role.as_ref().map(|r| r.name().as_str()).unwrap())
            .collect();
        assert_eq!(names, ["pub-alpha", "pub-beta"], "{vector}");
    }
}

#[test]
fn a_removed_delegation_leaves_only_the_other_role() {
    let delegations = delegations("delegated-removed");
    assert_eq!(delegations.roles().len(), 1);
    accepted(&delegations, "pub-alpha");
    assert!(delegations.role(&role("pub-beta")).is_none());
    // The snapshot still lists the role.
    assert!(
        snapshot("delegated-removed")
            .meta
            .contains_key("pub-beta.json")
    );
}

#[test]
fn a_delegation_by_path_hash_prefixes_refuses_that_role_alone() {
    let delegations = delegations("delegated-path-hash-prefixes");
    accepted(&delegations, "pub-alpha");
    assert_eq!(
        delegations.role(&role("pub-beta")),
        Some(Err(&RefusedRole {
            name: role("pub-beta"),
            error: DelegationError::HashPrefixes,
        }))
    );
}

#[test]
fn a_role_listed_twice_makes_the_delegations_unreadable_as_python_tuf_does() {
    let read = targets("delegated-duplicate-role", Profile::Delegating).unwrap();
    let e = read.delegations().unwrap_err();
    assert!(
        matches!(&e, TufError::Malformed { why, .. } if why.contains("twice")),
        "{e:?}"
    );
}

#[test]
fn a_top_level_role_name_makes_the_delegations_unreadable_as_python_tuf_does() {
    let read = targets("delegated-top-level-name", Profile::Delegating).unwrap();
    let e = read.delegations().unwrap_err();
    assert!(matches!(e, TufError::Malformed { .. }), "{e:?}");
}

#[test]
fn the_threshold_of_two_is_read_from_the_delegation() {
    let delegations = delegations("delegated-threshold-not-met");
    let beta = accepted(&delegations, "pub-beta");
    assert_eq!((beta.keys().threshold, beta.keys().keyids.len()), (2, 2));
}

#[test]
fn the_reused_key_is_the_roots_targets_key() {
    // The delegations alone cannot tell: the client refuses the role against the root.
    let delegations = delegations("delegated-key-reuse");
    let beta = accepted(&delegations, "pub-beta");
    assert_eq!(beta.keys().keyids, root().targets.keyids);
}

#[test]
fn the_role_files_are_signed_by_their_delegations_keys() {
    for vector in VECTORS_OF_TWO_ROLES {
        assert!(signed_by_its_delegation(vector, "pub-alpha"), "{vector}");
    }
    for vector in [
        "delegated-valid",
        "delegated-version-mismatch",
        "delegated-expired",
        "delegated-path-outside",
        "delegated-nested",
        "delegated-key-reuse",
        "delegated-glob-depth",
    ] {
        assert!(signed_by_its_delegation(vector, "pub-beta"), "{vector}");
    }
}

#[test]
fn a_flipped_signature_or_one_key_of_two_is_below_the_threshold() {
    for vector in [
        "delegated-bad-signature",
        "delegated-threshold-not-met",
        "delegated-hash-mismatch",
    ] {
        assert!(!signed_by_its_delegation(vector, "pub-beta"), "{vector}");
    }
}

#[test]
fn the_top_level_metadata_of_the_delegated_vectors_is_signed_by_their_root() {
    let root = root();
    for vector in VECTORS_OF_TWO_ROLES {
        let timestamp = envelope(vector, layout::TIMESTAMP_PATH);
        verify_role(&timestamp, &root, Role::Timestamp, vector).unwrap();
    }
}

// --- the whole client: `refresh` and `delegated` in the delegating profile ---

mod client {
    use oncl_update::tuf::{
        Delegated, DelegationError, Limits, MemoryFetcher, MemoryStore, Profile, Store, TufClient,
        TufError,
    };
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use super::{fixtures, role};

    fn read_tree(base: &std::path::Path, dir: &std::path::Path, out: &MemoryFetcher) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                read_tree(base, &path, out);
            } else if path.file_name().unwrap() != "expected.json" {
                let relative = path.strip_prefix(base).unwrap().to_string_lossy();
                out.put(relative.replace('\\', "/"), std::fs::read(&path).unwrap());
            }
        }
    }

    fn repository(name: &str) -> MemoryFetcher {
        let dir = fixtures().join(name);
        let repo = MemoryFetcher::new();
        read_tree(&dir, &dir, &repo);
        repo
    }

    fn now(name: &str) -> OffsetDateTime {
        let vector: serde_json::Value = serde_json::from_slice(
            &std::fs::read(fixtures().join(name).join("expected.json")).unwrap(),
        )
        .unwrap();
        OffsetDateTime::parse(vector["now"].as_str().unwrap(), &Rfc3339).unwrap()
    }

    fn client<'a>(
        repo: &'a MemoryFetcher,
        store: &'a mut MemoryStore,
    ) -> TufClient<&'a MemoryFetcher, &'a mut MemoryStore> {
        let anchor =
            std::fs::read(fixtures().join("delegated-valid/metadata/1.root.json")).unwrap();
        TufClient::new(&anchor, repo, store, Limits::default())
            .unwrap()
            .with_profile(Profile::Delegating)
    }

    /// `refresh` and `delegated` of the vector `name`, after `prior` was accepted.
    fn run(name: &str, store: &mut MemoryStore) -> Result<Delegated, TufError> {
        let repo = repository(name);
        let mut c = client(&repo, store);
        let trusted = c.refresh(now(name))?;
        c.delegated(&trusted, now(name))
    }

    fn verified(delegated: &Delegated, name: &str) -> u64 {
        match delegated.role(&role(name)) {
            Some(Ok(role)) => role.version(),
            other => panic!("{name}: {other:?}"),
        }
    }

    fn refused<'a>(delegated: &'a Delegated, name: &str) -> &'a TufError {
        match delegated.role(&role(name)) {
            Some(Err(e)) => e,
            other => panic!("{name}: {other:?}"),
        }
    }

    fn delegation(e: &TufError) -> &DelegationError {
        match e {
            TufError::Delegation { error, .. } => error,
            other => panic!("not a delegation error: {other:?}"),
        }
    }

    #[test]
    fn the_valid_repository_trusts_both_roles_and_saves_their_versions() {
        let mut store = MemoryStore::default();
        let delegated = run("delegated-valid", &mut store).unwrap();
        assert_eq!(verified(&delegated, "pub-alpha"), 2);
        assert_eq!(verified(&delegated, "pub-beta"), 1);
        let alpha = delegated.role(&role("pub-alpha")).unwrap().unwrap();
        assert!(
            alpha
                .target("plugins/alpha/kz.alpha.signer/1.0.0.onclp")
                .is_some()
        );
        let saved = store.load().unwrap().delegated;
        let version = |name: &str| saved.get(&role(name)).map(|accepted| accepted.version);
        assert_eq!(version("pub-alpha"), Some(2));
        assert_eq!(version("pub-beta"), Some(1));
    }

    #[test]
    fn a_bad_role_is_refused_alone_as_the_contract_says() {
        type Check = fn(&TufError) -> bool;
        let table: [(&str, Check); 9] = [
            ("delegated-bad-signature", |e| {
                matches!(e, TufError::Signature { valid: 0, .. })
            }),
            ("delegated-threshold-not-met", |e| {
                matches!(
                    e,
                    TufError::Signature {
                        valid: 1,
                        threshold: 2,
                        ..
                    }
                )
            }),
            ("delegated-version-mismatch", |e| {
                delegation(e)
                    == &DelegationError::VersionMismatch {
                        expected: 1,
                        found: 2,
                    }
            }),
            ("delegated-hash-mismatch", |e| {
                matches!(e, TufError::Hash { .. })
            }),
            ("delegated-expired", |e| {
                matches!(delegation(e), DelegationError::Expired { .. })
            }),
            ("delegated-not-in-snapshot", |e| {
                delegation(e) == &DelegationError::NotInSnapshot
            }),
            ("delegated-path-outside", |e| {
                matches!(delegation(e), DelegationError::PathOutside { path }
                    if path.as_str() == "plugins/alpha/kz.alpha.evil/9.0.0.onclp")
            }),
            ("delegated-nested", |e| {
                delegation(e) == &DelegationError::Nested
            }),
            ("delegated-path-hash-prefixes", |e| {
                delegation(e) == &DelegationError::HashPrefixes
            }),
        ];
        for (name, check) in table {
            let delegated = run(name, &mut MemoryStore::default()).unwrap();
            assert_eq!(verified(&delegated, "pub-alpha"), 2, "{name}");
            let e = refused(&delegated, "pub-beta");
            assert!(check(e), "{name}: {e:?}");
        }
    }

    #[test]
    fn a_role_on_a_key_of_the_root_is_refused() {
        let delegated = run("delegated-key-reuse", &mut MemoryStore::default()).unwrap();
        verified(&delegated, "pub-alpha");
        let e = refused(&delegated, "pub-beta");
        assert!(
            matches!(delegation(e), DelegationError::KeyReused { .. }),
            "{e:?}"
        );
    }

    #[test]
    fn a_target_one_segment_deeper_is_outside_the_role() {
        let delegated = run("delegated-glob-depth", &mut MemoryStore::default()).unwrap();
        verified(&delegated, "pub-beta");
        let e = refused(&delegated, "pub-alpha");
        assert!(
            matches!(delegation(e), DelegationError::PathOutside { .. }),
            "{e:?}"
        );
    }

    #[test]
    fn a_removed_delegation_is_no_role_at_all() {
        let delegated = run("delegated-removed", &mut MemoryStore::default()).unwrap();
        verified(&delegated, "pub-alpha");
        assert!(delegated.role(&role("pub-beta")).is_none());
        assert_eq!(delegated.roles().count(), 1);
    }

    #[test]
    fn a_rolled_back_role_is_refused_at_the_snapshot() {
        let mut store = MemoryStore::default();
        run("delegated-valid", &mut store).unwrap();
        let e = run("delegated-rollback", &mut store).unwrap_err();
        assert!(
            matches!(&e, TufError::Rollback { what, found: 1, trusted: 2 } if what.contains("pub-alpha.json")),
            "{e:?}"
        );
    }

    #[test]
    fn a_role_twice_or_a_top_level_name_fails_the_delegated_step_not_the_refresh() {
        for name in ["delegated-duplicate-role", "delegated-top-level-name"] {
            let repo = repository(name);
            let mut store = MemoryStore::default();
            let mut c = client(&repo, &mut store);
            let trusted = c.refresh(now(name)).unwrap();
            let e = c.delegated(&trusted, now(name)).unwrap_err();
            assert!(matches!(e, TufError::Malformed { .. }), "{name}: {e:?}");
            assert!(c.store().load().unwrap().delegated.is_empty(), "{name}");
        }
    }

    #[test]
    fn the_legacy_profile_refuses_the_delegated_repository_as_released_clients_do() {
        let repo = repository("delegated-valid");
        let mut store = MemoryStore::default();
        let anchor =
            std::fs::read(fixtures().join("delegated-valid/metadata/1.root.json")).unwrap();
        let mut c = TufClient::new(&anchor, &repo, &mut store, Limits::default())
            .unwrap()
            .with_profile(Profile::Legacy);
        let e = c.refresh(now("delegated-valid")).unwrap_err();
        assert!(matches!(e, TufError::Unsupported(_)), "{e:?}");
    }

    #[test]
    fn the_core_takes_a_snapshot_without_lengths_in_the_delegating_profile() {
        // The valid (v1) repository lists versions only, and no delegations.
        let repo = super::client_v1::repository();
        let mut store = MemoryStore::default();
        let anchor = std::fs::read(fixtures().join("valid/metadata/1.root.json")).unwrap();
        let mut c = TufClient::new(&anchor, &repo, &mut store, Limits::default())
            .unwrap()
            .with_profile(Profile::Delegating);
        let trusted = c.refresh(now("valid")).unwrap();
        assert_eq!(
            c.delegated(&trusted, now("valid")).unwrap().roles().count(),
            0
        );
    }

    #[test]
    fn a_kept_role_is_checked_again_offline() {
        let repo = repository("delegated-valid");
        let mut store = MemoryStore::default();
        let at = now("delegated-valid");
        let mut c = client(&repo, &mut store);
        let trusted = c.refresh(at).unwrap();
        let delegated = c.delegated(&trusted, at).unwrap();
        let alpha = delegated.role(&role("pub-alpha")).unwrap().unwrap();
        let beta = delegated.role(&role("pub-beta")).unwrap().unwrap();
        let again = c
            .verify_cached_role(&role("pub-alpha"), alpha.file(), at)
            .unwrap();
        assert_eq!(again.version(), 2);
        assert_eq!(again.targets(), alpha.targets());
        // Another role's bytes are not this role's.
        let e = c
            .verify_cached_role(&role("pub-alpha"), beta.file(), at)
            .unwrap_err();
        assert!(matches!(e, TufError::Hash { .. }), "{e:?}");
        // After the role expired.
        let late = alpha.expires();
        let e = c
            .verify_cached_role(&role("pub-alpha"), alpha.file(), late)
            .unwrap_err();
        assert!(
            matches!(e, TufError::Expired { .. } | TufError::Delegation { .. }),
            "{e:?}"
        );
        // A role the saved targets do not delegate to.
        let e = c
            .verify_cached_role(&role("pub-other"), alpha.file(), at)
            .unwrap_err();
        assert!(
            matches!(delegation(&e), DelegationError::NotDelegated),
            "{e:?}"
        );
    }

    #[test]
    fn a_kept_role_is_refused_once_its_delegation_names_other_keys() {
        // The saved targets are those of delegated-key-reuse: pub-beta is on another key.
        let mut store = MemoryStore::default();
        let valid = run("delegated-valid", &mut store).unwrap();
        let beta = valid
            .role(&role("pub-beta"))
            .unwrap()
            .unwrap()
            .file()
            .to_vec();
        let repo = repository("delegated-key-reuse");
        let at = now("delegated-key-reuse");
        let c = client(&repo, &mut store);
        // (The same targets version: the saved file is still that of delegated-valid.)
        c.verify_cached_role(&role("pub-beta"), &beta, at).unwrap();
        let mut state = c.store().load().unwrap();
        drop(c);
        let file = repo.get("metadata/1.targets.json").unwrap();
        state.targets_file =
            Some(oncl_update::tuf::Envelope::parse(&file, 1 << 20, "targets").unwrap());
        store.state = state;
        let c = client(&repo, &mut store);
        let e = c
            .verify_cached_role(&role("pub-beta"), &beta, at)
            .unwrap_err();
        assert!(
            matches!(delegation(&e), DelegationError::KeyReused { .. }),
            "{e:?}"
        );
    }
}

mod client_v1 {
    use oncl_update::tuf::MemoryFetcher;

    pub(super) fn repository() -> MemoryFetcher {
        let dir = super::fixtures().join("valid");
        let repo = MemoryFetcher::new();
        for path in walk(&dir) {
            let relative = path.strip_prefix(&dir).unwrap().to_string_lossy();
            repo.put(relative.replace('\\', "/"), std::fs::read(&path).unwrap());
        }
        repo
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else if path.file_name().unwrap() != "expected.json" {
                out.push(path);
            }
        }
        out
    }
}
