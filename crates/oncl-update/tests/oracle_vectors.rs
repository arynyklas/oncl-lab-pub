//! The whole client against the repositories python-tuf built (`tests/fixtures/tuf/`, see its
//! README): `valid/` is accepted, byte for byte, and every `<attack>/` is refused, at the
//! step and as the error the table below says, exactly. Each directory is a served root; the
//! files are read from disk into a `MemoryFetcher`, the clock is the `now` of the vector.
//! None of them has delegations: both profiles ([`Profile`]) must give the same outcome.

use std::path::{Path, PathBuf};

use oncl_update::tuf::{
    Limits, MemoryFetcher, MemoryStore, Profile, Role, Store, TufClient, TufError,
};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const MAX_TARGET: u64 = 1 << 20;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tuf")
}

fn read_tree(base: &Path, dir: &Path, out: &MemoryFetcher) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            read_tree(base, &path, out);
        } else if path.file_name().unwrap() != "expected.json" {
            let relative = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.put(relative, std::fs::read(&path).unwrap());
        }
    }
}

/// The repository served from the directory `name`.
fn repository(name: &str) -> MemoryFetcher {
    let dir = fixtures().join(name);
    let repo = MemoryFetcher::new();
    read_tree(&dir, &dir, &repo);
    repo
}

fn expected(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixtures().join(name).join("expected.json")).unwrap())
        .unwrap()
}

fn anchor() -> Vec<u8> {
    std::fs::read(fixtures().join("valid/metadata/1.root.json")).unwrap()
}

fn now(vector: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(vector["now"].as_str().unwrap(), &Rfc3339).unwrap()
}

/// How far into the workflow a path is: the step that asks for it. 0 root, 1 timestamp,
/// 2 snapshot, 3 targets, 4 a target file.
fn rank(path: &str) -> u8 {
    if path.ends_with(".root.json") {
        0
    } else if path == "metadata/timestamp.json" {
        1
    } else if path.ends_with(".snapshot.json") {
        2
    } else if path.ends_with(".targets.json") {
        3
    } else {
        4
    }
}

const PROFILES: [Profile; 2] = [Profile::Legacy, Profile::Delegating];

fn client<'a>(
    repo: &'a MemoryFetcher,
    store: &'a mut MemoryStore,
    profile: Profile,
) -> TufClient<&'a MemoryFetcher, &'a mut MemoryStore> {
    TufClient::new(&anchor(), repo, store, Limits::default())
        .unwrap()
        .with_profile(profile)
}

type Check = fn(&TufError) -> bool;

/// One attack: where the client refuses it (the deepest step it asks the repository for,
/// see [`rank`]), the step python-tuf refuses it at (as in `expected.json`'s `must_fail_at`),
/// and exactly the error.
struct Attack {
    name: &'static str,
    ours: u8,
    python_tuf: &'static str,
    error: Check,
}

fn attacks() -> Vec<Attack> {
    macro_rules! attack {
        ($name:literal, $ours:literal, $python:literal, $pattern:pat $(if $guard:expr)?) => {
            Attack {
                name: $name,
                ours: $ours,
                python_tuf: $python,
                error: |e| matches!(e, $pattern $(if $guard)?),
            }
        };
    }
    vec![
        attack!("bad-signature-targets", 3, "targets",
            TufError::Signature { what, valid: 0, threshold: 1 } if what == "the targets"),
        attack!(
            "expired-timestamp",
            1,
            "timestamp",
            TufError::Expired {
                role: Role::Timestamp,
                ..
            }
        ),
        attack!(
            "expired-snapshot",
            2,
            "snapshot",
            TufError::Expired {
                role: Role::Snapshot,
                ..
            }
        ),
        attack!(
            "expired-targets",
            3,
            "targets",
            TufError::Expired {
                role: Role::Targets,
                ..
            }
        ),
        attack!("new-root-signed-only-by-new-keys", 0, "root",
            TufError::Signature { what, valid: 0, threshold: 1 }
                if what == "root 3 by the keys of root 2"),
        // The next timestamp already lists snapshot 1 after snapshot 2 was accepted: refused
        // by 5.4.3.2 at the timestamp, one step before python-tuf, which refuses the snapshot.
        attack!("rollback-snapshot", 1, "snapshot",
            TufError::Rollback { what, found: 1, trusted: 2 }
                if what == "snapshot listed by the timestamp"),
        // The new snapshot lists targets 1 after targets 2: refused by 5.5.5 at the snapshot,
        // one step before python-tuf, which refuses the targets file.
        attack!("rollback-targets", 2, "snapshot or targets",
            TufError::Rollback { what, found: 1, trusted: 2 }
                if what == "targets.json listed by the snapshot"),
        attack!("rollback-timestamp", 1, "timestamp",
            TufError::Rollback { what, found: 1_794_697_200, trusted: 1_794_700_800 }
                if what == "timestamp"),
        attack!(
            "root-version-gap",
            0,
            "root",
            TufError::RootVersion {
                expected: 2,
                found: 3
            }
        ),
        attack!("tampered-unknown-field", 3, "targets",
            TufError::Signature { what, valid: 0, threshold: 1 } if what == "the targets"),
        attack!("threshold-not-met", 0, "root",
            TufError::Signature { what, valid: 1, threshold: 2 }
                if what == "root 2 by its own keys"),
        // python-tuf accepts this repository (`diverges_from_contract`): the contract has
        // the client recompute key ids.
        attack!("wrong-keyid-in-root", 0, "root",
            TufError::BadKeyId { claimed, actual }
                if claimed == &"0".repeat(64)
                    && actual == "e837e8b183c59a2b7ebcd3173500127f0c1ef57d5d590e0673c8190dd9536976"),
        // The metadata is fine; the target file is not (the step is 4: a target file).
        attack!("target-hash-mismatch", 4, "target",
            TufError::Hash { what } if what == "indexes/stable.json"),
        // A body longer than listed (1005 bytes) is stopped where it is read.
        attack!("target-length-mismatch", 4, "target",
            TufError::Fetch(m) if m.contains(".stable.json")
                && m.contains("larger than request limit: 1005")),
    ]
}

#[test]
fn the_valid_repository_is_accepted_and_both_indexes_come_out_byte_for_byte() {
    for profile in PROFILES {
        let vector = expected("valid");
        let repo = repository("valid");
        let mut store = MemoryStore::default();
        let mut c = client(&repo, &mut store, profile);
        let clock = now(&vector);
        let trusted = c.refresh(clock).unwrap();
        assert_eq!(trusted.state_was_reset(), None);

        // Root 1 -> 2 -> 3 (a timestamp key rotation, then a root key rotation), snapshot
        // and targets 2, the timestamp at the time of signing.
        assert_eq!(trusted.root().version, 3);
        assert_eq!(trusted.timestamp().version, 1_794_700_800);
        assert_eq!(
            (trusted.snapshot().version, trusted.targets().version),
            (2, 2)
        );
        assert!(
            trusted.snapshot().targets().length.is_none(),
            "python-tuf lists no length or hashes"
        );

        let targets = vector["targets"].as_object().unwrap();
        assert_eq!(targets.len(), 2);
        for (target, stored) in targets {
            let fixture =
                std::fs::read(fixtures().join("valid").join(stored.as_str().unwrap())).unwrap();
            let downloaded = c
                .download_target(&trusted, target, MAX_TARGET, clock)
                .unwrap();
            assert_eq!(downloaded, fixture, "{profile:?} {target}");
        }
        let state = store.load().unwrap();
        assert_eq!((state.root_version, state.roots.len()), (3, 2));
        assert_eq!(state.targets, Some(2));
    }
}

#[test]
fn every_attack_is_refused_at_its_step_as_its_error() {
    let table = attacks();
    // The table covers every attack directory of the valid repository, and nothing else (the
    // delegated repositories and cross-repo are `delegated_vectors.rs`'s).
    let mut names: Vec<String> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.path().is_dir() && e.file_name() != "valid")
        .map(|e| e.file_name().into_string().unwrap())
        .filter(|name| !name.starts_with("delegated-") && name != "cross-repo")
        .collect();
    names.sort();
    let mut listed: Vec<&str> = table.iter().map(|a| a.name).collect();
    listed.sort_unstable();
    assert_eq!(names, listed);
    assert_eq!(table.len(), 14);

    for attack in table {
        for profile in PROFILES {
            refused_at_its_step(&attack, profile);
        }
    }
}

/// `attack` is refused at its step as its error by a client of `profile`.
fn refused_at_its_step(attack: &Attack, profile: Profile) {
    let name = attack.name;
    let vector = expected(name);
    assert_eq!(
        vector["must_fail_at"].as_str().unwrap(),
        attack.python_tuf,
        "{name}: python-tuf's step"
    );
    let clock = now(&vector);
    let mut store = MemoryStore::default();
    if !vector["prior_state"].is_null() {
        // A client that has already accepted the valid repository on the same clock.
        let valid = repository("valid");
        client(&valid, &mut store, profile).refresh(clock).unwrap();
    }
    let repo = repository(name);
    repo.clear_requests();
    let mut c = client(&repo, &mut store, profile);
    let error = match c.refresh(clock) {
        Err(error) => error,
        Ok(trusted) => {
            assert_eq!(
                attack.ours, 4,
                "{profile:?} {name}: refresh accepted what must fail"
            );
            // The metadata is fine; of the two indexes the one in the vector is not, the
            // other is.
            let mut failures = Vec::new();
            for target in ["indexes/stable.json", "indexes/beta.json"] {
                match c.download_target(&trusted, target, MAX_TARGET, clock) {
                    Ok(_) => {}
                    Err(e) => failures.push((target, e)),
                }
            }
            assert_eq!(failures.len(), 1, "{profile:?} {name}: {failures:?}");
            let (target, error) = failures.remove(0);
            assert_eq!(target, "indexes/stable.json", "{profile:?} {name}");
            error
        }
    };
    assert!(
        (attack.error)(&error),
        "{profile:?} {name}: refused as {error:?}, expected {}",
        vector["error_class"]
    );
    // Exactly the step: the deepest file asked for is the one of that step.
    let deepest = repo.requests().iter().map(|p| rank(p)).max().unwrap();
    assert_eq!(
        deepest, attack.ours,
        "{profile:?} {name}: the deepest step asked for"
    );
}

#[test]
fn the_only_vector_python_tuf_accepts_is_the_one_the_contract_refuses() {
    for entry in std::fs::read_dir(fixtures()).unwrap() {
        let path = entry.unwrap().path();
        if path.join("expected.json").is_file() {
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let vector = expected(&name);
            let diverges = vector["python_tuf"]["diverges_from_contract"] == true;
            assert_eq!(diverges, name == "wrong-keyid-in-root", "{name}");
            if diverges {
                assert_eq!(vector["python_tuf"]["verdict"], "ACCEPT");
            }
        }
    }
}
