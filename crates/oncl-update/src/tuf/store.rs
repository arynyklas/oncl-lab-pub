//! What the client keeps between runs: the roots it has followed, and the versions of the
//! other roles it has accepted, so that no later run takes a step back.
//!
//! All of it is one [`TrustState`], so that a crash can never leave a new root with the old
//! timestamp (which would hide that the keys changed: step 5.3.11 of the specification).
//! [`FileStore`] writes it as `<dir>/state.json`, atomically, and under a lock on the
//! directory so that two processes (the updater and the plugin catalog) cannot lose each
//! other's update; [`Store::save`] merges what is on disk with what is saved and never
//! lowers a version.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use oncl_pki::fsutil::{Access, write_atomically};
use serde::{Deserialize, Serialize};

use super::canonical;
use super::error::TufError;
use super::model::{Digest, Envelope, MetaFile};
use super::names::RoleName;

/// The only `schema` of the state file this version reads.
pub const SCHEMA: u32 = 1;

/// The largest state file, read or written: a client that wrote a file it cannot read back
/// would reset itself every run.
pub const MAX_STATE_LEN: u64 = 2 << 20;

/// What the client trusts, apart from its built-in root.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustState {
    /// The version of the newest root trusted, the built-in one's or the last of `roots`;
    /// 0 before the first run.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub root_version: u64,
    /// The version of the newest root that changed the keys or threshold of the timestamp,
    /// snapshot or targets role: the versions below belong to the keys of that epoch, and
    /// are dropped when a later root starts another.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub keys_epoch: u64,
    /// The roots followed from the built-in one, in order (the built-in root's version plus
    /// one, and on), as downloaded. A run checks the whole chain again from the built-in
    /// root before it trusts any of it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<Envelope>,
    /// The newest timestamp accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<TimestampState>,
    /// The newest snapshot accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotState>,
    /// The version of the newest targets accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<u64>,
    /// The targets file of that version as downloaded: what [`super::TufClient::verify_cached_target`]
    /// checks a kept target against, offline, after checking its signature again from the
    /// chain of roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets_file: Option<Envelope>,
    /// The client has accepted a timestamp of this repository at least once. Never cleared by
    /// a rotation of keys or by dropping the saved versions (a reset of a state that did
    /// not hold sets it: nothing can be known then), so that a 404 for the timestamp is "not
    /// published" only for a client that never saw the repository. Absent means false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ever_published: bool,
    /// The file of each delegated role accepted last ([`super::TufClient::delegated`]), of
    /// the keys epoch of the versions above: never lowered, forgotten with them. A client of
    /// the legacy profile never has one, and writes nothing of it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delegated: BTreeMap<RoleName, RoleState>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// An accepted timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampState {
    /// Its version.
    pub version: u64,
    /// What it listed for the snapshot.
    pub snapshot: MetaFile,
}

/// An accepted snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotState {
    /// Its version.
    pub version: u64,
    /// The version of every file it listed, by file name (`targets.json`).
    pub meta: std::collections::BTreeMap<String, u64>,
}

/// An accepted delegated role: its version, and the sha256 of the file accepted, the only
/// bytes [`super::TufClient::verify_cached_role`] takes for it offline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleState {
    /// Its version.
    pub version: u64,
    /// The sha256 of its file.
    pub sha256: Digest,
}

impl TrustState {
    /// What a store holds after `mine` is saved over `disk`, the state found there: nothing
    /// that either knows is lost.
    ///
    /// The newer root (by `root_version`) and its chain win. The accepted versions of the
    /// newer keys epoch win; within one epoch each role keeps the higher version. A version
    /// of a role is never lowered, and a root is never replaced by an older one.
    pub fn merged(disk: TrustState, mine: &TrustState) -> TrustState {
        let mine_root_is_newer = mine.root_version > disk.root_version
            || (mine.root_version == disk.root_version && mine.roots.len() > disk.roots.len());
        let (root_version, roots) = if mine_root_is_newer {
            (mine.root_version, mine.roots.clone())
        } else {
            (disk.root_version, disk.roots.clone())
        };
        let (timestamp, snapshot, targets, targets_file, delegated) =
            match disk.keys_epoch.cmp(&mine.keys_epoch) {
                std::cmp::Ordering::Greater => (
                    disk.timestamp,
                    disk.snapshot,
                    disk.targets,
                    disk.targets_file,
                    disk.delegated,
                ),
                std::cmp::Ordering::Less => (
                    mine.timestamp.clone(),
                    mine.snapshot.clone(),
                    mine.targets,
                    mine.targets_file.clone(),
                    mine.delegated.clone(),
                ),
                std::cmp::Ordering::Equal => {
                    // The file goes with the higher version; mine if they are equal.
                    let file = if disk.targets > mine.targets {
                        disk.targets_file
                    } else {
                        mine.targets_file.clone().or(disk.targets_file)
                    };
                    let mut delegated = disk.delegated;
                    for (role, accepted) in &mine.delegated {
                        // The higher version wins; mine if they are equal (as the targets
                        // file above).
                        let kept = delegated.entry(role.clone()).or_insert(*accepted);
                        if accepted.version >= kept.version {
                            *kept = *accepted;
                        }
                    }
                    (
                        newest(disk.timestamp, mine.timestamp.clone(), |t| t.version),
                        newest(disk.snapshot, mine.snapshot.clone(), |s| s.version),
                        disk.targets.max(mine.targets),
                        file,
                        delegated,
                    )
                }
            };
        TrustState {
            root_version,
            keys_epoch: disk.keys_epoch.max(mine.keys_epoch),
            roots,
            timestamp,
            snapshot,
            targets,
            targets_file,
            ever_published: disk.ever_published || mine.ever_published,
            delegated,
        }
    }

    /// Forgets the versions of the timestamp, snapshot, targets and delegated roles: they
    /// belong to keys that are no longer trusted, and the epoch `epoch` starts.
    pub(super) fn forget_versions(&mut self, epoch: u64) {
        self.timestamp = None;
        self.snapshot = None;
        self.targets = None;
        self.targets_file = None;
        self.delegated.clear();
        self.keys_epoch = epoch;
    }
}

/// The one of `a` and `b` with the higher `version` (`b` if equal).
fn newest<T>(a: Option<T>, b: Option<T>, version: impl Fn(&T) -> u64) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if version(&a) > version(&b) { a } else { b }),
        (a, None) => a,
        (None, b) => b,
    }
}

/// Where a [`TrustState`] is kept.
pub trait Store {
    /// The state saved last; an empty one ([`TrustState::default`]) if nothing was saved.
    ///
    /// # Errors
    ///
    /// [`TufError::Store`] if it cannot be read, or is not a state: then with the error kind
    /// [`io::ErrorKind::InvalidData`], which the client takes for a corrupt state and starts
    /// over from the built-in root; any other kind it passes on.
    fn load(&self) -> Result<TrustState, TufError>;

    /// Saves `state` merged with what the store holds ([`TrustState::merged`]), all or
    /// nothing, and returns the merged state. A store shared by processes does the whole
    /// step under one lock.
    ///
    /// # Errors
    ///
    /// [`TufError::Store`] if it cannot be written; [`TufError::StateTooLarge`] if the state is
    /// larger than [`MAX_STATE_LEN`].
    fn save(&mut self, state: &TrustState) -> Result<TrustState, TufError>;

    /// Replaces what the store holds by `state`, whatever it is: how a corrupt state is
    /// started over from.
    ///
    /// # Errors
    ///
    /// As [`Store::save`].
    fn overwrite(&mut self, state: &TrustState) -> Result<(), TufError>;
}

impl<S: Store + ?Sized> Store for &mut S {
    fn load(&self) -> Result<TrustState, TufError> {
        (**self).load()
    }

    fn save(&mut self, state: &TrustState) -> Result<TrustState, TufError> {
        (**self).save(state)
    }

    fn overwrite(&mut self, state: &TrustState) -> Result<(), TufError> {
        (**self).overwrite(state)
    }
}

/// A state kept in memory: for tests, and for a run that keeps nothing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemoryStore {
    /// The state.
    pub state: TrustState,
    /// How many times it was saved.
    pub saves: usize,
}

impl Store for MemoryStore {
    fn load(&self) -> Result<TrustState, TufError> {
        Ok(self.state.clone())
    }

    fn save(&mut self, state: &TrustState) -> Result<TrustState, TufError> {
        self.state = TrustState::merged(std::mem::take(&mut self.state), state);
        self.saves += 1;
        Ok(self.state.clone())
    }

    fn overwrite(&mut self, state: &TrustState) -> Result<(), TufError> {
        self.state = state.clone();
        self.saves += 1;
        Ok(())
    }
}

/// A state kept in a directory, `<dir>/state.json`, with a lock file `<dir>/lock` that
/// every save holds while it reads, merges and writes.
#[derive(Clone, Debug)]
pub struct FileStore {
    dir: PathBuf,
}

/// The file `FileStore` writes, in its directory.
pub const STATE_FILE: &str = "state.json";
/// The file `FileStore` locks, in its directory.
pub const LOCK_FILE: &str = "lock";

impl FileStore {
    /// A store in `dir`; the directory is created by the first save.
    pub fn new(dir: impl Into<PathBuf>) -> FileStore {
        FileStore { dir: dir.into() }
    }

    /// The store of an installation: `<data_dir>/update/tuf`, beside the updater's
    /// `state.json` ([`crate::State::path`]).
    pub fn in_data_dir(data_dir: &Path) -> FileStore {
        FileStore::new(data_dir.join("update").join("tuf"))
    }

    /// `<dir>/state.json`.
    pub fn path(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }

    /// Runs `f` holding the exclusive lock of the directory (waiting for another process's).
    fn locked<R>(&self, f: impl FnOnce() -> Result<R, TufError>) -> Result<R, TufError> {
        std::fs::create_dir_all(&self.dir)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.dir.join(LOCK_FILE))?;
        lock.lock()?;
        let result = f();
        // Closing the file releases the lock too; this says so.
        let _ = lock.unlock();
        result
    }

    fn read(&self) -> Result<TrustState, TufError> {
        let path = self.path();
        let bad = |why: String| invalid(format!("{}: {why}", path.display()));
        match std::fs::metadata(&path) {
            Ok(meta) if meta.len() > MAX_STATE_LEN => {
                return Err(bad(format!("larger than {MAX_STATE_LEN} bytes")).into());
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(TrustState::default()),
            Err(e) => return Err(e.into()),
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(TrustState::default()),
            Err(e) => return Err(e.into()),
        };
        let mut value = canonical::parse(&bytes, MAX_STATE_LEN, "the TUF state")
            .map_err(|e| bad(e.to_string()))?;
        let schema = value
            .as_object_mut()
            .and_then(|members| members.remove("schema"))
            .and_then(|schema| schema.as_u64())
            .ok_or_else(|| bad("no schema".to_owned()))?;
        if schema != u64::from(SCHEMA) {
            return Err(bad(format!("schema {schema} is not supported")).into());
        }
        serde_json::from_value(value).map_err(|e| bad(e.to_string()).into())
    }

    fn write(&self, state: &TrustState) -> Result<(), TufError> {
        let mut file = serde_json::to_value(state).map_err(io::Error::other)?;
        if let Some(members) = file.as_object_mut() {
            members.insert("schema".to_owned(), SCHEMA.into());
        }
        let mut body = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        body.push(b'\n');
        if body.len() as u64 > MAX_STATE_LEN {
            return Err(TufError::StateTooLarge(MAX_STATE_LEN));
        }
        write_atomically(&self.path(), &body, Access::Default)?;
        Ok(())
    }
}

fn invalid(why: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_string())
}

impl Store for FileStore {
    fn load(&self) -> Result<TrustState, TufError> {
        self.read()
    }

    fn save(&mut self, state: &TrustState) -> Result<TrustState, TufError> {
        self.locked(|| {
            // A corrupt file is what is being replaced: nothing in it is kept.
            let disk = match self.read() {
                Err(TufError::Store(e)) if e.kind() == io::ErrorKind::InvalidData => {
                    TrustState::default()
                }
                other => other?,
            };
            let merged = TrustState::merged(disk, state);
            self.write(&merged)?;
            Ok(merged)
        })
    }

    fn overwrite(&mut self, state: &TrustState) -> Result<(), TufError> {
        self.locked(|| self.write(state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tuf::model::Digest;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn root_file(version: u64) -> Envelope {
        Envelope {
            signed: json!({"_type": "root", "version": version}),
            signatures: vec![],
        }
    }

    fn ts(version: u64) -> TimestampState {
        TimestampState {
            version,
            snapshot: MetaFile {
                version: 7,
                length: Some(500),
                sha256: Some(Digest([9; 32])),
            },
        }
    }

    fn snap(version: u64) -> SnapshotState {
        SnapshotState {
            version,
            meta: BTreeMap::from([("targets.json".to_owned(), 3)]),
        }
    }

    fn state() -> TrustState {
        TrustState {
            root_version: 3,
            keys_epoch: 2,
            roots: vec![root_file(2), root_file(3)],
            timestamp: Some(ts(1_800_000_000)),
            snapshot: Some(snap(7)),
            targets: Some(3),
            targets_file: None,
            ever_published: false,
            delegated: BTreeMap::new(),
        }
    }

    #[test]
    fn a_saved_state_loads_back_and_replaces_the_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::in_data_dir(dir.path());
        assert_eq!(
            store.load().unwrap(),
            TrustState::default(),
            "nothing saved yet"
        );
        assert!(
            !dir.path().join("update").exists(),
            "loading writes nothing"
        );

        assert_eq!(store.save(&state()).unwrap(), state());
        assert_eq!(store.load().unwrap(), state());
        assert_eq!(
            store.path(),
            dir.path().join("update").join("tuf").join("state.json")
        );

        let mut newer = state();
        newer.targets = Some(4);
        store.save(&newer).unwrap();
        assert_eq!(FileStore::in_data_dir(dir.path()).load().unwrap(), newer);
        let mut names: Vec<_> = std::fs::read_dir(dir.path().join("update").join("tuf"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["lock", "state.json"], "no temporary file stays");
    }

    #[test]
    fn a_corrupt_state_is_invalid_data_to_load_and_replaced_by_a_save() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::new(dir.path());
        store.save(&state()).unwrap();
        let good = std::fs::read_to_string(store.path()).unwrap();
        for (name, body) in [
            ("not json", "nope".to_owned()),
            (
                "other schema",
                good.replace("\"schema\": 1", "\"schema\": 2"),
            ),
            ("no schema", r#"{"targets": 1}"#.to_owned()),
            ("unknown member", good.replacen('{', "{\"later\": 1,", 1)),
            ("duplicate key", r#"{"schema": 1, "schema": 1}"#.to_owned()),
            ("bad version", r#"{"schema": 1, "targets": "x"}"#.to_owned()),
            (
                "an old accepted member",
                good.replacen('{', "{\"accepted\": {},", 1),
            ),
        ] {
            std::fs::write(store.path(), body).unwrap();
            match store.load() {
                Err(TufError::Store(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{name}")
                }
                other => panic!("{name}: {other:?}"),
            }
            // A save does not trip over it: what is there is not kept.
            assert_eq!(store.save(&state()).unwrap(), state(), "{name}");
            assert_eq!(store.load().unwrap(), state(), "{name}");
        }
    }

    #[test]
    fn the_state_file_has_the_same_size_limit_when_read_and_when_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::new(dir.path());
        store.save(&state()).unwrap();
        // Too large to write: refused, and the file that was there is untouched.
        let mut big = state();
        big.roots = (0..40_000).map(root_file).collect();
        big.root_version = 40_000;
        assert!(matches!(
            store.save(&big),
            Err(TufError::StateTooLarge(MAX_STATE_LEN))
        ));
        assert!(matches!(
            store.overwrite(&big),
            Err(TufError::StateTooLarge(_))
        ));
        assert_eq!(store.load().unwrap(), state());
        // Too large to read: not read at all, an invalid state.
        let huge = vec![b' '; MAX_STATE_LEN as usize + 1];
        std::fs::write(store.path(), huge).unwrap();
        match store.load() {
            Err(TufError::Store(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn saving_never_lowers_a_version_or_replaces_a_root_by_an_older_one() {
        let mut s = MemoryStore::default();
        s.save(&state()).unwrap();
        // An older view of the same epoch and root: nothing goes down.
        let older = TrustState {
            root_version: 3,
            keys_epoch: 2,
            roots: vec![root_file(2), root_file(3)],
            timestamp: Some(ts(5)),
            snapshot: Some(snap(1)),
            targets: Some(1),
            targets_file: None,
            ever_published: false,
            delegated: BTreeMap::new(),
        };
        assert_eq!(s.save(&older).unwrap(), state());
        // An older root with higher versions of its own: the root stays, the versions of the
        // same epoch are the highest of both.
        let stale_root = TrustState {
            root_version: 2,
            keys_epoch: 2,
            roots: vec![root_file(2)],
            timestamp: Some(ts(2_000_000_000)),
            snapshot: None,
            targets: None,
            targets_file: None,
            ever_published: false,
            delegated: BTreeMap::new(),
        };
        let merged = s.save(&stale_root).unwrap();
        assert_eq!(merged.root_version, 3);
        assert_eq!(merged.roots.len(), 2);
        assert_eq!(merged.timestamp.unwrap().version, 2_000_000_000);
        assert_eq!(merged.snapshot.unwrap().version, 7);
        assert_eq!(merged.targets, Some(3));
        // A newer root with a newer epoch (the keys rotated) starts the versions over; the
        // older epoch cannot bring them back.
        let rotated = TrustState {
            root_version: 4,
            keys_epoch: 4,
            roots: vec![root_file(2), root_file(3), root_file(4)],
            timestamp: None,
            snapshot: None,
            targets: None,
            targets_file: None,
            ever_published: false,
            delegated: BTreeMap::new(),
        };
        let merged = s.save(&rotated).unwrap();
        assert_eq!((merged.root_version, merged.keys_epoch), (4, 4));
        assert!(
            merged.timestamp.is_none() && merged.snapshot.is_none() && merged.targets.is_none()
        );
        let merged = s.save(&state()).unwrap();
        assert_eq!(merged.roots.len(), 3);
        assert!(
            merged.timestamp.is_none(),
            "the versions of the old keys do not come back"
        );
        // The newer epoch's versions come in.
        let mut fresh = rotated.clone();
        fresh.timestamp = Some(ts(10));
        assert_eq!(s.save(&fresh).unwrap().timestamp.unwrap().version, 10);
    }

    #[test]
    fn delegated_role_versions_merge_without_going_down_and_go_with_their_epoch() {
        let role = |name: &str| RoleName::parse(name).unwrap();
        let accepted = |version: u64| RoleState {
            version,
            sha256: Digest([version as u8; 32]),
        };
        let with = |epoch: u64, roles: &[(&str, u64)]| TrustState {
            keys_epoch: epoch,
            delegated: roles.iter().map(|(n, v)| (role(n), accepted(*v))).collect(),
            ..TrustState::default()
        };
        let mut s = MemoryStore::default();
        s.save(&with(2, &[("pub-ecc", 5), ("pub-abc", 1)])).unwrap();
        let merged = s.save(&with(2, &[("pub-ecc", 3), ("pub-xyz", 2)])).unwrap();
        assert_eq!(
            merged.delegated,
            with(2, &[("pub-ecc", 5), ("pub-abc", 1), ("pub-xyz", 2)]).delegated
        );
        // A newer epoch replaces them; an older one cannot bring them back.
        let merged = s.save(&with(3, &[("pub-ecc", 1)])).unwrap();
        assert_eq!(merged.delegated, with(3, &[("pub-ecc", 1)]).delegated);
        let merged = s.save(&with(2, &[("pub-ecc", 9)])).unwrap();
        assert_eq!(merged.delegated, with(3, &[("pub-ecc", 1)]).delegated);
    }

    #[test]
    fn a_state_with_delegated_roles_loads_back_and_one_without_writes_none() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::new(dir.path());
        store.save(&state()).unwrap();
        let text = std::fs::read_to_string(store.path()).unwrap();
        assert!(!text.contains("delegated"), "{text}");
        let mut with_roles = state();
        with_roles.delegated.insert(
            RoleName::parse("pub-ecc").unwrap(),
            RoleState {
                version: 4,
                sha256: Digest([4; 32]),
            },
        );
        store.save(&with_roles).unwrap();
        assert_eq!(store.load().unwrap(), with_roles);
    }

    #[test]
    fn of_two_files_of_one_role_version_the_one_saved_last_is_kept() {
        let role = RoleName::parse("pub-ecc").unwrap();
        let with = |sum: u8| TrustState {
            delegated: [(
                role.clone(),
                RoleState {
                    version: 3,
                    sha256: Digest([sum; 32]),
                },
            )]
            .into(),
            ..TrustState::default()
        };
        let mut s = MemoryStore::default();
        s.save(&with(1)).unwrap();
        assert_eq!(s.save(&with(2)).unwrap(), with(2));
    }

    #[test]
    fn two_stores_of_one_directory_do_not_lose_each_others_updates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_owned();
        let run = |kind: u8| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut store = FileStore::new(path);
                let mut last = TrustState::default();
                for n in 1..=60u64 {
                    // One writer advances the timestamp and root, the other the snapshot
                    // and targets, each with a state that knows nothing of the other's.
                    let mine = match kind {
                        0 => TrustState {
                            root_version: n,
                            roots: (2..=n).map(root_file).collect(),
                            timestamp: Some(ts(n)),
                            ..TrustState::default()
                        },
                        _ => TrustState {
                            snapshot: Some(snap(n)),
                            targets: Some(n),
                            ..TrustState::default()
                        },
                    };
                    let merged = store.save(&mine).unwrap();
                    // No version this writer has seen goes down.
                    assert!(merged.root_version >= last.root_version);
                    assert!(
                        merged.timestamp.as_ref().map(|t| t.version)
                            >= last.timestamp.as_ref().map(|t| t.version)
                    );
                    assert!(
                        merged.snapshot.as_ref().map(|t| t.version)
                            >= last.snapshot.as_ref().map(|t| t.version)
                    );
                    assert!(merged.targets >= last.targets);
                    last = merged;
                }
            })
        };
        let (a, b) = (run(0), run(1));
        a.join().unwrap();
        b.join().unwrap();
        let end = FileStore::new(dir.path()).load().unwrap();
        assert_eq!(end.root_version, 60);
        assert_eq!(end.roots.len(), 59);
        assert_eq!(end.timestamp.unwrap().version, 60);
        assert_eq!(end.snapshot.unwrap().version, 60);
        assert_eq!(end.targets, Some(60));
    }

    #[test]
    fn the_memory_store_keeps_counts_and_can_be_overwritten() {
        let mut store = MemoryStore::default();
        assert_eq!(store.load().unwrap(), TrustState::default());
        store.save(&state()).unwrap();
        assert_eq!((store.load().unwrap(), store.saves), (state(), 1));
        let by_ref: &mut MemoryStore = &mut store;
        by_ref.overwrite(&TrustState::default()).unwrap();
        assert_eq!((store.state, store.saves), (TrustState::default(), 2));
    }
}
