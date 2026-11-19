//! A TUF repository for the tests of whoever consumes this crate (feature `testing`): the
//! updater, the plugin catalog and their stores read their indexes through [`TufClient`], so
//! their tests serve one of these.
//!
//! The keys are **synthetic**, derived from fixed seeds: they sign nothing real. A
//! repository is made as the maintainer's tools make it ([`super::build`]), root 1 first,
//! then one publication per [`Repo::publish`]: targets, snapshot and timestamp each with
//! their own version and expiry, under consistent-snapshot names ([`super::layout`]).

use std::collections::BTreeMap;

use serde_json::Value;
use time::{Duration, OffsetDateTime};

use super::build::{self, RoleDef, RootDef};
use super::fetch::MemoryFetcher;
use super::layout;
use super::{Profile, SigningKey, TufClient};
use crate::Channel;

/// How long each role stays valid from the moment of signing, the design's values by
/// default (`docs/design/tuf.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lifetimes {
    /// 365 days.
    pub root: Duration,
    /// 7 days.
    pub timestamp: Duration,
    /// 30 days.
    pub snapshot: Duration,
    /// 30 days.
    pub targets: Duration,
}

impl Default for Lifetimes {
    fn default() -> Lifetimes {
        Lifetimes {
            root: Duration::days(365),
            timestamp: Duration::days(7),
            snapshot: Duration::days(30),
            targets: Duration::days(30),
        }
    }
}

/// A repository with root 1 of synthetic keys, and what has been published into it.
pub struct Repo {
    timestamp: SigningKey,
    snapshot: SigningKey,
    targets: SigningKey,
    anchor: Vec<u8>,
    files: BTreeMap<String, Vec<u8>>,
    indexes: BTreeMap<String, Vec<u8>>,
    /// The moment of the next signature: the roles expire [`Repo::lifetimes`] after it. The
    /// clock of the repository's creation until a test sets another.
    pub signed_at: OffsetDateTime,
    /// How long each role signed next stays valid.
    pub lifetimes: Lifetimes,
    /// The version of the targets and snapshot published next.
    pub next_version: u64,
    /// The version of the timestamp published next (it grows by one with each publication,
    /// as a timestamp signed later has a higher version).
    pub next_timestamp: u64,
    /// The `delegations` member of the top-level targets published next, as it is signed
    /// (`None`: no member). Anything, also what no client can read as delegations.
    pub delegations: Option<Value>,
}

impl Repo {
    /// A repository of the keys of `seed` (a different seed, different keys), root 1 valid
    /// for [`Lifetimes::root`] from now. Nothing is published yet.
    ///
    /// # Panics
    ///
    /// Never for a seed up to 252: the four keys are derived from it.
    pub fn with_seed(seed: u8) -> Repo {
        let key = |n: u8| SigningKey::from_seed(&[seed + n; 32]).expect("a 32-byte seed");
        let (root, timestamp, snapshot, targets) = (key(0), key(1), key(2), key(3));
        let signed_at = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let lifetimes = Lifetimes::default();
        let role = |key: &SigningKey| RoleDef {
            keys: vec![key.public()],
            threshold: 1,
        };
        let def = RootDef {
            root: role(&root),
            timestamp: role(&timestamp),
            snapshot: role(&snapshot),
            targets: role(&targets),
        };
        let signed =
            build::root(1, signed_at + lifetimes.root, &def).expect("a root of four roles");
        let anchor = build::sign(&signed, &[&root]).expect("a root file");
        let mut files = BTreeMap::new();
        files.insert(layout::root_path(1), anchor.clone());
        Repo {
            timestamp,
            snapshot,
            targets,
            anchor,
            files,
            indexes: BTreeMap::new(),
            signed_at,
            lifetimes,
            next_version: 1,
            next_timestamp: 1_000_000,
            delegations: None,
        }
    }

    /// [`Repo::with_seed`] 1.
    pub fn new() -> Repo {
        Repo::with_seed(1)
    }

    /// The trust anchor: root 1, what the client is built with.
    pub fn anchor(&self) -> &[u8] {
        &self.anchor
    }

    /// Publishes the index `bytes` of `channel` (the others stay as they were published):
    /// signs new targets, snapshot and timestamp at [`Repo::signed_at`] and puts them and the
    /// index under their consistent-snapshot names.
    pub fn publish(&mut self, channel: Channel, bytes: &[u8]) {
        self.indexes.insert(channel.target_path(), bytes.to_vec());
        let version = self.next_version;
        let timestamp_version = self.next_timestamp;
        self.next_version += 1;
        self.next_timestamp += 1;
        let at = self.signed_at;
        let listed: Vec<(&str, &[u8])> = self
            .indexes
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
            .collect();
        let mut targets_signed = build::targets(version, at + self.lifetimes.targets, &listed)
            .expect("targets of valid paths");
        if let (Some(delegations), Some(members)) =
            (&self.delegations, targets_signed.as_object_mut())
        {
            members.insert("delegations".to_owned(), delegations.clone());
        }
        let targets = build::sign(&targets_signed, &[&self.targets]).expect("a targets file");
        let snapshot_signed =
            build::snapshot(version, at + self.lifetimes.snapshot, version, &targets)
                .expect("a snapshot");
        let snapshot = build::sign(&snapshot_signed, &[&self.snapshot]).expect("a snapshot file");
        let timestamp_signed = build::timestamp(
            timestamp_version,
            at + self.lifetimes.timestamp,
            version,
            &snapshot,
        )
        .expect("a timestamp");
        let timestamp = build::sign(&timestamp_signed, &[&self.timestamp]).expect("a file");
        for (path, content) in build::target_files(&listed).expect("target files") {
            self.files.insert(path, content);
        }
        self.files.insert(layout::targets_path(version), targets);
        self.files.insert(layout::snapshot_path(version), snapshot);
        self.files
            .insert(layout::TIMESTAMP_PATH.to_owned(), timestamp);
    }

    /// Every file of the repository, by its path under the base.
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// The file at `path`.
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Puts `bytes` at `path`, replacing the file: how a test serves a tampered or older one.
    pub fn put(&mut self, path: &str, bytes: Vec<u8>) {
        self.files.insert(path.to_owned(), bytes);
    }

    /// The path of the index file of `channel` as published last, under its hash name.
    ///
    /// # Panics
    ///
    /// If nothing was published for the channel.
    pub fn index_file_path(&self, channel: Channel) -> String {
        let target = channel.target_path();
        let bytes = self.indexes.get(&target).expect("a published channel");
        let target = super::TargetPath::parse(&target).expect("a valid path");
        layout::target_file_path(&target, &super::Digest::of(bytes))
    }

    /// The files in a [`MemoryFetcher`].
    pub fn fetcher(&self) -> MemoryFetcher {
        let fetcher = MemoryFetcher::new();
        for (path, bytes) in &self.files {
            fetcher.put(path.clone(), bytes.clone());
        }
        fetcher
    }

    /// A client of `fetcher` and `store` that trusts this repository's root, in the profile
    /// of the program ([`Profile::Delegating`]).
    ///
    /// # Panics
    ///
    /// Never: the root is made here.
    pub fn client<F: super::Fetcher, S: super::Store>(
        &self,
        fetcher: F,
        store: S,
    ) -> TufClient<F, S> {
        TufClient::new(&self.anchor, fetcher, store, super::Limits::default())
            .expect("this repository's own root")
            .with_profile(Profile::Delegating)
    }
}

impl Default for Repo {
    fn default() -> Repo {
        Repo::new()
    }
}
