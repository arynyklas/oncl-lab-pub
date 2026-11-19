//! The TUF client: the "detailed client workflow" of the specification (version 1.0.37,
//! section 5), step by step, over a [`Fetcher`] and a [`Store`]. Step numbers in the
//! comments are that section's.
//!
//! Nothing here touches the network or the disk except through those two traits, and the
//! verification itself (the model, canonical JSON, signatures) is in modules that touch
//! neither.
//!
//! What differs from the specification, all of it stricter or a recovery the specification
//! leaves open:
//!
//! - hashes and lengths a role lists are enforced exactly (a file of another length is
//!   refused, not just a file over it);
//! - a timestamp of the version already trusted is not a reason to stop (the snapshot and
//!   targets are fetched anyway, from names that carry their version) but it must list the
//!   same snapshot;
//! - when a new root changes the keys or threshold of the timestamp, snapshot **or targets**
//!   role, the stored versions of all three are forgotten (step 5.3.11 names the first two;
//!   without the third, a targets key rotated after a fast-forward could never recover);
//! - the roots followed are saved with that deletion in one atomic write, before the expiry
//!   of the final root is checked (step 5.3.10), and also when a root further on is refused:
//!   a root that is too old to use is still remembered, the keys it rotated are still
//!   forgotten, and a chain too long for one refresh is followed in several;
//! - what is saved is the whole chain of roots from the built-in one; a later run checks it
//!   again from the built-in root, both thresholds at every step, before it trusts any of it
//!   (a saved root alone, signed by its own keys, would be whatever whoever writes the
//!   state says). A state that is not a state, or whose chain does not hold, is dropped and
//!   the run starts from the built-in root ([`Trusted::state_was_reset`]);
//! - a built-in root newer than the saved state drops the versions saved before it (its keys
//!   cannot be compared with those of roots it does not chain from);
//! - the targets file accepted is saved beside its version, so that a target kept from an
//!   earlier download can be checked again offline ([`TufClient::verify_cached_target`]);
//! - the profile ([`Profile`], [`Profile::Delegating`] unless set) only says how the
//!   top-level targets are read: in [`Profile::Legacy`], the model of the clients released
//!   before delegations, a `delegations` member refuses them; in [`Profile::Delegating`] the
//!   member is kept unread, so the program's updates ([`TufClient::refresh`], step 5.6.7 in
//!   the top-level targets only) never depend on it;
//! - the delegations are read apart, by [`TufClient::delegated`] (the updater of the program
//!   never needs a publisher's role); a role's file must be listed by the snapshot with its
//!   length and sha256 ([`DelegationError::Unhashed`]), other entries need not be.
//!   Step 5.6.7 searches for one target; the plugin catalog needs every target of every
//!   publisher, so `delegated` visits every delegated role with the same bounds: in order,
//!   each name once, at most [`Limits::max_delegations`], every target inside the role's
//!   paths. With the profile's disjoint, terminating, one-level delegations that gives, for
//!   any path, the answer the search of 5.6.7 gives. Stricter than the specification: a role
//!   that lists a target outside its paths, or delegates further, is not trusted at all, and
//!   the profile of each delegation ([`super::delegation`]) is enforced; and one role that is
//!   not trusted never touches the others or the top-level metadata.

use std::collections::{BTreeMap, BTreeSet};

use time::OffsetDateTime;

use super::delegation::{DelegatedRole, Delegations, RefusedRole};
use super::ed25519::{verify_role, verify_threshold};
use super::error::{DelegationError, Role, TufError};
use super::fetch::{Fetcher, Response};
use super::layout;
use super::model::{
    Digest, Envelope, MetaFile, Profile, Root, Snapshot, TARGETS_META, Target, Targets, Timestamp,
    ensure_fresh,
};
use super::names::{RoleName, TargetPath};
use super::store::{RoleState, SnapshotState, Store, TimestampState, TrustState};

/// The most each kind of file may be, when its size is not listed by the role above (and the
/// most a listed size may be).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// A root file (the size is unknown: the specification's W).
    pub root: u64,
    /// The timestamp (X).
    pub timestamp: u64,
    /// The snapshot (Y).
    pub snapshot: u64,
    /// The targets (Z).
    pub targets: u64,
    /// How many new roots one refresh follows (the specification's Y of step 5.3.3).
    pub max_roots: u32,
    /// A delegated role's file.
    pub delegated: u64,
    /// How many delegated roles [`TufClient::delegated`] follows; the roles after them are
    /// not trusted ([`DelegationError::TooMany`]).
    pub max_delegations: u32,
    /// How many targets a delegated role may list; a role that lists more is not trusted
    /// ([`DelegationError::TooManyTargets`]).
    pub max_role_targets: u32,
}

impl Default for Limits {
    /// 64 KiB per root, 16 KiB for the timestamp, 128 KiB for the snapshot, 256 KiB for the
    /// targets, 128 roots, 128 KiB per delegated role, 32 delegated roles, 256 targets per
    /// delegated role.
    fn default() -> Self {
        Limits {
            root: 64 << 10,
            timestamp: 16 << 10,
            snapshot: 128 << 10,
            targets: 256 << 10,
            max_roots: 128,
            delegated: 128 << 10,
            max_delegations: 32,
            max_role_targets: 256,
        }
    }
}

/// A delegated role that passed every check: signed by a threshold of the keys its
/// delegation names, the version the snapshot lists (or the version saved), not older than
/// one trusted before, not expired, no further delegations, every target inside its paths.
/// Only [`TufClient::delegated`] and [`TufClient::verify_cached_role`] make one.
#[derive(Clone, Debug)]
pub struct VerifiedRole {
    name: RoleName,
    targets: Targets,
    file: Vec<u8>,
    valid_until: OffsetDateTime,
}

impl VerifiedRole {
    /// The role.
    pub fn name(&self) -> &RoleName {
        &self.name
    }

    /// Its version.
    pub fn version(&self) -> u64 {
        self.targets.version
    }

    /// When the role's own file stops being trusted.
    pub fn expires(&self) -> OffsetDateTime {
        self.targets.expires
    }

    /// The earliest moment the role, or the metadata it was checked against, stops being
    /// trusted: for [`TufClient::delegated`] also the four top-level files, for
    /// [`TufClient::verify_cached_role`] the root and the top-level targets.
    pub fn valid_until(&self) -> OffsetDateTime {
        self.valid_until
    }

    /// The role's targets, every one inside its paths.
    pub fn targets(&self) -> &BTreeMap<TargetPath, Target> {
        &self.targets.targets
    }

    /// What the role says of the target `path`.
    pub fn target(&self, path: &str) -> Option<&Target> {
        self.targets.targets.get(path)
    }

    /// The role's file as it was checked: what a caller keeps to check it again offline
    /// ([`TufClient::verify_cached_role`]).
    pub fn file(&self) -> &[u8] {
        &self.file
    }
}

/// What [`TufClient::delegated`] found: each delegated role of the top-level targets, in
/// their order, trusted or with the reason it is not.
#[derive(Debug)]
pub struct Delegated {
    roles: Vec<(RoleName, Result<VerifiedRole, TufError>)>,
}

impl Delegated {
    /// Every role, in the order of the delegations.
    pub fn roles(&self) -> impl Iterator<Item = (&RoleName, Result<&VerifiedRole, &TufError>)> {
        self.roles.iter().map(|(name, role)| (name, role.as_ref()))
    }

    /// The role `name`, if the top-level targets delegate to it.
    pub fn role(&self, name: &RoleName) -> Option<Result<&VerifiedRole, &TufError>> {
        self.roles
            .iter()
            .find(|(role, _)| role == name)
            .map(|(_, role)| role.as_ref())
    }

    /// Every role, in the order of the delegations, owned.
    pub fn into_roles(self) -> Vec<(RoleName, Result<VerifiedRole, TufError>)> {
        self.roles
    }
}

/// The verified metadata of one [`TufClient::refresh`]: only what passed every check, and
/// the only way to name a target to [`TufClient::download_target`].
#[derive(Clone, Debug)]
pub struct Trusted {
    root: Root,
    timestamp: Timestamp,
    snapshot: Snapshot,
    targets: Targets,
    reset: Option<String>,
}

impl Trusted {
    /// Why this refresh started from the built-in root, ignoring the saved state: it was
    /// not readable, or did not hold up. The caller logs it; the state was replaced.
    pub fn state_was_reset(&self) -> Option<&str> {
        self.reset.as_deref()
    }

    /// The root in force.
    pub fn root(&self) -> &Root {
        &self.root
    }

    /// The timestamp.
    pub fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// The snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// The targets metadata.
    pub fn targets(&self) -> &Targets {
        &self.targets
    }

    /// What the targets metadata says of the target `path`.
    pub fn target(&self, path: &str) -> Option<&Target> {
        self.targets.targets.get(path)
    }

    /// The earliest moment one of the four files stops being trusted.
    pub fn expires(&self) -> OffsetDateTime {
        self.root
            .expires
            .min(self.timestamp.expires)
            .min(self.snapshot.expires)
            .min(self.targets.expires)
    }

    /// `Ok` if none of the four files has expired at `now`: metadata that was fresh when it
    /// was refreshed is not fresh for ever.
    ///
    /// # Errors
    ///
    /// [`TufError::Expired`] for the first of root, timestamp, snapshot, targets that has.
    pub fn ensure_fresh(&self, now: OffsetDateTime) -> Result<(), TufError> {
        ensure_fresh(Role::Root, self.root.expires, now)?;
        ensure_fresh(Role::Timestamp, self.timestamp.expires, now)?;
        ensure_fresh(Role::Snapshot, self.snapshot.expires, now)?;
        ensure_fresh(Role::Targets, self.targets.expires, now)
    }
}

/// A TUF repository's client.
pub struct TufClient<F, S> {
    fetcher: F,
    store: S,
    /// The root built into the program.
    anchor: Root,
    limits: Limits,
    profile: Profile,
    /// Why the last refresh that reset the saved state did (also when it then failed).
    last_reset: Option<String>,
}

impl<F: Fetcher, S: Store> TufClient<F, S> {
    /// A client of the repository `fetcher` reads, trusting `trust_anchor`: the bytes of a
    /// root file (`keys/root.json`, [`crate::embedded_root`]), signed by its own keys. Its
    /// expiry does not matter: the first refresh looks for a newer one. It reads in
    /// [`Profile::Delegating`], as the program from 0.1.2 does.
    ///
    /// # Errors
    ///
    /// The errors of [`Envelope::parse`] and [`Root::from_signed`], and
    /// [`TufError::Signature`] if the root is not signed by a threshold of its own root keys.
    pub fn new(
        trust_anchor: &[u8],
        fetcher: F,
        store: S,
        limits: Limits,
    ) -> Result<TufClient<F, S>, TufError> {
        let envelope = Envelope::parse(trust_anchor, limits.root, "the built-in root")?;
        let root = Root::from_signed(&envelope.signed)?;
        verify_role(&envelope, &root, Role::Root, "the built-in root")?;
        Ok(TufClient {
            fetcher,
            store,
            anchor: root,
            limits,
            last_reset: None,
            profile: Profile::Delegating,
        })
    }

    /// This client with the repository profile `profile` ([`Profile::Delegating`] unless
    /// set; [`Profile::Legacy`] tells what the clients released before delegations read).
    #[must_use]
    pub fn with_profile(mut self, profile: Profile) -> TufClient<F, S> {
        self.profile = profile;
        self
    }

    /// The repository profile this client reads.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// A client trusting the root built into this program, or `None` if the build has none:
    /// then there is no way to trust a repository, and updates are off.
    ///
    /// # Errors
    ///
    /// As [`TufClient::new`] (which the build already checked structurally).
    pub fn with_embedded_root(
        fetcher: F,
        store: S,
        limits: Limits,
    ) -> Result<Option<TufClient<F, S>>, TufError> {
        TufClient::with_root(crate::embedded_root(), fetcher, store, limits)
    }

    /// [`TufClient::with_embedded_root`] for the root `trust_anchor`, if there is one.
    pub(crate) fn with_root(
        trust_anchor: Option<&[u8]>,
        fetcher: F,
        store: S,
        limits: Limits,
    ) -> Result<Option<TufClient<F, S>>, TufError> {
        trust_anchor
            .map(|root| TufClient::new(root, fetcher, store, limits))
            .transpose()
    }

    /// Why the last refresh that reset the saved state did so, if one did, whether or not it
    /// went on to succeed (it is logged as a warning when it happens).
    pub fn last_reset(&self) -> Option<&str> {
        self.last_reset.as_deref()
    }

    /// The store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The fetcher.
    pub fn fetcher(&self) -> &F {
        &self.fetcher
    }

    /// Updates the metadata (steps 5.1 to 5.6): the chain of roots, then the timestamp,
    /// snapshot and targets, each checked against the trusted one above it, and saves what
    /// it accepted. `now` is the fixed update start time of 5.1: every expiry is checked
    /// against it.
    ///
    /// On an error nothing from the failing file onward is trusted; what was accepted
    /// before it stays saved, as the specification says: the roots followed before a root
    /// that is refused (or before the limit of roots one refresh follows), the timestamp
    /// before a snapshot that is refused, and so on.
    ///
    /// # Errors
    ///
    /// A [`TufError`] naming the check that failed: a signature below its threshold, a
    /// version that went back or is not the one listed, a hash or length that does not
    /// match, an expired file, a file that is not there, a chain of roots longer than
    /// [`Limits::max_roots`], or a store that cannot be written.
    pub fn refresh(&mut self, now: OffsetDateTime) -> Result<Trusted, TufError> {
        // 5.1: `now` is the fixed update start time.
        let (mut state, mut reset) = match self.store.load() {
            Ok(state) => (state, None),
            Err(TufError::Store(e)) if e.kind() == std::io::ErrorKind::InvalidData => (
                TrustState::default(),
                Some(format!("the saved state is not readable: {e}")),
            ),
            Err(e) => return Err(e),
        };
        // 5.2: the trusted root: the built-in one, and the saved chain after it if it holds.
        let loaded = state.clone();
        let mut root = match self.replay(&mut state) {
            Ok(root) => root,
            Err(why) => {
                state = TrustState::default();
                reset.get_or_insert(why);
                self.anchor.clone()
            }
        };
        if let Some(why) = &reset {
            tracing::warn!(reason = %why, "the saved TUF state was reset to the built-in root");
            self.last_reset = Some(why.clone());
        }
        if reset.is_some() {
            state.root_version = root.version;
            // Nothing can be known of what a state that did not hold had seen.
            state.ever_published = true;
            self.store.overwrite(&state)?;
        }

        // 5.3: the root chain.
        let mut downloaded = 0u32;
        let mut chain_error = None;
        // 5.3.2-5.3.3: N is the trusted version; try N+1.
        while let Some(next) = root.version.checked_add(1) {
            let path = layout::root_path(next);
            let body = match self.get(&path, self.limits.root) {
                Ok(Some(body)) => body,
                // 5.3.3: not available, go to 5.3.10.
                Ok(None) => break,
                Err(e) => {
                    chain_error = Some(e);
                    break;
                }
            };
            if downloaded >= self.limits.max_roots {
                // 5.3.3: more than Y roots: the chain ends here only if there is no more.
                chain_error = Some(TufError::RootChainTooLong(self.limits.max_roots));
                break;
            }
            downloaded += 1;
            match self.follow_root(&root, next, &body, &path) {
                Ok((file, new_root)) => {
                    // 5.3.6: the expiry of an intermediate root does not matter yet.
                    // 5.3.11: if the timestamp, snapshot (or targets) keys were rotated, the
                    // versions trusted before are forgotten.
                    if root.rotates(&new_root) {
                        state.forget_versions(new_root.version);
                    }
                    // 5.3.7: the new root is the trusted root.
                    state.roots.push(file);
                    state.root_version = new_root.version;
                    root = new_root;
                    // 5.3.9: repeat.
                }
                Err(e) => {
                    chain_error = Some(e);
                    break;
                }
            }
        }
        // 5.3.8: persist the roots followed, and what 5.3.11 dropped, in one write, also if
        // a root further on was refused (and before the expiry check below: a root too old
        // to use would otherwise be saved without the deletion).
        if state != loaded {
            state = self.store.save(&state)?;
        }
        if let Some(e) = chain_error {
            return Err(e);
        }
        // 5.3.10: a freeze attack, or a repository nobody re-signed.
        ensure_fresh(Role::Root, root.expires, now)?;
        // 5.3.12: consistent snapshots: `Root::from_signed` refuses a root without them.

        // 5.4: the timestamp.
        let timestamp = self.update_timestamp(&mut state, &root, now)?;
        // 5.5: the snapshot.
        let snapshot = self.update_snapshot(&mut state, &root, &timestamp, now)?;
        // 5.6: the targets.
        let targets = self.update_targets(&mut state, &root, &snapshot, now)?;
        Ok(Trusted {
            root,
            timestamp,
            snapshot,
            targets,
            reset,
        })
    }

    /// 5.3.4-5.3.5: the root file `body` as version `next` after `root`, the trusted one.
    fn follow_root(
        &self,
        root: &Root,
        next: u64,
        body: &[u8],
        path: &str,
    ) -> Result<(Envelope, Root), TufError> {
        let file = Envelope::parse(body, self.limits.root, path)?;
        accept_root(root, next, file)
    }

    /// 5.2: checks the saved chain of roots again from the built-in one, drops the entries
    /// the built-in root has overtaken, and returns the root in force. `Err` says why the
    /// state does not hold. If the built-in root is newer than the state, what was saved of
    /// the timestamp, snapshot and targets goes too.
    fn replay(&self, state: &mut TrustState) -> Result<Root, String> {
        let anchor = &self.anchor;
        let mut trusted = anchor.clone();
        let mut kept = Vec::new();
        for (i, file) in state.roots.iter().enumerate() {
            let root = Root::from_signed(&file.signed)
                .map_err(|e| format!("saved root #{} is not a root: {e}", i + 1))?;
            if root.version <= anchor.version {
                continue; // The built-in root has overtaken it.
            }
            let (file, root) =
                accept_root(&trusted, trusted.version + 1, file.clone()).map_err(|e| {
                    format!(
                        "saved root {} does not follow the built-in root: {e}",
                        root.version
                    )
                })?;
            kept.push(file);
            trusted = root;
        }
        if state.root_version > trusted.version {
            return Err(format!(
                "the saved state is of root {}, its chain ends at {}",
                state.root_version, trusted.version
            ));
        }
        if state.root_version != 0 && state.root_version < anchor.version {
            // A built-in root newer than anything saved: the keys of the roles in between
            // are not known, so the versions saved under them are not kept.
            state.forget_versions(anchor.version);
        }
        state.roots = kept;
        state.root_version = trusted.version;
        Ok(trusted)
    }

    fn update_timestamp(
        &mut self,
        state: &mut TrustState,
        root: &Root,
        now: OffsetDateTime,
    ) -> Result<Timestamp, TufError> {
        // 5.4.1: download it, up to X bytes.
        let body = self.get_required(layout::TIMESTAMP_PATH, self.limits.timestamp)?;
        let file = Envelope::parse(&body, self.limits.timestamp, "timestamp.json")?;
        // 5.4.2: signed by a threshold of the timestamp keys of the trusted root.
        verify_role(&file, root, Role::Timestamp, "the timestamp")?;
        let timestamp = Timestamp::from_signed(&file.signed)?;
        // 5.4.3: a rollback attack.
        if let Some(trusted) = &state.timestamp {
            // 5.4.3.1: the version must not be below the trusted one. An equal one is the
            // same timestamp (and then the rest of the update goes on, see the module's
            // description), unless it lists another snapshot.
            if timestamp.version < trusted.version {
                return Err(TufError::Rollback {
                    what: "timestamp".to_owned(),
                    found: timestamp.version,
                    trusted: trusted.version,
                });
            }
            if timestamp.version == trusted.version && timestamp.snapshot != trusted.snapshot {
                return Err(TufError::TimestampChanged(timestamp.version));
            }
            // 5.4.3.2: the snapshot it lists is not older than the trusted one's.
            if timestamp.snapshot.version < trusted.snapshot.version {
                return Err(TufError::Rollback {
                    what: "snapshot listed by the timestamp".to_owned(),
                    found: timestamp.snapshot.version,
                    trusted: trusted.snapshot.version,
                });
            }
        }
        // 5.4.4: a freeze attack.
        ensure_fresh(Role::Timestamp, timestamp.expires, now)?;
        // 5.4.5: persist.
        state.ever_published = true;
        state.timestamp = Some(TimestampState {
            version: timestamp.version,
            snapshot: timestamp.snapshot.clone(),
        });
        *state = self.store.save(state)?;
        Ok(timestamp)
    }

    fn update_snapshot(
        &mut self,
        state: &mut TrustState,
        root: &Root,
        timestamp: &Timestamp,
        now: OffsetDateTime,
    ) -> Result<Snapshot, TufError> {
        let listed = &timestamp.snapshot;
        // 5.5.1: download it, up to the length the timestamp lists (or Y), from the name
        // with its version.
        let body = self.get_listed(
            &layout::snapshot_path(listed.version),
            "snapshot.json",
            listed,
            self.limits.snapshot,
        )?;
        // 5.5.2: the hash the timestamp lists (checked in `get_listed`, before the
        // signature).
        let file = Envelope::parse(&body, self.limits.snapshot, "snapshot.json")?;
        // 5.5.3: signed by a threshold of the snapshot keys of the trusted root.
        verify_role(&file, root, Role::Snapshot, "the snapshot")?;
        let snapshot = Snapshot::from_signed(&file.signed)?;
        // 5.5.4: the version the timestamp lists.
        if snapshot.version != listed.version {
            return Err(TufError::VersionMismatch {
                role: Role::Snapshot,
                above: Role::Timestamp,
                expected: listed.version,
                found: snapshot.version,
            });
        }
        // 5.5.5: a rollback attack: no file's version goes back, no file listed is dropped.
        if let Some(trusted) = &state.snapshot {
            for (name, trusted_version) in &trusted.meta {
                match snapshot.meta.get(name) {
                    None => {
                        return Err(TufError::malformed(
                            "snapshot",
                            format!("{name} was listed by the snapshot trusted before"),
                        ));
                    }
                    Some(now_listed) if now_listed.version < *trusted_version => {
                        return Err(TufError::Rollback {
                            what: format!("{name} listed by the snapshot"),
                            found: now_listed.version,
                            trusted: *trusted_version,
                        });
                    }
                    Some(_) => {}
                }
            }
        }
        // 5.5.6: a freeze attack.
        ensure_fresh(Role::Snapshot, snapshot.expires, now)?;
        // 5.5.7: persist.
        state.snapshot = Some(SnapshotState {
            version: snapshot.version,
            meta: snapshot
                .meta
                .iter()
                .map(|(name, meta)| (name.clone(), meta.version))
                .collect(),
        });
        *state = self.store.save(state)?;
        Ok(snapshot)
    }

    fn update_targets(
        &mut self,
        state: &mut TrustState,
        root: &Root,
        snapshot: &Snapshot,
        now: OffsetDateTime,
    ) -> Result<Targets, TufError> {
        let listed = snapshot.targets();
        // 5.6.1: download it, up to the length the snapshot lists (or Z), from the name with
        // its version.
        let body = self.get_listed(
            &layout::targets_path(listed.version),
            TARGETS_META,
            listed,
            self.limits.targets,
        )?;
        // 5.6.2: the hash the snapshot lists (checked in `get_listed`).
        let file = Envelope::parse(&body, self.limits.targets, TARGETS_META)?;
        // 5.6.3: signed by a threshold of the targets keys of the trusted root.
        verify_role(&file, root, Role::Targets, "the targets")?;
        let targets = Targets::from_signed(&file.signed, self.profile)?;
        // 5.6.4: the version the snapshot lists.
        if targets.version != listed.version {
            return Err(TufError::VersionMismatch {
                role: Role::Targets,
                above: Role::Snapshot,
                expected: listed.version,
                found: targets.version,
            });
        }
        // The targets trusted before are not newer than these (5.5.5 holds the snapshot to
        // this too; the saved version is kept apart so that it outlives a snapshot's).
        if let Some(trusted) = state.targets
            && targets.version < trusted
        {
            return Err(TufError::Rollback {
                what: "targets".to_owned(),
                found: targets.version,
                trusted,
            });
        }
        // 5.6.5: a freeze attack.
        ensure_fresh(Role::Targets, targets.expires, now)?;
        // 5.6.6: persist.
        state.targets = Some(targets.version);
        state.targets_file = Some(file);
        *state = self.store.save(state)?;
        // 5.6.7: the search for a target is in the top-level targets only; the delegations,
        // if any, are read apart ([`TufClient::delegated`]).
        Ok(targets)
    }

    /// 5.7: the target `path` of `trusted`, as the repository has it: downloaded from its
    /// hash name, and handed over only if it is exactly the length and sha256 the targets
    /// metadata lists. `max_len` is the most the caller takes; a target the metadata lists
    /// as larger is refused without a request. `now` is the time of this call: `trusted` is
    /// not used once any of its files has expired.
    ///
    /// # Errors
    ///
    /// [`TufError::Expired`], [`TufError::NoSuchTarget`] (5.7.2), [`TufError::TargetTooLarge`],
    /// [`TufError::NotFound`] if the file is not there, [`TufError::Fetch`] if it is longer
    /// than listed, [`TufError::Length`] or [`TufError::Hash`] if it does not match.
    pub fn download_target(
        &self,
        trusted: &Trusted,
        path: &str,
        max_len: u64,
        now: OffsetDateTime,
    ) -> Result<Vec<u8>, TufError> {
        trusted.ensure_fresh(now)?;
        // 5.7.1-5.7.2: the metadata of the target.
        let (path, target) = trusted
            .targets
            .targets
            .get_key_value(path)
            .ok_or_else(|| TufError::NoSuchTarget(path.to_owned()))?;
        if target.length > max_len {
            return Err(TufError::TargetTooLarge {
                path: path.to_string(),
                len: target.length,
                max: max_len,
            });
        }
        // 5.7.3: download up to the listed length, from the name with the hash ...
        let stored = layout::target_file_path(path, &target.sha256);
        let body = self.get_required(&stored, target.length)?;
        // ... and verify its length and hash.
        if body.len() as u64 != target.length {
            return Err(TufError::Length {
                what: path.to_string(),
                expected: target.length,
                actual: body.len() as u64,
            });
        }
        if Digest::of(&body) != target.sha256 {
            return Err(TufError::Hash {
                what: path.to_string(),
            });
        }
        Ok(body)
    }

    /// The target `path` as a file kept from an earlier [`TufClient::download_target`]
    /// (`bytes`), checked again without the network: the saved targets file must still be
    /// signed by the targets keys of the root chain, which is replayed from the built-in
    /// root, be the version saved, and not have expired at `now`; the root in force must not
    /// have expired either; `bytes` must be exactly the length and sha256 it lists. Nothing
    /// is read from the repository and nothing is written.
    ///
    /// The timestamp and snapshot are not asked: they expire in days and say that the
    /// targets are *current*, which only a refresh can tell; this says that `bytes` are what
    /// the targets the client accepted last list. On success the moment this stops holding:
    /// the earlier of the expiry of the root and of the targets.
    ///
    /// # Errors
    ///
    /// [`TufError::Store`] if the state cannot be read, [`TufError::Malformed`] if it does
    /// not hold up from the built-in root or its targets are not the version saved,
    /// [`TufError::NoSuchTarget`] if no targets are saved or they do not list `path`,
    /// [`TufError::Signature`], [`TufError::Expired`], [`TufError::Length`] or
    /// [`TufError::Hash`].
    pub fn verify_cached_target(
        &self,
        path: &str,
        bytes: &[u8],
        now: OffsetDateTime,
    ) -> Result<OffsetDateTime, TufError> {
        let Some((root, targets, _)) = self.cached_targets(now)? else {
            return Err(TufError::NoSuchTarget(path.to_owned()));
        };
        let target = targets
            .targets
            .get(path)
            .ok_or_else(|| TufError::NoSuchTarget(path.to_owned()))?;
        if bytes.len() as u64 != target.length {
            return Err(TufError::Length {
                what: path.to_owned(),
                expected: target.length,
                actual: bytes.len() as u64,
            });
        }
        if Digest::of(bytes) != target.sha256 {
            return Err(TufError::Hash {
                what: path.to_owned(),
            });
        }
        Ok(root.expires.min(targets.expires))
    }

    /// The top-level targets saved by the last refresh, checked again without the network
    /// as [`TufClient::verify_cached_target`] checks them, and the moment they stop holding
    /// (the earlier of the expiry of the root and of the targets); `None` if no targets are
    /// saved. What a caller reads offline the delegations and the other targets from.
    /// Nothing is read from the repository and nothing is written.
    ///
    /// # Errors
    ///
    /// The errors of [`TufClient::verify_cached_target`] for the saved targets.
    pub fn verify_cached_top_level(
        &self,
        now: OffsetDateTime,
    ) -> Result<Option<(Targets, OffsetDateTime)>, TufError> {
        Ok(self.cached_targets(now)?.map(|(root, targets, _)| {
            let valid_until = root.expires.min(targets.expires);
            (targets, valid_until)
        }))
    }

    /// The saved top-level targets, checked again offline as
    /// [`TufClient::verify_cached_target`] says, with the root in force and the state; `None`
    /// if no targets are saved.
    fn cached_targets(
        &self,
        now: OffsetDateTime,
    ) -> Result<Option<(Root, Targets, TrustState)>, TufError> {
        let mut state = self.store.load()?;
        let root = self
            .replay(&mut state)
            .map_err(|why| TufError::malformed("the saved TUF state", why))?;
        ensure_fresh(Role::Root, root.expires, now)?;
        let (Some(version), Some(file)) = (state.targets, &state.targets_file) else {
            return Ok(None);
        };
        verify_role(file, &root, Role::Targets, "the saved targets")?;
        let targets = Targets::from_signed(&file.signed, self.profile)?;
        if targets.version != version {
            return Err(TufError::malformed(
                "the saved targets",
                format!("version {} is not the {version} saved", targets.version),
            ));
        }
        ensure_fresh(Role::Targets, targets.expires, now)?;
        Ok(Some((root, targets, state)))
    }

    /// Step 5.6.7, apart from the program's updates: every delegated role of `trusted`'s
    /// top-level targets, in order, each name once, at most [`Limits::max_delegations`]. A
    /// role is trusted if its delegation keeps the profile, none of its keys is a key of the
    /// root, the snapshot lists its file by its length and sha256, the file is exactly those,
    /// signed by a threshold of the delegation's keys, the version listed and not below the
    /// version saved, not expired, without delegations of its own, and lists only targets
    /// inside its paths.
    /// The version of each role trusted is saved, never lowered.
    ///
    /// A role that is not trusted is in the result with its error; it touches neither the
    /// other roles nor `trusted`.
    ///
    /// Top-level targets without a `delegations` member (always so in [`Profile::Legacy`])
    /// delegate to no role: the result is empty.
    ///
    /// # Errors
    ///
    /// [`TufError::Expired`] if `trusted` is no longer fresh at `now`, the errors of
    /// [`Targets::delegations`] if its `delegations` member cannot be read, and the errors of
    /// [`Store::load`] and [`Store::save`]: the state of the roles is all or nothing.
    pub fn delegated(
        &mut self,
        trusted: &Trusted,
        now: OffsetDateTime,
    ) -> Result<Delegated, TufError> {
        trusted.ensure_fresh(now)?;
        let Some(delegations) = trusted.targets.delegations()? else {
            return Ok(Delegated { roles: Vec::new() });
        };
        // The state is read here and saved once below, merged under the store's lock. If
        // another process rotates the keys in between (a refresh that forgets every version),
        // the merge keeps the newer epoch, so the versions saved below are dropped, not
        // brought back; and if it is the other way round, the next refresh starts the epoch
        // over anyway. Neither ever lowers a version within an epoch.
        let mut state = self.store.load()?;
        let loaded = state.clone();
        let max = self.limits.max_delegations;
        let mut visited = BTreeSet::new();
        let mut roles = Vec::new();
        for (index, entry) in delegations.roles().iter().enumerate() {
            let name = match entry {
                Ok(role) => role.name(),
                Err(refused) => &refused.name,
            };
            // 5.6.7.1: a role visited before is skipped.
            if !visited.insert(name.clone()) {
                continue;
            }
            let result = if u32::try_from(index).map_or(true, |index| index >= max) {
                Err(TufError::Delegation {
                    role: name.clone(),
                    error: DelegationError::TooMany { max },
                })
            } else {
                self.fetch_role(
                    trusted,
                    &delegations,
                    entry.as_ref(),
                    state.delegated.get(name).map(|accepted| accepted.version),
                    now,
                )
            };
            if let Ok(role) = &result {
                // 5.6.6: persist (below, once for every role), with the hash of the very
                // file accepted: the only bytes `verify_cached_role` takes for it.
                state.delegated.insert(
                    name.clone(),
                    RoleState {
                        version: role.version(),
                        sha256: Digest::of(role.file()),
                    },
                );
            }
            roles.push((name.clone(), result));
        }
        if state != loaded {
            self.store.save(&state)?;
        }
        Ok(Delegated { roles })
    }

    /// One delegated role of `trusted`, from the repository.
    fn fetch_role(
        &self,
        trusted: &Trusted,
        delegations: &Delegations,
        entry: Result<&DelegatedRole, &RefusedRole>,
        saved: Option<u64>,
        now: OffsetDateTime,
    ) -> Result<VerifiedRole, TufError> {
        let role = usable(entry, &trusted.root)?;
        let name = role.name();
        let meta_name = name.meta_name();
        // The snapshot lists the role's file.
        let listed = trusted
            .snapshot
            .meta
            .get(&meta_name)
            .ok_or_else(|| delegation_error(name, DelegationError::NotInSnapshot))?;
        // A role's file is listed by its length and sha256, so that the targets key, if it
        // also signs elsewhere, cannot bring a file of another repository here.
        if listed.length.is_none() || listed.sha256.is_none() {
            return Err(delegation_error(name, DelegationError::Unhashed));
        }
        // 5.6.1-5.6.2: at most the listed length (and the limit), then exactly the listed
        // length and sha256, before the signature.
        let body = self.get_listed(
            &layout::delegated_path(listed.version, name),
            &meta_name,
            listed,
            self.limits.delegated,
        )?;
        let targets = check_role_file(
            role,
            delegations,
            &body,
            &self.limits,
            listed.version,
            saved,
            now,
        )?;
        let valid_until = trusted.expires().min(targets.expires);
        Ok(VerifiedRole {
            name: name.clone(),
            targets,
            file: body,
            valid_until,
        })
    }

    /// The delegated role `role` as a file kept from an earlier [`TufClient::delegated`]
    /// (`bytes`), checked again without the network: `bytes` must be exactly the file that
    /// `delegated` accepted (its sha256 is saved), the saved top-level targets are checked as
    /// [`TufClient::verify_cached_target`] checks them, their delegation of `role` as
    /// [`TufClient::delegated`] checks it, and `bytes` signed by a threshold of its keys,
    /// exactly the version saved, not expired at `now`, without delegations, every target
    /// inside its paths. Nothing is read from the repository and nothing is written.
    ///
    /// # Errors
    ///
    /// The errors of [`TufClient::verify_cached_target`] for the saved targets, and of
    /// [`Targets::delegations`] for their `delegations` member;
    /// [`TufError::Delegation`] if they do not delegate to `role` (no `delegations` member,
    /// or no entry for it: [`DelegationError::NotDelegated`]), no version of it was accepted
    /// ([`DelegationError::NotAccepted`]), or for the rules of [`TufClient::delegated`]; and
    /// [`TufError::Hash`] if `bytes` are not the file accepted; [`TufError::Signature`] or
    /// the errors of [`Envelope::parse`] for `bytes`.
    pub fn verify_cached_role(
        &self,
        role: &RoleName,
        bytes: &[u8],
        now: OffsetDateTime,
    ) -> Result<VerifiedRole, TufError> {
        self.cached_role(role, bytes, now, false)
    }

    /// [`TufClient::verify_cached_role`], and the version accepted must be the one the saved
    /// snapshot lists: a newer version the last [`TufClient::delegated`] refused leaves the
    /// role untrusted offline too, not trusted at the version accepted before. What a client
    /// that uses a kept role in place of the repository's checks it with.
    ///
    /// # Errors
    ///
    /// Those of [`TufClient::verify_cached_role`]; [`DelegationError::NotAccepted`] also if
    /// the saved snapshot lists another version of the role, or none.
    pub fn verify_cached_current_role(
        &self,
        role: &RoleName,
        bytes: &[u8],
        now: OffsetDateTime,
    ) -> Result<VerifiedRole, TufError> {
        self.cached_role(role, bytes, now, true)
    }

    /// [`TufClient::verify_cached_role`], the snapshot's version required if `current`.
    fn cached_role(
        &self,
        role: &RoleName,
        bytes: &[u8],
        now: OffsetDateTime,
        current: bool,
    ) -> Result<VerifiedRole, TufError> {
        let Some((root, targets, state)) = self.cached_targets(now)? else {
            return Err(delegation_error(role, DelegationError::NotAccepted));
        };
        let delegations = targets
            .delegations()?
            .ok_or_else(|| delegation_error(role, DelegationError::NotDelegated))?;
        let entry = delegations
            .role(role)
            .ok_or_else(|| delegation_error(role, DelegationError::NotDelegated))?;
        let delegated = usable(entry, &root)?;
        let accepted = *state
            .delegated
            .get(role)
            .ok_or_else(|| delegation_error(role, DelegationError::NotAccepted))?;
        // The version the saved snapshot lists, no other: a newer one that was refused leaves
        // the role unavailable offline too, not trusted at the version accepted before.
        let listed = state
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.meta.get(&role.meta_name()).copied());
        if current && listed != Some(accepted.version) {
            return Err(delegation_error(role, DelegationError::NotAccepted));
        }
        // Only the file accepted: another file of the same version, even one signed by the
        // delegation's keys, was never checked against the snapshot.
        if Digest::of(bytes) != accepted.sha256 {
            return Err(TufError::Hash {
                what: format!("the kept file of the role {role}"),
            });
        }
        let role_targets = check_role_file(
            delegated,
            &delegations,
            bytes,
            &self.limits,
            accepted.version,
            None,
            now,
        )?;
        let valid_until = root.expires.min(targets.expires).min(role_targets.expires);
        Ok(VerifiedRole {
            name: role.clone(),
            targets: role_targets,
            file: bytes.to_vec(),
            valid_until,
        })
    }

    /// The file at `path`, or `None` for a 404; never more than `max_len` bytes, whatever
    /// the fetcher hands over.
    fn get(&self, path: &str, max_len: u64) -> Result<Option<Vec<u8>>, TufError> {
        match self.fetcher.fetch(path, max_len)? {
            Response::NotFound => Ok(None),
            Response::Body(body) if body.len() as u64 > max_len => Err(TufError::TooLarge {
                what: path.to_owned(),
                limit: max_len,
            }),
            Response::Body(body) => Ok(Some(body)),
        }
    }

    fn get_required(&self, path: &str, max_len: u64) -> Result<Vec<u8>, TufError> {
        self.get(path, max_len)?
            .ok_or_else(|| TufError::NotFound(path.to_owned()))
    }

    /// A metadata file a role above lists: at most `listed.length` bytes (or `limit`, which
    /// is also the most a listed length may be), then exactly that length and the listed
    /// sha256, if they are listed.
    fn get_listed(
        &self,
        path: &str,
        name: &str,
        listed: &MetaFile,
        limit: u64,
    ) -> Result<Vec<u8>, TufError> {
        let max_len = match listed.length {
            Some(length) if length > limit => {
                return Err(TufError::TooLarge {
                    what: name.to_owned(),
                    limit,
                });
            }
            Some(length) => length,
            None => limit,
        };
        let body = self.get_required(path, max_len)?;
        if let Some(length) = listed.length
            && body.len() as u64 != length
        {
            return Err(TufError::Length {
                what: name.to_owned(),
                expected: length,
                actual: body.len() as u64,
            });
        }
        if let Some(sum) = listed.sha256
            && Digest::of(&body) != sum
        {
            return Err(TufError::Hash {
                what: name.to_owned(),
            });
        }
        Ok(body)
    }
}

/// 5.3.4-5.3.5: `file` as root version `next` after `trusted`: signed by a threshold of the
/// keys of the trusted root and by a threshold of its own, and exactly that version.
fn accept_root(trusted: &Root, next: u64, file: Envelope) -> Result<(Envelope, Root), TufError> {
    // 5.3.4: signed by a threshold of the keys of the trusted root (N) ...
    verify_role(
        &file,
        trusted,
        Role::Root,
        &format!("root {next} by the keys of root {}", trusted.version),
    )?;
    let new_root = Root::from_signed(&file.signed)?;
    // ... and by a threshold of the keys of the new root (N+1).
    verify_role(
        &file,
        &new_root,
        Role::Root,
        &format!("root {next} by its own keys"),
    )?;
    // 5.3.5: exactly N+1.
    if new_root.version != next {
        return Err(TufError::RootVersion {
            expected: next,
            found: new_root.version,
        });
    }
    Ok((file, new_root))
}

fn delegation_error(role: &RoleName, error: DelegationError) -> TufError {
    TufError::Delegation {
        role: role.clone(),
        error,
    }
}

/// The role of a delegation entry, if it keeps the profile and none of its keys is a key of
/// `root` (one key, one role).
fn usable<'a>(
    entry: Result<&'a DelegatedRole, &RefusedRole>,
    root: &Root,
) -> Result<&'a DelegatedRole, TufError> {
    let role = entry.map_err(|refused| delegation_error(&refused.name, refused.error.clone()))?;
    if let Some(keyid) = role
        .keys()
        .keyids
        .iter()
        .find(|id| root.keys.contains_key(id))
    {
        return Err(delegation_error(
            role.name(),
            DelegationError::KeyReused { keyid: *keyid },
        ));
    }
    Ok(role)
}

/// 5.6.3-5.6.5 for the file `body` of the delegated role `role`: signed by a threshold of
/// its keys, a targets file of version `expected` and not below `trusted`, not expired at
/// `now`, without delegations, at most [`Limits::max_role_targets`] targets, every one
/// inside the role's paths.
fn check_role_file(
    role: &DelegatedRole,
    delegations: &Delegations,
    body: &[u8],
    limits: &Limits,
    expected: u64,
    trusted: Option<u64>,
    now: OffsetDateTime,
) -> Result<Targets, TufError> {
    let name = role.name();
    let what = name.meta_name();
    let file = Envelope::parse(body, limits.delegated, &what)?;
    // 5.6.3: signed by a threshold of the keys of the delegation.
    verify_threshold(
        &file,
        role.keys(),
        delegations.keys(),
        &format!("the role {name}"),
    )?;
    // Delegations are one level deep.
    if file
        .signed
        .as_object()
        .is_some_and(|members| members.contains_key("delegations"))
    {
        return Err(delegation_error(name, DelegationError::Nested));
    }
    let targets = Targets::from_signed(&file.signed, Profile::Legacy)?;
    // 5.6.4: the version listed (or saved).
    if targets.version != expected {
        return Err(delegation_error(
            name,
            DelegationError::VersionMismatch {
                expected,
                found: targets.version,
            },
        ));
    }
    if let Some(trusted) = trusted
        && targets.version < trusted
    {
        return Err(delegation_error(
            name,
            DelegationError::Rollback {
                found: targets.version,
                trusted,
            },
        ));
    }
    // 5.6.5: a freeze attack.
    if targets.expires <= now {
        return Err(delegation_error(
            name,
            DelegationError::Expired {
                expires: targets.expires,
            },
        ));
    }
    let max = limits.max_role_targets;
    if u32::try_from(targets.targets.len()).map_or(true, |count| count > max) {
        return Err(delegation_error(
            name,
            DelegationError::TooManyTargets { max },
        ));
    }
    // Section 4.5: every target inside the role's paths, or the role is not trusted.
    if let Some(path) = targets
        .targets
        .keys()
        .find(|path| !role.pattern().matches(path))
    {
        return Err(delegation_error(
            name,
            DelegationError::PathOutside { path: path.clone() },
        ));
    }
    Ok(targets)
}
