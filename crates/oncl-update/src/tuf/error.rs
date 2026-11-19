//! The roles and the one error type of the `tuf` module.

use std::fmt;
use std::io;

use time::OffsetDateTime;

use super::keys::KeyId;
use super::names::{RoleName, TargetPath};

/// A top-level TUF role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// The trust anchor: names the keys of every role, itself included.
    Root,
    /// The short-lived pointer to the snapshot.
    Timestamp,
    /// The versions (and hashes) of the targets metadata.
    Snapshot,
    /// The files of the repository (here: the update indexes).
    Targets,
}

impl Role {
    /// `root`, `timestamp`, `snapshot` or `targets`: the role's name in `roles` and in
    /// `_type`.
    pub fn name(self) -> &'static str {
        match self {
            Role::Root => "root",
            Role::Timestamp => "timestamp",
            Role::Snapshot => "snapshot",
            Role::Targets => "targets",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why metadata, a target or a key is refused.
#[derive(Debug, thiserror::Error)]
pub enum TufError {
    /// Not JSON, or JSON the strict parser refuses.
    #[error("malformed JSON: {0}")]
    Json(String),
    /// An object with the same key twice: which one signs is ambiguous.
    #[error("a JSON object has the key {0:?} twice")]
    DuplicateKey(String),
    /// A JSON number that is not an integer: the canonical form has no floats.
    #[error("a JSON number is not an integer")]
    Float,
    /// JSON nested deeper than the limit.
    #[error("JSON is nested deeper than {0} levels")]
    TooDeep(usize),
    /// More data than the limit allows (endless data).
    #[error("{what} is larger than {limit} bytes")]
    TooLarge {
        /// What was too large.
        what: String,
        /// The limit it broke.
        limit: u64,
    },
    /// Valid JSON that breaks a rule of the format.
    #[error("{what} is malformed: {why}")]
    Malformed {
        /// The file or field.
        what: String,
        /// The rule broken.
        why: String,
    },
    /// Something TUF allows that this client does not: another key type or scheme or hash
    /// algorithm, delegations, a spec version other than 1.x, no consistent snapshots.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// A key of a root under another id than its hash says.
    #[error("the key {claimed} of the root hashes to {actual}")]
    BadKeyId {
        /// The id the root gives the key.
        claimed: String,
        /// The id the key's own canonical form hashes to.
        actual: String,
    },
    /// Not a key, or a key file the signer cannot use.
    #[error("bad key: {0}")]
    Key(String),
    /// Fewer distinct keys signed than the threshold needs.
    #[error("{what}: {valid} valid signatures from distinct trusted keys, {threshold} needed")]
    Signature {
        /// The file, and whose keys were asked.
        what: String,
        /// How many distinct trusted keys made a valid signature.
        valid: usize,
        /// The threshold.
        threshold: u32,
    },
    /// A root that is not exactly the trusted one plus one.
    #[error("the root asked for as version {expected} is version {found}")]
    RootVersion {
        /// The version the file name asks for: the trusted one plus one.
        expected: u64,
        /// The version inside the file.
        found: u64,
    },
    /// More new roots than one refresh follows, and another one is there: the chain is too
    /// long to follow in one go (the roots followed so far are kept; refresh again).
    #[error("the root chain is longer than the {0} roots one refresh follows")]
    RootChainTooLong(u32),
    /// Metadata past its `expires` (a freeze attack, or a repository nobody re-signed).
    #[error("the {role} metadata expired at {expires}")]
    Expired {
        /// The role.
        role: Role,
        /// Its `expires`.
        expires: OffsetDateTime,
    },
    /// A version below one already trusted (a rollback attack).
    #[error("the {what} is version {found}, version {trusted} was trusted before")]
    Rollback {
        /// What went back: a role, or the snapshot or targets a role lists.
        what: String,
        /// The version offered.
        found: u64,
        /// The version trusted before.
        trusted: u64,
    },
    /// Metadata whose version is not the one the role above lists for it.
    #[error("the {role} metadata is version {found}, the {above} metadata says {expected}")]
    VersionMismatch {
        /// The role fetched.
        role: Role,
        /// The role that lists it.
        above: Role,
        /// The version listed.
        expected: u64,
        /// The version of the file.
        found: u64,
    },
    /// A file whose size is not the one the metadata lists.
    #[error("{what} is {actual} bytes, the metadata says {expected}")]
    Length {
        /// The file.
        what: String,
        /// The size listed.
        expected: u64,
        /// The size of the file.
        actual: u64,
    },
    /// A file whose sha256 is not the one the metadata lists.
    #[error("the sha256 of {what} does not match the metadata")]
    Hash {
        /// The file.
        what: String,
    },
    /// The same timestamp version with other content than the one trusted.
    #[error("a second, different timestamp of version {0}")]
    TimestampChanged(u64),
    /// The state to save is larger than the limit: nothing is written, and it is tried again.
    #[error("the TUF state is larger than {0} bytes")]
    StateTooLarge(u64),
    /// A file of the repository that must be there answers 404.
    #[error("{0} is not published")]
    NotFound(String),
    /// The repository could not be read: no response, a bad status, a redirect off-host.
    #[error("fetching {0}")]
    Fetch(String),
    /// A target the targets metadata does not list.
    #[error("{0} is not a target of the repository")]
    NoSuchTarget(String),
    /// A target bigger than the caller allows.
    #[error("the target {path} is {len} bytes, more than the {max} allowed")]
    TargetTooLarge {
        /// The target.
        path: String,
        /// Its size in the metadata.
        len: u64,
        /// What the caller allows.
        max: u64,
    },
    /// The state directory could not be read or written.
    #[error("TUF state: {0}")]
    Store(#[from] io::Error),
    /// A delegated role that is not trusted, for a reason only a delegation has. The other
    /// roles, and the top-level metadata, are not concerned.
    #[error("the delegated role {role}: {error}")]
    Delegation {
        /// The role.
        role: RoleName,
        /// Why it is not trusted.
        error: DelegationError,
    },
}

impl TufError {
    pub(crate) fn malformed(what: impl Into<String>, why: impl Into<String>) -> TufError {
        TufError::Malformed {
            what: what.into(),
            why: why.into(),
        }
    }
}

/// Why one delegated role is not trusted. Every reason is the role's own: the top-level
/// metadata and the other roles stay trusted.
///
/// The causes a delegated role shares with the top-level roles (a signature below its
/// threshold, a length or sha256 other than the snapshot lists, a file not published or
/// not readable) are [`TufError`]s of their own; only those whose top-level form names a
/// [`Role`] are repeated here.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DelegationError {
    /// The snapshot does not list the role's file.
    #[error("the snapshot does not list it")]
    NotInSnapshot,
    /// The snapshot lists the role's file without its length and sha256.
    #[error("the snapshot lists it without its length and sha256")]
    Unhashed,
    /// The role's file has a `delegations` member: delegations are one level deep.
    #[error("it delegates further")]
    Nested,
    /// The role lists a target outside its paths.
    #[error("it lists the target {path}, outside its paths")]
    PathOutside {
        /// The target.
        path: TargetPath,
    },
    /// The delegation's `paths` are not exactly `["plugins/<publisher>/*/*"]`.
    #[error("its paths are not exactly the publisher's plugins/<name>/*/*")]
    Pattern,
    /// The delegation has `path_hash_prefixes`.
    #[error("it is delegated by path_hash_prefixes")]
    HashPrefixes,
    /// The delegation is not `terminating`.
    #[error("its delegation is not terminating")]
    NotTerminating,
    /// The delegation lists a key id twice.
    #[error("its delegation lists the key {keyid} twice")]
    DuplicateKey {
        /// The key.
        keyid: KeyId,
    },
    /// The delegation lists a key id the delegations' `keys` do not have.
    #[error("its delegation lists the key {keyid}, which delegations.keys does not have")]
    UnknownKey {
        /// The key.
        keyid: KeyId,
    },
    /// A key of the role is also a key of another delegated role or of the root.
    #[error("its key {keyid} serves another role too")]
    KeyReused {
        /// The key.
        keyid: KeyId,
    },
    /// A threshold of 0, or above the number of keys.
    #[error("its threshold {threshold} is not between 1 and its {keys} keys")]
    Threshold {
        /// The threshold.
        threshold: u64,
        /// How many keys the delegation lists.
        keys: usize,
    },
    /// The role comes after the most delegated roles the client follows.
    #[error("it comes after the {max} delegated roles followed")]
    TooMany {
        /// [`super::Limits::max_delegations`].
        max: u32,
    },
    /// The role lists more targets than the client takes from one role.
    #[error("it lists more than {max} targets")]
    TooManyTargets {
        /// [`super::Limits::max_role_targets`].
        max: u32,
    },
    /// The role's file is not the version the snapshot lists for it (or, for a kept file,
    /// the version saved).
    #[error("it is version {found}, not the version {expected} listed")]
    VersionMismatch {
        /// The version listed or saved.
        expected: u64,
        /// The version of the file.
        found: u64,
    },
    /// The role's version is below one trusted before (a rollback).
    #[error("it is version {found}, version {trusted} was trusted before")]
    Rollback {
        /// The version offered.
        found: u64,
        /// The version trusted before.
        trusted: u64,
    },
    /// The role's file is past its `expires`.
    #[error("it expired at {expires}")]
    Expired {
        /// Its `expires`.
        expires: OffsetDateTime,
    },
    /// A kept file of the role is checked, but no version of the role was ever accepted.
    #[error("no version of it was accepted")]
    NotAccepted,
    /// A kept file of the role is checked, but the saved top-level targets do not delegate
    /// to it.
    #[error("the top-level targets do not delegate to it")]
    NotDelegated,
}
