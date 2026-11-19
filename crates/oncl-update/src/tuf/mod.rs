//! TUF (The Update Framework, specification 1.0.37) as OpenNCALayer uses it: a verifier for
//! the client and a builder for the tools that publish.
//!
//! The update indexes (`updates/v1/<channel>.json`, [`crate::index`]) are the *targets* of a
//! TUF repository, under the target paths `indexes/stable.json` and `indexes/beta.json`;
//! everything here is the authentication around them, and nothing in this module reads an
//! index. The subset implemented, anything else is refused:
//!
//! - roles `root`, `timestamp`, `snapshot` and top-level `targets`; one level of delegated
//!   roles of third-party publishers, read apart from the program's updates ([`delegation`],
//!   [`names`], [`Profile`]); no mirrors, no path hash prefixes;
//! - Ed25519 keys and signatures only, sha256 only ([`keys`], [`ed25519`]);
//! - consistent snapshots are required ([`layout`]);
//! - signatures over the OLPC canonical JSON of the `signed` value, whatever it holds
//!   ([`canonical`]).
//!
//! The layers:
//!
//! - [`canonical`], [`keys`], [`model`], [`ed25519`], [`layout`]: bytes in, verdicts out; no
//!   network, no disk, no clock. `build.rs` compiles [`canonical`], [`keys`] and [`model`]
//!   to check the embedded root.
//! - [`client`]: [`TufClient`] runs the specification's client workflow over a [`Fetcher`]
//!   ([`HttpFetcher`], [`MemoryFetcher`]) and a [`Store`] ([`FileStore`], [`MemoryStore`]).
//! - [`build`]: makes the metadata and signs it, with the same code.
//!
//! The client is what the updater and the plugin catalog read their index through. Its root
//! is built in ([`crate::embedded_root`], `keys/root.json`); without one there is nothing to
//! trust and updates are off.

pub mod build;
pub mod canonical;
pub mod client;
pub mod delegation;
pub mod ed25519;
mod error;
pub mod fetch;
pub mod keys;
pub mod layout;
pub mod model;
pub mod names;
pub mod store;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use client::{Delegated, Limits, Trusted, TufClient, VerifiedRole};
pub use delegation::{DelegatedRole, Delegations, RefusedRole};
pub use ed25519::SigningKey;
pub use error::{DelegationError, Role, TufError};
pub use fetch::{Fetcher, HttpFetcher, MemoryFetcher, Response};
pub use keys::{KeyId, PublicKey};
pub use model::{
    Digest, Envelope, MetaFile, Profile, RoleKeys, Root, Signature, Snapshot, Target, Targets,
    Timestamp,
};
pub use names::{NameError, NameKind, PathPattern, PublisherName, RoleName, TargetPath};
pub use store::{
    FileStore, MemoryStore, RoleState, SnapshotState, Store, TimestampState, TrustState,
};

#[cfg(test)]
mod delegated_tests;

#[cfg(test)]
mod tests;
