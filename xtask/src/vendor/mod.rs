//! `cargo xtask vendor …`: the tools of a third-party plugin publisher and of the CI that
//! takes its releases in (`docs/design/publishers.md`, «Команды издателя» and «Автослияние PR
//! издателя»; the walkthrough is `docs/dev/publishers.md`).
//!
//! The publisher's side, in a clone of this repository: a key ([`keys::keygen`]), the
//! onboarding file ([`onboard`]), the canonical source archive (`oncl-pack source`), the
//! reference build in the builder image ([`docker`]), the draft of the next role version
//! ([`draft`]: `add`, `set`, `prune`), its signature ([`keys::sign`], [`keys::cosign`]), and
//! the checks CI runs ([`pr::check_pr`]).
//!
//! The CI's side, each a pure function over data where it can be:
//!
//! - [`pr::check_pr`]: checks 1–9, 11–18, 23 and 24 of a release pull request over the files
//!   of its base and head read from git as data (nothing of the pull request is built or run);
//!   the source archives are downloaded by [`fetch`] under its host policy and read strictly;
//! - [`docker`]: the rebuild (checks 19 and 20): the archive's crates fetched with the network,
//!   the licences read by `cargo metadata` and the package built in a container without the
//!   network, taken out by `docker cp` and hashed outside;
//! - [`provenance`]: check 25, the git revision a publisher names, made into an archive and
//!   compared;
//! - [`mirror`] and [`pr::verdict_job`]: checks 21 and 22 on the rebuilt bytes, and
//!   `BUILDINFO.json`; [`diff`]: the `.src.diff` of the copies in the project's Releases.
//!
//! Every check reports under its number ([`verdict::CheckId`]); `check-pr` prints one JSON
//! verdict ([`verdict::PrVerdict`]).

pub mod checks;
pub mod cli;
pub mod diff;
pub mod docker;
pub mod draft;
pub mod fetch;
pub mod git;
pub mod keys;
pub mod licenses;
pub mod mirror;
pub mod onboard;
pub mod pr;
pub mod provenance;
pub mod verdict;

use std::time::Duration;

use oncl_update::Version;

/// The largest role file of a publisher (check 1): what the client reads.
pub const MAX_ROLE_FILE: u64 = 128 * 1024;

/// The most targets one role version lists (check 6).
pub const MAX_TARGETS: usize = 256;

/// The most new packages one pull request brings (check 6): the GitHub limit on creating
/// content (about 7 requests per package, 80 a minute).
pub const MAX_NEW_PACKAGES: usize = 8;

/// The earliest a role may expire, from the check (check 5): 14 days.
pub const MIN_EXPIRY_DAYS: i64 = 14;

/// The latest a role may expire, from the check (check 5): 180 days.
pub const MAX_EXPIRY_DAYS: i64 = 180;

/// The least time between two releases of one publisher (check 9, Р19).
pub const RELEASE_INTERVAL: time::Duration = time::Duration::hours(1);

/// How long the download of one source archive may take (check 13).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the fetch of a publisher's git revision may take (check 25).
pub const VCS_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long the rebuild of one package may take (check 19).
pub const REBUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The largest binary file of a source archive that need not be in `binary_files` (check 18).
pub const MAX_PLAIN_BINARY: usize = 64 * 1024;

/// The oldest core a publisher's release may name in `min_core` (check 6): Y, the first
/// release whose client reads the publishers' catalog (`docs/design/publishers.md`, «Цели
/// издателя»).
pub const MIN_CORE: &str = "0.1.3";

/// [`MIN_CORE`] as a version.
pub fn min_core() -> Version {
    // A constant of this module; its test reads it.
    Version::parse(MIN_CORE).unwrap_or_else(|_| Version::new(u64::MAX, 0, 0))
}

/// Where the files `vendor` reads are in a checkout, relative to its root: the real layout
/// ([`Layout::REPO`]), or another one for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The TUF repository (`tuf/v1`).
    pub tuf: &'static str,
    /// Its snapshot mode file (`tuf/v1.toml`).
    pub config: &'static str,
    /// The trust anchor the client embeds.
    pub anchor: &'static str,
    /// The owner's indexes (`updates/v1`).
    pub indexes: &'static str,
    /// The registry of the publishers (`publishers`).
    pub publishers: &'static str,
    /// `deny.toml`, whose `allow-git` names the git sources a lock file may have (check 17).
    pub deny: &'static str,
}

impl Layout {
    /// This repository.
    pub const REPO: Layout = Layout {
        tuf: crate::tuf::REPO_DIR,
        config: crate::tuf::CONFIG,
        anchor: crate::tuf::ANCHOR,
        indexes: crate::index::INDEX_DIR,
        publishers: crate::publishers::PUBLISHERS_DIR,
        deny: "deny.toml",
    };

    /// The directories and files `vendor check-pr` reads of the base.
    pub fn base_paths(&self) -> [&'static str; 6] {
        [
            self.tuf,
            self.config,
            self.anchor,
            self.indexes,
            self.publishers,
            self.deny,
        ]
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_oldest_core_of_a_release_is_a_version() {
        assert_eq!(super::min_core().to_string(), super::MIN_CORE);
    }
}
