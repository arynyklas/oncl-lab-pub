//! `cargo xtask tuf`: the operator's side of the TUF repositories that authenticate the
//! update indexes (`docs/design/tuf.md`, `docs/dev/release.md`) and, in `tuf/v2`, the
//! publishers' plugins (`docs/design/publishers.md`). The verifier and the builder are
//! `oncl_update::tuf`: this module only decides what to sign, when, and with which key, and
//! checks the result with the client's own code. Nothing here has a second implementation of
//! canonical JSON, signatures or the client workflow.
//!
//! - [`init`]: the keys and root version 1 (the ceremony, once per repository);
//! - [`update`]: targets (and, in `tuf/v1`, snapshot) over the update indexes and the
//!   publishers, signed with the owner's keys;
//! - [`snapshot`]: the snapshot of `tuf/v2`, which CI signs with its online key;
//! - [`timestamp`]: the file CI signs, with the online key, when Pages is published;
//! - [`root`]: the next root: a renewal, or a rotation of any role's key;
//! - [`check`], [`check_v2`]: offline verification of a repository with the client over a
//!   directory;
//! - [`published`]: the client over HTTPS against the published site.
//!
//! A repository is a directory ([`repo`]): `metadata/<N>.root.json`, `<N>.targets.json`,
//! `<N>.snapshot.json` (every version is kept for good), `metadata/timestamp.json` (never
//! committed) and `targets/indexes/<sha256>.<channel>.json`. `tuf/v2` has its own chain of
//! roots and online snapshot and timestamp keys, and shares the targets key of `tuf/v1`; its
//! top-level targets delegate to the publishers ([`crate::publishers`]) and also list
//! `targets/<sha256>.publishers.json`; the publishers' roles are
//! `metadata/<N>.pub-<name>.json`; its snapshot is never committed. Secret keys are in
//! [`keystore`].

pub mod check;
pub mod check_v2;
pub mod cli;
pub mod init;
pub mod keystore;
pub mod published;
pub mod repo;
pub mod root;
pub mod snapshot;
pub mod timestamp;
pub mod update;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

/// Where the repository is committed, from the workspace root.
pub const REPO_DIR: &str = "tuf/v1";

/// Where `tuf/v2` is committed, from the workspace root.
pub const V2_REPO_DIR: &str = "tuf/v2";

/// The root of trust the client embeds (a copy of root version 1), from the workspace root.
pub const ANCHOR: &str = "crates/oncl-update/keys/root.json";

/// The root of trust of `tuf/v2`, from the workspace root: its root version 1, until the
/// client that reads `tuf/v2` embeds it (`docs/design/publishers.md`, "Миграция").
pub const V2_ANCHOR: &str = "tuf/v2/metadata/1.root.json";

/// How long each role's metadata is valid, in days, from the moment it is signed
/// (`docs/design/tuf.md`).
pub const ROOT_DAYS: i64 = 365;
/// See [`ROOT_DAYS`].
pub const TARGETS_DAYS: i64 = 30;
/// See [`ROOT_DAYS`].
pub const SNAPSHOT_DAYS: i64 = 30;
/// See [`ROOT_DAYS`].
pub const TIMESTAMP_DAYS: i64 = 7;
/// The snapshot of `tuf/v2`, signed online on every publication
/// (`docs/design/publishers.md`, "Сроки и лимиты").
pub const V2_SNAPSHOT_DAYS: i64 = 7;

/// The largest index (and so target) the tools read: the client's own limit.
pub const MAX_TARGET: u64 = oncl_update::MAX_INDEX_LEN;

/// `now` in whole seconds (the metadata has no sub-seconds).
pub fn whole_seconds(now: OffsetDateTime) -> OffsetDateTime {
    now - Duration::nanoseconds(i64::from(now.nanosecond()))
}

/// The version after `version` of a file would not fit in a `u64`: the repository cannot
/// go on (a version is never reused, and never goes back).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionOverflow {
    /// What the version is of.
    pub what: &'static str,
    /// The version that has no next one.
    pub version: u64,
}

impl std::fmt::Display for VersionOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the {} is version {}: there is no next version",
            self.what, self.version
        )
    }
}

impl std::error::Error for VersionOverflow {}

/// The version after `version` of `what`.
///
/// # Errors
///
/// [`VersionOverflow`] for [`u64::MAX`].
pub fn next_version(what: &'static str, version: u64) -> Result<u64, VersionOverflow> {
    version
        .checked_add(1)
        .ok_or(VersionOverflow { what, version })
}

/// Removes `paths` (the files a failed run made). Returns what could not be removed, as
/// `"; could not remove: <path> (<error>), …"`, or nothing: the caller adds it to its error,
/// so that a file left behind is never silent.
pub fn remove_created(paths: &[PathBuf]) -> String {
    let failed: Vec<String> = paths
        .iter()
        .filter_map(|path| match fs::remove_file(path) {
            Ok(()) => None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => Some(format!("{} ({e})", path.display())),
        })
        .collect();
    if failed.is_empty() {
        String::new()
    } else {
        format!("; could not remove: {}", failed.join(", "))
    }
}

/// The moment `days` days after `now`, in whole seconds.
pub fn expiry(now: OffsetDateTime, days: i64) -> OffsetDateTime {
    whole_seconds(now) + Duration::days(days)
}

/// A time given on the command line: RFC 3339 (`2026-12-01T10:00:00Z`) or Unix seconds.
///
/// # Errors
///
/// If it is neither.
pub fn parse_time(text: &str) -> anyhow::Result<OffsetDateTime> {
    if let Ok(seconds) = text.parse::<i64>() {
        return OffsetDateTime::from_unix_timestamp(seconds)
            .with_context(|| format!("{text} is not a Unix time"));
    }
    OffsetDateTime::parse(text, &Rfc3339)
        .with_context(|| format!("{text:?} is neither RFC 3339 nor Unix seconds"))
}

/// `expires` as the metadata spells it (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn show_time(time: OffsetDateTime) -> String {
    oncl_update::tuf::model::format_expires(time).unwrap_or_else(|_| time.to_string())
}

/// Where the passphrase of the encrypted key files comes from.
#[derive(Clone, Debug)]
pub enum PassphraseSource {
    /// Asked on the terminal, without echo.
    Prompt,
    /// The first line of this file (for automation and tests; the file is as secret as the
    /// keys).
    File(PathBuf),
}

impl PassphraseSource {
    /// The passphrase of existing keys.
    ///
    /// # Errors
    ///
    /// If it cannot be read, or is empty.
    pub fn get(&self, prompt: &str) -> anyhow::Result<Zeroizing<String>> {
        let text = match self {
            PassphraseSource::Prompt => Zeroizing::new(
                rpassword::prompt_password(prompt).context("reading the passphrase")?,
            ),
            PassphraseSource::File(path) => read_passphrase_file(path)?,
        };
        if text.is_empty() {
            bail!("the passphrase must not be empty");
        }
        Ok(text)
    }

    /// The passphrase of new keys: asked twice.
    ///
    /// # Errors
    ///
    /// If it cannot be read, is empty, or the two entries differ.
    pub fn get_new(&self, prompt: &str) -> anyhow::Result<Zeroizing<String>> {
        let first = self.get(prompt)?;
        if matches!(self, PassphraseSource::Prompt) {
            let again = self.get("The passphrase again: ")?;
            if again != first {
                bail!("the passphrases differ");
            }
        }
        Ok(first)
    }
}

fn read_passphrase_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let text = Zeroizing::new(
        fs::read_to_string(path)
            .with_context(|| format!("reading the passphrase file {}", path.display()))?,
    );
    let line = text.lines().next().unwrap_or("");
    Ok(Zeroizing::new(line.to_owned()))
}

/// One thing a check found wrong or worth a warning: a stable `code` (documented in
/// `docs/dev/release.md`) and a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The stable code.
    pub code: &'static str,
    /// The message for the operator.
    pub message: String,
}

impl Problem {
    /// A problem.
    pub fn new(code: &'static str, message: impl Into<String>) -> Problem {
        Problem {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_version_has_no_next_one() {
        assert_eq!(next_version("targets", 41), Ok(42));
        assert_eq!(
            next_version("targets", u64::MAX),
            Err(VersionOverflow {
                what: "targets",
                version: u64::MAX
            })
        );
    }

    #[test]
    fn whole_seconds_drops_only_the_sub_seconds() {
        let t = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        assert_eq!(whole_seconds(t + Duration::milliseconds(999)), t);
        assert_eq!(whole_seconds(t), t);
    }

    #[test]
    fn a_file_that_cannot_be_removed_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("made.json");
        fs::write(&file, b"x").unwrap();
        let gone = dir.path().join("never-made.json");
        assert_eq!(remove_created(&[file.clone(), gone]), "");
        assert!(!file.exists());
        // A directory is not a file: removing it as one fails, and says so.
        let stuck = dir.path().join("stuck");
        fs::create_dir(&stuck).unwrap();
        assert!(remove_created(&[stuck]).contains("could not remove"));
    }
}
