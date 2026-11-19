//! `publishers/builders.toml`: the builder images a publisher's release may name in
//! `custom.oncl.source.builder` (docs/design/publishers.md, «Сборщик», check 12). Each is
//! [`IMAGE`] by its digest, built by `.github/workflows/plugin-builder.yml` from
//! `xtask/assets/plugin-builder/Dockerfile` at `commit`. Only the owner adds an entry, at the
//! end; an entry is never changed or removed, so old releases can still be rebuilt
//! ([`Builders::check_kept`]).
//!
//! ```toml
//! [[builder]]
//! digest = "sha256:<64 lowercase hex>"  # the image's manifest digest
//! commit = "<40 lowercase hex>"         # the commit of this repository it was built from
//! rust = "1.99.1"                       # the Rust release inside
//! added = 2026-11-19                    # when it was listed
//! ```
//!
//! The schema is strict: unknown keys are refused, digests are distinct, and `added` never
//! goes back from one entry to the next.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, bail};
use oncl_update::Version;
use serde::Deserialize;
use time::{Date, Month};

/// The file, in `publishers/`.
pub const FILE_NAME: &str = "builders.toml";

/// The image every entry is a digest of.
pub const IMAGE: &str = "ghcr.io/arynyklas/oncl-plugin-builder";

/// The largest file read.
const MAX_LEN: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    builder: Vec<RawBuilder>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBuilder {
    digest: String,
    commit: String,
    rust: String,
    added: toml::value::Datetime,
}

/// One builder image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Builder {
    /// `sha256:<64 lowercase hex>`, the image's manifest digest.
    pub digest: String,
    /// The commit (40 lowercase hex) of this repository the image was built from.
    pub commit: String,
    /// The Rust release inside.
    pub rust: Version,
    /// When the owner listed it.
    pub added: Date,
}

impl Builder {
    /// The image reference by digest: `ghcr.io/arynyklas/oncl-plugin-builder@sha256:…`.
    pub fn image(&self) -> String {
        format!("{IMAGE}@{}", self.digest)
    }
}

/// The builder images, in the order of the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Builders {
    builders: Vec<Builder>,
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Builders {
    /// Reads `publishers/builders.toml` text.
    ///
    /// # Errors
    ///
    /// A key the schema does not have, a malformed field, a digest listed twice, or an
    /// `added` earlier than the entry before it.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let raw: RawFile = toml::from_str(text).context("reading the builders")?;
        let mut seen = BTreeSet::new();
        let mut builders: Vec<Builder> = Vec::with_capacity(raw.builder.len());
        for (n, raw) in raw.builder.into_iter().enumerate() {
            let at = format!("builder {} ({})", n + 1, raw.digest);
            if !raw
                .digest
                .strip_prefix("sha256:")
                .is_some_and(|hex| is_hex(hex, 64))
            {
                bail!("{at}: the digest is not sha256:<64 lowercase hex>");
            }
            if !seen.insert(raw.digest.clone()) {
                bail!("{at}: the digest is listed twice");
            }
            if !is_hex(&raw.commit, 40) {
                bail!("{at}: the commit is not 40 lowercase hex");
            }
            let rust = Version::parse(&raw.rust)
                .ok()
                .filter(|v| v.pre.is_empty() && v.build.is_empty())
                .with_context(|| format!("{at}: rust {:?} is not a Rust release", raw.rust))?;
            let added = match (raw.added.date, raw.added.time, raw.added.offset) {
                (Some(date), None, None) => Month::try_from(date.month).ok().and_then(|month| {
                    Date::from_calendar_date(date.year.into(), month, date.day).ok()
                }),
                _ => None,
            }
            .with_context(|| format!("{at}: added is not a date (YYYY-MM-DD)"))?;
            if let Some(last) = builders.last()
                && added < last.added
            {
                bail!(
                    "{at}: added {added} is before the entry above it ({})",
                    last.added
                );
            }
            builders.push(Builder {
                digest: raw.digest,
                commit: raw.commit,
                rust,
                added,
            });
        }
        Ok(Self { builders })
    }

    /// Reads the file at `path`.
    ///
    /// # Errors
    ///
    /// The file is missing, unreadable or too large, or [`Builders::parse`] refuses it.
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let bytes = oncl_pack::read_limited(path, MAX_LEN)?;
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("{} is not UTF-8", path.display()))?;
        Self::parse(text).with_context(|| format!("reading {}", path.display()))
    }

    /// The entry of `digest` (`sha256:…`).
    pub fn get(&self, digest: &str) -> Option<&Builder> {
        self.builders.iter().find(|b| b.digest == digest)
    }

    /// The entries in the order of the file.
    pub fn iter(&self) -> impl Iterator<Item = &Builder> {
        self.builders.iter()
    }

    /// Checks that these builders keep every entry of `base` (the file on `main`) unchanged
    /// and in its place: new entries come only after them.
    ///
    /// # Errors
    ///
    /// An entry of `base` is missing, changed or moved.
    pub fn check_kept(&self, base: &Self) -> anyhow::Result<()> {
        for (n, old) in base.builders.iter().enumerate() {
            match self.builders.get(n) {
                Some(new) if new == old => {}
                Some(_) | None => bail!(
                    "builder {} ({}) is changed, moved or removed: entries of {FILE_NAME} are \
                     never touched, so the releases built with them can still be rebuilt",
                    n + 1,
                    old.digest
                ),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str =
        "sha256:a2cb97f28e8e44afe72af2cf31c32ccd365b65d9cc2e9b6a2d48c47b5dbaf94b";
    const DIGEST_B: &str =
        "sha256:05aa9d444d133af574add44561a094296c8254604b31adfa28197a5e16235f54";
    const COMMIT: &str = "102775c5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn entry(digest: &str, added: &str) -> String {
        format!(
            "[[builder]]\ndigest = \"{digest}\"\ncommit = \"{COMMIT}\"\nrust = \"1.99.1\"\nadded = {added}\n"
        )
    }

    fn error(text: &str) -> String {
        format!("{:#}", Builders::parse(text).unwrap_err())
    }

    #[test]
    fn the_file_of_the_repository_reads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(crate::publishers::PUBLISHERS_DIR)
            .join(FILE_NAME);
        Builders::read(&path).unwrap();
    }

    #[test]
    fn entries_read_in_order() {
        let builders =
            Builders::parse(&(entry(DIGEST_A, "2026-11-19") + &entry(DIGEST_B, "2026-11-19")))
                .unwrap();
        let all: Vec<&str> = builders.iter().map(|b| b.digest.as_str()).collect();
        assert_eq!(all, [DIGEST_A, DIGEST_B]);
        let a = builders.get(DIGEST_A).unwrap();
        assert_eq!(a.image(), format!("{IMAGE}@{DIGEST_A}"));
        assert_eq!(a.rust, Version::new(1, 99, 1));
        assert_eq!(
            a.added,
            Date::from_calendar_date(2026, Month::November, 19).unwrap()
        );
        assert!(builders.get("sha256:00").is_none());
        assert_eq!(Builders::parse("").unwrap(), Builders::default());
    }

    #[test]
    fn malformed_entries_are_refused() {
        let good = entry(DIGEST_A, "2026-11-19");
        for (text, expected) in [
            (good.replace("sha256:", "sha512:"), "the digest is not"),
            (
                good.replace(
                    DIGEST_A,
                    &DIGEST_A.to_uppercase().replace("SHA256", "sha256"),
                ),
                "the digest is not",
            ),
            (good.replace(COMMIT, "102775c5"), "the commit is not"),
            (good.replace("1.99.1", "1.99"), "is not a Rust release"),
            (
                good.replace("1.99.1", "1.99.1-beta.1"),
                "is not a Rust release",
            ),
            (
                good.replace("2026-11-19", "2026-11-19T10:00:00"),
                "added is not a date",
            ),
            (good.replace("2026-11-19", "\"2026-11-19\""), "invalid type"),
            (good.clone() + "image = \"x\"\n", "unknown field"),
            (good.clone() + &good, "listed twice"),
            (
                good.clone() + &entry(DIGEST_B, "2026-11-18"),
                "is before the entry above it",
            ),
            ("[[builders]]\n".to_owned(), "unknown field"),
        ] {
            let error = error(&text);
            assert!(error.contains(expected), "{text}: {error}");
        }
    }

    #[test]
    fn entries_are_never_changed_moved_or_removed() {
        let base = Builders::parse(&entry(DIGEST_A, "2026-11-19")).unwrap();
        let grown =
            Builders::parse(&(entry(DIGEST_A, "2026-11-19") + &entry(DIGEST_B, "2026-11-20")))
                .unwrap();
        grown.check_kept(&base).unwrap();
        base.check_kept(&base).unwrap();
        assert!(base.check_kept(&grown).is_err(), "removed");
        let changed =
            Builders::parse(&entry(DIGEST_A, "2026-11-19").replace("1.99.1", "1.99.2")).unwrap();
        assert!(changed.check_kept(&base).is_err(), "changed");
        let moved =
            Builders::parse(&(entry(DIGEST_B, "2026-11-19") + &entry(DIGEST_A, "2026-11-20")))
                .unwrap();
        let error = format!("{:#}", moved.check_kept(&base).unwrap_err());
        assert!(error.contains("never touched"), "{error}");
    }
}
