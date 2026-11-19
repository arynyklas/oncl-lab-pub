//! `publishers/sdk-revisions.toml`: the commits of this repository's released SDK a plugin may
//! take `oncl-pdk` and the rest of the SDK chain ([`crate::sdk_delivery::CHAIN`]) from
//! (docs/design/publishers.md, check 17 and Р44). The SDK is not on crates.io: a publisher
//! names this repository as a git dependency with the release's tag, and its `Cargo.lock`
//! pins the tag's commit, which must be one of these.
//!
//! ```toml
//! [[revision]]
//! tag = "v0.1.2"                                       # the release tag
//! commit = "cccfbb61274a8bdf715a3f72fcc65f3461218ef5"  # the commit it points to
//! ```
//!
//! The release process appends the new tag's entry (`cargo xtask sdk revision add v<version>`,
//! [`SdkRevisions::append`]). An entry is never changed or removed
//! ([`SdkRevisions::check_kept`]), and `vendor check-onboarding --base` checks each against
//! the repository's tags ([`SdkRevisions::check_tags`]). The schema is strict: unknown keys
//! are refused and tags are distinct.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, bail};
use oncl_update::Version;
use serde::Deserialize;

/// The file, in `publishers/`.
pub const FILE_NAME: &str = "sdk-revisions.toml";

/// The largest file read.
const MAX_LEN: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    revision: Vec<RawRevision>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRevision {
    tag: String,
    commit: String,
}

/// One released SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkRevision {
    /// The release tag, `v<version>`.
    pub tag: String,
    /// The commit (40 lowercase hex) the tag points to.
    pub commit: String,
}

/// The released SDK commits, in the order of the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SdkRevisions {
    revisions: Vec<SdkRevision>,
}

fn is_commit(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `tag` is `v` and a version without build metadata (`v0.1.2`, `v0.1.2-beta.1`).
pub fn is_release_tag(tag: &str) -> bool {
    tag.strip_prefix('v')
        .and_then(|v| Version::parse(v).ok())
        .is_some_and(|v| v.build.is_empty())
}

impl SdkRevisions {
    /// Reads `publishers/sdk-revisions.toml` text.
    ///
    /// # Errors
    ///
    /// A key the schema does not have, a tag that is not `v<version>`, a commit that is not
    /// 40 lowercase hex, or a tag listed twice.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let raw: RawFile = toml::from_str(text).context("reading the SDK revisions")?;
        let mut seen = BTreeSet::new();
        let mut revisions = Vec::with_capacity(raw.revision.len());
        for (n, raw) in raw.revision.into_iter().enumerate() {
            let at = format!("revision {} ({})", n + 1, raw.tag);
            if !is_release_tag(&raw.tag) {
                bail!("{at}: the tag is not v<version>");
            }
            if !seen.insert(raw.tag.clone()) {
                bail!("{at}: the tag is listed twice");
            }
            if !is_commit(&raw.commit) {
                bail!("{at}: the commit is not 40 lowercase hex");
            }
            revisions.push(SdkRevision {
                tag: raw.tag,
                commit: raw.commit,
            });
        }
        Ok(Self { revisions })
    }

    /// Reads the file at `path`.
    ///
    /// # Errors
    ///
    /// The file is unreadable or too large, or [`SdkRevisions::parse`] refuses it.
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let bytes = oncl_pack::read_limited(path, MAX_LEN)?;
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("{} is not UTF-8", path.display()))?;
        Self::parse(text).with_context(|| format!("reading {}", path.display()))
    }

    /// The file of the registry directory `publishers`; none without it.
    ///
    /// # Errors
    ///
    /// As [`SdkRevisions::read`].
    pub fn in_dir(publishers: &Path) -> anyhow::Result<Self> {
        let path = publishers.join(FILE_NAME);
        if path.is_file() {
            Self::read(&path)
        } else {
            Ok(Self::default())
        }
    }

    /// The release whose tag points to `commit`, if one does.
    pub fn by_commit(&self, commit: &str) -> Option<&SdkRevision> {
        self.revisions.iter().find(|r| r.commit == commit)
    }

    /// The entries in the order of the file.
    pub fn iter(&self) -> impl Iterator<Item = &SdkRevision> {
        self.revisions.iter()
    }

    /// Checks that these revisions keep every entry of `base` (the file on `main`) unchanged
    /// and in its place: new entries come only after them.
    ///
    /// # Errors
    ///
    /// An entry of `base` is missing, changed or moved.
    pub fn check_kept(&self, base: &Self) -> anyhow::Result<()> {
        for (n, old) in base.revisions.iter().enumerate() {
            if self.revisions.get(n) != Some(old) {
                bail!(
                    "SDK revision {} ({}) is changed, moved or removed: entries of {FILE_NAME} \
                     are never touched, so the plugins built on them can still be rebuilt",
                    n + 1,
                    old.tag
                );
            }
        }
        Ok(())
    }

    /// Checks every entry against the tags of the repository at `repo`: the tag exists and
    /// points to the entry's commit.
    ///
    /// # Errors
    ///
    /// A tag is missing (a clone without tags fails too) or points elsewhere.
    pub fn check_tags(&self, repo: &Path) -> anyhow::Result<()> {
        let git = crate::vendor::git::Git::new(repo);
        for revision in &self.revisions {
            let commit = git
                .commit(&format!("refs/tags/{}", revision.tag))
                .with_context(|| format!("{FILE_NAME} lists {}", revision.tag))?;
            if commit != revision.commit {
                bail!(
                    "{FILE_NAME} lists {} at {}, the tag points to {commit}",
                    revision.tag,
                    revision.commit
                );
            }
        }
        Ok(())
    }

    /// Appends the entry of `tag` at `commit` to the file at `path` (created if missing,
    /// its comments kept) and returns the file's new text.
    ///
    /// # Errors
    ///
    /// The tag is listed already, the entry is malformed, or the file does not read or write.
    pub fn append(path: &Path, tag: &str, commit: &str) -> anyhow::Result<String> {
        let mut text = if path.is_file() {
            let bytes = oncl_pack::read_limited(path, MAX_LEN)?;
            String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?
        } else {
            String::new()
        };
        let before = Self::parse(&text).with_context(|| format!("reading {}", path.display()))?;
        if let Some(listed) = before.revisions.iter().find(|r| r.tag == tag) {
            bail!("{tag} is listed already, at {}", listed.commit);
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&format!(
            "[[revision]]\ntag = \"{tag}\"\ncommit = \"{commit}\"\n"
        ));
        Self::parse(&text)?.check_kept(&before)?;
        std::fs::write(path, &text).with_context(|| format!("writing {}", path.display()))?;
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "cccfbb61274a8bdf715a3f72fcc65f3461218ef5";
    const B: &str = "703c4facbed6425b0695e231188182086dcf217e";

    fn entry(tag: &str, commit: &str) -> String {
        format!("[[revision]]\ntag = \"{tag}\"\ncommit = \"{commit}\"\n")
    }

    fn error(text: &str) -> String {
        format!("{:#}", SdkRevisions::parse(text).unwrap_err())
    }

    #[test]
    fn the_committed_file_reads_and_matches_the_tags() {
        let root = oncl_testkit::workspace_root();
        let revisions = SdkRevisions::read(&root.join("publishers").join(FILE_NAME)).unwrap();
        assert!(revisions.by_commit(A).is_some_and(|r| r.tag == "v0.1.2"));
        // Tags are only in a full clone; CI checks them in `vendor check-onboarding --base`.
        if revisions.check_tags(&root).is_err() {
            eprintln!("skipped: the tags of {FILE_NAME} are not in this clone");
        }
    }

    #[test]
    fn entries_read_in_order() {
        let revisions =
            SdkRevisions::parse(&(entry("v0.1.2-beta.1", B) + &entry("v0.1.2", A))).unwrap();
        let tags: Vec<&str> = revisions.iter().map(|r| r.tag.as_str()).collect();
        assert_eq!(tags, ["v0.1.2-beta.1", "v0.1.2"]);
        assert_eq!(revisions.by_commit(B).unwrap().tag, "v0.1.2-beta.1");
        assert!(revisions.by_commit(&"0".repeat(40)).is_none());
        assert_eq!(SdkRevisions::parse("").unwrap(), SdkRevisions::default());
    }

    #[test]
    fn malformed_entries_are_refused() {
        assert!(error(&entry("0.1.2", A)).contains("v<version>"));
        assert!(error(&entry("v0.1.2+build", A)).contains("v<version>"));
        assert!(error(&entry("main", A)).contains("v<version>"));
        assert!(error(&entry("v0.1.2", &A.to_uppercase())).contains("40 lowercase hex"));
        assert!(error(&entry("v0.1.2", &A[..12])).contains("40 lowercase hex"));
        assert!(error(&(entry("v0.1.2", A) + &entry("v0.1.2", B))).contains("twice"));
        assert!(error(&(entry("v0.1.2", A) + "added = 2026-11-19\n")).contains("unknown field"));
    }

    #[test]
    fn entries_are_never_changed_moved_or_removed() {
        let base = SdkRevisions::parse(&entry("v0.1.1", B)).unwrap();
        let grown = SdkRevisions::parse(&(entry("v0.1.1", B) + &entry("v0.1.2", A))).unwrap();
        grown.check_kept(&base).unwrap();
        base.check_kept(&base).unwrap();
        let changed = SdkRevisions::parse(&entry("v0.1.1", A)).unwrap();
        assert!(changed.check_kept(&base).is_err(), "changed");
        let moved = SdkRevisions::parse(&(entry("v0.1.2", A) + &entry("v0.1.1", B))).unwrap();
        assert!(moved.check_kept(&base).is_err(), "moved");
        assert!(
            SdkRevisions::default().check_kept(&base).is_err(),
            "removed"
        );
    }

    #[test]
    fn append_keeps_the_comments_and_refuses_a_listed_tag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, "# The released SDK.\n").unwrap();
        SdkRevisions::append(&path, "v0.1.1", B).unwrap();
        let text = SdkRevisions::append(&path, "v0.1.2", A).unwrap();
        assert_eq!(
            text,
            format!(
                "# The released SDK.\n\n{}\n{}",
                entry("v0.1.1", B),
                entry("v0.1.2", A)
            )
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        let error = format!(
            "{:#}",
            SdkRevisions::append(&path, "v0.1.2", B).unwrap_err()
        );
        assert!(error.contains("listed already"), "{error}");
        assert!(SdkRevisions::append(&path, "v0.1.3", "zz").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }
}
