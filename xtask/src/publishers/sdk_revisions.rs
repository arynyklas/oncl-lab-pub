//! `publishers/sdk-revisions.toml`: the commits of this repository's released SDK a plugin may
//! take `oncl-pdk` and the rest of the SDK chain ([`crate::sdk_delivery::CHAIN`]) from
//! (docs/design/publishers.md, check 17 and Р44). The SDK is not on crates.io: a publisher
//! names this repository as a git dependency with the release's tag, and its `Cargo.lock`
//! pins the tag's commit, which must be one of these.
//!
//! ```toml
//! [[revision]]
//! tag = "v0.1.2"                                       # the release tag
//! commit = "cccfbb61274a8bdf715a3f72fcc65f3461218ef5"  # a commit it pointed to
//! ```
//!
//! The release process appends the new tag's entry (`cargo xtask sdk revision add v<version>`,
//! [`SdkRevisions::add`]). An entry is never changed or removed
//! ([`SdkRevisions::check_kept`]), and `vendor check-onboarding --base` checks the entries
//! against the repository's tags ([`SdkRevisions::check_tags`]). The schema is strict:
//! unknown keys are refused and no entry is listed twice.
//!
//! A tag moved before its publication (a fix of the release workflow) gets a second entry at
//! its new commit, the old one stays: a plugin may already pin it. Each tag points to the
//! commit of one of its entries, and every other entry of the tag holds the same SDK
//! ([`sdk_difference`]): the trees of the [`crate::sdk_delivery::CHAIN`] crates and what they
//! inherit from the root `Cargo.toml`.
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
    /// 40 lowercase hex, or an entry (tag and commit) listed twice.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let raw: RawFile = toml::from_str(text).context("reading the SDK revisions")?;
        let mut seen = BTreeSet::new();
        let mut revisions = Vec::with_capacity(raw.revision.len());
        for (n, raw) in raw.revision.into_iter().enumerate() {
            let at = format!("revision {} ({})", n + 1, raw.tag);
            if !is_release_tag(&raw.tag) {
                bail!("{at}: the tag is not v<version>");
            }
            if !is_commit(&raw.commit) {
                bail!("{at}: the commit is not 40 lowercase hex");
            }
            if !seen.insert((raw.tag.clone(), raw.commit.clone())) {
                bail!("{at}: the entry is listed twice");
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

    /// The entry of `commit`, if one lists it.
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

    /// Checks the entries against the tags of the repository at `repo`. Each listed tag
    /// exists and points to the commit of one of its entries; every other entry of the tag
    /// holds the same SDK as that commit ([`sdk_difference`]).
    ///
    /// # Errors
    ///
    /// A tag is missing (a clone without tags fails too), points to a commit none of its
    /// entries lists, or an entry of it holds another SDK.
    pub fn check_tags(&self, repo: &Path) -> anyhow::Result<()> {
        let git = crate::vendor::git::Git::new(repo);
        let mut tags: Vec<&str> = Vec::new();
        for revision in &self.revisions {
            if !tags.contains(&revision.tag.as_str()) {
                tags.push(&revision.tag);
            }
        }
        for tag in tags {
            let pointed = git
                .commit(&format!("refs/tags/{tag}"))
                .with_context(|| format!("{FILE_NAME} lists {tag}"))?;
            let listed: Vec<&str> = self
                .revisions
                .iter()
                .filter(|r| r.tag == tag)
                .map(|r| r.commit.as_str())
                .collect();
            if !listed.contains(&pointed.as_str()) {
                bail!(
                    "{FILE_NAME} lists {tag} at {}, the tag points to {pointed}: after moving \
                     the tag, run `cargo xtask sdk revision add {tag}`",
                    listed.join(", ")
                );
            }
            for commit in listed.into_iter().filter(|c| *c != pointed) {
                let differs = sdk_difference(&git, commit, &pointed)?;
                if !differs.is_empty() {
                    bail!(
                        "{FILE_NAME} lists {tag} at {commit}, the tag points to {pointed} with \
                         another SDK ({}): a released SDK never changes",
                        differs.join(", ")
                    );
                }
            }
        }
        Ok(())
    }

    /// `sdk revision add`: appends the entry of `tag` at `commit` (the commit the tag points
    /// to in the repository at `repo`) to the file at `path` (created if missing, its
    /// comments kept) and returns the file's new text. A tag listed already is appended
    /// again only if it was moved: none of its entries is `commit`, and each holds the same
    /// SDK as `commit` ([`sdk_difference`]).
    ///
    /// # Errors
    ///
    /// The entry is listed already, the moved tag holds another SDK, the entry is
    /// malformed, git fails, or the file does not read or write.
    pub fn add(path: &Path, repo: &Path, tag: &str, commit: &str) -> anyhow::Result<String> {
        let mut text = if path.is_file() {
            let bytes = oncl_pack::read_limited(path, MAX_LEN)?;
            String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?
        } else {
            String::new()
        };
        let before = Self::parse(&text).with_context(|| format!("reading {}", path.display()))?;
        let git = crate::vendor::git::Git::new(repo);
        for listed in before.revisions.iter().filter(|r| r.tag == tag) {
            if listed.commit == commit {
                bail!("{tag} is listed already, at {commit}");
            }
            let differs = sdk_difference(&git, &listed.commit, commit)?;
            if !differs.is_empty() {
                bail!(
                    "{tag} is listed at {}, and its new commit {commit} holds another SDK ({}): \
                     a released SDK never changes, release a new version",
                    listed.commit,
                    differs.join(", ")
                );
            }
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

/// The root `Cargo.toml` tables the SDK crates inherit from (`version.workspace = true`,
/// `<dep>.workspace = true`); the rest of it (`[patch]`, `[profile]`, members) does not
/// reach a git dependent.
const INHERITED: [&str; 2] = ["package", "dependencies"];

/// What differs in the SDK between the commits `a` and `b`: the paths of
/// `crates/<crate>` (every crate of [`crate::sdk_delivery::CHAIN`]) whose git trees are not
/// the same object, and the `[workspace.<table>]` of the root `Cargo.toml` ([`INHERITED`])
/// that are not equal as TOML. Empty when the SDK is the same. Nothing is checked out.
///
/// # Errors
///
/// A commit is missing, git fails, or a root `Cargo.toml` does not read.
pub fn sdk_difference(
    git: &crate::vendor::git::Git,
    a: &str,
    b: &str,
) -> anyhow::Result<Vec<String>> {
    let mut differs = Vec::new();
    for name in crate::sdk_delivery::CHAIN {
        let path = format!("crates/{name}");
        if git.object(a, &path)? != git.object(b, &path)? {
            differs.push(path);
        }
    }
    let (a_root, b_root) = (inherited(git, a)?, inherited(git, b)?);
    for (table, (x, y)) in INHERITED.iter().zip(a_root.iter().zip(&b_root)) {
        if x != y {
            differs.push(format!("Cargo.toml [workspace.{table}]"));
        }
    }
    Ok(differs)
}

/// The [`INHERITED`] tables of the root `Cargo.toml` at `rev` (`None` for a missing one).
fn inherited(git: &crate::vendor::git::Git, rev: &str) -> anyhow::Result<[Option<toml::Value>; 2]> {
    let Some(bytes) = git.blob(rev, "Cargo.toml", MAX_LEN)? else {
        return Ok([None, None]);
    };
    let text =
        std::str::from_utf8(&bytes).with_context(|| format!("Cargo.toml of {rev} is not UTF-8"))?;
    let root: toml::Value =
        toml::from_str(text).with_context(|| format!("reading Cargo.toml of {rev}"))?;
    let workspace = root.get("workspace");
    Ok(INHERITED.map(|table| workspace.and_then(|w| w.get(table)).cloned()))
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
        assert!(error(&(entry("v0.1.2", A) + &entry("v0.1.2", A))).contains("twice"));
        // A moved tag: one entry per commit.
        SdkRevisions::parse(&(entry("v0.1.2", A) + &entry("v0.1.2", B))).unwrap();
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

    /// A repository with an SDK crate and a root `Cargo.toml`, committed by [`Repo::commit`].
    struct Repo {
        dir: tempfile::TempDir,
    }

    impl Repo {
        fn new() -> Self {
            let repo = Self {
                dir: tempfile::tempdir().unwrap(),
            };
            repo.git(&["init", "-q"]);
            repo.write("Cargo.toml", ROOT);
            repo.write("crates/oncl-pdk/src/lib.rs", "pub fn pdk() {}\n");
            repo.write(
                "crates/oncl-pdk/Cargo.toml",
                "[package]\nname = \"oncl-pdk\"\n",
            );
            repo.write(".github/workflows/release.yml", "on: push\n");
            repo
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }

        fn git(&self, args: &[&str]) -> String {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(self.path())
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@example.com",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "tag.gpgsign=false",
                    "-c",
                    "core.autocrlf=false",
                ])
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env(
                    "GIT_CONFIG_GLOBAL",
                    if cfg!(windows) { "NUL" } else { "/dev/null" },
                )
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        }

        fn write(&self, path: &str, text: &str) {
            let path = self.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        /// Commits the work tree and moves (or creates) `tag` to the commit.
        fn commit(&self, tag: &str) -> String {
            self.git(&["add", "-A"]);
            self.git(&["commit", "-q", "--allow-empty", "-m", "c"]);
            self.git(&["tag", "-f", tag]);
            self.git(&["rev-parse", "HEAD"])
        }

        fn file(&self) -> std::path::PathBuf {
            self.path().join(FILE_NAME)
        }

        fn listed(&self, entries: &[(&str, &str)]) -> SdkRevisions {
            let text: String = entries.iter().map(|(t, c)| entry(t, c)).collect();
            SdkRevisions::parse(&text).unwrap()
        }

        fn add(&self, tag: &str, commit: &str) -> anyhow::Result<String> {
            SdkRevisions::add(&self.file(), self.path(), tag, commit)
        }
    }

    const ROOT: &str = "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\n\
                        version = \"0.1.2\"\n\n[workspace.dependencies]\nserde = \"1\"\n\n\
                        [profile.dev]\nopt-level = 0\n";

    fn check_error(revisions: &SdkRevisions, repo: &Repo) -> String {
        format!("{:#}", revisions.check_tags(repo.path()).unwrap_err())
    }

    #[test]
    fn a_tag_moved_without_an_sdk_change_is_listed_again() {
        let repo = Repo::new();
        let first = repo.commit("v0.1.2");
        repo.add("v0.1.2", &first).unwrap();
        repo.listed(&[("v0.1.2", &first)])
            .check_tags(repo.path())
            .unwrap();
        // The release workflow and the root Cargo.toml outside what the SDK inherits change.
        repo.write(".github/workflows/release.yml", "on: workflow_dispatch\n");
        repo.write(
            "Cargo.toml",
            &ROOT.replace("opt-level = 0", "opt-level = 1"),
        );
        repo.write("README.md", "moved\n");
        let moved = repo.commit("v0.1.2");
        // The old entry alone: the commit the tag points to is not listed.
        let error = check_error(&repo.listed(&[("v0.1.2", &first)]), &repo);
        assert!(error.contains("sdk revision add v0.1.2"), "{error}");
        let text = repo.add("v0.1.2", &moved).unwrap();
        assert_eq!(
            text,
            format!("{}\n{}", entry("v0.1.2", &first), entry("v0.1.2", &moved))
        );
        let revisions = SdkRevisions::read(&repo.file()).unwrap();
        revisions.check_tags(repo.path()).unwrap();
        // Both commits stay accepted: plugins pinned to the first one still build.
        assert!(revisions.by_commit(&first).is_some());
        assert!(revisions.by_commit(&moved).is_some());
        let error = format!("{:#}", repo.add("v0.1.2", &moved).unwrap_err());
        assert!(error.contains("listed already"), "{error}");
        assert_eq!(std::fs::read_to_string(repo.file()).unwrap(), text);
    }

    #[test]
    fn a_tag_moved_with_an_sdk_change_is_refused() {
        for change in [
            ("crates/oncl-pdk/src/lib.rs", "pub fn pdk() { todo!() }\n"),
            (
                "Cargo.toml",
                &*ROOT.replace("version = \"0.1.2\"", "version = \"0.1.3\""),
            ),
            (
                "Cargo.toml",
                &*ROOT.replace("serde = \"1\"", "serde = \"=1.0.1\""),
            ),
            ("crates/oncl-gost/src/lib.rs", "pub fn gost() {}\n"),
        ] {
            let repo = Repo::new();
            let first = repo.commit("v0.1.2");
            repo.add("v0.1.2", &first).unwrap();
            repo.write(change.0, change.1);
            let moved = repo.commit("v0.1.2");
            let error = format!("{:#}", repo.add("v0.1.2", &moved).unwrap_err());
            assert!(error.contains("another SDK"), "{change:?}: {error}");
            assert_eq!(
                std::fs::read_to_string(repo.file()).unwrap(),
                entry("v0.1.2", &first)
            );
            let both = repo.listed(&[("v0.1.2", &first), ("v0.1.2", &moved)]);
            let error = check_error(&both, &repo);
            assert!(error.contains("another SDK"), "{change:?}: {error}");
        }
    }

    #[test]
    fn a_missing_or_unlisted_tag_commit_is_refused() {
        let repo = Repo::new();
        let first = repo.commit("v0.1.2");
        let error = check_error(&repo.listed(&[("v0.1.3", &first)]), &repo);
        assert!(error.contains("lists v0.1.3"), "{error}");
        repo.write("README.md", "second\n");
        let second = repo.commit("v0.1.2");
        repo.write("README.md", "third\n");
        repo.commit("v0.1.2");
        // Two entries of the tag, the same SDK, but the tag points to neither.
        let error = check_error(
            &repo.listed(&[("v0.1.2", &first), ("v0.1.2", &second)]),
            &repo,
        );
        assert!(error.contains("sdk revision add v0.1.2"), "{error}");
    }

    #[test]
    fn add_keeps_the_comments_and_refuses_a_listed_entry() {
        let repo = Repo::new();
        let first = repo.commit("v0.1.1");
        repo.write("crates/oncl-pdk/src/lib.rs", "pub fn pdk2() {}\n");
        let second = repo.commit("v0.1.2");
        std::fs::write(repo.file(), "# The released SDK.\n").unwrap();
        repo.add("v0.1.1", &first).unwrap();
        let text = repo.add("v0.1.2", &second).unwrap();
        assert_eq!(
            text,
            format!(
                "# The released SDK.\n\n{}\n{}",
                entry("v0.1.1", &first),
                entry("v0.1.2", &second)
            )
        );
        assert_eq!(std::fs::read_to_string(repo.file()).unwrap(), text);
        let error = format!("{:#}", repo.add("v0.1.2", &second).unwrap_err());
        assert!(error.contains("listed already"), "{error}");
        assert!(repo.add("v0.1.3", "zz").is_err());
        assert_eq!(std::fs::read_to_string(repo.file()).unwrap(), text);
        // After a retag, the old entries are still never changed or removed.
        let base = SdkRevisions::read(&repo.file()).unwrap();
        let replaced = repo.listed(&[("v0.1.1", &first), ("v0.1.2", &first)]);
        assert!(replaced.check_kept(&base).is_err());
    }
}
