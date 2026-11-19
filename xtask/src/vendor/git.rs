//! The git repository of a pull request, read as data: which paths it changes, the bytes of a
//! file at a commit, the files under some paths at the base, the time of the last commit of a
//! path. Nothing of a checked-out tree is read; nothing of the pull request is built or run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

/// How a path changed between two commits (`git diff --raw`, without rename detection).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// A new path.
    Added,
    /// New content or mode.
    Modified,
    /// The path is gone.
    Deleted,
    /// A file became a link or the other way round.
    TypeChanged,
    /// Anything else git reports (`U`, `X`).
    Other(char),
}

/// One changed path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// How it changed.
    pub kind: ChangeKind,
    /// Its mode before (`000000` for a new path).
    pub old_mode: String,
    /// Its mode after (`100644` a regular file, `100755` an executable one, `120000` a link,
    /// `160000` a submodule; `000000` for a deleted path).
    pub new_mode: String,
    /// The path, `/`-separated, from the root of the repository.
    pub path: String,
}

/// A git repository.
#[derive(Clone, Debug)]
pub struct Git {
    dir: PathBuf,
}

impl Git {
    /// The repository at (or above) `dir`.
    pub fn new(dir: &Path) -> Git {
        Git {
            dir: dir.to_owned(),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(&self.dir)
            .args(["-c", "core.quotepath=false"])
            // Nothing of the user's or the runner's configuration turns a byte into another.
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            // The objects as stored: a replace ref must not change what a commit holds.
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE");
        command
    }

    fn output(&self, args: &[&str]) -> anyhow::Result<Vec<u8>> {
        let output = self
            .command()
            .args(args)
            .output()
            .with_context(|| format!("running git {}", args.join(" ")))?;
        if !output.status.success() {
            bail!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output.stdout)
    }

    /// The commit `rev` names, as 40 (or 64) hex digits.
    ///
    /// # Errors
    ///
    /// `rev` names no commit.
    pub fn commit(&self, rev: &str) -> anyhow::Result<String> {
        let spec = format!("{rev}^{{commit}}");
        let out = self
            .output(&[
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                &spec,
            ])
            .with_context(|| format!("{rev} is not a commit of {}", self.dir.display()))?;
        Ok(String::from_utf8_lossy(&out).trim().to_owned())
    }

    /// What merging `head` into `base` changes, as GitHub's squash merge computes it
    /// (merge-ort, `git merge-tree --write-tree`): the paths of `base` against the merged
    /// tree. Refused (`Ok(Err(why))`) unless `base` and `head` have exactly one merge base,
    /// no merge commit lies between it and `head`, and the merge has no conflict: otherwise
    /// the diff of the pull request is not what lands.
    ///
    /// # Errors
    ///
    /// Git fails.
    pub fn merged_changes(
        &self,
        base: &str,
        head: &str,
    ) -> anyhow::Result<Result<Vec<Change>, String>> {
        let bases = self.output(&["merge-base", "--all", "--end-of-options", base, head]);
        let bases = match bases {
            Ok(out) => String::from_utf8_lossy(&out).trim().to_owned(),
            Err(_) => return Ok(Err("the head has no common history with main".to_owned())),
        };
        let bases: Vec<&str> = bases.lines().collect();
        let [fork] = bases.as_slice() else {
            return Ok(Err(format!(
                "the head and main have {} merge bases, not one",
                bases.len()
            )));
        };
        let merges = self.output(&[
            "rev-list",
            "--min-parents=2",
            "--end-of-options",
            &format!("{fork}..{head}"),
        ])?;
        if !String::from_utf8_lossy(&merges).trim().is_empty() {
            return Ok(Err(
                "the pull request has a merge commit: rebase it on main".to_owned(),
            ));
        }
        let merged = self
            .command()
            .args(["merge-tree", "--write-tree", "--no-messages", base, head])
            .output()
            .context("running git merge-tree")?;
        let tree = String::from_utf8_lossy(&merged.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        match merged.status.code() {
            Some(0) if !tree.is_empty() => Ok(Ok(self.changes(base, &tree)?)),
            Some(1) => Ok(Err(
                "the pull request does not merge into main cleanly".to_owned()
            )),
            _ => bail!(
                "git merge-tree failed: {}",
                String::from_utf8_lossy(&merged.stderr).trim()
            ),
        }
    }

    /// What changes from `from` to `to`, every path (no rename detection, no pathspec).
    ///
    /// # Errors
    ///
    /// Git fails or prints what this does not read.
    pub fn changes(&self, from: &str, to: &str) -> anyhow::Result<Vec<Change>> {
        let out = self.output(&[
            "diff",
            "--raw",
            "-z",
            "--no-renames",
            "--no-abbrev",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            from,
            to,
        ])?;
        parse_raw(&out)
    }

    /// The bytes of `path` at `rev`, `None` if it is not a file there; more than `limit` bytes
    /// is an error, found before the content is read.
    ///
    /// # Errors
    ///
    /// The file is larger than `limit`, or git fails.
    pub fn blob(&self, rev: &str, path: &str, limit: u64) -> anyhow::Result<Option<Vec<u8>>> {
        let files = self.ls_tree(rev, &[path])?;
        let Some(entry) = files.into_iter().find(|e| e.path == path) else {
            return Ok(None);
        };
        if entry.size > limit {
            bail!("{path} at {rev} is {} bytes, more than {limit}", entry.size);
        }
        Ok(Some(self.output(&["cat-file", "blob", &entry.oid])?))
    }

    /// Every regular file under `paths` (directories or files) at `rev`, by path; one larger
    /// than `limit` is an error. Links and submodules are left out.
    ///
    /// # Errors
    ///
    /// A file is larger than `limit`, or git fails.
    pub fn files(
        &self,
        rev: &str,
        paths: &[&str],
        limit: u64,
    ) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
        let mut files = BTreeMap::new();
        for entry in self.ls_tree(rev, paths)? {
            if !matches!(entry.mode.as_str(), "100644" | "100755") {
                continue;
            }
            if entry.size > limit {
                bail!(
                    "{} at {rev} is {} bytes, more than {limit}",
                    entry.path,
                    entry.size
                );
            }
            let bytes = self.output(&["cat-file", "blob", &entry.oid])?;
            files.insert(entry.path, bytes);
        }
        Ok(files)
    }

    /// The commit time (Unix seconds) of the last commit reachable from `rev` that touched a
    /// path matching the glob `pattern` (`*` does not cross `/`); `None` if none did.
    ///
    /// # Errors
    ///
    /// Git fails.
    pub fn last_commit_time(&self, rev: &str, pattern: &str) -> anyhow::Result<Option<i64>> {
        let spec = format!(":(glob){pattern}");
        let out = self.output(&["log", "-1", "--format=%ct", rev, "--", &spec])?;
        let text = String::from_utf8_lossy(&out);
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        text.parse()
            .map(Some)
            .with_context(|| format!("git log printed {text:?} for a commit time"))
    }

    fn ls_tree(&self, rev: &str, paths: &[&str]) -> anyhow::Result<Vec<TreeEntry>> {
        let mut args = vec!["ls-tree", "-r", "-z", "-l", "--full-tree", rev, "--"];
        args.extend_from_slice(paths);
        let out = self.output(&args)?;
        parse_ls_tree(&out)
    }
}

/// An entry of `git ls-tree -r -l`.
#[derive(Debug)]
struct TreeEntry {
    mode: String,
    oid: String,
    size: u64,
    path: String,
}

fn utf8(bytes: &[u8], what: &str) -> anyhow::Result<String> {
    String::from_utf8(bytes.to_vec()).with_context(|| format!("{what} is not UTF-8"))
}

/// `git ls-tree -r -z -l` output: `<mode> <type> <oid> <size>\t<path>\0`.
fn parse_ls_tree(out: &[u8]) -> anyhow::Result<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    for record in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let tab = record
            .iter()
            .position(|b| *b == b'\t')
            .context("git ls-tree printed a line without a tab")?;
        let head = utf8(&record[..tab], "a git ls-tree line")?;
        let path = utf8(&record[tab + 1..], "a path")?;
        let fields: Vec<&str> = head.split_whitespace().collect();
        let [mode, kind, oid, size] = fields.as_slice() else {
            bail!("git ls-tree printed {head:?}");
        };
        if *kind != "blob" {
            continue;
        }
        entries.push(TreeEntry {
            mode: (*mode).to_owned(),
            oid: (*oid).to_owned(),
            size: size
                .parse()
                .with_context(|| format!("git ls-tree printed the size {size:?}"))?,
            path,
        });
    }
    Ok(entries)
}

/// `git diff --raw -z` output: `:<old mode> <new mode> <old oid> <new oid> <status>\0<path>\0`.
fn parse_raw(out: &[u8]) -> anyhow::Result<Vec<Change>> {
    let mut changes = Vec::new();
    let mut fields = out.split(|b| *b == 0);
    while let Some(head) = fields.next() {
        if head.is_empty() {
            continue;
        }
        let head = utf8(head, "a git diff line")?;
        let words: Vec<&str> = head.trim_start_matches(':').split(' ').collect();
        let [old_mode, new_mode, _, _, status] = words.as_slice() else {
            bail!("git diff --raw printed {head:?}");
        };
        let path = utf8(
            fields
                .next()
                .with_context(|| format!("git diff --raw printed {head:?} without a path"))?,
            "a path",
        )?;
        let kind = match status.chars().next() {
            Some('A') => ChangeKind::Added,
            Some('M') => ChangeKind::Modified,
            Some('D') => ChangeKind::Deleted,
            Some('T') => ChangeKind::TypeChanged,
            Some(other) => ChangeKind::Other(other),
            None => bail!("git diff --raw printed {head:?} without a status"),
        };
        changes.push(Change {
            kind,
            old_mode: (*old_mode).to_owned(),
            new_mode: (*new_mode).to_owned(),
            path,
        });
    }
    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_diff_and_tree_listings_are_read() {
        let z = "0".repeat(40);
        let a = "a".repeat(40);
        let raw = format!(
            ":000000 100644 {z} {a} A\0tuf/v1/metadata/1.pub-ecc.json\0\
             :100644 120000 {a} {a} T\0x y\0"
        );
        let changes = parse_raw(raw.as_bytes()).unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].kind, ChangeKind::Added);
        assert_eq!(changes[0].new_mode, "100644");
        assert_eq!(changes[1].kind, ChangeKind::TypeChanged);
        assert_eq!(changes[1].path, "x y");
        let tree = format!(
            "100644 blob {a}     12\tpublishers/a b.toml\0160000 commit {a}       -\tsub\0"
        );
        let entries = parse_ls_tree(tree.as_bytes()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            (entries[0].size, entries[0].path.as_str()),
            (12, "publishers/a b.toml")
        );
    }
}
