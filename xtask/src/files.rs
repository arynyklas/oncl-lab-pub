//! Writing secret and repository files: a file that must not exist yet, and the refusal of a
//! secret key path that git could commit.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

/// Refuses `secret` if it lies in a git work tree and is not ignored there, so the secret
/// key is never committed by accident. A path outside any work tree passes.
///
/// The deepest existing directory of the path is resolved first (symlinks, junctions,
/// `..`), so a link into a work tree is caught and `../keys` beside one is not mistaken for
/// a path in it. The work tree is then the nearest ancestor with a `.git` entry
/// ([`work_tree_top`]), found by reading the directories and not by git's own discovery,
/// which a broken linked work tree, a mount point inside the tree or
/// `GIT_CEILING_DIRECTORIES` can cut short. git says whether the rest of the path is
/// ignored in that tree; a tracked file counts as not ignored.
///
/// # Errors
///
/// If the path is committable, names a directory with `..` after its last existing
/// directory, or git cannot tell.
pub fn refuse_committable(secret: &Path) -> anyhow::Result<()> {
    let absolute =
        std::path::absolute(secret).with_context(|| format!("resolving {}", secret.display()))?;
    let no_name = || format!("{}: no file name", secret.display());
    let mut rest: Vec<OsString> = vec![absolute.file_name().with_context(no_name)?.to_owned()];
    let mut existing = absolute.parent().with_context(no_name)?;
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let name = existing.file_name().with_context(|| {
                    format!(
                        "{}: write the directory without `..` after its last existing part",
                        secret.display()
                    )
                })?;
                rest.push(name.to_owned());
                existing = existing.parent().with_context(no_name)?;
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", existing.display())),
        }
    }
    let dir = plain(
        fs::canonicalize(existing).with_context(|| format!("resolving {}", existing.display()))?,
    );
    let Some(top) = work_tree_top(&dir) else {
        // No work tree above the directory, or it is the `.git` directory of one: nothing
        // there can be committed.
        return Ok(());
    };
    let mut parts: Vec<String> = dir
        .strip_prefix(top)
        .expect("the top is an ancestor of the directory")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    parts.extend(rest.iter().rev().map(|c| c.to_string_lossy().into_owned()));
    let relative = parts.join("/");

    let checked = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["check-ignore", "--quiet", "--"])
        .arg(&relative)
        .output()
        .context("running git to check that the secret key would not be committed")?;
    match checked.status.code() {
        Some(0) => Ok(()),
        Some(1) => bail!(
            "{} is in a git work tree and not ignored: keep the secret key outside the \
             repository (or in an ignored directory)",
            secret.display(),
        ),
        _ => bail!(
            "git check-ignore failed in {} ({}): {}; not writing the secret key there",
            top.display(),
            checked.status,
            String::from_utf8_lossy(&checked.stderr).trim()
        ),
    }
}

/// The root of the git work tree `dir` is in: its nearest ancestor with a `.git` entry (a
/// directory, or the file of a linked work tree). `None` if there is none, or if `dir` is
/// inside that `.git` itself, which holds nothing that is committed.
fn work_tree_top(dir: &Path) -> Option<&Path> {
    let top = dir.ancestors().find(|a| a.join(".git").exists())?;
    (!dir.starts_with(top.join(".git"))).then_some(top)
}

/// `path` without the `\\?\` prefix `canonicalize` gives on Windows, which git may not
/// read.
fn plain(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    if let Some(text) = path.to_str() {
        if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{unc}"));
        }
        if let Some(local) = text.strip_prefix(r"\\?\")
            && local.as_bytes().get(1) == Some(&b':')
        {
            return PathBuf::from(local);
        }
    }
    path
}

/// Writes a file that must not exist yet; `private` makes it readable by its owner only
/// (on Unix).
pub fn write_new(path: &Path, bytes: &[u8], private: bool) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", path.display()))
}
