//! `xtask::files`: secret key files are written only where git would not commit them.

use std::fs;
use std::path::Path;
use std::process::Command;

use xtask::files;

/// Whether `git` runs; prints the skip line (or fails under `ONCL_REQUIRE_ORACLES`) when not.
fn has_git() -> bool {
    oncl_testkit::tool::GIT.or_skip(&["--version"]).is_some()
}

/// Runs `git`; the test has checked [`has_git`] first.
fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "tag.forceSignAnnotated=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

fn error_text(result: anyhow::Result<impl std::fmt::Debug>) -> String {
    format!("{:#}", result.unwrap_err())
}

const SECRET: &str = "secret.key";

#[test]
fn a_tracked_secret_key_counts_as_committable() {
    if !has_git() {
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    fs::write(repo.path().join(".gitignore"), "/keys/\n").unwrap();
    let secret = repo.path().join("keys").join(SECRET);
    fs::create_dir(repo.path().join("keys")).unwrap();
    fs::write(&secret, "not a key").unwrap();
    files::refuse_committable(&secret).unwrap();
    git(repo.path(), &["add", "--force", "keys"]);
    assert!(error_text(files::refuse_committable(&secret)).contains("not ignored"));
}

#[test]
fn a_linked_work_tree_is_a_work_tree() {
    if !has_git() {
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let repo = base.path().join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "--quiet"]);
    git(
        &repo,
        &["commit", "--quiet", "--allow-empty", "-m", "start"],
    );
    let linked = base.path().join("linked");
    git(
        &repo,
        &["worktree", "add", "--quiet", linked.to_str().unwrap()],
    );
    assert!(linked.join(".git").is_file());
    let result = files::refuse_committable(&linked.join("keys").join(SECRET));
    assert!(error_text(result).contains("not ignored"));
}

#[test]
fn a_directory_inside_dot_git_is_not_committable() {
    // Nothing under `.git` is committed, and git would call a path there not ignored.
    if !has_git() {
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    let secret = repo.path().join(".git").join("oncl-keys").join(SECRET);
    files::refuse_committable(&secret).unwrap();
}

#[test]
fn a_work_tree_git_cannot_discover_is_refused() {
    // A linked work tree whose main repository is gone: git's own discovery dies there,
    // but the directory still belongs to a work tree that could commit the key once the
    // repository is back.
    if !has_git() {
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let linked = base.path().join("linked");
    fs::create_dir_all(&linked).unwrap();
    let gone = base.path().join("gone").display().to_string();
    fs::write(
        linked.join(".git"),
        format!("gitdir: {}\n", gone.replace('\\', "/")),
    )
    .unwrap();
    let keys = linked.join("keys");
    let text = error_text(files::refuse_committable(&keys.join(SECRET)));
    assert!(text.contains("check-ignore failed"), "{text}");
}

#[test]
fn the_directory_is_resolved_before_git_is_asked() {
    if !has_git() {
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let repo = base.path().join("repo");
    fs::create_dir_all(repo.join("inside")).unwrap();
    git(&repo, &["init", "--quiet"]);

    // `repo/../keys` is beside the work tree, not in it.
    let beside = repo.join("..").join("keys");
    files::refuse_committable(&beside.join(SECRET)).unwrap();

    // A link from outside into the work tree.
    let link = base.path().join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(repo.join("inside"), &link).unwrap();
    #[cfg(windows)]
    {
        let status = Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&link)
            .arg(repo.join("inside"))
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J");
    }
    let result = files::refuse_committable(&link.join("keys").join(SECRET));
    assert!(error_text(result).contains("not ignored"));
}

#[test]
fn a_new_file_is_never_written_over_an_existing_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SECRET);
    files::write_new(&path, b"first", true).unwrap();
    assert!(error_text(files::write_new(&path, b"second", true)).contains("creating"));
    assert_eq!(fs::read(&path).unwrap(), b"first");
}

#[cfg(unix)]
#[test]
fn only_the_owner_reads_a_private_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SECRET);
    files::write_new(&path, b"key", true).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
