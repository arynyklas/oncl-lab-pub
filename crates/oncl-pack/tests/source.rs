//! The canonical source archive: one input gives one archive, a directory and a git revision
//! of the same files give the same bytes, and every archive `oncl-pack source` would not
//! have written byte for byte is refused.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

use flate2::read::GzDecoder;
use flate2::{Compression, GzBuilder};
use oncl_pack::sha256_hex;
use oncl_pack::source::{ArchiveError, File, MAX_PATH, Tree};

/// The files of the test sources: nested directories, a path too long for the ustar name
/// field, non-ASCII and empty files.
fn files() -> Vec<(String, &'static [u8])> {
    vec![
        (
            "Cargo.toml".into(),
            b"[workspace]\nmembers = [\"crates/*\"]\n",
        ),
        ("Cargo.lock".into(), b"version = 4\n"),
        ("LICENSE".into(), b"Apache-2.0\n"),
        (
            "crates/plug-in/Cargo.toml".into(),
            b"[package]\nname = \"p\"\n",
        ),
        ("crates/plug-in/plugin.toml".into(), b"id = \"x\"\n"),
        (
            "crates/plug-in/src/lib.rs".into(),
            b"// \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82\n",
        ),
        ("crates/plug-in/src/empty.rs".into(), b""),
        ("crates/plug/x.rs".into(), b"fn main() {}\n"),
        (
            "docs/\u{0442}\u{0435}\u{043a}\u{0441}\u{0442}.md".into(),
            b"# text\n",
        ),
        (format!("deep/{}/file.txt", "d".repeat(120)), b"long\n"),
    ]
}

fn write_files(dir: &Path) {
    for (path, data) in files() {
        let path = dir.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
}

fn tree() -> Tree {
    let mut tree = Tree::new();
    for (path, data) in files() {
        tree.insert(
            &path,
            File {
                executable: false,
                data: data.to_vec(),
            },
        )
        .unwrap();
    }
    tree
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut tar = Vec::new();
    GzDecoder::new(bytes).read_to_end(&mut tar).unwrap();
    tar
}

/// gzip as the canonical archive has it (level 9, time 0, system 255), or at `level`.
fn gzip(tar: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::new(level));
    encoder.write_all(tar).unwrap();
    encoder.finish().unwrap()
}

/// The canonical archive of [`tree`] with its tar changed by `edit`, then gzipped as a
/// canonical archive is.
fn edited(edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut tar = gunzip(&tree().to_archive().unwrap());
    edit(&mut tar);
    gzip(&tar, 9)
}

/// The offset of the header whose name field starts with `name`.
fn header_of(tar: &[u8], name: &str) -> usize {
    (0..tar.len())
        .step_by(512)
        .find(|&at| tar[at..].starts_with(name.as_bytes()))
        .unwrap_or_else(|| panic!("no header {name}"))
}

/// Sets a header field and its checksum again, so only the field differs.
fn set_field(tar: &mut [u8], header: usize, range: std::ops::Range<usize>, value: &[u8]) {
    tar[header + range.start..header + range.start + value.len()].copy_from_slice(value);
    tar[header + 148..header + 156].fill(b' ');
    let sum: u32 = tar[header..header + 512]
        .iter()
        .map(|&b| u32::from(b))
        .sum();
    tar[header + 148..header + 156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

fn refused(bytes: &[u8]) -> ArchiveError {
    Tree::from_archive(bytes).unwrap_err()
}

#[test]
fn one_input_gives_one_archive() {
    let first = tree().to_archive().unwrap();
    // Another insertion order, the same files.
    let mut reversed = Tree::new();
    for (path, data) in files().into_iter().rev() {
        reversed
            .insert(
                &path,
                File {
                    executable: false,
                    data: data.to_vec(),
                },
            )
            .unwrap();
    }
    assert_eq!(first, reversed.to_archive().unwrap());
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path());
    assert_eq!(
        first,
        Tree::from_dir(dir.path()).unwrap().to_archive().unwrap()
    );
    assert_eq!(
        first,
        Tree::from_dir(dir.path()).unwrap().to_archive().unwrap()
    );
}

#[test]
fn an_archive_reads_back_into_the_same_files() {
    let bytes = tree().to_archive().unwrap();
    let read = Tree::from_archive(&bytes).unwrap();
    assert_eq!(read, tree());
    let out = tempfile::tempdir().unwrap();
    read.unpack(&out.path().join("src")).unwrap();
    for (path, data) in files() {
        assert_eq!(fs::read(out.path().join("src").join(path)).unwrap(), data);
    }
    assert!(
        read.unpack(&out.path().join("src")).is_err(),
        "unpacking over an existing directory"
    );
}

#[test]
fn the_tar_is_sorted_with_fixed_owners_modes_and_times() {
    let tar = gunzip(&tree().to_archive().unwrap());
    let mut names = Vec::new();
    let mut at = 0;
    while tar[at..at + 512].iter().any(|&b| b != 0) {
        let header = &tar[at..at + 512];
        let size =
            usize::from_str_radix(std::str::from_utf8(&header[124..135]).unwrap(), 8).unwrap();
        let name_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let kind = header[156];
        assert_eq!(
            &header[108..124],
            b"0000000\x000000000\x00",
            "uid and gid 0"
        );
        assert_eq!(&header[136..148], b"02263523000\x00", "1980-01-01");
        assert_eq!(&header[257..265], b"ustar\x0000");
        assert!(header[265..329].iter().all(|&b| b == 0), "no owner names");
        assert!(header[345..].iter().all(|&b| b == 0), "no prefix");
        if kind == b'x' {
            let record = std::str::from_utf8(&tar[at + 512..at + 512 + size]).unwrap();
            names.push(record.split_once("path=").unwrap().1.trim_end().to_owned());
        } else {
            let name = std::str::from_utf8(&header[..name_end]).unwrap();
            if names
                .last()
                .is_none_or(|last: &String| !last.starts_with(name))
            {
                names.push(name.to_owned());
            }
            let mode = if kind == b'5' {
                "0000755\0"
            } else {
                "0000644\0"
            };
            assert_eq!(&header[100..108], mode.as_bytes(), "{name}");
        }
        at += 512 + size.next_multiple_of(512);
    }
    assert_eq!(tar.len(), at + 1024, "two zero blocks, no record padding");
    let keys: Vec<String> = names
        .iter()
        .map(|n| n.trim_end_matches('/').to_owned())
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    assert_eq!(keys[0], "src");
    assert!(keys.contains(&"src/crates/plug-in/src".to_owned()));
    assert!(keys.contains(&format!("src/deep/{}/file.txt", "d".repeat(120))));
    let position = |key: &str| keys.iter().position(|k| k == key).unwrap();
    // A directory comes before what it holds, but `-` sorts before `/`: `plug` itself, then
    // `plug-in` and its files, then the files of `plug/`.
    assert!(position("src/crates/plug") < position("src/crates/plug-in"));
    assert!(position("src/crates/plug-in/src/lib.rs") < position("src/crates/plug/x.rs"));
}

#[test]
fn the_format_is_stable() {
    // The tar is the format; the gzip bytes are those of the compressor Cargo.lock pins.
    // If this changes, archives made by builder images listed in publishers/builders.toml no
    // longer check as canonical in a new image: change the format only with a new image and
    // never for the archives of the old ones.
    let bytes = tree().to_archive().unwrap();
    assert_eq!(
        sha256_hex(&gunzip(&bytes)),
        "786ca5edbce8a51659a8d6cc3d20f2c7b801954451ff47ca9610d667f767665a"
    );
    assert_eq!(
        sha256_hex(&bytes),
        "4a0ecdd8033e57d9883f7b7d6e1681d1d6019b4e0b620e4551b4829af6c4b97f"
    );
}

#[test]
fn a_directory_leaves_out_git_data_and_empty_directories() {
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path());
    fs::create_dir_all(dir.path().join(".git/objects")).unwrap();
    fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::create_dir_all(dir.path().join("empty/inner")).unwrap();
    assert_eq!(Tree::from_dir(dir.path()).unwrap(), tree());
}

#[cfg(unix)]
#[test]
fn a_directory_keeps_execute_bits_and_refuses_links() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path());
    let script = dir.path().join("build.sh");
    fs::write(&script, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let tree = Tree::from_dir(dir.path()).unwrap();
    assert!(tree.get("build.sh").unwrap().executable);
    let out = tempfile::tempdir().unwrap();
    tree.unpack(&out.path().join("src")).unwrap();
    let mode = fs::metadata(out.path().join("src/build.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o755);
    std::os::unix::fs::symlink("Cargo.toml", dir.path().join("link")).unwrap();
    let error = Tree::from_dir(dir.path()).unwrap_err().to_string();
    assert!(error.contains("\"link\": a symbolic link"), "{error}");
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(["-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn a_directory_and_a_git_revision_of_the_same_files_give_the_same_archive() {
    if oncl_testkit::tool::GIT.or_skip(&["--version"]).is_none() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    write_files(dir.path());
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-q", "-m", "one"]);
    let first = git(dir.path(), &["rev-parse", "HEAD"]);
    // A later commit changes the work tree; the first revision still gives the old files.
    fs::write(dir.path().join("LICENSE"), "MIT\n").unwrap();
    git(dir.path(), &["commit", "-q", "-am", "two"]);
    let from_git = Tree::from_git(dir.path(), first.trim()).unwrap();
    assert_eq!(from_git, tree());
    assert_eq!(
        from_git.to_archive().unwrap(),
        tree().to_archive().unwrap(),
        "the same bytes as from the directory"
    );
    // The mode git records, whatever the file system says.
    git(dir.path(), &["update-index", "--chmod=+x", "Cargo.toml"]);
    git(dir.path(), &["commit", "-q", "-m", "three"]);
    assert!(
        Tree::from_git(dir.path(), "HEAD")
            .unwrap()
            .get("Cargo.toml")
            .unwrap()
            .executable
    );
    assert!(matches!(
        Tree::from_git(dir.path(), "--output=x"),
        Err(ArchiveError::Git(_))
    ));
    assert!(matches!(
        Tree::from_git(dir.path(), "no-such-revision"),
        Err(ArchiveError::Git(_))
    ));
}

#[test]
fn a_git_revision_with_a_link_or_a_submodule_is_refused() {
    if oncl_testkit::tool::GIT.or_skip(&["--version"]).is_none() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    write_files(dir.path());
    git(dir.path(), &["add", "-A"]);
    // A link and a submodule recorded in the index directly (no file system support needed).
    let blob = git(dir.path(), &["hash-object", "-w", "Cargo.toml"]);
    git(
        dir.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{},link", blob.trim()),
        ],
    );
    git(dir.path(), &["commit", "-q", "-m", "link"]);
    let error = Tree::from_git(dir.path(), "HEAD").unwrap_err().to_string();
    assert!(error.contains("\"link\": a symbolic link"), "{error}");
    git(dir.path(), &["rm", "-q", "--cached", "link"]);
    let commit = git(dir.path(), &["rev-parse", "HEAD"]);
    git(
        dir.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},vendored", commit.trim()),
        ],
    );
    git(dir.path(), &["commit", "-q", "-m", "submodule"]);
    let error = Tree::from_git(dir.path(), "HEAD").unwrap_err().to_string();
    assert!(error.contains("\"vendored\": a submodule"), "{error}");
}

#[test]
fn paths_outside_the_rules_are_refused() {
    let file = || File {
        executable: false,
        data: Vec::new(),
    };
    for bad in [
        "",
        "/abs",
        "a//b",
        "a/",
        "./a",
        "a/../b",
        "..",
        "a\\b",
        "a\0b",
        "C:.gitconfig",
        "x/C:y",
        "a:b",
        "a\x1bb",
        "a\nb",
        "a\x7fb",
        "CON",
        "nul.txt",
        "dir/Com1.rs",
        "lpt9",
        "a.",
        "dir./x",
        "a ",
        &"x".repeat(MAX_PATH - 3),
    ] {
        assert!(Tree::new().insert(bad, file()).is_err(), "{bad:?}");
    }
    for good in [".gitignore", "a.b/c", "console.rs", "com10", "lpt", "nul_x"] {
        Tree::new().insert(good, file()).unwrap();
    }
    Tree::new()
        .insert(&"x".repeat(MAX_PATH - 4), file())
        .unwrap();
    let mut tree = Tree::new();
    tree.insert("a/b", file()).unwrap();
    assert!(tree.insert("a", file()).is_err(), "a file over a directory");
    assert!(
        tree.insert("a/b/c", file()).is_err(),
        "a directory over a file"
    );
    assert!(tree.insert("a/b", file()).is_err(), "twice");
    assert!(matches!(Tree::new().to_archive(), Err(ArchiveError::Empty)));
}

#[test]
fn an_archive_written_otherwise_is_not_canonical() {
    let canonical = tree().to_archive().unwrap();
    let tar = gunzip(&canonical);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("another gzip level", gzip(&tar, 6)),
        ("a gzip time", {
            let mut bytes = canonical.clone();
            bytes[4] = 1;
            // The header is not covered by the CRC: still readable, other bytes.
            bytes
        }),
        (
            "an owner",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 108..116, b"0001750\0");
            }),
        ),
        (
            "an owner name",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 265..269, b"root");
            }),
        ),
        (
            "another time",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 136..148, b"14000000000\0");
            }),
        ),
        (
            "two entries swapped",
            edited(|tar| {
                // src/Cargo.lock and src/Cargo.toml are adjacent, one block of data each.
                let lock = header_of(tar, "src/Cargo.lock");
                let toml = header_of(tar, "src/Cargo.toml");
                assert_eq!(toml, lock + 1024);
                let (first, second) = tar.split_at_mut(toml);
                first[lock..lock + 1024].swap_with_slice(&mut second[..1024]);
            }),
        ),
        (
            "a directory left out",
            edited(|tar| {
                let at = header_of(tar, "src/docs/");
                tar.drain(at..at + 512);
            }),
        ),
        (
            "a name in the prefix field",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 0..100, &[0; 100]);
                set_field(tar, at, 0..7, b"LICENSE");
                set_field(tar, at, 345..348, b"src");
            }),
        ),
    ];
    for (what, bytes) in cases {
        let error = refused(&bytes);
        assert!(
            matches!(error, ArchiveError::NotCanonical | ArchiveError::Invalid(_)),
            "{what}: {error}"
        );
        assert!(
            !matches!(error, ArchiveError::Invalid(_)) || what == "a name in the prefix field",
            "{what} reads, but is not canonical: {error}"
        );
    }
}

#[test]
fn a_broken_or_foreign_archive_is_refused() {
    let canonical = tree().to_archive().unwrap();
    let tar = gunzip(&canonical);
    let mut one_byte = canonical.clone();
    let middle = one_byte.len() / 2;
    one_byte[middle] ^= 1;
    let mut trailing = canonical.clone();
    trailing.push(0);
    let mut padded = tar.clone();
    padded.resize(10240 * tar.len().div_ceil(10240), 0);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("one byte changed", one_byte),
        ("a byte after the gzip stream", trailing),
        ("no gzip", tar.clone()),
        ("tar record padding", gzip(&padded, 9)),
        ("no end blocks", gzip(&tar[..tar.len() - 1024], 9)),
        (
            "a symbolic link",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 156..157, b"2");
            }),
        ),
        (
            "a path with ..",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 0..11, b"src/../LICE");
            }),
        ),
        (
            "a file outside src/",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 0..4, b"sr_/");
            }),
        ),
        (
            "a wrong checksum",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                tar[at + 5] = b'X';
            }),
        ),
        (
            "mode 0600",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 100..108, b"0000600\0");
            }),
        ),
        (
            "a drive-relative name",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 0..16, b"src/C:.gitconfig");
            }),
        ),
        (
            "an escape character",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 0..11, b"src/LI\x1b[31m");
            }),
        ),
        (
            "a device name",
            edited(|tar| {
                let at = header_of(tar, "src/LICENSE");
                set_field(tar, at, 0..11, b"src/nul.txt");
            }),
        ),
    ];
    for (what, bytes) in cases {
        let error = refused(&bytes);
        assert!(
            !matches!(error, ArchiveError::NotCanonical)
                || what == "one byte changed"
                || what == "a byte after the gzip stream",
            "{what}: {error}"
        );
    }
}
