//! The canonical source archive of a plugin (`<id>-<version>.src.tar.gz`,
//! docs/design/publishers.md, «Архив исходников»): exactly what [`Tree::to_archive`] writes.
//!
//! - one root directory `src/`; regular files and directories only (no links, devices or
//!   empty directories: a directory is there because a file is under it); relative UTF-8
//!   paths without `.`, `..`, `\` or empty components, at most [`MAX_PATH`] bytes;
//! - entries in ascending byte order of their path (a directory's without its trailing `/`,
//!   so a directory comes before what it holds); mode 0644, or 0755 for an executable file
//!   and every directory; uid and gid 0, empty owner names, time [`MTIME`];
//! - POSIX ustar headers, a pax extended header (`path` only) for a path longer than the
//!   100 bytes of the name field, never the `prefix` field; two zero blocks at the end and no
//!   record padding;
//! - gzip at level [`LEVEL`] by the compressor `Cargo.lock` pins (flate2 on zlib-rs), with no
//!   file name, time 0 and system byte 255;
//! - at most [`MAX_ARCHIVE`] bytes compressed, [`MAX_UNPACKED`] bytes of tar and
//!   [`MAX_ENTRIES`] entries.
//!
//! [`Tree::from_archive`] reads an archive strictly and packs what it read again: the
//! archive is canonical only if that gives the same bytes. A tree made from a directory
//! ([`Tree::from_dir`]) and from a git revision of the same files ([`Tree::from_git`]) give
//! the same archive.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use flate2::read::GzDecoder;
use flate2::{Compression, GzBuilder};

/// The one root directory of the archive.
pub const ROOT: &str = "src";
/// The time of every entry: 1980-01-01T00:00:00Z, as in the `.onclp` package.
pub const MTIME: u64 = 315_532_800;
/// The largest archive, compressed.
pub const MAX_ARCHIVE: u64 = 64 << 20;
/// The largest tar stream inside the archive.
pub const MAX_UNPACKED: u64 = 256 << 20;
/// The most entries (files and directories) an archive holds.
pub const MAX_ENTRIES: usize = 20_000;
/// The longest path of an entry, `src/` included, in bytes.
pub const MAX_PATH: usize = 255;
/// The gzip compression level.
pub const LEVEL: u32 = 9;

const BLOCK: usize = 512;
/// The length of the ustar name field.
const NAME_LEN: usize = 100;
/// The name of a pax extended header (as Go's `archive/tar` writes it).
const PAX_NAME: &[u8] = b"././@PaxHeader";
const MODE_FILE: u64 = 0o644;
const MODE_EXEC: u64 = 0o755;

/// Why an archive or a tree was refused.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// More than [`MAX_ARCHIVE`] bytes compressed.
    #[error("the archive exceeds {MAX_ARCHIVE} bytes")]
    TooLarge,
    /// More than [`MAX_UNPACKED`] bytes of tar (or of files, for a tree being made).
    #[error("the unpacked sources exceed {MAX_UNPACKED} bytes")]
    UnpackedTooLarge,
    /// More than [`MAX_ENTRIES`] entries.
    #[error("the sources have more than {MAX_ENTRIES} entries")]
    TooManyEntries,
    /// No file at all.
    #[error("the sources hold no file")]
    Empty,
    /// The archive or the sources break a rule of the format.
    #[error("{0}")]
    Invalid(String),
    /// A readable archive whose files `oncl-pack source` packs into other bytes.
    #[error(
        "the archive is not canonical: `oncl-pack source` packs the same files into other bytes"
    )]
    NotCanonical,
    /// A file could not be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The failure.
        source: io::Error,
    },
    /// `git` failed or said something unexpected.
    #[error("git: {0}")]
    Git(String),
}

fn invalid(message: impl Into<String>) -> ArchiveError {
    ArchiveError::Invalid(message.into())
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> ArchiveError {
    let path = path.to_path_buf();
    move |source| ArchiveError::Io { path, source }
}

/// A file of the sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// Mode 0755 rather than 0644.
    pub executable: bool,
    /// The contents.
    pub data: Vec<u8>,
}

/// The files of the sources by their path under `src/` (`/`-separated); the directories are
/// those the paths imply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    files: BTreeMap<String, File>,
    size: u64,
}

impl Tree {
    /// No file yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the file at `path` (relative to `src/`).
    ///
    /// # Errors
    ///
    /// A path breaking the rules of the format, one already there, a file where the tree has
    /// a directory or the other way round, or the sources growing over the limits.
    pub fn insert(&mut self, path: &str, file: File) -> Result<(), ArchiveError> {
        check_path(path)?;
        if self.files.contains_key(path) {
            return Err(invalid(format!("{path}: the file is there twice")));
        }
        for (at, _) in path.match_indices('/') {
            if self.files.contains_key(&path[..at]) {
                return Err(invalid(format!(
                    "{path}: {} is a file, not a directory",
                    &path[..at]
                )));
            }
        }
        let under = format!("{path}/");
        if self
            .files
            .range(under.clone()..)
            .next()
            .is_some_and(|(other, _)| other.starts_with(&under))
        {
            return Err(invalid(format!("{path}: a directory, not a file")));
        }
        if self.files.len() >= MAX_ENTRIES {
            return Err(ArchiveError::TooManyEntries);
        }
        self.size = self.size.saturating_add(file.data.len() as u64);
        if self.size > MAX_UNPACKED {
            return Err(ArchiveError::UnpackedTooLarge);
        }
        self.files.insert(path.to_owned(), file);
        Ok(())
    }

    /// The file at `path` (relative to `src/`).
    pub fn get(&self, path: &str) -> Option<&File> {
        self.files.get(path)
    }

    /// The files by path, in ascending order.
    pub fn files(&self) -> impl Iterator<Item = (&str, &File)> {
        self.files.iter().map(|(path, file)| (path.as_str(), file))
    }

    /// The files under `dir`, recursively, except anything named `.git` (a repository's own
    /// data, as `git archive` leaves it out). A file is executable if any execute bit is set;
    /// on Windows, which has none, no file is.
    ///
    /// # Errors
    ///
    /// A symbolic link, special file or name that is not UTF-8, an unreadable file, or the
    /// sources breaking a rule or a limit of the format.
    pub fn from_dir(dir: &Path) -> Result<Self, ArchiveError> {
        let mut tree = Self::new();
        walk(dir, "", &mut tree)?;
        tree.nonempty()
    }

    /// The whole tree of `rev` in the git repository at `repo` (`git ls-tree -r`, the blobs
    /// as stored, no checkout filters, no replace objects).
    ///
    /// # Errors
    ///
    /// `git` fails, the tree has a symbolic link or a submodule, or it breaks a rule or a
    /// limit of the format.
    pub fn from_git(repo: &Path, rev: &str) -> Result<Self, ArchiveError> {
        if rev.is_empty() || rev.starts_with('-') {
            return Err(ArchiveError::Git(format!("{rev:?} is not a revision")));
        }
        let listing = git(repo)
            .args(["ls-tree", "-r", "-z", "--full-tree", rev])
            .output()
            .map_err(|e| ArchiveError::Git(format!("running git: {e}")))?;
        if !listing.status.success() {
            return Err(ArchiveError::Git(format!(
                "ls-tree {rev}: {}",
                String::from_utf8_lossy(&listing.stderr).trim()
            )));
        }
        let mut blobs = Vec::new();
        for record in listing.stdout.split(|&b| b == 0).filter(|r| !r.is_empty()) {
            let record = std::str::from_utf8(record)
                .map_err(|_| invalid("a path of the revision is not UTF-8"))?;
            let (meta, path) = record
                .split_once('\t')
                .ok_or_else(|| ArchiveError::Git(format!("unexpected ls-tree line {record:?}")))?;
            let mut fields = meta.split(' ');
            let (Some(mode), Some(_kind), Some(oid), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(ArchiveError::Git(format!(
                    "unexpected ls-tree line {record:?}"
                )));
            };
            let executable = match mode {
                "100644" => false,
                "100755" => true,
                "120000" => {
                    return Err(invalid(format!(
                        "{path:?}: a symbolic link; the archive holds files and directories only"
                    )));
                }
                "160000" => {
                    return Err(invalid(format!(
                        "{path:?}: a submodule; the archive holds the files themselves"
                    )));
                }
                other => {
                    return Err(ArchiveError::Git(format!(
                        "{path:?}: unexpected mode {other}"
                    )));
                }
            };
            check_path(path)?;
            if blobs.len() >= MAX_ENTRIES {
                return Err(ArchiveError::TooManyEntries);
            }
            blobs.push((path.to_owned(), oid.to_owned(), executable));
        }
        let mut tree = Self::new();
        let contents = cat_blobs(repo, blobs.iter().map(|(_, oid, _)| oid.as_str()))?;
        for ((path, _, executable), data) in blobs.into_iter().zip(contents) {
            tree.insert(&path, File { executable, data })?;
        }
        tree.nonempty()
    }

    /// Reads a canonical archive.
    ///
    /// # Errors
    ///
    /// The archive is too large, is no gzip of a tar the format allows, or is not
    /// canonical ([`ArchiveError::NotCanonical`]).
    pub fn from_archive(bytes: &[u8]) -> Result<Self, ArchiveError> {
        if bytes.len() as u64 > MAX_ARCHIVE {
            return Err(ArchiveError::TooLarge);
        }
        let mut tar = Vec::new();
        GzDecoder::new(bytes)
            .take(MAX_UNPACKED + 1)
            .read_to_end(&mut tar)
            .map_err(|e| invalid(format!("the archive is not a gzip stream: {e}")))?;
        if tar.len() as u64 > MAX_UNPACKED {
            return Err(ArchiveError::UnpackedTooLarge);
        }
        let tree = read_tar(&tar)?.nonempty()?;
        if tree.to_archive()? != bytes {
            return Err(ArchiveError::NotCanonical);
        }
        Ok(tree)
    }

    /// The canonical archive of the tree.
    ///
    /// # Errors
    ///
    /// The tree is empty, or the archive would break a limit of the format.
    pub fn to_archive(&self) -> Result<Vec<u8>, ArchiveError> {
        if self.files.is_empty() {
            return Err(ArchiveError::Empty);
        }
        let entries = self.entries();
        if entries.len() > MAX_ENTRIES {
            return Err(ArchiveError::TooManyEntries);
        }
        let mut tar = Vec::new();
        for (path, file) in entries {
            let (name, mode, kind, data) = match file {
                None => (format!("{path}/"), MODE_EXEC, b'5', &[][..]),
                Some(file) => (
                    path,
                    if file.executable {
                        MODE_EXEC
                    } else {
                        MODE_FILE
                    },
                    b'0',
                    file.data.as_slice(),
                ),
            };
            let name = name.as_bytes();
            if name.len() > NAME_LEN {
                let record = pax_record("path", name);
                tar.extend_from_slice(&header(PAX_NAME, MODE_FILE, record.len() as u64, b'x'));
                push_padded(&mut tar, &record);
            }
            let short = &name[..name.len().min(NAME_LEN)];
            tar.extend_from_slice(&header(short, mode, data.len() as u64, kind));
            push_padded(&mut tar, data);
            if tar.len() as u64 > MAX_UNPACKED {
                return Err(ArchiveError::UnpackedTooLarge);
            }
        }
        tar.extend_from_slice(&[0; 2 * BLOCK]);
        if tar.len() as u64 > MAX_UNPACKED {
            return Err(ArchiveError::UnpackedTooLarge);
        }
        let mut gzip = GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(Vec::new(), Compression::new(LEVEL));
        let compressed = gzip
            .write_all(&tar)
            .and_then(|()| gzip.finish())
            .map_err(|e| invalid(format!("compressing the archive: {e}")))?;
        if compressed.len() as u64 > MAX_ARCHIVE {
            return Err(ArchiveError::TooLarge);
        }
        Ok(compressed)
    }

    /// Writes the files under `dest`, which must not exist yet: `dest` takes the place of
    /// `src/`. On Unix a file gets mode 0644 or 0755 and a directory 0755.
    ///
    /// # Errors
    ///
    /// `dest` exists or a file cannot be written.
    pub fn unpack(&self, dest: &Path) -> Result<(), ArchiveError> {
        fs::create_dir(dest).map_err(io_error(dest))?;
        for (path, file) in self.entries().into_iter().skip(1) {
            let relative = &path[ROOT.len() + 1..];
            if !Path::new(relative)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            {
                return Err(invalid(format!(
                    "{relative:?}: not a plain relative path here"
                )));
            }
            let target = dest.join(relative);
            match file {
                None => {
                    fs::create_dir(&target).map_err(io_error(&target))?;
                    set_mode(&target, true)?;
                }
                Some(file) => {
                    // A new file only: a name that the file system folds onto another
                    // (case, normalisation) is refused instead of overwriting it.
                    fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&target)
                        .and_then(|mut out| out.write_all(&file.data))
                        .map_err(io_error(&target))?;
                    set_mode(&target, file.executable)?;
                }
            }
        }
        Ok(())
    }

    fn nonempty(self) -> Result<Self, ArchiveError> {
        if self.files.is_empty() {
            Err(ArchiveError::Empty)
        } else {
            Ok(self)
        }
    }

    /// Every entry of the archive by its path (`src` and `src/…`, no trailing `/`) in
    /// ascending order: the file, or `None` for a directory.
    fn entries(&self) -> BTreeMap<String, Option<&File>> {
        let mut dirs = BTreeSet::from([ROOT.to_owned()]);
        for path in self.files.keys() {
            for (at, _) in path.match_indices('/') {
                dirs.insert(format!("{ROOT}/{}", &path[..at]));
            }
        }
        let mut entries: BTreeMap<String, Option<&File>> =
            dirs.into_iter().map(|dir| (dir, None)).collect();
        for (path, file) in &self.files {
            entries.insert(format!("{ROOT}/{path}"), Some(file));
        }
        entries
    }
}

/// Checks a path under `src/`.
fn check_path(path: &str) -> Result<(), ArchiveError> {
    if path.is_empty() {
        return Err(invalid("an empty path"));
    }
    if ROOT.len() + 1 + path.len() > MAX_PATH {
        return Err(invalid(format!(
            "{path:?}: the path is longer than {MAX_PATH} bytes with {ROOT}/"
        )));
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid(format!(
                "{path:?}: empty, `.` and `..` components are not allowed"
            )));
        }
        if component
            .chars()
            .any(|c| matches!(c, '\\' | ':') || c.is_ascii_control())
        {
            return Err(invalid(format!(
                "{path:?}: `\\`, `:` and control characters are not allowed"
            )));
        }
        if component.ends_with(['.', ' ']) {
            return Err(invalid(format!(
                "{path:?}: a name may not end with `.` or a space"
            )));
        }
        if is_reserved(component) {
            return Err(invalid(format!(
                "{path:?}: {component:?} is a device name on Windows"
            )));
        }
    }
    Ok(())
}

/// The device names Windows reserves in every directory, with any extension and in any
/// case (`CON`, `nul.txt`, `Com1.rs`).
fn is_reserved(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component).trim_end();
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        upper.strip_prefix(prefix).is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

/// Checks the path of a crate directory under `src/`: `""` for `src/` itself, otherwise
/// the rules of a file path.
///
/// # Errors
///
/// The path breaks a rule of the format.
pub fn check_dir_path(path: &str) -> Result<(), ArchiveError> {
    if path.is_empty() {
        Ok(())
    } else {
        check_path(path)
    }
}

fn walk(dir: &Path, prefix: &str, tree: &mut Tree) -> Result<(), ArchiveError> {
    for entry in fs::read_dir(dir).map_err(io_error(dir))? {
        let entry = entry.map_err(io_error(dir))?;
        let path = entry.path();
        let name = entry.file_name().into_string().map_err(|name| {
            invalid(format!(
                "{}: the name is not UTF-8",
                Path::new(&name).display()
            ))
        })?;
        if name == ".git" {
            continue;
        }
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let meta = path.symlink_metadata().map_err(io_error(&path))?;
        let kind = meta.file_type();
        if kind.is_symlink() {
            return Err(invalid(format!(
                "{relative:?}: a symbolic link; the archive holds files and directories only"
            )));
        } else if kind.is_dir() {
            walk(&path, &relative, tree)?;
        } else if kind.is_file() {
            if meta.len() > MAX_UNPACKED {
                return Err(ArchiveError::UnpackedTooLarge);
            }
            let data = fs::read(&path).map_err(io_error(&path))?;
            tree.insert(
                &relative,
                File {
                    executable: executable(&meta),
                    data,
                },
            )?;
        } else {
            return Err(invalid(format!(
                "{relative:?}: neither a file nor a directory"
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_mode(path: &Path, executable: bool) -> Result<(), ArchiveError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_error(path))
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: bool) -> Result<(), ArchiveError> {
    Ok(())
}

fn git(repo: &Path) -> Command {
    let mut git = Command::new("git");
    git.arg("-C")
        .arg(repo)
        // The objects as stored: a replace ref must not change what the revision holds.
        .env("GIT_NO_REPLACE_OBJECTS", "1");
    git
}

/// The contents of the blobs `oids` in order, through one `git cat-file --batch`.
fn cat_blobs<'a>(
    repo: &Path,
    oids: impl Iterator<Item = &'a str>,
) -> Result<Vec<Vec<u8>>, ArchiveError> {
    let oids: Vec<&str> = oids.collect();
    let failed = |e: io::Error| ArchiveError::Git(format!("cat-file: {e}"));
    let mut child = git(repo)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(failed)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ArchiveError::Git("cat-file has no input".into()))?;
    let request: String = oids.iter().map(|oid| format!("{oid}\n")).collect();
    // Written from a thread of its own: git answers while it reads, and a full pipe of
    // answers would otherwise stop both.
    let writer = std::thread::spawn(move || stdin.write_all(request.as_bytes()));
    let mut stdout = BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| ArchiveError::Git("cat-file has no output".into()))?,
    );
    let read = read_batch(&mut stdout, &oids);
    drop(stdout);
    if read.is_err() {
        // Nothing more is read: git must not wait on a full pipe for ever.
        let _ = child.kill();
    }
    let written = writer.join();
    let status = child.wait().map_err(failed)?;
    let blobs = read?;
    written
        .map_err(|_| ArchiveError::Git("the cat-file writer panicked".into()))?
        .map_err(failed)?;
    if !status.success() {
        return Err(ArchiveError::Git(format!("cat-file failed ({status})")));
    }
    Ok(blobs)
}

/// The answers of `git cat-file --batch` to `oids`.
fn read_batch(stdout: &mut impl BufRead, oids: &[&str]) -> Result<Vec<Vec<u8>>, ArchiveError> {
    let failed = |e: io::Error| ArchiveError::Git(format!("cat-file: {e}"));
    let mut blobs = Vec::with_capacity(oids.len());
    let mut total = 0u64;
    for oid in oids {
        let mut line = String::new();
        stdout.read_line(&mut line).map_err(failed)?;
        let mut fields = line.trim_end().split(' ');
        let (Some(got), Some("blob"), Some(size), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(ArchiveError::Git(format!(
                "unexpected cat-file answer {:?} for {oid}",
                line.trim_end()
            )));
        };
        if got != *oid {
            return Err(ArchiveError::Git(format!(
                "cat-file answered {got} for {oid}"
            )));
        }
        let size: u64 = size
            .parse()
            .map_err(|_| ArchiveError::Git(format!("unexpected size in {line:?}")))?;
        total = total.saturating_add(size);
        if total > MAX_UNPACKED {
            return Err(ArchiveError::UnpackedTooLarge);
        }
        let mut data = Vec::new();
        stdout
            .by_ref()
            .take(size)
            .read_to_end(&mut data)
            .map_err(failed)?;
        let mut newline = [0u8; 1];
        stdout.read_exact(&mut newline).map_err(failed)?;
        if data.len() as u64 != size || newline != *b"\n" {
            return Err(ArchiveError::Git(format!("cat-file cut {oid} short")));
        }
        blobs.push(data);
    }
    Ok(blobs)
}

/// A header block: ustar, uid and gid 0, no owner names, [`MTIME`].
fn header(name: &[u8], mode: u64, size: u64, kind: u8) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    block[..name.len()].copy_from_slice(name);
    octal(&mut block[100..108], mode);
    octal(&mut block[108..116], 0);
    octal(&mut block[116..124], 0);
    octal(&mut block[124..136], size);
    octal(&mut block[136..148], MTIME);
    block[148..156].fill(b' ');
    block[156] = kind;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    octal(&mut block[329..337], 0);
    octal(&mut block[337..345], 0);
    let sum = checksum(&block);
    // Six digits, NUL, space: what GNU tar and Go write.
    block[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
    block[154] = 0;
    block[155] = b' ';
    block
}

/// The sum of the header's bytes with its checksum field counted as spaces.
fn checksum(block: &[u8; BLOCK]) -> u64 {
    block
        .iter()
        .enumerate()
        .map(|(at, &byte)| {
            if (148..156).contains(&at) {
                u64::from(b' ')
            } else {
                u64::from(byte)
            }
        })
        .sum()
}

/// `value` in octal with leading zeros, filling all but the last byte of `field`, then NUL.
/// The values written fit: the limits keep sizes far below 8 GiB.
fn octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let digits = format!("{value:0width$o}");
    field[..width].copy_from_slice(&digits.as_bytes()[digits.len() - width..]);
    field[width] = 0;
}

/// One pax record, `<length> <key>=<value>\n`, the length counting itself.
fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let rest = 1 + key.len() + 1 + value.len() + 1;
    let mut length = rest + 1;
    while length.to_string().len() + rest != length {
        length = length.to_string().len() + rest;
    }
    let mut record = format!("{length} {key}=").into_bytes();
    record.extend_from_slice(value);
    record.push(b'\n');
    record
}

fn push_padded(tar: &mut Vec<u8>, data: &[u8]) {
    tar.extend_from_slice(data);
    tar.resize(tar.len().next_multiple_of(BLOCK), 0);
}

fn parse_octal(field: &[u8], what: &str) -> Result<u64, ArchiveError> {
    let digits = field
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .map_or(field, |end| &field[..end]);
    if digits.is_empty() || !digits.iter().all(|b| (b'0'..=b'7').contains(b)) {
        return Err(invalid(format!("a header has an invalid {what} field")));
    }
    digits.iter().try_fold(0u64, |value, &digit| {
        value
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(digit - b'0')))
            .ok_or_else(|| invalid(format!("a header's {what} is too large")))
    })
}

/// The path of a pax extended header: exactly one `path` record.
fn parse_pax(data: &[u8]) -> Result<String, ArchiveError> {
    let bad = || invalid("an extended header other than one `path` record");
    let space = data.iter().position(|&b| b == b' ').ok_or_else(bad)?;
    let length: usize = std::str::from_utf8(&data[..space])
        .ok()
        .and_then(|l| l.parse().ok())
        .ok_or_else(bad)?;
    if length != data.len() || data.last() != Some(&b'\n') {
        return Err(bad());
    }
    let value = data[space + 1..data.len() - 1]
        .strip_prefix(b"path=")
        .ok_or_else(bad)?;
    String::from_utf8(value.to_vec()).map_err(|_| invalid("a path is not UTF-8"))
}

/// The files of a tar stream the format allows; whether it is canonical is for the caller
/// to compare.
fn read_tar(tar: &[u8]) -> Result<Tree, ArchiveError> {
    let mut tree = Tree::new();
    let mut at = 0;
    let mut long_path: Option<String> = None;
    let mut entries = 0usize;
    loop {
        let block: &[u8; BLOCK] = tar
            .get(at..at + BLOCK)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("the archive ends without its two zero blocks"))?;
        if block.iter().all(|&b| b == 0) {
            if long_path.is_some() {
                return Err(invalid("an extended header without its entry"));
            }
            if tar.len() != at + 2 * BLOCK || tar[at..].iter().any(|&b| b != 0) {
                return Err(invalid("data after the end of the archive"));
            }
            return Ok(tree);
        }
        if parse_octal(&block[148..156], "checksum")? != checksum(block) {
            return Err(invalid("a header's checksum is wrong"));
        }
        if &block[257..265] != b"ustar\x0000" {
            return Err(invalid("a header is not ustar"));
        }
        let size = usize::try_from(parse_octal(&block[124..136], "size")?)
            .map_err(|_| invalid("an entry is too large"))?;
        let start = at + BLOCK;
        let data = tar
            .get(start..start.saturating_add(size))
            .ok_or_else(|| invalid("an entry is cut short"))?;
        at = start + size.next_multiple_of(BLOCK);
        let kind = block[156];
        if kind == b'x' {
            if long_path.is_some() {
                return Err(invalid("two extended headers in a row"));
            }
            long_path = Some(parse_pax(data)?);
            continue;
        }
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err(ArchiveError::TooManyEntries);
        }
        let name = match long_path.take() {
            Some(path) => path,
            None => {
                let field = &block[..NAME_LEN];
                let end = field.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
                String::from_utf8(field[..end].to_vec())
                    .map_err(|_| invalid("a path is not UTF-8"))?
            }
        };
        let mode = parse_octal(&block[100..108], "mode")?;
        match kind {
            b'5' => {
                let path = name
                    .strip_suffix('/')
                    .ok_or_else(|| invalid(format!("{name:?}: a directory without its `/`")))?;
                if path != ROOT {
                    check_path(path.strip_prefix("src/").ok_or_else(|| {
                        invalid(format!("{path:?}: outside the root directory {ROOT}/"))
                    })?)?;
                }
                if size != 0 || mode != MODE_EXEC {
                    return Err(invalid(format!(
                        "{path:?}: a directory must be empty and 0755"
                    )));
                }
            }
            b'0' => {
                let path = name.strip_prefix("src/").ok_or_else(|| {
                    invalid(format!("{name:?}: outside the root directory {ROOT}/"))
                })?;
                let executable = match mode {
                    MODE_FILE => false,
                    MODE_EXEC => true,
                    other => {
                        return Err(invalid(format!("{name:?}: mode {other:o}, not 644 or 755")));
                    }
                };
                tree.insert(
                    path,
                    File {
                        executable,
                        data: data.to_vec(),
                    },
                )?;
            }
            other => {
                return Err(invalid(format!(
                    "{name:?}: an entry of type {:?}; the archive holds files and directories only",
                    char::from(other)
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pax_record_counts_its_own_length() {
        for value_len in [0, 1, 85, 86, 87, 94, 95, 96, 300, 994, 995, 996] {
            let value = vec![b'a'; value_len];
            let record = pax_record("path", &value);
            let (length, _) = std::str::from_utf8(&record)
                .unwrap()
                .split_once(' ')
                .unwrap();
            assert_eq!(
                length.parse::<usize>().unwrap(),
                record.len(),
                "{value_len}"
            );
            assert_eq!(parse_pax(&record).unwrap().len(), value_len);
        }
    }

    #[test]
    fn a_header_reads_back() {
        let block = header(b"src/a", MODE_EXEC, 1234, b'0');
        assert_eq!(
            parse_octal(&block[148..156], "checksum").unwrap(),
            checksum(&block)
        );
        assert_eq!(parse_octal(&block[124..136], "size").unwrap(), 1234);
        assert_eq!(parse_octal(&block[136..148], "mtime").unwrap(), MTIME);
        assert_eq!(&block[100..108], b"0000755\0");
    }
}
