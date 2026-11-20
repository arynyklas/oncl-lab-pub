//! The repository as a directory: which files are there ([`Listing`]), reading them for the
//! client ([`DirFetcher`]) and writing new ones; and its snapshot mode ([`SnapshotMode`]),
//! in the file beside it.
//!
//! The layout is that of consistent snapshots: the top-level metadata, the update indexes,
//! and once there are publishers, the target `publishers.json` and the files of the
//! publishers' delegated roles, `metadata/<N>.pub-<name>.json`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::Channel;
use oncl_update::tuf::{Fetcher, Response, RoleName, TufError};
use serde::Deserialize;

/// Who signs the snapshot (`docs/design/publishers.md`, "Онлайн-снимок"): `snapshot` in
/// the file beside the repository ([`config_path`]), `offline` without the file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotMode {
    /// The owner signs it with `tuf update`, for 30 days, and it is committed.
    #[default]
    Offline,
    /// CI signs it with `tuf snapshot` on every publication, for 7 days; it is never
    /// committed. Set by the rotation of the root that moves the snapshot key into CI.
    Online,
}

impl SnapshotMode {
    /// `offline` or `online`.
    pub fn as_str(self) -> &'static str {
        match self {
            SnapshotMode::Offline => "offline",
            SnapshotMode::Online => "online",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    snapshot: SnapshotMode,
}

/// The file of the snapshot mode of the repository `dir`: `<dir>.toml` beside it
/// (`tuf/v1.toml` for `tuf/v1`).
pub fn config_path(dir: &Path) -> PathBuf {
    let mut name = dir.file_name().unwrap_or_default().to_os_string();
    name.push(".toml");
    dir.with_file_name(name)
}

/// The snapshot mode in the file `path`: [`SnapshotMode::Offline`] if there is none.
///
/// # Errors
///
/// If the file cannot be read or is not exactly `snapshot = "offline"|"online"`.
pub fn read_mode(path: &Path) -> anyhow::Result<SnapshotMode> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SnapshotMode::Offline),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let config: Config = toml::from_str(&text).with_context(|| {
        format!(
            "{} is not `snapshot = \"offline\"` or `snapshot = \"online\"`",
            path.display()
        )
    })?;
    Ok(config.snapshot)
}

/// The text of the file of `mode`.
pub fn mode_file(mode: SnapshotMode) -> String {
    format!(
        "# Who signs the snapshot of tuf/v1: `offline` (the owner, `cargo xtask tuf update`) or\n\
         # `online` (CI, `cargo xtask tuf snapshot`). docs/design/publishers.md, Р8.\n\
         snapshot = \"{}\"\n",
        mode.as_str()
    )
}

/// What a path of the repository is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `metadata/<N>.root.json`.
    Root(u64),
    /// `metadata/<N>.targets.json`.
    Targets(u64),
    /// `metadata/<N>.snapshot.json`.
    Snapshot(u64),
    /// `metadata/timestamp.json`.
    Timestamp,
    /// `targets/indexes/<sha256>.<channel>.json`.
    Target,
    /// `metadata/<N>.pub-<name>.json`: a version of a publisher's delegated role.
    Delegated {
        /// The version.
        version: u64,
        /// The role.
        role: RoleName,
    },
    /// `targets/<sha256>.publishers.json`.
    Publishers,
    /// Anything else.
    Stray,
}

/// A version as the file names spell it: decimal, no leading zero, not 0.
fn version(text: &str) -> Option<u64> {
    let v: u64 = text.parse().ok()?;
    (v >= 1 && v.to_string() == text).then_some(v)
}

/// Whether `hash` is 64 lowercase hex digits.
fn is_sha256(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// What the relative path `path` (with `/`) is.
pub fn classify(path: &str) -> Kind {
    if path == "metadata/timestamp.json" {
        return Kind::Timestamp;
    }
    if let Some(name) = path.strip_prefix("metadata/") {
        let Some((number, role)) = name.split_once('.') else {
            return Kind::Stray;
        };
        let Some(v) = version(number) else {
            return Kind::Stray;
        };
        return match role {
            "root.json" => Kind::Root(v),
            "targets.json" => Kind::Targets(v),
            "snapshot.json" => Kind::Snapshot(v),
            _ => match role.strip_suffix(".json").map(RoleName::parse) {
                Some(Ok(role)) => Kind::Delegated { version: v, role },
                _ => Kind::Stray,
            },
        };
    }
    if let Some(name) = path.strip_prefix("targets/indexes/")
        && let Some((hash, rest)) = name.split_once('.')
        && is_sha256(hash)
        && Channel::ALL
            .iter()
            .any(|c| rest == format!("{}.json", c.as_str()))
    {
        return Kind::Target;
    }
    if let Some(name) = path.strip_prefix("targets/")
        && let Some((hash, "publishers.json")) = name.split_once('.')
        && is_sha256(hash)
    {
        return Kind::Publishers;
    }
    Kind::Stray
}

/// The files of a repository directory, by kind.
#[derive(Clone, Debug, Default)]
pub struct Listing {
    /// The versions of the root.
    pub roots: BTreeSet<u64>,
    /// The versions of the targets.
    pub targets: BTreeSet<u64>,
    /// The versions of the snapshot.
    pub snapshots: BTreeSet<u64>,
    /// Whether `metadata/timestamp.json` is there.
    pub timestamp: bool,
    /// The files of `targets/`.
    pub target_files: BTreeSet<String>,
    /// The versions of each delegated role.
    pub delegated: BTreeMap<RoleName, BTreeSet<u64>>,
    /// Every other file.
    pub strays: Vec<String>,
    /// Every file, whatever it is.
    pub all: BTreeSet<String>,
}

impl Listing {
    /// The listing of the relative paths `files`.
    pub fn of(files: impl IntoIterator<Item = String>) -> Listing {
        let mut listing = Listing::default();
        for path in files {
            match classify(&path) {
                Kind::Root(v) => {
                    listing.roots.insert(v);
                }
                Kind::Targets(v) => {
                    listing.targets.insert(v);
                }
                Kind::Snapshot(v) => {
                    listing.snapshots.insert(v);
                }
                Kind::Timestamp => listing.timestamp = true,
                Kind::Target | Kind::Publishers => {
                    listing.target_files.insert(path.clone());
                }
                Kind::Delegated { version, role } => {
                    listing.delegated.entry(role).or_default().insert(version);
                }
                Kind::Stray => listing.strays.push(path.clone()),
            }
            listing.all.insert(path);
        }
        listing
    }

    /// The listing of the directory `dir`.
    ///
    /// # Errors
    ///
    /// If a directory cannot be read.
    pub fn read(dir: &Path) -> anyhow::Result<Listing> {
        Ok(Listing::of(walk(dir)?))
    }

    /// The highest root, targets and snapshot versions, 0 for none.
    pub fn highest(&self) -> (u64, u64, u64) {
        (
            self.roots.last().copied().unwrap_or(0),
            self.targets.last().copied().unwrap_or(0),
            self.snapshots.last().copied().unwrap_or(0),
        )
    }

    /// The newest version of each delegated role.
    pub fn newest_roles(&self) -> BTreeMap<RoleName, u64> {
        self.delegated
            .iter()
            .filter_map(|(role, versions)| versions.last().map(|v| (role.clone(), *v)))
            .collect()
    }
}

/// Every file below `dir`, as relative paths with `/`, sorted.
///
/// # Errors
///
/// If a directory cannot be read.
pub fn walk(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    walk_into(dir, "", &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_into(dir: &Path, prefix: &str, out: &mut Vec<String>) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let relative = format!("{prefix}{name}");
        let kind = entry
            .file_type()
            .with_context(|| format!("reading {}", entry.path().display()))?;
        if kind.is_dir() {
            walk_into(&entry.path(), &format!("{relative}/"), out)?;
        } else {
            out.push(relative);
        }
    }
    Ok(())
}

/// A repository directory as the client's [`Fetcher`]: a file is there or is a 404.
pub struct DirFetcher {
    dir: PathBuf,
    hide_timestamp: bool,
}

impl DirFetcher {
    /// The repository in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> DirFetcher {
        DirFetcher {
            dir: dir.into(),
            hide_timestamp: false,
        }
    }

    /// The same, with `metadata/timestamp.json` a 404 whatever is on disk: the client then
    /// follows the chain of roots and stops there.
    #[must_use]
    pub fn without_timestamp(mut self) -> DirFetcher {
        self.hide_timestamp = true;
        self
    }
}

impl Fetcher for DirFetcher {
    fn fetch(&self, path: &str, max_len: u64) -> Result<Response, TufError> {
        let safe = !path.is_empty()
            && !path.contains('\\')
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..");
        if !safe {
            return Err(TufError::Fetch(format!(
                "{path:?} is not a repository path"
            )));
        }
        if self.hide_timestamp && path == "metadata/timestamp.json" {
            return Ok(Response::NotFound);
        }
        let full = self.dir.join(path);
        match fs::metadata(&full) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => return Ok(Response::NotFound),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Response::NotFound),
            Err(e) => return Err(TufError::Fetch(format!("reading {path}: {e}"))),
        }
        let file =
            fs::File::open(&full).map_err(|e| TufError::Fetch(format!("reading {path}: {e}")))?;
        let mut body = Vec::new();
        file.take(max_len.saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|e| TufError::Fetch(format!("reading {path}: {e}")))?;
        if body.len() as u64 > max_len {
            return Err(TufError::Fetch(format!(
                "{path} is larger than {max_len} bytes"
            )));
        }
        Ok(Response::Body(body))
    }
}

/// Reads the file `path` of the repository `dir`.
///
/// # Errors
///
/// If it is not there or cannot be read.
pub fn read(dir: &Path, path: &str) -> anyhow::Result<Vec<u8>> {
    let full = dir.join(path);
    fs::read(&full).with_context(|| format!("reading {}", full.display()))
}

/// Writes `bytes` to the new file `path` of the repository `dir` (its directories are
/// made); an existing file is never replaced.
///
/// # Errors
///
/// If the file exists already or cannot be written.
pub fn write_new(dir: &Path, path: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
    let full = dir.join(path);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    if full.exists() {
        bail!(
            "{} exists already; refusing to overwrite it",
            full.display()
        );
    }
    crate::files::write_new(&full, bytes, false)?;
    Ok(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_classified_by_the_layout() {
        let hash = "ab".repeat(32);
        assert_eq!(classify("metadata/1.root.json"), Kind::Root(1));
        assert_eq!(classify("metadata/12.targets.json"), Kind::Targets(12));
        assert_eq!(classify("metadata/3.snapshot.json"), Kind::Snapshot(3));
        assert_eq!(classify("metadata/timestamp.json"), Kind::Timestamp);
        assert_eq!(
            classify(&format!("targets/indexes/{hash}.stable.json")),
            Kind::Target
        );
        assert_eq!(
            classify(&format!("targets/indexes/{hash}.beta.json")),
            Kind::Target
        );
        for stray in [
            "metadata/0.root.json",
            "metadata/01.root.json",
            "metadata/1.root.json.bak",
            "metadata/root.json",
            "metadata/2.timestamp.json",
            "targets/indexes/stable.json",
            "targets/indexes/ABAB.stable.json",
            &format!("targets/indexes/{hash}.nightly.json"),
            &format!("targets/other/{hash}.stable.json"),
            ".gitkeep",
            "README.md",
        ] {
            assert_eq!(classify(stray), Kind::Stray, "{stray}");
        }
    }

    #[test]
    fn the_files_of_the_publishers_are_classified() {
        let hash = "ab".repeat(32);
        let role = RoleName::parse("pub-ecc").unwrap();
        assert_eq!(
            classify("metadata/4.pub-ecc.json"),
            Kind::Delegated {
                version: 4,
                role: role.clone()
            }
        );
        let publishers = format!("targets/{hash}.publishers.json");
        assert_eq!(classify(&publishers), Kind::Publishers);
        for stray in [
            "metadata/0.pub-ecc.json",
            "metadata/1.pub-ecc.json.bak",
            "metadata/1.pub-root.json",
            "metadata/1.pub-EC.json",
            "metadata/1.ecc.json",
            "metadata/pub-ecc.json",
            "targets/publishers.json",
            &format!("targets/indexes/{hash}.publishers.json"),
            &format!("targets/{hash}.publishers.json.bak"),
        ] {
            assert_eq!(classify(stray), Kind::Stray, "{stray}");
        }
        let listing = Listing::of([
            "metadata/1.root.json".to_owned(),
            "metadata/4.pub-ecc.json".to_owned(),
            "metadata/3.pub-ecc.json".to_owned(),
            publishers.clone(),
        ]);
        assert!(listing.strays.is_empty());
        assert_eq!(listing.newest_roles(), BTreeMap::from([(role, 4)]));
        assert!(listing.target_files.contains(&publishers));
    }

    #[test]
    fn the_snapshot_mode_is_read_beside_the_repository() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("v1");
        let config = config_path(&repo);
        assert_eq!(config, dir.path().join("v1.toml"));
        assert_eq!(read_mode(&config).unwrap(), SnapshotMode::Offline);
        for mode in [SnapshotMode::Offline, SnapshotMode::Online] {
            fs::write(&config, mode_file(mode)).unwrap();
            assert_eq!(read_mode(&config).unwrap(), mode);
        }
        for bad in [
            "snapshot = \"later\"\n",
            "",
            "snapshot = \"online\"\nother = 1\n",
        ] {
            fs::write(&config, bad).unwrap();
            assert!(read_mode(&config).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_fetcher_serves_files_and_404s_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("metadata")).unwrap();
        fs::write(dir.path().join("metadata/1.root.json"), b"12345").unwrap();
        let fetcher = DirFetcher::new(dir.path());
        assert_eq!(
            fetcher.fetch("metadata/1.root.json", 5).unwrap(),
            Response::Body(b"12345".to_vec())
        );
        assert!(fetcher.fetch("metadata/1.root.json", 4).is_err());
        assert_eq!(
            fetcher.fetch("metadata/2.root.json", 5).unwrap(),
            Response::NotFound
        );
        assert_eq!(fetcher.fetch("metadata", 5).unwrap(), Response::NotFound);
        assert!(fetcher.fetch("../metadata/1.root.json", 5).is_err());
        assert!(fetcher.fetch("metadata\\1.root.json", 5).is_err());
    }
}
