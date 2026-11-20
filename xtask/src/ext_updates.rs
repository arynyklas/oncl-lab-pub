//! `cargo xtask ext updates`: the Firefox update manifest (`firefox/updates.json` on Pages),
//! the file the add-on's `update_url` points at.
//!
//! The versions listed are the published, non-pre-release GitHub releases from
//! [`FIRST_VERSION`] on whose `.xpi` is signed by AMO. The workflow downloads each candidate's
//! `.xpi` and `SHA256SUMS` into `<assets>/v<version>/`; a release without the files there is
//! left out. An `.xpi` counts as signed when it holds `META-INF/mozilla.rsa`, which AMO adds.
//! `update_hash` is the checksum from the release's `SHA256SUMS`, and it must equal the
//! checksum of the downloaded file.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use oncl_ipc::ids::FIREFOX_EXTENSION_ID;
use oncl_update::Version;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::registry::inputs::{Release, read_releases};

/// The first release whose `.xpi` is offered for updating.
pub const FIRST_VERSION: Version = Version::new(0, 1, 1);

/// The AMO signature file inside a signed `.xpi`.
const SIGNATURE: &str = "META-INF/mozilla.rsa";

#[derive(Serialize)]
struct Manifest {
    addons: std::collections::BTreeMap<&'static str, Addon>,
}

#[derive(Serialize)]
struct Addon {
    updates: Vec<Update>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
struct Update {
    version: String,
    update_link: String,
    update_hash: String,
}

/// Writes the update manifest for `releases` (a JSON Lines list as `gh api` gives it; `None`
/// when it could not be read) to `out`, using the files under `assets`. Links point at the
/// releases of `repo` (`owner/name`).
///
/// A release whose files are unusable (corrupt zip, `SHA256SUMS` missing, without a line for
/// the `.xpi` or with another checksum) is left out with a `::warning::` line.
///
/// # Errors
///
/// If the release list is malformed or `out` cannot be written.
pub fn write(releases: Option<&Path>, assets: &Path, repo: &str, out: &Path) -> anyhow::Result<()> {
    let releases = match releases {
        Some(path) => read_releases(path)?,
        None => Vec::new(),
    };
    let updates = updates(&releases, assets, repo);
    let manifest = Manifest {
        addons: [(FIREFOX_EXTENSION_ID, Addon { updates })].into(),
    };
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut text = serde_json::to_string_pretty(&manifest)?;
    text.push('\n');
    fs::write(out, text).with_context(|| format!("writing {}", out.display()))
}

/// The signed releases, oldest first.
fn updates(releases: &[Release], assets: &Path, repo: &str) -> Vec<Update> {
    let mut candidates: Vec<&Release> = releases
        .iter()
        .filter(|r| !r.prerelease && r.version.pre.is_empty() && r.version >= FIRST_VERSION)
        .collect();
    candidates.sort_by(|a, b| a.version.cmp(&b.version));
    let mut updates = Vec::new();
    for release in candidates {
        match update(&release.version, assets, repo) {
            Ok(Some(update)) => updates.push(update),
            Ok(None) => {}
            Err(e) => println!(
                "::warning::v{}: left out of the Firefox update manifest: {e:#}",
                release.version
            ),
        }
    }
    updates
}

/// The entry of `version`, `None` when it has no downloaded or no signed `.xpi`.
fn update(version: &Version, assets: &Path, repo: &str) -> anyhow::Result<Option<Update>> {
    let name = format!("openncalayer-firefox-{version}.xpi");
    let dir = assets.join(format!("v{version}"));
    let xpi = dir.join(&name);
    if !xpi.is_file() || !is_signed(&xpi)? {
        return Ok(None);
    }
    let sums = fs::read_to_string(dir.join("SHA256SUMS")).context("reading SHA256SUMS")?;
    let listed = checksum_of(&sums, &name)?;
    let mut file = File::open(&xpi).with_context(|| format!("opening {}", xpi.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .with_context(|| format!("reading {}", xpi.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let actual = hex(&hasher.finalize());
    ensure!(
        listed == actual,
        "{name}: SHA256SUMS says {listed}, the file is {actual}"
    );
    Ok(Some(Update {
        version: version.to_string(),
        update_link: format!("https://github.com/{repo}/releases/download/v{version}/{name}"),
        update_hash: format!("sha256:{actual}"),
    }))
}

fn is_signed(xpi: &Path) -> anyhow::Result<bool> {
    let file = File::open(xpi).with_context(|| format!("opening {}", xpi.display()))?;
    let archive =
        zip::ZipArchive::new(file).with_context(|| format!("{} is not a zip", xpi.display()))?;
    Ok(archive
        .file_names()
        .any(|n| matches!(n, Ok(n) if n == SIGNATURE)))
}

/// The lowercase hex checksum `sha256sum` printed for `name`.
fn checksum_of(sums: &str, name: &str) -> anyhow::Result<String> {
    for line in sums.lines() {
        let Some((sum, file)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if file.trim_start().trim_start_matches('*') == name {
            if sum.len() != 64 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("malformed checksum for {name}");
            }
            return Ok(sum.to_ascii_lowercase());
        }
    }
    bail!("no line for {name}")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::write::SimpleFileOptions;

    use super::*;

    fn xpi(path: &Path, signed: bool) {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        zip.start_file("manifest.json", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"{}").unwrap();
        if signed {
            zip.start_file(SIGNATURE, SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"sig").unwrap();
        }
        zip.finish().unwrap();
    }

    /// A downloaded release: its `.xpi` (signed or not) and `SHA256SUMS`.
    fn download(assets: &Path, version: &str, signed: bool) -> String {
        let dir = assets.join(format!("v{version}"));
        fs::create_dir_all(&dir).unwrap();
        let name = format!("openncalayer-firefox-{version}.xpi");
        xpi(&dir.join(&name), signed);
        let sum = hex(&Sha256::digest(fs::read(dir.join(&name)).unwrap()));
        fs::write(
            dir.join("SHA256SUMS"),
            format!("{}  other.zip\n{sum}  {name}\n", "0".repeat(64)),
        )
        .unwrap();
        sum
    }

    fn releases(dir: &Path, lines: &[(&str, bool, bool)]) -> std::path::PathBuf {
        let text: String = lines
            .iter()
            .map(|(tag, draft, pre)| {
                format!(
                    "{{\"tag_name\":\"{tag}\",\"draft\":{draft},\"prerelease\":{pre},\"assets\":[]}}\n"
                )
            })
            .collect();
        let path = dir.join("releases.jsonl");
        fs::write(&path, text).unwrap();
        path
    }

    const REPO: &str = "o/r";

    fn run(dir: &Path, releases: Option<&Path>) -> serde_json::Value {
        let out = dir.join("firefox/updates.json");
        write(releases, &dir.join("assets"), REPO, &out).unwrap();
        serde_json::from_str(&fs::read_to_string(out).unwrap()).unwrap()
    }

    #[test]
    fn lists_signed_releases_oldest_first_in_the_firefox_format() {
        let dir = tempfile::tempdir().unwrap();
        let assets = dir.path().join("assets");
        let s2 = download(&assets, "0.1.2", true);
        let s1 = download(&assets, "0.1.1", true);
        let list = releases(
            dir.path(),
            &[("v0.1.2", false, false), ("v0.1.1", false, false)],
        );
        let manifest = run(dir.path(), Some(&list));
        let updates = &manifest["addons"][FIREFOX_EXTENSION_ID]["updates"];
        assert_eq!(
            *updates,
            serde_json::json!([
                {
                    "version": "0.1.1",
                    "update_link": "https://github.com/o/r/releases/download/v0.1.1/openncalayer-firefox-0.1.1.xpi",
                    "update_hash": format!("sha256:{s1}"),
                },
                {
                    "version": "0.1.2",
                    "update_link": "https://github.com/o/r/releases/download/v0.1.2/openncalayer-firefox-0.1.2.xpi",
                    "update_hash": format!("sha256:{s2}"),
                },
            ])
        );
    }

    #[test]
    fn skips_unsigned_prerelease_draft_old_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let assets = dir.path().join("assets");
        download(&assets, "0.1.3", false); // unsigned
        download(&assets, "0.1.4-rc.1", true); // pre-release
        download(&assets, "0.1.5", true); // draft
        download(&assets, "0.1.0", true); // before FIRST_VERSION
        let kept = download(&assets, "0.1.6", true);
        let list = releases(
            dir.path(),
            &[
                ("v0.1.3", false, false),
                ("v0.1.4-rc.1", false, true),
                ("v0.1.5", true, false),
                ("v0.1.0", false, false),
                ("v0.1.7", false, false), // nothing downloaded
                ("plugins-20261101", false, false),
                ("v0.1.6", false, false),
            ],
        );
        let manifest = run(dir.path(), Some(&list));
        let updates = manifest["addons"][FIREFOX_EXTENSION_ID]["updates"]
            .as_array()
            .unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0]["version"], "0.1.6");
        assert_eq!(updates[0]["update_hash"], format!("sha256:{kept}"));
    }

    #[test]
    fn no_signed_versions_gives_an_empty_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        for list in [None, Some(releases(dir.path(), &[]))] {
            let manifest = run(dir.path(), list.as_deref());
            assert_eq!(
                manifest,
                serde_json::json!({"addons": {FIREFOX_EXTENSION_ID: {"updates": []}}})
            );
        }
    }

    #[test]
    fn a_bad_release_is_skipped_and_the_others_are_listed() {
        let dir = tempfile::tempdir().unwrap();
        let assets = dir.path().join("assets");
        download(&assets, "0.1.1", true); // checksum mismatch
        fs::write(
            assets.join("v0.1.1/SHA256SUMS"),
            format!("{}  openncalayer-firefox-0.1.1.xpi\n", "a".repeat(64)),
        )
        .unwrap();
        download(&assets, "0.1.2", true); // no SHA256SUMS
        fs::remove_file(assets.join("v0.1.2/SHA256SUMS")).unwrap();
        download(&assets, "0.1.3", true); // no line for the xpi
        fs::write(assets.join("v0.1.3/SHA256SUMS"), "").unwrap();
        download(&assets, "0.1.4", true); // corrupt zip
        fs::write(
            assets.join("v0.1.4/openncalayer-firefox-0.1.4.xpi"),
            b"not a zip",
        )
        .unwrap();
        let good = download(&assets, "0.1.5", true);
        let list = releases(
            dir.path(),
            &[
                ("v0.1.1", false, false),
                ("v0.1.2", false, false),
                ("v0.1.3", false, false),
                ("v0.1.4", false, false),
                ("v0.1.5", false, false),
            ],
        );
        let manifest = run(dir.path(), Some(&list));
        let updates = manifest["addons"][FIREFOX_EXTENSION_ID]["updates"]
            .as_array()
            .unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0]["version"], "0.1.5");
        assert_eq!(updates[0]["update_hash"], format!("sha256:{good}"));
    }

    #[test]
    fn a_malformed_release_list_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("releases.jsonl");
        fs::write(&list, "[1]\n").unwrap();
        let out = dir.path().join("u.json");
        assert!(write(Some(&list), dir.path(), REPO, &out).is_err());
    }
}
