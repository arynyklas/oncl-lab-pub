//! What goes beside a package in its release `pub-<publisher>-<sha256>` of the project's
//! Releases (`docs/design/publishers.md`, «Копии пакетов в наших Releases»), and the checks of
//! the rebuilt bytes before it goes there:
//!
//! - checks 21 and 22 ([`rebuilt_bytes`], [`rebuilt_package`]): the rebuilt package is the
//!   signed target byte for byte, reads as a package, its manifest is the entry's, its
//!   capabilities the entry's, and its `plugin.toml` the archive's;
//! - `BUILDINFO.json` ([`BuildInfo`]): the builder, the archive, its `Cargo.lock`, the package
//!   and the outcome of check 25, by the hashes the verdict job computed itself.

use std::io::{Cursor, Read as _};

use oncl_pack::source::Tree;
use oncl_plugin::{Capabilities, Package};
use oncl_update::catalog::PublisherRelease;
use oncl_update::tuf::{Target, TargetPath};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::checks::{Finding, finding};
use super::verdict::CheckResult;

/// The format version of `BUILDINFO.json`.
pub const SCHEMA: u32 = 1;

/// The file name beside the package.
pub const FILE_NAME: &str = "BUILDINFO.json";

/// The builder image a package was built in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderInfo {
    /// The image reference it ran.
    pub image: String,
    /// `sha256:<64 hex>`, its digest, when it ran by digest.
    pub digest: Option<String>,
    /// The Rust release inside, from `publishers/builders.toml`.
    pub rust: Option<String>,
    /// The commit of this repository it was built from, from `publishers/builders.toml`.
    pub commit: Option<String>,
}

/// A file and its hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileInfo {
    /// Its name.
    pub file: String,
    /// Its sha256, 64 lowercase hex.
    pub sha256: String,
    /// Its length.
    pub length: u64,
}

/// The source archive of a build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInfo {
    /// The archive.
    pub archive: FileInfo,
    /// The crate directory under `src/`.
    pub path: String,
    /// The crate's `license`, if its `Cargo.toml` says.
    pub license: Option<String>,
    /// The sha256 of the workspace's `Cargo.lock`.
    pub cargo_lock_sha256: Option<String>,
}

/// The publisher's release the copy is of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInfo {
    /// The publisher.
    pub publisher: String,
    /// The version of its role that lists the package.
    pub role_version: u64,
    /// The release of the copies.
    pub tag: String,
    /// The pull request's head commit.
    pub head: String,
    /// The base commit it was checked against.
    pub base: String,
}

/// Check 25.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VcsInfo {
    /// The repository.
    pub url: String,
    /// The revision.
    pub rev: String,
    /// `confirmed` (the revision gives the archive) or `unverified` (it could not be
    /// fetched).
    pub result: String,
}

/// `BUILDINFO.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInfo {
    /// [`SCHEMA`].
    pub schema: u32,
    /// The plugin.
    pub id: String,
    /// Its version.
    pub version: String,
    /// The builder.
    pub builder: BuilderInfo,
    /// The source archive.
    pub source: SourceInfo,
    /// The package.
    pub package: FileInfo,
    /// The release, for a copy in the project's Releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseInfo>,
    /// Check 25, if `source.vcs` names a revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcs: Option<VcsInfo>,
    /// The checks the build passed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<CheckResult>,
}

impl BuildInfo {
    /// The pretty JSON with a final newline.
    ///
    /// # Errors
    ///
    /// Never in practice: the type has no map with non-string keys.
    pub fn to_json(&self) -> anyhow::Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    /// Reads `BUILDINFO.json`.
    ///
    /// # Errors
    ///
    /// It is not of the format.
    pub fn from_json(bytes: &[u8]) -> anyhow::Result<BuildInfo> {
        let info: BuildInfo = serde_json::from_slice(bytes)?;
        if info.schema != SCHEMA {
            anyhow::bail!("BUILDINFO.json schema {} is not {SCHEMA}", info.schema);
        }
        Ok(info)
    }
}

/// The `[capabilities]` table of the manifest `plugin_toml` as a JSON object (empty without
/// one): `custom.oncl.capabilities` of the release.
///
/// # Errors
///
/// The manifest is not TOML, or the table is not a table.
pub fn capabilities_json(plugin_toml: &str) -> anyhow::Result<Value> {
    let manifest: toml::Value = toml::from_str(plugin_toml)?;
    match manifest.get("capabilities") {
        None => Ok(Value::Object(serde_json::Map::new())),
        Some(table @ toml::Value::Table(_)) => Ok(serde_json::to_value(table)?),
        Some(_) => anyhow::bail!("[capabilities] of plugin.toml is not a table"),
    }
}

/// The bytes of the file `name` in the zip `package`.
///
/// # Errors
///
/// It is not a zip with that file.
pub fn zip_entry(package: &[u8], name: &str) -> anyhow::Result<Vec<u8>> {
    let mut zip = zip::ZipArchive::new(Cursor::new(package))?;
    let mut entry = zip.by_name(name)?;
    let mut bytes = Vec::new();
    entry
        .by_ref()
        .take(oncl_plugin::MAX_MANIFEST + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Check 21: the rebuilt package is the signed target, length and sha256, as hashed here.
pub fn rebuilt_bytes(bytes: &[u8], target: &Target, path: &TargetPath) -> Vec<Finding> {
    let sha256 = oncl_pack::sha256_hex(bytes);
    if bytes.len() as u64 == target.length && sha256 == target.sha256.to_hex() {
        Vec::new()
    } else {
        vec![finding(
            21,
            format!(
                "{path}: the rebuild is {} bytes with sha256 {sha256}, the role signs {} bytes \
                 with {}",
                bytes.len(),
                target.length,
                target.sha256
            ),
        )]
    }
}

/// Check 22 on the rebuilt bytes: they read as a package (`Package::read`), its manifest has
/// the entry's id, version, modules, `replaces` and `min_core`, its capabilities are the
/// entry's `capabilities`, and its `plugin.toml` is the archive's `src/<path>/plugin.toml`
/// byte for byte.
pub fn rebuilt_package(
    bytes: &[u8],
    release: &PublisherRelease,
    tree: &Tree,
    crate_path: &str,
    path: &TargetPath,
) -> Vec<Finding> {
    let at = |message: String| finding(22, format!("{path}: {message}"));
    let package = match Package::read(bytes) {
        Ok(package) => package,
        Err(e) => return vec![at(format!("the rebuilt package does not read: {e}"))],
    };
    let mut findings = Vec::new();
    let m = &package.manifest;
    let r = release.release();
    let mut differs =
        |what: &str| findings.push(at(format!("the manifest's {what} differs from the entry")));
    if m.id != r.id {
        differs("id");
    }
    if m.version != r.version {
        differs("version");
    }
    if m.modules != r.modules {
        differs("modules");
    }
    if m.min_core != r.min_core {
        differs("min_core");
    }
    let replaces = m.replaces.as_ref().map(|x| (&x.symname, &x.version));
    let listed = r.replaces.as_ref().map(|x| (&x.symname, &x.version));
    if replaces != listed {
        differs("replaces");
    }
    match r.capabilities.as_ref().map(Capabilities::try_from) {
        Some(Ok(declared)) if declared == m.capabilities => {}
        Some(Ok(_)) => findings.push(at(
            "capabilities differ from the manifest's [capabilities]".to_owned()
        )),
        Some(Err(e)) => findings.push(at(format!("capabilities do not read: {e}"))),
        None => findings.push(at("the entry has no capabilities".to_owned())),
    }
    let manifest_path = if crate_path.is_empty() {
        "plugin.toml".to_owned()
    } else {
        format!("{crate_path}/plugin.toml")
    };
    match (zip_entry(bytes, "plugin.toml"), tree.get(&manifest_path)) {
        (Ok(packed), Some(source)) if packed == source.data => {}
        (Ok(_), Some(_)) => findings.push(at(format!(
            "plugin.toml in the package is not src/{manifest_path}"
        ))),
        (Ok(_), None) => findings.push(at(format!("src/{manifest_path} is not in the archive"))),
        (Err(e), _) => findings.push(at(format!("plugin.toml of the package: {e}"))),
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capabilities_table_becomes_the_json_object() {
        let json = capabilities_json(
            "id = \"kz.a.b\"\n[capabilities]\nkeys = true\nhttp = [\"https://api.example.com/\"]\n",
        )
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"keys": true, "http": ["https://api.example.com/"]})
        );
        assert_eq!(
            capabilities_json("id = \"x\"\n").unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn buildinfo_round_trips_and_refuses_unknown_members() {
        let info = BuildInfo {
            schema: SCHEMA,
            id: "kz.a.b".into(),
            version: "1.0.0".into(),
            builder: BuilderInfo {
                image: "img".into(),
                digest: None,
                rust: None,
                commit: None,
            },
            source: SourceInfo {
                archive: FileInfo {
                    file: "kz.a.b-1.0.0.src.tar.gz".into(),
                    sha256: "0".repeat(64),
                    length: 1,
                },
                path: String::new(),
                license: Some("MIT".into()),
                cargo_lock_sha256: None,
            },
            package: FileInfo {
                file: "kz.a.b-1.0.0.onclp".into(),
                sha256: "1".repeat(64),
                length: 2,
            },
            release: None,
            vcs: None,
            checks: Vec::new(),
        };
        let json = info.to_json().unwrap();
        assert_eq!(BuildInfo::from_json(json.as_bytes()).unwrap(), info);
        let extra = json.replacen("{", "{\"extra\": 1,", 1);
        assert!(BuildInfo::from_json(extra.as_bytes()).is_err());
    }
}
