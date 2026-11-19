//! `cargo xtask index`: the update indexes of the channels, `updates/v1/<channel>.json`
//! (`docs/design/update-index.md`).
//!
//! - [`add`] appends a released version to an index, from the downloaded assets of its
//!   GitHub release, with the next `seq` and a new validity.
//! - [`refresh`] gives an index the next `seq` and a new validity without other changes.
//! - [`check`] is the gate before publishing: the format, validity,
//!   asset URLs on the project's releases ([`check_asset_urls`]), `seq` growth against the
//!   base branch and, with a [`Remote`], that every asset answers `HEAD` with 200 and,
//!   behind flags, that new versions passed `vm-smoke` and new `stable` versions
//!   `conformance`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use anyhow::{Context, bail};
use oncl_update::{
    Asset, Channel, CoreRelease, Extension, Flavor, FlavorPackage, Index, MAX_INDEX_LEN, Package,
    PluginName, PluginRelease, PluginReplaces, Sha256, Version,
};
use serde_json::Value;
use sha2::Digest;
use time::OffsetDateTime;
use ureq::Agent;

use crate::registry::ports::Conformance;

/// The oldest an index may be, from its `generated`, whatever its `expires` says: the length
/// of the index's validity.
pub const MAX_AGE: time::Duration = time::Duration::days(30);

/// Where the indexes live, from the workspace root; published under `/updates/v1/`.
pub const INDEX_DIR: &str = "updates/v1";

/// The repository whose releases hold the assets.
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// The Velopack package id (`vpk pack --packId`), the first part of package file names.
pub const PACKAGE_ID: &str = "OpenNCALayer";

/// The `vm-smoke` commit status context (set on release tags by the lab agent).
pub const VM_SMOKE: &str = "vm-smoke";

/// The `conformance` commit status context: the release tag's build compared with the
/// original in the lab (set by the lab agent after `vm-smoke`).
pub const CONFORMANCE: &str = "conformance";

/// The index of `channel` in `dir`.
pub fn index_path(dir: &Path, channel: Channel) -> PathBuf {
    dir.join(format!("{channel}.json"))
}

/// The full package of `version` for `flavor`: `OpenNCALayer-<version>-<flavor>-full.nupkg`.
pub fn full_package_name(version: &Version, flavor: &str) -> String {
    format!("{PACKAGE_ID}-{version}-{flavor}-full.nupkg")
}

/// The delta package of `version` for `flavor`: `OpenNCALayer-<version>-<flavor>-delta.nupkg`.
pub fn delta_package_name(version: &Version, flavor: &str) -> String {
    format!("{PACKAGE_ID}-{version}-{flavor}-delta.nupkg")
}

/// The Chromium extension of `version`: `openncalayer-chromium-<version>.zip`.
pub fn chromium_name(version: &Version) -> String {
    format!("openncalayer-chromium-{version}.zip")
}

/// The Firefox extension of `version`: `openncalayer-firefox-<version>.xpi`.
pub fn firefox_name(version: &Version) -> String {
    format!("openncalayer-firefox-{version}.xpi")
}

/// The URL of the asset `name` of the release of `version`, tag `v<version>`.
pub fn release_asset_url(version: &Version, name: &str) -> String {
    format!("{REPOSITORY}/releases/download/v{version}/{name}")
}

/// The release notes of `version`.
pub fn release_notes_url(version: &Version) -> String {
    format!("{REPOSITORY}/releases/tag/v{version}")
}

/// The immutable asset name of a plugin release.
pub fn plugin_package_name(id: &str, version: &Version) -> String {
    format!("{id}-{version}.onclp")
}

/// Whether `tag` names a dated batch of plugin releases.
pub fn is_plugin_tag(tag: &str) -> bool {
    let Some(date) = tag.strip_prefix("plugins-") else {
        return false;
    };
    let (date, revision) = date
        .split_once('.')
        .map_or((date, None), |(d, r)| (d, Some(r)));
    date.len() == 8
        && date.bytes().all(|b| b.is_ascii_digit())
        && revision.is_none_or(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()))
}

/// The URL of one package in a dated plugin release.
///
/// # Errors
///
/// A tag not of the form `plugins-YYYYMMDD[.N]`.
pub fn plugin_asset_url(tag: &str, id: &str, version: &Version) -> anyhow::Result<String> {
    if !is_plugin_tag(tag) {
        bail!("the tag {tag:?} is not plugins-YYYYMMDD[.N]");
    }
    Ok(format!(
        "{REPOSITORY}/releases/download/{tag}/{}",
        plugin_package_name(id, version)
    ))
}

/// Refuses an index whose files are not where the release workflow puts them: every URL
/// must be exactly [`release_asset_url`] of the entry's own version and the file name of
/// its kind (full or delta package of that flavor, Chromium or Firefox extension), and
/// `notes_url` [`release_notes_url`]. So no host, repository, tag, query or fragment other
/// than the project's releases gets signed or published. Flavors this version does not
/// know are refused too, and so are plugins sharing a module or a replaced bundle
/// (`replaces.symname`) with another plugin id, and plugins claiming what is the core's: an
/// id under the built-in modules' prefix, a built-in module's name ([`builtin_modules`]) or
/// a bundle of the original the core implements itself.
///
/// # Errors
///
/// The first URL that differs, or the first module or bundle of two plugins.
pub fn check_asset_urls(index: &Index) -> anyhow::Result<()> {
    let expect = |what: &str, url: &str, expected: String| {
        if url == expected {
            Ok(())
        } else {
            bail!("{what}: {url:?} is not {expected:?}, the asset of the project's release")
        }
    };
    for release in &index.core {
        let v = &release.version;
        if let Some(url) = &release.notes_url {
            expect(&format!("core {v} notes_url"), url, release_notes_url(v))?;
        }
        for (flavor, packages) in &release.flavors {
            if !Flavor::ALL.iter().any(|f| f.as_str() == flavor) {
                bail!("core {v}: unknown flavor {flavor:?}");
            }
            expect(
                &format!("core {v} {flavor}"),
                &packages.full.url,
                release_asset_url(v, &full_package_name(v, flavor)),
            )?;
            for (from, delta) in &packages.delta_from {
                expect(
                    &format!("core {v} {flavor} delta from {from}"),
                    &delta.url,
                    release_asset_url(v, &delta_package_name(v, flavor)),
                )?;
            }
        }
    }
    if let Some(ext) = &index.extension {
        let v = &ext.version;
        expect(
            "extension chromium_zip",
            &ext.chromium_zip.url,
            release_asset_url(v, &chromium_name(v)),
        )?;
        expect(
            "extension firefox_xpi",
            &ext.firefox_xpi.url,
            release_asset_url(v, &firefox_name(v)),
        )?;
    }
    let plugin_base = format!("{REPOSITORY}/releases/download/");
    let builtin = builtin_modules()?;
    let mut owners = BTreeMap::new();
    let mut replacers = BTreeMap::new();
    for plugin in &index.plugins {
        if plugin.id.starts_with(oncl_plugin::BUILTIN_ID_PREFIX) {
            bail!(
                "plugin {}: the id is reserved for the built-in modules",
                plugin.id
            );
        }
        if let Some(module) = plugin.modules.iter().find(|m| builtin.contains(m)) {
            bail!("plugin {}: {module} is a built-in module", plugin.id);
        }
        if let Some(replaces) = &plugin.replaces
            && oncl_builtin_accessory::CORE_BUNDLES
                .iter()
                .any(|(symname, _)| *symname == replaces.symname)
        {
            bail!(
                "plugin {}: the bundle {} is the core's",
                plugin.id,
                replaces.symname
            );
        }
        let (tag, _) = plugin
            .package
            .url
            .strip_prefix(&plugin_base)
            .and_then(|tail| tail.split_once('/'))
            .with_context(|| {
                format!(
                    "plugin {}: URL is not an asset of the project's release",
                    plugin.id
                )
            })?;
        expect(
            &format!("plugin {} {}", plugin.id, plugin.version),
            &plugin.package.url,
            plugin_asset_url(tag, &plugin.id, &plugin.version)?,
        )?;
        if index.channel == Channel::Stable && !plugin.version.pre.is_empty() {
            bail!(
                "plugin {} {} is a prerelease in stable",
                plugin.id,
                plugin.version
            );
        }
        for module in &plugin.modules {
            if let Some(owner) = owners.insert(module, &plugin.id)
                && owner != &plugin.id
            {
                bail!("module {module} is owned by both {owner} and {}", plugin.id);
            }
        }
        // A bundle of the original is replaced by one plugin, whatever its version:
        // `installBundle` picks the plugin to install by it.
        if let Some(replaces) = &plugin.replaces
            && let Some(owner) = replacers.insert(&replaces.symname, &plugin.id)
            && owner != &plugin.id
        {
            bail!(
                "the bundle {} is replaced by both {owner} and {}",
                replaces.symname,
                plugin.id
            );
        }
    }
    Ok(())
}

/// The module names of the built-in modules (`crates/oncl-builtin-*/plugin.toml`), which no
/// plugin may serve.
///
/// # Errors
///
/// A built-in module's manifest cannot be read.
pub fn builtin_modules() -> anyhow::Result<Vec<String>> {
    let root = oncl_testkit::workspace_root();
    let mut modules = Vec::new();
    for guest in oncl_builtins_build::GUESTS {
        let path = root.join(guest.dir).join("plugin.toml");
        let text = fs::read_to_string(&path).with_context(|| format!("{}", path.display()))?;
        let manifest = oncl_plugin::Manifest::from_toml_builtin(&text)
            .with_context(|| format!("{}", path.display()))?;
        modules.extend(manifest.modules);
    }
    Ok(modules)
}

/// An index written by [`add`] or [`refresh`].
#[derive(Debug)]
pub struct Written {
    /// The index.
    pub path: PathBuf,
    /// Its new `seq`.
    pub seq: u64,
}

/// What [`add`] did.
#[derive(Debug)]
pub struct Added {
    /// The index written.
    pub written: Written,
    /// The flavors of the new version.
    pub flavors: Vec<Flavor>,
    /// Whether the new version brought the browser extension.
    pub extension: bool,
}

/// Appends the version of `tag` (`v<semver>`) to the index of `channel` in `dir`, created if
/// missing, from the release's downloaded assets in `assets`:
///
/// - per flavor, [`full_package_name`] (required for at least one flavor) and optionally
///   [`delta_package_name`], whose base version is the newest older full package in
///   Velopack's `releases.<flavor>.json` beside it;
/// - optionally the extension, [`chromium_name`] and [`firefox_name`] together.
///
/// sha256 and sizes come from the files; URLs are [`release_asset_url`]. `seq` grows by
/// one, `generated` is `now` and `expires` 30 days later ([`MAX_AGE`]).
///
/// # Errors
///
/// A tag that is not `v<semver>`, a version already listed, missing or half-present assets,
/// an existing index that is invalid, of another channel or with URLs
/// [`check_asset_urls`] refuses, or a failure to read or write.
pub fn add(
    dir: &Path,
    channel: Channel,
    tag: &str,
    assets: &Path,
    rollout: u8,
    now: OffsetDateTime,
) -> anyhow::Result<Added> {
    let version = tag
        .strip_prefix('v')
        .and_then(|v| Version::parse(v).ok())
        .filter(|v| format!("v{v}") == tag)
        .with_context(|| format!("the tag {tag:?} is not v<semver>"))?;
    if rollout > 100 {
        bail!("rollout {rollout} is over 100");
    }
    let path = index_path(dir, channel);
    let mut index = if path.exists() {
        read_index(&path, channel)?
    } else {
        Index {
            schema: oncl_update::index::SCHEMA,
            channel,
            seq: 0,
            generated: now,
            expires: now,
            core: Vec::new(),
            extension: None,
            plugins: Vec::new(),
        }
    };
    if index.release(&version).is_some() {
        bail!("{version} is in {} already", path.display());
    }

    let names = file_names(assets)?;
    let mut release = CoreRelease {
        version: version.clone(),
        flavors: Default::default(),
        rollout,
        revoked: false,
        notes_url: Some(release_notes_url(&version)),
    };
    let mut flavors = Vec::new();
    for flavor in Flavor::ALL {
        let full = full_package_name(&version, flavor.as_str());
        if !names.contains(&full) {
            continue;
        }
        let mut packages = FlavorPackage {
            full: package(assets, &version, &full)?,
            contents_sha256: None,
            delta_from: Default::default(),
        };
        let delta = delta_package_name(&version, flavor.as_str());
        if names.contains(&delta) {
            let base = delta_base(assets, flavor, &version)?;
            packages
                .delta_from
                .insert(base, package(assets, &version, &delta)?);
            // What the client checks the full package rebuilt from the delta against.
            let path = assets.join(&full);
            packages.contents_sha256 = Some(
                oncl_update::contents_sha256(&path)
                    .with_context(|| format!("reading the files of {}", path.display()))?,
            );
        }
        release.flavors.insert(flavor.as_str().to_owned(), packages);
        flavors.push(flavor);
    }
    if flavors.is_empty() {
        bail!(
            "{} has no {}",
            assets.display(),
            full_package_name(&version, "<flavor>")
        );
    }

    let chromium = chromium_name(&version);
    let firefox = firefox_name(&version);
    let extension = match (names.contains(&chromium), names.contains(&firefox)) {
        (true, true) => {
            index.extension = Some(Extension {
                version: version.clone(),
                chromium_zip: asset(assets, &version, &chromium)?,
                firefox_xpi: asset(assets, &version, &firefox)?,
            });
            true
        }
        (false, false) => false,
        (true, false) => bail!("{} has {chromium} but not {firefox}", assets.display()),
        (false, true) => bail!("{} has {firefox} but not {chromium}", assets.display()),
    };

    index.core.push(release);
    index.core.sort_by(|a, b| a.version.cmp(&b.version));
    let written = write_next(&path, index, now)?;
    Ok(Added {
        written,
        flavors,
        extension,
    })
}

/// Gives the index of `channel` in `dir` the next `seq`, `generated` = `now` and `expires`
/// 30 days later, and nothing else, before it expires.
///
/// # Errors
///
/// A missing or invalid index, one of another channel or with URLs [`check_asset_urls`]
/// refuses, or a failure to write.
pub fn refresh(dir: &Path, channel: Channel, now: OffsetDateTime) -> anyhow::Result<Written> {
    let path = index_path(dir, channel);
    let index = read_index(&path, channel)?;
    write_next(&path, index, now)
}

/// Appends validated plugin packages to a channel's index.
///
/// Package hashes and metadata come from their bytes, never from their file names. A
/// package goes to `stable` only if its port in `plugins` has `conformance = "confirmed"`
/// ([`crate::plugin::registry_conformance`]); `beta` does not read `plugins`.
///
/// # Errors
///
/// An invalid tag or package, an existing version, a prerelease or a port without confirmed
/// conformance in stable, conflicting module owners or bundles replaced by two plugins
/// (checked before anything is written), an invalid existing index, or an I/O failure.
pub fn add_plugins(
    dir: &Path,
    plugins: &Path,
    channel: Channel,
    tag: &str,
    packages: &[PathBuf],
    rollout: u8,
    now: OffsetDateTime,
) -> anyhow::Result<Written> {
    if !is_plugin_tag(tag) {
        bail!("the tag {tag:?} is not plugins-YYYYMMDD[.N]");
    }
    if packages.is_empty() || rollout > 100 {
        bail!("at least one plugin package and rollout from 0 to 100 are required");
    }
    let path = index_path(dir, channel);
    let mut index = if path.exists() {
        read_index(&path, channel)?
    } else {
        Index {
            schema: oncl_update::index::SCHEMA,
            channel,
            seq: 0,
            generated: now,
            expires: now,
            core: Vec::new(),
            extension: None,
            plugins: Vec::new(),
        }
    };
    for path in packages {
        let (bytes, package) = crate::plugin::read_package(path)?;
        let manifest = package.manifest;
        if channel == Channel::Stable {
            if !manifest.version.pre.is_empty() {
                bail!(
                    "plugin {} {} is a prerelease; add it to beta",
                    manifest.id,
                    manifest.version
                );
            }
            let conformance = crate::plugin::registry_conformance(plugins, &manifest.id)?;
            if conformance != Conformance::Confirmed.as_str() {
                bail!(
                    "{}: conformance with the original is not confirmed (conformance = \
                     {conformance}); add it to beta",
                    manifest.id
                );
            }
        }
        if index
            .plugins
            .iter()
            .any(|r| r.id == manifest.id && r.version == manifest.version)
        {
            bail!(
                "plugin {} {} is in the index already",
                manifest.id,
                manifest.version
            );
        }
        index.plugins.push(PluginRelease {
            package: Package {
                url: plugin_asset_url(tag, &manifest.id, &manifest.version)?,
                sha256: Sha256(package.sha256),
                size: bytes.len() as u64,
            },
            id: manifest.id,
            version: manifest.version,
            min_core: manifest.min_core,
            modules: manifest.modules,
            replaces: manifest.replaces.map(|r| PluginReplaces {
                symname: r.symname,
                version: r.version,
            }),
            name: PluginName {
                ru: manifest.name.ru,
                kk: manifest.name.kk,
                en: manifest.name.en,
            },
            rollout,
            revoked: false,
            publisher: None,
            capabilities: None,
        });
    }
    check_asset_urls(&index)
        .with_context(|| format!("the plugins of {tag} do not fit {}", path.display()))?;
    write_next(&path, index, now)
}

/// The index at `path`, which must be of `channel` and pass [`check_asset_urls`].
pub(crate) fn read_index(path: &Path, channel: Channel) -> anyhow::Result<Index> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let index = Index::from_json(&bytes).with_context(|| format!("reading {}", path.display()))?;
    if index.channel != channel {
        bail!("{} is of the {} channel", path.display(), index.channel);
    }
    check_asset_urls(&index).with_context(|| format!("reading {}", path.display()))?;
    Ok(index)
}

/// Writes `index` to `path` with the next `seq` and a validity from `now`.
fn write_next(path: &Path, mut index: Index, now: OffsetDateTime) -> anyhow::Result<Written> {
    index.seq = index
        .seq
        .checked_add(1)
        .context("seq cannot grow any further")?;
    index.generated = now.replace_nanosecond(0).expect("0 is a valid nanosecond");
    index.expires = index.generated + MAX_AGE;

    let mut json = serde_json::to_string_pretty(&index).context("serializing the index")?;
    json.push('\n');
    // What is written must read back as valid.
    let reread = Index::from_json(json.as_bytes()).context("the new index is invalid")?;
    check_asset_urls(&reread).context("the new index is invalid")?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(Written {
        path: path.to_owned(),
        seq: index.seq,
    })
}

/// The names of the files in `dir`.
fn file_names(dir: &Path) -> anyhow::Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        if entry.file_type()?.is_file()
            && let Ok(name) = entry.file_name().into_string()
        {
            names.insert(name);
        }
    }
    Ok(names)
}

/// The sha256 and size of `path`.
fn sum(path: &Path) -> anyhow::Result<(Sha256, u64)> {
    let mut file = File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((Sha256(hasher.finalize().into()), size))
}

fn package(assets: &Path, version: &Version, name: &str) -> anyhow::Result<Package> {
    let (sha256, size) = sum(&assets.join(name))?;
    Ok(Package {
        url: release_asset_url(version, name),
        sha256,
        size,
    })
}

fn asset(assets: &Path, version: &Version, name: &str) -> anyhow::Result<Asset> {
    let (sha256, _) = sum(&assets.join(name))?;
    Ok(Asset {
        url: release_asset_url(version, name),
        sha256,
    })
}

/// The version a delta package of `version` applies to: the newest full package older than
/// `version` in Velopack's `releases.<flavor>.json`, the feed `vpk pack` made it from.
fn delta_base(assets: &Path, flavor: Flavor, version: &Version) -> anyhow::Result<Version> {
    let path = assets.join(format!("releases.{flavor}.json"));
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let feed: Value =
        serde_json::from_str(&text).with_context(|| format!("reading {}", path.display()))?;
    let entries = feed["Assets"]
        .as_array()
        .with_context(|| format!("{}: no Assets", path.display()))?;
    let mut base: Option<Version> = None;
    for entry in entries {
        if entry["Type"] != "Full" {
            continue;
        }
        let v = entry["Version"]
            .as_str()
            .and_then(|v| Version::parse(v).ok())
            .with_context(|| format!("{}: bad Version in {entry}", path.display()))?;
        if v < *version && base.as_ref().is_none_or(|b| v > *b) {
            base = Some(v);
        }
    }
    base.with_context(|| {
        format!(
            "{}: no full package older than {version} for the {flavor} delta",
            path.display()
        )
    })
}

/// The network side of [`check`].
pub trait Remote {
    /// The HTTP status of `HEAD url`, after redirects.
    ///
    /// # Errors
    ///
    /// If no response arrives.
    fn head(&self, url: &str) -> anyhow::Result<u16>;

    /// Whether the commit of `tag` has the commit status `context` ([`VM_SMOKE`],
    /// [`CONFORMANCE`]) set to `success`.
    ///
    /// # Errors
    ///
    /// If the statuses cannot be read.
    fn status_passed(&self, tag: &str, context: &str) -> anyhow::Result<bool>;
}

/// [`Remote`] over the network: assets as they are, commit statuses through the GitHub API
/// (with `GITHUB_TOKEN` if set).
pub struct GitHub {
    agent: Agent,
    token: Option<String>,
}

impl GitHub {
    /// The longest a request may take.
    const TIMEOUT: Duration = Duration::from_secs(60);

    /// A client; `GITHUB_TOKEN` is read now.
    pub fn new() -> GitHub {
        GitHub {
            agent: Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(Self::TIMEOUT))
                .build()
                .into(),
            token: std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()),
        }
    }
}

impl Default for GitHub {
    fn default() -> GitHub {
        GitHub::new()
    }
}

impl Remote for GitHub {
    fn head(&self, url: &str) -> anyhow::Result<u16> {
        let response = self
            .agent
            .head(url)
            .header("User-Agent", "OpenNCALayer-xtask")
            .call()
            .with_context(|| format!("HEAD {url}"))?;
        Ok(response.status().as_u16())
    }

    fn status_passed(&self, tag: &str, context: &str) -> anyhow::Result<bool> {
        let repo = REPOSITORY
            .strip_prefix("https://github.com/")
            .context("the repository is not on GitHub")?;
        let url = format!("https://api.github.com/repos/{repo}/commits/{tag}/status");
        let mut request = self
            .agent
            .get(&url)
            .header("User-Agent", "OpenNCALayer-xtask")
            .header("Accept", "application/vnd.github+json");
        if let Some(token) = &self.token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let mut response = request.call().with_context(|| format!("GET {url}"))?;
        if response.status() != 200 {
            bail!("GET {url}: {}", response.status());
        }
        let body = response
            .body_mut()
            .read_to_string()
            .with_context(|| format!("GET {url}"))?;
        let status: Value = serde_json::from_str(&body).with_context(|| format!("GET {url}"))?;
        // The combined status lists the latest status of each context.
        Ok(status["statuses"].as_array().is_some_and(|statuses| {
            statuses
                .iter()
                .any(|s| s["context"] == context && s["state"] == "success")
        }))
    }
}

/// What [`check`] reads besides the indexes.
pub struct CheckOptions<'a> {
    /// The git revision of the base branch whose indexes `seq` must grow from; `None` skips
    /// it (the schema, expiry and URLs are still checked).
    pub base: Option<&'a str>,
    /// Require [`VM_SMOKE`] = `success` on the tag of every version new against `base`.
    /// Needs a [`Remote`].
    pub vm_smoke: bool,
    /// Require [`CONFORMANCE`] = `success` on the tag of every `stable` version new
    /// against `base`; `beta` versions are not gated. Needs a [`Remote`].
    pub conformance: bool,
    /// The time the indexes must be valid at.
    pub now: OffsetDateTime,
}

/// An index that passed [`check`].
#[derive(Debug)]
pub struct Checked {
    /// Its channel.
    pub channel: Channel,
    /// Its `seq`.
    pub seq: u64,
    /// The `seq` of the base branch's index, if it has one.
    pub base_seq: Option<u64>,
    /// Core versions that the base branch's index lacks.
    pub new_versions: Vec<Version>,
}

/// Reads the index `bytes` of `channel`: at most [`MAX_INDEX_LEN`] bytes, valid
/// ([`Index::from_json`]), of `channel`, and at `now` before its `expires` and less than
/// [`MAX_AGE`] after its `generated`.
fn read_valid(bytes: &[u8], channel: Channel, now: OffsetDateTime) -> anyhow::Result<Index> {
    if bytes.len() as u64 > MAX_INDEX_LEN {
        bail!("the index is larger than {MAX_INDEX_LEN} bytes");
    }
    let index = Index::from_json(bytes)?;
    if index.channel != channel {
        bail!(
            "the index is for the {} channel, not {channel}",
            index.channel
        );
    }
    let deadline = match index.generated.checked_add(MAX_AGE) {
        Some(aged) => aged.min(index.expires),
        None => index.expires,
    };
    if now >= deadline {
        bail!("the index expired at {deadline}");
    }
    Ok(index)
}

/// Checks the indexes in `dir`: each is valid at `options.now` ([`read_valid`]) and passes
/// [`check_asset_urls`]; against `options.base`, a changed index has a greater `seq` and no
/// index is removed. With `remote`, every asset URL answers `HEAD` with 200, if
/// `options.vm_smoke` every new version passed `vm-smoke`, and if `options.conformance`
/// every new `stable` version passed `conformance`.
///
/// A `dir` that does not exist (no index published yet) passes with nothing checked,
/// unless the base has an index there. An existing `dir` needs at least one index.
///
/// # Errors
///
/// The first failed check.
pub fn check(
    dir: &Path,
    options: &CheckOptions<'_>,
    remote: Option<&dyn Remote>,
) -> anyhow::Result<Vec<Checked>> {
    for (gate, context) in [
        (options.vm_smoke, VM_SMOKE),
        (options.conformance, CONFORMANCE),
    ] {
        if gate && remote.is_none() {
            bail!("the {context} gate needs the network");
        }
    }
    let mut checked = Vec::new();
    for channel in Channel::ALL {
        let path = index_path(dir, channel);
        let base = match options.base {
            Some(rev) => base_index(dir, rev, channel)?,
            None => None,
        };
        if !path.exists() {
            if base.is_some() {
                bail!(
                    "{} is in {} but removed here",
                    path.display(),
                    options.base.unwrap_or_default()
                );
            }
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let index = read_valid(&bytes, channel, options.now)
            .with_context(|| format!("{} is refused", path.display()))?;
        check_asset_urls(&index).with_context(|| format!("{} is refused", path.display()))?;

        let (base_seq, new_versions) = match &base {
            Some((base_bytes, base_index)) => {
                if *base_bytes != bytes && index.seq <= base_index.seq {
                    bail!(
                        "{} changed, but its seq {} does not grow from {} of {}",
                        path.display(),
                        index.seq,
                        base_index.seq,
                        options.base.unwrap_or_default()
                    );
                }
                let new = index
                    .core
                    .iter()
                    .filter(|r| base_index.release(&r.version).is_none())
                    .map(|r| r.version.clone())
                    .collect();
                (Some(base_index.seq), new)
            }
            None => (None, index.core.iter().map(|r| r.version.clone()).collect()),
        };

        // A version an installation may be moved onto must be able to update itself again.
        if options.base.is_some() {
            for release in &index.core {
                let changed = match &base {
                    Some((_, base_index)) => base_index
                        .release(&release.version)
                        .is_none_or(|old| old.flavors != release.flavors),
                    None => true,
                };
                if changed {
                    check_tag_root(dir, &release.version)
                        .with_context(|| format!("{} is refused", path.display()))?;
                }
            }
        }

        if let Some(remote) = remote {
            for url in asset_urls(&index) {
                let status = remote.head(url)?;
                if status != 200 {
                    bail!("{}: HEAD {url} answered {status}", path.display());
                }
            }
            let gates = [
                (options.vm_smoke, VM_SMOKE),
                (
                    options.conformance && channel == Channel::Stable,
                    CONFORMANCE,
                ),
            ];
            for version in &new_versions {
                let tag = format!("v{version}");
                for (gate, context) in gates {
                    if gate && !remote.status_passed(&tag, context)? {
                        bail!("{tag} has no successful {context} status");
                    }
                }
            }
        }
        checked.push(Checked {
            channel,
            seq: index.seq,
            base_seq,
            new_versions,
        });
    }
    if checked.is_empty() && dir.exists() {
        bail!("{} has no index", dir.display());
    }
    Ok(checked)
}

/// The URLs of every downloadable file of `index`.
fn asset_urls(index: &Index) -> BTreeSet<&str> {
    let mut urls = BTreeSet::new();
    for release in &index.core {
        for package in release.flavors.values() {
            urls.insert(package.full.url.as_str());
            urls.extend(package.delta_from.values().map(|d| d.url.as_str()));
        }
    }
    if let Some(ext) = &index.extension {
        urls.insert(ext.chromium_zip.url.as_str());
        urls.insert(ext.firefox_xpi.url.as_str());
    }
    urls.extend(index.plugins.iter().map(|p| p.package.url.as_str()));
    urls
}

/// The index of `channel` at the git revision `rev`, in `dir`'s directory of that
/// revision: its bytes and contents, or `None` if it has none.
fn base_index(dir: &Path, rev: &str, channel: Channel) -> anyhow::Result<Option<(Vec<u8>, Index)>> {
    let (repo, below) = existing_ancestor(dir)?;
    let commit = format!("{rev}^{{commit}}");
    if !git(&repo, &["rev-parse", "--verify", "--quiet", &commit])?
        .status
        .success()
    {
        bail!(
            "the base revision {rev} is not in the repository of {}",
            dir.display()
        );
    }
    let object = format!("{rev}:./{below}{channel}.json");
    if !git(&repo, &["cat-file", "-e", &object])?.status.success() {
        return Ok(None);
    }
    let output = git(&repo, &["cat-file", "blob", &object])?;
    if !output.status.success() {
        bail!(
            "git cat-file blob {object}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let index = Index::from_json(&output.stdout).with_context(|| format!("reading {object}"))?;
    Ok(Some((output.stdout, index)))
}

/// The nearest directory of `dir` that exists (`dir` itself, or an ancestor when no index
/// was published yet), where git runs, and the path from it down to `dir` (`a/b/`, empty
/// for `dir` itself). A relative `dir` is taken from the current directory, so
/// `updates/v1` without `updates/` resolves to the current directory, not to `""`.
pub(crate) fn existing_ancestor(dir: &Path) -> anyhow::Result<(PathBuf, String)> {
    let dir = std::path::absolute(dir).with_context(|| format!("resolving {}", dir.display()))?;
    let repo = dir
        .ancestors()
        .find(|d| d.is_dir())
        .with_context(|| format!("{} is not in a directory", dir.display()))?;
    let mut below = String::new();
    for part in dir.strip_prefix(repo).unwrap_or(Path::new("")).components() {
        below.push_str(&part.as_os_str().to_string_lossy());
        below.push('/');
    }
    Ok((repo.to_owned(), below))
}

pub(crate) fn git(dir: &Path, args: &[&str]) -> anyhow::Result<Output> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))
}

/// Where a build's TUF trust root is, from the workspace root: what the client embeds.
pub const TAG_ROOT: &str = "crates/oncl-update/keys/root.json";

/// Refuses `version` unless its tag `v<version>`, in the git repository of `dir`, holds
/// [`TAG_ROOT`]: an installation moved onto it must be able to verify later indexes. A
/// build without the root has its updater off for good.
///
/// # Errors
///
/// The tag is missing or has no trust root.
pub fn check_tag_root(dir: &Path, version: &Version) -> anyhow::Result<()> {
    let tag = format!("v{version}");
    // The index directory may not exist yet (the first index of a channel).
    let (dir, _) = existing_ancestor(dir)?;
    let dir = dir.as_path();
    let commit = format!("refs/tags/{tag}^{{commit}}");
    if !git(dir, &["rev-parse", "--verify", "--quiet", &commit])?
        .status
        .success()
    {
        bail!("{version}: there is no tag {tag} (fetch the tags)");
    }
    let object = format!("refs/tags/{tag}:{TAG_ROOT}");
    if !git(dir, &["cat-file", "-e", &object])?.status.success() {
        bail!(
            "{version}: {tag} has no {TAG_ROOT}: its build cannot update itself, so no installation may be moved onto it"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(generated: OffsetDateTime, expires: OffsetDateTime) -> Vec<u8> {
        use time::format_description::well_known::Rfc3339;
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": 1,
            "channel": "beta",
            "seq": 1,
            "generated": generated.format(&Rfc3339).unwrap(),
            "expires": expires.format(&Rfc3339).unwrap(),
            "core": [],
        }))
        .unwrap()
    }

    #[test]
    fn an_index_over_the_size_limit_is_refused() {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let mut bytes = valid(now, now + MAX_AGE);
        read_valid(&bytes, Channel::Beta, now).unwrap();
        bytes.resize(MAX_INDEX_LEN as usize + 1, b' ');
        let error = read_valid(&bytes, Channel::Beta, now).unwrap_err();
        assert!(error.to_string().contains("larger than"), "{error}");
    }

    #[test]
    fn an_index_older_than_max_age_is_refused_whatever_its_expires() {
        let generated = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let bytes = valid(generated, generated + time::Duration::days(365));
        read_valid(&bytes, Channel::Beta, generated + time::Duration::days(29)).unwrap();
        let error = read_valid(&bytes, Channel::Beta, generated + MAX_AGE).unwrap_err();
        assert!(error.to_string().contains("expired"), "{error}");
    }
}
