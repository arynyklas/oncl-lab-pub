//! The draft of a publisher's next role version, `target/vendor/<name>/role.json`
//! (`docs/design/publishers.md`, «Команды издателя»): started from the newest version of the
//! role in the repository, changed by `vendor add` (a new package, its entry filled from the
//! build's output and the package's manifest), `vendor set` (rollout, channel, revoked) and
//! `vendor prune` (an old version, where check 8 allows), and signed by `vendor sign`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_plugin::Package;
use oncl_update::catalog::{PluginId, PublisherRelease, mirror_url};
use oncl_update::tuf::{Digest, Envelope, Profile, TargetPath, Targets};
use oncl_update::{Channel, Version};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::checks;
use super::keys;
use super::mirror::{self, BuildInfo};
use crate::publishers::Publisher;

/// The format version of the draft.
const SCHEMA: u32 = 1;

/// The draft.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    /// [`SCHEMA`].
    pub schema: u32,
    /// The publisher.
    pub publisher: String,
    /// The version of the role it was started from; none before the first release.
    pub base_version: Option<u64>,
    /// The targets of the next version.
    pub targets: Map<String, Value>,
}

/// Where the draft of `publisher` is, from the root of the checkout.
pub fn path(root: &Path, publisher: &str) -> PathBuf {
    root.join("target/vendor").join(publisher).join("role.json")
}

/// The source of a new entry.
#[derive(Clone, Debug)]
pub struct Addition<'a> {
    /// `BUILDINFO.json` of `vendor build`.
    pub build: &'a BuildInfo,
    /// The package it made.
    pub package: &'a [u8],
    /// Where CI downloads the archive once (`source.fetch`).
    pub fetch: &'a str,
    /// The git revision the archive was made from, if the publisher names one.
    pub vcs: Option<(&'a str, &'a str)>,
    /// `beta` or `stable`.
    pub channel: Channel,
    /// The share of installations offered the release.
    pub rollout: u8,
}

/// `targets` as the client reads a role's (the version and expiry do not matter here).
fn read_targets(targets: &Map<String, Value>) -> anyhow::Result<Targets> {
    let signed = json!({
        "_type": "targets",
        "spec_version": oncl_update::tuf::model::SPEC_VERSION,
        "version": 1,
        "expires": "2100-01-01T00:00:00Z",
        "targets": targets,
    });
    Targets::from_signed(&signed, Profile::Legacy).map_err(|e| anyhow::anyhow!("{e}"))
}

impl Draft {
    /// The draft of `publisher` in `root`, or a new one from the newest version of its role
    /// in the repository `tuf`.
    ///
    /// # Errors
    ///
    /// The draft or the role file cannot be read.
    pub fn open(root: &Path, tuf: &Path, publisher: &Publisher) -> anyhow::Result<Draft> {
        let file = path(root, publisher.name.as_str());
        if file.is_file() {
            let draft: Draft = serde_json::from_slice(&fs::read(&file)?)
                .with_context(|| format!("reading {}", file.display()))?;
            if draft.schema != SCHEMA || draft.publisher != publisher.name.as_str() {
                bail!("{} is not a draft of {}", file.display(), publisher.name);
            }
            return Ok(draft);
        }
        let (base_version, targets) = match keys::newest_targets(tuf, &publisher.name)? {
            Some((version, targets)) => (Some(version), targets),
            None => (None, Map::new()),
        };
        Ok(Draft {
            schema: SCHEMA,
            publisher: publisher.name.as_str().to_owned(),
            base_version,
            targets,
        })
    }

    /// Writes the draft into `root`.
    ///
    /// # Errors
    ///
    /// Writing fails.
    pub fn save(&self, root: &Path) -> anyhow::Result<PathBuf> {
        let file = path(root, &self.publisher);
        if let Some(dir) = file.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        fs::write(&file, text).with_context(|| format!("writing {}", file.display()))?;
        Ok(file)
    }

    /// Adds the package of `addition` as a new target: its length and sha256, the computed
    /// copy's `url`, `source` from the build, and the manifest's id, version, `min_core`,
    /// modules, `replaces`, name and `[capabilities]`. Returns the target path.
    ///
    /// # Errors
    ///
    /// The package does not read or is not the build's, the version is there already or has
    /// build metadata, the build ran in no listed builder, the id or a module is not the
    /// publisher's, or the client would leave the entry out.
    pub fn add(&mut self, publisher: &Publisher, addition: &Addition) -> anyhow::Result<String> {
        let package = Package::read(addition.package).context("reading the package")?;
        let m = &package.manifest;
        if !m.version.build.is_empty() {
            bail!(
                "{} {}: a publisher's version has no build metadata (+…)",
                m.id,
                m.version
            );
        }
        if !(publisher.covers(&m.id) && m.id.len() > publisher.id_prefix.len()) {
            bail!("{} is not under the prefix {}", m.id, publisher.id_prefix);
        }
        if let Some(module) = m.modules.iter().find(|x| !publisher.modules.contains(x)) {
            bail!(
                "the module {module} is not one of publishers/{}",
                publisher.name
            );
        }
        if let Some(replaces) = &m.replaces
            && !publisher.bundles.contains(&replaces.symname)
        {
            bail!(
                "replaces {} is not one of the bundles of publishers/{}",
                replaces.symname,
                publisher.name
            );
        }
        let build = addition.build;
        if build.package.sha256 != oncl_pack::sha256_hex(addition.package) {
            bail!("the package is not the one BUILDINFO.json describes");
        }
        let digest = build
            .builder
            .digest
            .as_deref()
            .context("the build ran in an image without a digest: build with --builder")?;
        let license = build
            .source
            .license
            .as_deref()
            .context("the crate's Cargo.toml has no license")?;
        let id = PluginId::parse(&m.id).map_err(|e| anyhow::anyhow!("{e}"))?;
        let path = format!("plugins/{}/{}/{}.onclp", publisher.name, m.id, m.version);
        if self.targets.contains_key(&path) {
            bail!("{path} is in the role already: a version is released once");
        }
        let sha256 = Digest::of(addition.package);
        let manifest_text = mirror::zip_entry(addition.package, "plugin.toml")?;
        let capabilities = mirror::capabilities_json(
            std::str::from_utf8(&manifest_text).context("plugin.toml is not UTF-8")?,
        )?;
        let mut source = json!({
            "archive_sha256": build.source.archive.sha256,
            "archive_length": build.source.archive.length,
            "fetch": addition.fetch,
            "path": build.source.path,
            "license": license,
            "builder": digest,
        });
        if let Some((url, rev)) = addition.vcs {
            source["vcs"] = json!({"url": url, "rev": rev});
        }
        let mut entry = json!({
            "schema": PublisherRelease::SCHEMA,
            "id": m.id,
            "version": m.version.to_string(),
            "url": mirror_url(&publisher.name, &id, &m.version, &sha256),
            "source": source,
            "channel": addition.channel,
            "min_core": m.min_core.to_string(),
            "modules": m.modules,
            "name": {"ru": m.name.ru, "kk": m.name.kk, "en": m.name.en},
            "capabilities": capabilities,
            "rollout": addition.rollout,
            "revoked": false,
        });
        if let Some(replaces) = &m.replaces {
            entry["replaces"] = json!({"symname": replaces.symname, "version": replaces.version});
        }
        let target = json!({
            "length": addition.package.len(),
            "hashes": {"sha256": sha256.to_hex()},
            "custom": {"oncl": entry},
        });
        // The client's reading of the new target.
        let target_path = TargetPath::parse(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut alone = Map::new();
        alone.insert(path.clone(), target.clone());
        let probe = read_targets(&alone)?;
        let read = probe
            .targets
            .get(&target_path)
            .context("the new target is not read back")?;
        PublisherRelease::parse(&publisher.name, &target_path, read)
            .map_err(|e| anyhow::anyhow!("the client would leave {path} out: {e}"))?;
        self.targets.insert(path.clone(), target);
        Ok(path)
    }

    /// Changes what a later version of the role may change of a release: its channel (only
    /// `beta` to `stable`), rollout and `revoked`.
    ///
    /// # Errors
    ///
    /// The release is not in the draft, the channel would go back to `beta` or a pre-release
    /// to `stable`, or the rollout is above 100.
    pub fn set(
        &mut self,
        id: &str,
        version: &Version,
        channel: Option<Channel>,
        rollout: Option<u8>,
        revoked: Option<bool>,
    ) -> anyhow::Result<()> {
        let path = format!("plugins/{}/{id}/{version}.onclp", self.publisher);
        let entry = self
            .targets
            .get_mut(&path)
            .and_then(|t| t.get_mut("custom"))
            .and_then(|c| c.get_mut("oncl"))
            .and_then(Value::as_object_mut)
            .with_context(|| format!("{path} is not in the draft"))?;
        if let Some(channel) = channel {
            if entry.get("channel").and_then(Value::as_str) == Some("stable")
                && channel == Channel::Beta
            {
                bail!("{id} {version} is on stable: a channel only widens (check 8)");
            }
            if channel == Channel::Stable && !version.pre.is_empty() {
                bail!("{id} {version} is a pre-release: it stays on beta");
            }
            entry.insert("channel".to_owned(), json!(channel));
        }
        if let Some(rollout) = rollout {
            if rollout > 100 {
                bail!("rollout {rollout} is over 100");
            }
            entry.insert("rollout".to_owned(), json!(rollout));
        }
        if let Some(revoked) = revoked {
            entry.insert("revoked".to_owned(), json!(revoked));
        }
        Ok(())
    }

    /// Removes a release, if check 8 lets it go: not revoked by the publisher or the owner,
    /// and a newer unrevoked version of the plugin stays on the same or a wider channel.
    ///
    /// # Errors
    ///
    /// The release is not in the draft, or it may not go.
    pub fn prune(
        &mut self,
        publisher: &Publisher,
        id: &str,
        version: &Version,
    ) -> anyhow::Result<()> {
        let path = format!("plugins/{}/{id}/{version}.onclp", publisher.name);
        if !self.targets.contains_key(&path) {
            bail!("{path} is not in the draft");
        }
        let before = read_targets(&self.targets)?;
        let mut after = self.targets.clone();
        after.remove(&path);
        let found = checks::history(Some(&before), &read_targets(&after)?, publisher);
        if let Some(why) = found.first() {
            bail!("{}", why.message);
        }
        self.targets = after;
        Ok(())
    }
}

/// The targets of a role file, as the client reads them.
///
/// # Errors
///
/// It does not read as a role.
pub fn role_targets(bytes: &[u8]) -> anyhow::Result<Targets> {
    let envelope =
        Envelope::parse(bytes, super::MAX_ROLE_FILE, "role").map_err(|e| anyhow::anyhow!("{e}"))?;
    Targets::from_signed(&envelope.signed, Profile::Legacy).map_err(|e| anyhow::anyhow!("{e}"))
}
