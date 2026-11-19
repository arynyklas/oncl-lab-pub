//! Plugin releases in the signed channel index and in publishers' roles, and the version an
//! installation may use.

use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::catalog::{Catalog, DeclaredCapabilities, PublisherState};
use crate::tuf::PublisherName;
use crate::{Package, UpdateError};

/// A version of one plugin, independently released from the core.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRelease {
    /// Its stable identifier, also used in the package's manifest.
    pub id: String,
    /// The version of our port, not the original bundle's version.
    pub version: Version,
    /// The immutable package URL, hash and byte size.
    #[serde(flatten)]
    pub package: Package,
    /// The oldest core version this plugin can run on.
    pub min_core: Version,
    /// Protocol module names provided by this plugin.
    pub modules: Vec<String>,
    /// The original NCALayer bundle this port replaces, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<PluginReplaces>,
    /// Its name in the three interface languages.
    pub name: PluginName,
    /// Percentage of installations offered this release, from zero to 100.
    pub rollout: u8,
    /// Stop offering this release and move installed copies away from it.
    #[serde(default)]
    pub revoked: bool,
    /// The publisher whose role signed the release; `None` for the owner's index. Never
    /// read from JSON, so the owner's index cannot pass a port off as a publisher's plugin.
    #[serde(skip)]
    pub publisher: Option<PublisherName>,
    /// The capabilities a publisher's release declares (`custom.oncl.capabilities`); `None`
    /// for the owner's index, whose packages are checked against their manifest alone.
    #[serde(skip)]
    pub capabilities: Option<DeclaredCapabilities>,
}

/// The symbolic name and version exposed to sites as an installed original bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginReplaces {
    /// Its original OSGi symbolic name.
    pub symname: String,
    /// Its original version; OSGi versions need not be semver.
    pub version: String,
}

/// A plugin's display name in each supported language.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginName {
    /// Russian.
    pub ru: String,
    /// Kazakh.
    pub kk: String,
    /// English.
    pub en: String,
}

impl PluginRelease {
    /// The rules a client needs to read the entry: an `https://` package (checked by the
    /// caller with the other URLs), `rollout` up to 100 and at least one module. The rest of
    /// the entry (id, module names, name, `replaces`) is compared with the package's own
    /// manifest before anything is installed, so a grammar of the plugin format is not
    /// repeated here: an index carrying a plugin the core cannot install still updates the
    /// core.
    pub(crate) fn check(&self) -> Result<(), UpdateError> {
        let invalid = |what: &str| {
            UpdateError::Malformed(format!("plugin {} {}: {what}", self.id, self.version))
        };
        if self.rollout > 100 {
            return Err(invalid(&format!("rollout {} is over 100", self.rollout)));
        }
        if self.modules.is_empty() {
            return Err(invalid("no modules"));
        }
        Ok(())
    }
}

/// The rollout bucket of `install_id` for one plugin release, from zero to 99.
///
/// It hashes `install_id ‖ id ‖ 0x00 ‖ version`, so separate plugins do not share a rollout.
pub fn plugin_bucket(install_id: &[u8; 16], id: &str, version: &Version) -> u8 {
    let digest = sha2::Sha256::new()
        .chain_update(install_id)
        .chain_update(id.as_bytes())
        .chain_update([0])
        .chain_update(version.to_string().as_bytes())
        .finalize();
    (u16::from(digest[0]) * 100 / 256) as u8
}

/// What to do with an installed plugin after accepting a new catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PluginChoice<'a> {
    /// Leave the installed version alone.
    Keep,
    /// Load a newer version without restarting the core.
    Update(&'a PluginRelease),
    /// Replace a revoked version with an older release.
    Downgrade(&'a PluginRelease),
    /// The installed version is revoked and no eligible replacement exists.
    Withdrawn,
    /// The plugin's publisher is revoked: the caller turns it off as if withdrawn.
    PublisherRevoked(&'a PublisherName),
}

/// Whether `release` may be offered to this installation: not revoked, compatible with
/// `core`, not `bad` and rolled out to `install_id`.
pub(crate) fn offerable(
    release: &PluginRelease,
    core: &Version,
    install_id: &[u8; 16],
    bad: &BTreeMap<String, BTreeSet<Version>>,
) -> bool {
    !release.revoked
        && release.min_core <= *core
        && !bad
            .get(&release.id)
            .is_some_and(|versions| versions.contains(&release.version))
        && plugin_bucket(install_id, &release.id, &release.version) < release.rollout
}

/// Chooses a plugin update compatible with `core` and not known to fail here.
///
/// Ordinary updates respect rollout and never downgrade. Revocation bypasses rollout:
/// getting off the withdrawn version takes precedence, including by downgrade. If no
/// safe replacement exists the caller must unload it. An unlisted current version alone
/// never causes a downgrade or removal.
///
/// A publisher's plugin is [`PluginChoice::PublisherRevoked`] once its publisher is revoked.
/// While its publisher is retired or unavailable it is kept as it is, unless its version is
/// revoked ([`Catalog::is_revoked`]: by the owner in `publishers.json`, or by a verified
/// role of the publisher): then it is [`PluginChoice::Withdrawn`]. A revoked version is
/// revoked even if its publisher no longer lists it. The publisher is found by the prefixes
/// of `publishers.json` ([`choose_installed`] takes the one recorded).
pub fn choose_plugin<'a>(
    catalog: &'a Catalog,
    id: &str,
    current: &Version,
    core: &Version,
    install_id: &[u8; 16],
    bad: &BTreeSet<Version>,
) -> PluginChoice<'a> {
    choose_installed(catalog, id, None, current, core, install_id, bad)
}

/// [`choose_plugin`] for an installed plugin whose publisher was recorded when it was
/// installed (`recorded`). Should it differ from the publisher whose prefix covers `id`, the
/// choice fails closed: the stricter state of the two holds, a version either revokes is
/// revoked ([`Catalog::publisher_state_of`], [`Catalog::is_installed_revoked`]), and only
/// the recorded publisher's releases may replace the version installed. A recorded
/// publisher `publishers.json` does not name is unavailable: kept unless revoked.
pub fn choose_installed<'a>(
    catalog: &'a Catalog,
    id: &str,
    recorded: Option<&'a PublisherName>,
    current: &Version,
    core: &Version,
    install_id: &[u8; 16],
    bad: &BTreeSet<Version>,
) -> PluginChoice<'a> {
    let revoked = catalog.is_installed_revoked(id, current, recorded);
    if let Some((publisher, state)) = catalog.publisher_state_of(id, recorded) {
        match state {
            PublisherState::Active => {}
            PublisherState::Retired | PublisherState::Unavailable if revoked => {
                return PluginChoice::Withdrawn;
            }
            PublisherState::Retired | PublisherState::Unavailable => return PluginChoice::Keep,
            PublisherState::Revoked => return PluginChoice::PublisherRevoked(publisher),
        }
    }
    // The owner's index (`None`) for its ports, else the plugin's publisher.
    let source = recorded.or_else(|| catalog.publisher_of(id));
    let candidate = catalog
        .releases()
        .filter(|r| {
            r.id == id
                && r.publisher.as_ref() == source
                && !r.revoked
                && r.min_core <= *core
                && !bad.contains(&r.version)
                && (revoked || plugin_bucket(install_id, id, &r.version) < r.rollout)
        })
        .max_by(|a, b| a.version.cmp(&b.version));
    match candidate {
        Some(r) if r.version > *current => PluginChoice::Update(r),
        Some(r) if revoked && r.version < *current => PluginChoice::Downgrade(r),
        _ if revoked => PluginChoice::Withdrawn,
        _ => PluginChoice::Keep,
    }
}

/// Finds the newest compatible, non-revoked offered release matching a module or bundle.
/// A port a publisher replaces is not offered once its replacement is
/// ([`Catalog::replacement`]).
///
/// `pick` supplies the lookup, for example a `replaces.symname` or a `modules` member.
pub fn offer<'a>(
    catalog: &'a Catalog,
    core: &Version,
    install_id: &[u8; 16],
    bad: &BTreeMap<String, BTreeSet<Version>>,
    pick: impl Fn(&PluginRelease) -> bool,
) -> Option<&'a PluginRelease> {
    catalog
        .releases()
        .filter(|r| {
            offerable(r, core, install_id, bad)
                && pick(r)
                && catalog.replacement(&r.id, core, install_id, bad).is_none()
        })
        .max_by(|a, b| a.version.cmp(&b.version).then_with(|| b.id.cmp(&a.id)))
}
