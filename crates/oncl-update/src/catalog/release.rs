//! A publisher's release: a target `plugins/<publisher>/<id>/<version>.onclp` of its
//! delegated role, read into a [`PluginRelease`] from the target's `custom.oncl`. The rules
//! that need the publisher's entry of `publishers.json` or the owner's index are the
//! catalog's ([`super::Catalog`]); here only what the target says of itself is checked.

use std::sync::Arc;

use semver::Version;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::names::PluginId;
use super::source::{ReleaseSource, SourceError};
use crate::index::{Channel, Package, Sha256};
use crate::plugins::{PluginName, PluginRelease, PluginReplaces};
use crate::tuf::{Digest, PublisherName, Target, TargetPath};

/// The longest URL a publisher's entry or `publishers.json` names, in bytes.
pub const MAX_URL: usize = 2048;

/// Where the copies of the publishers' packages are downloaded from: the project's GitHub
/// Releases (the repository of this crate), one release `pub-<publisher>-<sha256>` per
/// package.
pub const MIRROR_BASE: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/download/");

/// Whether `repository` is a repository page on GitHub: `https://github.com/` and more,
/// not ending in `/` or `.git`, so that [`MIRROR_BASE`] is its releases' download path.
const fn is_github_repository(repository: &str) -> bool {
    const PREFIX: &[u8] = b"https://github.com/";
    const GIT: &[u8] = b".git";
    let bytes = repository.as_bytes();
    if bytes.len() <= PREFIX.len() || bytes[bytes.len() - 1] == b'/' {
        return false;
    }
    let mut at = 0;
    while at < PREFIX.len() {
        if bytes[at] != PREFIX[at] {
            return false;
        }
        at += 1;
    }
    let tail = bytes.len() - GIT.len();
    let mut at = 0;
    while at < GIT.len() {
        if bytes[tail + at] != GIT[at] {
            return true;
        }
        at += 1;
    }
    false
}

const _: () = assert!(
    is_github_repository(env!("CARGO_PKG_REPOSITORY")),
    "the crate's repository must be https://github.com/<owner>/<repo>"
);

/// The only `url` a publisher's release may have: the copy of its package in the project's
/// Releases, `<MIRROR_BASE>pub-<publisher>-<sha256>/<id>-<version>.onclp`, with the
/// package's sha256 in lowercase hex.
pub fn mirror_url(
    publisher: &PublisherName,
    id: &PluginId,
    version: &Version,
    sha256: &Digest,
) -> String {
    format!("{}{id}-{version}.onclp", mirror_release(publisher, sha256))
}

/// The project's release that holds the copies of a publisher's package of `sha256` and of
/// its source archive: `<MIRROR_BASE>pub-<publisher>-<sha256>/`. The one formatter of both
/// addresses.
fn mirror_release(publisher: &PublisherName, sha256: &impl std::fmt::Display) -> String {
    format!("{MIRROR_BASE}pub-{publisher}-{sha256}/")
}

/// The source archive of a publisher's release as the windows link it: its copy in the
/// project's Releases and the license the signed release declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceArchive {
    /// `<id>-<version>.src.tar.gz`.
    pub name: String,
    /// The copy in the release of the package ([`mirror_url`]), built from the signed
    /// fields alone, never from `source.fetch`.
    pub url: String,
    /// The license, an SPDX expression.
    pub license: String,
}

impl SourceArchive {
    /// The archive of the publisher's `release` built from `source`; `None` for a release of
    /// the owner's index.
    pub(crate) fn of(release: &PluginRelease, source: &ReleaseSource) -> Option<SourceArchive> {
        let publisher = release.publisher.as_ref()?;
        let name = format!("{}-{}.src.tar.gz", release.id, release.version);
        Some(SourceArchive {
            url: format!(
                "{}{name}",
                mirror_release(publisher, &release.package.sha256)
            ),
            name,
            license: source.license.clone(),
        })
    }
}

/// Whether `url` is an anonymous `https://` URL of at most [`MAX_URL`] bytes: a host, no
/// user info or fragment, no whitespace or control characters. A query is allowed.
pub(crate) fn anonymous_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    url.len() <= MAX_URL
        && !authority.is_empty()
        && !authority.contains('@')
        && !url.contains('#')
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Whether `url` is a plain `https://` URL of at most [`MAX_URL`] bytes: an anonymous one
/// without a query.
pub(crate) fn plain_https_url(url: &str) -> bool {
    anonymous_https_url(url) && !url.contains('?')
}

/// The `capabilities` of a publisher's release (`custom.oncl.capabilities`): the
/// `[capabilities]` table of the package's manifest as a JSON object, kept as signed. This
/// crate does not read the plugin format; the caller reads it into the plugin's
/// capabilities, and compares them with the package's manifest before installing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredCapabilities(Map<String, Value>);

impl DeclaredCapabilities {
    /// The largest object, in bytes of compact JSON.
    pub const MAX_LEN: usize = 16 * 1024;

    /// The object as signed.
    pub fn as_object(&self) -> &Map<String, Value> {
        &self.0
    }

    /// The object as signed, owned.
    pub fn into_object(self) -> Map<String, Value> {
        self.0
    }
}

/// Why a `capabilities` value is not a [`DeclaredCapabilities`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CapabilitiesError {
    /// It is not a JSON object.
    #[error("capabilities are not a JSON object")]
    NotObject,
    /// It is larger than [`DeclaredCapabilities::MAX_LEN`].
    #[error("capabilities are {len} bytes, more than {max}")]
    TooLarge {
        /// Its length in compact JSON.
        len: usize,
        /// The limit.
        max: usize,
    },
}

impl TryFrom<Value> for DeclaredCapabilities {
    type Error = CapabilitiesError;

    fn try_from(value: Value) -> Result<DeclaredCapabilities, CapabilitiesError> {
        let Value::Object(object) = value else {
            return Err(CapabilitiesError::NotObject);
        };
        // Writing a `Value` to a `Vec` does not fail: its keys are strings.
        let len = serde_json::to_vec(&object).map_or(usize::MAX, |bytes| bytes.len());
        if len > DeclaredCapabilities::MAX_LEN {
            return Err(CapabilitiesError::TooLarge {
                len,
                max: DeclaredCapabilities::MAX_LEN,
            });
        }
        Ok(DeclaredCapabilities(object))
    }
}

/// Why a publisher's target is left out of the catalog. The other targets of its role are
/// unaffected.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EntryRejection {
    /// The path is not `plugins/<publisher>/<id>/<version>.onclp` of the role's publisher.
    #[error("the path is not plugins/<publisher>/<id>/<version>.onclp of its role")]
    Path,
    /// The target has no `custom.oncl`.
    #[error("the target has no custom.oncl")]
    NoEntry,
    /// `custom.oncl` has a `schema` this version does not read.
    #[error("custom.oncl schema {0} is not supported")]
    Schema(u64),
    /// `custom.oncl` is not of the expected shape.
    #[error("custom.oncl is malformed")]
    Malformed(#[source] Arc<serde_json::Error>),
    /// `id` or `version` differ from the path.
    #[error("id or version differ from the target path")]
    PathMismatch,
    /// The version has build metadata (`+…`): GitHub renames such release files, and
    /// versions differing only in it are equal in precedence.
    #[error("the version has build metadata")]
    BuildMetadata,
    /// `url` is not the copy of the package in the project's Releases ([`mirror_url`]) for
    /// this publisher, id, version and the target's sha256.
    #[error("the package url is not its copy in the project's releases")]
    NotMirrored,
    /// `source` is missing or breaks a rule of its fields.
    #[error("invalid source")]
    Source(#[source] SourceError),
    /// `rollout` is over 100.
    #[error("rollout {0} is over 100")]
    Rollout(u8),
    /// No module, or more than [`PublisherRelease::MAX_MODULES`].
    #[error("{0} modules, not 1 to 32")]
    Modules(usize),
    /// A pre-release version on the `stable` channel.
    #[error("a pre-release on the stable channel")]
    StablePrerelease,
    /// `capabilities` are missing.
    #[error("capabilities are missing")]
    NoCapabilities,
    /// `capabilities` are not a [`DeclaredCapabilities`].
    #[error("invalid capabilities")]
    Capabilities(#[source] CapabilitiesError),
    /// `capabilities` do not read by the rules of a plugin manifest's `[capabilities]`
    /// table (the reader given to [`super::CatalogBuilder::capabilities`]).
    #[error("capabilities do not read as a manifest's: {0}")]
    CapabilitiesUnreadable(String),
    /// `id` is not under the publisher's prefix.
    #[error("the id is outside the publisher's prefix")]
    IdOutsidePrefix,
    /// A module is not one the publisher was approved for.
    #[error("module {0} is not the publisher's")]
    ModuleNotAllowed(String),
    /// `replaces.symname` is not one the publisher was approved for.
    #[error("bundle {0} is not the publisher's")]
    BundleNotAllowed(String),
    /// The owner's index has a release of the same id: the owner's wins.
    #[error("the owner's index has the same id")]
    OwnerId,
    /// A release of the owner's index serves the module, and the publisher does not replace
    /// it: the owner's wins.
    #[error("the owner's index serves module {0}")]
    OwnerModule(String),
    /// A release of the owner's index stands for the bundle, and the publisher does not
    /// replace it: the owner's wins.
    #[error("the owner's index stands for bundle {0}")]
    OwnerBundle(String),
}

/// A publisher's target left out of the catalog, and why.
#[derive(Clone, Debug, thiserror::Error)]
#[error("publisher target {path} is left out")]
#[non_exhaustive]
pub struct EntryRejected {
    /// The target.
    pub path: TargetPath,
    /// Why.
    #[source]
    pub reason: EntryRejection,
}

/// A target path of a publisher's role: `plugins/<publisher>/<id>/<version>.onclp`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublisherTarget {
    /// The publisher.
    pub publisher: PublisherName,
    /// The plugin.
    pub id: PluginId,
    /// Its version.
    pub version: Version,
}

impl PublisherTarget {
    /// `path` read as a publisher's target; `None` for any other form.
    pub fn parse(path: &TargetPath) -> Option<PublisherTarget> {
        let mut segments = path.as_str().split('/');
        let (Some("plugins"), Some(publisher), Some(id), Some(file), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return None;
        };
        Some(PublisherTarget {
            publisher: PublisherName::parse(publisher).ok()?,
            id: PluginId::parse(id).ok()?,
            version: Version::parse(file.strip_suffix(".onclp")?).ok()?,
        })
    }
}

/// `custom.oncl` as signed; members this version does not know are skipped.
#[derive(Deserialize)]
struct RawRelease {
    id: String,
    version: Version,
    url: String,
    channel: Channel,
    min_core: Version,
    modules: Vec<String>,
    #[serde(default)]
    replaces: Option<PluginReplaces>,
    name: PluginName,
    #[serde(default)]
    capabilities: Option<Value>,
    #[serde(default)]
    source: Option<Value>,
    rollout: u8,
    #[serde(default)]
    revoked: bool,
}

/// A publisher's release as its role signs it: a [`PluginRelease`] with
/// [`PluginRelease::publisher`] and [`PluginRelease::capabilities`] set, the channel it is
/// published to and the source archive it was built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublisherRelease {
    channel: Channel,
    source: ReleaseSource,
    release: PluginRelease,
}

impl PublisherRelease {
    /// The `custom.oncl` format version read.
    pub const SCHEMA: u64 = 1;
    /// The most modules one release serves.
    pub const MAX_MODULES: usize = 32;

    /// Reads the target `path` of `publisher`'s role: the path names the publisher, id and
    /// version; `custom.oncl` the rest; the target's length and sha256 are the package's,
    /// and its `url` the copy of the package in the project's Releases ([`mirror_url`]).
    ///
    /// # Errors
    ///
    /// [`EntryRejection`] for a target that breaks a rule of its own.
    pub fn parse(
        publisher: &PublisherName,
        path: &TargetPath,
        target: &Target,
    ) -> Result<PublisherRelease, EntryRejection> {
        let place = PublisherTarget::parse(path)
            .filter(|place| place.publisher == *publisher)
            .ok_or(EntryRejection::Path)?;
        if !place.version.build.is_empty() {
            return Err(EntryRejection::BuildMetadata);
        }
        let entry = target
            .custom
            .as_ref()
            .and_then(|custom| custom.get("oncl"))
            .ok_or(EntryRejection::NoEntry)?;
        match entry.get("schema").and_then(Value::as_u64) {
            Some(PublisherRelease::SCHEMA) => {}
            Some(schema) => return Err(EntryRejection::Schema(schema)),
            None => {
                return Err(EntryRejection::Malformed(Arc::new(
                    <serde_json::Error as serde::de::Error>::missing_field("schema"),
                )));
            }
        }
        let raw =
            RawRelease::deserialize(entry).map_err(|e| EntryRejection::Malformed(Arc::new(e)))?;
        if raw.id != place.id.as_str() || raw.version != place.version {
            return Err(EntryRejection::PathMismatch);
        }
        if raw.url != mirror_url(publisher, &place.id, &place.version, &target.sha256) {
            return Err(EntryRejection::NotMirrored);
        }
        let source = ReleaseSource::parse(raw.source.as_ref()).map_err(EntryRejection::Source)?;
        if raw.rollout > 100 {
            return Err(EntryRejection::Rollout(raw.rollout));
        }
        if !(1..=PublisherRelease::MAX_MODULES).contains(&raw.modules.len()) {
            return Err(EntryRejection::Modules(raw.modules.len()));
        }
        if raw.channel == Channel::Stable && !raw.version.pre.is_empty() {
            return Err(EntryRejection::StablePrerelease);
        }
        let capabilities =
            DeclaredCapabilities::try_from(raw.capabilities.ok_or(EntryRejection::NoCapabilities)?)
                .map_err(EntryRejection::Capabilities)?;
        Ok(PublisherRelease {
            channel: raw.channel,
            source,
            release: PluginRelease {
                id: raw.id,
                version: raw.version,
                package: Package {
                    url: raw.url,
                    sha256: Sha256(target.sha256.0),
                    size: target.length,
                },
                min_core: raw.min_core,
                modules: raw.modules,
                replaces: raw.replaces,
                name: raw.name,
                rollout: raw.rollout,
                revoked: raw.revoked,
                publisher: Some(publisher.clone()),
                capabilities: Some(capabilities),
            },
        })
    }

    /// The channel the publisher chose: `stable` is offered on both channels, `beta` only on
    /// `beta`.
    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// The source archive the package was built from.
    pub fn source(&self) -> &ReleaseSource {
        &self.source
    }

    /// Whether a client of `channel` is offered the release.
    pub fn offered_on(&self, channel: Channel) -> bool {
        match self.channel {
            Channel::Stable => true,
            Channel::Beta => channel == Channel::Beta,
        }
    }

    /// The release.
    pub fn release(&self) -> &PluginRelease {
        &self.release
    }

    /// The release, owned.
    pub fn into_release(self) -> PluginRelease {
        self.release
    }

    /// Marks the release revoked: the owner revoked its version.
    pub(crate) fn revoke(&mut self) {
        self.release.revoked = true;
    }
}

#[cfg(test)]
mod tests {
    use super::is_github_repository;

    #[test]
    fn the_mirror_needs_a_github_repository_page() {
        assert!(is_github_repository(
            "https://github.com/arynyklas/OpenNCALayer"
        ));
        for bad in [
            "",
            "https://github.com/",
            "https://github.com/arynyklas/OpenNCALayer/",
            "https://github.com/arynyklas/OpenNCALayer.git",
            "https://gitlab.com/arynyklas/OpenNCALayer",
            "http://github.com/arynyklas/OpenNCALayer",
        ] {
            assert!(!is_github_repository(bad), "{bad}");
        }
    }
}
