//! `publishers.json`: the owner-signed rules of the third-party publishers (a target of the
//! top-level targets of `tuf/v1`). It names every publisher ever approved, active, retired,
//! revoked or of a state this version does not know, with the id prefix it owns, and for
//! all but a revoked one the modules and bundles it may serve, the ports it replaces and the
//! versions the owner revoked. The file is checked as a whole; a breach makes every
//! publisher unavailable, never revoked.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use semver::Version;
use serde::Deserialize;
use time::{Date, Month};

use super::names::{BundleName, IdPrefix, ModuleName, PROJECT_PREFIX, PluginId};
use super::release::plain_https_url;
use crate::tuf::{NameError, PublisherName, TargetPath};

/// The longest translation of a publisher's display name, in characters.
const MAX_DISPLAY: usize = 128;

/// Why `publishers.json` is not used: every publisher is unavailable while it holds.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogError {
    /// The file is larger than [`PublisherPolicy::MAX_LEN`].
    #[error("publishers.json is {len} bytes, more than {max}")]
    TooLarge {
        /// Its length.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// The file is not JSON of the expected shape.
    #[error("publishers.json is malformed")]
    Json(#[source] Arc<serde_json::Error>),
    /// The file has a `schema` this version does not read.
    #[error("publishers.json schema {0} is not supported")]
    Schema(u32),
    /// More publishers than [`PublisherPolicy::MAX_PUBLISHERS`].
    #[error("publishers.json lists {count} publishers, more than {max}")]
    TooMany {
        /// How many it lists.
        count: usize,
        /// The limit.
        max: usize,
    },
    /// More revoked versions, all publishers together, than
    /// [`PublisherPolicy::MAX_REVOKED_VERSIONS`].
    #[error("publishers.json lists {count} revoked versions, more than {max}")]
    TooManyRevoked {
        /// How many it lists.
        count: usize,
        /// The limit.
        max: usize,
    },
    /// A name, prefix, id, module or bundle breaks its grammar.
    #[error("publishers.json has an invalid name")]
    Name(#[from] NameError),
    /// A publisher is listed twice.
    #[error("publisher {0} is listed twice")]
    Duplicate(PublisherName),
    /// A publisher's prefix covers the project's ids or lies under them.
    #[error("the id prefix of publisher {0} overlaps the project's")]
    ProjectPrefix(PublisherName),
    /// Two publishers' prefixes lie one under the other.
    #[error("the id prefixes of publishers {0} and {1} overlap")]
    NestedPrefix(PublisherName, PublisherName),
    /// A module is listed twice, or by two publishers.
    #[error("module {module} is listed twice (publisher {publisher})")]
    SharedModule {
        /// The module.
        module: ModuleName,
        /// The publisher listing it a second time.
        publisher: PublisherName,
    },
    /// A bundle is listed twice, or by two publishers.
    #[error("bundle {bundle} is listed twice (publisher {publisher})")]
    SharedBundle {
        /// The bundle.
        bundle: BundleName,
        /// The publisher listing it a second time.
        publisher: PublisherName,
    },
    /// A module a publisher lists is served by a built-in module of the core.
    #[error("publisher {publisher} lists the built-in module {module}")]
    BuiltinModule {
        /// The publisher.
        publisher: PublisherName,
        /// The module.
        module: ModuleName,
    },
    /// A replaced port lies under a publisher's prefix, the replacement outside the
    /// replacing publisher's, or two publishers replace the same port.
    #[error("publisher {publisher} cannot replace {port} with {plugin}")]
    Supersedes {
        /// The publisher.
        publisher: PublisherName,
        /// The port it replaces.
        port: PluginId,
        /// Its plugin.
        plugin: PluginId,
    },
    /// The owner revoked a version outside the publisher's prefix.
    #[error("publisher {publisher} has a revoked version of {id}, outside its prefix")]
    RevokedVersion {
        /// The publisher.
        publisher: PublisherName,
        /// The plugin.
        id: PluginId,
    },
    /// A date is not `YYYY-MM-DD`.
    #[error("publisher {publisher} has an invalid date {value:?}")]
    Date {
        /// The publisher.
        publisher: PublisherName,
        /// The text.
        value: String,
    },
    /// An active publisher has no role in the delegations.
    #[error("active publisher {0} has no delegated role")]
    NotDelegated(PublisherName),
    /// The delegations have a role of a publisher the file does not name, or names revoked.
    #[error("the delegations have a role of {0}, which is unnamed or revoked")]
    NotActive(PublisherName),
    /// The top-level targets list a publisher's target (`plugins/…`): only publishers'
    /// roles may.
    #[error("the top-level targets list {0}, a publisher's target")]
    OwnerPluginTarget(TargetPath),
    /// A translation of a publisher's display name is empty, longer than 128 characters,
    /// has a control character or names the project.
    #[error("the display name of publisher {0} is not acceptable")]
    Display(PublisherName),
    /// A publisher's homepage is not a plain `https://` URL of at most 2048 bytes.
    #[error("the homepage of publisher {0} is not a plain https:// url")]
    Homepage(PublisherName),
}

/// A publisher's display name in each interface language.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct PublisherDisplay {
    /// Russian.
    pub ru: String,
    /// Kazakh.
    pub kk: String,
    /// English.
    pub en: String,
}

/// A version of a publisher's plugin the owner revoked: revoked whatever the publisher's
/// role says.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RevokedVersion {
    /// The plugin, under the publisher's prefix.
    pub id: PluginId,
    /// The version.
    pub version: Version,
    /// When the owner revoked it.
    pub date: Date,
}

/// What a publisher may publish while active, and the owner's rules that still hold once it
/// retires or takes a state this version does not know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivePublisher {
    modules: BTreeSet<ModuleName>,
    bundles: BTreeSet<BundleName>,
    supersedes: BTreeMap<PluginId, PluginId>,
    revoked_versions: Vec<RevokedVersion>,
    homepage: Option<String>,
}

impl ActivePublisher {
    /// The modules its plugins may serve.
    pub fn modules(&self) -> &BTreeSet<ModuleName> {
        &self.modules
    }

    /// The original bundles (`replaces.symname`) its plugins may stand for.
    pub fn bundles(&self) -> &BTreeSet<BundleName> {
        &self.bundles
    }

    /// The ports of the owner it replaces: port → its plugin, under its prefix.
    pub fn supersedes(&self) -> &BTreeMap<PluginId, PluginId> {
        &self.supersedes
    }

    /// The versions of its plugins the owner revoked.
    pub fn revoked_versions(&self) -> &[RevokedVersion] {
        &self.revoked_versions
    }

    /// Its web site.
    pub fn homepage(&self) -> Option<&str> {
        self.homepage.as_deref()
    }

    /// Whether the owner revoked `version` of `id`. Build metadata does not tell versions
    /// apart: revoking `1.1.0` revokes `1.1.0+anything`.
    pub fn revokes(&self, id: &str, version: &Version) -> bool {
        self.revoked_versions.iter().any(|r| {
            r.id.as_str() == id
                && (
                    r.version.major,
                    r.version.minor,
                    r.version.patch,
                    &r.version.pre,
                ) == (version.major, version.minor, version.patch, &version.pre)
        })
    }
}

/// Whether a publisher may publish.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Standing {
    /// It may, within these rules (if its role is also delegated and verified).
    Active(ActivePublisher),
    /// It no longer publishes: no new versions are offered, installed plugins keep working
    /// unless the owner revokes their versions. Its modules, bundles and prefix stay its own.
    Retired(ActivePublisher),
    /// The owner revoked it: its plugins are turned off. The entry stays so its prefix is
    /// never given to another publisher, and its plugins are still recognised by it.
    Revoked {
        /// When, if the file says.
        date: Option<Date>,
    },
    /// A `state` this version does not know: the publisher is unavailable, its installed
    /// plugins stay as they are unless the owner revoked their versions. Its rules are still
    /// read and checked, and what it owns stays its own. The rest of the file is used.
    Unknown {
        /// The value read, cut to 32 characters.
        state: String,
        /// Its rules, read as for an active publisher.
        rules: ActivePublisher,
    },
}

/// The most characters of an unknown `state` kept for the logs.
const MAX_STATE: usize = 32;

/// One publisher of `publishers.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publisher {
    name: PublisherName,
    display: PublisherDisplay,
    id_prefix: IdPrefix,
    standing: Standing,
}

impl Publisher {
    /// Its name, as in its role `pub-<name>`.
    pub fn name(&self) -> &PublisherName {
        &self.name
    }

    /// Its name shown to users.
    pub fn display(&self) -> &PublisherDisplay {
        &self.display
    }

    /// The prefix of its plugins' ids.
    pub fn id_prefix(&self) -> &IdPrefix {
        &self.id_prefix
    }

    /// Whether it is active, retired, revoked or of an unknown state.
    pub fn standing(&self) -> &Standing {
        &self.standing
    }

    /// Its rules, if it is active.
    pub fn active(&self) -> Option<&ActivePublisher> {
        match &self.standing {
            Standing::Active(active) => Some(active),
            _ => None,
        }
    }

    /// Its rules, unless it is revoked: what it owns and which versions the owner revoked.
    pub fn rules(&self) -> Option<&ActivePublisher> {
        match &self.standing {
            Standing::Active(rules)
            | Standing::Retired(rules)
            | Standing::Unknown { rules, .. } => Some(rules),
            Standing::Revoked { .. } => None,
        }
    }
}

/// `publishers.json`, checked as a whole: the prefixes neither nest nor touch the
/// project's, no module or bundle belongs to two publishers, every replacement and revoked
/// version lies under its publisher's prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublisherPolicy {
    publishers: Vec<Publisher>,
}

impl PublisherPolicy {
    /// The format version read.
    pub const SCHEMA: u32 = 1;
    /// The largest file, in bytes; also the most the caller downloads.
    pub const MAX_LEN: usize = 1024 * 1024;
    /// The most publishers, revoked ones included.
    pub const MAX_PUBLISHERS: usize = 128;
    /// The most revoked versions, all publishers together.
    pub const MAX_REVOKED_VERSIONS: usize = 8000;

    /// Reads `publishers.json`. Members this version does not know are skipped.
    ///
    /// # Errors
    ///
    /// [`CatalogError`] for a file too large, malformed, of another schema, or that breaks
    /// a rule of the whole.
    pub fn from_json(bytes: &[u8]) -> Result<PublisherPolicy, CatalogError> {
        #[derive(Deserialize)]
        struct Probe {
            schema: u32,
        }
        if bytes.len() > PublisherPolicy::MAX_LEN {
            return Err(CatalogError::TooLarge {
                len: bytes.len(),
                max: PublisherPolicy::MAX_LEN,
            });
        }
        let json = |e| CatalogError::Json(Arc::new(e));
        let probe: Probe = serde_json::from_slice(bytes).map_err(json)?;
        if probe.schema != PublisherPolicy::SCHEMA {
            return Err(CatalogError::Schema(probe.schema));
        }
        let raw: RawPolicy = serde_json::from_slice(bytes).map_err(json)?;
        PublisherPolicy::try_from(raw)
    }

    /// Every publisher, in the order of the file.
    pub fn publishers(&self) -> &[Publisher] {
        &self.publishers
    }

    /// The publisher `name`.
    pub fn publisher(&self, name: &PublisherName) -> Option<&Publisher> {
        self.publishers.iter().find(|p| p.name == *name)
    }

    /// The publisher whose prefix covers `id`, whatever its standing.
    pub fn covering(&self, id: &str) -> Option<&Publisher> {
        self.publishers.iter().find(|p| p.id_prefix.covers(id))
    }

    /// The active publisher replacing the port `port`, and its plugin.
    pub fn superseding(&self, port: &str) -> Option<(&Publisher, &PluginId)> {
        self.publishers.iter().find_map(|p| {
            p.active()
                .and_then(|active| active.supersedes.get(port))
                .map(|plugin| (p, plugin))
        })
    }

    /// Checks no active or retired publisher lists a module of `builtin`.
    pub(crate) fn check_builtin(&self, builtin: &BTreeSet<String>) -> Result<(), CatalogError> {
        for publisher in &self.publishers {
            let Some(active) = publisher.rules() else {
                continue;
            };
            if let Some(module) = active
                .modules
                .iter()
                .find(|m| builtin.iter().any(|b| b.eq_ignore_ascii_case(m.as_str())))
            {
                return Err(CatalogError::BuiltinModule {
                    publisher: publisher.name.clone(),
                    module: module.clone(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RawPolicy {
    publishers: Vec<RawPublisher>,
}

#[derive(Deserialize)]
struct RawPublisher {
    name: String,
    /// `active`, `retired`, `revoked`; any other value makes this publisher alone
    /// unavailable.
    state: String,
    display: PublisherDisplay,
    id_prefix: String,
    #[serde(default)]
    modules: Vec<String>,
    #[serde(default)]
    bundles: Vec<String>,
    #[serde(default)]
    supersedes: BTreeMap<String, String>,
    #[serde(default)]
    revoked_versions: Vec<RawRevokedVersion>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    revoked: Option<String>,
}

#[derive(Deserialize)]
struct RawRevokedVersion {
    id: String,
    version: Version,
    date: String,
}

/// `YYYY-MM-DD`.
fn parse_date(publisher: &PublisherName, text: &str) -> Result<Date, CatalogError> {
    let invalid = || CatalogError::Date {
        publisher: publisher.clone(),
        value: text.to_owned(),
    };
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(invalid());
    }
    let number = |range: std::ops::Range<usize>| {
        text.get(range)
            .filter(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u16>().ok())
    };
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return Err(invalid());
    };
    let month = u8::try_from(month)
        .ok()
        .and_then(|m| Month::try_from(m).ok())
        .ok_or_else(invalid)?;
    let day = u8::try_from(day).map_err(|_| invalid())?;
    Date::from_calendar_date(i32::from(year), month, day).map_err(|_| invalid())
}

impl RawPublisher {
    fn check(self) -> Result<Publisher, CatalogError> {
        let name = PublisherName::parse(&self.name)?;
        let display = &self.display;
        let acceptable = |text: &str| {
            (1..=MAX_DISPLAY).contains(&text.chars().count())
                && !text.trim().is_empty()
                && !text.chars().any(char::is_control)
                && !text.to_lowercase().contains("openncalayer")
        };
        if ![&display.ru, &display.kk, &display.en]
            .into_iter()
            .all(|text| acceptable(text))
        {
            return Err(CatalogError::Display(name));
        }
        if self
            .homepage
            .as_deref()
            .is_some_and(|url| !plain_https_url(url))
        {
            return Err(CatalogError::Homepage(name));
        }
        let id_prefix = IdPrefix::parse(&self.id_prefix)?;
        if id_prefix.overlaps(PROJECT_PREFIX) {
            return Err(CatalogError::ProjectPrefix(name));
        }
        let standing = match self.state.as_str() {
            "revoked" => Standing::Revoked {
                date: self
                    .revoked
                    .as_deref()
                    .map(|date| parse_date(&name, date))
                    .transpose()?,
            },
            state => {
                let mut modules = BTreeSet::new();
                for module in &self.modules {
                    let module = ModuleName::parse(module)?;
                    if !modules.insert(module.clone()) {
                        return Err(CatalogError::SharedModule {
                            module,
                            publisher: name,
                        });
                    }
                }
                let mut bundles = BTreeSet::new();
                for bundle in &self.bundles {
                    let bundle = BundleName::parse(bundle)?;
                    if !bundles.insert(bundle.clone()) {
                        return Err(CatalogError::SharedBundle {
                            bundle,
                            publisher: name,
                        });
                    }
                }
                let mut supersedes = BTreeMap::new();
                for (port, plugin) in &self.supersedes {
                    let port = PluginId::parse(port)?;
                    let plugin = PluginId::parse(plugin)?;
                    if !id_prefix.covers(plugin.as_str()) {
                        return Err(CatalogError::Supersedes {
                            publisher: name,
                            port,
                            plugin,
                        });
                    }
                    supersedes.insert(port, plugin);
                }
                let mut revoked_versions = Vec::with_capacity(self.revoked_versions.len());
                for revoked in &self.revoked_versions {
                    let id = PluginId::parse(&revoked.id)?;
                    if !id_prefix.covers(id.as_str()) {
                        return Err(CatalogError::RevokedVersion {
                            publisher: name,
                            id,
                        });
                    }
                    revoked_versions.push(RevokedVersion {
                        id,
                        version: revoked.version.clone(),
                        date: parse_date(&name, &revoked.date)?,
                    });
                }
                let rules = ActivePublisher {
                    modules,
                    bundles,
                    supersedes,
                    revoked_versions,
                    homepage: self.homepage,
                };
                match state {
                    "active" => Standing::Active(rules),
                    "retired" => Standing::Retired(rules),
                    other => Standing::Unknown {
                        state: other.chars().take(MAX_STATE).collect(),
                        rules,
                    },
                }
            }
        };
        Ok(Publisher {
            name,
            display: self.display,
            id_prefix,
            standing,
        })
    }
}

impl TryFrom<RawPolicy> for PublisherPolicy {
    type Error = CatalogError;

    fn try_from(raw: RawPolicy) -> Result<PublisherPolicy, CatalogError> {
        if raw.publishers.len() > PublisherPolicy::MAX_PUBLISHERS {
            return Err(CatalogError::TooMany {
                count: raw.publishers.len(),
                max: PublisherPolicy::MAX_PUBLISHERS,
            });
        }
        let revoked = raw
            .publishers
            .iter()
            .map(|p| p.revoked_versions.len())
            .sum::<usize>();
        if revoked > PublisherPolicy::MAX_REVOKED_VERSIONS {
            return Err(CatalogError::TooManyRevoked {
                count: revoked,
                max: PublisherPolicy::MAX_REVOKED_VERSIONS,
            });
        }
        let publishers = raw
            .publishers
            .into_iter()
            .map(RawPublisher::check)
            .collect::<Result<Vec<_>, _>>()?;
        // Names differing only in ASCII case count as the same: the registries match them
        // exactly, but one publisher's name in another's case is too close to give out.
        let mut modules = BTreeSet::new();
        let mut bundles = BTreeSet::new();
        let mut ports = BTreeSet::new();
        for (index, publisher) in publishers.iter().enumerate() {
            for earlier in &publishers[..index] {
                if earlier.name == publisher.name {
                    return Err(CatalogError::Duplicate(publisher.name.clone()));
                }
                if earlier.id_prefix.overlaps(publisher.id_prefix.as_str()) {
                    return Err(CatalogError::NestedPrefix(
                        earlier.name.clone(),
                        publisher.name.clone(),
                    ));
                }
            }
            let Some(active) = publisher.rules() else {
                continue;
            };
            if let Some(module) = active
                .modules
                .iter()
                .find(|m| !modules.insert(m.as_str().to_ascii_lowercase()))
            {
                return Err(CatalogError::SharedModule {
                    module: module.clone(),
                    publisher: publisher.name.clone(),
                });
            }
            if let Some(bundle) = active
                .bundles
                .iter()
                .find(|b| !bundles.insert(b.as_str().to_ascii_lowercase()))
            {
                return Err(CatalogError::SharedBundle {
                    bundle: bundle.clone(),
                    publisher: publisher.name.clone(),
                });
            }
            for (port, plugin) in &active.supersedes {
                let covered = publishers.iter().any(|p| p.id_prefix.covers(port.as_str()));
                if covered || !ports.insert(port) {
                    return Err(CatalogError::Supersedes {
                        publisher: publisher.name.clone(),
                        port: port.clone(),
                        plugin: plugin.clone(),
                    });
                }
            }
        }
        Ok(PublisherPolicy { publishers })
    }
}
