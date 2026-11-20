//! The plugin catalog of a channel: the owner's index plus the releases of third-party
//! publishers (`docs/design/publishers.md`, «Каталог»).
//!
//! A [`Catalog`] is built from the owner's [`Index`], the top-level targets,
//! `publishers.json` read into a [`PublisherPolicy`] and the delegated roles of the
//! publishers. The owner's word wins:
//!
//! 1. a version the owner revoked in `publishers.json` is revoked whatever the publisher's
//!    role says;
//! 2. a publisher's release with an id of the owner's index is left out;
//! 3. a publisher's release serving a module or standing for a bundle of a release of the
//!    owner's index is left out, unless the publisher replaces that port (`supersedes`);
//! 4. a publisher's release outside its prefix, modules or bundles is left out.
//!
//! A publisher's target (`plugins/…`) in the top-level targets makes every publisher
//! unavailable: the owner's tools never write one.
//!
//! Each publisher is [`PublisherState::Active`], [`PublisherState::Retired`] (it publishes no
//! more: no new versions, installed ones stay unless revoked),
//! [`PublisherState::Unavailable`] (its role, `publishers.json` or the delegations did not
//! hold up, its `state` is unknown to this version, or `publishers.json` does not name it:
//! its plugins are not updated and stay installed, except versions revoked by the owner in
//! `publishers.json` or by a role still verified) or [`PublisherState::Revoked`] (the
//! verified `publishers.json` says so). An error or a missing entry never revokes a
//! publisher.
//!
//! A catalog of the owner's index alone ([`Catalog::owner`]) behaves as the index did:
//! every publisher is unavailable and only the index's releases are offered.

mod names;
mod policy;
mod release;
mod source;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use tracing::warn;

pub use names::{BundleName, IdPrefix, ModuleName, PROJECT_PREFIX, PluginId};
pub use policy::{
    ActivePublisher, CatalogError, Publisher, PublisherDisplay, PublisherPolicy, RevokedVersion,
    Standing,
};
pub use release::{
    CapabilitiesError, DeclaredCapabilities, EntryRejected, EntryRejection, MAX_URL, MIRROR_BASE,
    PublisherRelease, PublisherTarget, SourceArchive, mirror_url,
};
pub use source::{ReleaseSource, SourceError, SourceVcs};

use crate::index::Index;
use crate::plugins::{PluginRelease, offerable};
use crate::tuf::{Delegated, PublisherName, RoleName, Target, TargetPath};

/// What the catalog knows of a publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PublisherState {
    /// Its role was verified; its releases are in the catalog.
    Active,
    /// It publishes no more: none of its releases is offered, its installed plugins stay
    /// unless their versions are revoked ([`Catalog::is_revoked`]).
    Retired,
    /// Its role, `publishers.json` or the delegations did not hold up, its `state` is
    /// unknown to this version, or `publishers.json` does not name it: its installed plugins
    /// stay as they are until they do, unless their versions are revoked.
    Unavailable,
    /// The verified `publishers.json` names it revoked: its plugins are turned off.
    Revoked,
}

/// The plugin catalog of a channel: the owner's index and the publishers' releases.
#[derive(Debug)]
pub struct Catalog {
    index: Index,
    /// `None`: `publishers.json` is unknown (a catalog of the owner's index alone) or was not
    /// used; every publisher is unavailable.
    policy: Option<PublisherPolicy>,
    /// The state of every publisher of `policy`.
    states: BTreeMap<PublisherName, PublisherState>,
    /// The releases of the active publishers offered on the index's channel.
    releases: Vec<PluginRelease>,
    /// The source archives of `releases`, by package URL (unique: it names the package's
    /// sha256).
    sources: BTreeMap<String, SourceArchive>,
    /// The versions (build metadata cleared) the publishers' verified roles revoke, by
    /// publisher and id, on every channel, whatever their publisher's state: read by the
    /// target path alone.
    self_revoked: BTreeMap<PublisherName, BTreeMap<String, BTreeSet<Version>>>,
    rejected: Vec<EntryRejected>,
}

/// The publishers' side of a [`Catalog`] being built ([`Catalog::builder`]).
#[derive(Debug)]
#[must_use = "a builder does nothing until built"]
pub struct CatalogBuilder<'r> {
    index: Index,
    policy: Result<PublisherPolicy, CatalogError>,
    /// A publisher's target the top-level targets list, if any.
    owner_plugin: Option<TargetPath>,
    builtin_modules: BTreeSet<String>,
    /// The delegated roles, in order, each name once: its targets if it was verified.
    roles: Vec<(PublisherName, Option<&'r BTreeMap<TargetPath, Target>>)>,
    /// The delegations could not be read ([`CatalogBuilder::delegations_unavailable`]).
    delegations_unavailable: bool,
    capabilities: Option<CapabilitiesReader<'r>>,
}

/// How a publisher's declared capabilities are read ([`CatalogBuilder::capabilities`]).
type ReadCapabilities<'r> = dyn Fn(&DeclaredCapabilities) -> Result<(), String> + 'r;

/// What reads a publisher's declared capabilities by the rules of a plugin manifest
/// ([`CatalogBuilder::capabilities`]).
struct CapabilitiesReader<'r>(Box<ReadCapabilities<'r>>);

impl std::fmt::Debug for CapabilitiesReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapabilitiesReader")
    }
}

impl Catalog {
    /// The catalog of the owner's index alone, as before publishers: every publisher is
    /// unavailable.
    pub fn owner(index: Index) -> Catalog {
        Catalog {
            index,
            policy: None,
            states: BTreeMap::new(),
            releases: Vec::new(),
            sources: BTreeMap::new(),
            self_revoked: BTreeMap::new(),
            rejected: Vec::new(),
        }
    }

    /// Starts a catalog of `index`, the verified top-level targets `top_level` and
    /// `publishers.json` read as `policy`. An `Err`, or a publisher's target (`plugins/…`)
    /// among `top_level`, makes every publisher unavailable.
    pub fn builder<'r>(
        index: Index,
        top_level: &BTreeMap<TargetPath, Target>,
        policy: Result<PublisherPolicy, CatalogError>,
    ) -> CatalogBuilder<'r> {
        CatalogBuilder {
            index,
            policy,
            owner_plugin: top_level
                .keys()
                .find(|path| path.as_str().starts_with("plugins/"))
                .cloned(),
            builtin_modules: BTreeSet::new(),
            roles: Vec::new(),
            delegations_unavailable: false,
            capabilities: None,
        }
    }

    /// The owner's index.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// `publishers.json`, if it is used.
    pub fn policy(&self) -> Option<&PublisherPolicy> {
        self.policy.as_ref()
    }

    /// Every release: the owner's index's, then the active publishers' offered on its
    /// channel. A port another publisher replaces is among them ([`Catalog::replacement`]).
    pub fn releases(&self) -> impl Iterator<Item = &PluginRelease> {
        self.index.plugins.iter().chain(&self.releases)
    }

    /// The source archive `release` of this catalog was built from, as the windows link it:
    /// `None` for a release of the owner's index or one this catalog does not offer.
    pub fn source_archive(&self, release: &PluginRelease) -> Option<&SourceArchive> {
        release.publisher.as_ref()?;
        self.sources.get(&release.package.url)
    }

    /// The publishers' targets left out, and why.
    pub fn rejected(&self) -> &[EntryRejected] {
        &self.rejected
    }

    /// The state of `publisher`; unavailable if `publishers.json` is not used or does not
    /// name it.
    pub fn publisher_state(&self, publisher: &PublisherName) -> PublisherState {
        self.states
            .get(publisher)
            .copied()
            .unwrap_or(PublisherState::Unavailable)
    }

    /// The publisher of the plugin `id`, by the prefixes of `publishers.json` (revoked
    /// publishers included); `None` for a plugin of the owner's index, or while
    /// `publishers.json` is not used.
    pub fn publisher_of(&self, id: &str) -> Option<&PublisherName> {
        if self.index.plugins.iter().any(|r| r.id == id) {
            return None;
        }
        Some(self.policy.as_ref()?.covering(id)?.name())
    }

    /// The publisher of the installed plugin `id` and its state. Its publishers are
    /// `recorded`, the one recorded when it was installed, and [`Catalog::publisher_of`],
    /// the one whose prefix covers `id`; they are the same one unless the record or
    /// `publishers.json` is wrong, and then the stricter state of the two holds (revoked,
    /// then unavailable, then retired, then active; the recorded one when as strict). A
    /// recorded publisher `publishers.json` does not name is unavailable, not revoked.
    /// `None` for a port of the owner's index, or a plugin no publisher's prefix covers,
    /// without a recorded publisher.
    pub fn publisher_state_of<'a>(
        &'a self,
        id: &str,
        recorded: Option<&'a PublisherName>,
    ) -> Option<(&'a PublisherName, PublisherState)> {
        recorded
            .into_iter()
            .chain(self.publisher_of(id))
            .map(|publisher| (publisher, self.publisher_state(publisher)))
            .reduce(|first, other| {
                if strictness(other.1) > strictness(first.1) {
                    other
                } else {
                    first
                }
            })
    }

    /// Whether `version` of `id` is revoked: by its release in the catalog, by the owner in
    /// `publishers.json`, or by a verified role of its publisher on any channel (build
    /// metadata aside, listed in the catalog or not). The publisher's revocations hold while
    /// it is active, retired or unavailable; they need `publishers.json`. The publisher is
    /// found by the prefixes of `publishers.json` ([`Catalog::is_installed_revoked`] also
    /// takes the one recorded).
    pub fn is_revoked(&self, id: &str, version: &Version) -> bool {
        self.is_revoked_for(id, version, self.publisher_of(id))
    }

    /// [`Catalog::is_revoked`] of the installed `id`: revoked for the publisher whose prefix
    /// covers it or for the publisher `recorded` when it was installed, if there is one
    /// ([`Catalog::publisher_state_of`]).
    pub fn is_installed_revoked(
        &self,
        id: &str,
        version: &Version,
        recorded: Option<&PublisherName>,
    ) -> bool {
        let covering = self.publisher_of(id);
        self.is_revoked_for(id, version, covering)
            || recorded.is_some_and(|recorded| {
                covering != Some(recorded) && self.is_revoked_for(id, version, Some(recorded))
            })
    }

    /// [`Catalog::is_revoked`] for a plugin of `publisher`: its owner's revocations and its
    /// own, unless it is revoked.
    fn is_revoked_for(
        &self,
        id: &str,
        version: &Version,
        publisher: Option<&PublisherName>,
    ) -> bool {
        self.releases()
            .any(|r| r.id == id && r.version == *version && r.revoked)
            || publisher.is_some_and(|publisher| {
                self.publisher_state(publisher) != PublisherState::Revoked
                    && (self
                        .policy
                        .as_ref()
                        .and_then(|policy| policy.publisher(publisher))
                        .and_then(Publisher::rules)
                        .is_some_and(|rules| rules.revokes(id, version))
                        || self
                            .self_revoked
                            .get(publisher)
                            .and_then(|ids| ids.get(id))
                            .is_some_and(|versions| {
                                if version.build.is_empty() {
                                    versions.contains(version)
                                } else {
                                    versions.contains(&without_build(version))
                                }
                            }))
            })
    }

    /// The release replacing the port `port`, if an active publisher replaces it
    /// (`supersedes`) and offers this installation a version of its plugin: the newest one
    /// compatible with `core`, not revoked, not `bad`, rolled out to `install_id`, serving
    /// every module and standing for every bundle of the port's releases in the owner's
    /// index. Until then the port stays as it is.
    pub fn replacement(
        &self,
        port: &str,
        core: &Version,
        install_id: &[u8; 16],
        bad: &BTreeMap<String, BTreeSet<Version>>,
    ) -> Option<&PluginRelease> {
        let (publisher, plugin) = self.policy.as_ref()?.superseding(port)?;
        if self.publisher_state(publisher.name()) != PublisherState::Active {
            return None;
        }
        let ports = || self.index.plugins.iter().filter(|r| r.id == port);
        let covers = |r: &PluginRelease| {
            ports().all(|p| {
                p.modules.iter().all(|m| r.modules.contains(m))
                    && p.replaces.as_ref().is_none_or(|bundle| {
                        r.replaces
                            .as_ref()
                            .is_some_and(|own| own.symname == bundle.symname)
                    })
            })
        };
        self.releases
            .iter()
            .filter(|r| r.id == plugin.as_str() && offerable(r, core, install_id, bad) && covers(r))
            .max_by(|a, b| a.version.cmp(&b.version))
    }
}

impl<'r> CatalogBuilder<'r> {
    /// The modules the core serves itself: a `publishers.json` that gives one to a
    /// publisher is not used.
    pub fn builtin_modules(mut self, modules: impl IntoIterator<Item = String>) -> Self {
        self.builtin_modules.extend(modules);
        self
    }

    /// How a publisher's declared capabilities are read (for the core, as a manifest's
    /// `[capabilities]` table): a release whose capabilities `read` refuses is left out
    /// ([`EntryRejection::CapabilitiesUnreadable`]). Without one they are taken as signed.
    pub fn capabilities(
        mut self,
        read: impl Fn(&DeclaredCapabilities) -> Result<(), String> + 'r,
    ) -> Self {
        self.capabilities = Some(CapabilitiesReader(Box::new(read)));
        self
    }

    /// The verified role `role` and its targets.
    pub fn role(mut self, role: &RoleName, targets: &'r BTreeMap<TargetPath, Target>) -> Self {
        self.add(role, Some(targets));
        self
    }

    /// The role `role`, delegated but not verified: its publisher is unavailable.
    pub fn unavailable_role(mut self, role: &RoleName) -> Self {
        self.add(role, None);
        self
    }

    /// Every role of the delegated step ([`crate::tuf::TufClient::delegated`]).
    pub fn delegated(mut self, delegated: &'r Delegated) -> Self {
        for (name, role) in delegated.roles() {
            self.add(name, role.ok().map(|role| role.targets()));
        }
        self
    }

    fn add(&mut self, role: &RoleName, targets: Option<&'r BTreeMap<TargetPath, Target>>) {
        let publisher = role.publisher();
        if !self.roles.iter().any(|(name, _)| *name == publisher) {
            self.roles.push((publisher, targets));
        }
    }

    /// The delegations of the top-level targets could not be read (or their step failed as
    /// a whole): every publisher with a role is unavailable, as with an unverified role, and
    /// the roles given are not used. The owner's revocations in `publishers.json` still hold.
    pub fn delegations_unavailable(mut self) -> Self {
        self.delegations_unavailable = true;
        self
    }

    /// The catalog. A publisher's target among the top-level targets, or a
    /// `publishers.json` that gives a publisher a built-in module, names a publisher active
    /// without a delegated role, or does not name (or names revoked) the publisher of a
    /// delegated role, is not used: every publisher is unavailable. Unless the delegations
    /// are unavailable, active publishers' targets are offered. Of every verified role,
    /// whatever its publisher's state, the versions it revokes are read by their target path
    /// alone, on every channel, so they stay withdrawn even when the rest of the target no
    /// longer holds. Each target left out of an active role is logged once.
    pub fn build(self) -> Catalog {
        let CatalogBuilder {
            index,
            policy,
            owner_plugin,
            builtin_modules,
            mut roles,
            delegations_unavailable,
            capabilities,
        } = self;
        if delegations_unavailable {
            roles.clear();
        }
        let policy = policy.and_then(|policy| {
            if let Some(path) = owner_plugin {
                return Err(CatalogError::OwnerPluginTarget(path));
            }
            policy.check_builtin(&builtin_modules)?;
            if !delegations_unavailable {
                check_delegations(&policy, &roles)?;
            }
            Ok(policy)
        });
        let policy = match policy {
            Ok(policy) => policy,
            Err(error) => {
                warn!(error = ?error, "the publishers' catalog is unavailable");
                return Catalog::owner(index);
            }
        };
        let mut states = BTreeMap::new();
        let mut releases = Vec::new();
        let mut sources = BTreeMap::new();
        let mut self_revoked =
            BTreeMap::<PublisherName, BTreeMap<String, BTreeSet<Version>>>::new();
        let mut rejected = Vec::new();
        let owner = Owner::of(&index);
        for publisher in policy.publishers() {
            let name = publisher.name();
            let targets = roles
                .iter()
                .find(|(role, _)| role == name)
                .and_then(|(_, targets)| *targets);
            let (rules, state) = match publisher.standing() {
                Standing::Active(rules) => (rules, PublisherState::Active),
                Standing::Retired(rules) => (rules, PublisherState::Retired),
                Standing::Unknown { state, rules } => {
                    warn!(publisher = %name, state = ?state, "a publisher of an unknown state is unavailable");
                    (rules, PublisherState::Unavailable)
                }
                Standing::Revoked { .. } => {
                    states.insert(name.clone(), PublisherState::Revoked);
                    continue;
                }
            };
            let Some(targets) = targets else {
                let state = match state {
                    PublisherState::Active => PublisherState::Unavailable,
                    other => other,
                };
                states.insert(name.clone(), state);
                continue;
            };
            states.insert(name.clone(), state);
            for (id, version) in self_revocations(publisher, targets) {
                self_revoked
                    .entry(name.clone())
                    .or_default()
                    .entry(id)
                    .or_default()
                    .insert(version);
            }
            if state != PublisherState::Active {
                continue;
            }
            for (path, target) in targets {
                let admitted = admit(publisher, rules, &owner, path, target).and_then(|release| {
                    match (&capabilities, &release.release().capabilities) {
                        (Some(CapabilitiesReader(read)), Some(declared)) => read(declared)
                            .map_err(EntryRejection::CapabilitiesUnreadable)
                            .map(|()| release),
                        _ => Ok(release),
                    }
                });
                match admitted {
                    Ok(release) if release.offered_on(index.channel) => {
                        if let Some(archive) =
                            SourceArchive::of(release.release(), release.source())
                        {
                            sources.insert(release.release().package.url.clone(), archive);
                        }
                        releases.push(release.into_release());
                    }
                    Ok(_) => {}
                    Err(reason) => {
                        warn!(publisher = %name, path = %path, reason = %reason, "a publisher's target is left out of the catalog");
                        rejected.push(EntryRejected {
                            path: path.clone(),
                            reason,
                        });
                    }
                }
            }
        }
        Catalog {
            index,
            policy: Some(policy),
            states,
            releases,
            sources,
            self_revoked,
            rejected,
        }
    }
}

/// How strict `state` is with an installed plugin: revoked turns it off, unavailable and
/// retired keep it unless revoked (unavailable first: nothing about it held up), active
/// updates it.
fn strictness(state: PublisherState) -> u8 {
    match state {
        PublisherState::Active => 0,
        PublisherState::Retired => 1,
        PublisherState::Unavailable => 2,
        PublisherState::Revoked => 3,
    }
}

/// `version` without build metadata: revocations do not tell versions apart by it.
fn without_build(version: &Version) -> Version {
    Version {
        build: semver::BuildMetadata::EMPTY,
        ..version.clone()
    }
}

/// The versions `publisher`'s verified role revokes (`custom.oncl.revoked` is `true`),
/// read from the target path alone: a path of its role, an id under its prefix. Nothing
/// else of the target has to hold, so a revocation survives a rule the target no longer
/// meets (a module the owner since took back, a newer schema).
fn self_revocations<'t>(
    publisher: &'t Publisher,
    targets: &'t BTreeMap<TargetPath, Target>,
) -> impl Iterator<Item = (String, Version)> + 't {
    targets.iter().filter_map(move |(path, target)| {
        let revoked = target
            .custom
            .as_ref()
            .and_then(|custom| custom.get("oncl"))
            .and_then(|oncl| oncl.get("revoked"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let place = PublisherTarget::parse(path)?;
        (revoked
            && place.publisher == *publisher.name()
            && publisher.id_prefix().covers(place.id.as_str()))
        .then(|| (place.id.as_str().to_owned(), without_build(&place.version)))
    })
}

/// The active publishers are exactly those with a delegated role; a retired publisher or one
/// of an unknown state may keep its role or not, a revoked or unnamed one has none.
fn check_delegations(
    policy: &PublisherPolicy,
    roles: &[(PublisherName, Option<&BTreeMap<TargetPath, Target>>)],
) -> Result<(), CatalogError> {
    if let Some((name, _)) = roles.iter().find(|(name, _)| {
        policy
            .publisher(name)
            .is_none_or(|p| matches!(p.standing(), Standing::Revoked { .. }))
    }) {
        return Err(CatalogError::NotActive(name.clone()));
    }
    if let Some(publisher) = policy
        .publishers()
        .iter()
        .find(|p| p.active().is_some() && !roles.iter().any(|(name, _)| name == p.name()))
    {
        return Err(CatalogError::NotDelegated(publisher.name().clone()));
    }
    Ok(())
}

/// What the owner's index claims: ids, and the ids serving each module and bundle. Module
/// and bundle names are keyed in ASCII lowercase: the registries match them exactly, but a
/// name differing only in case is still too close to the owner's to give to a publisher.
struct Owner<'i> {
    ids: BTreeSet<&'i str>,
    modules: BTreeMap<String, BTreeSet<&'i str>>,
    bundles: BTreeMap<String, BTreeSet<&'i str>>,
}

impl<'i> Owner<'i> {
    fn of(index: &'i Index) -> Owner<'i> {
        let mut owner = Owner {
            ids: BTreeSet::new(),
            modules: BTreeMap::new(),
            bundles: BTreeMap::new(),
        };
        for release in &index.plugins {
            let id = release.id.as_str();
            owner.ids.insert(id);
            for module in &release.modules {
                owner
                    .modules
                    .entry(module.to_ascii_lowercase())
                    .or_default()
                    .insert(id);
            }
            if let Some(replaces) = &release.replaces {
                owner
                    .bundles
                    .entry(replaces.symname.to_ascii_lowercase())
                    .or_default()
                    .insert(id);
            }
        }
        owner
    }
}

/// `path` of `publisher`'s verified role, checked against its rules and the owner's index;
/// revoked if the owner revoked the version.
fn admit(
    publisher: &Publisher,
    active: &ActivePublisher,
    owner: &Owner<'_>,
    path: &TargetPath,
    target: &Target,
) -> Result<PublisherRelease, EntryRejection> {
    let mut release = PublisherRelease::parse(publisher.name(), path, target)?;
    let id = release.release().id.as_str();
    if !publisher.id_prefix().covers(id) {
        return Err(EntryRejection::IdOutsidePrefix);
    }
    let modules = &release.release().modules;
    if let Some(module) = modules
        .iter()
        .find(|m| !active.modules().contains(m.as_str()))
    {
        return Err(EntryRejection::ModuleNotAllowed(module.clone()));
    }
    let bundle = release.release().replaces.as_ref().map(|r| &r.symname);
    if let Some(symname) = bundle.filter(|s| !active.bundles().contains(s.as_str())) {
        return Err(EntryRejection::BundleNotAllowed(symname.clone()));
    }
    if owner.ids.contains(id) {
        return Err(EntryRejection::OwnerId);
    }
    // A port the publisher replaces with this very plugin may share its modules and bundle.
    let replaced = |ports: &BTreeSet<&str>| {
        ports.iter().all(|port| {
            active
                .supersedes()
                .get(*port)
                .is_some_and(|plugin| plugin.as_str() == id)
        })
    };
    if let Some(module) = modules.iter().find(|m| {
        owner
            .modules
            .get(&m.to_ascii_lowercase())
            .is_some_and(|p| !replaced(p))
    }) {
        return Err(EntryRejection::OwnerModule(module.clone()));
    }
    if let Some(symname) = bundle.filter(|s| {
        owner
            .bundles
            .get(&s.to_ascii_lowercase())
            .is_some_and(|p| !replaced(p))
    }) {
        return Err(EntryRejection::OwnerBundle(symname.clone()));
    }
    if active.revokes(id, &release.release().version) {
        release.revoke();
    }
    Ok(release)
}
