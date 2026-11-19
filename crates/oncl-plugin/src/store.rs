//! `<data>/plugins/`: the installed plugins and what is kept about them between runs.
//!
//! - `state.json` ([`StoreState`]): the installed plugins, the versions that failed here, the
//!   install id of the rollouts and the highest `seq` of each catalog accepted;
//! - `packages/<id>-<version>.onclp`: the package of each installed plugin, as downloaded or
//!   chosen;
//! - `catalog/<channel>.json`: the last update index of the channel accepted, checked again
//!   whenever it is read, against the targets metadata of the TUF state ([`Store::load_catalog`]);
//! - `catalog/publishers.json` and `catalog/roles/pub-<publisher>.json`: the publishers'
//!   rules and each publisher's delegated role as last verified, kept beside the index and
//!   checked again offline the same way ([`Store::load_publishers`], [`Store::load_role`]);
//! - `settings/<id>.json`: a plugin's settings (`settings_*`), kept across its updates and
//!   removed with it.
//!
//! Every file is replaced atomically ([`write_atomically`]); every change of the state is
//! made under one lock and saved before it is seen.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use oncl_pki::fsutil::{Access, write_atomically};
use oncl_update::tuf::{PublisherName, RoleName};
use oncl_update::{Channel, Index, Sha256, Version};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{MAX_PACKAGE, PACKAGE_EXT, Package, PackageError};

/// What is kept between runs: `<data>/plugins/state.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreState {
    /// This installation's random id, for the rollout buckets of plugin releases; never sent
    /// anywhere. Drawn anew if missing.
    #[serde(with = "hex16", default = "random_install_id")]
    pub install_id: [u8; 16],
    /// The highest `seq` of each channel's catalog accepted: an older one is refused.
    #[serde(default)]
    pub last_seq: BTreeMap<Channel, u64>,
    /// The installed plugins, by id.
    #[serde(default)]
    pub plugins: BTreeMap<String, Installed>,
    /// Versions of plugins that failed to load here, by id: never offered again.
    #[serde(default)]
    pub bad: BTreeMap<String, BTreeSet<Version>>,
    /// Ports the user would not have replaced by a publisher's plugin: the port's id, the
    /// id of the plugin declined. Not asked again for that plugin.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub declined_replacements: BTreeMap<String, String>,
}

/// An installed plugin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installed {
    pub version: Version,
    /// The sum of its package file: the file is not loaded if it no longer matches.
    pub sha256: Sha256,
    pub source: Source,
    /// Turned on: its modules are served.
    pub enabled: bool,
    /// Its version is revoked in the catalog with nothing to move to: it is not loaded.
    #[serde(default)]
    pub withdrawn: bool,
    /// The publisher whose delegated role signed the release installed; `None` for a port of
    /// the owner's index and for a file the user chose. A state written before publishers has
    /// none, nor has one whose name this version does not accept (logged, the rest of the
    /// state is kept): it is restored from the publishers' prefixes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient_publisher"
    )]
    pub publisher: Option<PublisherName>,
}

/// [`Installed::publisher`] as read: anything but a valid publisher name is `None` (logged),
/// never an error that would lose the whole state.
fn lenient_publisher<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PublisherName>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    let publisher = value
        .as_str()
        .and_then(|name| PublisherName::parse(name).ok());
    if publisher.is_none() {
        tracing::warn!(publisher = %value, "the recorded publisher of a plugin is not a publisher's name; dropped");
    }
    Ok(publisher)
}

/// Where an installed plugin came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The catalog (the signed update index): updated and withdrawn by it.
    Catalog,
    /// A file the user chose: never touched by the catalog.
    Local,
}

/// Why an installed plugin's package cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// No plugin of this id is installed.
    #[error("the plugin {0} is not installed")]
    NotInstalled(String),
    /// The package file cannot be read.
    #[error("the plugin package cannot be read: {0}")]
    Io(#[from] io::Error),
    /// The package file is not the one installed: its sha256 differs.
    #[error("the plugin package was changed after its installation")]
    Tampered,
    /// The package file is not a valid package.
    #[error(transparent)]
    Package(#[from] PackageError),
    /// The package is valid, but of another plugin or version.
    #[error("the plugin package is of {0}")]
    Mismatch(String),
}

/// A catalog kept by [`Store::save_catalog`] that still holds.
#[derive(Clone, Debug)]
pub struct KeptCatalog {
    /// The index.
    pub index: Index,
    /// When the TUF metadata that vouches for it expires.
    pub valid_until: OffsetDateTime,
}

/// The plugins' directory; see the [module](self).
pub struct Store {
    dir: PathBuf,
    state: Mutex<StoreState>,
}

impl StoreState {
    /// Nothing installed, nothing seen, a new random install id.
    pub fn fresh() -> StoreState {
        StoreState {
            install_id: random_install_id(),
            last_seq: BTreeMap::new(),
            plugins: BTreeMap::new(),
            bad: BTreeMap::new(),
            declined_replacements: BTreeMap::new(),
        }
    }
}

impl Store {
    /// How old a file no installed plugin owns must be before [`Store::prune_files`]
    /// removes it.
    pub const PRUNE_AFTER: std::time::Duration = std::time::Duration::from_secs(10 * 60);

    /// The store in `<data_dir>/plugins/`, created if missing. A missing `state.json` starts
    /// a fresh state, saved at once (its install id is kept); one that is not a state
    /// (damaged) is replaced by a fresh state (logged).
    ///
    /// # Errors
    ///
    /// Any other error reading the state, and any error creating the directory or saving a
    /// fresh state.
    pub fn open(data_dir: &Path) -> io::Result<Store> {
        let dir = data_dir.join("plugins");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("state.json");
        let (state, save) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<StoreState>(&bytes) {
                Ok(state) => (state, false),
                Err(e) => {
                    tracing::warn!(error = %e, "the plugins' state is broken; starting a new one");
                    (StoreState::fresh(), true)
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (StoreState::fresh(), true),
            Err(e) => return Err(e),
        };
        let store = Store {
            dir,
            state: Mutex::new(state),
        };
        if save {
            store.save(&lock(&store.state))?;
        }
        Ok(store)
    }

    /// The state now.
    pub fn state(&self) -> StoreState {
        lock(&self.state).clone()
    }

    /// Installs `package`, whose file is `bytes`, from `source`, released by `publisher` (a
    /// publisher's plugin of the catalog, else `None`): the package file is written, then the
    /// state; the package of the version installed before, if another, is removed after that.
    /// A plugin installed before keeps whether it is enabled; a new one is enabled. It is no
    /// longer withdrawn.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] if `bytes` is not `package`'s file; any I/O error
    /// writing the package or the state (nothing is installed then).
    pub fn install(
        &self,
        package: &Package,
        bytes: &[u8],
        source: Source,
        publisher: Option<&PublisherName>,
    ) -> io::Result<()> {
        let sha256 = Sha256::of(bytes);
        if sha256.0 != package.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the bytes are not the package's file",
            ));
        }
        let id = &package.manifest.id;
        let version = &package.manifest.version;
        let mut state = lock(&self.state);
        let file = self.package_path(id, version);
        std::fs::create_dir_all(self.dir.join("packages"))?;
        write_atomically(&file, bytes, Access::Default)?;
        let before = state.plugins.get(id).cloned();
        let mut next = state.clone();
        next.plugins.insert(
            id.clone(),
            Installed {
                version: version.clone(),
                sha256,
                source,
                enabled: before.as_ref().is_none_or(|b| b.enabled),
                withdrawn: false,
                publisher: publisher.cloned(),
            },
        );
        if let Err(e) = self.save(&next) {
            if before.as_ref().is_none_or(|b| b.version != *version) {
                remove_file(&file);
            }
            return Err(e);
        }
        *state = next;
        if let Some(before) = before
            && before.version != *version
        {
            remove_file(&self.package_path(id, &before.version));
        }
        Ok(())
    }

    /// Uninstalls `id`: the state (with the replacement the user declined for it, if it is a
    /// port), then its settings file (a failure only logged), then its package file.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if it is not installed; any I/O error saving the state
    /// (it stays installed then) or removing the package file (it is uninstalled, the file
    /// stays).
    pub fn remove(&self, id: &str) -> io::Result<()> {
        let mut state = lock(&self.state);
        let mut next = state.clone();
        let Some(removed) = next.plugins.remove(id) else {
            return Err(not_installed(id));
        };
        next.declined_replacements.remove(id);
        self.save(&next)?;
        *state = next;
        remove_file(&self.settings_path(id));
        match std::fs::remove_file(self.package_path(id, &removed.version)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Replaces the installed port `port` by `package`, a publisher's plugin of the catalog
    /// whose file is `bytes`, released by `publisher` (Р11). The package file is written,
    /// then one save records the plugin (on or off as the port was, not withdrawn) and
    /// forgets the port and the replacement declined for it; the port's settings and
    /// package files go after that (a failure only logged).
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if `port` is not installed;
    /// [`io::ErrorKind::AlreadyExists`] if `package`'s plugin is (a port and its replacement
    /// are never both installed); [`io::ErrorKind::InvalidInput`] if `bytes` is not
    /// `package`'s file or `package` is `port`; any I/O error writing the package or the
    /// state (nothing changes then).
    pub fn replace(
        &self,
        port: &str,
        package: &Package,
        bytes: &[u8],
        publisher: Option<&PublisherName>,
    ) -> io::Result<()> {
        let sha256 = Sha256::of(bytes);
        if sha256.0 != package.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the bytes are not the package's file",
            ));
        }
        let id = &package.manifest.id;
        if id == port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a plugin does not replace itself",
            ));
        }
        let version = &package.manifest.version;
        let mut state = lock(&self.state);
        if state.plugins.contains_key(id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("the plugin {id} is installed already"),
            ));
        }
        let mut next = state.clone();
        let Some(removed) = next.plugins.remove(port) else {
            return Err(not_installed(port));
        };
        next.declined_replacements.remove(port);
        next.plugins.insert(
            id.clone(),
            Installed {
                version: version.clone(),
                sha256,
                source: Source::Catalog,
                enabled: removed.enabled,
                withdrawn: false,
                publisher: publisher.cloned(),
            },
        );
        let file = self.package_path(id, version);
        std::fs::create_dir_all(self.dir.join("packages"))?;
        write_atomically(&file, bytes, Access::Default)?;
        if let Err(e) = self.save(&next) {
            remove_file(&file);
            return Err(e);
        }
        *state = next;
        remove_file(&self.settings_path(port));
        remove_file(&self.package_path(port, &removed.version));
        Ok(())
    }

    /// Removes the package and settings files no installed plugin owns: what a crash left
    /// between a save of the state and the removal of the files it no longer names (a port
    /// replaced, a plugin removed, an old version). The built-in modules' settings stay, and
    /// so does a file changed within [`Store::PRUNE_AFTER`] (or whose time cannot be read):
    /// another process (`oncl plugin install`) may have written it and not yet saved the
    /// state that names it. Call it before any plugin is installed in this run. Each failure
    /// is only logged.
    pub fn prune_files(&self) {
        let now = std::time::SystemTime::now();
        let state = lock(&self.state);
        let packages: BTreeSet<PathBuf> = state
            .plugins
            .iter()
            .map(|(id, installed)| self.package_path(id, &installed.version))
            .collect();
        let settings: BTreeSet<PathBuf> = state
            .plugins
            .keys()
            .map(|id| self.settings_path(id))
            .collect();
        for (dir, ext, keep) in [
            (self.dir.join("packages"), PACKAGE_EXT, &packages),
            (self.settings_dir(), "json", &settings),
        ] {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let builtin = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(crate::BUILTIN_ID_PREFIX));
                let recent = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .is_none_or(|at| {
                        !now.duration_since(at)
                            .is_ok_and(|age| age >= Store::PRUNE_AFTER)
                    });
                if path.extension().is_some_and(|e| e == ext)
                    && path.is_file()
                    && !builtin
                    && !recent
                    && !keep.contains(&path)
                {
                    tracing::info!(path = %path.display(), "a plugin file no plugin owns is removed");
                    remove_file(&path);
                }
            }
        }
    }

    /// Turns `id` on or off.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if it is not installed; any I/O error saving the state.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> io::Result<()> {
        self.change_installed(id, |installed| installed.enabled = enabled)
    }

    /// Marks `id` withdrawn by the catalog, or not.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if it is not installed; any I/O error saving the state.
    pub fn set_withdrawn(&self, id: &str, withdrawn: bool) -> io::Result<()> {
        self.change_installed(id, |installed| installed.withdrawn = withdrawn)
    }

    /// Records `publisher` as the one that released the installed `id` (`None`: a port, or
    /// a file the user chose).
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if it is not installed; any I/O error saving the state.
    pub fn set_publisher(&self, id: &str, publisher: Option<PublisherName>) -> io::Result<()> {
        self.change_installed(id, |installed| installed.publisher = publisher)
    }

    /// Records that the user declined to replace the port `port` by the plugin `plugin`
    /// (`None`: forgets it, the replacement may be offered again).
    ///
    /// # Errors
    ///
    /// Any I/O error saving the state.
    pub fn set_declined_replacement(&self, port: &str, plugin: Option<&str>) -> io::Result<()> {
        self.change(|state| match plugin {
            Some(plugin) => {
                state
                    .declined_replacements
                    .insert(port.to_owned(), plugin.to_owned());
            }
            None => {
                state.declined_replacements.remove(port);
            }
        })
    }

    /// Marks `version` of `id` as failing here: it is not offered again.
    ///
    /// # Errors
    ///
    /// Any I/O error saving the state.
    pub fn mark_bad(&self, id: &str, version: &Version) -> io::Result<()> {
        self.change(|state| {
            state
                .bad
                .entry(id.to_owned())
                .or_default()
                .insert(version.clone());
        })
    }

    /// The package of the installed `id`, checked against the sum recorded at its
    /// installation and against its id and version.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn load_package(&self, id: &str) -> Result<Package, StoreError> {
        let installed = lock(&self.state)
            .plugins
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::NotInstalled(id.to_owned()))?;
        let file = std::fs::File::open(self.package_path(id, &installed.version))?;
        let mut bytes = Vec::new();
        file.take(MAX_PACKAGE + 1).read_to_end(&mut bytes)?;
        if Sha256::of(&bytes) != installed.sha256 {
            return Err(StoreError::Tampered);
        }
        let package = Package::read(&bytes)?;
        let manifest = &package.manifest;
        if manifest.id != id || manifest.version != installed.version {
            return Err(StoreError::Mismatch(format!(
                "{} {}",
                manifest.id, manifest.version
            )));
        }
        Ok(package)
    }

    /// Keeps the index of `channel`, the bytes the TUF client verified, and raises the
    /// channel's `last_seq` to its `seq`.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidData`] if `index` is not an index; any I/O error.
    pub fn save_catalog(&self, channel: Channel, index: &[u8]) -> io::Result<()> {
        let seq = Index::from_json(index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .seq;
        let dir = self.dir.join("catalog");
        std::fs::create_dir_all(&dir)?;
        write_atomically(&self.catalog_path(channel), index, Access::Default)?;
        self.change(|state| {
            let last = state.last_seq.entry(channel).or_insert(seq);
            *last = (*last).max(seq);
        })
    }

    /// The kept index of `channel`, if there is one and it still holds: `check` is given
    /// its bytes and must vouch for them (for the TUF client,
    /// [`oncl_update::tuf::TufClient::verify_cached_target`]: the saved targets metadata
    /// lists exactly these bytes and has not expired) and says until when they hold; then the
    /// index must be of `channel` and not older than the channel's `last_seq`. `None` if
    /// there is none, or it no longer holds (logged).
    pub fn load_catalog(
        &self,
        channel: Channel,
        check: impl FnOnce(&[u8]) -> Result<OffsetDateTime, String>,
    ) -> Option<KeptCatalog> {
        let path = self.catalog_path(channel);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read the kept plugin catalog");
                return None;
            }
        };
        let last_seq = lock(&self.state).last_seq.get(&channel).copied();
        let kept = check(&bytes).and_then(|valid_until| {
            Index::accept(&bytes, channel, last_seq)
                .map(|index| KeptCatalog { index, valid_until })
                .map_err(|e| e.to_string())
        });
        match kept {
            Ok(kept) => Some(kept),
            Err(e) => {
                tracing::info!(%channel, error = %e, "the kept plugin catalog no longer holds");
                None
            }
        }
    }

    /// Keeps `publishers.json`, the bytes the TUF client verified.
    ///
    /// # Errors
    ///
    /// Any I/O error.
    pub fn save_publishers(&self, bytes: &[u8]) -> io::Result<()> {
        std::fs::create_dir_all(self.dir.join("catalog"))?;
        write_atomically(&self.publishers_path(), bytes, Access::Default)
    }

    /// The kept `publishers.json`, if there is one and `check` vouches for its bytes (for
    /// the TUF client, [`oncl_update::tuf::TufClient::verify_cached_target`]) and says until
    /// when they hold. `None` if there is none, or it no longer holds (logged).
    pub fn load_publishers(
        &self,
        check: impl FnOnce(&[u8]) -> Result<OffsetDateTime, String>,
    ) -> Option<(Vec<u8>, OffsetDateTime)> {
        let bytes = read_kept(&self.publishers_path(), PUBLISHERS_MAX)?;
        match check(&bytes) {
            Ok(valid_until) => Some((bytes, valid_until)),
            Err(e) => {
                tracing::info!(error = %e, "the kept publishers' rules no longer hold");
                None
            }
        }
    }

    /// Keeps the file of the delegated role `role`, the bytes the TUF client verified.
    ///
    /// # Errors
    ///
    /// Any I/O error.
    pub fn save_role(&self, role: &RoleName, bytes: &[u8]) -> io::Result<()> {
        std::fs::create_dir_all(self.roles_dir())?;
        write_atomically(&self.role_path(role), bytes, Access::Default)
    }

    /// The kept file of the role `role`, if there is one, with what `check` says of its
    /// bytes (for the TUF client, [`oncl_update::tuf::TufClient::verify_cached_role`]). A file
    /// longer than a role may be, or that cannot be read, is none (logged).
    pub fn load_role<T>(&self, role: &RoleName, check: impl FnOnce(&[u8]) -> T) -> Option<T> {
        read_kept(&self.role_path(role), role_max()).map(|bytes| check(&bytes))
    }

    /// Removes the kept role files of every role not in `keep`: the roles the top-level
    /// targets no longer delegate to. A temporary file of a write ([`write_atomically`],
    /// `*.tmp`) is left alone: it may be a role being saved now.
    ///
    /// # Errors
    ///
    /// Any I/O error reading the directory (a file that cannot be removed is only logged).
    pub fn prune_roles(&self, keep: &BTreeSet<RoleName>) -> io::Result<()> {
        let entries = match std::fs::read_dir(self.roles_dir()) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let path = entry?.path();
            let name = path.file_name().and_then(|name| name.to_str());
            if name.is_some_and(|name| name.ends_with(".tmp")) {
                continue;
            }
            let kept = name
                .and_then(|name| name.strip_suffix(".json"))
                .and_then(|name| RoleName::parse(name).ok())
                .is_some_and(|role| keep.contains(&role));
            if !kept {
                remove_file(&path);
            }
        }
        Ok(())
    }

    /// `settings/`: the folder of the plugins' settings files
    /// ([`HostServices::settings_dir`](crate::HostServices::settings_dir)).
    pub fn settings_dir(&self) -> PathBuf {
        self.dir.join("settings")
    }

    /// [`Store::settings_dir`] of the store in `<data_dir>/plugins/`, without opening it.
    pub fn settings_dir_in(data_dir: &Path) -> PathBuf {
        data_dir.join("plugins").join("settings")
    }

    /// `settings/<id>.json`: the settings file of `id`.
    pub fn settings_path(&self, id: &str) -> PathBuf {
        self.settings_dir().join(format!("{id}.json"))
    }

    /// `packages/<id>-<version>.onclp`.
    fn package_path(&self, id: &str, version: &Version) -> PathBuf {
        self.dir
            .join("packages")
            .join(format!("{id}-{version}.{PACKAGE_EXT}"))
    }

    fn catalog_path(&self, channel: Channel) -> PathBuf {
        self.dir.join("catalog").join(format!("{channel}.json"))
    }

    fn publishers_path(&self) -> PathBuf {
        self.dir.join("catalog").join("publishers.json")
    }

    fn roles_dir(&self) -> PathBuf {
        self.dir.join("catalog").join("roles")
    }

    fn role_path(&self, role: &RoleName) -> PathBuf {
        self.roles_dir().join(role.meta_name())
    }

    /// Applies `f` to the installed `id` and saves the state.
    fn change_installed(&self, id: &str, f: impl FnOnce(&mut Installed)) -> io::Result<()> {
        let mut state = lock(&self.state);
        let mut next = state.clone();
        let Some(installed) = next.plugins.get_mut(id) else {
            return Err(not_installed(id));
        };
        f(installed);
        if next != *state {
            self.save(&next)?;
            *state = next;
        }
        Ok(())
    }

    /// Applies `f` to the state and saves it if it changed.
    fn change(&self, f: impl FnOnce(&mut StoreState)) -> io::Result<()> {
        let mut state = lock(&self.state);
        let mut next = state.clone();
        f(&mut next);
        if next != *state {
            self.save(&next)?;
            *state = next;
        }
        Ok(())
    }

    fn save(&self, state: &StoreState) -> io::Result<()> {
        let mut body = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
        body.push(b'\n');
        write_atomically(&self.dir.join("state.json"), &body, Access::Default)
    }
}

fn not_installed(id: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("the plugin {id} is not installed"),
    )
}

/// The longest kept `publishers.json` read: what the client downloads at most.
const PUBLISHERS_MAX: u64 = oncl_update::PublisherPolicy::MAX_LEN as u64;

/// The longest kept role file read: what the client downloads at most.
fn role_max() -> u64 {
    oncl_update::tuf::Limits::default().delegated
}

/// The kept file at `path`, at most `max` bytes; `None` if there is none, it is longer or
/// it cannot be read (logged).
fn read_kept(path: &Path, max: u64) -> Option<Vec<u8>> {
    let read = std::fs::File::open(path).and_then(|file| {
        let mut bytes = Vec::new();
        file.take(max + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    match read {
        Ok(bytes) if bytes.len() as u64 > max => {
            tracing::warn!(path = %path.display(), max, "a kept catalog file is longer than any the client keeps");
            None
        }
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "cannot read a kept catalog file");
            None
        }
    }
}

/// Removes a file of a plugin that is no longer installed (or no longer that version); a
/// failure is only logged.
fn remove_file(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), error = %e, "cannot remove an old plugin file");
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn random_install_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("operating system RNG failed");
    id
}

/// 16 bytes as 32 lowercase hexadecimal digits.
mod hex16 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        let text: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&text)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let text = String::deserialize(d)?;
        let bad = || D::Error::custom("expected 32 lowercase hexadecimal digits");
        let digits = text.as_bytes();
        if digits.len() != 32
            || !digits
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(bad());
        }
        let mut bytes = [0u8; 16];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| bad())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
        }
        Ok(bytes)
    }
}
