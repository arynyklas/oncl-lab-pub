//! The plugins of the daemon: installed in `<data>/plugins/` ([`Store`]), loaded as dynamic
//! modules ([`PluginModules`]), installed, updated and withdrawn from the catalog (the
//! plugin releases of the update index of the channel in the settings and of the
//! publishers' delegated roles, read through the TUF repository: [`catalog`]), or installed
//! from a file the user chose.
//!
//! - At the start the enabled plugins not withdrawn are loaded (one that fails is shown with
//!   its error and logged), and the catalog kept last is read again.
//! - The catalog is checked within 10 to 60 s of the start if none is kept, else after
//!   [`FIRST_CHECK`], then every [`catalog::PUBLISHER_CHECK_EVERY`] while a publisher's
//!   plugin is installed, else every [`crate::update::CHECK_EVERY`] ([`RETRY_AFTER`] after
//!   a download failed); also on demand (the plugin window, a page's `installBundle`,
//!   «Проверить сейчас»). A scheduled check that finds the repository's snapshot as it was
//!   when the catalog was last applied reads nothing more.
//! - After every catalog accepted, each plugin installed from the catalog moves to the
//!   version [`choose_installed`] picks for it and its publisher: downloaded, checked against
//!   the catalog (HTTPS, size, sha256, then its manifest: id, version, modules, `replaces`,
//!   `min_core` and a publisher's declared capabilities), loaded, then recorded; a version
//!   that fails any of it is marked bad and the old one stays. A version revoked with nothing
//!   to move to, or a plugin of a revoked publisher, is unloaded and marked withdrawn.
//!   Plugins installed from a file are never touched. With updates off (`updates.enabled` of
//!   the settings) only the revocations are applied ([`catalog::Apply::RevocationsOnly`]),
//!   on schedule only while «Проверять отзывы плагинов» (`updates.check_revocations`) is on.
//! - A port an active publisher's plugin replaces (Р11, `supersedes`) gets only its
//!   revocations from the catalog; with updates on its replacement is downloaded, checked
//!   and offered in a window: agreed, it takes the port's place (the port, its package and
//!   settings removed); declined, the port runs on, the offer is not repeated for that
//!   plugin and stays in the plugin window ([`PluginService::replace_port`]). Once the
//!   publisher is no longer active the port is an ordinary port again.
//! - An install asks the user ([`InstallUi`]) with the capabilities the package declares.
//! - A request for a module nothing serves that a plugin of the catalog would serve is told
//!   ([`PluginNotice::Needed`]) and listed in the plugin window.
//!
//! Without the trust root of the update repository built in there is no catalog: plugins are
//! installed from files only.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use oncl_desktop::UpdateSettings;
use oncl_flows::capabilities::{CapabilityLine, OperationConsent};
use oncl_pki::http::HttpTransport;
use oncl_plugin::core::Bundles;
use oncl_plugin::operations::{AddedOperation, AddedReason};
use oncl_plugin::{
    Added, BUILT_IN, Capabilities, Installed, LoadError, Localized, MAX_PACKAGE, Manifest, Package,
    PluginModules, Replaces, Source, Store, StoreState,
};
use oncl_protocol::{AddInfo, DynamicModules};
use oncl_ui::PluginActionError;
use oncl_update::catalog::SourceArchive;
use oncl_update::tuf::PublisherName;
use oncl_update::{
    Channel, PluginChoice, PluginName, PluginRelease, Sha256, UpdateError, Version,
    choose_installed, offer,
};
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::load_settings;
use crate::repository::{CatalogRead, PUBLISHERS_TIMEOUT, Repository};
use crate::update::installer::fetch_package;
use crate::update::{DOWNLOAD_TIMEOUT, FIRST_CHECK, INDEX_TIMEOUT, RETRY_AFTER, jitter};
use catalog::{Apply, InUse};

/// The first download of the catalog when none is kept, this long after the start.
pub const FIRST_CHECK_WITHOUT_CATALOG: (Duration, Duration) =
    (Duration::from_secs(10), Duration::from_secs(60));

/// How often a bounded wait looks whether a catalog download running has ended.
const CATALOG_POLL: Duration = Duration::from_millis(20);

/// How long after a catalog download failed a page's request (`installBundle`, an install
/// a page started) does without a catalog instead of downloading it again.
pub const PAGE_RETRY_AFTER: Duration = Duration::from_secs(5 * 60);

/// How often an install a page started may tell that it failed, per plugin.
pub const PAGE_FAILURE_EVERY: Duration = Duration::from_secs(10 * 60);

/// The longest sleep of the schedule: the wall clock is compared at least this often.
const WAKE_EVERY: Duration = Duration::from_secs(3600);

/// What asks the user before a plugin is installed.
pub trait InstallUi: Send + Sync {
    /// Asks about `request` and returns at once; the answer goes to `decide` (`true`:
    /// install), once, from any thread. A request that cannot be shown is declined.
    fn confirm(&self, request: InstallRequest, decide: Box<dyn FnOnce(bool) + Send>);
}

/// A plugin about to be installed, as the user is asked about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRequest {
    /// The page that asked for it (`installBundle`), if one did.
    pub origin: Option<String>,
    pub name: Localized,
    pub version: Version,
    pub replaces: Option<Replaces>,
    /// The installed plugin of the same id it would replace: its version and origin.
    pub replacing: Option<(Version, ReleaseOrigin)>,
    /// What its manifest declares it may do.
    pub capabilities: Capabilities,
    /// What its `[[operations]]` do, said from checked fields; over the installed version
    /// of the plugin, if any, with what is new or wider marked.
    pub operations: Vec<OperationConsent>,
    /// Who released it: the project, a publisher, or a file the user chose (nobody has
    /// reviewed it).
    pub origin_kind: ReleaseOrigin,
    /// The installed port this publisher's plugin is to replace (Р11): its name and version.
    /// The port and its settings go if the user agrees; declining is remembered.
    pub replaces_port: Option<(Localized, Version)>,
}

/// Who released a plugin, as the windows name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseOrigin {
    /// A port of the owner's index.
    Project,
    /// A publisher's plugin of the catalog.
    Publisher {
        /// Its display name in `publishers.json` (its name if the catalog does not have it).
        display: Localized,
        /// The source archive of the release, if the catalog in use lists the release.
        source: Option<SourceArchive>,
    },
    /// Of the catalog, but its publisher is not known (its record lost it and no catalog
    /// tells it): nobody is named.
    Unknown,
    /// A file the user chose.
    LocalFile,
}

/// Who released `release` of `catalog` (none: the release is not known), the plugin `id`
/// of `publisher` installed from `source`. A plugin of the catalog whose publisher is not
/// known is the project's only if it is one of its ports (its prefix, or the owner's index
/// lists it); otherwise nobody is named.
fn release_origin(
    catalog: Option<&oncl_update::Catalog>,
    release: Option<&PluginRelease>,
    id: &str,
    publisher: Option<&PublisherName>,
    source: Source,
) -> ReleaseOrigin {
    if source == Source::Local {
        return ReleaseOrigin::LocalFile;
    }
    let Some(publisher) = publisher else {
        let port = release.is_some_and(|r| r.publisher.is_none())
            || id.starts_with(oncl_update::catalog::PROJECT_PREFIX)
            || catalog.is_some_and(|c| c.index().plugins.iter().any(|r| r.id == id));
        return if port {
            ReleaseOrigin::Project
        } else {
            ReleaseOrigin::Unknown
        };
    };
    ReleaseOrigin::Publisher {
        display: catalog.map_or_else(
            || same_name(publisher.as_str()),
            |catalog| publisher_display(catalog, publisher),
        ),
        source: catalog
            .zip(release)
            .and_then(|(catalog, release)| catalog.source_archive(release).cloned()),
    }
}

/// The display name of `publisher` in `catalog`'s `publishers.json`, or its name.
fn publisher_display(catalog: &oncl_update::Catalog, publisher: &PublisherName) -> Localized {
    catalog
        .policy()
        .and_then(|policy| policy.publisher(publisher))
        .map_or_else(
            || same_name(publisher.as_str()),
            |p| Localized {
                ru: p.display().ru.clone(),
                kk: p.display().kk.clone(),
                en: p.display().en.clone(),
            },
        )
}

/// Who released the installed `id` (`installed`): its release in `catalog`, if listed, gives
/// the source archive.
fn installed_origin(
    catalog: Option<&oncl_update::Catalog>,
    id: &str,
    installed: &Installed,
) -> ReleaseOrigin {
    let publisher = installed
        .publisher
        .as_ref()
        .or_else(|| catalog.and_then(|catalog| catalog.publisher_of(id)));
    let release = catalog.and_then(|catalog| {
        catalog.releases().find(|r| {
            r.id == id
                && r.version == installed.version
                && r.publisher.as_ref() == publisher
                && r.package.sha256 == installed.sha256
        })
    });
    release_origin(catalog, release, id, publisher, installed.source)
}

/// What the plugins tell the user (tray notifications).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginNotice {
    /// A plugin is installed.
    Installed { name: Localized },
    /// The port `port` is replaced by the publisher's plugin `name`, the user agreeing
    /// (Р11).
    PortReplaced { port: Localized, name: Localized },
    /// A plugin is updated to `version` (or moved back to it from a revoked one).
    Updated { name: Localized, version: Version },
    /// A plugin's version is revoked with nothing to move to: it is off.
    Withdrawn { name: Localized },
    /// The publisher of a plugin is revoked in the catalog: the plugin is off.
    PublisherRevoked {
        name: Localized,
        /// The publisher's display name.
        publisher: Localized,
    },
    /// Installing or updating a plugin failed.
    Failed { name: Localized, error: String },
    /// An update of a plugin to `version` may do more than the version installed: it waits
    /// for the user, in the plugin window; the installed version runs on, unless it is
    /// revoked (then it is off meanwhile).
    UpdateNeedsConfirmation { name: Localized, version: Version },
    /// A page (`origin`) called a module of the plugin `id` of the catalog, not installed.
    Needed {
        origin: Option<String>,
        name: Localized,
        id: String,
    },
}

/// Where and with what the plugins work.
pub struct PluginConfig {
    /// The data directory: `plugins/` is there.
    pub data_dir: PathBuf,
    /// `settings.json`: its `updates` (on or off, the channel) are read at every check.
    pub settings: PathBuf,
    /// The update repository the catalog is read through, shared with the updater; none:
    /// no catalog.
    pub repository: Option<Arc<Repository>>,
    /// This version of OpenNCALayer: plugins needing a newer one are not offered or loaded.
    pub core: Version,
    /// The network: the catalog and the packages.
    pub http: Arc<dyn HttpTransport>,
    pub modules: Arc<PluginModules>,
    pub ui: Arc<dyn InstallUi>,
    /// Tells the user; called from any thread, must not block.
    pub notify: Arc<dyn Fn(PluginNotice) + Send + Sync>,
    /// How long `installBundle` waits for the catalog when none is in use:
    /// [`OFFER_TIMEOUT`].
    pub offer_timeout: Duration,
}

/// The plugins as the plugin window shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceView {
    pub catalog: CatalogView,
    /// By id.
    pub installed: Vec<InstalledView>,
    /// Offered by the catalog, not installed; by id.
    pub available: Vec<AvailableView>,
}

/// The catalog's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogView {
    /// This build has no trust root of the update repository built in: no catalog.
    Unavailable,
    /// The catalog of `channel` is in use, made at `generated`; `checked` is when it was
    /// last downloaded in this run, `error` why the last download failed, if it did.
    Ready {
        channel: Channel,
        generated: OffsetDateTime,
        checked: Option<OffsetDateTime>,
        error: Option<String>,
    },
    /// No catalog of `channel` in use: not downloaded yet (`error` none), not published, or
    /// the download failed (`error`).
    Missing {
        channel: Channel,
        error: Option<String>,
    },
}

/// An installed plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledView {
    pub id: String,
    pub name: Localized,
    pub version: Version,
    pub replaces: Option<Replaces>,
    pub origin: ReleaseOrigin,
    pub state: PluginState,
    /// An update that waits for the user: it may do more than this version.
    pub pending_update: Option<PendingView>,
    /// A port an active publisher's plugin replaces, the replacement declined once (and
    /// updates on): the publisher's display name ([`PluginService::replace_port`]).
    pub replacement: Option<Localized>,
}

/// An update waiting for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingView {
    pub version: Version,
    /// What it may do that the installed version may not: capabilities and operations.
    pub added: Added,
    /// All the operations of the update, said from checked fields, with what is new or
    /// wider marked.
    pub operations: Vec<OperationConsent>,
    /// The sha256 of the package of this update (hex, from the signed index): the answer the
    /// user gives is for this package ([`PluginService::confirm_update`]).
    pub package_sha256: String,
    /// Who released the update.
    pub origin: ReleaseOrigin,
}

impl PendingView {
    /// What the user is asked to agree to, a line each: the capabilities, then (if any) the
    /// operations that are new or wider, by name (their labels are the plugin's own text and
    /// are not shown as a promise).
    pub fn lines(&self) -> Vec<CapabilityLine> {
        let mut lines = self.added.capabilities.lines();
        if !self.added.operations.is_empty() {
            lines.push(CapabilityLine::Operations(
                self.added
                    .operations
                    .iter()
                    .map(|o| o.name.clone())
                    .collect(),
            ));
        }
        lines
    }
}

/// Whether an installed plugin serves its modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginState {
    Enabled,
    Disabled,
    /// Revoked in the catalog with nothing to move to.
    Withdrawn,
    /// Enabled, but it could not be loaded: why.
    Error(String),
}

/// A plugin of the catalog not installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableView {
    pub id: String,
    pub name: Localized,
    pub version: Version,
    pub replaces: Option<Replaces>,
    pub origin: ReleaseOrigin,
    /// A page called one of its modules: its origin (`Some(None)`: without an origin).
    pub needed_by: Option<Option<String>>,
}

/// The plugins; see the [module](self).
pub struct PluginService {
    /// This service, for the installs started in the background.
    me: Weak<PluginService>,
    cfg: PluginConfig,
    store: Store,
    catalog: Mutex<Catalog>,
    /// Why an installed plugin is not loaded, by id.
    errors: Mutex<BTreeMap<String, String>>,
    /// The names of installed plugins and what they replace, by id, from their packages.
    known: Mutex<BTreeMap<String, Known>>,
    /// Plugins of the catalog a page needed, by id: the page's origin.
    needed: Mutex<BTreeMap<String, Option<String>>>,
    /// Plugins being installed (downloaded, or waiting for the user), by id.
    installing: Mutex<BTreeSet<String>>,
    /// When an install a page started last told that it failed, by plugin id.
    page_failures: Mutex<BTreeMap<String, Instant>>,
    /// Versions of the catalog that could not load because another plugin serves one of
    /// their modules, by id: not updated to until the plugins change. Not recorded: the
    /// package is not at fault.
    conflicts: Mutex<BTreeMap<String, BTreeSet<Version>>>,
    /// Updates that may do more than the version installed, waiting for the user, by id.
    pending: Mutex<BTreeMap<String, PendingUpdate>>,
    /// One catalog download at a time.
    checking: Mutex<()>,
    /// One application of the catalog at a time.
    applying: Mutex<()>,
    /// An application asked for while one ran, the last one asked for: the running one goes
    /// over the catalog again, never wider than the settings allow then.
    apply_pending: Mutex<Option<Apply>>,
    /// Every change of an installed plugin (turned on or off, removed, installed, updated,
    /// withdrawn): each acts on the state as it is once it holds this.
    changing: Mutex<()>,
}

/// The catalog in use.
#[derive(Default)]
struct Catalog {
    in_use: Option<InUse>,
    /// The last catalog applied whole: a scheduled check that finds its snapshot again reads
    /// nothing more, unless it is to apply more than was applied.
    applied: Option<Applied>,
    /// When it was last downloaded in this run.
    checked: Option<OffsetDateTime>,
    /// Why the last download failed.
    error: Option<String>,
    /// When the last download failed to bring a catalog; `None` after one that did.
    failed_at: Option<Instant>,
}

/// A catalog applied ([`Catalog::applied`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Applied {
    channel: Channel,
    /// The snapshot it was read under.
    snapshot: u64,
    /// The widest application of it.
    apply: Apply,
}

/// Who wants the catalog: how long they wait for a download running, and whether a recent
/// failure is tried again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asker {
    /// The user, in the plugin window: waits for a download running, and downloads again.
    User,
    /// A page: waits only within its time, and does without a catalog for
    /// [`PAGE_RETRY_AFTER`] after a download failed.
    Page,
}

#[derive(Clone)]
struct Known {
    name: Localized,
    replaces: Option<Replaces>,
    manifest: Manifest,
}

/// An update downloaded and checked, waiting for the user: it may do more (`added`) than
/// `snapshot`, the version installed.
struct PendingUpdate {
    release: PluginRelease,
    package: Package,
    bytes: Vec<u8>,
    snapshot: Installed,
    added: Added,
}

/// Why a catalog download did not bring a catalog.
#[derive(Debug)]
enum Refresh {
    NoRepository,
    /// It could not be downloaded (or recorded): try again soon.
    Unreachable(String),
    /// The channel has no index yet.
    NotPublished,
    /// It was refused (an expired or rolled-back TUF role, a signature or hash that does not
    /// match, an older `seq`).
    Refused(String),
}

/// What a catalog download that did not fail brought.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fresh {
    /// The catalog, read and in use.
    Read,
    /// The snapshot is the one of the catalog applied last: nothing else was read.
    Unchanged,
}

/// What came of an update to a release of the catalog ([`PluginService::update_to`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Updated {
    /// Installed.
    Installed,
    /// It waited for the user before, and still does.
    StillWaiting,
    /// It may do more than the version installed: it waits for the user from now on.
    NowWaiting,
    /// Not downloaded, refused (marked bad), or the plugin changed meanwhile.
    Failed,
}

/// Why a downloaded package is not installed.
enum Download {
    /// It could not be downloaded: try again later.
    Unreachable(String),
    /// It is not what the index says: the version is marked bad.
    Bad(String),
}

impl PluginService {
    /// The plugins of `cfg`: the files no installed plugin owns removed (left by a crash),
    /// the enabled ones loaded, the kept catalog read; without a schedule
    /// ([`PluginService::start`] has one).
    ///
    /// # Errors
    ///
    /// `<data>/plugins/` cannot be opened ([`Store::open`]).
    pub fn new(cfg: PluginConfig) -> std::io::Result<Arc<PluginService>> {
        let store = Store::open(&cfg.data_dir)?;
        store.prune_files();
        let service = Arc::new_cyclic(|me| PluginService {
            me: Weak::clone(me),
            cfg,
            store,
            catalog: Mutex::new(Catalog::default()),
            errors: Mutex::default(),
            known: Mutex::default(),
            needed: Mutex::default(),
            installing: Mutex::default(),
            page_failures: Mutex::default(),
            conflicts: Mutex::default(),
            pending: Mutex::default(),
            checking: Mutex::new(()),
            applying: Mutex::new(()),
            apply_pending: Mutex::new(None),
            changing: Mutex::new(()),
        });
        for (id, installed) in service.store.state().plugins {
            if installed.enabled && !installed.withdrawn {
                // Logged and shown in the plugin window.
                let _ = service.load_installed(&id);
            } else {
                service.read_known(&id);
            }
        }
        let weak = Arc::downgrade(&service);
        service
            .cfg
            .modules
            .set_on_missing(Arc::new(move |module: &str, add_info: &AddInfo| {
                if let Some(service) = weak.upgrade() {
                    service.missing(module, add_info);
                }
            }));
        Ok(service)
    }

    /// [`PluginService::new`], and the schedule of the catalog downloads on a thread (none
    /// without keys).
    ///
    /// # Errors
    ///
    /// As [`PluginService::new`].
    pub fn start(cfg: PluginConfig) -> std::io::Result<Arc<PluginService>> {
        let service = PluginService::new(cfg)?;
        if service.cfg.repository.is_none() {
            info!("the update trust root is not built in: no plugin catalog");
            return Ok(service);
        }
        let scheduled = Arc::clone(&service);
        let spawned = thread::Builder::new()
            .name("plugins".into())
            .spawn(move || scheduled.run_schedule());
        if let Err(e) = spawned {
            warn!(error = %e, "cannot start the plugin catalog's schedule");
        }
        Ok(service)
    }

    /// «Проверить сейчас»: reads the catalog whole, even with updates off, and applies it:
    /// with updates on the plugins of the catalog are updated by it, with them off only the
    /// revocations are applied (Р38). Blocks for the downloads.
    pub fn check_now(&self) {
        let apply = Apply::with_updates(self.update_settings().enabled);
        if self.refresh(INDEX_TIMEOUT, None).is_ok() {
            self.apply_catalog(apply);
        }
    }

    /// One turn of the schedule: the catalog checked and, if the repository published
    /// since it was last applied, read and applied (with updates off only its revocations).
    /// With updates and «Проверять отзывы плагинов» both off nothing is checked: the turn
    /// only waits ([`Apply::scheduled`]). How long until the next: [`catalog::check_every`].
    pub fn scheduled_check(&self) -> Duration {
        let Some(apply) = Apply::scheduled(&self.update_settings()) else {
            return jitter(self.check_every());
        };
        match self.refresh(INDEX_TIMEOUT, Some(apply)) {
            Ok(Fresh::Read) => {
                self.apply_catalog(apply);
                jitter(self.check_every())
            }
            Ok(Fresh::Unchanged) => jitter(self.check_every()),
            Err(Refresh::Unreachable(_)) => jitter(RETRY_AFTER),
            Err(_) => jitter(self.check_every()),
        }
    }

    /// How far apart the scheduled checks are now: whether a publisher's plugin is
    /// installed from the catalog (its publisher recorded, or the catalog in use knows it
    /// by its prefix).
    fn check_every(&self) -> (Duration, Duration) {
        let in_use = lock(&self.catalog).in_use.clone();
        let publisher_plugin = self.store.state().plugins.iter().any(|(id, installed)| {
            installed.source == Source::Catalog
                && (installed.publisher.is_some()
                    || in_use
                        .as_ref()
                        .is_some_and(|in_use| in_use.catalog.publisher_of(id).is_some()))
        });
        catalog::check_every(publisher_plugin)
    }

    fn run_schedule(&self) {
        let first = if self.valid_catalog().is_some() {
            FIRST_CHECK
        } else {
            FIRST_CHECK_WITHOUT_CATALOG
        };
        let mut due = SystemTime::now() + jitter(first);
        loop {
            // A computer's sleep stops monotonic time: compare the wall clock hourly.
            while let Ok(left) = due.duration_since(SystemTime::now())
                && !left.is_zero()
            {
                thread::sleep(left.min(WAKE_EVERY));
            }
            due = SystemTime::now() + self.scheduled_check();
        }
    }

    /// The plugins, their states, the catalog's state and what it offers.
    pub fn view(&self) -> ServiceView {
        let state = self.store.state();
        let errors = lock(&self.errors).clone();
        let known = lock(&self.known).clone();
        let index = self.valid_catalog().map(|in_use| in_use.catalog);
        let pending: BTreeMap<String, PendingView> = lock(&self.pending)
            .iter()
            .map(|(id, p)| {
                let view = PendingView {
                    version: p.release.version.clone(),
                    added: p.added.clone(),
                    operations: p.package.manifest.operation_consents(Some(&p.added)),
                    package_sha256: p.release.package.sha256.to_string(),
                    origin: release_origin(
                        index.as_deref(),
                        Some(&p.release),
                        &p.release.id,
                        p.release.publisher.as_ref(),
                        Source::Catalog,
                    ),
                };
                (id.clone(), view)
            })
            .collect();
        // A replacement the user declined is offered again from its port's row while
        // updates are on (they install it); its plugin is not listed apart.
        let replacements = index
            .as_ref()
            .map(|index| self.replacements(index, &state))
            .unwrap_or_default();
        let updates = self.update_settings().enabled;
        let installed = state
            .plugins
            .iter()
            .map(|(id, installed)| {
                let known = known.get(id);
                InstalledView {
                    id: id.clone(),
                    name: known.map_or_else(|| same_name(id), |k| k.name.clone()),
                    version: installed.version.clone(),
                    replaces: known.and_then(|k| k.replaces.clone()),
                    origin: installed_origin(index.as_deref(), id, installed),
                    state: if installed.withdrawn {
                        PluginState::Withdrawn
                    } else if !installed.enabled {
                        PluginState::Disabled
                    } else if let Some(error) = errors.get(id) {
                        PluginState::Error(error.clone())
                    } else {
                        PluginState::Enabled
                    },
                    pending_update: pending.get(id).cloned(),
                    replacement: replacements
                        .get(id)
                        .filter(|q| updates && state.declined_replacements.get(id) == Some(&q.id))
                        .zip(index.as_deref())
                        .and_then(|(q, index)| {
                            q.publisher.as_ref().map(|p| publisher_display(index, p))
                        }),
                }
            })
            .collect();
        if self.cfg.repository.is_none() {
            return ServiceView {
                catalog: CatalogView::Unavailable,
                installed,
                available: Vec::new(),
            };
        }
        let channel = self.update_settings().channel;
        let (checked, error) = {
            let catalog = lock(&self.catalog);
            (catalog.checked, catalog.error.clone())
        };
        let catalog = match &index {
            Some(index) => CatalogView::Ready {
                channel,
                generated: index.index().generated,
                checked,
                error,
            },
            None => CatalogView::Missing { channel, error },
        };
        let needed = lock(&self.needed).clone();
        let available = index
            .as_ref()
            .map(|index| {
                let ids: BTreeSet<&str> = index.releases().map(|r| r.id.as_str()).collect();
                ids.into_iter()
                    .filter(|id| !state.plugins.contains_key(*id))
                    .filter(|id| !self.replaces_installed_port(index, &state, id))
                    .filter_map(|id| {
                        let release =
                            offer(index, &self.cfg.core, &state.install_id, &state.bad, |r| {
                                r.id == id
                            })?;
                        Some(AvailableView {
                            id: id.to_owned(),
                            name: localized(&release.name),
                            version: release.version.clone(),
                            replaces: replaces_of(release),
                            origin: release_origin(
                                Some(index.as_ref()),
                                Some(release),
                                id,
                                release.publisher.as_ref(),
                                Source::Catalog,
                            ),
                            needed_by: needed.get(id).cloned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        ServiceView {
            catalog,
            installed,
            available,
        }
    }

    /// Installs the plugin `id` of the catalog (downloaded first if none is in use): its
    /// package is downloaded and checked, then the user is asked; `origin` is the page that
    /// asked for it. Blocks for the downloads, not for the user. An installed plugin, or one
    /// being installed, is left alone; a failure is told ([`PluginNotice::Failed`]), for an
    /// install a page started at most once per [`PAGE_FAILURE_EVERY`]. For a page the
    /// catalog is not downloaded again within [`PAGE_RETRY_AFTER`] of a failed download.
    ///
    /// # Errors
    ///
    /// Why nothing is asked, for the plugin window (also told in the tray, but for a plugin
    /// installed or being installed already).
    pub fn install_from_catalog(
        self: &Arc<Self>,
        id: &str,
        origin: Option<String>,
    ) -> Result<(), PluginActionError> {
        if self.store.state().plugins.contains_key(id) {
            info!(plugin = id, "installed already");
            return Err(PluginActionError::InstalledAlready);
        }
        let Some(guard) = self.begin_install(id) else {
            return Err(PluginActionError::BeingInstalled);
        };
        let asker = if origin.is_some() {
            Asker::Page
        } else {
            Asker::User
        };
        let failed = |name: Localized, error: String| self.install_failed(id, name, error, asker);
        let Some(index) = self.ensure_catalog(INDEX_TIMEOUT, asker) else {
            failed(
                same_name(id),
                "the plugin catalog is unavailable".to_owned(),
            );
            return Err(PluginActionError::NoCatalog);
        };
        let state = self.store.state();
        if self.replaces_installed_port(&index, &state, id) {
            failed(
                same_name(id),
                "it replaces an installed port: the plugin window offers it from the port"
                    .to_owned(),
            );
            return Err(PluginActionError::NotOffered);
        }
        let Some(release) = offer(&index, &self.cfg.core, &state.install_id, &state.bad, |r| {
            r.id == id
        })
        .cloned() else {
            failed(
                same_name(id),
                "the plugin catalog does not offer it".to_owned(),
            );
            return Err(PluginActionError::NotOffered);
        };
        let (package, bytes) = match self.download(&release) {
            Ok(downloaded) => downloaded,
            Err(Download::Unreachable(e)) => {
                failed(localized(&release.name), e.clone());
                return Err(PluginActionError::Failed(e));
            }
            Err(Download::Bad(e)) => {
                self.mark_bad(&release, &e);
                failed(localized(&release.name), e.clone());
                return Err(PluginActionError::Failed(e));
            }
        };
        if let Err(e) = self.cfg.modules.check(&package) {
            self.refused(&release.id, &release.version, &e);
            failed(localized(&release.name), e.to_string());
            return Err(PluginActionError::Failed(e.to_string()));
        }
        let origin_kind = release_origin(
            Some(index.as_ref()),
            Some(&release),
            id,
            release.publisher.as_ref(),
            Source::Catalog,
        );
        self.ask(package, bytes, Some(release), origin, origin_kind, guard);
        Ok(())
    }

    /// Installs the package file at `path` as a local plugin, once the user agreed (warned
    /// that nobody reviewed it). A failure is told ([`PluginNotice::Failed`]).
    ///
    /// # Errors
    ///
    /// Why nothing is asked, for the plugin window.
    pub fn install_from_file(self: &Arc<Self>, path: PathBuf) -> Result<(), PluginActionError> {
        let file_name = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let checked = read_package(&path)
            .map_err(PluginActionError::Failed)
            .and_then(|(package, bytes)| {
                if package.manifest.min_core > self.cfg.core {
                    return Err(PluginActionError::NeedsCore(
                        package.manifest.min_core.to_string(),
                    ));
                }
                self.cfg
                    .modules
                    .check(&package)
                    .map_err(|e| PluginActionError::Failed(e.to_string()))?;
                Ok((package, bytes))
            });
        let (package, bytes) = match checked {
            Ok(checked) => checked,
            Err(e) => {
                let detail = match &e {
                    PluginActionError::NeedsCore(v) => {
                        format!("the plugin needs OpenNCALayer {v} or newer")
                    }
                    PluginActionError::Failed(detail) => detail.clone(),
                    other => format!("{other:?}"),
                };
                warn!(path = %path.display(), error = %detail, "cannot install the plugin file");
                self.failed(same_name(&file_name), detail);
                return Err(e);
            }
        };
        let Some(guard) = self.begin_install(&package.manifest.id) else {
            return Err(PluginActionError::BeingInstalled);
        };
        self.ask(package, bytes, None, None, ReleaseOrigin::LocalFile, guard);
        Ok(())
    }

    /// Turns the installed `id` on (loaded, unless withdrawn) or off (unloaded).
    ///
    /// # Errors
    ///
    /// What failed, for the user: it is not installed, the state cannot be saved, or it
    /// cannot be loaded (it stays on, in error).
    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), PluginActionError> {
        let _change = lock(&self.changing);
        let Some(installed) = self.store.state().plugins.get(id).cloned() else {
            return Err(PluginActionError::NotInstalled);
        };
        self.store
            .set_enabled(id, enabled)
            .map_err(|e| PluginActionError::Failed(e.to_string()))?;
        if !enabled {
            self.cfg.modules.unload(id);
            lock(&self.errors).remove(id);
            lock(&self.conflicts).clear();
            return Ok(());
        }
        if installed.withdrawn {
            return Ok(());
        }
        self.load_installed(id).map_err(PluginActionError::Failed)
    }

    /// Uninstalls `id`: removed from `<data>/plugins/`, then unloaded. If its record is gone
    /// but its package file stays, it is unloaded all the same (and the error returned); if
    /// the record cannot be saved, it stays installed and loaded.
    ///
    /// # Errors
    ///
    /// What failed.
    pub fn remove(&self, id: &str) -> Result<(), PluginActionError> {
        let _change = lock(&self.changing);
        let removed = self.store.remove(id).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound
                && !self.store.state().plugins.contains_key(id)
                && !self.cfg.modules.loaded().iter().any(|p| p.id == id)
            {
                PluginActionError::NotInstalled
            } else {
                PluginActionError::Failed(e.to_string())
            }
        });
        if !self.store.state().plugins.contains_key(id) {
            self.cfg.modules.unload(id);
            lock(&self.errors).remove(id);
            lock(&self.known).remove(id);
            lock(&self.conflicts).clear();
            lock(&self.pending).remove(id);
        }
        removed
    }

    /// The newest release of the catalog porting the original's bundle `symname`, if the
    /// catalog has one for this installation. Without a catalog in use one is downloaded,
    /// all within `timeout`: a download already running is waited for within it, and then
    /// used; none within [`PAGE_RETRY_AFTER`] of a failed one.
    pub fn catalog_offer_for_symname(
        &self,
        symname: &str,
        timeout: Duration,
    ) -> Option<PluginRelease> {
        let index = self.ensure_catalog(timeout, Asker::Page)?;
        let state = self.store.state();
        offer(&index, &self.cfg.core, &state.install_id, &state.bad, |r| {
            r.replaces.as_ref().is_some_and(|p| p.symname == symname)
        })
        .cloned()
    }

    /// A request named `module`, which nothing serves: if a plugin of the catalog in use
    /// would, and is not installed, the page's need is listed, and told (the plugin window
    /// read again) when its entry changes: a plugin newly needed, or by another page. Never
    /// downloads.
    fn missing(&self, module: &str, add_info: &AddInfo) {
        let Some(index) = self.valid_catalog().map(|in_use| in_use.catalog) else {
            return;
        };
        let state = self.store.state();
        let Some(release) = offer(&index, &self.cfg.core, &state.install_id, &state.bad, |r| {
            r.modules.iter().any(|m| m == module)
        }) else {
            return;
        };
        // Installed, or the replacement of an installed port (offered from the port, not
        // installed beside it).
        if state.plugins.contains_key(&release.id)
            || self.replaces_installed_port(&index, &state, &release.id)
        {
            return;
        }
        let before = lock(&self.needed).insert(release.id.clone(), add_info.origin.clone());
        if before.as_ref() == Some(&add_info.origin) {
            return;
        }
        info!(plugin = %release.id, module, origin = ?add_info.origin, "a page needs a plugin of the catalog");
        (self.cfg.notify)(PluginNotice::Needed {
            origin: add_info.origin.clone(),
            name: localized(&release.name),
            id: release.id.clone(),
        });
    }

    /// Reads the catalog of the channel in the settings within `timeout` (the publishers'
    /// side within [`PUBLISHERS_TIMEOUT`] more), verifies it and keeps it. `unless`: a
    /// scheduled check that is to apply this much; if the catalog last applied that much
    /// was read under the snapshot the repository has now, nothing more is read
    /// ([`Fresh::Unchanged`]).
    fn refresh(&self, timeout: Duration, unless: Option<Apply>) -> Result<Fresh, Refresh> {
        if self.cfg.repository.is_none() {
            return Err(Refresh::NoRepository);
        }
        let one = lock(&self.checking);
        self.refresh_locked(&one, timeout, PUBLISHERS_TIMEOUT, unless)
    }

    /// [`PluginService::refresh`], `checking` held, the publishers' side given `publishers`
    /// more than `timeout` (none for a page, which keeps to its time): the parts of the
    /// catalog kept in the store are written by one check at a time.
    fn refresh_locked(
        &self,
        _one: &MutexGuard<'_, ()>,
        timeout: Duration,
        publishers: Duration,
        unless: Option<Apply>,
    ) -> Result<Fresh, Refresh> {
        let channel = self.update_settings().channel;
        // Only with a catalog in use to go on with: else the read rebuilds one.
        let in_use = unless.is_some() && self.valid_catalog().is_some();
        let unless_snapshot = unless.filter(|_| in_use).and_then(|apply| {
            lock(&self.catalog)
                .applied
                .filter(|applied| applied.channel == channel && applied.apply >= apply)
                .map(|applied| applied.snapshot)
        });
        let result = self.download_catalog(channel, timeout, publishers, unless_snapshot);
        let mut catalog = lock(&self.catalog);
        match &result {
            Ok(read) => {
                match read {
                    Some(in_use) => {
                        let index = in_use.catalog.index();
                        info!(%channel, seq = index.seq, plugins = in_use.catalog.releases().count(), "the plugin catalog is downloaded");
                        catalog.in_use = Some(in_use.clone());
                    }
                    None => {
                        info!(%channel, "the plugin catalog is as it was applied last");
                    }
                }
                catalog.checked = Some(OffsetDateTime::now_utc());
                catalog.error = None;
                catalog.failed_at = None;
            }
            Err(Refresh::NotPublished) => {
                catalog.error = None;
                catalog.failed_at = Some(Instant::now());
            }
            Err(Refresh::Unreachable(e) | Refresh::Refused(e)) => {
                catalog.error = Some(e.clone());
                catalog.failed_at = Some(Instant::now());
            }
            Err(Refresh::NoRepository) => {}
        }
        result.map(|read| match read {
            Some(_) => Fresh::Read,
            None => Fresh::Unchanged,
        })
    }

    /// The catalog of `channel` read and kept; `None` if the snapshot is `unless_snapshot`.
    fn download_catalog(
        &self,
        channel: Channel,
        timeout: Duration,
        publishers: Duration,
        unless_snapshot: Option<u64>,
    ) -> Result<Option<InUse>, Refresh> {
        let Some(repository) = &self.cfg.repository else {
            return Err(Refresh::NoRepository);
        };
        let last_seq = self.store.state().last_seq.get(&channel).copied();
        let read = repository
            .catalog(channel, last_seq, timeout, publishers, unless_snapshot)
            .map_err(|e| match e {
                UpdateError::NotPublished(_) => Refresh::NotPublished,
                e if e.retry_soon() => Refresh::Unreachable(e.to_string()),
                e => Refresh::Refused(e.to_string()),
            })?;
        match read {
            CatalogRead::Unchanged => Ok(None),
            // A catalog whose `seq` is not recorded is not used.
            CatalogRead::Read(read) => {
                catalog::from_read(*read, channel, &self.store, repository, self.builtin())
                    .map(Some)
                    .map_err(Refresh::Unreachable)
            }
        }
    }

    /// The modules the core serves itself.
    fn builtin(&self) -> impl Iterator<Item = String> + '_ {
        self.cfg.modules.builtin_modules().map(str::to_owned)
    }

    /// The catalog of the channel in the settings, if one in use still holds: the one
    /// downloaded, or the one kept in `<data>/plugins/` (every part checked again against
    /// the saved TUF state, offline: [`catalog::kept`]).
    fn valid_catalog(&self) -> Option<InUse> {
        let repository = self.cfg.repository.as_ref()?;
        let channel = self.update_settings().channel;
        let now = OffsetDateTime::now_utc();
        let mut catalog = lock(&self.catalog);
        if let Some(in_use) = &catalog.in_use
            && in_use.catalog.index().channel == channel
            && now < in_use.valid_until
        {
            return Some(in_use.clone());
        }
        catalog.in_use = catalog::kept(channel, &self.store, repository, self.builtin(), now);
        catalog.in_use.clone()
    }

    /// [`PluginService::valid_catalog`], or one downloaded within `timeout`. A download
    /// already running is waited for: fully for the user, or only within `timeout` for a
    /// page (then `None` once it runs out); a catalog it brought is used, else a download of
    /// our own gets the time left. A page does not download within [`PAGE_RETRY_AFTER`] of a
    /// failed download. A catalog downloaded here is applied in the background, with updates
    /// off its revocations only.
    fn ensure_catalog(&self, timeout: Duration, asker: Asker) -> Option<Arc<oncl_update::Catalog>> {
        if let Some(in_use) = self.valid_catalog() {
            return Some(in_use.catalog);
        }
        if self.cfg.repository.is_none() || self.page_waits_out_failure(asker) {
            return None;
        }
        let wait = asker == Asker::User;
        let deadline = std::time::Instant::now() + timeout;
        let one = if wait {
            lock(&self.checking)
        } else {
            loop {
                match self.checking.try_lock() {
                    Ok(one) => break one,
                    Err(TryLockError::Poisoned(e)) => break e.into_inner(),
                    Err(TryLockError::WouldBlock) => {
                        if std::time::Instant::now() >= deadline {
                            info!("the plugin catalog download running took too long; not waiting");
                            return None;
                        }
                        thread::sleep(CATALOG_POLL);
                    }
                }
            }
        };
        if let Some(in_use) = self.valid_catalog() {
            return Some(in_use.catalog);
        }
        if self.page_waits_out_failure(asker) {
            return None;
        }
        let left = if wait {
            timeout
        } else {
            deadline.saturating_duration_since(std::time::Instant::now())
        };
        if left.is_zero() {
            return None;
        }
        // A page keeps to its own time, the publishers' side included.
        let publishers = match asker {
            Asker::User => PUBLISHERS_TIMEOUT,
            Asker::Page => Duration::ZERO,
        };
        self.refresh_locked(&one, left, publishers, None).ok()?;
        drop(one);
        if let Some(service) = self.me.upgrade() {
            let apply = Apply::with_updates(self.update_settings().enabled);
            let spawned = thread::Builder::new()
                .name("plugins-apply".into())
                .spawn(move || service.apply_catalog(apply));
            if let Err(e) = spawned {
                warn!(error = %e, "cannot start a thread: the plugin catalog is not applied");
            }
        }
        self.valid_catalog().map(|in_use| in_use.catalog)
    }

    /// Whether `asker` is a page and the last catalog download failed within
    /// [`PAGE_RETRY_AFTER`]: the page does without a catalog then.
    fn page_waits_out_failure(&self, asker: Asker) -> bool {
        let recent = lock(&self.catalog)
            .failed_at
            .is_some_and(|at| at.elapsed() < PAGE_RETRY_AFTER);
        if asker == Asker::Page && recent {
            info!("the plugin catalog failed to download a moment ago; not again for a page");
            return true;
        }
        false
    }

    /// Moves each plugin installed from the catalog to the version the catalog in use
    /// chooses for it, as far as `apply` allows. One application at a time: one asked for
    /// while another runs marks itself pending, and the running one goes over the newest
    /// catalog once more, as the last one asked for. Each pass is capped by the settings as
    /// they are then ([`Apply::with_updates`]): one asked for with updates on applies only
    /// revocations once they are off. Each plugin is changed under `changing`, and only if it
    /// is still the one installed from the catalog at the version the choice was made for.
    fn apply_catalog(&self, apply: Apply) {
        let _one = match self.applying.try_lock() {
            Ok(one) => one,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => {
                info!("the plugin catalog is being applied already; it goes over it again");
                *lock(&self.apply_pending) = Some(apply);
                return;
            }
        };
        let mut apply = apply;
        loop {
            if let Some(asked) = lock(&self.apply_pending).take() {
                apply = asked;
            }
            let apply_now = apply.min(Apply::with_updates(self.update_settings().enabled));
            if let Some(in_use) = self.valid_catalog()
                && self.apply_index(&in_use.catalog, apply_now)
            {
                self.record_applied(&in_use, apply_now);
            }
            match lock(&self.apply_pending).take() {
                Some(asked) => apply = asked,
                None => break,
            }
        }
    }

    /// `in_use` is applied as far as `apply` allows and every plugin settled: if it was read
    /// whole, a scheduled check that finds its snapshot again reads nothing more; else the
    /// next one reads it again.
    fn record_applied(&self, in_use: &InUse, apply: Apply) {
        let channel = in_use.catalog.index().channel;
        let mut catalog = lock(&self.catalog);
        catalog.applied = in_use.whole_at.map(|snapshot| match catalog.applied {
            Some(before) if before.channel == channel && before.snapshot == snapshot => Applied {
                apply: before.apply.max(apply),
                ..before
            },
            _ => Applied {
                channel,
                snapshot,
                apply,
            },
        });
    }

    /// One pass of [`PluginService::apply_catalog`] over `catalog`; whether every plugin
    /// settled: each is where the catalog puts it, or waits for the user as it did before
    /// the pass. A download that failed, a version marked bad, an update newly waiting for
    /// the user or a plugin changed meanwhile leaves the pass unsettled, and the next check
    /// goes over the catalog again.
    ///
    /// A plugin's publisher not recorded is restored from the prefixes of `publishers.json`
    /// first. A revoked version never keeps running: with [`Apply::RevocationsOnly`] it is
    /// turned off even if the catalog has a version to move to (nothing is installed), with
    /// [`Apply::Full`] if the version to move to is not installed in this pass. An update
    /// waiting for the user is dropped unless it is still the catalog's choice.
    ///
    /// A port an active publisher's plugin replaces (Р11, [`PluginService::replacements`])
    /// gets only its revocations: its replacement is offered instead, with [`Apply::Full`]
    /// only and unless the user declined that plugin for it.
    fn apply_index(&self, catalog: &oncl_update::Catalog, apply: Apply) -> bool {
        let state = self.store.state();
        let replacements = self.replacements(catalog, &state);
        let mut settled = true;
        for (id, snapshot) in &state.plugins {
            if snapshot.source != Source::Catalog {
                continue;
            }
            let recorded = match &snapshot.publisher {
                Some(publisher) => Some(publisher.clone()),
                None => self.restore_publisher(catalog, id, snapshot),
            };
            let mut bad = state.bad.get(id).cloned().unwrap_or_default();
            bad.extend(lock(&self.conflicts).get(id).into_iter().flatten().cloned());
            let revoked = catalog.is_installed_revoked(id, &snapshot.version, recorded.as_ref());
            let choice = choose_installed(
                catalog,
                id,
                recorded.as_ref(),
                &snapshot.version,
                &self.cfg.core,
                &state.install_id,
                &bad,
            );
            // A port being replaced: its own updates are not installed, nor waited for.
            let replacement = replacements.get(id).copied();
            let apply_here = if replacement.is_some() {
                Apply::RevocationsOnly
            } else {
                apply
            };
            let target = match &choice {
                PluginChoice::Update(release) | PluginChoice::Downgrade(release)
                    if replacement.is_none() =>
                {
                    Some(*release)
                }
                _ => None,
            };
            self.drop_pending_unless(id, target);
            settled &= match choice {
                PluginChoice::Keep => self.unwithdraw(catalog, id, snapshot),
                PluginChoice::Update(release) | PluginChoice::Downgrade(release)
                    if apply_here == Apply::Full =>
                {
                    match self.update_to(release, snapshot) {
                        Updated::Installed => true,
                        outcome => {
                            // A revoked version stays off until the one to move to is
                            // installed; one no longer revoked runs on meanwhile.
                            let off = if revoked {
                                self.withdraw(id, snapshot, None)
                            } else {
                                self.unwithdraw(catalog, id, snapshot)
                            };
                            off && outcome == Updated::StillWaiting
                        }
                    }
                }
                // Revocations only: off a revoked version, never onto another one.
                PluginChoice::Update(_) | PluginChoice::Downgrade(_) => {
                    if revoked {
                        self.withdraw(id, snapshot, None)
                    } else {
                        self.unwithdraw(catalog, id, snapshot)
                    }
                }
                PluginChoice::Withdrawn => self.withdraw(id, snapshot, None),
                PluginChoice::PublisherRevoked(publisher) => {
                    let display = publisher_display(catalog, publisher);
                    self.withdraw(id, snapshot, Some(display))
                }
                // A choice this core does not know leaves the plugin as it is, but is logged:
                // a newer library may mean a withdrawal by it.
                other => {
                    warn!(plugin = %id, choice = ?other, "unknown plugin choice; the plugin is left as it is");
                    true
                }
            };
            if let Some(release) = replacement
                && apply == Apply::Full
                && state.declined_replacements.get(id) != Some(&release.id)
            {
                settled &= self.offer_replacement(catalog, id, snapshot, release);
            }
        }
        settled
    }

    /// The publishers' plugins `catalog` has to replace the ports `state` has installed from
    /// the catalog (Р11: [`oncl_update::Catalog::replacement`], an active publisher's
    /// `supersedes`), by port: never a version bad here, nor any version of a plugin held
    /// back by a failed load until the plugins change (`conflicts`). A port whose
    /// replacement is installed already has none.
    fn replacements<'c>(
        &self,
        catalog: &'c oncl_update::Catalog,
        state: &StoreState,
    ) -> BTreeMap<String, &'c PluginRelease> {
        let held = lock(&self.conflicts).clone();
        state
            .plugins
            .iter()
            .filter(|(_, installed)| installed.source == Source::Catalog)
            .filter_map(|(port, _)| {
                let release =
                    catalog.replacement(port, &self.cfg.core, &state.install_id, &state.bad)?;
                (!state.plugins.contains_key(&release.id) && !held.contains_key(&release.id))
                    .then(|| (port.clone(), release))
            })
            .collect()
    }

    /// Whether `id` is the plugin of an active publisher that replaces a port installed from
    /// `catalog` (any version of it offered here, bad or held back or not): it is offered from
    /// the port, never installed beside it.
    fn replaces_installed_port(
        &self,
        catalog: &oncl_update::Catalog,
        state: &StoreState,
        id: &str,
    ) -> bool {
        let any = BTreeMap::new();
        state.plugins.iter().any(|(port, installed)| {
            installed.source == Source::Catalog
                && catalog
                    .replacement(port, &self.cfg.core, &state.install_id, &any)
                    .is_some_and(|q| q.id == id)
        })
    }

    /// Whether `release` is still what the catalog in use offers to replace the installed
    /// port `port`, with updates on: what the user agrees to is installed only then.
    fn still_replacing(&self, port: &str, release: &PluginRelease) -> bool {
        if !self.update_settings().enabled {
            return false;
        }
        let Some(in_use) = self.valid_catalog() else {
            return false;
        };
        let state = self.store.state();
        self.replacements(&in_use.catalog, &state)
            .get(port)
            .is_some_and(|q| {
                q.id == release.id
                    && q.version == release.version
                    && q.package.sha256 == release.package.sha256
            })
    }

    /// Whether the catalog in use still offers `release` for a first install as the user was
    /// shown it: the newest offered version of its id, the same package, and not the
    /// replacement of an installed port.
    fn still_offered(&self, release: &PluginRelease) -> bool {
        let Some(in_use) = self.valid_catalog() else {
            return false;
        };
        let state = self.store.state();
        !self.replaces_installed_port(&in_use.catalog, &state, &release.id)
            && offer(
                &in_use.catalog,
                &self.cfg.core,
                &state.install_id,
                &state.bad,
                |r| r.id == release.id,
            )
            .is_some_and(|r| {
                r.version == release.version && r.package.sha256 == release.package.sha256
            })
    }

    /// Offers `release`, the publisher's plugin replacing the installed port `port`
    /// (`snapshot`), in the replacement window, once it is downloaded and checked. Whether it
    /// settled: only if the user is being asked already; asking anew, a download that failed
    /// or a version marked bad leave the pass unsettled.
    fn offer_replacement(
        &self,
        catalog: &oncl_update::Catalog,
        port: &str,
        snapshot: &Installed,
        release: &PluginRelease,
    ) -> bool {
        let Some(service) = self.me.upgrade() else {
            return true;
        };
        let Some(guard) = service.begin_install(&release.id) else {
            return true;
        };
        // A failure is logged (and a bad version told) there; the next check tries again.
        let _ = service.ask_replacement(catalog, port, snapshot, release, guard);
        false
    }

    /// Asks again whether the publisher's plugin that replaces the installed port `port` may
    /// replace it, the catalog downloaded first if none is in use: the user declined it once
    /// and the plugin window offers it ([`InstalledView::replacement`]). Blocks for the
    /// downloads, not for the user.
    ///
    /// # Errors
    ///
    /// Why nothing is asked: updates are off, the port is not installed from the catalog, no
    /// catalog, the catalog offers no replacement for it, it is being asked already, or the
    /// package failed (a bad one also told in the tray).
    pub fn replace_port(self: &Arc<Self>, port: &str) -> Result<(), PluginActionError> {
        if !self.update_settings().enabled {
            return Err(PluginActionError::UpdatesOff);
        }
        if !self.store.state().plugins.contains_key(port) {
            return Err(PluginActionError::NotInstalled);
        }
        let Some(catalog) = self.ensure_catalog(INDEX_TIMEOUT, Asker::User) else {
            return Err(PluginActionError::NoCatalog);
        };
        // The port as it is now, after the download.
        let state = self.store.state();
        let Some(snapshot) = state.plugins.get(port).cloned() else {
            return Err(PluginActionError::NotInstalled);
        };
        let Some(release) = self.replacements(&catalog, &state).remove(port).cloned() else {
            return Err(PluginActionError::NotOffered);
        };
        let Some(guard) = self.begin_install(&release.id) else {
            return Err(PluginActionError::BeingInstalled);
        };
        self.ask_replacement(&catalog, port, &snapshot, &release, guard)
    }

    /// Downloads and checks `release`, the publisher's plugin replacing the installed port
    /// `port` (`snapshot`), then asks the user in the replacement window: «Заменить»
    /// replaces the port ([`PluginService::finish_replacement`]), «Не сейчас» or closing the
    /// window is remembered ([`PluginService::decline_replacement`]).
    fn ask_replacement(
        self: &Arc<Self>,
        catalog: &oncl_update::Catalog,
        port: &str,
        snapshot: &Installed,
        release: &PluginRelease,
        guard: Installing,
    ) -> Result<(), PluginActionError> {
        let (package, bytes) = match self.download(release) {
            Ok(downloaded) => downloaded,
            Err(Download::Unreachable(e)) => {
                warn!(port, plugin = %release.id, error = %e, "cannot download the port's replacement");
                return Err(PluginActionError::Failed(e));
            }
            Err(Download::Bad(e)) => {
                self.bad(release, e.clone());
                return Err(PluginActionError::Failed(e));
            }
        };
        info!(port, plugin = %release.id, version = %release.version, "a publisher's plugin replaces the port; the user is asked");
        let m = &package.manifest;
        let request = InstallRequest {
            origin: None,
            name: m.name.clone(),
            version: m.version.clone(),
            replaces: m.replaces.clone(),
            replacing: None,
            capabilities: m.capabilities.clone(),
            operations: m.operation_consents(None),
            origin_kind: release_origin(
                Some(catalog),
                Some(release),
                &release.id,
                release.publisher.as_ref(),
                Source::Catalog,
            ),
            replaces_port: Some((self.name_of(port), snapshot.version.clone())),
        };
        let service = Arc::downgrade(self);
        let (port, snapshot, release) = (port.to_owned(), snapshot.clone(), release.clone());
        self.cfg.ui.confirm(
            request,
            Box::new(move |yes| {
                let _guard = guard;
                let Some(service) = service.upgrade() else {
                    return;
                };
                if yes {
                    service.finish_replacement(&port, &snapshot, &release, package, &bytes);
                } else {
                    service.decline_replacement(&port, &release.id);
                }
            }),
        );
        Ok(())
    }

    /// «Заменить»: under `changing`, if the port is still `snapshot` and `release` still
    /// what the catalog in use offers for it with updates on ([`PluginService::still_replacing`];
    /// else nothing changes and nothing is recorded), the port is unloaded and `package` of
    /// `release` loaded in its place (checked only if the port is off); then one save records
    /// the plugin with its publisher and forgets the port, whose settings and package go
    /// ([`Store::replace`]). If the plugin does not load, its version is marked bad (unless
    /// another plugin serves its module), the plugin is held back until the plugins change,
    /// and the port runs again; if it cannot be recorded, the port runs again.
    fn finish_replacement(
        &self,
        port: &str,
        snapshot: &Installed,
        release: &PluginRelease,
        package: Package,
        bytes: &[u8],
    ) {
        let _change = lock(&self.changing);
        let name = package.manifest.name.clone();
        let Some(fresh) = self.still(port, snapshot) else {
            return self.failed(name, "the port changed meanwhile".to_owned());
        };
        if !self.still_replacing(port, release) {
            info!(port, plugin = %release.id, version = %release.version, "the catalog no longer offers the port's replacement; nothing is replaced");
            return self.failed(
                name,
                "the catalog no longer offers this replacement, or updates are off".to_owned(),
            );
        }
        let port_ran = fresh.enabled && !fresh.withdrawn;
        self.cfg.modules.unload(port);
        let loaded = if fresh.enabled {
            self.cfg.modules.load(package.clone())
        } else {
            self.cfg.modules.check(&package)
        };
        if let Err(e) = loaded {
            warn!(port, plugin = %release.id, error = %e, "cannot load the port's replacement; the port stays");
            if port_ran {
                let _ = self.load_installed(port);
            }
            self.refused(&release.id, &release.version, &e);
            // No window for an older version meanwhile: the whole plugin waits.
            lock(&self.conflicts)
                .entry(release.id.clone())
                .or_default()
                .insert(release.version.clone());
            return self.failed(name, e.to_string());
        }
        if let Err(e) = self
            .store
            .replace(port, &package, bytes, release.publisher.as_ref())
        {
            warn!(port, plugin = %release.id, error = %e, "cannot record the port's replacement; the port stays");
            self.cfg.modules.unload(&release.id);
            if port_ran {
                let _ = self.load_installed(port);
            }
            return self.failed(name, e.to_string());
        }
        info!(port, plugin = %release.id, version = %release.version, "the port is replaced by the publisher's plugin");
        let port_name = self.name_of(port);
        lock(&self.errors).remove(port);
        lock(&self.known).remove(port);
        lock(&self.pending).remove(port);
        lock(&self.conflicts).clear();
        self.remember(&package);
        lock(&self.errors).remove(&release.id);
        lock(&self.needed).remove(&release.id);
        (self.cfg.notify)(PluginNotice::PortReplaced {
            port: port_name,
            name,
        });
    }

    /// «Не сейчас», or the replacement window closed: the port runs on, and `plugin` is not
    /// offered for it again but from its row in the plugin window.
    fn decline_replacement(&self, port: &str, plugin: &str) {
        let _change = lock(&self.changing);
        if !self.store.state().plugins.contains_key(port) {
            return;
        }
        info!(
            port,
            plugin, "the user declined the port's replacement; it is not offered again"
        );
        if let Err(e) = self.store.set_declined_replacement(port, Some(plugin)) {
            warn!(port, plugin, error = %e, "cannot record the declined replacement");
        }
    }

    /// Drops the update of `id` waiting for the user unless it is of `release`, the
    /// catalog's choice now.
    fn drop_pending_unless(&self, id: &str, release: Option<&PluginRelease>) {
        let mut pending = lock(&self.pending);
        let current = pending.get(id).is_some_and(|p| {
            release.is_some_and(|r| {
                p.release.version == r.version && p.release.package.sha256 == r.package.sha256
            })
        });
        if !current && pending.remove(id).is_some() {
            info!(
                plugin = id,
                "the update waiting for the user is no longer the catalog's choice"
            );
        }
    }

    /// Turns the installed `id` (`snapshot`) back on if it is withdrawn and the catalog
    /// lists its version not revoked. Whether it settled (not changed meanwhile, recorded).
    fn unwithdraw(&self, catalog: &oncl_update::Catalog, id: &str, snapshot: &Installed) -> bool {
        let listed = catalog
            .releases()
            .any(|r| r.id == *id && r.version == snapshot.version && !r.revoked);
        if !(snapshot.withdrawn && listed) {
            return true;
        }
        let _change = lock(&self.changing);
        let Some(fresh) = self.still(id, snapshot) else {
            return false;
        };
        info!(plugin = %id, "the plugin's version is no longer revoked");
        if let Err(e) = self.store.set_withdrawn(id, false) {
            warn!(plugin = %id, error = %e, "cannot record the plugin's state");
            return false;
        }
        if fresh.enabled {
            let _ = self.load_installed(id);
        }
        true
    }

    /// The publisher of the installed `id` (`snapshot`, none recorded) by the prefixes of
    /// `catalog`'s `publishers.json`, recorded if the plugin is still `snapshot`. A plugin of
    /// the owner's index, or one no prefix covers, has none.
    fn restore_publisher(
        &self,
        catalog: &oncl_update::Catalog,
        id: &str,
        snapshot: &Installed,
    ) -> Option<PublisherName> {
        let publisher = catalog.publisher_of(id)?.clone();
        let _change = lock(&self.changing);
        self.still(id, snapshot)?;
        info!(plugin = id, %publisher, "the plugin's publisher is restored from its prefix");
        if let Err(e) = self.store.set_publisher(id, Some(publisher.clone())) {
            warn!(plugin = id, error = %e, "cannot record the plugin's publisher");
        }
        Some(publisher)
    }

    /// Turns the installed `id` (`snapshot`) off: its version is revoked, or its publisher
    /// (`publisher`, its display name) is. Told once: a plugin withdrawn already is left as
    /// it is. Whether it settled (not changed meanwhile, recorded).
    fn withdraw(&self, id: &str, snapshot: &Installed, publisher: Option<Localized>) -> bool {
        if snapshot.withdrawn {
            // Told already; whatever loaded it meanwhile, it does not run.
            let _change = lock(&self.changing);
            if self
                .still(id, snapshot)
                .is_some_and(|fresh| fresh.withdrawn)
            {
                self.cfg.modules.unload(id);
            }
            return true;
        }
        let _change = lock(&self.changing);
        if self.still(id, snapshot).is_none() {
            return false;
        }
        match &publisher {
            Some(publisher) => {
                warn!(plugin = %id, publisher = %publisher.en, "the plugin's publisher is revoked; it is turned off");
            }
            None => {
                warn!(plugin = %id, version = %snapshot.version, "the plugin's version is revoked; it is turned off");
            }
        }
        self.cfg.modules.unload(id);
        lock(&self.conflicts).clear();
        let recorded = self.store.set_withdrawn(id, true);
        if let Err(e) = &recorded {
            warn!(plugin = %id, error = %e, "cannot record the plugin's state");
        }
        let name = self.name_of(id);
        (self.cfg.notify)(match publisher {
            Some(publisher) => PluginNotice::PublisherRevoked { name, publisher },
            None => PluginNotice::Withdrawn { name },
        });
        recorded.is_ok()
    }

    /// The installed `id` as it is now, if it is still `snapshot`'s: from the catalog, at
    /// the same version. Call it holding `changing`.
    fn still(&self, id: &str, snapshot: &Installed) -> Option<Installed> {
        let fresh = self.store.state().plugins.get(id).cloned();
        let same = fresh
            .as_ref()
            .is_some_and(|f| f.source == Source::Catalog && f.version == snapshot.version);
        if !same {
            info!(
                plugin = id,
                "the plugin changed meanwhile; the catalog leaves it alone"
            );
        }
        fresh.filter(|_| same)
    }

    /// Installs `release` over `snapshot`, the version installed when it was chosen:
    /// downloaded and checked, then, under `changing` and only if the plugin is still
    /// `snapshot`, loaded (if it is on; else checked only) and recorded. A release whose
    /// capabilities go beyond the installed version's is not installed: it waits for the
    /// user ([`PluginService::confirm_update`]), told once, and the installed version runs on
    /// unless it is revoked ([`PluginService::apply_index`] turns it off meanwhile).
    /// What came of it.
    fn update_to(&self, release: &PluginRelease, snapshot: &Installed) -> Updated {
        let waiting = lock(&self.pending).get(&release.id).is_some_and(|p| {
            p.release.version == release.version && p.snapshot.version == snapshot.version
        });
        if waiting {
            return Updated::StillWaiting;
        }
        info!(plugin = %release.id, version = %release.version, "updating the plugin");
        let (package, bytes) = match self.download(release) {
            Ok(downloaded) => downloaded,
            Err(Download::Unreachable(e)) => {
                // Quietly: the next check tries again.
                warn!(plugin = %release.id, error = %e, "cannot download the plugin's update");
                return Updated::Failed;
            }
            Err(Download::Bad(e)) => {
                self.bad(release, e);
                return Updated::Failed;
            }
        };
        let added = self.added_over_installed(&package.manifest);
        if added.is_empty() {
            return match self.install_update(release, package, &bytes, snapshot) {
                Ok(()) => Updated::Installed,
                Err(_) => Updated::Failed,
            };
        }
        let _change = lock(&self.changing);
        if self.still(&release.id, snapshot).is_none() {
            return Updated::Failed;
        }
        info!(plugin = %release.id, version = %release.version, ?added, "the plugin's update asks for more; it waits for the user");
        let notice = PluginNotice::UpdateNeedsConfirmation {
            name: package.manifest.name.clone(),
            version: release.version.clone(),
        };
        lock(&self.pending).insert(
            release.id.clone(),
            PendingUpdate {
                release: release.clone(),
                package,
                bytes,
                snapshot: snapshot.clone(),
                added,
            },
        );
        (self.cfg.notify)(notice);
        Updated::NowWaiting
    }

    /// Installs the update of `id` waiting for the user ([`PluginNotice::UpdateNeedsConfirmation`]):
    /// the user has seen what more it may do and agrees. `expected_sha256` is the package
    /// the user was shown ([`PendingView::package_sha256`]): a newer update that took its
    /// place meanwhile is not installed unseen.
    ///
    /// # Errors
    ///
    /// No update of `id` waits ([`PluginActionError::NothingToConfirm`]); another package
    /// waits than the one shown ([`PluginActionError::Superseded`], it stays waiting); updates
    /// are off ([`PluginActionError::UpdatesOff`], it stays waiting); the catalog in use no longer chooses it (revoked, marked
    /// bad, another version: dropped, [`PluginActionError::NothingToConfirm`]); or it failed
    /// (also told in the tray); the plugin changed meanwhile: nothing is done.
    pub fn confirm_update(&self, id: &str, expected_sha256: &str) -> Result<(), PluginActionError> {
        if !self.update_settings().enabled {
            info!(
                plugin = id,
                "updates are off; the plugin's update keeps waiting"
            );
            return Err(PluginActionError::UpdatesOff);
        }
        let pending = {
            let mut waiting = lock(&self.pending);
            match waiting.get(id) {
                None => return Err(PluginActionError::NothingToConfirm),
                Some(p) if p.release.package.sha256.to_string() != expected_sha256 => {
                    return Err(PluginActionError::Superseded);
                }
                Some(_) => {}
            }
            waiting
                .remove(id)
                .ok_or(PluginActionError::NothingToConfirm)?
        };
        if !self.still_chosen(&pending.release) {
            info!(plugin = id, version = %pending.release.version, "the catalog no longer chooses the plugin's update; dropped");
            return Err(PluginActionError::NothingToConfirm);
        }
        info!(plugin = id, version = %pending.release.version, "the user agrees to the plugin's update");
        self.install_update(
            &pending.release,
            pending.package,
            &pending.bytes,
            &pending.snapshot,
        )
        .map_err(PluginActionError::Failed)
    }

    /// Whether the catalog in use still chooses `release` for the plugin installed: the
    /// version installed, its publisher and the versions bad here as they are now.
    fn still_chosen(&self, release: &PluginRelease) -> bool {
        let Some(in_use) = self.valid_catalog() else {
            return false;
        };
        let state = self.store.state();
        let Some(installed) = state.plugins.get(&release.id) else {
            return false;
        };
        let mut bad = state.bad.get(&release.id).cloned().unwrap_or_default();
        bad.extend(
            lock(&self.conflicts)
                .get(&release.id)
                .into_iter()
                .flatten()
                .cloned(),
        );
        matches!(
            choose_installed(
                &in_use.catalog,
                &release.id,
                installed.publisher.as_ref(),
                &installed.version,
                &self.cfg.core,
                &state.install_id,
                &bad,
            ),
            PluginChoice::Update(chosen) | PluginChoice::Downgrade(chosen)
                if chosen.version == release.version
                    && chosen.package.sha256 == release.package.sha256
        )
    }

    /// What the manual-tools window may offer of the plugins installed now: the registry
    /// and the list ([`manual::ManualPlugins`]). Built from the store under the lock that
    /// installs and updates, so it never sees a plugin half-replaced.
    pub fn manual_plugins(&self) -> manual::ManualPlugins {
        let _change = lock(&self.changing);
        manual::ManualPlugins::build(&self.store)
    }

    /// What `new` asks for over the installed plugin of its id: capabilities and
    /// `[[operations]]` ([`Manifest::added_over`]). An installed package that cannot be read
    /// counts as one that may do nothing: everything `new` asks for waits for the user.
    fn added_over_installed(&self, new: &Manifest) -> Added {
        let id = &new.id;
        let known = lock(&self.known).get(id).map(|k| k.manifest.clone());
        let old = known.or_else(|| match self.store.load_package(id) {
            Ok(package) => {
                self.remember(&package);
                Some(package.manifest)
            }
            Err(e) => {
                warn!(plugin = %id, error = %e, "cannot read the installed plugin");
                None
            }
        });
        match old {
            Some(old) => new.added_over(&old),
            None => Added {
                capabilities: new.capabilities.added_over(&Capabilities::default()),
                operations: new
                    .operations()
                    .iter()
                    .map(|o| AddedOperation {
                        name: o.name().to_owned(),
                        reasons: vec![AddedReason::New],
                    })
                    .collect(),
            },
        }
    }

    /// The rest of [`PluginService::update_to`]: `package` of `release` installed over
    /// `snapshot`, under `changing`, if the plugin is still `snapshot`. Why not, if it was
    /// not.
    fn install_update(
        &self,
        release: &PluginRelease,
        package: Package,
        bytes: &[u8],
        snapshot: &Installed,
    ) -> Result<(), String> {
        let _change = lock(&self.changing);
        let Some(fresh) = self.still(&release.id, snapshot) else {
            return Err("the plugin changed meanwhile".to_owned());
        };
        let enabled = fresh.enabled;
        let loaded = if enabled {
            self.cfg.modules.load(package.clone())
        } else {
            self.cfg.modules.check(&package)
        };
        if let Err(e) = loaded {
            self.refused(&release.id, &release.version, &e);
            self.failed(localized(&release.name), e.to_string());
            return Err(e.to_string());
        }
        if let Err(e) =
            self.store
                .install(&package, bytes, Source::Catalog, release.publisher.as_ref())
        {
            warn!(plugin = %release.id, error = %e, "cannot record the plugin's update");
            if enabled && !fresh.withdrawn {
                // The version recorded runs again.
                let _ = self.load_installed(&release.id);
            } else {
                // Off, or withdrawn (a revoked version waiting for this one): nothing runs.
                self.cfg.modules.unload(&release.id);
            }
            self.failed(localized(&release.name), e.to_string());
            return Err(e.to_string());
        }
        self.remember(&package);
        lock(&self.errors).remove(&release.id);
        lock(&self.conflicts).clear();
        lock(&self.pending).remove(&release.id);
        (self.cfg.notify)(PluginNotice::Updated {
            name: package.manifest.name.clone(),
            version: package.manifest.version.clone(),
        });
        Ok(())
    }

    /// Downloads the package of `release` and checks it against the index and this core.
    fn download(&self, release: &PluginRelease) -> Result<(Package, Vec<u8>), Download> {
        let package = &release.package;
        if !package.url.starts_with("https://") {
            return Err(Download::Bad(format!(
                "{} is not an https URL",
                package.url
            )));
        }
        let bytes = fetch_package(&*self.cfg.http, package, DOWNLOAD_TIMEOUT)
            .map_err(Download::Unreachable)?;
        if bytes.len() as u64 != package.size {
            return Err(Download::Bad(format!(
                "{}: {} bytes, the index says {}",
                package.url,
                bytes.len(),
                package.size
            )));
        }
        if Sha256::of(&bytes) != package.sha256 {
            return Err(Download::Bad(format!(
                "{}: the sha256 does not match the index",
                package.url
            )));
        }
        let read = Package::read(&bytes).map_err(|e| Download::Bad(e.to_string()))?;
        check_manifest(&read, release, &self.cfg.core).map_err(Download::Bad)?;
        Ok((read, bytes))
    }

    /// Asks the user about `package` (released as `origin_kind` says); installs it if they
    /// agree: `release` of the catalog (with its publisher), or a file the user chose (none).
    fn ask(
        self: &Arc<Self>,
        package: Package,
        bytes: Vec<u8>,
        release: Option<PluginRelease>,
        origin: Option<String>,
        origin_kind: ReleaseOrigin,
        guard: Installing,
    ) {
        let m = &package.manifest;
        let replacing = self.store.state().plugins.get(&m.id).map(|installed| {
            let catalog = self.valid_catalog().map(|in_use| in_use.catalog);
            (
                installed.version.clone(),
                installed_origin(catalog.as_deref(), &m.id, installed),
            )
        });
        let added = replacing.is_some().then(|| self.added_over_installed(m));
        let request = InstallRequest {
            origin,
            name: m.name.clone(),
            version: m.version.clone(),
            replaces: m.replaces.clone(),
            replacing,
            capabilities: m.capabilities.clone(),
            operations: m.operation_consents(added.as_ref()),
            origin_kind,
            replaces_port: None,
        };
        let service = Arc::downgrade(self);
        self.cfg.ui.confirm(
            request,
            Box::new(move |yes| {
                let _guard = guard;
                let Some(service) = service.upgrade() else {
                    return;
                };
                if yes {
                    service.finish_install(package, &bytes, release.as_ref());
                } else {
                    info!(plugin = %package.manifest.id, "the user declined the plugin");
                }
            }),
        );
    }

    /// Loads `package`, then records it: of `release` of the catalog, or from a file (none).
    /// A release of the catalog is installed only if the catalog in use still offers it
    /// as it was shown ([`PluginService::still_offered`]); else nothing changes.
    fn finish_install(&self, package: Package, bytes: &[u8], release: Option<&PluginRelease>) {
        let _change = lock(&self.changing);
        let id = package.manifest.id.clone();
        let name = package.manifest.name.clone();
        if let Some(release) = release
            && !self.still_offered(release)
        {
            info!(plugin = %id, version = %release.version, "the catalog no longer offers the plugin as it was shown; not installed");
            return self.failed(name, "the catalog no longer offers this plugin".to_owned());
        }
        let source = if release.is_some() {
            Source::Catalog
        } else {
            Source::Local
        };
        let publisher = release.and_then(|r| r.publisher.as_ref());
        if let Err(e) = self.cfg.modules.load(package.clone()) {
            warn!(plugin = %id, error = %e, "cannot load the plugin");
            if source == Source::Catalog {
                self.refused(&id, &package.manifest.version, &e);
            }
            return self.failed(name, e.to_string());
        }
        if let Err(e) = self.store.install(&package, bytes, source, publisher) {
            warn!(plugin = %id, error = %e, "cannot record the plugin");
            self.cfg.modules.unload(&id);
            // The version installed before, if any, runs again.
            if self.store.state().plugins.contains_key(&id) {
                let _ = self.load_installed(&id);
            }
            return self.failed(name, e.to_string());
        }
        if self
            .store
            .state()
            .plugins
            .get(&id)
            .is_some_and(|installed| !installed.enabled)
        {
            // Installed again over one turned off: it stays off.
            self.cfg.modules.unload(&id);
        }
        info!(plugin = %id, version = %package.manifest.version, ?source, "plugin installed");
        lock(&self.conflicts).clear();
        lock(&self.pending).remove(&id);
        self.remember(&package);
        lock(&self.errors).remove(&id);
        lock(&self.needed).remove(&id);
        (self.cfg.notify)(PluginNotice::Installed { name });
    }

    /// Loads the installed `id` from its package; a failure is kept for the plugin window.
    fn load_installed(&self, id: &str) -> Result<(), String> {
        let loaded = self
            .store
            .load_package(id)
            .map_err(|e| e.to_string())
            .and_then(|package| {
                self.remember(&package);
                if package.manifest.min_core > self.cfg.core {
                    return Err(format!(
                        "the plugin needs OpenNCALayer {} or newer",
                        package.manifest.min_core
                    ));
                }
                self.cfg.modules.load(package).map_err(|e| e.to_string())
            });
        match &loaded {
            Ok(()) => {
                lock(&self.errors).remove(id);
            }
            Err(e) => {
                warn!(plugin = id, error = %e, "cannot load the installed plugin");
                lock(&self.errors).insert(id.to_owned(), e.clone());
            }
        }
        loaded
    }

    /// Reads the installed `id`'s name from its package, for the plugin window.
    fn read_known(&self, id: &str) {
        match self.store.load_package(id) {
            Ok(package) => self.remember(&package),
            Err(e) => {
                warn!(plugin = id, error = %e, "cannot read the installed plugin");
                lock(&self.errors).insert(id.to_owned(), e.to_string());
            }
        }
    }

    fn remember(&self, package: &Package) {
        lock(&self.known).insert(
            package.manifest.id.clone(),
            Known {
                name: package.manifest.name.clone(),
                replaces: package.manifest.replaces.clone(),
                manifest: package.manifest.clone(),
            },
        );
    }

    fn name_of(&self, id: &str) -> Localized {
        lock(&self.known)
            .get(id)
            .map_or_else(|| same_name(id), |k| k.name.clone())
    }

    /// `id` marked as being installed, until the returned guard goes; `None` if it is
    /// already.
    fn begin_install(self: &Arc<Self>, id: &str) -> Option<Installing> {
        if !lock(&self.installing).insert(id.to_owned()) {
            info!(plugin = id, "being installed already");
            return None;
        }
        Some(Installing {
            service: Arc::downgrade(self),
            id: id.to_owned(),
        })
    }

    /// `release` failed its checks here: marked bad, the user told.
    fn bad(&self, release: &PluginRelease, error: String) {
        self.mark_bad(release, &error);
        self.failed(localized(&release.name), error);
    }

    /// `release` failed its checks here: marked bad.
    fn mark_bad(&self, release: &PluginRelease, error: &str) {
        self.mark_version_bad(&release.id, &release.version, error);
    }

    fn mark_version_bad(&self, id: &str, version: &Version, error: &str) {
        warn!(plugin = id, %version, error = %error, "the plugin's package is refused; the version is marked bad");
        if let Err(e) = self.store.mark_bad(id, version) {
            warn!(plugin = id, error = %e, "cannot record the plugin's failure");
        }
    }

    /// The catalog's `version` of `id` could not be loaded (or checked): marked bad if the
    /// package is at fault; if another plugin serves one of its modules, which depends on
    /// this installation and not on the package, only kept from updates until the plugins
    /// change.
    fn refused(&self, id: &str, version: &Version, e: &LoadError) {
        if matches!(e, LoadError::ModuleTaken { owner, .. } if owner != BUILT_IN) {
            warn!(plugin = id, %version, error = %e, "another plugin serves a module of the plugin; the version is not marked bad");
            lock(&self.conflicts)
                .entry(id.to_owned())
                .or_default()
                .insert(version.clone());
        } else {
            self.mark_version_bad(id, version, &e.to_string());
        }
    }

    /// The install of `id` failed: told, but for one a page started only if no failure of
    /// `id`'s was told within [`PAGE_FAILURE_EVERY`] (a page may ask again and again).
    fn install_failed(&self, id: &str, name: Localized, error: String, asker: Asker) {
        if asker == Asker::Page {
            let mut told = lock(&self.page_failures);
            if told
                .get(id)
                .is_some_and(|at| at.elapsed() < PAGE_FAILURE_EVERY)
            {
                info!(plugin = id, error = %error, "a page's install of the plugin failed again; told already");
                return;
            }
            told.insert(id.to_owned(), Instant::now());
        }
        self.failed(name, error);
    }

    fn failed(&self, name: Localized, error: String) {
        (self.cfg.notify)(PluginNotice::Failed { name, error });
    }

    fn update_settings(&self) -> UpdateSettings {
        load_settings(&self.cfg.settings).updates
    }
}

/// A plugin being installed: [`PluginService::begin_install`].
struct Installing {
    service: Weak<PluginService>,
    id: String,
}

impl Drop for Installing {
    fn drop(&mut self) {
        if let Some(service) = self.service.upgrade() {
            lock(&service.installing).remove(&self.id);
        }
    }
}

/// Whether `package`'s manifest is the one `release` describes, for `core`: for a
/// publisher's release also the capabilities its role declares (`custom.oncl.capabilities`),
/// read by the rules of the manifest's own.
fn check_manifest(
    package: &Package,
    release: &PluginRelease,
    core: &Version,
) -> Result<(), String> {
    let m = &package.manifest;
    let differs = |what: &str| Err(format!("the package's {what} differs from the index"));
    if m.id != release.id {
        return differs("id");
    }
    if m.version != release.version {
        return differs("version");
    }
    if m.modules != release.modules {
        return differs("modules");
    }
    let replaces = m.replaces.as_ref().map(|r| (&r.symname, &r.version));
    let listed = release.replaces.as_ref().map(|r| (&r.symname, &r.version));
    if replaces != listed {
        return differs("replaces");
    }
    if let Some(declared) = &release.capabilities {
        let declared = Capabilities::try_from(declared)
            .map_err(|e| format!("the catalog's capabilities cannot be read: {e}"))?;
        if m.capabilities != declared {
            return differs("capabilities");
        }
    }
    if m.min_core > *core {
        return Err(format!(
            "the plugin needs OpenNCALayer {} or newer",
            m.min_core
        ));
    }
    Ok(())
}

/// The package file at `path` and its bytes.
fn read_package(path: &Path) -> Result<(Package, Vec<u8>), String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_PACKAGE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let package = Package::read(&bytes).map_err(|e| e.to_string())?;
    Ok((package, bytes))
}

fn localized(name: &PluginName) -> Localized {
    Localized {
        ru: name.ru.clone(),
        kk: name.kk.clone(),
        en: name.en.clone(),
    }
}

fn replaces_of(release: &PluginRelease) -> Option<Replaces> {
    release.replaces.as_ref().map(|r| Replaces {
        symname: r.symname.clone(),
        version: r.version.clone(),
    })
}

/// `text` in every language: a name not known otherwise.
fn same_name(text: &str) -> Localized {
    Localized {
        ru: text.to_owned(),
        kk: text.to_owned(),
        en: text.to_owned(),
    }
}

/// The daemon's [`PluginConfig::offer_timeout`]: how long `installBundle` waits for the
/// catalog when none is in use.
pub const OFFER_TIMEOUT: Duration = Duration::from_secs(10);

impl Bundles for PluginService {
    fn services(&self) -> Vec<String> {
        self.cfg.modules.names()
    }

    fn bundles(&self) -> Vec<(String, String)> {
        self.cfg
            .modules
            .loaded()
            .into_iter()
            .filter_map(|plugin| plugin.replaces.map(|r| (r.symname, r.version)))
            .collect()
    }

    /// Looks in the catalog in use (downloaded within [`PluginConfig::offer_timeout`] if
    /// there is none) for a plugin porting `symname`; one not installed is installed in the
    /// background (the user is asked) and `true` returned. The replacement of an installed
    /// port (off, withdrawn or failed) is not: the plugin window offers it from the port.
    fn request_install(&self, symname: &str, origin: &str) -> bool {
        let Some(release) = self.catalog_offer_for_symname(symname, self.cfg.offer_timeout) else {
            return false;
        };
        let state = self.store.state();
        let installed = state.plugins.contains_key(&release.id)
            || self.cfg.modules.loaded().iter().any(|p| {
                p.id == release.id || p.replaces.as_ref().is_some_and(|r| r.symname == symname)
            });
        if installed {
            return false;
        }
        if let Some(in_use) = self.valid_catalog()
            && self.replaces_installed_port(&in_use.catalog, &state, &release.id)
        {
            info!(plugin = %release.id, "a page asks for the replacement of an installed port; it is offered from the port");
            return false;
        }
        if lock(&self.installing).contains(&release.id) {
            // Going on already: the page's request is served by it.
            info!(plugin = %release.id, "being installed already");
            return true;
        }
        let Some(service) = self.me.upgrade() else {
            return false;
        };
        let origin = origin.to_owned();
        let spawned = thread::Builder::new()
            .name("plugin-install".into())
            .spawn(move || service.install_from_catalog(&release.id, Some(origin)));
        match spawned {
            Ok(_) => true,
            Err(e) => {
                warn!(error = %e, "cannot start a thread: the plugin is not installed");
                false
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub mod catalog;
pub mod manual;
pub mod window;

#[cfg(test)]
mod tests;
