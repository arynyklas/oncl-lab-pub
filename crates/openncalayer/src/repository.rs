//! The update repository: the one TUF client, over one state directory
//! (`<data>/update/tuf/`), through which the updater ([`crate::update`]) and the plugin
//! catalog ([`crate::plugins`]) read the update index of a channel.
//!
//! The index is the target `indexes/<channel>.json` of the repository
//! ([`Channel::target_path`]); the client verifies the chain from the root built in
//! (`keys/root.json`, [`oncl_update::embedded_root`]) to the bytes, and what is kept of that
//! (the roots followed, the versions accepted, the targets file) is the state both consumers
//! share, saved under a lock of the directory and merged so that neither loses the other's
//! versions. A build without a root has no [`Repository`]: updates are off for both.
//!
//! The plugin catalog also reads the publishers' side of the repository
//! ([`Repository::catalog`], `docs/design/publishers.md`): `publishers.json` among the
//! top-level targets and the publishers' delegated roles ([`TufClient::delegated`]). Their
//! bytes are kept by the plugin store and checked again offline here
//! ([`Repository::verify_kept_publishers`], [`Repository::verify_kept_role`],
//! [`Repository::kept_top_level`]).
//!
//! What the consumers get is the index (its `seq` and channel checked by [`Index::accept`]
//! against the `last_seq` they pass), its bytes, and until when the metadata that vouches for
//! it holds. Every failure is an [`UpdateError`] ([`UpdateError::from_tuf`]) and is logged
//! here, once: a repository that is not published or cannot be read at `info`, one that is
//! refused (an expired or rolled-back role, a signature, a hash) at `warn`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use oncl_pki::http::HttpTransport;
use oncl_update::tuf::{
    Delegated, Fetcher, FileStore, HttpFetcher, Limits, Profile, Response, RoleName, Store, Target,
    TargetPath, Targets, Trusted, TufClient, TufError, VerifiedRole, layout, model::TARGETS_META,
};
use oncl_update::{Channel, Index, MAX_INDEX_LEN, PublisherPolicy, UpdateError};
use time::OffsetDateTime;
use tracing::{info, warn};

/// An index the repository vouches for.
#[derive(Clone, Debug)]
pub struct VerifiedIndex {
    /// The index, read from `bytes`.
    pub index: Index,
    /// The bytes as the repository has them (what the plugin store keeps and checks again).
    pub bytes: Vec<u8>,
    /// When the root or the targets metadata that vouches for the index expires: the index is
    /// not used after it without a new refresh.
    pub valid_until: OffsetDateTime,
}

/// What [`Repository::catalog`] read.
#[derive(Debug)]
pub enum CatalogRead {
    /// The repository's snapshot is the version the caller named: nothing else was read.
    Unchanged,
    /// The catalog as the repository has it now.
    Read(Box<VerifiedCatalog>),
}

/// The plugin catalog the repository vouches for: the owner's index and the publishers'
/// side, each part on its own (an unavailable part leaves its publishers unavailable).
#[derive(Debug)]
pub struct VerifiedCatalog {
    /// The owner's index.
    pub index: VerifiedIndex,
    /// The version of the snapshot it was read under.
    pub snapshot: u64,
    /// The top-level targets.
    pub top_level: BTreeMap<TargetPath, Target>,
    /// `publishers.json`'s bytes: `None` if the top-level targets list none; `Err` why it
    /// could not be downloaded or verified.
    pub publishers: Result<Option<Vec<u8>>, String>,
    /// The delegated roles; `Err` why the delegations could not be read (every publisher
    /// is unavailable).
    pub roles: Result<Delegated, String>,
}

/// The top-level targets saved by the last refresh, as checked offline
/// ([`Repository::kept_top_level`]).
#[derive(Debug)]
pub struct KeptTopLevel {
    /// The targets file.
    pub targets: Targets,
    /// When it, or the root in force, stops being trusted.
    pub valid_until: OffsetDateTime,
}

/// The repository's files over HTTPS, all of one call within one deadline.
struct DeadlineFetcher {
    transport: Arc<dyn HttpTransport>,
    base: String,
    deadline: Mutex<Instant>,
}

impl Fetcher for DeadlineFetcher {
    fn fetch(&self, path: &str, max_len: u64) -> Result<Response, TufError> {
        let deadline = *self.deadline.lock().unwrap_or_else(PoisonError::into_inner);
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(TufError::Fetch(format!("{path}: no time left")));
        }
        HttpFetcher::new(&*self.transport, &self.base)?
            .with_timeout(left)
            .fetch(path, max_len)
    }
}

/// What the offline checks read the repository with: nothing.
struct Offline;

impl Fetcher for Offline {
    fn fetch(&self, path: &str, _max_len: u64) -> Result<Response, TufError> {
        Err(TufError::Fetch(format!("{path}: offline")))
    }
}

/// The shared TUF client; see the [module](self).
///
/// One state directory and one trust anchor, two handles on them: the client that refreshes
/// (one refresh at a time, for as long as its requests take) and one that checks kept bytes
/// from the saved state alone, so that a page asking for the catalog never waits for a
/// download in progress.
pub struct Repository {
    client: Mutex<TufClient<DeadlineFetcher, FileStore>>,
    offline: TufClient<Offline, FileStore>,
    /// The last refusal of each part of the publishers' side (`publishers.json`, the
    /// delegations, each role), so that each is logged once, not at every check.
    refusals: Mutex<BTreeMap<String, String>>,
}

/// The time `publishers.json` and the publishers' roles get, on top of the index's: up to
/// 33 downloads of at most 1 MiB and 128 KiB.
pub const PUBLISHERS_TIMEOUT: Duration = Duration::from_secs(120);

impl Repository {
    /// The repository at `base` (`https://…/tuf/v1`) read through `transport` (the proxy of
    /// the settings), with its state in `<data_dir>/update/tuf/`, trusting the root built in.
    /// `None`, logged, if the build has no root or it is unusable: updates are off.
    pub fn open(
        data_dir: &Path,
        base: &str,
        transport: Arc<dyn HttpTransport>,
    ) -> Option<Arc<Repository>> {
        Repository::from_root(oncl_update::embedded_root(), data_dir, base, transport)
    }

    /// [`Repository::open`] for the root `root`, if there is one: none (nothing asked of the
    /// network), logged, is no root or a root that is not usable.
    pub fn from_root(
        root: Option<&[u8]>,
        data_dir: &Path,
        base: &str,
        transport: Arc<dyn HttpTransport>,
    ) -> Option<Arc<Repository>> {
        let Some(anchor) = root else {
            info!("the update trust root is not built into this build: updates are off");
            return None;
        };
        match Repository::with_anchor(anchor, data_dir, base, transport) {
            Ok(repository) => Some(Arc::new(repository)),
            Err(e) => {
                tracing::error!(error = %e, "the built-in update trust root is unusable: updates are off");
                None
            }
        }
    }

    /// [`Repository::open`] trusting `anchor`, the bytes of a root file, instead of the root
    /// built in.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Tuf`] if `anchor` is not a root signed by its own keys, or `base` is
    /// not an `https://` URL.
    pub fn with_anchor(
        anchor: &[u8],
        data_dir: &Path,
        base: &str,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Repository, UpdateError> {
        // The URL is checked once, here.
        HttpFetcher::new(&*transport, base).map_err(UpdateError::Tuf)?;
        let fetcher = DeadlineFetcher {
            transport,
            base: base.to_owned(),
            deadline: Mutex::new(Instant::now()),
        };
        let store = FileStore::in_data_dir(data_dir);
        // `delegations` in the top-level targets, whatever it is, is no concern of the
        // program's updates: the profile keeps it unread.
        let client = TufClient::new(anchor, fetcher, store.clone(), Limits::default())
            .map_err(UpdateError::Tuf)?
            .with_profile(Profile::Delegating);
        let offline = TufClient::new(anchor, Offline, store, Limits::default())
            .map_err(UpdateError::Tuf)?
            .with_profile(Profile::Delegating);
        Ok(Repository {
            client: Mutex::new(client),
            offline,
            refusals: Mutex::default(),
        })
    }

    /// Logs `error` of the part `part` of the publishers' side at `warn` if it is not the one
    /// logged last for it, else at `debug`; no error forgets the last one.
    fn tell_refusal(&self, part: &str, error: Option<&String>, what: &str) {
        let mut refusals = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        match error {
            None => {
                refusals.remove(part);
            }
            Some(error) if refusals.get(part) == Some(error) => {
                tracing::debug!(part, %error, "{what} (as before)");
            }
            Some(error) => {
                warn!(part, %error, "{what}");
                refusals.insert(part.to_owned(), error.clone());
            }
        }
    }

    /// The index of `channel`, refreshed and downloaded within `timeout` (all the requests
    /// of the call together): the metadata chain is verified, the target downloaded, checked
    /// against the targets metadata, and read ([`Index::accept`]: of this channel, `seq` not
    /// below `last_seq`).
    ///
    /// # Errors
    ///
    /// [`UpdateError::NotPublished`] for a repository or a channel that is not there,
    /// otherwise [`UpdateError::Tuf`] for the client's refusals and failures, and the errors
    /// of [`Index::accept`]. [`UpdateError::retry_soon`] says which are worth trying again
    /// soon.
    pub fn index(
        &self,
        channel: Channel,
        last_seq: Option<u64>,
        timeout: Duration,
    ) -> Result<VerifiedIndex, UpdateError> {
        let result = self.read(channel, timeout, |client, trusted, now| {
            download_index(client, trusted, channel, last_seq, now)
        });
        log_read(&result, channel);
        result
    }

    /// The plugin catalog of `channel`, read within `timeout` as [`Repository::index`]
    /// reads the index, unless the snapshot refreshed is version `unless_snapshot`: then
    /// nothing more is read ([`CatalogRead::Unchanged`]). Else the index, then the
    /// publishers' side: `publishers.json` (at most [`PublisherPolicy::MAX_LEN`] bytes) and
    /// the delegated roles ([`TufClient::delegated`]), within what is left of `timeout` or,
    /// if later, `publishers` from the end of the index's download ([`PUBLISHERS_TIMEOUT`]
    /// for a scheduled or the user's check; zero for a page, which keeps to its own time). A
    /// failure of the publishers' side is in the result, logged once until it changes, and
    /// fails nothing else.
    ///
    /// # Errors
    ///
    /// Those of [`Repository::index`].
    pub fn catalog(
        &self,
        channel: Channel,
        last_seq: Option<u64>,
        timeout: Duration,
        publishers: Duration,
        unless_snapshot: Option<u64>,
    ) -> Result<CatalogRead, UpdateError> {
        let side_budget = publishers;
        let result = self.read(channel, timeout, |client, trusted, now| {
            let snapshot = trusted.snapshot().version;
            if unless_snapshot == Some(snapshot) {
                return Ok(CatalogRead::Unchanged);
            }
            let index = download_index(client, trusted, channel, last_seq, now)?;
            // The publishers' side may have a time of its own: on a slow link the roles
            // would otherwise run out of the index's.
            {
                let mut deadline = client
                    .fetcher()
                    .deadline
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *deadline = (*deadline).max(Instant::now() + side_budget);
            }
            let publishers = match trusted.target(PublisherPolicy::TARGET) {
                None => Ok(None),
                Some(_) => client
                    .download_target(
                        trusted,
                        PublisherPolicy::TARGET,
                        PublisherPolicy::MAX_LEN as u64,
                        now,
                    )
                    .map(Some)
                    .map_err(|e| e.to_string()),
            };
            self.tell_refusal(
                PublisherPolicy::TARGET,
                publishers.as_ref().err(),
                "cannot read the publishers' rules; every publisher is unavailable",
            );
            let roles = client.delegated(trusted, now).map_err(|e| e.to_string());
            self.tell_refusal(
                "delegations",
                roles.as_ref().err(),
                "cannot read the publishers' delegations; every publisher is unavailable",
            );
            // The roles no longer delegated (or none, delegations unread) are forgotten.
            let delegated: Vec<String> = roles
                .as_ref()
                .map(|roles| roles.roles().map(|(role, _)| role.to_string()).collect())
                .unwrap_or_default();
            self.refusals
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retain(|part, _| !part.starts_with("pub-") || delegated.contains(part));
            if let Ok(roles) = &roles {
                for (role, verified) in roles.roles() {
                    let error = verified.err().map(ToString::to_string);
                    self.tell_refusal(
                        role.as_str(),
                        error.as_ref(),
                        "a publisher's role is refused; the publisher is unavailable",
                    );
                }
            }
            Ok(CatalogRead::Read(Box::new(VerifiedCatalog {
                index,
                snapshot,
                top_level: trusted.targets().targets.clone(),
                publishers,
                roles,
            })))
        });
        log_read(&result, channel);
        result
    }

    /// Refreshes the metadata within `timeout`, then `then`, the client still held.
    fn read<T>(
        &self,
        channel: Channel,
        timeout: Duration,
        then: impl FnOnce(
            &mut TufClient<DeadlineFetcher, FileStore>,
            &Trusted,
            OffsetDateTime,
        ) -> Result<T, UpdateError>,
    ) -> Result<T, UpdateError> {
        // The deadline counts from the call, the wait for a refresh running included: a caller
        // with ten seconds does not wait twenty for another's download and then take its own.
        let deadline = Instant::now() + timeout;
        let mut client = self.client_until(deadline)?;
        *client
            .fetcher()
            .deadline
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = deadline;
        let now = OffsetDateTime::now_utc();
        // Nothing accepted yet: a repository that is not there is not published (to this
        // client); once one was, a missing file is a refusal.
        let never_published = self
            .offline
            .store()
            .load()
            .map(|state| !state.ever_published)
            .unwrap_or(false);
        let trusted = client.refresh(now).map_err(|e| match e {
            TufError::NotFound(path)
                if never_published
                    && client.last_reset().is_none()
                    && path == layout::TIMESTAMP_PATH =>
            {
                UpdateError::NotPublished(channel)
            }
            e => UpdateError::from_tuf(e, channel),
        })?;
        then(&mut client, &trusted, now)
    }

    /// The refreshing client, once no other read holds it, or an error at `deadline`.
    fn client_until(
        &self,
        deadline: Instant,
    ) -> Result<MutexGuard<'_, TufClient<DeadlineFetcher, FileStore>>, UpdateError> {
        loop {
            match self.client.try_lock() {
                Ok(client) => return Ok(client),
                Err(TryLockError::Poisoned(e)) => return Ok(e.into_inner()),
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(UpdateError::Tuf(TufError::Fetch(
                            "another check of the update repository is running: no time left"
                                .to_owned(),
                        )));
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    /// Whether `bytes`, an index of `channel` kept from an earlier download, are what the
    /// targets metadata saved by the last refresh lists, still signed by the chain from the
    /// root built in and not expired at `now`, without the network
    /// ([`TufClient::verify_cached_target`]); and until when.
    ///
    /// # Errors
    ///
    /// Why not, in words.
    pub fn verify_kept(
        &self,
        channel: Channel,
        bytes: &[u8],
        now: OffsetDateTime,
    ) -> Result<OffsetDateTime, String> {
        self.offline
            .verify_cached_target(&channel.target_path(), bytes, now)
            .map_err(|e| e.to_string())
    }

    /// Whether `bytes`, a `publishers.json` kept from an earlier [`Repository::catalog`],
    /// are what the targets metadata saved by the last refresh lists, as
    /// [`Repository::verify_kept`] checks an index; and until when.
    ///
    /// # Errors
    ///
    /// Why not, in words.
    pub fn verify_kept_publishers(
        &self,
        bytes: &[u8],
        now: OffsetDateTime,
    ) -> Result<OffsetDateTime, String> {
        self.offline
            .verify_cached_target(PublisherPolicy::TARGET, bytes, now)
            .map_err(|e| e.to_string())
    }

    /// The file `bytes` of the delegated role `role` kept from an earlier
    /// [`Repository::catalog`], checked again without the network
    /// ([`TufClient::verify_cached_current_role`]).
    ///
    /// # Errors
    ///
    /// Why not, in words.
    pub fn verify_kept_role(
        &self,
        role: &RoleName,
        bytes: &[u8],
        now: OffsetDateTime,
    ) -> Result<VerifiedRole, String> {
        self.offline
            .verify_cached_current_role(role, bytes, now)
            .map_err(|e| e.to_string())
    }

    /// The top-level targets saved by the last refresh, checked again without the network
    /// ([`TufClient::verify_cached_top_level`]); `None` if none are saved.
    ///
    /// # Errors
    ///
    /// Why they do not hold, in words.
    pub fn kept_top_level(&self, now: OffsetDateTime) -> Result<Option<KeptTopLevel>, String> {
        self.offline
            .verify_cached_top_level(now)
            .map(|kept| {
                kept.map(|(targets, valid_until)| KeptTopLevel {
                    targets,
                    valid_until,
                })
            })
            .map_err(|e| e.to_string())
    }

    /// Whether the saved state has seen newer metadata than it has accepted: a timestamp
    /// that lists a newer snapshot than the one accepted, or a snapshot that lists newer
    /// targets than the ones accepted. A refresh that failed halfway leaves that: the
    /// repository has published something the saved state does not hold, and what the
    /// saved state vouches for may be what that publication withdrew.
    ///
    /// # Errors
    ///
    /// Why the saved state cannot be read.
    pub fn newer_metadata_seen(&self) -> Result<bool, String> {
        let state = self.offline.store().load().map_err(|e| e.to_string())?;
        let behind = |listed: Option<u64>, accepted: Option<u64>| match (listed, accepted) {
            (Some(listed), Some(accepted)) => listed > accepted,
            (Some(_), None) => true,
            (None, _) => false,
        };
        let listed_snapshot = state.timestamp.as_ref().map(|t| t.snapshot.version);
        let accepted_snapshot = state.snapshot.as_ref().map(|s| s.version);
        let listed_targets = state
            .snapshot
            .as_ref()
            .and_then(|s| s.meta.get(TARGETS_META).copied());
        Ok(behind(listed_snapshot, accepted_snapshot) || behind(listed_targets, state.targets))
    }
}

/// The index of `channel` among `trusted`'s targets, downloaded and accepted.
fn download_index(
    client: &TufClient<DeadlineFetcher, FileStore>,
    trusted: &Trusted,
    channel: Channel,
    last_seq: Option<u64>,
    now: OffsetDateTime,
) -> Result<VerifiedIndex, UpdateError> {
    let bytes = client
        .download_target(trusted, &channel.target_path(), MAX_INDEX_LEN, now)
        .map_err(|e| UpdateError::from_tuf(e, channel))?;
    let index = Index::accept(&bytes, channel, last_seq)?;
    Ok(VerifiedIndex {
        index,
        bytes,
        valid_until: trusted.root().expires.min(trusted.targets().expires),
    })
}

/// Logs a failed read of `channel`'s index, once.
fn log_read<T>(result: &Result<T, UpdateError>, channel: Channel) {
    match result {
        Ok(_) => {}
        Err(UpdateError::NotPublished(_)) => {
            info!(%channel, "the update repository has no index of the channel yet");
        }
        // A published repository that lost a file: refused, though tried again soon.
        Err(e @ UpdateError::Tuf(TufError::NotFound(_))) => {
            warn!(error = %e, %channel, "the update repository lost a file; trying again later");
        }
        Err(e) if e.retry_soon() => {
            info!(error = %e, %channel, "cannot read the update repository; trying again later");
        }
        Err(e) => warn!(error = %e, %channel, "the update index is refused"),
    }
}

#[cfg(test)]
pub(crate) mod tests;
