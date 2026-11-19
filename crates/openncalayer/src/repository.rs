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
//! What the consumers get is the index (its `seq` and channel checked by [`Index::accept`]
//! against the `last_seq` they pass), its bytes, and until when the metadata that vouches for
//! it holds. Every failure is an [`UpdateError`] ([`UpdateError::from_tuf`]) and is logged
//! here, once: a repository that is not published or cannot be read at `info`, one that is
//! refused (an expired or rolled-back role, a signature, a hash) at `warn`.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use oncl_pki::http::HttpTransport;
use oncl_update::tuf::{
    Fetcher, FileStore, HttpFetcher, Limits, Profile, Response, Store, TufClient, TufError, layout,
    model::TARGETS_META,
};
use oncl_update::{Channel, Index, MAX_INDEX_LEN, UpdateError};
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
}

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
        })
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
        let result = self.download(channel, last_seq, timeout);
        match &result {
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
        result
    }

    fn download(
        &self,
        channel: Channel,
        last_seq: Option<u64>,
        timeout: Duration,
    ) -> Result<VerifiedIndex, UpdateError> {
        // The deadline counts from the call, the wait for a refresh running included: a caller
        // with ten seconds does not wait twenty for another's download and then take its own.
        let deadline = Instant::now() + timeout;
        let mut client = loop {
            match self.client.try_lock() {
                Ok(client) => break client,
                Err(TryLockError::Poisoned(e)) => break e.into_inner(),
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
        };
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
        let of_channel = |e| UpdateError::from_tuf(e, channel);
        let trusted = client.refresh(now).map_err(|e| match e {
            TufError::NotFound(path)
                if never_published
                    && client.last_reset().is_none()
                    && path == layout::TIMESTAMP_PATH =>
            {
                UpdateError::NotPublished(channel)
            }
            e => of_channel(e),
        })?;
        let bytes = client
            .download_target(&trusted, &channel.target_path(), MAX_INDEX_LEN, now)
            .map_err(of_channel)?;
        let index = Index::accept(&bytes, channel, last_seq)?;
        Ok(VerifiedIndex {
            index,
            bytes,
            valid_until: trusted.root().expires.min(trusted.targets().expires),
        })
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

#[cfg(test)]
pub(crate) mod tests;
