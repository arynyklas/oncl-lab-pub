//! The plugin catalog in use (`docs/design/publishers.md`, «Каталог» and «Клиент»): the
//! owner's index and the publishers' side, built from what the repository read
//! ([`Repository::catalog`]) or, without the network, from the files the plugin store keeps,
//! each checked again against the saved TUF state; and how often it is checked («Когда
//! клиент проверяет каталог»).
//!
//! The publishers' side holds only what was verified: without a verified `publishers.json`
//! every publisher is unavailable ([`oncl_update::Catalog::owner`]); without readable
//! delegations every publisher is unavailable but the owner's revocations hold; a role that
//! is not verified leaves its publisher unavailable. Unavailable never revokes: the
//! publisher's plugins stay as they are.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use oncl_desktop::UpdateSettings;
use oncl_plugin::{Capabilities, Store};
use oncl_update::tuf::{Limits, RoleName, Target, TargetPath, VerifiedRole};
use oncl_update::{Channel, Index, PublisherPolicy};
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::repository::{Repository, VerifiedCatalog};
use crate::update::CHECK_EVERY;

/// The checks, this far apart, while a publisher's plugin is installed: a revocation
/// reaches it within hours (Р26). Otherwise [`CHECK_EVERY`].
pub const PUBLISHER_CHECK_EVERY: (Duration, Duration) =
    (Duration::from_secs(3600), Duration::from_secs(3 * 3600));

/// What an application of the catalog may do to the installed plugins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Apply {
    /// Updates are off (Р27, Р38): plugins are only turned off (a revoked version, a revoked
    /// publisher) or back on (a version no longer revoked); nothing is installed, updated or
    /// moved back.
    RevocationsOnly,
    /// Updates are on: the plugins move to the versions the catalog chooses.
    Full,
}

impl Apply {
    /// What an application asked for by the user («Проверить сейчас») or of a catalog read
    /// on demand may do: everything with updates on, the revocations alone with them off
    /// (Р38), whatever «Проверять отзывы плагинов».
    pub fn with_updates(enabled: bool) -> Apply {
        if enabled {
            Apply::Full
        } else {
            Apply::RevocationsOnly
        }
    }

    /// What the schedule checks the catalog for («Когда клиент проверяет каталог»):
    /// everything with updates on, the revocations alone with them off and
    /// [`UpdateSettings::check_revocations`] on, and `None` with both off: the schedule
    /// does not contact the repository at all then.
    pub fn scheduled(settings: &UpdateSettings) -> Option<Apply> {
        (settings.enabled || settings.check_revocations)
            .then(|| Apply::with_updates(settings.enabled))
    }
}

/// How far apart the scheduled checks are: [`PUBLISHER_CHECK_EVERY`] while a publisher's
/// plugin is installed, else [`CHECK_EVERY`]. The same with updates on or off.
pub fn check_every(publisher_plugin: bool) -> (Duration, Duration) {
    if publisher_plugin {
        PUBLISHER_CHECK_EVERY
    } else {
        CHECK_EVERY
    }
}

/// A catalog in use.
#[derive(Clone, Debug)]
pub struct InUse {
    pub catalog: Arc<oncl_update::Catalog>,
    /// Until when everything it was built from holds: the index, `publishers.json` and the
    /// roles used. After it the catalog is built again from the kept files.
    pub valid_until: OffsetDateTime,
    /// The snapshot it was read under, if the repository brought all of it (no part of the
    /// publishers' side failed to download or verify): a check that finds this snapshot
    /// again need not read it again. `None` for a catalog built from the kept files.
    pub whole_at: Option<u64>,
}

/// The catalog `read` brings: its parts kept in `store` (the index first: a catalog whose
/// index is not kept is not used), then built. A `publishers.json` that could not be
/// downloaded is taken from the store if the bytes kept are the ones the targets now list.
///
/// # Errors
///
/// Why the index could not be kept.
pub fn from_read(
    read: VerifiedCatalog,
    channel: Channel,
    store: &Store,
    repository: &Repository,
    builtin: impl IntoIterator<Item = String>,
) -> Result<InUse, String> {
    let VerifiedCatalog {
        index,
        snapshot,
        top_level,
        publishers,
        roles,
    } = read;
    store.save_catalog(channel, &index.bytes).map_err(|e| {
        warn!(error = %e, "cannot keep the plugin catalog");
        e.to_string()
    })?;
    let mut whole = true;
    let publishers = match publishers {
        Ok(Some(bytes)) => {
            if let Err(e) = store.save_publishers(&bytes) {
                warn!(error = %e, "cannot keep the publishers' rules");
            }
            Some(bytes)
        }
        Ok(None) => None,
        Err(_) => {
            whole = false;
            let now = OffsetDateTime::now_utc();
            store
                .load_publishers(|bytes| repository.verify_kept_publishers(bytes, now))
                .map(|(bytes, _)| bytes)
        }
    };
    let roles = match roles {
        Ok(delegated) => {
            let mut keep = BTreeSet::new();
            let mut listed = Vec::new();
            for (role, verified) in delegated.roles() {
                keep.insert(role.clone());
                match verified {
                    Ok(verified) => {
                        if let Err(e) = store.save_role(role, verified.file()) {
                            warn!(%role, error = %e, "cannot keep a publisher's role");
                        }
                        listed.push((role.clone(), Some(verified.clone())));
                    }
                    Err(_) => {
                        whole = false;
                        listed.push((role.clone(), None));
                    }
                }
            }
            if let Err(e) = store.prune_roles(&keep) {
                warn!(error = %e, "cannot remove the roles no longer delegated");
            }
            Some(listed)
        }
        Err(_) => {
            whole = false;
            None
        }
    };
    let valid_until = earliest(index.valid_until, roles.as_deref());
    let catalog = build(
        index.index,
        &top_level,
        publishers.as_deref(),
        roles.as_deref(),
        builtin,
    );
    Ok(InUse {
        catalog: Arc::new(catalog),
        valid_until,
        whole_at: whole.then_some(snapshot),
    })
}

/// The catalog of `channel` the store keeps, every part checked again without the network
/// against the saved TUF state at `now`; `None` if no index of the channel is kept or it no
/// longer holds. A part of the publishers' side that does not hold leaves its publishers
/// unavailable.
pub fn kept(
    channel: Channel,
    store: &Store,
    repository: &Repository,
    builtin: impl IntoIterator<Item = String>,
    now: OffsetDateTime,
) -> Option<InUse> {
    let index = store.load_catalog(channel, |bytes| repository.verify_kept(channel, bytes, now))?;
    let top_level = match repository.kept_top_level(now) {
        Ok(Some(top_level)) => top_level,
        Ok(None) => {
            return Some(owner_only(index.index, index.valid_until));
        }
        Err(e) => {
            info!(error = %e, "the kept top-level targets do not hold; every publisher is unavailable");
            return Some(owner_only(index.index, index.valid_until));
        }
    };
    let publishers = store
        .load_publishers(|bytes| repository.verify_kept_publishers(bytes, now))
        .map(|(bytes, _)| bytes);
    let roles = match top_level.targets.delegations() {
        Ok(delegations) => {
            let names = delegations
                .iter()
                .flat_map(|delegations| delegations.roles())
                .map(|entry| match entry {
                    Ok(role) => role.name().clone(),
                    Err(refused) => refused.name.clone(),
                });
            // Only the roles delegated now, each once (and at most as many as the client
            // follows): no other kept file is read.
            let mut listed: Vec<(RoleName, Option<VerifiedRole>)> = Vec::new();
            let most = usize::try_from(Limits::default().max_delegations).unwrap_or(usize::MAX);
            for name in names.take(most) {
                if listed.iter().any(|(listed, _)| *listed == name) {
                    continue;
                }
                let verified = store
                    .load_role(&name, |bytes| repository.verify_kept_role(&name, bytes, now))
                    .and_then(|verified| match verified {
                        Ok(verified) => Some(verified),
                        Err(e) => {
                            info!(role = %name, error = %e, "a kept publisher's role does not hold; the publisher is unavailable");
                            None
                        }
                    });
                listed.push((name, verified));
            }
            Some(listed)
        }
        Err(e) => {
            info!(error = %e, "the kept delegations cannot be read; every publisher is unavailable");
            None
        }
    };
    let valid_until = earliest(
        index.valid_until.min(top_level.valid_until),
        roles.as_deref(),
    );
    let catalog = build(
        index.index,
        &top_level.targets.targets,
        publishers.as_deref(),
        roles.as_deref(),
        builtin,
    );
    Some(InUse {
        catalog: Arc::new(catalog),
        valid_until,
        whole_at: None,
    })
}

/// The catalog of `index` alone: every publisher unavailable.
fn owner_only(index: Index, valid_until: OffsetDateTime) -> InUse {
    InUse {
        catalog: Arc::new(oncl_update::Catalog::owner(index)),
        valid_until,
        whole_at: None,
    }
}

/// `valid_until`, or earlier if a verified role of `roles` stops holding before.
fn earliest(
    valid_until: OffsetDateTime,
    roles: Option<&[(RoleName, Option<VerifiedRole>)]>,
) -> OffsetDateTime {
    roles
        .into_iter()
        .flatten()
        .filter_map(|(_, verified)| verified.as_ref())
        .map(VerifiedRole::valid_until)
        .fold(valid_until, OffsetDateTime::min)
}

/// The catalog of `index` and the publishers' side: the verified `top_level` targets,
/// `publishers.json` (`None`: none verified, every publisher unavailable) and the delegated
/// roles in order, each verified or not (`None`: the delegations are unavailable). A
/// publisher's declared capabilities are read by the rules of a manifest's.
fn build(
    index: Index,
    top_level: &BTreeMap<TargetPath, Target>,
    publishers: Option<&[u8]>,
    roles: Option<&[(RoleName, Option<VerifiedRole>)]>,
    builtin: impl IntoIterator<Item = String>,
) -> oncl_update::Catalog {
    let Some(publishers) = publishers else {
        return oncl_update::Catalog::owner(index);
    };
    let builder =
        oncl_update::Catalog::builder(index, top_level, PublisherPolicy::from_json(publishers))
            .builtin_modules(builtin)
            .capabilities(|declared| {
                Capabilities::try_from(declared)
                    .map(drop)
                    .map_err(|e| e.to_string())
            });
    match roles {
        None => builder.delegations_unavailable(),
        Some(roles) => roles
            .iter()
            .fold(builder, |builder, (role, verified)| match verified {
                Some(verified) => builder.role(role, verified.targets()),
                None => builder.unavailable_role(role),
            }),
    }
    .build()
}
