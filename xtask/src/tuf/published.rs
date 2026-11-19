//! `cargo xtask tuf verify-published`: the real client over HTTPS against the published site,
//! the smoke check after a deployment. It starts at the trust anchor, follows the roots,
//! verifies the timestamp, snapshot and targets, and downloads every target (the update
//! indexes), each of which must be a valid index of its channel.
//!
//! [`verify_published_v2`] reads `tuf/v2` in the delegating profile: also `publishers.json`,
//! whose active publishers must be exactly the roles delegated to, and every delegated role
//! ([`TufClient::delegated`]); a role without any file yet (a publisher without a release)
//! is not a failure. The publishers' packages are not downloaded: CI checked them when their
//! roles were merged.
//!
//! A repository that is not published yet is a failure unless `allow_missing` says it may be
//! (the first deployments, before the owner's timestamp secret exists).

use std::collections::BTreeSet;

use oncl_update::tuf::{
    DelegationError, Fetcher, Limits, MemoryStore, Profile, Trusted, TufClient, TufError, layout,
};
use oncl_update::{Channel, Index};
use serde_json::Value;
use time::OffsetDateTime;

use super::{MAX_TARGET, show_time};
use crate::publishers;

/// What was found.
#[derive(Debug, PartialEq, Eq)]
pub enum Published {
    /// The repository answers and verifies.
    Verified {
        /// A line per file the client trusts.
        lines: Vec<String>,
    },
    /// There is no timestamp (and `allow_missing` was set).
    NotPublished,
}

/// Runs the client over `fetcher` from `anchor` at `now`.
///
/// # Errors
///
/// If the repository does not verify, a target is not a valid index of its channel, or the
/// repository is not published and `allow_missing` is off.
pub fn verify_published<F: Fetcher>(
    fetcher: F,
    anchor: &[u8],
    now: OffsetDateTime,
    allow_missing: bool,
) -> anyhow::Result<Published> {
    // What the clients released before delegations read: `tuf/v1` must stay readable by them.
    let mut client = TufClient::new(anchor, fetcher, MemoryStore::default(), Limits::default())
        .map_err(|e| anyhow::anyhow!("the trust anchor is not usable: {e}"))?
        .with_profile(Profile::Legacy);
    let trusted = match client.refresh(now) {
        Ok(trusted) => trusted,
        Err(TufError::NotFound(path)) if allow_missing && path == layout::TIMESTAMP_PATH => {
            return Ok(Published::NotPublished);
        }
        Err(e) => anyhow::bail!("the published repository does not verify: {e}"),
    };
    let mut lines = top_lines(&trusted);
    for path in trusted.targets().targets.keys() {
        let bytes = client
            .download_target(&trusted, path.as_str(), MAX_TARGET, now)
            .map_err(|e| anyhow::anyhow!("the target {path}: {e}"))?;
        lines.push(index_line(path.as_str(), &bytes)?);
    }
    Ok(Published::Verified { lines })
}

/// A line for each of the top-level files `trusted`.
fn top_lines(trusted: &Trusted) -> Vec<String> {
    vec![
        format!(
            "root {} (expires {})",
            trusted.root().version,
            show_time(trusted.root().expires)
        ),
        format!(
            "timestamp {} (expires {})",
            trusted.timestamp().version,
            show_time(trusted.timestamp().expires)
        ),
        format!(
            "snapshot {} (expires {})",
            trusted.snapshot().version,
            show_time(trusted.snapshot().expires)
        ),
        format!(
            "targets {} (expires {})",
            trusted.targets().version,
            show_time(trusted.targets().expires)
        ),
    ]
}

/// The target `path` (`bytes`) as an index of the channel its path names.
fn index_line(path: &str, bytes: &[u8]) -> anyhow::Result<String> {
    let name = path
        .strip_prefix("indexes/")
        .and_then(|n| n.strip_suffix(".json"))
        .ok_or_else(|| anyhow::anyhow!("{path} is not an update index"))?;
    let channel = Channel::ALL
        .into_iter()
        .find(|c| c.as_str() == name)
        .ok_or_else(|| anyhow::anyhow!("{path} is not an index of a known channel"))?;
    let index = Index::from_json(bytes)
        .map_err(|e| anyhow::anyhow!("the target {path} is not a valid index: {e}"))?;
    if index.channel != channel {
        anyhow::bail!(
            "the target {path} is an index of the {} channel",
            index.channel
        );
    }
    Ok(format!("{path}: {} bytes, seq {}", bytes.len(), index.seq))
}

/// The names of the active publishers of `publishers.json`.
fn active_publishers(bytes: &[u8]) -> anyhow::Result<BTreeSet<String>> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|e| anyhow::anyhow!("{} is not JSON: {e}", publishers::TARGET))?;
    if value.get("schema").and_then(Value::as_u64) != Some(u64::from(publishers::SCHEMA)) {
        anyhow::bail!(
            "{} is not of schema {}",
            publishers::TARGET,
            publishers::SCHEMA
        );
    }
    let entries = value
        .get("publishers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("{} has no publishers", publishers::TARGET))?;
    let mut active = BTreeSet::new();
    for entry in entries {
        let name = entry.get("name").and_then(Value::as_str);
        let state = entry.get("state").and_then(Value::as_str);
        match (name, state) {
            (Some(name), Some("active")) => {
                active.insert(name.to_owned());
            }
            (Some(_), Some("revoked")) => {}
            _ => anyhow::bail!(
                "{} has an entry without a name and a state",
                publishers::TARGET
            ),
        }
    }
    Ok(active)
}

/// Runs the client of `tuf/v2` over `fetcher` from `anchor` at `now` (see the module's
/// description).
///
/// # Errors
///
/// If the repository does not verify, a target is not a valid index or `publishers.json`, a
/// delegated role is not trusted, the active publishers are not the roles delegated to, or
/// the repository is not published and `allow_missing` is off.
pub fn verify_published_v2<F: Fetcher>(
    fetcher: F,
    anchor: &[u8],
    now: OffsetDateTime,
    allow_missing: bool,
) -> anyhow::Result<Published> {
    let mut client = TufClient::new(anchor, fetcher, MemoryStore::default(), Limits::default())
        .map_err(|e| anyhow::anyhow!("the trust anchor is not usable: {e}"))?
        .with_profile(Profile::Delegating);
    let trusted = match client.refresh(now) {
        Ok(trusted) => trusted,
        Err(TufError::NotFound(path)) if allow_missing && path == layout::TIMESTAMP_PATH => {
            return Ok(Published::NotPublished);
        }
        Err(e) => anyhow::bail!("the published tuf/v2 does not verify: {e}"),
    };
    let mut lines = top_lines(&trusted);
    let mut active = None;
    for path in trusted.targets().targets.keys() {
        let bytes = client
            .download_target(&trusted, path.as_str(), MAX_TARGET, now)
            .map_err(|e| anyhow::anyhow!("the target {path}: {e}"))?;
        if path.as_str() == publishers::TARGET {
            let names = active_publishers(&bytes)?;
            lines.push(format!(
                "{path}: {} bytes, {} active publishers",
                bytes.len(),
                names.len()
            ));
            active = Some(names);
        } else {
            lines.push(index_line(path.as_str(), &bytes)?);
        }
    }
    let Some(active) = active else {
        anyhow::bail!("the targets of tuf/v2 do not list {}", publishers::TARGET);
    };
    // Clients keep the member unread with the targets; `tuf/v2` must have one.
    if !matches!(trusted.targets().delegations(), Ok(Some(_))) {
        anyhow::bail!("the targets of tuf/v2 have no readable delegations");
    }
    let delegated = client
        .delegated(&trusted, now)
        .map_err(|e| anyhow::anyhow!("the delegated roles: {e}"))?;
    let mut names = BTreeSet::new();
    for (name, role) in delegated.roles() {
        names.insert(name.publisher().as_str().to_owned());
        match role {
            Ok(role) => lines.push(format!(
                "{name} {}: {} targets (expires {})",
                role.version(),
                role.targets().len(),
                show_time(role.expires())
            )),
            Err(TufError::Delegation {
                error: DelegationError::NotInSnapshot,
                ..
            }) => lines.push(format!("{name}: no release yet")),
            Err(e) => anyhow::bail!("the role {name} is not trusted: {e}"),
        }
    }
    if names != active {
        anyhow::bail!(
            "{} names the active publishers {active:?}, the targets delegate to {names:?}",
            publishers::TARGET
        );
    }
    Ok(Published::Verified { lines })
}
