//! The one download of a source archive by CI (check 13): `source.fetch` as signed, under a
//! host policy, at most `archive_length` bytes, within [`super::FETCH_TIMEOUT`]. The answer is
//! only compared with the signed sha256 and read as data.
//!
//! The policy ([`host_policy`]), for the first URL and every redirect: `https://` only, no
//! user info, no IP literal in any form, no `localhost` or other name of the local network,
//! a name with a dot. The client ([`crate::upstream::http::Fetcher`]) then resolves the name
//! once and connects only to public addresses, so a name that resolves to the runner's
//! network is refused as well (DNS rebinding included). No proxy, no cookie, no credential.

use std::net::IpAddr;

use crate::upstream::http::{Fetcher, RequestCtx, UrlParts};

/// What downloads a source archive: the network ([`HttpsFetcher`]) or, in tests, a table.
pub trait ArchiveFetcher {
    /// The bytes at `url`, at most `limit`.
    ///
    /// # Errors
    ///
    /// Why there are none: the policy, the network, a status, more than `limit` bytes.
    fn fetch(&self, url: &str, limit: u64) -> Result<Vec<u8>, String>;
}

/// The names of the local network that resolve to nothing a runner should reach.
const LOCAL_SUFFIXES: [&str; 6] = [
    "localhost",
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".lan",
];

/// Whether `host` is an IP address in any spelling a resolver takes: dotted, IPv6, or the
/// all-digit and hexadecimal forms (`2130706433`, `0x7f.1`).
fn is_ip_literal(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() || host.contains(':') {
        return true;
    }
    // The inet_aton forms: up to four parts, each decimal, octal or 0x hexadecimal.
    let parts: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    parts.len() <= 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && (p.bytes().all(|b| b.is_ascii_digit())
                    || p.strip_prefix("0x")
                        .or_else(|| p.strip_prefix("0X"))
                        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())))
        })
}

/// Checks `url` against the host policy (see the module's description).
///
/// # Errors
///
/// Why it is refused.
pub fn host_policy(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err(format!("{url}: only https:// is fetched"));
    }
    if url.contains('#') {
        return Err(format!("{url}: a fragment is not fetched"));
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("{url}: white space or a control character"));
    }
    let parts = UrlParts::parse(url).map_err(|e| format!("{url}: {e}"))?;
    let authority = url["https://".len()..]
        .split(['/', '?'])
        .next()
        .unwrap_or_default();
    if authority.contains('@') {
        return Err(format!("{url}: credentials are not sent"));
    }
    let host = parts.host.trim_end_matches('.');
    if is_ip_literal(host) {
        return Err(format!("{url}: an IP address, not a name"));
    }
    if !host.contains('.') {
        return Err(format!("{url}: {host} is no public name"));
    }
    if LOCAL_SUFFIXES
        .iter()
        .any(|suffix| host == suffix.trim_start_matches('.') || host.ends_with(suffix))
    {
        return Err(format!("{url}: {host} is a name of the local network"));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(format!("{url}: {host} is not an ASCII host name"));
    }
    Ok(())
}

/// The download over the network: [`host_policy`] on every hop, public addresses only,
/// [`super::FETCH_TIMEOUT`].
pub struct HttpsFetcher {
    client: Fetcher,
}

impl HttpsFetcher {
    /// The client of check 13.
    pub fn new() -> HttpsFetcher {
        HttpsFetcher {
            client: Fetcher::new()
                .capped(super::FETCH_TIMEOUT)
                .restricted_to(|url| host_policy(url).is_ok()),
        }
    }
}

impl Default for HttpsFetcher {
    fn default() -> Self {
        HttpsFetcher::new()
    }
}

impl ArchiveFetcher for HttpsFetcher {
    fn fetch(&self, url: &str, limit: u64) -> Result<Vec<u8>, String> {
        host_policy(url)?;
        self.client
            .get(url, limit, &RequestCtx::default())
            .map(|fetched| fetched.body)
            .map_err(|e| format!("{url}: {e}"))
    }
}

/// Downloads nothing: every URL is refused (`--offline`).
pub struct NoFetcher;

impl ArchiveFetcher for NoFetcher {
    fn fetch(&self, url: &str, _limit: u64) -> Result<Vec<u8>, String> {
        Err(format!("{url}: not fetched (offline)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_policy_takes_public_https_names_only() {
        for good in [
            "https://downloads.ecc.kz/oncl/kz.ecc.market-1.2.0.src.tar.gz",
            "https://github.com/ecc/market/releases/download/v1.2.0/a.src.tar.gz?x=1",
            "https://example.com:8443/a",
        ] {
            host_policy(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in [
            "http://example.com/a",
            "ftp://example.com/a",
            "https://user:pw@example.com/a",
            "https://example.com/a#frag",
            "https://127.0.0.1/a",
            "https://[::1]/a",
            "https://[fd00::1]/a",
            "https://2130706433/a",
            "https://0x7f.1/a",
            "https://10.0.0.1/a",
            "https://localhost/a",
            "https://a.localhost/a",
            "https://metadata.google.internal/a",
            "https://printer.local/a",
            "https://intranet/a",
            "https://exam ple.com/a",
            "https://пример.рф/a",
        ] {
            assert!(host_policy(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn offline_fetches_nothing() {
        assert!(NoFetcher.fetch("https://example.com/a", 1).is_err());
    }
}
