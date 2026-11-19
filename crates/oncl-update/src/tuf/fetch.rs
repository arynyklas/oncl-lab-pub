//! Reading the files of a repository: the [`Fetcher`] the client asks for them, over HTTPS
//! ([`HttpFetcher`]) or from memory ([`MemoryFetcher`], for tests and tools).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use oncl_pki::http::{GetOptions, HttpTransport};

use super::error::TufError;

/// What a [`Fetcher`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The file.
    Body(Vec<u8>),
    /// The repository has no such file (HTTP 404). For `<N+1>.root.json` it is the end of
    /// the chain, anywhere else an error.
    NotFound,
}

/// Reads files of a repository by their path under its base ([`super::layout`]). Blocking;
/// it does not decide what is trusted, only what the bytes are.
pub trait Fetcher {
    /// The file at `path`: at most `max_len` bytes. A file of exactly `max_len` bytes is
    /// returned, one byte more is an error (reading stops there: endless data is never
    /// buffered).
    ///
    /// # Errors
    ///
    /// [`TufError::Fetch`] if there is no answer, or the answer is not the file or a 404,
    /// or is over `max_len`.
    fn fetch(&self, path: &str, max_len: u64) -> Result<Response, TufError>;
}

impl<F: Fetcher + ?Sized> Fetcher for &F {
    fn fetch(&self, path: &str, max_len: u64) -> Result<Response, TufError> {
        (**self).fetch(path, max_len)
    }
}

impl<F: Fetcher + ?Sized> Fetcher for Box<F> {
    fn fetch(&self, path: &str, max_len: u64) -> Result<Response, TufError> {
        (**self).fetch(path, max_len)
    }
}

/// The time one file may take, redirects included, unless [`HttpFetcher::with_timeout`]
/// says otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// The most redirects one file follows.
const MAX_REDIRECTS: usize = 3;

/// A repository at an `https://` base URL, read through the caller's [`HttpTransport`] (its
/// proxy and TLS).
///
/// Every request is `https_only` and `max_len` limited. The transport follows no redirects:
/// this follows a 301, 302, 303, 307 or 308 itself, only to an `https://` URL on the same
/// host and port as the request (an absolute `https://` URL there, or an absolute path), up
/// to 3 times; a redirect elsewhere is an error, so a base on a host that serves
/// someone else's content cannot be redirected into it.
pub struct HttpFetcher<'a> {
    transport: &'a dyn HttpTransport,
    base: String,
    timeout: Duration,
}

impl<'a> HttpFetcher<'a> {
    /// A fetcher of the repository at `base` (with or without a trailing `/`), e.g.
    /// `https://arynyklas.github.io/OpenNCALayer/tuf/v1`.
    ///
    /// # Errors
    ///
    /// [`TufError::Fetch`] if `base` is not an `https://` URL.
    pub fn new(transport: &'a dyn HttpTransport, base: &str) -> Result<HttpFetcher<'a>, TufError> {
        let rest = base.strip_prefix("https://").unwrap_or_default();
        if rest.is_empty() || rest.starts_with('/') {
            return Err(TufError::Fetch(format!("{base} is not an https URL")));
        }
        Ok(HttpFetcher {
            transport,
            base: base.trim_end_matches('/').to_owned(),
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// The time one file may take, all its requests together.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> HttpFetcher<'a> {
        self.timeout = timeout;
        self
    }

    /// The URL of `path`.
    pub fn url(&self, path: &str) -> String {
        format!("{}/{path}", self.base)
    }
}

impl Fetcher for HttpFetcher<'_> {
    fn fetch(&self, path: &str, max_len: u64) -> Result<Response, TufError> {
        let deadline = Instant::now() + self.timeout;
        let mut url = self.url(path);
        for _ in 0..=MAX_REDIRECTS {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(TufError::Fetch(format!("{url}: no time left")));
            }
            let opts = GetOptions {
                timeout: left,
                connect_timeout: GetOptions::default().connect_timeout.min(left),
                max_len,
                https_only: true,
                redirects: false,
            };
            let reply = self
                .transport
                .get_with(&url, opts)
                .map_err(|e| TufError::Fetch(format!("{url}: {e}")))?;
            match reply.status {
                200 => {
                    // A transport that ignores `max_len` still does not hand over more.
                    if reply.body.len() as u64 > max_len {
                        return Err(TufError::Fetch(format!("{url}: over {max_len} bytes")));
                    }
                    return Ok(Response::Body(reply.body));
                }
                404 => return Ok(Response::NotFound),
                301 | 302 | 303 | 307 | 308 => {
                    let next = reply
                        .location
                        .as_deref()
                        .and_then(|location| same_host_redirect(&url, location));
                    url = next.ok_or_else(|| {
                        TufError::Fetch(format!(
                            "{url}: redirect to {}, which is not an https URL on the same host",
                            printable(reply.location.as_deref())
                        ))
                    })?;
                }
                status => return Err(TufError::Fetch(format!("{url}: HTTP {status}"))),
            }
        }
        Err(TufError::Fetch(format!(
            "{path}: more than {MAX_REDIRECTS} redirects"
        )))
    }
}

/// What a server sent as a `Location`, for an error message: at most 80 characters, control
/// characters shown as `?`, in quotes. The header is not trusted.
fn printable(location: Option<&str>) -> String {
    let Some(location) = location else {
        return "nothing".to_owned();
    };
    let shown: String = location
        .chars()
        .take(80)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    let more = if location.chars().count() > 80 {
        "..."
    } else {
        ""
    };
    format!("\"{shown}{more}\"")
}

/// The `host[:port]` of an `https://` URL.
fn authority(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    Some(&rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())])
}

/// Where a redirect to `location` goes from `current`, if that is on the same host and
/// port, over HTTPS.
fn same_host_redirect(current: &str, location: &str) -> Option<String> {
    let current_authority = authority(current)?;
    let location = location.trim();
    if location.starts_with("https://") {
        authority(location)?
            .eq_ignore_ascii_case(current_authority)
            .then(|| location.to_owned())
    } else if location.starts_with('/') && !location.starts_with("//") {
        Some(format!("https://{current_authority}{location}"))
    } else {
        None
    }
}

/// A repository held in memory: files that are put there, a log of what was asked for. It
/// answers like a transport that honours `max_len`: a file over it is an error.
#[derive(Debug, Default)]
pub struct MemoryFetcher {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    requests: Mutex<Vec<String>>,
}

impl MemoryFetcher {
    /// An empty repository.
    pub fn new() -> MemoryFetcher {
        MemoryFetcher::default()
    }

    /// Puts (or replaces) the file at `path`.
    pub fn put(&self, path: impl Into<String>, body: impl Into<Vec<u8>>) {
        lock(&self.files).insert(path.into(), body.into());
    }

    /// Removes the file at `path`: it answers 404 from now on.
    pub fn remove(&self, path: &str) -> Option<Vec<u8>> {
        lock(&self.files).remove(path)
    }

    /// The file at `path`.
    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        lock(&self.files).get(path).cloned()
    }

    /// The paths asked for, in order, since the last [`MemoryFetcher::clear_requests`].
    pub fn requests(&self) -> Vec<String> {
        lock(&self.requests).clone()
    }

    /// Forgets the log of requests.
    pub fn clear_requests(&self) {
        lock(&self.requests).clear();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Fetcher for MemoryFetcher {
    fn fetch(&self, path: &str, max_len: u64) -> Result<Response, TufError> {
        lock(&self.requests).push(path.to_owned());
        match lock(&self.files).get(path) {
            None => Ok(Response::NotFound),
            Some(body) if body.len() as u64 > max_len => Err(TufError::Fetch(format!(
                "{path}: the body is larger than request limit: {max_len}"
            ))),
            Some(body) => Ok(Response::Body(body.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::http::{HttpError, HttpMethod, HttpReply, HttpRequest};

    /// Answers by URL from a table, and records what was asked: URL and options.
    struct Table {
        replies: Vec<(String, HttpReply)>,
        asked: Mutex<Vec<(String, GetOptions)>>,
    }

    fn reply(status: u16, location: Option<&str>, body: &[u8]) -> HttpReply {
        HttpReply {
            status,
            content_type: None,
            location: location.map(str::to_owned),
            body: body.to_vec(),
        }
    }

    impl HttpTransport for Table {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            assert_eq!(request.method, HttpMethod::Get);
            self.asked
                .lock()
                .unwrap()
                .push((request.url.to_owned(), request.opts));
            self.replies
                .iter()
                .find(|(url, _)| url.eq_ignore_ascii_case(request.url))
                .map(|(_, reply)| reply.clone())
                .ok_or_else(|| HttpError::other("connection refused"))
        }
    }

    fn table(replies: Vec<(&str, HttpReply)>) -> Table {
        Table {
            replies: replies
                .into_iter()
                .map(|(u, r)| (u.to_owned(), r))
                .collect(),
            asked: Mutex::new(Vec::new()),
        }
    }

    const BASE: &str = "https://example.org/tuf/v1";

    #[test]
    fn a_file_is_fetched_over_https_within_its_limit() {
        let t = table(vec![
            (
                "https://example.org/tuf/v1/metadata/1.root.json",
                reply(200, None, b"root"),
            ),
            (
                "https://example.org/tuf/v1/metadata/2.root.json",
                reply(404, None, b""),
            ),
        ]);
        let f = HttpFetcher::new(&t, &format!("{BASE}/")).unwrap();
        assert_eq!(
            f.fetch("metadata/1.root.json", 4).unwrap(),
            Response::Body(b"root".to_vec())
        );
        assert_eq!(
            f.fetch("metadata/2.root.json", 10).unwrap(),
            Response::NotFound
        );
        let asked = t.asked.lock().unwrap();
        assert_eq!(asked[0].1.max_len, 4);
        assert!(
            asked
                .iter()
                .all(|(_, o)| o.https_only && !o.redirects && o.timeout <= DEFAULT_TIMEOUT)
        );
    }

    #[test]
    fn failures_and_oversized_bodies_are_fetch_errors() {
        let t = table(vec![
            ("https://example.org/tuf/v1/a", reply(503, None, b"")),
            ("https://example.org/tuf/v1/big", reply(200, None, b"12345")),
        ]);
        let f = HttpFetcher::new(&t, BASE).unwrap();
        for (path, expected) in [
            ("a", "HTTP 503"),
            ("big", "over 4 bytes"),
            ("none", "connection refused"),
        ] {
            match f.fetch(path, 4) {
                Err(TufError::Fetch(m)) => assert!(m.contains(expected), "{m}"),
                other => panic!("{other:?}"),
            }
        }
        for base in [
            "http://example.org/tuf",
            "ftp://x",
            "https://",
            "https:///x",
            "example.org",
        ] {
            assert!(
                matches!(HttpFetcher::new(&t, base), Err(TufError::Fetch(_))),
                "{base}"
            );
        }
        match f.fetch("big", 5) {
            Ok(Response::Body(b)) => assert_eq!(b, b"12345"),
            other => panic!("{other:?}"),
        }
        let none = HttpFetcher::new(&t, BASE)
            .unwrap()
            .with_timeout(Duration::ZERO);
        assert!(
            matches!(none.fetch("big", 5), Err(TufError::Fetch(m)) if m.contains("no time left"))
        );
    }

    #[test]
    fn redirects_stay_on_the_host_and_on_https() {
        let t = table(vec![
            (
                "https://example.org/tuf/v1/a",
                reply(301, Some("/tuf/v1/b"), b""),
            ),
            (
                "https://example.org/tuf/v1/b",
                reply(302, Some("https://EXAMPLE.org/tuf/v1/c"), b""),
            ),
            ("https://example.org/tuf/v1/c", reply(200, None, b"ok")),
            (
                "https://example.org/tuf/v1/x1",
                reply(302, Some("https://evil.example/tuf/v1/c"), b""),
            ),
            (
                "https://example.org/tuf/v1/x2",
                reply(302, Some("http://example.org/tuf/v1/c"), b""),
            ),
            (
                "https://example.org/tuf/v1/x3",
                reply(302, Some("//evil.example/c"), b""),
            ),
            (
                "https://example.org/tuf/v1/x4",
                reply(302, Some("https://example.org:8443/c"), b""),
            ),
            ("https://example.org/tuf/v1/x5", reply(302, Some("c"), b"")),
            ("https://example.org/tuf/v1/x6", reply(302, None, b"")),
            (
                "https://example.org/tuf/v1/loop",
                reply(302, Some("/tuf/v1/loop"), b""),
            ),
        ]);
        let f = HttpFetcher::new(&t, BASE).unwrap();
        assert_eq!(f.fetch("a", 10).unwrap(), Response::Body(b"ok".to_vec()));
        for path in ["x1", "x2", "x3", "x4", "x5", "x6"] {
            assert!(
                matches!(f.fetch(path, 10), Err(TufError::Fetch(m)) if m.contains("redirect")),
                "{path}"
            );
        }
        assert!(matches!(f.fetch("loop", 10), Err(TufError::Fetch(m)) if m.contains("redirects")));
        // Nothing was asked of another host.
        assert!(
            t.asked
                .lock()
                .unwrap()
                .iter()
                .all(|(u, _)| u.to_ascii_lowercase().starts_with("https://example.org/"))
        );
    }

    #[test]
    fn an_untrusted_location_is_shortened_and_has_no_control_characters_in_the_error() {
        let long = format!("https://evil.example/\r\n\u{1b}[31m{}", "a".repeat(500));
        let t = table(vec![(
            "https://example.org/tuf/v1/a",
            reply(302, Some(&long), b""),
        )]);
        let f = HttpFetcher::new(&t, BASE).unwrap();
        let Err(TufError::Fetch(message)) = f.fetch("a", 10) else {
            panic!("not refused");
        };
        assert!(!message.chars().any(char::is_control), "{message:?}");
        assert!(message.len() < 250, "{} bytes", message.len());
        assert!(message.contains("..."), "{message}");
    }

    #[test]
    fn the_memory_fetcher_answers_like_a_transport() {
        let m = MemoryFetcher::new();
        m.put("a", b"12345".to_vec());
        assert_eq!(m.fetch("a", 5).unwrap(), Response::Body(b"12345".to_vec()));
        assert!(matches!(m.fetch("a", 4), Err(TufError::Fetch(_))));
        assert_eq!(m.fetch("b", 4).unwrap(), Response::NotFound);
        assert_eq!(m.requests(), ["a", "a", "b"]);
        assert_eq!(m.remove("a"), Some(b"12345".to_vec()));
        assert_eq!(m.fetch("a", 5).unwrap(), Response::NotFound);
        m.clear_requests();
        assert!(m.requests().is_empty());
    }
}
