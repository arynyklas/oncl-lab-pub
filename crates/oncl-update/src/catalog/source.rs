//! `custom.oncl.source` of a publisher's release: the source archive its package was built
//! from (`docs/design/publishers.md`, «Поле `source`»). Every publisher's target carries
//! one; the client checks its form only, builds nothing and shows no `vcs`.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use super::release::anonymous_https_url;
use crate::index::Sha256;

/// The longest crate directory inside the archive, in bytes: the archive's own limit on a
/// path.
const MAX_PATH: usize = 255;
/// The longest license expression, in bytes.
const MAX_LICENSE: usize = 256;

/// The source archive of a publisher's release, checked against the rules of its fields.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReleaseSource {
    /// The sha256 of the canonical archive.
    pub archive_sha256: Sha256,
    /// Its length in bytes, at most [`ReleaseSource::MAX_ARCHIVE`].
    pub archive_length: u64,
    /// Where the project's CI fetched the archive once; clients link to the copy in the
    /// project's Releases instead.
    pub fetch: String,
    /// The crate's directory inside the archive's `src/`, `""` for its root.
    pub path: String,
    /// The crate's license, an SPDX expression (its syntax only is checked here).
    pub license: String,
    /// The digest of the reference builder image.
    pub builder: Sha256,
    /// The git revision the publisher says the archive was made from, unchecked here.
    pub vcs: Option<SourceVcs>,
}

/// The git revision a publisher names for its source archive.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceVcs {
    /// The repository, an anonymous `https://` URL.
    pub url: String,
    /// The commit: 40 lowercase hex digits (SHA-1) or 64 (SHA-256).
    pub rev: String,
}

/// Why `custom.oncl.source` is not a [`ReleaseSource`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SourceError {
    /// The target has no `source`.
    #[error("source is missing")]
    Missing,
    /// `source` is not an object of the expected members.
    #[error("source is malformed")]
    Malformed(#[source] Arc<serde_json::Error>),
    /// `archive_sha256` is not 64 lowercase hex digits.
    #[error("source.archive_sha256 is not 64 lowercase hex digits")]
    ArchiveSha256,
    /// `archive_length` is zero or over [`ReleaseSource::MAX_ARCHIVE`].
    #[error("source.archive_length {0} is not 1 to 64 MiB")]
    ArchiveLength(u64),
    /// `fetch` is not an anonymous `https://` URL of printable ASCII, at most 2048 bytes,
    /// without a fragment.
    #[error("source.fetch is not an anonymous https:// url of at most 2048 bytes")]
    Fetch,
    /// `path` is not a relative `/`-separated directory of printable ASCII, at most 255
    /// bytes.
    #[error("source.path is not a relative directory")]
    Path,
    /// `license` is not an SPDX license expression.
    #[error("source.license is not an SPDX license expression")]
    License,
    /// `builder` is not `sha256:` and 64 lowercase hex digits.
    #[error("source.builder is not sha256:<64 hex>")]
    Builder,
    /// `vcs` has a `url` that is not an anonymous `https://` URL of printable ASCII, or a
    /// `rev` that is not 40 or 64 lowercase hex digits.
    #[error("source.vcs is not an https:// url and a 40 or 64 hex revision")]
    Vcs,
}

/// `custom.oncl.source` as signed; members this version does not know are skipped.
#[derive(Deserialize)]
struct RawSource {
    archive_sha256: String,
    archive_length: u64,
    fetch: String,
    path: String,
    license: String,
    builder: String,
    #[serde(default)]
    vcs: Option<RawVcs>,
}

#[derive(Deserialize)]
struct RawVcs {
    url: String,
    rev: String,
}

impl ReleaseSource {
    /// The largest source archive, in bytes.
    pub const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;

    /// Reads `custom.oncl.source`; `None` is a target without one.
    ///
    /// # Errors
    ///
    /// [`SourceError`] for a missing `source` or one that breaks a rule of its fields.
    pub fn parse(source: Option<&Value>) -> Result<ReleaseSource, SourceError> {
        let raw = RawSource::deserialize(source.ok_or(SourceError::Missing)?)
            .map_err(|e| SourceError::Malformed(Arc::new(e)))?;
        let archive_sha256 = crate::hex::decode(&raw.archive_sha256)
            .map(Sha256)
            .ok_or(SourceError::ArchiveSha256)?;
        if !(1..=ReleaseSource::MAX_ARCHIVE).contains(&raw.archive_length) {
            return Err(SourceError::ArchiveLength(raw.archive_length));
        }
        if !(printable_ascii(&raw.fetch) && anonymous_https_url(&raw.fetch)) {
            return Err(SourceError::Fetch);
        }
        if !is_crate_dir(&raw.path) {
            return Err(SourceError::Path);
        }
        if !is_spdx_expression(&raw.license) {
            return Err(SourceError::License);
        }
        let builder = raw
            .builder
            .strip_prefix("sha256:")
            .and_then(crate::hex::decode)
            .map(Sha256)
            .ok_or(SourceError::Builder)?;
        let vcs = raw
            .vcs
            .map(|vcs| {
                let rev = crate::hex::decode::<20>(&vcs.rev).is_some()
                    || crate::hex::decode::<32>(&vcs.rev).is_some();
                if rev && printable_ascii(&vcs.url) && anonymous_https_url(&vcs.url) {
                    Ok(SourceVcs {
                        url: vcs.url,
                        rev: vcs.rev,
                    })
                } else {
                    Err(SourceError::Vcs)
                }
            })
            .transpose()?;
        Ok(ReleaseSource {
            archive_sha256,
            archive_length: raw.archive_length,
            fetch: raw.fetch,
            path: raw.path,
            license: raw.license,
            builder,
            vcs,
        })
    }
}

/// Whether `text` is printable ASCII without spaces: no format characters (bidi overrides,
/// zero-width ones) or look-alike letters for the site to show.
fn printable_ascii(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_graphic())
}

/// `""`, or `/`-separated segments of printable ASCII, none empty, `.` or `..`, without
/// `\`, at most [`MAX_PATH`] bytes.
fn is_crate_dir(path: &str) -> bool {
    path.is_empty()
        || (path.len() <= MAX_PATH
            && printable_ascii(path)
            && !path.contains('\\')
            && path
                .split('/')
                .all(|segment| !matches!(segment, "" | "." | "..")))
}

/// An SPDX `idstring`: `[A-Za-z0-9.-]+`.
fn is_idstring(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// `["DocumentRef-" idstring ":"] <kind> idstring`, for `LicenseRef-` and `AdditionRef-`.
fn is_reference(word: &str, kind: &str) -> bool {
    let reference = match word.split_once(':') {
        Some((document, reference)) => {
            if !document
                .strip_prefix("DocumentRef-")
                .is_some_and(is_idstring)
            {
                return false;
            }
            reference
        }
        None => word,
    };
    reference.strip_prefix(kind).is_some_and(is_idstring)
}

/// A `simple-expression`: a license id, with `+` for "or later", or a `LicenseRef-`.
fn is_simple(word: &str) -> bool {
    if word.starts_with("LicenseRef-") || word.starts_with("DocumentRef-") {
        return is_reference(word, "LicenseRef-");
    }
    is_idstring(word.strip_suffix('+').unwrap_or(word))
}

/// A license exception id or an `AdditionRef-`.
fn is_exception(word: &str) -> bool {
    if word.starts_with("AdditionRef-") || word.starts_with("DocumentRef-") {
        return is_reference(word, "AdditionRef-");
    }
    is_idstring(word)
}

/// Whether `text` is an SPDX license expression (SPDX 2.3, annex D), at most
/// [`MAX_LICENSE`] bytes: ids joined by `AND`, `OR` and `WITH` (upper case), in brackets
/// or not. Whether each id is a known license is not checked.
fn is_spdx_expression(text: &str) -> bool {
    if text.len() > MAX_LICENSE {
        return false;
    }
    let mut tokens = Vec::new();
    for word in text.split(' ').filter(|word| !word.is_empty()) {
        let mut rest = word;
        while let Some(inner) = rest.strip_prefix('(') {
            tokens.push("(");
            rest = inner;
        }
        let mut closing = 0;
        while let Some(inner) = rest.strip_suffix(')') {
            closing += 1;
            rest = inner;
        }
        if !rest.is_empty() {
            tokens.push(rest);
        }
        tokens.extend(std::iter::repeat_n(")", closing));
    }
    let mut parser = Spdx {
        tokens: &tokens,
        at: 0,
    };
    parser.or() && parser.at == tokens.len()
}

/// A recursive-descent reader of SPDX expression tokens; the nesting is bounded by
/// [`MAX_LICENSE`].
struct Spdx<'t> {
    tokens: &'t [&'t str],
    at: usize,
}

impl Spdx<'_> {
    fn next_is(&self, token: &str) -> bool {
        self.tokens.get(self.at) == Some(&token)
    }

    fn or(&mut self) -> bool {
        if !self.and() {
            return false;
        }
        while self.next_is("OR") {
            self.at += 1;
            if !self.and() {
                return false;
            }
        }
        true
    }

    fn and(&mut self) -> bool {
        if !self.term() {
            return false;
        }
        while self.next_is("AND") {
            self.at += 1;
            if !self.term() {
                return false;
            }
        }
        true
    }

    fn term(&mut self) -> bool {
        if self.next_is("(") {
            self.at += 1;
            if !self.or() || !self.next_is(")") {
                return false;
            }
            self.at += 1;
            return true;
        }
        let Some(&word) = self.tokens.get(self.at) else {
            return false;
        };
        if matches!(word, "AND" | "OR" | "WITH" | ")") || !is_simple(word) {
            return false;
        }
        self.at += 1;
        if self.next_is("WITH") {
            self.at += 1;
            let Some(&exception) = self.tokens.get(self.at) else {
                return false;
            };
            if matches!(exception, "AND" | "OR" | "WITH" | "(" | ")") || !is_exception(exception) {
                return false;
            }
            self.at += 1;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spdx_expressions_are_read_by_their_syntax_alone() {
        for good in [
            "MIT",
            "Apache-2.0",
            "MIT OR Apache-2.0",
            "(MIT OR Apache-2.0) AND Unicode-3.0",
            "((MIT))",
            "GPL-2.0+",
            "GPL-2.0-or-later WITH Classpath-exception-2.0",
            "LicenseRef-ecc-1",
            "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
            "Apache-2.0 WITH AdditionRef-my-exception",
            "Not-A-Known-License-9",
        ] {
            assert!(is_spdx_expression(good), "{good}");
        }
        for bad in [
            "",
            " ",
            "MIT/Apache-2.0",
            "MIT or Apache-2.0",
            "MIT OR",
            "AND MIT",
            "(MIT",
            "MIT)",
            "MIT AND (Apache-2.0",
            "()",
            "WITH",
            "MIT WITH",
            "MIT WITH (Classpath-exception-2.0)",
            "(MIT) WITH Classpath-exception-2.0",
            "Apache 2.0",
            "MIT\tOR Apache-2.0",
            "LicenseRef-",
            "DocumentRef-x:MIT",
            "LicenseRef-x+",
            "MIT++",
        ] {
            assert!(!is_spdx_expression(bad), "{bad:?}");
        }
        assert!(is_spdx_expression(&format!(
            "A{}",
            "-".repeat(MAX_LICENSE - 1)
        )));
        assert!(!is_spdx_expression(&format!(
            "A{}",
            "-".repeat(MAX_LICENSE)
        )));
    }

    #[test]
    fn a_crate_dir_is_relative_and_plain() {
        for good in ["", "crates/market", "a", "a.b/c-d"] {
            assert!(is_crate_dir(good), "{good}");
        }
        for bad in [
            "/crates",
            "crates/",
            "a//b",
            "a/../b",
            "./a",
            "..",
            "a\\b",
            "a\nb",
            "a b",
            "crates/маркет",
            "a\u{202e}b",
            "a\u{200b}b",
        ] {
            assert!(!is_crate_dir(bad), "{bad:?}");
        }
        assert!(is_crate_dir(&"a".repeat(MAX_PATH)));
        assert!(!is_crate_dir(&"a".repeat(MAX_PATH + 1)));
    }
}
