//! The names the TUF layer reads at its boundary and nowhere else: target paths, the names
//! of third-party publishers and of their delegated roles, and the one path pattern a
//! delegation may use. Each is a newtype whose constructor holds its grammar, so a value of
//! the type is valid wherever it travels.
//!
//! - [`TargetPath`]: at most 512 bytes of `A-Za-z0-9._+-` in segments separated by `/`, no
//!   segment empty, `.` or `..`.
//! - [`PublisherName`]: `^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`, not one of the reserved names.
//! - [`RoleName`]: exactly `pub-<publisher>`; it can never be the name of a top-level role.
//! - [`PathPattern`]: exactly `plugins/<publisher>/*/*`, `*` matching one whole segment.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// What kind of name a [`NameError`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NameKind {
    /// A [`TargetPath`].
    TargetPath,
    /// A [`PublisherName`].
    PublisherName,
    /// A [`RoleName`].
    RoleName,
    /// A [`PathPattern`].
    PathPattern,
    /// A plugin id (`crate::catalog::PluginId`).
    PluginId,
    /// A plugin id prefix (`crate::catalog::IdPrefix`).
    IdPrefix,
    /// A module name (`crate::catalog::ModuleName`).
    ModuleName,
    /// A bundle name (`crate::catalog::BundleName`).
    BundleName,
}

impl fmt::Display for NameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameKind::TargetPath => "target path",
            NameKind::PublisherName => "publisher name",
            NameKind::RoleName => "delegated role name",
            NameKind::PathPattern => "delegation path pattern",
            NameKind::PluginId => "plugin id",
            NameKind::IdPrefix => "plugin id prefix",
            NameKind::ModuleName => "module name",
            NameKind::BundleName => "bundle name",
        })
    }
}

/// A string that is not a valid name of its kind.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{value:?} is not a valid {kind}")]
pub struct NameError {
    /// What it was read as.
    pub kind: NameKind,
    /// The string refused.
    pub value: String,
}

impl NameError {
    pub(crate) fn new(kind: NameKind, value: &str) -> NameError {
        NameError {
            kind,
            value: value.to_owned(),
        }
    }
}

/// Implements the string views and conversions every name here shares; the type needs a
/// `parse(&str) -> Result<Self, NameError>`, and `NameError` in scope where it is used.
macro_rules! string_name {
    ($name:ident) => {
        impl $name {
            /// The name as written.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl ::std::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = NameError;

            fn from_str(text: &str) -> Result<$name, NameError> {
                $name::parse(text)
            }
        }

        impl TryFrom<String> for $name {
            type Error = NameError;

            fn try_from(text: String) -> Result<$name, NameError> {
                $name::parse(&text)
            }
        }

        impl From<$name> for String {
            fn from(name: $name) -> String {
                name.0
            }
        }
    };
}

pub(crate) use string_name;

/// A target path this client accepts: at most [`TargetPath::MAX_LEN`] bytes of
/// `A-Za-z0-9._+-` in segments separated by `/`, no segment empty, `.` or `..`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TargetPath(String);

impl TargetPath {
    /// The longest target path, in bytes.
    pub const MAX_LEN: usize = 512;

    /// `text` as a target path.
    ///
    /// # Errors
    ///
    /// [`NameError`] if it breaks the grammar.
    pub fn parse(text: &str) -> Result<TargetPath, NameError> {
        let valid = !text.is_empty()
            && text.len() <= TargetPath::MAX_LEN
            && text.split('/').all(|segment| {
                !matches!(segment, "" | "." | "..")
                    && segment.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-')
                    })
            });
        if valid {
            Ok(TargetPath(text.to_owned()))
        } else {
            Err(NameError::new(NameKind::TargetPath, text))
        }
    }

    /// The segments between the `/`s, none of them empty.
    fn segments(&self) -> std::str::Split<'_, char> {
        self.0.split('/')
    }
}

string_name!(TargetPath);

/// The names a publisher may not take: they are the project's own, or a top-level role's.
const RESERVED_PUBLISHERS: [&str; 10] = [
    "openncalayer",
    "oncl",
    "owner",
    "builtin",
    "port",
    "ports",
    "root",
    "targets",
    "snapshot",
    "timestamp",
];

/// The name of a third-party publisher: `^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$` (3 to 32
/// bytes), none of the reserved names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublisherName(String);

impl PublisherName {
    /// `text` as a publisher name.
    ///
    /// # Errors
    ///
    /// [`NameError`] if it breaks the grammar or is reserved.
    pub fn parse(text: &str) -> Result<PublisherName, NameError> {
        let bytes = text.as_bytes();
        let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        let valid = (3..=32).contains(&bytes.len())
            && bytes.first().is_some_and(edge)
            && bytes.last().is_some_and(edge)
            && bytes.iter().all(|b| edge(b) || *b == b'-')
            && !RESERVED_PUBLISHERS.contains(&text);
        if valid {
            Ok(PublisherName(text.to_owned()))
        } else {
            Err(NameError::new(NameKind::PublisherName, text))
        }
    }
}

string_name!(PublisherName);

/// The prefix of every delegated role's name.
const ROLE_PREFIX: &str = "pub-";

/// The name of a publisher's delegated role: exactly `pub-<publisher>`. No top-level role
/// has that form, so a delegated role can never be taken for one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RoleName(String);

impl RoleName {
    /// The role of `publisher`.
    pub fn of(publisher: &PublisherName) -> RoleName {
        RoleName(format!("{ROLE_PREFIX}{publisher}"))
    }

    /// `text` as a role name.
    ///
    /// # Errors
    ///
    /// [`NameError`] unless it is `pub-` and a [`PublisherName`].
    pub fn parse(text: &str) -> Result<RoleName, NameError> {
        text.strip_prefix(ROLE_PREFIX)
            .and_then(|publisher| PublisherName::parse(publisher).ok())
            .map(|publisher| RoleName::of(&publisher))
            .ok_or_else(|| NameError::new(NameKind::RoleName, text))
    }

    /// The publisher whose role this is.
    pub fn publisher(&self) -> PublisherName {
        // The constructors only make `pub-` and a valid publisher name.
        PublisherName(self.0[ROLE_PREFIX.len()..].to_owned())
    }

    /// The name a snapshot lists the role's file under: `pub-<publisher>.json`.
    pub fn meta_name(&self) -> String {
        format!("{}.json", self.0)
    }
}

string_name!(RoleName);

/// The one path pattern a delegation to a publisher may have: `plugins/<publisher>/*/*`.
/// As in section 4.5 of the specification, `*` matches one whole segment and never a `/`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPattern {
    publisher: PublisherName,
}

/// The first segment of every publisher's target paths.
const PLUGINS_SEGMENT: &str = "plugins";

impl PathPattern {
    /// The pattern of `publisher`'s targets.
    pub fn of(publisher: &PublisherName) -> PathPattern {
        PathPattern {
            publisher: publisher.clone(),
        }
    }

    /// `text` as a path pattern.
    ///
    /// # Errors
    ///
    /// [`NameError`] unless it is exactly `plugins/<publisher>/*/*`.
    pub fn parse(text: &str) -> Result<PathPattern, NameError> {
        let mut segments = text.split('/');
        let shape = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        );
        match shape {
            (Some(PLUGINS_SEGMENT), Some(publisher), Some("*"), Some("*"), None) => {
                PublisherName::parse(publisher)
                    .map(|publisher| PathPattern { publisher })
                    .map_err(|_| NameError::new(NameKind::PathPattern, text))
            }
            _ => Err(NameError::new(NameKind::PathPattern, text)),
        }
    }

    /// The publisher the pattern is of.
    pub fn publisher(&self) -> &PublisherName {
        &self.publisher
    }

    /// Whether `path` is `plugins/<publisher>/<one segment>/<one segment>`.
    pub fn matches(&self, path: &TargetPath) -> bool {
        let mut segments = path.segments();
        segments.next() == Some(PLUGINS_SEGMENT)
            && segments.next() == Some(self.publisher.as_str())
            && segments.next().is_some()
            && segments.next().is_some()
            && segments.next().is_none()
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PLUGINS_SEGMENT}/{}/*/*", self.publisher)
    }
}

impl FromStr for PathPattern {
    type Err = NameError;

    fn from_str(text: &str) -> Result<PathPattern, NameError> {
        PathPattern::parse(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publisher(name: &str) -> PublisherName {
        PublisherName::parse(name).unwrap()
    }

    fn path(text: &str) -> TargetPath {
        TargetPath::parse(text).unwrap()
    }

    #[test]
    fn target_paths_of_the_grammar_are_accepted() {
        for text in [
            "indexes/stable.json",
            "a/b-c_d+e.1",
            "top.bin",
            &"a".repeat(512),
        ] {
            assert_eq!(TargetPath::parse(text).unwrap().as_str(), text);
        }
    }

    #[test]
    fn target_paths_outside_the_grammar_are_refused() {
        let long = "a".repeat(513);
        for text in [
            "", "/a", "a/", "a//b", "./a", "a/../b", "..", "a\\b", "a b", "a%2fb", "é", "a:b",
            &long,
        ] {
            assert_eq!(
                TargetPath::parse(text),
                Err(NameError {
                    kind: NameKind::TargetPath,
                    value: text.to_owned()
                }),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_target_path_is_looked_up_by_its_text() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(path("indexes/stable.json"), 1);
        assert_eq!(map.get("indexes/stable.json"), Some(&1));
    }

    #[test]
    fn publisher_names_of_the_grammar_are_accepted() {
        for name in ["ecc", "a-b", "kz-ecc-2", "0ab", &"a".repeat(32)] {
            assert_eq!(publisher(name).as_str(), name);
        }
    }

    #[test]
    fn publisher_names_outside_the_grammar_are_refused() {
        let long = "a".repeat(33);
        for name in [
            "", "ab", "-ab", "ab-", "Abc", "a_b", "a.b", "a b", "ab/c", "pub-é", &long,
        ] {
            assert!(PublisherName::parse(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn reserved_publisher_names_are_refused() {
        for name in RESERVED_PUBLISHERS {
            assert!(PublisherName::parse(name).is_err(), "{name}");
        }
    }

    #[test]
    fn a_role_name_is_pub_and_the_publisher_and_back() {
        let role = RoleName::of(&publisher("ecc"));
        assert_eq!(role.as_str(), "pub-ecc");
        assert_eq!(role.publisher(), publisher("ecc"));
        assert_eq!(role.meta_name(), "pub-ecc.json");
        assert_eq!(RoleName::parse("pub-ecc").unwrap(), role);
    }

    #[test]
    fn role_names_not_of_a_publisher_are_refused() {
        for name in [
            "root",
            "targets",
            "snapshot",
            "timestamp",
            "ecc",
            "pub-",
            "pub-ab",
            "pub-root",
            "pub-Ecc",
            "pubecc",
            "PUB-ecc",
            "pub-ecc/x",
        ] {
            assert!(RoleName::parse(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn a_role_name_round_trips_through_serde_and_refuses_bad_names() {
        let role = RoleName::parse("pub-ecc").unwrap();
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"pub-ecc\"");
        assert_eq!(serde_json::from_str::<RoleName>(&json).unwrap(), role);
        assert!(serde_json::from_str::<RoleName>("\"targets\"").is_err());
    }

    #[test]
    fn a_publisher_name_round_trips_through_serde_and_refuses_bad_names() {
        let name = PublisherName::parse("ecc").unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"ecc\"");
        assert_eq!(serde_json::from_str::<PublisherName>(&json).unwrap(), name);
        for bad in [
            "\"root\"",
            "\"Ecc\"",
            "\"ab\"",
            "\"-ecc\"",
            "\"pub-ecc/x\"",
            "7",
        ] {
            assert!(serde_json::from_str::<PublisherName>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_path_pattern_is_exactly_plugins_publisher_star_star() {
        let pattern = PathPattern::parse("plugins/ecc/*/*").unwrap();
        assert_eq!(pattern, PathPattern::of(&publisher("ecc")));
        assert_eq!(pattern.to_string(), "plugins/ecc/*/*");
        for text in [
            "plugins/ecc/*",
            "plugins/ecc/*/*/*",
            "plugins/ecc/**",
            "plugins/ecc/x/*",
            "plugins/*/*/*",
            "plugins/root/*/*",
            "indexes/ecc/*/*",
            "plugins/ecc/*/*.onclp",
            "/plugins/ecc/*/*",
        ] {
            assert!(PathPattern::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn the_path_pattern_matches_one_segment_per_star() {
        let pattern = PathPattern::of(&publisher("abc"));
        assert!(pattern.matches(&path("plugins/abc/x/1.onclp")));
        assert!(pattern.matches(&path("plugins/abc/kz.abc.x/1.2.0-rc.1.onclp")));
        for outside in [
            "plugins/abc/x/y/1.onclp",
            "plugins/abcd/x/1.onclp",
            "plugins/ab/x/1.onclp",
            "plugins/abc/1.onclp",
            "plugins/abc",
            "indexes/abc/x/1.onclp",
            "other/plugins/abc/x/1.onclp",
        ] {
            assert!(!pattern.matches(&path(outside)), "{outside}");
        }
    }
}
