//! The names the catalog of publishers reads: plugin ids, the id prefixes publishers own,
//! module names and the symbolic names of original bundles. Each holds the grammar of the
//! plugin manifest (`oncl-plugin`'s `manifest.rs`), repeated here because this crate does
//! not depend on the plugin format.

use crate::tuf::names::string_name;
use crate::tuf::{NameError, NameKind};

/// The id prefix of the project: no publisher's prefix covers it or lies under it.
pub const PROJECT_PREFIX: &str = "io.github.arynyklas.openncalayer.";

/// Longest plugin id, in bytes.
const MAX_ID: usize = 64;
/// Longest module name or bundle symbolic name, in bytes.
const MAX_SYMBOLIC_NAME: usize = 128;

/// `^[a-z0-9][a-z0-9.-]{1,62}[a-z0-9]$` with at least one dot.
fn is_plugin_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    (3..=MAX_ID).contains(&bytes.len())
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge)
        && bytes.iter().all(|b| edge(b) || matches!(b, b'.' | b'-'))
        && bytes.contains(&b'.')
}

/// `^[A-Za-z0-9._-]{1,128}$`.
fn is_symbolic_name(text: &str) -> bool {
    (1..=MAX_SYMBOLIC_NAME).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A plugin id: a lowercase reverse domain name, `^[a-z0-9][a-z0-9.-]{1,62}[a-z0-9]$` with
/// at least one dot.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginId(String);

impl PluginId {
    /// `text` as a plugin id.
    ///
    /// # Errors
    ///
    /// [`NameError`] if it breaks the grammar.
    pub fn parse(text: &str) -> Result<PluginId, NameError> {
        if is_plugin_id(text) {
            Ok(PluginId(text.to_owned()))
        } else {
            Err(NameError::new(NameKind::PluginId, text))
        }
    }
}

string_name!(PluginId);

/// The id prefix a publisher owns: a reverse domain name of at least two labels followed by
/// a dot, such as `kz.ecc.`; no label is empty, and the prefix leaves room for an id.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdPrefix(String);

impl IdPrefix {
    /// `text` as an id prefix.
    ///
    /// # Errors
    ///
    /// [`NameError`] if it breaks the grammar.
    pub fn parse(text: &str) -> Result<IdPrefix, NameError> {
        let valid = text.len() < MAX_ID
            && text.strip_suffix('.').is_some_and(|stem| {
                is_plugin_id(stem) && stem.split('.').all(|label| !label.is_empty())
            });
        if valid {
            Ok(IdPrefix(text.to_owned()))
        } else {
            Err(NameError::new(NameKind::IdPrefix, text))
        }
    }

    /// Whether `id` lies under the prefix.
    pub fn covers(&self, id: &str) -> bool {
        id.len() > self.0.len() && id.starts_with(&self.0)
    }

    /// Whether one of the two prefixes lies under the other (or they are the same).
    pub fn overlaps(&self, other: &str) -> bool {
        self.0.starts_with(other) || other.starts_with(&self.0)
    }
}

string_name!(IdPrefix);

/// The name of a protocol module a plugin serves: `^[A-Za-z0-9._-]{1,128}$`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleName(String);

impl ModuleName {
    /// `text` as a module name.
    ///
    /// # Errors
    ///
    /// [`NameError`] if it breaks the grammar.
    pub fn parse(text: &str) -> Result<ModuleName, NameError> {
        if is_symbolic_name(text) {
            Ok(ModuleName(text.to_owned()))
        } else {
            Err(NameError::new(NameKind::ModuleName, text))
        }
    }
}

string_name!(ModuleName);

/// The OSGi symbolic name of an original bundle a plugin stands for (`replaces.symname`):
/// `^[A-Za-z0-9._-]{1,128}$`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BundleName(String);

impl BundleName {
    /// `text` as a bundle name.
    ///
    /// # Errors
    ///
    /// [`NameError`] if it breaks the grammar.
    pub fn parse(text: &str) -> Result<BundleName, NameError> {
        if is_symbolic_name(text) {
            Ok(BundleName(text.to_owned()))
        } else {
            Err(NameError::new(NameKind::BundleName, text))
        }
    }
}

string_name!(BundleName);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_ids_follow_the_manifest_grammar() {
        for good in ["kz.ecc.market", "a.b", "x-1.y2"] {
            assert!(PluginId::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "kzecc", "Kz.ecc", ".kz.ecc", "kz.ecc.", "kz_ecc.x", "", "ab",
        ] {
            assert!(PluginId::parse(bad).is_err(), "{bad}");
        }
        assert!(PluginId::parse(&format!("a.{}", "b".repeat(63))).is_err());
    }

    #[test]
    fn id_prefixes_need_two_labels_and_a_trailing_dot() {
        for good in ["kz.ecc.", "com.example.sub."] {
            assert!(IdPrefix::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "kz.ecc", "ecc.", "kz..ecc.", ".kz.ecc.", "kz.Ecc.", "kz.ecc-.",
        ] {
            assert!(IdPrefix::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_prefix_covers_ids_under_it_but_not_itself_or_a_sibling() {
        let prefix = IdPrefix::parse("kz.ecc.").unwrap();
        assert!(prefix.covers("kz.ecc.market"));
        assert!(!prefix.covers("kz.ecc."));
        assert!(!prefix.covers("kz.eccx.market"));
        assert!(!prefix.covers("kz.ec"));
        assert!(prefix.overlaps("kz."));
        assert!(prefix.overlaps("kz.ecc.sub."));
        assert!(!prefix.overlaps("kz.eccx."));
    }

    #[test]
    fn module_and_bundle_names_follow_the_symbolic_name_grammar() {
        assert!(ModuleName::parse("kz.ecc.market.Signer").is_ok());
        assert!(BundleName::parse("kz.gov.pki.knca_basics").is_ok());
        assert!(ModuleName::parse("").is_err());
        assert!(ModuleName::parse("a b").is_err());
        assert!(BundleName::parse(&"a".repeat(129)).is_err());
    }
}
