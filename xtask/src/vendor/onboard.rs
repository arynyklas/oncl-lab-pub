//! A publisher's onboarding pull request (`docs/design/publishers.md`, «Подключение
//! издателя»): `vendor onboard` writes `publishers/<name>/publisher.toml`, and `vendor
//! check-onboarding` (CI on every pull request) checks the registry as it is in the checkout:
//! each file by its schema and the rules between publishers, no key of a root, no plugin of the
//! owner's indexes under a prefix, and, against the base, no entry of `publishers/` removed or
//! renamed (Р28) and every entry of `publishers/builders.toml` kept unchanged in its place
//! ([`Builders::check_kept`]).

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::index::Index;
use oncl_update::tuf::{PublicKey, PublisherName};

use super::Layout;
use super::git::Git;
use crate::publishers::builders::{self, Builders};
use crate::publishers::{self, Registry};

/// What `vendor onboard` writes.
#[derive(Clone, Debug, Default)]
pub struct Onboarding {
    /// The publisher's name.
    pub name: String,
    /// Its id prefix (`kz.ecc.`).
    pub prefix: String,
    /// The modules its plugins serve.
    pub modules: Vec<String>,
    /// The bundles of the original they stand for.
    pub bundles: Vec<String>,
    /// Its name in Russian, Kazakh and English.
    pub display: [String; 3],
    /// The GitHub accounts that open its release pull requests.
    pub github: Vec<String>,
    /// Its public keys, 64 hex each.
    pub keys: Vec<String>,
    /// How many keys sign a role file.
    pub threshold: u32,
    /// Its website.
    pub homepage: Option<String>,
    /// Where security reports go.
    pub contact: Option<String>,
}

fn quoted(text: &str) -> String {
    toml::Value::String(text.to_owned()).to_string()
}

fn list(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|i| quoted(i)).collect();
    format!("[{}]", quoted.join(", "))
}

/// The text of `publisher.toml` of `onboarding`.
pub fn publisher_toml(onboarding: &Onboarding) -> String {
    let o = onboarding;
    let mut text = String::new();
    let _ = writeln!(text, "name = {}", quoted(&o.name));
    let _ = writeln!(text, "state = \"active\"");
    let _ = writeln!(
        text,
        "display = {{ ru = {}, kk = {}, en = {} }}",
        quoted(&o.display[0]),
        quoted(&o.display[1]),
        quoted(&o.display[2])
    );
    let _ = writeln!(text, "id_prefix = {}", quoted(&o.prefix));
    let _ = writeln!(text, "modules = {}", list(&o.modules));
    let _ = writeln!(text, "bundles = {}", list(&o.bundles));
    let _ = writeln!(text, "github = {}", list(&o.github));
    if let Some(homepage) = &o.homepage {
        let _ = writeln!(text, "homepage = {}", quoted(homepage));
    }
    if let Some(contact) = &o.contact {
        let _ = writeln!(text, "contact = {}", quoted(contact));
    }
    let _ = writeln!(text, "threshold = {}", o.threshold);
    for key in &o.keys {
        let _ = writeln!(text, "\n[[keys]]\npublic = {}", quoted(key));
    }
    text
}

/// Writes `publishers/<name>/publisher.toml` of `onboarding` into the checkout `root` and
/// checks the registry with it ([`check_onboarding`], without a base).
///
/// # Errors
///
/// The file exists, it breaks a rule, or the registry with it does.
pub fn onboard(root: &Path, layout: &Layout, onboarding: &Onboarding) -> anyhow::Result<PathBuf> {
    let name = PublisherName::parse(&onboarding.name).map_err(|e| anyhow::anyhow!("{e}"))?;
    for key in &onboarding.keys {
        PublicKey::from_hex(key)
            .with_context(|| format!("--key {key:?} is not 64 lowercase hex digits"))?;
    }
    let text = publisher_toml(onboarding);
    publishers::parse_publisher(&text, name.as_str())?;
    let dir = root.join(layout.publishers).join(name.as_str());
    let file = dir.join(publishers::FILE_NAME);
    if file.exists() {
        bail!("{} exists already", file.display());
    }
    fs::create_dir_all(&dir)?;
    fs::write(&file, &text).with_context(|| format!("writing {}", file.display()))?;
    if let Err(e) = check_onboarding(root, layout, None) {
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir(&dir);
        return Err(e);
    }
    Ok(file)
}

/// `name` and `id_prefix` of a `publisher.toml` as any schema has them.
fn name_and_prefix(text: &[u8]) -> Option<(String, String)> {
    let value: toml::Value = toml::from_str(std::str::from_utf8(text).ok()?).ok()?;
    Some((
        value.get("name")?.as_str()?.to_owned(),
        value.get("id_prefix")?.as_str()?.to_owned(),
    ))
}

/// Checks the registry of the checkout `root` (see the module's description); with `base`,
/// also against that revision. Returns a line per finding of note.
///
/// # Errors
///
/// The first rule broken.
pub fn check_onboarding(
    root: &Path,
    layout: &Layout,
    base: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let mut notes = Vec::new();
    let dir = root.join(layout.publishers);
    let registry = Registry::read(&dir)?;
    notes.push(format!(
        "{} publishers ({} active)",
        registry.publishers().count(),
        registry.active().count()
    ));
    let tuf = root.join(layout.tuf);
    if tuf.join("metadata/1.root.json").is_file() {
        let chain = crate::tuf::check::committed_chain(&tuf)?;
        let roots: Vec<(&str, &oncl_update::tuf::Root)> =
            chain.iter().map(|r| ("the root of tuf/v1", r)).collect();
        registry.check_roots(&roots)?;
    }
    let indexes_dir = root.join(layout.indexes);
    if indexes_dir.is_dir() {
        let indexes = crate::tuf::update::read_indexes(&indexes_dir)?
            .into_iter()
            .map(|(_, bytes)| Index::from_json(&bytes).map_err(|e| anyhow::anyhow!("{e}")))
            .collect::<anyhow::Result<Vec<_>>>()?;
        registry.check_indexes(&indexes)?;
    }
    let builders_file = dir.join(builders::FILE_NAME);
    let builders = if builders_file.is_file() {
        Builders::read(&builders_file)?
    } else {
        Builders::default()
    };
    notes.push(format!("{} builder images", builders.iter().count()));
    if let Some(base) = base {
        let git = Git::new(root);
        let commit = git.commit(base)?;
        let files = git.files(&commit, &[layout.publishers], 1 << 20)?;
        let builders_path = format!("{}/{}", layout.publishers, builders::FILE_NAME);
        if let Some(text) = files.get(&builders_path) {
            let text = std::str::from_utf8(text).context("builders.toml on the base")?;
            builders.check_kept(&Builders::parse(text)?)?;
        }
        let mut gone = Vec::new();
        for (path, bytes) in &files {
            if !path.ends_with(&format!("/{}", publishers::FILE_NAME)) {
                continue;
            }
            let Some((name, prefix)) = name_and_prefix(bytes) else {
                continue;
            };
            let now = PublisherName::parse(&name)
                .ok()
                .and_then(|n| registry.get(&n).cloned());
            match now {
                None => gone.push(format!("{name} is gone")),
                Some(p) if p.id_prefix != prefix => gone.push(format!(
                    "{name} has the id_prefix {} instead of {prefix}",
                    p.id_prefix
                )),
                Some(_) => {}
            }
        }
        if !gone.is_empty() {
            bail!(
                "{}: an entry of publishers/ is never removed, and its name and id_prefix never \
                 change (Р28)",
                gone.join("; ")
            );
        }
        notes.push(format!("kept everything of {base}"));
    }
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_onboarding_file_reads_back_as_the_publisher() {
        let key = oncl_update::tuf::SigningKey::from_seed(&[9; 32])
            .unwrap()
            .public()
            .to_hex();
        let onboarding = Onboarding {
            name: "ecc".into(),
            prefix: "kz.ecc.".into(),
            modules: vec!["kz.ecc.market.Signer".into()],
            bundles: vec!["kz.ecc.market".into()],
            display: ["ТОО «Э\"К»".into(), "ЕКК".into(), "ECC".into()],
            github: vec!["ecc-release".into()],
            keys: vec![key],
            threshold: 1,
            homepage: Some("https://ecc.kz/".into()),
            contact: None,
        };
        let text = publisher_toml(&onboarding);
        let p = publishers::parse_publisher(&text, "ecc").unwrap();
        assert_eq!(p.display.ru, "ТОО «Э\"К»");
        assert_eq!(p.modules, onboarding.modules);
        assert_eq!(p.keys.len(), 1);
        assert!(p.is_active());
    }
}
