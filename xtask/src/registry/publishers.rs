//! The third-party publishers the site lists (`docs/design/publishers.md`, «Сайт»): every
//! `publishers/<name>/publisher.toml` ([`Registry::read`], the strict reading `tuf update`
//! does) and, for a publisher that is not revoked, the newest file of its role in
//! `tuf/v1/metadata/`. Each target of that role is read as the client reads it
//! ([`PublisherRelease::parse`]) plus the publisher's own rules (prefix, modules, bundles,
//! capabilities a manifest could declare); a target that breaks one is left out with a
//! warning, as the client leaves it out of its catalog. The role's signatures are not
//! checked here: `tuf check` verifies the same tree before it is published.
//!
//! The texts in the result are the owner's (`display`, `homepage`, `contact`) or the
//! publisher's (plugin names, `vcs`): untrusted, printed escaped by the templates. Every
//! link is made here from signed hashes and names (the package's is checked to be
//! [`mirror_url`]), never taken from a target as it is; `vcs.url` and the publisher's
//! homepage are shown as text only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use oncl_flows::capabilities::capability_text;
use oncl_pack::read_limited;
use oncl_plugin::operations::is_invisible;
use oncl_plugin::{Capabilities, is_symbolic_name};
use oncl_update::Channel;
#[cfg(doc)]
use oncl_update::catalog::mirror_url;
use oncl_update::catalog::{MIRROR_BASE, PublisherRelease};
use oncl_update::tuf::{Envelope, Limits, Profile, Targets};
use serde::Serialize;

use super::LANGS;
use crate::publishers::{Publisher, Registry, State};

/// The repository: the copies of the packages are its releases.
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// The reference builder's image (`docs/design/publishers.md`, Р32), pinned by the digest
/// each release names.
const BUILDER_IMAGE: &str = "ghcr.io/arynyklas/oncl-plugin-builder";

/// A publisher and the releases of its newest role: none for a revoked publisher, or one
/// without a role file yet.
#[derive(Debug, Clone)]
pub struct SitePublisher {
    /// The publisher, as its file says.
    pub publisher: Publisher,
    /// Its releases, by id, newest version first.
    pub releases: Vec<SiteRelease>,
}

/// A release of a publisher's role.
#[derive(Debug, Clone)]
pub struct SiteRelease {
    /// The release, as signed.
    pub release: PublisherRelease,
    /// What it may do, read as a manifest's `[capabilities]`.
    pub capabilities: Capabilities,
    /// Whether it is revoked: by its role or by the owner (`revoked_versions`).
    pub revoked: bool,
}

/// The publishers of `dir` (`publishers/`; no directory is none) with the releases of their
/// newest roles in the repository `repo` (`tuf/v1`), if given, by name; and the warnings
/// about the targets left out.
///
/// # Errors
///
/// The registry is invalid ([`Registry::read`]), or a role file cannot be read as a role.
pub fn load(dir: &Path, repo: Option<&Path>) -> anyhow::Result<(Vec<SitePublisher>, Vec<String>)> {
    let registry = Registry::read(dir)?;
    let newest = match repo {
        Some(repo) if repo.is_dir() => crate::tuf::repo::Listing::read(repo)?.newest_roles(),
        _ => BTreeMap::new(),
    };
    let mut warnings = Vec::new();
    let mut publishers = Vec::new();
    for publisher in registry.publishers() {
        let role = publisher.role();
        let releases = match (publisher.state, newest.get(&role), repo) {
            (State::Active | State::Retired, Some(version), Some(repo)) => {
                let what = oncl_update::tuf::layout::delegated_path(*version, &role);
                let read = read_limited(&repo.join(&what), Limits::default().delegated)
                    .and_then(|bytes| role_releases(publisher, &bytes, &what, &mut warnings));
                match read {
                    Ok(releases) => releases,
                    // A retired publisher's role is no longer delegated: `tuf check` reads it
                    // leniently, and so does the site.
                    Err(e) if publisher.state == State::Retired => {
                        warnings.push(format!("{what} is left out: {e:#}"));
                        Vec::new()
                    }
                    Err(e) => return Err(e),
                }
            }
            _ => Vec::new(),
        };
        publishers.push(SitePublisher {
            publisher: publisher.clone(),
            releases,
        });
    }
    Ok((publishers, warnings))
}

/// The releases of the role file `bytes` (`what`) of `publisher` that keep its rules.
fn role_releases(
    publisher: &Publisher,
    bytes: &[u8],
    what: &str,
    warnings: &mut Vec<String>,
) -> anyhow::Result<Vec<SiteRelease>> {
    let envelope = Envelope::parse(bytes, Limits::default().delegated, what)
        .map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    // A role delegates no further: the profile that refuses `delegations` reads it.
    let targets = Targets::from_signed(&envelope.signed, Profile::Legacy)
        .map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    let mut releases = Vec::new();
    for (path, target) in &targets.targets {
        let read = PublisherRelease::parse(&publisher.name, path, target)
            .map_err(|e| format!("{:#}", anyhow::Error::new(e)))
            .and_then(|release| site_release(publisher, release));
        match read {
            Ok(release) => releases.push(release),
            Err(why) => warnings.push(format!("{what}: the target {path} is left out: {why}")),
        }
    }
    releases.sort_by(|a, b| {
        let (a, b) = (a.release.release(), b.release.release());
        a.id.cmp(&b.id).then_with(|| b.version.cmp(&a.version))
    });
    Ok(releases)
}

/// The longest translation of a plugin's name, in characters (as in a manifest).
const MAX_NAME: usize = 128;

/// `release` of `publisher`, if it keeps the rules of the publisher's entry the client
/// checks: the id under its prefix, its modules and bundles, capabilities a manifest could
/// declare; and a name the site can show: each translation 1 to [`MAX_NAME`] characters,
/// without control or invisible characters ([`oncl_plugin::operations::is_invisible`]: bidi
/// overrides, zero-width ones).
fn site_release(publisher: &Publisher, release: PublisherRelease) -> Result<SiteRelease, String> {
    let r = release.release();
    for (lang, name) in [("ru", &r.name.ru), ("kk", &r.name.kk), ("en", &r.name.en)] {
        let count = name.chars().count();
        if name.trim().is_empty()
            || count > MAX_NAME
            || name.chars().any(|c| c.is_control() || is_invisible(c))
        {
            return Err(format!(
                "name.{lang} is not 1 to {MAX_NAME} characters without control or format \
                 characters"
            ));
        }
    }
    if !publisher.covers(&r.id) {
        return Err(format!(
            "{} is outside the prefix {}",
            r.id, publisher.id_prefix
        ));
    }
    if let Some(module) = r.modules.iter().find(|m| !publisher.modules.contains(m)) {
        return Err(format!("the module {module} is not the publisher's"));
    }
    if let Some(replaces) = &r.replaces
        && !publisher.bundles.contains(&replaces.symname)
    {
        return Err(format!(
            "the bundle {} is not the publisher's",
            replaces.symname
        ));
    }
    let capabilities = r
        .capabilities
        .as_ref()
        .ok_or_else(|| "no capabilities".to_owned())
        .and_then(|declared| {
            Capabilities::try_from(declared).map_err(|e| format!("capabilities: {e}"))
        })?;
    let revoked = r.revoked
        || publisher
            .revoked_versions
            .iter()
            .any(|v| v.id == r.id && v.version == r.version);
    Ok(SiteRelease {
        release,
        capabilities,
        revoked,
    })
}

/// What the site shows of the publishers.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PublishersData {
    /// Every publisher, by name.
    pub list: BTreeMap<String, PublisherData>,
    /// The names in each language's order of their display names.
    pub order: BTreeMap<String, Vec<String>>,
    /// The plugins of the publishers that are not revoked, by id.
    pub plugins: BTreeMap<String, PublisherPluginData>,
    /// Those plugins' ids in each language's order of their names.
    pub catalog: BTreeMap<String, Vec<String>>,
}

/// A publisher.
#[derive(Debug, Clone, Serialize)]
pub struct PublisherData {
    /// Its name: the directory and the page.
    pub name: String,
    /// `active`, `retired` or `revoked`.
    pub state: &'static str,
    /// When it was revoked, `YYYY-MM-DD`.
    pub revoked: Option<String>,
    /// Its name for people, by language.
    pub display: BTreeMap<String, String>,
    /// The prefix of its plugin ids.
    pub id_prefix: String,
    /// Its website, shown as text.
    pub homepage: Option<String>,
    /// Where security reports go.
    pub contact: Option<String>,
    /// The modules its plugins may serve.
    pub modules: Vec<String>,
    /// The bundles of the original its plugins may replace.
    pub bundles: Vec<String>,
    /// Its plugins' ids, in order; none for a revoked publisher.
    pub plugins: Vec<String>,
}

/// A plugin of a publisher: its newest release's name, modules and capabilities, and every
/// version of the role.
#[derive(Debug, Clone, Serialize)]
pub struct PublisherPluginData {
    /// Its id.
    pub id: String,
    /// Its publisher's name.
    pub publisher: String,
    /// Its name, by language.
    pub name: BTreeMap<String, String>,
    /// The `id` of its row in the catalog, the symbolic name of the bundle it replaces,
    /// when no other row has it (set by [`super::data::site_data`]).
    pub anchor: Option<String>,
    /// The bundle of the original it replaces.
    pub replaces: Option<ReplacesData>,
    /// The modules it serves.
    pub modules: Vec<String>,
    /// What it may do, a line each, by language.
    pub capabilities: BTreeMap<String, Vec<String>>,
    /// The version each channel offers, for an active publisher: the newest one not revoked
    /// (`stable` releases are offered on `beta` too).
    pub channels: BTreeMap<String, OfferedData>,
    /// Every version of the role, newest first.
    pub versions: Vec<VersionData>,
}

/// `replaces`.
#[derive(Debug, Clone, Serialize)]
pub struct ReplacesData {
    /// The bundle's symbolic name.
    pub symname: String,
    /// Its version.
    pub version: String,
}

/// A version a channel offers.
#[derive(Debug, Clone, Serialize)]
pub struct OfferedData {
    /// The version.
    pub version: String,
    /// The share of installations offered it, in percent.
    pub rollout: u8,
}

/// A version of a publisher's plugin and the files of its release in the project's
/// Releases.
#[derive(Debug, Clone, Serialize)]
pub struct VersionData {
    /// The version.
    pub version: String,
    /// The channel the publisher chose.
    pub channel: &'static str,
    /// The share of installations offered it, in percent.
    pub rollout: u8,
    /// The oldest core it runs on.
    pub min_core: String,
    /// Whether it is revoked.
    pub revoked: bool,
    /// The copy of the package.
    pub package_url: String,
    /// The package's sha256, hex.
    pub sha256: String,
    /// The package's size in bytes.
    pub size: u64,
    /// The license, an SPDX expression.
    pub license: String,
    /// `<id>-<version>.src.tar.gz`.
    pub source_name: String,
    /// The copy of the source archive.
    pub source_url: String,
    /// The archive's sha256, hex.
    pub source_sha256: String,
    /// The crate's directory in the archive's `src/`.
    pub source_path: String,
    /// `BUILDINFO.json` of the release: how it was rebuilt and whether `vcs` matched.
    pub buildinfo_url: String,
    /// The release's page.
    pub release_url: String,
    /// The git revision the publisher names, shown as text.
    pub vcs: Option<VcsData>,
    /// The command that rebuilds the package from the archive in the reference builder.
    pub verify: String,
}

/// `source.vcs`.
#[derive(Debug, Clone, Serialize)]
pub struct VcsData {
    /// The repository.
    pub url: String,
    /// The commit.
    pub rev: String,
}

/// The publishers' data. `taken` are the `id`s the catalog's other rows have: the symbolic
/// names of the ports' bundles.
pub fn publishers_data(publishers: &[SitePublisher], taken: &BTreeSet<String>) -> PublishersData {
    let mut list = BTreeMap::new();
    let mut plugins = BTreeMap::new();
    let mut anchors = taken.clone();
    for site in publishers {
        let p = &site.publisher;
        let mut ids = Vec::new();
        if p.state != State::Revoked {
            for releases in site
                .releases
                .chunk_by(|a, b| a.release.release().id == b.release.release().id)
            {
                let mut plugin = plugin_data(p, releases);
                // The bundle's row is the client's hint target: only a publisher that may
                // still offer the plugin takes it.
                plugin.anchor =
                    plugin
                        .replaces
                        .as_ref()
                        .map(|r| r.symname.clone())
                        .filter(|symname| {
                            p.is_active()
                                && is_symbolic_name(symname)
                                && anchors.insert(symname.clone())
                        });
                ids.push(plugin.id.clone());
                plugins.insert(plugin.id.clone(), plugin);
            }
        }
        list.insert(
            p.name.as_str().to_owned(),
            PublisherData {
                name: p.name.as_str().to_owned(),
                state: p.state.as_str(),
                revoked: p.revoked.clone(),
                display: BTreeMap::from([
                    ("ru".to_owned(), p.display.ru.clone()),
                    ("kk".to_owned(), p.display.kk.clone()),
                    ("en".to_owned(), p.display.en.clone()),
                ]),
                id_prefix: p.id_prefix.clone(),
                homepage: p.homepage.clone(),
                contact: p.contact.clone(),
                modules: p.modules.clone(),
                bundles: p.bundles.clone(),
                plugins: ids,
            },
        );
    }
    let order = LANGS
        .iter()
        .map(|(lang, _)| {
            let mut names: Vec<&String> = list.keys().collect();
            names.sort_by_cached_key(|name| (list[*name].display[*lang].to_lowercase(), *name));
            ((*lang).to_owned(), names.into_iter().cloned().collect())
        })
        .collect();
    let catalog = LANGS
        .iter()
        .map(|(lang, _)| {
            let mut ids: Vec<&String> = plugins.keys().collect();
            ids.sort_by_cached_key(|id| {
                let plugin: &PublisherPluginData = &plugins[*id];
                (plugin.name[*lang].to_lowercase(), *id)
            });
            ((*lang).to_owned(), ids.into_iter().cloned().collect())
        })
        .collect();
    PublishersData {
        list,
        order,
        plugins,
        catalog,
    }
}

/// The plugin of `releases`, one id's, newest first.
fn plugin_data(publisher: &Publisher, releases: &[SiteRelease]) -> PublisherPluginData {
    let newest = &releases[0];
    let r = newest.release.release();
    let lines = newest.capabilities.lines();
    let channels = if publisher.is_active() {
        [Channel::Beta, Channel::Stable]
            .into_iter()
            .filter_map(|channel| {
                releases
                    .iter()
                    .find(|s| !s.revoked && s.release.offered_on(channel))
                    .map(|s| {
                        let offered = s.release.release();
                        (
                            channel.as_str().to_owned(),
                            OfferedData {
                                version: offered.version.to_string(),
                                rollout: offered.rollout,
                            },
                        )
                    })
            })
            .collect()
    } else {
        BTreeMap::new()
    };
    PublisherPluginData {
        id: r.id.clone(),
        publisher: publisher.name.as_str().to_owned(),
        name: BTreeMap::from([
            ("ru".to_owned(), r.name.ru.clone()),
            ("kk".to_owned(), r.name.kk.clone()),
            ("en".to_owned(), r.name.en.clone()),
        ]),
        anchor: None,
        replaces: r.replaces.as_ref().map(|replaces| ReplacesData {
            symname: replaces.symname.clone(),
            version: replaces.version.clone(),
        }),
        modules: r.modules.clone(),
        capabilities: LANGS
            .iter()
            .map(|(lang, l)| {
                (
                    (*lang).to_owned(),
                    lines.iter().map(|line| capability_text(line, *l)).collect(),
                )
            })
            .collect(),
        channels,
        versions: releases
            .iter()
            .map(|site| version_data(publisher, site))
            .collect(),
    }
}

/// A version's data. The `.src.diff` of its release is not linked: whether it has one
/// depends on the history of the mirror, not on the role; the release's page lists it.
fn version_data(publisher: &Publisher, site: &SiteRelease) -> VersionData {
    let r = site.release.release();
    let source = site.release.source();
    let sha256 = r.package.sha256.to_string();
    let tag = format!("pub-{}-{sha256}", publisher.name);
    let files = format!("{MIRROR_BASE}{tag}/");
    let stem = format!("{}-{}", r.id, r.version);
    let source_name = format!("{stem}.src.tar.gz");
    VersionData {
        version: r.version.to_string(),
        channel: site.release.channel().as_str(),
        rollout: r.rollout,
        min_core: r.min_core.to_string(),
        revoked: site.revoked,
        package_url: r.package.url.clone(),
        sha256: sha256.clone(),
        size: r.package.size,
        license: source.license.clone(),
        source_url: format!("{files}{source_name}"),
        source_sha256: source.archive_sha256.to_string(),
        source_path: source.path.clone(),
        buildinfo_url: format!("{files}BUILDINFO.json"),
        release_url: format!("{REPOSITORY}/releases/tag/{tag}"),
        vcs: source.vcs.as_ref().map(|vcs| VcsData {
            url: vcs.url.clone(),
            rev: vcs.rev.clone(),
        }),
        verify: verify_commands(
            &source.builder.to_string(),
            &source_name,
            &source.path,
            &sha256,
        ),
        source_name,
    }
}

/// The commands that rebuild a package from its source archive (`source_name`, downloaded
/// into the current directory) in the reference builder of digest `builder` and compare it
/// with `sha256`: the dependencies fetched in one container, the build without a network in
/// another (the builder's `fetch` and `verify`). Exit 0 means the same bytes.
fn verify_commands(builder: &str, source_name: &str, path: &str, sha256: &str) -> String {
    const VOLUME: &str = "oncl-verify-cargo";
    let image = format!("{BUILDER_IMAGE}@sha256:{builder}");
    let common = "--read-only --cap-drop=ALL --security-opt no-new-privileges";
    let mounts = "--mount type=volume,dst=/build -v \"$PWD:/in:ro\"";
    let args = format!("--source /in/{source_name} --path={}", shell_quoted(path));
    [
        format!("docker volume create {VOLUME}"),
        format!("docker run --rm {common} -v {VOLUME}:/cargo {mounts} {image} fetch {args}"),
        format!(
            "docker run --rm --network=none {common} -v {VOLUME}:/cargo:ro {mounts} {image} \
             verify {args} --sha256 {sha256}"
        ),
        format!("docker volume rm {VOLUME}"),
    ]
    .join("\n")
}

/// `text` in single quotes for a POSIX shell, a `'` in it closed, escaped and reopened.
fn shell_quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn fixtures() -> PathBuf {
        oncl_testkit::workspace_root().join("fixtures/registry")
    }

    /// A copy of the fixture's registry and repository.
    fn copy() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (from, to) in [
            ("publishers", "publishers"),
            ("tuf/v1/metadata", "tuf/metadata"),
        ] {
            let to = dir.path().join(to);
            fs::create_dir_all(&to).unwrap();
            for entry in fs::read_dir(fixtures().join(from)).unwrap() {
                let entry = entry.unwrap();
                if entry.path().is_dir() {
                    fs::create_dir_all(to.join(entry.file_name())).unwrap();
                    for file in fs::read_dir(entry.path()).unwrap() {
                        let file = file.unwrap();
                        fs::copy(
                            file.path(),
                            to.join(entry.file_name()).join(file.file_name()),
                        )
                        .unwrap();
                    }
                } else {
                    fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
                }
            }
        }
        dir
    }

    #[test]
    fn no_registry_is_no_publishers() {
        let dir = tempfile::tempdir().unwrap();
        let (publishers, warnings) = load(&dir.path().join("publishers"), None).unwrap();
        assert!(publishers.is_empty() && warnings.is_empty());
        let data = publishers_data(&publishers, &BTreeSet::new());
        assert!(data.list.is_empty() && data.plugins.is_empty());
        assert_eq!(data.order["ru"], Vec::<String>::new());
        assert_eq!(data.catalog["en"], Vec::<String>::new());
    }

    #[test]
    fn without_the_repository_publishers_have_no_plugins() {
        let (publishers, warnings) = load(&fixtures().join("publishers"), None).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(publishers.len(), 3);
        assert!(publishers.iter().all(|p| p.releases.is_empty()));
    }

    #[test]
    fn a_revoked_publishers_role_is_not_read() {
        let dir = copy();
        let meta = dir.path().join("tuf/metadata");
        fs::write(meta.join("1.pub-gone.json"), "not json").unwrap();
        let repo = dir.path().join("tuf");
        let (publishers, _) = load(&dir.path().join("publishers"), Some(&repo)).unwrap();
        let gone = publishers
            .iter()
            .find(|p| p.publisher.name.as_str() == "gone")
            .unwrap();
        assert!(gone.releases.is_empty());
        // A retired publisher's role that cannot be read is a warning.
        fs::write(meta.join("1.pub-olden.json"), "not json").unwrap();
        let (publishers, warnings) = load(&dir.path().join("publishers"), Some(&repo)).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("1.pub-olden.json")),
            "{warnings:?}"
        );
        assert!(
            publishers
                .iter()
                .all(|p| p.publisher.name.as_str() != "olden" || p.releases.is_empty())
        );
        // An active publisher's role that cannot be read stops the build.
        fs::write(meta.join("2.pub-acme.json"), "not json").unwrap();
        let err = load(&dir.path().join("publishers"), Some(&repo)).unwrap_err();
        assert!(format!("{err:#}").contains("2.pub-acme.json"), "{err:#}");
    }

    #[test]
    fn a_broken_registry_stops_the_build() {
        let dir = copy();
        let file = dir.path().join("publishers/olden/publisher.toml");
        let text = fs::read_to_string(&file).unwrap();
        fs::write(&file, text.replace("retired", "sleeping")).unwrap();
        let err = load(&dir.path().join("publishers"), None).unwrap_err();
        assert!(format!("{err:#}").contains("olden"), "{err:#}");
    }

    #[test]
    fn a_path_is_quoted_for_the_shell() {
        assert_eq!(shell_quoted(""), "''");
        assert_eq!(shell_quoted("crates/market"), "'crates/market'");
        assert_eq!(shell_quoted("a';rm -rf ~;'"), r"'a'\'';rm -rf ~;'\'''");
    }
}
