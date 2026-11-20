//! `cargo xtask vendor …` (`docs/design/publishers.md`, «Команды издателя»; the walkthrough is
//! `docs/dev/publishers.md`).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::{Subcommand, ValueEnum};
use oncl_pack::source::{MAX_ARCHIVE, Tree};
use oncl_update::catalog::{PublisherRelease, PublisherTarget, mirror_url};
use oncl_update::tuf::{PublisherName, TargetPath, layout as tuf_layout};
use oncl_update::{Channel, Version};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::docker::{self, Engine};
use super::draft::{self, Addition, Draft};
use super::fetch::{ArchiveFetcher, HttpsFetcher};
use super::mirror::{self, BuildInfo, BuilderInfo, FileInfo, SourceInfo};
use super::onboard::{self, Onboarding};
use super::pr::{self, VerdictInputs};
use super::verdict::{CheckResult, Checks, SCHEMA};
use super::{Layout, checks, keys, licenses};
use crate::publishers::builders::{self, Builders};
use crate::publishers::{Publisher, Registry};
use crate::tuf::PassphraseSource;
use crate::tuf::keystore::Unlock;
use crate::tuf::repo::{self, Listing};

/// A release channel on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ChannelArg {
    /// Offered to the beta channel only.
    Beta,
    /// Offered to both channels.
    Stable,
}

impl From<ChannelArg> for Channel {
    fn from(c: ChannelArg) -> Channel {
        match c {
            ChannelArg::Beta => Channel::Beta,
            ChannelArg::Stable => Channel::Stable,
        }
    }
}

/// The subcommands of `cargo xtask vendor`.
#[derive(Subcommand)]
pub enum VendorCommand {
    /// A new Ed25519 key of a publisher, encrypted with a passphrase, written into a key
    /// directory outside the repository; prints its public key and key id.
    Keygen {
        /// The publisher.
        #[arg(long)]
        name: String,
        /// The key directory (not where git would commit it).
        #[arg(long)]
        out: PathBuf,
        /// Read the passphrase from this file instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Writes publishers/<name>/publisher.toml of an onboarding pull request and checks it.
    Onboard {
        /// The publisher's name.
        #[arg(long)]
        name: String,
        /// Its id prefix, a reverse domain ending in `.` (kz.ecc.).
        #[arg(long)]
        prefix: String,
        /// A module its plugins serve (repeat).
        #[arg(long = "module", required = true)]
        modules: Vec<String>,
        /// A bundle of the original its plugins stand for (repeat).
        #[arg(long = "bundle")]
        bundles: Vec<String>,
        /// Its name in Russian.
        #[arg(long)]
        display_ru: String,
        /// Its name in Kazakh.
        #[arg(long)]
        display_kk: String,
        /// Its name in English.
        #[arg(long)]
        display_en: String,
        /// A GitHub account that opens its release pull requests (repeat).
        #[arg(long = "github", required = true)]
        github: Vec<String>,
        /// A public key, 64 hex (repeat).
        #[arg(long = "key", required = true)]
        keys: Vec<String>,
        /// How many keys sign a role file.
        #[arg(long, default_value_t = 1)]
        threshold: u32,
        /// Its website.
        #[arg(long)]
        homepage: Option<String>,
        /// Where security reports go.
        #[arg(long)]
        contact: Option<String>,
    },
    /// Checks publishers/ of the checkout: each file, the rules between publishers, and
    /// against --base no entry removed or renamed, builders.toml and sdk-revisions.toml kept
    /// and each SDK revision's tag pointing to its commit.
    CheckOnboarding {
        /// The revision the registry must extend (main).
        #[arg(long)]
        base: Option<String>,
    },
    /// The canonical source archive of a directory or of a git revision (`oncl-pack source`);
    /// prints its sha256 and length.
    Source {
        /// The directory of the sources.
        #[arg(long, conflicts_with_all = ["git", "rev"])]
        dir: Option<PathBuf>,
        /// The git repository of the sources.
        #[arg(long, requires = "rev")]
        git: Option<PathBuf>,
        /// The revision.
        #[arg(long, requires = "git")]
        rev: Option<String>,
        /// The archive to write, `<id>-<version>.src.tar.gz`.
        #[arg(long)]
        out: PathBuf,
    },
    /// The reference build of the archive in the builder image (Docker or Podman): the
    /// package, THIRD-PARTY.txt and BUILDINFO.json in --out.
    Build {
        /// The canonical source archive.
        #[arg(long)]
        source: PathBuf,
        /// The crate directory under src/ (source.path; "" for src/ itself).
        #[arg(long)]
        path: String,
        /// The builder's digest (sha256:…) from publishers/builders.toml; the newest by
        /// default.
        #[arg(long)]
        builder: Option<String>,
        /// Another image, built locally: its output cannot be released (no digest).
        #[arg(long, conflicts_with = "builder")]
        image: Option<String>,
        /// Where the outputs go.
        #[arg(long, default_value = "target/vendor/build")]
        out: PathBuf,
        /// Cargo's --jobs inside the container.
        #[arg(long)]
        jobs: Option<u32>,
    },
    /// Adds a package built by `vendor build` to the draft of the next role version
    /// (target/vendor/<name>/role.json).
    Add {
        /// The publisher.
        #[arg(long)]
        name: String,
        /// The output directory of `vendor build`.
        #[arg(long)]
        build: PathBuf,
        /// Where CI downloads the source archive once (anonymous https://).
        #[arg(long)]
        fetch: String,
        /// The git repository the archive was made from.
        #[arg(long, requires = "vcs_rev")]
        vcs_url: Option<String>,
        /// The commit (40 or 64 hex).
        #[arg(long, requires = "vcs_url")]
        vcs_rev: Option<String>,
        /// The channel.
        #[arg(long, value_enum)]
        channel: ChannelArg,
        /// The share of installations offered the release, 0 to 100.
        #[arg(long, default_value_t = 100)]
        rollout: u8,
    },
    /// Changes the channel (beta to stable), rollout or revocation of a release in the draft.
    Set {
        /// The publisher.
        #[arg(long)]
        name: String,
        /// The plugin.
        #[arg(long)]
        id: String,
        /// The version.
        #[arg(long)]
        version: Version,
        /// The new channel.
        #[arg(long, value_enum)]
        channel: Option<ChannelArg>,
        /// The new rollout.
        #[arg(long)]
        rollout: Option<u8>,
        /// Revoke the version.
        #[arg(long, conflicts_with = "unrevoke")]
        revoke: bool,
        /// Take the revocation back.
        #[arg(long)]
        unrevoke: bool,
    },
    /// Removes an old release from the draft, where check 8 allows.
    Prune {
        /// The publisher.
        #[arg(long)]
        name: String,
        /// The plugin.
        #[arg(long)]
        id: String,
        /// The version.
        #[arg(long)]
        version: Version,
    },
    /// Signs the draft as the next version of the role:
    /// tuf/v1/metadata/<N+1>.pub-<name>.json.
    Sign {
        /// The publisher.
        #[arg(long)]
        name: String,
        /// The key directory.
        #[arg(long)]
        keys: PathBuf,
        /// Days until the role expires (14 to 180).
        #[arg(long, default_value_t = 90)]
        expires_days: i64,
        /// Read the passphrase from this file instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Adds the signatures of the keys of a directory to a role file (a threshold above 1).
    Cosign {
        /// The role file.
        file: PathBuf,
        /// The key directory.
        #[arg(long)]
        keys: PathBuf,
        /// Read the passphrase from this file instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// The checks CI makes of a release pull request, on the commits --base..--head of this
    /// clone (commit the role file first).
    Check {
        /// The publisher.
        #[arg(long)]
        name: String,
        /// The base.
        #[arg(long, default_value = "origin/main")]
        base: String,
        /// The head.
        #[arg(long, default_value = "HEAD")]
        head: String,
        /// Do not download the source archives (checks 13 to 18 are skipped).
        #[arg(long)]
        offline: bool,
    },
    /// CI: checks 1–9, 11–18, 23 and 24 of a release pull request; prints the JSON verdict.
    CheckPr {
        /// The base revision (main).
        #[arg(long)]
        base: String,
        /// The head revision of the pull request.
        #[arg(long)]
        head: String,
        /// The pull request's author (check 2).
        #[arg(long)]
        author: String,
        /// Where verdict.json and the archives go.
        #[arg(long)]
        out: Option<PathBuf>,
        /// The git repository (the workspace by default).
        #[arg(long)]
        repo: Option<PathBuf>,
        /// The time of the check, RFC 3339 (now by default).
        #[arg(long, hide = true)]
        now: Option<String>,
    },
    /// CI: checks 19 and 20 of one archive in the builder image: the package and
    /// THIRD-PARTY.txt in --out, with rebuild.json.
    Rebuild {
        /// The archive.
        #[arg(long)]
        archive: PathBuf,
        /// The crate directory under src/.
        #[arg(long)]
        path: String,
        /// The builder's digest, sha256:…, listed in publishers/builders.toml.
        #[arg(long)]
        builder: String,
        /// Where the outputs go.
        #[arg(long)]
        out: PathBuf,
        /// Cargo's --jobs inside the container.
        #[arg(long)]
        jobs: Option<u32>,
    },
    /// CI: check 25 for every new target naming a git revision, git in a container of the
    /// builder image on --network; writes the report.
    Provenance {
        /// The base revision.
        #[arg(long)]
        base: String,
        /// The head revision.
        #[arg(long)]
        head: String,
        /// The archives of `check-pr --out`.
        #[arg(long)]
        archives: PathBuf,
        /// The container network git runs on: outbound internet only, nothing of the runner.
        #[arg(long)]
        network: String,
        /// The builder's digest (sha256:…); the newest of publishers/builders.toml by default.
        #[arg(long)]
        builder: Option<String>,
        /// The report to write (JSON).
        #[arg(long)]
        out: PathBuf,
    },
    /// CI: the whole verdict: checks 1–9 and 11–18, 23, 24 again (the archives handed over,
    /// hashed again), 17, 19 and 20 from every rebuild report, 21 and 22 by hashes computed
    /// here, 25 from the report; BUILDINFO.json of each new package into
    /// --out/<id>-<version>/, and verdict.json.
    Verdict {
        /// The base revision.
        #[arg(long)]
        base: String,
        /// The head revision.
        #[arg(long)]
        head: String,
        /// The pull request's author (check 2).
        #[arg(long)]
        author: String,
        /// The archives of `check-pr --out`.
        #[arg(long)]
        archives: PathBuf,
        /// The outputs of the rebuild jobs.
        #[arg(long)]
        rebuilt: PathBuf,
        /// The report of `vendor provenance`.
        #[arg(long)]
        provenance: Option<PathBuf>,
        /// Where the outputs go.
        #[arg(long)]
        out: PathBuf,
    },
    /// CI: the .src.diff of a new version's archive against the previous version's.
    SrcDiff {
        /// The previous version's archive (none for a first version).
        #[arg(long, requires = "old_sha256")]
        old: Option<PathBuf>,
        /// Its signed sha256.
        #[arg(long)]
        old_sha256: Option<String>,
        /// The new archive.
        #[arg(long)]
        new: PathBuf,
        /// The diff to write.
        #[arg(long)]
        out: PathBuf,
    },
    /// Downloads a published release's archive from the project's Releases, rebuilds it in
    /// its builder image and compares the package with the role's target.
    Verify {
        /// The publisher.
        #[arg(long)]
        name: String,
        /// The plugin.
        #[arg(long)]
        id: String,
        /// The version.
        #[arg(long)]
        version: Version,
    },
}

fn passphrase(file: Option<PathBuf>) -> PassphraseSource {
    file.map_or(PassphraseSource::Prompt, PassphraseSource::File)
}

fn publisher_of(root: &Path, name: &str) -> anyhow::Result<Publisher> {
    let name = PublisherName::parse(name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let registry = Registry::read(&root.join(Layout::REPO.publishers))?;
    registry
        .get(&name)
        .cloned()
        .with_context(|| format!("{name} is not in publishers/"))
}

fn now(text: Option<&str>) -> anyhow::Result<OffsetDateTime> {
    match text {
        Some(text) => OffsetDateTime::parse(text, &Rfc3339).context("--now is not RFC 3339"),
        None => Ok(OffsetDateTime::now_utc()),
    }
}

fn print_json(value: &impl serde::Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn fail_on(results: &[CheckResult]) -> anyhow::Result<()> {
    let failed = Checks::from_results(results).failures();
    if failed.is_empty() {
        Ok(())
    } else {
        let ids: Vec<String> = failed.iter().map(ToString::to_string).collect();
        bail!("checks {} failed", ids.join(", "))
    }
}

fn print_checks(results: &[CheckResult]) {
    for result in results {
        let why = if result.messages.is_empty() {
            String::new()
        } else {
            format!(": {}", result.messages.join("; "))
        };
        println!("check {:>2}: {:?}{why}", result.id, result.status);
    }
}

/// The builder `digest` (the newest without one) of the checkout's `publishers/builders.toml`.
fn listed_builder(root: &Path, digest: Option<&str>) -> anyhow::Result<builders::Builder> {
    let file = root.join(Layout::REPO.publishers).join(builders::FILE_NAME);
    let builders = Builders::read(&file)?;
    match digest {
        Some(digest) => builders
            .get(digest)
            .cloned()
            .with_context(|| format!("{digest} is not in publishers/builders.toml")),
        None => builders
            .iter()
            .last()
            .cloned()
            .context("publishers/builders.toml lists no builder yet"),
    }
}

/// Builds `archive` in `image` into `out`: the package, `THIRD-PARTY.txt` and
/// `BUILDINFO.json`, only if checks 17 (on what `cargo metadata` resolved), 19 and 20 pass;
/// the checks.
fn build_into(
    image: &str,
    builder: Option<&builders::Builder>,
    archive: &Path,
    crate_path: &str,
    git_sources: &checks::GitSources,
    out: &Path,
    jobs: Option<u32>,
) -> anyhow::Result<Checks> {
    let bytes = oncl_pack::read_limited(archive, MAX_ARCHIVE)?;
    let tree = Tree::from_archive(&bytes).with_context(|| format!("{}", archive.display()))?;
    let work = tempfile::tempdir()?;
    let rebuilt = docker::rebuild(
        &Engine::from_env(),
        image,
        archive,
        crate_path,
        git_sources,
        jobs,
        work.path(),
    )?;
    fs::create_dir_all(out)?;
    let Some((_, package)) = &rebuilt.package else {
        return Ok(rebuilt.checks);
    };
    if !rebuilt.checks.failures().is_empty() {
        return Ok(rebuilt.checks);
    }
    let read = oncl_plugin::Package::read(package).context("the rebuilt package")?;
    let id = &read.manifest.id;
    let version = read.manifest.version.to_string();
    // Named here, not by the container.
    let name = format!("{id}-{version}.onclp");
    fs::write(out.join(&name), package)?;
    fs::write(
        out.join("THIRD-PARTY.txt"),
        licenses::third_party(id, &version, &rebuilt.crates, &rebuilt.licences),
    )?;
    let info = BuildInfo {
        schema: mirror::SCHEMA,
        id: id.clone(),
        version: version.clone(),
        builder: BuilderInfo {
            image: image.to_owned(),
            digest: builder.map(|b| b.digest.clone()),
            rust: builder.map(|b| b.rust.to_string()),
            commit: builder.map(|b| b.commit.clone()),
        },
        source: SourceInfo {
            archive: FileInfo {
                file: format!("{id}-{version}.src.tar.gz"),
                sha256: oncl_pack::sha256_hex(&bytes),
                length: bytes.len() as u64,
            },
            path: crate_path.to_owned(),
            license: checks::crate_license(&tree, crate_path),
            cargo_lock_sha256: checks::lock_sha256(&tree, crate_path),
        },
        package: FileInfo {
            file: name.clone(),
            sha256: oncl_pack::sha256_hex(package),
            length: package.len() as u64,
        },
        release: None,
        vcs: None,
        checks: rebuilt.checks.to_vec(),
    };
    fs::write(out.join(mirror::FILE_NAME), info.to_json()?)?;
    Ok(rebuilt.checks)
}

/// `vendor verify`: the archive of a published release from the project's Releases, rebuilt
/// in its builder image and compared with the newest role's target.
fn verify(root: &Path, name: &str, id: &str, version: &Version) -> anyhow::Result<()> {
    let publisher = publisher_of(root, name)?;
    let tuf = root.join(Layout::REPO.tuf);
    let role = publisher.role();
    let newest = Listing::read(&tuf)?
        .newest_roles()
        .get(&role)
        .copied()
        .with_context(|| format!("{name} has no role file yet"))?;
    let read = draft::role_targets(&repo::read(
        &tuf,
        &tuf_layout::delegated_path(newest, &role),
    )?)?;
    let path_text = format!("plugins/{name}/{id}/{version}.onclp");
    let path = TargetPath::parse(&path_text).map_err(|e| anyhow::anyhow!("{e}"))?;
    let target = read
        .targets
        .get(&path)
        .with_context(|| format!("{path_text} is not in the newest role"))?;
    let release = PublisherRelease::parse(&publisher.name, &path, target)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let source = release.source();
    let place = PublisherTarget::parse(&path).context("the target path")?;
    let package_url = mirror_url(&publisher.name, &place.id, &place.version, &target.sha256);
    let (release_dir, _) = package_url.rsplit_once('/').context("the copy's address")?;
    let archive_url = format!("{release_dir}/{id}-{version}.src.tar.gz");
    let bytes = HttpsFetcher::new()
        .fetch(&archive_url, source.archive_length)
        .map_err(|e| anyhow::anyhow!(e))?;
    if let Some(f) = checks::download(&bytes, source, &path).first() {
        bail!("{}", f.message);
    }
    let work = tempfile::tempdir()?;
    let archive = work.path().join("source.src.tar.gz");
    fs::write(&archive, &bytes)?;
    let digest = format!(
        "sha256:{}",
        oncl_update::tuf::Digest(source.builder.0).to_hex()
    );
    let image = format!("{}@{digest}", builders::IMAGE);
    docker::verify(
        &Engine::from_env(),
        &image,
        &archive,
        &source.path,
        &target.sha256.to_hex(),
        &work.path().join("build"),
    )?;
    println!(
        "{path_text}: the rebuild in {image} gives the signed package {}",
        target.sha256
    );
    Ok(())
}

/// Runs `command`; for the checks, a failure is an error after the verdict is printed.
///
/// # Errors
///
/// Whatever the command refuses or fails with.
#[allow(clippy::too_many_lines)] // One arm per command, each a few lines.
pub fn run(command: VendorCommand) -> anyhow::Result<()> {
    let root = oncl_testkit::workspace_root();
    let layout = Layout::REPO;
    match command {
        VendorCommand::Keygen {
            name,
            out,
            passphrase_file,
        } => {
            let name = PublisherName::parse(&name).map_err(|e| anyhow::anyhow!("{e}"))?;
            let secret = passphrase(passphrase_file)
                .get_new("The passphrase of the new key (at least 12 characters): ")?;
            let (path, public) = keys::keygen(&name, &out, &secret)?;
            println!("key file: {}", path.display());
            println!("key id: {}", public.key_id());
            println!(
                "for publisher.toml:\n[[keys]]\npublic = \"{}\"",
                public.to_hex()
            );
            Ok(())
        }
        VendorCommand::Onboard {
            name,
            prefix,
            modules,
            bundles,
            display_ru,
            display_kk,
            display_en,
            github,
            keys,
            threshold,
            homepage,
            contact,
        } => {
            let file = onboard::onboard(
                &root,
                &layout,
                &Onboarding {
                    name,
                    prefix,
                    modules,
                    bundles,
                    display: [display_ru, display_kk, display_en],
                    github,
                    keys,
                    threshold,
                    homepage,
                    contact,
                },
            )?;
            println!("wrote {}", file.display());
            Ok(())
        }
        VendorCommand::CheckOnboarding { base } => {
            for note in onboard::check_onboarding(&root, &layout, base.as_deref())? {
                println!("vendor check-onboarding: {note}");
            }
            Ok(())
        }
        VendorCommand::Source { dir, git, rev, out } => {
            let tree = match (dir, git, rev) {
                (Some(dir), None, None) => Tree::from_dir(&dir)?,
                (None, Some(git), Some(rev)) => Tree::from_git(&git, &rev)?,
                _ => bail!("give --dir, or --git and --rev"),
            };
            let bytes = tree.to_archive()?;
            if out.exists() {
                bail!("{} exists already", out.display());
            }
            fs::write(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;
            println!("wrote {}", out.display());
            println!("archive_sha256 = {}", oncl_pack::sha256_hex(&bytes));
            println!("archive_length = {}", bytes.len());
            Ok(())
        }
        VendorCommand::Build {
            source,
            path,
            builder,
            image,
            out,
            jobs,
        } => {
            let (image, listed) = match image {
                Some(image) => (image, None),
                None => {
                    let b = listed_builder(&root, builder.as_deref())?;
                    (b.image(), Some(b))
                }
            };
            let sources = pr::git_sources_in(&root, &layout)?;
            let checks = build_into(
                &image,
                listed.as_ref(),
                &source,
                &path,
                &sources,
                &out,
                jobs,
            )?;
            print_checks(&checks.to_vec());
            fail_on(&checks.to_vec())?;
            println!("wrote {}", out.display());
            Ok(())
        }
        VendorCommand::Add {
            name,
            build,
            fetch,
            vcs_url,
            vcs_rev,
            channel,
            rollout,
        } => {
            let publisher = publisher_of(&root, &name)?;
            let info = BuildInfo::from_json(&fs::read(build.join(mirror::FILE_NAME))?)?;
            let package =
                oncl_pack::read_limited(&build.join(&info.package.file), oncl_plugin::MAX_PACKAGE)?;
            let mut draft = Draft::open(&root, &root.join(layout.tuf), &publisher)?;
            let path = draft.add(
                &publisher,
                &Addition {
                    build: &info,
                    package: &package,
                    fetch: &fetch,
                    vcs: vcs_url.as_deref().zip(vcs_rev.as_deref()),
                    channel: channel.into(),
                    rollout,
                },
            )?;
            let file = draft.save(&root)?;
            println!("added {path} to {}", file.display());
            Ok(())
        }
        VendorCommand::Set {
            name,
            id,
            version,
            channel,
            rollout,
            revoke,
            unrevoke,
        } => {
            let publisher = publisher_of(&root, &name)?;
            let mut draft = Draft::open(&root, &root.join(layout.tuf), &publisher)?;
            let revoked = match (revoke, unrevoke) {
                (true, _) => Some(true),
                (_, true) => Some(false),
                _ => None,
            };
            draft.set(&id, &version, channel.map(Into::into), rollout, revoked)?;
            println!("wrote {}", draft.save(&root)?.display());
            Ok(())
        }
        VendorCommand::Prune { name, id, version } => {
            let publisher = publisher_of(&root, &name)?;
            let mut draft = Draft::open(&root, &root.join(layout.tuf), &publisher)?;
            draft.prune(&publisher, &id, &version)?;
            println!("wrote {}", draft.save(&root)?.display());
            Ok(())
        }
        VendorCommand::Sign {
            name,
            keys: dir,
            expires_days,
            passphrase_file,
        } => {
            let publisher = publisher_of(&root, &name)?;
            let tuf = root.join(layout.tuf);
            let draft = Draft::open(&root, &tuf, &publisher)?;
            let mut unlock =
                Unlock::new(passphrase(passphrase_file), "The passphrase of the key: ");
            let found = keys::publisher_keys(&dir, &publisher, &mut unlock)?;
            let signed = keys::sign(
                &tuf,
                &publisher,
                draft.base_version,
                &draft.targets,
                OffsetDateTime::now_utc(),
                expires_days,
                &found,
            )?;
            let _ = fs::remove_file(draft::path(&root, publisher.name.as_str()));
            println!("wrote {}", signed.path.display());
            if signed.signatures < signed.threshold as usize {
                println!(
                    "{} of {} signatures: the other key holders run `cargo xtask vendor cosign {}`",
                    signed.signatures,
                    signed.threshold,
                    signed.path.display()
                );
            }
            Ok(())
        }
        VendorCommand::Cosign {
            file,
            keys: dir,
            passphrase_file,
        } => {
            let role = keys::role_of_file(&file)?;
            let publisher = publisher_of(&root, role.publisher().as_str())?;
            let mut unlock =
                Unlock::new(passphrase(passphrase_file), "The passphrase of the key: ");
            let found = keys::publisher_keys(&dir, &publisher, &mut unlock)?;
            let count = keys::cosign(&file, &publisher, &found)?;
            println!(
                "{}: {count} of {} signatures",
                file.display(),
                publisher.threshold
            );
            Ok(())
        }
        VendorCommand::Check {
            name,
            base,
            head,
            offline,
        } => {
            let https = HttpsFetcher::new();
            let verdict = pr::check_pr(&pr::Options {
                repo: &root,
                base: &base,
                head: &head,
                author: None,
                now: OffsetDateTime::now_utc(),
                layout,
                fetcher: (!offline).then_some(&https as &dyn ArchiveFetcher),
                out: None,
                builtin_modules: None,
            })?;
            if let Some(other) = verdict.publisher.as_deref().filter(|p| *p != name) {
                bail!("{base}..{head} is a release of {other}, not of {name}");
            }
            print_checks(&verdict.checks);
            fail_on(&verdict.checks)
        }
        VendorCommand::CheckPr {
            base,
            head,
            author,
            out,
            repo,
            now: at,
        } => {
            let https = HttpsFetcher::new();
            let repo = repo.unwrap_or(root);
            let verdict = pr::check_pr(&pr::Options {
                repo: &repo,
                base: &base,
                head: &head,
                author: Some(&author),
                now: now(at.as_deref())?,
                layout,
                fetcher: Some(&https as &dyn ArchiveFetcher),
                out: out.as_deref(),
                builtin_modules: None,
            })?;
            print_json(&verdict)?;
            fail_on(&verdict.checks)?;
            if verdict.ok {
                Ok(())
            } else {
                bail!("a required check did not pass")
            }
        }
        VendorCommand::Rebuild {
            archive,
            path,
            builder,
            out,
            jobs,
        } => {
            let listed = listed_builder(&root, Some(&builder))?;
            let sources = pr::git_sources_in(&root, &layout)?;
            let checks = build_into(
                &listed.image(),
                Some(&listed),
                &archive,
                &path,
                &sources,
                &out,
                jobs,
            )?;
            let results = checks.to_vec();
            let report = pr::RebuildReport {
                schema: SCHEMA,
                checks: results.clone(),
            };
            fs::write(
                out.join("rebuild.json"),
                serde_json::to_string_pretty(&report)?,
            )?;
            print_json(&report)?;
            fail_on(&results)
        }
        VendorCommand::Provenance {
            base,
            head,
            archives,
            network,
            builder,
            out,
        } => {
            let engine = Engine::from_env();
            docker::check_network(&engine, &network)?;
            let loaded = pr::load_pr(&root, &base, &head, &layout, OffsetDateTime::now_utc())?;
            let work = tempfile::tempdir()?;
            let listed = listed_builder(&root, builder.as_deref())?;
            let image = listed.image();
            let sandbox = super::provenance::Sandbox {
                engine: &engine,
                image: &image,
                network: &network,
            };
            let report = pr::provenance_job(&loaded, &sandbox, &archives, work.path())?;
            fs::write(&out, serde_json::to_string_pretty(&report)?)?;
            print_json(&report)
        }
        VendorCommand::Verdict {
            base,
            head,
            author,
            archives,
            rebuilt,
            provenance,
            out,
        } => {
            let report = match provenance {
                Some(file) => Some(serde_json::from_slice(&fs::read(&file)?)?),
                None => None,
            };
            fs::create_dir_all(&out)?;
            let verdict = pr::whole_verdict(
                &pr::WholeOptions {
                    repo: &root,
                    base: &base,
                    head: &head,
                    author: &author,
                    now: OffsetDateTime::now_utc(),
                    layout,
                    builtin_modules: None,
                },
                &VerdictInputs {
                    archives: &archives,
                    rebuilt: &rebuilt,
                    provenance: report.as_ref(),
                },
                &out,
            )?;
            fs::write(
                out.join("verdict.json"),
                serde_json::to_string_pretty(&verdict)?,
            )?;
            print_json(&verdict)?;
            fail_on(&verdict.checks)?;
            if verdict.ok {
                Ok(())
            } else {
                bail!("a required check did not pass")
            }
        }
        VendorCommand::SrcDiff {
            old,
            old_sha256,
            new,
            out,
        } => {
            let old_tree = match (old, old_sha256) {
                (Some(old), Some(sha256)) => {
                    let bytes = oncl_pack::read_limited(&old, MAX_ARCHIVE)?;
                    if oncl_pack::sha256_hex(&bytes) != sha256 {
                        bail!("{} is not the archive of sha256 {sha256}", old.display());
                    }
                    Some(Tree::from_archive(&bytes)?)
                }
                _ => None,
            };
            let new_tree = Tree::from_archive(&oncl_pack::read_limited(&new, MAX_ARCHIVE)?)?;
            fs::write(&out, super::diff::trees(old_tree.as_ref(), &new_tree))?;
            println!("wrote {}", out.display());
            Ok(())
        }
        VendorCommand::Verify { name, id, version } => verify(&root, &name, &id, &version),
    }
}
