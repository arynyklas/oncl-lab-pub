//! `vendor check-pr`: checks 1–9, 11–18, 23 and 24 of a publisher's release pull request
//! (`docs/design/publishers.md`, «Автослияние PR издателя») between the commits `base`
//! (`main`) and `head` of a git repository, as data:
//!
//! 1. the paths the pull request changes since its merge base (`git diff --raw`), and checks
//!    1 and 2 first: anything but one new role file of an active publisher, or an author not
//!    in its `github`, stops here;
//! 2. the base's `tuf/v1`, `publishers/`, indexes, anchor and `deny.toml`, read from git into
//!    a temporary directory and verified by the client's code ([`crate::tuf::check::verify`]);
//! 3. the role file's bytes from `head` (`git cat-file`), checks 3–9, 12, 23, 24 over them
//!    ([`super::checks`]), and check 11: `tuf check` of the base's tree with the file added;
//! 4. with the network, each new package's source archive by `source.fetch`
//!    ([`super::fetch`]), and checks 13–18 over its bytes.
//!
//! Nothing of the pull request is checked out, built or run. The verdict is one JSON object
//! ([`PrVerdict`]); with `out`, it is written there as `verdict.json` beside the archives
//! (`<id>-<version>.src.tar.gz`) for the rebuild and mirror jobs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, bail};
use oncl_update::catalog::{PublisherTarget, ReleaseSource, mirror_url};
use oncl_update::index::Index;
use oncl_update::tuf::{Envelope, Profile, RoleName, TargetPath, Targets, layout};
use serde_json::Value;
use time::OffsetDateTime;

use super::checks::{self, Base, Finding, RoleAt};
use super::fetch::ArchiveFetcher;
use super::git::Git;
use super::verdict::{
    ARCHIVE_CHECKS, Checks, NewTarget, PrVerdict, Previous, SCHEMA, STATIC_CHECKS,
};
use super::{Layout, MAX_ROLE_FILE};
use crate::publishers::Registry;
use crate::publishers::builders::{self, Builders};
use crate::tuf::check::{self, Expiry, Outcome, Stage};
use crate::tuf::repo::{self, Listing};

/// The largest file of the base read.
const MAX_BASE_FILE: u64 = 16 << 20;

/// What [`check_pr`] checks.
pub struct Options<'a> {
    /// The git repository.
    pub repo: &'a Path,
    /// The base revision (`main`).
    pub base: &'a str,
    /// The pull request's head revision.
    pub head: &'a str,
    /// The pull request's author (check 2); none for a publisher's own check.
    pub author: Option<&'a str>,
    /// The time of the check.
    pub now: OffsetDateTime,
    /// Where the files are.
    pub layout: Layout,
    /// What downloads the archives; `None` skips checks 13–18 (`--offline`).
    pub fetcher: Option<&'a dyn ArchiveFetcher>,
    /// Where the verdict and the archives go.
    pub out: Option<&'a Path>,
    /// The modules built into the core; `None` reads them from this checkout.
    pub builtin_modules: Option<Vec<String>>,
}

/// Fails each finding's check, then passes each of `ran` that did not fail.
fn apply(checks: &mut Checks, ran: &[u8], findings: Vec<Finding>) {
    for f in findings {
        checks.fail(f.check, f.message);
    }
    for id in ran {
        checks.pass(*id);
    }
}

/// `allow-git` of `deny.toml`.
fn allowed_git(deny: &[u8]) -> anyhow::Result<Vec<String>> {
    let value: toml::Value =
        toml::from_str(std::str::from_utf8(deny).context("deny.toml is not UTF-8")?)
            .context("reading deny.toml")?;
    Ok(value
        .get("sources")
        .and_then(|s| s.get("allow-git"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect())
}

/// Writes `files` (paths relative to the repository) under `dir`.
fn materialize(dir: &Path, files: &BTreeMap<String, Vec<u8>>) -> anyhow::Result<()> {
    for (path, bytes) in files {
        let file = dir.join(path);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&file, bytes).with_context(|| format!("writing {}", file.display()))?;
    }
    Ok(())
}

/// The base materialized in `dir`, read and verified (see the module's description).
///
/// # Errors
///
/// The base does not verify or a file of it does not read: no pull request can be checked
/// against it.
pub fn load_base(
    dir: &Path,
    layout: &Layout,
    now: OffsetDateTime,
    builtin_modules: Vec<String>,
) -> anyhow::Result<Base> {
    let tuf = dir.join(layout.tuf);
    let anchor = fs::read(dir.join(layout.anchor)).context("the base has no trust anchor")?;
    let mode = repo::read_mode(&dir.join(layout.config))?;
    let mut problems = Vec::new();
    let verified = check::verify(&tuf, &anchor, now, Stage::Tree, mode, &mut problems)?
        .map_err(|p| anyhow::anyhow!("the base's {} does not verify: {p}", layout.tuf))?;
    let delegations = verified
        .targets
        .delegations()
        .map_err(|e| anyhow::anyhow!("the base's delegations do not read: {e}"))?;
    let registry = Registry::read(&dir.join(layout.publishers))?;
    let builders_file = dir.join(layout.publishers).join(builders::FILE_NAME);
    let builders = if builders_file.is_file() {
        Builders::read(&builders_file)?
    } else {
        Builders::default()
    };
    let indexes_dir = dir.join(layout.indexes);
    let indexes = if indexes_dir.is_dir() {
        crate::tuf::update::read_indexes(&indexes_dir)?
            .into_iter()
            .map(|(_, bytes)| Index::from_json(&bytes).map_err(|e| anyhow::anyhow!("{e}")))
            .collect::<anyhow::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let mut roles = BTreeMap::new();
    for (role, version) in Listing::read(&tuf)?.newest_roles() {
        let bytes = repo::read(&tuf, &layout::delegated_path(version, &role))?;
        roles.insert(role.publisher(), RoleAt { version, bytes });
    }
    let deny = dir.join(layout.deny);
    let allowed_git = if deny.is_file() {
        allowed_git(&fs::read(&deny)?)?
    } else {
        Vec::new()
    };
    Ok(Base {
        registry,
        builders,
        delegations,
        indexes,
        roles,
        builtin_modules,
        allowed_git,
    })
}

/// Check 11: `tuf check` of the base's tree in `dir` with the role file added.
fn tuf_check(
    dir: &Path,
    layout: &Layout,
    role_path: &str,
    bytes: &[u8],
    now: OffsetDateTime,
) -> anyhow::Result<Vec<Finding>> {
    let file = dir.join(role_path);
    fs::write(&file, bytes)?;
    let tuf = dir.join(layout.tuf);
    let mode = repo::read_mode(&dir.join(layout.config))?;
    let indexes = dir.join(layout.indexes);
    let publishers = dir.join(layout.publishers);
    let anchor = dir.join(layout.anchor);
    let outcome = check::check(&check::Options {
        dir: &tuf,
        index: indexes.is_dir().then_some(indexes.as_path()),
        publishers: Some(&publishers),
        anchor: Some(&anchor),
        now,
        stage: Stage::Tree,
        mode,
        expiry: Expiry {
            min_days: 0,
            min_root_days: 0,
            fail: false,
        },
        base: None,
    })?;
    let Outcome::Checked(report) = outcome else {
        bail!("the base has no repository");
    };
    Ok(report
        .problems
        .iter()
        .map(|p| checks::finding(11, format!("tuf check with the file: error{p}")))
        .collect())
}

/// The targets of a role file as signed, leniently (the base's: it went in already).
fn base_targets(role: &RoleAt) -> Option<Targets> {
    let envelope = Envelope::parse(&role.bytes, MAX_ROLE_FILE, "role").ok()?;
    Targets::from_signed(&envelope.signed, Profile::Delegating).ok()
}

/// Runs the checks of `options` (see the module's description).
///
/// # Errors
///
/// The revisions or the base cannot be read: no verdict can be given. What the pull request
/// breaks is in the verdict, never an error.
pub fn check_pr(options: &Options) -> anyhow::Result<PrVerdict> {
    let git = Git::new(options.repo);
    let base_commit = git.commit(options.base)?;
    let head_commit = git.commit(options.head)?;
    let changes = git.merged_changes(&base_commit, &head_commit)?;
    let mut checks = Checks::new();
    let mut all: Vec<u8> = STATIC_CHECKS.to_vec();
    all.extend(ARCHIVE_CHECKS);
    let mut verdict = PrVerdict {
        schema: SCHEMA,
        ok: false,
        base: base_commit.clone(),
        head: head_commit.clone(),
        publisher: None,
        role_version: None,
        checks: Vec::new(),
        new_targets: Vec::new(),
    };
    let finish = |mut checks: Checks, mut verdict: PrVerdict, all: &[u8]| -> PrVerdict {
        checks.skip_rest(all.iter().copied(), "an earlier check failed");
        let mut required: Vec<u8> = all.to_vec();
        if options.author.is_none() {
            required.retain(|id| *id != 2);
        }
        if options.fetcher.is_none() {
            required.retain(|id| !ARCHIVE_CHECKS.contains(id));
        }
        verdict.ok = checks.all_pass(required);
        verdict.checks = checks.into_vec();
        verdict
    };

    // Check 1, the paths of what the merge lands: nothing else is read before it.
    let role = match changes.map(|c| checks::role_path(&c, &options.layout)) {
        Ok(Ok(role)) => role,
        Ok(Err(findings)) => {
            apply(&mut checks, &[], findings);
            return Ok(finish(checks, verdict, &all));
        }
        Err(why) => {
            checks.fail(1, why);
            return Ok(finish(checks, verdict, &all));
        }
    };
    verdict.publisher = Some(role.publisher.as_str().to_owned());
    verdict.role_version = Some(role.version);

    let scratch = tempfile::tempdir()?;
    let base_dir = scratch.path().join("base");
    let files = git.files(&base_commit, &options.layout.base_paths(), MAX_BASE_FILE)?;
    materialize(&base_dir, &files)?;
    let builtin = match &options.builtin_modules {
        Some(modules) => modules.clone(),
        None => crate::index::builtin_modules()?,
    };
    let base = load_base(&base_dir, &options.layout, options.now, builtin)?;

    let bytes = match git.blob(&head_commit, &role.path, MAX_ROLE_FILE) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => bail!("{} is not a file of {head_commit}", role.path),
        Err(e) => {
            checks.fail(1, format!("{e:#}"));
            return Ok(finish(checks, verdict, &all));
        }
    };
    apply(
        &mut checks,
        &[1],
        checks::role_admitted(&base, &role, bytes.len() as u64),
    );
    let publisher = base.registry.get(&role.publisher).cloned();
    match (options.author, &publisher) {
        (Some(author), Some(p)) => apply(&mut checks, &[2], checks::author_listed(p, author)),
        (Some(_), None) => checks.fail(2, "the publisher is not in publishers/"),
        (None, _) => checks.skip(2, "no --author: the check of a publisher's own clone"),
    }
    let Some(publisher) = publisher.filter(|_| !checks.failed(1) && !checks.failed(2)) else {
        return Ok(finish(checks, verdict, &all));
    };

    let previous = base.roles.get(&role.publisher);
    apply(
        &mut checks,
        &[3],
        checks::next_version(previous.map(|r| r.version), &role),
    );
    let pattern = format!(
        "{}/metadata/*.{}.json",
        options.layout.tuf,
        RoleName::of(&role.publisher)
    );
    let last = git
        .last_commit_time(&base_commit, &pattern)?
        .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok());
    apply(&mut checks, &[9], checks::frequency(last, options.now));

    let targets = match checks::signed_role(&bytes, &role, base.delegations.as_ref()) {
        Ok(targets) => {
            checks.pass(4);
            Some(targets)
        }
        Err(findings) => {
            apply(&mut checks, &[], findings);
            None
        }
    };
    let mut new = BTreeSet::new();
    if let Some(targets) = &targets {
        apply(
            &mut checks,
            &[5],
            checks::expiry(targets.expires, options.now),
        );
        let previous_targets = match previous.map(|p| (p, base_targets(p))) {
            Some((p, None)) => {
                checks.fail(
                    8,
                    format!("version {} of the role on main does not read", p.version),
                );
                None
            }
            Some((_, Some(t))) => Some(t),
            None => None,
        };
        new = targets
            .targets
            .keys()
            .filter(|p| {
                previous_targets
                    .as_ref()
                    .is_none_or(|prev| !prev.targets.contains_key(*p))
            })
            .cloned()
            .collect();
        let entries = checks::entries(
            &publisher,
            targets,
            &new,
            &base.builders,
            &base.builtin_modules,
        );
        apply(&mut checks, &[6, 12, 23], entries.findings);
        apply(
            &mut checks,
            &[7],
            checks::catalog(&base, &publisher, &entries.releases),
        );
        apply(
            &mut checks,
            &[8, 24],
            checks::history(previous_targets.as_ref(), targets, &publisher),
        );
        verdict.new_targets =
            new_targets(&publisher.name, targets, &new, previous_targets.as_ref());
    } else {
        checks.skip_rest(
            [5, 6, 7, 8, 12, 23, 24],
            "check 4 failed: the file does not read",
        );
    }

    let found = tuf_check(&base_dir, &options.layout, &role.path, &bytes, options.now)?;
    apply(&mut checks, &[11], found);

    match (options.fetcher, &targets) {
        (None, _) => checks.skip_rest(ARCHIVE_CHECKS, "offline: the archives were not fetched"),
        (Some(_), None) => checks.skip_rest(ARCHIVE_CHECKS, "check 4 failed"),
        (Some(fetcher), Some(targets)) => {
            for path in &new {
                let Some(target) = targets.targets.get(path) else {
                    continue;
                };
                let source = target
                    .custom
                    .as_ref()
                    .and_then(|c| c.get("oncl"))
                    .and_then(|o| o.get("source"));
                let Ok(source) = ReleaseSource::parse(source) else {
                    continue;
                };
                let found = archive_checks(
                    fetcher,
                    path,
                    &source,
                    &base.allowed_git,
                    &publisher.binary_files,
                    options.out,
                )?;
                apply(&mut checks, &[], found);
            }
            if checks.failed(12) {
                checks.skip_rest(ARCHIVE_CHECKS, "check 12 failed for a new target");
            }
            for id in ARCHIVE_CHECKS {
                checks.pass(id);
            }
        }
    }

    let verdict = finish(checks, verdict, &all);
    if let Some(out) = options.out {
        fs::create_dir_all(out)?;
        let mut text = serde_json::to_string_pretty(&verdict)?;
        text.push('\n');
        fs::write(out.join("verdict.json"), text)?;
    }
    Ok(verdict)
}

/// Checks 13–18 of the new target `path`: the download, then the archive's files. The
/// archive goes into `out` as `<id>-<version>.src.tar.gz` once it matches the signed hash.
fn archive_checks(
    fetcher: &dyn ArchiveFetcher,
    path: &TargetPath,
    source: &ReleaseSource,
    allowed_git: &[String],
    binary_files: &[String],
    out: Option<&Path>,
) -> anyhow::Result<Vec<Finding>> {
    let bytes = match fetcher.fetch(&source.fetch, source.archive_length) {
        Ok(bytes) => bytes,
        Err(e) => return Ok(vec![checks::finding(13, format!("{path}: {e}"))]),
    };
    let mut findings = checks::download(&bytes, source, path);
    if !findings.is_empty() {
        return Ok(findings);
    }
    if let (Some(out), Some(place)) = (out, PublisherTarget::parse(path)) {
        fs::create_dir_all(out)?;
        fs::write(
            out.join(format!("{}-{}.src.tar.gz", place.id, place.version)),
            &bytes,
        )?;
    }
    let tree = match checks::canonical(&bytes, path) {
        Ok(tree) => tree,
        Err(f) => return Ok(vec![f]),
    };
    findings.extend(checks::crate_files(&tree, source, path));
    findings.extend(checks::cargo_config(&tree, &source.path, path));
    findings.extend(checks::lock_sources(&tree, allowed_git, path));
    findings.extend(checks::binaries(&tree, binary_files, path));
    Ok(findings)
}

/// What the later jobs need of each new target.
fn new_targets(
    publisher: &oncl_update::tuf::PublisherName,
    targets: &Targets,
    new: &BTreeSet<TargetPath>,
    previous: Option<&Targets>,
) -> Vec<NewTarget> {
    let mut out = Vec::new();
    for path in new {
        let (Some(target), Some(place)) = (targets.targets.get(path), PublisherTarget::parse(path))
        else {
            continue;
        };
        let source = target
            .custom
            .as_ref()
            .and_then(|c| c.get("oncl"))
            .and_then(|o| o.get("source"))
            .cloned()
            .unwrap_or(Value::Null);
        let previous = previous.and_then(|prev| {
            prev.targets
                .iter()
                .filter_map(|(p, t)| Some((PublisherTarget::parse(p)?, t)))
                .filter(|(p, _)| p.id == place.id && p.version < place.version)
                .max_by(|a, b| a.0.version.cmp(&b.0.version))
                .and_then(|(p, t)| {
                    let source = t.custom.as_ref()?.get("oncl")?.get("source")?;
                    let url = mirror_url(publisher, &p.id, &p.version, &t.sha256);
                    // The archive is beside the package in the same release.
                    let (release, _) = url.rsplit_once('/')?;
                    let archive_url = format!("{release}/{}-{}.src.tar.gz", p.id, p.version);
                    Some(Previous {
                        version: p.version.to_string(),
                        archive_url,
                        archive_sha256: source.get("archive_sha256")?.as_str()?.to_owned(),
                    })
                })
        });
        out.push(NewTarget {
            path: path.as_str().to_owned(),
            id: place.id.as_str().to_owned(),
            version: place.version.to_string(),
            length: target.length,
            sha256: target.sha256.to_hex(),
            tag: format!("pub-{publisher}-{}", target.sha256.to_hex()),
            package: format!("{}-{}.onclp", place.id, place.version),
            archive: format!("{}-{}.src.tar.gz", place.id, place.version),
            source,
            previous,
        });
    }
    out
}

/// A release pull request read for the jobs after `publisher-check` (provenance, verdict),
/// which trust nothing that job wrote: the role file again from git, against the base again.
pub struct PrRole {
    /// The base, verified.
    pub base: Base,
    /// The base commit.
    pub base_commit: String,
    /// The head commit.
    pub head_commit: String,
    /// The role file.
    pub role: checks::RoleFile,
    /// Its publisher.
    pub publisher: crate::publishers::Publisher,
    /// Its targets, as signed.
    pub targets: Targets,
    /// The targets the base's role does not have.
    pub new: BTreeSet<TargetPath>,
    /// The base's newest version of the role.
    pub previous: Option<Targets>,
    _scratch: tempfile::TempDir,
}

/// Reads the pull request `base`..`head` of `repo` again, its role file through checks 1 and
/// 4 (which `publisher-check` passed already).
///
/// # Errors
///
/// The revisions or the base do not read, or the role file fails check 1 or 4.
pub fn load_pr(
    repo: &Path,
    base: &str,
    head: &str,
    layout: &Layout,
    now: OffsetDateTime,
) -> anyhow::Result<PrRole> {
    let git = Git::new(repo);
    let base_commit = git.commit(base)?;
    let head_commit = git.commit(head)?;
    let messages = |f: Vec<Finding>| {
        f.into_iter()
            .map(|f| format!("check {}: {}", f.check, f.message))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let changes = git
        .merged_changes(&base_commit, &head_commit)?
        .map_err(|why| anyhow::anyhow!("check 1: {why}"))?;
    let role =
        checks::role_path(&changes, layout).map_err(|f| anyhow::anyhow!("{}", messages(f)))?;
    let scratch = tempfile::tempdir()?;
    let base_dir = scratch.path().join("base");
    materialize(
        &base_dir,
        &git.files(&base_commit, &layout.base_paths(), MAX_BASE_FILE)?,
    )?;
    let base_data = load_base(&base_dir, layout, now, Vec::new())?;
    let publisher = base_data
        .registry
        .get(&role.publisher)
        .cloned()
        .with_context(|| format!("{} is not in publishers/", role.publisher))?;
    let bytes = git
        .blob(&head_commit, &role.path, MAX_ROLE_FILE)?
        .with_context(|| format!("{} is not a file of {head_commit}", role.path))?;
    let targets = checks::signed_role(&bytes, &role, base_data.delegations.as_ref())
        .map_err(|f| anyhow::anyhow!("{}", messages(f)))?;
    let previous = base_data.roles.get(&role.publisher).and_then(base_targets);
    let new = targets
        .targets
        .keys()
        .filter(|p| {
            previous
                .as_ref()
                .is_none_or(|prev| !prev.targets.contains_key(*p))
        })
        .cloned()
        .collect();
    Ok(PrRole {
        base: base_data,
        base_commit,
        head_commit,
        role,
        publisher,
        targets,
        new,
        previous,
        _scratch: scratch,
    })
}

/// The outcome of check 25 for each new target with `source.vcs`, by target path.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceReport {
    /// [`SCHEMA`].
    pub schema: u32,
    /// By target path.
    pub targets: BTreeMap<String, super::provenance::Provenance>,
}

/// The provenance job: check 25 for every new target of `pr` that names a revision, against
/// the archives in `archives` (`<id>-<version>.src.tar.gz`, hashed again here).
///
/// # Errors
///
/// An archive is missing or is not the signed one.
pub fn provenance_job(
    pr: &PrRole,
    sandbox: &super::provenance::Sandbox,
    archives: &Path,
    work: &Path,
) -> anyhow::Result<ProvenanceReport> {
    let mut report = ProvenanceReport {
        schema: SCHEMA,
        targets: BTreeMap::new(),
    };
    for path in &pr.new {
        let (Some(target), Some(place)) =
            (pr.targets.targets.get(path), PublisherTarget::parse(path))
        else {
            continue;
        };
        let source = ReleaseSource::parse(
            target
                .custom
                .as_ref()
                .and_then(|c| c.get("oncl"))
                .and_then(|o| o.get("source")),
        )
        .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        let Some(vcs) = &source.vcs else {
            continue;
        };
        let file = archives.join(format!("{}-{}.src.tar.gz", place.id, place.version));
        let bytes = oncl_pack::read_limited(&file, source.archive_length)?;
        if let Some(f) = checks::download(&bytes, &source, path).first() {
            bail!("{}", f.message);
        }
        let dir = work.join(format!("{}-{}", place.id, place.version));
        std::fs::create_dir_all(&dir)?;
        let found = super::provenance::check(
            sandbox,
            &vcs.url,
            &vcs.rev,
            &bytes,
            &dir,
            super::VCS_TIMEOUT,
        );
        report.targets.insert(path.as_str().to_owned(), found);
    }
    Ok(report)
}

/// What the verdict job reads besides git.
pub struct VerdictInputs<'a> {
    /// The archives `publisher-check` downloaded (`<id>-<version>.src.tar.gz`).
    pub archives: &'a Path,
    /// The packages the rebuild jobs made (`<id>-<version>.onclp`, any depth).
    pub rebuilt: &'a Path,
    /// The provenance job's report, if it ran.
    pub provenance: Option<&'a ProvenanceReport>,
}

/// Finds the file `name` anywhere under `dir` (the artifacts of a matrix job unpack into
/// one directory each).
fn find_file(dir: &Path, name: &str) -> anyhow::Result<Option<std::path::PathBuf>> {
    if !dir.is_dir() {
        return Ok(None);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            if let Some(found) = find_file(&entry.path(), name)? {
                return Ok(Some(found));
            }
        } else if kind.is_file() && entry.file_name() == name {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

/// The verdict job: checks 21, 22 and 25 of every new target of `pr`, by hashes computed
/// here, and `BUILDINFO.json` of each into `out/<id>-<version>/`.
///
/// # Errors
///
/// A file cannot be read or written.
pub fn verdict_job(pr: &PrRole, inputs: &VerdictInputs, out: &Path) -> anyhow::Result<Checks> {
    use super::mirror::{BuildInfo, BuilderInfo, FileInfo, ReleaseInfo, SourceInfo, VcsInfo};
    use super::provenance::Provenance;

    let mut checks = Checks::new();
    for path in &pr.new {
        let (Some(target), Some(place)) =
            (pr.targets.targets.get(path), PublisherTarget::parse(path))
        else {
            continue;
        };
        let release =
            match oncl_update::catalog::PublisherRelease::parse(&pr.publisher.name, path, target) {
                Ok(release) => release,
                Err(e) => {
                    checks.fail(22, format!("{path}: the client would leave it out: {e}"));
                    continue;
                }
            };
        let source = release.source().clone();
        let stem = format!("{}-{}", place.id, place.version);
        let archive_name = format!("{stem}.src.tar.gz");
        let Some(archive_file) = find_file(inputs.archives, &archive_name)? else {
            checks.fail(
                21,
                format!("{path}: the archive {archive_name} was not handed over"),
            );
            continue;
        };
        let archive = oncl_pack::read_limited(&archive_file, source.archive_length)?;
        let mismatch = checks::download(&archive, &source, path);
        if !mismatch.is_empty() {
            for f in mismatch {
                checks.fail(21, format!("the handed-over archive: {}", f.message));
            }
            continue;
        }
        let tree = match checks::canonical(&archive, path) {
            Ok(tree) => tree,
            Err(f) => {
                checks.fail(21, f.message);
                continue;
            }
        };
        let package_name = format!("{stem}.onclp");
        let Some(package_file) = find_file(inputs.rebuilt, &package_name)? else {
            checks.fail(21, format!("{path}: no rebuilt {package_name}"));
            continue;
        };
        // The rebuild's own report beside the package: 17 (what Cargo resolved), 19, 20.
        let report = package_file
            .parent()
            .map(|dir| dir.join(REBUILD_REPORT))
            .filter(|file| file.is_file())
            .map(|file| -> anyhow::Result<RebuildReport> {
                Ok(serde_json::from_slice(&fs::read(file)?)?)
            })
            .transpose();
        let mut target_failed = false;
        match report {
            Ok(Some(report)) => {
                let rebuilt = Checks::from_results(&report.checks);
                for id in [17, 19, 20] {
                    if rebuilt.status(id) != Some(super::verdict::Status::Pass) {
                        target_failed = true;
                        checks.fail(id, format!("{path}: the rebuild did not pass check {id}"));
                    }
                }
                checks.merge(&rebuilt);
            }
            Ok(None) => {
                target_failed = true;
                checks.fail(
                    19,
                    format!("{path}: no {REBUILD_REPORT} beside the package"),
                );
            }
            Err(e) => {
                target_failed = true;
                checks.fail(19, format!("{path}: {REBUILD_REPORT}: {e:#}"));
            }
        }
        let package = oncl_pack::read_limited(&package_file, oncl_plugin::MAX_PACKAGE)?;
        let bytes = super::mirror::rebuilt_bytes(&package, target, path);
        let contents =
            super::mirror::rebuilt_package(&package, &release, &tree, &source.path, path);
        target_failed |= !bytes.is_empty() || !contents.is_empty();
        apply(&mut checks, &[21], bytes);
        apply(&mut checks, &[22], contents);
        let vcs = match (&source.vcs, inputs.provenance) {
            (None, _) => None,
            (Some(vcs), report) => {
                let found = report.and_then(|r| r.targets.get(path.as_str()));
                match found {
                    Some(Provenance::Mismatch(sha)) => checks.fail(
                        25,
                        format!(
                            "{path}: {} {} makes another archive ({sha})",
                            vcs.url, vcs.rev
                        ),
                    ),
                    Some(_) => checks.pass(25),
                    None => checks.fail(25, format!("{path}: no outcome of check 25")),
                }
                Some(VcsInfo {
                    url: vcs.url.clone(),
                    rev: vcs.rev.clone(),
                    result: found.map_or("unverified", Provenance::word).to_owned(),
                })
            }
        };
        let digest = format!(
            "sha256:{}",
            oncl_update::tuf::Digest(source.builder.0).to_hex()
        );
        let builder = pr.base.builders.get(&digest);
        let license = checks::crate_license(&tree, &source.path);
        let cargo_lock_sha256 = checks::lock_sha256(&tree, &source.path);
        let info = BuildInfo {
            schema: super::mirror::SCHEMA,
            id: place.id.as_str().to_owned(),
            version: place.version.to_string(),
            builder: BuilderInfo {
                image: format!("{}@{digest}", crate::publishers::builders::IMAGE),
                digest: Some(digest.clone()),
                rust: builder.map(|b| b.rust.to_string()),
                commit: builder.map(|b| b.commit.clone()),
            },
            source: SourceInfo {
                archive: FileInfo {
                    file: archive_name,
                    sha256: oncl_pack::sha256_hex(&archive),
                    length: archive.len() as u64,
                },
                path: source.path.clone(),
                license,
                cargo_lock_sha256,
            },
            package: FileInfo {
                file: package_name,
                sha256: oncl_pack::sha256_hex(&package),
                length: package.len() as u64,
            },
            release: Some(ReleaseInfo {
                publisher: pr.publisher.name.as_str().to_owned(),
                role_version: pr.role.version,
                tag: format!("pub-{}-{}", pr.publisher.name, target.sha256.to_hex()),
                head: pr.head_commit.clone(),
                base: pr.base_commit.clone(),
            }),
            vcs,
            checks: Vec::new(),
        };
        // Nothing goes to the mirror of a target that failed.
        if !target_failed {
            let dir = out.join(&stem);
            fs::create_dir_all(&dir)?;
            fs::write(dir.join(super::mirror::FILE_NAME), info.to_json()?)?;
        }
    }
    for id in [17, 19, 20, 21, 22] {
        checks.pass(id);
    }
    if pr.new.is_empty() || checks.status(25).is_none() {
        checks.skip(25, "no new target names a revision");
    }
    Ok(checks)
}

/// The rebuild job's report beside its package (`vendor rebuild --out`).
pub const REBUILD_REPORT: &str = "rebuild.json";

/// `rebuild.json`: checks 17 (on what `cargo metadata` resolved), 19 and 20.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebuildReport {
    /// [`SCHEMA`].
    pub schema: u32,
    /// The checks.
    pub checks: Vec<super::verdict::CheckResult>,
}

/// `allow-git` of the `deny.toml` at `path` (none without the file).
///
/// # Errors
///
/// The file does not read.
pub fn allowed_git_in(path: &Path) -> anyhow::Result<Vec<String>> {
    if path.is_file() {
        allowed_git(&fs::read(path)?)
    } else {
        Ok(Vec::new())
    }
}

/// The archives `publisher-check` handed over, by the `source.fetch` the role signs: what
/// checks 13–18 read again in the verdict job (hashed again by check 13).
struct HandedOver(BTreeMap<String, Vec<u8>>);

impl ArchiveFetcher for HandedOver {
    fn fetch(&self, url: &str, limit: u64) -> Result<Vec<u8>, String> {
        match self.0.get(url) {
            Some(bytes) if bytes.len() as u64 <= limit => Ok(bytes.clone()),
            Some(_) => Err(format!(
                "{url}: the handed-over archive is over {limit} bytes"
            )),
            None => Err(format!("{url}: the archive was not handed over")),
        }
    }
}

/// What [`whole_verdict`] checks.
pub struct WholeOptions<'a> {
    /// The git repository.
    pub repo: &'a Path,
    /// The base revision (`main`).
    pub base: &'a str,
    /// The pull request's head revision.
    pub head: &'a str,
    /// The pull request's author.
    pub author: &'a str,
    /// The time of the check.
    pub now: OffsetDateTime,
    /// Where the files are.
    pub layout: Layout,
    /// The modules built into the core; `None` reads them from this checkout.
    pub builtin_modules: Option<Vec<String>>,
}

/// The whole verdict of the pull request, in one job: [`check_pr`] again (its archives the
/// handed-over ones, hashed again), every rebuild report and [`verdict_job`]. `ok` only if
/// no check failed and every one of 1–9, 11–24 passed; `BUILDINFO.json` of each new package
/// that passed goes into `out`.
///
/// # Errors
///
/// The revisions or the base cannot be read, or a file cannot be read or written.
pub fn whole_verdict(
    options: &WholeOptions,
    inputs: &VerdictInputs,
    out: &Path,
) -> anyhow::Result<PrVerdict> {
    let pr = load_pr(
        options.repo,
        options.base,
        options.head,
        &options.layout,
        options.now,
    );
    let mut handed = BTreeMap::new();
    if let Ok(pr) = &pr {
        for path in &pr.new {
            let (Some(target), Some(place)) =
                (pr.targets.targets.get(path), PublisherTarget::parse(path))
            else {
                continue;
            };
            let source = target
                .custom
                .as_ref()
                .and_then(|c| c.get("oncl"))
                .and_then(|o| o.get("source"));
            let Ok(source) = ReleaseSource::parse(source) else {
                continue;
            };
            let name = format!("{}-{}.src.tar.gz", place.id, place.version);
            if let Some(file) = find_file(inputs.archives, &name)? {
                handed.insert(
                    source.fetch.clone(),
                    oncl_pack::read_limited(&file, source.archive_length)?,
                );
            }
        }
    }
    let fetcher = HandedOver(handed);
    let mut verdict = check_pr(&Options {
        repo: options.repo,
        base: options.base,
        head: options.head,
        author: Some(options.author),
        now: options.now,
        layout: options.layout,
        fetcher: Some(&fetcher),
        out: None,
        builtin_modules: options.builtin_modules.clone(),
    })?;
    let mut checks = Checks::from_results(&verdict.checks);
    match &pr {
        Ok(pr) if verdict.ok => checks.merge(&verdict_job(pr, inputs, out)?),
        _ => checks.skip_rest(
            [19, 20, 21, 22, super::verdict::PROVENANCE_CHECK],
            "the checks of the pull request failed",
        ),
    }
    let mut required: Vec<u8> = STATIC_CHECKS.to_vec();
    required.extend(ARCHIVE_CHECKS);
    required.extend([19, 20, 21, 22]);
    verdict.ok = checks.all_pass(required);
    verdict.checks = checks.into_vec();
    Ok(verdict)
}
