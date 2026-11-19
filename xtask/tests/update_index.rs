//! `cargo xtask index`: an index made from release assets and the checks before publishing.

use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::process::Command;

use oncl_update::{Channel, Flavor, Index, Sha256, Version};
use time::{Duration, OffsetDateTime};
use xtask::index::{self, CheckOptions, Remote};

const TAG: &str = "v0.2.0-beta.1";
const NEXT_TAG: &str = "v0.2.0-beta.2";
const STABLE_TAG: &str = "v0.2.0";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn version(tag: &str) -> Version {
    Version::parse(tag.strip_prefix('v').unwrap()).unwrap()
}

/// The assets of the release `tag`: full packages for `flavors`, the delta of win-x64 when
/// `delta_base` is given (with Velopack's feed naming its base, and the win-x64 full
/// package a zip archive, whose files the index sums), and the extension.
fn release_assets(tag: &str, flavors: &[Flavor], delta_base: Option<&str>) -> tempfile::TempDir {
    let v = version(tag);
    let dir = tempfile::tempdir().unwrap();
    for flavor in flavors {
        fs::write(
            dir.path()
                .join(format!("OpenNCALayer-{v}-{flavor}-full.nupkg")),
            format!("full {v} {flavor}"),
        )
        .unwrap();
    }
    if let Some(base) = delta_base {
        let full = dir
            .path()
            .join(format!("OpenNCALayer-{v}-win-x64-full.nupkg"));
        let mut zip = zip::ZipWriter::new(fs::File::create(full).unwrap());
        zip.start_file(
            "lib/app/openncalayer.exe",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        std::io::Write::write_all(&mut zip, format!("program {v}").as_bytes()).unwrap();
        zip.finish().unwrap();
        fs::write(
            dir.path()
                .join(format!("OpenNCALayer-{v}-win-x64-delta.nupkg")),
            format!("delta {base} -> {v}"),
        )
        .unwrap();
        let feed = serde_json::json!({"Assets": [
            {"PackageId": "OpenNCALayer", "Version": "0.1.0", "Type": "Full",
             "FileName": "OpenNCALayer-0.1.0-win-x64-full.nupkg"},
            {"PackageId": "OpenNCALayer", "Version": base, "Type": "Full",
             "FileName": format!("OpenNCALayer-{base}-win-x64-full.nupkg")},
            {"PackageId": "OpenNCALayer", "Version": v.to_string(), "Type": "Full",
             "FileName": format!("OpenNCALayer-{v}-win-x64-full.nupkg")},
            {"PackageId": "OpenNCALayer", "Version": v.to_string(), "Type": "Delta",
             "FileName": format!("OpenNCALayer-{v}-win-x64-delta.nupkg")},
        ]});
        fs::write(dir.path().join("releases.win-x64.json"), feed.to_string()).unwrap();
    }
    fs::write(
        dir.path().join(format!("openncalayer-chromium-{v}.zip")),
        "chromium",
    )
    .unwrap();
    fs::write(
        dir.path().join(format!("openncalayer-firefox-{v}.xpi")),
        "firefox",
    )
    .unwrap();
    fs::write(dir.path().join("SHA256SUMS"), "not a package").unwrap();
    dir
}

fn add(dir: &Path, tag: &str, assets: &Path) -> index::Added {
    index::add(dir, Channel::Beta, tag, assets, 100, now()).unwrap()
}

fn read(path: &Path) -> Index {
    Index::from_json(&fs::read(path).unwrap()).unwrap()
}

fn options(base: Option<&str>) -> CheckOptions<'_> {
    CheckOptions {
        base,
        vm_smoke: false,
        conformance: false,
        now: now(),
    }
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "tag.forceSignAnnotated=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

/// A git repository with one commit. Its indexes are [`Repo::path`], `updates/v1`.
struct Repo {
    repo: tempfile::TempDir,
    dir: std::path::PathBuf,
}

impl Repo {
    fn path(&self) -> &Path {
        &self.dir
    }
}

/// `None` after the skip line when there is no `git`.
fn empty_repo() -> Option<Repo> {
    oncl_testkit::tool::GIT.or_skip(&["--version"])?;
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    let root = repo.path().join(index::TAG_ROOT);
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    fs::write(&root, "{}").unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "--quiet", "-m", "start"]);
    for tag in [TAG, NEXT_TAG, STABLE_TAG] {
        git(repo.path(), &["tag", tag]);
    }
    let dir = repo.path().join("updates").join("v1");
    Some(Repo { repo, dir })
}

/// [`empty_repo`] whose next commit holds `updates/v1/beta.json` at seq 1 with [`TAG`].
fn repository_with_index() -> Option<(tempfile::TempDir, std::path::PathBuf)> {
    let Repo { repo, dir } = empty_repo()?;
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    add(&dir, TAG, assets.path());
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "--quiet", "-m", "index"]);
    Some((repo, dir))
}

fn error_text(result: anyhow::Result<impl std::fmt::Debug>) -> String {
    format!("{:#}", result.unwrap_err())
}

#[test]
fn add_takes_sums_and_sizes_from_the_assets() {
    let dir = tempfile::tempdir().unwrap();
    let first = release_assets(TAG, &[Flavor::WinX64, Flavor::LinuxX64], None);
    let added = add(dir.path(), TAG, first.path());
    assert_eq!(added.written.path, dir.path().join("beta.json"));
    assert_eq!(added.written.seq, 1);
    assert_eq!(added.flavors, [Flavor::WinX64, Flavor::LinuxX64]);
    assert!(added.extension);

    let index = read(&added.written.path);
    assert_eq!((index.channel, index.seq), (Channel::Beta, 1));
    assert_eq!(index.generated, now());
    assert_eq!(index.expires, now() + Duration::days(30));
    let release = index.release(&version(TAG)).unwrap();
    assert_eq!(release.rollout, 100);
    assert!(!release.revoked);
    let linux = release.package(Flavor::LinuxX64).unwrap();
    let content = "full 0.2.0-beta.1 linux-x64";
    assert_eq!(linux.full.sha256, Sha256::of(content.as_bytes()));
    assert_eq!(linux.full.size, content.len() as u64);
    assert_eq!(
        linux.full.url,
        "https://github.com/arynyklas/OpenNCALayer/releases/download/v0.2.0-beta.1/\
         OpenNCALayer-0.2.0-beta.1-linux-x64-full.nupkg"
    );
    assert!(linux.delta_from.is_empty());
    let extension = index.extension.as_ref().unwrap();
    assert_eq!(extension.version, version(TAG));
    assert_eq!(extension.firefox_xpi.sha256, Sha256::of(b"firefox"));

    // The next version: seq grows, its delta applies to the newest older full package of
    // Velopack's feed.
    let second = release_assets(NEXT_TAG, &[Flavor::WinX64], Some("0.2.0-beta.1"));
    let added = index::add(
        dir.path(),
        Channel::Beta,
        NEXT_TAG,
        second.path(),
        25,
        now() + Duration::days(1),
    )
    .unwrap();
    assert_eq!(added.written.seq, 2);
    let index = read(&added.written.path);
    assert_eq!(index.seq, 2);
    assert_eq!(index.expires, now() + Duration::days(31));
    let versions: Vec<_> = index.core.iter().map(|r| r.version.to_string()).collect();
    assert_eq!(versions, ["0.2.0-beta.1", "0.2.0-beta.2"]);
    let release = index.release(&version(NEXT_TAG)).unwrap();
    assert_eq!(release.rollout, 25);
    let win = release.package(Flavor::WinX64).unwrap();
    let delta = &win.delta_from[&version(TAG)];
    assert_eq!(
        delta.sha256,
        Sha256::of(b"delta 0.2.0-beta.1 -> 0.2.0-beta.2")
    );
    assert_eq!(win.delta_from.len(), 1);
    // The files of the full package, for the one the client rebuilds from the delta.
    let full = second
        .path()
        .join("OpenNCALayer-0.2.0-beta.2-win-x64-full.nupkg");
    assert_eq!(
        win.contents_sha256,
        Some(oncl_update::contents_sha256(&full).unwrap())
    );
    assert_eq!(index.extension.unwrap().version, version(NEXT_TAG));

    // A version is added once.
    let again = index::add(
        dir.path(),
        Channel::Beta,
        NEXT_TAG,
        second.path(),
        100,
        now(),
    );
    assert!(error_text(again).contains("already"));
}

#[test]
fn add_refuses_bad_input() {
    let dir = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let result = index::add(dir.path(), Channel::Beta, TAG, empty.path(), 100, now());
    assert!(error_text(result).contains("full.nupkg"));

    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let result = index::add(
        dir.path(),
        Channel::Beta,
        "0.2.0",
        assets.path(),
        100,
        now(),
    );
    assert!(error_text(result).contains("v<semver>"));

    // A delta without Velopack's feed has no known base.
    let assets = release_assets(TAG, &[Flavor::WinX64], Some("0.1.5"));
    fs::remove_file(assets.path().join("releases.win-x64.json")).unwrap();
    let result = index::add(dir.path(), Channel::Beta, TAG, assets.path(), 100, now());
    assert!(error_text(result).contains("releases.win-x64.json"));

    // Half of the extension.
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    fs::remove_file(assets.path().join("openncalayer-firefox-0.2.0-beta.1.xpi")).unwrap();
    let result = index::add(dir.path(), Channel::Beta, TAG, assets.path(), 100, now());
    assert!(error_text(result).contains("firefox"));
    assert!(!dir.path().join("beta.json").exists());

    // An index of another channel in the channel's file.
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let beta = add(dir.path(), TAG, assets.path()).written.path;
    fs::copy(&beta, dir.path().join("stable.json")).unwrap();
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    let result = index::add(
        dir.path(),
        Channel::Stable,
        NEXT_TAG,
        assets.path(),
        100,
        now(),
    );
    assert!(error_text(result).contains("is of the beta channel"));
    let result = index::refresh(dir.path(), Channel::Stable, now());
    assert!(error_text(result).contains("is of the beta channel"));
}

#[test]
fn a_valid_index_passes_the_check() {
    let dir = tempfile::tempdir().unwrap();
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let path = add(dir.path(), TAG, assets.path()).written.path;

    let checked = index::check(dir.path(), &options(None), None).unwrap();
    assert_eq!(checked.len(), 1);
    assert_eq!((checked[0].channel, checked[0].seq), (Channel::Beta, 1));
    assert_eq!(checked[0].new_versions, [version(TAG)]);

    // An index of another channel in the channel's file.
    fs::copy(&path, dir.path().join("stable.json")).unwrap();
    let result = index::check(dir.path(), &options(None), None);
    assert!(error_text(result).contains("is for the beta channel, not stable"));
    fs::remove_file(dir.path().join("stable.json")).unwrap();

    // Not an index.
    fs::write(&path, "not json").unwrap();
    let result = index::check(dir.path(), &options(None), None);
    assert!(error_text(result).contains("is refused"));
}

#[test]
fn an_expired_index_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    add(dir.path(), TAG, assets.path());
    let late = CheckOptions {
        now: now() + Duration::days(30),
        ..options(None)
    };
    let result = index::check(dir.path(), &late, None);
    assert!(error_text(result).contains("expired"));
    let in_time = CheckOptions {
        now: now() + Duration::days(29),
        ..options(None)
    };
    index::check(dir.path(), &in_time, None).unwrap();
}

#[test]
fn seq_must_grow_from_the_base() {
    let Some((repo, dir)) = repository_with_index() else {
        return;
    };
    let path = dir.join("beta.json");

    // Unchanged: passes, nothing new.
    let checked = index::check(&dir, &options(Some("HEAD")), None).unwrap();
    assert_eq!(checked[0].base_seq, Some(1));
    assert!(checked[0].new_versions.is_empty());

    // A new version, seq 2: passes, the version is new.
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    add(&dir, NEXT_TAG, assets.path());
    let checked = index::check(&dir, &options(Some("HEAD")), None).unwrap();
    assert_eq!((checked[0].seq, checked[0].base_seq), (2, Some(1)));
    assert_eq!(checked[0].new_versions, [version(NEXT_TAG)]);
    git(repo.path(), &["commit", "--quiet", "-am", "seq 2"]);

    // Changed with the same seq, then with seq going back: refused.
    let mut index = read(&path);
    index.core[0].rollout = 50;
    for seq in [2, 1] {
        index.seq = seq;
        fs::write(&path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
        let result = index::check(&dir, &options(Some("HEAD")), None);
        assert!(error_text(result).contains("does not grow"), "seq {seq}");
    }

    // A removed index.
    fs::remove_file(&path).unwrap();
    let result = index::check(&dir, &options(Some("HEAD")), None);
    assert!(error_text(result).contains("removed"));

    // A base that does not exist.
    let result = index::check(&dir, &options(Some("no-such-branch")), None);
    assert!(error_text(result).contains("no-such-branch"));
}

/// Answers `HEAD` with 200 except for URLs containing `missing`; a status passes for the
/// `(tag, context)` pairs of `passed`. Records the pairs asked about.
struct FakeRemote {
    missing: Option<&'static str>,
    passed: &'static [(&'static str, &'static str)],
    asked: RefCell<Vec<(String, String)>>,
}

impl FakeRemote {
    fn new(missing: Option<&'static str>, passed: &'static [(&'static str, &'static str)]) -> Self {
        FakeRemote {
            missing,
            passed,
            asked: RefCell::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<(String, String)> {
        self.asked.borrow().clone()
    }
}

impl Remote for FakeRemote {
    fn head(&self, url: &str) -> anyhow::Result<u16> {
        assert!(url.starts_with("https://github.com/arynyklas/OpenNCALayer/releases/"));
        Ok(match self.missing {
            Some(m) if url.contains(m) => 404,
            _ => 200,
        })
    }

    fn status_passed(&self, tag: &str, context: &str) -> anyhow::Result<bool> {
        self.asked
            .borrow_mut()
            .push((tag.to_owned(), context.to_owned()));
        Ok(self.passed.contains(&(tag, context)))
    }
}

fn pair(tag: &str, context: &str) -> (String, String) {
    (tag.to_owned(), context.to_owned())
}

#[test]
fn network_checks_go_through_the_remote() {
    let Some((_repo, dir)) = repository_with_index() else {
        return;
    };
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64, Flavor::Osx], None);
    add(&dir, NEXT_TAG, assets.path());

    let ok = FakeRemote::new(None, &[]);
    index::check(&dir, &options(Some("HEAD")), Some(&ok)).unwrap();
    assert!(ok.asked().is_empty(), "the status gates are off by default");

    let missing = FakeRemote::new(Some("osx-full"), &[]);
    let result = index::check(&dir, &options(Some("HEAD")), Some(&missing));
    assert!(error_text(result).contains("answered 404"));

    let gated = CheckOptions {
        vm_smoke: true,
        ..options(Some("HEAD"))
    };
    let unsmoked = FakeRemote::new(None, &[(TAG, index::VM_SMOKE)]);
    let result = index::check(&dir, &gated, Some(&unsmoked));
    assert!(error_text(result).contains("vm-smoke"));
    // Another context's success does not count.
    let other = FakeRemote::new(None, &[(NEXT_TAG, index::CONFORMANCE)]);
    let result = index::check(&dir, &gated, Some(&other));
    assert!(error_text(result).contains("v0.2.0-beta.2 has no successful vm-smoke status"));
    let smoked = FakeRemote::new(None, &[(NEXT_TAG, index::VM_SMOKE)]);
    index::check(&dir, &gated, Some(&smoked)).unwrap();
    // Only the version new against the base is asked about.
    assert_eq!(smoked.asked(), [pair(NEXT_TAG, index::VM_SMOKE)]);

    let result = index::check(&dir, &gated, None);
    assert!(error_text(result).contains("the vm-smoke gate needs the network"));
}

#[test]
fn check_conformance_required_for_new_stable() {
    let Some(repo) = empty_repo() else {
        return;
    };
    let stable = release_assets(STABLE_TAG, &[Flavor::WinX64], None);
    index::add(
        repo.path(),
        Channel::Stable,
        STABLE_TAG,
        stable.path(),
        100,
        now(),
    )
    .unwrap();
    let beta = release_assets(TAG, &[Flavor::WinX64], None);
    add(repo.path(), TAG, beta.path());
    let gated = CheckOptions {
        conformance: true,
        ..options(Some("HEAD"))
    };

    let none = FakeRemote::new(None, &[]);
    let result = index::check(repo.path(), &gated, Some(&none));
    assert!(
        error_text(result).contains("v0.2.0 has no successful conformance status"),
        "{:?}",
        none.asked()
    );
    // `vm-smoke` is not `conformance`.
    let smoked = FakeRemote::new(None, &[(STABLE_TAG, index::VM_SMOKE)]);
    let result = index::check(repo.path(), &gated, Some(&smoked));
    assert!(error_text(result).contains("no successful conformance status"));

    let conformed = FakeRemote::new(None, &[(STABLE_TAG, index::CONFORMANCE)]);
    index::check(repo.path(), &gated, Some(&conformed)).unwrap();
    // Asked about the new stable version only, not the beta one.
    assert_eq!(conformed.asked(), [pair(STABLE_TAG, index::CONFORMANCE)]);

    // Published (in the base), the version is not new and is not asked about again.
    git(repo.repo.path(), &["add", "."]);
    git(repo.repo.path(), &["commit", "--quiet", "-m", "indexes"]);
    let none = FakeRemote::new(None, &[]);
    index::check(repo.path(), &gated, Some(&none)).unwrap();
    assert!(none.asked().is_empty());
}

#[test]
fn check_conformance_not_required_for_beta() {
    let Some((_repo, dir)) = repository_with_index() else {
        return;
    };
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    add(&dir, NEXT_TAG, assets.path());

    let gated = CheckOptions {
        conformance: true,
        ..options(Some("HEAD"))
    };
    let none = FakeRemote::new(None, &[]);
    index::check(&dir, &gated, Some(&none)).unwrap();
    assert!(none.asked().is_empty());

    // With both gates, the new beta version needs `vm-smoke` only.
    let both = CheckOptions {
        vm_smoke: true,
        ..gated
    };
    let smoked = FakeRemote::new(None, &[(NEXT_TAG, index::VM_SMOKE)]);
    index::check(&dir, &both, Some(&smoked)).unwrap();
    assert_eq!(smoked.asked(), [pair(NEXT_TAG, index::VM_SMOKE)]);
}

#[test]
fn check_conformance_needs_network() {
    let Some((_repo, dir)) = repository_with_index() else {
        return;
    };
    let gated = CheckOptions {
        conformance: true,
        ..options(Some("HEAD"))
    };
    let result = index::check(&dir, &gated, None);
    assert!(error_text(result).contains("the conformance gate needs the network"));
    // The command refuses the flag offline.
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["index", "check"])
        .arg(&dir)
        .args(["--offline", "--conformance"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--conformance"), "{stderr}");
}

#[test]
fn urls_off_the_project_releases_are_refused() {
    const FULL: &str = "https://github.com/arynyklas/OpenNCALayer/releases/download/\
                        v0.2.0-beta.1/OpenNCALayer-0.2.0-beta.1-win-x64-full.nupkg";
    const CHROMIUM: &str = "https://github.com/arynyklas/OpenNCALayer/releases/download/\
                            v0.2.0-beta.1/openncalayer-chromium-0.2.0-beta.1.zip";
    const NOTES: &str = "https://github.com/arynyklas/OpenNCALayer/releases/tag/v0.2.0-beta.1";
    let swaps = [
        (
            FULL,
            FULL.replace("https://github.com/", "https://example.com/"),
        ),
        (
            FULL,
            FULL.replace("arynyklas/OpenNCALayer", "someone/OpenNCALayer"),
        ),
        (FULL, FULL.replace("/v0.2.0-beta.1/", "/v0.1.0/")),
        (FULL, FULL.replace("https://", "http://")),
        (FULL, format!("{FULL}?download=1")),
        (FULL, format!("{FULL}#x")),
        (FULL, FULL.replace("-win-x64-full", "-linux-x64-full")),
        (FULL, FULL.replace("-full.nupkg", "-delta.nupkg")),
        (
            CHROMIUM,
            CHROMIUM.replace("/v0.2.0-beta.1/", "/v0.2.0-beta.2/"),
        ),
        (
            CHROMIUM,
            CHROMIUM.replace("github.com", "github.com.example.net"),
        ),
        (NOTES, NOTES.replace("arynyklas", "someone")),
    ];
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    for (from, to) in swaps {
        let dir = tempfile::tempdir().unwrap();
        let path = add(dir.path(), TAG, assets.path()).written.path;
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(&format!("\"{from}\"")), "{from}");
        fs::write(
            &path,
            text.replace(&format!("\"{from}\""), &format!("\"{to}\"")),
        )
        .unwrap();

        let result = index::check(dir.path(), &options(None), None);
        assert!(result.is_err(), "check accepted {to}");
    }

    // The messages name the rule for a URL the client itself would take.
    let dir = tempfile::tempdir().unwrap();
    let path = add(dir.path(), TAG, assets.path()).written.path;
    let text = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        text.replace(FULL, &FULL.replace("github.com", "example.com")),
    )
    .unwrap();
    let result = index::check(dir.path(), &options(None), None);
    assert!(error_text(result).contains("the asset of the project's release"));
    // So does `add` reading it.
    let next = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    let result = index::add(dir.path(), Channel::Beta, NEXT_TAG, next.path(), 100, now());
    assert!(error_text(result).contains("the asset of the project's release"));
}

#[test]
fn refresh_bumps_seq_and_validity_only() {
    let Some((repo, dir)) = repository_with_index() else {
        return;
    };
    let path = dir.join("beta.json");
    let before = read(&path);

    let later = now() + Duration::days(25);
    let written = index::refresh(&dir, Channel::Beta, later).unwrap();
    assert_eq!((written.path.as_path(), written.seq), (path.as_path(), 2));
    let after = read(&path);
    assert_eq!(after.seq, 2);
    assert_eq!(after.generated, later);
    assert_eq!(after.expires, later + Duration::days(30));
    assert_eq!(
        (&after.core, &after.extension, &after.plugins),
        (&before.core, &before.extension, &before.plugins)
    );

    // It passes the gate against the committed seq 1.
    let checked = index::check(
        &dir,
        &CheckOptions {
            now: later,
            ..options(Some("HEAD"))
        },
        None,
    )
    .unwrap();
    assert_eq!((checked[0].seq, checked[0].base_seq), (2, Some(1)));
    assert!(checked[0].new_versions.is_empty());
    drop(repo);

    let empty = tempfile::tempdir().unwrap();
    let result = index::refresh(empty.path(), Channel::Stable, now());
    assert!(error_text(result).contains("stable.json"));
}

#[test]
fn no_index_published_yet_passes() {
    let Some(repo) = empty_repo() else {
        return;
    };
    assert!(!repo.path().exists(), "no updates/v1 in the tree");
    for base in [Some("HEAD"), None] {
        let checked = index::check(repo.path(), &options(base), None).unwrap();
        assert!(checked.is_empty(), "{base:?}");
    }

    // The command, as the workflows run it.
    let xtask = |base: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["index", "check"])
            .arg(repo.path())
            .arg("--offline")
            .args(base)
            .output()
            .unwrap()
    };
    for base in [&["--base", "HEAD"][..], &["--no-base"]] {
        let ok = xtask(base);
        let stdout = String::from_utf8_lossy(&ok.stdout);
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        assert!(stdout.contains("no index is published yet"), "{stdout}");
    }

    // Relative, as the workflows pass it, from the repository root: `updates/` is not
    // there either.
    let relative = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .current_dir(repo.repo.path())
        .args([
            "index",
            "check",
            "updates/v1",
            "--offline",
            "--base",
            "HEAD",
        ])
        .output()
        .unwrap();
    assert!(
        relative.status.success(),
        "{}",
        String::from_utf8_lossy(&relative.stderr)
    );
    assert!(String::from_utf8_lossy(&relative.stdout).contains("no index is published yet"));

    // Once published, the directory may not go.
    let Some((repo, dir)) = repository_with_index() else {
        return;
    };
    fs::remove_dir_all(repo.path().join("updates")).unwrap();
    let result = index::check(&dir, &options(Some("HEAD")), None);
    assert!(error_text(result).contains("removed here"));
}

#[test]
fn a_version_tagged_without_the_tuf_root_is_refused() {
    let Some(repo) = empty_repo() else {
        return;
    };
    // Retag NEXT_TAG on a commit without the root.
    let root = repo.repo.path().join(index::TAG_ROOT);
    fs::remove_file(&root).unwrap();
    git(repo.repo.path(), &["add", "--all", "."]);
    git(repo.repo.path(), &["commit", "--quiet", "-m", "no root"]);
    git(repo.repo.path(), &["tag", "--force", NEXT_TAG]);

    // `index add` refuses it, the check too (against a base without the index).
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    let result = index::check_tag_root(repo.path(), &version(NEXT_TAG));
    assert!(error_text(result).contains("has no crates/oncl-update/keys/root.json"));
    add(repo.path(), NEXT_TAG, assets.path());
    let result = index::check(repo.path(), &options(Some("HEAD")), None);
    let text = error_text(result);
    assert!(
        text.contains("has no crates/oncl-update/keys/root.json"),
        "{text}"
    );

    // A tag with the root passes; a tag that is not there is refused.
    index::check_tag_root(repo.path(), &version(TAG)).unwrap();
    let result = index::check_tag_root(repo.path(), &version("v0.3.0"));
    assert!(error_text(result).contains("there is no tag v0.3.0"));
}
