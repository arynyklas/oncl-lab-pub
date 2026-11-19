//! `cargo xtask vendor` end to end with a synthetic publisher on the world of
//! `delegations.rs` made a git repository: `keygen`, `onboard`, the owner's `tuf update`, the
//! canonical source archive, the build's output, `add` and `sign`, then `check-pr` of the
//! release pull request passes every check it makes, the verdict job passes checks 21 and 22
//! and writes `BUILDINFO.json`; pull requests tampered with one way each fail with the check
//! that names that way.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use oncl_pack::source::{File, Tree};
use oncl_update::tuf::{PublisherName, SigningKey, build};
use serde_json::{Map, Value, json};
use time::{Duration, OffsetDateTime};
use xtask::publishers::Registry;
use xtask::tuf::PassphraseSource;
use xtask::tuf::keystore::Unlock;
use xtask::vendor::draft::{Addition, Draft};
use xtask::vendor::fetch::ArchiveFetcher;
use xtask::vendor::mirror::{BuildInfo, BuilderInfo, FileInfo, SourceInfo};
use xtask::vendor::onboard::{self, Onboarding};
use xtask::vendor::pr::{self, ProvenanceReport, VerdictInputs};
use xtask::vendor::provenance::Provenance;
use xtask::vendor::verdict::{PrVerdict, Status};
use xtask::vendor::{Layout, checks, diff, keys};

use super::delegations::{online_world, t1};
use super::{PASSPHRASE, World, has_git};

/// What `vendor rebuild --out` leaves: the package and `rebuild.json`, checks 17, 19 and 20
/// passed but for `failed`.
fn rebuilt_into(dir: &Path, package: &[u8], failed: &[u8]) {
    use xtask::vendor::verdict::Checks;
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("kz.zeta.market-1.0.0.onclp"), package).unwrap();
    let mut checks = Checks::new();
    for id in [17, 19, 20] {
        if failed.contains(&id) {
            checks.fail(id, "failed");
        } else {
            checks.pass(id);
        }
    }
    let report = pr::RebuildReport {
        schema: 1,
        checks: checks.into_vec(),
    };
    fs::write(
        dir.join(pr::REBUILD_REPORT),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
}

/// The world's layout: `repo` is `tuf/v1`.
const LAYOUT: Layout = Layout {
    tuf: "repo",
    config: "repo.toml",
    anchor: "anchor/root.json",
    indexes: "indexes",
    publishers: "publishers",
    deny: "deny.toml",
};

fn builder() -> String {
    format!("sha256:{}", "b".repeat(64))
}

/// The base commit's time.
fn t_base() -> OffsetDateTime {
    t1() + Duration::minutes(10)
}

/// The time of the checks.
fn t_check() -> OffsetDateTime {
    t1() + Duration::hours(3)
}

/// `git` in `dir` with a fixed identity, its commits dated `when`.
fn git_at(dir: &Path, args: &[&str], when: Option<OffsetDateTime>) -> String {
    let mut command = Command::new("git");
    command.arg("-C").arg(dir).args([
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.autocrlf=false",
    ]);
    if let Some(when) = when {
        let date = format!("@{} +0000", when.unix_timestamp());
        command
            .env("GIT_AUTHOR_DATE", &date)
            .env("GIT_COMMITTER_DATE", &date);
    }
    let out = command.args(args).output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A branch `name` from `from` with `files` written (path relative to the world), committed
/// at `when`; the checkout goes back to `main`.
fn branch(w: &World, name: &str, from: &str, files: &[(String, Vec<u8>)], when: OffsetDateTime) {
    let root = w.p("");
    git_at(&root, &["checkout", "-q", "-B", name, from], None);
    for (path, bytes) in files {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }
    git_at(&root, &["add", "-A"], None);
    git_at(&root, &["commit", "-q", "-m", name], Some(when));
    git_at(&root, &["checkout", "-q", "main"], None);
}

/// The archives CI downloads, by URL; a missing one is unreachable.
struct Table(BTreeMap<String, Vec<u8>>);

impl ArchiveFetcher for Table {
    fn fetch(&self, url: &str, limit: u64) -> Result<Vec<u8>, String> {
        match self.0.get(url) {
            Some(bytes) if bytes.len() as u64 <= limit => Ok(bytes.clone()),
            Some(_) => Err(format!("{url}: more than {limit} bytes")),
            None => Err(format!("{url}: unreachable")),
        }
    }
}

fn manifest(capabilities: &str) -> String {
    format!(
        "id = \"kz.zeta.market\"\nversion = \"1.0.0\"\nmin_core = \"0.1.3\"\n\
         modules = [\"kz.zeta.Signer\"]\n\n\
         [name]\nru = \"Маркет\"\nkk = \"Маркет\"\nen = \"Market\"\n\n\
         [capabilities]\n{capabilities}\n"
    )
}

/// The publisher's sources: a workspace with the plugin crate at `crates/p`, plus `extra`.
fn sources(manifest: &str, extra: &[(&str, &[u8])]) -> Tree {
    let mut files: Vec<(&str, Vec<u8>)> = vec![
        ("LICENSE", b"MIT License\n".to_vec()),
        (
            "Cargo.toml",
            b"[workspace]\nmembers = [\"crates/p\"]\n[workspace.package]\nlicense = \"MIT\"\n"
                .to_vec(),
        ),
        (
            "Cargo.lock",
            b"version = 4\n\n[[package]]\nname = \"p\"\nversion = \"1.0.0\"\n\n\
              [[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
              source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
                .to_vec(),
        ),
        (
            "crates/p/Cargo.toml",
            b"[package]\nname = \"p\"\nversion = \"1.0.0\"\nlicense.workspace = true\n".to_vec(),
        ),
        ("crates/p/plugin.toml", manifest.as_bytes().to_vec()),
        ("crates/p/src/lib.rs", b"// the plugin\n".to_vec()),
    ];
    for (path, data) in extra {
        files.retain(|(p, _)| p != path);
        files.push((path, data.to_vec()));
    }
    let mut tree = Tree::new();
    for (path, data) in files {
        tree.insert(
            path,
            File {
                executable: false,
                data,
            },
        )
        .unwrap();
    }
    tree
}

/// The package a build of `manifest` gives (an empty module: the checks read the package as
/// data).
fn package(manifest: &str) -> Vec<u8> {
    oncl_plugin::archive(manifest.as_bytes(), b"\0asm\x01\0\0\0").unwrap()
}

/// What `vendor build` writes into BUILDINFO.json for `archive` and `package`.
fn build_info(archive: &[u8], package: &[u8], tree: &Tree) -> BuildInfo {
    BuildInfo {
        schema: 1,
        id: "kz.zeta.market".into(),
        version: "1.0.0".into(),
        builder: BuilderInfo {
            image: format!("ghcr.io/arynyklas/oncl-plugin-builder@{}", builder()),
            digest: Some(builder()),
            rust: Some("1.99.1".into()),
            commit: Some("c".repeat(40)),
        },
        source: SourceInfo {
            archive: FileInfo {
                file: "kz.zeta.market-1.0.0.src.tar.gz".into(),
                sha256: oncl_pack::sha256_hex(archive),
                length: archive.len() as u64,
            },
            path: "crates/p".into(),
            license: checks::crate_license(tree, "crates/p"),
            cargo_lock_sha256: checks::lock_sha256(tree, "crates/p"),
        },
        package: FileInfo {
            file: "kz.zeta.market-1.0.0.onclp".into(),
            sha256: oncl_pack::sha256_hex(package),
            length: package.len() as u64,
        },
        release: None,
        vcs: None,
        checks: Vec::new(),
    }
}

const PATH: &str = "plugins/zeta/kz.zeta.market/1.0.0.onclp";

/// The world after onboarding: the publisher `zeta` with its key, delegated to on `main`.
struct Released {
    w: World,
    keys: PathBuf,
    _keys_dir: tempfile::TempDir,
    key: SigningKey,
    archive: Vec<u8>,
    tree: Tree,
    package: Vec<u8>,
    target: Value,
    role: Vec<u8>,
}

fn zeta() -> PublisherName {
    PublisherName::parse("zeta").unwrap()
}

fn publisher(w: &World) -> xtask::publishers::Publisher {
    Registry::read(&w.publishers())
        .unwrap()
        .get(&zeta())
        .unwrap()
        .clone()
}

/// The target of `archive` and `package` as `vendor add` makes it, fetched from `fetch`.
fn target(
    w: &World,
    archive: &[u8],
    package: &[u8],
    tree: &Tree,
    fetch: &str,
    vcs: Option<(&str, &str)>,
) -> Value {
    let mut draft = Draft {
        schema: 1,
        publisher: "zeta".into(),
        base_version: None,
        targets: Map::new(),
    };
    let info = build_info(archive, package, tree);
    let path = draft
        .add(
            &publisher(w),
            &Addition {
                build: &info,
                package,
                fetch,
                vcs,
                channel: oncl_update::Channel::Stable,
                rollout: 100,
            },
        )
        .unwrap();
    draft.targets[&path].clone()
}

/// A role file of `targets`, version `version`, expiring `days` after the check, signed by
/// `key`.
fn role(targets: &Map<String, Value>, version: u64, days: i64, key: &SigningKey) -> Vec<u8> {
    let signed =
        keys::role_signed(&zeta(), version, t_check() + Duration::days(days), targets).unwrap();
    build::sign(&signed, &[key]).unwrap()
}

fn one(target: Value) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(PATH.to_owned(), target);
    map
}

const FETCH: &str = "https://downloads.zeta.example/kz.zeta.market-1.0.0.src.tar.gz";

/// keygen → onboard → the owner's update and commit → source → build output → add → sign.
fn released() -> Released {
    let w = online_world();
    let root = w.p("");
    // The publisher's key, outside the repository.
    let keys_dir = tempfile::tempdir().unwrap();
    let pass = keys_dir.path().join("pass.txt");
    fs::write(&pass, PASSPHRASE).unwrap();
    let keys = keys_dir.path().join("keys");
    let (file, public) = keys::keygen(&zeta(), &keys, PASSPHRASE).unwrap();
    assert!(file.starts_with(&keys));
    // Onboarding, then the owner lists a builder and delegates (`tuf update`).
    let onboarded = onboard::onboard(
        &root,
        &LAYOUT,
        &Onboarding {
            name: "zeta".into(),
            prefix: "kz.zeta.".into(),
            modules: vec!["kz.zeta.Signer".into()],
            bundles: Vec::new(),
            display: ["Зета".into(), "Зета".into(), "Zeta".into()],
            github: vec!["zeta-release".into()],
            keys: vec![public.to_hex()],
            threshold: 1,
            homepage: Some("https://zeta.example/".into()),
            contact: None,
        },
    )
    .unwrap();
    assert!(onboarded.ends_with("publishers/zeta/publisher.toml"));
    fs::write(
        w.publishers().join("builders.toml"),
        format!(
            "[[builder]]\ndigest = \"{}\"\ncommit = \"{}\"\nrust = \"1.99.1\"\nadded = 2026-09-01\n",
            builder(),
            "c".repeat(40)
        ),
    )
    .unwrap();
    fs::write(
        w.p("deny.toml"),
        "[sources]\nallow-git = [\"https://github.com/arynyklas/slint\"]\n",
    )
    .unwrap();
    assert!(matches!(
        w.update(t1(), false).unwrap(),
        xtask::tuf::update::Outcome::Written(_)
    ));
    git_at(&root, &["init", "-q", "-b", "main"], None);
    git_at(&root, &["add", "-A"], None);
    git_at(&root, &["commit", "-q", "-m", "base"], Some(t_base()));
    // `vendor source` of a directory, as the publisher runs it.
    let crate_dir = tempfile::tempdir().unwrap();
    let tree = sources(&manifest("keys = true"), &[]);
    tree.unpack(&crate_dir.path().join("src")).unwrap();
    let from_dir = Tree::from_dir(&crate_dir.path().join("src")).unwrap();
    assert_eq!(from_dir, tree);
    let archive = from_dir.to_archive().unwrap();
    let package = package(&manifest("keys = true"));
    // `vendor add`, `vendor sign`.
    let publisher = publisher(&w);
    let mut draft = Draft::open(&root, &w.repo(), &publisher).unwrap();
    assert_eq!(draft.base_version, None);
    let info = build_info(&archive, &package, &tree);
    let added = draft
        .add(
            &publisher,
            &Addition {
                build: &info,
                package: &package,
                fetch: FETCH,
                vcs: None,
                channel: oncl_update::Channel::Stable,
                rollout: 100,
            },
        )
        .unwrap();
    assert_eq!(added, PATH);
    let mut unlock = Unlock::new(PassphraseSource::File(pass), "");
    let found = keys::publisher_keys(&keys, &publisher, &mut unlock).unwrap();
    let signed = keys::sign(
        &w.repo(),
        &publisher,
        draft.base_version,
        &draft.targets,
        t_check(),
        90,
        &found,
    )
    .unwrap();
    assert_eq!((signed.version, signed.signatures), (1, 1));
    let role = fs::read(&signed.path).unwrap();
    fs::remove_file(&signed.path).unwrap();
    let key = found.into_iter().next().unwrap();
    Released {
        target: draft.targets[PATH].clone(),
        w,
        keys,
        _keys_dir: keys_dir,
        key,
        archive,
        tree,
        package,
        role,
    }
}

fn role_path(version: u64) -> String {
    format!("repo/metadata/{version}.pub-zeta.json")
}

fn check(
    r: &Released,
    base: &str,
    head: &str,
    author: &str,
    table: &Table,
    now: OffsetDateTime,
) -> PrVerdict {
    pr::check_pr(&pr::Options {
        repo: &r.w.p(""),
        base,
        head,
        author: Some(author),
        now,
        layout: LAYOUT,
        fetcher: Some(table),
        out: None,
        builtin_modules: Some(Vec::new()),
    })
    .unwrap()
}

fn table(entries: &[(&str, &[u8])]) -> Table {
    Table(
        entries
            .iter()
            .map(|(url, bytes)| ((*url).to_owned(), bytes.to_vec()))
            .collect(),
    )
}

fn failed(verdict: &PrVerdict) -> Vec<u8> {
    verdict.failures().iter().map(|c| c.0).collect()
}

fn status(verdict: &PrVerdict, id: u8) -> Option<Status> {
    verdict
        .checks
        .iter()
        .find(|c| c.id.0 == id)
        .map(|c| c.status)
}

#[test]
fn a_synthetic_publisher_releases_and_the_pull_request_passes_every_check() {
    if !has_git() {
        return;
    }
    let r = released();
    branch(
        &r.w,
        "pr",
        "main",
        &[(role_path(1), r.role.clone())],
        t_check() - Duration::minutes(5),
    );
    let out = tempfile::tempdir().unwrap();
    let fetcher = table(&[(FETCH, &r.archive)]);
    let verdict = pr::check_pr(&pr::Options {
        repo: &r.w.p(""),
        base: "main",
        head: "pr",
        author: Some("zeta-release"),
        now: t_check(),
        layout: LAYOUT,
        fetcher: Some(&fetcher),
        out: Some(out.path()),
        builtin_modules: Some(Vec::new()),
    })
    .unwrap();
    assert!(verdict.ok, "{:#?}", verdict.checks);
    for id in [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 23, 24,
    ] {
        assert_eq!(
            status(&verdict, id),
            Some(Status::Pass),
            "check {id}: {:#?}",
            verdict.checks
        );
    }
    assert_eq!(verdict.publisher.as_deref(), Some("zeta"));
    assert_eq!(verdict.role_version, Some(1));
    let [new] = verdict.new_targets.as_slice() else {
        panic!("{:?}", verdict.new_targets);
    };
    assert_eq!(new.path, PATH);
    assert_eq!(
        new.tag,
        format!("pub-zeta-{}", oncl_pack::sha256_hex(&r.package))
    );
    assert_eq!(new.archive, "kz.zeta.market-1.0.0.src.tar.gz");
    assert!(new.previous.is_none());
    // The JSON verdict and the archive for the later jobs.
    let written: PrVerdict =
        serde_json::from_slice(&fs::read(out.path().join("verdict.json")).unwrap()).unwrap();
    assert_eq!(written, verdict);
    assert_eq!(
        fs::read(out.path().join("kz.zeta.market-1.0.0.src.tar.gz")).unwrap(),
        r.archive
    );

    // The verdict job, from git again, over the archive and the rebuilt package.
    let rebuilt = tempfile::tempdir().unwrap();
    let matrix = rebuilt.path().join("rebuild-0");
    fs::create_dir_all(&matrix).unwrap();
    rebuilt_into(&matrix, &r.package, &[]);
    let loaded = pr::load_pr(&r.w.p(""), "main", "pr", &LAYOUT, t_check()).unwrap();
    let final_dir = tempfile::tempdir().unwrap();
    let checks = pr::verdict_job(
        &loaded,
        &VerdictInputs {
            archives: out.path(),
            rebuilt: rebuilt.path(),
            provenance: None,
        },
        final_dir.path(),
    )
    .unwrap();
    assert!(checks.failures().is_empty(), "{:?}", checks.to_vec());
    assert_eq!(checks.status(21), Some(Status::Pass));
    assert_eq!(checks.status(22), Some(Status::Pass));
    let info = BuildInfo::from_json(
        &fs::read(final_dir.path().join("kz.zeta.market-1.0.0/BUILDINFO.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(info.package.sha256, oncl_pack::sha256_hex(&r.package));
    assert_eq!(
        info.source.archive.sha256,
        oncl_pack::sha256_hex(&r.archive)
    );
    assert_eq!(info.source.license.as_deref(), Some("MIT"));
    assert_eq!(info.builder.digest.as_deref(), Some(builder().as_str()));
    assert_eq!(info.builder.rust.as_deref(), Some("1.99.1"));
    let release = info.release.unwrap();
    assert_eq!(
        (release.publisher.as_str(), release.role_version),
        ("zeta", 1)
    );
    // The .src.diff of a first version lists every file as new.
    let first = diff::trees(None, &r.tree);
    assert!(
        first.contains("new file") && first.contains("+++ b/src/crates/p/plugin.toml"),
        "{first}"
    );
    // The whole verdict in one job: check-pr again over the handed-over archive, the rebuild
    // report, 21 and 22.
    let whole = |rebuilt: &Path| {
        pr::whole_verdict(
            &pr::WholeOptions {
                repo: &r.w.p(""),
                base: "main",
                head: "pr",
                author: "zeta-release",
                now: t_check(),
                layout: LAYOUT,
                builtin_modules: Some(Vec::new()),
            },
            &VerdictInputs {
                archives: out.path(),
                rebuilt,
                provenance: None,
            },
            final_dir.path(),
        )
        .unwrap()
    };
    let verdict = whole(rebuilt.path());
    assert!(verdict.ok, "{:#?}", verdict.checks);
    // A rebuild whose licences failed (check 20) fails the whole verdict, the package there
    // or not.
    let refused = tempfile::tempdir().unwrap();
    rebuilt_into(&refused.path().join("rebuild-0"), &r.package, &[20]);
    let verdict = whole(refused.path());
    assert_eq!(failed(&verdict), [20], "{:#?}", verdict.checks);
    assert!(!verdict.ok);
    // A tampered rebuild is check 21.
    fs::write(
        matrix.join("kz.zeta.market-1.0.0.onclp"),
        package(&manifest("keys = false")),
    )
    .unwrap();
    let checks = pr::verdict_job(
        &loaded,
        &VerdictInputs {
            archives: out.path(),
            rebuilt: rebuilt.path(),
            provenance: None,
        },
        final_dir.path(),
    )
    .unwrap();
    assert_eq!(
        checks.failures().iter().map(|c| c.0).collect::<Vec<_>>(),
        [21, 22]
    );
}

#[test]
fn a_head_whose_merge_is_not_its_diff_fails_check_1() {
    if !has_git() {
        return;
    }
    let r = released();
    let root = r.w.p("");
    let at = t_check() - Duration::minutes(30);
    // main moves on after a fork point F: an owner's change P.
    git_at(&root, &["checkout", "-q", "-b", "side", "main"], None);
    fs::write(root.join("side.txt"), "side\n").unwrap();
    git_at(&root, &["add", "-A"], None);
    git_at(&root, &["commit", "-q", "-m", "side"], Some(at));
    git_at(&root, &["checkout", "-q", "main"], None);
    fs::write(root.join("owner.txt"), "the owner's change\n").unwrap();
    git_at(&root, &["add", "-A"], None);
    git_at(&root, &["commit", "-q", "-m", "owner"], Some(at));
    git_at(
        &root,
        &["merge", "-q", "--no-ff", "-m", "merge side", "side"],
        Some(at),
    );
    // A head with two parents, the merge's own, whose tree lacks the owner's change: its
    // diff from `git merge-base` is the role file alone, but the squash would revert.
    let parents: Vec<String> = git_at(&root, &["rev-parse", "main^1", "main^2"], None)
        .lines()
        .map(str::to_owned)
        .collect();
    git_at(&root, &["checkout", "-q", "-B", "crafted", "side"], None);
    fs::create_dir_all(root.join("repo/metadata")).unwrap();
    fs::write(root.join(role_path(1)), &r.role).unwrap();
    git_at(&root, &["add", "-A"], None);
    let tree = git_at(&root, &["write-tree"], None);
    let commit = git_at(
        &root,
        &[
            "commit-tree",
            &tree,
            "-p",
            &parents[0],
            "-p",
            &parents[1],
            "-m",
            "crafted",
        ],
        Some(at),
    );
    git_at(&root, &["checkout", "-q", "main"], None);
    let verdict = check(
        &r,
        "main",
        &commit,
        "zeta-release",
        &table(&[(FETCH, &r.archive)]),
        t_check(),
    );
    assert_eq!(failed(&verdict), [1], "{:#?}", verdict.checks);
    // Rebased onto main, the same file passes check 1.
    branch(
        &r.w,
        "rebased",
        "main",
        &[(role_path(1), r.role.clone())],
        t_check() - Duration::minutes(5),
    );
    let verdict = check(
        &r,
        "main",
        "rebased",
        "zeta-release",
        &table(&[(FETCH, &r.archive)]),
        t_check(),
    );
    assert!(verdict.ok, "{:#?}", verdict.checks);
}

#[test]
fn tampered_pull_requests_fail_with_the_check_that_names_the_tampering() {
    if !has_git() {
        return;
    }
    let r = released();
    let w = &r.w;
    let now = t_check();
    let at = now - Duration::minutes(5);
    let good = || table(&[(FETCH, &r.archive)]);
    let expect = |name: &str,
                  base: &str,
                  author: &str,
                  fetcher: &Table,
                  now: OffsetDateTime,
                  wanted: &[u8]| {
        let verdict = check(&r, base, name, author, fetcher, now);
        assert_eq!(failed(&verdict), wanted, "{name}: {:#?}", verdict.checks);
        assert!(!verdict.ok, "{name}");
    };

    // 1: another file with the role file.
    branch(
        w,
        "extra-file",
        "main",
        &[
            (role_path(1), r.role.clone()),
            (
                "publishers/zeta/publisher.toml".into(),
                b"name = \"zeta\"\n".to_vec(),
            ),
        ],
        at,
    );
    expect("extra-file", "main", "zeta-release", &good(), now, &[1]);
    // 2: an author not in github.
    branch(w, "pr", "main", &[(role_path(1), r.role.clone())], at);
    expect("pr", "main", "mallory", &good(), now, &[2]);
    // 3: a jump of the version.
    let v2 = role(&one(r.target.clone()), 2, 90, &r.key);
    branch(w, "jump", "main", &[(role_path(2), v2)], at);
    // `tuf check` of main with the file refuses the gap in the role's versions too.
    expect("jump", "main", "zeta-release", &good(), now, &[3, 11]);
    // 4: signed by a key the delegation does not name.
    let stranger = SigningKey::from_seed(&[99; 32]).unwrap();
    branch(
        w,
        "stranger",
        "main",
        &[(role_path(1), role(&one(r.target.clone()), 1, 90, &stranger))],
        at,
    );
    // ...and so does the client's own verification of the role inside `tuf check`.
    expect("stranger", "main", "zeta-release", &good(), now, &[4, 11]);
    // 5: valid for 200 days, past any revocation's reach.
    branch(
        w,
        "long",
        "main",
        &[(role_path(1), role(&one(r.target.clone()), 1, 200, &r.key))],
        at,
    );
    expect("long", "main", "zeta-release", &good(), now, &[5]);
    // 6: a module the publisher was not approved for.
    let mut foreign = r.target.clone();
    foreign["custom"]["oncl"]["modules"] = json!(["kz.ecc.Signer"]);
    branch(
        w,
        "module",
        "main",
        &[(role_path(1), role(&one(foreign), 1, 90, &r.key))],
        at,
    );
    expect("module", "main", "zeta-release", &good(), now, &[6]);
    // 23: a url that is not the copy.
    let mut url = r.target.clone();
    url["custom"]["oncl"]["url"] =
        json!("https://downloads.zeta.example/kz.zeta.market-1.0.0.onclp");
    branch(
        w,
        "url",
        "main",
        &[(role_path(1), role(&one(url), 1, 90, &r.key))],
        at,
    );
    expect("url", "main", "zeta-release", &good(), now, &[23]);
    // 12: a builder the owner did not list.
    let mut unlisted = r.target.clone();
    unlisted["custom"]["oncl"]["source"]["builder"] = json!(format!("sha256:{}", "e".repeat(64)));
    branch(
        w,
        "builder",
        "main",
        &[(role_path(1), role(&one(unlisted), 1, 90, &r.key))],
        at,
    );
    expect("builder", "main", "zeta-release", &good(), now, &[12]);

    // 13: the archive at `fetch` is not the signed one, or is not there.
    let mut other = r.archive.clone();
    other[20] ^= 1;
    expect(
        "pr",
        "main",
        "zeta-release",
        &table(&[(FETCH, &other)]),
        now,
        &[13],
    );
    expect("pr", "main", "zeta-release", &table(&[]), now, &[13]);

    // 14–18: archives that hash as signed but break a rule of their contents.
    let variants: Vec<(&str, Vec<u8>, u8)> = vec![
        ("non-canonical", {
            use std::io::{Read as _, Write as _};
            let mut tar = Vec::new();
            flate2::read::GzDecoder::new(r.archive.as_slice())
                .read_to_end(&mut tar)
                .unwrap();
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gz.write_all(&tar).unwrap();
            gz.finish().unwrap()
        }, 14),
        (
            "licence",
            sources(&manifest("keys = true"), &[("crates/p/Cargo.toml", b"[package]\nname = \"p\"\nlicense = \"Apache-2.0\"\n")])
                .to_archive()
                .unwrap(),
            15,
        ),
        (
            "cargo-config",
            sources(&manifest("keys = true"), &[(".cargo/config.toml", b"[source.crates-io]\nreplace-with = \"mine\"\n")])
                .to_archive()
                .unwrap(),
            16,
        ),
        (
            "git-source",
            sources(
                &manifest("keys = true"),
                &[(
                    "Cargo.lock",
                    b"version = 4\n[[package]]\nname = \"evil\"\nversion = \"1.0.0\"\n\
                      source = \"git+https://github.com/evil/evil#0123456789abcdef0123456789abcdef01234567\"\n",
                )],
            )
            .to_archive()
            .unwrap(),
            17,
        ),
        (
            "wasm",
            sources(&manifest("keys = true"), &[("prebuilt/plugin.wasm", b"\0asm\x01\0\0\0")])
                .to_archive()
                .unwrap(),
            18,
        ),
    ];
    for (name, archive, wanted) in variants {
        let fetch = format!("https://downloads.zeta.example/{name}.src.tar.gz");
        // The publisher signs what it hands over, so check 13 holds.
        let mut t = r.target.clone();
        t["custom"]["oncl"]["source"]["archive_sha256"] = json!(oncl_pack::sha256_hex(&archive));
        t["custom"]["oncl"]["source"]["archive_length"] = json!(archive.len());
        t["custom"]["oncl"]["source"]["fetch"] = json!(fetch);
        branch(
            w,
            name,
            "main",
            &[(role_path(1), role(&one(t), 1, 90, &r.key))],
            at,
        );
        expect(
            name,
            "main",
            "zeta-release",
            &table(&[(&fetch, &archive)]),
            now,
            &[wanted],
        );
    }

    // 11: `tuf check` of main with the file fails when main's registry and its signed
    // targets disagree (an edit of publishers/ without `tuf update`).
    let edited = fs::read_to_string(w.publishers().join("zeta/publisher.toml"))
        .unwrap()
        .replace("en = \"Zeta\"", "en = \"Zeta Ltd\"");
    branch(
        w,
        "main-edited",
        "main",
        &[("publishers/zeta/publisher.toml".into(), edited.into_bytes())],
        t_base(),
    );
    branch(
        w,
        "on-edited",
        "main-edited",
        &[(role_path(1), r.role.clone())],
        at,
    );
    expect(
        "on-edited",
        "main-edited",
        "zeta-release",
        &good(),
        now,
        &[11],
    );

    // 9: one release an hour. The first is merged at `merged`; the next comes 59 minutes
    // later (refused) or 61 (taken).
    let merged = now;
    git_at(&w.p(""), &["merge", "-q", "--ff-only", "pr"], None);
    let _ = merged;
    let pkg2 = package(&manifest("keys = true").replace("1.0.0", "1.0.1"));
    let tree2 = sources(&manifest("keys = true").replace("1.0.0", "1.0.1"), &[]);
    let archive2 = tree2.to_archive().unwrap();
    let fetch2 = "https://downloads.zeta.example/kz.zeta.market-1.0.1.src.tar.gz";
    let t2 = target(w, &archive2, &pkg2, &tree2, fetch2, None);
    let mut v2 = one(r.target.clone());
    v2.insert("plugins/zeta/kz.zeta.market/1.0.1.onclp".into(), t2);
    let second = role(&v2, 2, 90, &r.key);
    branch(w, "second", "main", &[(role_path(2), second)], at);
    let fetcher2 = table(&[(fetch2, &archive2)]);
    let pr_time = OffsetDateTime::from_unix_timestamp(
        git_at(&w.p(""), &["log", "-1", "--format=%ct", "main"], None)
            .parse()
            .unwrap(),
    )
    .unwrap();
    expect(
        "second",
        "main",
        "zeta-release",
        &fetcher2,
        pr_time + Duration::minutes(59),
        &[9],
    );
    let taken = check(
        &r,
        "main",
        "second",
        "zeta-release",
        &fetcher2,
        pr_time + Duration::minutes(61),
    );
    assert!(taken.ok, "{:#?}", taken.checks);
    let [new] = taken.new_targets.as_slice() else {
        panic!("{:?}", taken.new_targets);
    };
    // The second version's .src.diff starts from the first's archive in the Releases.
    let previous = new.previous.as_ref().unwrap();
    assert_eq!(previous.version, "1.0.0");
    assert!(
        previous
            .archive_url
            .ends_with("/kz.zeta.market-1.0.0.src.tar.gz"),
        "{}",
        previous.archive_url
    );
    let between = diff::trees(Some(&r.tree), &tree2);
    assert!(
        between.contains("-version = \"1.0.0\"\n+version = \"1.0.1\""),
        "{between}"
    );

    // 8 and 24: a later version changes what was released.
    let mut moved = r.target.clone();
    moved["length"] = json!(r.package.len() + 1);
    branch(
        w,
        "length",
        "main",
        &[(role_path(2), role(&one(moved), 2, 90, &r.key))],
        at,
    );
    expect(
        "length",
        "main",
        "zeta-release",
        &good(),
        pr_time + Duration::hours(2),
        &[8],
    );
    let mut resourced = r.target.clone();
    resourced["custom"]["oncl"]["source"]["fetch"] =
        json!("https://elsewhere.zeta.example/a.src.tar.gz");
    branch(
        w,
        "source",
        "main",
        &[(role_path(2), role(&one(resourced), 2, 90, &r.key))],
        at,
    );
    expect(
        "source",
        "main",
        "zeta-release",
        &good(),
        pr_time + Duration::hours(2),
        &[24],
    );
    // Removing the only version, revoked or not, is check 8.
    branch(
        w,
        "gone",
        "main",
        &[(role_path(2), role(&Map::new(), 2, 90, &r.key))],
        at,
    );
    expect(
        "gone",
        "main",
        "zeta-release",
        &good(),
        pr_time + Duration::hours(2),
        &[8],
    );
}

#[test]
fn the_verdict_job_holds_the_capabilities_and_the_named_revision_to_the_release() {
    if !has_git() {
        return;
    }
    let r = released();
    let w = &r.w;
    let at = t_check() - Duration::minutes(5);
    // 22: the package asks for more than the entry says (the publisher edited the entry).
    let wide = manifest("keys = true\ndialogs = true");
    let tree = sources(&wide, &[]);
    let archive = tree.to_archive().unwrap();
    let pkg = package(&wide);
    let mut narrow = target(w, &archive, &pkg, &tree, FETCH, None);
    narrow["custom"]["oncl"]["capabilities"] = json!({"keys": true});
    branch(
        w,
        "caps",
        "main",
        &[(role_path(1), role(&one(narrow), 1, 90, &r.key))],
        at,
    );
    let dirs = tempfile::tempdir().unwrap();
    let archives = dirs.path().join("archives");
    let rebuilt = dirs.path().join("rebuilt");
    fs::create_dir_all(&archives).unwrap();
    fs::create_dir_all(&rebuilt).unwrap();
    fs::write(archives.join("kz.zeta.market-1.0.0.src.tar.gz"), &archive).unwrap();
    rebuilt_into(&rebuilt, &pkg, &[]);
    let loaded = pr::load_pr(&w.p(""), "main", "caps", &LAYOUT, t_check()).unwrap();
    let inputs = VerdictInputs {
        archives: &archives,
        rebuilt: &rebuilt,
        provenance: None,
    };
    let checks = pr::verdict_job(&loaded, &inputs, &dirs.path().join("out")).unwrap();
    assert_eq!(
        checks.failures().iter().map(|c| c.0).collect::<Vec<_>>(),
        [22]
    );

    // 25: the revision the publisher names gives another archive.
    let rev = "1".repeat(40);
    let named = target(
        w,
        &r.archive,
        &r.package,
        &r.tree,
        FETCH,
        Some(("https://git.zeta.example/market.git", &rev)),
    );
    branch(
        w,
        "vcs",
        "main",
        &[(role_path(1), role(&one(named), 1, 90, &r.key))],
        at,
    );
    fs::write(archives.join("kz.zeta.market-1.0.0.src.tar.gz"), &r.archive).unwrap();
    rebuilt_into(&rebuilt, &r.package, &[]);
    let loaded = pr::load_pr(&w.p(""), "main", "vcs", &LAYOUT, t_check()).unwrap();
    let report = |found: Provenance| ProvenanceReport {
        schema: 1,
        targets: [(PATH.to_owned(), found)].into_iter().collect(),
    };
    for (found, wanted, word) in [
        (Provenance::Confirmed, vec![], "confirmed"),
        (
            Provenance::Unverified("no host".into()),
            vec![],
            "unverified",
        ),
        (Provenance::Mismatch("ab".into()), vec![25], "mismatch"),
    ] {
        let report = report(found);
        let out = dirs.path().join(format!("out-{word}"));
        let checks = pr::verdict_job(
            &loaded,
            &VerdictInputs {
                archives: &archives,
                rebuilt: &rebuilt,
                provenance: Some(&report),
            },
            &out,
        )
        .unwrap();
        assert_eq!(
            checks.failures().iter().map(|c| c.0).collect::<Vec<_>>(),
            wanted,
            "{word}"
        );
        let info = BuildInfo::from_json(
            &fs::read(out.join("kz.zeta.market-1.0.0/BUILDINFO.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(info.vcs.unwrap().result, word);
    }
    // What check 25 compares: a git revision of the same files gives the same archive.
    let repo = tempfile::tempdir().unwrap();
    r.tree.unpack(&repo.path().join("src")).unwrap();
    let src = repo.path().join("src");
    git_at(&src, &["init", "-q"], None);
    git_at(&src, &["add", "-A"], None);
    git_at(&src, &["commit", "-q", "-m", "v1.0.0"], Some(t_base()));
    let head = git_at(&src, &["rev-parse", "HEAD"], None);
    let from_git = Tree::from_git(&src, &head).unwrap();
    assert_eq!(
        xtask::vendor::provenance::compare(&from_git, &r.archive),
        Provenance::Confirmed
    );
    fs::write(src.join("build.rs"), "fn main() {}\n").unwrap();
    git_at(&src, &["add", "-A"], None);
    git_at(&src, &["commit", "-q", "-m", "more"], Some(t_base()));
    let more = Tree::from_git(&src, "HEAD").unwrap();
    assert_eq!(
        xtask::vendor::provenance::compare(&more, &r.archive).word(),
        "mismatch"
    );
    let _ = r.keys;
}

#[test]
fn check_onboarding_keeps_builders_and_entries_against_the_base() {
    if !has_git() {
        return;
    }
    let r = released();
    let root = r.w.p("");
    onboard::check_onboarding(&root, &LAYOUT, Some("main")).unwrap();
    // A builder entry changed.
    let builders = r.w.publishers().join("builders.toml");
    let text = fs::read_to_string(&builders).unwrap();
    fs::write(&builders, text.replace("1.99.1", "1.99.2")).unwrap();
    let err = onboard::check_onboarding(&root, &LAYOUT, Some("main")).unwrap_err();
    assert!(
        format!("{err:#}").contains("changed, moved or removed"),
        "{err:#}"
    );
    fs::write(&builders, text).unwrap();
    // A publisher renamed its prefix.
    let file = r.w.publishers().join("zeta/publisher.toml");
    let toml = fs::read_to_string(&file).unwrap();
    fs::write(&file, toml.replace("kz.zeta.", "kz.zeta2.")).unwrap();
    let err = onboard::check_onboarding(&root, &LAYOUT, Some("main")).unwrap_err();
    assert!(format!("{err:#}").contains("Р28"), "{err:#}");
}

#[test]
fn tuf_check_warns_of_a_newest_role_that_breaks_todays_rules() {
    // `ecc`'s role in this world has entries without `custom.oncl`: accepted once, they break
    // today's rules, and a rule applies to new versions only.
    let w = online_world();
    let report = w.tree(t1());
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let warned: Vec<&String> = report
        .warnings
        .iter()
        .filter(|p| p.code == "publisher-rules")
        .map(|p| &p.message)
        .collect();
    assert!(
        warned.iter().any(|m| m.starts_with("pub-ecc 1: check 6:")),
        "{warned:?}"
    );
}
