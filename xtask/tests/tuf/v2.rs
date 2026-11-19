//! `tuf/v2` (`docs/design/publishers.md`): `init --repo v2`, `update` of both repositories
//! from `publishers/`, `snapshot`, `timestamp --repo v2`, `check` and `verify-published`
//! with delegations, and `root --repo v2`, on repositories made with synthetic keys in
//! temporary directories, and the real client of `tuf/v2` over the results.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use oncl_update::tuf::{
    Delegated, Limits, MemoryStore, Profile, Role, RoleName, SigningKey, TufClient, build,
};
use time::{Duration, OffsetDateTime};
use xtask::tuf::check::{self, Expiry, TimestampMode};
use xtask::tuf::check_v2::{self, Report, Stage};
use xtask::tuf::published::{self, Published};
use xtask::tuf::repo::DirFetcher;
use xtask::tuf::timestamp::{self, KeySource};
use xtask::tuf::{PassphraseSource, init, keystore, root, snapshot, update};

use super::{copy_dir, files, git, index, t0, template};

/// The key of the synthetic publisher `n`.
fn publisher_key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[40 + n; 32]).unwrap()
}

fn publisher_toml(name: &str, n: u8, extra: &str) -> String {
    format!(
        "name = \"{name}\"\n\
         display = {{ ru = \"{name} ру\", kk = \"{name} қа\", en = \"{name} en\" }}\n\
         id_prefix = \"kz.{name}.\"\n\
         modules = [\"kz.{name}.Signer\"]\n\
         bundles = [\"kz.{name}.bundle\"]\n\
         github = [\"{name}-release\"]\n\
         homepage = \"https://{name}.example/\"\n\
         {extra}\
         [[keys]]\n\
         public = \"{}\"\n",
        publisher_key(n).public().to_hex()
    )
}

/// One `tuf/v1` world (the template of `tuf.rs`) with `tuf/v2` beside it: two active
/// publishers, `ecc` with one release and `acme` without any.
static V2_TEMPLATE: LazyLock<PathBuf> = LazyLock::new(|| {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("tuf-v2-world-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    copy_dir(template(), &dir);
    let w = V2World {
        dir: Dir::Kept(dir.clone()),
    };
    w.write_publisher("ecc", 0, "");
    w.write_publisher("acme", 1, "");
    init::init_v2(&init::V2Options {
        keys: &w.keys(),
        out: &w.v2(),
        v1: &w.v1(),
        anchor: None,
        now: t0(),
        passphrase: &w.pass(),
    })
    .unwrap();
    let both = w.update(t0(), false).unwrap();
    assert!(matches!(both.v1, update::Outcome::UpToDate { .. }));
    assert!(matches!(both.v2, Some(update::V2Outcome::Written(_))));
    w.release("ecc", 0, 1, &[("kz.ecc.market", "1.0.0")]);
    dir
});

enum Dir {
    Temp(tempfile::TempDir),
    Kept(PathBuf),
}

/// A scratch directory: `keys`, `repo` (`tuf/v1`), `v2` (`tuf/v2`), `anchor`, `indexes`,
/// `publishers` and the passphrase file.
struct V2World {
    dir: Dir,
}

fn v2_world() -> V2World {
    let dir = tempfile::tempdir().unwrap();
    copy_dir(&V2_TEMPLATE, dir.path());
    V2World {
        dir: Dir::Temp(dir),
    }
}

impl V2World {
    fn p(&self, rel: &str) -> PathBuf {
        match &self.dir {
            Dir::Temp(t) => t.path().join(rel),
            Dir::Kept(p) => p.join(rel),
        }
    }
    fn root_dir(&self) -> PathBuf {
        self.p("")
    }
    fn keys(&self) -> PathBuf {
        self.p("keys")
    }
    fn v1(&self) -> PathBuf {
        self.p("repo")
    }
    fn v2(&self) -> PathBuf {
        self.p("v2")
    }
    fn anchor(&self) -> PathBuf {
        self.p("anchor/root.json")
    }
    fn v2_anchor(&self) -> PathBuf {
        self.v2().join("metadata/1.root.json")
    }
    fn indexes(&self) -> PathBuf {
        self.p("indexes")
    }
    fn publishers(&self) -> PathBuf {
        self.p("publishers")
    }
    fn pass(&self) -> PassphraseSource {
        PassphraseSource::File(self.p("pass.txt"))
    }

    fn write_publisher(&self, name: &str, n: u8, extra: &str) {
        let dir = self.publishers().join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("publisher.toml"), publisher_toml(name, n, extra)).unwrap();
    }

    /// Version `version` of the role of `name`, signed by the key of publisher `n`, listing a
    /// package for each `(id, version)`.
    fn release(&self, name: &str, n: u8, version: u64, plugins: &[(&str, &str)]) -> PathBuf {
        let packages: Vec<(String, Vec<u8>)> = plugins
            .iter()
            .map(|(id, v)| {
                (
                    format!("plugins/{name}/{id}/{v}.onclp"),
                    format!("{id} {v}").into_bytes(),
                )
            })
            .collect();
        let refs: Vec<(&str, &[u8])> = packages
            .iter()
            .map(|(p, b)| (p.as_str(), b.as_slice()))
            .collect();
        let signed = build::targets(version, t0() + Duration::days(90), &refs).unwrap();
        let file = build::sign(&signed, &[&publisher_key(n)]).unwrap();
        let path = self
            .v2()
            .join(format!("metadata/{version}.pub-{name}.json"));
        fs::write(&path, file).unwrap();
        path
    }

    fn update(&self, now: OffsetDateTime, refresh: bool) -> anyhow::Result<update::Both> {
        update::update_both(&update::BothOptions {
            keys: &self.keys(),
            index: &self.indexes(),
            v1: &self.v1(),
            v2: &self.v2(),
            publishers: &self.publishers(),
            refresh,
            now,
            passphrase: &self.pass(),
        })
    }

    fn check(&self, dir: &Path, stage: Stage, now: OffsetDateTime, base: Option<&str>) -> Report {
        match check_v2::check(&check_v2::Options {
            dir,
            index: Some(&self.indexes()),
            publishers: Some(&self.publishers()),
            anchor: Some(&self.v2_anchor()),
            now,
            stage,
            expiry: Expiry {
                min_days: 10,
                min_root_days: 45,
                fail: false,
            },
            base,
        })
        .unwrap()
        {
            check_v2::Outcome::Checked(report) => *report,
            check_v2::Outcome::NoRepository => panic!("no repository"),
        }
    }

    fn tree(&self, now: OffsetDateTime) -> Report {
        self.check(&self.v2(), Stage::Tree, now, None)
    }

    /// A copy of `tuf/v2` for publication.
    fn copy(&self, name: &str) -> PathBuf {
        let out = self.p(name);
        copy_dir(&self.v2(), &out);
        out
    }

    /// The snapshot of `out`, extending the published copy `previous`, or the first
    /// publication.
    fn snapshot(
        &self,
        out: &Path,
        now: OffsetDateTime,
        previous: Option<&Path>,
    ) -> anyhow::Result<snapshot::Signed> {
        self.snapshot_with(out, now, previous, "v2-snapshot.key")
    }

    fn snapshot_with(
        &self,
        out: &Path,
        now: OffsetDateTime,
        previous: Option<&Path>,
        key: &str,
    ) -> anyhow::Result<snapshot::Signed> {
        let fetcher = previous.map(DirFetcher::new);
        snapshot::snapshot(
            &snapshot::Options {
                out,
                anchor: &self.v2_anchor(),
                index: &self.indexes(),
                publishers: &self.publishers(),
                key: &KeySource::File(self.keys().join(key)),
                now,
            },
            match &fetcher {
                Some(f) => snapshot::Previous::Published(f),
                None => snapshot::Previous::FirstPublication,
            },
        )
    }

    fn timestamp(&self, out: &Path, now: OffsetDateTime) -> anyhow::Result<timestamp::Signed> {
        timestamp::timestamp_v2(&timestamp::V2Options {
            out,
            anchor: &self.v2_anchor(),
            index: &self.indexes(),
            publishers: &self.publishers(),
            key: &KeySource::File(self.keys().join("v2-timestamp.key")),
            now,
        })
    }

    /// A published copy: snapshot and timestamp signed at `now`, over `previous`.
    fn publish(&self, name: &str, now: OffsetDateTime, previous: Option<&Path>) -> PathBuf {
        let out = self.copy(name);
        self.snapshot(&out, now, previous).unwrap();
        self.timestamp(&out, now).unwrap();
        out
    }
}

fn codes(report: &Report) -> Vec<&'static str> {
    report.problems.iter().map(|p| p.code).collect()
}

/// The client of `tuf/v2` over `dir`: refresh, then every delegated role.
fn delegated(w: &V2World, dir: &Path, now: OffsetDateTime) -> Delegated {
    let anchor = fs::read(w.v2_anchor()).unwrap();
    let mut client = TufClient::new(
        &anchor,
        DirFetcher::new(dir),
        MemoryStore::default(),
        Limits::default(),
    )
    .unwrap()
    .with_profile(Profile::Delegating);
    let trusted = client.refresh(now).unwrap();
    client.delegated(&trusted, now).unwrap()
}

fn role(name: &str) -> RoleName {
    RoleName::parse(name).unwrap()
}

#[test]
fn v2_is_made_beside_v1_and_published_end_to_end() {
    let w = v2_world();
    // tuf/v1 is exactly the world without tuf/v2: not one byte differs.
    for file in files(&template().join("repo")) {
        assert_eq!(
            fs::read(template().join("repo").join(&file)).unwrap(),
            fs::read(w.v1().join(&file)).unwrap(),
            "{file}"
        );
    }
    assert_eq!(files(&template().join("repo")), files(&w.v1()));
    let tree = files(&w.v2());
    assert!(
        tree.contains(&"metadata/1.root.json".to_owned()),
        "{tree:?}"
    );
    assert!(
        tree.contains(&"metadata/1.targets.json".to_owned()),
        "{tree:?}"
    );
    assert!(
        tree.contains(&"metadata/1.pub-ecc.json".to_owned()),
        "{tree:?}"
    );
    assert!(
        tree.iter()
            .any(|f| f.starts_with("targets/") && f.ends_with(".publishers.json")),
        "{tree:?}"
    );
    assert!(!tree.iter().any(|f| f.contains("snapshot")), "{tree:?}");
    for key in ["v2-root.key", "v2-snapshot.key", "v2-timestamp.key"] {
        assert!(w.keys().join(key).is_file(), "{key}");
    }
    let report = w.tree(t0());
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert!(
        report
            .notes
            .contains(&"root 1, targets 1, snapshot absent, timestamp absent".to_owned()),
        "{:?}",
        report.notes
    );

    // Pages: the snapshot, then the timestamp, in a copy.
    let now = t0() + Duration::hours(1);
    let site = w.copy("site");
    let signed = w.snapshot(&site, now, None).unwrap();
    assert_eq!(signed.version, now.unix_timestamp() as u64);
    assert_eq!((signed.targets, signed.roles), (1, 1));
    assert!(signed.previous.is_none());
    w.timestamp(&site, now).unwrap();
    let report = w.check(&site, Stage::Published, now, None);
    assert!(report.problems.is_empty(), "{:?}", report.problems);

    // The client of tuf/v2 trusts both roles: ecc with its release, acme without any.
    let roles = delegated(&w, &site, now);
    let ecc = roles.role(&role("pub-ecc")).unwrap().unwrap();
    assert_eq!(ecc.version(), 1);
    assert!(
        ecc.target("plugins/ecc/kz.ecc.market/1.0.0.onclp")
            .is_some()
    );
    assert!(matches!(
        roles.role(&role("pub-acme")),
        Some(Err(oncl_update::tuf::TufError::Delegation { .. }))
    ));

    // And so does the smoke check after a deployment.
    let anchor = fs::read(w.v2_anchor()).unwrap();
    let Published::Verified { lines } =
        published::verify_published_v2(DirFetcher::new(&site), &anchor, now, false).unwrap()
    else {
        panic!("published");
    };
    assert!(
        lines.iter().any(|l| l.starts_with("pub-ecc 1: 1 targets")),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"pub-acme: no release yet".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("publishers.json") && l.contains("2 active")),
        "{lines:?}"
    );
    // The client of tuf/v1 is not concerned: its repository still verifies as before.
    let v1 = check::check(&check::Options {
        dir: &w.v1(),
        index: Some(&w.indexes()),
        anchor: Some(&w.anchor()),
        now,
        timestamp: TimestampMode::Absent,
        expiry: Expiry {
            min_days: 0,
            min_root_days: 0,
            fail: false,
        },
        base: None,
    })
    .unwrap();
    let check::Outcome::Checked(v1) = v1 else {
        panic!("tuf/v1");
    };
    assert!(v1.problems.is_empty(), "{:?}", v1.problems);
    let (problems, warnings) = check_v2::cross(
        v1.verified.as_ref().unwrap(),
        &check::committed_chain(&w.v1()).unwrap(),
        report.verified.as_ref().unwrap(),
    );
    assert!(
        problems.is_empty() && warnings.is_empty(),
        "{problems:?} {warnings:?}"
    );
}

#[test]
fn the_v1_client_never_sees_the_v2_files() {
    let w = v2_world();
    // tuf/v2 files dropped into tuf/v1 are strays there, and its legacy client refuses
    // targets with delegations.
    fs::copy(
        w.v2().join("metadata/1.pub-ecc.json"),
        w.v1().join("metadata/1.pub-ecc.json"),
    )
    .unwrap();
    let report = check::check(&check::Options {
        dir: &w.v1(),
        index: Some(&w.indexes()),
        anchor: Some(&w.anchor()),
        now: t0(),
        timestamp: TimestampMode::Absent,
        expiry: Expiry {
            min_days: 0,
            min_root_days: 0,
            fail: false,
        },
        base: None,
    })
    .unwrap();
    let check::Outcome::Checked(report) = report else {
        panic!("tuf/v1");
    };
    assert_eq!(
        report.problems.iter().map(|p| p.code).collect::<Vec<_>>(),
        ["stray-file"]
    );
}

#[test]
fn update_follows_the_registry_of_the_publishers() {
    let w = v2_world();
    let later = t0() + Duration::days(1);
    let both = w.update(later, false).unwrap();
    assert!(matches!(both.v1, update::Outcome::UpToDate { .. }));
    assert!(matches!(
        both.v2,
        Some(update::V2Outcome::UpToDate { targets: 1 })
    ));

    // The owner revokes a version: publishers.json changes, the delegations do not.
    w.write_publisher(
        "ecc",
        0,
        "[[revoked_versions]]\nid = \"kz.ecc.market\"\nversion = \"1.0.0\"\ndate = \"2027-02-10\"\n",
    );
    assert!(codes(&w.tree(later)).contains(&"publishers-mismatch"));
    let Some(update::V2Outcome::Written(written)) = w.update(later, false).unwrap().v2 else {
        panic!("a revoked version writes");
    };
    assert_eq!((written.targets, written.delegated), (2, 2));
    assert!(
        written.reason.contains("publishers.json"),
        "{}",
        written.reason
    );
    let report = w.tree(later);
    assert!(report.problems.is_empty(), "{:?}", report.problems);

    // The owner revokes a publisher: its delegation goes, its entry and its role file stay.
    w.write_publisher("ecc", 0, "state = \"revoked\"\nrevoked = \"2027-03-01\"\n");
    assert!(codes(&w.tree(later)).contains(&"delegations-mismatch"));
    let Some(update::V2Outcome::Written(written)) = w.update(later, false).unwrap().v2 else {
        panic!("a revoked publisher writes");
    };
    assert_eq!((written.targets, written.delegated), (3, 1));
    assert!(written.reason.contains("delegations"), "{}", written.reason);
    let report = w.tree(later);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let roles = &report.verified.as_ref().unwrap().roles;
    assert!(!roles[&role("pub-ecc")].delegated);

    // The revoked publisher's role stays in every snapshot, so no client takes the
    // snapshot for a rollback.
    let now = later + Duration::hours(1);
    let site = w.publish("site", now, None);
    let report = w.check(&site, Stage::Published, now, None);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let snapshot = report.verified.unwrap().snapshot.unwrap();
    assert_eq!(snapshot.meta["pub-ecc.json"].version, 1);
    let roles = delegated(&w, &site, now);
    assert!(
        roles.role(&role("pub-ecc")).is_none(),
        "not delegated any more"
    );
}

#[test]
fn a_registry_that_breaks_a_rule_writes_nothing_in_either_repository() {
    let w = v2_world();
    let v1_before = files(&w.v1());
    let v2_before = files(&w.v2());
    // tuf/v1 has something to do, tuf/v2 refuses: two publishers with one prefix.
    fs::write(w.indexes().join("stable.json"), index("stable", 2)).unwrap();
    let dir = w.publishers().join("other");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("publisher.toml"),
        publisher_toml("other", 2, "").replace("kz.other.", "kz.ecc.x."),
    )
    .unwrap();
    let err = w.update(t0() + Duration::days(1), false).unwrap_err();
    assert!(format!("{err:#}").contains("nested"), "{err:#}");
    assert!(
        format!("{err:#}").contains("nothing was written"),
        "tuf/v2's inputs are refused before tuf/v1 is touched: {err:#}"
    );
    assert_eq!(files(&w.v1()), v1_before);
    assert_eq!(files(&w.v2()), v2_before);

    // A key of a root is not a publisher's key.
    let root_key = fs::read_to_string(w.v2_anchor()).unwrap();
    let root: serde_json::Value = serde_json::from_str(&root_key).unwrap();
    let (_, key) = root["signed"]["keys"]
        .as_object()
        .unwrap()
        .iter()
        .next()
        .unwrap();
    let hex = key["keyval"]["public"].as_str().unwrap();
    fs::write(
        dir.join("publisher.toml"),
        publisher_toml("other", 2, "").replace(&publisher_key(2).public().to_hex(), hex),
    )
    .unwrap();
    let err = w.update(t0() + Duration::days(1), false).unwrap_err();
    assert!(format!("{err:#}").contains("is a key of"), "{err:#}");
    assert_eq!(files(&w.v1()), v1_before);
}

#[test]
fn a_new_snapshot_extends_the_published_one() {
    let w = v2_world();
    let now = t0() + Duration::hours(1);
    let first = w.publish("first", now, None);
    let first_version = now.unix_timestamp() as u64;

    // The publisher's next release, merged; Pages signs a snapshot over the published one,
    // at the same second: one version more, and the published one kept beside it.
    w.release(
        "ecc",
        0,
        2,
        &[("kz.ecc.market", "1.0.0"), ("kz.ecc.market", "1.1.0")],
    );
    let report = w.tree(now);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let second = w.copy("second");
    let signed = w.snapshot(&second, now, Some(&first)).unwrap();
    assert_eq!(signed.version, first_version + 1);
    assert_eq!(signed.previous.as_ref().map(|p| p.0), Some(first_version));
    w.timestamp(&second, now).unwrap();
    let report = w.check(&second, Stage::Published, now, None);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let roles = delegated(&w, &second, now);
    assert_eq!(roles.role(&role("pub-ecc")).unwrap().unwrap().version(), 2);

    // A tree that lost the role file would drop it from the snapshot: refused.
    let lost = w.copy("lost");
    fs::remove_file(lost.join("metadata/1.pub-ecc.json")).unwrap();
    fs::remove_file(lost.join("metadata/2.pub-ecc.json")).unwrap();
    let err = w.snapshot(&lost, now, Some(&second)).unwrap_err();
    assert!(format!("{err:#}").contains("snapshot-rollback"), "{err:#}");
    assert!(!files(&lost).iter().any(|f| f.contains("snapshot")));
}

#[test]
fn the_check_guards_the_online_snapshot() {
    let w = v2_world();
    let now = t0() + Duration::hours(1);
    let site = w.copy("site");
    // A snapshot that lists the targets but not the publisher's role, signed with the
    // right key: what CI must never publish.
    let key = xtask::tuf::keystore::parse_seed(
        &fs::read_to_string(w.keys().join("v2-snapshot.key")).unwrap(),
    )
    .unwrap();
    let targets = fs::read(site.join("metadata/1.targets.json")).unwrap();
    let signed = build::snapshot(9, now + Duration::days(7), 1, &targets).unwrap();
    fs::write(
        site.join("metadata/9.snapshot.json"),
        build::sign(&signed, &[&key]).unwrap(),
    )
    .unwrap();
    let found = codes(&w.check(&site, Stage::Snapshotted, now, None));
    assert!(found.contains(&"snapshot-role-missing"), "{found:?}");
    // A snapshot is never committed.
    let found = codes(&w.check(&site, Stage::Tree, now, None));
    assert!(found.contains(&"snapshot-committed"), "{found:?}");

    // An older snapshot beside a newer one that lowers a version: a rollback.
    let site = w.publish("published", now, None);
    let older: Vec<String> = files(&site)
        .into_iter()
        .filter(|f| f.ends_with(".snapshot.json"))
        .collect();
    assert_eq!(older.len(), 1);
    let bytes = fs::read(site.join(&older[0])).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["signed"]["version"] = (now.unix_timestamp() - 10).into();
    value["signed"]["meta"]["pub-ecc.json"]["version"] = 5.into();
    let older_path = site.join(format!(
        "metadata/{}.snapshot.json",
        now.unix_timestamp() - 10
    ));
    fs::write(&older_path, build::sign(&value["signed"], &[&key]).unwrap()).unwrap();
    let found = codes(&w.check(&site, Stage::Published, now, None));
    assert!(found.contains(&"snapshot-rollback"), "{found:?}");
}

#[test]
fn a_role_the_client_would_refuse_fails_the_check_and_the_snapshot() {
    let w = v2_world();
    // Signed by the other publisher's key.
    w.release("ecc", 1, 2, &[("kz.ecc.market", "1.1.0")]);
    let found = codes(&w.tree(t0()));
    assert!(found.contains(&"role"), "{found:?}");
    let site = w.copy("site");
    let err = w.snapshot(&site, t0(), None).unwrap_err();
    assert!(format!("{err:#}").contains("[role]"), "{err:#}");
    fs::remove_file(w.v2().join("metadata/2.pub-ecc.json")).unwrap();

    // A target outside the role's paths: under another publisher's.
    let path = w.v2().join("metadata/2.pub-ecc.json");
    let refs: Vec<(&str, &[u8])> = vec![("plugins/acme/kz.acme.x/1.0.0.onclp", b"x")];
    let signed = build::targets(2, t0() + Duration::days(90), &refs).unwrap();
    fs::write(&path, build::sign(&signed, &[&publisher_key(0)]).unwrap()).unwrap();
    let found = codes(&w.tree(t0()));
    assert!(found.contains(&"role"), "{found:?}");
    fs::remove_file(&path).unwrap();

    // A gap in the versions, and a role nobody delegated to.
    w.release("ecc", 0, 3, &[("kz.ecc.market", "1.1.0")]);
    w.release("zzz", 7, 1, &[]);
    let found = codes(&w.tree(t0()));
    assert!(found.contains(&"role-gap"), "{found:?}");
    assert!(found.contains(&"role-not-delegated"), "{found:?}");
}

#[test]
fn a_role_version_is_history_against_the_base() {
    if !super::has_git() {
        return;
    }
    let w = v2_world();
    git(&w.root_dir(), &["init", "-q"]);
    git(&w.root_dir(), &["add", "v2"]);
    git(&w.root_dir(), &["commit", "-q", "-m", "base"]);
    let base = Some("HEAD");
    let report = w.check(&w.v2(), Stage::Tree, t0(), base);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    // A publisher's release alone is a version bump.
    w.release("ecc", 0, 2, &[("kz.ecc.market", "1.1.0")]);
    let report = w.check(&w.v2(), Stage::Tree, t0(), base);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    // A role file gone is history rewritten.
    fs::remove_file(w.v2().join("metadata/2.pub-ecc.json")).unwrap();
    fs::remove_file(w.v2().join("metadata/1.pub-ecc.json")).unwrap();
    let found = codes(&w.check(&w.v2(), Stage::Tree, t0(), base));
    assert!(found.contains(&"file-removed"), "{found:?}");
    assert!(found.contains(&"version-rollback"), "{found:?}");
}

#[test]
fn both_repositories_must_list_the_same_indexes() {
    let w = v2_world();
    fs::write(w.indexes().join("stable.json"), index("stable", 2)).unwrap();
    let later = t0() + Duration::days(1);
    // Only tuf/v1 is updated.
    update::update(&update::Options {
        keys: &w.keys(),
        index: &w.indexes(),
        out: &w.v1(),
        refresh: false,
        now: later,
        passphrase: &w.pass(),
    })
    .unwrap();
    let v1 = match check::check(&check::Options {
        dir: &w.v1(),
        index: Some(&w.indexes()),
        anchor: Some(&w.anchor()),
        now: later,
        timestamp: TimestampMode::Absent,
        expiry: Expiry {
            min_days: 0,
            min_root_days: 0,
            fail: false,
        },
        base: None,
    })
    .unwrap()
    {
        check::Outcome::Checked(r) => r,
        check::Outcome::NoRepository => panic!("tuf/v1"),
    };
    let v2 = w.tree(later);
    assert!(codes(&v2).contains(&"index-mismatch"), "{:?}", v2.problems);
    let (problems, _) = check_v2::cross(
        v1.verified.as_ref().unwrap(),
        &check::committed_chain(&w.v1()).unwrap(),
        v2.verified.as_ref().unwrap(),
    );
    assert_eq!(
        problems.iter().map(|p| p.code).collect::<Vec<_>>(),
        ["index-diverged"]
    );
    // `tuf update` brings tuf/v2 along.
    let both = w.update(later, false).unwrap();
    assert!(matches!(both.v2, Some(update::V2Outcome::Written(_))));
    assert!(w.tree(later).problems.is_empty());
}

#[test]
fn the_v2_root_follows_the_targets_key_of_v1_and_rotates_online_keys() {
    let w = v2_world();
    let now = t0() + Duration::days(2);
    // A rotation of the snapshot key of tuf/v2 writes an online line.
    let rotated = root::root_v2(&root::V2Options {
        keys: &w.keys(),
        out: &w.v2(),
        v1: &w.v1(),
        rotate_root: false,
        rotate_snapshot: true,
        rotate_timestamp: false,
        now,
        passphrase: &w.pass(),
    })
    .unwrap();
    assert_eq!(rotated.version, 2);
    assert!(!rotated.targets_changed);
    let (role_name, _, path) = &rotated.new_keys[0];
    assert_eq!(*role_name, Role::Snapshot);
    assert!(path.ends_with("v2-snapshot.v2.key"));
    xtask::tuf::keystore::parse_seed(&fs::read_to_string(path).unwrap()).unwrap();
    assert!(w.tree(now).problems.is_empty());

    // The targets key is rotated in tuf/v1; tuf/v2's next root follows it, and `tuf
    // update` signs both repositories' targets with it.
    root::root(&root::Options {
        keys: &w.keys(),
        out: &w.v1(),
        rotate_root: false,
        rotate_targets: true,
        rotate_snapshot: false,
        rotate_timestamp: false,
        now,
        passphrase: &w.pass(),
    })
    .unwrap();
    let followed = root::root_v2(&root::V2Options {
        keys: &w.keys(),
        out: &w.v2(),
        v1: &w.v1(),
        rotate_root: false,
        rotate_snapshot: false,
        rotate_timestamp: false,
        now,
        passphrase: &w.pass(),
    })
    .unwrap();
    assert_eq!(followed.version, 3);
    assert!(followed.targets_changed);
    let both = w.update(now, false).unwrap();
    assert!(matches!(both.v1, update::Outcome::Written(_)));
    let Some(update::V2Outcome::Written(written)) = both.v2 else {
        panic!("tuf/v2 signs again after the rotation");
    };
    assert!(written.reason.contains("rotated"), "{}", written.reason);
    let site = w.copy("site");
    // The old snapshot key is not the one of the root in force any more.
    let err = w.snapshot(&site, now, None).unwrap_err();
    assert!(err.to_string().contains("is not a snapshot key"), "{err:#}");
    w.snapshot_with(&site, now, None, "v2-snapshot.v2.key")
        .unwrap();
    w.timestamp(&site, now).unwrap();
    let report = w.check(&site, Stage::Published, now, None);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
}

#[test]
fn the_check_command_checks_both_repositories() {
    let w = v2_world();
    let s = |p: PathBuf| p.to_string_lossy().into_owned();
    let run = |extra: &[&str]| {
        let mut args = vec![
            "check".to_owned(),
            "--dir".to_owned(),
            s(w.v1()),
            "--anchor".to_owned(),
            s(w.anchor()),
            "--index".to_owned(),
            s(w.indexes()),
            "--publishers".to_owned(),
            s(w.publishers()),
            "--no-timestamp".to_owned(),
            "--now".to_owned(),
            "1790000000".to_owned(),
        ];
        args.extend(extra.iter().map(|e| (*e).to_owned()));
        super::xtask(&args.iter().map(String::as_str).collect::<Vec<_>>())
    };
    // `tuf/v2` is beside `tuf/v1`: both are checked.
    let ok = run(&[]);
    let text = String::from_utf8_lossy(&ok.stdout);
    assert!(
        ok.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(
        text.contains("tuf check: root 1, targets 1, snapshot 1, timestamp absent"),
        "{text}"
    );
    assert!(
        text.contains("tuf check: tuf/v2: root 1, targets 1, snapshot absent, timestamp absent"),
        "{text}"
    );
    assert!(
        text.contains("tuf check: tuf/v2: pub-ecc 1, delegated"),
        "{text}"
    );
    assert!(text.trim_end().ends_with("tuf check: ok"), "{text}");
    // A registry that differs fails the v2 check only.
    w.write_publisher("acme", 1, "contact = \"security@acme.example\"\n");
    w.write_publisher(
        "ecc",
        0,
        "[[revoked_versions]]\nid = \"kz.ecc.market\"\nversion = \"1.0.0\"\ndate = \"2027-02-10\"\n",
    );
    let v1_only = run(&["--repo", "v1"]);
    assert!(v1_only.status.success());
    assert!(!String::from_utf8_lossy(&v1_only.stdout).contains("tuf/v2"));
    let fail = run(&["--repo", "v2"]);
    assert_eq!(fail.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&fail.stderr)
            .contains("tuf check: error[publishers-mismatch]: tuf/v2: "),
        "{}",
        String::from_utf8_lossy(&fail.stderr)
    );
}

#[test]
fn a_key_rotated_out_of_v1_is_never_a_key_of_v2() {
    let w = v2_world();
    let now = t0() + Duration::days(2);
    // tuf/v1 rotates its snapshot key: the old one is in no root in force any more.
    let old_v1_snapshot =
        keystore::load_encrypted(&w.keys().join("snapshot.key"), super::PASSPHRASE).unwrap();
    root::root(&root::Options {
        keys: &w.keys(),
        out: &w.v1(),
        rotate_root: false,
        rotate_targets: false,
        rotate_snapshot: true,
        rotate_timestamp: false,
        now,
        passphrase: &w.pass(),
    })
    .unwrap();
    update::update(&update::Options {
        keys: &w.keys(),
        index: &w.indexes(),
        out: &w.v1(),
        refresh: false,
        now,
        passphrase: &w.pass(),
    })
    .unwrap();
    // A root of tuf/v2 that takes it as its snapshot key, signed by tuf/v2's root key.
    let v2_root = check::committed_root(&w.v2()).unwrap();
    let def = build::RootDef {
        root: check::role_def(&v2_root, Role::Root).unwrap(),
        timestamp: check::role_def(&v2_root, Role::Timestamp).unwrap(),
        snapshot: build::RoleDef {
            keys: vec![old_v1_snapshot.public()],
            threshold: 1,
        },
        targets: check::role_def(&v2_root, Role::Targets).unwrap(),
    };
    let root_key =
        keystore::load_encrypted(&w.keys().join("v2-root.key"), super::PASSPHRASE).unwrap();
    let signed = build::root(2, now + Duration::days(365), &def).unwrap();
    fs::write(
        w.v2().join("metadata/2.root.json"),
        build::sign(&signed, &[&root_key]).unwrap(),
    )
    .unwrap();
    let v2 = w.tree(now);
    let v2_verified = v2.verified.as_ref().unwrap();
    let v1 = match check::check(&check::Options {
        dir: &w.v1(),
        index: Some(&w.indexes()),
        anchor: Some(&w.anchor()),
        now,
        timestamp: TimestampMode::Absent,
        expiry: Expiry {
            min_days: 0,
            min_root_days: 0,
            fail: false,
        },
        base: None,
    })
    .unwrap()
    {
        check::Outcome::Checked(r) => r,
        check::Outcome::NoRepository => panic!("tuf/v1"),
    };
    let v1_verified = v1.verified.as_ref().unwrap();
    // The roots in force alone share nothing: only the whole chain shows it.
    let (in_force, _) = check_v2::cross(
        v1_verified,
        std::slice::from_ref(&v1_verified.root),
        v2_verified,
    );
    assert!(in_force.is_empty(), "{in_force:?}");
    let (problems, _) = check_v2::cross(
        v1_verified,
        &check::committed_chain(&w.v1()).unwrap(),
        v2_verified,
    );
    let id = old_v1_snapshot.key_id().to_string();
    assert!(
        problems
            .iter()
            .any(|p| p.code == "shared-key" && p.message.contains(&id)),
        "{problems:?}"
    );
    // `tuf update` refuses it, and the check command too.
    let err = w.update(now, false).unwrap_err();
    assert!(format!("{err:#}").contains("shared-key"), "{err:#}");
}

#[test]
fn the_snapshot_extends_the_published_one_unless_it_is_the_first_publication() {
    let w = v2_world();
    let now = t0() + Duration::hours(1);
    // A site without a timestamp is not "nothing published yet".
    let unpublished = w.copy("unpublished");
    let site = w.copy("site");
    let err = w.snapshot(&site, now, Some(&unpublished)).unwrap_err();
    assert!(
        format!("{err:#}").contains("--first-publication"),
        "{err:#}"
    );
    assert!(!files(&site).iter().any(|f| f.contains("snapshot")));
    // The command line asks for one or the other.
    let s = |p: PathBuf| p.to_string_lossy().into_owned();
    let neither = super::xtask(&["snapshot", "--out", &s(site.clone())]);
    assert_eq!(neither.status.code(), Some(2));
    let both = super::xtask(&[
        "snapshot",
        "--out",
        &s(site),
        "--previous",
        "https://example.invalid/tuf/v2/",
        "--first-publication",
    ]);
    assert_eq!(both.status.code(), Some(2));
}

#[test]
fn a_published_snapshot_of_the_last_version_has_no_next_one() {
    let w = v2_world();
    let now = t0() + Duration::hours(1);
    let published = w.copy("published");
    let seed = |name: &str| {
        keystore::parse_seed(&fs::read_to_string(w.keys().join(name)).unwrap()).unwrap()
    };
    let targets = fs::read(published.join("metadata/1.targets.json")).unwrap();
    let role = fs::read(published.join("metadata/1.pub-ecc.json")).unwrap();
    let mut signed = build::snapshot(u64::MAX, now + Duration::days(7), 1, &targets).unwrap();
    signed["meta"]["pub-ecc.json"] = serde_json::json!({
        "version": 1,
        "length": role.len(),
        "hashes": {"sha256": oncl_update::tuf::Digest::of(&role).to_hex()},
    });
    let snapshot_file = build::sign(&signed, &[&seed("v2-snapshot.key")]).unwrap();
    fs::write(
        published.join(format!("metadata/{}.snapshot.json", u64::MAX)),
        &snapshot_file,
    )
    .unwrap();
    let timestamp = build::timestamp(1, now + Duration::days(7), u64::MAX, &snapshot_file).unwrap();
    fs::write(
        published.join("metadata/timestamp.json"),
        build::sign(&timestamp, &[&seed("v2-timestamp.key")]).unwrap(),
    )
    .unwrap();
    let site = w.copy("site");
    let err = w.snapshot(&site, now, Some(&published)).unwrap_err();
    let overflow = err
        .chain()
        .find_map(|e| e.downcast_ref::<xtask::tuf::VersionOverflow>())
        .unwrap_or_else(|| panic!("{err:#}"));
    assert_eq!(overflow.version, u64::MAX);
    assert!(!files(&site).iter().any(|f| f.contains("snapshot")));
}

#[test]
fn a_role_file_larger_than_a_client_reads_is_refused() {
    let w = v2_world();
    let limit = Limits::default().delegated;
    fs::write(
        w.v2().join("metadata/2.pub-ecc.json"),
        vec![b' '; usize::try_from(limit).unwrap() + 1],
    )
    .unwrap();
    let found = codes(&w.tree(t0()));
    assert!(found.contains(&"too-large"), "{found:?}");
}

/// Writes `metadata/<version>.targets.json` into `dir`: targets 1 of `dir` with `version`,
/// without its `delegations` member, signed by the targets key. The file written.
fn targets_without_delegations(w: &V2World, dir: &Path, version: u64) -> Vec<u8> {
    let key = keystore::load_encrypted(&w.keys().join("targets.key"), super::PASSPHRASE).unwrap();
    let file = fs::read(dir.join("metadata/1.targets.json")).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&file).unwrap();
    let signed = value["signed"].as_object_mut().unwrap();
    assert!(signed.remove("delegations").is_some());
    signed.insert("version".to_owned(), version.into());
    let file = build::sign(&value["signed"], &[&key]).unwrap();
    fs::write(dir.join(format!("metadata/{version}.targets.json")), &file).unwrap();
    file
}

#[test]
fn newest_targets_without_delegations_are_a_finding_of_the_check() {
    let w = v2_world();
    targets_without_delegations(&w, &w.v2(), 2);
    let found = codes(&w.tree(t0()));
    assert!(found.contains(&"delegations-missing"), "{found:?}");
}

#[test]
fn older_targets_without_delegations_are_a_finding_of_the_check() {
    let w = v2_world();
    // Version 2 is version 1 as it was; version 1 loses its delegations.
    let first = fs::read(w.v2().join("metadata/1.targets.json")).unwrap();
    let key = keystore::load_encrypted(&w.keys().join("targets.key"), super::PASSPHRASE).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&first).unwrap();
    value["signed"]["version"] = 2.into();
    fs::write(
        w.v2().join("metadata/2.targets.json"),
        build::sign(&value["signed"], &[&key]).unwrap(),
    )
    .unwrap();
    targets_without_delegations(&w, &w.v2(), 1);
    let report = w.tree(t0());
    let missing: Vec<&str> = report
        .problems
        .iter()
        .filter(|p| p.code == "delegations-missing")
        .map(|p| p.message.as_str())
        .collect();
    assert_eq!(missing.len(), 1, "{:?}", report.problems);
    assert!(
        missing[0].contains("metadata/1.targets.json"),
        "{missing:?}"
    );
}

#[test]
fn a_published_tuf_v2_without_delegations_does_not_verify() {
    let w = v2_world();
    let now = t0() + Duration::hours(1);
    let site = w.copy("site");
    let targets = targets_without_delegations(&w, &site, 2);
    let seed = |name: &str| {
        keystore::parse_seed(&fs::read_to_string(w.keys().join(name)).unwrap()).unwrap()
    };
    let snapshot = build::snapshot(1, now + Duration::days(7), 2, &targets).unwrap();
    let snapshot = build::sign(&snapshot, &[&seed("v2-snapshot.key")]).unwrap();
    fs::write(site.join("metadata/1.snapshot.json"), &snapshot).unwrap();
    let timestamp = build::timestamp(1, now + Duration::days(7), 1, &snapshot).unwrap();
    fs::write(
        site.join("metadata/timestamp.json"),
        build::sign(&timestamp, &[&seed("v2-timestamp.key")]).unwrap(),
    )
    .unwrap();
    let anchor = fs::read(w.v2_anchor()).unwrap();
    let err =
        published::verify_published_v2(DirFetcher::new(&site), &anchor, now, false).unwrap_err();
    assert!(
        format!("{err:#}").contains("no readable delegations"),
        "{err:#}"
    );
}
