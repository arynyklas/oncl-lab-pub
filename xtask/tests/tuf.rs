//! `cargo xtask tuf`: init, update, timestamp, root and check on repositories made here with
//! synthetic keys in temporary directories, and the real client (`oncl_update::tuf`) over
//! the results. Key passphrases come from a file; the keys and the clock are the test's.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use oncl_update::tuf::{Limits, MemoryStore, Role, TufClient, TufError, build};
use time::{Duration, OffsetDateTime};
use xtask::tuf::check::{self, Expiry, Options, Outcome, Report, TimestampMode};
use xtask::tuf::keystore;
use xtask::tuf::published::{self, Published};
use xtask::tuf::repo::DirFetcher;
use xtask::tuf::timestamp::{self, KeySource};
use xtask::tuf::{PassphraseSource, init, root, update};

const PASSPHRASE: &str = "correct horse battery staple";

fn t0() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn index(channel: &str, seq: u32) -> Vec<u8> {
    format!(
        "{{\"schema\":1,\"channel\":\"{channel}\",\"seq\":{seq},\
         \"generated\":\"2026-09-20T00:00:00Z\",\"expires\":\"2026-10-20T00:00:00Z\",\
         \"core\":[]}}\n"
    )
    .into_bytes()
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A scratch directory with the keys, the repository, the anchor, the indexes and the
/// passphrase file.
struct World {
    dir: tempfile::TempDir,
}

/// One world, made once (key generation is slow), and copied for each test: init, then
/// `update` over a stable and a beta index.
static TEMPLATE: LazyLock<PathBuf> = LazyLock::new(|| {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("tuf-world-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("indexes")).unwrap();
    fs::write(dir.join("pass.txt"), PASSPHRASE).unwrap();
    fs::write(dir.join("indexes/stable.json"), index("stable", 1)).unwrap();
    fs::write(dir.join("indexes/beta.json"), index("beta", 1)).unwrap();
    let source = PassphraseSource::File(dir.join("pass.txt"));
    init::init(&init::Options {
        keys: &dir.join("keys"),
        out: &dir.join("repo"),
        anchor: &dir.join("anchor/root.json"),
        now: t0(),
        passphrase: &source,
    })
    .unwrap();
    update::update(&update::Options {
        keys: &dir.join("keys"),
        index: &dir.join("indexes"),
        out: &dir.join("repo"),
        refresh: false,
        now: t0(),
        passphrase: &source,
    })
    .unwrap();
    dir
});

fn template() -> &'static Path {
    &TEMPLATE
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    copy_dir(template(), dir.path());
    World { dir }
}

impl World {
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn keys(&self) -> PathBuf {
        self.p("keys")
    }
    fn repo(&self) -> PathBuf {
        self.p("repo")
    }
    fn anchor(&self) -> PathBuf {
        self.p("anchor/root.json")
    }
    fn indexes(&self) -> PathBuf {
        self.p("indexes")
    }
    fn pass(&self) -> PassphraseSource {
        PassphraseSource::File(self.p("pass.txt"))
    }

    fn update(&self, now: OffsetDateTime, refresh: bool) -> anyhow::Result<update::Outcome> {
        update::update(&update::Options {
            keys: &self.keys(),
            index: &self.indexes(),
            out: &self.repo(),
            refresh,
            now,
            passphrase: &self.pass(),
        })
    }

    fn timestamp_at(
        &self,
        out: &Path,
        now: OffsetDateTime,
        key: &Path,
    ) -> anyhow::Result<timestamp::Signed> {
        timestamp::timestamp(&timestamp::Options {
            out,
            anchor: &self.anchor(),
            index: &self.indexes(),
            key: &KeySource::File(key.to_owned()),
            now,
        })
    }

    fn timestamp(&self, now: OffsetDateTime) -> anyhow::Result<timestamp::Signed> {
        self.timestamp_at(&self.repo(), now, &self.keys().join("timestamp.key"))
    }

    fn check(
        &self,
        mode: TimestampMode,
        now: OffsetDateTime,
        fail: bool,
        base: Option<&str>,
    ) -> Report {
        match check::check(&Options {
            dir: &self.repo(),
            index: Some(&self.indexes()),
            anchor: Some(&self.anchor()),
            now,
            timestamp: mode,
            expiry: Expiry {
                min_days: 10,
                min_root_days: 45,
                fail,
            },
            base,
        })
        .unwrap()
        {
            Outcome::Checked(report) => *report,
            Outcome::NoRepository => panic!("no repository"),
        }
    }

    fn tree(&self, now: OffsetDateTime) -> Report {
        self.check(TimestampMode::Absent, now, false, None)
    }
}

fn codes(report: &Report) -> Vec<&'static str> {
    report.problems.iter().map(|p| p.code).collect()
}

fn files(dir: &Path) -> Vec<String> {
    xtask::tuf::repo::walk(dir).unwrap()
}

/// The client, from the anchor, over the repository, with `store`.
fn refresh(
    world: &World,
    store: &mut MemoryStore,
    now: OffsetDateTime,
) -> Result<oncl_update::tuf::Trusted, TufError> {
    let anchor = fs::read(world.anchor()).unwrap();
    let mut client = TufClient::new(
        &anchor,
        DirFetcher::new(world.repo()),
        store,
        Limits::default(),
    )?;
    client.refresh(now)
}

#[test]
fn init_update_timestamp_check_end_to_end() {
    let w = world();
    let before = files(&w.repo());
    assert!(before.contains(&"metadata/1.root.json".to_owned()));
    assert!(before.contains(&"metadata/1.targets.json".to_owned()));
    assert!(before.contains(&"metadata/1.snapshot.json".to_owned()));
    assert_eq!(
        before
            .iter()
            .filter(|f| f.starts_with("targets/indexes/"))
            .count(),
        2
    );
    // The anchor is root 1, byte for byte.
    assert_eq!(
        fs::read(w.anchor()).unwrap(),
        fs::read(w.repo().join("metadata/1.root.json")).unwrap()
    );
    // The committed tree verifies without a timestamp, and has none.
    let tree = w.tree(t0());
    assert!(tree.problems.is_empty(), "{:?}", tree.problems);
    assert!(!before.contains(&"metadata/timestamp.json".to_owned()));

    // The timestamp is signed over a copy, the client accepts it, and so does the check.
    let signed = w.timestamp(t0() + Duration::hours(1)).unwrap();
    assert_eq!(signed.version, (1_790_000_000 + 3600) as u64);
    let full = w.check(
        TimestampMode::Required,
        t0() + Duration::hours(1),
        true,
        None,
    );
    assert!(full.problems.is_empty(), "{:?}", full.problems);
    let mut store = MemoryStore::default();
    let trusted = refresh(&w, &mut store, t0() + Duration::hours(1)).unwrap();
    assert_eq!(trusted.targets().targets.len(), 2);
    let bytes = oncl_update::tuf::TufClient::new(
        &fs::read(w.anchor()).unwrap(),
        DirFetcher::new(w.repo()),
        MemoryStore::default(),
        Limits::default(),
    )
    .unwrap()
    .download_target(
        &trusted,
        "indexes/stable.json",
        1 << 20,
        t0() + Duration::hours(1),
    )
    .unwrap();
    assert_eq!(bytes, fs::read(w.indexes().join("stable.json")).unwrap());
    // And the published-smoke check, over the same files.
    let verdict = published::verify_published(
        DirFetcher::new(w.repo()),
        &fs::read(w.anchor()).unwrap(),
        t0() + Duration::hours(1),
        false,
    )
    .unwrap();
    assert!(matches!(verdict, Published::Verified { .. }));
}

#[test]
fn update_is_idempotent_and_refresh_moves_the_expiry() {
    let w = world();
    let before = files(&w.repo());
    // Nothing changed: nothing written, and no passphrase is needed to find that out.
    let source = PassphraseSource::File(w.p("no-such-passphrase-file"));
    let done = update::update(&update::Options {
        keys: &w.keys(),
        index: &w.indexes(),
        out: &w.repo(),
        refresh: false,
        now: t0() + Duration::days(1),
        passphrase: &source,
    })
    .unwrap();
    assert!(matches!(
        done,
        update::Outcome::UpToDate {
            targets: 1,
            snapshot: 1
        }
    ));
    assert_eq!(files(&w.repo()), before);

    // A refresh signs version 2 of both over the same targets (the files are not copied again).
    let later = t0() + Duration::days(25);
    let update::Outcome::Written(written) = w.update(later, true).unwrap() else {
        panic!("a refresh writes");
    };
    assert_eq!((written.targets, written.snapshot), (2, 2));
    let after = files(&w.repo());
    assert_eq!(after.len(), before.len() + 2, "{after:?}");
    let report = w.tree(later);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    // The expiry moved: 30 days from the refresh.
    let v = report.verified.unwrap();
    assert_eq!(v.targets.expires, later + Duration::days(30));
    assert_eq!(v.snapshot.expires, later + Duration::days(30));
    assert_eq!(v.targets.version, 2);

    // Changed content: a new version with a new file, and the old one stays.
    fs::write(w.indexes().join("stable.json"), index("stable", 2)).unwrap();
    let update::Outcome::Written(written) = w.update(later + Duration::days(1), false).unwrap()
    else {
        panic!("a changed index writes");
    };
    assert_eq!((written.targets, written.snapshot), (3, 3));
    assert!(
        written.reason.contains("indexes/stable.json"),
        "{}",
        written.reason
    );
    assert_eq!(files(&w.repo()).len(), after.len() + 3);
    assert!(w.tree(later + Duration::days(1)).problems.is_empty());
}

#[test]
fn stale_target_bytes_are_detected() {
    let w = world();
    fs::write(w.indexes().join("beta.json"), index("beta", 2)).unwrap();
    let report = w.tree(t0());
    assert_eq!(codes(&report), ["index-mismatch"], "{:?}", report.problems);
    assert!(report.problems[0].message.contains("tuf update"));
    // An index that is not a target at all, and a target without an index.
    fs::write(w.indexes().join("beta.json"), index("beta", 1)).unwrap();
    fs::remove_file(w.indexes().join("beta.json")).unwrap();
    assert_eq!(codes(&w.tree(t0())), ["index-missing"]);
    // `update` refuses to drop a channel's index silently.
    let err = w.update(t0() + Duration::days(1), false).unwrap_err();
    assert!(err.to_string().contains("left without updates"), "{err}");
}

#[test]
fn expiring_and_expired_metadata_is_flagged() {
    let w = world();
    // 25 days in: 5 left of 30.
    let soon = t0() + Duration::days(25);
    let warn = w.check(TimestampMode::Absent, soon, false, None);
    assert!(warn.problems.is_empty(), "{:?}", warn.problems);
    let w_codes: Vec<_> = warn.warnings.iter().map(|p| p.code).collect();
    assert_eq!(w_codes, ["expiring", "expiring"], "{:?}", warn.warnings);
    let fail = w.check(TimestampMode::Absent, soon, true, None);
    assert_eq!(codes(&fail), ["expiring", "expiring"]);
    // Past the 30 days the signatures and the chain are still verified, and the expiry is
    // what is reported.
    let late = t0() + Duration::days(31);
    let report = w.check(TimestampMode::Absent, late, false, None);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(
        report
            .warnings
            .iter()
            .filter(|p| p.code == "expired")
            .count(),
        2
    );
    assert_eq!(
        codes(&w.check(TimestampMode::Absent, late, true, None)),
        ["expired", "expired"]
    );
    // The root has a year: 330 days in, 35 are left, under the 45.
    let year = t0() + Duration::days(330);
    let report = w.check(TimestampMode::Absent, year, false, None);
    assert!(
        report
            .warnings
            .iter()
            .any(|p| p.code == "expiring" && p.message.contains("root"))
    );
}

#[test]
fn a_missing_file_and_a_stray_file_are_detected() {
    let w = world();
    let stable = files(&w.repo())
        .into_iter()
        .find(|f| f.ends_with(".stable.json"))
        .unwrap();
    let saved = fs::read(w.repo().join(&stable)).unwrap();
    fs::remove_file(w.repo().join(&stable)).unwrap();
    assert_eq!(codes(&w.tree(t0())), ["missing-file"]);
    fs::write(w.repo().join(&stable), b"{}").unwrap();
    assert_eq!(codes(&w.tree(t0())), ["hash-mismatch"]);
    fs::write(w.repo().join(&stable), &saved).unwrap();
    assert!(w.tree(t0()).problems.is_empty());

    fs::write(w.repo().join("README.md"), b"hello").unwrap();
    fs::write(
        w.repo()
            .join(format!("targets/indexes/{}.stable.json", "0".repeat(64))),
        b"{}",
    )
    .unwrap();
    let report = w.tree(t0());
    assert_eq!(
        codes(&report),
        ["stray-file", "stray-file"],
        "{:?}",
        report.problems
    );
    // A committed timestamp is a problem of the tree.
    fs::remove_file(w.repo().join("README.md")).unwrap();
    fs::remove_file(
        w.repo()
            .join(format!("targets/indexes/{}.stable.json", "0".repeat(64))),
    )
    .unwrap();
    w.timestamp(t0() + Duration::hours(1)).unwrap();
    let report = w.tree(t0() + Duration::hours(1));
    assert!(
        codes(&report).contains(&"timestamp-committed"),
        "{:?}",
        report.problems
    );
}

#[test]
fn a_wrong_passphrase_writes_nothing_and_keys_are_not_overwritten() {
    let w = world();
    let before = files(&w.repo());
    fs::write(w.p("wrong.txt"), "not the passphrase").unwrap();
    let err = update::update(&update::Options {
        keys: &w.keys(),
        index: &w.indexes(),
        out: &w.repo(),
        refresh: true,
        now: t0() + Duration::days(1),
        passphrase: &PassphraseSource::File(w.p("wrong.txt")),
    })
    .unwrap_err();
    assert!(format!("{err:#}").contains("reading the key"), "{err:#}");
    assert_eq!(files(&w.repo()), before);

    // `init` over the same keys, the same repository or the same anchor refuses.
    let again = |keys: &Path, out: &Path, anchor: &Path| {
        init::init(&init::Options {
            keys,
            out,
            anchor,
            now: t0(),
            passphrase: &w.pass(),
        })
    };
    let err = again(&w.keys(), &w.p("repo2"), &w.p("anchor2.json")).unwrap_err();
    assert!(err.to_string().contains("refusing to overwrite"), "{err}");
    let err = again(&w.p("keys2"), &w.repo(), &w.p("anchor2.json")).unwrap_err();
    assert!(err.to_string().contains("refusing to overwrite"), "{err}");
    let err = again(&w.p("keys2"), &w.p("repo2"), &w.anchor()).unwrap_err();
    assert!(err.to_string().contains("refusing to overwrite"), "{err}");
    assert!(
        !w.p("keys2").exists() && !w.p("repo2").exists(),
        "nothing was made"
    );
}

fn rotation_case(role: Role) {
    let w = world();
    let now = t0() + Duration::days(2);
    // A client that has seen the repository before the rotation.
    w.timestamp(t0() + Duration::hours(1)).unwrap();
    let mut store = MemoryStore::default();
    refresh(&w, &mut store, t0() + Duration::hours(1)).unwrap();
    fs::remove_file(w.repo().join("metadata/timestamp.json")).unwrap();

    let rotated = root::root(&root::Options {
        keys: &w.keys(),
        out: &w.repo(),
        rotate_root: role == Role::Root,
        rotate_targets: role == Role::Targets,
        rotate_snapshot: role == Role::Snapshot,
        rotate_timestamp: role == Role::Timestamp,
        now,
        passphrase: &w.pass(),
    })
    .unwrap();
    assert_eq!(rotated.version, 2);
    assert_eq!(rotated.new_keys.len(), 1);
    let (new_role, id, file) = &rotated.new_keys[0];
    assert_eq!(*new_role, role);
    assert!(file.ends_with(keystore::file_name(role, Some(2))));

    // After a rotation of targets or snapshot the tree needs new versions; `update` finds out.
    let needs_update = matches!(role, Role::Targets | Role::Snapshot);
    if needs_update {
        assert!(!w.tree(now).problems.is_empty(), "old keys no longer sign");
        let update::Outcome::Written(written) = w.update(now, false).unwrap() else {
            panic!("update signs again after a rotation");
        };
        assert!(written.reason.contains("rotated"), "{}", written.reason);
    } else {
        assert!(matches!(
            w.update(now, false).unwrap(),
            update::Outcome::UpToDate { .. }
        ));
    }
    let report = w.tree(now);
    assert!(report.problems.is_empty(), "{role}: {:?}", report.problems);
    let v = report.verified.unwrap();
    assert_eq!(v.root.version, 2);
    assert!(v.root.role(role).keyids.iter().any(|k| k == id));

    let key = if role == Role::Timestamp {
        w.keys().join("timestamp.v2.key")
    } else {
        w.keys().join("timestamp.key")
    };
    // The old timestamp key no longer signs after its rotation.
    if role == Role::Timestamp {
        let err = w
            .timestamp_at(&w.repo(), now, &w.keys().join("timestamp.key"))
            .unwrap_err();
        assert!(err.to_string().contains("not a timestamp key"), "{err}");
    }
    w.timestamp_at(&w.repo(), now, &key).unwrap();

    // The client that knew root 1 follows the chain to root 2 and the new keys.
    let trusted = refresh(&w, &mut store, now).unwrap();
    assert_eq!(trusted.root().version, 2);
    // And one that starts from the anchor does too.
    refresh(&w, &mut MemoryStore::default(), now).unwrap();
}

#[test]
fn rotating_the_timestamp_key_is_followed_by_a_client_that_knew_the_old_root() {
    rotation_case(Role::Timestamp);
}

#[test]
fn rotating_the_snapshot_key_is_followed_by_a_client_that_knew_the_old_root() {
    rotation_case(Role::Snapshot);
}

#[test]
fn rotating_the_targets_key_is_followed_by_a_client_that_knew_the_old_root() {
    rotation_case(Role::Targets);
}

#[test]
fn rotating_the_root_key_is_followed_by_a_client_that_knew_the_old_root() {
    rotation_case(Role::Root);
}

#[test]
fn a_plain_root_is_a_renewal_with_the_same_keys() {
    let w = world();
    let later = t0() + Duration::days(340);
    let rotated = root::root(&root::Options {
        keys: &w.keys(),
        out: &w.repo(),
        rotate_root: false,
        rotate_targets: false,
        rotate_snapshot: false,
        rotate_timestamp: false,
        now: later,
        passphrase: &w.pass(),
    })
    .unwrap();
    assert!(rotated.new_keys.is_empty());
    // The targets and snapshot of root 1 still verify (same keys); refresh them and check.
    w.update(later, true).unwrap();
    let report = w.tree(later);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(
        report.verified.unwrap().root.expires,
        later + Duration::days(365)
    );
    // A renewal of an expired root works too (that is what it is for), and the chain from the
    // anchor holds with the new root, which is then in force.
    let w = world();
    let expired = t0() + Duration::days(400);
    let renewed = root::root(&root::Options {
        keys: &w.keys(),
        out: &w.repo(),
        rotate_root: false,
        rotate_targets: false,
        rotate_snapshot: false,
        rotate_timestamp: false,
        now: expired,
        passphrase: &w.pass(),
    })
    .unwrap();
    assert_eq!(renewed.version, 2);
    assert_eq!(renewed.expires, expired + Duration::days(365));
    let anchor = fs::read(w.anchor()).unwrap();
    let in_force = check::final_root(&w.repo(), &anchor, expired).unwrap();
    assert_eq!(in_force.version, 2);
    assert_eq!(in_force.expires, expired + Duration::days(365));
}

/// Runs `git`; the test has checked [`has_git`] first.
fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Whether `git` is there; prints the skip line when it is not.
fn has_git() -> bool {
    oncl_testkit::tool::GIT.or_skip(&["--version"]).is_some()
}

#[test]
fn history_is_kept_against_the_base_revision() {
    if !has_git() {
        return;
    }
    let w = world();
    // A second version, committed as the base.
    let later = t0() + Duration::days(1);
    w.update(later, true).unwrap();
    git(w.dir.path(), &["init", "-q"]);
    git(w.dir.path(), &["add", "repo"]);
    git(w.dir.path(), &["commit", "-q", "-m", "base"]);
    let base = Some("HEAD");

    // Nothing changed: nothing to say.
    let report = w.check(TimestampMode::Absent, later, false, base);
    assert!(report.problems.is_empty(), "{:?}", report.problems);

    // A new version extends it.
    w.update(later + Duration::days(1), true).unwrap();
    let report = w.check(
        TimestampMode::Absent,
        later + Duration::days(1),
        false,
        base,
    );
    assert!(report.problems.is_empty(), "{:?}", report.problems);

    // A published file changed or gone, or the newest version back.
    fs::remove_file(w.repo().join("metadata/3.targets.json")).unwrap();
    fs::remove_file(w.repo().join("metadata/3.snapshot.json")).unwrap();
    fs::remove_file(w.repo().join("metadata/2.targets.json")).unwrap();
    fs::remove_file(w.repo().join("metadata/2.snapshot.json")).unwrap();
    let report = w.check(TimestampMode::Absent, later, false, base);
    let found = codes(&report);
    assert!(found.contains(&"file-removed"), "{found:?}");
    assert!(found.contains(&"version-rollback"), "{found:?}");
    let root_file = w.repo().join("metadata/1.root.json");
    let mut bytes = fs::read(&root_file).unwrap();
    bytes.push(b'\n');
    fs::write(&root_file, bytes).unwrap();
    let report = w.check(TimestampMode::Absent, later, false, base);
    assert!(
        codes(&report).contains(&"file-modified"),
        "{:?}",
        report.problems
    );

    // A repository that was there and is gone.
    let nothing = check::check(&Options {
        dir: &w.p("repo-gone"),
        index: None,
        anchor: Some(&w.p("anchor-gone.json")),
        now: later,
        timestamp: TimestampMode::Absent,
        expiry: Expiry {
            min_days: 10,
            min_root_days: 45,
            fail: false,
        },
        base: None,
    })
    .unwrap();
    assert!(matches!(nothing, Outcome::NoRepository));
}

fn assert_refused(w: &World, now: OffsetDateTime, anchor: Option<&Path>, what: &str) {
    let out = w.p("publish");
    let _ = fs::remove_dir_all(&out);
    copy_dir(&w.repo(), &out);
    let key_line = fs::read_to_string(w.keys().join("timestamp.key")).unwrap();
    let err = timestamp::timestamp(&timestamp::Options {
        out: &out,
        anchor: anchor.unwrap_or(&w.anchor()),
        index: &w.indexes(),
        key: &KeySource::File(w.keys().join("timestamp.key")),
        now,
    })
    .expect_err(what);
    let message = format!("{err:#}");
    assert!(
        !message.contains(key_line.trim()),
        "the message has the key: {message}"
    );
    assert!(
        !out.join("metadata/timestamp.json").exists(),
        "{what}: a timestamp was made"
    );
}

#[test]
fn timestamp_refuses_a_repository_the_client_would_refuse() {
    let w = world();
    let now = t0() + Duration::hours(1);

    // A damaged signature of the snapshot.
    let snapshot = w.repo().join("metadata/1.snapshot.json");
    let good = fs::read_to_string(&snapshot).unwrap();
    let at = good.find("\"sig\":\"").unwrap() + 7;
    let mut bad = good.clone().into_bytes();
    bad[at] = if bad[at] == b'0' { b'1' } else { b'0' };
    fs::write(&snapshot, &bad).unwrap();
    assert_refused(&w, now, None, "a damaged signature");
    fs::write(&snapshot, good).unwrap();

    // A targets file that is not the one the snapshot lists.
    let targets = w.repo().join("metadata/1.targets.json");
    let good = fs::read(&targets).unwrap();
    let mut other = good.clone();
    other.insert(other.len() - 1, b' ');
    fs::write(&targets, other).unwrap();
    assert_refused(&w, now, None, "a replaced targets file");
    fs::write(&targets, good).unwrap();

    // An index that is not the tree's.
    fs::write(w.indexes().join("stable.json"), index("stable", 9)).unwrap();
    assert_refused(&w, now, None, "a target that is not the index");
    fs::write(w.indexes().join("stable.json"), index("stable", 1)).unwrap();

    // An expired snapshot, and one that expires within the day.
    assert_refused(&w, t0() + Duration::days(31), None, "an expired snapshot");
    assert_refused(
        &w,
        t0() + Duration::days(29) + Duration::hours(2),
        None,
        "a snapshot expiring today",
    );

    // A root that does not come from the anchor: the anchor of another world.
    let other = tempfile::tempdir().unwrap();
    fs::write(other.path().join("pass.txt"), PASSPHRASE).unwrap();
    init::init(&init::Options {
        keys: &other.path().join("keys"),
        out: &other.path().join("repo"),
        anchor: &other.path().join("root.json"),
        now: t0(),
        passphrase: &PassphraseSource::File(other.path().join("pass.txt")),
    })
    .unwrap();
    assert_refused(
        &w,
        now,
        Some(&other.path().join("root.json")),
        "a foreign anchor",
    );

    // A stray file, a missing anchor.
    fs::write(w.repo().join("extra.json"), b"{}").unwrap();
    assert_refused(&w, now, None, "a stray file");
    fs::remove_file(w.repo().join("extra.json")).unwrap();
    assert_refused(&w, now, Some(&w.p("no-anchor.json")), "no anchor");

    // And with everything right it signs, once, and refuses to sign over its own file.
    let out = w.p("publish");
    let _ = fs::remove_dir_all(&out);
    copy_dir(&w.repo(), &out);
    w.timestamp_at(&out, now, &w.keys().join("timestamp.key"))
        .unwrap();
    let again = w
        .timestamp_at(&out, now, &w.keys().join("timestamp.key"))
        .unwrap_err();
    assert!(
        again.to_string().contains("refusing to overwrite"),
        "{again}"
    );
    // The key of another role is not the timestamp key.
    let _ = fs::remove_file(out.join("metadata/timestamp.json"));
    let (_, line) = keystore::generate_seed().unwrap();
    fs::write(w.p("other.key"), line.as_bytes()).unwrap();
    let err = w.timestamp_at(&out, now, &w.p("other.key")).unwrap_err();
    assert!(err.to_string().contains("not a timestamp key"), "{err}");
    assert!(!out.join("metadata/timestamp.json").exists());
}

#[test]
fn the_timestamp_key_comes_from_the_environment_and_a_missing_one_fails() {
    let w = world();
    let now = t0() + Duration::hours(1);
    let out = w.p("publish");
    copy_dir(&w.repo(), &out);
    let err = timestamp::timestamp(&timestamp::Options {
        out: &out,
        anchor: &w.anchor(),
        index: &w.indexes(),
        key: &KeySource::Env("ONCL_TUF_TEST_NO_SUCH_VARIABLE".to_owned()),
        now,
    })
    .unwrap_err();
    assert!(err.to_string().contains("is not set"), "{err}");
    assert!(!out.join("metadata/timestamp.json").exists());
}

#[test]
fn published_check_tolerates_a_repository_that_is_not_published_when_told_to() {
    let w = world();
    let anchor = fs::read(w.anchor()).unwrap();
    // The tree has no timestamp: as a site before the first deployment of the secret.
    let missing =
        published::verify_published(DirFetcher::new(w.repo()), &anchor, t0(), true).unwrap();
    assert_eq!(missing, Published::NotPublished);
    let err =
        published::verify_published(DirFetcher::new(w.repo()), &anchor, t0(), false).unwrap_err();
    assert!(err.to_string().contains("timestamp.json"), "{err}");
    // An expired timestamp is a failure either way.
    w.timestamp(t0() + Duration::hours(1)).unwrap();
    let err = published::verify_published(
        DirFetcher::new(w.repo()),
        &anchor,
        t0() + Duration::days(8),
        true,
    )
    .unwrap_err();
    assert!(err.to_string().contains("xpired"), "{err}");
}

fn xtask(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["tuf"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn the_check_command_has_stable_exit_codes_and_messages() {
    let w = world();
    let s = |p: PathBuf| p.to_string_lossy().into_owned();
    // No repository and no anchor: the state before the ceremony.
    let out = xtask(&[
        "check",
        "--dir",
        &s(w.p("nothing")),
        "--anchor",
        &s(w.p("nothing.json")),
        "--index",
        &s(w.indexes()),
    ]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("tuf check: no TUF repository yet"));
    // A good tree: exit 0, `ok`, and the facts.
    let args = |extra: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = [
            "check",
            "--dir",
            &s(w.repo()),
            "--anchor",
            &s(w.anchor()),
            "--index",
            &s(w.indexes()),
            "--no-timestamp",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        v.extend(extra.iter().map(|e| (*e).to_owned()));
        v
    };
    let run = |a: Vec<String>| xtask(&a.iter().map(String::as_str).collect::<Vec<_>>());
    let ok = run(args(&["--now", "1790000000"]));
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let text = String::from_utf8_lossy(&ok.stdout);
    assert!(
        text.contains("tuf check: root 1, targets 1, snapshot 1, timestamp absent"),
        "{text}"
    );
    assert!(text.trim_end().ends_with("tuf check: ok"), "{text}");
    // Expiring is a warning, and an error with the flag.
    let warn = run(args(&["--now", "1792160000"]));
    assert!(warn.status.success());
    assert!(String::from_utf8_lossy(&warn.stdout).contains("warning[expiring]"));
    let fail = run(args(&["--now", "1792160000", "--fail-on-expiring"]));
    assert_eq!(fail.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&fail.stderr).contains("tuf check: error[expiring]"));
    // The required timestamp is not there.
    let missing = run([
        "check",
        "--dir",
        &s(w.repo()),
        "--anchor",
        &s(w.anchor()),
        "--index",
        &s(w.indexes()),
    ]
    .map(String::from)
    .to_vec());
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("error[no-timestamp]"));
    // A repository without its anchor.
    let no_anchor = xtask(&[
        "check",
        "--dir",
        &s(w.repo()),
        "--anchor",
        &s(w.p("none.json")),
        "--index",
        &s(w.indexes()),
    ]);
    assert_eq!(no_anchor.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&no_anchor.stderr).contains("error[anchor-missing]"));
}

/// Version 2 of the targets and snapshot, signed with the world's keys and made to order:
/// the expiry of each, and one more target.
fn craft(
    w: &World,
    targets_expires: OffsetDateTime,
    snapshot_expires: OffsetDateTime,
    extra: Option<(&str, &[u8])>,
) {
    let targets_key = keystore::load_encrypted(&w.keys().join("targets.key"), PASSPHRASE).unwrap();
    let snapshot_key =
        keystore::load_encrypted(&w.keys().join("snapshot.key"), PASSPHRASE).unwrap();
    let stable = fs::read(w.indexes().join("stable.json")).unwrap();
    let beta = fs::read(w.indexes().join("beta.json")).unwrap();
    let mut refs: Vec<(&str, &[u8])> = vec![
        ("indexes/stable.json", &stable),
        ("indexes/beta.json", &beta),
    ];
    refs.extend(extra);
    let targets = build::sign(
        &build::targets(2, targets_expires, &refs).unwrap(),
        &[&targets_key],
    )
    .unwrap();
    let snapshot = build::sign(
        &build::snapshot(2, snapshot_expires, 2, &targets).unwrap(),
        &[&snapshot_key],
    )
    .unwrap();
    for (path, content) in build::target_files(&refs).unwrap() {
        let full = w.repo().join(path);
        if !full.exists() {
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, content).unwrap();
        }
    }
    fs::write(w.repo().join("metadata/2.targets.json"), targets).unwrap();
    fs::write(w.repo().join("metadata/2.snapshot.json"), snapshot).unwrap();
}

/// A world with its own keys whose first targets list only `channels`.
fn fresh_world(channels: &[&str]) -> World {
    let dir = tempfile::tempdir().unwrap();
    let w = World { dir };
    fs::create_dir_all(w.indexes()).unwrap();
    fs::write(w.p("pass.txt"), PASSPHRASE).unwrap();
    for channel in channels {
        fs::write(
            w.indexes().join(format!("{channel}.json")),
            index(channel, 1),
        )
        .unwrap();
    }
    init::init(&init::Options {
        keys: &w.keys(),
        out: &w.repo(),
        anchor: &w.anchor(),
        now: t0(),
        passphrase: &w.pass(),
    })
    .unwrap();
    w.update(t0(), false).unwrap();
    w
}

#[test]
fn a_missing_and_a_removed_repository_are_told_apart() {
    if !has_git() {
        return;
    }
    let w = world();
    // The anchor is there, the directory is not.
    let report = match check::check(&Options {
        dir: &w.p("no-such-repository"),
        index: None,
        anchor: Some(&w.anchor()),
        now: t0(),
        timestamp: TimestampMode::Absent,
        expiry: Expiry {
            min_days: 10,
            min_root_days: 45,
            fail: false,
        },
        base: None,
    })
    .unwrap()
    {
        Outcome::Checked(report) => report,
        Outcome::NoRepository => panic!("the anchor is there"),
    };
    assert_eq!(codes(&report), ["repository-missing"]);

    // A repository in the base, and now neither it nor the anchor: clients would be left
    // without updates.
    git(w.dir.path(), &["init", "-q"]);
    git(w.dir.path(), &["add", "repo"]);
    git(w.dir.path(), &["commit", "-q", "-m", "base"]);
    fs::remove_dir_all(w.repo()).unwrap();
    let gone = |base| {
        check::check(&Options {
            dir: &w.repo(),
            index: None,
            anchor: Some(&w.p("no-anchor.json")),
            now: t0(),
            timestamp: TimestampMode::Absent,
            expiry: Expiry {
                min_days: 10,
                min_root_days: 45,
                fail: false,
            },
            base,
        })
        .unwrap()
    };
    match gone(Some("HEAD")) {
        Outcome::Checked(report) => assert_eq!(codes(&report), ["repository-removed"]),
        Outcome::NoRepository => panic!("the base has a repository"),
    }
    // Without a base that has one, it is only the state before the ceremony.
    assert!(matches!(gone(None), Outcome::NoRepository));
}

#[test]
fn an_anchor_that_is_not_a_root_of_the_repository_and_a_gap_in_the_roots_are_detected() {
    let w = world();
    let other = fresh_world(&["stable"]);
    let report = check::check(&Options {
        dir: &w.repo(),
        index: None,
        anchor: Some(&other.anchor()),
        now: t0(),
        timestamp: TimestampMode::Absent,
        expiry: Expiry {
            min_days: 10,
            min_root_days: 45,
            fail: false,
        },
        base: None,
    })
    .unwrap();
    let Outcome::Checked(report) = report else {
        panic!()
    };
    assert!(
        codes(&report).contains(&"anchor-mismatch"),
        "{:?}",
        report.problems
    );

    root::root(&root::Options {
        keys: &w.keys(),
        out: &w.repo(),
        rotate_root: false,
        rotate_targets: false,
        rotate_snapshot: false,
        rotate_timestamp: false,
        now: t0() + Duration::days(1),
        passphrase: &w.pass(),
    })
    .unwrap();
    assert!(w.tree(t0() + Duration::days(1)).problems.is_empty());
    fs::remove_file(w.repo().join("metadata/1.root.json")).unwrap();
    let report = w.tree(t0() + Duration::days(1));
    assert!(
        codes(&report).contains(&"root-gap"),
        "{:?}",
        report.problems
    );
}

#[test]
fn files_without_a_version_an_unlisted_index_and_a_foreign_target_are_detected() {
    if !has_git() {
        return;
    }
    // Files added against the base and no version higher.
    let w = world();
    git(w.dir.path(), &["init", "-q"]);
    git(w.dir.path(), &["add", "repo"]);
    git(w.dir.path(), &["commit", "-q", "-m", "base"]);
    fs::write(w.repo().join("notes.txt"), b"x").unwrap();
    let report = w.check(TimestampMode::Absent, t0(), false, Some("HEAD"));
    let found = codes(&report);
    assert!(found.contains(&"no-version-bump"), "{found:?}");
    assert!(found.contains(&"stray-file"), "{found:?}");

    // An index file the targets do not list.
    let w = fresh_world(&["stable"]);
    assert!(w.tree(t0()).problems.is_empty());
    fs::write(w.indexes().join("beta.json"), index("beta", 1)).unwrap();
    assert_eq!(codes(&w.tree(t0())), ["index-not-listed"]);

    // A target that is not an index.
    let w = world();
    craft(
        &w,
        t0() + Duration::days(30),
        t0() + Duration::days(30),
        Some(("notes/readme.txt", b"x")),
    );
    let found = codes(&w.tree(t0()));
    assert!(found.contains(&"unexpected-target"), "{found:?}");
    assert!(found.contains(&"stray-file"), "{found:?}");
}

#[test]
fn timestamp_refuses_an_early_clock_and_expiring_root_and_targets() {
    // The clock is three days before the snapshot was signed.
    let w = world();
    let err = w.timestamp(t0() - Duration::days(3)).unwrap_err();
    assert!(
        err.to_string().contains("before snapshot 1 was signed"),
        "{err}"
    );
    assert!(!w.repo().join("metadata/timestamp.json").exists());

    // The root has half a day left; the targets and snapshot were just refreshed.
    let late = t0() + Duration::days(364) + Duration::hours(1);
    w.update(late, true).unwrap();
    let err = w.timestamp(late + Duration::hours(11)).unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("expiring") && text.contains("root 1"),
        "{text}"
    );
    assert!(!text.contains("targets 2"), "{text}");
    assert!(!w.repo().join("metadata/timestamp.json").exists());

    // Only the targets are about to expire.
    let w = world();
    craft(
        &w,
        t0() + Duration::hours(12),
        t0() + Duration::days(30),
        None,
    );
    let err = w.timestamp(t0() + Duration::hours(1)).unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("expiring") && text.contains("targets 2"),
        "{text}"
    );
    assert!(!text.contains("snapshot 2"), "{text}");
    assert!(!w.repo().join("metadata/timestamp.json").exists());
}

#[test]
fn a_root_that_does_not_verify_takes_the_new_keys_with_it() {
    let w = world();
    // A file where root 3 would be: the client follows the chain to it once root 2 is there.
    fs::write(w.repo().join("metadata/3.root.json"), b"not a root").unwrap();
    let rotate = || {
        root::root(&root::Options {
            keys: &w.keys(),
            out: &w.repo(),
            rotate_root: false,
            rotate_targets: true,
            rotate_snapshot: false,
            rotate_timestamp: true,
            now: t0() + Duration::days(1),
            passphrase: &w.pass(),
        })
    };
    let err = rotate().unwrap_err();
    assert!(err.to_string().contains("does not verify"), "{err}");
    assert!(!w.repo().join("metadata/2.root.json").exists());
    assert!(!w.keys().join("targets.v2.key").exists());
    assert!(!w.keys().join("timestamp.v2.key").exists());
    // The retry does not meet files it made.
    fs::remove_file(w.repo().join("metadata/3.root.json")).unwrap();
    let rotated = rotate().unwrap();
    assert_eq!(rotated.new_keys.len(), 2);
}

#[test]
fn new_keys_need_a_long_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("pass.txt"), "too short").unwrap();
    let err = init::init(&init::Options {
        keys: &dir.path().join("keys"),
        out: &dir.path().join("repo"),
        anchor: &dir.path().join("root.json"),
        now: t0(),
        passphrase: &PassphraseSource::File(dir.path().join("pass.txt")),
    })
    .unwrap_err();
    assert!(err.to_string().contains("at least 12"), "{err}");
    assert!(!dir.path().join("keys").exists() && !dir.path().join("repo").exists());
}

#[cfg(unix)]
#[test]
fn key_files_are_readable_by_their_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    for name in ["root.key", "targets.key", "snapshot.key", "timestamp.key"] {
        let mode = fs::metadata(w.keys().join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

#[test]
fn a_timestamp_key_with_the_line_end_of_a_secret_still_signs() {
    // `gh secret set < timestamp.key` and `Get-Content -Raw timestamp.key | gh secret set`
    // keep the line end of the file: LF, or CRLF from PowerShell.
    for end in ["\n", "\r\n", ""] {
        let w = world();
        let line = fs::read_to_string(w.keys().join("timestamp.key")).unwrap();
        let key = w.p("secret.key");
        fs::write(&key, format!("{}{end}", line.trim_end())).unwrap();
        w.timestamp_at(&w.repo(), t0() + Duration::hours(1), &key)
            .unwrap_or_else(|e| panic!("{end:?}: {e:#}"));
    }
}

/// The committed `tuf/v1` of this repository, as every client reads it: those released before
/// delegations (`Profile::Legacy`) and those from 0.1.2 (`Profile::Delegating`). Its
/// timestamp is signed online when Pages is published, so the client follows the chain of
/// roots up to it, and the newest snapshot and targets are then checked against the final
/// root as the client checks them.
#[test]
fn the_committed_tuf_v1_reads_in_both_profiles() {
    use oncl_update::tuf::ed25519::verify_role;
    use oncl_update::tuf::model::TARGETS_META;
    use oncl_update::tuf::{Digest, Envelope, Profile, Root, Snapshot, Targets, layout};

    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let dir = workspace.join(xtask::tuf::REPO_DIR);
    let anchor = fs::read(workspace.join("crates/oncl-update/keys/root.json")).unwrap();
    let limits = Limits::default();
    let (last_root, last_targets, last_snapshot) =
        xtask::tuf::repo::Listing::read(&dir).unwrap().highest();
    let read = |path: &str, limit: u64| {
        let bytes = fs::read(dir.join(path)).unwrap();
        let file = Envelope::parse(&bytes, limit, path).unwrap();
        (bytes, file)
    };
    let (_, root_file) = read(&layout::root_path(last_root), limits.root);
    let (_, snapshot_file) = read(&layout::snapshot_path(last_snapshot), limits.snapshot);
    let (targets_bytes, targets_file) = read(&layout::targets_path(last_targets), limits.targets);
    let snapshot = Snapshot::from_signed(&snapshot_file.signed).unwrap();
    // A clock at which every newest file is still valid.
    let now = [
        Root::from_signed(&root_file.signed).unwrap().expires,
        snapshot.expires,
        Targets::from_signed(&targets_file.signed, Profile::Delegating)
            .unwrap()
            .expires,
    ]
    .into_iter()
    .min()
    .unwrap()
        - Duration::seconds(1);

    for profile in [Profile::Legacy, Profile::Delegating] {
        let fetcher = DirFetcher::new(dir.clone()).without_timestamp();
        let mut client = TufClient::new(&anchor, &fetcher, MemoryStore::default(), limits)
            .unwrap()
            .with_profile(profile);
        match client.refresh(now) {
            Err(TufError::NotFound(path)) if path == layout::TIMESTAMP_PATH => {}
            other => panic!("{profile:?}: the chain of roots: {:?}", other.map(drop)),
        }
        let root = match client.store().state.roots.last() {
            Some(file) => Root::from_signed(&file.signed).unwrap(),
            None => Root::from_signed(
                &Envelope::parse(&anchor, limits.root, "the anchor")
                    .unwrap()
                    .signed,
            )
            .unwrap(),
        };
        assert_eq!(root.version, last_root, "{profile:?}");
        verify_role(&snapshot_file, &root, Role::Snapshot, "the snapshot").unwrap();
        let listed = snapshot.targets();
        assert_eq!(listed.version, last_targets, "{profile:?}");
        assert!(
            listed
                .length
                .is_none_or(|l| l == targets_bytes.len() as u64)
                && listed
                    .sha256
                    .is_none_or(|h| h == Digest::of(&targets_bytes)),
            "{profile:?}: the snapshot lists other targets"
        );
        verify_role(&targets_file, &root, Role::Targets, "the targets").unwrap();
        let targets = Targets::from_signed(&targets_file.signed, profile)
            .unwrap_or_else(|e| panic!("{profile:?}: {e}"));
        assert_eq!(targets.version, last_targets, "{profile:?}");
        if profile == Profile::Delegating {
            // What the plugin catalog reads apart: the delegations, if any, and every role's
            // file listed by its length and sha256.
            targets.delegations().unwrap();
            for (name, meta) in &snapshot.meta {
                assert!(
                    name.as_str() == TARGETS_META
                        || (meta.length.is_some() && meta.sha256.is_some()),
                    "{name} is listed without its length and sha256"
                );
            }
        }
    }
}

#[path = "tuf/v2.rs"]
mod v2;
