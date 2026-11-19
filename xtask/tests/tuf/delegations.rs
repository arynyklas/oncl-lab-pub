//! The publishers in `tuf/v1` (`docs/design/publishers.md`): `tuf update` from `publishers/`
//! (delegations and `publishers.json` from the first entry on, `retired`, `revoke_all`, the
//! rules Р24 and Р28), `tuf check` of the delegated roles, and the client over the results,
//! on repositories made with synthetic keys in temporary directories.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use oncl_update::catalog::{PublisherPolicy, Standing};
use oncl_update::tuf::{
    Delegated, Envelope, Limits, MemoryStore, Profile, Role, RoleName, SigningKey, Targets,
    TufClient, build,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use xtask::publishers::{Registry, State};
use xtask::tuf::check::{Report, Stage};
use xtask::tuf::published::{self, Published};
use xtask::tuf::repo::{DirFetcher, SnapshotMode};
use xtask::tuf::timestamp::KeySource;
use xtask::tuf::{keystore, snapshot, update};

use super::{PASSPHRASE, World, codes, copy_dir, files, git, has_git, t0, world, world_of, xtask};

/// The key of the synthetic publisher `n`.
pub(super) fn publisher_key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[40 + n; 32]).unwrap()
}

/// The `publisher.toml` of `name` with the key of publisher `n`; `extra` goes before its
/// `[[keys]]`.
pub(super) fn publisher_toml(name: &str, n: u8, extra: &str) -> String {
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

/// The clock of the tests on [`online_world`]: after the rotation, inside the validity of
/// everything.
pub(super) fn t1() -> OffsetDateTime {
    t0() + Duration::days(1) + Duration::hours(1)
}

/// `now` as a date, `YYYY-MM-DD`.
fn day(now: OffsetDateTime) -> String {
    let date = now.date();
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// The world of `tuf.rs` as it goes to production: published with the owner's offline
/// snapshot (`published-offline`), then the root rotation that moves the snapshot key into CI
/// (root 2, `snapshot.v2.key`, `repo.toml` online), then two publishers, `ecc` with one
/// release and `acme` without any (targets 2).
static ONLINE: LazyLock<PathBuf> = LazyLock::new(|| {
    let kept = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tuf-online-world-{}", std::process::id()));
    let _ = fs::remove_dir_all(&kept);
    let w = world();
    let published = w.p("published-offline");
    copy_dir(&w.repo(), &published);
    w.timestamp_at(
        &published,
        t0() + Duration::hours(1),
        &w.keys().join("timestamp.key"),
    )
    .unwrap();
    w.root(t0() + Duration::days(1), &[Role::Snapshot], true)
        .unwrap();
    w.write_publisher("ecc", 0, "");
    w.write_publisher("acme", 1, "");
    let update::Outcome::Written(written) = w.update(t0() + Duration::days(1), false).unwrap()
    else {
        panic!("the first publishers write");
    };
    assert_eq!((written.targets, written.snapshot), (2, None));
    w.release("ecc", 0, 1, &[("kz.ecc.market", "1.0.0")]);
    copy_dir(&w.p(""), &kept);
    kept
});

/// A copy of the world of [`ONLINE`].
pub(super) fn online_world() -> World {
    world_of(&ONLINE)
}

impl World {
    pub(super) fn write_publisher(&self, name: &str, n: u8, extra: &str) {
        self.write_publisher_toml(name, &publisher_toml(name, n, extra));
    }

    pub(super) fn write_publisher_toml(&self, name: &str, text: &str) {
        let dir = self.publishers().join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("publisher.toml"), text).unwrap();
    }

    pub(super) fn publisher_text(&self, name: &str) -> String {
        fs::read_to_string(self.publishers().join(name).join("publisher.toml")).unwrap()
    }

    /// Version `version` of the role of `name`, signed by the key of publisher `n`, listing a
    /// package for each `(id, version)`.
    pub(super) fn release(&self, name: &str, n: u8, version: u64, plugins: &[(&str, &str)]) {
        let plugins: Vec<(&str, &str, bool)> =
            plugins.iter().map(|(id, v)| (*id, *v, false)).collect();
        self.release_revoking(name, n, version, &plugins);
    }

    /// [`World::release`], each package with its `revoked` flag.
    pub(super) fn release_revoking(
        &self,
        name: &str,
        n: u8,
        version: u64,
        plugins: &[(&str, &str, bool)],
    ) {
        let packages: Vec<(String, Vec<u8>, bool)> = plugins
            .iter()
            .map(|(id, v, revoked)| {
                (
                    format!("plugins/{name}/{id}/{v}.onclp"),
                    format!("{id} {v}").into_bytes(),
                    *revoked,
                )
            })
            .collect();
        let refs: Vec<(&str, &[u8])> = packages
            .iter()
            .map(|(p, b, _)| (p.as_str(), b.as_slice()))
            .collect();
        let mut signed = build::targets(version, t0() + Duration::days(90), &refs).unwrap();
        for (path, _, revoked) in &packages {
            signed["targets"][path]["custom"] = json!({"oncl": {"revoked": revoked}});
        }
        let file = build::sign(&signed, &[&publisher_key(n)]).unwrap();
        fs::write(
            self.repo()
                .join(format!("metadata/{version}.pub-{name}.json")),
            file,
        )
        .unwrap();
    }

    /// A copy of the repository for publication.
    pub(super) fn copy(&self, name: &str) -> PathBuf {
        let out = self.p(name);
        copy_dir(&self.repo(), &out);
        out
    }

    /// `tuf snapshot` over `out`, extending the published copy `previous`, with the key file
    /// `key`.
    pub(super) fn snapshot(
        &self,
        out: &Path,
        now: OffsetDateTime,
        previous: &Path,
        key: &str,
    ) -> anyhow::Result<snapshot::Signed> {
        snapshot::snapshot(
            &snapshot::Options {
                out,
                anchor: &self.anchor(),
                index: &self.indexes(),
                publishers: &self.publishers(),
                mode: self.mode(),
                key: &KeySource::File(self.keys().join(key)),
                now,
            },
            &DirFetcher::new(previous),
        )
    }

    /// A published copy: snapshot and timestamp signed at `now`, over `previous` (the site
    /// before the rotation by default).
    pub(super) fn publish(
        &self,
        name: &str,
        now: OffsetDateTime,
        previous: Option<&Path>,
    ) -> PathBuf {
        let out = self.copy(name);
        let before = self.p("published-offline");
        self.snapshot(&out, now, previous.unwrap_or(&before), "snapshot.v2.key")
            .unwrap();
        self.timestamp_at(&out, now, &self.keys().join("timestamp.key"))
            .unwrap();
        out
    }

    /// The newest targets of the repository.
    pub(super) fn newest_targets(&self) -> (u64, Value) {
        let (_, last, _) = xtask::tuf::repo::Listing::read(&self.repo())
            .unwrap()
            .highest();
        let bytes = fs::read(self.repo().join(format!("metadata/{last}.targets.json"))).unwrap();
        (last, serde_json::from_slice(&bytes).unwrap())
    }

    /// Writes `signed` as the targets of its version, signed by the targets key.
    pub(super) fn sign_targets(&self, signed: &Value) {
        let key = keystore::load_encrypted(&self.keys().join("targets.key"), PASSPHRASE).unwrap();
        let version = signed["version"].as_u64().unwrap();
        fs::write(
            self.repo().join(format!("metadata/{version}.targets.json")),
            build::sign(signed, &[&key]).unwrap(),
        )
        .unwrap();
    }
}

/// The client from 0.1.2 over `dir`: refresh, then every delegated role.
pub(super) fn delegated(w: &World, dir: &Path, now: OffsetDateTime) -> Delegated {
    let anchor = fs::read(w.anchor()).unwrap();
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

/// `publishers.json` the newest targets of `w` list, as the client reads it.
fn signed_policy(w: &World) -> PublisherPolicy {
    let (_, targets) = w.newest_targets();
    let hash = targets["signed"]["targets"]["publishers.json"]["hashes"]["sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let bytes = fs::read(w.repo().join(format!("targets/{hash}.publishers.json"))).unwrap();
    PublisherPolicy::from_json(&bytes).unwrap()
}

fn assert_clean(report: &Report) {
    assert!(report.problems.is_empty(), "{:?}", report.problems);
}

#[test]
fn the_publishers_are_delegated_to_in_tuf_v1_and_published_end_to_end() {
    let w = online_world();
    assert_eq!(w.mode(), SnapshotMode::Online);
    let tree = files(&w.repo());
    for file in [
        "metadata/2.root.json",
        "metadata/2.targets.json",
        "metadata/1.pub-ecc.json",
    ] {
        assert!(tree.contains(&file.to_owned()), "{file}: {tree:?}");
    }
    assert!(
        tree.iter()
            .any(|f| f.starts_with("targets/") && f.ends_with(".publishers.json")),
        "{tree:?}"
    );
    assert!(
        !tree.contains(&"metadata/2.snapshot.json".to_owned()),
        "an online snapshot is never committed"
    );
    // Targets 1, before the first publisher, had no delegations: the released clients read
    // it. Targets 2 has them.
    let first = fs::read(w.repo().join("metadata/1.targets.json")).unwrap();
    let first = Envelope::parse(&first, 1 << 20, "targets 1").unwrap();
    assert!(Targets::from_signed(&first.signed, Profile::Legacy).is_ok());

    let report = w.tree(t1());
    assert_clean(&report);
    for note in [
        "root 2, targets 2, snapshot absent, timestamp absent",
        "pub-ecc 1, delegated",
        "clients 0.1.0 and 0.1.1 do not read this repository: its targets have delegations, \
         they stop updating (Р16)",
    ] {
        assert!(
            report.notes.contains(&note.to_owned()),
            "{note}: {:?}",
            report.notes
        );
    }

    // Pages: the snapshot, then the timestamp, in a copy.
    let site = w.publish("site", t1(), None);
    assert_clean(&w.check_dir(&site, Stage::Published, t1(), false, None));
    // The client trusts both roles: ecc with its release, acme without any.
    let roles = delegated(&w, &site, t1());
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
    let anchor = fs::read(w.anchor()).unwrap();
    let Published::Verified { lines } =
        published::verify_published(DirFetcher::new(&site), &anchor, t1(), false).unwrap()
    else {
        panic!("published");
    };
    for wanted in [
        "pub-ecc 1: 1 targets",
        "pub-acme: no release yet",
        "2 active",
    ] {
        assert!(
            lines.iter().any(|l| l.contains(wanted)),
            "{wanted}: {lines:?}"
        );
    }
}

#[test]
fn update_follows_the_registry_of_the_publishers() {
    let w = online_world();
    let later = t1();
    assert!(matches!(
        w.update(later, false).unwrap(),
        update::Outcome::UpToDate {
            targets: 2,
            snapshot: None
        }
    ));

    // The owner revokes a version: publishers.json changes, the delegations do not.
    w.write_publisher(
        "ecc",
        0,
        "[[revoked_versions]]\nid = \"kz.ecc.market\"\nversion = \"1.0.0\"\ndate = \"2026-09-20\"\n",
    );
    assert!(codes(&w.tree(later)).contains(&"publishers-mismatch"));
    let update::Outcome::Written(written) = w.update(later, false).unwrap() else {
        panic!("a revoked version writes");
    };
    assert_eq!(
        (written.targets, written.snapshot, written.delegated),
        (3, None, Some(2))
    );
    assert!(
        written.reason.contains("publishers.json"),
        "{}",
        written.reason
    );
    assert_clean(&w.tree(later));

    // The owner revokes a publisher: its delegation goes, its entry and its role file stay.
    w.write_publisher("ecc", 0, "state = \"revoked\"\nrevoked = \"2026-09-21\"\n");
    assert!(codes(&w.tree(later)).contains(&"delegations-mismatch"));
    let update::Outcome::Written(written) = w.update(later, false).unwrap() else {
        panic!("a revoked publisher writes");
    };
    assert_eq!((written.targets, written.delegated), (4, Some(1)));
    assert!(written.reason.contains("delegations"), "{}", written.reason);
    let report = w.tree(later);
    assert_clean(&report);
    assert!(!report.verified.unwrap().roles[&role("pub-ecc")].delegated);
    assert!(matches!(
        signed_policy(&w).publishers()[1].standing(),
        Standing::Revoked { .. }
    ));

    // The revoked publisher's role stays in every snapshot, so no client takes the snapshot
    // for a rollback.
    let site = w.publish("site", later, None);
    let report = w.check_dir(&site, Stage::Published, later, false, None);
    assert_clean(&report);
    assert_eq!(
        report.verified.unwrap().snapshot.unwrap().meta["pub-ecc.json"].version,
        1
    );
    assert!(
        delegated(&w, &site, later).role(&role("pub-ecc")).is_none(),
        "not delegated any more"
    );
}

#[test]
fn retiring_a_publisher_keeps_the_revocations_of_its_role() {
    let w = online_world();
    let later = t1();
    // The publisher revoked 1.0.0 itself, in its role.
    w.release_revoking(
        "ecc",
        0,
        2,
        &[
            ("kz.ecc.market", "1.0.0", true),
            ("kz.ecc.market", "1.1.0", false),
        ],
    );
    assert_clean(&w.tree(later));

    w.write_publisher("ecc", 0, "state = \"retired\"\n");
    let found = codes(&w.tree(later));
    for code in [
        "retired-revocations-missing",
        "delegations-mismatch",
        "publishers-mismatch",
    ] {
        assert!(found.contains(&code), "{code}: {found:?}");
    }
    let update::Outcome::Written(written) = w.update(later, false).unwrap() else {
        panic!("retiring writes");
    };
    assert_eq!(written.delegated, Some(1));
    assert_eq!(written.settled.len(), 1);
    assert_eq!(
        written.settled[0].path,
        w.publishers().join("ecc").join("publisher.toml")
    );
    let text = w.publisher_text("ecc");
    assert!(
        text.contains(&format!(
            "[[revoked_versions]]\nid = \"kz.ecc.market\"\nversion = \"1.0.0\"\ndate = \"{}\"\n",
            day(later)
        )),
        "{text}"
    );
    assert!(!text.contains("1.1.0"), "{text}");
    let report = w.tree(later);
    assert_clean(&report);
    assert!(!report.verified.unwrap().roles[&role("pub-ecc")].delegated);
    let policy = signed_policy(&w);
    let Standing::Retired(rules) = policy.publishers()[1].standing() else {
        panic!("ecc is retired");
    };
    assert!(rules.revokes("kz.ecc.market", &"1.0.0".parse().unwrap()));
    // Settled once: the role is not delegated any more.
    assert!(matches!(
        w.update(later + Duration::days(1), false).unwrap(),
        update::Outcome::UpToDate { .. }
    ));
}

#[test]
fn revoke_all_revokes_every_version_its_role_had_in_git_on_that_date() {
    if !has_git() {
        return;
    }
    let w = online_world();
    let root = w.p("");
    git(&root, &["init", "-q"]);
    git(&root, &["add", "-A"]);
    // The commit of the first release, dated a day before the leak is noticed.
    commit_at(&root, t0());
    // A release after the commit is not in git on any date yet.
    w.release(
        "ecc",
        0,
        2,
        &[("kz.ecc.market", "1.0.0"), ("kz.ecc.market", "2.0.0")],
    );
    // A date after today (UTC) is refused: a revocation is dated when it is made.
    w.write_publisher(
        "ecc",
        0,
        "state = \"retired\"\nrevoke_all = \"2099-12-31\"\n",
    );
    let err = w.update(t1(), false).unwrap_err();
    assert!(format!("{err:#}").contains("after today"), "{err:#}");

    let date = day(t1());
    w.write_publisher(
        "ecc",
        0,
        &format!("state = \"retired\"\nrevoke_all = \"{date}\"   # the leak\n"),
    );
    let found = codes(&w.tree(t1()));
    assert!(found.contains(&"revoke-all-pending"), "{found:?}");
    let update::Outcome::Written(written) = w.update(t1(), false).unwrap() else {
        panic!("revoke_all writes");
    };
    assert!(written.reason.contains("revoke_all"), "{}", written.reason);
    assert_eq!(written.settled[0].added.len(), 1);
    let text = w.publisher_text("ecc");
    assert!(!text.contains("revoke_all"), "{text}");
    let registry = Registry::read(&w.publishers()).unwrap();
    let ecc = registry
        .get(&oncl_update::tuf::PublisherName::parse("ecc").unwrap())
        .unwrap();
    assert_eq!(ecc.state, State::Retired);
    let revoked: Vec<(String, String, String)> = ecc
        .revoked_versions
        .iter()
        .map(|r| (r.id.clone(), r.version.to_string(), r.date.clone()))
        .collect();
    assert_eq!(
        revoked,
        [("kz.ecc.market".to_owned(), "1.0.0".to_owned(), date)]
    );
    assert_clean(&w.tree(t1()));

    // A date before the first commit finds nothing while the role has files: refused, not
    // a revocation of nothing.
    let w = online_world();
    let root = w.p("");
    git(&root, &["init", "-q"]);
    git(&root, &["add", "-A"]);
    commit_at(&root, t0());
    w.write_publisher("ecc", 0, "revoke_all = \"2000-01-01\"\n");
    let before = w.publisher_text("ecc");
    let err = w.update(t1(), false).unwrap_err();
    assert!(format!("{err:#}").contains("finds no version"), "{err:#}");
    assert_eq!(w.publisher_text("ecc"), before);

    // A shallow clone has no history to look in (two commits, so that depth 1 cuts one).
    fs::write(root.join("note.txt"), "x").unwrap();
    git(&root, &["add", "note.txt"]);
    commit_at(&root, t1());
    let shallow = w.p("shallow");
    let path = root.to_string_lossy().replace('\\', "/");
    let url = if path.starts_with('/') {
        format!("file://{path}")
    } else {
        format!("file:///{path}")
    };
    git(
        &root,
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &url,
            &shallow.to_string_lossy(),
        ],
    );
    let copy = world_of(&shallow);
    copy.write_publisher("ecc", 0, &format!("revoke_all = \"{}\"\n", day(t1())));
    let err = copy.update(t1(), false).unwrap_err();
    assert!(format!("{err:#}").contains("shallow"), "{err:#}");
}

/// `git commit` of what is staged in `root`, dated `when`.
fn commit_at(root: &Path, when: OffsetDateTime) {
    let date = format!("@{} +0000", when.unix_timestamp());
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "base",
        ])
        .env("GIT_AUTHOR_DATE", &date)
        .env("GIT_COMMITTER_DATE", &date)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_state_the_client_does_not_know_is_never_signed() {
    let w = online_world();
    let before = files(&w.repo());
    w.write_publisher("ecc", 0, "state = \"suspended\"\n");
    let err = w.update(t1(), false).unwrap_err();
    assert!(format!("{err:#}").contains("suspended"), "{err:#}");
    assert_eq!(files(&w.repo()), before);
    let found = codes(&w.tree(t1()));
    assert!(found.contains(&"publishers-invalid"), "{found:?}");
}

#[test]
fn an_entry_of_publishers_is_never_removed_or_renamed() {
    let w = online_world();
    let before = files(&w.repo());
    let acme = w.publisher_text("acme");
    fs::remove_dir_all(w.publishers().join("acme")).unwrap();
    let found = codes(&w.tree(t1()));
    assert!(found.contains(&"publisher-removed"), "{found:?}");
    let err = w.update(t1(), false).unwrap_err();
    assert!(format!("{err:#}").contains("never removed"), "{err:#}");
    assert_eq!(files(&w.repo()), before);

    // Its prefix changed is the same thing.
    w.write_publisher_toml("acme", &acme.replace("kz.acme.", "kz.acme2."));
    let report = w.tree(t1());
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.code == "publisher-removed" && p.message.contains("kz.acme2.")),
        "{:?}",
        report.problems
    );
    assert!(w.update(t1(), false).is_err());

    // Against the base too.
    if has_git() {
        w.write_publisher_toml("acme", &acme);
        let root = w.p("");
        git(&root, &["init", "-q"]);
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "base"]);
        fs::remove_dir_all(w.publishers().join("acme")).unwrap();
        let report = w.check(Stage::Tree, t1(), false, Some("HEAD"));
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.code == "publisher-removed" && p.message.contains("in the base")),
            "{:?}",
            report.problems
        );
    }
}

#[test]
fn the_delegations_once_there_never_go() {
    let w = online_world();
    let (version, targets) = w.newest_targets();
    let mut signed = targets["signed"].clone();
    signed["version"] = (version + 1).into();
    signed.as_object_mut().unwrap().remove("delegations");
    w.sign_targets(&signed);
    let found = codes(&w.tree(t1()));
    assert!(found.contains(&"delegations-dropped"), "{found:?}");
    assert!(found.contains(&"delegations-mismatch"), "{found:?}");
}

/// Р24: the old key of a publisher goes only after the newest role is signed by the keys
/// that stay; `tuf update` refuses before, `tuf check` finds it, and both accept after.
#[test]
fn a_publisher_key_is_removed_only_after_the_role_is_re_signed() {
    let w = online_world();
    let new_key = format!(
        "[[keys]]\npublic = \"{}\"\n",
        publisher_key(5).public().to_hex()
    );
    // Step 1: the new key beside the old one.
    w.write_publisher("ecc", 0, &new_key);
    w.update(t1(), false).unwrap();
    assert_clean(&w.tree(t1()));

    // The old key removed before the role was re-signed: refused, nothing written.
    let before = files(&w.repo());
    w.write_publisher("ecc", 5, "");
    let e = w.update(t1(), false).unwrap_err();
    let message = format!("{e:#}");
    assert!(
        message.contains("publishers/ecc") && message.contains("Р24"),
        "{message}"
    );
    assert_eq!(files(&w.repo()), before);
    assert!(codes(&w.tree(t1())).contains(&"role-key-removed"));

    // Step 2: the role re-signed with the new key (under the delegation to both keys).
    w.write_publisher("ecc", 0, &new_key);
    w.release("ecc", 5, 2, &[("kz.ecc.market", "1.0.1")]);
    assert_clean(&w.tree(t1()));

    // Step 3: now the old key goes.
    w.write_publisher("ecc", 5, "");
    w.update(t1(), false).unwrap();
    assert_clean(&w.tree(t1()));
}

#[test]
fn a_role_the_client_would_refuse_fails_the_check_and_the_snapshot() {
    let w = online_world();
    // Signed by the other publisher's key.
    w.release("ecc", 1, 2, &[("kz.ecc.market", "1.1.0")]);
    assert!(codes(&w.tree(t1())).contains(&"role"));
    let site = w.copy("site");
    let err = w
        .snapshot(&site, t1(), &w.p("published-offline"), "snapshot.v2.key")
        .unwrap_err();
    assert!(format!("{err:#}").contains("[role]"), "{err:#}");
    fs::remove_file(w.repo().join("metadata/2.pub-ecc.json")).unwrap();

    // A target outside the role's paths: under another publisher's.
    let path = w.repo().join("metadata/2.pub-ecc.json");
    let refs: Vec<(&str, &[u8])> = vec![("plugins/acme/kz.acme.x/1.0.0.onclp", b"x")];
    let signed = build::targets(2, t0() + Duration::days(90), &refs).unwrap();
    fs::write(&path, build::sign(&signed, &[&publisher_key(0)]).unwrap()).unwrap();
    assert!(codes(&w.tree(t1())).contains(&"role"));
    fs::remove_file(&path).unwrap();

    // A gap in the versions, and a role nobody delegated to.
    w.release("ecc", 0, 3, &[("kz.ecc.market", "1.1.0")]);
    w.release("zzz", 7, 1, &[]);
    let found = codes(&w.tree(t1()));
    assert!(found.contains(&"role-gap"), "{found:?}");
    assert!(found.contains(&"role-not-delegated"), "{found:?}");
    fs::remove_file(w.repo().join("metadata/3.pub-ecc.json")).unwrap();
    fs::remove_file(w.repo().join("metadata/1.pub-zzz.json")).unwrap();

    // A role file larger than a client reads.
    let limit = Limits::default().delegated;
    fs::write(
        w.repo().join("metadata/2.pub-ecc.json"),
        vec![b' '; usize::try_from(limit).unwrap() + 1],
    )
    .unwrap();
    assert!(codes(&w.tree(t1())).contains(&"too-large"));
}

#[test]
fn a_role_version_is_history_against_the_base() {
    if !has_git() {
        return;
    }
    let w = online_world();
    let root = w.p("");
    git(&root, &["init", "-q"]);
    git(&root, &["add", "repo"]);
    git(&root, &["commit", "-q", "-m", "base"]);
    let base = Some("HEAD");
    assert_clean(&w.check(Stage::Tree, t1(), false, base));
    // A publisher's release alone is a version bump.
    w.release("ecc", 0, 2, &[("kz.ecc.market", "1.1.0")]);
    assert_clean(&w.check(Stage::Tree, t1(), false, base));
    // A role file gone is history rewritten.
    fs::remove_file(w.repo().join("metadata/2.pub-ecc.json")).unwrap();
    fs::remove_file(w.repo().join("metadata/1.pub-ecc.json")).unwrap();
    let found = codes(&w.check(Stage::Tree, t1(), false, base));
    assert!(found.contains(&"file-removed"), "{found:?}");
    assert!(found.contains(&"version-rollback"), "{found:?}");
}

/// Before the rotation the owner signs the snapshot: the first publisher waits for it, or
/// every release would wait for the owner (Р35).
#[test]
fn the_first_publisher_waits_for_the_online_snapshot() {
    let w = world();
    let before = files(&w.repo());
    w.write_publisher("ecc", 0, "");
    let err = w.update(t0() + Duration::days(1), false).unwrap_err();
    assert!(format!("{err:#}").contains("online snapshot"), "{err:#}");
    assert_eq!(files(&w.repo()), before);
}

/// The delegations share the client's 256 KiB of the top-level targets with the targets: a
/// file past three quarters of it is a warning.
#[test]
fn top_level_targets_near_the_client_limit_are_a_warning() {
    let w = online_world();
    assert!(
        !w.tree(t1())
            .warnings
            .iter()
            .any(|p| p.code == "targets-large")
    );
    let (version, targets) = w.newest_targets();
    let mut signed = targets["signed"].clone();
    signed["version"] = (version + 1).into();
    signed["targets"]["indexes/stable.json"]["custom"] = json!({"pad": "x".repeat(200 << 10)});
    w.sign_targets(&signed);
    let report = w.tree(t1());
    assert!(
        report.warnings.iter().any(|p| p.code == "targets-large"),
        "{:?}",
        report.warnings
    );
}

#[test]
fn the_check_command_reads_the_publishers_and_the_snapshot_mode() {
    let w = online_world();
    let s = |p: PathBuf| p.to_string_lossy().into_owned();
    let run = || {
        xtask(&[
            "check",
            "--dir",
            &s(w.repo()),
            "--anchor",
            &s(w.anchor()),
            "--index",
            &s(w.indexes()),
            "--publishers",
            &s(w.publishers()),
            "--config",
            &s(w.config()),
            "--no-timestamp",
            "--now",
            &t1().unix_timestamp().to_string(),
        ])
    };
    let ok = run();
    let text = String::from_utf8_lossy(&ok.stdout);
    assert!(
        ok.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    for line in [
        "tuf check: root 2, targets 2, snapshot absent, timestamp absent",
        "tuf check: pub-ecc 1, delegated",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
    assert!(text.trim_end().ends_with("tuf check: ok"), "{text}");
    // A registry that differs fails.
    w.write_publisher(
        "ecc",
        0,
        "[[revoked_versions]]\nid = \"kz.ecc.market\"\nversion = \"1.0.0\"\ndate = \"2026-09-20\"\n",
    );
    let fail = run();
    assert_eq!(fail.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&fail.stderr).contains("tuf check: error[publishers-mismatch]: "),
        "{}",
        String::from_utf8_lossy(&fail.stderr)
    );
}
