//! The snapshot of `tuf/v1` moved into CI (`docs/design/publishers.md`, "Онлайн-снимок",
//! Р8, Р25): `tuf root --rotate-snapshot --online`, `tuf update` without a snapshot,
//! `tuf snapshot` over the published site, and the clients released before and after
//! delegations over the result.

use std::fs;
use std::path::PathBuf;

use oncl_update::tuf::{Limits, MemoryStore, Profile, Role, TufClient, build};
use time::Duration;
use xtask::tuf::check::Stage;
use xtask::tuf::published::{self, Published};
use xtask::tuf::repo::{DirFetcher, SnapshotMode};
use xtask::tuf::{keystore, update};

use super::delegations::{online_world, t1};
use super::{codes, copy_dir, files, t0, world, xtask};

#[test]
fn rotating_the_snapshot_key_online_moves_it_into_ci() {
    let w = world();
    let now = t0() + Duration::days(1);
    let err = w.root(now, &[], true).unwrap_err();
    assert!(err.to_string().contains("--online"), "{err}");
    assert!(!w.repo().join("metadata/2.root.json").exists());

    let rotated = w.root(now, &[Role::Snapshot], true).unwrap();
    assert_eq!(rotated.mode, SnapshotMode::Online);
    assert_eq!(rotated.config.as_deref(), Some(w.config().as_path()));
    assert_eq!(w.mode(), SnapshotMode::Online);
    let (role, id, path) = &rotated.new_keys[0];
    assert_eq!(*role, Role::Snapshot);
    let key = keystore::parse_seed(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(key.key_id(), *id);

    // The committed tree holds as it is: its snapshots are the owner's old ones.
    let report = w.tree(now);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert!(report.verified.unwrap().snapshot.is_none());
    // `tuf update` has nothing to sign, and a refresh signs the targets alone.
    assert!(matches!(
        w.update(now, false).unwrap(),
        update::Outcome::UpToDate {
            targets: 1,
            snapshot: None
        }
    ));
    let update::Outcome::Written(written) = w.update(now, true).unwrap() else {
        panic!("a refresh writes");
    };
    assert_eq!((written.targets, written.snapshot), (2, None));
    assert_eq!(written.files, [w.repo().join("metadata/2.targets.json")]);
    assert!(w.tree(now).problems.is_empty());

    // A snapshot signed by the key in force is never committed.
    let targets = fs::read(w.repo().join("metadata/2.targets.json")).unwrap();
    let signed = build::snapshot(9, now + Duration::days(7), 2, &targets).unwrap();
    fs::write(
        w.repo().join("metadata/9.snapshot.json"),
        build::sign(&signed, &[&key]).unwrap(),
    )
    .unwrap();
    assert!(codes(&w.tree(now)).contains(&"snapshot-committed"));
}

/// Stage 2 of the rollout: the first online snapshot extends the owner's last offline one,
/// which the root before the rotation signed, and every client follows it: those released
/// before delegations too.
#[test]
fn the_first_online_snapshot_extends_the_published_offline_one() {
    let w = world();
    let published = w.p("published");
    copy_dir(&w.repo(), &published);
    w.timestamp_at(
        &published,
        t0() + Duration::hours(1),
        &w.keys().join("timestamp.key"),
    )
    .unwrap();
    let now = t0() + Duration::days(1);
    w.root(now, &[Role::Snapshot], true).unwrap();

    let site = w.copy("site");
    let signed = w
        .snapshot(&site, now, &published, "snapshot.v2.key")
        .unwrap();
    assert_eq!(signed.version, now.unix_timestamp() as u64);
    assert_eq!(signed.previous.0, 1);
    assert_eq!((signed.targets, signed.roles), (1, 0));
    assert_eq!(signed.expires, now + Duration::days(7));
    w.timestamp_at(&site, now, &w.keys().join("timestamp.key"))
        .unwrap();
    let report = w.check_dir(&site, Stage::Published, now, true, None);
    assert!(report.problems.is_empty(), "{:?}", report.problems);

    let anchor = fs::read(w.anchor()).unwrap();
    for profile in [Profile::Legacy, Profile::Delegating] {
        let mut client = TufClient::new(
            &anchor,
            DirFetcher::new(&site),
            MemoryStore::default(),
            Limits::default(),
        )
        .unwrap()
        .with_profile(profile);
        let trusted = client.refresh(now).unwrap();
        assert_eq!(trusted.root().version, 2, "{profile:?}");
        assert_eq!(trusted.snapshot().version, signed.version, "{profile:?}");
    }
    let Published::Verified { lines } =
        published::verify_published(DirFetcher::new(&site), &anchor, now, false).unwrap()
    else {
        panic!("published");
    };
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("clients 0.1.0 and 0.1.1 read it")),
        "{lines:?}"
    );

    // The next publication, at the same second, extends this one by one version.
    let next = w.copy("next");
    let again = w.snapshot(&next, now, &site, "snapshot.v2.key").unwrap();
    assert_eq!(again.version, signed.version + 1);
}

#[test]
fn a_publisher_release_needs_no_owner_signature_once_the_snapshot_is_online() {
    let w = online_world();
    let first = w.publish("first", t1(), None);
    w.release(
        "ecc",
        0,
        2,
        &[("kz.ecc.market", "1.0.0"), ("kz.ecc.market", "1.1.0")],
    );
    // Nothing for the owner to sign: the tree holds, and CI's snapshot lists the role.
    assert!(matches!(
        w.update(t1(), false).unwrap(),
        update::Outcome::UpToDate { .. }
    ));
    assert!(w.tree(t1()).problems.is_empty());
    let second = w.publish("second", t1(), Some(&first));
    let report = w.check_dir(&second, Stage::Published, t1(), false, None);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(
        report.verified.unwrap().snapshot.unwrap().meta["pub-ecc.json"].version,
        2
    );

    // A tree that lost the role file would drop it from the snapshot: refused.
    let lost = w.copy("lost");
    fs::remove_file(lost.join("metadata/1.pub-ecc.json")).unwrap();
    fs::remove_file(lost.join("metadata/2.pub-ecc.json")).unwrap();
    let err = w
        .snapshot(&lost, t1(), &second, "snapshot.v2.key")
        .unwrap_err();
    assert!(format!("{err:#}").contains("snapshot-rollback"), "{err:#}");
    assert_eq!(
        files(&lost)
            .iter()
            .filter(|f| f.ends_with(".snapshot.json"))
            .collect::<Vec<_>>(),
        ["metadata/1.snapshot.json"]
    );
}

#[test]
fn the_snapshot_refuses_what_it_cannot_extend() {
    // The snapshot is offline: the owner signs it.
    let w = world();
    let site = w.copy("site");
    let err = w
        .snapshot(&site, t1(), &w.repo(), "snapshot.key")
        .unwrap_err();
    assert!(err.to_string().contains("offline"), "{err:#}");

    let w = online_world();
    let unchanged = |dir: &PathBuf| {
        assert!(
            !files(dir)
                .iter()
                .any(|f| f.ends_with(".snapshot.json") && !f.starts_with("metadata/1.")),
            "a snapshot was made"
        );
    };
    // A site without a timestamp: no way around it (Р25).
    let site = w.copy("site");
    let err = w
        .snapshot(&site, t1(), &w.repo(), "snapshot.v2.key")
        .unwrap_err();
    assert!(format!("{err:#}").contains("Р25"), "{err:#}");
    unchanged(&site);
    // The key of the root before the rotation, or another one.
    let (_, line) = keystore::generate_seed().unwrap();
    fs::write(w.keys().join("other.key"), line.as_bytes()).unwrap();
    let err = w
        .snapshot(&site, t1(), &w.p("published-offline"), "other.key")
        .unwrap_err();
    assert!(err.to_string().contains("is not a snapshot key"), "{err:#}");
    unchanged(&site);

    // A published snapshot far ahead of the clock (here the last version, which would have no
    // next one) is not extended.
    let published = w.p("published-offline");
    let seed = keystore::parse_seed(&fs::read_to_string(w.keys().join("snapshot.v2.key")).unwrap())
        .unwrap();
    let targets = fs::read(published.join("metadata/1.targets.json")).unwrap();
    let snapshot = build::sign(
        &build::snapshot(u64::MAX, t1() + Duration::days(7), 1, &targets).unwrap(),
        &[&seed],
    )
    .unwrap();
    fs::write(
        published.join(format!("metadata/{}.snapshot.json", u64::MAX)),
        &snapshot,
    )
    .unwrap();
    let timestamp_key =
        keystore::parse_seed(&fs::read_to_string(w.keys().join("timestamp.key")).unwrap()).unwrap();
    fs::write(
        published.join("metadata/timestamp.json"),
        build::sign(
            &build::timestamp(2, t1() + Duration::days(7), u64::MAX, &snapshot).unwrap(),
            &[&timestamp_key],
        )
        .unwrap(),
    )
    .unwrap();
    let err = w
        .snapshot(&site, t1(), &published, "snapshot.v2.key")
        .unwrap_err();
    assert!(format!("{err:#}").contains("ahead of the clock"), "{err:#}");
    unchanged(&site);

    // The command line wants the published site.
    let neither = xtask(&["snapshot", "--out", &site.to_string_lossy()]);
    assert_eq!(neither.status.code(), Some(2));
}
