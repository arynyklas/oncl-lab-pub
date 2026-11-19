//! The repository over a fake transport serving a TUF repository of synthetic keys.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oncl_pki::http::HttpTransport;
use oncl_update::tuf::PublicKey;
use oncl_update::tuf::store::{FileStore, Store};
use oncl_update::tuf::testing::Repo;
use oncl_update::{Channel, Index, UpdateError};
use serde_json::{Map, Value, json};
use time::{Duration as TimeDuration, OffsetDateTime};

use super::Repository;
use crate::update::tests::FakeTransport;

/// Where the fake repository is "published".
pub(crate) const BASE: &str = "https://example.org/tuf/v1";

/// The URL of `path` of the repository.
pub(crate) fn url(path: &str) -> String {
    format!("{BASE}/{path}")
}

/// The URL of the timestamp.
pub(crate) fn timestamp_url() -> String {
    url("metadata/timestamp.json")
}

/// The URL whose requests count the downloads of the index: every refresh asks first for the
/// next root, whatever else fails after it.
pub(crate) fn refresh_url() -> String {
    url("metadata/2.root.json")
}

/// A TUF repository of synthetic keys, and the way it is put on a [`FakeTransport`].
pub(crate) struct Server {
    pub(crate) repo: Mutex<Repo>,
}

impl Server {
    pub(crate) fn new() -> Server {
        Server {
            repo: Mutex::new(Repo::new()),
        }
    }

    /// The root the clients are built with.
    pub(crate) fn anchor(&self) -> Vec<u8> {
        self.repo().anchor().to_vec()
    }

    pub(crate) fn repo(&self) -> std::sync::MutexGuard<'_, Repo> {
        self.repo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publishes `body` as the index of `channel` and serves every file of the repository.
    pub(crate) fn publish(&self, transport: &FakeTransport, channel: Channel, body: &[u8]) {
        self.repo().publish(channel, body);
        self.serve(transport);
    }

    /// Serves every file of the repository; the next root is not there.
    pub(crate) fn serve(&self, transport: &FakeTransport) {
        for (path, bytes) in self.repo().files() {
            transport.serve(&url(path), bytes);
        }
        transport.reply(&url("metadata/2.root.json"), 404, b"");
    }
}

/// An empty index of `channel`.
pub(crate) fn index(channel: Channel, seq: u64) -> Vec<u8> {
    let generated = OffsetDateTime::now_utc() - TimeDuration::hours(1);
    serde_json::to_vec_pretty(&Index {
        schema: 1,
        channel,
        seq,
        generated,
        expires: generated + TimeDuration::days(14),
        core: Vec::new(),
        extension: None,
        plugins: Vec::new(),
    })
    .unwrap()
}

/// `delegations` members the top-level targets of `tuf/v1` may carry, by what they are:
/// none of them is the concern of the program's updates.
pub(crate) fn delegations_members() -> [(&'static str, Value); 3] {
    let key = PublicKey::from_bytes([9; 32]);
    let keyid = key.key_id().to_hex();
    let keys: Map<String, Value> = [(keyid.clone(), key.to_value())].into_iter().collect();
    [
        ("empty", json!({"keys": {}, "roles": []})),
        (
            "one role",
            json!({
                "keys": keys,
                "roles": [{
                    "name": "pub-acme", "keyids": [keyid], "threshold": 1,
                    "paths": ["plugins/acme/*/*"], "terminating": true,
                }],
            }),
        ),
        ("unreadable", json!({"keys": {}, "roles": 7})),
    ]
}

const TIMEOUT: Duration = Duration::from_secs(20);

fn repository(
    server: &Server,
    dir: &std::path::Path,
    transport: &Arc<FakeTransport>,
) -> Repository {
    Repository::with_anchor(
        &server.anchor(),
        dir,
        BASE,
        Arc::clone(transport) as Arc<dyn HttpTransport>,
    )
    .unwrap()
}

fn refused(e: &UpdateError) -> bool {
    matches!(e, UpdateError::Tuf(_)) && !e.retry_soon()
}

#[test]
fn the_index_is_read_through_tuf_and_held_to_its_channel_and_seq() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    let body = index(Channel::Stable, 7);
    server.publish(&transport, Channel::Stable, &body);
    let r = repository(&server, dir.path(), &transport);

    let got = r.index(Channel::Stable, Some(7), TIMEOUT).unwrap();
    assert_eq!((got.index.seq, got.bytes.as_slice()), (7, body.as_slice()));
    // It holds until the first of the root's and the targets' expiry: 30 days.
    let left = got.valid_until - OffsetDateTime::now_utc();
    assert!(
        left > TimeDuration::days(29) && left <= TimeDuration::days(30),
        "{left}"
    );
    // Every request is HTTPS only, within the size of the file it is for.
    assert!(
        transport
            .asked()
            .iter()
            .all(|(_, _, https_only)| *https_only)
    );

    // An index whose `seq` went back, or of another channel, is refused though the
    // repository vouches for it.
    let e = r.index(Channel::Stable, Some(8), TIMEOUT).unwrap_err();
    assert!(
        matches!(e, UpdateError::Rollback { seq: 7, last: 8 }),
        "{e}"
    );
    assert!(!e.retry_soon());
    server.publish(&transport, Channel::Beta, &index(Channel::Stable, 9));
    let e = r.index(Channel::Beta, None, TIMEOUT).unwrap_err();
    assert!(matches!(e, UpdateError::WrongChannel { .. }), "{e}");
    // The age of the index (generated long ago, expires in the past) is not what ends it.
    let old = {
        let generated = OffsetDateTime::now_utc() - TimeDuration::days(90);
        let mut v: serde_json::Value = serde_json::from_slice(&index(Channel::Stable, 10)).unwrap();
        v["generated"] = serde_json::json!(
            generated
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        );
        v["expires"] = v["generated"].clone();
        serde_json::to_vec(&v).unwrap()
    };
    server.publish(&transport, Channel::Stable, &old);
    assert_eq!(
        r.index(Channel::Stable, Some(10), TIMEOUT)
            .unwrap()
            .index
            .seq,
        10
    );
}

#[test]
fn a_rolled_back_timestamp_is_refused_by_every_handle_on_the_state() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let old_timestamp = server
        .repo()
        .get("metadata/timestamp.json")
        .unwrap()
        .to_vec();
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 2));

    // One handle (the updater's) takes the newer; another (the plugin catalog's, as a
    // second process would be) on the same directory, shown the older one, refuses it.
    let updater = repository(&server, dir.path(), &transport);
    assert_eq!(
        updater
            .index(Channel::Stable, None, TIMEOUT)
            .unwrap()
            .index
            .seq,
        2
    );
    transport.serve(&timestamp_url(), &old_timestamp);
    let catalog = repository(&server, dir.path(), &transport);
    let e = catalog.index(Channel::Stable, None, TIMEOUT).unwrap_err();
    assert!(refused(&e), "{e}");
    assert!(e.to_string().contains("was trusted before"), "{e}");
    // The same one, on a directory that has seen nothing, takes it: only the state refuses.
    let fresh = tempfile::tempdir().unwrap();
    assert_eq!(
        repository(&server, fresh.path(), &transport)
            .index(Channel::Stable, None, TIMEOUT)
            .unwrap()
            .index
            .seq,
        1
    );
}

#[test]
fn what_each_handle_saves_the_other_keeps() {
    // `a` is in the middle of a refresh (it has accepted timestamp 1, and holds its state in
    // memory) when `b` takes a newer publication and saves it. What `a` saves next must not
    // lower what `b` saved: the saved versions are the highest of both.
    let server = Arc::new(Server::new());
    let transport = Arc::new(FakeTransport::default());
    let dir = tempfile::tempdir().unwrap();
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let a = repository(&server, dir.path(), &transport);
    let b = Arc::new(repository(&server, dir.path(), &transport));
    let (s, t, b2) = (Arc::clone(&server), Arc::clone(&transport), Arc::clone(&b));
    transport.during(&url("metadata/1.snapshot.json"), move || {
        s.publish(&t, Channel::Stable, &index(Channel::Stable, 2));
        b2.index(Channel::Stable, None, TIMEOUT).unwrap();
    });
    // `a`'s own save of its older snapshot merges into the newer state it learns of, and it is
    // then refused (its targets are older than `b`'s) instead of lowering anything.
    let e = a.index(Channel::Stable, None, TIMEOUT).unwrap_err();
    assert!(e.to_string().contains("was trusted before"), "{e}");
    let saved = FileStore::in_data_dir(dir.path()).load().unwrap();
    assert_eq!(saved.timestamp.unwrap().version, 1_000_001, "b's timestamp");
    assert_eq!(saved.snapshot.unwrap().version, 2, "b's snapshot");
    assert_eq!(
        saved.targets,
        Some(2),
        "b's targets, which a's older ones did not lower"
    );
}

#[test]
fn an_expired_timestamp_a_tampered_index_and_a_wrong_key_are_refused() {
    let transport = Arc::new(FakeTransport::default());
    let dir = tempfile::tempdir().unwrap();
    let server = Server::new();
    // Signed 8 days ago: the timestamp's 7 days are over.
    server.repo().signed_at = OffsetDateTime::now_utc() - TimeDuration::days(8);
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let r = repository(&server, dir.path(), &transport);
    let e = r.index(Channel::Stable, None, TIMEOUT).unwrap_err();
    assert!(refused(&e) && e.to_string().contains("expired"), "{e}");

    // The index file served is not the one the targets list.
    let server = Server::new();
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let path = server.repo().index_file_path(Channel::Stable);
    let mut body = server.repo().get(&path).unwrap().to_vec();
    body[10] ^= 1;
    transport.serve(&url(&path), &body);
    let dir = tempfile::tempdir().unwrap();
    let e = repository(&server, dir.path(), &transport)
        .index(Channel::Stable, None, TIMEOUT)
        .unwrap_err();
    assert!(
        refused(&e) && e.to_string().contains("does not match"),
        "{e}"
    );

    // A repository of other keys than the root built in.
    let hostile = Server::new();
    *hostile.repo() = Repo::with_seed(41);
    hostile.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let dir = tempfile::tempdir().unwrap();
    let e = repository(&server, dir.path(), &transport)
        .index(Channel::Stable, None, TIMEOUT)
        .unwrap_err();
    assert!(refused(&e) && e.to_string().contains("signatures"), "{e}");
}

#[test]
fn a_repository_that_is_not_there_is_not_published_and_one_that_cannot_be_read_is_retried() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    let r = repository(&server, dir.path(), &transport);
    // Nothing answers: retry soon.
    let e = r.index(Channel::Stable, None, TIMEOUT).unwrap_err();
    assert!(e.retry_soon(), "{e}");
    // 404 for the timestamp: not published.
    transport.reply(&timestamp_url(), 404, b"");
    transport.reply(&url("metadata/2.root.json"), 404, b"");
    assert!(matches!(
        r.index(Channel::Stable, None, TIMEOUT),
        Err(UpdateError::NotPublished(Channel::Stable))
    ));
    // Published, but the channel has no entry in the targets: not published either.
    server.publish(&transport, Channel::Beta, &index(Channel::Beta, 1));
    assert!(matches!(
        r.index(Channel::Stable, None, TIMEOUT),
        Err(UpdateError::NotPublished(Channel::Stable))
    ));
    r.index(Channel::Beta, None, TIMEOUT).unwrap();
    // A server error: retry soon; no time left: the same.
    transport.reply(&timestamp_url(), 503, b"");
    let e = r.index(Channel::Beta, None, TIMEOUT).unwrap_err();
    assert!(e.retry_soon() && e.to_string().contains("HTTP 503"), "{e}");
    let e = r.index(Channel::Beta, None, Duration::ZERO).unwrap_err();
    assert!(
        e.retry_soon() && e.to_string().contains("no time left"),
        "{e}"
    );
}

#[test]
fn a_kept_index_is_checked_offline_against_the_saved_targets() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    let body = index(Channel::Stable, 3);
    server.publish(&transport, Channel::Stable, &body);
    let r = repository(&server, dir.path(), &transport);
    let now = OffsetDateTime::now_utc();
    // Before any refresh nothing is vouched for.
    assert!(r.verify_kept(Channel::Stable, &body, now).is_err());
    r.index(Channel::Stable, None, TIMEOUT).unwrap();
    let asked = transport.asked().len();

    let until = r.verify_kept(Channel::Stable, &body, now).unwrap();
    assert!(until > now + TimeDuration::days(29));
    assert!(
        r.verify_kept(Channel::Stable, &index(Channel::Stable, 4), now)
            .is_err()
    );
    assert!(r.verify_kept(Channel::Beta, &body, now).is_err());
    assert!(
        r.verify_kept(Channel::Stable, &body, now + TimeDuration::days(31))
            .is_err()
    );
    assert_eq!(transport.asked().len(), asked, "no request was made");
}

#[test]
fn the_updater_reads_tuf_v1_with_delegations() {
    for (what, delegations) in delegations_members() {
        let (server, transport, dir) = (
            Server::new(),
            Arc::new(FakeTransport::default()),
            tempfile::tempdir().unwrap(),
        );
        server.repo().delegations = Some(delegations);
        let body = index(Channel::Stable, 5);
        server.publish(&transport, Channel::Stable, &body);
        let r = repository(&server, dir.path(), &transport);
        let got = r
            .index(Channel::Stable, None, TIMEOUT)
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!((got.index.seq, got.bytes), (5, body.clone()), "{what}");
        let now = OffsetDateTime::now_utc();
        let until = r
            .verify_kept(Channel::Stable, &body, now)
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(until > now + TimeDuration::days(29), "{what}");
    }
}

#[test]
fn a_file_missing_from_a_published_repository_is_a_refusal_not_a_missing_channel() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let r = repository(&server, dir.path(), &transport);
    r.index(Channel::Stable, None, TIMEOUT).unwrap();
    let file = url(&server.repo().index_file_path(Channel::Stable));
    for missing in [
        timestamp_url(),
        url("metadata/1.snapshot.json"),
        url("metadata/1.targets.json"),
        file,
    ] {
        let saved = transport.reply_of(&missing);
        transport.reply(&missing, 404, b"");
        let e = r.index(Channel::Stable, None, TIMEOUT).unwrap_err();
        assert!(matches!(&e, UpdateError::Tuf(_)), "{missing}: {e}");
        assert!(e.retry_soon(), "{missing}: the short interval");
        transport.reply(&missing, saved.0, &saved.1);
    }
    r.index(Channel::Stable, None, TIMEOUT).unwrap();
    // The same 404 for the timestamp on a state that has accepted nothing: not published.
    let fresh = tempfile::tempdir().unwrap();
    transport.reply(&timestamp_url(), 404, b"");
    assert!(matches!(
        repository(&server, fresh.path(), &transport).index(Channel::Stable, None, TIMEOUT),
        Err(UpdateError::NotPublished(Channel::Stable))
    ));
}

#[test]
fn a_caller_waiting_for_another_check_keeps_to_its_own_deadline() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let r = Arc::new(repository(&server, dir.path(), &transport));
    // While the first check is at its first request, a second one, with 300 ms, asks from
    // another thread; the first waits for its answer for up to 10 s, which is a failure.
    let (r2, outcome) = (Arc::clone(&r), Arc::new(Mutex::new(None)));
    let o = Arc::clone(&outcome);
    transport.during(&refresh_url(), move || {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let e = r2
                .index(Channel::Stable, None, Duration::from_millis(300))
                .unwrap_err();
            let _ = tx.send((e, started.elapsed()));
        });
        let got = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the second call did not return within its own deadline");
        *o.lock().unwrap() = Some(got);
    });
    r.index(Channel::Stable, None, TIMEOUT).unwrap();
    let (e, waited) = outcome.lock().unwrap().take().unwrap();
    assert!(
        e.retry_soon() && e.to_string().contains("no time left"),
        "{e}"
    );
    assert!(
        waited >= Duration::from_millis(300) && waited < Duration::from_secs(5),
        "{waited:?}"
    );
}

#[test]
fn a_404_for_the_timestamp_after_a_reset_of_the_state_is_still_a_refusal() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let r = repository(&server, dir.path(), &transport);
    r.index(Channel::Stable, None, TIMEOUT).unwrap();
    let state = FileStore::in_data_dir(dir.path()).path();
    std::fs::write(&state, b"nope").unwrap();
    transport.reply(&timestamp_url(), 404, b"");
    // Run 1: the state did not hold; run 2: the reset state. Neither is "not published".
    for run in 1..=2 {
        let e = repository(&server, dir.path(), &transport)
            .index(Channel::Stable, None, TIMEOUT)
            .unwrap_err();
        assert!(
            matches!(&e, UpdateError::Tuf(_)) && e.retry_soon(),
            "run {run}: {e}"
        );
    }
}

#[test]
fn no_usable_root_means_no_repository_and_nothing_asked() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(FakeTransport::default());
    let open = |root: Option<&[u8]>| {
        Repository::from_root(
            root,
            dir.path(),
            BASE,
            Arc::clone(&transport) as Arc<dyn HttpTransport>,
        )
    };
    assert!(open(None).is_none(), "no root built in");
    assert!(
        open(Some(b"not a root")).is_none(),
        "a root that is not one"
    );
    assert!(transport.asked().is_empty());
    let server = Server::new();
    assert!(open(Some(&server.anchor())).is_some());
    // A base that is not HTTPS is no repository either.
    let other: Arc<dyn HttpTransport> = Arc::new(FakeTransport::default());
    assert!(
        Repository::with_anchor(
            &server.anchor(),
            dir.path(),
            "http://example.org/tuf",
            other
        )
        .is_err()
    );
}
