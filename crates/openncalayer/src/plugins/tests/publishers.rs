//! The catalog with a third-party publisher, `acme` (`docs/design/publishers.md`), served by
//! the sandbox's repository with its delegation, its role and `publishers.json`: its plugin
//! offered, installed with its publisher and updated; kept, withdrawn or turned off by the
//! states of `publishers.json` and of its role; with updates off only revocations; how often
//! the catalog is checked; and the kept catalog checked again offline. A port acme replaces:
//! [`replacement`].

use oncl_update::PublisherPolicy;
use oncl_update::catalog::MIRROR_BASE;
use oncl_update::tuf::{RoleName, SigningKey, testing};
use serde_json::{Map, Value};

use super::*;
use crate::plugins::catalog::PUBLISHER_CHECK_EVERY;

mod replacement;

const ACME_ID: &str = "kz.acme.example";
const ACME_MODULE: &str = "kz.acme.Example";
const ACME_BUNDLE: &str = "kz.acme.echo";

fn acme() -> PublisherName {
    PublisherName::parse("acme").unwrap()
}

fn acme_role() -> RoleName {
    RoleName::parse("pub-acme").unwrap()
}

fn acme_key() -> SigningKey {
    SigningKey::from_seed(&[77; 32]).unwrap()
}

fn acme_display() -> Localized {
    Localized {
        ru: "ТОО «Акме»".to_owned(),
        kk: "«Акме» ЖШС".to_owned(),
        en: "Acme LLP".to_owned(),
    }
}

/// The example plugin as acme's: its id, module and bundle under acme's prefix.
fn acme_package(version: &str) -> Vec<u8> {
    example_at(version, |m| {
        m.replace(ID, ACME_ID)
            .replace(MODULE, ACME_MODULE)
            .replace("kz.example.echo", ACME_BUNDLE)
    })
}

/// acme's entry of `publishers.json` in `state`.
fn entry(state: &str) -> Value {
    let display = acme_display();
    let mut entry = json!({
        "name": "acme", "state": state,
        "display": {"ru": display.ru, "kk": display.kk, "en": display.en},
        "id_prefix": "kz.acme.",
        "modules": [ACME_MODULE],
        "bundles": [ACME_BUNDLE],
    });
    if state == "revoked" {
        entry["revoked"] = json!("2027-03-01");
    }
    entry
}

/// `entry` with the owner's revocation of `version`.
fn revoking(mut entry: Value, version: &str) -> Value {
    entry["revoked_versions"] = json!([{"id": ACME_ID, "version": version, "date": "2027-04-01"}]);
    entry
}

fn policy(publishers: Vec<Value>) -> Value {
    json!({"schema": 1, "publishers": publishers})
}

/// acme's target of release `version` of `bytes`, the package served at its copy in the
/// project's Releases; `edit` changes its `custom.oncl`.
fn release(
    sandbox: &Sandbox,
    version: &str,
    bytes: &[u8],
    edit: impl FnOnce(&mut Value),
) -> (String, Value) {
    let sha256 = Sha256::of(bytes).to_string();
    let url = format!("{MIRROR_BASE}pub-acme-{sha256}/{ACME_ID}-{version}.onclp");
    sandbox.transport.serve(&url, bytes);
    let mut oncl = json!({
        "schema": 1, "id": ACME_ID, "version": version, "url": url,
        "source": {
            "archive_sha256": "ab".repeat(32),
            "archive_length": 2_345_678,
            "fetch": format!("https://downloads.acme.kz/{ACME_ID}-{version}.src.tar.gz"),
            "path": "plugin",
            "license": "Apache-2.0",
            "builder": format!("sha256:{}", "cd".repeat(32)),
        },
        "channel": "stable", "min_core": "0.1.0-alpha.2",
        "modules": [ACME_MODULE],
        "replaces": {"symname": ACME_BUNDLE, "version": "1.0.0"},
        "name": {"ru": "Пример плагина", "kk": "Плагин үлгісі", "en": "Example plugin"},
        "capabilities": {
            "keys": true, "dialogs": true, "files": true,
            "http": ["https://example.invalid/"],
        },
        "rollout": 100, "revoked": false,
    });
    edit(&mut oncl);
    let target = json!({
        "length": bytes.len(),
        "hashes": {"sha256": sha256},
        "custom": {"oncl": oncl},
    });
    (format!("plugins/acme/{ACME_ID}/{version}.onclp"), target)
}

/// acme's release `version` as published.
fn plain(sandbox: &Sandbox, version: &str) -> (String, Value) {
    release(sandbox, version, &acme_package(version), |_| {})
}

/// The targets of acme's role listing `releases`.
fn role(releases: &[(String, Value)]) -> Map<String, Value> {
    releases.iter().cloned().collect()
}

/// The URL of acme's package `version`, as `release` serves it.
fn package_url_of(version: &str) -> String {
    let sha256 = Sha256::of(&acme_package(version)).to_string();
    format!("{MIRROR_BASE}pub-acme-{sha256}/{ACME_ID}-{version}.onclp")
}

fn downloads(sandbox: &Sandbox, version: &str) -> usize {
    let url = package_url_of(version);
    sandbox
        .transport
        .asked()
        .iter()
        .filter(|(asked, ..)| *asked == url)
        .count()
}

/// Publishes the stable catalog `seq` (an owner's index without plugins) with `policy` as
/// `publishers.json` (none: not listed) and, if `role`, acme's delegated role of that
/// version listing those targets, signed by acme's key (none: no delegations; the role's
/// last file stays listed in the snapshot).
fn publish(
    sandbox: &Sandbox,
    seq: u64,
    policy: Option<&Value>,
    role: Option<(u64, Map<String, Value>)>,
) {
    publish_with(sandbox, seq, Vec::new(), policy, role);
}

/// [`publish`] with `ports` in the owner's index.
fn publish_with(
    sandbox: &Sandbox,
    seq: u64,
    ports: Vec<PluginRelease>,
    policy: Option<&Value>,
    role: Option<(u64, Map<String, Value>)>,
) {
    {
        let mut repo = sandbox.server.repo();
        match policy {
            Some(policy) => {
                repo.set_target(
                    PublisherPolicy::TARGET,
                    &serde_json::to_vec(policy).unwrap(),
                );
            }
            None => repo.remove_target(PublisherPolicy::TARGET),
        }
        match role {
            Some((version, targets)) => {
                let file = repo.role_file(version, targets, &[&acme_key()]);
                repo.set_role(&acme_role(), version, file);
                repo.delegations = Some(testing::delegations(&[(&acme_role(), &acme_key())]));
            }
            None => repo.delegations = None,
        }
    }
    sandbox.publish(seq, ports);
}

fn installed(sandbox: &Sandbox) -> Installed {
    sandbox.store().state().plugins[ACME_ID].clone()
}

/// acme's 1.0.0 installed from the catalog `seq` 1 (role version 1); its target returned.
fn acme_installed(sandbox: &Sandbox, service: &Arc<PluginService>) -> (String, Value) {
    let first = plain(sandbox, "1.0.0");
    publish(
        sandbox,
        1,
        Some(&policy(vec![entry("active")])),
        Some((1, role(std::slice::from_ref(&first)))),
    );
    service.check_now();
    service.install_from_catalog(ACME_ID, None).unwrap();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Installed { name: name() }]
    );
    sandbox.requests();
    first
}

/// acme's plugin runs as it did: 1.0.0, loaded, not withdrawn, nothing told.
fn kept(sandbox: &Sandbox) {
    assert!(sandbox.notices().is_empty());
    let installed = installed(sandbox);
    assert_eq!(installed.version, v("1.0.0"));
    assert!(installed.enabled && !installed.withdrawn);
    assert_eq!(sandbox.modules.names(), [ACME_MODULE]);
}

#[test]
fn a_publishers_plugin_is_offered_installed_with_its_publisher_and_updated() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = plain(&sandbox, "1.0.0");
    publish(
        &sandbox,
        1,
        Some(&policy(vec![entry("active")])),
        Some((1, role(std::slice::from_ref(&first)))),
    );
    service.check_now();
    let view = service.view();
    assert_eq!(
        view.available
            .iter()
            .map(|a| (a.id.as_str(), a.version.clone()))
            .collect::<Vec<_>>(),
        [(ACME_ID, v("1.0.0"))]
    );
    // Named by its publisher, its source archive beside its package in the project's
    // Releases (not the publisher's `fetch`), its license from the signed release.
    let acme_origin = |version: &str| ReleaseOrigin::Publisher {
        display: acme_display(),
        source: Some(SourceArchive {
            name: format!("{ACME_ID}-{version}.src.tar.gz"),
            url: package_url_of(version).replace(".onclp", ".src.tar.gz"),
            license: "Apache-2.0".to_owned(),
        }),
    };
    assert_eq!(view.available[0].origin, acme_origin("1.0.0"));

    service.install_from_catalog(ACME_ID, None).unwrap();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Installed { name: name() }]
    );
    let requests = sandbox.requests();
    assert_eq!(requests[0].origin_kind, acme_origin("1.0.0"));
    assert_eq!(service.view().installed[0].origin, acme_origin("1.0.0"));
    let record = installed(&sandbox);
    assert_eq!(record.source, Source::Catalog);
    assert_eq!(record.publisher, Some(acme()));
    assert_eq!(sandbox.modules.names(), [ACME_MODULE]);

    // Its role lists a newer release: the plugin is updated, its publisher kept.
    let second = plain(&sandbox, "1.1.0");
    publish(
        &sandbox,
        2,
        Some(&policy(vec![entry("active")])),
        Some((2, role(&[first, second]))),
    );
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Updated {
            name: name(),
            version: v("1.1.0"),
        }]
    );
    let record = installed(&sandbox);
    assert_eq!(record.version, v("1.1.0"));
    assert_eq!(record.publisher, Some(acme()));
}

#[test]
fn a_package_whose_capabilities_differ_from_its_entry_is_refused_and_marked_bad() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let narrower = release(&sandbox, "1.0.0", &acme_package("1.0.0"), |oncl| {
        oncl["capabilities"] = json!({"keys": true});
    });
    publish(
        &sandbox,
        1,
        Some(&policy(vec![entry("active")])),
        Some((1, role(&[narrower]))),
    );
    let refused = service.install_from_catalog(ACME_ID, None);
    assert!(
        matches!(&refused, Err(PluginActionError::Failed(e)) if e.contains("capabilities")),
        "{refused:?}"
    );
    assert!(sandbox.requests().is_empty(), "the user is not asked");
    assert!(sandbox.store().state().bad[ACME_ID].contains(&v("1.0.0")));
    assert!(sandbox.store().state().plugins.is_empty());
}

#[test]
fn a_retired_publishers_plugin_is_kept_until_the_owner_revokes_its_version() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    acme_installed(&sandbox, &service);
    // Retired, its role gone: nothing offered, the plugin runs on.
    publish(&sandbox, 2, Some(&policy(vec![entry("retired")])), None);
    service.check_now();
    kept(&sandbox);

    publish(
        &sandbox,
        3,
        Some(&policy(vec![revoking(entry("retired"), "1.0.0")])),
        None,
    );
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Withdrawn { name: name() }]
    );
    assert!(installed(&sandbox).withdrawn);
    assert!(sandbox.modules.names().is_empty());
}

#[test]
fn a_revoked_publisher_turns_its_plugins_off_once_until_it_is_back() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = acme_installed(&sandbox, &service);
    publish(&sandbox, 2, Some(&policy(vec![entry("revoked")])), None);
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::PublisherRevoked {
            name: name(),
            publisher: acme_display(),
        }]
    );
    assert!(installed(&sandbox).withdrawn);
    assert!(sandbox.modules.names().is_empty());
    assert_eq!(service.view().installed[0].state, PluginState::Withdrawn);
    service.check_now();
    assert!(sandbox.notices().is_empty(), "told once");

    // The owner makes it active again: the version, not revoked, runs again.
    publish(
        &sandbox,
        3,
        Some(&policy(vec![entry("active")])),
        Some((2, role(&[first]))),
    );
    service.check_now();
    kept(&sandbox);
}

#[test]
fn an_unavailable_publisher_keeps_its_plugins_unless_the_owner_revoked_them() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = acme_installed(&sandbox, &service);
    let newer = plain(&sandbox, "1.1.0");

    // Its role is signed by a key its delegation does not name: refused.
    {
        let mut repo = sandbox.server.repo();
        let stranger = SigningKey::from_seed(&[78; 32]).unwrap();
        let file = repo.role_file(2, role(&[first.clone(), newer.clone()]), &[&stranger]);
        repo.set_role(&acme_role(), 2, file);
    }
    sandbox.publish(2, Vec::new());
    service.check_now();
    kept(&sandbox);
    assert_eq!(downloads(&sandbox, "1.1.0"), 0, "nothing offered");

    // `publishers.json` (another one than kept) cannot be downloaded.
    let mut other = entry("active");
    other["homepage"] = json!("https://acme.kz/");
    let other = policy(vec![other]);
    publish(
        &sandbox,
        3,
        Some(&other),
        Some((3, role(&[first.clone(), newer.clone()]))),
    );
    let sha256 = Sha256::of(&serde_json::to_vec(&other).unwrap()).to_string();
    sandbox.transport.reply(
        &crate::repository::tests::url(&format!("targets/{sha256}.publishers.json")),
        404,
        b"",
    );
    service.check_now();
    kept(&sandbox);
    assert_eq!(downloads(&sandbox, "1.1.0"), 0, "nothing offered");

    // `publishers.json` does not name it (Р28): unavailable, not revoked.
    let stranger = json!({
        "name": "other", "state": "retired",
        "display": {"ru": "Другой", "kk": "Басқа", "en": "Other"},
        "id_prefix": "kz.other.", "modules": ["kz.other.Module"],
    });
    publish(&sandbox, 4, Some(&policy(vec![stranger])), None);
    service.check_now();
    kept(&sandbox);

    // Its role refused, but `publishers.json` holds and the owner revoked the version.
    {
        let mut repo = sandbox.server.repo();
        let stranger = SigningKey::from_seed(&[78; 32]).unwrap();
        repo.delegations = Some(testing::delegations(&[(&acme_role(), &acme_key())]));
        let file = repo.role_file(5, role(&[first, newer]), &[&stranger]);
        repo.set_role(&acme_role(), 5, file);
        repo.set_target(
            PublisherPolicy::TARGET,
            &serde_json::to_vec(&policy(vec![revoking(entry("active"), "1.0.0")])).unwrap(),
        );
    }
    sandbox.publish(5, Vec::new());
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Withdrawn { name: name() }]
    );
    assert_eq!(downloads(&sandbox, "1.1.0"), 0);
}

#[test]
fn with_updates_off_a_publishers_plugin_is_only_turned_off() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = acme_installed(&sandbox, &service);
    std::fs::write(
        sandbox.dir.path().join("settings.json"),
        r#"{"updates": {"enabled": false, "channel": "stable"}}"#,
    )
    .unwrap();
    let newer = plain(&sandbox, "1.1.0");
    publish(
        &sandbox,
        2,
        Some(&policy(vec![entry("active")])),
        Some((2, role(&[first.clone(), newer.clone()]))),
    );
    service.scheduled_check();
    kept(&sandbox);
    assert_eq!(downloads(&sandbox, "1.1.0"), 0, "not updated");

    // Its own role revokes the version installed: off, the newer one not installed.
    let (path, mut target) = first;
    target["custom"]["oncl"]["revoked"] = json!(true);
    publish(
        &sandbox,
        3,
        Some(&policy(vec![entry("active")])),
        Some((3, role(&[(path, target), newer]))),
    );
    service.scheduled_check();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Withdrawn { name: name() }]
    );
    assert!(installed(&sandbox).withdrawn);
    assert_eq!(installed(&sandbox).version, v("1.0.0"));
    assert_eq!(downloads(&sandbox, "1.1.0"), 0, "nothing installed");
}

#[test]
fn with_updates_off_check_now_turns_off_a_revoked_publishers_plugins() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    acme_installed(&sandbox, &service);
    std::fs::write(
        sandbox.dir.path().join("settings.json"),
        r#"{"updates": {"enabled": false, "channel": "stable"}}"#,
    )
    .unwrap();
    publish(&sandbox, 2, Some(&policy(vec![entry("revoked")])), None);
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::PublisherRevoked {
            name: name(),
            publisher: acme_display(),
        }]
    );
    assert!(installed(&sandbox).withdrawn);
}

#[test]
fn with_updates_and_revocations_off_the_schedule_contacts_nothing() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    acme_installed(&sandbox, &service);
    std::fs::write(
        sandbox.dir.path().join("settings.json"),
        r#"{"updates": {"enabled": false, "channel": "stable", "check_revocations": false}}"#,
    )
    .unwrap();
    publish(&sandbox, 2, Some(&policy(vec![entry("revoked")])), None);
    let asked = sandbox.transport.asked().len();
    let wait = service.scheduled_check();
    assert!(PUBLISHER_CHECK_EVERY.0 <= wait && wait <= PUBLISHER_CHECK_EVERY.1);
    assert_eq!(sandbox.transport.asked().len(), asked, "no request");
    assert!(sandbox.notices().is_empty());
    assert!(!installed(&sandbox).withdrawn);

    // «Проверить сейчас» still applies the revocations (Р38).
    service.check_now();
    assert!(sandbox.transport.asked().len() > asked);
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::PublisherRevoked {
            name: name(),
            publisher: acme_display(),
        }]
    );
    assert!(installed(&sandbox).withdrawn);
}

#[test]
fn the_schedule_follows_the_settings() {
    let settings = |enabled, check_revocations| UpdateSettings {
        enabled,
        check_revocations,
        ..UpdateSettings::default()
    };
    assert_eq!(Apply::scheduled(&settings(true, true)), Some(Apply::Full));
    assert_eq!(Apply::scheduled(&settings(true, false)), Some(Apply::Full));
    assert_eq!(
        Apply::scheduled(&settings(false, true)),
        Some(Apply::RevocationsOnly)
    );
    assert_eq!(Apply::scheduled(&settings(false, false)), None);
}

#[test]
fn the_catalog_is_checked_every_few_hours_while_a_publishers_plugin_is_installed() {
    let within = |wait: Duration, (low, high): (Duration, Duration)| low <= wait && wait <= high;
    assert_eq!(catalog::check_every(true), PUBLISHER_CHECK_EVERY);
    assert_eq!(catalog::check_every(false), CHECK_EVERY);
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = plain(&sandbox, "1.0.0");
    publish(
        &sandbox,
        1,
        Some(&policy(vec![entry("active")])),
        Some((1, role(&[first]))),
    );
    assert!(within(service.scheduled_check(), CHECK_EVERY));
    service.install_from_catalog(ACME_ID, None).unwrap();
    assert!(within(service.scheduled_check(), PUBLISHER_CHECK_EVERY));
    // With updates off as well: its revocations are checked as often.
    std::fs::write(
        sandbox.dir.path().join("settings.json"),
        r#"{"updates": {"enabled": false, "channel": "stable"}}"#,
    )
    .unwrap();
    assert!(within(service.scheduled_check(), PUBLISHER_CHECK_EVERY));
}

#[test]
fn a_publisher_not_recorded_is_restored_from_its_prefix() {
    let sandbox = Sandbox::new(true);
    let bytes = acme_package("1.0.0");
    sandbox
        .store()
        .install(
            &Package::read(&bytes).unwrap(),
            &bytes,
            Source::Catalog,
            None,
        )
        .unwrap();
    let service = sandbox.service();
    let first = plain(&sandbox, "1.0.0");
    publish(
        &sandbox,
        1,
        Some(&policy(vec![entry("active")])),
        Some((1, role(&[first]))),
    );
    service.check_now();
    assert_eq!(installed(&sandbox).publisher, Some(acme()));
    // As frequently checked as a plugin installed with its publisher.
    assert!(PUBLISHER_CHECK_EVERY.1 >= service.scheduled_check());
}

#[test]
fn the_kept_catalog_and_its_publishers_are_checked_again_offline() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = plain(&sandbox, "1.0.0");
    publish(
        &sandbox,
        1,
        Some(&policy(vec![entry("active")])),
        Some((1, role(&[first]))),
    );
    service.check_now();
    drop(service);

    // A restart: the catalog kept is read again without the network, acme's plugin offered.
    let asked = sandbox.transport.asked().len();
    let again = sandbox.service();
    let view = again.view();
    assert_eq!(
        view.available
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>(),
        [ACME_ID]
    );
    assert_eq!(sandbox.transport.asked().len(), asked, "nothing downloaded");
    drop(again);

    // A kept role file other than the one accepted: acme is unavailable, the index stays.
    let roles = sandbox
        .dir
        .path()
        .join("plugins/catalog/roles/pub-acme.json");
    std::fs::write(&roles, b"{}").unwrap();
    let third = sandbox.service();
    let view = third.view();
    assert!(view.available.is_empty(), "{:?}", view.available);
    assert!(matches!(view.catalog, CatalogView::Ready { .. }));
    assert_eq!(sandbox.transport.asked().len(), asked, "nothing downloaded");
}

#[test]
fn a_failed_download_of_publishers_json_falls_back_to_the_same_kept_file() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = acme_installed(&sandbox, &service);
    let newer = plain(&sandbox, "1.1.0");
    let same = policy(vec![entry("active")]);
    publish(&sandbox, 2, Some(&same), Some((2, role(&[first, newer]))));
    let sha256 = Sha256::of(&serde_json::to_vec(&same).unwrap()).to_string();
    sandbox.transport.reply(
        &crate::repository::tests::url(&format!("targets/{sha256}.publishers.json")),
        404,
        b"",
    );
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Updated {
            name: name(),
            version: v("1.1.0"),
        }]
    );
}

#[test]
fn unreadable_delegations_keep_a_publishers_plugin_unless_the_owner_revoked_it() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = acme_installed(&sandbox, &service);
    let newer = plain(&sandbox, "1.1.0");
    let unreadable = |sandbox: &Sandbox, seq: u64, policy: &Value| {
        {
            let mut repo = sandbox.server.repo();
            repo.set_target(
                PublisherPolicy::TARGET,
                &serde_json::to_vec(policy).unwrap(),
            );
            let file = repo.role_file(seq, role(&[first.clone(), newer.clone()]), &[&acme_key()]);
            repo.set_role(&acme_role(), seq, file);
            repo.delegations = Some(json!({"keys": {}, "roles": 7}));
        }
        sandbox.publish(seq, Vec::new());
    };
    unreadable(&sandbox, 2, &policy(vec![entry("active")]));
    service.check_now();
    kept(&sandbox);
    assert_eq!(downloads(&sandbox, "1.1.0"), 0, "nothing offered");

    unreadable(
        &sandbox,
        3,
        &policy(vec![revoking(entry("active"), "1.0.0")]),
    );
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Withdrawn { name: name() }]
    );
}

#[test]
fn an_expired_role_leaves_its_publisher_unavailable_in_the_catalog_rebuilt() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = plain(&sandbox, "1.0.0");
    {
        let mut repo = sandbox.server.repo();
        repo.set_target(
            PublisherPolicy::TARGET,
            &serde_json::to_vec(&policy(vec![entry("active")])).unwrap(),
        );
        let lifetimes = repo.lifetimes;
        repo.signed_at = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        repo.lifetimes.targets = time::Duration::seconds(8);
        let file = repo.role_file(1, role(&[first]), &[&acme_key()]);
        repo.lifetimes = lifetimes;
        repo.set_role(&acme_role(), 1, file);
        repo.delegations = Some(testing::delegations(&[(&acme_role(), &acme_key())]));
    }
    sandbox.publish(1, Vec::new());
    service.check_now();
    assert_eq!(service.view().available.len(), 1);
    thread::sleep(Duration::from_secs(10));
    // The catalog in use holds no longer: rebuilt from the kept files, without acme.
    let view = service.view();
    assert!(view.available.is_empty(), "{:?}", view.available);
    assert!(matches!(view.catalog, CatalogView::Ready { .. }));
}

/// The user agrees to install acme's plugin after acme was revoked while the window was
/// open: nothing is installed.
#[test]
fn agreeing_to_install_a_plugin_no_longer_offered_installs_nothing() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let first = plain(&sandbox, "1.0.0");
    publish(
        &sandbox,
        1,
        Some(&policy(vec![entry("active")])),
        Some((1, role(std::slice::from_ref(&first)))),
    );
    *lock(&sandbox.ui.answer) = None;
    service.install_from_catalog(ACME_ID, None).unwrap();
    assert_eq!(sandbox.requests().len(), 1);
    publish(&sandbox, 2, Some(&policy(vec![entry("revoked")])), None);
    service.check_now();
    let decide = lock(&sandbox.ui.waiting).pop().expect("the window waits");
    decide(true);
    assert!(
        matches!(&sandbox.notices()[..], [PluginNotice::Failed { error, .. }] if error.contains("no longer offers")),
    );
    assert!(sandbox.store().state().plugins.is_empty());
    assert!(sandbox.modules.names().is_empty());
}
