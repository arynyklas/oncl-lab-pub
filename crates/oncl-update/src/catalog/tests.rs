//! Tests of the catalog: one rule each.

use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use serde_json::{Value, json};

use super::*;
use crate::index::{Channel, Index, Sha256};
use crate::plugins::{PluginChoice, choose_plugin, offer};
use crate::tuf::{Digest, PublisherName, RoleName, Target, TargetPath};

const INSTALL: [u8; 16] = [7; 16];
const PORT: &str = "io.github.arynyklas.openncalayer.port.market";
const OTHER_PORT: &str = "io.github.arynyklas.openncalayer.port.other";
const MARKET: &str = "kz.ecc.market";
const SIGNER: &str = "kz.ecc.market.Signer";
const OTHER_MODULE: &str = "kz.ecc.other.Module";

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn core() -> Version {
    v("0.1.2")
}

fn ecc() -> PublisherName {
    PublisherName::parse("ecc").unwrap()
}

fn no_bad() -> BTreeMap<String, BTreeSet<Version>> {
    BTreeMap::new()
}

/// A release of the owner's index.
fn port(id: &str, version: &str, module: &str, symname: &str) -> Value {
    json!({
        "id": id, "version": version,
        "url": format!("https://example.invalid/{id}-{version}.onclp"),
        "sha256": "00".repeat(32), "size": 120,
        "min_core": "0.1.0",
        "modules": [module],
        "replaces": {"symname": symname, "version": "1.2.1"},
        "name": {"ru": "Порт", "kk": "Порт", "en": "Port"},
        "rollout": 100
    })
}

fn index_of(channel: &str, plugins: Vec<Value>) -> Index {
    let document = json!({
        "schema": 1, "channel": channel, "seq": 1,
        "generated": "2026-10-01T00:00:00Z", "expires": "2026-10-31T00:00:00Z",
        "core": [], "plugins": plugins
    });
    Index::from_json(&serde_json::to_vec(&document).unwrap()).unwrap()
}

fn index(plugins: Vec<Value>) -> Index {
    index_of("stable", plugins)
}

fn display() -> Value {
    json!({"ru": "ТОО «ЕЦЦ»", "kk": "ЕЦЦ", "en": "ECC"})
}

/// The active publisher `ecc`: prefix `kz.ecc.`, two modules, one bundle.
fn ecc_entry() -> Value {
    json!({
        "name": "ecc", "state": "active", "display": display(),
        "id_prefix": "kz.ecc.",
        "modules": [SIGNER, OTHER_MODULE],
        "bundles": [MARKET],
        "homepage": "https://ecc.kz/"
    })
}

fn policy_json(publishers: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({"schema": 1, "publishers": publishers})).unwrap()
}

fn policy(publishers: Vec<Value>) -> PublisherPolicy {
    PublisherPolicy::from_json(&policy_json(publishers)).unwrap()
}

fn refused(publishers: Vec<Value>) -> CatalogError {
    PublisherPolicy::from_json(&policy_json(publishers)).unwrap_err()
}

/// The sha256 of every test package (`target`), in hex.
fn package_hex() -> String {
    "09".repeat(32)
}

/// The copy of `ecc`'s package `id` `version` in the project's Releases.
fn mirrored(id: &str, version: &str) -> String {
    format!(
        "https://github.com/arynyklas/OpenNCALayer/releases/download/pub-ecc-{}/{id}-{version}.onclp",
        package_hex()
    )
}

/// A `custom.oncl.source` meeting every rule.
fn source() -> Value {
    json!({
        "archive_sha256": "ab".repeat(32),
        "archive_length": 2_345_678,
        "fetch": "https://downloads.ecc.kz/oncl/kz.ecc.market-1.2.0.src.tar.gz",
        "path": "crates/market",
        "license": "Apache-2.0",
        "builder": format!("sha256:{}", "cd".repeat(32)),
        "vcs": {"url": "https://git.ecc.kz/oncl/market.git", "rev": "ef".repeat(20)}
    })
}

/// `custom.oncl` of a stable release of `id` serving `kz.ecc.market.Signer`.
fn entry(id: &str, version: &str) -> Value {
    json!({
        "schema": 1, "id": id, "version": version,
        "url": mirrored(id, version),
        "source": source(),
        "channel": "stable", "min_core": "0.1.0",
        "modules": [SIGNER],
        "replaces": {"symname": MARKET, "version": "1.2.0"},
        "name": {"ru": "Маркет", "kk": "Маркет", "en": "Market"},
        "capabilities": {"keys": true, "http": ["https://api.ecc.kz/"]},
        "rollout": 100, "revoked": false
    })
}

fn target(oncl: Value) -> Target {
    Target {
        length: 4096,
        sha256: Digest([9; 32]),
        custom: Some(json!({ "oncl": oncl })),
    }
}

fn path_of(entry: &Value) -> TargetPath {
    let id = entry["id"].as_str().unwrap();
    let version = entry["version"].as_str().unwrap();
    TargetPath::parse(&format!("plugins/ecc/{id}/{version}.onclp")).unwrap()
}

fn role(entries: &[Value]) -> BTreeMap<TargetPath, Target> {
    entries
        .iter()
        .map(|e| (path_of(e), target(e.clone())))
        .collect()
}

fn role_name(publisher: &str) -> RoleName {
    RoleName::parse(&format!("pub-{publisher}")).unwrap()
}

type Roles<'a> = [(&'a str, Option<&'a BTreeMap<TargetPath, Target>>)];

fn build(index: Index, publishers: Vec<Value>, roles: &Roles<'_>) -> Catalog {
    roles
        .iter()
        .fold(
            Catalog::builder(index, &BTreeMap::new(), Ok(policy(publishers))),
            |builder, (name, targets)| match targets {
                Some(targets) => builder.role(&role_name(name), targets),
                None => builder.unavailable_role(&role_name(name)),
            },
        )
        .build()
}

/// A catalog of the empty owner's index and `ecc` with the role `entries`.
fn ecc_catalog(entries: &[Value]) -> Catalog {
    let targets = role(entries);
    build(index(vec![]), vec![ecc_entry()], &[("ecc", Some(&targets))])
}

fn choose<'a>(catalog: &'a Catalog, id: &str, current: &str) -> PluginChoice<'a> {
    choose_plugin(
        catalog,
        id,
        &v(current),
        &core(),
        &INSTALL,
        &BTreeSet::new(),
    )
}

fn by_module<'a>(catalog: &'a Catalog, module: &str) -> Option<&'a PluginRelease> {
    offer(catalog, &core(), &INSTALL, &no_bad(), |r| {
        r.modules.iter().any(|m| m == module)
    })
}

#[test]
fn owner_only_catalog_lists_the_index_and_knows_no_publisher() {
    let index = index(vec![port(PORT, "1.0.0", SIGNER, MARKET)]);
    let catalog = Catalog::owner(index.clone());
    assert_eq!(
        catalog.releases().cloned().collect::<Vec<_>>(),
        index.plugins
    );
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Unavailable);
    assert_eq!(catalog.publisher_of(MARKET), None);
    assert!(catalog.policy().is_none());
}

#[test]
fn the_owner_index_cannot_pass_a_port_off_as_a_publisher_plugin() {
    let mut release = port(PORT, "1.0.0", SIGNER, MARKET);
    release["publisher"] = json!("ecc");
    release["capabilities"] = json!({"keys": true});
    let index = index(vec![release]);
    assert_eq!(index.plugins[0].publisher, None);
    assert_eq!(index.plugins[0].capabilities, None);
}

#[test]
fn custom_oncl_maps_onto_a_plugin_release() {
    let catalog = ecc_catalog(&[entry(MARKET, "1.2.0")]);
    let release = catalog.releases().next().unwrap();
    assert_eq!(release.id, MARKET);
    assert_eq!(release.version, v("1.2.0"));
    assert_eq!(release.package.url, mirrored(MARKET, "1.2.0"));
    assert_eq!(release.package.size, 4096);
    assert_eq!(release.package.sha256, Sha256([9; 32]));
    assert_eq!(release.min_core, v("0.1.0"));
    assert_eq!(release.modules, vec![SIGNER.to_owned()]);
    assert_eq!(release.replaces.as_ref().unwrap().symname, MARKET);
    assert_eq!(release.name.en, "Market");
    assert_eq!(release.rollout, 100);
    assert!(!release.revoked);
    assert_eq!(release.publisher, Some(ecc()));
    assert_eq!(
        release.capabilities.as_ref().unwrap().as_object()["keys"],
        json!(true)
    );
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Active);
    assert_eq!(catalog.publisher_of(MARKET), Some(&ecc()));
    assert!(catalog.rejected().is_empty());
}

#[test]
fn an_owner_index_id_wins_over_a_publisher_release() {
    let targets = role(&[entry(MARKET, "2.0.0")]);
    let owner = port(MARKET, "1.0.0", "kz.owner.Module", "kz.owner.bundle");
    let catalog = build(
        index(vec![owner]),
        vec![ecc_entry()],
        &[("ecc", Some(&targets))],
    );
    assert!(matches!(
        catalog.rejected()[0].reason,
        EntryRejection::OwnerId
    ));
    let chosen = offer(&catalog, &core(), &INSTALL, &no_bad(), |r| r.id == MARKET).unwrap();
    assert_eq!(chosen.version, v("1.0.0"));
    assert_eq!(chosen.publisher, None);
    assert!(matches!(
        choose(&catalog, MARKET, "1.0.0"),
        PluginChoice::Keep
    ));
}

#[test]
fn an_owner_module_wins_over_a_publisher_release() {
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let owner = port(PORT, "1.0.0", SIGNER, "kz.owner.bundle");
    let catalog = build(
        index(vec![owner]),
        vec![ecc_entry()],
        &[("ecc", Some(&targets))],
    );
    assert!(matches!(
        &catalog.rejected()[0].reason,
        EntryRejection::OwnerModule(module) if module == SIGNER
    ));
    assert_eq!(by_module(&catalog, SIGNER).unwrap().id, PORT);
}

#[test]
fn an_owner_bundle_wins_over_a_publisher_release() {
    let mut other = entry("kz.ecc.other", "1.0.0");
    other["modules"] = json!([OTHER_MODULE]);
    let targets = role(&[other]);
    let owner = port(PORT, "1.0.0", "kz.owner.Module", MARKET);
    let catalog = build(
        index(vec![owner]),
        vec![ecc_entry()],
        &[("ecc", Some(&targets))],
    );
    assert!(matches!(
        &catalog.rejected()[0].reason,
        EntryRejection::OwnerBundle(bundle) if bundle == MARKET
    ));
}

#[test]
fn a_version_the_owner_revoked_is_revoked_whatever_the_role_says() {
    let mut publisher = ecc_entry();
    publisher["revoked_versions"] =
        json!([{"id": MARKET, "version": "1.1.0", "date": "2027-02-10"}]);
    let targets = role(&[entry(MARKET, "1.0.0"), entry(MARKET, "1.1.0")]);
    let catalog = build(index(vec![]), vec![publisher], &[("ecc", Some(&targets))]);
    let revoked = catalog
        .releases()
        .find(|r| r.version == v("1.1.0"))
        .unwrap();
    assert!(revoked.revoked);
    assert_eq!(by_module(&catalog, SIGNER).unwrap().version, v("1.0.0"));
    let PluginChoice::Downgrade(fallback) = choose(&catalog, MARKET, "1.1.0") else {
        panic!("the revoked version did not fall back");
    };
    assert_eq!(fallback.version, v("1.0.0"));
}

#[test]
fn a_version_the_owner_revoked_is_withdrawn_even_if_the_role_dropped_it() {
    let mut publisher = ecc_entry();
    publisher["revoked_versions"] =
        json!([{"id": MARKET, "version": "1.1.0", "date": "2027-02-10"}]);
    let mut newer = entry(MARKET, "1.2.0");
    newer["min_core"] = json!("9.0.0");
    let targets = role(&[newer]);
    let catalog = build(index(vec![]), vec![publisher], &[("ecc", Some(&targets))]);
    assert!(catalog.is_revoked(MARKET, &v("1.1.0")));
    assert!(matches!(
        choose(&catalog, MARKET, "1.1.0"),
        PluginChoice::Withdrawn
    ));
}

#[test]
fn a_revoked_publisher_hides_its_plugins_and_withdraws_them() {
    let revoked = json!({
        "name": "ecc", "state": "revoked", "display": display(),
        "id_prefix": "kz.ecc.", "revoked": "2027-03-01"
    });
    let catalog = build(index(vec![]), vec![revoked], &[]);
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Revoked);
    assert_eq!(catalog.publisher_of(MARKET), Some(&ecc()));
    assert!(by_module(&catalog, SIGNER).is_none());
    assert!(matches!(
        choose(&catalog, MARKET, "1.0.0"),
        PluginChoice::PublisherRevoked(name) if *name == ecc()
    ));
}

#[test]
fn a_publisher_publishers_json_does_not_name_is_unavailable_not_revoked() {
    let catalog = build(index(vec![]), vec![], &[]);
    let gone = PublisherName::parse("gone").unwrap();
    assert_eq!(catalog.publisher_state(&gone), PublisherState::Unavailable);
    assert!(matches!(
        choose(&catalog, "kz.gone.tool", "1.0.0"),
        PluginChoice::Keep
    ));
}

#[test]
fn an_unavailable_role_keeps_installed_plugins_unless_the_owner_revoked_them() {
    let mut publisher = ecc_entry();
    publisher["revoked_versions"] =
        json!([{"id": MARKET, "version": "1.1.0", "date": "2027-02-10"}]);
    let catalog = build(index(vec![]), vec![publisher], &[("ecc", None)]);
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Unavailable);
    assert_eq!(catalog.releases().count(), 0);
    assert!(matches!(
        choose(&catalog, MARKET, "1.0.0"),
        PluginChoice::Keep
    ));
    assert!(catalog.is_revoked(MARKET, &v("1.1.0")));
    assert!(matches!(
        choose(&catalog, MARKET, "1.1.0"),
        PluginChoice::Withdrawn
    ));
}

#[test]
fn an_unknown_state_makes_only_that_publisher_unavailable() {
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let strange = json!({
        "name": "next", "state": "suspended", "display": display(),
        "id_prefix": "kz.next."
    });
    let catalog = build(
        index(vec![]),
        vec![ecc_entry(), strange],
        &[("ecc", Some(&targets)), ("next", None)],
    );
    let next = PublisherName::parse("next").unwrap();
    assert_eq!(catalog.publisher_state(&next), PublisherState::Unavailable);
    assert!(matches!(
        catalog
            .policy()
            .unwrap()
            .publisher(&next)
            .unwrap()
            .standing(),
        Standing::Unknown { state, .. } if state == "suspended"
    ));
    assert!(matches!(
        choose(&catalog, "kz.next.tool", "1.0.0"),
        PluginChoice::Keep
    ));
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Active);
    assert_eq!(by_module(&catalog, SIGNER).unwrap().version, v("1.0.0"));
}

#[test]
fn a_retired_publisher_offers_nothing_new_and_keeps_installed_plugins() {
    let mut retired = ecc_entry();
    retired["state"] = json!("retired");
    retired["revoked_versions"] = json!([{"id": MARKET, "version": "1.1.0", "date": "2027-02-10"}]);
    let targets = role(&[entry(MARKET, "1.0.0"), entry(MARKET, "1.2.0")]);
    for roles in [&[("ecc", Some(&targets))][..], &[]] {
        let catalog = build(index(vec![]), vec![retired.clone()], roles);
        assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Retired);
        assert_eq!(catalog.releases().count(), 0);
        assert!(matches!(
            choose(&catalog, MARKET, "1.0.0"),
            PluginChoice::Keep
        ));
        assert!(catalog.is_revoked(MARKET, &v("1.1.0")));
        assert!(matches!(
            choose(&catalog, MARKET, "1.1.0"),
            PluginChoice::Withdrawn
        ));
    }
}

#[test]
fn a_retired_publisher_keeps_its_modules() {
    let mut retired = ecc_entry();
    retired["state"] = json!("retired");
    let mut other = second("kz.other.");
    other["modules"] = json!([SIGNER]);
    assert!(matches!(
        refused(vec![retired, other]),
        CatalogError::SharedModule { .. }
    ));
}

#[test]
fn an_unknown_state_still_enforces_the_owner_revoked_versions() {
    let mut strange = ecc_entry();
    strange["state"] = json!("suspended");
    strange["revoked_versions"] = json!([{"id": MARKET, "version": "1.1.0", "date": "2027-02-10"}]);
    let mut broken = entry(MARKET, "1.3.0");
    broken["url"] = json!("http://downloads.ecc.kz/p.onclp");
    let targets = role(&[entry(MARKET, "1.0.0"), entry(MARKET, "1.2.0"), broken]);
    for roles in [&[("ecc", Some(&targets))][..], &[("ecc", None)], &[]] {
        let catalog = build(index(vec![]), vec![strange.clone()], roles);
        assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Unavailable);
        assert_eq!(catalog.releases().count(), 0);
        assert!(catalog.rejected().is_empty());
        assert!(matches!(
            choose(&catalog, MARKET, "1.0.0"),
            PluginChoice::Keep
        ));
        assert!(matches!(
            choose(&catalog, MARKET, "1.1.0"),
            PluginChoice::Withdrawn
        ));
    }
}

#[test]
fn an_unknown_state_keeps_its_prefix_modules_and_ports() {
    let mut strange = ecc_entry();
    strange["state"] = json!("suspended");
    assert!(matches!(
        refused(vec![strange.clone(), second("kz.ecc.sub.")]),
        CatalogError::NestedPrefix(..)
    ));
    let mut other = second("kz.other.");
    other["modules"] = json!([SIGNER]);
    assert!(matches!(
        refused(vec![strange.clone(), other]),
        CatalogError::SharedModule { .. }
    ));
    let mut taker = second("kz.other.");
    taker["supersedes"] = json!({ PORT: "kz.other.market" });
    strange["supersedes"] = json!({ PORT: MARKET });
    assert!(matches!(
        refused(vec![strange, taker]),
        CatalogError::Supersedes { .. }
    ));
}

#[test]
fn a_retired_publisher_keeps_the_versions_it_revoked_withdrawn() {
    let mut retired = ecc_entry();
    retired["state"] = json!("retired");
    let mut revoked = entry(MARKET, "1.1.0");
    revoked["revoked"] = json!(true);
    let mut broken = entry(MARKET, "1.3.0");
    broken["url"] = json!("http://downloads.ecc.kz/p.onclp");
    let targets = role(&[
        entry(MARKET, "1.0.0"),
        revoked,
        entry(MARKET, "1.2.0"),
        broken,
    ]);
    let catalog = build(index(vec![]), vec![retired], &[("ecc", Some(&targets))]);
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Retired);
    assert!(catalog.releases().all(|r| r.revoked));
    assert!(by_module(&catalog, SIGNER).is_none());
    assert!(catalog.rejected().is_empty());
    assert!(matches!(
        choose(&catalog, MARKET, "1.0.0"),
        PluginChoice::Keep
    ));
    assert!(matches!(
        choose(&catalog, MARKET, "1.1.0"),
        PluginChoice::Withdrawn
    ));
}

#[test]
fn a_retired_publisher_does_not_replace_its_port() {
    let mut retired = superseding_ecc();
    retired["state"] = json!("retired");
    let owner = port(PORT, "1.0.0", SIGNER, MARKET);
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let catalog = build(
        index(vec![owner]),
        vec![retired],
        &[("ecc", Some(&targets))],
    );
    assert!(
        catalog
            .replacement(PORT, &core(), &INSTALL, &no_bad())
            .is_none()
    );
}

#[test]
fn an_owner_revocation_ignores_build_metadata() {
    let mut publisher = ecc_entry();
    publisher["revoked_versions"] =
        json!([{"id": MARKET, "version": "1.1.0", "date": "2027-02-10"}]);
    let targets = role(&[entry(MARKET, "1.0.0"), entry(MARKET, "1.1.0")]);
    let catalog = build(index(vec![]), vec![publisher], &[("ecc", Some(&targets))]);
    assert!(catalog.is_revoked(MARKET, &v("1.1.0+x")));
    assert!(!catalog.is_revoked(MARKET, &v("1.1.0-rc.1")));
    let PluginChoice::Downgrade(fallback) = choose(&catalog, MARKET, "1.1.0+x") else {
        panic!("the revoked version did not fall back");
    };
    assert_eq!(fallback.version, v("1.0.0"));
}

#[test]
fn an_unusable_publishers_json_makes_every_publisher_unavailable() {
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let owner = port(PORT, "1.0.0", "kz.owner.Module", "kz.owner.bundle");
    let catalog = Catalog::builder(
        index(vec![owner]),
        &BTreeMap::new(),
        Err(CatalogError::Schema(2)),
    )
    .role(&role_name("ecc"), &targets)
    .build();
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Unavailable);
    assert_eq!(catalog.publisher_of(MARKET), None);
    assert!(matches!(
        choose(&catalog, MARKET, "1.0.0"),
        PluginChoice::Keep
    ));
    assert_eq!(by_module(&catalog, "kz.owner.Module").unwrap().id, PORT);
}

#[test]
fn publishers_json_and_delegations_must_agree_on_the_active_publishers() {
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let undelegated = build(index(vec![]), vec![ecc_entry()], &[]);
    assert_eq!(
        undelegated.publisher_state(&ecc()),
        PublisherState::Unavailable
    );
    let unnamed = build(index(vec![]), vec![], &[("ecc", Some(&targets))]);
    assert_eq!(unnamed.publisher_state(&ecc()), PublisherState::Unavailable);
    assert_eq!(unnamed.releases().count(), 0);
}

#[test]
fn a_builtin_module_in_publishers_json_makes_every_publisher_unavailable() {
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let catalog = Catalog::builder(
        index(vec![]),
        &BTreeMap::new(),
        Ok(policy(vec![ecc_entry()])),
    )
    .builtin_modules([SIGNER.to_owned()])
    .role(&role_name("ecc"), &targets)
    .build();
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Unavailable);
    assert!(by_module(&catalog, SIGNER).is_none());
    let catalog = Catalog::builder(
        index(vec![]),
        &BTreeMap::new(),
        Ok(policy(vec![ecc_entry()])),
    )
    .builtin_modules([SIGNER.to_ascii_uppercase()])
    .role(&role_name("ecc"), &targets)
    .build();
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Unavailable);
}

#[test]
fn an_owner_module_in_another_case_still_wins() {
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let owner = port(
        PORT,
        "1.0.0",
        &SIGNER.to_ascii_uppercase(),
        "kz.owner.bundle",
    );
    let catalog = build(
        index(vec![owner]),
        vec![ecc_entry()],
        &[("ecc", Some(&targets))],
    );
    assert!(matches!(
        &catalog.rejected()[0].reason,
        EntryRejection::OwnerModule(module) if module == SIGNER
    ));
}

#[test]
fn a_port_is_hidden_only_by_a_replacement_serving_all_its_modules_and_bundle() {
    let mut wide = port(PORT, "1.0.0", SIGNER, MARKET);
    wide["modules"] = json!([SIGNER, OTHER_MODULE]);
    let mut both = entry(MARKET, "2.0.0");
    both["modules"] = json!([SIGNER, OTHER_MODULE]);
    let mut unbundled = both.clone();
    unbundled["version"] = json!("3.0.0");
    unbundled["url"] = json!(mirrored(MARKET, "3.0.0"));
    unbundled["replaces"] = Value::Null;
    let cases = [
        (vec![entry(MARKET, "1.0.0")], None),
        (vec![unbundled], None),
        (vec![both], Some("2.0.0")),
    ];
    for (entries, replaced_by) in cases {
        let targets = role(&entries);
        let catalog = build(
            index(vec![wide.clone()]),
            vec![superseding_ecc()],
            &[("ecc", Some(&targets))],
        );
        assert!(catalog.rejected().is_empty());
        let replacement = catalog.replacement(PORT, &core(), &INSTALL, &no_bad());
        assert_eq!(
            replacement.map(|r| r.version.to_string()).as_deref(),
            replaced_by
        );
        let port_offered = offer(&catalog, &core(), &INSTALL, &no_bad(), |r| r.id == PORT);
        assert_eq!(port_offered.is_some(), replaced_by.is_none());
    }
}

fn superseding_ecc() -> Value {
    let mut publisher = ecc_entry();
    publisher["supersedes"] = json!({ PORT: MARKET });
    publisher
}

fn ports() -> Index {
    index(vec![
        port(PORT, "1.0.0", SIGNER, MARKET),
        port(OTHER_PORT, "1.0.0", OTHER_MODULE, "kz.owner.other"),
    ])
}

#[test]
fn supersedes_replaces_only_the_ports_it_lists() {
    let mut other = entry("kz.ecc.other", "1.0.0");
    other["modules"] = json!([OTHER_MODULE]);
    other["replaces"] = Value::Null;
    let targets = role(&[entry(MARKET, "1.0.0"), other]);
    let catalog = build(ports(), vec![superseding_ecc()], &[("ecc", Some(&targets))]);
    assert_eq!(catalog.rejected().len(), 1);
    assert!(matches!(
        &catalog.rejected()[0].reason,
        EntryRejection::OwnerModule(module) if module == OTHER_MODULE
    ));
    assert_eq!(by_module(&catalog, SIGNER).unwrap().id, MARKET);
    assert_eq!(by_module(&catalog, OTHER_MODULE).unwrap().id, OTHER_PORT);
    let replacement = catalog.replacement(PORT, &core(), &INSTALL, &no_bad());
    assert_eq!(replacement.unwrap().id, MARKET);
    assert!(
        catalog
            .replacement(OTHER_PORT, &core(), &INSTALL, &no_bad())
            .is_none()
    );
    // The port's own lifecycle is unchanged: its installations are moved by the caller.
    assert!(matches!(
        choose(&catalog, PORT, "1.0.0"),
        PluginChoice::Keep
    ));
}

#[test]
fn a_port_stays_offered_until_its_replacement_is() {
    let mut later = entry(MARKET, "1.0.0");
    later["min_core"] = json!("9.0.0");
    let targets = role(&[later]);
    let catalog = build(ports(), vec![superseding_ecc()], &[("ecc", Some(&targets))]);
    assert!(catalog.rejected().is_empty());
    assert_eq!(by_module(&catalog, SIGNER).unwrap().id, PORT);
    assert!(
        catalog
            .replacement(PORT, &core(), &INSTALL, &no_bad())
            .is_none()
    );
    let bad = BTreeMap::from([(MARKET.to_owned(), BTreeSet::from([v("1.0.0")]))]);
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let catalog = build(ports(), vec![superseding_ecc()], &[("ecc", Some(&targets))]);
    let found = offer(&catalog, &core(), &INSTALL, &bad, |r| {
        r.modules.iter().any(|m| m == SIGNER)
    });
    assert_eq!(found.unwrap().id, PORT);
}

#[test]
fn an_unavailable_publisher_supersedes_nothing() {
    let catalog = build(ports(), vec![superseding_ecc()], &[("ecc", None)]);
    assert_eq!(by_module(&catalog, SIGNER).unwrap().id, PORT);
    assert!(
        catalog
            .replacement(PORT, &core(), &INSTALL, &no_bad())
            .is_none()
    );
}

#[test]
fn beta_releases_reach_only_the_beta_channel() {
    let mut beta = entry(MARKET, "2.0.0-beta.1");
    beta["channel"] = json!("beta");
    let targets = role(&[entry(MARKET, "1.0.0"), beta]);
    for (channel, newest) in [("stable", "1.0.0"), ("beta", "2.0.0-beta.1")] {
        let catalog = build(
            index_of(channel, vec![]),
            vec![ecc_entry()],
            &[("ecc", Some(&targets))],
        );
        assert!(catalog.rejected().is_empty(), "{channel}");
        assert_eq!(catalog.index().channel.as_str(), channel);
        assert_eq!(by_module(&catalog, SIGNER).unwrap().version, v(newest));
    }
}

/// Builds `ecc` with a single target at `path` of `oncl`, and returns why it was left out.
fn rejection_at(path: &str, oncl: Value) -> EntryRejection {
    let targets = BTreeMap::from([(TargetPath::parse(path).unwrap(), target(oncl))]);
    let catalog = build(index(vec![]), vec![ecc_entry()], &[("ecc", Some(&targets))]);
    assert_eq!(catalog.releases().count(), 0, "{path}");
    assert_eq!(catalog.rejected().len(), 1, "{path}");
    catalog.rejected()[0].reason.clone()
}

/// A change to a target's `custom.oncl`.
type Change = Box<dyn FnOnce(&mut Value)>;
/// Whether a rejection is the one expected.
type Expected = fn(&EntryRejection) -> bool;

fn rejection(change: impl FnOnce(&mut Value)) -> EntryRejection {
    let mut oncl = entry(MARKET, "1.0.0");
    change(&mut oncl);
    rejection_at("plugins/ecc/kz.ecc.market/1.0.0.onclp", oncl)
}

#[test]
fn each_broken_rule_leaves_a_publisher_target_out() {
    use EntryRejection as R;
    let path = |p: &str| rejection_at(p, entry(MARKET, "1.0.0"));
    assert!(matches!(
        path("plugins/ecc/kz.ecc.market/1.0.0.zip"),
        R::Path
    ));
    assert!(matches!(
        path("plugins/ecc/kz.ecc.market/one.onclp"),
        R::Path
    ));
    assert!(matches!(
        path("plugins/other/kz.ecc.market/1.0.0.onclp"),
        R::Path
    ));
    assert!(matches!(
        path("plugins/ecc/kz.ecc.market/1.0.1.onclp"),
        R::PathMismatch
    ));
    let outside = entry("kz.other.market", "1.0.0");
    assert!(matches!(
        rejection_at("plugins/ecc/kz.other.market/1.0.0.onclp", outside),
        R::IdOutsidePrefix
    ));
    let cases: Vec<(Change, Expected)> = vec![
        (Box::new(|e| *e = json!({"schema": 1})), |r| {
            matches!(r, R::Malformed(_))
        }),
        (Box::new(|e| e["schema"] = json!(2)), |r| {
            matches!(r, R::Schema(2))
        }),
        (Box::new(|e| e["rollout"] = json!("all")), |r| {
            matches!(r, R::Malformed(_))
        }),
        (Box::new(|e| e["rollout"] = json!(101)), |r| {
            matches!(r, R::Rollout(101))
        }),
        (
            Box::new(|e| e["url"] = json!("https://downloads.ecc.kz/p.onclp")),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| {
                e["url"] = json!(mirrored(MARKET, "1.0.0").replace("https://", "http://"));
            }),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| {
                e["url"] = json!(mirrored(MARKET, "1.0.0").replace("arynyklas/", "other/"));
            }),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| {
                e["url"] = json!(mirrored(MARKET, "1.0.0").replace("pub-ecc-", "pub-other-"));
            }),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| e["url"] = json!(mirrored(MARKET, "1.0.0").replace("0909", "0a0a"))),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| e["url"] = json!(mirrored(MARKET, "1.0.0").to_ascii_uppercase())),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| e["url"] = json!(mirrored(MARKET, "1.0.1"))),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| e["url"] = json!(mirrored("kz.ecc.other", "1.0.0"))),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| e["url"] = json!(format!("{}?x=1", mirrored(MARKET, "1.0.0")))),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| e["url"] = json!(format!("{}/", mirrored(MARKET, "1.0.0")))),
            |r| matches!(r, R::NotMirrored),
        ),
        (
            Box::new(|e| {
                e.as_object_mut().unwrap().remove("source");
            }),
            |r| matches!(r, R::Source(SourceError::Missing)),
        ),
        (Box::new(|e| e["modules"] = json!([])), |r| {
            matches!(r, R::Modules(0))
        }),
        (Box::new(|e| e["modules"] = json!(vec![SIGNER; 33])), |r| {
            matches!(r, R::Modules(33))
        }),
        (
            Box::new(|e| e["modules"] = json!(["kz.ecc.unlisted.Module"])),
            |r| matches!(r, R::ModuleNotAllowed(m) if m == "kz.ecc.unlisted.Module"),
        ),
        (
            Box::new(|e| e["replaces"]["symname"] = json!("kz.ecc.unlisted")),
            |r| matches!(r, R::BundleNotAllowed(b) if b == "kz.ecc.unlisted"),
        ),
        (
            Box::new(|e| {
                e.as_object_mut().unwrap().remove("capabilities");
            }),
            |r| matches!(r, R::NoCapabilities),
        ),
        (Box::new(|e| e["capabilities"] = json!(["keys"])), |r| {
            matches!(r, R::Capabilities(CapabilitiesError::NotObject))
        }),
        (
            Box::new(|e| {
                e["capabilities"] = json!({ "http": vec!["https://api.ecc.kz/".repeat(8); 128] });
            }),
            |r| matches!(r, R::Capabilities(CapabilitiesError::TooLarge { .. })),
        ),
    ];
    for (index, (change, expected)) in cases.into_iter().enumerate() {
        let reason = rejection(change);
        assert!(expected(&reason), "case {index}: {reason:?}");
    }
    let mut no_entry = target(Value::Null);
    no_entry.custom = Some(json!({"other": {}}));
    let targets = BTreeMap::from([(path_of(&entry(MARKET, "1.0.0")), no_entry)]);
    let catalog = build(index(vec![]), vec![ecc_entry()], &[("ecc", Some(&targets))]);
    assert!(matches!(catalog.rejected()[0].reason, R::NoEntry));
}

#[test]
fn a_prerelease_cannot_be_stable() {
    let mut oncl = entry(MARKET, "1.0.0-rc.1");
    oncl["channel"] = json!("stable");
    assert!(matches!(
        rejection_at("plugins/ecc/kz.ecc.market/1.0.0-rc.1.onclp", oncl),
        EntryRejection::StablePrerelease
    ));
}

#[test]
fn a_broken_target_leaves_the_rest_of_its_role_alone() {
    let mut broken = entry(MARKET, "1.1.0");
    broken["url"] = json!("http://downloads.ecc.kz/p.onclp");
    let catalog = ecc_catalog(&[entry(MARKET, "1.0.0"), broken]);
    assert_eq!(catalog.rejected().len(), 1);
    assert_eq!(by_module(&catalog, SIGNER).unwrap().version, v("1.0.0"));
}

#[test]
fn publishers_json_reads_active_and_revoked_publishers() {
    let mut active = superseding_ecc();
    active["revoked_versions"] = json!([{"id": MARKET, "version": "1.1.0", "date": "2027-02-10"}]);
    let revoked = json!({
        "name": "old", "state": "revoked", "display": display(),
        "id_prefix": "kz.old.", "revoked": "2027-03-01", "future": true
    });
    let policy = policy(vec![active, revoked]);
    let ecc = policy.publisher(&ecc()).unwrap();
    assert_eq!(ecc.id_prefix().as_str(), "kz.ecc.");
    assert_eq!(ecc.display().en, "ECC");
    let rules = ecc.active().unwrap();
    assert!(rules.modules().contains(SIGNER));
    assert!(rules.bundles().contains(MARKET));
    assert_eq!(rules.supersedes()[PORT].as_str(), MARKET);
    assert_eq!(rules.homepage(), Some("https://ecc.kz/"));
    assert_eq!(
        rules.revoked_versions()[0].date,
        time::macros::date!(2027 - 02 - 10)
    );
    assert!(rules.revokes(MARKET, &v("1.1.0")));
    assert_eq!(
        policy.covering("kz.old.thing").unwrap().name().as_str(),
        "old"
    );
    assert_eq!(
        policy.publishers()[1].standing(),
        &Standing::Revoked {
            date: Some(time::macros::date!(2027 - 03 - 01))
        }
    );
    assert_eq!(policy.superseding(PORT).unwrap().1.as_str(), MARKET);
}

fn with(change: impl FnOnce(&mut Value)) -> Value {
    let mut publisher = ecc_entry();
    change(&mut publisher);
    publisher
}

fn second(prefix: &str) -> Value {
    json!({
        "name": "second", "state": "active", "display": display(),
        "id_prefix": prefix, "modules": ["kz.second.Module"], "bundles": []
    })
}

#[test]
fn publishers_json_refuses_overlapping_prefixes() {
    assert!(matches!(
        refused(vec![ecc_entry(), second("kz.ecc.sub.")]),
        CatalogError::NestedPrefix(..)
    ));
    assert!(matches!(
        refused(vec![second("kz.ecc."), ecc_entry()]),
        CatalogError::NestedPrefix(..)
    ));
    for prefix in ["io.github.", "io.github.arynyklas.openncalayer.port."] {
        assert!(matches!(
            refused(vec![second(prefix)]),
            CatalogError::ProjectPrefix(_)
        ));
    }
}

#[test]
fn publishers_json_refuses_shared_modules_and_bundles() {
    let mut taker = second("kz.second.");
    taker["modules"] = json!([SIGNER]);
    assert!(matches!(
        refused(vec![ecc_entry(), taker]),
        CatalogError::SharedModule { .. }
    ));
    let mut taker = second("kz.second.");
    taker["bundles"] = json!([MARKET]);
    assert!(matches!(
        refused(vec![ecc_entry(), taker]),
        CatalogError::SharedBundle { .. }
    ));
    assert!(matches!(
        refused(vec![with(|p| p["modules"] = json!([SIGNER, SIGNER]))]),
        CatalogError::SharedModule { .. }
    ));
}

#[test]
fn publishers_json_refuses_what_lies_outside_a_prefix() {
    let foreign_revocation = with(|p| {
        p["revoked_versions"] =
            json!([{"id": "kz.other.market", "version": "1.0.0", "date": "2027-02-10"}]);
    });
    assert!(matches!(
        refused(vec![foreign_revocation]),
        CatalogError::RevokedVersion { .. }
    ));
    let foreign_replacement = with(|p| p["supersedes"] = json!({ PORT: "kz.other.market" }));
    assert!(matches!(
        refused(vec![foreign_replacement]),
        CatalogError::Supersedes { .. }
    ));
    let own_port = with(|p| p["supersedes"] = json!({ "kz.ecc.port": MARKET }));
    assert!(matches!(
        refused(vec![own_port]),
        CatalogError::Supersedes { .. }
    ));
    let mut twice = second("kz.second.");
    twice["supersedes"] = json!({ PORT: "kz.second.market" });
    assert!(matches!(
        refused(vec![superseding_ecc(), twice]),
        CatalogError::Supersedes { .. }
    ));
}

#[test]
fn publishers_json_refuses_unacceptable_display_names_and_homepages() {
    for name in ["", " ", "ECC\u{7}", "OpenNCALayer", "ECC openncalayer"] {
        let publisher = with(|p| p["display"]["kk"] = json!(name));
        assert!(
            matches!(refused(vec![publisher]), CatalogError::Display(_)),
            "{name:?}"
        );
    }
    let long = with(|p| p["display"]["en"] = json!("Е".repeat(129)));
    assert!(matches!(refused(vec![long]), CatalogError::Display(_)));
    for homepage in ["http://ecc.kz/", "https://ecc.kz/?a=1", "https://a@ecc.kz/"] {
        let publisher = with(|p| p["homepage"] = json!(homepage));
        assert!(
            matches!(refused(vec![publisher]), CatalogError::Homepage(_)),
            "{homepage}"
        );
    }
}

#[test]
fn publishers_json_compares_module_and_bundle_names_ignoring_case() {
    let mut taker = second("kz.second.");
    taker["modules"] = json!([SIGNER.to_ascii_uppercase()]);
    assert!(matches!(
        refused(vec![ecc_entry(), taker]),
        CatalogError::SharedModule { .. }
    ));
    let mut taker = second("kz.second.");
    taker["bundles"] = json!([MARKET.to_ascii_uppercase()]);
    assert!(matches!(
        refused(vec![ecc_entry(), taker]),
        CatalogError::SharedBundle { .. }
    ));
}

#[test]
fn publishers_json_refuses_bad_shapes() {
    assert!(matches!(
        refused(vec![ecc_entry(), ecc_entry()]),
        CatalogError::Duplicate(_)
    ));
    assert!(matches!(
        refused(vec![with(|p| p["name"] = json!("owner"))]),
        CatalogError::Name(_)
    ));
    assert!(matches!(
        refused(vec![with(|p| p["id_prefix"] = json!("kz.ecc"))]),
        CatalogError::Name(_)
    ));
    assert!(matches!(
        refused(vec![with(|p| p["state"] = json!(7))]),
        CatalogError::Json(_)
    ));
    let bad_date = with(|p| {
        p["revoked_versions"] = json!([{"id": MARKET, "version": "1.0.0", "date": "2027-02-30"}]);
    });
    assert!(matches!(refused(vec![bad_date]), CatalogError::Date { .. }));
    let schema = serde_json::to_vec(&json!({"schema": 2, "publishers": "?"})).unwrap();
    assert!(matches!(
        PublisherPolicy::from_json(&schema),
        Err(CatalogError::Schema(2))
    ));
}

#[test]
fn declared_capabilities_are_an_object_of_at_most_16_kib() {
    let fits = json!({ "pad": "x".repeat(DeclaredCapabilities::MAX_LEN - 12) });
    assert!(DeclaredCapabilities::try_from(fits).is_ok());
    let over = json!({ "pad": "x".repeat(DeclaredCapabilities::MAX_LEN) });
    assert!(matches!(
        DeclaredCapabilities::try_from(over),
        Err(CapabilitiesError::TooLarge { .. })
    ));
    assert_eq!(
        DeclaredCapabilities::try_from(json!(true)),
        Err(CapabilitiesError::NotObject)
    );
}

#[test]
fn the_first_role_of_a_publisher_counts() {
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let catalog = Catalog::builder(
        index(vec![]),
        &BTreeMap::new(),
        Ok(policy(vec![ecc_entry()])),
    )
    .role(&role_name("ecc"), &targets)
    .unavailable_role(&role_name("ecc"))
    .build();
    assert_eq!(catalog.publisher_state(&ecc()), PublisherState::Active);
    assert_eq!(catalog.releases().count(), 1);
    assert_eq!(Channel::Stable, catalog.index().channel);
}

#[test]
fn publishers_json_takes_up_to_its_limits_and_no_more() {
    let publishers = |count: usize| -> Vec<Value> {
        (0..count)
            .map(|n| {
                json!({
                    "name": format!("p{n:03}"), "state": "revoked", "display": display(),
                    "id_prefix": format!("kz.p{n:03}.")
                })
            })
            .collect()
    };
    let most = PublisherPolicy::MAX_PUBLISHERS;
    assert_eq!(most, 128);
    assert_eq!(policy(publishers(most)).publishers().len(), most);
    assert!(matches!(
        refused(publishers(most + 1)),
        CatalogError::TooMany {
            count: 129,
            max: 128
        }
    ));

    // The revoked versions count across all publishers.
    let revocations = |id: &str, numbers: std::ops::Range<usize>| -> Value {
        numbers
            .map(|n| json!({"id": id, "version": format!("1.0.{n}"), "date": "2027-02-10"}))
            .collect()
    };
    let split = |total: usize| -> Vec<u8> {
        let half = total / 2;
        let mut ecc = ecc_entry();
        ecc["revoked_versions"] = revocations(MARKET, 0..half);
        let mut other = second("kz.second.");
        other["revoked_versions"] = revocations("kz.second.tool", half..total);
        policy_json(vec![ecc, other])
    };
    let most = PublisherPolicy::MAX_REVOKED_VERSIONS;
    assert_eq!(most, 8000);
    let fits = split(most);
    assert!(fits.len() <= PublisherPolicy::MAX_LEN);
    let read = PublisherPolicy::from_json(&fits).unwrap();
    assert!(
        read.publishers()[1]
            .rules()
            .unwrap()
            .revokes("kz.second.tool", &v("1.0.7999"))
    );
    assert!(matches!(
        PublisherPolicy::from_json(&split(most + 1)),
        Err(CatalogError::TooManyRevoked {
            count: 8001,
            max: 8000
        })
    ));

    // The file: 1 MiB, padding included.
    assert_eq!(PublisherPolicy::MAX_LEN, 1024 * 1024);
    let mut bytes = policy_json(vec![ecc_entry()]);
    bytes.resize(PublisherPolicy::MAX_LEN, b' ');
    assert!(PublisherPolicy::from_json(&bytes).is_ok());
    bytes.push(b' ');
    assert!(matches!(
        PublisherPolicy::from_json(&bytes),
        Err(CatalogError::TooLarge { len, max }) if len == max + 1 && max == 1024 * 1024
    ));
}

#[test]
fn the_mirror_is_the_projects_releases() {
    assert_eq!(
        MIRROR_BASE,
        "https://github.com/arynyklas/OpenNCALayer/releases/download/"
    );
    let place = PublisherTarget::parse(&path_of(&entry(MARKET, "1.2.0"))).unwrap();
    assert_eq!(
        mirror_url(&ecc(), &place.id, &place.version, &Digest([9; 32])),
        mirrored(MARKET, "1.2.0")
    );
}

#[test]
fn a_publisher_version_has_no_build_metadata() {
    assert!(matches!(
        rejection_at(
            "plugins/ecc/kz.ecc.market/1.1.0+build.7.onclp",
            entry(MARKET, "1.1.0+build.7")
        ),
        EntryRejection::BuildMetadata
    ));
}

/// `PublisherRelease::parse` of `entry(MARKET, "1.0.0")` with `change` made to its `source`.
fn parse_with_source(change: impl FnOnce(&mut Value)) -> Result<PublisherRelease, EntryRejection> {
    let mut oncl = entry(MARKET, "1.0.0");
    change(&mut oncl["source"]);
    PublisherRelease::parse(&ecc(), &path_of(&oncl), &target(oncl))
}

#[test]
fn a_source_is_read_by_the_rules_of_its_fields() {
    let release = parse_with_source(|_| {}).unwrap();
    let source = release.source();
    assert_eq!(source.archive_sha256, Sha256([0xab; 32]));
    assert_eq!(source.archive_length, 2_345_678);
    assert_eq!(
        source.fetch,
        "https://downloads.ecc.kz/oncl/kz.ecc.market-1.2.0.src.tar.gz"
    );
    assert_eq!(source.path, "crates/market");
    assert_eq!(source.license, "Apache-2.0");
    assert_eq!(source.builder, Sha256([0xcd; 32]));
    let vcs = source.vcs.as_ref().unwrap();
    assert_eq!(vcs.url, "https://git.ecc.kz/oncl/market.git");
    assert_eq!(vcs.rev, "ef".repeat(20));

    let accepted: Vec<Change> = vec![
        Box::new(|s| {
            s.as_object_mut().unwrap().remove("vcs");
        }),
        Box::new(|s| s["vcs"] = Value::Null),
        Box::new(|s| s["vcs"]["rev"] = json!("ef".repeat(32))),
        Box::new(|s| s["path"] = json!("")),
        Box::new(|s| s["fetch"] = json!("https://downloads.ecc.kz/get?file=market.tar.gz")),
        Box::new(|s| s["archive_length"] = json!(ReleaseSource::MAX_ARCHIVE)),
        Box::new(|s| s["license"] = json!("(MIT OR Apache-2.0) AND Unicode-3.0")),
        Box::new(|s| s["license"] = json!("Not-Yet-Listed-1.0")),
        Box::new(|s| s["future"] = json!({"any": 1})),
    ];
    for (index, change) in accepted.into_iter().enumerate() {
        if let Err(reason) = parse_with_source(change) {
            panic!("case {index}: {reason:?}");
        }
    }

    type SourceExpected = fn(&SourceError) -> bool;
    use SourceError as S;
    let refused: Vec<(Change, SourceExpected)> = vec![
        (Box::new(|s| *s = json!("https://x/")), |e| {
            matches!(e, S::Malformed(_))
        }),
        (
            Box::new(|s| {
                s.as_object_mut().unwrap().remove("license");
            }),
            |e| matches!(e, S::Malformed(_)),
        ),
        (Box::new(|s| s["archive_length"] = json!(-1)), |e| {
            matches!(e, S::Malformed(_))
        }),
        (Box::new(|s| s["vcs"] = json!("https://x/")), |e| {
            matches!(e, S::Malformed(_))
        }),
        (
            Box::new(|s| s["archive_sha256"] = json!("AB".repeat(32))),
            |e| matches!(e, S::ArchiveSha256),
        ),
        (
            Box::new(|s| s["archive_sha256"] = json!("ab".repeat(31))),
            |e| matches!(e, S::ArchiveSha256),
        ),
        (Box::new(|s| s["archive_length"] = json!(0)), |e| {
            matches!(e, S::ArchiveLength(0))
        }),
        (
            Box::new(|s| s["archive_length"] = json!(ReleaseSource::MAX_ARCHIVE + 1)),
            |e| matches!(e, S::ArchiveLength(_)),
        ),
        (
            Box::new(|s| s["fetch"] = json!("http://downloads.ecc.kz/a.tar.gz")),
            |e| matches!(e, S::Fetch),
        ),
        (
            Box::new(|s| s["fetch"] = json!("https://user:pw@downloads.ecc.kz/a.tar.gz")),
            |e| matches!(e, S::Fetch),
        ),
        (
            Box::new(|s| s["fetch"] = json!("https://downloads.ecc.kz/a.tar.gz#top")),
            |e| matches!(e, S::Fetch),
        ),
        (
            Box::new(|s| s["fetch"] = json!(format!("https://ecc.kz/{}", "a".repeat(2048)))),
            |e| matches!(e, S::Fetch),
        ),
        (Box::new(|s| s["path"] = json!("/crates/market")), |e| {
            matches!(e, S::Path)
        }),
        (Box::new(|s| s["path"] = json!("crates/../market")), |e| {
            matches!(e, S::Path)
        }),
        (Box::new(|s| s["license"] = json!("MIT/Apache-2.0")), |e| {
            matches!(e, S::License)
        }),
        (Box::new(|s| s["license"] = json!("")), |e| {
            matches!(e, S::License)
        }),
        (Box::new(|s| s["builder"] = json!("cd".repeat(32))), |e| {
            matches!(e, S::Builder)
        }),
        (
            Box::new(|s| s["builder"] = json!(format!("sha256:{}", "CD".repeat(32)))),
            |e| matches!(e, S::Builder),
        ),
        (
            Box::new(|s| s["builder"] = json!(format!("sha512:{}", "cd".repeat(32)))),
            |e| matches!(e, S::Builder),
        ),
        (
            Box::new(|s| s["vcs"]["url"] = json!("http://git.ecc.kz/market.git")),
            |e| matches!(e, S::Vcs),
        ),
        (
            Box::new(|s| s["vcs"]["rev"] = json!("ef".repeat(21))),
            |e| matches!(e, S::Vcs),
        ),
        (
            Box::new(|s| s["vcs"]["rev"] = json!("EF".repeat(20))),
            |e| matches!(e, S::Vcs),
        ),
        (
            Box::new(|s| s["fetch"] = json!("https://downloads.ecc.kz/\u{202e}zg.rat.gz")),
            |e| matches!(e, S::Fetch),
        ),
        (
            Box::new(|s| s["fetch"] = json!("https://downloads.ecс.kz/a.tar.gz")),
            |e| matches!(e, S::Fetch),
        ),
        (
            Box::new(|s| s["vcs"]["url"] = json!("https://git.ecc.kz/\u{200b}market.git")),
            |e| matches!(e, S::Vcs),
        ),
        (
            Box::new(|s| s["path"] = json!("crates/маркет")),
            |e| matches!(e, S::Path),
        ),
        (Box::new(|s| s["path"] = json!("crates/my market")), |e| {
            matches!(e, S::Path)
        }),
    ];
    for (index, (change, expected)) in refused.into_iter().enumerate() {
        match parse_with_source(change) {
            Err(EntryRejection::Source(error)) if expected(&error) => {}
            other => panic!("case {index}: {other:?}"),
        }
    }
    // In a catalog the target is left out with the rest of its role kept.
    let mut broken = entry(MARKET, "1.1.0");
    broken["source"]["license"] = json!("MIT/Apache-2.0");
    let catalog = ecc_catalog(&[entry(MARKET, "1.0.0"), broken]);
    assert!(matches!(
        catalog.rejected()[0].reason,
        EntryRejection::Source(SourceError::License)
    ));
    assert_eq!(by_module(&catalog, SIGNER).unwrap().version, v("1.0.0"));
}

#[test]
fn a_publisher_target_in_the_top_level_targets_makes_every_publisher_unavailable() {
    let targets = role(&[entry(MARKET, "1.0.0")]);
    let owner = port(PORT, "1.0.0", "kz.owner.Module", "kz.owner.bundle");
    let top = |path: &str| {
        BTreeMap::from([
            (
                TargetPath::parse("indexes/stable.json").unwrap(),
                target(Value::Null),
            ),
            (TargetPath::parse(path).unwrap(), target(Value::Null)),
        ])
    };
    let catalog_with = |path: &str| {
        Catalog::builder(
            index(vec![owner.clone()]),
            &top(path),
            Ok(policy(vec![ecc_entry()])),
        )
        .role(&role_name("ecc"), &targets)
        .build()
    };
    let clean = catalog_with("publishers.json");
    assert_eq!(clean.publisher_state(&ecc()), PublisherState::Active);
    for path in ["plugins/ecc/kz.ecc.market/1.0.0.onclp", "plugins/x"] {
        let tainted = catalog_with(path);
        assert_eq!(
            tainted.publisher_state(&ecc()),
            PublisherState::Unavailable,
            "{path}"
        );
        assert!(tainted.policy().is_none());
        assert_eq!(tainted.releases().count(), 1);
        assert_eq!(by_module(&tainted, "kz.owner.Module").unwrap().id, PORT);
    }
}

#[test]
fn a_publisher_revocation_holds_on_every_channel_whatever_else_the_target_breaks() {
    let mut beta = entry(MARKET, "2.0.0-beta.1");
    beta["channel"] = json!("beta");
    beta["revoked"] = json!(true);
    // A module the owner since took back from the publisher.
    let mut taken = entry(MARKET, "1.1.0");
    taken["modules"] = json!(["kz.ecc.taken.Module"]);
    taken["revoked"] = json!(true);
    // A newer schema this version does not read.
    let mut newer = entry(MARKET, "1.2.0");
    newer["schema"] = json!(2);
    newer["revoked"] = json!(true);
    // Under another publisher's prefix: not this role's to revoke.
    let mut foreign = entry("kz.second.tool", "1.0.0");
    foreign["revoked"] = json!(true);
    let targets = role(&[entry(MARKET, "1.0.0"), beta, taken, newer, foreign]);
    let mut other = second("kz.second.");
    other["state"] = json!("retired");
    for state in ["active", "retired", "suspended"] {
        let mut publisher = ecc_entry();
        publisher["state"] = json!(state);
        let catalog = build(
            index(vec![]),
            vec![publisher, other.clone()],
            &[("ecc", Some(&targets))],
        );
        for revoked in ["2.0.0-beta.1", "1.1.0", "1.1.0+local", "1.2.0"] {
            assert!(catalog.is_revoked(MARKET, &v(revoked)), "{state} {revoked}");
        }
        assert!(!catalog.is_revoked(MARKET, &v("1.0.0")), "{state}");
        assert!(
            !catalog.is_revoked("kz.second.tool", &v("1.0.0")),
            "{state}"
        );
        for current in ["2.0.0-beta.1", "1.1.0"] {
            let choice = choose(&catalog, MARKET, current);
            if state == "active" {
                assert!(
                    matches!(choice, PluginChoice::Downgrade(r) if r.version == v("1.0.0")),
                    "{state} {current}: {choice:?}"
                );
            } else {
                assert_eq!(choice, PluginChoice::Withdrawn, "{state} {current}");
            }
        }
    }
}

#[test]
fn a_replaced_port_lies_under_no_publishers_prefix() {
    for state in ["active", "retired", "revoked"] {
        let mut other = second("kz.second.");
        other["state"] = json!(state);
        let replacing = with(|p| p["supersedes"] = json!({ "kz.second.port": MARKET }));
        assert!(
            matches!(
                refused(vec![replacing.clone(), other.clone()]),
                CatalogError::Supersedes { .. }
            ),
            "{state}"
        );
        assert!(
            matches!(
                refused(vec![other, replacing]),
                CatalogError::Supersedes { .. }
            ),
            "{state}"
        );
    }
}

#[test]
fn one_publishers_modules_and_bundles_differ_in_more_than_case() {
    let lower = SIGNER.to_ascii_lowercase();
    assert!(matches!(
        refused(vec![with(|p| p["modules"] = json!([SIGNER, lower]))]),
        CatalogError::SharedModule { .. }
    ));
    let upper = MARKET.to_ascii_uppercase();
    assert!(matches!(
        refused(vec![with(|p| p["bundles"] = json!([MARKET, upper]))]),
        CatalogError::SharedBundle { .. }
    ));
}

#[test]
fn the_mirror_url_has_the_package_hash_in_lowercase_hex_only() {
    let oncl = entry(MARKET, "1.0.0");
    let path = path_of(&oncl);
    let lower = format!("pub-ecc-{}", "ab".repeat(32));
    let upper = format!("pub-ecc-{}", "AB".repeat(32));
    let package = |url: String| {
        let mut oncl = oncl.clone();
        oncl["url"] = json!(url);
        let mut target = target(oncl);
        target.sha256 = Digest([0xab; 32]);
        PublisherRelease::parse(&ecc(), &path, &target)
    };
    let url = mirrored(MARKET, "1.0.0").replace(&format!("pub-ecc-{}", package_hex()), &lower);
    assert!(package(url.clone()).is_ok());
    assert!(matches!(
        package(url.replace(&lower, &upper)),
        Err(EntryRejection::NotMirrored)
    ));
}
