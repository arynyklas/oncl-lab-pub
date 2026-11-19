//! The project site from the fixtures of `fixtures/registry` and from the repository's own
//! ports. The tests that run Zola download the pinned Zola once: they are `#[ignore]`d and
//! named `zola_…`: the `test` job of CI skips them, the `site` job runs them.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde_json::Value;
use sha2::{Digest, Sha256};
use xtask::registry::{Inputs, build, check, generate, site, zola};

fn root() -> PathBuf {
    oncl_testkit::workspace_root()
}

fn fixtures() -> PathBuf {
    root().join("fixtures/registry")
}

fn fixture_inputs() -> Inputs {
    Inputs {
        plugins: fixtures().join("plugins"),
        updates: Some(fixtures().join("updates/v1")),
        releases: Some(fixtures().join("releases.jsonl")),
        upstream: Some(fixtures().join("upstream")),
        publishers: Some(fixtures().join("publishers")),
        tuf: Some(fixtures().join("tuf/v1")),
    }
}

/// Every file under `dir` and its sha256.
fn hashes(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                // The ports' build output is not an input.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else {
                let digest = Sha256::digest(fs::read(&path).unwrap()).to_vec();
                out.insert(path, digest);
            }
        }
    }
    out
}

#[test]
fn generate_leaves_inputs_untouched() {
    let dirs = [fixtures(), root().join("plugins"), root().join("site")];
    let before: Vec<_> = dirs.iter().map(|d| hashes(d)).collect();
    let out = tempfile::tempdir().unwrap();
    generate(&root(), &fixture_inputs(), &out.path().join("fixtures")).unwrap();
    let committed = Inputs {
        plugins: root().join("plugins"),
        updates: None,
        releases: None,
        upstream: None,
        publishers: None,
        tuf: None,
    };
    generate(&root(), &committed, &out.path().join("committed")).unwrap();
    let after: Vec<_> = dirs.iter().map(|d| hashes(d)).collect();
    assert_eq!(before, after);
}

fn fixture_data() -> Value {
    let out = tempfile::tempdir().unwrap();
    generate(&root(), &fixture_inputs(), out.path()).unwrap();
    serde_json::from_slice(&fs::read(out.path().join("data/site.json")).unwrap()).unwrap()
}

#[test]
fn fixture_data_matches_expectations() {
    let data = fixture_data();
    let plugins = &data["plugins"];
    assert_eq!(plugins["alpha"]["original"]["state"], "same");
    assert_eq!(plugins["gamma"]["original"]["state"], "changed");
    assert_eq!(plugins["gamma"]["original"]["current"], "1.1");
    assert_eq!(plugins["hostile"]["original"]["state"], "removed");

    assert_eq!(plugins["alpha"]["channels"]["stable"]["version"], "1.0.0");
    assert_eq!(
        plugins["alpha"]["channels"]["beta"]["version"],
        "1.1.0-beta.1"
    );
    assert_eq!(plugins["alpha"]["channels"]["beta"]["rollout"], 25);
    assert_eq!(plugins["gamma"]["channels"], serde_json::json!({}));
    let hostile: Vec<&String> = plugins["hostile"]["channels"]
        .as_object()
        .unwrap()
        .keys()
        .collect();
    assert_eq!(hostile, ["beta"]);

    assert_eq!(data["channels"]["stable"]["seq"], 3);
    assert_eq!(data["channels"]["stable"]["core"], "0.2.0");
    assert_eq!(data["channels"]["beta"]["core"], "0.3.0-beta.1");
    assert_eq!(data["channels"]["beta"]["expires"], "2026-12-01");

    let releases = &data["releases"];
    assert_eq!(releases["available"], true);
    assert_eq!(releases["release"]["version"], "0.2.0");
    assert_eq!(releases["release"]["published"], "2026-10-20");
    assert_eq!(releases["release"]["assets"].as_array().unwrap().len(), 10);
    assert_eq!(releases["prerelease"]["version"], "0.3.0-beta.1");
    let kinds: Vec<&str> = releases["prerelease"]["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["kind"].as_str().unwrap())
        .collect();
    assert!(
        !kinds.contains(&"osx-pkg") && !kinds.contains(&"osx-zip"),
        "{kinds:?}"
    );

    let upstream = &data["upstream"];
    assert_eq!(upstream["available"], true);
    assert_eq!(upstream["version"], "1.4");
    let core = upstream["bundles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["symname"] == "kz.gov.pki.kalkan.xmldsig")
        .unwrap();
    assert_eq!(core["changed"], true);
    assert_eq!(upstream["history"][0]["url"], Value::Null);
    assert_eq!(upstream["history"].as_array().unwrap().len(), 2);
}

#[test]
fn fixture_publishers_data_matches_expectations() {
    let data = fixture_data();
    let publishers = &data["publishers"];
    let list = &publishers["list"];
    assert_eq!(list["acme"]["state"], "active");
    assert_eq!(list["olden"]["state"], "retired");
    assert_eq!(list["gone"]["state"], "revoked");
    assert_eq!(list["gone"]["revoked"], "2026-10-01");
    // A revoked publisher's plugins are gone from the site, its role file aside.
    assert_eq!(list["gone"]["plugins"], serde_json::json!([]));
    assert_eq!(
        list["acme"]["plugins"],
        serde_json::json!(["kz.acme.market", "kz.acme.sign"])
    );
    assert_eq!(
        list["olden"]["plugins"],
        serde_json::json!(["kz.olden.tool"])
    );
    // Latin before Cyrillic, case-insensitively.
    assert_eq!(
        publishers["order"]["en"],
        serde_json::json!(["acme", "gone", "olden"])
    );

    let plugins = &publishers["plugins"];
    let keys: Vec<&String> = plugins.as_object().unwrap().keys().collect();
    // The newest role only (not 1.pub-acme.json's 0.1.0); the rogue module left out.
    assert_eq!(keys, ["kz.acme.market", "kz.acme.sign", "kz.olden.tool"]);
    let market = &plugins["kz.acme.market"];
    let versions: Vec<&str> = market["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.2.0-beta.1", "1.1.0", "1.0.0"]);
    // 1.1.0 is revoked by the owner: stable offers 1.0.0.
    assert_eq!(market["versions"][1]["revoked"], true);
    assert_eq!(market["versions"][2]["revoked"], false);
    assert_eq!(market["channels"]["stable"]["version"], "1.0.0");
    assert_eq!(market["channels"]["beta"]["version"], "1.2.0-beta.1");
    assert_eq!(market["channels"]["beta"]["rollout"], 50);
    // Its bundle has a port: the port's row keeps the id.
    assert_eq!(market["anchor"], Value::Null);
    let sign = &plugins["kz.acme.sign"];
    assert_eq!(sign["versions"][0]["revoked"], true);
    assert_eq!(sign["channels"]["beta"]["version"], "2.0.0");
    assert_eq!(sign["anchor"], "kz.example.unported");
    // A retired publisher's plugins are offered on no channel.
    assert_eq!(plugins["kz.olden.tool"]["channels"], serde_json::json!({}));

    let v = &market["versions"][2];
    let sha = v["sha256"].as_str().unwrap();
    let release =
        format!("https://github.com/arynyklas/OpenNCALayer/releases/download/pub-acme-{sha}/");
    assert_eq!(
        v["package_url"],
        format!("{release}kz.acme.market-1.0.0.onclp")
    );
    assert_eq!(
        v["source_url"],
        format!("{release}kz.acme.market-1.0.0.src.tar.gz")
    );
    assert_eq!(v["buildinfo_url"], format!("{release}BUILDINFO.json"));
    assert_eq!(
        v["release_url"],
        format!("https://github.com/arynyklas/OpenNCALayer/releases/tag/pub-acme-{sha}")
    );
    assert_eq!(v["license"], "Apache-2.0");
    // No `.src.diff` link: the role does not tell whether the release has one.
    assert_eq!(v.get("diff_url"), None);
    // A name with a bidi override is left out.
    assert!(plugins.get("kz.acme.bidi").is_none());
    // The crate's directory is quoted for the shell, whatever it holds; the build runs
    // without a network after a separate fetch.
    let verify = market["versions"][1]["verify"].as_str().unwrap();
    let lines: Vec<&str> = verify.lines().collect();
    assert_eq!(lines.len(), 4, "{verify}");
    assert_eq!(lines[0], "docker volume create oncl-verify-cargo");
    assert_eq!(lines[3], "docker volume rm oncl-verify-cargo");
    let image = "ghcr.io/arynyklas/oncl-plugin-builder@sha256:";
    assert!(
        lines[1].contains(image)
            && lines[1].contains(
                r#" fetch --source /in/kz.acme.market-1.1.0.src.tar.gz --path='it'\''s;$(id)'"#
            )
            && !lines[1].contains("--network=none"),
        "{verify}"
    );
    assert!(
        lines[2].starts_with("docker run --rm --network=none ")
            && lines[2].contains("-v oncl-verify-cargo:/cargo:ro ")
            && lines[2].ends_with(&format!(
                r#" verify --source /in/kz.acme.market-1.1.0.src.tar.gz --path='it'\''s;$(id)' --sha256 {}"#,
                market["versions"][1]["sha256"].as_str().unwrap()
            )),
        "{verify}"
    );
    assert!(
        sign["versions"][1]["verify"]
            .as_str()
            .unwrap()
            .contains("--path='' "),
    );

    // The port the active publisher supersedes names its replacement.
    assert_eq!(
        data["plugins"]["alpha"]["replaced_by"],
        serde_json::json!({"publisher": "acme", "id": "kz.acme.market"})
    );
    assert_eq!(data["plugins"]["gamma"]["replaced_by"], Value::Null);
    let unported = data["upstream"]["bundles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["symname"] == "kz.example.unported")
        .unwrap();
    assert_eq!(unported["replacement"], "kz.acme.sign");
}

/// The pinned Zola, downloaded once for all tests.
static ZOLA: LazyLock<PathBuf> = LazyLock::new(|| zola::ensure(&root()).unwrap());

fn zola() -> &'static Path {
    &ZOLA
}

fn base_url() -> String {
    site::site_config(&root()).unwrap().base_url
}

fn built(inputs: &Inputs) -> (tempfile::TempDir, PathBuf) {
    let out = tempfile::tempdir().unwrap();
    let public = build(&root(), inputs, out.path(), Some(zola())).unwrap();
    (out, public)
}

fn read(public: &Path, page: &str) -> String {
    fs::read_to_string(public.join(page)).unwrap_or_else(|e| panic!("{page}: {e}"))
}

const LANG_PREFIXES: [&str; 3] = ["", "kk/", "en/"];

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_builds_from_committed_data() {
    let existing = |path: &str| {
        let dir = root().join(path);
        dir.is_dir().then_some(dir)
    };
    let inputs = Inputs {
        plugins: root().join("plugins"),
        updates: existing("updates/v1"),
        releases: None,
        upstream: None,
        publishers: existing("publishers"),
        tuf: existing("tuf/v1"),
    };
    let (_out, public) = built(&inputs);
    let ports = xtask::registry::ports::load(&root().join("plugins")).unwrap();
    assert_eq!(ports.len(), 35);
    for port in &ports {
        for prefix in LANG_PREFIXES {
            let page = format!("{prefix}plugins/{}/index.html", port.short);
            assert!(public.join(&page).is_file(), "{page}");
        }
    }
    check(&public, &base_url()).unwrap();
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_builds_from_fixtures() {
    let (_out, public) = built(&fixture_inputs());
    assert!(!public.join("updates").exists());
    copy_tree(&fixtures().join("updates"), &public.join("updates"));
    let report = check(&public, &base_url()).unwrap();
    assert!(report.pages >= 22, "{report:?}");
    assert_eq!(
        fs::read(public.join("updates/v1/beta.json")).unwrap(),
        fs::read(fixtures().join("updates/v1/beta.json")).unwrap()
    );
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_escapes_hostile_fixture() {
    let (_out, public) = built(&fixture_inputs());
    let mut pages: Vec<String> = LANG_PREFIXES
        .iter()
        .flat_map(|p| {
            [
                format!("{p}plugins/hostile/index.html"),
                format!("{p}plugins/index.html"),
                format!("{p}upstream/index.html"),
                format!("{p}publishers/index.html"),
                format!("{p}publishers/acme/index.html"),
                format!("{p}plugins/alpha/index.html"),
            ]
        })
        .collect();
    pages.push("download/index.html".to_owned());
    for page in pages {
        let html = read(&public, &page);
        let lower = html.to_ascii_lowercase();
        assert!(!lower.contains("<script"), "{page}");
        assert!(!lower.contains("<img"), "{page}");
        if page.contains("hostile")
            || page.contains("plugins/index")
            || page.contains("upstream")
            || page.contains("publishers")
            || page.contains("alpha")
        {
            assert!(
                html.contains("&lt;script&gt;alert(1)&lt;&#x2F;script&gt;")
                    || html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
                "{page}"
            );
            assert!(html.contains("{{ config.base_url }}"), "{page}");
            assert!(html.contains("{% raw %}"), "{page}");
            // Every `onerror=` is inside escaped text, after an escaped `<img`.
            for (at, _) in html.match_indices("onerror=") {
                let before = &html[..at];
                let tag = before.rfind('<').unwrap_or(0);
                let escaped = before.rfind("&lt;img").unwrap_or(0);
                assert!(escaped > tag, "{page}: onerror= in markup");
            }
        }
    }
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_works_without_any_optional_input() {
    let inputs = Inputs {
        plugins: fixtures().join("plugins"),
        updates: None,
        releases: None,
        upstream: None,
        publishers: None,
        tuf: None,
    };
    let (_out, public) = built(&inputs);
    for prefix in LANG_PREFIXES {
        for page in ["download/index.html", "upstream/index.html"] {
            let html = read(&public, &format!("{prefix}{page}"));
            assert!(html.contains("class=\"nodata\""), "{prefix}{page}");
        }
    }
    let ru = read(&public, "download/index.html");
    assert!(ru.contains("Список релизов недоступен"), "{ru}");
    assert!(read(&public, "upstream/index.html").contains("Данных наблюдателя пока нет"));
    // No publishers: the list says so, and so does the catalog's table of their plugins.
    for (prefix, none, plugins_none) in [
        ("", "Издателей пока нет", "Плагинов издателей пока нет"),
        (
            "kk/",
            "Жариялаушылар әзірге жоқ",
            "Жариялаушылардың плагиндері әзірге жоқ",
        ),
        // `'` may be printed as an entity.
        ("en/", "No publishers yet", "plugins yet."),
    ] {
        let list = read(&public, &format!("{prefix}publishers/index.html"));
        assert!(list.contains("class=\"nodata\""), "{prefix}");
        assert!(list.contains(none), "{prefix}");
        assert!(!list.contains("<table"), "{prefix}");
        let catalog = read(&public, &format!("{prefix}plugins/index.html"));
        assert!(catalog.contains(plugins_none), "{prefix}");
    }
    assert!(!public.join("publishers/acme").exists());
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_lists_publishers() {
    let (_out, public) = built(&fixture_inputs());
    // Tera may print `/` as `&#x2F;`, in links too.
    let read = |page: &str| read(&public, page).replace("&#x2F;", "/");
    for (prefix, note, retired, revoked, page_revoked) in [
        (
            "",
            "Сам код OpenNCALayer не проверял.",
            "не выпускает новых версий",
            "отключён 2026-10-01",
            "Издатель отключён 2026-10-01",
        ),
        (
            "kk/",
            "OpenNCALayer кодтың өзін тексерген жоқ.",
            "жаңа нұсқалар шығармайды",
            "2026-10-01 ажыратылды",
            "Жариялаушы 2026-10-01 ажыратылды",
        ),
        (
            "en/",
            "OpenNCALayer did not review the code.",
            "publishes no new versions",
            "revoked on 2026-10-01",
            "The publisher was revoked on 2026-10-01",
        ),
    ] {
        let list = read(&format!("{prefix}publishers/index.html"));
        for name in ["acme", "olden", "gone"] {
            assert!(
                list.contains(&format!("<tr id=\"pub-{name}\">")),
                "{prefix}{name}"
            );
            assert!(
                list.contains(&format!("publishers/{name}/\"")),
                "{prefix}{name}"
            );
        }
        assert!(
            list.contains(&format!("<span class=\"badge\">{retired}</span>")),
            "{prefix}"
        );
        assert!(
            list.contains(&format!("<span class=\"badge revoked\">{revoked}</span>")),
            "{prefix}"
        );
        assert!(list.contains("<code>kz.acme.</code>"), "{prefix}");

        let acme = read(&format!("{prefix}publishers/acme/index.html"));
        assert!(acme.contains(note), "{prefix}");
        assert!(acme.contains("id=\"plugin-kz.acme.market\""), "{prefix}");
        assert!(acme.contains("id=\"plugin-kz.acme.sign\""), "{prefix}");
        assert!(
            acme.contains(".src.tar.gz\">kz.acme.market-1.0.0.src.tar.gz</a> · Apache-2.0"),
            "{prefix}"
        );
        assert!(
            acme.contains("/BUILDINFO.json\">BUILDINFO.json</a>"),
            "{prefix}"
        );
        assert!(acme.contains("oncl-plugin-builder@sha256:"), "{prefix}");
        assert!(!acme.contains("kz.acme.rogue"), "{prefix}");
        // The homepage and the stated repository are text, not links.
        assert!(!acme.contains("href=\"https://acme.example"), "{prefix}");
        assert!(
            !acme.contains("href=\"https://git.acme.example"),
            "{prefix}"
        );

        let olden = read(&format!("{prefix}publishers/olden/index.html"));
        assert!(olden.contains("class=\"notice\""), "{prefix}");
        assert!(olden.contains(retired), "{prefix}");
        assert!(olden.contains("id=\"plugin-kz.olden.tool\""), "{prefix}");

        let gone = read(&format!("{prefix}publishers/gone/index.html"));
        assert!(gone.contains(page_revoked), "{prefix}");
        assert!(!gone.contains("kz.gone.thing"), "{prefix}");
        assert!(!gone.contains(note), "{prefix}");

        let catalog = read(&format!("{prefix}plugins/index.html"));
        assert!(catalog.contains("class=\"publisher-plugins\""), "{prefix}");
        assert!(
            catalog.contains("publishers/acme/#plugin-kz.acme.market"),
            "{prefix}"
        );
        assert!(
            catalog.contains("publishers/olden/#plugin-kz.olden.tool"),
            "{prefix}"
        );
        assert!(!catalog.contains("kz.gone.thing"), "{prefix}");
        // The bundle a publisher's plugin replaces without a port: its row has the id, once.
        assert_eq!(
            catalog.matches("id=\"kz.example.unported\"").count(),
            1,
            "{prefix}"
        );
        let row = catalog.find("<tr id=\"kz.example.unported\">").unwrap();
        assert!(
            catalog[row..]
                .starts_with("<tr id=\"kz.example.unported\">\n<th scope=\"row\"><a href=\""),
            "{prefix}"
        );
        assert!(catalog[row..].contains("#plugin-kz.acme.sign"), "{prefix}");

        let alpha = read(&format!("{prefix}plugins/alpha/index.html"));
        assert!(
            alpha.contains("publishers/acme/#plugin-kz.acme.market"),
            "{prefix}"
        );
    }
    check(&public, &base_url()).unwrap();
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_catalog_anchor_for_every_port() {
    let (_out, public) = built(&fixture_inputs());
    for prefix in LANG_PREFIXES {
        let html = read(&public, &format!("{prefix}plugins/index.html"));
        for symname in ["kz.example.alpha", "kz.example.gamma", "kz.example.hostile"] {
            assert!(
                html.contains(&format!("<tr id=\"{symname}\">")),
                "{prefix}: {symname}"
            );
        }
        // The original's bundle without a port has its row too.
        assert!(html.contains("id=\"kz.example.unported\""), "{prefix}");
    }
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_catalog_lists_unported_bundles_only_from_facts() {
    let (_out, public) = built(&fixture_inputs());
    assert!(read(&public, "plugins/index.html").contains("id=\"unported-caption\""));
    // The history alone says nothing about which bundles have no port.
    let upstream = tempfile::tempdir().unwrap();
    fs::copy(
        fixtures().join("upstream/index.json"),
        upstream.path().join("index.json"),
    )
    .unwrap();
    let inputs = Inputs {
        upstream: Some(upstream.path().to_path_buf()),
        ..fixture_inputs()
    };
    let (_out, public) = built(&inputs);
    for prefix in LANG_PREFIXES {
        let catalog = read(&public, &format!("{prefix}plugins/index.html"));
        assert!(!catalog.contains("unported-caption"), "{prefix}");
    }
    assert!(read(&public, "upstream/index.html").contains("2026-10-20"));
}
