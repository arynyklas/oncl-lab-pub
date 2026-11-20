//! The rules of the bot that merges publishers' release pull requests,
//! `.github/workflows/publisher-pr.yml` (docs/design/publishers.md, «Jobs `publisher-pr.yml`»
//! and «Workflow и права»), checked on the workflow files as they are, and shown to catch what
//! they claim to: the negative tests below break a copy in each way a mistake or an attack
//! would, and each must be found.
//!
//! The rules:
//!
//! - only `publisher-pr.yml` names `pull_request_target`, and it runs on nothing else: pull
//!   requests to `main` that touch a role file of a publisher;
//! - `permissions: {}` at the top, and each job exactly its own: `publisher-check` and
//!   `verdict` read the contents, `provenance` and `rebuild` hold nothing, `mirror` writes the
//!   releases and attests, `merge` merges and starts Pages; one run per pull request;
//! - no `environment`, no secret, no cache, every action pinned by commit (or one of this
//!   repository's composite actions, from the checkout of `main`);
//! - every checkout is `main` as the event saw it (`github.sha`) without persisted
//!   credentials; the head of the pull request is fetched into a ref, never into the work tree;
//! - no `${{ … }}` inside a `run:`: every value reaches the scripts through `env:`;
//! - the jobs that run xtask build it from that checkout first (`cargo build --locked -p
//!   xtask`, then `target/debug/xtask`), before any artifact or the head is on the runner;
//!   `mirror` and `merge` have no checkout and no cargo;
//! - the jobs in the order of the design, each needing exactly its predecessors; `verdict`
//!   decides on what it derives (it reads no output of `provenance` or `rebuild`), `mirror`
//!   and `merge` take its outputs only, `mirror` runs only on its `ok`, `merge` only after
//!   `mirror`;
//! - `mirror`: the files hashed before `gh release create --draft`, then the attestation, then
//!   the draft downloaded and compared, then `--draft=false`; no `gh release upload`;
//! - `merge`: `gh pr checks --required --watch` within 30 minutes, then `gh pr merge --squash
//!   --match-head-commit`, then `gh workflow run pages.yml`;
//! - the commands: `check-pr` and `verdict` with the author from the event, `provenance` on the
//!   bridge `oncl-vcs` made with its firewall first, `rebuild` per matrix entry on Docker with
//!   a disk of limited size; containers only through xtask.
//!
//! Beside it: `pages.yml` does not start itself for a `pub-*` release, and the index check runs
//! `vendor check-onboarding` against the base.

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

mod workflow_yaml;

use workflow_yaml::{leaves, parse_yaml, pinned};

const FILE: &str = "publisher-pr.yml";
const PATHS: &str = "tuf/v1/metadata/*.pub-*.json";
const DISK_ACTION: &str = "./.github/actions/docker-disk";
const BUILD_XTASK: &str = "cargo build --locked -p xtask";
const AUTHOR: &str = "${{ github.event.pull_request.user.login }}";
const HEAD: &str = "${{ github.event.pull_request.head.sha }}";

/// A job: its name, its permissions, and the jobs it needs.
type Job = (
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static [&'static str],
);

/// The jobs, in their order, with the permissions and the needs of each.
const JOBS: [Job; 6] = [
    ("publisher-check", &[("contents", "read")], &[]),
    ("provenance", &[], &["publisher-check"]),
    ("rebuild", &[], &["publisher-check"]),
    (
        "verdict",
        &[("contents", "read")],
        &["publisher-check", "provenance", "rebuild"],
    ),
    (
        "mirror",
        &[
            ("contents", "write"),
            ("id-token", "write"),
            ("attestations", "write"),
        ],
        &["verdict"],
    ),
    (
        "merge",
        &[
            ("contents", "write"),
            ("pull-requests", "write"),
            ("actions", "write"),
        ],
        &["verdict", "mirror"],
    ),
];

/// The jobs that build and run xtask.
const XTASK_JOBS: [&str; 4] = ["publisher-check", "provenance", "rebuild", "verdict"];

/// Git commands that would put the pull request's files into the work tree.
const WORK_TREE: [&str; 11] = [
    "git checkout",
    "git switch",
    "git worktree",
    "git reset",
    "git restore",
    "git merge",
    "git pull",
    "git am",
    "git apply",
    "git cherry-pick",
    "git rebase",
];

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn steps(job: &Value) -> &[Value] {
    job.get("steps")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The index of the first step of `job` that `pred` accepts.
fn step_where(job: &Value, pred: impl Fn(&Value) -> bool) -> Option<usize> {
    steps(job).iter().position(pred)
}

fn run_has(needle: &str) -> impl Fn(&Value) -> bool + '_ {
    move |step: &Value| str_of(step, "run").contains(needle)
}

fn uses_starts(prefix: &str) -> impl Fn(&Value) -> bool + '_ {
    move |step: &Value| str_of(step, "uses").starts_with(prefix)
}

/// Every string of `value`, joined: what a job refers to anywhere.
fn all_text(value: &Value) -> String {
    let mut out = Vec::new();
    leaves(value, &mut Vec::new(), &mut out);
    out.into_iter()
        .map(|(_, s)| s)
        .collect::<Vec<_>>()
        .join("\n")
}

/// `before` comes before `after` in `text`, both there.
fn in_order(text: &str, before: &str, after: &str) -> bool {
    match (text.find(before), text.find(after)) {
        (Some(a), Some(b)) => a < b,
        _ => false,
    }
}

/// What is wrong with `text`, the text of `publisher-pr.yml`.
#[allow(clippy::too_many_lines)] // One rule after another, each a few lines.
fn check_publisher_pr(text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    let doc = match parse_yaml(text) {
        Ok(doc) => doc,
        Err(e) => return vec![format!("{FILE} cannot be read: {e}")],
    };

    // The event.
    let on = &doc["on"];
    let only_event = on
        .as_object()
        .is_some_and(|o| o.len() == 1 && o.contains_key("pull_request_target"));
    if !only_event {
        bad.push(format!(
            "{FILE} runs on events other than pull_request_target: {on}"
        ));
    }
    let event = &on["pull_request_target"];
    if event["branches"] != json!(["main"]) {
        bad.push(format!(
            "pull_request_target is not for main only: {}",
            event["branches"]
        ));
    }
    if event["paths"] != json!([PATHS]) {
        bad.push(format!(
            "the paths of pull_request_target are not {PATHS}: {}",
            event["paths"]
        ));
    }
    if event["types"]
        != json!([
            "opened",
            "edited",
            "synchronize",
            "reopened",
            "ready_for_review"
        ])
    {
        bad.push(format!(
            "unexpected types of pull_request_target: {}",
            event["types"]
        ));
    }

    // Permissions, concurrency.
    if doc.get("permissions") != Some(&json!({})) {
        bad.push("the workflow's permissions are not {}".to_owned());
    }
    let concurrency = &doc["concurrency"];
    if !str_of(concurrency, "group").contains("github.event.pull_request.number")
        || str_of(concurrency, "cancel-in-progress") != "true"
    {
        bad.push(format!(
            "the concurrency is not one run per pull request: {concurrency}"
        ));
    }

    // No secrets, no environment, no cache, pinned actions.
    let lower = text.to_lowercase();
    let compact: String = lower.split_whitespace().collect();
    for banned in ["secrets.", "secrets[", "secrets:inherit", "tojson(secrets)"] {
        if compact.contains(banned) {
            bad.push(format!("{FILE} reads a secret ({banned})"));
        }
    }
    for banned in ["actions/cache", "rust-cache", "sccache"] {
        if lower.contains(banned) {
            bad.push(format!("{FILE} uses a cache ({banned})"));
        }
    }

    let Some(jobs) = doc["jobs"].as_object() else {
        bad.push("no jobs".to_owned());
        return bad;
    };
    let names: Vec<&str> = JOBS.iter().map(|(name, _, _)| *name).collect();
    let mut found: Vec<&str> = jobs.keys().map(String::as_str).collect();
    found.sort_unstable();
    let mut wanted = names.clone();
    wanted.sort_unstable();
    if found != wanted {
        bad.push(format!("the jobs are {found:?}, not {wanted:?}"));
    }
    let positions: Vec<Option<usize>> = names
        .iter()
        .map(|name| text.find(&format!("\n  {name}:\n")))
        .collect();
    if positions.windows(2).any(|w| match (w[0], w[1]) {
        (Some(a), Some(b)) => a > b,
        _ => true,
    }) {
        bad.push(format!("the jobs are not in the order {names:?}"));
    }

    for (name, permissions, needs) in JOBS {
        let Some(job) = jobs.get(name) else {
            continue;
        };
        let want: serde_json::Map<String, Value> = permissions
            .iter()
            .map(|(k, v)| ((*k).to_owned(), json!(v)))
            .collect();
        if job.get("permissions") != Some(&Value::Object(want.clone())) {
            bad.push(format!(
                "the permissions of {name} are {}, not {}",
                job.get("permissions").unwrap_or(&Value::Null),
                Value::Object(want)
            ));
        }
        let got_needs: Vec<&str> = match job.get("needs") {
            None => Vec::new(),
            Some(Value::String(one)) => vec![one.as_str()],
            Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
            Some(other) => {
                bad.push(format!("the needs of {name} do not read: {other}"));
                Vec::new()
            }
        };
        if got_needs != needs {
            bad.push(format!("{name} needs {got_needs:?}, not {needs:?}"));
        }
        if job.get("environment").is_some() {
            bad.push(format!("{name} runs in an environment"));
        }
        if job.get("timeout-minutes").is_none() {
            bad.push(format!("{name} has no timeout"));
        }
        for (i, step) in steps(job).iter().enumerate() {
            let uses = str_of(step, "uses");
            if !uses.is_empty() && !pinned(uses) && !uses.starts_with(DISK_ACTION) {
                bad.push(format!("{name}: the action {uses} is not pinned by commit"));
            }
            if step.get("with").and_then(|w| w.get("cache")).is_some() {
                bad.push(format!("{name}: step {i} uses a cache"));
            }
            let run = str_of(step, "run");
            if run.contains("${{") {
                bad.push(format!(
                    "{name}: an expression in a run (step {i}); values go through env"
                ));
            }
            for command in WORK_TREE {
                if run.contains(command) {
                    bad.push(format!(
                        "{name}: {command} puts the pull request into the work tree"
                    ));
                }
            }
            if run.contains("docker run") {
                bad.push(format!("{name}: a container started outside xtask"));
            }
            if run.contains("gh release upload") {
                bad.push(format!("{name}: gh release upload"));
            }
            if run.contains("cargo") && run.trim() != BUILD_XTASK {
                bad.push(format!("{name}: cargo other than {BUILD_XTASK}"));
            }
            if uses.starts_with("actions/checkout@") {
                let with = step.get("with").unwrap_or(&Value::Null);
                if str_of(with, "ref") != "${{ github.sha }}" || with.get("repository").is_some() {
                    bad.push(format!("{name}: a checkout of something other than main"));
                }
                if str_of(with, "persist-credentials") != "false" {
                    bad.push(format!("{name}: a checkout that keeps the credentials"));
                }
            }
        }
        if name != "publisher-check" {
            continue;
        }
        if !str_of(job, "if").contains("github.repository == 'arynyklas/OpenNCALayer'") {
            bad.push("publisher-check runs outside this repository".to_owned());
        }
    }

    // xtask from main, built first.
    for name in XTASK_JOBS {
        let Some(job) = jobs.get(name) else {
            continue;
        };
        let Some(build) = step_where(job, |s| str_of(s, "run").trim() == BUILD_XTASK) else {
            bad.push(format!("{name} does not build xtask from its checkout"));
            continue;
        };
        let later = [
            step_where(job, run_has("refs/pull/")),
            step_where(job, uses_starts("actions/download-artifact@")),
        ];
        if later.into_iter().flatten().any(|i| i < build) {
            bad.push(format!(
                "{name} has the pull request or an artifact on the runner before it builds xtask"
            ));
        }
        for step in steps(job) {
            let run = str_of(step, "run");
            if run.contains("xtask ") && run.trim() != BUILD_XTASK {
                let calls_built = run
                    .match_indices("xtask ")
                    .all(|(at, _)| run[..at].ends_with("target/debug/"));
                if !calls_built {
                    bad.push(format!("{name} runs an xtask other than the one it built"));
                }
            }
        }
    }
    for name in ["mirror", "merge"] {
        let Some(job) = jobs.get(name) else {
            continue;
        };
        if step_where(job, uses_starts("actions/checkout@")).is_some() {
            bad.push(format!("{name} checks out the repository"));
        }
        if step_where(job, |s| {
            let run = str_of(s, "run");
            run.contains("cargo") || run.contains("xtask")
        })
        .is_some()
        {
            bad.push(format!("{name} runs cargo or xtask"));
        }
    }

    // What each job trusts.
    for (name, job) in jobs {
        let refers = all_text(job);
        for other in ["provenance", "rebuild"] {
            if refers.contains(&format!("needs.{other}.outputs")) {
                bad.push(format!("{name} reads an output of {other}"));
            }
        }
        if ["mirror", "merge"].contains(&name.as_str())
            && refers.contains("needs.publisher-check.outputs")
        {
            bad.push(format!(
                "{name} reads an output of publisher-check, not of verdict"
            ));
        }
    }

    let job = |name: &str| jobs.get(name).unwrap_or(&Value::Null);

    // publisher-check and verdict: the author from the event.
    for (name, command) in [
        (
            "publisher-check",
            "vendor check-pr --base \"$GITHUB_SHA\" --head \"$HEAD_SHA\" --author \"$AUTHOR\"",
        ),
        (
            "verdict",
            "vendor verdict --base \"$GITHUB_SHA\" --head \"$HEAD_SHA\" --author \"$AUTHOR\"",
        ),
    ] {
        match step_where(job(name), run_has(command)) {
            Some(i) => {
                let env = &steps(job(name))[i]["env"];
                if str_of(env, "AUTHOR") != AUTHOR || str_of(env, "HEAD_SHA") != HEAD {
                    bad.push(format!("{name}: the author or the head is not the event's"));
                }
                if !str_of(&steps(job(name))[i], "run").contains(".ok == true") {
                    bad.push(format!("{name}: the verdict's ok is not checked"));
                }
            }
            None => bad.push(format!("{name} does not run `{command}`")),
        }
    }

    // provenance: the firewalled bridge first.
    let provenance = job("provenance");
    let network = step_where(provenance, |s| {
        let run = str_of(s, "run");
        run.contains("docker network create")
            && run.contains("DOCKER-USER")
            && run.contains("ip6tables -I DOCKER-USER -i oncl-vcs -j DROP")
            && run.contains("iptables -I INPUT -i oncl-vcs -j DROP")
            && run.contains("168.63.129.16/32")
            && run.contains("{{.Server.Version}}")
    });
    let check25 = step_where(provenance, run_has("vendor provenance"));
    match (network, check25) {
        (Some(n), Some(c)) if n < c => {
            if !str_of(&steps(provenance)[c], "run").contains("--network oncl-vcs") {
                bad.push("provenance does not run on the bridge oncl-vcs".to_owned());
            }
        }
        _ => bad.push("provenance does not make the firewalled bridge before check 25".to_owned()),
    }

    // provenance and rebuild: Docker on a disk of limited size, before Docker is used.
    for (name, command) in [
        ("provenance", "vendor provenance"),
        ("rebuild", "vendor rebuild"),
    ] {
        let disk = step_where(job(name), uses_starts(DISK_ACTION));
        let first_docker = step_where(job(name), |s| {
            let run = str_of(s, "run");
            run.contains("docker ") || run.contains(command)
        });
        if !matches!((disk, first_docker), (Some(d), Some(f)) if d < f) {
            bad.push(format!("{name} uses Docker before it limits its disk"));
        }
    }

    // rebuild: one entry of the matrix, through env.
    let rebuild = job("rebuild");
    if rebuild["strategy"]["matrix"]["target"]
        != "${{ fromJSON(needs.publisher-check.outputs.targets) }}"
    {
        bad.push("the matrix of rebuild is not the new targets of publisher-check".to_owned());
    }
    match step_where(rebuild, run_has("target/debug/xtask vendor rebuild")) {
        Some(i) => {
            let env = &steps(rebuild)[i]["env"];
            if str_of(env, "ARCHIVE") != "${{ matrix.target.archive }}"
                || str_of(env, "CRATE_PATH") != "${{ matrix.target.path }}"
                || str_of(env, "BUILDER") != "${{ matrix.target.builder }}"
            {
                bad.push("rebuild does not take its matrix entry through env".to_owned());
            }
        }
        None => bad.push("rebuild does not run `vendor rebuild`".to_owned()),
    }

    // verdict: after both, never after a failure of one.
    let condition: String = str_of(job("verdict"), "if")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for part in [
        "!cancelled()",
        "needs.publisher-check.result == 'success'",
        "needs.provenance.result == 'success'",
        "needs.rebuild.result == 'success'",
        "(needs.rebuild.result == 'skipped' && needs.publisher-check.outputs.count == '0')",
    ] {
        if !condition.contains(part) {
            bad.push(format!("the condition of verdict lacks {part}"));
        }
    }
    if condition.contains("always()") || condition.contains("failure()") {
        bad.push("verdict may run after a failure".to_owned());
    }

    // mirror: only on the verdict's ok; hash, draft, attest, check, publish.
    let mirror = job("mirror");
    if str_of(mirror, "if") != "needs.verdict.outputs.ok == 'true'" {
        bad.push(format!(
            "mirror does not run on the verdict's ok only: {}",
            str_of(mirror, "if")
        ));
    }
    if mirror["concurrency"]["group"] != "publisher-mirror"
        || mirror["concurrency"]["cancel-in-progress"] != "false"
    {
        bad.push("mirror may run beside another mirror".to_owned());
    }
    let create = step_where(mirror, run_has("gh release create"));
    let attest = step_where(mirror, uses_starts("actions/attest-build-provenance@"));
    let publish = step_where(mirror, run_has("--draft=false"));
    match (create, attest, publish) {
        (Some(c), Some(a), Some(p)) if c < a && a < p => {
            let drafts = str_of(&steps(mirror)[c], "run");
            if !drafts.contains("gh release create \"$tag\" --repo \"$GITHUB_REPOSITORY\" --draft ")
            {
                bad.push("mirror creates a release that is not a draft".to_owned());
            }
            if !in_order(drafts, "sha256sum", "gh release create") {
                bad.push("mirror does not hash the files before the release".to_owned());
            }
            for bound in [
                "!= \"$third_party_sha256\"",
                "!= \"$buildinfo_sha256\"",
                "!= \"$diff_sha256\"",
            ] {
                if !in_order(drafts, bound, "gh release create") {
                    bad.push(format!(
                        "mirror does not compare {bound} before the release"
                    ));
                }
            }
            if !in_order(drafts, "'.isImmutable == true'", "published already") {
                bad.push(
                    "mirror keeps a published release without checking it is immutable".to_owned(),
                );
            }
            let check = str_of(&steps(mirror)[p], "run");
            if !in_order(check, "gh release download", "--draft=false")
                || !in_order(check, "cmp -s", "--draft=false")
                || !check.contains("isImmutable == true")
            {
                bad.push("mirror publishes a draft it has not checked".to_owned());
            }
        }
        _ => bad.push("mirror does not draft, attest, then publish".to_owned()),
    }
    for (name, job) in jobs {
        if name != "mirror" {
            let refers = all_text(job);
            if refers.contains("gh release create") || refers.contains("--draft=false") {
                bad.push(format!("{name} makes a release"));
            }
        }
    }

    // merge: after the required checks, the checked head, then Pages.
    let merge = job("merge");
    if merge.get("if").is_some() {
        bad.push("merge has a condition of its own".to_owned());
    }
    let wait = step_where(merge, |s| {
        let run = str_of(s, "run");
        run.contains("gh pr checks") && run.contains("--required --watch") && run.contains("1800")
    });
    let merged = step_where(merge, |s| {
        let run = str_of(s, "run");
        run.contains("gh pr merge")
            && run.contains("--squash")
            && run.contains("--match-head-commit \"$HEAD_SHA\"")
            && str_of(&s["env"], "HEAD_SHA") == HEAD
            && in_order(
                run,
                ".baseRefName == \"main\" and .headRefOid == $head and .state == \"OPEN\" and .isDraft == false",
                "gh pr merge",
            )
            && in_order(run, "[ \"$main\" = \"$GITHUB_SHA\" ]", "gh pr merge")
    });
    let pages = step_where(merge, run_has("gh workflow run pages.yml"));
    if !matches!((wait, merged, pages), (Some(w), Some(m), Some(p)) if w < m && m < p) {
        bad.push(
            "merge does not wait for the required checks, merge the checked head, then start Pages"
                .to_owned(),
        );
    }
    for (name, job) in jobs {
        if name != "merge" && all_text(job).contains("gh pr merge") {
            bad.push(format!("{name} merges"));
        }
    }
    bad
}

/// What is wrong with the workflows `(file name, text)` and the composite action that limits
/// Docker's disk.
fn check_workflows(files: &[(String, String)]) -> Vec<String> {
    let mut bad = Vec::new();
    for (name, text) in files {
        if name != FILE && text.to_lowercase().contains("pull_request_target") {
            bad.push(format!("{name} uses pull_request_target"));
        }
    }
    let text = |name: &str| {
        files
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, t)| t.as_str())
    };
    if text(FILE).is_empty() {
        bad.push(format!("there is no {FILE}"));
    } else {
        bad.extend(check_publisher_pr(text(FILE)));
    }
    match parse_yaml(text("pages.yml")) {
        Ok(pages) => {
            let dispatch = str_of(&pages["jobs"]["dispatch"], "if");
            if !dispatch.contains("!startsWith(github.event.release.tag_name, 'pub-')") {
                bad.push(format!(
                    "pages.yml starts itself for a pub-* release: {dispatch}"
                ));
            }
        }
        Err(e) => bad.push(format!("pages.yml cannot be read: {e}")),
    }
    if !text("index-check.yml").contains("vendor check-onboarding --base \"$BASE\"") {
        bad.push("index-check.yml does not run vendor check-onboarding".to_owned());
    }
    match parse_yaml(text("docker-disk/action.yml")) {
        Ok(action) => {
            let runs = steps(&action["runs"])
                .iter()
                .map(|step| str_of(step, "run"))
                .collect::<Vec<_>>()
                .join("\n");
            if runs.contains("${{") {
                bad.push("the docker-disk action has an expression in a run".to_owned());
            }
            if !runs.contains("/var/lib/docker") || !runs.contains("/var/lib/containerd") {
                bad.push("the docker-disk action does not hold Docker's data".to_owned());
            }
        }
        Err(e) => bad.push(format!("the docker-disk action cannot be read: {e}")),
    }
    bad
}

fn real_files() -> Vec<(String, String)> {
    let github = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.github");
    let read = |path: &PathBuf| fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    let mut files = Vec::new();
    for entry in fs::read_dir(github.join("workflows")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            files.push((name, read(&path)));
        }
    }
    files.push((
        "docker-disk/action.yml".to_owned(),
        read(&github.join("actions/docker-disk/action.yml")),
    ));
    assert!(
        files.len() > 5,
        "the workflows were not found in {}",
        github.display()
    );
    files
}

#[test]
fn the_publisher_workflow_keeps_its_rules() {
    let bad = check_workflows(&real_files());
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn the_parser_reads_an_empty_mapping() {
    assert_eq!(
        parse_yaml("permissions: {}\n").unwrap()["permissions"],
        json!({})
    );
    assert!(parse_yaml("permissions: {contents: read}\n").is_err());
}

/// The real files with `file` changed by replacing `from` (which must be there) with `to`.
fn mutated(file: &str, from: &str, to: &str) -> Vec<(String, String)> {
    let mut files = real_files();
    let (_, text) = files
        .iter_mut()
        .find(|(n, _)| n == file)
        .unwrap_or_else(|| panic!("{file}"));
    assert!(text.contains(from), "the mutation target is gone: {from:?}");
    *text = text.replacen(from, to, 1);
    files
}

fn assert_found(files: &[(String, String)], needle: &str) {
    let bad = check_workflows(files);
    assert!(
        bad.iter().any(|b| b.contains(needle)),
        "not caught ({needle:?}): {bad:#?}"
    );
}

#[test]
fn pull_request_target_elsewhere_is_found() {
    let mut files = real_files();
    files.push((
        "x.yml".to_owned(),
        "on:\n  pull_request_target:\njobs: {}\n".to_owned(),
    ));
    assert_found(&files, "x.yml uses pull_request_target");
}

#[test]
fn other_events_or_paths_are_found() {
    assert_found(
        &mutated(
            FILE,
            "on:\n  pull_request_target:\n",
            "on:\n  pull_request:\n  pull_request_target:\n",
        ),
        "events other than",
    );
    assert_found(
        &mutated(
            FILE,
            "      - \"tuf/v1/metadata/*.pub-*.json\"\n",
            "      - \"tuf/**\"\n",
        ),
        "the paths of pull_request_target",
    );
    assert_found(&mutated(FILE, "    branches: [main]\n", ""), "main only");
}

#[test]
fn permissions_are_found() {
    assert_found(
        &mutated(
            FILE,
            "permissions: {}\n\n# One run",
            "permissions:\n  contents: write\n\n# One run",
        ),
        "the workflow's permissions",
    );
    assert_found(
        &mutated(
            FILE,
            "    permissions: {}\n    strategy:",
            "    permissions:\n      contents: read\n    strategy:",
        ),
        "the permissions of rebuild",
    );
    assert_found(
        &mutated(
            FILE,
            "      contents: write\n      id-token: write\n",
            "      contents: write\n      id-token: write\n      packages: write\n",
        ),
        "the permissions of mirror",
    );
    assert_found(
        &mutated(
            FILE,
            "  cancel-in-progress: true\n",
            "  cancel-in-progress: false\n",
        ),
        "one run per pull request",
    );
}

#[test]
fn secrets_environments_caches_and_unpinned_actions_are_found() {
    assert_found(
        &mutated(
            FILE,
            "    needs: verdict\n",
            "    needs: verdict\n    environment: releases\n",
        ),
        "mirror runs in an environment",
    );
    assert_found(
        &mutated(
            FILE,
            "          GH_TOKEN: ${{ github.token }}\n",
            "          GH_TOKEN: ${{ secrets.BOT_TOKEN }}\n",
        ),
        "reads a secret",
    );
    assert_found(
        &mutated(
            FILE,
            "      - name: Build xtask\n",
            "      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3\n      - name: Build xtask\n",
        ),
        "uses a cache",
    );
    assert_found(
        &mutated(
            FILE,
            "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2",
            "actions/attest-build-provenance@v4",
        ),
        "not pinned by commit",
    );
}

#[test]
fn the_head_of_the_pull_request_in_the_work_tree_is_found() {
    assert_found(
        &mutated(
            FILE,
            "          ref: ${{ github.sha }}\n",
            &format!("          ref: {HEAD}\n"),
        ),
        "a checkout of something other than main",
    );
    assert_found(
        &mutated(
            FILE,
            "          persist-credentials: false\n",
            "          persist-credentials: true\n",
        ),
        "keeps the credentials",
    );
    assert_found(
        &mutated(
            FILE,
            "          got=\"$(git rev-parse --verify 'refs/oncl/head^{commit}')\"\n",
            "          git checkout refs/oncl/head\n          got=\"$(git rev-parse --verify 'refs/oncl/head^{commit}')\"\n",
        ),
        "git checkout puts the pull request into the work tree",
    );
}

#[test]
fn an_expression_in_a_run_is_found() {
    assert_found(
        &mutated(
            FILE,
            "--author \"$AUTHOR\" --out \"$out\"",
            &format!("--author \"{AUTHOR}\" --out \"$out\""),
        ),
        "publisher-check: an expression in a run",
    );
    assert_found(
        &mutated(
            "docker-disk/action.yml",
            "        image=\"$best/oncl-docker.img\"\n",
            "        image=\"$best/${{ inputs.gib }}.img\"\n",
        ),
        "docker-disk action has an expression",
    );
}

#[test]
fn xtask_not_from_main_or_too_late_is_found() {
    assert_found(
        &mutated(
            FILE,
            "target/debug/xtask vendor verdict",
            "cargo xtask vendor verdict",
        ),
        "cargo other than",
    );
    // The build of verdict moved after the downloads.
    let text = real_files().into_iter().find(|(n, _)| n == FILE).unwrap().1;
    let verdict = text.find("\n  verdict:\n").unwrap();
    let build = "      - name: Build xtask\n        run: cargo build --locked -p xtask\n";
    let at = verdict + text[verdict..].find(build).unwrap();
    let mut moved = text.clone();
    moved.replace_range(at..at + build.len(), "");
    let anchor = verdict
        + moved[verdict..]
            .find("      - name: The verdict\n")
            .unwrap();
    moved.insert_str(anchor, build);
    let mut files = real_files();
    files.iter_mut().find(|(n, _)| n == FILE).unwrap().1 = moved;
    assert_found(
        &files,
        "verdict has the pull request or an artifact on the runner before it builds xtask",
    );
    assert_found(
        &mutated(
            FILE,
            "      - name: Draft the releases\n",
            "      - run: cargo build --locked -p xtask\n      - name: Draft the releases\n",
        ),
        "mirror runs cargo or xtask",
    );
    assert_found(
        &mutated(
            FILE,
            "    steps:\n      - uses: actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0 # v5.0.0\n        if: needs.verdict.outputs.targets != '[]'\n",
            "    steps:\n      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0\n        with:\n          ref: ${{ github.sha }}\n          persist-credentials: false\n      - uses: actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0 # v5.0.0\n        if: needs.verdict.outputs.targets != '[]'\n",
        ),
        "mirror checks out the repository",
    );
}

#[test]
fn the_graph_of_jobs_is_pinned() {
    assert_found(
        &mutated(
            FILE,
            "    needs: [verdict, mirror]\n",
            "    needs: [verdict]\n",
        ),
        "merge needs [\"verdict\"]",
    );
    assert_found(
        &mutated(
            FILE,
            "    needs: verdict\n",
            "    needs: [publisher-check]\n",
        ),
        "mirror needs [\"publisher-check\"]",
    );
    assert_found(
        &mutated(
            FILE,
            "    needs: [publisher-check, provenance, rebuild]\n",
            "    needs: [publisher-check, rebuild]\n",
        ),
        "verdict needs",
    );
    assert_found(
        &mutated(
            FILE,
            "    needs: [verdict, mirror]\n",
            "    needs: [verdict, mirror]\n    if: always()\n",
        ),
        "merge has a condition of its own",
    );
    assert_found(
        &mutated(
            FILE,
            "    if: needs.verdict.outputs.ok == 'true'\n",
            "    if: always()\n",
        ),
        "mirror does not run on the verdict's ok only",
    );
    assert_found(
        &mutated(
            FILE,
            "      ${{ !cancelled() && needs.publisher-check.result",
            "      ${{ always() && needs.publisher-check.result",
        ),
        "the condition of verdict lacks !cancelled()",
    );
    assert_found(
        &mutated(FILE, "      needs.provenance.result == 'success' &&\n", ""),
        "the condition of verdict lacks needs.provenance.result",
    );
    // mirror after merge in the file.
    let text = real_files().into_iter().find(|(n, _)| n == FILE).unwrap().1;
    let (m, g) = (
        text.find("\n  # The copies").unwrap(),
        text.find("\n  # The merge,").unwrap(),
    );
    let swapped = format!("{}{}{}", &text[..m], &text[g..], &text[m..g]);
    let mut files = real_files();
    files.iter_mut().find(|(n, _)| n == FILE).unwrap().1 = swapped;
    assert_found(&files, "the jobs are not in the order");
}

#[test]
fn trusting_what_a_job_was_handed_is_found() {
    assert_found(
        &mutated(
            FILE,
            "          AUTHOR: ${{ github.event.pull_request.user.login }}\n        run: |\n          in=",
            "          AUTHOR: ${{ github.event.pull_request.user.login }}\n          OK: ${{ needs.rebuild.outputs.ok }}\n        run: |\n          in=",
        ),
        "verdict reads an output of rebuild",
    );
    assert_found(
        &mutated(
            FILE,
            "          TARGETS: ${{ needs.verdict.outputs.targets }}\n",
            "          TARGETS: ${{ needs.publisher-check.outputs.targets }}\n",
        ),
        "mirror reads an output of publisher-check",
    );
    assert_found(
        &mutated(
            FILE,
            "          AUTHOR: ${{ github.event.pull_request.user.login }}\n        run: |\n          out=",
            "          AUTHOR: mallory\n        run: |\n          out=",
        ),
        "publisher-check: the author or the head is not the event's",
    );
    assert_found(
        &mutated(
            FILE,
            "--provenance \"$in/provenance/provenance.json\" --out \"$RUNNER_TEMP/verdict\"\n          jq -e --arg head \"$HEAD_SHA\" '.ok == true and .head == $head' \"$RUNNER_TEMP/verdict/verdict.json\" > /dev/null\n",
            "--provenance \"$in/provenance/provenance.json\" --out \"$RUNNER_TEMP/verdict\" || true\n",
        ),
        "verdict: the verdict's ok is not checked",
    );
}

#[test]
fn a_release_not_drafted_checked_and_published_in_order_is_found() {
    assert_found(
        &mutated(
            FILE,
            "--repo \"$GITHUB_REPOSITORY\" --draft --prerelease",
            "--repo \"$GITHUB_REPOSITORY\" --prerelease",
        ),
        "not a draft",
    );
    assert_found(
        &mutated(
            FILE,
            "            cp -- \"$dir/$package\" \"$root/attest/\"\n",
            "            gh release edit \"$tag\" --repo \"$GITHUB_REPOSITORY\" --draft=false\n            cp -- \"$dir/$package\" \"$root/attest/\"\n",
        ),
        "mirror does not draft, attest, then publish",
    );
    assert_found(
        &mutated(
            FILE,
            "            gh release edit \"$tag\" --repo \"$GITHUB_REPOSITORY\" --draft=false\n",
            "            gh release upload \"$tag\" --repo \"$GITHUB_REPOSITORY\" \"$dir\"/*\n            gh release edit \"$tag\" --repo \"$GITHUB_REPOSITORY\" --draft=false\n",
        ),
        "gh release upload",
    );
    assert_found(
        &mutated(
            FILE,
            "              cmp -s -- \"$dir/$name\" \"$got/$name\" || fail \"the draft's $name is not the file uploaded\"\n",
            "",
        ),
        "publishes a draft it has not checked",
    );
}

#[test]
fn a_merge_without_its_guards_is_found() {
    assert_found(
        &mutated(
            FILE,
            "--squash --match-head-commit \"$HEAD_SHA\"",
            "--squash",
        ),
        "merge does not wait for the required checks, merge the checked head",
    );
    assert_found(
        &mutated(
            FILE,
            "--required --watch --fail-fast",
            "--watch --fail-fast",
        ),
        "merge does not wait for the required checks",
    );
    assert_found(
        &mutated(
            FILE,
            "        run: gh workflow run pages.yml --repo \"$GITHUB_REPOSITORY\" --ref main\n",
            "        run: echo no pages\n",
        ),
        "then start Pages",
    );
    assert_found(
        &mutated(
            FILE,
            "          [ \"$main\" = \"$GITHUB_SHA\" ] || fail",
            "          true || fail",
        ),
        "merge the checked head",
    );
    assert_found(
        &mutated(FILE, ".baseRefName == \"main\" and ", ""),
        "merge the checked head",
    );
    assert_found(
        &mutated(FILE, "[opened, edited, synchronize", "[opened, synchronize"),
        "unexpected types",
    );
    assert_found(
        &mutated(
            FILE,
            "      group: publisher-mirror\n",
            "      group: mirror-${{ github.run_id }}\n",
        ),
        "mirror may run beside another mirror",
    );
    assert_found(
        &mutated(
            FILE,
            " || [ \"$(hex \"$dir/BUILDINFO.json\")\" != \"$buildinfo_sha256\" ]",
            "",
        ),
        "does not compare != \"$buildinfo_sha256\"",
    );
    assert_found(
        &mutated(
            FILE,
            " 168.63.129.16/32; do\n            sudo iptables -I",
            "; do\n            sudo iptables -I",
        ),
        "firewalled bridge before check 25",
    );
}

#[test]
fn the_commands_of_the_checks_are_pinned() {
    assert_found(
        &mutated(
            FILE,
            "          sudo ip6tables -I DOCKER-USER -i oncl-vcs -j DROP\n",
            "",
        ),
        "firewalled bridge before check 25",
    );
    assert_found(
        &mutated(
            FILE,
            "--archives \"$RUNNER_TEMP/archives\" --network oncl-vcs",
            "--archives \"$RUNNER_TEMP/archives\" --network bridge",
        ),
        "does not run on the bridge oncl-vcs",
    );
    assert_found(
        &mutated(
            FILE,
            "          CRATE_PATH: ${{ matrix.target.path }}\n",
            "          CRATE_PATH: crates/x\n",
        ),
        "rebuild does not take its matrix entry through env",
    );
    assert_found(
        &mutated(
            FILE,
            "          target/debug/xtask vendor rebuild --archive",
            "          docker run --rm --network=none \"$BUILDER\" true\n          target/debug/xtask vendor rebuild --archive",
        ),
        "a container started outside xtask",
    );
    // The disk limit after the first use of Docker.
    let text = real_files().into_iter().find(|(n, _)| n == FILE).unwrap().1;
    let rebuild = text.find("\n  rebuild:\n").unwrap();
    let disk = "      - uses: ./.github/actions/docker-disk\n";
    let at = rebuild + text[rebuild..].find(disk).unwrap();
    let mut moved = text.clone();
    moved.replace_range(at..at + disk.len(), "");
    let anchor = rebuild
        + moved[rebuild..]
            .find("      - uses: actions/upload-artifact@")
            .unwrap();
    moved.insert_str(anchor, disk);
    let mut files = real_files();
    files.iter_mut().find(|(n, _)| n == FILE).unwrap().1 = moved;
    assert_found(&files, "rebuild uses Docker before it limits its disk");
}

#[test]
fn pages_and_the_index_check_keep_their_part() {
    assert_found(
        &mutated(
            "pages.yml",
            "    if: github.event_name == 'release' && !startsWith(github.event.release.tag_name, 'pub-')\n",
            "    if: github.event_name == 'release'\n",
        ),
        "pages.yml starts itself for a pub-* release",
    );
    assert_found(
        &mutated(
            "index-check.yml",
            "cargo xtask vendor check-onboarding --base \"$BASE\"",
            "true",
        ),
        "index-check.yml does not run vendor check-onboarding",
    );
}
