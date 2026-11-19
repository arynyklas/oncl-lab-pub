//! The rules for the secrets CI holds, the online TUF keys (`docs/dev/release.md`, section
//! 10; `docs/design/publishers.md`, "Онлайн-снимок"), checked on the workflow files as they
//! are, and shown to catch what they claim to: the negative tests below break a copy of
//! `pages.yml` (or add a workflow, or break the script that carries the snapshots) in each
//! way a mistake or an attack would, and each must be found.
//!
//! The secrets: `TUF_SNAPSHOT_KEY` in the environment `tuf-snapshot` (job `snapshot`),
//! `TUF_TIMESTAMP_KEY` in `tuf-timestamp` (job `timestamp`). The rules:
//!
//! - no workflow reads secrets wholesale (`toJSON(secrets)`, `secrets: inherit`, `secrets[`);
//! - the secrets and the environments are named in `pages.yml` only;
//! - `pages.yml` is not triggered by a pull request; each secret is read once, in the `env`
//!   of a step of its job, which runs in the secret's environment, only in this repository,
//!   only on `main`, only on events of the maintainers or the schedule (the `if` is parsed,
//!   not searched), with `contents: read` and nothing else; an environment is used by the job
//!   of its secret only; every action in such a job is pinned by commit, none restores a
//!   cache or uploads an artifact, no checkout keeps its credentials; xtask is built by an
//!   earlier step; the step with the secret is the last of its job, uses no action and no
//!   `cargo`, and masks the key;
//! - `snapshot` signs only when `tuf/v1.toml` says `snapshot = "online"` (an unknown setting
//!   fails the job), with `tuf snapshot --previous` over the published `tuf/v1` (one Pages
//!   address, `PAGES_URL`); its files reach `timestamp` (before the key) and `build` only
//!   through `.github/scripts/snapshot-files.sh`, which keeps rules of its own;
//! - nothing is published when `snapshot` failed (Р25): `timestamp` runs only after it
//!   succeeded, `build` not when it or `timestamp` failed; `oracle`, `deploy` and `verify`
//!   name their conditions (`!cancelled()` and the results they need), and `deploy` accepts
//!   a skipped `oracle` only without a signed repository;
//! - `tuf-expiry.yml` checks the committed tree with `--fail-on-expiring` and makes the
//!   expiry of the publishers' roles annotations, without hiding the check's result;
//! - only the `deploy` job may write Pages.
//!
//! `pages.yml` is read by the small parser of `workflow_yaml`: it fails on what it does not
//! understand, so a workflow written so that this test cannot read it fails the test instead
//! of passing it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use serde_json::{Map, Value};

mod workflow_yaml;

use workflow_yaml::{leaves, parse_yaml, pinned};

/// The secrets CI holds, each with its environment and the job that reads it.
const SECRETS: [(&str, &str, &str); 2] = [
    ("TUF_SNAPSHOT_KEY", "tuf-snapshot", "snapshot"),
    ("TUF_TIMESTAMP_KEY", "tuf-timestamp", "timestamp"),
];
const ENVIRONMENTS: [&str; 2] = ["tuf-snapshot", "tuf-timestamp"];
const PAGES: &str = "pages.yml";
const EXPIRY: &str = "tuf-expiry.yml";
/// The script that carries the online snapshots from `snapshot` to `timestamp` and `build`.
const SCRIPT: &str = ".github/scripts/snapshot-files.sh";
const REPOSITORY: &str = "arynyklas/OpenNCALayer";
/// The events the jobs with a secret may run on: started by the maintainers or the schedule,
/// never by a pull request. `repository_dispatch` (the upstream watcher) is there because
/// `build` does not run without the timestamp they make.
const EVENTS: [&str; 5] = [
    "push",
    "schedule",
    "workflow_run",
    "workflow_dispatch",
    "repository_dispatch",
];

// ---- the rules ----

/// The parts of `expr` between `op` at the top level (outside parentheses and quotes).
fn split_top<'a>(expr: &'a str, op: &str) -> Vec<&'a str> {
    let (mut parts, mut depth, mut quote, mut start) = (Vec::new(), 0usize, false, 0usize);
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => quote = !quote,
            b'(' if !quote => depth += 1,
            b')' if !quote => depth = depth.saturating_sub(1),
            _ if !quote && depth == 0 && expr[i..].starts_with(op) => {
                parts.push(&expr[start..i]);
                i += op.len();
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&expr[start..]);
    parts
}

/// Whether `text` is one parenthesized group, not `(a) || (b)`.
fn whole_group(text: &str) -> bool {
    if !(text.starts_with('(') && text.ends_with(')')) {
        return false;
    }
    let mut depth = 0usize;
    let mut quote = false;
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'\'' => quote = !quote,
            b'(' if !quote => depth += 1,
            b')' if !quote => {
                depth -= 1;
                if depth == 0 && i != text.len() - 1 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

/// `github.ref == main && github.repository == ours && (event == a || event == b …)`, and
/// nothing else.
fn check_condition(raw: &str) -> Result<(), String> {
    let text = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let text = text
        .strip_prefix("${{")
        .and_then(|t| t.strip_suffix("}}"))
        .map_or(text.as_str(), str::trim);
    let conjuncts = split_top(text, "&&");
    if conjuncts.len() != 3 {
        return Err(format!("the condition is not three `&&` parts: {text}"));
    }
    let (mut main, mut repository, mut events) = (false, false, false);
    for part in conjuncts.iter().map(|p| p.trim()) {
        if part == "github.ref == 'refs/heads/main'" {
            main = true;
        } else if part == format!("github.repository == '{REPOSITORY}'") {
            repository = true;
        } else if whole_group(part) {
            let alternatives = split_top(&part[1..part.len() - 1], "||");
            for alt in alternatives {
                let event = alt
                    .trim()
                    .strip_prefix("github.event_name == '")
                    .and_then(|a| a.strip_suffix('\''))
                    .ok_or_else(|| format!("not an event test: {}", alt.trim()))?;
                if !EVENTS.contains(&event) {
                    return Err(format!("the event {event} is not one the job may run on"));
                }
            }
            events = true;
        } else {
            return Err(format!("not an allowed part of the condition: {part}"));
        }
    }
    if main && repository && events {
        Ok(())
    } else {
        Err(format!(
            "the condition lacks main, the repository or the events: {text}"
        ))
    }
}

/// The environment `job` runs in (`environment: x` or `environment: {name: x}`).
fn environment_of(job: &Value) -> Option<String> {
    match job.get("environment")? {
        Value::String(s) => Some(s.clone()),
        Value::Object(m) => Some(m.get("name").map_or_else(String::new, Value::to_string)),
        other => Some(other.to_string()),
    }
}

/// Every string inside `value`, joined.
fn all_text(value: &Value) -> String {
    let mut inside = Vec::new();
    leaves(value, &mut Vec::new(), &mut inside);
    inside
        .into_iter()
        .map(|(_, v)| v)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The step of `job` with the id `id`.
fn step_with_id<'a>(job: Option<&'a Value>, id: &str) -> Option<&'a Value> {
    job?.get("steps")?
        .as_array()?
        .iter()
        .find(|s| s.get("id").and_then(Value::as_str) == Some(id))
}

/// The string `key` of `step` (empty without one).
fn field<'a>(step: Option<&'a Value>, key: &str) -> &'a str {
    step.and_then(|s| s.get(key))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// The text of `text` after the first `start` and before the next `end`.
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let rest = text.split_once(start)?.1;
    Some(rest.split_once(end)?.0)
}

/// The rules of the job `job_id` that reads a secret in its step `secret_step`.
fn check_secret_job(job_id: &str, job: &Value, secret_step: usize, bad: &mut Vec<String>) {
    match job.get("if").and_then(Value::as_str) {
        Some(condition) => {
            if let Err(e) = check_condition(condition) {
                bad.push(format!("{job_id}: {e}"));
            }
        }
        None => bad.push(format!("the job {job_id} has no `if`")),
    }
    if job.get("permissions") != Some(&serde_json::json!({"contents": "read"})) {
        bad.push(format!(
            "the job {job_id}'s permissions are not exactly `contents: read`"
        ));
    }
    if job.get("env").is_some() {
        bad.push(format!("the job {job_id} has an env of its own"));
    }
    let Some(steps) = job.get("steps").and_then(Value::as_array) else {
        bad.push(format!("the job {job_id} has no steps"));
        return;
    };
    for step in steps {
        if let Some(uses) = step.get("uses").and_then(Value::as_str) {
            if !pinned(uses) {
                bad.push(format!(
                    "an action in the secret's job {job_id} is not pinned by commit: {uses}"
                ));
            }
            if uses.contains("upload-artifact") {
                bad.push(format!("the secret's job {job_id} uploads an artifact"));
            }
            if uses.contains("cache") {
                bad.push(format!(
                    "the secret's job {job_id} restores a cache: {uses}"
                ));
            }
            if uses.starts_with("actions/checkout@")
                && step
                    .get("with")
                    .and_then(|w| w.get("persist-credentials"))
                    .and_then(Value::as_str)
                    != Some("false")
            {
                bad.push(format!(
                    "the checkout of the secret's job {job_id} keeps its credentials"
                ));
            }
        }
    }
    if secret_step + 1 != steps.len() {
        bad.push(format!(
            "the step with the secret is not the last of its job {job_id}"
        ));
    }
    let built = steps[..secret_step.min(steps.len())].iter().any(|s| {
        s.get("run")
            .and_then(Value::as_str)
            .is_some_and(|r| r.contains("cargo build --locked -p xtask"))
    });
    if !built {
        bad.push(format!(
            "the job {job_id} does not build xtask (--locked) before the secret"
        ));
    }
    let Some(step) = steps.get(secret_step) else {
        return;
    };
    if step.get("uses").is_some() {
        bad.push(format!("the step with the secret in {job_id} is an action"));
    }
    if field(Some(step), "run").contains("cargo ") {
        bad.push(format!(
            "the step with the secret in {job_id} runs cargo (builds next to the key)"
        ));
    }
}

/// What is wrong with `pages_yml` (the text of `pages.yml`).
fn check_pages(text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    let doc = match parse_yaml(text) {
        Ok(doc) => doc,
        Err(e) => return vec![format!("pages.yml cannot be read by this test: {e}")],
    };
    // Triggers.
    let on = doc.get("on").cloned().unwrap_or(Value::Null);
    let triggers: Vec<String> = match &on {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        Value::Object(m) => m.keys().cloned().collect(),
        _ => Vec::new(),
    };
    if triggers.is_empty() {
        bad.push("pages.yml has no triggers".to_owned());
    }
    if triggers.iter().any(|t| t.starts_with("pull_request")) {
        bad.push("pages.yml is triggered by a pull request".to_owned());
    }
    let Some(jobs) = doc.get("jobs").and_then(Value::as_object) else {
        bad.push("pages.yml has no jobs".to_owned());
        return bad;
    };
    // Where each secret is read.
    let mut all = Vec::new();
    leaves(&doc, &mut Vec::new(), &mut all);
    let mut secret_steps = BTreeMap::new();
    for (secret, environment, owner) in SECRETS {
        let reads: Vec<&(Vec<String>, String)> = all
            .iter()
            .filter(|(_, v)| {
                v.to_lowercase()
                    .contains(&format!("secrets.{}", secret.to_lowercase()))
            })
            .collect();
        if reads.len() != 1 {
            bad.push(format!(
                "the secret {secret} is read {} times, not once",
                reads.len()
            ));
            continue;
        }
        let (path, value) = reads[0];
        let step = path.get(3).and_then(|s| s.parse::<usize>().ok());
        let shape = path.len() == 6
            && path[0] == "jobs"
            && path[2] == "steps"
            && path[4] == "env"
            && path[5] == secret
            && *value == format!("${{{{ secrets.{secret} }}}}");
        let (true, Some(step)) = (shape, step) else {
            bad.push(format!(
                "the secret {secret} is read at {}, not in the env of a step",
                path.join(".")
            ));
            continue;
        };
        let job_id = &path[1];
        if job_id != owner {
            bad.push(format!(
                "the secret {secret} is read in the job {job_id}, not {owner}"
            ));
            continue;
        }
        if environment_of(&jobs[job_id]).as_deref() != Some(environment) {
            bad.push(format!(
                "the job {job_id} reads {secret} outside the environment {environment}"
            ));
        }
        if !field(Some(&jobs[job_id]["steps"][step]), "run")
            .contains(&format!("echo \"::add-mask::${secret}\""))
        {
            bad.push(format!("the step with {secret} does not mask it"));
        }
        secret_steps.insert(job_id.clone(), step);
    }
    // One address of the site, at the top: no other place names the Pages host.
    let pages_url = doc
        .get("env")
        .and_then(|e| e.get("PAGES_URL"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !(pages_url.starts_with("https://") && pages_url.ends_with('/')) {
        bad.push("pages.yml has no workflow-level PAGES_URL".to_owned());
    }
    if all
        .iter()
        .any(|(p, v)| v.contains("github.io") && p.as_slice() != ["env", "PAGES_URL"])
    {
        bad.push("pages.yml names the Pages host outside PAGES_URL".to_owned());
    }
    // Each environment is used by the job of its secret only.
    for (id, job) in jobs {
        if let Some(env) = environment_of(job) {
            for environment in ENVIRONMENTS {
                let owns = SECRETS.iter().any(|(_, e, o)| *e == environment && o == id);
                if env.contains(environment) && !owns {
                    bad.push(format!(
                        "the environment {environment} is used by the job {id}, which holds none of its secrets"
                    ));
                }
            }
        }
        if job.get("secrets").is_some() {
            bad.push(format!("the job {id} passes secrets to a workflow"));
        }
    }
    for (job_id, step) in &secret_steps {
        check_secret_job(job_id, &jobs[job_id], *step, &mut bad);
    }
    check_graph(jobs, &mut bad);
    check_online_snapshot(jobs, &mut bad);
    match jobs.get("oracle") {
        None => bad.push("there is no oracle job".to_owned()),
        Some(oracle) => {
            if oracle.get("secrets").is_some() || oracle.get("environment").is_some() {
                bad.push("the oracle job has secrets or an environment".to_owned());
            }
            if oracle.get("permissions") != Some(&serde_json::json!({"contents": "read"})) {
                bad.push(
                    "the oracle job's permissions are not exactly `contents: read`".to_owned(),
                );
            }
            let inside = all_text(oracle);
            if inside.to_lowercase().contains("secrets.") || inside.contains("upload-") {
                bad.push("the oracle job reads secrets or uploads an artifact".to_owned());
            }
        }
    }
    // Writing Pages: the deploy job only.
    let writes = |permissions: Option<&Value>| {
        permissions.and_then(Value::as_object).is_some_and(|p| {
            p.get("pages").is_some_and(|v| v == "write")
                || p.get("id-token").is_some_and(|v| v == "write")
        })
    };
    if writes(doc.get("permissions")) {
        bad.push("the workflow's permissions write Pages".to_owned());
    }
    for (id, other) in jobs {
        if id != "deploy" && writes(other.get("permissions")) {
            bad.push(format!("the job {id} may write Pages"));
        }
    }
    bad
}

/// The graph of jobs: nothing is deployed after a failed `snapshot` or `timestamp` (Р25), and
/// `oracle`, `deploy` and `verify` name their conditions in full.
fn check_graph(jobs: &Map<String, Value>, bad: &mut Vec<String>) {
    let needs = |job: &str| -> Vec<String> {
        match jobs.get(job).and_then(|j| j.get("needs")) {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    };
    let condition = |job: &str| {
        field(jobs.get(job), "if")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    if !needs("timestamp").contains(&"snapshot".to_owned()) {
        bad.push("timestamp does not need the snapshot job".to_owned());
    }
    // The implicit `success()`: `timestamp` never signs after a failed `snapshot`.
    let timestamp_if = condition("timestamp");
    if [
        "always()",
        "cancelled()",
        "failure()",
        "needs.snapshot.result",
    ]
    .iter()
    .any(|f| timestamp_if.contains(f))
    {
        bad.push("timestamp runs although the snapshot job failed".to_owned());
    }
    for needed in ["snapshot", "timestamp"] {
        if !needs("build").contains(&needed.to_owned()) {
            bad.push(format!("build does not need the {needed} job"));
        }
        if !condition("build").contains(&format!(
            "contains(fromJSON('[\"success\",\"skipped\"]'), needs.{needed}.result)"
        )) {
            bad.push(format!("build runs although the {needed} job failed"));
        }
    }
    let deploy_needs = needs("deploy");
    for needed in ["build", "oracle"] {
        if !deploy_needs.contains(&needed.to_owned()) {
            bad.push(format!("deploy does not need {needed}"));
        }
    }
    for (job, parts) in [
        (
            "deploy",
            &[
                "!cancelled()",
                "needs.build.result == 'success'",
                "(needs.oracle.result == 'success' || (needs.oracle.result == 'skipped' && needs.build.outputs.tuf != 'signed'))",
            ][..],
        ),
        (
            "oracle",
            &["!cancelled()", "needs.build.result == 'success'"][..],
        ),
        (
            "verify",
            &["!cancelled()", "needs.deploy.result == 'success'"][..],
        ),
    ] {
        let text = condition(job);
        for part in parts {
            if !text.contains(part) {
                bad.push(format!("the condition of {job} lacks {part}"));
            }
        }
    }
}

/// The online snapshot: signed only when `tuf/v1.toml` says so, over the published `tuf/v1`,
/// and carried by the script to `timestamp` (before the key) and `build`.
fn check_online_snapshot(jobs: &Map<String, Value>, bad: &mut Vec<String>) {
    let snapshot = jobs.get("snapshot");
    let mode = field(step_with_id(snapshot, "mode"), "run");
    if !(mode.contains("tuf/v1.toml")
        && mode.contains("'snapshot = \"online\"') mode=online ;;")
        && between(mode, "*)", ";;").is_some_and(|branch| branch.contains("exit 1")))
    {
        bad.push(
            "the snapshot job does not read its mode from tuf/v1.toml, or takes an unknown setting for one"
                .to_owned(),
        );
    }
    let sign = step_with_id(snapshot, "sign");
    if field(sign, "if") != "steps.mode.outputs.mode == 'online'" {
        bad.push("the snapshot is signed whatever tuf/v1.toml says".to_owned());
    }
    let sign_run = field(sign, "run");
    if !sign_run.contains(
        "target/debug/xtask tuf snapshot --out \"$copy\" --previous \"${PAGES_URL}tuf/v1/\"",
    ) {
        bad.push("the snapshot does not extend the published tuf/v1".to_owned());
    }
    if !sign_run.contains(&format!(
        "bash {SCRIPT} pack tuf/v1/metadata \"$copy/metadata\""
    )) {
        bad.push(format!("the snapshots are not packed by {SCRIPT}"));
    }
    if snapshot.and_then(|j| j.get("outputs"))
        != Some(&serde_json::json!({
            "mode": "${{ steps.mode.outputs.mode }}",
            "files": "${{ steps.sign.outputs.files }}",
        }))
    {
        bad.push("the snapshot job's outputs are not exactly its mode and its files".to_owned());
    }
    for (id, job) in jobs {
        if id != "snapshot" && all_text(job).contains("tuf snapshot ") {
            bad.push(format!("the job {id} signs a snapshot"));
        }
    }
    // The snapshots go where they are needed only through the script, with the mode.
    let handed = serde_json::json!({
        "MODE": "${{ needs.snapshot.outputs.mode }}",
        "SNAPSHOTS": "${{ needs.snapshot.outputs.files }}",
    });
    let timestamp = jobs.get("timestamp");
    let unpack = format!("bash {SCRIPT} unpack \"$copy/metadata\"");
    let copy = timestamp
        .and_then(|j| j.get("steps"))
        .and_then(Value::as_array)
        .and_then(|steps| {
            steps
                .iter()
                .find(|s| field(Some(s), "run").contains(&unpack))
        });
    let before_key = copy.is_some_and(|s| {
        !all_text(s).to_lowercase().contains("secrets.") && s.get("env") == Some(&handed)
    });
    let sign_run = field(step_with_id(timestamp, "sign"), "run");
    if !before_key || sign_run.contains("SNAPSHOTS") || sign_run.contains("base64") {
        bad.push(format!(
            "the snapshots are not unpacked by {SCRIPT} into the timestamp's copy before the key"
        ));
    }
    let publish = step_with_id(jobs.get("build"), "tuf");
    let publish_run = field(publish, "run");
    let unpacked = publish_run.find(&format!("bash {SCRIPT} unpack _site/tuf/v1/metadata"));
    let checked = publish_run.find("cargo xtask tuf check --dir _site/tuf/v1 ");
    let env_handed = publish
        .and_then(|s| s.get("env"))
        .and_then(Value::as_object)
        .is_some_and(|env| {
            handed
                .as_object()
                .is_some_and(|h| h.iter().all(|(k, v)| env.get(k) == Some(v)))
        });
    if !(env_handed && matches!((unpacked, checked), (Some(u), Some(c)) if u < c)) {
        bad.push(
            "build does not publish the online snapshots before it checks the copy".to_owned(),
        );
    }
}

/// What is wrong with `tuf-expiry.yml`.
fn check_expiry(text: &str) -> Vec<String> {
    let doc = match parse_yaml(text) {
        Ok(doc) => doc,
        Err(e) => return vec![format!("{EXPIRY} cannot be read by this test: {e}")],
    };
    let mut bad = Vec::new();
    if doc.get("on").and_then(|o| o.get("schedule")).is_none() {
        bad.push(format!("{EXPIRY} has no schedule"));
    }
    let mut all = Vec::new();
    leaves(
        doc.get("jobs").unwrap_or(&Value::Null),
        &mut Vec::new(),
        &mut all,
    );
    let run = all
        .iter()
        .map(|(_, v)| v.as_str())
        .find(|v| v.contains("cargo xtask tuf check "))
        .unwrap_or("");
    for (needle, rule) in [
        (
            "cargo xtask tuf check --no-timestamp --fail-on-expiring --min-days 10 --min-root-days 45",
            "it does not check the committed tree with --fail-on-expiring at 10 and 45 days",
        ),
        ("|| status=$?", "it does not keep the result of the check"),
        (
            "*\"warning[role-expired]\"* | *\"warning[role-expiring]\"*) echo \"::warning::${line//%/%25}\" ;;",
            "it does not make the expiry of the publishers' roles annotations",
        ),
        (
            "echo \"::stop-commands::$token\"\ncat \"$RUNNER_TEMP/expiry.log\"\necho \"::$token::\"",
            "it prints the log with workflow commands on",
        ),
    ] {
        if !run.contains(needle) {
            bad.push(format!("{EXPIRY}: {rule}"));
        }
    }
    if !run.trim_end().ends_with("exit \"$status\"") || run.contains("|| true") {
        bad.push(format!(
            "{EXPIRY}: it does not end with the result of the check"
        ));
    }
    bad
}

/// What is wrong with the workflows `(file name, text)`.
fn check_workflows(files: &[(String, String)]) -> Vec<String> {
    let mut bad = Vec::new();
    for (name, text) in files {
        let lower = text.to_lowercase();
        // Without white space: `toJSON( secrets )` and `secrets [` are the same thing.
        let compact: String = lower.split_whitespace().collect();
        for banned in ["tojson(secrets)", "secrets:inherit", "secrets["] {
            if compact.contains(banned) {
                bad.push(format!("{name} reads secrets wholesale ({banned})"));
            }
        }
        let named = SECRETS
            .iter()
            .any(|(s, _, _)| lower.contains(&s.to_lowercase()))
            || ENVIRONMENTS.iter().any(|e| lower.contains(e));
        if name != PAGES && named {
            bad.push(format!("{name} names a TUF secret or environment"));
        }
    }
    match files.iter().find(|(n, _)| n == PAGES) {
        Some((_, text)) => bad.extend(check_pages(text)),
        None => bad.push("there is no pages.yml".to_owned()),
    }
    match files.iter().find(|(n, _)| n == EXPIRY) {
        Some((_, text)) => bad.extend(check_expiry(text)),
        None => bad.push(format!("there is no {EXPIRY}")),
    }
    bad
}

fn real_workflows() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows");
    let mut files = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            files.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                // A Windows checkout may have CRLF line ends: the mutations are written with LF.
                fs::read_to_string(&path).unwrap().replace("\r\n", "\n"),
            ));
        }
    }
    assert!(
        files.len() > 5,
        "the workflows were not found in {}",
        dir.display()
    );
    files
}

#[test]
fn the_workflows_keep_the_rules_for_the_online_secrets() {
    let bad = check_workflows(&real_workflows());
    assert!(bad.is_empty(), "{bad:#?}");
}

/// `tuf check` compares the signed repository with `publishers/`: a change there runs the
/// index check on pull requests, Pages on `main`, and counts as a site change in CI.
#[test]
fn a_change_of_publishers_runs_the_tuf_check_and_pages() {
    let files = real_workflows();
    let text = |name: &str| {
        files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, t)| t.as_str())
            .unwrap_or_else(|| panic!("{name}"))
    };
    assert!(
        text("index-check.yml")
            .contains("grep -qE '^(updates/|tuf/|publishers/|crates/oncl-update/keys/)'"),
        "index-check.yml"
    );
    let pages: Value = parse_yaml(text("pages.yml")).unwrap();
    let paths = format!("{:?}", pages["on"]["push"]["paths"]);
    assert!(paths.contains("publishers/**"), "{paths}");
    // The script that carries the snapshots is part of Pages too.
    assert!(paths.contains(SCRIPT), "{paths}");
    assert!(
        text("ci.yml").contains("updates/* | tuf/* | publishers/*) site=true ;;"),
        "ci.yml"
    );
}

/// The real workflows with the file `file` changed by replacing `from` with `to` (which must
/// be there) and `extra` files added.
fn mutated_file(file: &str, from: &str, to: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut files = real_workflows();
    for (name, text) in &mut files {
        if name == file && !from.is_empty() {
            assert!(text.contains(from), "the mutation target is gone: {from:?}");
            *text = text.replacen(from, to, 1);
        }
    }
    files.extend(
        extra
            .iter()
            .map(|(n, t)| ((*n).to_owned(), (*t).to_owned())),
    );
    files
}

/// The real workflows with `pages.yml` changed by replacing `from` with `to` (which must be
/// there) and `extra` files added.
fn mutated(from: &str, to: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    mutated_file(PAGES, from, to, extra)
}

fn assert_found(files: Vec<(String, String)>, needle: &str) {
    let bad = check_workflows(&files);
    assert!(
        bad.iter().any(|b| b.contains(needle)),
        "not caught ({needle:?}): {bad:#?}"
    );
}

#[test]
fn a_pull_request_trigger_is_found() {
    assert_found(
        mutated("on:\n  push:", "on:\n  pull_request:\n  push:", &[]),
        "pull request",
    );
}

#[test]
fn a_condition_with_another_event_or_without_main_is_found() {
    // The first condition is the snapshot job's; the timestamp job's is the one before its
    // environment.
    assert_found(
        mutated(
            "github.event_name == 'repository_dispatch')",
            "github.event_name == 'repository_dispatch') || github.event_name == 'release'",
            &[],
        ),
        "snapshot: not an allowed part of the condition",
    );
    assert_found(
        mutated(
            "github.event_name == 'repository_dispatch')\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    environment: tuf-timestamp\n",
            "github.event_name == 'repository_dispatch') || github.event_name == 'release'\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    environment: tuf-timestamp\n",
            &[],
        ),
        "timestamp: not an allowed part of the condition",
    );
    assert_found(
        mutated(
            "github.event_name == 'push' ||",
            "github.event_name == 'pull_request' ||",
            &[],
        ),
        "not one the job may run on",
    );
    assert_found(
        mutated("      github.ref == 'refs/heads/main' &&\n", "", &[]),
        "condition",
    );
    assert_found(
        mutated(
            "      github.repository == 'arynyklas/OpenNCALayer' && (\n",
            "      (\n",
            &[],
        ),
        "condition",
    );
}

#[test]
fn the_secret_outside_one_step_env_is_found() {
    assert_found(
        mutated(
            "    environment: tuf-timestamp\n",
            "    environment: tuf-timestamp\n    env:\n      TUF_TIMESTAMP_KEY: ${{ secrets.TUF_TIMESTAMP_KEY }}\n",
            &[],
        ),
        "TUF_TIMESTAMP_KEY is read 2 times, not once",
    );
    assert_found(
        mutated(
            "env:\n  CARGO_TERM_COLOR: always\n",
            "env:\n  CARGO_TERM_COLOR: always\n  TUF_SNAPSHOT_KEY: ${{ secrets.TUF_SNAPSHOT_KEY }}\n",
            &[],
        ),
        "TUF_SNAPSHOT_KEY is read 2 times, not once",
    );
    // A key read in the other key's job.
    let moved: Vec<(String, String)> = mutated(
        "          TUF_TIMESTAMP_KEY: ${{ secrets.TUF_TIMESTAMP_KEY }}\n",
        "",
        &[],
    )
    .into_iter()
    .map(|(n, t)| {
        let t = t.replacen(
            "          TUF_SNAPSHOT_KEY: ${{ secrets.TUF_SNAPSHOT_KEY }}\n",
            "          TUF_SNAPSHOT_KEY: ${{ secrets.TUF_SNAPSHOT_KEY }}\n          TUF_TIMESTAMP_KEY: ${{ secrets.TUF_TIMESTAMP_KEY }}\n",
            1,
        );
        (n, t)
    })
    .collect();
    assert_found(
        moved,
        "TUF_TIMESTAMP_KEY is read in the job snapshot, not timestamp",
    );
}

#[test]
fn the_secret_or_the_environment_in_another_workflow_is_found() {
    let other = "name: x\non:\n  pull_request:\njobs:\n  a:\n    environment: tuf-timestamp\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo ${{ secrets.TUF_TIMESTAMP_KEY }}\n";
    assert_found(mutated("", "", &[("evil.yml", other)]), "evil.yml names");
    // The `.yaml` extension is a workflow too, and a copy of pages.yml is another file.
    assert_found(mutated("", "", &[("evil.yaml", other)]), "evil.yaml names");
    for name in ["TUF_SNAPSHOT_KEY", "tuf-snapshot"] {
        let other = format!("name: x\njobs:\n  a:\n    steps:\n      - run: echo {name}\n");
        assert_found(mutated("", "", &[("evil.yml", &other)]), "evil.yml names");
    }
    let copy = real_workflows()
        .into_iter()
        .find(|(n, _)| n == PAGES)
        .unwrap()
        .1;
    assert_found(
        mutated("", "", &[("pages.yaml", &copy)]),
        "pages.yaml names",
    );
    assert_found(
        mutated(
            "",
            "",
            &[("all.yml", "name: x\njobs:\n  a:\n    secrets: inherit\n")],
        ),
        "wholesale",
    );
    assert_found(
        mutated(
            "",
            "",
            &[("all.yml", "name: x\nenv:\n  A: ${{ toJSON(secrets) }}\n")],
        ),
        "wholesale",
    );
    assert_found(
        mutated(
            "",
            "",
            &[("all.yml", "name: x\nenv:\n  A: ${{ secrets['X'] }}\n")],
        ),
        "wholesale",
    );
}

#[test]
fn an_unpinned_action_a_later_step_or_a_write_permission_in_a_secret_job_is_found() {
    assert_found(
        mutated(
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5",
            "actions/checkout@v5",
            &[],
        ),
        "in the secret's job snapshot is not pinned by commit",
    );
    assert_found(
        mutated(
            "    environment: tuf-timestamp\n    permissions:\n      contents: read\n",
            "    environment: tuf-timestamp\n    permissions:\n      contents: read\n      pages: write\n",
            &[],
        ),
        "timestamp's permissions are not exactly",
    );
    assert_found(
        mutated(
            "    environment: tuf-snapshot\n    permissions:\n      contents: read\n",
            "    environment: tuf-snapshot\n    permissions:\n      contents: write\n",
            &[],
        ),
        "snapshot's permissions are not exactly",
    );
    assert_found(
        mutated(
            "          } >> \"$GITHUB_OUTPUT\"\n\n  dispatch:",
            "          } >> \"$GITHUB_OUTPUT\"\n      - uses: actions/upload-artifact@v5\n        with:\n          path: x\n\n  dispatch:",
            &[],
        ),
        "not the last of its job timestamp",
    );
    assert_found(
        mutated(
            "            echo \"TUF_SNAPSHOT_EOF\"\n          } >> \"$GITHUB_OUTPUT\"\n",
            "            echo \"TUF_SNAPSHOT_EOF\"\n          } >> \"$GITHUB_OUTPUT\"\n      - run: echo later\n",
            &[],
        ),
        "not the last of its job snapshot",
    );
    assert_found(
        mutated(
            "          echo \"::add-mask::$TUF_TIMESTAMP_KEY\"\n",
            "",
            &[],
        ),
        "the step with TUF_TIMESTAMP_KEY does not mask it",
    );
    assert_found(
        mutated(
            "          echo \"::add-mask::$TUF_SNAPSHOT_KEY\"\n",
            "          echo \"::add-mask::$TUF_TIMESTAMP_KEY\"\n",
            &[],
        ),
        "the step with TUF_SNAPSHOT_KEY does not mask it",
    );
    assert_found(
        mutated("    environment: tuf-timestamp\n", "", &[]),
        "reads TUF_TIMESTAMP_KEY outside the environment tuf-timestamp",
    );
    assert_found(
        mutated(
            "    environment: tuf-snapshot\n",
            "    environment: tuf-timestamp\n",
            &[],
        ),
        "reads TUF_SNAPSHOT_KEY outside the environment tuf-snapshot",
    );
    assert_found(
        mutated(
            "  oracle:\n    needs: build\n",
            "  oracle:\n    needs: build\n    environment: tuf-snapshot\n",
            &[],
        ),
        "tuf-snapshot is used by the job oracle",
    );
}

#[test]
fn a_cache_cargo_next_to_the_key_or_no_build_in_the_snapshot_job_is_found() {
    assert_found(
        mutated(
            "      - name: Is the snapshot online?\n",
            "      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3\n      - name: Is the snapshot online?\n",
            &[],
        ),
        "the secret's job snapshot restores a cache",
    );
    assert_found(
        mutated(
            "          target/debug/xtask tuf snapshot --out",
            "          cargo xtask tuf snapshot --out",
            &[],
        ),
        "in snapshot runs cargo",
    );
    assert_found(
        mutated(
            "        if: steps.mode.outputs.mode == 'online'\n        run: cargo build --locked -p xtask\n",
            "        if: steps.mode.outputs.mode == 'online'\n        run: echo no build\n",
            &[],
        ),
        "the job snapshot does not build xtask (--locked) before the secret",
    );
    assert_found(
        mutated(
            "        if: steps.tree.outputs.exists == 'true'\n        run: cargo build --locked -p xtask\n",
            "        if: steps.tree.outputs.exists == 'true'\n        run: cargo build -p xtask\n",
            &[],
        ),
        "the job timestamp does not build xtask (--locked) before the secret",
    );
    assert_found(
        mutated(
            "      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5\n        with:\n          persist-credentials: false\n",
            "      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5\n        with:\n          persist-credentials: true\n",
            &[],
        ),
        "the checkout of the secret's job snapshot keeps its credentials",
    );
    assert_found(
        mutated(
            "  snapshot:\n    if: >-\n      github.ref == 'refs/heads/main' &&\n",
            "  snapshot:\n    if: >-\n",
            &[],
        ),
        "snapshot: the condition",
    );
}

#[test]
fn the_online_snapshot_is_pinned() {
    // Signed only when tuf/v1.toml says online; an unknown setting fails.
    assert_found(
        mutated(
            "        id: sign\n        if: steps.mode.outputs.mode == 'online'\n",
            "        id: sign\n        if: steps.mode.outputs.mode != 'none'\n",
            &[],
        ),
        "signed whatever tuf/v1.toml says",
    );
    assert_found(
        mutated(
            "                exit 1\n                ;;\n            esac\n",
            "                mode=offline\n                ;;\n            esac\n",
            &[],
        ),
        "takes an unknown setting for one",
    );
    // Over the published tuf/v1, at the one Pages address.
    assert_found(
        mutated(
            " --previous \"${PAGES_URL}tuf/v1/\"",
            " --previous \"$RUNNER_TEMP/old\"",
            &[],
        ),
        "does not extend the published tuf/v1",
    );
    assert_found(
        mutated(
            "  PAGES_URL: https://arynyklas.github.io/OpenNCALayer/\n",
            "  PAGES_URL: https://arynyklas.github.io/OpenNCALayer\n",
            &[],
        ),
        "no workflow-level PAGES_URL",
    );
    assert_found(
        mutated(
            " --previous \"${PAGES_URL}tuf/v1/\"",
            " --previous \"https://arynyklas.github.io/OpenNCALayer/tuf/v1/\"",
            &[],
        ),
        "names the Pages host outside PAGES_URL",
    );
    // Carried by the script, to the timestamp before its key, and to the site before its check.
    assert_found(
        mutated(
            "bash .github/scripts/snapshot-files.sh pack ",
            "bash .github/scripts/other.sh pack ",
            &[],
        ),
        "not packed by .github/scripts/snapshot-files.sh",
    );
    assert_found(
        mutated(
            "      files: ${{ steps.sign.outputs.files }}\n",
            "      files: ${{ steps.sign.outputs.files }}\n      key: ${{ steps.sign.outputs.key }}\n",
            &[],
        ),
        "outputs are not exactly its mode and its files",
    );
    assert_found(
        mutated(
            "            bash .github/scripts/snapshot-files.sh unpack \"$copy/metadata\"\n",
            "            printf '%s' \"$SNAPSHOTS\" > \"$copy/metadata/x\"\n",
            &[],
        ),
        "into the timestamp's copy before the key",
    );
    assert_found(
        mutated(
            "          SNAPSHOTS: ${{ needs.snapshot.outputs.files }}\n        run: |\n          copy=",
            "          SNAPSHOTS: ${{ needs.snapshot.outputs.files }}\n          TUF_TIMESTAMP_KEY: ${{ secrets.TUF_TIMESTAMP_KEY }}\n        run: |\n          copy=",
            &[],
        ),
        "TUF_TIMESTAMP_KEY is read 2 times",
    );
    assert_found(
        mutated(
            "            bash .github/scripts/snapshot-files.sh unpack _site/tuf/v1/metadata\n",
            "",
            &[],
        ),
        "build does not publish the online snapshots",
    );
    assert_found(
        mutated(
            "          cargo xtask tuf check --dir _site/tuf/v1 ",
            "          cargo xtask tuf snapshot --out _site/tuf/v1\n          cargo xtask tuf check --dir _site/tuf/v1 ",
            &[],
        ),
        "the job build signs a snapshot",
    );
}

#[test]
fn only_the_deploy_job_may_write_pages() {
    assert_found(
        mutated(
            "    timeout-minutes: 15\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@v5\n        with:\n          persist-credentials: false\n      - uses: actions/download-artifact@v5",
            "    timeout-minutes: 15\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - uses: actions/checkout@v5\n        with:\n          persist-credentials: false\n      - uses: actions/download-artifact@v5",
            &[],
        ),
        "may write Pages",
    );
}

#[test]
fn what_the_parser_does_not_read_is_an_error_and_not_a_pass() {
    for yaml in [
        "a: {b: c}\n",
        "a: &x 1\n",
        "a: !tag b\n",
        "a: b\n  continued\n",
        "---\na: b\n",
        "a: 1\na: 2\n",
    ] {
        assert!(parse_yaml(yaml).is_err(), "{yaml:?}");
    }
    let doc =
        parse_yaml("a:\n  - b: 1  # c\n    d: [e, \"f g\"]\n  - x\nh: >-\n  one\n  two\n").unwrap();
    assert_eq!(doc["a"][0]["b"], "1");
    assert_eq!(doc["a"][0]["d"], serde_json::json!(["e", "f g"]));
    assert_eq!(doc["a"][1], "x");
    assert_eq!(doc["h"], "one two");
    // A workflow the parser cannot read fails the rules.
    assert_found(
        mutated("name: Pages\n", "name: Pages\nanchor: &a 1\n", &[]),
        "cannot be read",
    );
    assert_found(
        mutated_file(
            EXPIRY,
            "name: TUF expiry\n",
            "name: TUF expiry\nanchor: &a 1\n",
            &[],
        ),
        "tuf-expiry.yml cannot be read",
    );
    // A set of conditions the checker has to take apart correctly.
    let keep: BTreeSet<&str> = EVENTS.into_iter().collect();
    assert_eq!(keep.len(), 5);
    assert!(check_condition("github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push')").is_ok());
    assert!(check_condition("github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push') || (github.event_name == 'release')").is_err());
    assert!(check_condition("github.event_name == 'release' || github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push')").is_err());
    // A status function in a job with a key: it would run after a failed `snapshot`.
    assert!(check_condition("!cancelled() && github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push')").is_err());
}

#[test]
fn the_graph_of_jobs_is_pinned() {
    // A failed snapshot stops the publication (Р25).
    assert_found(
        mutated("  timestamp:\n    needs: snapshot\n", "  timestamp:\n", &[]),
        "timestamp does not need the snapshot job",
    );
    assert_found(
        mutated(
            "  timestamp:\n    needs: snapshot\n    if: >-\n      github.ref == 'refs/heads/main' &&\n",
            "  timestamp:\n    needs: snapshot\n    if: >-\n      !cancelled() &&\n      github.ref == 'refs/heads/main' &&\n",
            &[],
        ),
        "timestamp runs although the snapshot job failed",
    );
    assert_found(
        mutated(
            "    needs: [snapshot, timestamp]\n",
            "    needs: [snapshot]\n",
            &[],
        ),
        "build does not need the timestamp job",
    );
    assert_found(
        mutated(
            "    needs: [snapshot, timestamp]\n",
            "    needs: [timestamp]\n",
            &[],
        ),
        "build does not need the snapshot job",
    );
    assert_found(
        mutated(
            "contains(fromJSON('[\"success\",\"skipped\"]'), needs.snapshot.result)",
            "needs.snapshot.result != 'failure'",
            &[],
        ),
        "build runs although the snapshot job failed",
    );
    assert_found(
        mutated(
            "contains(fromJSON('[\"success\",\"skipped\"]'), needs.timestamp.result)",
            "needs.timestamp.result != 'failure'",
            &[],
        ),
        "build runs although the timestamp job failed",
    );
    assert_found(
        mutated("    needs: [build, oracle]\n", "    needs: [build]\n", &[]),
        "deploy does not need oracle",
    );
    assert_found(
        mutated("    needs: [build, oracle]\n", "    needs: [oracle]\n", &[]),
        "deploy does not need build",
    );
    // No implicit `success()`, and no skipped oracle over a signed repository.
    assert_found(
        mutated(
            "(needs.oracle.result == 'success' || (needs.oracle.result == 'skipped' && needs.build.outputs.tuf != 'signed'))",
            "contains(fromJSON('[\"success\",\"skipped\"]'), needs.oracle.result)",
            &[],
        ),
        "the condition of deploy lacks",
    );
    assert_found(
        mutated(
            "needs.build.result == 'success' && needs.build.outputs.publish == 'true' && (needs.oracle",
            "needs.build.outputs.publish == 'true' && (needs.oracle",
            &[],
        ),
        "the condition of deploy lacks",
    );
    assert_found(
        mutated(
            "if: ${{ !cancelled() && needs.build.result == 'success' && needs.build.outputs.publish == 'true' && needs.build.outputs.tuf == 'signed' }}",
            "if: needs.build.outputs.publish == 'true' && needs.build.outputs.tuf == 'signed'",
            &[],
        ),
        "the condition of oracle lacks",
    );
    assert_found(
        mutated(
            "if: ${{ !cancelled() && needs.deploy.result == 'success' && needs.build.outputs.tuf == 'signed' }}",
            "if: needs.build.outputs.tuf == 'signed'",
            &[],
        ),
        "the condition of verify lacks",
    );
    assert_found(
        mutated(
            "  oracle:\n    needs: build\n",
            "  oracle:\n    needs: build\n    environment: tuf-timestamp\n",
            &[],
        ),
        "oracle job has secrets or an environment",
    );
    assert_found(
        mutated(
            "--index \"$RUNNER_TEMP/site/updates/v1\"\n",
            "--index \"$RUNNER_TEMP/site/updates/v1\"\n      - uses: actions/upload-artifact@v5\n        with:\n          path: x\n",
            &[],
        ),
        "uploads an artifact",
    );
    assert_found(
        mutated(
            "  oracle:\n    needs: build\n",
            "  oracle:\n    needs: build\n    secrets: inherit\n",
            &[],
        ),
        "wholesale",
    );
}

#[test]
fn white_space_does_not_hide_a_wholesale_read_of_secrets() {
    for text in [
        "env:\n  A: ${{ toJSON( secrets ) }}\n",
        "env:\n  A: ${{ secrets [ 'X' ] }}\n",
        "jobs:\n  a:\n    secrets:   inherit\n",
    ] {
        assert_found(mutated("", "", &[("x.yml", text)]), "wholesale");
    }
}

#[test]
fn the_expiry_workflow_keeps_its_rules() {
    for (from, to, needle) in [
        (
            " --fail-on-expiring --min-days 10",
            " --min-days 10",
            "--fail-on-expiring at 10 and 45 days",
        ),
        (
            "          exit \"$status\"\n",
            "          exit 0\n",
            "does not end with the result of the check",
        ),
        (
            " || status=$?",
            " || true",
            "does not keep the result of the check",
        ),
        (
            " | *\"warning[role-expiring]\"*)",
            ")",
            "the publishers' roles annotations",
        ),
        ("  schedule:\n", "  push:\n", "has no schedule"),
        (
            "          echo \"::stop-commands::$token\"\n",
            "",
            "with workflow commands on",
        ),
    ] {
        assert_found(mutated_file(EXPIRY, from, to, &[]), needle);
    }
}

fn snapshot_script() -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(SCRIPT),
    )
    .unwrap()
    .replace("\r\n", "\n")
}

/// What is wrong with the script that carries the snapshots between the jobs.
fn check_snapshot_script(text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for (needle, rule) in [
        (
            "set -euo pipefail\n",
            "it does not stop on the first failure",
        ),
        ("\nMAX=131072\n", "the cap is not the client's 128 KiB"),
        (
            "\nNAME='^[0-9]{1,20}\\.snapshot\\.json$'\n",
            "it does not allow only <N>.snapshot.json",
        ),
        (
            "echo \"::error::snapshot-files.sh: $1\"",
            "a refusal is not an error annotation",
        ),
    ] {
        if !text.contains(needle) {
            bad.push(rule.to_owned());
        }
    }
    let pack = between(text, "\n  pack)\n", "\n    ;;").unwrap_or("");
    for (needle, rule) in [
        (
            "[[ \"$name\" =~ $NAME ]] || fail",
            "it packs a file that is not <N>.snapshot.json",
        ),
        (
            "{ [ -f \"$file\" ] && [ ! -L \"$file\" ]; } || fail",
            "it packs what is not a regular file (a symlink)",
        ),
        (
            "shopt -s nullglob dotglob\n",
            "it does not see every file of the copy",
        ),
        (
            "printf '%s %s\\n' \"$name\" \"$(base64 -w0 -- \"$file\")\"",
            "it does not pack one line of base64 per file",
        ),
        (
            "{ [ \"$count\" -ge 1 ] && [ \"$count\" -le 2 ]; } || fail",
            "it packs other than one or two files",
        ),
    ] {
        if !pack.contains(needle) {
            bad.push(rule.to_owned());
        }
    }
    let unpack = between(text, "\n  unpack)\n", "\n    ;;").unwrap_or("");
    for (needle, rule) in [
        (
            "[ -n \"${SNAPSHOTS:-}\" ] || fail",
            "it takes nothing for snapshots",
        ),
        (
            "{ [ \"${#lines[@]}\" -ge 1 ] && [ \"${#lines[@]}\" -le 2 ]; } || fail",
            "it does not allow only one or two files",
        ),
        (
            "{ [[ \"$name\" =~ $NAME ]] && [[ \"$data\" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; }",
            "it does not check each line",
        ),
        (
            "{ [ ! -e \"$2/$name\" ] && [ ! -L \"$2/$name\" ] && [ ! -e \"$staged/$name\" ]; } || fail",
            "it may overwrite a file",
        ),
        (
            "[ \"${#data}\" -le $(((MAX + 2) / 3 * 4)) ] || fail",
            "it decodes before it caps the length",
        ),
        (
            "trap 'rm -rf -- \"$staged\"' EXIT\n",
            "it leaves the staged files behind",
        ),
        (
            "    staged=$(mktemp -d)\n",
            "it does not stage the files outside the directory",
        ),
    ] {
        if !unpack.contains(needle) {
            bad.push(rule.to_owned());
        }
    }
    // Nothing is written into the directory before every line is checked.
    let checks_end = unpack.find("\n    done\n");
    let capped = unpack.find("[ \"$size\" -le \"$MAX\" ] || fail");
    let written = unpack.find("mv -n -- ");
    if !matches!((capped, checks_end, written), (Some(c), Some(e), Some(w)) if c < e && e < w) {
        bad.push("it writes before every line is checked".to_owned());
    }
    if unpack.contains("> \"$2") {
        bad.push("it writes into the directory other than with mv -n".to_owned());
    }
    bad
}

#[test]
fn the_snapshot_script_keeps_its_rules() {
    let text = snapshot_script();
    let bad = check_snapshot_script(&text);
    assert!(bad.is_empty(), "{bad:#?}");
    for (from, to, needle) in [
        ("\nMAX=131072\n", "\nMAX=1310720\n", "the cap"),
        (
            "^[0-9]{1,20}\\.snapshot\\.json$",
            "^.*$",
            "only <N>.snapshot.json",
        ),
        (
            "{ [ ! -e \"$2/$name\" ] && [ ! -L \"$2/$name\" ] && [ ! -e \"$staged/$name\" ]; } || fail",
            "true || fail",
            "may overwrite",
        ),
        (
            "    staged=$(mktemp -d)\n",
            "    staged=\"$2\"\n",
            "outside the directory",
        ),
        (
            "      names+=(\"$name\")\n    done\n",
            "      names+=(\"$name\")\n      mv -n -- \"$staged/$name\" \"$2/$name\"\n    done\n",
            "before every line is checked",
        ),
        (
            "    { [ \"$count\" -ge 1 ] && [ \"$count\" -le 2 ]; } || fail",
            "    true || fail",
            "other than one or two",
        ),
        (
            "{ [ -f \"$file\" ] && [ ! -L \"$file\" ]; } || fail",
            "true || fail",
            "not a regular file",
        ),
        (
            "[ \"${#data}\" -le $(((MAX + 2) / 3 * 4)) ] || fail",
            "true || fail",
            "caps the length",
        ),
    ] {
        assert!(text.contains(from), "the mutation target is gone: {from:?}");
        let broken = check_snapshot_script(&text.replacen(from, to, 1));
        assert!(
            broken.iter().any(|b| b.contains(needle)),
            "not caught ({needle:?}): {broken:#?}"
        );
    }
}
