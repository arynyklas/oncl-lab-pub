//! The rules for the one secret CI holds, the online TUF timestamp key (`docs/dev/release.md`),
//! checked on the workflow files as they are, and shown to catch what they claim to: the
//! negative tests below break a copy of `pages.yml` (or add a workflow) in each way a mistake
//! or an attack would, and each must be found.
//!
//! The rules:
//!
//! - no workflow reads secrets wholesale (`toJSON(secrets)`, `secrets: inherit`, `secrets[`);
//! - the secret and the environment are named in `pages.yml` only;
//! - `pages.yml` is not triggered by a pull request; the secret is read once, in the `env` of
//!   a step, of a job that runs in the environment `tuf-timestamp`, only in this repository,
//!   only on `main`, only on events of the maintainers or the schedule (the `if` is parsed,
//!   not searched), with `contents: read` and nothing else; every action in that job is
//!   pinned by commit; the step with the secret is the last, uses no action and masks the key;
//! - only the `deploy` job may write Pages.
//!
//! `pages.yml` is read by a small parser of the block-style YAML the workflows are written in
//! (a YAML parser is not a dependency of `xtask`): it fails on what it does not understand
//! (flow mappings, anchors, tags, continuation lines), so a workflow written so that this
//! test cannot read it fails the test instead of passing it.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::{Map, Value};

const SECRET: &str = "TUF_TIMESTAMP_KEY";
const ENVIRONMENT: &str = "tuf-timestamp";
const PAGES: &str = "pages.yml";
const REPOSITORY: &str = "arynyklas/OpenNCALayer";
/// The events the timestamp job may run on: started by the maintainers or the schedule, never
/// by a pull request. `repository_dispatch` (the upstream watcher) is there because `build`
/// does not run without the timestamp this job makes.
const EVENTS: [&str; 5] = [
    "push",
    "schedule",
    "workflow_run",
    "workflow_dispatch",
    "repository_dispatch",
];

// ---- a parser for the block-style YAML of the workflows ----

struct Parser {
    lines: Vec<String>,
    i: usize,
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

impl Parser {
    fn blank(line: &str) -> bool {
        let t = line.trim();
        t.is_empty() || t.starts_with('#')
    }

    /// The next line with content: its indentation and text.
    fn peek(&mut self) -> Result<Option<(usize, String)>, String> {
        while self.i < self.lines.len() && Parser::blank(&self.lines[self.i]) {
            self.i += 1;
        }
        let Some(line) = self.lines.get(self.i) else {
            return Ok(None);
        };
        if line.trim_start_matches(' ').starts_with('\t') {
            return Err(format!("line {}: a tab in the indentation", self.i + 1));
        }
        Ok(Some((indent_of(line), line.trim().to_owned())))
    }

    fn block(&mut self, indent: usize) -> Result<Value, String> {
        let Some((n, text)) = self.peek()? else {
            return Ok(Value::Null);
        };
        if n != indent {
            return Err(format!("line {}: unexpected indentation", self.i + 1));
        }
        if text == "-" || text.starts_with("- ") {
            self.sequence(indent)
        } else if split_key(&text)?.is_some() {
            self.mapping(indent)
        } else {
            self.i += 1;
            scalar(&text)
        }
    }

    fn sequence(&mut self, n: usize) -> Result<Value, String> {
        let mut items = Vec::new();
        while let Some((ind, text)) = self.peek()? {
            if ind != n || !(text == "-" || text.starts_with("- ")) {
                break;
            }
            let rest = text[1..].trim_start();
            if rest.is_empty() {
                self.i += 1;
                items.push(match self.peek()? {
                    Some((next, _)) if next > n => self.block(next)?,
                    _ => Value::Null,
                });
            } else {
                // The item's first line is the rest of this one, further in.
                let at = n + (text.len() - rest.len());
                self.lines[self.i] = format!("{}{rest}", " ".repeat(at));
                items.push(self.block(at)?);
            }
        }
        Ok(Value::Array(items))
    }

    fn mapping(&mut self, n: usize) -> Result<Value, String> {
        let mut map = Map::new();
        while let Some((ind, text)) = self.peek()? {
            if ind < n || (ind == n && (text == "-" || text.starts_with("- "))) {
                break;
            }
            if ind > n {
                return Err(format!(
                    "line {}: unexpected indentation (a continued scalar?)",
                    self.i + 1
                ));
            }
            let Some((key, rest)) = split_key(&text)? else {
                return Err(format!("line {}: not a `key: value` line", self.i + 1));
            };
            self.i += 1;
            let value = if rest.is_empty() {
                match self.peek()? {
                    Some((next, _)) if next > n => self.block(next)?,
                    Some((next, text)) if next == n && (text == "-" || text.starts_with("- ")) => {
                        self.sequence(n)?
                    }
                    _ => Value::Null,
                }
            } else if rest.starts_with('|') || rest.starts_with('>') {
                self.block_scalar(n, &rest)?
            } else {
                scalar(&rest)?
            };
            if map.insert(key.clone(), value).is_some() {
                return Err(format!("the key {key:?} is twice in a mapping"));
            }
        }
        Ok(Value::Object(map))
    }

    fn block_scalar(&mut self, n: usize, header: &str) -> Result<Value, String> {
        let folded = header.starts_with('>');
        let mut body: Vec<String> = Vec::new();
        while let Some(line) = self.lines.get(self.i) {
            if !line.trim().is_empty() && indent_of(line) <= n {
                break;
            }
            body.push(line.clone());
            self.i += 1;
        }
        let strip = body
            .iter()
            .filter(|l| !l.trim().is_empty())
            .map(|l| indent_of(l))
            .min()
            .unwrap_or(0);
        let lines: Vec<&str> = body
            .iter()
            .map(|l| {
                if l.len() >= strip {
                    l[strip..].trim_end()
                } else {
                    ""
                }
            })
            .collect();
        let mut text = if folded {
            let mut out = String::new();
            for (k, line) in lines.iter().enumerate() {
                if k > 0 {
                    let blank = line.is_empty() || lines[k - 1].is_empty();
                    out.push(if blank { '\n' } else { ' ' });
                    if line.is_empty() && lines[k - 1].is_empty() {
                        continue;
                    }
                }
                out.push_str(line);
            }
            out
        } else {
            lines.join("\n")
        };
        text = text.trim_end_matches('\n').to_owned();
        if !header.contains('-') {
            text.push('\n');
        }
        Ok(Value::String(text))
    }
}

/// `key: rest` of a mapping line, or `None` if the line is not one.
fn split_key(text: &str) -> Result<Option<(String, String)>, String> {
    if let Some(quoted) = text.strip_prefix('"') {
        let Some(end) = quoted.find('"') else {
            return Err(format!("an unterminated key in {text:?}"));
        };
        let rest = quoted[end + 1..].strip_prefix(':').map(str::trim);
        return Ok(rest.map(|r| (quoted[..end].to_owned(), r.to_owned())));
    }
    let at = if text.ends_with(':') && !text[..text.len() - 1].contains(": ") {
        Some(text.len() - 1)
    } else {
        text.find(": ")
    };
    Ok(at.map(|at| {
        (
            text[..at].trim().to_owned(),
            text[at + 1..].trim().to_owned(),
        )
    }))
}

/// A one-line value, comments removed; what the parser does not read is an error.
fn scalar(text: &str) -> Result<Value, String> {
    let text = strip_comment(text);
    let text = text.trim();
    let Some(first) = text.chars().next() else {
        return Ok(Value::Null);
    };
    match first {
        '"' => {
            let inner = text
                .strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .ok_or_else(|| format!("a quoted scalar that does not end: {text:?}"))?;
            Ok(Value::String(
                inner
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\")
                    .replace("\\n", "\n"),
            ))
        }
        '\'' => {
            let inner = text
                .strip_prefix('\'')
                .and_then(|t| t.strip_suffix('\''))
                .ok_or_else(|| format!("a quoted scalar that does not end: {text:?}"))?;
            Ok(Value::String(inner.replace("''", "'")))
        }
        '[' => {
            let inner = text
                .strip_prefix('[')
                .and_then(|t| t.strip_suffix(']'))
                .ok_or_else(|| format!("a flow sequence that does not end: {text:?}"))?;
            if inner.contains(['[', '{']) {
                return Err(format!("a nested flow collection: {text:?}"));
            }
            let mut items = Vec::new();
            for item in inner.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                items.push(scalar(item)?);
            }
            Ok(Value::Array(items))
        }
        '{' | '&' | '*' | '!' | '?' | '%' | '@' | '`' => {
            Err(format!("YAML this test does not read: {text:?}"))
        }
        _ => Ok(Value::String(text.to_owned())),
    }
}

fn strip_comment(text: &str) -> &str {
    let mut quote = None;
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match (quote, b) {
            (None, b'"' | b'\'') => quote = Some(b),
            (Some(q), c) if c == q => quote = None,
            (None, b'#') if i == 0 || bytes[i - 1] == b' ' => return &text[..i],
            _ => {}
        }
    }
    text
}

fn parse_yaml(text: &str) -> Result<Value, String> {
    let mut parser = Parser {
        lines: text
            .lines()
            .map(|l| l.trim_end_matches('\r').to_owned())
            .collect(),
        i: 0,
    };
    if parser.peek()?.is_some_and(|(_, t)| t == "---") {
        return Err("a document marker".to_owned());
    }
    let value = parser.block(0)?;
    match parser.peek()? {
        None => Ok(value),
        Some(_) => Err(format!("line {}: text after the document", parser.i + 1)),
    }
}

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

/// Every string of `value` with its path.
fn leaves(value: &Value, path: &mut Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
    match value {
        Value::String(s) => out.push((path.clone(), s.clone())),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                path.push(i.to_string());
                leaves(item, path, out);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                path.push(k.clone());
                leaves(v, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}

fn pinned(uses: &str) -> bool {
    uses.split('@')
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .is_some_and(|r| r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit()))
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
    // Where the secret is read.
    let mut all = Vec::new();
    leaves(&doc, &mut Vec::new(), &mut all);
    let reads: Vec<&(Vec<String>, String)> = all
        .iter()
        .filter(|(_, v)| {
            v.to_lowercase()
                .contains(&format!("secrets.{}", SECRET.to_lowercase()))
        })
        .collect();
    if reads.len() != 1 {
        bad.push(format!(
            "the secret is read {} times, not once",
            reads.len()
        ));
        return bad;
    }
    let (path, value) = reads[0];
    let shape = path.len() == 6
        && path[0] == "jobs"
        && path[2] == "steps"
        && path[3].parse::<usize>().is_ok()
        && path[4] == "env"
        && path[5] == SECRET;
    if !shape || *value != format!("${{{{ secrets.{SECRET} }}}}") {
        bad.push(format!(
            "the secret is read at {}, not in the env of a step",
            path.join(".")
        ));
        return bad;
    }
    let (job_id, step_index) = (path[1].clone(), path[3].parse::<usize>().unwrap());
    let jobs = doc["jobs"].as_object().expect("jobs");
    let job = &jobs[&job_id];
    // The environment is this job's alone.
    for (id, other) in jobs {
        let env = other.get("environment");
        let named = env.is_some_and(|e| e.to_string().contains(ENVIRONMENT));
        if (id == &job_id) != named {
            bad.push(format!(
                "the environment {ENVIRONMENT} is not used by exactly the secret's job ({id})"
            ));
        }
        if other.get("secrets").is_some() {
            bad.push(format!("the job {id} passes secrets to a workflow"));
        }
    }
    // Its condition, permissions and environment.
    match job.get("if").and_then(Value::as_str) {
        Some(condition) => {
            if let Err(e) = check_condition(condition) {
                bad.push(e);
            }
        }
        None => bad.push("the job has no `if`".to_owned()),
    }
    if job.get("permissions") != Some(&serde_json::json!({"contents": "read"})) {
        bad.push("the job's permissions are not exactly `contents: read`".to_owned());
    }
    if job.get("env").is_some() {
        bad.push("the job has an env of its own".to_owned());
    }
    // Its steps: every action pinned, the step with the secret last and plain.
    let steps = job["steps"].as_array().expect("steps");
    for step in steps {
        if let Some(uses) = step.get("uses").and_then(Value::as_str) {
            if !pinned(uses) {
                bad.push(format!(
                    "an action in the secret's job is not pinned by commit: {uses}"
                ));
            }
            if uses.contains("upload-artifact") {
                bad.push("the secret's job uploads an artifact".to_owned());
            }
        }
    }
    if step_index != steps.len() - 1 {
        bad.push("the step with the secret is not the last of its job".to_owned());
    }
    let step = &steps[step_index];
    if step.get("uses").is_some() {
        bad.push("the step with the secret is an action".to_owned());
    }
    if !step
        .get("run")
        .and_then(Value::as_str)
        .is_some_and(|r| r.contains("::add-mask::$"))
    {
        bad.push("the step with the secret does not mask it".to_owned());
    }
    // The graph of jobs: nothing is deployed unless the timestamp job did not fail and the
    // oracle did not fail; the oracle has no secret, no environment and writes no artifact.
    let list = |v: Option<&Value>| -> Vec<String> {
        match v {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    };
    let text = |job: &str, key: &str| {
        jobs.get(job)
            .and_then(|j| j.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    if !list(jobs.get("build").and_then(|j| j.get("needs"))).contains(&"timestamp".to_owned()) {
        bad.push("build does not need the timestamp job".to_owned());
    }
    if !text("build", "if").contains("needs.timestamp.result != 'failure'") {
        bad.push("build runs although the timestamp job failed".to_owned());
    }
    let deploy_needs = list(jobs.get("deploy").and_then(|j| j.get("needs")));
    for needed in ["build", "oracle"] {
        if !deploy_needs.contains(&needed.to_owned()) {
            bad.push(format!("deploy does not need {needed}"));
        }
    }
    let deploy_if = text("deploy", "if");
    for part in [
        "needs.build.result == 'success'",
        "contains(fromJSON('[\"success\",\"skipped\"]'), needs.oracle.result)",
    ] {
        if !deploy_if.contains(part) {
            bad.push(format!("the condition of deploy lacks {part}"));
        }
    }
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
            let mut inside = Vec::new();
            leaves(oracle, &mut Vec::new(), &mut inside);
            if inside
                .iter()
                .any(|(_, v)| v.to_lowercase().contains("secrets.") || v.contains("upload-"))
            {
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
        if name != PAGES && (lower.contains(&SECRET.to_lowercase()) || lower.contains(ENVIRONMENT))
        {
            bad.push(format!(
                "{name} names the TUF timestamp secret or environment"
            ));
        }
    }
    match files.iter().find(|(n, _)| n == PAGES) {
        Some((_, text)) => bad.extend(check_pages(text)),
        None => bad.push("there is no pages.yml".to_owned()),
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
fn the_workflows_keep_the_rules_for_the_timestamp_secret() {
    let bad = check_workflows(&real_workflows());
    assert!(bad.is_empty(), "{bad:#?}");
}

/// The real workflows with `pages.yml` changed by replacing `from` with `to` (which must be
/// there) and `extra` files added.
fn mutated(from: &str, to: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut files = real_workflows();
    for (name, text) in &mut files {
        if name == PAGES && !from.is_empty() {
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
    assert_found(
        mutated(
            "github.event_name == 'repository_dispatch')",
            "github.event_name == 'repository_dispatch') || github.event_name == 'release'",
            &[],
        ),
        "condition",
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
        "times, not once",
    );
    assert_found(
        mutated(
            "env:\n  CARGO_TERM_COLOR: always\n",
            "env:\n  CARGO_TERM_COLOR: always\n  TUF_TIMESTAMP_KEY: ${{ secrets.TUF_TIMESTAMP_KEY }}\n",
            &[],
        ),
        "times, not once",
    );
}

#[test]
fn the_secret_or_the_environment_in_another_workflow_is_found() {
    let other = "name: x\non:\n  pull_request:\njobs:\n  a:\n    environment: tuf-timestamp\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo ${{ secrets.TUF_TIMESTAMP_KEY }}\n";
    assert_found(mutated("", "", &[("evil.yml", other)]), "evil.yml names");
    // The `.yaml` extension is a workflow too, and a copy of pages.yml is another file.
    assert_found(mutated("", "", &[("evil.yaml", other)]), "evil.yaml names");
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
fn an_unpinned_action_a_later_step_or_a_write_permission_in_the_secret_job_is_found() {
    assert_found(
        mutated(
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5",
            "actions/checkout@v5",
            &[],
        ),
        "not pinned by commit",
    );
    assert_found(
        mutated(
            "    environment: tuf-timestamp\n    permissions:\n      contents: read\n",
            "    environment: tuf-timestamp\n    permissions:\n      contents: read\n      pages: write\n",
            &[],
        ),
        "permissions are not exactly",
    );
    assert_found(
        mutated(
            "          } >> \"$GITHUB_OUTPUT\"\n\n  dispatch:",
            "          } >> \"$GITHUB_OUTPUT\"\n      - uses: actions/upload-artifact@v5\n        with:\n          path: x\n\n  dispatch:",
            &[],
        ),
        "not the last",
    );
    assert_found(
        mutated(
            "          echo \"::add-mask::$TUF_TIMESTAMP_KEY\"\n",
            "",
            &[],
        ),
        "does not mask",
    );
    assert_found(
        mutated("    environment: tuf-timestamp\n", "", &[]),
        "environment",
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
    // A set of conditions the checker has to take apart correctly.
    let keep: BTreeSet<&str> = EVENTS.into_iter().collect();
    assert_eq!(keep.len(), 5);
    assert!(check_condition("github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push')").is_ok());
    assert!(check_condition("github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push') || (github.event_name == 'release')").is_err());
    assert!(check_condition("github.event_name == 'release' || github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push')").is_err());
}

#[test]
fn the_graph_of_jobs_is_pinned() {
    assert_found(
        mutated("    needs: timestamp\n", "", &[]),
        "build does not need the timestamp job",
    );
    assert_found(
        mutated("needs.timestamp.result != 'failure' && ", "", &[]),
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
    assert_found(
        mutated(
            "contains(fromJSON('[\"success\",\"skipped\"]'), needs.oracle.result)",
            "needs.oracle.result != 'failure'",
            &[],
        ),
        "the condition of deploy lacks",
    );
    assert_found(
        mutated("needs.build.result == 'success' && ", "", &[]),
        "the condition of deploy lacks",
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
