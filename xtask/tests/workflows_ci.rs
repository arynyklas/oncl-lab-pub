//! The shape of ci.yml that the repository's required status rests on (docs/dev/development.md,
//! «Что запускает CI»), checked on the file as it is and shown to catch what it claims to: the
//! negative tests below break a copy of `ci.yml` in each way a mistake would, and each must be
//! found.
//!
//! The rules:
//!
//! - `check` (the status the ruleset requires) runs `if: always()` and needs every other job
//!   of the file, so a job added later cannot fail without failing `check`;
//! - what `check` needs is a job of the file;
//! - `privacy` and `index` run on every run: no `if`, or one that names events only
//!   (`github.event_name == '…'` joined by `||`), never an output of `changes`.
//!
//! And in every workflow and composite action (`.github/workflows/*.yml`,
//! `.github/actions/*/action.yml`): each `apt-get` command carries the network timeouts and
//! retries of [`APT_OPTIONS`], and its step has a `timeout-minutes` of its own, so a stalled
//! mirror fails the step in minutes instead of holding the job to its limit.
//!
//! The file is read line by line in the block style it is written in: jobs are the keys
//! indented by two spaces under `jobs:`, their keys by four; steps are the items of a
//! `steps:` list.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// The jobs `check` does not need: itself.
const NOT_NEEDED: [&str; 1] = ["check"];
/// The jobs that must run on every run.
const ALWAYS: [&str; 2] = ["privacy", "index"];
/// What every `apt-get` command passes: 30 s network timeouts and 3 retries.
const APT_OPTIONS: [&str; 3] = [
    "-o Acquire::http::Timeout=30",
    "-o Acquire::https::Timeout=30",
    "-o Acquire::Retries=3",
];

/// One job: its id and the lines of its body (indentation kept).
struct Job {
    id: String,
    body: Vec<String>,
}

fn jobs(text: &str) -> Result<Vec<Job>, String> {
    let mut lines = text.lines().skip_while(|l| *l != "jobs:");
    if lines.next().is_none() {
        return Err("no `jobs:`".to_owned());
    }
    let mut jobs: Vec<Job> = Vec::new();
    for line in lines {
        if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('#') {
            break;
        }
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        if indent == 2 && !trimmed.starts_with('#') {
            let id = trimmed
                .strip_suffix(':')
                .filter(|id| !id.contains([' ', ':']))
                .ok_or_else(|| format!("not a job id: {line:?}"))?;
            jobs.push(Job {
                id: id.to_owned(),
                body: Vec::new(),
            });
        } else if let Some(job) = jobs.last_mut() {
            job.body.push(line.to_owned());
        }
    }
    Ok(jobs)
}

/// The value of the job key `key` (`    key: value`), if the job has it.
fn key<'a>(job: &'a Job, key: &str) -> Option<&'a str> {
    let prefix = format!("    {key}:");
    job.body
        .iter()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::trim)
}

/// The jobs a job needs: `needs: a`, `needs: [a, b]` or a block list.
fn needs(job: &Job) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(start) = job.body.iter().position(|l| l.starts_with("    needs:")) else {
        return out;
    };
    let inline = job.body[start]["    needs:".len()..].trim();
    if inline.is_empty() {
        for line in &job.body[start + 1..] {
            match line.strip_prefix("      - ") {
                Some(item) => {
                    out.insert(item.trim().to_owned());
                }
                None if line.trim().is_empty() || line.trim_start().starts_with('#') => {}
                None => break,
            }
        }
    } else {
        let inline = inline.trim_start_matches('[').trim_end_matches(']');
        out.extend(
            inline
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
        );
    }
    out
}

/// Whether `condition` names events only.
fn events_only(condition: &str) -> bool {
    condition.split("||").all(|clause| {
        clause
            .trim()
            .strip_prefix("github.event_name == '")
            .and_then(|rest| rest.strip_suffix('\''))
            .is_some_and(|event| event.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
    })
}

/// What is wrong with the text of ci.yml.
fn check_ci(text: &str) -> Vec<String> {
    let jobs = match jobs(text) {
        Ok(jobs) => jobs,
        Err(e) => return vec![e],
    };
    let mut bad = Vec::new();
    let ids: BTreeSet<&str> = jobs.iter().map(|j| j.id.as_str()).collect();
    let Some(check) = jobs.iter().find(|j| j.id == "check") else {
        return vec!["there is no job `check`".to_owned()];
    };
    if key(check, "if") != Some("always()") {
        bad.push("`check` does not run `if: always()`".to_owned());
    }
    let needed = needs(check);
    for id in &ids {
        if !NOT_NEEDED.contains(id) && !needed.contains(*id) {
            bad.push(format!("the job {id} is not needed by `check`"));
        }
    }
    for id in &needed {
        if !ids.contains(id.as_str()) {
            bad.push(format!("`check` needs {id}, which is not a job"));
        }
    }
    for id in ALWAYS {
        match jobs.iter().find(|j| j.id == id) {
            None => bad.push(format!("there is no job `{id}`")),
            Some(job) => {
                if let Some(condition) = key(job, "if")
                    && !events_only(condition)
                {
                    bad.push(format!(
                        "the job {id} has a condition beyond the event: {condition}"
                    ));
                }
            }
        }
    }
    bad
}

fn real_ci() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
    // A Windows checkout may have CRLF line ends: the mutations are written with LF.
    fs::read_to_string(&path).unwrap().replace("\r\n", "\n")
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// The steps of a workflow or a composite action: each item of every `steps:` list, with its
/// lines (indentation kept) and the indentation of its `- `.
fn steps(text: &str) -> Vec<(usize, Vec<&str>)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<(usize, Vec<&str>)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let opener = lines[i];
        i += 1;
        if opener.trim() != "steps:" {
            continue;
        }
        let mut item = None;
        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();
            let at = indent(line);
            // Blank lines, and comments outside a step's body, neither belong to a step nor
            // end the list.
            if trimmed.is_empty() || (trimmed.starts_with('#') && item.is_none_or(|s| at <= s)) {
                i += 1;
                continue;
            }
            let item_at = *item.get_or_insert(at);
            if at == item_at && trimmed.starts_with("- ") {
                out.push((at, vec![line]));
            } else if at > item_at
                && let Some(step) = out.last_mut()
            {
                step.1.push(line);
            } else {
                break;
            }
            i += 1;
        }
    }
    out
}

/// The number of steps of a workflow or composite action that run `apt-get`, and what is
/// wrong with them.
fn check_apt(file: &str, text: &str) -> (usize, Vec<String>) {
    let mut count = 0;
    let mut bad = Vec::new();
    for (at, lines) in steps(text) {
        // The commands, `\` continuations joined, comments left out.
        let mut commands = Vec::new();
        let mut current = String::new();
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            match trimmed.strip_suffix('\\') {
                Some(part) => {
                    current.push_str(part);
                    current.push(' ');
                }
                None => {
                    current.push_str(trimmed);
                    commands.push(std::mem::take(&mut current));
                }
            }
        }
        commands.push(current);
        let apt: Vec<&String> = commands.iter().filter(|c| c.contains("apt-get")).collect();
        if apt.is_empty() {
            continue;
        }
        count += 1;
        let step = lines
            .iter()
            .find_map(|l| l.trim().trim_start_matches("- ").strip_prefix("name:"))
            .map_or_else(|| lines[0].trim().to_owned(), |n| n.trim().to_owned());
        let has_timeout = lines.iter().any(|l| {
            indent(l) <= at + 2
                && l.trim()
                    .trim_start_matches("- ")
                    .starts_with("timeout-minutes:")
        });
        if !has_timeout {
            bad.push(format!(
                "{file}: the step {step:?} runs apt-get without its own timeout-minutes"
            ));
        }
        for command in apt {
            for option in APT_OPTIONS {
                if !command.contains(option) {
                    bad.push(format!(
                        "{file}: the step {step:?} runs apt-get without {option}: {command}"
                    ));
                }
            }
        }
    }
    (count, bad)
}

/// The workflows and composite actions, by their path under `.github/`.
fn github_files() -> Vec<(String, String)> {
    let github = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.github");
    let mut paths = Vec::new();
    for entry in fs::read_dir(github.join("workflows")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            paths.push(path);
        }
    }
    for entry in fs::read_dir(github.join("actions")).unwrap() {
        let dir = entry.unwrap().path();
        for name in ["action.yml", "action.yaml"] {
            if dir.join(name).is_file() {
                paths.push(dir.join(name));
            }
        }
    }
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let name = path.strip_prefix(&github).unwrap().display().to_string();
            (
                name,
                fs::read_to_string(&path).unwrap().replace("\r\n", "\n"),
            )
        })
        .collect()
}

#[test]
fn every_apt_step_fails_fast() {
    let mut count = 0;
    let mut bad = Vec::new();
    for (name, text) in github_files() {
        let (n, b) = check_apt(&name, &text);
        count += n;
        bad.extend(b);
    }
    assert!(bad.is_empty(), "{bad:#?}");
    // The check sees the steps it is about.
    assert!(count >= 1, "no step runs apt-get");
}

fn assert_apt_found(text: &str, needle: &str) {
    let (_, bad) = check_apt("ci.yml", text);
    assert!(
        bad.iter().any(|b| b.contains(needle)),
        "not caught ({needle:?}): {bad:#?}"
    );
}

#[test]
fn an_apt_step_without_its_timeout_is_found() {
    assert_apt_found(
        &mutated(
            "      - name: Install pcscd and vpcd\n        timeout-minutes: 10\n",
            "      - name: Install pcscd and vpcd\n",
        ),
        "\"Install pcscd and vpcd\" runs apt-get without its own timeout-minutes",
    );
}

#[test]
fn an_apt_command_without_the_options_is_found() {
    assert_apt_found(
        &mutated(" -o Acquire::Retries=3 update\n", " update\n"),
        "without -o Acquire::Retries=3",
    );
    // The options count per command, continuations included.
    assert_apt_found(
        &mutated(
            "if ! sudo apt-get -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3 \\\n",
            "if ! sudo apt-get \\\n",
        ),
        "\"Install pcscd and vpcd\" runs apt-get without -o Acquire::http::Timeout=30",
    );
}

#[test]
fn ci_keeps_the_rules_of_the_required_check() {
    let bad = check_ci(&real_ci());
    assert!(bad.is_empty(), "{bad:#?}");
}

/// The real ci.yml with `from` (which must be there) replaced by `to`.
fn mutated(from: &str, to: &str) -> String {
    let text = real_ci();
    assert!(text.contains(from), "the mutation target is gone: {from:?}");
    text.replacen(from, to, 1)
}

fn assert_found(text: &str, needle: &str) {
    let bad = check_ci(text);
    assert!(
        bad.iter().any(|b| b.contains(needle)),
        "not caught ({needle:?}): {bad:#?}"
    );
}

#[test]
fn a_new_job_missing_from_needs_is_found() {
    let text = mutated(
        "\n  fmt:\n",
        "\n  extra:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: \"true\"\n\n  fmt:\n",
    );
    assert_found(&text, "the job extra is not needed");
}

#[test]
fn a_job_dropped_from_needs_is_found() {
    assert_found(
        &mutated("      - linux-checks\n", ""),
        "the job linux-checks is not needed",
    );
}

#[test]
fn a_need_that_is_no_job_is_found() {
    assert_found(
        &mutated(
            "      - linux-checks\n",
            "      - linux-checks\n      - gone\n",
        ),
        "needs gone, which is not a job",
    );
}

#[test]
fn check_without_always_is_found() {
    assert_found(
        &mutated(
            "  check:\n    if: always()\n",
            "  check:\n    if: success()\n",
        ),
        "always()",
    );
}

#[test]
fn a_path_filter_on_privacy_or_index_is_found() {
    assert_found(
        &mutated(
            "  privacy:\n",
            "  privacy:\n    needs: changes\n    if: needs.changes.outputs.rust == 'true'\n",
        ),
        "the job privacy has a condition",
    );
    assert_found(
        &mutated(
            "  index:\n",
            "  index:\n    if: github.event_name == 'push' && needs.changes.outputs.site == 'true'\n",
        ),
        "the job index has a condition",
    );
    // An event-only condition is allowed.
    let events = mutated(
        "  index:\n",
        "  index:\n    if: github.event_name == 'push' || github.event_name == 'pull_request'\n",
    );
    assert!(check_ci(&events).is_empty(), "{:#?}", check_ci(&events));
}
