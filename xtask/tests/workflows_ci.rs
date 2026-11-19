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
//! The file is read line by line in the block style it is written in: jobs are the keys
//! indented by two spaces under `jobs:`, their keys by four.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// The jobs `check` does not need: itself.
const NOT_NEEDED: [&str; 1] = ["check"];
/// The jobs that must run on every run.
const ALWAYS: [&str; 2] = ["privacy", "index"];

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
