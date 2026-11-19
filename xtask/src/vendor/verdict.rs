//! The machine-readable outcome of the checks of a publisher's release pull request
//! (`docs/design/publishers.md`, «Проверки» 1–11 and «Проверки PR издателя» 12–25): each
//! check by its number, passed, failed (with why) or skipped (with why), and what the later
//! jobs need of each new package.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The format version of the JSON verdicts.
pub const SCHEMA: u32 = 1;

/// The number of a check, as `docs/design/publishers.md` names it (1–25; 10 is replaced by
/// 12–25 and has none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CheckId(pub u8);

impl fmt::Display for CheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What a check concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// It holds.
    Pass,
    /// It does not: the pull request is not merged.
    Fail,
    /// It was not run: an earlier check failed, or this run does not make it.
    Skip,
}

/// One check's outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    /// The check.
    pub id: CheckId,
    /// Its outcome.
    pub status: Status,
    /// Why it failed or was skipped (one line each); empty when it passed.
    pub messages: Vec<String>,
}

/// The outcomes of a run, by check: a failure is never overwritten by a pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checks {
    results: BTreeMap<CheckId, CheckResult>,
}

impl Checks {
    /// No outcome yet.
    pub fn new() -> Checks {
        Checks::default()
    }

    /// Check `id` holds (unless it failed already).
    pub fn pass(&mut self, id: u8) {
        self.results
            .entry(CheckId(id))
            .or_insert_with(|| CheckResult {
                id: CheckId(id),
                status: Status::Pass,
                messages: Vec::new(),
            });
    }

    /// Check `id` fails, for `why`.
    pub fn fail(&mut self, id: u8, why: impl Into<String>) {
        let entry = self
            .results
            .entry(CheckId(id))
            .or_insert_with(|| CheckResult {
                id: CheckId(id),
                status: Status::Fail,
                messages: Vec::new(),
            });
        if entry.status != Status::Fail {
            entry.status = Status::Fail;
            entry.messages.clear();
        }
        entry.messages.push(why.into());
    }

    /// Check `id` was not run, for `why` (unless it has an outcome already).
    pub fn skip(&mut self, id: u8, why: impl Into<String>) {
        self.results
            .entry(CheckId(id))
            .or_insert_with(|| CheckResult {
                id: CheckId(id),
                status: Status::Skip,
                messages: vec![why.into()],
            });
    }

    /// `result` of check `id`: `Ok` passes, each message of `Err` fails it.
    pub fn record(&mut self, id: u8, result: Result<(), Vec<String>>) {
        match result {
            Ok(()) => self.pass(id),
            Err(why) if why.is_empty() => self.fail(id, "failed"),
            Err(why) => why.into_iter().for_each(|w| self.fail(id, w)),
        }
    }

    /// Every check of `ids` without an outcome is skipped for `why`.
    pub fn skip_rest(&mut self, ids: impl IntoIterator<Item = u8>, why: &str) {
        for id in ids {
            self.skip(id, why);
        }
    }

    /// The outcome of check `id`.
    pub fn status(&self, id: u8) -> Option<Status> {
        self.results.get(&CheckId(id)).map(|r| r.status)
    }

    /// Whether check `id` failed.
    pub fn failed(&self, id: u8) -> bool {
        self.status(id) == Some(Status::Fail)
    }

    /// The checks that failed.
    pub fn failures(&self) -> Vec<CheckId> {
        self.results
            .values()
            .filter(|r| r.status == Status::Fail)
            .map(|r| r.id)
            .collect()
    }

    /// Whether no check failed and every one of `required` passed.
    pub fn all_pass(&self, required: impl IntoIterator<Item = u8>) -> bool {
        self.failures().is_empty()
            && required
                .into_iter()
                .all(|id| self.status(id) == Some(Status::Pass))
    }

    /// Adds the outcomes of `other`; a failure wins.
    pub fn merge(&mut self, other: &Checks) {
        for result in other.results.values() {
            match result.status {
                Status::Pass => self.pass(result.id.0),
                Status::Fail => result
                    .messages
                    .iter()
                    .for_each(|m| self.fail(result.id.0, m.clone())),
                Status::Skip => result
                    .messages
                    .iter()
                    .for_each(|m| self.skip(result.id.0, m.clone())),
            }
        }
    }

    /// The outcomes, by check.
    pub fn into_vec(self) -> Vec<CheckResult> {
        self.results.into_values().collect()
    }

    /// The outcomes, by check.
    pub fn to_vec(&self) -> Vec<CheckResult> {
        self.results.values().cloned().collect()
    }

    /// The outcomes read back from a verdict.
    pub fn from_results(results: &[CheckResult]) -> Checks {
        Checks {
            results: results.iter().map(|r| (r.id, r.clone())).collect(),
        }
    }
}

/// The checks `vendor check-pr` makes without the network: 1–9, 11, 12, 23, 24.
pub const STATIC_CHECKS: [u8; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 23, 24];

/// The checks of the downloaded source archives: 13–18.
pub const ARCHIVE_CHECKS: [u8; 6] = [13, 14, 15, 16, 17, 18];

/// The checks of the rebuild job: 19, 20.
pub const REBUILD_CHECKS: [u8; 2] = [19, 20];

/// The checks of the verdict job: 21, 22.
pub const VERDICT_CHECKS: [u8; 2] = [21, 22];

/// The check of the provenance job: 25.
pub const PROVENANCE_CHECK: u8 = 25;

/// A package the pull request adds, and where the mirror job puts it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewTarget {
    /// The target path, `plugins/<publisher>/<id>/<version>.onclp`.
    pub path: String,
    /// The plugin.
    pub id: String,
    /// Its version.
    pub version: String,
    /// The package's length, as signed.
    pub length: u64,
    /// The package's sha256, as signed (64 lowercase hex).
    pub sha256: String,
    /// The release of the copies, `pub-<publisher>-<sha256>`.
    pub tag: String,
    /// The package's file name in that release, `<id>-<version>.onclp`.
    pub package: String,
    /// The source archive's file name in that release, `<id>-<version>.src.tar.gz`.
    pub archive: String,
    /// `custom.oncl.source` as signed.
    pub source: Value,
    /// The newest earlier version of the same plugin in the role on the base, whose archive
    /// the `.src.diff` compares with: none for the first version.
    pub previous: Option<Previous>,
}

/// The version a new package's `.src.diff` starts from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Previous {
    /// Its version.
    pub version: String,
    /// The copy of its source archive in the project's Releases.
    pub archive_url: String,
    /// Its archive's sha256, as signed.
    pub archive_sha256: String,
}

/// The outcome of `vendor check-pr`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrVerdict {
    /// [`SCHEMA`].
    pub schema: u32,
    /// Whether every check run passed and none was skipped for a failure.
    pub ok: bool,
    /// The base commit (`main`).
    pub base: String,
    /// The head commit of the pull request.
    pub head: String,
    /// The publisher whose role file the pull request adds, once check 1 read it.
    pub publisher: Option<String>,
    /// The version of that file.
    pub role_version: Option<u64>,
    /// Every check, by number.
    pub checks: Vec<CheckResult>,
    /// The packages the pull request adds.
    pub new_targets: Vec<NewTarget>,
}

impl PrVerdict {
    /// The failed checks.
    pub fn failures(&self) -> Vec<CheckId> {
        Checks::from_results(&self.checks).failures()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_is_never_overwritten_and_skips_only_fill_gaps() {
        let mut checks = Checks::new();
        checks.fail(3, "jump");
        checks.pass(3);
        checks.skip(3, "later");
        checks.pass(4);
        checks.skip(4, "no");
        checks.skip(5, "not run");
        assert_eq!(checks.status(3), Some(Status::Fail));
        assert_eq!(checks.status(4), Some(Status::Pass));
        assert_eq!(checks.status(5), Some(Status::Skip));
        assert_eq!(checks.failures(), vec![CheckId(3)]);
        assert!(!checks.all_pass([4]));
        let json = serde_json::to_value(checks.to_vec()).unwrap();
        assert_eq!(json[0]["id"], 3);
        assert_eq!(json[0]["status"], "fail");
        assert_eq!(json[0]["messages"][0], "jump");
    }

    #[test]
    fn a_skip_is_no_pass_of_a_required_check() {
        let mut checks = Checks::new();
        checks.pass(1);
        checks.skip(2, "no author");
        assert!(checks.all_pass([1]));
        assert!(!checks.all_pass([1, 2]));
    }
}
