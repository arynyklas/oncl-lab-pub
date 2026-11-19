//! Check 25 (`docs/design/publishers.md`, «Проверки PR издателя»): the git revision a
//! publisher names in `source.vcs`, fetched alone into a bare repository and made into the
//! canonical archive by the same code as `oncl-pack source`. The same bytes as the signed
//! archive: confirmed; the host or the revision unreachable: unverified, which does not stop
//! the pull request; other bytes: the pull request is refused.
//!
//! git runs only inside a container of the builder image ([`Sandbox`],
//! [`super::docker::git_fetch`]): unprivileged, read-only, redirects off, `https` only, on a
//! container network that reaches the internet and nothing of the runner (its addresses,
//! private ranges, link-local metadata endpoints). Making that network is the workflow's
//! (`docs/dev/publishers.md`, «Проверки CI»); the host policy ([`host_policy`]) is checked
//! first, here. The bare repository is copied out with `docker cp` and read as data.

use std::path::Path;
use std::time::Duration;

use oncl_pack::source::Tree;
use serde::{Deserialize, Serialize};

use super::docker::{self, Engine};
use super::fetch::host_policy;

/// What check 25 found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "result", content = "detail")]
pub enum Provenance {
    /// The revision gives the signed archive byte for byte.
    Confirmed,
    /// The revision could not be had (the host, the network, the revision): why.
    Unverified(String),
    /// The revision gives another archive: the sha256 it gives.
    Mismatch(String),
}

impl Provenance {
    /// The word of `BUILDINFO.json` and the site: `confirmed`, `unverified`, `mismatch`.
    pub fn word(&self) -> &'static str {
        match self {
            Provenance::Confirmed => "confirmed",
            Provenance::Unverified(_) => "unverified",
            Provenance::Mismatch(_) => "mismatch",
        }
    }
}

/// Compares the archive `tree` of the fetched revision gives with the signed `archive`.
pub fn compare(tree: &Tree, archive: &[u8]) -> Provenance {
    match tree.to_archive() {
        Ok(bytes) if bytes == archive => Provenance::Confirmed,
        Ok(bytes) => Provenance::Mismatch(oncl_pack::sha256_hex(&bytes)),
        Err(e) => Provenance::Mismatch(format!("the revision makes no archive: {e}")),
    }
}

/// Where git runs for check 25.
#[derive(Clone, Debug)]
pub struct Sandbox<'a> {
    /// Docker or Podman.
    pub engine: &'a Engine,
    /// The builder image, by digest (it has git).
    pub image: &'a str,
    /// The container network: outbound internet only, nothing of the runner.
    pub network: &'a str,
}

/// Check 25: `rev` of `url` against the signed `archive`, fetched in `sandbox`, the bare
/// repository copied into a new directory under `work`.
pub fn check(
    sandbox: &Sandbox,
    url: &str,
    rev: &str,
    archive: &[u8],
    work: &Path,
    timeout: Duration,
) -> Provenance {
    if let Err(e) = host_policy(url) {
        return Provenance::Unverified(e);
    }
    let dir = work.join("vcs.git");
    if let Err(e) = docker::git_fetch(
        sandbox.engine,
        sandbox.image,
        sandbox.network,
        url,
        rev,
        &dir,
        timeout,
    ) {
        return Provenance::Unverified(format!("{e:#}"));
    }
    match Tree::from_git(&dir, rev) {
        Ok(tree) => compare(&tree, archive),
        Err(e) => Provenance::Unverified(format!("reading {rev}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use oncl_pack::source::File;

    use super::*;

    #[test]
    fn the_same_files_confirm_and_other_files_refuse() {
        let mut tree = Tree::new();
        tree.insert(
            "Cargo.toml",
            File {
                executable: false,
                data: b"[package]\n".to_vec(),
            },
        )
        .unwrap();
        let archive = tree.to_archive().unwrap();
        assert_eq!(compare(&tree, &archive), Provenance::Confirmed);
        let mut other = tree.clone();
        other
            .insert(
                "build.rs",
                File {
                    executable: false,
                    data: b"fn main() {}\n".to_vec(),
                },
            )
            .unwrap();
        assert_eq!(compare(&other, &archive).word(), "mismatch");
    }

    #[test]
    fn a_host_the_policy_refuses_is_unverified_without_a_container() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine("no-such-engine".to_owned());
        let sandbox = Sandbox {
            engine: &engine,
            image: "img",
            network: "net",
        };
        let found = check(
            &sandbox,
            "https://127.0.0.1/repo.git",
            &"a".repeat(40),
            b"",
            dir.path(),
            Duration::from_secs(5),
        );
        assert!(
            matches!(&found, Provenance::Unverified(why) if why.contains("IP address")),
            "{found:?}"
        );
    }
}
