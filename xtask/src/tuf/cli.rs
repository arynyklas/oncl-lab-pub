//! The command line of `cargo xtask tuf` (`docs/dev/release.md` says when each is run).
//!
//! Two repositories (`docs/design/publishers.md`): `tuf/v1`, the default of every command,
//! and `tuf/v2`, chosen with `--repo v2`. `tuf update` and `tuf check` work on both by
//! default (`--repo both`): `--out`/`--dir` name `tuf/v1`, `--v2-out`/`--v2-dir` name
//! `tuf/v2`, by default the directory `v2` beside the one of `tuf/v1`; a `tuf/v2` that is not
//! there yet is skipped.
//!
//! Exit codes: 0 when the command did what it says (`tuf check` also when it found only
//! warnings, or no repository yet); 1 when it refused, failed, or `tuf check` found
//! problems; 2 for a command line that does not parse.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::Subcommand;
use oncl_update::tuf::HttpFetcher;
use time::OffsetDateTime;

use super::check::{self, Expiry, TimestampMode};
use super::check_v2::{self, Stage};
use super::published::{self, Published};
use super::repo::Layout;
use super::timestamp::KeySource;
use super::{
    ANCHOR, PassphraseSource, Problem, REPO_DIR, V2_ANCHOR, V2_REPO_DIR, init, parse_time, root,
    show_time, snapshot, timestamp, update,
};
use crate::publishers::PUBLISHERS_DIR;

/// Which repositories a command works on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Repos {
    /// `tuf/v1` only.
    V1,
    /// `tuf/v2` only.
    V2,
    /// `tuf/v1`, and `tuf/v2` if it is there.
    Both,
}

/// `cargo xtask tuf …`: the operator's side of the TUF repositories of the update indexes.
#[derive(Subcommand)]
pub enum TufCommand {
    /// The owner's ceremony: make the root, targets, snapshot and timestamp keys, root
    /// version 1 in the repository, and a copy of it as the client's trust anchor. The
    /// root, targets and snapshot keys are written encrypted with one passphrase (asked
    /// twice, at least 12 characters; one passphrase for the three is the owner's choice);
    /// the timestamp key is one unencrypted line, for the GitHub secret
    /// `TUF_TIMESTAMP_KEY`. Nothing existing is overwritten. With `--repo v2`: the ceremony
    /// of `tuf/v2`, a new root key (encrypted), online snapshot and timestamp keys
    /// (`v2-snapshot.key`, `v2-timestamp.key`: one line each, for the GitHub secrets
    /// `TUF_V2_SNAPSHOT_KEY` and `TUF_V2_TIMESTAMP_KEY`) and the targets key of `tuf/v1`;
    /// a trust anchor is written only with `--anchor`.
    Init {
        /// The directory of the secret keys: outside the repository, or git-ignored.
        #[arg(long)]
        keys: PathBuf,
        /// The repository directory [default: `tuf/v1` (`tuf/v2` with `--repo v2`) of the
        /// workspace].
        #[arg(long)]
        out: Option<PathBuf>,
        /// The trust anchor file [default: `crates/oncl-update/keys/root.json`; none with
        /// `--repo v2`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Read the passphrase from the first line of this file instead of asking
        /// (automation and tests).
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// The repository.
        #[arg(long, value_enum, default_value_t = Layout::V1)]
        repo: Layout,
        /// With `--repo v2`: `tuf/v1`, whose targets key `tuf/v2` shares [default: `v1`
        /// beside the repository directory].
        #[arg(long)]
        v1: Option<PathBuf>,
    },
    /// Sign new targets and snapshot over `updates/v1/{stable,beta}.json` (those that
    /// exist): copies the indexes under their hashes and writes `metadata/<N+1>.targets.json`
    /// and `<N+1>.snapshot.json`, valid for 30 days. With nothing changed it says "up to
    /// date" and writes nothing; `--refresh` signs new versions anyway, to push the expiry
    /// forward. Never touches the timestamp. In `tuf/v2` (if it is there) it signs new
    /// top-level targets over the same indexes and `publishers.json`, delegating to the
    /// active publishers of `publishers/`, and no snapshot (CI signs that one).
    Update {
        /// The directory of the secret keys.
        #[arg(long)]
        keys: PathBuf,
        /// The directory of the indexes [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The directory of `tuf/v1` [default: `tuf/v1` of the workspace].
        #[arg(long)]
        out: Option<PathBuf>,
        /// The directory of `tuf/v2` [default: `v2` beside `tuf/v1`].
        #[arg(long)]
        v2_out: Option<PathBuf>,
        /// The registry of the publishers [default: `publishers` of the workspace].
        #[arg(long)]
        publishers: Option<PathBuf>,
        /// The repositories.
        #[arg(long, value_enum, default_value_t = Repos::Both)]
        repo: Repos,
        /// Sign new versions even if the indexes did not change (the monthly job).
        #[arg(long)]
        refresh: bool,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Sign the snapshot of a copy of `tuf/v2` for publication, with the online key
    /// (version: Unix seconds, or one more than the published one; valid for 7 days). The
    /// copy is verified first, every delegated role's newest file included; the published
    /// snapshot (`--previous`, required unless `--first-publication`) is verified, kept
    /// beside the new one, and the new one may drop or lower nothing it listed. Run by Pages:
    /// the file is never committed. The key is never printed.
    Snapshot {
        /// The repository directory (a copy of `tuf/v2` for publication).
        #[arg(long)]
        out: PathBuf,
        /// The trust anchor of `tuf/v2` [default: `tuf/v2/metadata/1.root.json` of the
        /// workspace].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The indexes the targets must be [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The registry of the publishers [default: `publishers` of the workspace].
        #[arg(long)]
        publishers: Option<PathBuf>,
        /// The published `tuf/v2`, `https://…/tuf/v2/`, whose snapshot the new one extends;
        /// its timestamp must be there.
        #[arg(long, required_unless_present = "first_publication")]
        previous: Option<String>,
        /// The first publication of `tuf/v2`: there is no published snapshot to extend.
        #[arg(long, conflicts_with = "previous")]
        first_publication: bool,
        /// The environment variable that holds the key line [default: TUF_V2_SNAPSHOT_KEY].
        #[arg(long, conflicts_with = "key_file")]
        key_env: Option<String>,
        /// A key file instead of the environment.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
    },
    /// Sign `metadata/timestamp.json` for the newest committed snapshot in `--out`, with the
    /// online key (version: Unix seconds, valid for 7 days). Verifies the repository first
    /// and refuses a snapshot, targets or root that has expired or expires within a day. Run
    /// by Pages on the copy that is published: the file is never committed. The key is
    /// never printed. With `--repo v2`: over the snapshot `tuf snapshot` signed.
    Timestamp {
        /// The repository directory (a copy for publication).
        #[arg(long)]
        out: PathBuf,
        /// The trust anchor the repository is verified from [default:
        /// `crates/oncl-update/keys/root.json`; `tuf/v2/metadata/1.root.json` with `--repo
        /// v2`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The indexes the targets must be [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// With `--repo v2`: the registry of the publishers [default: `publishers` of the
        /// workspace].
        #[arg(long)]
        publishers: Option<PathBuf>,
        /// The environment variable that holds the key line [default: TUF_TIMESTAMP_KEY;
        /// TUF_V2_TIMESTAMP_KEY with `--repo v2`].
        #[arg(long, conflicts_with = "key_file")]
        key_env: Option<String>,
        /// A key file instead of the environment.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// The repository.
        #[arg(long, value_enum, default_value_t = Layout::V1)]
        repo: Layout,
    },
    /// The next root (version N+1, valid for 365 days), signed by the keys of the root in
    /// force: a renewal when no `--rotate-*` is given, else a rotation of those roles'
    /// keys (the new root key signs too). New keys are written next to the old as
    /// `<role>.v<N>.key` (`v2-<role>.v<N>.key` in `tuf/v2`). In `tuf/v2` the snapshot key
    /// is an online key too, and the targets keys are always those of `tuf/v1`'s root in
    /// force: the shared targets key is rotated in `tuf/v1`, then `tuf/v2` follows.
    Root {
        /// The directory of the secret keys.
        #[arg(long)]
        keys: PathBuf,
        /// The repository directory [default: `tuf/v1` (`tuf/v2` with `--repo v2`) of the
        /// workspace].
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace the root key.
        #[arg(long)]
        rotate_root: bool,
        /// Replace the targets key (then `tuf update` signs new versions); `tuf/v1` only.
        #[arg(long)]
        rotate_targets: bool,
        /// Replace the snapshot key (then `tuf update` signs new versions; in `tuf/v2`,
        /// replace the GitHub secret).
        #[arg(long)]
        rotate_snapshot: bool,
        /// Replace the timestamp key (then replace the GitHub secret).
        #[arg(long)]
        rotate_timestamp: bool,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// The repository.
        #[arg(long, value_enum, default_value_t = Layout::V1)]
        repo: Layout,
        /// With `--repo v2`: `tuf/v1`, whose targets key `tuf/v2` shares [default: `v1`
        /// beside the repository directory].
        #[arg(long)]
        v1: Option<PathBuf>,
    },
    /// Verify a repository offline with the client's code over the directory: the chain of
    /// roots from the trust anchor, the newest snapshot and targets, every file listed, no
    /// stray file, the targets equal to the indexes in the tree, history unchanged against
    /// `--base`, expiry. With neither the directory nor the anchor it says "no TUF
    /// repository yet" and succeeds. In `tuf/v2` also the delegations and `publishers.json`
    /// against `publishers/`, the newest file of every role, every version of every role, and
    /// with a snapshot the guard of the online snapshot; the two repositories share no key
    /// but the targets key and list the same indexes. Findings are `error[<code>]` (exit 1)
    /// and `warning[<code>]`; the codes are in `docs/dev/release.md`.
    Check {
        /// The directory of `tuf/v1` [default: `tuf/v1` of the workspace].
        #[arg(long)]
        dir: Option<PathBuf>,
        /// The directory of `tuf/v2` [default: `v2` beside `tuf/v1`].
        #[arg(long)]
        v2_dir: Option<PathBuf>,
        /// The directory of the indexes [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The registry of the publishers [default: `publishers` of the workspace].
        #[arg(long)]
        publishers: Option<PathBuf>,
        /// The trust anchor of `tuf/v1` [default: `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The trust anchor of `tuf/v2` [default: its own `metadata/1.root.json`].
        #[arg(long)]
        v2_anchor: Option<PathBuf>,
        /// The repositories.
        #[arg(long, value_enum, default_value_t = Repos::Both)]
        repo: Repos,
        /// The time to judge expiry at, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Targets and snapshot with fewer days left are expiring.
        #[arg(long, default_value_t = 10)]
        min_days: i64,
        /// The root with fewer days left is expiring.
        #[arg(long, default_value_t = 45)]
        min_root_days: i64,
        /// Expired and expiring metadata is an error, not a warning.
        #[arg(long)]
        fail_on_expiring: bool,
        /// The git revision whose repository this one extends: published files may not
        /// change or go, no version may go back.
        #[arg(long)]
        base: Option<String>,
        /// The directory is the committed tree: there must be no timestamp (the default
        /// requires one, as in a repository about to be published), and in `tuf/v2` no
        /// snapshot.
        #[arg(long)]
        no_timestamp: bool,
    },
    /// The client over HTTPS against the published site (the smoke check after a
    /// deployment): the whole chain, and every index target. With `--repo v2` also
    /// `publishers.json` and every delegated role.
    VerifyPublished {
        /// The base URL of the repository, `https://…/tuf/v1/` (`…/tuf/v2/`).
        #[arg(long)]
        url: String,
        /// The trust anchor [default: `crates/oncl-update/keys/root.json`;
        /// `tuf/v2/metadata/1.root.json` with `--repo v2`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// A repository that is not published yet (no timestamp) is not a failure.
        #[arg(long)]
        allow_missing: bool,
        /// The time to judge expiry at [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// The repository.
        #[arg(long, value_enum, default_value_t = Layout::V1)]
        repo: Layout,
    },
}

/// On Windows the key files are written with the permissions of their folder.
fn windows_key_warning(command: &str) {
    if cfg!(windows) {
        println!(
            "{command}: warning: on Windows the key files get the permissions of their \
             folder (no owner-only mode is set): keep the key directory where only you can \
             read it, on an encrypted volume"
        );
    }
}

fn workspace(path: Option<PathBuf>, default: &str) -> PathBuf {
    path.unwrap_or_else(|| oncl_testkit::workspace_root().join(default))
}

/// The directory `name` beside `dir` (`tuf/v2` beside `tuf/v1`).
fn sibling(dir: &Path, name: &str) -> PathBuf {
    dir.parent()
        .map_or_else(|| PathBuf::from(name), |parent| parent.join(name))
}

fn passphrase(file: Option<PathBuf>) -> PassphraseSource {
    file.map_or(PassphraseSource::Prompt, PassphraseSource::File)
}

fn now_or(now: Option<OffsetDateTime>) -> OffsetDateTime {
    now.unwrap_or_else(OffsetDateTime::now_utc)
}

fn print_init(made: &init::Initialized) {
    println!("tuf init: key ids");
    for (name, id) in &made.key_ids {
        println!("  {name}: {id}");
    }
    println!("tuf init: secret keys (keep them offline, never in the repository)");
    for file in &made.key_files {
        println!("  {}", file.display());
    }
    windows_key_warning("tuf init");
    println!("tuf init: wrote {}", made.root.display());
}

fn print_v2_update(outcome: &update::V2Outcome) {
    match outcome {
        update::V2Outcome::UpToDate { targets } => println!(
            "tuf update: tuf/v2: up to date (targets {targets} lists the indexes and the \
             publishers); nothing written"
        ),
        update::V2Outcome::Written(w) => {
            println!("tuf update: tuf/v2: {}", w.reason);
            for file in &w.files {
                println!("tuf update: wrote {}", file.display());
            }
            println!(
                "tuf update: tuf/v2: targets {} delegating to {} publisher(s), valid until {}; \
                 CI signs its snapshot when Pages is published",
                w.targets,
                w.delegated,
                show_time(w.expires)
            );
        }
    }
}

fn print_v1_update(outcome: &update::Outcome) {
    match outcome {
        update::Outcome::UpToDate { targets, snapshot } => println!(
            "tuf update: up to date (targets {targets}, snapshot {snapshot} list the \
             indexes); nothing written"
        ),
        update::Outcome::Written(w) => {
            println!("tuf update: {}", w.reason);
            for file in &w.files {
                println!("tuf update: wrote {}", file.display());
            }
            println!(
                "tuf update: targets {}, snapshot {}, valid until {}",
                w.targets,
                w.snapshot,
                show_time(w.expires)
            );
        }
    }
}

/// Prints the findings of one repository (`label` before each message, empty for
/// `tuf/v1`), and counts its problems.
fn print_report(
    label: &str,
    notes: &[String],
    warnings: &[Problem],
    problems: &[Problem],
) -> usize {
    for note in notes {
        println!("tuf check: {label}{note}");
    }
    for w in warnings {
        println!("tuf check: warning[{}]: {label}{}", w.code, w.message);
    }
    for p in problems {
        eprintln!("tuf check: error[{}]: {label}{}", p.code, p.message);
    }
    problems.len()
}

fn key_source(key_file: Option<PathBuf>, key_env: Option<String>, default: &str) -> KeySource {
    key_file.map_or_else(
        || KeySource::Env(key_env.unwrap_or_else(|| default.to_owned())),
        KeySource::File,
    )
}

/// Runs `command`.
///
/// # Errors
///
/// Whatever the command refuses or fails with; for `check`, any problem found.
pub fn run(command: TufCommand) -> anyhow::Result<()> {
    match command {
        TufCommand::Init {
            keys,
            out,
            anchor,
            now,
            passphrase_file: file,
            repo: Layout::V1,
            v1,
        } => {
            if v1.is_some() {
                bail!("--v1 is for --repo v2");
            }
            let out = workspace(out, REPO_DIR);
            let anchor = workspace(anchor, ANCHOR);
            let source = passphrase(file);
            let made = init::init(&init::Options {
                keys: &keys,
                out: &out,
                anchor: &anchor,
                now: now_or(now),
                passphrase: &source,
            })?;
            print_init(&made);
            println!("tuf init: wrote the trust anchor {}", made.anchor.display());
            println!(
                "tuf init: the timestamp key is the single line of timestamp.key: put it in the \
                 GitHub secret TUF_TIMESTAMP_KEY of the environment tuf-timestamp, then keep \
                 no other copy"
            );
            Ok(())
        }
        TufCommand::Init {
            keys,
            out,
            anchor,
            now,
            passphrase_file: file,
            repo: Layout::V2,
            v1,
        } => {
            let out = workspace(out, V2_REPO_DIR);
            let v1 = v1.unwrap_or_else(|| sibling(&out, "v1"));
            let source = passphrase(file);
            let made = init::init_v2(&init::V2Options {
                keys: &keys,
                out: &out,
                v1: &v1,
                anchor: anchor.as_deref(),
                now: now_or(now),
                passphrase: &source,
            })?;
            print_init(&made);
            if anchor.is_some() {
                println!("tuf init: wrote the trust anchor {}", made.anchor.display());
            }
            println!(
                "tuf init: the snapshot and timestamp keys of tuf/v2 are the single lines of \
                 v2-snapshot.key and v2-timestamp.key: put them in the GitHub secrets \
                 TUF_V2_SNAPSHOT_KEY of the environment tuf-snapshot and TUF_V2_TIMESTAMP_KEY \
                 of the environment tuf-timestamp, then keep no other copy; then `cargo xtask \
                 tuf update` signs the first targets of tuf/v2"
            );
            Ok(())
        }
        TufCommand::Update {
            keys,
            index,
            out,
            v2_out,
            publishers,
            repo,
            refresh,
            now,
            passphrase_file: file,
        } => {
            let source = passphrase(file);
            let index = workspace(index, crate::index::INDEX_DIR);
            let v1 = workspace(out, REPO_DIR);
            let v2 = v2_out.unwrap_or_else(|| sibling(&v1, "v2"));
            let publishers = workspace(publishers, PUBLISHERS_DIR);
            let now = now_or(now);
            match repo {
                Repos::V1 => print_v1_update(&update::update(&update::Options {
                    keys: &keys,
                    index: &index,
                    out: &v1,
                    refresh,
                    now,
                    passphrase: &source,
                })?),
                Repos::V2 => print_v2_update(&update::update_v2(&update::V2Options {
                    keys: &keys,
                    index: &index,
                    out: &v2,
                    v1: Some(&v1),
                    publishers: &publishers,
                    refresh,
                    now,
                    passphrase: &source,
                })?),
                Repos::Both => {
                    let both = update::update_both(&update::BothOptions {
                        keys: &keys,
                        index: &index,
                        v1: &v1,
                        v2: &v2,
                        publishers: &publishers,
                        refresh,
                        now,
                        passphrase: &source,
                    })?;
                    print_v1_update(&both.v1);
                    match &both.v2 {
                        Some(outcome) => print_v2_update(outcome),
                        None => println!(
                            "tuf update: no tuf/v2 in {} yet: only tuf/v1 was updated",
                            v2.display()
                        ),
                    }
                }
            }
            Ok(())
        }
        TufCommand::Snapshot {
            out,
            anchor,
            index,
            publishers,
            previous,
            first_publication: _,
            key_env,
            key_file,
            now,
        } => {
            let source = key_source(key_file, key_env, "TUF_V2_SNAPSHOT_KEY");
            let options = snapshot::Options {
                out: &out,
                anchor: &workspace(anchor, V2_ANCHOR),
                index: &workspace(index, crate::index::INDEX_DIR),
                publishers: &workspace(publishers, PUBLISHERS_DIR),
                key: &source,
                now: now_or(now),
            };
            let transport = oncl_pki::http::UreqTransport::default();
            let signed = match &previous {
                Some(url) => {
                    let fetcher = HttpFetcher::new(&transport, url)
                        .map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
                    snapshot::snapshot(&options, snapshot::Previous::Published(&fetcher))?
                }
                // clap allows no `--previous` only with `--first-publication`.
                None => snapshot::snapshot(&options, snapshot::Previous::FirstPublication)?,
            };
            if let Some((version, path)) = &signed.previous {
                println!(
                    "tuf snapshot: kept the published snapshot {version} beside it: {}",
                    path.display()
                );
            }
            println!(
                "tuf snapshot: wrote {} (version {}, targets {}, {} role file(s), valid until \
                 {})",
                signed.path.display(),
                signed.version,
                signed.targets,
                signed.roles,
                show_time(signed.expires)
            );
            Ok(())
        }
        TufCommand::Timestamp {
            out,
            anchor,
            index,
            publishers,
            key_env,
            key_file,
            now,
            repo,
        } => {
            let index = workspace(index, crate::index::INDEX_DIR);
            let signed = match repo {
                Layout::V1 => {
                    if publishers.is_some() {
                        bail!("--publishers is for --repo v2");
                    }
                    timestamp::timestamp(&timestamp::Options {
                        out: &out,
                        anchor: &workspace(anchor, ANCHOR),
                        index: &index,
                        key: &key_source(key_file, key_env, "TUF_TIMESTAMP_KEY"),
                        now: now_or(now),
                    })?
                }
                Layout::V2 => timestamp::timestamp_v2(&timestamp::V2Options {
                    out: &out,
                    anchor: &workspace(anchor, V2_ANCHOR),
                    index: &index,
                    publishers: &workspace(publishers, PUBLISHERS_DIR),
                    key: &key_source(key_file, key_env, "TUF_V2_TIMESTAMP_KEY"),
                    now: now_or(now),
                })?,
            };
            println!(
                "tuf timestamp: wrote {} (version {}, snapshot {}, valid until {})",
                signed.path.display(),
                signed.version,
                signed.snapshot,
                show_time(signed.expires)
            );
            Ok(())
        }
        TufCommand::Root {
            keys,
            out,
            rotate_root,
            rotate_targets,
            rotate_snapshot,
            rotate_timestamp,
            now,
            passphrase_file: file,
            repo,
            v1,
        } => {
            let source = passphrase(file);
            let made = match repo {
                Layout::V1 => {
                    if v1.is_some() {
                        bail!("--v1 is for --repo v2");
                    }
                    root::root(&root::Options {
                        keys: &keys,
                        out: &workspace(out, REPO_DIR),
                        rotate_root,
                        rotate_targets,
                        rotate_snapshot,
                        rotate_timestamp,
                        now: now_or(now),
                        passphrase: &source,
                    })?
                }
                Layout::V2 => {
                    if rotate_targets {
                        bail!(
                            "tuf/v2 shares the targets key of tuf/v1: rotate it there (`cargo \
                             xtask tuf root --rotate-targets`), then `cargo xtask tuf root \
                             --repo v2` follows it"
                        );
                    }
                    let out = workspace(out, V2_REPO_DIR);
                    let v1 = v1.unwrap_or_else(|| sibling(&out, "v1"));
                    root::root_v2(&root::V2Options {
                        keys: &keys,
                        out: &out,
                        v1: &v1,
                        rotate_root,
                        rotate_snapshot,
                        rotate_timestamp,
                        now: now_or(now),
                        passphrase: &source,
                    })?
                }
            };
            println!(
                "tuf root: wrote {} (root {}, valid until {})",
                made.root.display(),
                made.version,
                show_time(made.expires)
            );
            for (role, id, path) in &made.new_keys {
                println!("tuf root: new {role} key {id}: {}", path.display());
            }
            if !made.new_keys.is_empty() {
                windows_key_warning("tuf root");
            }
            match repo {
                Layout::V1 => {
                    if rotate_targets || rotate_snapshot {
                        println!(
                            "tuf root: the committed targets and snapshot are signed by the old \
                             keys: run `cargo xtask tuf update` now"
                        );
                    }
                    if rotate_timestamp {
                        println!(
                            "tuf root: put the new timestamp key in the GitHub secret \
                             TUF_TIMESTAMP_KEY (`gh secret set --env tuf-timestamp \
                             TUF_TIMESTAMP_KEY < <file>`) before the root is merged"
                        );
                    }
                    if rotate_targets {
                        println!(
                            "tuf root: tuf/v2 shares the targets key: run `cargo xtask tuf root \
                             --repo v2` too, if it is there"
                        );
                    }
                }
                Layout::V2 => {
                    if made.targets_changed {
                        println!(
                            "tuf root: the targets key of tuf/v2 now follows tuf/v1: run `cargo \
                             xtask tuf update` now"
                        );
                    }
                    if rotate_snapshot {
                        println!(
                            "tuf root: put the new snapshot key in the GitHub secret \
                             TUF_V2_SNAPSHOT_KEY (`gh secret set --env tuf-snapshot \
                             TUF_V2_SNAPSHOT_KEY < <file>`) before the root is merged"
                        );
                    }
                    if rotate_timestamp {
                        println!(
                            "tuf root: put the new timestamp key in the GitHub secret \
                             TUF_V2_TIMESTAMP_KEY (`gh secret set --env tuf-timestamp \
                             TUF_V2_TIMESTAMP_KEY < <file>`) before the root is merged"
                        );
                    }
                }
            }
            Ok(())
        }
        TufCommand::Check {
            dir,
            v2_dir,
            index,
            publishers,
            anchor,
            v2_anchor,
            repo,
            now,
            min_days,
            min_root_days,
            fail_on_expiring,
            base,
            no_timestamp,
        } => {
            let dir = workspace(dir, REPO_DIR);
            let v2_dir = v2_dir.unwrap_or_else(|| sibling(&dir, "v2"));
            let index = workspace(index, crate::index::INDEX_DIR);
            let publishers = workspace(publishers, PUBLISHERS_DIR);
            let anchor = workspace(anchor, ANCHOR);
            let now = now_or(now);
            let expiry = Expiry {
                min_days,
                min_root_days,
                fail: fail_on_expiring,
            };
            let mut failed = 0;
            let mut checked = false;
            let mut v1_verified = None;
            if matches!(repo, Repos::V1 | Repos::Both) {
                let outcome = check::check(&check::Options {
                    dir: &dir,
                    index: Some(&index),
                    anchor: Some(&anchor),
                    now,
                    timestamp: if no_timestamp {
                        TimestampMode::Absent
                    } else {
                        TimestampMode::Required
                    },
                    expiry,
                    base: base.as_deref(),
                })?;
                match outcome {
                    check::Outcome::NoRepository => println!(
                        "tuf check: no TUF repository yet (no {}, no trust anchor {})",
                        dir.display(),
                        anchor.display()
                    ),
                    check::Outcome::Checked(report) => {
                        checked = true;
                        failed +=
                            print_report("", &report.notes, &report.warnings, &report.problems);
                        v1_verified = report.verified;
                    }
                }
            }
            if matches!(repo, Repos::V2 | Repos::Both) {
                let outcome = check_v2::check(&check_v2::Options {
                    dir: &v2_dir,
                    index: Some(&index),
                    publishers: Some(&publishers),
                    anchor: v2_anchor.as_deref(),
                    now,
                    stage: if no_timestamp {
                        Stage::Tree
                    } else {
                        Stage::Published
                    },
                    expiry,
                    base: base.as_deref(),
                })?;
                match outcome {
                    check_v2::Outcome::NoRepository => println!(
                        "tuf check: tuf/v2: no repository yet (no {})",
                        v2_dir.display()
                    ),
                    check_v2::Outcome::Checked(report) => {
                        checked = true;
                        let label = "tuf/v2: ";
                        failed +=
                            print_report(label, &report.notes, &report.warnings, &report.problems);
                        if let (Some(v1), Some(v2)) = (&v1_verified, &report.verified) {
                            let (problems, warnings) = match check::committed_chain(&dir) {
                                Ok(v1_roots) => check_v2::cross(v1, &v1_roots, v2),
                                Err(e) => {
                                    (vec![Problem::new("client", format!("{e:#}"))], Vec::new())
                                }
                            };
                            failed +=
                                print_report("tuf/v1 and tuf/v2: ", &[], &warnings, &problems);
                        }
                    }
                }
            }
            if failed > 0 {
                bail!("tuf check: failed with {failed} problem(s)");
            }
            if checked {
                println!("tuf check: ok");
            }
            Ok(())
        }
        TufCommand::VerifyPublished {
            url,
            anchor,
            allow_missing,
            now,
            repo,
        } => {
            let anchor = workspace(
                anchor,
                match repo {
                    Layout::V1 => ANCHOR,
                    Layout::V2 => V2_ANCHOR,
                },
            );
            let anchor = std::fs::read(&anchor)
                .with_context(|| format!("reading the trust anchor {}", anchor.display()))?;
            let transport = oncl_pki::http::UreqTransport::default();
            let fetcher =
                HttpFetcher::new(&transport, &url).map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
            let verdict = match repo {
                Layout::V1 => {
                    published::verify_published(fetcher, &anchor, now_or(now), allow_missing)?
                }
                Layout::V2 => {
                    published::verify_published_v2(fetcher, &anchor, now_or(now), allow_missing)?
                }
            };
            match verdict {
                Published::NotPublished => println!(
                    "tuf verify-published: {url} has no timestamp yet (allowed): nothing verified"
                ),
                Published::Verified { lines } => {
                    for line in lines {
                        println!("tuf verify-published: {line}");
                    }
                    println!("tuf verify-published: ok");
                }
            }
            Ok(())
        }
    }
}
