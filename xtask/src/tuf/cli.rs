//! The command line of `cargo xtask tuf` (`docs/dev/release.md` says when each is run).
//!
//! One repository, `tuf/v1`. Its snapshot mode is the file `tuf/v1.toml`
//! ([`super::repo::SnapshotMode`]): `--config` names it, by default the file beside
//! `--out` for `update` and `root` (which write the repository), and the workspace's
//! `tuf/v1.toml` for `check` (also run on the copy Pages publishes), `snapshot` and
//! `timestamp`.
//!
//! Exit codes: 0 when the command did what it says (`tuf check` also when it found only
//! warnings, or no repository yet); 1 when it refused, failed, or `tuf check` found
//! problems; 2 for a command line that does not parse.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::Subcommand;
use oncl_update::tuf::HttpFetcher;
use time::OffsetDateTime;

use super::check::{self, Expiry, Stage};
use super::published::{self, Published};
use super::repo::{self, SnapshotMode};
use super::timestamp::KeySource;
use super::{
    ANCHOR, CONFIG, PassphraseSource, Problem, REPO_DIR, init, parse_time, root, show_time,
    snapshot, timestamp, update,
};
use crate::publishers::PUBLISHERS_DIR;

/// `cargo xtask tuf …`: the operator's side of the TUF repository of the update indexes and
/// the publishers' plugins.
#[derive(Subcommand)]
pub enum TufCommand {
    /// The owner's ceremony: make the root, targets, snapshot and timestamp keys, root
    /// version 1 in the repository, and a copy of it as the client's trust anchor. The
    /// root, targets and snapshot keys are written encrypted with one passphrase (asked
    /// twice, at least 12 characters; one passphrase for the three is the owner's choice);
    /// the timestamp key is one unencrypted line, for the GitHub secret
    /// `TUF_TIMESTAMP_KEY`. The snapshot starts offline. Nothing existing is overwritten.
    Init {
        /// The directory of the secret keys: outside the repository, or git-ignored.
        #[arg(long)]
        keys: PathBuf,
        /// The repository directory [default: `tuf/v1` of the workspace].
        #[arg(long)]
        out: Option<PathBuf>,
        /// The trust anchor file [default: `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Read the passphrase from the first line of this file instead of asking
        /// (automation and tests).
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Sign new top-level targets over `updates/v1/{stable,beta}.json` (those that exist)
    /// and, once `publishers/` has an entry, over `publishers.json`, delegating to the active
    /// publishers: copies the target files under their hashes and writes
    /// `metadata/<N+1>.targets.json` and, while the snapshot is offline,
    /// `<N+1>.snapshot.json`, valid for 30 days. A publisher moved to `retired` and
    /// `revoke_all` are settled into its `publisher.toml` first. With nothing changed it
    /// says "up to date" and writes nothing; `--refresh` signs new versions anyway, to push
    /// the expiry forward. Never touches the timestamp.
    Update {
        /// The directory of the secret keys.
        #[arg(long)]
        keys: PathBuf,
        /// The directory of the indexes [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The repository directory [default: `tuf/v1` of the workspace].
        #[arg(long)]
        out: Option<PathBuf>,
        /// The registry of the publishers [default: `publishers` of the workspace].
        #[arg(long)]
        publishers: Option<PathBuf>,
        /// The snapshot mode [default: the `.toml` file beside the repository directory].
        #[arg(long)]
        config: Option<PathBuf>,
        /// Sign new versions even if nothing changed (the monthly job).
        #[arg(long)]
        refresh: bool,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Sign the snapshot of a copy of `tuf/v1` for publication with the online key, once the
    /// snapshot is online (version: Unix seconds, or one more than the published one; valid
    /// for 7 days). The copy is verified first, every delegated role's newest file
    /// included; the published snapshot (`--previous`) is verified, kept beside the new one,
    /// and the new one may drop or lower nothing it listed. If the published site cannot be
    /// read or verified, nothing is signed. Run by Pages: the file is never committed. The
    /// key is never printed.
    Snapshot {
        /// The repository directory (a copy of `tuf/v1` for publication).
        #[arg(long)]
        out: PathBuf,
        /// The trust anchor [default: `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The indexes the targets must be [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The registry of the publishers [default: `publishers` of the workspace].
        #[arg(long)]
        publishers: Option<PathBuf>,
        /// The snapshot mode [default: `tuf/v1.toml` of the workspace].
        #[arg(long)]
        config: Option<PathBuf>,
        /// The published `tuf/v1`, `https://…/tuf/v1/`, whose snapshot the new one extends;
        /// its timestamp must be there.
        #[arg(long)]
        previous: String,
        /// The environment variable that holds the key line [default: TUF_SNAPSHOT_KEY].
        #[arg(long, conflicts_with = "key_file")]
        key_env: Option<String>,
        /// A key file instead of the environment.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
    },
    /// Sign `metadata/timestamp.json` for the newest snapshot in `--out` (the owner's while
    /// the snapshot is offline, the one `tuf snapshot` signed once it is online), with the
    /// online key (version: Unix seconds, valid for 7 days). Verifies the repository first
    /// and refuses a snapshot, targets or root that has expired or expires within a day.
    /// Run by Pages on the copy that is published: the file is never committed. The key is
    /// never printed.
    Timestamp {
        /// The repository directory (a copy for publication).
        #[arg(long)]
        out: PathBuf,
        /// The trust anchor the repository is verified from [default:
        /// `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The indexes the targets must be [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The registry of the publishers [default: `publishers` of the workspace].
        #[arg(long)]
        publishers: Option<PathBuf>,
        /// The snapshot mode [default: `tuf/v1.toml` of the workspace].
        #[arg(long)]
        config: Option<PathBuf>,
        /// The environment variable that holds the key line [default: TUF_TIMESTAMP_KEY].
        #[arg(long, conflicts_with = "key_file")]
        key_env: Option<String>,
        /// A key file instead of the environment.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
    },
    /// The next root (version N+1, valid for 365 days), signed by the keys of the root in
    /// force: a renewal when no `--rotate-*` is given, else a rotation of those roles'
    /// keys (the new root key signs too). New keys are written next to the old as
    /// `<role>.v<N>.key`. `--rotate-snapshot --online` moves the snapshot key into CI: the
    /// new key is an online line for the GitHub secret `TUF_SNAPSHOT_KEY`, and the snapshot
    /// mode file gets `snapshot = "online"`.
    Root {
        /// The directory of the secret keys.
        #[arg(long)]
        keys: PathBuf,
        /// The repository directory [default: `tuf/v1` of the workspace].
        #[arg(long)]
        out: Option<PathBuf>,
        /// The snapshot mode [default: the `.toml` file beside the repository directory].
        #[arg(long)]
        config: Option<PathBuf>,
        /// Replace the root key.
        #[arg(long)]
        rotate_root: bool,
        /// Replace the targets key (then `tuf update` signs new versions).
        #[arg(long)]
        rotate_targets: bool,
        /// Replace the snapshot key (offline: then `tuf update` signs new versions; online:
        /// then replace the GitHub secret).
        #[arg(long)]
        rotate_snapshot: bool,
        /// With `--rotate-snapshot`: the new snapshot key is an online key, and the snapshot
        /// goes online.
        #[arg(long, requires = "rotate_snapshot")]
        online: bool,
        /// Replace the timestamp key (then replace the GitHub secret).
        #[arg(long)]
        rotate_timestamp: bool,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Verify the repository offline with the client's code over the directory: the chain of
    /// roots from the trust anchor, the newest snapshot (unless it is online and this is the
    /// committed tree) and targets, every file listed, the newest file of every role, no
    /// stray file, the targets equal to the indexes in the tree, `publishers.json` and the
    /// delegations equal to what `publishers/` makes, no entry of `publishers/` removed,
    /// history unchanged against `--base`, expiry. With neither the directory nor the anchor
    /// it says "no TUF repository yet" and succeeds. Findings are `error[<code>]` (exit 1)
    /// and `warning[<code>]`; the codes are in `docs/dev/release.md`.
    Check {
        /// The repository directory [default: `tuf/v1` of the workspace].
        #[arg(long)]
        dir: Option<PathBuf>,
        /// The directory of the indexes [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The registry of the publishers [default: `publishers` of the workspace].
        #[arg(long)]
        publishers: Option<PathBuf>,
        /// The trust anchor [default: `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The snapshot mode [default: `tuf/v1.toml` of the workspace].
        #[arg(long)]
        config: Option<PathBuf>,
        /// The time to judge expiry at, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Targets and an offline snapshot with fewer days left are expiring.
        #[arg(long, default_value_t = 10)]
        min_days: i64,
        /// The root with fewer days left is expiring.
        #[arg(long, default_value_t = 45)]
        min_root_days: i64,
        /// Expired and expiring metadata is an error, not a warning.
        #[arg(long)]
        fail_on_expiring: bool,
        /// The git revision whose repository this one extends: published files may not
        /// change or go, no version may go back, no entry of `publishers/` may go.
        #[arg(long)]
        base: Option<String>,
        /// The directory is the committed tree: there must be no timestamp (the default
        /// requires one, as in a repository about to be published).
        #[arg(long)]
        no_timestamp: bool,
    },
    /// The client over HTTPS against the published site (the smoke check after a
    /// deployment): the whole chain, every target, and every delegated role.
    VerifyPublished {
        /// The base URL of the repository, `https://…/tuf/v1/`.
        #[arg(long)]
        url: String,
        /// The trust anchor [default: `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// A repository that is not published yet (no timestamp) is not a failure.
        #[arg(long)]
        allow_missing: bool,
        /// The time to judge expiry at [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
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

/// The snapshot mode of `config`, or of the file beside the repository `dir`.
fn mode_beside(config: Option<PathBuf>, dir: &Path) -> anyhow::Result<SnapshotMode> {
    repo::read_mode(&config.unwrap_or_else(|| repo::config_path(dir)))
}

fn passphrase(file: Option<PathBuf>) -> PassphraseSource {
    file.map_or(PassphraseSource::Prompt, PassphraseSource::File)
}

fn now_or(now: Option<OffsetDateTime>) -> OffsetDateTime {
    now.unwrap_or_else(OffsetDateTime::now_utc)
}

fn print_update(outcome: &update::Outcome) {
    match outcome {
        update::Outcome::UpToDate { targets, snapshot } => match snapshot {
            Some(snapshot) => println!(
                "tuf update: up to date (targets {targets}, snapshot {snapshot} list the \
                 indexes and the publishers); nothing written"
            ),
            None => println!(
                "tuf update: up to date (targets {targets} lists the indexes and the \
                 publishers); nothing written"
            ),
        },
        update::Outcome::Written(w) => {
            println!("tuf update: {}", w.reason);
            for s in &w.settled {
                println!("tuf update: settled {}", s.path.display());
                for r in &s.added {
                    println!(
                        "tuf update:   {} revokes {} {} (date {})",
                        s.name, r.id, r.version, r.date
                    );
                }
            }
            for file in &w.files {
                println!("tuf update: wrote {}", file.display());
            }
            let delegated = w
                .delegated
                .map_or_else(String::new, |n| format!(" delegating to {n} publisher(s)"));
            match w.snapshot {
                Some(snapshot) => println!(
                    "tuf update: targets {}{delegated}, snapshot {snapshot}, valid until {}",
                    w.targets,
                    show_time(w.expires)
                ),
                None => println!(
                    "tuf update: targets {}{delegated}, valid until {}; the snapshot is online: \
                     CI signs it when Pages is published",
                    w.targets,
                    show_time(w.expires)
                ),
            }
        }
    }
}

/// Prints the findings, and counts the problems.
fn print_report(notes: &[String], warnings: &[Problem], problems: &[Problem]) -> usize {
    for note in notes {
        println!("tuf check: {note}");
    }
    for w in warnings {
        println!("tuf check: warning[{}]: {}", w.code, w.message);
    }
    for p in problems {
        eprintln!("tuf check: error[{}]: {}", p.code, p.message);
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
        } => {
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
            println!("tuf init: wrote the trust anchor {}", made.anchor.display());
            println!(
                "tuf init: the timestamp key is the single line of timestamp.key: put it in the \
                 GitHub secret TUF_TIMESTAMP_KEY of the environment tuf-timestamp, then keep \
                 no other copy"
            );
            Ok(())
        }
        TufCommand::Update {
            keys,
            index,
            out,
            publishers,
            config,
            refresh,
            now,
            passphrase_file: file,
        } => {
            let out = workspace(out, REPO_DIR);
            let mode = mode_beside(config, &out)?;
            print_update(&update::update(&update::Options {
                keys: &keys,
                index: &workspace(index, crate::index::INDEX_DIR),
                out: &out,
                publishers: &workspace(publishers, PUBLISHERS_DIR),
                mode,
                refresh,
                now: now_or(now),
                passphrase: &passphrase(file),
            })?);
            Ok(())
        }
        TufCommand::Snapshot {
            out,
            anchor,
            index,
            publishers,
            config,
            previous,
            key_env,
            key_file,
            now,
        } => {
            let config = workspace(config, CONFIG);
            let transport = oncl_pki::http::UreqTransport::default();
            let fetcher = HttpFetcher::new(&transport, &previous)
                .map_err(|e| anyhow::anyhow!("{previous}: {e}"))?;
            let signed = snapshot::snapshot(
                &snapshot::Options {
                    out: &out,
                    anchor: &workspace(anchor, ANCHOR),
                    index: &workspace(index, crate::index::INDEX_DIR),
                    publishers: &workspace(publishers, PUBLISHERS_DIR),
                    mode: repo::read_mode(&config)?,
                    key: &key_source(key_file, key_env, "TUF_SNAPSHOT_KEY"),
                    now: now_or(now),
                },
                &fetcher,
            )?;
            println!(
                "tuf snapshot: kept the published snapshot {} beside it: {}",
                signed.previous.0,
                signed.previous.1.display()
            );
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
            config,
            key_env,
            key_file,
            now,
        } => {
            let config = workspace(config, CONFIG);
            let signed = timestamp::timestamp(&timestamp::Options {
                out: &out,
                anchor: &workspace(anchor, ANCHOR),
                index: &workspace(index, crate::index::INDEX_DIR),
                publishers: &workspace(publishers, PUBLISHERS_DIR),
                mode: repo::read_mode(&config)?,
                key: &key_source(key_file, key_env, "TUF_TIMESTAMP_KEY"),
                now: now_or(now),
            })?;
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
            config,
            rotate_root,
            rotate_targets,
            rotate_snapshot,
            online,
            rotate_timestamp,
            now,
            passphrase_file: file,
        } => {
            let out = workspace(out, REPO_DIR);
            let config = config.unwrap_or_else(|| repo::config_path(&out));
            let made = root::root(&root::Options {
                keys: &keys,
                out: &out,
                config: &config,
                rotate_root,
                rotate_targets,
                rotate_snapshot,
                rotate_timestamp,
                online,
                now: now_or(now),
                passphrase: &passphrase(file),
            })?;
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
            if let Some(config) = &made.config {
                println!(
                    "tuf root: wrote {} (snapshot = \"{}\"): commit it with the root",
                    config.display(),
                    made.mode.as_str()
                );
            }
            let offline = made.mode == SnapshotMode::Offline;
            if rotate_targets || (rotate_snapshot && offline) {
                println!(
                    "tuf root: the committed targets and snapshot are signed by the old keys: \
                     run `cargo xtask tuf update` now"
                );
            }
            if rotate_snapshot && !offline {
                println!(
                    "tuf root: put the new snapshot key in the GitHub secret TUF_SNAPSHOT_KEY \
                     (`gh secret set --env tuf-snapshot TUF_SNAPSHOT_KEY < <file>`) before the \
                     root is merged"
                );
            }
            if rotate_timestamp {
                println!(
                    "tuf root: put the new timestamp key in the GitHub secret \
                     TUF_TIMESTAMP_KEY (`gh secret set --env tuf-timestamp \
                     TUF_TIMESTAMP_KEY < <file>`) before the root is merged"
                );
            }
            Ok(())
        }
        TufCommand::Check {
            dir,
            index,
            publishers,
            anchor,
            config,
            now,
            min_days,
            min_root_days,
            fail_on_expiring,
            base,
            no_timestamp,
        } => {
            let dir = workspace(dir, REPO_DIR);
            let mode = repo::read_mode(&workspace(config, CONFIG))?;
            let anchor = workspace(anchor, ANCHOR);
            let outcome = check::check(&check::Options {
                dir: &dir,
                index: Some(&workspace(index, crate::index::INDEX_DIR)),
                publishers: Some(&workspace(publishers, PUBLISHERS_DIR)),
                anchor: Some(&anchor),
                now: now_or(now),
                stage: if no_timestamp {
                    Stage::Tree
                } else {
                    Stage::Published
                },
                mode,
                expiry: Expiry {
                    min_days,
                    min_root_days,
                    fail: fail_on_expiring,
                },
                base: base.as_deref(),
            })?;
            match outcome {
                check::Outcome::NoRepository => println!(
                    "tuf check: no TUF repository yet (no {}, no trust anchor {})",
                    dir.display(),
                    anchor.display()
                ),
                check::Outcome::Checked(report) => {
                    let failed = print_report(&report.notes, &report.warnings, &report.problems);
                    if failed > 0 {
                        bail!("tuf check: failed with {failed} problem(s)");
                    }
                    println!("tuf check: ok");
                }
            }
            Ok(())
        }
        TufCommand::VerifyPublished {
            url,
            anchor,
            allow_missing,
            now,
        } => {
            let anchor = workspace(anchor, ANCHOR);
            let anchor = std::fs::read(&anchor)
                .with_context(|| format!("reading the trust anchor {}", anchor.display()))?;
            let transport = oncl_pki::http::UreqTransport::default();
            let fetcher =
                HttpFetcher::new(&transport, &url).map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
            match published::verify_published(fetcher, &anchor, now_or(now), allow_missing)? {
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
