//! `oncl-pack`: the canonical source archive of a plugin and its reference build, as the
//! builder image `ghcr.io/arynyklas/oncl-plugin-builder` runs them (docs/dev/publishers.md).

use std::num::NonZeroU32;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use oncl_pack::builder::{self, WORK};
use oncl_pack::source::{MAX_ARCHIVE, Tree};
use oncl_pack::{read_limited, sha256_hex};
use oncl_pki::fsutil::{Access, write_atomically};

#[derive(Parser)]
#[command(name = "oncl-pack", version, about = "OpenNCALayer's plugin builder")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Makes the canonical source archive (`<id>-<version>.src.tar.gz`) of a directory or of
    /// a git revision; prints its SHA-256 and path.
    Source {
        /// A directory: every file under it, except anything named `.git`.
        #[arg(long, conflicts_with_all = ["git", "rev"], required_unless_present = "git")]
        dir: Option<PathBuf>,
        /// A git repository: the whole tree of `--rev`.
        #[arg(long, requires = "rev")]
        git: Option<PathBuf>,
        /// The revision of `--git` (a commit, tag or tree).
        #[arg(long, requires = "git")]
        rev: Option<String>,
        /// The archive to write.
        #[arg(long)]
        out: PathBuf,
    },
    /// Checks that an archive is canonical; prints its SHA-256 and length.
    Check {
        /// The archive.
        archive: PathBuf,
    },
    /// Unpacks the archive and downloads the crates its lock file names into `CARGO_HOME`
    /// (the one step with the network).
    Fetch(Input),
    /// Builds the package twice from the archive, without the network, compares the two and
    /// writes `<id>-<version>.onclp` into `--out`; prints its SHA-256 and path.
    Build {
        #[command(flatten)]
        input: Input,
        /// The directory for the package.
        #[arg(long)]
        out: PathBuf,
        /// Cargo's `--jobs` (the bytes do not depend on it).
        #[arg(long)]
        jobs: Option<NonZeroU32>,
    },
    /// Rebuilds the package from the archive, without the network, and compares it with a
    /// published one. The crates must be in `CARGO_HOME` already: run `fetch` first, in a
    /// container of its own.
    Verify {
        #[command(flatten)]
        input: Input,
        /// The published package's SHA-256.
        #[arg(long, required_unless_present = "package", conflicts_with = "package")]
        sha256: Option<String>,
        /// The published package.
        #[arg(long)]
        package: Option<PathBuf>,
        /// Cargo's `--jobs` (the bytes do not depend on it).
        #[arg(long)]
        jobs: Option<NonZeroU32>,
    },
}

#[derive(Args)]
struct Input {
    /// The canonical source archive.
    #[arg(long)]
    source: PathBuf,
    /// The crate directory under `src/` (`source.path`; "" for `src/` itself).
    #[arg(long)]
    path: String,
    /// The work directory; the archive is unpacked into `<work>/src`, which must not exist.
    #[arg(long, default_value = WORK)]
    work: PathBuf,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Source { dir, git, rev, out } => {
            let tree = match (dir, git, rev) {
                (Some(dir), None, None) => {
                    Tree::from_dir(&dir).with_context(|| format!("reading {}", dir.display()))?
                }
                (None, Some(git), Some(rev)) => Tree::from_git(&git, &rev)
                    .with_context(|| format!("reading {rev} of {}", git.display()))?,
                _ => unreachable!("clap requires --dir or --git with --rev"),
            };
            let bytes = tree.to_archive()?;
            write_atomically(&out, &bytes, Access::Default)
                .with_context(|| format!("writing {}", out.display()))?;
            println!("{}  {}", sha256_hex(&bytes), out.display());
        }
        Command::Check { archive } => {
            let bytes = read_limited(&archive, MAX_ARCHIVE)?;
            Tree::from_archive(&bytes).with_context(|| format!("reading {}", archive.display()))?;
            println!(
                "{}  {}  {}",
                sha256_hex(&bytes),
                bytes.len(),
                archive.display()
            );
        }
        Command::Fetch(input) => {
            let prepared = builder::prepare(&input.source, &input.path, &input.work)?;
            builder::fetch(&prepared)?;
        }
        Command::Build { input, out, jobs } => {
            let prepared = builder::prepare(&input.source, &input.path, &input.work)?;
            let packed = builder::build(&prepared, jobs)?;
            std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
            let path = out.join(packed.file_name());
            write_atomically(&path, &packed.bytes, Access::Default)
                .with_context(|| format!("writing {}", path.display()))?;
            println!("{}  {}", sha256_hex(&packed.bytes), path.display());
        }
        Command::Verify {
            input,
            sha256,
            package,
            jobs,
        } => {
            let expected = match (sha256, package) {
                (Some(sha256), None) => sha256,
                (None, Some(package)) => {
                    sha256_hex(&read_limited(&package, oncl_plugin::MAX_PACKAGE)?)
                }
                _ => unreachable!("clap requires one of --sha256 and --package"),
            };
            let prepared = builder::prepare(&input.source, &input.path, &input.work)?;
            let packed = builder::verify(&prepared, &expected, jobs)?;
            println!(
                "{}: the rebuild from the archive (sha256 {}) gives the same bytes, sha256 {}",
                packed.file_name(),
                prepared.archive_sha256,
                sha256_hex(&packed.bytes)
            );
        }
    }
    Ok(())
}
