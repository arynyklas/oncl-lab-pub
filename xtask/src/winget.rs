//! `cargo xtask winget manifest`: the three WinGet manifest files of a published release.
//!
//! The installers are the release's `openncalayer-<version>-win-<x64|x86>-winget-setup.exe`
//! (`docs/dev/winget-installer.md`); their SHA-256 come from the release's `SHA256SUMS`. The
//! command writes files and nothing else: it does not submit, fork or remember anything
//! (`docs/dev/winget.md`).

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Subcommand;
use oncl_update::Version;

use crate::package::windows::{flavor, winget_setup_name};
use crate::upstream::http::{Fetcher, RequestCtx, UrlParts};

/// The package identifier (free in `microsoft/winget-pkgs` or not: checked before submitting).
const PACKAGE_IDENTIFIER: &str = "arynyklas.OpenNCALayer";
/// The GitHub repository the assets are published in.
const REPOSITORY: &str = "arynyklas/OpenNCALayer";
const MANIFEST_VERSION: &str = "1.12.0";
/// Windows 10 version 1809: the oldest Windows the installer entry runs on.
const MINIMUM_OS_VERSION: &str = "10.0.17763.0";
/// The exit code of the entry for a busy program (an active signature): not a success.
const BUSY_EXIT_CODE: u8 = 4;
/// The most a `SHA256SUMS` may have.
const SUMS_LIMIT: u64 = 1 << 20;
/// `(WinGet architecture, release flavor)` of the installers.
const INSTALLERS: [(&str, &str); 2] = [("x64", "win-x64"), ("x86", "win-x86")];

/// `cargo xtask winget …`.
#[derive(Subcommand)]
pub enum WingetCommand {
    /// Write the manifest (version, defaultLocale, installer) of a published release.
    Manifest {
        /// The version of the release, without `v`: `0.2.0`.
        #[arg(long)]
        version: Version,
        /// The release's `SHA256SUMS`; downloaded from the release when not given.
        #[arg(long)]
        sums: Option<PathBuf>,
        /// The directory to write; must not hold the files yet.
        #[arg(long, default_value = "target/winget")]
        out: PathBuf,
    },
}

/// Runs `command`.
///
/// # Errors
///
/// `SHA256SUMS` cannot be read or lacks an installer, or the files cannot be written.
pub fn run(command: WingetCommand) -> anyhow::Result<()> {
    let WingetCommand::Manifest { version, sums, out } = command;
    let sums = match sums {
        Some(path) => {
            std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?
        }
        None => download_sums(&version)?,
    };
    let files = render(&version, &sums)?;
    std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
    for (name, _) in &files {
        let path = out.join(name);
        if path.exists() {
            bail!("{} exists; remove it or pick another --out", path.display());
        }
    }
    for (name, text) in &files {
        std::fs::write(out.join(name), text).with_context(|| format!("writing {name}"))?;
    }
    println!(
        "WinGet manifest of {version} written to {}: check it with `winget validate {}`",
        out.display(),
        out.display()
    );
    Ok(())
}

fn download_sums(version: &Version) -> anyhow::Result<String> {
    let url = format!("{}/SHA256SUMS", download_base(version));
    let fetcher = Fetcher::new().restricted_to(|hop| {
        UrlParts::parse(hop).is_ok_and(|parts| {
            parts.scheme == "https"
                && (parts.host == "github.com" || parts.host.ends_with(".githubusercontent.com"))
        })
    });
    let answer = fetcher
        .get(&url, SUMS_LIMIT, &RequestCtx::default())
        .with_context(|| format!("downloading {url}"))?;
    if answer.status != 200 {
        bail!("{url} answered {}", answer.status);
    }
    String::from_utf8(answer.body).context("SHA256SUMS is not UTF-8")
}

/// The URL prefix of the assets of release `version`: it does not change when a newer release
/// appears, unlike `releases/latest/download`.
fn download_base(version: &Version) -> String {
    format!("https://github.com/{REPOSITORY}/releases/download/v{version}")
}

/// The SHA-256 (lowercase hex) of `name` in the text of a `SHA256SUMS` (`<hex>  <name>`).
fn sha256_of(sums: &str, name: &str) -> anyhow::Result<String> {
    let mut found = None;
    for line in sums.lines() {
        let Some((digest, file)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if file.trim_start().trim_start_matches('*') != name {
            continue;
        }
        if found.is_some() {
            bail!("SHA256SUMS lists {name} twice");
        }
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("SHA256SUMS has no SHA-256 for {name}: {digest:?}");
        }
        found = Some(digest.to_ascii_lowercase());
    }
    found.with_context(|| format!("SHA256SUMS does not list {name}"))
}

fn quote(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn header(kind: &str) -> String {
    format!(
        "# yaml-language-server: $schema=https://aka.ms/winget-manifest.{kind}.{MANIFEST_VERSION}.schema.json\n"
    )
}

/// The three files `(name, text)` of the manifest of release `version`.
///
/// # Errors
///
/// `sums` lacks the installer of an architecture.
pub fn render(version: &Version, sums: &str) -> anyhow::Result<Vec<(String, String)>> {
    let id = PACKAGE_IDENTIFIER;
    let tag = format!("v{version}");
    let common = format!(
        "PackageIdentifier: {}\nPackageVersion: {}\n",
        quote(id),
        quote(&version.to_string())
    );
    let tail = |kind: &str| format!("ManifestType: {kind}\nManifestVersion: {MANIFEST_VERSION}\n");

    let version_file = format!(
        "{}{common}DefaultLocale: en-US\n{}",
        header("version"),
        tail("version")
    );

    let locale = format!(
        "{header}{common}PackageLocale: en-US\n\
         Publisher: {publisher}\n\
         PublisherUrl: https://github.com/arynyklas\n\
         PublisherSupportUrl: https://github.com/{REPOSITORY}/issues\n\
         PackageName: OpenNCALayer\n\
         PackageUrl: https://github.com/{REPOSITORY}\n\
         License: Apache-2.0\n\
         LicenseUrl: https://github.com/{REPOSITORY}/blob/{tag}/LICENSE\n\
         ShortDescription: {short}\n\
         Moniker: openncalayer\n\
         Tags:\n- ncalayer\n- kazakhstan\n- egov\n- digital-signature\n\
         ReleaseNotesUrl: https://github.com/{REPOSITORY}/releases/tag/{tag}\n\
         {tail}",
        header = header("defaultLocale"),
        publisher = quote("OpenNCALayer contributors"),
        short = quote(
            "Open-source replacement for NCALayer, the signing daemon of Kazakhstan's e-government services"
        ),
        tail = tail("defaultLocale"),
    );

    let mut installers = String::new();
    for (arch, flavor_name) in INSTALLERS {
        let flavor = flavor(flavor_name)?;
        let name = winget_setup_name(version, &flavor);
        let sha = sha256_of(sums, &name)?.to_ascii_uppercase();
        installers.push_str(&format!(
            "- Architecture: {arch}\n  InstallerUrl: {}/{name}\n  InstallerSha256: {sha}\n",
            download_base(version)
        ));
    }
    // The entry takes only `--silent` and has no interactive mode; its busy code is an answer,
    // never a success (InstallerSuccessCodes stays unset). docs/dev/winget-installer.md.
    let installer = format!(
        "{header}{common}Platform:\n- Windows.Desktop\n\
         MinimumOSVersion: {MINIMUM_OS_VERSION}\n\
         InstallerType: exe\n\
         Scope: user\n\
         InstallModes:\n- silent\n- silentWithProgress\n\
         InstallerSwitches:\n  Silent: --silent\n  SilentWithProgress: --silent\n\
         ExpectedReturnCodes:\n- InstallerReturnCode: {BUSY_EXIT_CODE}\n  ReturnResponse: packageInUse\n\
         UpgradeBehavior: install\n\
         ElevationRequirement: elevationProhibited\n\
         RequireExplicitUpgrade: true\n\
         UnsupportedArguments:\n- log\n- location\n\
         Installers:\n{installers}{tail}",
        header = header("installer"),
        tail = tail("installer"),
    );

    Ok(vec![
        (format!("{id}.yaml"), version_file),
        (format!("{id}.locale.en-US.yaml"), locale),
        (format!("{id}.installer.yaml"), installer),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const X64: &str = "aa11111111111111111111111111111111111111111111111111111111111111";
    const X86: &str = "bb22222222222222222222222222222222222222222222222222222222222222";

    fn sums() -> String {
        format!(
            "{X64}  openncalayer-1.2.3-win-x64-winget-setup.exe\n\
             {X86}  openncalayer-1.2.3-win-x86-winget-setup.exe\n\
             cc33333333333333333333333333333333333333333333333333333333333333  openncalayer-1.2.3-win-x64-setup.exe\n"
        )
    }

    #[test]
    fn each_architecture_gets_its_own_installer_and_hash() {
        let version = Version::parse("1.2.3").unwrap();
        let files = render(&version, &sums()).unwrap();
        let installer = &files[2].1;
        let x64 = "- Architecture: x64\n  InstallerUrl: https://github.com/arynyklas/OpenNCALayer/releases/download/v1.2.3/openncalayer-1.2.3-win-x64-winget-setup.exe\n  InstallerSha256: AA11";
        let x86 = "- Architecture: x86\n  InstallerUrl: https://github.com/arynyklas/OpenNCALayer/releases/download/v1.2.3/openncalayer-1.2.3-win-x86-winget-setup.exe\n  InstallerSha256: BB22";
        assert!(installer.contains(x64), "{installer}");
        assert!(installer.contains(x86), "{installer}");
        assert!(installer.contains(&X64.to_ascii_uppercase()));
        assert!(installer.contains(&X86.to_ascii_uppercase()));
        assert!(
            !installer.contains("CC33"),
            "the plain installer is not a WinGet asset"
        );
    }

    #[test]
    fn a_missing_or_malformed_hash_is_an_error() {
        let version = Version::parse("1.2.3").unwrap();
        let only_x64 = format!("{X64}  openncalayer-1.2.3-win-x64-winget-setup.exe\n");
        assert!(render(&version, &only_x64).is_err());
        let short = "abc  openncalayer-1.2.3-win-x64-winget-setup.exe\n";
        assert!(render(&version, short).is_err());
        let other_version = Version::parse("1.2.4").unwrap();
        assert!(render(&other_version, &sums()).is_err());
    }

    #[test]
    fn sums_text_forms_are_read_the_way_sha256sum_writes_them() {
        let version = Version::parse("1.2.3").unwrap();
        let duplicate = format!(
            "{}{X64}  openncalayer-1.2.3-win-x64-winget-setup.exe\n",
            sums()
        );
        assert!(render(&version, &duplicate).is_err(), "a name listed twice");
        let binary_and_crlf = format!(
            "{X64} *openncalayer-1.2.3-win-x64-winget-setup.exe\r\n\
             {X86}  openncalayer-1.2.3-win-x86-winget-setup.exe\r\n"
        );
        let files = render(&version, &binary_and_crlf).unwrap();
        assert!(files[2].1.contains(&X64.to_ascii_uppercase()));
        assert!(files[2].1.contains(&X86.to_ascii_uppercase()));
    }
}
