//! The plugin registry: the ports of `plugins/`, the third-party publishers of
//! `publishers/` and what the project says about them, and the project site that shows it
//! (`site/`, built with Zola into `target/site/`).

use std::path::{Path, PathBuf};

use oncl_flows::Locale;

pub mod check;
pub mod data;
pub mod generate;
pub mod inputs;
pub mod ports;
pub mod publishers;
pub mod site;
pub mod zola;

pub use check::check;
pub use generate::generate;

/// The site's hand-written sources, from the workspace root.
pub const SITE_DIR: &str = "site";

/// The site's languages: the directory name (none for the default, `ru`) and the locale.
pub const LANGS: [(&str, Locale); 3] = [("ru", Locale::Ru), ("kk", Locale::Kk), ("en", Locale::En)];

/// What the site is generated from.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// The ports: `plugins/`.
    pub plugins: PathBuf,
    /// The update indexes: `updates/v1/`, if there are any.
    pub updates: Option<PathBuf>,
    /// The project's releases, JSON Lines.
    pub releases: Option<PathBuf>,
    /// A copy of the `upstream` branch's `index.json` and `latest/facts.json`.
    pub upstream: Option<PathBuf>,
    /// The publishers' registry: `publishers/`, if there is one.
    pub publishers: Option<PathBuf>,
    /// The TUF repository with the publishers' roles: `tuf/v1`, if there is one.
    pub tuf: Option<PathBuf>,
}

/// Builds the site into `out`: the build copy `out/src` ([`generate`]), Zola's output
/// `out/public` ([`zola::build`], the pinned Zola of [`zola::ensure`] unless `zola` is
/// given), then [`check`]. Warnings about external inputs are printed as GitHub
/// annotations. Returns `out/public`.
///
/// # Errors
///
/// Generation, Zola or the check fails.
pub fn build(
    root: &Path,
    inputs: &Inputs,
    out: &Path,
    zola: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    let src = out.join("src");
    let public = out.join("public");
    for warning in generate(root, inputs, &src)? {
        println!("::warning::{}", workflow_escaped(&warning));
    }
    let zola = match zola {
        Some(zola) => zola.to_path_buf(),
        None => zola::ensure(root)?,
    };
    zola::build(&zola, &src, &public)?;
    let report = check(&public, &site::site_config(root)?.base_url)?;
    println!(
        "{}: {} pages, {} links checked",
        public.display(),
        report.pages,
        report.links
    );
    Ok(public)
}

/// `text` as the message of a GitHub workflow command: `%`, `\r` and `\n` escaped, so a
/// warning that quotes an input (a publisher's role) cannot end the line and start another
/// command.
fn workflow_escaped(text: &str) -> String {
    text.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

#[cfg(test)]
mod tests {
    #[test]
    fn warnings_cannot_start_a_workflow_command() {
        assert_eq!(
            super::workflow_escaped("a\n::error::b\r%"),
            "a%0A::error::b%0D%25"
        );
    }
}
