//! Build a Rust plugin for core Wasm and package its checked manifest and module.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_pack::pack::{Build, Mode};
use oncl_pack::read_limited;
use oncl_pki::fsutil::{Access, write_atomically};
use oncl_plugin::{MAX_MANIFEST, MAX_PACKAGE, Manifest, Package};

use crate::index::{index_path, read_index};
use oncl_update::Channel;

/// Reads bounded package bytes and the checked plugin inside them.
///
/// # Errors
///
/// An oversized, unreadable or invalid package.
pub fn read_package(path: &Path) -> anyhow::Result<(Vec<u8>, Package)> {
    let bytes = read_limited(path, MAX_PACKAGE)?;
    let package = Package::read(&bytes).with_context(|| format!("reading {}", path.display()))?;
    Ok((bytes, package))
}

/// Builds one `cdylib` Rust crate of the workspace at `root` (`oncl_pack::pack::pack` in
/// [`Mode::Workspace`]) and writes its deterministic `.onclp` package into `out`.
///
/// The workspace and the crate directory are named `/workspace` and `/plugin` in the module.
///
/// # Errors
///
/// An invalid crate or manifest, a failed build, an unsupported Wasm module or I/O error.
pub fn pack(root: &Path, directory: &Path, out: &Path) -> anyhow::Result<PathBuf> {
    let packed = oncl_pack::pack::pack(&Build {
        crate_dir: directory,
        target_dir: &root.join("target/plugin-build"),
        remaps: vec![
            (root.to_path_buf(), "/workspace"),
            (directory.to_path_buf(), "/plugin"),
        ],
        mode: &Mode::Workspace,
    })?;
    fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let path = out.join(packed.file_name());
    write_atomically(&path, &packed.bytes, Access::Default)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// The directories of `plugins` not shared by the ports: the guest libraries and the build
/// output.
const NOT_PORTS: [&str; 2] = ["common", "target"];

/// The port directories under `plugins`: every directory except [`NOT_PORTS`] and hidden
/// ones, sorted by name.
///
/// # Errors
///
/// An unreadable directory or a name that is not UTF-8.
pub fn port_names(plugins: &Path) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(plugins).with_context(|| format!("reading {}", plugins.display()))? {
        let entry = entry.with_context(|| format!("reading {}", plugins.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            bail!("{} is not a UTF-8 name", entry.path().display());
        };
        if !entry.file_type()?.is_dir() || NOT_PORTS.contains(&name) || name.starts_with('.') {
            continue;
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

/// The port directories (names under `plugins`) whose `plugin.toml` names an `(id,
/// version)` that `channel`'s index in `index_dir` does not list yet, sorted by name;
/// every port if the channel has no index.
///
/// # Errors
///
/// A port directory without a valid `plugin.toml`, an invalid index, or an I/O failure.
pub fn pending(plugins: &Path, index_dir: &Path, channel: Channel) -> anyhow::Result<Vec<String>> {
    let path = index_path(index_dir, channel);
    let published = if path.exists() {
        read_index(&path, channel)?.plugins
    } else {
        Vec::new()
    };
    let mut pending = Vec::new();
    for name in port_names(plugins)? {
        let manifest_path = plugins.join(&name).join("plugin.toml");
        let text = String::from_utf8(read_limited(&manifest_path, MAX_MANIFEST)?)
            .with_context(|| format!("reading {}", manifest_path.display()))?;
        let manifest = Manifest::from_toml(&text)
            .with_context(|| format!("reading {}", manifest_path.display()))?;
        if !published
            .iter()
            .any(|r| r.id == manifest.id && r.version == manifest.version)
        {
            pending.push(name);
        }
    }
    Ok(pending)
}

/// The `[port] conformance` of the port with plugin `id` under `plugins_dir`
/// (`computed` or `confirmed`), from the checked ports ([`crate::registry::ports::load`]).
///
/// # Errors
///
/// No port has `id`, or a port of `plugins_dir` is invalid.
pub fn registry_conformance(plugins_dir: &Path, id: &str) -> anyhow::Result<String> {
    let ports = crate::registry::ports::load(plugins_dir)?;
    let port = ports
        .iter()
        .find(|port| port.registry.id == id)
        .with_context(|| format!("{id}: no port in {} has this id", plugins_dir.display()))?;
    Ok(port.registry.port.conformance.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_names_skip_common_target_and_hidden() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["zeta", "common", "target", ".git", "alpha"] {
            fs::create_dir(dir.path().join(name)).unwrap();
        }
        fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        assert_eq!(port_names(dir.path()).unwrap(), ["alpha", "zeta"]);
    }
}
