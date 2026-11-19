//! Embeds `keys/root.json`, the TUF client's root of trust, if it is there: the owner's key
//! ceremony creates it. A build without it has nothing to trust, and its updater is off. If
//! it is there it is embedded after the code of `src/tuf` that reads a root has checked it (a
//! root of spec version 1.x, its keys' ids, its roles, its thresholds, signatures by listed
//! keys of the root role, at least its threshold of them: [`check_root`]); a malformed one
//! fails the build instead of shipping a release whose updater is off. Whether those
//! signatures verify is not known here (no signature algorithm is built into this script),
//! only when the client starts from the root.

use std::collections::BTreeSet;
use std::path::Path;

// The part of `src/tuf` that reads a root, compiled again for this script: `model` needs
// `keys`, `canonical`, `error`, `names` and `delegation`, and `crate::hex`.
#[path = "src/hex.rs"]
#[allow(dead_code)]
mod hex;

// (Flat, with `src/tuf`'s own names: its files reach each other as `super::keys`, and
// `super` is this crate root here.)
#[path = "src/tuf/canonical.rs"]
#[allow(dead_code)]
mod canonical;
#[path = "src/tuf/delegation.rs"]
#[allow(dead_code)]
mod delegation;
#[path = "src/tuf/error.rs"]
#[allow(dead_code)]
mod error;
#[path = "src/tuf/keys.rs"]
#[allow(dead_code)]
mod keys;
#[path = "src/tuf/model.rs"]
#[allow(dead_code)]
mod model;
#[path = "src/tuf/names.rs"]
#[allow(dead_code, unused_imports)]
mod names;

/// The most a root file may be: `tuf::Limits::default().root`.
const MAX_ROOT_LEN: u64 = 64 << 10;

fn main() {
    let dir = Path::new("keys");
    // A missing path would rerun the script on every build; until `keys/` exists, the
    // crate's directory is watched for it instead.
    if dir.is_dir() {
        println!("cargo:rerun-if-changed=keys");
    } else {
        println!("cargo:rerun-if-changed=.");
    }
    let out = std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR");
    let root = dir.join("root.json");
    let code = match std::fs::read(&root) {
        Ok(bytes) => {
            check_root(&root, &bytes);
            "Some(include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/keys/root.json\")))"
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "None",
        Err(e) => panic!("cannot read {}: {e}", root.display()),
    };
    std::fs::write(Path::new(&out).join("tuf_root.rs"), code).expect("cannot write tuf_root.rs");
}

fn not_a_root(path: &Path, why: &dyn std::fmt::Display) -> ! {
    panic!("{} is not a TUF root: {why}", path.display())
}

/// Panics, failing the build, unless `bytes` is a root file the client can start from, as far
/// as can be told without verifying a signature.
fn check_root(path: &Path, bytes: &[u8]) {
    let file = match model::Envelope::parse(bytes, MAX_ROOT_LEN, "root.json") {
        Ok(file) => file,
        Err(e) => not_a_root(path, &e),
    };
    let root = match model::Root::from_signed(&file.signed) {
        Ok(root) => root,
        Err(e) => not_a_root(path, &e),
    };
    let signers: BTreeSet<_> = file
        .signatures
        .iter()
        .filter_map(|s| keys::KeyId::from_hex(&s.keyid))
        .filter(|id| root.root.keyids.contains(id))
        .collect();
    if signers.len() < root.root.threshold as usize {
        not_a_root(
            path,
            &format_args!(
                "{} signatures by keys of its own root role, {} needed",
                signers.len(),
                root.root.threshold
            ),
        );
    }
}
