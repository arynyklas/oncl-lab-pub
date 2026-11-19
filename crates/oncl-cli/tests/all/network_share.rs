//! A user whose files and working directory are on a network share (on Windows the
//! drive's administrative share `\\localhost\C$\…`, as `\\server\share` or a mapped
//! drive reaches it): both owner-only temporary stores (beside the destination, and the
//! working directory) keep their protected ACL over SMB, so `sign` publishes there and
//! `verify` spools there. A share that cannot keep that ACL fails closed by design,
//! like FAT; this proves an ordinary NTFS-backed share is not such a share.
use crate::support;
use support::*;

#[test]
fn sign_and_verify_with_files_and_working_directory_on_a_network_share() {
    let w = world();
    let Some(share) = oncl_testkit::network_form(w.dir.path()) else {
        return;
    };
    let share = std::path::PathBuf::from(share);
    let document = share.join("document.bin");
    std::fs::write(&document, b"network document").unwrap();
    let signature = share.join("document.der");
    let common = [
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ];
    let mut sign = vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(&document),
        "--output",
        path(&signature),
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    sign.extend(common);
    let signed = run_in(&share, &sign, b"");
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let mut verify = vec![
        "verify",
        "--profile",
        "cms",
        "--input",
        path(&signature),
        "--detached",
        path(&document),
    ];
    verify.extend(common);
    let verified = run_in(&share, &verify, b"");
    assert_eq!(verified.status.code(), Some(0), "{verified:?}");
    // Each store removed itself; only the user's two files remain.
    let mut left: Vec<_> = std::fs::read_dir(&share)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    left.sort();
    let named = |name: &str| left.iter().any(|n| n == name);
    assert!(named("document.bin") && named("document.der"), "{left:?}");
    assert!(
        left.iter()
            .all(|n| !n.to_string_lossy().starts_with(".oncl")),
        "{left:?}"
    );
}
