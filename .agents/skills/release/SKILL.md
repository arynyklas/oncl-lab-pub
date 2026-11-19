---
name: release
description: Use when preparing or checking an OpenNCALayer release, an update-index PR or an index renewal. The agent prepares and verifies; it never signs.
---

# Release

Authoritative procedure: `docs/dev/release.md`. Read the section you need; do not work from memory.

## Hard limits

- Never create, use or ask for signing keys (minisign, TUF). The maintainer signs locally.
- Never run `cargo xtask sign` or `cargo xtask tuf update` with real keys, never push tags, never merge.
- Never hand-edit `updates/v1/*` or `tuf/v1/*`; never resolve a `seq` conflict by hand.
- Never upload to, replace assets of or delete a GitHub release. Releases are immutable once published, and a deleted release burns its tag (`docs/dev/release.md`, sections 1 and 5).

## Prepare the version bump (release.md, section 3, step 1)

1. Raise `[workspace.package].version` in `Cargo.toml`.
2. Raise every `version = "=<version>"` pin of the SDK chain in `[workspace.dependencies]`, the four built-in module `plugin.toml` files and the lock files (details: `docs/dev/sdk.md`, section 6).
3. `cargo check --workspace` to refresh `Cargo.lock`.
4. Run the checks: `cargo fmt -p <crate> --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo deny check`, `cargo xtask licenses --check`, `cargo xtask privacy`.
5. Move `CHANGELOG.md` entries from Unreleased into the new version section.
6. Commit as `chore(release): bump the version to <version>`.

## What the maintainer does next (do not do it)

Signed tag `v<version>` -> `release.yml` builds and opens an `updates/v<version>` PR with unsigned indexes -> maintainer runs `cargo xtask sign`, then `cargo xtask tuf update`, then `cargo xtask index check`, pushes, merges (sections 4, 7g).

## Verify an index PR (read-only)

```sh
cargo xtask index check updates/v1 --offline --base origin/main
cargo xtask tuf check --no-timestamp --base origin/main
```

Report failures verbatim. Missing `vm-smoke` or `conformance` statuses mean wait and re-run the check, not edit.

## Renewal and revocation

An index unchanged for 30 days must be renewed (`cargo xtask index refresh --channel <channel>`, section 5); a revoked version needs `"revoked": true` in every index that lists it (section 6). Both end in a maintainer-signed PR.
