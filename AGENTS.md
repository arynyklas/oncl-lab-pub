# AGENTS.md

Rules for coding agents (and humans) working in this repository. Keep this file short; details live in `docs/dev/`.

## Overview

OpenNCALayer is an independent, Apache-2.0 replacement for NCALayer (Kazakhstan e-signature host). Sites talk to it over `wss://127.0.0.1:13579` exactly as to the original. It is not affiliated with НУЦ РК. The same engine is also an SDK (`oncl-core` and friends), a CLI (`oncl`) and an HTTP service (`oncl-server`).

Docs are in Russian and written for simple readers. Code, comments, commit messages, this file and `.agents/skills/` are in English.

## Crate map

| Crate | Role |
|---|---|
| `oncl-core` | Engine: protocol dispatch, key use, limits, plugin host |
| `oncl-protocol`, `oncl-ipc` | Wire protocol and IPC types (names shared with the browser extension) |
| `oncl-pki`, `oncl-gost`, `oncl-xml`, `oncl-pdf` | Certificates, CMS/CAdES, GOST crypto, XML and PDF signing |
| `oncl-token` | Hardware tokens (experimental) |
| `oncl-tls`, `oncl-trust` | Local TLS certificate and trust roots |
| `oncl-plugin`, `oncl-pdk`, `oncl-registry` | Plugin host (wasm), plugin SDK, plugin registry data |
| `oncl-flows`, `oncl-ui` | Signing windows and flows (Slint) |
| `oncl-update` | Update index and TUF client |
| `oncl-api`, `oncl-server`, `oncl-cli` | Library API, HTTP service, `oncl` command |
| `oncl-desktop`, `openncalayer`, `oncl-nmhost` | Desktop app, the main binary, browser native-messaging host |
| `oncl-builtin-*`, `oncl-builtins-build` | Built-in modules (wasm guests) and their build |
| `oncl-winget-setup`, `oncl-win7shim-*` | WinGet installer entry, Windows 7 shims |
| `oncl-testkit`, `oncl-builtin-tests`, `oncl-port-tests` | Test support and test suites |
| `xtask` | Every automation: `cargo xtask <command>` |

Rough dependency direction: `openncalayer`/`oncl-server`/`oncl-cli` -> `oncl-api`/`oncl-flows`/`oncl-ui` -> `oncl-core` -> `oncl-pki`/`oncl-gost`/`oncl-xml`/`oncl-pdf`/`oncl-plugin`.

## Directories

| Path | What |
|---|---|
| `crates/` | Workspace crates (above) |
| `xtask/` | `cargo xtask` commands and their tests |
| `plugins/` | Ports of original plugins; a separate workspace for `wasm32-unknown-unknown` |
| `extension/` | Browser extension |
| `web/` | Demo page |
| `site/` | Project site sources (Zola); built by `cargo xtask registry build` |
| `fixtures/` | Test data (`synthetic/` is invented, never real keys) |
| `updates/v1/`, `tuf/v1/` | Published update indexes and TUF repository |
| `deploy/` | Server deployment files |
| `docs/user`, `docs/dev`, `docs/design`, `docs/original` | Docs by audience; index in `docs/README.md` |
| `.github/` | Workflows, templates |

## Commands

```sh
cargo build --release -p openncalayer
cargo fmt -p <crate> --check            # NOT --all: format only the crates you touched
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo xtask licenses --check
cargo xtask privacy
cargo test -p <crate>
```

- Plugin ports have their own workspace: `cargo fmt --manifest-path plugins/Cargo.toml --all --check`.
- Changing `updates/` or `tuf/`: `cargo xtask index check updates/v1 --offline --base origin/main` and `cargo xtask tuf check --no-timestamp --base origin/main`.
- Run `cargo xtask privacy` before every push. It rejects drive-letter paths, recorder transcripts and test-CA certificates in code, docs and commit messages.

## Test prerequisites

`cargo test` fails (does not skip) when an independent checker is missing: `openssl` 3 in `PATH`, and the Python oracle venv `.venv-oracle` exported as `ONCL_PYHANKO_PYTHON`. Test data: `cargo xtask fetch-fixtures`. Exact steps: `docs/dev/development.md`, section "Что нужно для тестов".

## Security invariants

- Never generate, replace, rotate or commit signing keys. Secret keys never go into the repository or CI (the single exception is the TUF `timestamp` key held as a GitHub secret). Do not edit `crates/oncl-update/keys/`.
- `updates/v1/*` and `tuf/v1/*` are owner-signed. Never edit, re-sign or "fix" them by hand; an index change comes only from the release workflow plus the maintainer's signature (`docs/dev/release.md`). Do not resolve `seq` conflicts manually.
- Forked dependencies are pinned by full `rev` in the root `Cargo.toml`. Fork branches are never rewritten; a change is a new commit and a new `rev` (`docs/dev/development.md`, "Форки сторонних крейтов").
- Secret input (keys, passwords) is wiped; never log or persist it. GOST hashing of secrets (VKO shared point, KDF keys) goes through the secret-input Streebog/HMAC of `oncl-gost` (`streebog_secret.rs`, `secret_hmac.rs`), never through the public `streebog`/`hmac`.
- Do not change test expectations, fixtures or `expected` files only to make a test pass. State the failure mode first.
- Never publish recordings of the original, private paths, hostnames or real certificates.

## Generated files: edit the input, not the output

| File | Regenerate with |
|---|---|
| `crates/oncl-core/THIRD-PARTY.txt`, `crates/oncl-ui/assets/THIRD-PARTY.txt` | `cargo xtask licenses` |
| `plugins/THIRD-PARTY.txt` | `cargo xtask licenses --plugins` |
| `fixtures/synthetic/*` | `cargo xtask gen-fixtures` |
| `extension/src/host.js` (untracked) | `cargo xtask ext build` |
| `updates/v1/*.json`, `*.minisig`, `tuf/v1/**` | release workflow and maintainer signing only |
| `target/**` | build output |

## Conventions

- Conventional Commits: `feat(oncl-update): ...`, `fix(oncl-pki): ...`, `docs: ...`, `chore(updates): ...`. One logical change per commit and per PR.
- Commits and tags are signed. Never force-push; never rewrite published history.
- Do not commit, push, open PRs or post issue comments unless asked.
- Behavior change visible to users: update `docs/user/` (or `docs/dev/`, `docs/design/`) and add a line to `CHANGELOG.md` under Unreleased.
- Docs: Russian, simple words, task first. See `.agents/skills/docs-style/SKILL.md`.
- Tests name a real failure mode; no tests that grep source text.

## Skills

`.agents/skills/release`, `.agents/skills/plugin-port`, `.agents/skills/docs-style`.
