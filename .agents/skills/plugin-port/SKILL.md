---
name: plugin-port
description: Use when adding or changing a port of an original NCALayer plugin under plugins/<short>. Not for built-in modules or the plugin host.
---

# Plugin port

Authoritative text: `docs/design/plugins.md`, section "Порты". Ports live in `plugins/`, a separate workspace for `wasm32-unknown-unknown`.

## Add a port

1. Create `plugins/<short>` (the name must not start with `c`: that is how the workspace tells ports from `common/`).
2. `plugin.toml`: `id = io.github.arynyklas.openncalayer.port.<short>`, the `module` names served, `[replaces]` with the original's `symname` and bundle version, only the capabilities the port needs.
3. `registry.toml`: `id` and `modules` equal to `plugin.toml`; `[original]` `symname`, `version`, `vendor`; `[port]` `status` (`full`, `partial`, `needs-tokens`) and `conformance` (`computed` or `confirmed`); `[[differences]]` with a `ru` text for each deviation from the original. Unknown keys are errors.
4. Sources: crate `oncl-port-<short>`; shared code goes to `plugins/common/{kit,legacy,pki}`.
5. Tests: add them to `crates/oncl-port-tests`, with hand-written expectations on synthetic values.
6. New dependencies: `cargo xtask licenses --plugins`.

## Rules for behavior

- Keep what the page sees: answer shape, error codes and texts, order of checks, field order (including Java `HashMap` order), bytes of signatures and requests.
- Fix what is unsafe or depends on state outside the sandbox: no SHA-1 signatures, HTTPS only with certificate checks and manifest addresses, no secrets stored or written, no original settings or caches read.
- Tokens only through the experimental support.
- Never copy recordings of the original, serials or test-certificate names into the repository.

## Check

```sh
cargo xtask plugin pack plugins/<short>
cargo xtask registry build          # fails if any registry.toml breaks the schema
cargo xtask plugin-version-check
cargo fmt --manifest-path plugins/Cargo.toml --all --check
cargo xtask privacy
```

`conformance = "confirmed"` is only for a port checked against the working original; a `computed` port cannot enter the `stable` channel.
