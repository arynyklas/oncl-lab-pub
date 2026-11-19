---
name: docs-style
description: Use when writing or editing any file under docs/ or README.md, CONTRIBUTING.md, CHANGELOG.md. Not for code comments.
---

# Docs style

User and developer docs are in Russian, for simple readers. Index of all docs: `docs/README.md`; add a line there for every new file.

## Shape

1. Title, then one or two sentences: who the page is for and what it lets them do.
2. The task first: steps or commands the reader needs. Background after.
3. One page, one purpose. Link to the authoritative page instead of copying it; links are relative.
4. Commands and paths go in code blocks and must exist in the repository. Check them against `xtask/src`, workflows and `Cargo.toml`; never invent a command.

## Words

- Plain words, short sentences, active voice. Explain a term at first use, in one clause.
- Name things by what the user sees (window titles, menu items), not by internal names.
- Say honestly what does not work.

## Never in docs

- Plan or task ids (`P12`, `MP6`, `G1`), phase names, status notes ("done", "in progress", "later").
- Release numbers of the form "since 0.1.x" unless behavior really depends on them; per-release history belongs in `CHANGELOG.md`.
- Owner or agent tags, session notes, names of private labs or hosts.
- Drive-letter paths, home directories, secrets, real certificates, recordings of the original. `cargo xtask privacy` rejects these.

## Check

Run `cargo xtask privacy`. Re-read the page as a newcomer: could they finish the task from this page alone?
