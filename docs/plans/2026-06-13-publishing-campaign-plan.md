# Publishing Campaign Plan (#71) — registry-ize issen's cross-repo deps

**Date:** 2026-06-13 · **Status:** PLAN (no crate published yet) · **Gate:** every
`cargo publish` is **irreversible** (no unpublish, no version reuse) — execute only
on an explicit per-batch go.

## Scope

issen path-deps ~24 crates across **8 fleet repos**. Goal: publish each to
crates.io and switch issen's `path = "../x"` deps to
`{ version = "…", package = "x-core" }` (registry), so issen builds reproducibly
without the sibling checkouts. (`issen-core` is an internal workspace member —
not in scope.)

## Publish status (crates.io, 2026-06-13)

| Crate | On crates.io | Repo |
|---|---|---|
| forensicnomicon | **0.4.2** (local 0.4.3 unpublished — adds `decmpfs`) | forensicnomicon |
| disk-forensic | **0.4.0** | disk-forensic |
| aff4-core, dd-core, vhd-core | UNPUBLISHED | aff4, dd, vhd |
| winreg-core, winreg-artifacts | UNPUBLISHED | winreg-forensic |
| winevt-core, winevt-extract, winevt-analysis | UNPUBLISHED | winevt-forensic |
| srum-core, srum-parser | UNPUBLISHED | srum-forensic |
| browser-core, browser-{chrome,firefox,safari} | UNPUBLISHED | browser-forensic |
| memf-core/format/symbols/windows/linux/correlate/strings, forensic-hashdb | UNPUBLISHED | **memory-forensic (BLOCKED)** |

## Publish order (leaf-first — a crate publishes only after every dep it needs is on the registry)

1. **forensicnomicon 0.4.3** — the KNOWLEDGE leaf; everything depends down onto it. (Republish: adds the `decmpfs` module from the hfsplus work.)
2. **Reader `*-core` crates** (depend only on forensicnomicon): aff4-core, dd-core, vhd-core, winreg-core, winevt-core, winevt-extract, srum-core, browser-core. (ntfs-core/ewf already published per fleet status.)
3. **Analyzer / higher crates** (depend on their core): winreg-artifacts, winevt-analysis, srum-parser, browser-{chrome,firefox,safari}.
4. **memory-forensic crates** — forensic-hashdb → memf-core → memf-format/symbols → memf-windows/linux/correlate/strings. **BLOCKED** (see below).
5. **disk-forensic** (bump; depends on the container cores).
6. **issen** — switch all path-deps to registry, bump, last.

## Blockers / preconditions (must clear before publishing)

- **memory-forensic working tree is DIRTY** (~63 files of uncommitted WIP that is **not mine to commit**). The 8 memf/forensic-hashdb crates **cannot be published** until its owner commits/stashes that tree. Publishing over uncommitted WIP would ship an unreviewed, non-reproducible state.
- **Per-repo publish-readiness**, verified the *real* way (the `rtk` clippy wrapper HIDES `-D warnings` errors — see `feedback_rtk_clippy_masks_warnings` memory): for each repo run `rtk proxy cargo clippy --workspace --all-targets -- -D warnings; echo $?` (must be 0), `cargo test`, `cargo publish --dry-run`, version bump, README/docs current. Several repos likely carry hidden clippy debt that `--dry-run` won't catch but the repo standard requires.
- **Name mapping**: bare names taken by third parties publish as `x-core` with `[lib] name = "x"` (import path unchanged). Confirm each crate's published name before switching issen's `package = "…"`.
- **Irreversibility**: confirm the exact `(crate, version)` list per batch before running `cargo publish`. crates.io versions can never be reused or unpublished.

## Recommended execution (when unblocked + confirmed)

Batch 1 (no memf, no blockers): forensicnomicon 0.4.3 → the non-memf `*-core`
readers → their analyzers → switch issen's non-memf path-deps to registry. This
de-risks ~16 of the 24 deps without touching the blocked memory-forensic tree.
Batch 2 (after the memf tree is committed by its owner): the 8 memf crates →
switch issen's memf path-deps. Batch 3: disk-forensic + issen final bump.

**This document is the plan only. No crate is published until each batch is
explicitly confirmed.**
