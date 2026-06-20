# One Code Path, One Parser-Anchor Source — Design Plan

_Status: DRAFT — **revised after Codex critique** · 2026-06-20 · branch `real-oracle-corpus-catalog`_

## Executive Summary

`issen-cli` builds **two artifacts from two module trees that are compiled separately**: the binary (`main.rs`, 673 lines: the `Cli`, the dispatch `match`, and a 27-line `extern crate … as _;` force-link list) and the library (`lib.rs`, 68 lines). Both **re-declare the same modules** — `mod commands; mod parsers; mod scanning;` appear in main.rs **and** `pub mod …` in lib.rs — so those modules are compiled **twice**, into two artifacts each with its **own `inventory` parser registry**. That duplicated code path is a DRY violation and is the direct cause of the registry divergence the supertimeline bug exposed: the binary's registry had 27 parsers, the library's had 1.

**This plan kills the duplication in two stacked moves:**

1. **Collapse `main.rs` into a thin shim over `lib.rs`** (the DRY fix). The CLI logic and the force-link anchors move into the library; `main.rs` becomes a few lines that call `issen_cli::run()`. This removes the **duplicate `commands/parsers/scanning` module tree** (compiled once into the binary, once into the library) and the duplicate anchor list — the `issen` binary now executes *through* the library artifact, so the binary and the library share one compilation and one anchor set.
2. **Replace the remaining force-link lists with aggregator crates whose `build.rs` generates the anchors from their own `Cargo.toml` dependencies.** Adding a parser/provider becomes **one action** — add it as a dependency of the aggregator — and every artifact that links `issen_cli` gets it. **Zero hand-written `extern crate` lines.**

Plus a **drift gate** that counts parser *registrations* (not crates — several crates register multiple parsers) so a dependency that is not anchored fails CI instead of silently vanishing.

**Precise claim (per Codex review — see below).** `inventory` is collected **per final linked artifact** (the binary, *and each test executable*), not once globally. So "one registry" is not literally true and "structurally impossible" is too strong. What this plan actually guarantees: *every* artifact that links `issen_cli` sees the complete set **iff** the anchor chain is real and unbroken — `issen_cli`'s `lib.rs` carries a real `extern crate issen_parsers as _;` (and `…issen_providers…`), each aggregator's generated `lib.rs` carries a real `extern crate issen_parser_x as _;` per dep, and `main.rs` links `issen_cli`. The win is that this chain lives in **one** place and the duplicate module tree (the actual cause of the supertimeline skew) is gone — not that Rust stops collecting per-artifact.

> Note: the supertimeline subagent's pending fix (mirror the 27 lines into `lib.rs`) is a **stopgap that this plan supersedes** — with a thin-shim `main`, the list exists once and is never mirrored. Recommend NOT integrating that stopgap; land Move 1 instead.

---

## Problem statement

Rust statically links and dead-code-eliminates: an `inventory::submit!` registration survives only if its crate is linked, and a crate is linked only if something references it. Hence the `extern crate issen_parser_X as _;` **link anchors**. Two failure modes today:

1. **Duplicate module tree → divergent per-artifact link sets (DRY violation).** `commands/parsers/scanning` are compiled into the binary (via `main.rs`'s `mod`) *and* into the library (via `lib.rs`'s `pub mod`). There are not "two registries inside one executable" — rather, the binary, the library's unit-test executable, and each integration-test executable are **separate final artifacts, each with its own linked `inventory` section** populated by whatever anchors its link set pulled in. The anchor list was complete in `main.rs` (so the binary + `cargo_bin` tests were fine) but length-1 in `lib.rs` (so library-linked harnesses — lib unit tests, `tests/*.rs` using `use issen_cli`, external callers — saw an incomplete set). *This is the supertimeline bug.*
2. **Hand-maintained anchor list.** Even within one artifact, the 27 `extern crate` lines are typed by hand; forgetting one makes that parser silently disappear from `all_parsers()` despite being a Cargo dependency.

---

## Current state (verified)

- `main.rs:7-9` — `mod commands; mod parsers; mod scanning;` (binary's own tree). `main.rs:469` `fn main() -> ExitCode` with the full `Cli`/dispatch. `main.rs:12-43` — 27 `extern crate issen_parser_* as _;`.
- `lib.rs:45` — `extern crate issen_parser_registry as _;` (only **1**). `lib.rs:47-49` — `pub mod commands; pub mod parsers; pub mod scanning;` (same modules again).
- Registry: `issen-core::plugin::registry` — `inventory::collect!(ParserRegistration)`, `all_parsers()` = `inventory::iter`.
- No aggregator crate; all 27 parser deps sit in `issen-cli/Cargo.toml`.

---

## Design

### Move 1 — Thin-shim `main`, single code path (the DRY fix; do this first)

- Move the `Cli`/`Commands` definitions and the dispatch `match` from `main.rs` into `lib.rs`. **Split the entry points** (per Codex): `pub fn run() -> ExitCode` does one-time process setup (tracing init, parse `std::env::args`) then calls `pub fn run_with_args<I>(args: I) -> ExitCode` / `pub fn dispatch(cli: Cli) -> ExitCode`, which tests can call directly without re-doing process setup. Module declarations live **once** in `lib.rs` (`pub mod commands; pub mod parsers; pub mod scanning;`).
- `main.rs` shrinks to:
  ```rust
  fn main() -> std::process::ExitCode { issen_cli::run() }
  ```
- The force-link anchors move to `lib.rs` (temporarily — Move 2 replaces them with the aggregators). `main.rs` keeps **none** (it links the library, which carries them).
- **Tracing:** use `tracing_subscriber::fmt().try_init()` (not `.init()`, which **panics** if a global subscriber already exists — e.g. `run()`/`dispatch()` invoked twice in one test process). Keep tracing init in `run()` only, never in `dispatch()`.
- **Outcome:** binary and library share one compilation of `commands/parsers/scanning` and one anchor set; the library-linked harness no longer diverges from the binary. (Each test executable still has its own link set — see the precise claim above — but they now anchor through the *same* library code.)
- `Cli` fields can stay **private** (Clap does not require `pub` unless an external test constructs `Cli` directly); expose `dispatch(cli)` for tests instead.
- Risk: `main.rs`'s `#[cfg(test)] mod tests` (line 664) moves with the code it tests (into `lib.rs`) or becomes a `tests/*.rs` integration test against `issen_cli::dispatch`.

### Move 2 — aggregator crate(s) + `build.rs` codegen (zero hand-written anchors)

**Two categories of inventory, not one (per Codex).** `main.rs` force-links not only the 27 **parser** crates but also 7 **container/provider** crates — `issen_dd, issen_ewf, issen_iso, issen_qcow2, issen_vhd, issen_vhdx, issen_vmdk` (main.rs:46-52), which register *provider* inventory. Anchoring only parsers would silently break provider collection. So either two umbrellas (`issen-parsers` + `issen-providers`) or one umbrella with explicit categories. **Recommend two** (clean separation; each gates its own category).

- Each aggregator (Pattern-B umbrella, `publish = false`, **not itself a parser/provider**) lists its category's crates as `Cargo.toml` dependencies.
- Its `build.rs` reads **its own manifest** — prefer parsing `CARGO_MANIFEST_DIR/Cargo.toml` with the `toml` crate and selecting **direct normal deps** matching the `issen-parser-*` / provider names — and generates `anchors.rs` = one **real** `extern crate <dep> as _;` per dep into `OUT_DIR`; the aggregator's `lib.rs` does `include!(concat!(env!("OUT_DIR"), "/anchors.rs"));`.
  - Decision (per Codex): **prefer direct manifest parsing over `cargo_metadata`.** `cargo_metadata` from a build script observes the whole resolved graph and is easy to mis-filter (it would anchor *transitive* parser crates); if used, it MUST filter to the aggregator package's direct, normal (non-dev/build) deps by package id.
- **The root anchor is mandatory and explicit (per Codex):** `issen-cli/lib.rs` MUST contain a real `extern crate issen_parsers as _;` **and** `extern crate issen_providers as _;`. A bare `Cargo.toml` dependency or a passive `pub use` does **not** guarantee the link edge — the anchor must be a real item reference in a linked path.
- `issen-cli` drops its 27+7 force-links and the per-parser deps (now transitive via the aggregators), keeping only the two aggregator deps + the two root anchors.
- **Outcome:** each **aggregator's `Cargo.toml` dependency list is the single source of truth** for its category. Add a parser → add one dep to `issen-parsers` → build regenerates the anchor → every `issen_cli`-linking artifact sees it.

### Move 3 — Drift gate (count registrations, not crates)

- **A crate-count gate is wrong (per Codex, verified):** `issen-parser-linux` has **4** `inventory::submit!`s and `issen-parser-macos` has **2** — so `all_parsers().len() == <crate count>` would false-fail and pressure hiding legitimate multi-registrations. Instead, gate on one of:
  - **registration set**: assert the live `all_parsers()` parser *names* (or `(name, supported_artifacts)` pairs) are a superset of an expected list generated alongside `anchors.rs`; or
  - **anchor completeness**: assert every direct `issen-parser-*` dep of the aggregator appears as a real `extern crate … as _;` in the generated `anchors.rs`, plus a runtime smoke check (`all_parsers()` non-empty and contains known multi-registration names like the linux history/auth/cron/syslog set).
- Update/replace the **source-scraping gates** that assume anchors live under `issen-cli/src`: `tests/link_completeness.rs` (`collect_src_text` over `issen-cli/src`, manifest_dir/`src`) must instead scan the aggregator's generated `anchors.rs` / its manifest, or it becomes meaningless. Same audit for `reachability_gate.rs`/`producer_coverage.rs`.

---

## Phasing & TDD (strict RED → GREEN, separate signed commits)

1. **M1 RED**: a library-linked test asserting `issen_cli::run`-reachable registry == binary registry (or simply: `all_parsers()` from a `use issen_cli` context returns the full set). Fails today.
   **M1 GREEN**: collapse `main.rs` → shim; move logic + force-links into `lib.rs`. Verify `issen --help`, `issen ingest` smoke unchanged; full `cargo test -p issen-cli` green; `Command::cargo_bin` tests still pass.
2. **M2 RED**: add `issen-parsers` with build.rs but anchor only a subset → drift gate fails. **M2 GREEN**: build.rs emits all anchors from deps; `issen-cli` switches to the aggregator; delete the 27 lines.
3. **M3**: finalize the count/drift gate; document "add a parser = add one dep to `issen-parsers`."

## Validation (Doer-Checker)
- After M1: `cargo test -p issen-cli` (lib + integration) green; `issen ingest <dir>` on a real `$J` still produces events (binary path unchanged).
- After M2: add a throwaway parser dep, confirm it appears in `all_parsers()` **without** touching any `.rs` force-link line; remove it; confirm the gate would have caught its omission.
- `cargo build --release` produces one static binary; `cargo install --path crates/issen-cli` still works (no cdylib/plugin dir).

## Trade-offs considered (and rejected for the default path)
- **Dynamic `cdylib` + `libloading` plugins** (true runtime discovery): breaks single-static-binary/`cargo install`, adds ABI-stability + version-skew hazards, and `dlopen`ing an attacker-supplied `.so` on an evidence workstation is arbitrary code execution. Rejected for the shipping default; could be a future opt-in `--plugin-dir` for research only.
- **Leaving two code paths and just syncing the lists** (the supertimeline stopgap): perpetuates the DRY violation; a future divergence is one forgotten edit away.

## Codex review — corrections incorporated
1. Softened "structurally impossible"/"binary is the library" → precise per-artifact link-set claim + the required anchor chain. ✅
2. Added the **container/provider** anchors (`issen_dd/ewf/iso/qcow2/vhd/vhdx/vmdk`, main.rs:46-52) — a second `issen-providers` aggregator. ✅ verified.
3. Made the root anchor explicit and mandatory (`issen-cli/lib.rs` must `extern crate issen_parsers as _;`). ✅
4. Drift gate counts **registrations, not crates** (`issen-parser-linux`=4, `-macos`=2). ✅ verified.
5. `try_init()` for tracing + `run()`/`run_with_args()`/`dispatch()` split. ✅
6. Flagged source-scraping gates (`link_completeness.rs` scans `issen-cli/src`) for rewrite. ✅ verified.
7. Prefer manifest-`toml` parse over `cargo_metadata` (avoids anchoring transitive crates).

## Open questions for review
1. Move 1 scope: is `pub fn run()` the right public surface, or expose `Cli`/`dispatch` too (for embedders/tests)? Minimal surface preferred (YAGNI).
2. Move 2: `cargo_metadata` build-dep vs manifest-text parse — accept the build-dep?
3. Naming: `issen-parsers` aggregator crate (Pattern-B umbrella; `publish = false` since it's internal wiring, not a reusable library)?
4. Sequencing vs the extraction plan (`2026-06-20-registry-derived-extraction-design.md`): independent; either order. M1 is the highest value-per-effort (kills the live supertimeline-class bug).
