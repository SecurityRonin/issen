# Registry-Driven Artifact Selector — Design

**Status:** approved design, not yet implemented
**Date:** 2026-06-20
**Issue:** issen #114 (dark-parser reachability)
**Decision:** Option 1 (selectors drive collection *and* classification), staged migration behind a differential safety-gate.

## Executive Summary

A parser produces timeline events only if **four independently hand-maintained surfaces agree**: inventory registration, force-link anchor, disk-image collection allow-list, and the path classifier. They drift silently, and a drifted parser produces **zero events — indistinguishable from "the artifact wasn't there,"** the worst failure mode for a forensic tool. This has bitten three times in sequence (`.lnk`, `$Recycle.Bin\$I`, `setupapi.dev.log`): each was registered, anchored, and classified, yet dark on raw disk-image ingest because the collection allow-list never pulled its bytes.

This design makes each parser **declare what it consumes in one place** — an `ArtifactSelector` on its `ParserRegistration` — and **derives** both classification and disk collection from that single registry. Adding a parser then wires it into every path automatically; "registered but not collected/classified" becomes structurally impossible rather than a recurring silent bug.

The selector is **multi-OS by construction**: a medium-agnostic matcher drives the loose-file walker and classification on any OS, while optional **filesystem-keyed disk sources** (`Ntfs` today; `Ext4`/`Apfs` dormant) describe how to pull the artifact off a raw image. The classifier (`detect_artifact_type`) is replaced, but only after a **differential test proves the registry-derived classifier agrees with the old one on a corpus of real paths**. Migration is staged so nothing is deleted blind.

Out of scope: building the ext4/APFS image extractors, wiring the DD/VHD/VHDX/QCOW2 providers to triage, and the rotated-`setupapi.dev.*.log` glob — all noted as follow-ups.

## Background — the drift the design removes

For a parser to emit events, four surfaces must currently agree:

| # | Surface | Where | Maintained |
|---|---|---|---|
| 1 | inventory registration | `inventory::submit!{ParserRegistration}` in each parser crate | auto |
| 2 | force-link anchor | `extern crate … as _;` in `crates/issen-cli/src/lib.rs` | hand (gated by `link_completeness.rs`) |
| 3 | disk-image collection | `extract_triage` + `WINDOWS_*` consts, `crates/issen-disk/src/lib.rs` | **hand, ungated until now** |
| 4 | classification | `detect_artifact_type`, `crates/issen-fswalker/src/orchestrator.rs:89` | hand (gated by `reachability_gate.rs`) |

Two collection paths exist and diverge: the **loose-file/UAC/KAPE walker** auto-classifies every walked file (≈14 types), while the **disk-image path** is a hand-maintained allow-list (≈8 types). A parser can pass surfaces 1, 2, and 4 and still be dark on a raw E01 because surface 3 never collected its bytes. `disk_collection_gate.rs` (added 2026-06-20) now fails CI on that specific drift, but it is a tripwire over a second source of truth, not a cure.

`ParserRegistration` today carries only `create: fn() -> Box<dyn ForensicParser>` (`crates/issen-core/src/plugin/registry.rs`). The path→artifact knowledge lives nowhere near the parser; it is re-encoded by hand in surfaces 3 and 4. That is the structural defect.

## The Design

### One declaration per parser

Each parser registers an `ArtifactSelector` alongside its constructor. The selector is the **single source of truth** for what the parser consumes:

```rust
// crates/issen-core/src/plugin/registry.rs
pub struct ParserRegistration {
    pub create: fn() -> Box<dyn ForensicParser>,
    pub selector: ArtifactSelector,            // NEW
}

pub struct ArtifactSelector {
    /// The type this parser produces — the routing label.
    pub artifact_type: ArtifactType,

    /// Medium-agnostic: does this path belong to this artifact?
    /// Drives the loose-file walker AND classification, on ANY OS / filesystem.
    /// A function (not just a glob) so nuanced rules stay faithful:
    ///   Lnk:     |p| ext_eq(p, "lnk")
    ///   Recycle: |p| name(p).starts_with("$i") && full(p).contains("$recycle.bin")
    ///   Pe:      |p| is_pe_ext(p) && in_suspicious_dir(p)
    pub matches: fn(&Path) -> bool,

    /// Precedence when >1 selector matches a path; higher wins. Replaces the
    /// implicit top-to-bottom order of the old detect_artifact_type if-ladder.
    pub priority: u8,

    /// How to pull this artifact off a RAW disk image, keyed by filesystem.
    /// Empty ⇒ collected ONLY via loose-file/UAC/KAPE ingest (no image
    /// extractor for its filesystem yet) — honest, not silently dark.
    pub disk_sources: &'static [DiskSource],

    /// Whether default triage collects it, or it is opt-in (e.g. PE carving).
    pub cost: CostTier,
}
```

### Two orthogonal dimensions: matcher vs. disk source

The earlier sketch said "NTFS disk-paths," which baked in a Windows assumption. Corrected, the selector separates two genuinely different questions:

- **What is this file?** → `matches` (medium-agnostic). Works identically on a Windows, Linux, or macOS file, wherever it came from. This is *why the Linux/macOS parsers already work on loose-file ingest* — the walker calls the matcher, not anything NTFS-specific.
- **Where on a raw image do I find it?** → `disk_sources` (filesystem-keyed). NTFS today; ext4/APFS are seams for later.

```rust
pub enum DiskSource {
    Ntfs(NtfsLoc),
    Ext4(PosixLoc),   // declared but dormant until an ext4 extractor exists
    Apfs(PosixLoc),   // declared but dormant until an APFS extractor exists
}

/// The NTFS collection shapes — one variant per existing extract_* primitive,
/// so the derived extractor is a thin dispatch over code we already trust.
pub enum NtfsLoc {
    FixedPath(&'static str),                         // extract_files
    DirSuffix { dir: &'static str, suffix: &'static str }, // extract_dir_suffix
    PerUserFile(&'static str),                       // extract_per_subdir over \Users
    PerSubdirSweep {                                 // extract_subdir_sweep
        parent: &'static str,
        rel: &'static str,
        name: NameMatch,                             // Suffix(".lnk") | Prefix("$i")
    },
    NamedStream { path: &'static str, stream: &'static str }, // extract_named_streams
}
```

A Linux parser then reads naturally — live on loose ingest now, image-ready the day an ext4 extractor lands:

```rust
ArtifactSelector {
    artifact_type: ArtifactType::LoginHistory,
    matches: |p| name_is(p, "auth.log") || name_starts(p, "auth.log."),
    priority: 50,
    disk_sources: &[DiskSource::Ext4(PosixLoc::FixedPath("/var/log/auth.log"))],
    cost: CostTier::Default,
}
```

### Derivation — both layers read the one registry

- **Classification** becomes `detect_from_registry(path)`: iterate registrations, keep those whose `matches` returns true, return the **highest-`priority`** one's `artifact_type`. The hand-written `detect_artifact_type` if-ladder is deleted; each arm's logic now lives in the parser that owns it.
- **Disk collection** becomes a loop in `extract_triage`: for each registration, for each `Ntfs(…)` source (respecting `cost`), dispatch to the matching existing `extract_*` primitive. The `WINDOWS_*` consts disappear; their content moves onto the parsers that need those files.

```rust
fn detect_from_registry(path: &Path) -> Option<ArtifactType> {
    all_registrations()
        .filter(|r| (r.selector.matches)(path))
        .max_by_key(|r| r.selector.priority)
        .map(|r| r.selector.artifact_type)
}
```

### Ordering — explicit priority, asserted no-collision

The current classifier resolves ambiguity by if-ladder order (e.g. `$MFT` is checked before generic Prefetch, recycle `$I` before PE). That implicit precedence is replaced by the explicit `priority` field **plus** a test asserting that, across the real-path corpus, **no two equal-priority selectors match the same path**. Genuine broad/narrow overlaps (recycle `$I*` must beat a PE `.scr` that happens to sit in a recycle bin) are expressed as a priority gap, documented at the selector.

## Migration plan — staged, nothing deleted blind

**Stage 0 — safety net (done, 2026-06-20).** `disk_collection_gate.rs` + the three collection fixes (`.lnk`, `$I`, `setupapi`). CI now fails on collection drift.

**Stage 1 — additive selectors.** Add `selector` to `ParserRegistration`; populate it for every parser. `detect_artifact_type` and `extract_triage` are **untouched** — the selectors exist but nothing reads them yet. Pure addition, no behavior change.

**Stage 2 — differential classifier.** Add `detect_from_registry` *beside* `detect_artifact_type`. A committed **real-path corpus** (paths sourced from the real Szechuan DC+WS images and the existing fixtures — LNK, recycle `$I`, setupapi, machine + per-user registry hives, Linux logs, PE-in-suspicious-path) drives a CI test asserting the two classifiers return **identical** results on every path. Any intended difference is annotated. Add the priority-collision assertion.

**Stage 3 — derived collection.** Rewrite `extract_triage` to loop the `Ntfs(…)` sources. `disk_collection_gate` stays green throughout and proves the derived collector ⊇ the old allow-list. Re-ingest the real Szechuan DC+WS and confirm per-source event counts are unchanged.

**Stage 4 — flip and delete.** Point the pipeline at `detect_from_registry`; delete `detect_artifact_type` and the `WINDOWS_*` consts only once Stages 2–3 are green. `reachability_gate`/`producer_coverage`/`disk_collection_gate` either become trivially-true (single source) or are repointed to assert the registry is internally consistent.

Each stage is independently shippable and TDD'd (RED/GREEN). The differential test in Stage 2 is the load-bearing safety mechanism — it is the thing that makes "delete the classifier" a verified step rather than a leap.

## Testing & validation

- **Differential classifier test** (Stage 2): old vs. new must agree on every corpus path; zero unintended diffs is the merge gate.
- **Priority-collision test**: no two equal-priority selectors match one corpus path.
- **`disk_collection_gate`** (kept through Stage 3): every classified NTFS artifact is collected.
- **Real-data end-to-end** (Doer-Checker): re-ingest the Szechuan DC + WS E01s after Stages 3 and 4; assert the per-source event counts (Mft/Registry/EventLog/Lnk/RecycleBin/Srum/Amcache/…) and Beth's `SECRET_beth.txt` `$I` recovery are unchanged from the pre-refactor baseline.
- **Existing suites** (`extract_user_artifacts`, the parser unit tests) stay green.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Classification regression when nuance moves into predicates | Differential corpus test (old≡new) before deleting `detect_artifact_type` |
| Ordering ambiguity (≥2 selectors match a path) | Explicit `priority` + no-equal-priority-collision assertion on the corpus |
| Selector bloat / unreadable registrations | Declarative `NtfsLoc`/`NameMatch` enums for the common shapes; `fn` predicates only for the nuanced arms (registry magic-byte fallback, PE suspicious-dir gating) |
| `fn`-pointer matchers aren't statically introspectable by the gate | Gates run the matcher over the real-path corpus (runtime), which is what we want anyway |
| Big-bang risk across ~30 parser crates | Staged; Stages 1–2 are additive and reversible; only Stage 4 removes code |

## Companion track — Parser Output Depth (systemic; same theme, separate execution)

The selector refactor above fixes **wiring** ("capability built, not surfaced" at the *routing* layer). Research on 2026-06-20 (14-parser survey, two anchors independently verified) found the **same disease one layer deeper, at the *output* layer**: a wrapper that *is* wired still surfaces only a fraction of the forensic richness its **owned core already parses**. This is **systemic, not LNK-specific** — **11 of 14** sampled wrappers are materially shallow; **MFT is the lone DEEP one**, proving it is a discipline gap, not a capability gap.

Verified anchors: `issen-parser-registry`'s base path calls only `registry_keys::walk_keys` against a **13-module** artifact crate; `issen-parser-srum` calls **2 of 7** table parsers; `issen-parser-biome` comments *"does not CRC-validate"* while `segb-core` exposes `crc_ok()`/`stored_crc32()`/`computed_crc32()` — **dropping tamper evidence**; `issen-parser-prefetch` keeps a run count where the core has all 8 run times + the loaded-file list; `issen-parser-lnk` (the trigger) drops target path, drive serial, UNC, and birth-droid NetBIOS.

These two tracks share the **capability-inventory theme** but **must execute separately**: the selector refactor's safety rests on a differential test (*same events out*), so changing *what* a parser emits cannot ride in the same step as changing *how* it is routed. Depth is its own phase, ordered by forensic value, landed **after or beside** the wiring refactor.

### The depth gate (sibling to the wiring gates)

`reachability_gate`/`disk_collection_gate` prove a parser is *reached*; nothing proves it surfaces its core's *richness*, so every dropped field is invisible — no error, no failing test, the parser looks done. That invisibility is why 11/14 drifted shallow. The fix is a **lightweight, declarative depth gate**, modeled on `reachability_gate` but asserting *capability surfaced*:

- Each parser declares a small **manifest of required output keys** it must surface (e.g. lnk ⊃ `{drive_serial, net_name, machine_netbios}`; prefetch ⊃ `{loaded_files: list, device_path}`; biome ⊃ `{crc_ok}`).
- One workspace test drives each parser over its **existing real-data fixture** (reuse the corpus the other gates use) and asserts every declared key appears in the emitted `TimelineEvent` metadata.
- The manifest is a curated, human-judged *minimum depth* — **not** an automated "emit every core field."

**Land the gate first declaring the current (shallow) state, then ratchet**: each depth backlog item adds its keys to the manifest as it ships, so the contract is visible and regression-proof — exactly how the wiring gates work.

**Over-engineering traps to avoid** (explicit): no generic reflection framework diffing core struct fields vs output (brittle, over-couples, forces low-value fields like MFT `sequence_number`); no percentage gate ("surface ≥70% of fields") — forensic value isn't uniform per field, a curated value-ranked allowlist beats a coverage ratio (coverage is a backstop, not a target).

### Depth backlog, ranked by forensic value

1. **registry (base) → wire the 13-module artifact catalog** (highest leverage; the *per-artifact* wrappers already call their decoders — this is the generic base path reducing everything to "key modified").
2. **lnk → drive serial + CommonNetworkRelativeLink + droid NetBIOS** (USB origin, network-exec, cross-machine provenance).
3. **biome → CRC validation + timestamp-order anomaly Findings** (anti-forensic evidence currently dropped).
4. **prefetch → all 8 run times + loaded-file list + device_path** (execution timeline + DLL-load evidence).
5. **amcache → size + version strings**; **6. userassist → focus_duration_ms**; **7. srum → 5 unused tables**; **8. shimcache → insertion_flags** (cached vs executed); **9. usnjrnl → security_id + source_info** (near-zero-cost, already parsed); **10. trash → $R content_path**.

(evtx = a wiring decision: depend on `winevt-forensic` for ATT&CK semantics. setupapi = small regex split for USB VID/PID/serial.)

## Explicitly out of scope (follow-ups)

- Building the **ext4 / APFS image extractors** — the `Ext4`/`Apfs` `DiskSource` variants are declared so Linux/macOS parsers can name their image location, but they stay dormant until those extractors exist. Until then those parsers remain loose-file-only — now *declared* as such, not silently dark.
- Wiring **DD/VHD/VHDX/QCOW2** providers to `triage_manifest` (they currently fail loud; wiring needs a real NTFS image per format to validate).
- The rotated **`setupapi.dev.*.log`** prefix-glob (a new `NtfsLoc` prefix variant).
