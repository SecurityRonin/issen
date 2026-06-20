# Closing the LNK + Recycle-Bin Extraction Gap — Design Plan

_Status: DRAFT — **revised after Codex critique** (which flipped the recommendation) · 2026-06-20 · branch `real-oracle-corpus-catalog`_

## Executive Summary

On the real Szechuan Sauce DC+WS images, the `Lnk` and `Trash` (recycle-bin) parsers produce **0 events** despite being force-linked and despite `detect_artifact_type` classifying their files. Root cause: the disk-extraction list in `issen-disk` never pulls `.lnk` files or `$Recycle.Bin\<SID>\$I*` from the image, so the parsers are *dark* — built and reachable, but starved of bytes.

**Recommendation (revised): ship the targeted fix, not a big registry-derived refactor.** A first draft proposed deriving the extraction target set from `forensicnomicon::catalog` and unifying the two `ArtifactType` enums. **Codex review (verified against source) showed that premise is wrong:** `forensicnomicon::catalog::ArtifactType` is a **location-kind** enum (`RegistryKey, RegistryValue, File, Directory, EventLog, MemoryRegion, LiveResponse, DatabaseEntry, EseDatabase`) — *not* a semantic parser-artifact enum (`Lnk, Mft, Prefetch, …`). You cannot key parser extraction off it; `File` does not map to `Lnk`. So the refactor as drafted is dropped.

**What to build:**
1. **Bounded per-user `.lnk` sweeps** (Recent + Desktop) and **bounded `$Recycle.Bin\<SID>\$I*` extraction** in `issen-disk`, added to the existing triage path — closes the two gaps on real data.
2. **Hard extraction caps** enforced *during* enumeration/read (not after), to stay safe on attacker-crafted NTFS.
3. **A small local coverage test** proving extracted `.lnk` / `$I*` survive into fswalker classification and parser dispatch.
4. **(Optional, later)** if the duplicate "where artifacts live" list is still worth de-duplicating, build a **local Issen triage-location table keyed by `issen_core::ArtifactType`** (a new extraction-policy module/crate) — **not** keyed off forensicnomicon's location-kind enum, and **not** folded in fswalker (too late — see layering below).

This is the conservative scope: it recovers Loot.lnk/Secret.lnk targets and Beth's deleted `SECRET_beth.txt` `$I` record now, without a risky cross-crate enum unification.

---

## Problem statement

Three knowledge axes that must agree:

| Axis | Question | Where it lives | Dynamic? |
|---|---|---|---|
| Parse | "given bytes, what do they mean?" | parser registry (`inventory`, `supported_artifacts()`) | ✅ |
| Classify | "given a path, which artifact type?" | `issen_fswalker::orchestrator::detect_artifact_type` | ✅ |
| **Extract** | **"where on the image do those bytes live?"** | `issen-disk` static arrays | ❌ hand-typed |

The extract axis is hand-maintained and runs *first* (before any file exists to classify), so it needs a declared "where to look" map. The map omits `.lnk` and `$Recycle.Bin\<SID>\$I*` even though their parsers + classification are ready → dark parsers. The fix is to add those locations; the *optional* later step is to stop maintaining the map as a second source of truth — **but that de-duplication must be done locally (issen_core::ArtifactType), because forensicnomicon's catalog is a different semantic unit.**

### Evidence (real data, `/tmp/unified.duckdb`, 1.58 M events)
- `Lnk`: linked + classified (`orchestrator.rs:145`), **0 parsed events**; `.lnk` only as MFT/USN filenames (2,360 + 601).
- `Trash`: linked + classified (`orchestrator.rs:149-154`, gated on `$I` prefix under `$Recycle.Bin\<SID>`), **0 parsed events**.

---

## Current state (verified)

- `issen-disk/src/lib.rs:121` — `WINDOWS_TRIAGE_PATHS` (**13** fixed paths), `WINDOWS_TRIAGE_GLOBS` (2 `TriageGlob{dir,suffix}`, non-recursive), `WINDOWS_USER_FILES` (2 per-`\Users\<u>\` relative files), **and** `WINDOWS_TRIAGE_STREAMS` (`:182`, `:425`) — the USN journal is an **ADS** `\$Extend\$UsnJrnl:$J` pulled via `extract_named_streams`. **Any pattern model must preserve ADS, or USN extraction regresses.**
- Entry point: `triage_manifest(source, name) -> …` (`:204`) calls `extract_triage(source)` (`:210`). **Providers call `triage_manifest` directly** — `issen-ewf/src/lib.rs:210`, `issen-vmdk/src/lib.rs:125`. So extraction happens *inside the provider*, **below** fswalker — a fswalker-side fold cannot influence it.
- Extraction primitives: `extract_files`, `extract_dir_suffix`, `extract_per_subdir`, `extract_named_streams`. All read whole files into `Vec<u8>` and return `Vec<ExtractedFile>` (`:172`) — caps must be applied *before/during* read.
- `detect_artifact_type` classifies `.lnk` and `$I*` (**not** `$R*`) — so RecycleBin extraction targets `$I*` only; `$R*` (raw deleted content) is out of scope for the current parser.
- Two **unrelated** `ArtifactType` enums: `issen_core` (27, semantic, what parsers use) and `forensicnomicon::catalog` (9, location-kind). They are different concepts; do not unify.

---

## Design

### Step 1 — Add LNK + RecycleBin extraction (the value slice)

- **LNK**: per-user sweeps under each `\Users\<u>\` for `AppData\Roaming\Microsoft\Windows\Recent\*.lnk` and `Desktop\*.lnk`. Extend `WINDOWS_USER_FILES` semantics from "fixed relative file" to also allow a "relative dir + suffix" per-user sweep (new `WINDOWS_USER_GLOBS` or a small enum), reusing `extract_per_subdir` + suffix matching.
- **RecycleBin**: enumerate `\$Recycle.Bin\<SID>\` directories, extract entries whose basename starts with `$I` (matches `detect_artifact_type`). New primitive `extract_recycle_index` (SID-dir enumeration + `$I` prefix filter).
- **Do NOT extract `$R*`** (Codex: scope creep — the current parser only consumes `$I`; `$R` would sharply expand volume with no consumer).
- Keep these additive to the existing `WINDOWS_TRIAGE_PATHS/GLOBS/STREAMS/USER_FILES` — **no deletion** of the static arrays in this step (deleting them is the optional Step 4, and must preserve ADS).

### Step 2 — Hard extraction caps (Paranoid Gatekeeper; do alongside Step 1)

Caps enforced *during* enumeration and read, not after — current code reads whole files into `Vec<u8>`, so an attacker-crafted volume with millions of `Recent\*.lnk` or huge `$I` files is a memory bomb today. Required, all `const`-configurable with loud truncation reporting in the manifest/log (Show-the-value: log what was dropped + why):
- max files per pattern, max files global
- max bytes per file, max bytes per pattern + global
- max directory entries scanned per dir
- max recursion depth + cycle protection keyed by MFT record/reference number

### Step 3 — Coverage test (local, small)

An integration test that builds a synthetic NTFS volume with a `Recent\foo.lnk` and a `$Recycle.Bin\S-1-5-21-…\ $IABC.txt`, runs the disk pipeline, and asserts both survive into fswalker classification → parser dispatch (a `Lnk` event and a `Trash` event appear). This locks the extract→classify→parse chain end-to-end for these two types.

### Step 4 — (Optional, later) local triage-location table — de-duplicate the map

Only if the hand-maintained list is still worth removing as a second source of truth:
- A `issen_core` (or new `issen-triage-policy`) table keyed by **`issen_core::ArtifactType`** → `&[TriagePattern]`, where `TriagePattern` covers the shapes the **real** static arrays use today: exact file, dir+suffix, per-user dir+suffix, recycle-SID prefix, **and ADS `(path, stream)`** (must include this or regress USN).
- **Layering (corrected):** the derivation must happen **above the provider call**, since providers call `issen_disk::triage_manifest` directly. Options: (a) `triage_manifest`/`extract_triage` gain a `policy: &ExtractionPolicy` parameter that the *caller* (the layer that has the parser registry linked) supplies; providers thread it through. (b) Keep the policy a `const` in `issen-disk` derived at compile time from a table that lives in `issen-core` (issen-disk already deps issen-core) — simplest, no API churn, but the "filtered to registered parsers" part is dropped (extract everything in the table regardless of which parsers are linked — acceptable, since unlinked parsers just mean unused extracted files).
- A coverage gate ("every disk-sourced `issen_core::ArtifactType` with a registered parser has ≥1 `TriagePattern`, or is tagged memory/live-only") becomes meaningful only after this table exists.

---

## Phasing & TDD (strict RED → GREEN, separate signed commits)

1. **S2 caps first** (so S1's new sweeps are bounded from birth) — RED: a synthetic volume exceeding a cap; assert truncation + manifest note. GREEN: enforce caps in the extractors.
2. **S1 LNK** — RED: synthetic `Recent\foo.lnk` not extracted today; GREEN: per-user `.lnk` sweep. **S1 RecycleBin** — RED: synthetic `$IABC.txt` not extracted; GREEN: `$I` SID sweep.
3. **S3** end-to-end coverage test → then validate on **real DC+WS E01**: Loot.lnk/Secret.lnk targets parsed, `SECRET_beth.txt` `$I` recovered; reconcile against an **independent oracle** (TSK `fls` on `$Recycle.Bin`; LECmd/`lnkinfo` on the LNKs) per Doer-Checker.
4. **S4 (optional, separate PR)** local triage-location table + policy param + coverage gate.

## Out of scope (flagged)
- Unifying the two `ArtifactType` enums / keying off `forensicnomicon::catalog` — **dropped** (wrong premise).
- `$R` deleted-content carving (no current consumer).
- Broader LNK surface (Public Desktop, Start Menu\Programs, Office Recent, OneDrive redirection) — declare incrementally; not a glob engine.
- Runtime `--targets` (KAPE-style) override — later additive layer; attacker-influenceable-path trust boundary.
- Linux/macOS triage tables.

## Codex review — corrections incorporated
1. Dropped Phase 0 enum-unification (forensicnomicon `ArtifactType` is location-kind, not semantic). ✅ verified.
2. Layering fixed: providers call `triage_manifest` directly → derivation/policy must come from above, not a fswalker fold. ✅ verified (`issen-ewf:210`, `issen-vmdk:125`).
3. ADS preservation made explicit (`WINDOWS_TRIAGE_STREAMS` / `$UsnJrnl:$J`). ✅ verified.
4. Caps respecified as enforced-during-read mechanisms, not a slogan.
5. `$R` removed (parser consumes `$I` only). Fixed-path count corrected (13).
6. "Single source of truth" de-claimed — classification stays in `detect_artifact_type`, parsers keep `supported_artifacts()`.
**Verdict (Codex): do the targeted fix now; revisit the bigger refactor later, locally keyed.**
