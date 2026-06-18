# Fleet Task Status — Living Tracker

The single living answer to "what's left to do" across the Issen forensic fleet.
Strategy lives in [`north-star-advisor/docs/ACTION_ROADMAP.md`](../../north-star-advisor/docs/ACTION_ROADMAP.md)
(30/60/90-day "report-engine-first" plan); **this file tracks the tactical
backlog and in-flight work underneath it.**

> **How to update:** when you finish a unit of work, move it to *Recently
> Completed* with its commit SHA(s) + repo; when you pick something up, move it
> to *In Flight*. Keep it short — one line per item. Last reviewed: **2026-06-18**.

Legend: ✅ done · 🔧 in flight · ⬜ backlog · 🚩 flagged issue/decision

---

## In Flight

_(nothing actively in progress — pick the next item from the backlog below)_

---

## Recently Completed (verified + pushed)

| Date | Repo | Work | Commits |
|---|---|---|---|
| 2026-06-18 | forensicnomicon | Paranoid Gatekeeper lint migration (clippy `--workspace` 0/0; 20 prod unwrap/expect remediated; ~3100 tests green) | `7ff50cb`→`c1e9ab6` |
| 2026-06-18 | forensicnomicon | CI test job widened to `--workspace`; 4 live-network fetch tests `#[ignore]`d (deterministic) | `fda01bd` |
| 2026-06-18 | issen | **#115** warm-resume parse-skip optimization (cold 7.36s → warm 0.20s; validated on Collection-A380) | `285f753`→`b61f844` |
| 2026-06-18 | issen | Velociraptor collection ingest fix — `CollectionManifest` tempdir use-after-free in `run_auto_units` (was: 0 artifacts parsed) | `4d3c3a8`→`7c30c9b` |
| 2026-06-18 | issen | **#114** producer-coverage gate (every classified `ArtifactType` has a producing parser) | `0457f25` |
| 2026-06-18 | issen | **#114** wire LNK trait `parse()` — removed the `lnk` dark parser (machinery existed, trait was a stub) | `1fa4d11`→`175ca20` |
| 2026-06-18 | issen | **#114** dark-parser gate — static check flags any `parse()` that ignores its emitter; caught 3 dark parsers (incl. one I'd dismissed) | `f250de5`→`d5022f3` |
| 2026-06-18 | issen | **#114** wire SetupAPI trait `parse()` — removed the `setupapi` dark parser (the third the gate caught) | `a42244d`→`b212545` |
| 2026-06-18 | issen | **#109** issen-cli clippy greening (510→0 errors; pragmatic-allow config) | `5af7d86`, `ae8cce5`, `04b9888` |

---

## Tactical Backlog — issen

- ✅ **#114 dark parsers — DONE:** all registered parsers wired (`dark_parser_gate` allowlist EMPTY), every advertised type reachable (`reachability_gate` GREEN), setupapi retyped to `DeviceInstall`. Real-data validated (auth.log 519, lnk 3, setupapi 1). Remaining #114 sub-items: **CoverageManifest** + **catalog-driven discovery** (forensic knowledge → `forensicnomicon`).
- 🚩 `issen-parser-setupapi` pre-existing clippy debt (2 test `result.unwrap()` + a `fn name` literal-bound) — trivial, flagged during the #114 wiring, not folded in.
- ⬜ **#112** de-specialize over-fit temporal correlation rules — needs Case-001 validation/judgment (rules look well-built but unverified).
- ⬜ **#110** unified timeline P3/P4.
- ⬜ **#37** correlate capstone — open tail: brute-force join-key false-positive (see [[project_correlate_realdata_validation]]).
- ⬜ **#70** fleet reorg.
- 🚩 timestomp detector is deliberately an **Info lead** (`$SI<$FN` FP-prone) — layered redesign staged, not a bug.

---

## Fleet-Wide Debt

- ⬜ **#109 CI greening — sibling repos still red/with debt:** `srum-forensic`, `ext4fs-forensic`, `4n6mount`, `winevt-forensic`. (issen + forensicnomicon now green.)
- ✅ **Docs → MkDocs — DONE (CLAUDE.md note was stale, verified 2026-06-18):** all four (`forensicnomicon`, `memory-forensic`, `winevt-forensic`, `srum-forensic`) already have `mkdocs.yml` + `mkdocs build` deploy workflows; forensicnomicon footer links verified **live** (HTTP 200, real content). No migration work left.
- 🚩 forensicnomicon CI **test** job MSRV-1.75 stays root-only on purpose (the unpublished `ingest`/`4n6query` bins pull deps above 1.75); MSRV is a *library* guarantee.

---

## Design Tasks (larger refactors)

### ⬜ Two-axis artifact model — `SourceType` + `ForensicCategory` (issen #NEW)

**Problem.** `ArtifactType` (issen-core/artifacts/types.rs) conflates two orthogonal axes:
1. **Source / format** — *which parser reads this file* (routing). A registry hive ≠ a setupapi text log ≠ an evtx. `detect_artifact_type` needs this.
2. **Forensic semantic** — *what the evidence means* (a category that **spans many sources**).

The enum already mixes them: `Registry`/`Prefetch`/`Mft`/`Lnk` are *sources*, but `LoginHistory`/`SystemInfo`/`CrontabConfig`/`DeviceInstall` are *semantics*. Symptoms:
- **Cross-feeding:** `auth.log` and `.bash_history` both route to *both* parsers because they share the `LoginHistory` type (coarse routing). Same for syslog/macos sharing `SystemInfo`.
- **Can't express cross-source evidence:** "device-install" comes from setupapi.dev.log **and** registry `USBSTOR`/`MountedDevices` **and** EVTX — but `DeviceInstall` is pinned to one parser. (This is the flaw that surfaced when setupapi was retyped: a semantic name was given to a routing type.)

**Design — split the axes:**
- **`SourceType`** (routing): file/format → its parser, source-specific (`RegistryHive`, `SetupApiLog`, `AuthLog`, `Syslog`, `BashHistory`, `Evtx`, `Prefetch`, `Mft`, `Lnk`, `UsnJournal`, `Srum`, `Amcache`, …). `detect_artifact_type` returns this; a parser declares the exact source it consumes → **precise routing, no cross-feed**.
- **`ForensicCategory`** (semantic, cross-source): `DeviceInstall`, `LoginActivity`, `Execution`, `Persistence`, `NetworkActivity`, `ScheduledTask`, … carried by **each emitted `TimelineEvent`**. Correlation + the report group by **this** → "all device-install evidence regardless of source" becomes a category query. (Precedent: `forensicnomicon::report::Category` is a sibling semantic axis.)

> **Knowledge placement (binding):** `ForensicCategory` and the artifact→category mapping ("which artifact answers LoginActivity/Execution") are **forensic knowledge → they live in `forensicnomicon`**, never in issen-core/issen. issen depends DOWN on forensicnomicon and consumes them. Only the *routing* type (`SourceType`/`ArtifactType` — which parser reads a file) is issen plumbing.

**Migration plan (phased, TDD per phase):**
1. ✅ **Add `ForensicCategory`** — done **in `forensicnomicon`** (v0.5.6, commits `1e7c342`→`4bf8982`). **Grounded in prior art, not invented:** a documented synthesis of **SANS "Evidence of…"** (FOR500), **Plaso** tags (cross-platform precedent), and **MITRE ATT&CK** tactics (`attack_tactic()` for the adversarial overlap; `None` for benign — it's a superset of ATT&CK). 16 variants + stable `code()`/`from_code()` (the serialization contract a future **CASE/UCO** *export* layer maps to UCO `Action`/`Observable`). `FileSystemActivity` kept **unified** (observed activity, not SANS's inferred open/download/delete split). Next: the artifact→category mapping (also forensicnomicon knowledge — derive from the catalog's `mitre_techniques`). issen consumes it after publish.
2. **Rename `ArtifactType` → `SourceType`**; split the semantic variants into real sources: `LoginHistory`→{`AuthLog`,`BashHistory`,`Wtmp`,…}; `SystemInfo`→{`Syslog`,`MacosUnifiedLog`,`FsEvents`}; `CrontabConfig`→`CronLog`; `DeviceInstall`→`SetupApiLog`.
3. **`detect_artifact_type` → returns `SourceType`** (one file → one precise source → one parser; no cross-feed). Update the per-source classification.
4. **Each parser:** `supported_artifacts` → the specific `SourceType`(s) it reads; tag emitted events with `ForensicCategory`.
5. **`TimelineEvent`:** add a `category: ForensicCategory` (or `Vec<>`); persist + index it.
6. **Correlation + report:** group/pivot by category (cross-source), not by source.
7. **Gates:** update `producer_coverage` / `reachability_gate` / `dark_parser_gate` to the two-axis model; the reachability gate's current **type-level blind spot** (a parser advertising a classified type whose files aren't its real input — how setupapi slipped through) disappears once routing is source-exact.

**Scope/risk:** touches the core enum, every `issen-parser-*`, `detect_artifact_type`, the timeline schema, correlation, the report, and all three gates. Large — do it phased, not as a drive-by. **Benefits:** exact routing (no cross-feed), cross-source semantic queries, cleaner correlation/reporting, and `DeviceInstall`-as-category done right.

---

## Strategic (pointer, not tracked here)

`ACTION_ROADMAP.md` — report-engine-first: issen-core/pipeline foundation →
issen-timeline query engine → issen-report HTML MVP → MFT/EventLog parsers →
DOCX reports → intel + community. Recent tactical work is hardening *underneath*
this, not on its critical path.
