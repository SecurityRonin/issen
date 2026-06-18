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

### ⬜ Two-axis artifact model — keep `ArtifactType` (routing) + add `ActivityCategory` (CADET, meaning) (issen #NEW)

**Problem.** `ArtifactType` (issen-core/artifacts/types.rs) conflates two orthogonal axes:
1. **Artifact / format** — *which parser reads this file* (routing). A registry hive ≠ a setupapi text log ≠ an evtx. `detect_artifact_type` needs this.
2. **Forensic semantic** — *what the evidence means* (a category that **spans many artifacts**).

The enum mixes them: `Registry`/`Prefetch`/`Mft`/`Lnk` are *artifact kinds*, but `LoginHistory`/`SystemInfo`/`CrontabConfig`/`DeviceInstall` are *meanings*. The real defect is **the conflation, not the name** — `ArtifactType` is the correct noun for the routing axis (auth.log *is* an artifact). The motivating symptom:
- **Can't express cross-artifact evidence:** "device-install" comes from setupapi.dev.log **and** registry `USBSTOR`/`MountedDevices` **and** EVTX — but `DeviceInstall` is pinned to one parser. (This is the flaw that surfaced when setupapi was retyped: a *meaning* was given to a *routing* slot.) The `TimelineEvent` has no category field, so cross-artifact category queries are impossible today.
- (NOTE — the earlier "cross-feed" symptom does NOT hold: each meaning-named type has exactly one parser; the `Registry`→12-parser fan-out is *intentional* via `run_pipeline`.)

**Design — evict the meanings; do NOT rename the routing type:**
- **`ArtifactType`** (routing) stays as-is — name AND stored-data contract (DuckDB `source` column keyed on `from_debug_str`) unchanged. `SourceType` was rejected: "source" already means the *evidence source* (the image/collection; cf. `Finding.source`, `evidence_source_id`) — overloading it onto an artifact is a category error.
- **`ActivityCategory`** (CADET — semantic, cross-artifact): `DeviceInstall`, `LoginActivity`, `Execution`, … carried by **each emitted `TimelineEvent`**. Correlation + the report group by **this** → "all device-install evidence regardless of artifact" becomes a category query. (Precedent: `forensicnomicon::report::Category` is a sibling semantic axis.)

> **Knowledge placement (binding):** `ActivityCategory` (CADET) and the artifact→category mapping ("which artifact answers LoginActivity/Execution") are **forensic knowledge → they live in `forensicnomicon`**, never in issen-core/issen. issen depends DOWN on forensicnomicon and consumes them. Only the *routing* type (`ArtifactType` — which parser reads a file) is issen plumbing.

**Migration plan (phased, TDD per phase):**
1. ✅ **Add the activity taxonomy — branded `CADET`** (Categories of Activity in Digital Evidence Taxonomy), type **`forensicnomicon::cadet::ActivityCategory`** (v0.5.6, commits `1e7c342`→`a454a12`). **Grounded in prior art, not invented:** a documented synthesis of **SANS "Evidence of…"** (FOR500), **Plaso** tags (cross-platform precedent), and **MITRE ATT&CK** tactics (`attack_tactic()` for the adversarial overlap; `None` for benign — it's a superset of ATT&CK). 16 variants + stable `code()`/`from_code()` (the serialization contract a future **CASE/UCO** *export* layer maps to UCO `Action`/`Observable`). `FileSystemActivity` kept **unified** (observed activity, not SANS's inferred open/download/delete split). **Brand vs type** mirrors ATT&CK / `AttackTechnique`; CADET cleared against DFIR prior art (≠ Shavers' F.A.C.T., the TRACE toolkit, Vestige Ltd).
   - **1b — the `source → ActivityCategory` mapping (forensicnomicon knowledge), built INCREMENTALLY at phase 4 — NOT derived wholesale from the catalog.** Investigated 2026-06-18: the 6,548-entry catalog is too heterogeneous to classify structurally (96 `linux_*`/39 `macos_*` IDs span login/exec/persistence with no prefix→category rule), and `mitre_techniques` is the *adversarial* axis — it would miscategorize benign artifacts (`browser_chrome_history` carries `T1217`→Discovery, but its category is **BrowserActivity**). So the mapping is a **curated knowledge table sized to issen's ~30 real parser sources**, grounded in SANS "Evidence of…" families, with ATT&CK as a cross-check only — added as each parser is wired (phase 4), where it is actually consumed. issen consumes `ActivityCategory` after the fn **0.5.6 publish** (enum is complete + grounded + tested; the mapping ships with the parsers that use it).
2. ✅ **`TimelineEvent`: `activity_category: Option<ActivityCategory>`** (`#[serde(default)]` — additive, no data migration) + `with_activity_category` builder; issen on forensicnomicon **0.5.6** (`serde` feature). RED `5b3e48b` / GREEN `016e0f8`; 5 tests, 40/40 issen-core, consumers+parsers compile, excluded from `record_hash`. (Cargo.lock bump `e710a7d`.)
3. **Each parser tags its emitted events** with the right `ActivityCategory` — added incrementally as each parser is touched (the parser knows its output's category; the *vocabulary* is forensicnomicon's, re-exported as `issen_core::ActivityCategory`). A formal forensicnomicon source→category lookup table (1b) is deferred until ≥2 parsers need to share one.
   - ✅ **20 parsers tagged.** Unit-test RED/GREEN (the `issen_core::ActivityCategory` re-export lives in issen-core): **usnjrnl**→FileSystemActivity (`c37555a`/`20e9364`), **prefetch**→Execution (`49b160c`/`ad246fe`); batch (`71a2d45`/`295459c`): **setupapi**→DeviceInstall, **lnk**/**mft**/**macos·fsevents**→FileSystemActivity, **macos·unified_log**/**syslog**→SystemState, **biome**→UserActivity, **auth_log**→LoginActivity, **bash_history**/**fish_history**→Execution, **cron**→ScheduledTask.
   - ✅ **Registry parsers — real Case-001 hive tests** (`tests/real_hive_category.rs`, skip-if-absent; hives extracted from `DC01-ProtectedFiles.zip`, catalog §A3b): **runkeys**→Persistence (`2a177cc`/`5a75530`), then batch (`621bb6e`/`3c8fcc0`): **userassist**/**shimcache**→Execution, **sam**→AccountActivity, **shellbags**→FileSystemActivity, **registry**→SystemState, **typedurls**→BrowserActivity. Honest skips (artifact absent in Case-001): **lsadump** (no DCC2), **comhijack** (no COM hijacks), **svcdiff** (no service diff); **amcache** needs `Amcache.hve` (not in zip).
   - ✅ **Mixed parsers — per-event-type mapping (3/5):** `boot_log` (ld.preload→Persistence / sshd→SystemState, `22ff1b8`/`7921011`), `evtx` (`event_id_to_category` incl. 1102→AntiForensics, `3902f25`/`44926f9`), `srum` (network→NetworkActivity / app→Execution, real SRUDB, `5945d01`/`fc92463`). ⬜ blocked: `lxss` (no WSL hive fixture anywhere), `regcatalog` (genuinely needs the deferred 1b forensicnomicon per-descriptor table — it surfaces the whole catalog).
   - ✅ **The 4 "blocked" registry parsers re-diagnosed (background agent) — 2 were PARSER BUGS (silently dead on ALL offline hives), now FIXED + published in `winreg-artifacts 0.1.2`:**
     - ✅ **`svcdiff`** read `CurrentControlSet\Services` — a *volatile symlink absent from offline hives*. Fixed `svc_diff::parse` to resolve `Select\Current`→`ControlSet00N` (RED `f848155`/GREEN `e8ae333`, winreg-forensic). issen bumped to 0.1.2, real Case-001 SYSTEM test + Persistence tag (RED `979c024`/GREEN `2b1933d`) — non-empty result proves the fix end-to-end (was zero on every dead-box image).
     - ✅ **`comhijack`** read `NTUSER.DAT` for `Software\Classes\CLSID`, but on Win10 that lives in **`UsrClass.dat`** (root `CLSID`). Fixed via shared `open_user_clsid_key` trying `Software\Classes\CLSID`/`Classes\CLSID`/`CLSID` (fixes both `parse_hkcu_only` + `parse_pair`; RED `d99bfcc`/GREEN `319591e`). issen: carved `UsrClass.dat` (ricksanchez) from `DESKTOP-E01` via the `extract_usrclass` issen-disk example, real-data test + Persistence tag + `can_parse` accepts UsrClass.dat (RED `64b1d44`/GREEN `cbb53ac`). Non-empty result proves the fix end-to-end.
     - ⬜ **`lsadump`** DCC2 `Cache` genuinely empty in Case-001 (correct zero), but `Policy\Secrets` IS present — a real-data test is possible if the event path surfaces secrets.
     - ⬜ **`amcache`** no `Amcache.hve` in `tests/data/` but extractable from our E01s (`Windows/AppCompat/Programs/Amcache.hve`) or Ali Hadi Challenge #7's small hive.
     - NOTE: `case001-hives/` is the **DC (CITADEL-DC01)**; Desktop workstation hives (richer) are in `DESKTOP-SDN1RPT-Protected Files.zip`.
   - **(Resolved)** the working-tree dirty files were **pure rustfmt drift**, not another session — committed `57a1493` (`style:` no-logic). Untracked `issen-disk/examples/dump_file.rs` left as-is (one-off, would add clippy debt).
4. **Correlation + report:** group/pivot by `ActivityCategory` (cross-artifact), in addition to by `ArtifactType`.
5. **(Optional, deferred — separate data migration) variant cleanup:** rename the few *meaning-named* `ArtifactType` variants to honest artifact names so the routing enum is internally pure: `LoginHistory`→{`AuthLog`,`BashHistory`,`Wtmp`}; `SystemInfo`→{`Syslog`,`MacosUnifiedLog`,`FsEvents`}; `CrontabConfig`→`CronLog`; `DeviceInstall`→`SetupApiLog`. Touches the DuckDB `source` column (keyed on `from_debug_str`) — needs a migration, so it's NOT a prerequisite for the category work.

**`SourceType` REJECTED (2026-06-18):** "source" already means the *evidence source* (image/collection; `Finding.source`, `evidence_source_id`) — an auth.log is an *artifact*, not a source. Keep `ArtifactType` for routing; the original name was right, the defect was only the conflation. The earlier "cross-feed / exact-routing" benefit was also illusory (one parser per meaning-type; `Registry` fan-out intentional).

**Scope/risk:** the essential slice (steps 2–4) is **additive** — a new `Option` field + per-parser tagging + a dep bump; no enum rename, no forced migration. The optional step 5 is the only data-migration piece and stays deferred. **Benefit:** cross-artifact semantic queries ("all device-install evidence regardless of artifact"), `DeviceInstall`-as-category done right.

---

## Strategic (pointer, not tracked here)

`ACTION_ROADMAP.md` — report-engine-first: issen-core/pipeline foundation →
issen-timeline query engine → issen-report HTML MVP → MFT/EventLog parsers →
DOCX reports → intel + community. Recent tactical work is hardening *underneath*
this, not on its critical path.
