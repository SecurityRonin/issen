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
| 2026-06-18 | issen | **#109** issen-cli clippy greening (510→0 errors; pragmatic-allow config) | `5af7d86`, `ae8cce5`, `04b9888` |

---

## Tactical Backlog — issen

- ⬜ **#114** remaining dark parsers (gate-tracked in `dark_parser_gate.rs` `KNOWN_DARK_PARSERS`): **`setupapi`** — wireable now (`parse_setupapi` exists, like lnk was); **`linux`** / **`macos`** — need real parser implementations (only `can_parse` detection today). Then **CoverageManifest** + **catalog-driven discovery** (forensic knowledge → `forensicnomicon`).
- ⬜ **#112** de-specialize over-fit temporal correlation rules — needs Case-001 validation/judgment (rules look well-built but unverified).
- ⬜ **#110** unified timeline P3/P4.
- ⬜ **#37** correlate capstone — open tail: brute-force join-key false-positive (see [[project_correlate_realdata_validation]]).
- ⬜ **#70** fleet reorg.
- 🚩 timestomp detector is deliberately an **Info lead** (`$SI<$FN` FP-prone) — layered redesign staged, not a bug.

---

## Fleet-Wide Debt

- ⬜ **#109 CI greening — sibling repos still red/with debt:** `srum-forensic`, `ext4fs-forensic`, `4n6mount`, `winevt-forensic`. (issen + forensicnomicon now green.)
- ⬜ **Docs → MkDocs (CLAUDE.md standard):** `memory-forensic`, `winevt-forensic`, `forensicnomicon`, `srum-forensic` still ship rustdoc-only `docs.yml` → their README footer Privacy/Terms links **404** until converted. Reference impl: `sqlite-forensic`.
- 🚩 forensicnomicon CI **test** job MSRV-1.75 stays root-only on purpose (the unpublished `ingest`/`4n6query` bins pull deps above 1.75); MSRV is a *library* guarantee.

---

## Strategic (pointer, not tracked here)

`ACTION_ROADMAP.md` — report-engine-first: issen-core/pipeline foundation →
issen-timeline query engine → issen-report HTML MVP → MFT/EventLog parsers →
DOCX reports → intel + community. Recent tactical work is hardening *underneath*
this, not on its critical path.
