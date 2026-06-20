# Issen Fleet — Mega Plan (single source of truth)

**Last updated:** 2026-06-17. **This is the one living plan.** All prior/superseded planning docs and
the detailed design docs live in `archive/` (referenced below for detail). Strategic roadmap context:
`archive/2026-06-09-issen-grand-plan.md`.

---

## ✅ Recently completed (latest session)

- **Publish backlog closed** — 14 new crates on crates.io: `blazehash-core`, `blazehash 0.2.5`,
  `ese-carver/-integrity`, `winevt-cli` (`ev4n6`), `forensicnomicon-cli` (ships `4n6query`),
  `srum-analysis/-cli`, `ext4fs-core/-cli/-fuse`, `dmg-core`, `exec-pe-core/-analysis`,
  `forensic-mount`. Only `srum-gui` (Tauri) unpublished — not a crates.io target.
- **blazehash split** live (lean `blazehash-core` + full `blazehash`).
- **Dark winreg artifacts wired + linked** (comhijack/lsadump/svcdiff/typedurls/lxss + regcatalog).
- **Link-completeness gate** + revived 7 orphaned parsers (mft/usnjrnl/pe/lnk/linux/macos/setupapi).
- **17 temporal rules** in the shared registry. **Timeline sorted** chronologically (mode 6E).
- **ParseCompletion contract** + MFT/USN/EVTX/Prefetch declare it (resumable-ingestion step 1).
- **CLAUDE.md standards:** Batteries-Included; lean-lib/full-binary split; Fleet GUI Standard
  (egui + egui-phosphor; Tauri banned / `publish=false`).

---

## 🔴 Active work — prioritized

### A. Resumable ingestion (#115) — current focus
Detail: `archive/2026-06-17-resumable-ingestion-design.md` (Codex-critiqued). MVP order:
1. **Completion contract** — DONE for MFT/USN/EVTX/Prefetch (`ParseCompletion`, secure-by-default).
   Remaining: declare completion in the other parsers as touched.
2. **Schema + migration** ← NEXT — `ingest_log` table + `timeline.ingest_unit_id` + indexes
   (additive; legacy rows immutable).
3. **Per-unit transaction** — `begin → delete unit rows → insert → mark complete → commit`, reusing
   `insert_batch_at_epoch`.
4. **Stable unit ids** + deterministic discovery.
5. **Streaming `StoreEmitter`** (replace collect-all-in-RAM).
6. **Case-level ingest lock** + `--refresh` (CLI) / `ingest.refresh` (config).
Defer to phase 2: nested-volume recursion (threaded/bounded); per-artifact-type + intra-artifact progress.

### B. All-encompassing supertimeline mechanism (#114)
Detail: `archive/2026-06-16-all-encompassing-supertimeline-design.md`. Item 1 (link gate) + sort done.
Remaining (Codex order): 2 stub-parse gate · 3 classifier-producer gate · 4 CoverageManifest in the
supertimeline header · 5 catalog-driven `detect_artifact_type` (**discovery knowledge → forensicnomicon**)
· 6 dirty-hive `.LOG` replay · 8 catalog breadth scanner · 9 breadth/depth dedup · 10 fleet-capability
gate · 11 nested archive/VHD/VSS expansion.

### C. Unified timeline workflow (#110)
Detail: `archive/2026-06-16-unified-timeline-workflow-design.md`. P1 (narrative-over-DB) + P2 (rule
registry) done. Remaining: **P3** smart front-door (ingest-if-evidence, managed workspace DB);
**P4** forensic soundness (per-event provenance, `timestamp_quality`, manifest-keyed cache).

### D. Temporal-rule registry (#112)
17 rules integrated. Remaining: **de-specialize the 2 over-fit originals** (`/tmp/silly.txt` PAM hook;
boot-log-predates-mft); **real Case-001 validation** of the new rules.

### E. CI greening (#109)
6/7 repos green. **issen CI** remains — run once the timeline/parser churn settles.

---

## 🟡 Housekeeping / fleet-wide

- **`publish = false` on `srum-gui`** (+ audit fleet for other Tauri/app crates) — intentional exclusion.
- **Re-platform `srum-gui` on egui** (new GUI standard) → ships like `srum-cli`.
- **`forensic-mount` relicense** MIT → Apache-2.0.
- **ext4fs/ewf → `blazehash-core`** migration (drop `default-features=false`; batteries-included).
- **clippy/fmt automation** — Stop hook (`fmt` + `clippy --fix` + `clippy -D warnings` on changed
  crates) + `rust-toolchain.toml` pinned to CI's version (kills "passed local, failed CI 1.96").
- **Real-hive fixtures** for the 6 wired winreg parsers (synthetic-only today); regcatalog
  `scan_users` multi-profile TODO.

---

## 🔵 Strategic / larger (own efforts)

- **issen correlate capstone** (#37) — `archive/2026-06-11-issen-correlate-capstone-v5.md`.
- **Fleet hierarchy reorg** (#70) — `archive/2026-06-09-fleet-hierarchy-reorg.md`.
- **FindEvil MCP fleet** — `archive/2026-06-15-findevil-mcp-fleet-design.md` (design only).
- **forensicnomicon version unification** — `archive/2026-06-14-...md` (Phase 1 partial).
- **Artifact expansion** backlog — `archive/2026-06-12-artifact-expansion.md`.

---

## blazehash 0.2.4 note (#111 residual)
`blazehash 0.2.4`'s compile-bug report was false (compiles fine). Real items: `xxhash-rust` is BSL-1.0
(allowlist in fleet `deny.toml`, don't amputate); `ml-dsa 0.1.0-rc.8` pre-release (pin); commit
`Cargo.lock` in binary repos. The split (done) makes `blazehash-core` the lean dep for libraries.
