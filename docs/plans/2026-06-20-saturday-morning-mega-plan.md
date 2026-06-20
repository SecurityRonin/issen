# Saturday Morning Mega Plan — Issen Fleet (single source of truth)

**Marked:** Saturday morning, 2026-06-20. **Supersedes `archive/MEGA-PLAN.md` and the two 2026-06-20
design docs (extraction, linkage), now in `archive/`.** This is the one living plan. Codex-reviewed
(ordering corrected — see "Codex review" below).

## Thesis — one source of truth per fact

Almost every open structural item this week reduces to the **same defect class: a fact maintained in
two places that drift apart.** Dark parsers (parser knows it handles `Lnk`; a human separately types the
path into `issen-disk`). The lib/bin registry skew (the parser-anchor list typed in both `main.rs` and
`lib.rs`). The MSRV literal (`1.96.0` in `rust-toolchain.toml` *and* re-typed in config). The roadmap
collapses each duplicate to its **canonical home** — and for *forensic knowledge*, that home is
**`forensicnomicon`** (per the fleet rule; precedent: `ActivityCategory`/CADET, the former
`ForensicCategory`, already lives in `forensicnomicon::cadet`).

Two epics carry the structural work:
- **Epic L (Linkage)** — plumbing only, *no forensic knowledge*. Collapse the duplicate `main.rs`/`lib.rs`
  code path and the hand-typed anchor lists. Independent; do early (fixes a live bug).
- **Epic K (Knowledge → forensicnomicon)** — reach the **destination** the user chose (Option 1: semantic
  `ArtifactType` + triage-location + classification knowledge all in forensicnomicon). **But sequenced
  value-first, per Codex:** `ArtifactType`'s crate home is *cleanup*, **not** a prerequisite for the
  LNK/recycle-bin forensic value — so ship the extraction fix first (local paths), then relocate the
  knowledge. Same destination, value not blocked behind a fleet-wide enum move.

> **Decision flag for the user:** you said "use Option 1." Codex (which you asked to review) rejects
> Option 1's *ordering* — doing the cross-fleet `ArtifactType` move *before* recovering Beth's deleted
> file front-loads high-risk churn the value doesn't need. This plan adopts **Option 1's destination with
> value-first sequencing** (the reconciliation). Say the word if you want strict Option-1 ordering instead.

---

## ✅ Recently completed (this session, 2026-06-19→20)

- **Multi-source / folder unified-timeline ingest** — `issen ingest <DC.E01> <WS.E01> -o db`; per-source
  `evidence_source_id` re-stamp (Codex P1 fix) keeps hosts distinct. Real DC+WS: 1.58 M events, 2 sources.
  RED 57b1129 / GREEN cfce2f8.
- **`-o` optional** → auto-name `issen-ingested-<UTC>Z.duckdb` (RED fdf9774 / GREEN 5258173).
- **Resumable ingestion #115 — DONE** (per-unit commit, resume, case lock, `--refresh`).
- **Netstat C2 recovered (DC 9/9)** — symbol-free `TcpE` pool-scan + build-9600 overlay + RSDS base;
  `coreupdater.exe → 203.78.103.109:443`. memf 0.2.1 published.
- **EVTX "failed to parse chunk N"** = benign NTFS slack (zero records lost); routed to `debug!`.
- **supertimeline dark-registry root cause found** — lib/bin link skew; subagent stopgap **superseded by
  L1**, do not integrate.
- **MSRV single-source-of-truth fix** — dropped hardcoded `1.96.0` from config (toml is authoritative);
  pinned `ci.yml` to `1.96.0` (was floating `stable`).
- **Two Codex-critiqued design docs** merged here (now in `archive/`).

---

## 🔴 The ordered roadmap (Codex-corrected; dependencies explicit)

### Phase 0 — Cheap single-source-of-truth wins
- **0.1 MSRV de-duplication — DONE** (config points to `rust-toolchain.toml`; `ci.yml` pinned to `1.96.0`).
- **0.2 Clippy-debt clearance** — `cargo clippy --workspace --all-targets -- -D warnings` → 0 (pre-existing
  debt in `issen-parser-*`, `issen-unpack`, `issen-timeline`, `forensic-pivot`). *In flight (subagent).*
  Gates Phase E CI greening.

### Phase 1 — Epic L1: thin-shim `main` (do first; independent, low semantic risk)
Detail: `archive/2026-06-20-parser-linkage-aggregator-design.md`.
- Move `Cli`/dispatch into `lib.rs` (`run()` / `run_with_args()` / `dispatch()`, `try_init()` tracing);
  `main.rs` → `fn main(){ issen_cli::run() }`. Kills the duplicate `commands/parsers/scanning` module tree
  → removes the lib/bin registry skew. **Supersedes the supertimeline stopgap.** Highest value-per-effort.

### Phase 2 — Value slice: close the LNK + recycle-bin gaps NOW (no enum move needed)
This is the archived extraction doc's targeted S1–S3 path — Codex-endorsed as the real unblock.
- **2.1 Hard extraction caps in `issen-disk`** (was K2) — enforce **during** read (current code reads whole
  files into `Vec<u8>`): max files/bytes per pattern + global, max dir entries, max depth + MFT-ref cycle
  guard, loud truncation reporting. Defensive prerequisite for any new sweep.
- **2.2 Bounded LNK + recycle-bin extraction** — per-user `.lnk` sweeps (Recent + Desktop) and
  `$Recycle.Bin\<SID>\$I*` (NOT `$R` — no consumer), paths as **local `issen-disk` consts for now**,
  **ADS preserved** (`$UsnJrnl:$J`). **→ Closes gaps 2 (LNK targets) + 4 (Beth's `SECRET_beth.txt` `$I`).**
- **2.3 End-to-end test + real-image oracle** — synthetic NTFS (Recent LNK + `$IABC`) survives
  extract→classify→parse; then real DC+WS vs an independent oracle (TSK `fls`, LECmd).

### Phase 3 — Epic L2/L3: aggregators + drift gate (land L3 with/before L2)
- **L2 `issen-parsers` + `issen-providers` aggregators** (providers `issen_dd/ewf/iso/qcow2/vhd/vhdx/vmdk`
  are also force-linked — don't forget them); `build.rs` generates anchors from each manifest's direct
  deps (parse `Cargo.toml` via `toml`, not `cargo_metadata`); explicit root anchors in `lib.rs`.
- **L3 drift gate** — count **registrations** not crates (`issen-parser-linux`=4, `-macos`=2); **rewrite
  the source-scraping gates** (`tests/link_completeness.rs` scans `issen-cli/src`) — must land **with or
  before** L2 or CI gates on a moved anchor source.

### Phase 4 — Reach the Option-1 destination: knowledge → forensicnomicon (de-risked, after value)
Detail: `archive/2026-06-20-registry-derived-extraction-design.md`.
- **4.1 Move semantic `ArtifactType` → forensicnomicon** (was K1) — `issen_core` re-exports. **Blast radius
  (Codex, verified): 12 issen crate-groups** (cli, core, correlation, evtx, fswalker, mem, navigator,
  remote-access, report, timeline, unpack, parsers) **+ 27 parser crates + forensicnomicon.** `ArtifactType`
  carries `Serialize/Deserialize/Hash/Display/from_debug_str`, and **timeline persists `format!("{:?}")`** —
  a re-export is non-breaking **only with explicit compatibility tests**: Debug variant spelling, serde repr,
  Display text, `from_debug_str` round-trip, and timeline read-back must be identical. (Not a prerequisite
  for Phase 2 — pure taxonomy cleanup.)
- **4.2 Extraction-policy threading design** (the missing K4 prereq, per Codex) — `CollectionProvider::open`
  has no policy param and EWF/VMDK call `issen_disk::triage_manifest` directly. Decide: extend the provider
  trait, add a policy-aware open path, **or** accept a static/default policy in `issen-disk`. Required before
  4.4.
- **4.3 `forensicnomicon::triage` facet** *(dep 4.1)* — `TriagePattern` shapes: exact file, dir+suffix,
  per-user dir+suffix, `$Recycle.Bin\<SID>` `$I` prefix, **ADS `(path,stream)`**.
- **4.4 Migrate paths → forensicnomicon; delete issen-disk arrays** *(dep 4.2, 4.3)* — relocate Phase-2's
  local LNK/recycle consts **and** the legacy `WINDOWS_TRIAGE_PATHS/GLOBS/STREAMS/USER_FILES` into
  `forensicnomicon::triage` (preserve ADS). Completes the de-duplication.
- **4.5 Catalog-driven `detect_artifact_type`** *(dep 4.1; old B.5)* + **migrate the existing gates**
  (`producer_coverage.rs`, `reachability_gate.rs`, `link_completeness.rs`) in the **same step** — K5 breaks
  them otherwise.
- **4.6 Coverage gate** — every disk-sourced `ArtifactType` with a parser has ≥1 triage entry, or is tagged
  memory/live-only.

### Phase 5 — Remaining forensic gaps + carry-forward
- **Shimcache wiring** — linked + SYSTEM hive extracted, 0 events; wire AppCompatCache decode.
- **Timestomp `$FN`** — MFT is `$SI`-only; add `$FN` parsing + `$SI`<`$FN` detector (keep **Info** — FP-prone).
- *(G1 execution DONE via Prefetch+Amcache; G3 registry values largely DONE, minor DWORD-render bug.)*

---

## 🟡 Carry-forward backlog (from the prior Mega-Plan; still open)
- **Supertimeline #114**: CoverageManifest header · dirty-hive `.LOG` replay · catalog breadth scanner ·
  breadth/depth dedup · fleet-capability gate · nested archive/VHD/VSS expansion. *(link-gate items fold into L/K.)*
- **Unified timeline #110**: P3 smart front-door · P4 forensic soundness (provenance, `timestamp_quality`, manifest cache).
- **Temporal rules #112**: de-specialize the 2 over-fit originals; real Case-001 validation.
- **CI greening #109**: after Phase 0.2 + churn settles.
- **Housekeeping**: `srum-gui`→egui (+`publish=false` audit); `forensic-mount` MIT→Apache-2.0; ext4fs/ewf→`blazehash-core`; real-hive fixtures (6 winreg parsers); regcatalog `scan_users` multi-profile.

## 🔵 Strategic (larger)
- correlate capstone #37 · fleet hierarchy reorg #70 · FindEvil MCP fleet · forensicnomicon version unification · artifact expansion. (Detail in `archive/`.)

---

## Codex review — corrections incorporated
1. **Ordering flipped to value-first** — `ArtifactType`'s crate home (4.1) is NOT a blocker for the LNK/
   recycle-bin value (Phase 2); ship extraction first. (My "keystone unblocks both" was overstated.) ✅
2. **K4 hidden prereq surfaced** — providers call `triage_manifest` directly; policy threading is its own
   step (4.2). ✅ verified.
3. **K1 blast radius corrected** — 12 issen crate-groups + 27 parsers + forensicnomicon; compat tests
   required (serde/Debug/Display/`from_debug_str`/timeline read-back). ✅ verified.
4. **L3 lands with/before L2** (`link_completeness.rs` scans `issen-cli/src`). ✅ verified.
5. **K7/gates partly exist** (`producer_coverage`/`reachability_gate`/`link_completeness`); migrate in the
   same step as the classifier change. ✅ verified.
6. **Misrepresentation fixed** — the archived extraction doc concluded *targeted-fix-first*; this plan now
   **agrees** with it (value-first) rather than claiming it supported Option-1 ordering. ✅
7. **Precedent corrected** — `ForensicCategory` → `ActivityCategory` (CADET) in `forensicnomicon::cadet`. ✅ verified.

**Codex verdict:** value-first interleave (Phase 1→2→3→4), Option-1 *destination* preserved. User to confirm or override.
