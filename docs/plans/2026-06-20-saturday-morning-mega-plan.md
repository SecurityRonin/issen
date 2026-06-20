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
  `$Recycle.Bin\<SID>\$I*` (NOT `$R` — no consumer), paths as **local `issen-disk` consts for now**.
  **→ Closes gaps 2 (LNK targets) + 4 (Beth's `SECRET_beth.txt` `$I`).** (The new artifacts `.lnk`/`$I`
  do **not** use ADS, so the ADS work below is a *non-regression* constraint, not part of their extraction.)
- **2.3 ADS non-regression guard (investigated 2026-06-20).** Clarification: `sanitize_ntfs_path`
  (issen-disk:248) strips the colon only from the **output filename** (you can't host a file named
  `$UsnJrnl:$J`); the ADS *data* is read correctly via `extract_named_streams` → `read_named_stream(path,
  stream)` (issen-disk:435+), and `ExtractedFile.path` keeps `path:stream`. So the current code does NOT
  lose ADS data — **this is a constraint+test, not a blocker.** Two real risks to guard when Epic K
  migrates the static arrays to a catalog/registry model: **(a)** the `TriagePattern` model MUST carry an
  ADS `(path,stream)` shape routed to `extract_named_streams`, or USN-journal (`$UsnJrnl:$J`) extraction
  regresses — add a regression test asserting `$J` still extracts after the migration; **(b)** an
  **output-name collision**: if a future pattern extracts both `$UsnJrnl:$J` and `$UsnJrnl:$Max`, both
  sanitize to `$Extend/$UsnJrnl` and one overwrites the other (today only `:$J` is extracted, so no
  collision yet) — the migration should encode the stream into the output name (e.g. `$UsnJrnl_$J`) or
  collision-check.
- **2.4 End-to-end test + real-image oracle** — synthetic NTFS (Recent LNK + `$IABC` + a `$J` ADS to lock
  2.3) survives extract→classify→parse; then real DC+WS vs an independent oracle (TSK `fls`, LECmd).

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
- **NTFS metadata-integrity capability (researched 2026-06-20, Codex-verified).** A new analyzer
  family cross-referencing NTFS system metadata for tamper-detection + recovery. Components:
  (1) **`$LogFile` parser** — the metadata transaction journal (RSTR/RCRD pages, log records with
  LSN + redo/undo); finer-grained metadata ops than `$UsnJrnl`, timestomp detection (logged
  SetInformation vs current `$SI`), recent-metadata recovery (undo data), anti-forensic (`$J`-clearing)
  detection. The David Cowen **NTFS TriForce** idea (`$MFT`+`$LogFile`+`$UsnJrnl`); prior art:
  Schicht LogFileParser, NTFS Log Tracker. Each MFT record header carries the `$LogFile` LSN of its
  last modification → MFT↔$LogFile LSN consistency check. **BUILD PLAN (researched+verified
  2026-06-20):** no general-purpose Rust `$LogFile` crate exists; **build-from-scratch in Rust, do NOT
  bind C** (libfsntfs has no `$LogFile` decoder + fleet is `forbid(unsafe)`). Two partial fleet readers
  to CONSOLIDATE (avoid a third): `crates/issen-mft-tree/src/logfile.rs` (**RSTR restart-area parsing —
  DONE**, ~105 hits) + `usnjrnl-forensic` (recovers USN records from `$LogFile`, NOT full RCRD
  redo/undo). Path: extend a fleet `*-core` reader to RSTR+RCRD-fixup+LSN/redo-undo, then a thin
  `issen-parser-logfile` wrapper. **Needs a NEW `ArtifactType::LogFile` variant** (none today).
  Selector: `artifact_type: LogFile`, matcher on RSTR/RCRD magic, `disk_sources: FixedPath(\$LogFile)`
  (un-exempts the Stage-3 drop). **Effort M; risk = USA/fixup + circular-buffer wrap** (mis-applied
  fixups silently corrupt every record); LSN redo/undo is the long tail. **First TDD increment: parse
  + USA-fixup-validate an RCRD page** from a real Szechuan `$LogFile` (RSTR header already done). Oracle:
  Schicht LogFileParser / NTFS Log Tracker on the same extracted `$LogFile`. (2) **`$MFT` vs `$MFTMirr`** — mirror is record #1, copies the first `max(4,
  cluster/record)` records; compare the mirrored byte range **after fixups** → integrity-anomaly /
  **recovery anchor** for a damaged `$MFT[0]` (relocate the full MFT via the mirrored `$MFT::$DATA`
  runlist). Classify as anomaly/recovery, **NEVER "tamper detected"** (desync has benign causes:
  deferred mirror write, crash, unreplayed `$LogFile`). (3) **`$Boot` vs backup `$Boot`** (volume end)
  — both carry `$MFT`/`$MFTMirr` LCNs. Verdict: real value, but findings must be **graded as
  consistency anomalies fused with replay-state/fixup-validity/sector-health**, not standalone tamper
  proof. Registry-model bonus: a `$LogFile`/`$MFTMirr` parser auto-re-collects those files via its
  selector (e.g. `$LogFile` un-exempts the Stage-3 drop). Validate on real images (Szechuan + a
  known-timestomped corpus).
- **Shimcache wiring** — linked + SYSTEM hive extracted, 0 events; wire AppCompatCache decode.
- **Parser Output Depth — SYSTEMIC (capability-built-not-surfaced, researched 2026-06-20).** Not an LNK
  one-off: a 14-parser survey found **11/14 wrappers materially shallow** — they surface a fraction of the
  forensic richness their **owned core already parses** (MFT is the lone DEEP one, proving it's discipline,
  not capability). Verified anchors: `issen-parser-registry` base calls 1 of **13** decoder modules; srum
  2 of **7** tables; biome *"does not CRC-validate"* while segb-core exposes `crc_ok()` (drops tamper
  evidence); prefetch keeps a run count vs the core's 8 run times + loaded-file list; lnk drops target
  path/drive-serial/UNC/birth-droid NetBIOS. **Full plan + ranked backlog + the "depth gate" design now
  live in the Companion Track of**
  [`2026-06-20-registry-driven-artifact-selector-design.md`](2026-06-20-registry-driven-artifact-selector-design.md).
  Same capability-inventory theme as the selector refactor, **separate execution** (changing *what* a
  parser emits cannot ride the wiring refactor's differential gate). Ranked #1 registry-base catalog,
  #2 lnk, #3 biome CRC/anomaly, #4 prefetch — gate-first-then-ratchet, validate on real corpora.
  **PROGRESS: #2 lnk PARTIALLY DONE (RED ad78504 / GREEN 3944384)** — issen-parser-lnk now uses
  lnk-core (stopped hand-rolling) and surfaces target_path + drive_serial + drive_type + volume_label
  (TDD on the real removable_media.lnk: `E:\payload.exe` on KINGSTON USB, serial 0xDEADBEEF). lnk follow-ups:
  network UNC (CommonNetworkRelativeLink), birth-droid NetBIOS origin, command-line args, JumpLists.
  First depth-track fix landed — proves the pattern. The DEPTH GATE (declare-current-then-ratchet) is
  still TODO.
- **Timestomp `$FN`** — MFT is `$SI`-only; add `$FN` parsing + `$SI`<`$FN` detector (keep **Info** — FP-prone).
- *(G1 execution DONE via Prefetch+Amcache; G3 registry values largely DONE, minor DWORD-render bug.)*

---

## 🟡 Carry-forward backlog — **triaged 2026-06-20 (my review × Codex critic)**

**Correctness-first do-next (Codex elevated these above features):**
1. **ParseCompletion on commit — ✅ core DONE** (`f585856`): incomplete units re-parse on resume.
   **Hardening follow-ups (Codex review of the fix):** **(HIGH ✅ DONE 13cfdb1)** `--refresh` re-parsing a previously-`complete`
   unit that now returns incomplete deletes the good rows and downgrades to `incomplete` (data loss) —
   guard: reject complete→incomplete downgrade (or gate behind an explicit destructive flag) + test;
   **(MED)** don't collapse `ParseCompletion` to `bool` — `Unsupported`/`CorruptFatal` (not-valid / unparseable)
   arguably should NOT commit events at all, unlike `Incomplete` (partial-but-real); **(MED)** surface
   partial provenance — tag timeline rows / warn in the CLI summary so incomplete-derived events are visible;
   **(LOW)** add resume-contract tests (incomplete→complete clears rows, incomplete→incomplete replaces,
   complete→incomplete under refresh, events-with-Unsupported/CorruptFatal).
2. **Deterministic per-unit ordering (#110 P4 / parallel-ingest prereq) — do-before-parallel (Codex: not
   "cosmetic").** `run_auto` already sorts `timestamp_ns, record_hash` (orchestrator.rs:421) but
   `run_auto_units` (the resumable ingest path) does not, and **every DB reader orders only by `timestamp_ns`**
   — `query()` (query.rs:134), `fetch_events()`/`load_timeline_events()` (events.rs:310/371), report
   (report/lib.rs:230), SQLite export (export.rs:12). Equal-timestamp order is SQL-undefined → non-deterministic
   exports/narrative/temporal-eval. Fix = `ORDER BY timestamp_ns ASC, record_hash ASC` in **every** read/export/
   report + equal-timestamp tests. `id`/`ingested_at` are insertion/wall-clock derived — **must not** be the
   tie-break. (Pre-sorting before insert is optional hygiene, not the boundary.)
3. **Evidence-source provenance (#110 P4) — do-before-parallel.** ingest passes `None, None` for source
   hash/size (ingest.rs:130) though schema/fn support them (ingest.rs:309-315). **Correction (we own `ewf`):
   the `ewf` crate ALREADY exposes the stored ACQUISITION hash** — `EwfReader::stored_hashes() ->
   StoredHashes{md5, sha1}` (from the `hash`/`digest` sections), plus `metadata()`, `acquisition_errors()`,
   and stored-vs-computed verification — but **issen pins a stale `ewf = "0.1"`** (Cargo.toml:196) while the
   crate is at `0.2.1`. The stored acquisition hash is forensically *superior* to re-hashing (it's the
   chain-of-custody value recorded at imaging; stored-vs-recomputed is an integrity check). Fix: **(a)** bump
   issen `ewf 0.1 → 0.2` (publish 0.2.x first if needed — our crate); **(b)** `EwfDataSource` already holds
   `Mutex<EwfReader>` (issen-ewf:95) → surface `stored_hashes()` (ideally via a provider-abstraction
   `acquisition_metadata()` so EWF returns stored MD5/SHA1, raw/dd returns None); **(c)** loose file →
   `len()` + streamed SHA-256; directory → NULL; **(d)** bonus: opt-in `--verify` (stored vs recomputed) as
   a real chain-of-custody check. **Fleet-hygiene note:** the stale `ewf 0.1` pin means other fleet deps may
   also be stale — audit + bump (prefer-published-latest).
4. **CoverageManifest header (#114)** — KEEP; no such type exists yet; runtime completeness report.
5. **ADS-preserving extraction + caps** — folded into Phase 2.1/2.3 (constraint + regression test).
6. **Real-hive fixtures (6 winreg parsers)** — KEEP/ELEVATE; synthetic masked svcdiff/comhijack dead on real
   images; real Szechuan hives now available. (Skip-if-absent corpus tests — not always CI-enforced.)

**Fold into Epic K (knowledge→forensicnomicon):** catalog-driven discovery (#114 breadth scanner);
migrate the existing static gates (link/producer/reachability) into L/K rather than add a 5th; coordinate
`forensicnomicon` version-unification in the Epic-K compatibility wave (its ArtifactType-debug-string
persistence needs the same compat tests). **NOTE (Codex):** breadth/depth **dedup** does NOT fold away —
`regcatalog` emits broad events overlapping specialized parsers, so dedup stays an issen timeline/report task.

**Keep separate (own roadmaps):**
- **dirty-hive `.LOG` replay** — SPLIT: parser replay → `winreg-core`; **issen keeps an extraction item** —
  it pulls hives but not adjacent `.LOG1/.LOG2` (issen-disk:118/211), and must collocate + preserve source paths.
- **Nested archive/VHD/VSS expansion (#114)** — KEEP, big; coordinates with parallel-ingest + `[H]`.
- **Artifact expansion** — KEEP as its own parser/fixture/validation roadmap (Codex: do NOT fold wholly
  into Epic K — K is only the knowledge/detection substrate).
- **Temporal rules #112** — de-specialize the over-fit `/tmp/silly.txt` rule (temporal_rule.rs:240) + real Case-001 validation.
- **CI greening #109** — clippy now green; finish full test/fmt/deny/coverage/fuzz.

**Dropped from issen's plan (verified other repos / out of focus):**
- `srum-gui`→egui, `forensic-mount` relicense, ext4fs/ewf→`blazehash-core` — **`srum-forensic`/`ext4fs-forensic`
  are separate repos**; track in their plans, not issen's (keep only issen-local dep/publish fallout).
- **FindEvil MCP fleet** — DEFER (design-only, broad surface). **Fleet hierarchy reorg #70** — below correctness work.

**Rescoped (partly done this session):**
- **#110 P3 smart front-door** — multi-source/folder + auto-naming done (sources.rs); remaining = remote-URI
  ingest (still a stub returning early, ingest.rs:51) + managed workspace DB.
- **correlate capstone #37** — Codex: my "join-key FP tail" is **stale** — regression tests for the brute-force
  AND dense-success FP already exist (correlate_runner.rs:493/514); remaining = real-data oracle closure/reporting.
- **regcatalog `scan_users` multi-profile** — KEEP, small (explicitly out of scope today, regcatalog lib.rs:15).

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
