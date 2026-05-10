# Issen Consolidated Grand Implementation Plan

**Date**: 2026-05-04
**Status**: ACTIVE
**Authority**: This plan consolidates and supersedes all sub-repo plans. It is the authoritative cross-repo roadmap for the Issen forensic platform.

---

## 1. Architecture

The platform follows a strict layer hierarchy. Each layer has defined dependency rules that must not be violated.

```
KNOWLEDGE      forensicnomicon          zero-dep, compile-time artifact specs
               [repo: forensicnomicon]

CONTAINER      decode an image/dump format into raw physical data stream
               ewf          E01/EWF -> raw sector stream          [repo: ewf]
               memf-format  memory dumps -> raw page stream        [repo: memory-forensic]

               A container holds either disk sectors or memory pages.
               The two paths below are parallel and independent;
               both converge at PARSER.

               --- contains disk sectors ---       --- contains memory pages ---

FILESYSTEM     ext4fs-forensic  ext4->files        PAGING     memf-hw (rename of memf-core)
               ntfs-forensic    [planned]                     OS-agnostic page-table walker
               apfs-forensic    [planned]                     x86_64 PML4/PAE, AArch64
               4n6mount         FUSE bridge                   VA->PA translation
               [repos: ext4fs-forensic,
                4n6mount]                          OS STRUCT   memf-windows  EPROCESS, VAD,
                                                               DPAPI, DKOM, Kerberos
                                                               memf-linux  [planned]

PARSER         browser-forensic, winevt-forensic, srum-forensic,
               [future: registry, prefetch]
               -- accept Path or &[u8]; NO import of CONTAINER/FILESYSTEM/PAGING/OS STRUCT
               -- OS STRUCT (memf-windows) MAY call PARSER when it finds artifact bytes

ORCHESTRATION  Issen -- wires all layers, correlation, TimelineEvent/Evidence, CLI
```

### Dependency Rules

| Layer | May Depend On |
|---|---|
| KNOWLEDGE (forensicnomicon) | Nothing (zero-dep) |
| CONTAINER (ewf, memf-format) | KNOWLEDGE only |
| FILESYSTEM (ext4fs, ntfs, apfs, 4n6mount) | CONTAINER + KNOWLEDGE |
| PAGING (memf-hw) | CONTAINER + KNOWLEDGE |
| OS STRUCT (memf-windows, memf-linux) | PAGING + CONTAINER + KNOWLEDGE; MAY call PARSER |
| PARSER (browser, winevt, srum, etc.) | NO dependency below itself; receives `Path` or `&[u8]` |
| ORCHESTRATION (Issen) | All layers |

**Critical constraint**: PARSER crates must never import CONTAINER, FILESYSTEM, PAGING, or OS STRUCT. They receive data as file paths or byte slices. OS STRUCT crates (e.g., memf-windows) may call PARSER crates when they discover artifact bytes in memory (e.g., calling `browser-carve` on SQLite pages found in a VAD region).

---

## 2. Global Naming Decisions

These naming conventions are enforced across all repos. Any deviation is a bug to be fixed.

### 2.1 IntegrityIndicator (not AntiForensicIndicator)

The structural anomaly indicator enum in each parser repo is named `IntegrityIndicator`. The crate is named `<format>-integrity`, not `<format>-antiforensic`.

| Repo | Crate Name | Status |
|---|---|---|
| browser-forensic | `browser-integrity` | Correct |
| srum-forensic | `ese-integrity` | Correct |
| winevt-forensic | `winevt-integrity` | ✅ DONE |

### 2.2 memf-hw (not memf-core)

The crate performing OS-agnostic page-table walking is `memf-hw` (hardware abstraction). The current name `memf-core` is misleading. **Rename PENDING**.

### 2.3 Standard Parser Crate Pattern

Each parser repo follows this four-crate structure:

| Crate | Purpose |
|---|---|
| `<format>-core` | Domain types |
| `<format>-integrity` | Structural anomaly detection (formerly "antiforensic") |
| `<format>-carve` | Disk/raw-image carving (`browser-carve`, `winevt-carver`) |
| `<format>-memory` | Pure byte-pattern scanner; NO memory-forensic dependency |

---

## 3. Repo Status Matrix

| Repo | Status | Done | Pending |
|---|---|---|---|
| **forensicnomicon** | EXISTS, partial | LOL/LOFL, abusable sites, MITRE mappings, Sigma refs, event IDs, artifact profiles | Browser artifact profiles (13 entries), ESE/SRUM structural constants, EVTX binary constants |
| **winevt-forensic** | EXISTS, Phases 0-3 done | winevt-core (EvtxEvent, LogonSession, ProcessEvent, binary format), winevt-integrity (gap detection, checksum, timestamp monotonicity), winevt-carver (carve_from_bytes, recover_records_from_slice) | Phase 4: carver enhancements (US-01–03); Phase 5: winevt-memory crate (US-04–05); Phase 6: memf-windows constant import |
| **srum-forensic** | EXISTS, BROKEN internals | ese-core (EseHeader, EseDatabase, EsePage), srum-core (types), srum-parser (broken), sr-cli | Fix page flag bug (0x0400 -> 0x0020), real ESE catalog walk, real column decoder, ese-integrity, ese-carver, ese-memory, 6 SRUM table parsers |
| **browser-forensic** | EXISTS, Phase 1 complete | browser-core, browser-chrome (8 parsers), browser-firefox (9 parsers), browser-safari (5 parsers), browser-discovery, bw-cli (12 subcommands) | v2 Phases 1-9: forensicnomicon profiles, new types, browser-integrity, browser-carve, browser-memory, new parsers, browser-rt, CLI, integration tests |
| **memory-forensic** | EXISTS, partial | memf-format (physical dump I/O), memf-core (VA translation, ObjectReader), memf-windows (80+ modules), memf-linux (partial) | Rename memf-core -> memf-hw; import winevt-core constants; import browser-carve; import browser-memory |
| **ext4fs-forensic** | EXISTS | ext4 filesystem parsing | - |
| **4n6mount** | EXISTS | FUSE bridge | - |
| **ewf** | EXISTS | E01/EWF container decoding | - |
| **Issen** | EXISTS, multiple workstreams | Correlation engine, CLI, parser integration | Workstreams 1-10 (see Section 6) |

---

## 4. Execution Phases

Work within each group can proceed in parallel. Later groups depend on earlier groups completing.

### Group 0 -- Critical Bugfixes (do first, no dependencies)

These block all downstream work and must be resolved before any feature work.

| Repo | Task | Detail |
|---|---|---|
| srum-forensic | Fix ESE_PAGE_FLAG_SPACE_TREE | Change 0x0400 to 0x0020 in ese-core |
| srum-forensic | Real ESE catalog walk | Implement real MSysObjects format (replace synthetic 32-byte flat decoders) |
| srum-forensic | Real column-type-aware record decoder | Implement fixed/variable/tagged column encoding (current srum-parser silently produces garbage against real SRUDB.dat) |
| winevt-forensic | ~~Rename AntiForensicIndicator -> IntegrityIndicator~~ | ✅ DONE — winevt-integrity crate, IntegrityIndicator enum |

### Group 1 -- Parallel, no inter-repo dependencies

| Repo | Task |
|---|---|
| forensicnomicon | Add browser artifact profiles (13 entries) |
| forensicnomicon | Add ESE/SRUM structural constants |
| forensicnomicon | Add EVTX binary constants |
| winevt-forensic | Phase 4: wire detect_record_id_gaps post-carve, carve_from_file + verify_integrity, aggressive scan for corrupt chunks |
| srum-forensic | Create ese-integrity, ese-carver, ese-memory crates |
| srum-forensic | Implement 6 remaining SRUM table parsers (currently only network + app usage) |
| browser-forensic | Phase 1: forensicnomicon browser profiles (depends on forensicnomicon Group 1 item) |
| browser-forensic | Phase 2: browser-core new types (ForensicMeta, ArtifactKind::Integrity/Carved/Memory, EvidenceStrength) |
| browser-forensic | Phase 3: browser-integrity crate (IntegrityIndicator, check_database_integrity, check_wal_state, check_history_integrity, check_cookie_integrity) |
| browser-forensic | Phase 4: browser-carve crate (CarvedRecord, CarveResult, CarveStats, SQLite free-page carving, WAL recovery) |
| browser-forensic | Phase 5: browser-memory crate (scan_bytes_for_urls, scan_bytes_for_cookies -- NO memf dependency) |

### Group 2 -- Depends on Group 1

| Repo | Task |
|---|---|
| winevt-forensic | Phase 5: winevt-memory crate (MemoryRecoveredChunk, RecoveredEtwSession, EtwTamperingIndicator) |
| browser-forensic | Phase 6: new parsers (Windows paths in discovery, parse_local_state, Safari TopSites) |
| browser-forensic | Phase 7: browser-rt crate (TriageReport, triage orchestration) |
| memory-forensic | Rename memf-core -> memf-hw |

### Group 3 -- Depends on Group 2

| Repo | Task |
|---|---|
| winevt-forensic | Phase 6: memf-windows imports winevt-core constants (replace local ELFCHNK_MAGIC, etc.) |
| memory-forensic | Import browser-carve for SQLite page interpretation from VA space |
| memory-forensic | Import browser-memory for URL/cookie byte scanning from VA regions |
| browser-forensic | Phase 8: CLI subcommands (integrity, carve, triage) |
| browser-forensic | Phase 9: cross-crate integration tests |

### Group 4 -- Depends on Group 3

| Repo | Task |
|---|---|
| Issen | rt-evtx integrates winevt-carver + winevt-integrity (carver fallback, integrity reporting) |
| Issen | Workstreams 1-9: evidence model, rendering, narrative, calibration (see Section 6) |
| Issen | rt CLI: add `rt evtx sessions`, `rt evtx processes`, `rt evtx frequency` subcommands (hayabusa differentiators via rt-evtx) |

### Group 5 -- Capstone (depends on all parsers)

| Repo | Task |
|---|---|
| Issen | Workstream 10: Supertimeline Engine (see Section 6.10) |
| Issen | rt-timeline enhancements: EntityIndex, temporal_join, absence detection, timestamp normalization |
| Issen | TemporalRule YAML schema in rt-correlation (10+ temporal patterns) |
| Issen | `rt supertimeline` CLI command (JSONL, CSV, narrative, HTML outputs) |
| Issen | Wire all parser crates into supertimeline assembler |

---

## 5. Core Principle: Evidence Truth Model

Issen must distinguish clearly between:

- **Observed** -- directly present in parsed artifacts
- **Correlated** -- derived by joining observed facts across sources
- **Inferred** -- likely explanation, but not directly proven

This distinction must exist in:

- Internal evidence models
- Correlation findings
- CLI output
- Documentation wording

### Current Gaps

1. **Thread Display Semantics**: `process_name` comes from main thread (`tid == pid`); `thread_names` only contains non-main-thread names. Cannot surface combined thread listing.
2. **Hardcoded Narrative Strings**: `rt analyse` contains hardcoded miner/rootkit/tunnel prose in `crates/rt-cli/src/commands/analyse.rs`, creating drift from detection logic.
3. **Correlation Findings Not Human-Readable**: Expose `rule_id`, `title`, `severity`, `evidence_ids` but not rendered evidence, calibrated explanations, confidence, or assertion level.
4. **Tunnel/Miner Claims Overstated**: Cannot fully prove forward destination is a mining pool, that all miner traffic exits only as SSH, or the exact remote pool target.
5. **Rootkit Hook Claims Overstated**: Detects `ld_preload` indicator but cannot prove exact hooked libc functions for `libymv.so.3`.
6. **Documentation Drift**: Scenario document is not truly verbatim against current code.

---

## 6. Issen Internal: Workstreams 1-10

### Workstream 1: Evidence Truth Model

**Objective**: Extend findings and output so the system can explicitly mark whether a claim is observed, correlated, or inferred.

**Changes**:
- Extend `rt-correlation::model::Finding` with:
  - `summary` -- human-readable one-line summary
  - `explanation` -- detailed explanation text
  - `confidence` -- numeric confidence score
  - `assertion_level` -- Observed / Correlated / Inferred
  - `evidence_rendered` -- Vec of rendered evidence lines

**Assertion Level Enum**: `Observed`, `Correlated`, `Inferred`

**TDD Sequence**:
1. RED: Add failing tests for finding model carrying assertion/confidence/rendered evidence
2. GREEN: Implement model changes
3. Update correlation engine outputs
4. Update CLI rendering tests

### Workstream 2: Hidden Process Thread Model

**Objective**: Make the parser capable of supporting both machine-accurate semantics and richer CLI display.

**Changes in `rt-parser-uac`**:
- Keep `process_name` as-is for compatibility
- Keep `thread_names` as current behavior (non-main-thread names only)
- Add `all_thread_names` (main thread name + non-main-thread names)

**TDD Sequence**:
1. RED: Add failing parser test proving `all_thread_names` includes both `top` and `libuv-worker`
2. GREEN: Implement model extension in `rt-parser-uac`
3. Update CLI display logic to use `all_thread_names` when desired
4. Preserve current hidden-process tests for non-main-thread behavior

### Workstream 3: Human-Readable Evidence Rendering

**Objective**: Replace raw evidence IDs like `rk-1, proc-14, net-16` with meaningful rendered lines.

**Changes**: Add evidence rendering layer in `rt-correlation`:
- Render rootkit evidence: `ld_preload /lib/x86_64-linux-gnu/libymv.so.3`
- Render process evidence: `PID 977 "top" [thread: libuv-worker]`
- Render network evidence: `127.0.0.1:59182 -> 127.0.0.1:3333 [ESTABLISHED]`
- Render CPU anomaly evidence

**TDD Sequence**:
1. RED: Add failing tests for evidence rendering by kind/source/attrs
2. GREEN: Implement render helpers
3. Attach rendered evidence to findings
4. Update `rt analyse` output tests

### Workstream 4: Correlation-Driven Narrative

**Objective**: Stop encoding miner/rootkit/tunnel explanations directly in `analyse.rs`.

**Changes**:
- Move explanation ownership into correlation rule metadata and rendered findings
- Reduce `build_narrative()` until it either delegates entirely to correlation findings or only prints generic fallback text

**TDD Sequence**:
1. RED: Add failing integration test for `rt analyse` output using correlation-generated summaries
2. GREEN: Extend YAML rule schema with `summary_template`, `explanation_template`, `assertion_level`, `default_confidence`
3. Implement template rendering in `rt-correlation`
4. Update `analyse.rs` to render correlation findings instead of hardcoded miner prose
5. Remove duplicated logic from `build_narrative()`

### Workstream 5: Terminology Cleanup

**Objective**: Make naming consistent with current architecture.

**Changes**:
- Replace `PIVOT FINDINGS` with `CORRELATION FINDINGS`
- Rename `evaluate_pivot` module/function to `evaluate_correlation`
- Keep temporary compatibility aliases only if needed during transition

**TDD Sequence**:
1. RED: Add failing output test expecting `CORRELATION FINDINGS`
2. GREEN: Update CLI output
3. Rename function/module surfaces
4. Remove stale "pivot" wording from docs/comments/tests

### Workstream 6: Calibrated Miner / Tunnel Claims

**Objective**: Make miner and SSH-tunnel output say only what the current evidence supports.

**Evidence classification**:

| Level | Claims |
|---|---|
| **Observed** | Hidden process exists; `libuv-worker` thread observed; hidden process connects to `127.0.0.1:3333`; hidden `ssh` process has `3333` listener; hidden `ssh` process has established connection to remote `:22` |
| **Correlated** | Hidden miner likely using local port-forwarding over SSH |
| **Inferred** | Likely XMRig or compatible miner; likely tunneling miner traffic through SSH |

**Output Policy**: Prefer `consistent with`, `likely`, `compatible miner`. Avoid `proves`, `all traffic exits as SSH`, explicit `<pool>` unless actually observed.

**TDD Sequence**:
1. RED: Add failing tests for calibrated finding wording
2. GREEN: Move tunnel/miner wording into rule metadata
3. Update CLI output

### Workstream 7: Rootkit Narrative Calibration

**Objective**: Stop claiming exact hook behavior unless actually evidenced.

**Default wording**:
- `LD_PRELOAD rootkit/library configured`
- `consistent with userspace process hiding`

Only print exact hooked functions if: reverse-engineering module exists, YARA/signature metadata identifies the family, or catalog entry in forensicnomicon has evidentiary basis.

**TDD Sequence**:
1. RED: Add failing output test rejecting exact hook-function claims by default
2. GREEN: Update `analyse.rs` / correlation rule templates
3. Add optional extension point for family-specific enrichment later

### Workstream 8: Verbatim Output Regeneration

**Objective**: Make the scenario doc truly match current code.

**Changes**:
- Add full integration/snapshot test for the scenario: run `rt analyse` against fixture, snapshot output, update documentation from snapshot
- If fixture cannot be checked in, create a stable fixture harness that synthesizes the relevant artifacts

**TDD Sequence**:
1. RED: Add failing integration test for full `rt analyse` output
2. GREEN: Capture snapshot
3. Make code changes until snapshot matches desired calibrated output
4. Update `docs/ctf-submission-linux-forensic-scenario.md`
5. Change wording from `verbatim` to `representative` only if a real snapshot cannot be maintained

### Workstream 9: Stronger Miner Confirmation

**Objective**: Support stronger conclusions when stronger evidence exists.

**Tiered conclusions**:
- `likely_xmrig_or_compatible` -- from `libuv-worker` + miner ports + hidden process + CPU anomaly
- `confirmed_xmrig` -- requires one of: process name `xmrig`, YARA hit, binary hash/signature hit, direct command-line artifact

**TDD Sequence**:
1. RED: Add failing rule tests for `likely` vs `confirmed`
2. GREEN: Add enrichment tags from YARA/signature/process-name sources
3. Update rule pack and output rendering

### Workstream 10: Supertimeline Engine -- the Plaso Replacement

#### Strategic Position

Plaso (log2timeline) is the incumbent supertimeline tool. It is Python-based, requires a local disk image, and is fundamentally a **timestamp aggregator**: it collects timestamps from many artifact types and outputs a sorted list. The analyst then loads that list into Timesketch to search and pivot manually.

Issen's supertimeline is a different thing: a **semantic evidence chain builder**. The difference is not performance (though Rust wins that too). The difference is that a sorted list of timestamps is not an investigation -- it is raw material for one. Issen hands the analyst a *narrative*, not a spreadsheet.

**The CTF design principle** (from the Hal Pomeranz 2026-03-24 Father rootkit scenario): the boot log entry at 23:16 showing `libymv.so.3` as "file too short" was meaningless in isolation. It became decisive evidence only when correlated with the file's own `$MFT` born time of 23:24 -- an 8-minute gap proving the rootkit existed before its filesystem timestamps claimed. This is not a coincidence to reconcile. It is the finding. **Temporal discrepancy between artifact sources IS a finding, not noise.**

This principle generalises:
- Prefetch `first_run` timestamp earlier than `$MFT` born time -> timestomping
- `$UsnJrnl` DELETE entry for a binary + Prefetch entry exists -> ran-then-deleted
- Log entry references a file at T1; file's own timestamps say T2 > T1 -> file existed before it claims to
- `4688 process creation` with no corresponding Prefetch update -> hollow process or process injection

Plaso does not detect any of these. It would list all those timestamps side by side in a CSV and leave the analyst to notice the contradiction manually.

#### Scope Clarification

`winevt-forensic` parses EVTX files. That is one artifact type among roughly thirty that contribute to a Windows supertimeline. Even "all Windows logs" is broader than EVTX -- `setupapi.dev.log` (USB first-connect timestamps), `CBS.log` (patch application), `netsetup.log` -- none of these are EVTX. And all Windows logs combined still need correlation with execution artifacts (Prefetch, AmCache, SRUM), file-access artifacts (LNK, Jump Lists, MRU registry keys, Shellbags), and filesystem metadata ($MFT, $UsnJrnl) to produce an investigation-grade timeline.

There is no Linux equivalent of winevt-forensic as a standalone crate because the Linux log landscape has no single dominant binary format and no hayabusa-style user persona to target. Linux log correlation lives inside Issen's parser stack (`rt-parser-linux`, memory dump parsers, etc.) and flows through `rt-correlation`.

#### Artifact Catalog

**Windows: execution evidence** -- confirms a program ran at a specific time.

| Artifact | Key Forensic Value |
|---|---|
| Prefetch (.pf) | First 8 run timestamps + last run + referenced DLLs/files |
| AmCache (hve) | SHA1 hash + first execution -- survives binary deletion |
| AppCompatCache (Shimcache) | Presence = ran or was on disk; no run timestamp |
| BAM/DAM (SYSTEM reg) | Background activity per SID with exact timestamps (Win10+) |
| SRUM (SRUDB.dat) | 60-day CPU/network/energy usage per process per hour |
| UserAssist (NTUSER.DAT) | GUI launch count + last execution (ROT13 encoded path) |

**Windows: file-access evidence** -- confirms a user or process touched a specific file.

| Artifact | Key Forensic Value |
|---|---|
| $MFT | MACB timestamps -- Modify / Access / Change-metadata / Born |
| $UsnJrnl ($J) | High-fidelity change journal: rename, overwrite, delete events |
| LNK files | Target MACB + volume serial + MFT reference -- persists after target deleted |
| Jump Lists (AutoDest/CustomDest) | AppID + target path + timestamps + interaction count |
| RecentDocs (NTUSER.DAT) | Recently opened documents per application |
| OpenSaveMRU (NTUSER.DAT) | Files opened via file-picker dialog |
| LastVisitedMRU (NTUSER.DAT) | Last folder visited in Open dialog |
| Shellbags (UsrClass.dat) | Folder access including network shares and removable media |

**Windows: system-event evidence**

| Artifact | Key Event IDs / Notes |
|---|---|
| EVTX Security | 4624/4625/4648 logon; 4688/4689 process; 4663 object access; 4698/4702 task |
| EVTX System | 6005/6006 boot/shutdown; 7045/7034 service; setupapi events |
| EVTX PowerShell | 4103/4104 ScriptBlock -- command text captured |
| EVTX Sysmon | 1/3/7/8/10/11/22 -- process/network/driver/injection/DNS |
| setupapi.dev.log | USB device first-connect timestamps -- plain text, often overlooked |
| CBS.log | Patch application timeline -- useful for compromise window |
| System/Software reg last-write | Installed software + configuration change timestamps |

**Linux: supertimeline inputs**

| Artifact | Key Forensic Value |
|---|---|
| boot.log | System startup sequence; library load errors -- **temporal anchors** |
| systemd journal (binary) | Covers most subsystems; UTC timestamps; structured |
| auth.log / secure | SSH accept/fail, PAM events, sudo |
| wtmp / btmp | Binary login records -- who was logged in and when |
| auditd audit.log | syscall-level execve, file access, network -- ground truth |
| bash/zsh history | Command execution (optional HISTTIMEFORMAT timestamps) |
| /proc/PID snapshot | From memory dump: cmdline, environ, maps, fd |
| apt/dpkg/yum logs | Software installation timeline |
| /tmp/*.txt, /dev/shm/* | PAM hook output, credential dumps (Father rootkit pattern) |

#### Temporal Correlation Patterns

These are the semantic joins that transform a list of timestamps into findings. Each pattern becomes a `TemporalRule` in `rt-correlation`'s extended YAML schema.

**Pattern 1 -- Execution Confirmation Trinity (Windows)**

```
4688 process creation  }
Prefetch .pf updated   } -- all three within 5s, same binary path
AmCache entry exists   }
-> FINDING: confirmed_execution (confidence: high, three independent sources)
```

**Pattern 2 -- Deleted Execution Recovery**

```
$UsnJrnl CLOSE + DELETE for <binary>.exe
Prefetch entry for same binary exists (any timestamp)
-> FINDING: execution_then_deletion -- binary ran before cleanup
   (the CTF case: rm -rf kit after launching top/xmrig)
```

**Pattern 3 -- Timestomping Detection**

```
$MFT born_time > $MFT modify_time             -- creation after modification (impossible legitimately)
OR
Prefetch first_run_timestamp < $MFT born_time  -- ran before it existed per filesystem
-> FINDING: timestamp_manipulation -- born time was altered after the fact
```

**Pattern 4 -- Boot Log Temporal Anchor (the CTF Pattern)**

```
log_entry references file_path at T1
file_path $MFT born_time = T2  where T2 > T1
-> FINDING: file_predates_own_timestamps -- file existed at T1, not T2
   (the Father rootkit 23:16 boot error vs 23:24 $MFT born time)
```

**Pattern 5 -- Lateral Movement Installation**

```
4624 type-3 logon from <IP>
within 60s:
  7045 service installed
  OR 4698 scheduled task created
  OR Run registry key written
-> FINDING: lateral_movement_persistence -- installed persistence immediately after network logon
```

**Pattern 6 -- Exfiltration Staging**

```
LNK / RecentDocs entry for <file>
within 300s:
  5156 / EVTX network connection from non-browser process
-> FINDING: possible_exfiltration -- file accessed then outbound connection
```

**Pattern 7 -- Living-off-the-Land Pivot**

```
4688 lolbin.exe (certutil / mshta / wscript / regsvr32 / rundll32)
command line contains: -urlcache / -decode / javascript / http / -e / EncodedCommand
no new Prefetch entry created (binary was pre-existing)
-> FINDING: lolbin_proxy_execution -- suspicious use of trusted binary
```

**Pattern 8 -- Layered Persistence Stack**

```
any 2+ of within 30s:
  registry Run key write
  7045 service install
  4698 task create
  startup folder LNK written
-> FINDING: persistence_stack -- multiple redundant persistence mechanisms installed together
```

**Pattern 9 -- Linux Rootkit GID Anomaly**

```
process gid = <unusual numeric value not in /etc/group>
files in same directory share same gid
-> FINDING: rootkit_magic_gid -- process/file GID matches known rootkit config pattern
   (Father rootkit: GID 7823)
```

**Pattern 10 -- PAM Credential Hook Artifact**

```
file created in /tmp/ or /dev/shm/ with timestamp matching a recent PAM logon
file content matches credential format (user:password lines)
-> FINDING: pam_hook_artifact -- rootkit may be capturing credentials via PAM hook
   (Father rootkit: /tmp/silly.txt)
```

**Pattern 11 -- SSH Source-Port Backdoor Trigger**

```
incoming SSH connection source port = known rootkit SOURCEPORT constant
(default Father: 48411)
-> FINDING: rootkit_backdoor_activation -- incoming connection matches rootkit trigger
```

#### Supertimeline Architecture

```
All rt-parser-* crates
        |
        |  Vec<TimelineEvent> (normalized: UTC-ns timestamp, source tag, entity refs)
        v
   rt-timeline (enhanced)
    +-- assemble()          -- merge + sort all events from all parsers
    +-- entity_index()      -- group by file path / process / user / IP
    +-- temporal_join()     -- find events within N seconds of anchor
    +-- deduplicate()       -- collapse same event from multiple sources
        |
        |  SuperTimeline { events, entity_map, source_map }
        v
   rt-correlation (extended schema)
    +-- existing semantic rules (YAML)
    +-- new TemporalRule type:
         within_seconds: N
         entity_matches: [path | process | user | ip]
         absent: <event_type>          -- absence is a finding
         discrepancy: <artifact_a> vs <artifact_b>  -- contradiction is a finding
        |
        |  Vec<Finding> with assertion_level: Observed/Correlated/Inferred
        v
   rt-cli: `rt supertimeline <collection>`
    +-- --format jsonl       -- machine-readable, Plaso-compatible output
    +-- --format csv         -- analyst-friendly, importable into Timesketch
    +-- --format narrative   -- paragraph-form investigation story
    +-- --format html        -- self-contained report with timeline visualization
```

#### New YAML Schema: TemporalRule

Extends the existing correlation rule YAML with temporal constraints:

```yaml
id: temporal-001
name: execution-confirmation-trinity
description: Three independent sources confirm binary execution at same timestamp
severity: info
assertion_level: Correlated
clauses:
  - tag: process_creation
    source: evtx
    event_id: 4688
  - tag: prefetch_updated
    source: prefetch
    event_type: FileModify
  - tag: amcache_entry
    source: amcache
temporal:
  within_seconds: 5
  entity: new_process_name   # the join key -- same binary path across all three
confidence_boost: 30         # each additional source adds confidence

---
id: temporal-004
name: boot-log-temporal-anchor
description: Log entry references file earlier than file's own timestamps claim
severity: high
assertion_level: Correlated
clauses:
  - tag: log_file_reference
    source: [boot_log, journal, cups_log]
    contains_path: true
  - tag: filesystem_born_time
    source: mft
    event_type: FileCreate
temporal:
  discrepancy:
    earlier: log_file_reference
    later: filesystem_born_time
    same_entity: file_path
# discrepancy IS the finding -- no within_seconds needed
```

#### rt-timeline Enhancements Needed

Current `rt-timeline` is a basic sorted store. It needs:

1. **Entity index**: Group `TimelineEvent`s by their entity references (file path, process name, user, IP address). Currently events have no cross-reference.

2. **Temporal join primitive**: Given an anchor event, return all events from specified sources within +/-N seconds. This is the fundamental operation underlying all temporal correlation patterns.

3. **Absence detection**: Given a set of events and a temporal window, assert whether an expected event type is present. Absence of expected events (e.g., no Prefetch update after 4688) is forensically significant.

4. **Timestamp normalization registry**: Each parser reports its timestamp precision and timezone assumptions. The assembler normalises all to UTC nanoseconds with a recorded precision level (second / millisecond / nanosecond). Low-precision sources (bash_history without HISTTIMEFORMAT) are flagged.

5. **Source confidence weighting**: Not all artifact sources are equally reliable. EVTX with a sequence number is more trustworthy than a bash_history line. Temporal joins should carry a `source_confidence` weight.

#### Supertimeline TDD Sequence

**Phase 1 -- rt-timeline enhancements (RED then GREEN)**:
- `temporal_join_returns_events_within_window`
- `temporal_join_excludes_events_outside_window`
- `entity_index_groups_by_file_path`
- `entity_index_groups_by_process_name`
- `entity_index_groups_by_user`
- `deduplication_removes_same_event_from_multiple_sources`
- `timestamp_normalization_converts_windows_filetime_to_utc_ns`
- `absence_detection_fires_when_event_type_missing_in_window`

**Phase 2 -- TemporalRule in rt-correlation (RED then GREEN)**:
- `temporal_rule_within_60s_matches_sequence`
- `temporal_rule_outside_window_no_match`
- `absent_clause_fires_when_prefetch_missing_after_4688`
- `discrepancy_clause_fires_when_log_timestamp_before_mft_born_time`
- `boot_log_anchor_contradicts_file_mtime` (the CTF pattern as a test)
- `father_rootkit_gid_7823_anomaly_detected`
- `pam_hook_artifact_tmp_silly_txt_detected`
- `deleted_execution_recovery_usnJrnl_plus_prefetch`
- `timestomping_mft_born_after_modify`

**Phase 3 -- `rt supertimeline` CLI command (RED then GREEN)**:
- `supertimeline_command_exists_with_collection_arg`
- `supertimeline_jsonl_output_is_valid`
- `supertimeline_csv_output_has_correct_headers`
- `supertimeline_narrative_output_is_non_empty`
- `supertimeline_with_no_parsers_returns_empty_gracefully`
- `supertimeline_temporal_findings_appear_in_output`

#### Supertimeline Implementation Tasks

- [ ] Extend `TimelineEvent` with `entity_refs: Vec<EntityRef>` (file/process/user/ip)
- [ ] Add `EntityIndex` and `temporal_join()` to rt-timeline
- [ ] Add `absent:` and `discrepancy:` clauses to rt-correlation YAML schema
- [ ] Implement `TemporalRule` evaluation in rt-correlation engine
- [ ] Port CTF boot-log-anchor pattern as a bundled TemporalRule
- [ ] Port Father rootkit GID anomaly as a bundled TemporalRule
- [ ] Port PAM hook artifact pattern (`/tmp/silly.txt`) as a bundled TemporalRule
- [ ] Add `rt supertimeline` subcommand to rt-cli
- [ ] Wire all existing parser crates into supertimeline assembler
- [ ] Add SRUM parser (ESE database) -- high-value execution/network evidence
- [ ] Add AmCache parser -- execution with SHA1 hash
- [ ] Add AppCompatCache (Shimcache) parser
- [ ] Add Shellbags parser
- [ ] Add setupapi.dev.log parser (USB first-connect timestamps)

---

## 7. Supertimeline Positioning vs Plaso

| Dimension | Plaso | Issen Supertimeline |
|---|---|---|
| Language | Python | Rust |
| Requires full disk image | Yes | No -- streams from S3/SFTP/local |
| Output | CSV / PLASO DB | JSONL, CSV, narrative, HTML |
| Visualisation | Needs Timesketch | Built-in narrative + HTML |
| Temporal discrepancy detection | No | Yes -- finding-level |
| Absence-as-a-finding | No | Yes |
| Cross-artifact semantic correlation | No | Yes (rt-correlation rules) |
| Clock skew detection | No | Yes (rt-correlation/skew.rs) |
| Narrative generation | No | Yes |
| Linux correlation | Parser coverage | Parser coverage + temporal rules |

**The pitch: Plaso tells you what happened. Issen tells you what it means.**

---

## 8. Ecosystem CLI Strategy

### 8.1 Confirmed Architecture: Pure Libraries + Single rt CLI

```
winevt-forensic   <-- pure library, NO CLI  (publish to crates.io)
srum-forensic     <-- standalone lib + sr-cli
browser-forensic  <-- standalone lib + bw-cli
memory-forensic   <-- standalone lib, NO CLI
        all are library deps of
Issen       <-- full suite, cross-artifact correlation, the rt CLI
```

**winevt-forensic has no CLI.** The decision was made to keep it a pure library crate. The `rt` CLI in Issen is the single entry point for EVTX-based investigation workflows. Issen must never shell out to other CLIs; it imports them as Rust library crates.

### 8.2 rt CLI -- EVTX Subcommands (Hayabusa Differentiator)

The EVTX investigation subcommands that were once planned as a `wt-evtx` standalone CLI now belong to `rt` via `rt-evtx`. The audience is the same (hayabusa users), the delivery mechanism changed.

**Our differentiators -- what hayabusa cannot do:**

```bash
rt evtx sessions   --directory /evidence/evtx                   # 4624->4634 LogonID correlation
rt evtx processes  --directory /evidence/evtx --link-sessions   # 4688 attributed to session
rt evtx frequency  --directory /evidence/evtx --cap 5           # anomaly-by-rarity
```

hayabusa is a **defender tool** (bulk alerting, Sigma rules, EDR). `rt` is an **investigator tool** (session reconstruction, attribution, timeline narrative). The audiences overlap but the job-to-be-done differs. `rt-signatures` handles Sigma-equivalent rules at the Issen level.

**Implementation tasks (Group 4, after rt-evtx library is complete):**
- [ ] Add `rt evtx sessions` subcommand to rt-cli
- [ ] Add `rt evtx processes --link-sessions` subcommand
- [ ] Add `rt evtx frequency --cap N` subcommand
- [ ] Wire winevt-carver fallback: when `EvtxParser::from_path` fails, fall back to `carve_from_file`
- [ ] Wire `IntegrityIndicator`s into triage output as anti-forensic report section

### 8.3 memory-forensic CLI -- Volatility Compatibility Strategy

Target audience: Volatility users with `vol -f mem.dmp windows.pslist` muscle memory.

Win them by:
1. Accepting their flag shapes (`-f`, `--output`)
2. Making common operations faster (native Rust, no Python startup)
3. Adding something Volatility cannot: session linkage across memory + EVTX (cross-tool joins requiring winevt-forensic + memory-forensic together, orchestrated by Issen)

### 8.4 Adoption Benefits

- Multiple adoption vectors: hayabusa users, Volatility users, Issen users
- Clean library boundaries: Issen compiles against library APIs, not CLIs
- Independent community growth and GitHub presence per tool
- Smaller blast radius: breaking changes in one crate do not cascade

---

## 9. Critical Bugs to Fix First

These are Group 0 blockers. No feature work should begin until these are resolved.

### 9.1 srum-forensic: ESE_PAGE_FLAG_SPACE_TREE Wrong Value

**Current**: `0x0400`
**Correct**: `0x0020`
**Location**: ese-core page flag constants
**Impact**: Incorrect page type identification; any page parsing that checks this flag produces wrong results.

### 9.2 srum-forensic: Synthetic ESE Catalog Decoders

**Problem**: `CatalogEntry` uses a synthetic 32-byte flat format that does not match the real ESE catalog wire format (MSysObjects). `srum-parser` silently produces garbage against real `SRUDB.dat` files.

**Fix**: Implement real ESE B-tree catalog walk using the actual MSysObjects table format with proper column-type-aware record decoding (fixed/variable/tagged column encoding).

### 9.3 winevt-forensic: IntegrityIndicator Naming — ✅ DONE

Enum renamed to `IntegrityIndicator`, crate renamed to `winevt-integrity`. All source files updated, tests pass, clippy clean.

---

## 10. TDD Requirements

**Mandatory for all work in this plan. No exceptions.**

### Process

1. **RED**: Write failing tests first that define the expected behavior. Run them. Confirm they fail.
2. **GREEN**: Write the minimal implementation to make tests pass. Run them. Confirm they pass.
3. **REFACTOR**: Clean up while keeping tests green.

### Commit Discipline

- **Separate commits are mandatory**: RED commit (failing tests only), then GREEN commit (implementation that makes them pass).
- The RED commit is verifiable proof that TDD actually happened. Without it, there is no evidence the tests were written first.
- The only exception is trivial one-line changes where a single commit is clearly sufficient.

### Subagent Instructions

When dispatching subagents, explicitly instruct them to make **two separate commits per task** -- one RED (tests that fail) and one GREEN (implementation that passes). Include this instruction verbatim in the subagent prompt. Do not accept a single combined commit.

### Test Execution Safety

- **NEVER run multiple vitest/test processes concurrently** -- this has repeatedly consumed all system RAM
- Prefer targeted test runs over full-suite runs
- For Rust: `cargo test -p <crate> -- <test_name>` over `cargo test --workspace`

---

## Recommended Workstream Order (within Issen)

1. Add integration snapshot test for the scenario (Workstream 8 -- establishes baseline)
2. Rename `PIVOT FINDINGS` to `CORRELATION FINDINGS` (Workstream 5)
3. Add evidence rendering in `rt-correlation` (Workstream 3)
4. Extend findings with summary/explanation/confidence/assertion level (Workstream 1)
5. Add `all_thread_names` support in `rt-parser-uac` (Workstream 2)
6. Rework `analyse.rs` to use correlation-driven rendering (Workstream 4)
7. Recalibrate tunnel/miner/rootkit wording (Workstreams 6 + 7)
8. Add stronger miner confirmation tiers (Workstream 9)
9. Regenerate the scenario doc from actual output (Workstream 8 finalization)
10. Supertimeline Engine (Workstream 10 -- capstone, depends on all parsers)

---

## Success Criteria

The plan is complete when:

- The current code can generate output that is either truly verbatim or intentionally marked as representative
- Miner/rootkit/tunnel conclusions are calibrated to available evidence
- The doc no longer promises behavior the code does not implement
- `rt analyse` relies primarily on structured correlation findings rather than hardcoded scenario prose
- All parser repos follow the `IntegrityIndicator` naming convention
- `memf-core` has been renamed to `memf-hw`
- srum-forensic correctly parses real SRUDB.dat files
- The supertimeline engine detects temporal discrepancies as first-class findings
- All 11 temporal correlation patterns are implemented as TemporalRules
- `rt supertimeline` produces JSONL, CSV, narrative, and HTML output
