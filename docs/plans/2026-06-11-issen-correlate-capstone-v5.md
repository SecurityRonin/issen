# Design Memo — `issen correlate` Capstone v5 (Task #37 / WS-E + P3)

**Date:** 2026-06-11 · **Status:** DESIGN v5 (pre-implementation)
**Predecessors:** [`2026-06-11-issen-correlate-capstone.md`](2026-06-11-issen-correlate-capstone.md)
(v4 — the walshcat oracle F1–F25, PRE-1..6, the 10-rule set),
[`2026-06-11-case001-ground-truth-corpus.md`](2026-06-11-case001-ground-truth-corpus.md)
(#74 — the union write-up corpus: F1–F25 corroborated, F26–F44 added, memory-leg posture
corrected), measured baseline
[`../workshop-3hr/issen-measured-coverage.md`](../workshop-3hr/issen-measured-coverage.md).
**v5 change:** the acceptance target widens from the single walshcat write-up (F1–F25) to the
**union finding set F1–F44** across all twelve retrieved write-ups; every status label is
re-graded against the *measured* baseline and the codebase **at HEAD, re-verified this date**
(§3); two acceptance **gates** (G1 disk re-run, G2 memory first-run) are promoted from
assumptions to explicit blocking steps; two scoped **memory builds** (M-1, M-2) join the
pre-task list; the rule set grows 10 → 11 (`CORR-PROC-MIGRATION`) and the Session Envelope
widens to multi-session (F44).

## Executive Summary

`issen correlate <case-dir>` is one command that turns a directory of raw evidence — for
Case 001: two E01 disk images and two memory dumps — into a single cross-artifact,
cross-host DuckDB super-timeline plus an HTML report whose findings are *correlations*
(joined observations spanning five evidence sources: MFT, USN journal, EVTX, registry,
memory) rather than N independent per-artifact rows.

**The testable target:** produce at least every in-scope finding in the **union ground-truth
set F1–F44** — the walshcat write-up's F1–F25 (each now corroborated by ≥ 1 additional
published write-up, none contradicted) plus the memory/Volatility findings F26–F37 and the
non-memory deltas F38–F44 that the broader corpus adds. The §2 matrix maps each finding to
its evidence source, the issen capability that produces it, an honest status, and the
pre-task/build/gate that blocks it. The matrix is the acceptance test (§8.1).

**The honest count across all 44 findings:**

| Status | Count | Findings |
|---|---|---|
| **MEASURED-TODAY** | **1** | F5 |
| **DESIGN** | **27** | F1, F2, F4, F6, F8, F9, F12, F13, F14, F17, F19, F20, F21, F22, F23, F25, F26, F27, F28, F29, F31, F32, F34, F36, F37, F41, F44 |
| **PARTIAL** | **9** | F3, F10, F11, F15, F24, F30, F33, F35, F40 |
| **OUT** | **7** | F7, F16, F18, F38, F39, F42, F43 |

Only one finding is *fully demonstrated on the actual Case 001 corpus today* (F5, the 4625
brute-force burst at 03:21:25 UTC) — and even that measurement comes from a DC01 ingest
that was killed at 23 minutes, so it re-verifies under gate G1 like everything else. This
is a deliberate v5 downgrade from v4's "4 TODAY": F13/F20/F25 had TODAY labels resting on
member events or on a partial/under-parsed ingest, not on the full finding being
demonstrated (§1.3). Many DESIGN rows already have **measured member events** (the 4624
from `194.61.24.102` at 03:21:48, first coreupdater MFT event 03:24:06, the Desktop 4624
type 10 at 03:36:24, 129 × 7045, 5 loot.zip events, 8 Beth_Secret MFT events) — the
*findings* are DESIGN because the correlation, the missing leg, or the unverified-at-scale
pipeline still gates them.

**The corrected memory-leg posture (do not regress):** the memory leg is issen's strongest
in *capability* — `memf ps`/`netstat`/`scan`/`creds` are now routed end-to-end for
Windows-profiled dumps at the code level, with auto-profile (kernel-scan → RSDS GUID →
`AutoProfile`) landed in `build_reader` (§3.6, fresher than the #74 corpus snapshot) — but
it is **honestly gated**: nothing has yet been run against the real Case 001 dumps (gate
G2), results are not persisted to the timeline (PRE-1), and two scoped **builds** remain:
the C2 annotation does not cover the Szechuan C2's `:443` (`is_suspicious_remote_port`
matches only `4444`, so the C2 surfaces as `external-established` — build M-1), and
malfind sub-classification cannot emit `injected-PE` because `WinMalfindInfo.first_bytes`
is an empty placeholder (`memory-forensic/crates/memf-windows/src/vad.rs:135` — build M-2).
Once PRE-1 + M-1 + M-2 + G2 land, issen's memory output is **consistent with matching**
the published memory analyses (W1, W7–W9) and **consistent with exceeding** the walshcat
write-up's coverage (which contains no memory analysis) — neither is claimed as
demonstrated today.

**Two blocking acceptance gates, not assumptions (§5):** the measured baseline predates
the #23 (batched insert), #26 (Desktop `$MFT` under-parse) and #61 (ntfs-core
`$ATTRIBUTE_LIST` runlist) fixes. Every disk-leg label that leans on the baseline assumes
those fixes hold at this image's scale. **G1** (fresh end-to-end DC01 + Desktop ingest)
and **G2** (first end-to-end `memf` run on both dumps) must pass — and the matrix be
re-graded against their output — before any rule-tier implementation begins.

**Validation:** fast synthetic fixtures gate CI; the real Case 001 corpus is the
`#[ignore]`-gated oracle behind a documented release gate. The corpus test is the §2
matrix made executable — one assertion block per in-scope row (37 blocks; 7 OUT rows
documented as exclusions), so "produces at least every union finding" is machine-checked,
not narrated.

**Architecture (unchanged from v4):** an ordered-window correlation evaluator in
`issen-correlation` (DuckDB-free) over stored-event slices fetched through a
bounded-by-construction `fetch_events` API in `issen-timeline`, persisting into
`correlations` + `correlation_members` (keyed on `timeline.id`), rendered by new report
sections. Findings are observations, never legal conclusions — "consistent with"
throughout; the tribunal concludes.

---

## 1 · The oracle — the union finding set F1–F44

### 1.1 Definition by reference (no restatement)

- **F1–F25** are defined verbatim in the v4 memo §1.3 (walshcat decomposition, with the
  §1.2 reconciliation notes: the pcap-clock skew, the `194.61.24.102` body-text typo, the
  Q9 host↔IP label swap). The #74 corpus §2.1 corroborates every one of them from ≥ 1
  additional write-up; none is contradicted.
- **F26–F37** (memory/Volatility) and **F38–F44** (non-memory deltas) are defined in the
  #74 corpus §2.2–2.3, with single-source leads U1–U4 explicitly quarantined (corpus §2.4
  — they do **not** enter this acceptance set).
- The §2 matrix abridges each finding to one line; the definitions above are normative.

### 1.2 Status taxonomy (stricter than v4)

- **MEASURED-TODAY** — the finding's full in-scope assertion has been demonstrated on the
  actual Case 001 corpus, with recorded values. (Member events alone do not qualify.)
- **DESIGN** — produced once the named pre-task(s)/build(s)/rule(s)/gate(s) land. The
  matrix's "Measured members today" column records partial demonstrations honestly.
- **PARTIAL** — the in-scope half is produced (or designed); a named leg is out of
  scope/reach and stays so in v5.
- **OUT** — out of reach/scope, with the reason and the (unpromised) closure path.

### 1.3 The v4→v5 re-grades (the honesty corrections, recorded once)

| F | v4 label | v5 label | Why |
|---|---|---|---|
| F13 | TODAY | DESIGN (G1) | The 03:24:06 MFT value was measured, but from the killed-at-23-min DC01 partial ingest, and the finding's USN-agreement leg was never demonstrated — the DC01 run emitted MFT + EventLog events only, no USN rows (`issen-measured-coverage.md:35`). Full finding = MFT + USN on a completed run. |
| F20 | TODAY | DESIGN (G1) | No Secret-folder `FileAccess` measurement exists in the baseline at all; the Desktop `$MFT` parsed to only 31 records (`issen-measured-coverage.md:46`), so the per-file access claim is unverified on both hosts. |
| F25 | TODAY (events) | DESIGN | `Logoff` events are present (baseline Q13 row), but the finding — *the last adversary logoff, time-pinned* — needs the session-envelope surfacing, which does not exist; the specific UTC value is still unreconciled (open Q4). |
| F12 | DESIGN, "measured ground truth confirms it is memory-resident" | DESIGN, reworded | No issen memory run has touched the dumps; the C2-in-RAM observation belongs to the published write-ups (W1/W7/W8/W9), not to an issen measurement. The wording is now "the published netscan results are consistent with the C2 being recoverable from RAM by issen's netstat route." |
| F34 | (corpus) "EXCEEDS" | DESIGN (G2) | `classify_connection` mechanizes the analyst's noise triage and is unit-tested, but has never run on the real dump; "matches the analyst's first pass" is the claim *after* G2, "exceeds" is claimed nowhere. |
| memory headline | v4: "the memory leg is where issen *exceeds* the oracle" | §4 posture | Detects-locally + wiring + two builds + validation; "consistent with exceeding" only after the gates land. |

---

## 2 · The unified acceptance matrix (F1–F44)

**Legend.** *Kind*: `CORR` = needs a correlation rule; `single` = single-artifact
surfacing. *Gate/Pre*: what blocks the row (G1/G2 gates §5; PRE-1..6 §6.1; M-1/M-2 §6.2;
rule tiers §7). Statuses per §1.2. File:line citations are verified at HEAD (§3).

### 2.1 Disk / EVTX / registry leg (F1–F25)

| F | Finding (abridged) | Evidence | Producing capability | Kind | Status | Gate/Pre | Measured members today |
|---|---|---|---|---|---|---|---|
| F1 | DC OS = Win Server 2012 (R2) | registry | PRE-3 `CurrentVersion\ProductName` → host profile | single | DESIGN | PRE-3, G1 | — |
| F2 | Desktop OS = Win 10 Enterprise | registry | same, Desktop hive | single | DESIGN | PRE-3, G1 | — |
| F3 | DC tz misconfigured Pacific → clock skew | registry + EVTX | PRE-3 `TimeZoneInformation` values; EVTX 6013 flows as `Other("EventID:6013")` (mapper catch-all, lib.rs:75); EVTX-internal skew via `detect_time_skew` (`issen-correlation/src/skew.rs:74`) | single | PARTIAL | PRE-3, G1 | — (pcap cross-check leg OUT) |
| F4 | A breach occurred | all five | the correlation chain + report (the capstone) | CORR | DESIGN | all tiers | burst + logons + 7045s exist as events |
| F5 | 4625 brute-force burst vs Administrator | EVTX | 4625→`LogonFailure` (lib.rs:62) + `failed_logon_burst_finding` (`issen-signatures/src/attack_classifier.rs:105`) | single | **MEASURED-TODAY** | re-verify under G1 | burst @ 03:21:25 UTC (DC01 partial ingest) |
| F6 | 4624 from `194.61.24.102` follows burst → RDP brute initial access | EVTX | `CORR-BRUTEFORCE-LOGON` | CORR | DESIGN | PRE-2/4, Tier B | the 4624 type 10, Administrator, 03:21:48 is measured |
| F7 | pcap: ICMP probe then RDP brute traffic | pcap | none | — | OUT | no pcap parser (§2.4) | — |
| F8 | `coreupdater.exe` is the malicious file, HTTP-fetched | MFT+USN+EVTX+mem | the chain LOGON-MALWARE-WRITE → RELOCATE → PERSIST → PROC-DISK-MATCH names it by convergence | CORR | DESIGN | Tiers A–C | 4 coreupdater MFT events (DC01) |
| F9 | SHA256 of the binary, known-bad | disk bytes | PRE-6 extract (`issen-disk/src/lib.rs:273 extract_files`) + hash + `--hash-iocs` match (`issen-cli/src/commands/ingest.rs:214`) | single | DESIGN | PRE-6 | — (hash now text-corroborated: corpus §1, `10f3b920…cfda6`) |
| F10 | Download corroborated by webcache + Amcache | Amcache (+webcache) | Amcache parser exists (`crates/parsers/issen-parser-amcache/`) but is dead code — not force-linked | single | PARTIAL | PRE-5, G1 | — (IE WebCache/ESE leg OUT) |
| F11 | `194.61.24.102` = payload-delivery IP | EVTX | IP surfaced as BRUTEFORCE-LOGON subject + 4624 metadata | single/CORR | PARTIAL | rides F6 | IP present in measured 4624 metadata |
| F12 | C2 = `203.78.103.109` | memory | PRE-1 netstat → `NetworkConnect` + `CORR-INJECTED-C2`; a local-RAM route where the write-ups pivoted via VirusTotal (W1/W7/W8/W9 report it from netscan — consistent with it being recoverable by issen's route) | CORR | DESIGN | PRE-1, G2, Tier C | — |
| F13 | coreupdater first on DC 2020-09-19 03:24:06 UTC, MFT **with USN agreement** | MFT + USN | `FileCreate` from both parsers (`issen-cli/src/parsers/mft.rs:119`, `usnjrnl.rs:118`) | single | DESIGN | **G1 only** (re-grade §1.3) | MFT value 03:24:06 measured; USN leg never ran on DC01 |
| F14 | Moved Downloads → System32 (both hosts) | USN + MFT | `CORR-MALWARE-RELOCATE`, asserted on both hosts | CORR | DESIGN | Tier A, G1 | — (webcache corroboration leg OUT) |
| F15 | Malware = Meterpreter/Metasploit | OSINT (+memory route) | family naming is out of local scope; hash-IOC labels (PRE-6) and YARA over malfind dumps (F30) carry "consistent with" labels | — | PARTIAL | PRE-6 label / F30 | — |
| F16 | Metasploit easily obtained | — | not evidence-derived | — | OUT | excluded | — |
| F17 | Persistence both hosts: `coreupdater` service (7045) + Run/Services key | EVTX + registry | 7045→`ServiceInstall` (lib.rs:66) + `CORR-MALWARE-PERSIST` + `CORR-PERSIST-REGCONFIRM` | single+CORR | DESIGN | PRE-3, Tier B' | 129 × 7045 measured (coreupdater among them) |
| F18 | OSINT on both IPs (CVE-2015-1635, AlienVault) | OSINT | none (W2's APT link was retracted by its author — never assert) | — | OUT | enrichment out of scope | — |
| F19 | Lateral movement RDP DC→Desktop ~03:36 UTC, Administrator | EVTX (+reg inventory) | `CORR-LATERAL-MOVE` (5 guards, v4 §5.3) | CORR | DESIGN | PRE-2/3, Tier D | Desktop 4624 type 10 from `10.42.85.10`, 03:36:24 measured |
| F20 | Administrator accessed all Secret-share files (both hosts) | MFT | `FileAccess` events (mft.rs:111) over Secret paths | single | DESIGN | **G1 only** (re-grade §1.3) | — (no measurement exists; Desktop MFT was under-parsed) |
| F21 | Staging: `loot.zip` (Desktop) + `secret.zip` (DC) + `Loot.lnk`/`Secret.lnk` | USN+MFT+LNK | `CORR-EXFIL-STAGE` on **both** hosts; LNK corroboration after PRE-5 (parser exists; no `.lnk` arm in `detect_artifact_type`, `issen-fswalker/src/orchestrator.rs:78`) | CORR+single | DESIGN | Tier B, PRE-5, G1 | 5 loot.zip events measured (Desktop); secret.zip unmeasured (DC01 USN never ran) |
| F22 | Domain C137; CITADEL-DC01 + DESKTOP-SDN1RPT on 10.42.85.0/24 | registry + EVTX | PRE-3 `ComputerName` + `Tcpip\…\Interfaces` → host profile; EVTX `Computer` today | single | DESIGN | PRE-3, G1 | hostnames flow in measured EVTX events |
| F23 | The sauce was stolen (rides F20+F21) | MFT + USN | both F20 and F21 members in one chain; narrated "consistent with staging for exfiltration" | CORR | DESIGN | rides F20/F21 | — |
| F24 | `SECRET_beth.txt` deleted ~03:32; copy `Beth_Secret.txt` ~03:38; recycle bin | USN + MFT | singles: `FileDelete`/`FileCreate` (usnjrnl.rs:118-120); `CORR-COPY-DELETE` joins them | single+CORR | PARTIAL | Tier A, G1 | 8 Beth_Secret MFT events measured (content-diff leg OUT; recycle *content* OUT → F43) |
| F25 | Last adversary contact: last DC logoff (~"2:57" pcap-clock) | EVTX | 4634/4647→`Logoff` (lib.rs:63) + Session-Envelope surfacing | single | DESIGN (re-grade §1.3) | envelope (§7.3), open Q4 | Logoff events present in baseline |

### 2.2 Memory leg (F26–F37)

`memf` capability references: `crates/issen-mem/src/dispatch.rs` + `cmd_memf.rs` (this
repo) and `~/src/memory-forensic/crates/memf-windows/src/` (path-dep fleet repo). All
"routed" claims verified at HEAD (§3.6); **none has run on the real dumps yet — every row
is G2-gated on top of its named pre/build.**

| F | Finding (abridged) | Vol-plugin equivalent | issen capability (verified) | Status | Gate/Pre |
|---|---|---|---|---|---|
| F26 | `coreupdater.exe` PID 3644 present, dead (0 threads), orphaned (PPID absent) | `pslist`/`pstree` | `memf ps` → `dispatch_windows_ps` (dispatch.rs:792) → `walk_processes`; routed for Windows (cmd_memf.rs:167); auto-profile in `build_reader` (dispatch.rs:35-96) | DESIGN | PRE-1 (persist), G2 |
| F27 | C2: PID 3644 ESTABLISHED to `203.78.103.109:443` | `netscan` | `memf netstat` → `dispatch_windows_netstat` (dispatch.rs:854) + Note column via `classify_connection` (dispatch.rs:771,:883). **Today the C2 row would read `external-established`, not a C2-graded note: `is_suspicious_remote_port` = `matches!(port, 4444)` (dispatch.rs:761; test at :1986 pins `!443`)** | DESIGN | **M-1 (build)**, PRE-1, G2 |
| F28 | `spoolsv.exe` PID 3724 injected: RWX-private VAD with MZ header = injected PE | `malfind` | `memf scan` → `dispatch_windows_scan` (dispatch.rs:1015) → `vad::walk_malfind` (:1043), labels `malfind:{classify_malfind_region(first_bytes)}` (:1048). **Detection fires; sub-classification cannot: `first_bytes` is `Vec::new()` placeholder (memf-windows `vad.rs:135`), so the label is always `injected-code`, never `injected-PE` (`classify_malfind_region(&[])` default, test :1957)** | DESIGN | **M-2 (build)**, PRE-1, G2 |
| F29 | Process migration coreupdater → spoolsv (dead orphan ∧ injected ∧ shared C2) | `pstree`+`netscan`+`malfind` joined | **new rule `CORR-PROC-MIGRATION`** (§7.2) | DESIGN | Tier C', after F26–F28 |
| F30 | Injected region classifies as Meterpreter (ClamScan/FLOSS on dump) | `malfind -D` + AV/strings | region dump + `memf-windows::yara_scan`/strings; family naming = rule/AV territory, carried only as "consistent with" | PARTIAL | rides F28; family leg unpromised |
| F31 | spoolsv also LISTENING on 62475 | `netscan` | netstat LISTENING rows (same route as F27) | DESIGN | PRE-1, G2 |
| F32 | Malware at SYSTEM → credential exposure (DC-wide) | (inference) + `hashdump` | `memf creds` → `dispatch_windows_creds` **is routed** (cmd_memf.rs:172; walkers `hashdump.rs`/`lsadump.rs`/`sam.rs` in memf-windows) — unvalidated on any real dump | DESIGN | G2 (validation), PRE-1 |
| F33 | Desktop dump defeats structured parse; strings/IOC sweep still hits the IOCs — Desktop-memory conclusions carry lower (FLOSS-grade) confidence | (vol failure) + strings | `memf-strings` is an issen-mem dependency (Cargo.toml:16) but no `strings` subcommand exists in `MemfCommand`; the fallback path + the confidence labeling are design work | PARTIAL | §7.4 fallback design, G2 |
| F34 | DC netscan noise triage (subtract known-noise, keep external-established) | analyst technique | `classify_connection` Note column mechanizes it (unit-tested, dispatch.rs:1992-2005) — consistent with matching the analyst's first pass once measured | DESIGN | G2 (re-grade §1.3) |
| F35 | OS/build confirmable from RAM (KDBG profile; in-RAM SOFTWARE hive) | `kdbgscan`/`printkey` | auto-profile resolution landed (B1, dispatch.rs:59,:86-96); in-RAM `registry.rs` walker exists but is not a wired subcommand | PARTIAL | G2; printkey wiring unpromised |
| F36 | Memory-resident ShimCache feeds evidence-of-execution | `timeliner`/shimcache | `memf-windows::shimcache.rs` walker exists; unwired to any timeline | DESIGN | PRE-1-adjacent (§6.1), G2 |
| F37 | Memory bodyfile merged into the super-timeline | `timeliner` bodyfile | `MemfCommand::Timeline` is declared but returns "not yet wired for this OS" for Windows (cmd_memf.rs:177-182) | DESIGN | PRE-1 (§6.1), G2 |

### 2.3 Non-memory deltas (F38–F44)

| F | Finding (abridged) | Evidence | Producing capability | Status | Gate/Pre |
|---|---|---|---|---|---|
| F38 | Brute tool was Hydra | behaviour (named in W2) | F5/F6 reach "RDP brute force" without naming the tool — the correct epistemic ceiling for local evidence | OUT (as-named) | — |
| F39 | Recon: ICMP probe + NMAP scan of 3389, Snort alert | pcap + IDS | none | OUT | no pcap parser (§2.4) |
| F40 | Attacker Kali hostname via EVTX 4776 (NTLM) / LLMNR | EVTX 4776 | 4776 is **not** in the EVTX map (verified: zero matches in `issen-parser-evtx/src/lib.rs`); add a 4776 mapping + hostname metadata (D2) | PARTIAL | D2 mapping (§6.1); LLMNR leg OUT (pcap) |
| F41 | Single compromised credential reused for the DC→Desktop pivot | EVTX cross-host | exactly `CORR-LATERAL-MOVE` guard (3) — same account as the host-A chain | DESIGN | Tier D (rides F19) |
| F42 | C2 geolocates to Netway, Bangkok (whois) | whois/RIR | none — online enrichment, deliberately unpromised | OUT | — |
| F43 | Beth's file *content* recovered from `$Recycle.Bin\S-1-…-500` | `$I`/`$R` carve | no `$I`/`$R` content carver; USN rename-into-`$RECYCLE.BIN` movement is covered under F24 | OUT | — |
| F44 | A **second adversary session** (logoff → un-migrated meterpreter dies → re-login → migrate → exit) | EVTX + memory | **multi-session Session Envelope** (§7.3) + `CORR-PROC-MIGRATION` members | DESIGN | envelope (§7.3), Tier C' |

### 2.4 The honest out-of-reach list (what would close each — named, not promised)

| Missing leg | Findings affected | Why out of reach | Closure path |
|---|---|---|---|
| pcap parsing | F7, F39, F8 (mechanism), F9 (pcap-carve route), F11 (delivery role), F3 (clock cross-check), F40 (LLMNR) | no pcap parser in `crates/` | zeek-forensic (planned LOG FORMAT crate) |
| IE/Edge WebCache (ESE) | F10, F14/F21 corroboration | no ESE-webcache parser (issen-browser = Chrome/Firefox/Safari) | webcache parser riding srum-forensic's ESE layer |
| online enrichment (VT/whois/AlienVault) | F15, F18, F42 | local-evidence-only scope; lookups are not reproducible oracle inputs | optional `enrich` pass, separate task |
| file-content extraction + diff | F24 content leg | PRE-6 hashes flagged executables; no document diff | future content-diff work |
| recycle-bin `$I`/`$R` carving | F43, F24 deletion detail | no carver; USN movement events cover the observation | small `$I`/`$R` carver, low priority |
| memory family naming (YARA/AV) | F30 family leg, F15 | rule-pack territory; `yara_scan.rs` exists but no curated rules ship | optional rule pack, unpromised |

---

## 3 · What exists today (re-verified 2026-06-11 at HEAD, file:line)

All citations below were re-checked against the working tree this date. Two v4 citation
classes the prior review flagged are corrected and re-verified here: the artifact-discovery
path is **`crates/issen-fswalker/src/orchestrator.rs`** (`detect_artifact_type` at :78,
registry-directory path guard at ~:111), and the hash-IOC load lives in
**`crates/issen-cli/src/commands/ingest.rs:214`** (`if let Some(hash_files) = hash_iocs`;
scanning enabled at :125-126). There is no `issen-disk/src/ingest.rs`.

### 3.1 CLI surface (`crates/issen-cli/src/main.rs`)
Force-linked parser crates are exactly four (main.rs:12-15): `issen_parser_evtx`,
`issen_parser_registry`, `issen_parser_uac`, `issen_parser_velociraptor`. Disk-container
providers at :18-24. **No `Correlate` command variant** (grep: only a doc comment on the
`Session` command mentions the word). Amcache/lnk/shimcache/prefetch parser crates exist
under `crates/parsers/` with `inventory::submit!` but are never linked — the PRE-5 gap
holds.

### 3.2 Artifact discovery (`crates/issen-fswalker/src/orchestrator.rs:78`)
`detect_artifact_type` arms: `$J`/usnjrnl, `$MFT`, `.evtx`, `.pf`, registry-hive basenames
(only when the full path contains "registry" or "config", ~:111), `amcache.hve`,
`srudb.dat` — and nothing else. **No `.lnk` arm** (and none for shellbags). The
registry-zero-events failure stays undiagnosed; the path guard remains the prime suspect
(PRE-3 diagnoses, doesn't guess).

### 3.3 Timeline store / event model / correlation library — v4 §3 verified at HEAD
No `entity_refs` column and no correlation tables anywhere in `issen-timeline` (grep:
`entity_refs` appears only in `temporal.rs` over in-memory events); no
`fetch_events`/`EventQuery` anywhere in `crates/` (grep: zero matches). Production
`with_entity_ref` call sites remain exactly three, all in
`issen-cli/src/commands/supertimeline.rs` (:78, :108, :130). `issen-correlation` is
DuckDB-free; `detect_time_skew` at `skew.rs:74`; no ordered evaluator exists.

### 3.4 EVTX parser (`crates/parsers/issen-parser-evtx/src/lib.rs`)
Event-ID map at :61-75: 4624/4625/4634+4647/4688/4689/7045/7036/4698/4702/4720+4722/
boot-shutdown/5156-5157 → typed; else `Other("EventID:<n>")` (:75). An accuracy regression
test pins the table (lib.rs:443+). **4776 is absent** (zero matches) — F40's D2 extension
is real work. Zero `with_entity_ref` calls — PRE-2 holds.

### 3.5 Registry / MFT / USN / disk / signatures — v4 §3 verified at HEAD
`events_from_hive` (`issen-parser-registry/src/parser.rs:51`) is key-level only
(`value_count` metadata at :76); winreg-core + winreg-artifacts already in Cargo.toml.
MFT/USN emitters unchanged (`issen-cli/src/parsers/mft.rs:103/:111/:119`,
`usnjrnl.rs:118-129`). `issen-disk`: `find_ntfs_partitions` :58, `extract_triage` :172,
`extract_files` :273. `failed_logon_burst_finding` at
`issen-signatures/src/attack_classifier.rs:105`.

### 3.6 Memory path — **fresher than the #74 corpus snapshot** (commits 8dded9c, acec39f, e401bfa)
The B1–B4 workstream has advanced since the corpus doc was written; current state:

- **B1 (auto-profile): landed at code level.** `build_reader` (dispatch.rs:35) resolves
  `None`/`"auto"` via `resolve_auto_profile` (:59, :86-96): kernel-PE scan → RSDS PDB
  GUID → `memf_symbols::AutoProfile`. A test pins failure without CR3 in the dump
  (:1441). Real-dump validation = G2.
- **B2 (ps routing): landed.** `(TargetOs::Windows, Ps) → dispatch_windows_ps`
  (cmd_memf.rs:167; dispatch.rs:792 → `walk_processes`).
- **B3 (netstat): landed at code level.** `dispatch_windows_netstat` (dispatch.rs:854) →
  `network::walk_tcp_endpoints` (:871), Note column via `classify_connection` (:883).
  Pool-scan (`TcpE`/`UdpA` carve for freed sockets) completeness and real-dump behavior =
  G2; the freed-socket rows matter for F29 (the dead process's C2 row).
- **B4 (scan/malfind): landed at code level.** `dispatch_windows_scan` (dispatch.rs:1015)
  runs `pool_scan::walk_pool_scan` (:1022) **and** `vad::walk_malfind` (:1043), labeling
  rows `malfind:{classify_malfind_region(&m.first_bytes)}` (:1048). Decision helpers:
  `is_injected_pe_header` (MZ check, :727), `classify_malfind_region` → `injected-PE` /
  `injected-code` (:730-736; tests :1952-1957).
- **`memf creds` is routed** (cmd_memf.rs:172 → `dispatch_windows_creds`) — the corpus
  doc's "creds not wired" is stale at the routing level; *validation* on a real dump is
  not, hence F32 stays DESIGN behind G2.
- **The two builds stand exactly as the corpus corrected them:**
  `is_suspicious_remote_port` = `matches!(remote_port, 4444)` (dispatch.rs:761), with an
  explicit test asserting `!is_suspicious_remote_port(443)` (:1986) and a doc comment
  stating the conservative design — so the Szechuan C2 on `:443` surfaces as
  `external-established` (M-1). `WinMalfindInfo.first_bytes` is still
  `Vec::new(), // would read from process VA space`
  (`memory-forensic/crates/memf-windows/src/vad.rs:135`) — so `injected-PE` can never be
  emitted (M-2).
- **`MemfCommand::Timeline`** returns "not yet wired for this OS" for Windows
  (cmd_memf.rs:177-182) — F37 DESIGN holds.
- **PRE-1 gap holds:** `issen-cli/src/commands/memf.rs` (88 lines) contains zero
  `TimelineStore`/`TimelineEvent` references; `run_memf_command` prints string rows.
  issen-mem depends on `memf-strings` (Cargo.toml:16) and re-exports
  `forensic_hashdb::known_bad::KnownBadDb` (`hashdb.rs:2`) — both relevant to F33/PRE-6.

### 3.7 Measured baseline (what "measured" means in §2)
All measured values in the matrix come from `issen-measured-coverage.md`: DC01 ingest
**killed at 23 min** with 369,492 events inserted (`Mft` 348,512 + `EventLog` 20,980 —
**no USN, registry, SRUM, prefetch, amcache rows**); Desktop ingest completed (84K events)
but `$MFT` parsed to **31 records**. The measured literals (03:21:25 burst; 03:21:48 4624;
03:24:06 first coreupdater; 03:36:24 Desktop 4624; 129 × 7045; 5 loot.zip events; 8
Beth_Secret events) are real query results over those databases — and all of them
re-verify under G1 because both runs predate the #23/#26/#61 fixes.

---

## 4 · The memory-leg posture (binding narrative for README/report/flyer language)

The memory leg is issen's **strongest leg in capability**: the fleet ships walkers and
classifiers covering everything the published memory analyses did (process walk, netstat
with mechanized noise triage, malfind-equivalent RWX-private detection, credential
walkers, plus dozens of walkers no write-up used), and as of HEAD the Windows dispatch
path (ps/netstat/scan/creds, auto-profile) is routed end-to-end at the code level.

It is also **honestly gated**, and the gates are of three different kinds:

1. **Wiring** — results never reach the case timeline (PRE-1); the Windows memory
   bodyfile (F37) and memory-ShimCache (F36) routes are stubs/unwired.
2. **Two scoped builds** — M-1 (the C2 note for the Szechuan `:443` connection) and
   M-2 (malfind `first_bytes` capture so `injected-PE` can fire). Without them issen's
   output on this case reads `external-established` and `injected-code` where the
   write-ups concluded "C2 on 443" and "injected PE (Meterpreter)".
3. **Validation** — no issen memory command has ever run against the real Case 001 dumps
   (G2). The Desktop dump is *known hostile to structured parsing* (it defeated
   Volatility and Rekall in W1 — F33), so G2 may demote Desktop-memory rows to the
   strings-fallback path with explicitly lower confidence labels.

**Approved claim ladder** (use the highest rung that is true at the time of writing):
(a) today: "issen's memory walkers detect the same core IOC classes the published
analyses found — orphaned malware process, external-established C2 connection,
RWX-private injection — at the code level, pending first validation on this corpus";
(b) after G2 + PRE-1 + M-1 + M-2: "issen reproduces the published memory findings
F26–F28/F31 from RAM locally"; (c) only after (b) is demonstrated: "issen's memory
coverage is consistent with exceeding the walshcat write-up, which performed no memory
analysis." The words "exceeds", "confirms", "proves" do not appear in report output or
marketing copy at any rung.

---

## 5 · Acceptance gates G1/G2 (blockers promoted from assumptions)

The #74 corpus §4 caveat becomes two explicit, blocking steps. **No rule tier is
implemented before its gate has run**, because the gates can re-grade matrix rows and
re-aim assertion literals.

### G1 — fresh end-to-end disk run (DC01 + Desktop)
Re-run `issen ingest` on both E01s at HEAD. Verifies, at this image's scale, that the
completed fixes actually closed the three recorded failures: #23 (DC01 killed at 23 min —
batched insert), #26 (Desktop `$MFT` → 31 records), #61 (ntfs-core `$ATTRIBUTE_LIST`
full-runlist). **Exit criteria:** both ingests complete; DC01 emits USN events (F13's
second leg); Desktop MFT record count is plausible for a full Win10 volume (≫ 31);
registry/prefetch/amcache event counts recorded (expected 0 until PRE-3/PRE-5 — the
recording is the point: it is the PRE-3/PRE-5 RED baseline). Outputs: re-measured
literals for every §2.1 "Measured members today" cell; any row whose literal moves gets
re-pinned in the same commit.

**G1 RAN 2026-06-11 — PASSED, with one root-cause fix landed.** Both ingests complete
(DC01 15 s, Desktop ~30 s — #23's batched insert holds at scale). DC01: 689,605 events
(Mft 349,136 / Registry 193,636 / EventLog 85,342 / **UsnJournal 61,491** — F13's USN leg
fires). Desktop initially produced **Mft = 124** — G1 caught the true #26 root cause:
`triage_manifest` flattened every partition's files into one temp dir keyed by NTFS path,
so the recovery partition's 256-record `$MFT` overwrote C:'s 104,960-record table (DC01
passed only by partition order). Fixed RED→GREEN (`issen-disk`: per-partition
`part-<offset>/` namespacing; commits 136f6f6/28a68f3). Re-run: Desktop **768,862** events
(Mft 417,628) — `Windows/System32/coreupdater.exe` FileCreate `2020-09-19T03:40:00Z` and
its Prefetch file creation `03:40:59Z` now surface. Re-pinned literals: attacker-IP
`194.61.24.102` on **611** events (metadata); first attacker `LogonSuccess`
`2020-09-19T03:21:48Z`; LogonFailure 107. **Re-grades:** (1) registry is NOT zero-events
(193,636 / 271,245) — PRE-3's "zero events" RED baseline is stale; PRE-3 re-scopes to the
named-value table only. (2) `ServiceStart`+coreupdater matches 0 — the F17 7045 literal
needs re-pinning against the actual 7045 event shape before Tier D. (3) prefetch/amcache/
lnk/shimcache event sources are absent as expected — the PRE-5 RED baseline stands.

### G2 — first end-to-end memory run (both dumps)
Run `issen memf ps|netstat|scan|creds` against the DC and Desktop dumps at HEAD.
Validates B1 auto-profile (CR3 + RSDS resolution) on real WinPMEM-acquired images.
**Exit criteria per dump:** profile resolves (or the failure mode is recorded and the
strings-fallback question — open Q3 — is answered with data); ps shows the
coreupdater/spoolsv rows; netstat shows the `203.78.103.109` row (expected Note:
`external-established` until M-1); scan flags the spoolsv RWX region (expected label:
`injected-code` until M-2). The Desktop dump is expected to be hostile (F33); a
structured-parse failure there is a *recorded finding of G2*, not a gate failure —
it re-grades the Desktop-side memory assertions to the fallback path.

**G2 FIRST CONTACT 2026-06-11 — failure mode recorded (gate not yet passed).** DC dump
(`citadeldc01.mem`, raw WinPMEM, 2 GB): format detects as Raw, then every subcommand
(ps/check) refuses with "dump has no embedded CR3; use --cr3" — **the memf-symbols
header-less DTB scanner (#58/#62) is not wired into the Raw-dump dispatch path.** This is
the concrete shape of self-flagged Risk 2: B1's components are unit-tested but the
raw-dump → auto-CR3 wiring is missing, so every memory matrix row stays gated. New
prerequisite (B1-wire, RED→GREEN): route Raw dumps through the memf-symbols DTB scan in
`build_reader` before the CR3 bail-out; G2 re-runs after it lands.

**G2 DEEP DIAGNOSIS 2026-06-11 (two memf-symbols fixes landed, one blocker isolated).**
B1-wire shipped (issen-mem `03cf932`): `build_reader` resolves CR3 via embedded → `--cr3` →
`memf_symbols::scan_for_kernel_dtb`. A `probe_dtb` example walked the real DC dump:
1. **Enumeration was keyed to one self-map slot (`0x1F9`)**, but the DC is Windows Server
   2012 R2 (self-map `0x1ED`), so the scan found **zero** candidates. Fixed RED→GREEN
   (`memf-symbols fb32f86`): scan every kernel-half slot `0x100..0x200`. Now **41**
   self-ref PML4 candidates surface, all at `0x1ED`.
2. **Paging walk + large-page translation verified** — the lowest candidate reaches 14
   kernel-half MZ images.
3. **Blocker isolated:** `try_kernel_at_va` anchors verification on *ntoskrnl's* MZ header,
   which is **not page-table-resident** in this dump — the 14 reachable images are all boot
   drivers; a 64 KiB sweep finds no `nt*`. ntoskrnl *is* physically present (`ntkrnlmp.pdb`
   RSDS at file offset `0x2219698`), but its PE-header page is paged out, so a
   header-anchored discriminator rejects all 41 genuine DTBs.

**B1-kerneldtb — LANDED 2026-06-11 (option a), steelmanned against Volatility 2/3, Rekall,
MemProcFS.** Dropped the resident-ntoskrnl-header assumption: a self-ref candidate is a
genuine page-table root if it maps *any* kernel-space PE+RSDS (`dtb_maps_kernel_space`,
`memf-symbols 19cb1c3`), selected by lowest-physical; the kernel **profile** is recovered by
a physical RSDS sweep when the header is paged (`scan_physical_for_kernel_rsds`, `22ac1a6`),
gated on a 64-bit DTB (the architecture gate vol3 applies at the DTB layer). On the real DC
dump: DTB `0x1a7000`, profile `ntkrnlmp.pdb` resolved, ISF downloaded — and the **ps walker
now runs**, failing one layer deeper at VA `0x2b00a0` (the bare RVA of `PsActiveProcessHead`).

**Steelman (`memory-forensic/docs/steelman-vs-reference-tools.md`, `88b5756`):** our core
algorithms track the reference tools (self-ref DTB ≈ vol3 `DtbSelfReferential`; physical RSDS
≈ vol3 `pdbscan`). The `0x2b00a0` failure is a *missing step*: nothing adds the kernel base
virtual address (KVO) to symbol RVAs. **Fix landed — the x64 Low Stub** (`find_low_stub`,
`dce43bb`; vol3 `method_low_stub`, clean-room from the `PROCESSOR_START_BLOCK` layout): scans
the lower 1 MiB for the boot processor block carrying the kernel CR3 (`+0xA0`) and the
LmTarget kernel VA (`+0x70`). On the real DC dump it returns **`cr3=0x1a7000`** (cross-validating
the self-ref DTB exactly) and **`kernel_base_va=0xfffff800cbe00000`** — the KVO (ntoskrnl sits
at `0xcbe00000`, a different region than the drivers at `0x64xxxxxx`, which is why the VA MZ
scan never found it).

**B1-kvo — LANDED (symbol rebasing) 2026-06-11.** `RebasedResolver` (memf-symbols) decorates
the symbol resolver so **every** `symbol_address` caller — the memf-windows walkers resolve
`PsActiveProcessHead` directly off the resolver, bypassing `required_symbol` — gets `kvo + rva`
by construction (secure-by-design, steelman fix #1). `build_reader` leads CR3 resolution with
the Low Stub and wraps the resolver with its KVO. **Verified on the real DC dump:**
`PsActiveProcessHead` now rebases from the bare RVA `0x2b00a0` to the kernel VA
`0xfffff800cc0b00a0` (KVO `0xfffff800cbe00000` + RVA) — the walker reaches a real kernel
address.

**Sole remaining gate (B1-kvo-refine):** that VA's page reads "not present" — the Low Stub's
LmTarget rounded to 2 MiB approximates ntoskrnl's base; the exact 2 MiB base needs vol3's
`method_low_stub` refinement (scan down for the MZ — paged out here) or cross-validation
against the physical ntkrnlmp RSDS's mapped VA, plus confirming the resolved ISF GUID matches
this exact build (the RVA must be correct for *this* kernel). Once the KVO pins ntoskrnl's
true base, the EPROCESS walk lists processes. Until then F26–F37 stand write-up-corroborated
in `docs/case001-union-answers.md`, not yet issen-measured. Steelman fixes #2 (vol3 `seen`-set
list-walk loop detection) and #3 (DTB precision rules) follow as hardening.

**Memory-leg progress this session (all RED→GREEN, vol2/vol3/rekall/MemProcFS-steelmanned):**
0 candidates → multi-slot self-ref enumeration (2012 R2 `0x1ED`) → DTB `0x1a7000` (header-paged
discriminator) → profile via physical RSDS → Low Stub CR3 (cross-validates the DTB) + KVO →
resolver-level symbol rebasing → walker resolving real kernel VAs.

**G2 PASSED 2026-06-11 — issen lists the Case 001 DC processes.** The KVO refinement proved a
dead end on this dump (sweep: no valid `LIST_ENTRY` at any candidate base, no MZ within
±32 MiB — the kernel *data* pages are paged out, so the `PsActiveProcessHead` walk
fundamentally cannot run). The reference-aligned answer is **psscan** (vol2 `psscan` / vol3
`PoolScanner`): `memf_windows::psscan` scans physical memory for the `Proc` pool tag, gated on
the `_DISPATCHER_HEADER.Type==0x03` signature + plausible-pid + valid-name validation;
`dispatch_windows_ps` falls back to it when the list walk fails. **`issen memf ps` on the real
`citadeldc01.mem` now lists 40 processes — including `coreupdater.exe` PID 3644 and
`spoolsv.exe` PID 3724** (F26/F28 process identities, matching the union ground truth exactly).
The memory process leg is now **issen-MEASURED**, not just write-up-corroborated. Remaining
memory enrichment (netstat C2 row, malfind injection detail) needs per-process VAD/translation
beyond the process list, tracked as follow-on; the headline IOCs are measured.

---

## 6 · Prerequisites — PRE-1..6 (carried) + M-1/M-2 (new builds)

Each is independently RED→GREEN-able: **two commits per task — RED (failing tests) first,
then GREEN** — landing before the tiers that depend on it (§8).

### 6.1 PRE-1..PRE-6 (carried from v4; deltas only)
- **PRE-1 — memory → typed `TimelineEvent`s, persisted.** Unchanged in shape (typed
  results at the dispatch boundary; `memory_events(...) -> Vec<TimelineEvent>` with
  `EntityRef::Process`/`Ip`; acquisition-timestamp semantics per v4 §5.6; issen-mem gains
  exactly one new edge to issen-core; persistence stays in issen-cli). **Widened:** the
  conversion covers ps, netstat, scan **and creds** rows (F32), and defines the seam the
  Windows `Timeline` bodyfile (F37) and memory-ShimCache (F36) routes will reuse —
  designed now, wired as Tier C'-adjacent work. Serves F12, F26–F28, F31–F32, F36–F37.
- **PRE-2 — parsers populate `entity_refs`.** Unchanged. Serves F6, F14, F17, F19, F21,
  F24 join keys.
- **PRE-3 — registry: root-cause zero events + the declarative named-value table.**
  Unchanged (v4 §4 table: CurrentVersion, TimeZoneInformation, ComputerName,
  Tcpip Interfaces, Services\<name>, Run*). G1's recorded registry count is the RED
  baseline. Serves F1–F3, F17, F19, F22.
- **PRE-4 — `entity_refs` schema + backfill.** Unchanged.
- **PRE-5 — force-link inert parsers + `.lnk` discovery arm.** Unchanged. Serves F10
  (Amcache leg), F21 (LNK leg).
- **PRE-6 — flagged-executable extract + hash + known-bad match.** Unchanged
  (`extract_files` at issen-disk lib.rs:273; `--hash-iocs` at ingest.rs:214; hash-what-
  you-flag, never a whole-image sweep). Serves F9, F15 label.
- **D2 (small, new) — EVTX 4776 mapping.** Add 4776 → a typed credential-validation
  event (workstation-name metadata carries the attacker hostname). One mapper arm + the
  accuracy-table row. Serves F40's in-scope half.

### 6.2 The two memory builds (new in v5; both small, both general)

- **M-1 — process-context C2 annotation (issen-mem).** The corpus correction stands: a
  bare port-number list cannot cover `:443` without flagging every HTTPS browser session
  (the existing code's doc comment makes the same point). The general mechanism — no
  special case for this corpus — is **process-context escalation**: when the dump's own
  ps/scan results mark the owning PID anomalous (dead-but-present, orphaned parent, or
  owner of an injected region), an `ESTABLISHED` external connection from that PID
  escalates from `external-established` to a C2-graded note (`suspicious-c2-process`),
  regardless of port. Port `4444` keeps its number-alone grading. This is correct for any
  port a future case uses, and on Case 001 it grades the `:443` row via the same evidence
  the analysts used (the malware PID), not via the port literal. Note the layering: M-1
  is the netstat *Note* enrichment (single-dump, intra-`memf`); `CORR-INJECTED-C2`
  remains the cross-source correlation that persists a finding. M-1's inputs are walker
  outputs already produced in the same `memf` run; it adds no new walker.
- **M-2 — malfind `first_bytes` capture (memory-forensic repo, memf-windows).** Replace
  the `Vec::new()` placeholder at `vad.rs:135` with a bounded read of the region's
  leading bytes from process VA space (the VA-read machinery `walk_malfind` already uses
  to find the region). Downstream `classify_malfind_region` then distinguishes
  `injected-PE` from `injected-code` with zero further change. **Repo-boundary caveat:**
  this lands in `~/src/memory-forensic` (issen consumes it via path deps) — a dirty
  memory-forensic tree breaks all issen compiles, so M-2 is sequenced solo, never
  concurrent with issen-side agents.

### 6.3 Sequencing
G1 ∥ G2 first (read-only, independent) → PRE-4 → PRE-2 → PRE-5 → PRE-1 → PRE-3 → D2 →
M-2 (solo, fleet repo) → M-1 → PRE-6 (lands with §8 step 15, after rules exist to flag
paths). Full ordering in §8.2.

---

## 7 · `issen correlate <case-dir>` — behavior, rules, surfacing

### 7.1 The six phases (unchanged from v4 §5.1)
Discovery → disk ingest per image into one DuckDB → memory ingest per dump (PRE-1) →
per-event findings pass (+ PRE-6 hash pass) → correlation pass (now 11 rules) → report
(Host Profiles, Correlated Findings, Attack Chain, Session Envelope).

### 7.2 Rule table (11 rules; ★ = new in v5)

Rows 1–10 are v4 §5.2 verbatim (anchors, scopes, windows, ATT&CK, guards — including
`CORR-COPY-DELETE`'s token-set/subtree/size guards and `CORR-LATERAL-MOVE`'s five guards);
they are not restated. The addition:

| Code | Anchor → consequents (point-in-time) | Shared subject + scope | ATT&CK | Oracle rows |
|---|---|---|---|---|
| ★ `CORR-PROC-MIGRATION` | memory ps row that is **dead-and-orphaned** (0 threads ∧ parent PID absent from the same dump's process set) → (a) a malfind/injection finding on a *different, live* PID, **and** (b) netstat rows tying **both** PIDs to the **same remote endpoint** | remote address equality joins the PIDs; `SameDump` strictly | consistent with T1055 (process injection / migration) | F29 (+ members feed F44's envelope) |

Status: **DESIGN** (Tier C', after Tier C). Precision guards: the dead process must
*itself* have (or have had — pool-scanned/freed socket rows count, with their provenance
recorded) a connection to the shared endpoint; the injected PID must be live; both rows
from one dump. Negative controls: injected process with no shared endpoint; dead orphan
with no injection elsewhere in the dump; two healthy live processes sharing an endpoint
(e.g. connection pool to one server) must not fire. Dependency note: the dead-PID
connection row likely exists only via pool-scan carving of freed sockets — G2 must
establish whether the DC dump yields it; if not, the rule's (b) clause degrades to
"the live injected PID holds the endpoint and the dead PID is name-linked to the same
image stem", with the weaker form recorded in the finding's confidence.

### 7.3 Session Envelope — widened to multi-session (F25, F44) — DESIGN
The v4 envelope (per correlated adversary session: first/last observed event) becomes
**multi-session by construction**: sessions are keyed on `logon_id` (EVTX `logon_id` is
already promoted to metadata), grouped per host, ordered by time. The report renders one
envelope row per session — Case 001's expected shape is **two adversary sessions on the
DC** (logon → activity → logoff; second logon → migration-era activity → exit), with the
F29 correlation members attributed to the session whose window contains the dump's
acquisition timestamp semantics (v4 §5.6). "Last observed activity" (F25) is the last
event of the *last* adversary session. No new rule: this is report-layer sessionization
over chain members.

### 7.4 Single-artifact surfacing (delta to v4 §5.4)
v4's table carries forward (burst finding, logon/service events, MFT/USN file events,
host profile, Amcache/LNK/Prefetch evidence, flagged-file hashes, skew observation).
Additions: **memory rows as first-class timeline events** (PRE-1) with acquisition-time
provenance and `point_in_time` tags; **the strings-fallback path** (F33): when G2 shows a
dump defeats structured parse, `memf-strings` + the hashdb IOC store sweep the raw dump
and emit IOC-hit events explicitly labeled `confidence: strings-carve` — lower than
structured-walk rows, never silently equal (design here; wired as part of PRE-1's
converter; open Q3 decides whether it is a guarantee or best-effort).

### 7.5 Epistemics enforcement (unchanged from v4 §6.3, now also over memory notes)
Unit test over every CORR-* and memory-note template: must contain "consistent with",
must not match `(?i)\b(confirm(s|ed)?|prove[sdn]?|proof|exceed(s|ed)?|undoubtedly|certainly)\b`
— **"exceeds" joins the forbidden list** (§4 claim ladder); render test asserts the
tribunal footer; the same regex gates console output.

---

## 8 · TDD plan (ordered RED→GREEN; two commits per step, RED first)

Fast synthetic fixtures gate CI; heavy-corpus tests are `#[ignore]`-gated, sequential
(`--test-threads=1`), one at a time, never parallel. The corpus gate is a documented
release gate (docs/validation.md entry + recorded gate run).

### 8.1 The acceptance oracle (the §2 matrix made executable)
`cargo test -p issen-cli --test correlate_case001 -- --ignored --test-threads=1` runs
`issen correlate` once over the cached corpus workdir, then asserts **one block per
in-scope matrix row: 37 blocks** (1 MEASURED-TODAY + 27 DESIGN + the in-scope halves of
9 PARTIALs); the 7 OUT rows (F7, F16, F18, F38, F39, F42, F43) are documented exclusions.
The v4 §8.1 assertion sketches for F1–F25 carry forward with their literals re-pinned
from G1 output. New representative blocks:

- F26: a memory-sourced process event exists for `coreupdater.exe` with metadata
  consistent with dead-and-orphaned (0 threads, absent parent), evidence_source = the DC
  dump stem.
- F27: a memory `NetworkConnect` event with remote `203.78.103.109` exists; its note is
  C2-graded via M-1's process-context escalation; `CORR-INJECTED-C2` references it.
- F28: a malfind event for the spoolsv PID exists labeled `injected-PE` (M-2 landed) —
  the RED form of this assertion (pre-M-2) pins `injected-code` to verify detection fires
  before sub-classification does.
- F29: a `CORR-PROC-MIGRATION` correlation exists whose members are the F26 ps row, the
  F28 scan row, and netstat rows sharing `203.78.103.109` (or the documented degraded
  form, per §7.2, if G2 shows no freed-socket row).
- F31: a LISTENING netstat row exists under the injected PID.
- F32: a **credential-exposure finding** is emitted for the DC dump — the typed inference
  that SYSTEM-context malware exposes domain credentials — with the `memf creds` walker's
  behavior recorded during G2. The oracle is the *exposure finding being emitted*, NOT
  extracted credential material (no hash literals are committed to the repo, and raw
  hashdump output is explicitly not required).
- F33: **best-effort, not a blocking §8.1 oracle.** The `strings` fallback subcommand does
  not exist in `MemfCommand` yet (see §3.4 and open Q3), so F33 stays PARTIAL with no hard
  acceptance assertion. *Should* a strings-fallback ship and the Desktop dump's structured
  parse fail at G2, its IOC-hit events for `coreupdater` / `203.78.103.109` are expected to
  carry `confidence: strings-carve`, with no structured-confidence Desktop-memory assertion
  made — but that is a future capability, not a gate this spec enforces.
- F34: the DC netstat surface contains both noise rows (unflagged) and the
  external-established rows (flagged) — the triage split is present, not a single
  undifferentiated list.
- F36/F37: ShimCache-from-RAM events and memory-bodyfile events exist in the case DB with
  acquisition-time provenance tags.
- F40: a 4776-mapped event exists carrying the attacker workstation name (literal pinned
  at G1/first parse — expected: the Kali hostname the write-ups report).
- F44: the DC Session Envelope renders ≥ 2 adversary sessions; the last envelope's last
  event is a `Logoff` (its UTC literal pinned per open Q4).

Timestamps asserted in UTC per G1-re-measured values, ± 60 s where write-ups give minute
precision. Any row that cannot be asserted after implementation moves — loudly, in the
same commit — to §2.4 with its reason.

### 8.2 Ordered steps

**Phase 0 — gates (read-only, run first, can run in either order but never concurrently
with each other on the same machine):**
1. **G1** — fresh DC01 + Desktop ingest; record counts + re-pin literals (§5).
2. **G2** — first memf run on both dumps; record profile-resolution outcomes; answer the
   freed-socket question for `CORR-PROC-MIGRATION` and the F33 fallback question.

**Phase 1 — pre-tasks (each: RED commit, then GREEN commit):**
3. PRE-4 (schema + backfill) · 4. PRE-2 (entity refs) · 5. PRE-5 (force-link + `.lnk`
arm; G1's zero-counts are the RED baseline) · 6. PRE-1 (memory seam; `#[ignore]` RED uses
the G2-validated dump) · 7. PRE-3 (registry root-cause + named-value table; G1 baseline)
· 8. D2 (4776 mapping).

**Phase 2 — the two builds:**
9. **M-2** (memf-windows `first_bytes` capture — fleet repo, sequenced solo; RED in
memory-forensic pins `injected-PE` from a synthetic MZ region, GREEN implements the VA
read; issen picks it up via path dep, registry version on publish).
10. **M-1** (process-context C2 note; RED: synthetic dump fixtures where an anomalous-PID
`:443` connection escalates and a healthy-PID `:443` does not).

**Phase 3 — engine (v4 steps, renumbered):**
11. Correlation schema + model · 12. `EventQuery`/`StoredEvent`/`fetch_events`/
`burst_windows` · 13. `EventSource` + ordered evaluator (with point-in-time/`SameDump`
semantics for the memory rules).

**Phase 4 — rule tiers (small, independently revertable; corpus `#[ignore]` tests cite
their F-rows):**
14. Tier A (RELOCATE, PERSIST, COPY-DELETE) · 15. Tier B (BRUTEFORCE-LOGON,
LOGON-MALWARE-WRITE, EXFIL-STAGE both hosts) + **PRE-6** (consumes flagged paths) ·
16. Tier B' (PERSIST-REGCONFIRM + host profiles) · 17. Tier C (PROC-DISK-MATCH,
INJECTED-C2) · 18. **Tier C' — ★`CORR-PROC-MIGRATION` + multi-session envelope**
(F29/F44; synthetic dead-orphan/injected/shared-endpoint fixtures + the three negative
controls) · 19. Tier D (LATERAL-MOVE).

**Phase 5 — assembly:**
20. Workdir policy · 21. `correlate` CLI command · 22. Report sections + epistemics
regex gates (incl. "exceeds") · 23. **End-to-end acceptance: the §8.1 oracle** (RED: 37
assertion blocks; GREEN: residual wiring; record the gate run).

YAGNI line: the MVP is exactly what makes the §2 matrix true — gates G1/G2, PRE-1..6,
D2, M-1/M-2, the engine, the 11 rules, the two report surfaces, the oracle test. The
§2.4 closure paths, SRUM exfil-bytes ledger, `[H]` epochs, `[Q]`/`[C]`, YAML rule UX,
GUI all stay out.

---

## 9 · Open questions for Codex to attack

1. **F5's MEASURED-TODAY under a killed run** — the burst literal came from the same
   partial DC01 ingest that forces F13's downgrade. Is one-finding-measured defensible,
   or should v5 zero out MEASURED-TODAY entirely until G1? (The matrix survives either
   answer; the BLUF tally changes 1→0.)
2. **M-1's process-context escalation vs. a port heuristic** — the corpus sketched a
   ":443-on-odd-local-port" build; v5 generalizes to anomalous-owning-PID escalation to
   avoid a port special case. Attack the FP/FN envelope: does context-escalation miss a
   C2 whose owning process looks healthy (e.g. injection into a browser — `:443` from an
   injected `chrome.exe` *would* still fire via the injected-region arm, but a
   stealthier in-module hook would not)? Is a hybrid (context escalation + an
   odd-local-port prior) warranted?
3. **F33 fallback: guarantee or best-effort** — carried from corpus open Q3, now with a
   concrete seam (§7.4). If guaranteed, it needs its own RED on a deliberately corrupted
   dump fixture.
4. **F25/F44 logoff literal** — the "2:57" pcap-clock value still has no measured UTC
   counterpart; pin at G1 (carried from v4 open Q4).
5. **`CORR-PROC-MIGRATION` degraded form** — if G2 finds no freed-socket row for the
   dead PID, the (b) clause degrades to name-stem linkage (§7.2). Is that still strong
   enough to assert F29, or should the assertion then move to the weaker "injected +
   orphan + live-PID C2" conjunction without the shared-endpoint join?
6. **Acquisition-time values for the dumps** (`--acquired-at`) — still to be pinned from
   the case documentation (carried from v4 open Q5).
7. **walshcat Q9 label swap (F22)** — settle from primary evidence via PRE-3's
   Interfaces extraction (carried from v4 open Q9).
8. **13Cubed** — a dedicated Case-001 analysis could not be retrieved (corpus open Q1);
   if found later it may add findings — the union set would version to F45+ rather than
   renumber.

---

## G1 re-run 2026-06-12 — PREFETCH LEG CLOSED (GREEN)

After building `prefetch-forensic` (real MAM/Xpress-Huffman + SCCA v30/31),
migrating `issen-parser-prefetch` onto it, AND wiring `ForensicParser::parse()`
(which was a stub `Ok(ParseStats::new())` — the reason prefetch stayed dark even
once the parser worked), a fresh Desktop E01 ingest produces:

- **636 prefetch execution events** (was **0**) across **107 distinct executables**,
  each with real run count + last-run timestamps (the prior stub emitted `ts=0`).
- The implant: **`COREUPDATER.EXE` executed 1× @ 2020-09-19T03:40:49Z** — the
  evidence-of-execution answer several Case-001 questions require.

DB: `g1-output/desktop-prefetch2.duckdb` · query: `description LIKE 'Prefetch:%'`.

**Still dark (same stub-`parse()` gap, same one-each fix):** amcache / shimcache /
shellbags decoders now run via `winreg-artifacts`, but their `ForensicParser::parse()`
trait methods still return `Ok(ParseStats::new())` — so they emit nothing in ingest
until wired like prefetch (read DataSource bytes → `events_from_*` → `emit_batch`).

### G1 re-run (cont.) — amcache LIT UP, shimcache/shellbags need discovery

After wiring `ForensicParser::parse()` for amcache/shimcache/shellbags (same stub fix
as prefetch): fresh Desktop ingest now emits **97 AmCache execution events** (SHA-1 +
path + publisher; was 0). Prefetch holds at 636. **Shimcache = 0** despite the SYSTEM
hive being discovered (12,253 registry events from it) — dispatch likely runs only the
registry walker on a `Registry`-typed hive, starving the shimcache adapter; OR the
AppCompatCache decode returns empty on this hive (needs standalone check). **Shellbags = 0**
— not force-linked + NTUSER/UsrClass not discovered as `Shellbags`. Both scoped in
`docs/fleet-capability-inventory.md` §1.

### #1 wiring complete — shimcache + shellbags un-darked

- **shellbags**: 0 → **55 events** (force-linked + `supported_artifacts → [Registry]` so NTUSER/UsrClass, discovered as Registry, dispatch to it).
- **shimcache**: 0 → **1** (the AppCompatCache blob is now FOUND — fixed the winreg-artifacts ControlSet bug: offline SYSTEM hives have no `CurrentControlSet`; resolve via `Select\Current`→`ControlSet00N`, RED/GREEN TDD). **Caveat:** the 1 entry is a raw sentinel (empty path) — the Win10 AppCompatCache *blob-entry decoder* doesn't yet parse this format into N executables; separate follow-up in `winreg-artifacts::shimcache`.
- **usnjrnl**: confirmed NOT dark (39,076 USN events; the inventory audit conflated "not force-linked as a parser" with dark — issen-disk handles MFT/USN/EVTX directly).

Full Desktop ingest now: Prefetch 636, AmCache 97, Shellbags 55, Shimcache 1(blob-found).

### Shimcache root cause — winreg-core big-data (db) reassembly (deeper than the decoder)

Two shimcache decoder bugs fixed by TDD in winreg-artifacts (committed): (1) offline
ControlSet resolution via `Select\Current`; (2) the real Win10 AppCompatCache header +
`10ts` entry layout. BUT real-data re-ingest still yields 1 sentinel because the REAL
blocker is in **winreg-core**, not shimcache:

Extracting the Desktop SYSTEM hive and probing `ControlSet001\…\AppCompatCache` shows the
value's data is **12 bytes: `64 62 05 00 …` = ASCII "db"** — the NT registry **big-data
record** (values > 16344 B are split into segments via a `db` cell + segment list).
`winreg-core::value::raw_data()` (`value.rs:45`) reads the data cell and returns
`body[..size]` WITHOUT detecting the `db` record and following its `segment_list_offset`
to reassemble the segments. So AppCompatCache — and **every large registry value
fleet-wide** — comes back as the 12-byte db header.

**Next TDD step (bounded):** extend `TestHiveBuilder` to emit a `db` record for values
> 16344 B (it currently puts all data in one cell, so it can't reproduce the bug), write
the RED (read a >16 KB value back, assert full length/content), then GREEN: in
`raw_data()`, when the data cell is `Cell::BigData`, walk the segment list and concatenate
segment-cell bodies, truncating to `data_size`. winreg-format already exposes
`RawBigData::parse` + `Cell::BigData`.

---

## Implementation progress — 2026-06-13 (analytical core COMPLETE + runnable)

The capstone's analytical machine is built, wired, and verified on synthetic
fixtures (every phase `rtk proxy cargo test`-green at HEAD; one real regression
caught + fixed mid-pipeline). Done:

- **PRE-4** entity_refs persisted (schema + ALTER backfill + both ingest paths).
- **PRE-2** disk parsers (EVTX/MFT/USN) populate EntityRef User/Ip/Session/Process/FilePath.
- **PRE-1** `issen-mem::timeline::memory_events` converter + `persist_memory_events`
  (process/netstat/malfind → typed memory TimelineEvents, EventSource::Memory).
- **Engine** (issen-correlation): correlation schema, `EventQuery`/`fetch_events`/
  `burst_windows`, ordered `evaluate()` + `RuleSpec.guard`/`ordered` hook + `EventView`.
- **All 11 rules**: Tier A (RELOCATE/PERSIST/COPY-DELETE), Tier B (BRUTEFORCE-LOGON/
  LOGON-MALWARE-WRITE/EXFIL-STAGE), Tier B' (PERSIST-REGCONFIRM), Tier D (LATERAL-MOVE),
  Tier C (INJECTED-C2/PROC-DISK-MATCH/PROC-MIGRATION + degraded). Each with negative
  controls + the epistemics ("consistent with", no verdict words) gate.
- **Runner + `run_and_persist`** (memory-aware), **`correlate` CLI**, **Correlated
  Findings report** (tribunal footer). `cargo build --bin issen` Finished.

REMAINING (gated, not reachable without the external blockers):
- **§8.1 acceptance oracle** — the real Case-001 corpus run asserting F1–F44 incl.
  memory F26–F37. Gated: needs the live `memf` walk on the actual dumps.
- **dispatch→PRE-1 live wiring** (turn `dispatch_windows_*` string-row output into
  PRE-1 rows + call `persist_memory_events` from the CLI) — dump-gated follow-on.
- **M-2** (malfind `first_bytes`) lives in the memory-forensic repo — blocked on its
  dirty tree being committed. **M-1** (netstat C2 note) is issen-side, small, optional
  (INJECTED-C2 already grades the C2 via the injected-process join).
- Disk evidence-surfacing pre-tasks **PRE-5 / PRE-3 / D2** (force-link inert parsers,
  registry named-value table, EVTX 4776) — reachable enrichment; the correlation
  engine does not depend on them.
