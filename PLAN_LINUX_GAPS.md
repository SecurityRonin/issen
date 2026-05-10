# Linux DFIR Gap-Closing Plan

Derived from running the Hal Linux DFIR Challenge through `issen analyse` and tracing
exactly which questions could not be auto-answered and why.  The Father rootkit is used
as a concrete test case but **every gap is solved generically** — the resulting detections
catch the full LD_PRELOAD rootkit class (Father, Jynx, Azazel, bdvl, libprocesshider,
and future variants) regardless of library name, staging path, or minor implementation
differences.

Each gap maps to one or more CTF questions; each task follows strict TDD
(RED commit then GREEN commit, per CLAUDE.md).

---

## Corrected Capability Picture

Before listing gaps, record what is **already handled**:

| Capability | How it works today |
|---|---|
| Thread name → XMRig attribution | `build_evidence()` tags `miner_thread` on `libuv-worker`; rule `010-miner-rootkit-concealment` fires → "Rootkit-concealed crypto miner" |
| Port 3333 → Stratum label | `build_evidence()` tags `mining_pool` on dst_port 3333; src_port 3333 gets `stratum_listener` |
| SSH tunnel detection | Rules 020/025 fire on hidden SSH PID with stratum_listener + external TCP |
| Cross-finding compounding | Rules 010, 035, 070 correlate rootkit+miner+CPU indicators |
| LD_PRELOAD activation sequence | Rule 070 fires on ld.so.preload write + sshd restart within 120 s |
| CPU anomaly | `build_evidence()` emits `cpu_anomaly` evidence at ≥90%; rule 010 consumes it |

---

## Confirmed Gaps

### Gap 1 — PAM Credential-Capture Staging Not Detected

**Manifestation in Father:** `/tmp/silly.txt` — lines of the form `UID:1:password:CAPTURED_PASS`  
**CTF question answered:** Q3 (definitive rootkit family + credentials)  
**Why the filename is not the fingerprint:**  A Father variant can trivially rename the
staging file (`/tmp/.x11-lock`, `/dev/shm/.cache`, etc.) or change the directory.  The
durable fingerprint is the **content structure**: Father's PAM hook serialises credentials
as `UID:COUNTER:FIELDNAME:VALUE` because that pattern is baked into the hook's `fprintf`
call.  A variant that changes the path but keeps the hook implementation will produce the
same format.  Detection must match the *structural pattern* across all files in all writable
temp-like directories, making filename irrelevant.

**Evidence:** `rootkit.rs:64` — `KNOWN_ROOTKIT_LIBS` does not contain Father patterns.
`scan_rootkit_indicators()` checks four paths; no PAM staging file pattern is checked.

**Files to change:**
- `crates/parsers/issen-parser-uac/src/parsers/rootkit.rs`
  - New fn `scan_pam_credential_staging(root: &Path) -> Vec<RootkitFinding>`
  - Scans ALL files under `live_response/tmp/`, `tmp/`, `live_response/var/tmp/`, `var/tmp/`,
    `live_response/dev/shm/`, `live_response/run/` for any file whose content contains a line
    matching the structural regex `^\d+:\d+:\w+:[^\n]+` (UID:N:fieldname:value)
  - The regex matches Father's exact format AND variants that change the field name
    (`passwd`, `secret`, `pw`, etc.)
  - For each matched file: `Critical` finding listing credential count + matched lines
  - If scan dirs present but no match: no finding
  - Update `scan_rootkit_indicators()` to call it
- `crates/parsers/issen-parser-uac/src/parsers/rootkit.rs`
  - Remove `KNOWN_ROOTKIT_LIBS` string-matching from severity calculation — demote to a
    hint-only label displayed alongside ELF capability findings from Gap 5

**TDD RED tests:**
```rust
fn pam_staging_absent_when_tmp_empty()
fn pam_staging_detected_in_live_response_tmp()
fn pam_staging_detected_in_var_tmp()
fn pam_staging_detected_in_dev_shm()
fn pam_staging_parses_credential_lines()
fn pam_staging_severity_is_critical()
fn pam_staging_renamed_file_still_detected()       // /tmp/.x11-lock with Father format
fn pam_staging_variant_field_name_still_detected() // UID:1:passwd:VALUE (not "password")
fn pam_staging_unmatched_format_file_not_flagged() // random text file not flagged
fn pam_staging_multiple_files_returns_all()
fn pam_staging_with_multiple_credential_lines()
fn scan_rootkit_indicators_includes_pam_staging()
```

**GREEN implementation sketch:**
```rust
const PAM_STAGING_DIRS: &[&str] = &[
    "live_response/tmp", "tmp",
    "live_response/var/tmp", "var/tmp",
    "live_response/dev/shm", "dev/shm",
    "live_response/run", "run",
];
// Structural pattern: UID:counter:fieldname:value — matches Father and variants.
// Does NOT hardcode "password" as the field name.
static PAM_CRED_RE: LazyLock<Regex> = LazyLock::new(||
    Regex::new(r"^\d+:\d+:\w+:[^\n]+").unwrap()
);

pub fn scan_pam_credential_staging(root: &Path) -> Vec<RootkitFinding> {
    let mut findings = vec![];
    for dir in PAM_STAGING_DIRS {
        let dir_path = root.join(dir);
        let Ok(entries) = std::fs::read_dir(&dir_path) else { continue };
        for entry in entries.flatten() {
            if !entry.file_type().map_or(false, |t| t.is_file()) { continue }
            let Ok(content) = std::fs::read_to_string(entry.path()) else { continue };
            let matched_lines: Vec<&str> = content.lines()
                .filter(|l| PAM_CRED_RE.is_match(l))
                .collect();
            if !matched_lines.is_empty() {
                findings.push(RootkitFinding {
                    severity: RootkitSeverity::Critical,
                    check: "pam_credential_staging".into(),
                    description: format!(
                        "PAM hook credential staging file: {} ({} credential line(s))",
                        entry.path().display(), matched_lines.len()
                    ),
                    evidence: entry.path().to_string_lossy().into_owned(),
                });
            }
        }
    }
    findings
}
```

---

### Gap 2 — Interactive Shell Upgrade Chain Not Detected

**Manifestation in Father:** `sh→python3→bash` via `pty.spawn("/bin/bash")` over SSH  
**CTF question answered:** Q1 (why did NMS alert on `pty.spawn` over port 22?)  
**Why it matters:** `analyze_hidden_processes()` correctly surfaces the sh/python/bash
triple all connected to the same attacker endpoint. But no rule recognises this as the
canonical interactive shell-upgrade pattern (T1059.006). The pattern is interpreter-agnostic:
any `<sh-ancestor> → <interpreter> → <shell>` triple on a shared external endpoint qualifies,
covering `python2`/`python3`/`ruby`/`perl`/`socat` and future interpreter variants.

**Evidence:** 25 bundled rules — none match sh+interpreter+bash on shared SSH endpoint.
`mod.rs` has `analyze_ssh_reverse_shell_chain` test confirming data is available.

**Files to change:**
- `crates/parsers/issen-parser-uac/src/parsers/mod.rs`
  - New fn `detect_shell_upgrade_chain(findings: &[HiddenProcessFinding]) -> Option<ShellUpgradeAlert>`
  - Pattern: any finding whose `process_name` matches an interpreter (python2/3, ruby, perl, socat, lua, node)
    AND whose connections share an external IP:port with a `sh`/`dash` finding AND a `bash` finding
  - `ShellUpgradeAlert { attacker_ip, attacker_port, interpreter, pids: Vec<u32>, technique: "T1059.006" }`
  - Interpreter list sourced from `forensicnomicon::heuristics::linux_rootkit::SHELL_UPGRADE_INTERPRETERS`
    (see `forensicnomicon/PLAN_LINUX_HEURISTICS.md`)
- `crates/issen-cli/src/commands/pivot.rs`
  - Call `detect_shell_upgrade_chain()` on hidden findings
  - Emit Evidence with tag `shell_upgrade_chain`, attrs `attacker_ip`, `attacker_port`, `interpreter`
- `crates/issen-correlation/rules/080-shell-upgrade-chain.yml` (new file)
  - Fires on `shell_upgrade_chain` tag
  - Finding: "Interactive shell upgrade via <interpreter> — PTY over SSH (T1059.006)"
  - Severity: high, confidence: 90%
- `crates/issen-cli/src/commands/analyse.rs`
  - Surface ShellUpgradeAlert in hidden process section output

**TDD RED tests:**
```rust
fn shell_upgrade_none_when_no_hidden_processes()
fn shell_upgrade_none_when_only_bash_no_interpreter()
fn shell_upgrade_detected_sh_python3_bash_on_same_socket()
fn shell_upgrade_detected_sh_python2_bash()
fn shell_upgrade_detected_sh_ruby_bash()
fn shell_upgrade_detected_sh_perl_bash()
fn shell_upgrade_detected_sh_socat_bash()
fn shell_upgrade_attacker_ip_extracted()
fn shell_upgrade_requires_shared_external_ip()
fn shell_upgrade_interpreter_field_set()
```

**GREEN implementation sketch:**
```rust
pub struct ShellUpgradeAlert {
    pub attacker_ip: String,
    pub attacker_port: u16,
    pub interpreter: String,
    pub pids: Vec<u32>,
}

const SHELL_INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "ruby", "perl", "lua", "node", "socat",
];

pub fn detect_shell_upgrade_chain(
    findings: &[HiddenProcessFinding],
) -> Option<ShellUpgradeAlert> {
    let is_sh    = |n: &str| matches!(n, "sh" | "dash");
    let is_bash  = |n: &str| matches!(n, "bash" | "zsh" | "fish");
    let is_interp = |n: &str| SHELL_INTERPRETERS.iter().any(|i| n.starts_with(i));

    let interp = findings.iter().find(|f| {
        f.process_name.as_deref().is_some_and(is_interp)
    })?;

    let externals: Vec<(&str, u16)> = interp.connections.iter()
        .filter(|c| !c.dst_addr.starts_with("127.") && c.dst_addr != "::1")
        .filter_map(|c| c.dst_port.map(|p| (c.dst_addr.as_str(), p)))
        .collect();
    if externals.is_empty() { return None; }

    let shares = |f: &HiddenProcessFinding, ip: &str, port: u16| {
        f.connections.iter().any(|c| c.dst_addr == ip && c.dst_port == Some(port))
    };

    for (ip, port) in &externals {
        let sh_hit   = findings.iter().any(|f| f.process_name.as_deref().is_some_and(is_sh)
                                           && shares(f, ip, *port));
        let bash_hit = findings.iter().any(|f| f.process_name.as_deref().is_some_and(is_bash)
                                           && shares(f, ip, *port));
        if sh_hit && bash_hit {
            let pids = findings.iter()
                .filter(|f| f.process_name.as_deref()
                    .is_some_and(|n| is_sh(n) || is_interp(n) || is_bash(n)))
                .map(|f| f.pid).collect();
            return Some(ShellUpgradeAlert {
                attacker_ip: ip.to_string(),
                attacker_port: *port,
                interpreter: interp.process_name.clone().unwrap_or_default(),
                pids,
            });
        }
    }
    None
}
```

---

### Gap 3 — Hardcoded Year in `auth_log.rs`

**CTF question answered:** Q5 (when did the attack happen? — correct timestamps)  
**Why it matters:** `parse_syslog_ts()` at line 42 calls `NaiveDate::from_ymd_opt(2026, ...)`.
For any collection not from early 2026, all auth.log timestamps are silently wrong by years,
breaking timeline correlation across all Linux engagements.

**Evidence:** `crates/parsers/issen-parser-linux/src/auth_log.rs:42` — literal `2026`.
`boot_log.rs` shares `parse_syslog_ts` and inherits the bug.

**Files to change:**
- `crates/parsers/issen-parser-linux/src/auth_log.rs`
  - Change `parse_syslog_ts(line: &str)` → `parse_syslog_ts(line: &str, year_hint: i32)`
  - If parsed timestamp is `> now + 30 days`: retry with `year_hint - 1` (log spanning year boundary)
  - Update `parse_auth_log` to accept `year_hint: Option<i32>`; default to `Utc::now().year()`
- `crates/parsers/issen-parser-linux/src/boot_log.rs`
  - Update call to pass `year_hint`
- `crates/issen-cli/src/commands/analyse.rs`
  - Extract year from `manifest.metadata.collection_time`; pass to parsers

**TDD RED tests:**
```rust
fn parse_syslog_ts_uses_year_hint_not_hardcoded_2026()
fn parse_syslog_ts_rolls_back_one_year_when_result_is_future()
fn parse_auth_log_respects_year_hint()
fn parse_auth_log_year_hint_2025_timestamps_correct()
fn parse_auth_log_year_hint_none_uses_current_year()
```

---

### Gap 4 — No Compromise Verdict Display

**CTF question answered:** Q4 (is the system compromised?)  
**Why it matters:** `analyse.rs` produces good individual sections but no top-level verdict.
Output ends with "Issen analysis complete" whether the system has a rootkit or is clean.

**Files to change:**
- `crates/issen-cli/src/commands/analyse.rs`
  - New fn `compute_verdict(findings: &[Finding], hidden_count: usize, cpu_pct: Option<f32>) -> Verdict`
  - `Verdict { level: VerdictLevel, critical_count: usize, warning_count: usize, techniques: Vec<String> }`
  - `VerdictLevel`: `Confirmed` (any Critical), `Probable` (≥2 Warning or Warning+hidden_pids),
    `Suspicious` (1 Warning), `Clean` (no findings)
  - Print verdict banner **first**, before all sections
  - Print ATT&CK technique list (deduplicated from `mitre_techniques` fields) as last section

**TDD RED tests:**
```rust
fn verdict_confirmed_on_critical_finding()
fn verdict_confirmed_on_hidden_pids_plus_rootkit_warning()
fn verdict_probable_on_two_warnings()
fn verdict_suspicious_on_single_warning()
fn verdict_clean_on_empty_findings()
fn verdict_confirmed_on_cpu_anomaly_plus_hidden_pids()
```

---

### Gap 5 — Library Detection Is Name-Based, Not Capability-Based

**CTF question answered:** Q3 robustness — catches rootkits regardless of library name  
**Why it matters:** `analyse.rs:232-234` hardcodes `"libymv"`, `"libhide"`, `"libproc"` as
substrings. This only catches installations that happen to use those names. An attacker
who names their rootkit `libssl-extra.so.3` bypasses detection entirely.

**Two-layer generic detection required:**

**Layer A — Preload Path Cross-Reference** (catches any preloaded `.so`, name-agnostic):
- Any `.so` listed in `ld.so.preload` AND found in `hash_executables/` is flagged as a
  preloaded foreign library — no name pattern needed.
- Replaces the `p.contains("libymv")` block in `analyse.rs`.

**Layer B — ELF Symbol Import Analysis** (classifies capability, name-agnostic):
- Read the preloaded `.so` file bytes (from `hash_executables/` or file carve).
- Parse ELF dynamic symbol table (see `memory-forensic/PLAN_LINUX_ELF_ANALYSIS.md` for
  the new `memf-linux` capability).
- Classify by imported hooks: `readdir64`/`getdents64` → process-hiding; `pam_get_item` →
  PAM credential theft; `getpwuid` → UID spoofing; `write` override → I/O interception.
- This replaces `KNOWN_ROOTKIT_LIBS` name-matching with behavioral fingerprinting.
- Constants live in `forensicnomicon::heuristics::linux_rootkit` (see
  `forensicnomicon/PLAN_LINUX_HEURISTICS.md`).

**Layer C — Library Provenance Check** (catches any library not from package manager):
- Read installed package file list from UAC `packages/` artifacts.
- Any library in `ld.so.preload` whose absolute path is NOT owned by any installed package →
  `Critical` finding, regardless of name or capability.
- Complements Layer A (which requires the library to appear in `hash_executables/`).

**Evidence:** `analyse.rs:232` — `if p.contains("libymv") || p.contains("libhide") ...`

**Files to change:**
- `crates/parsers/issen-parser-uac/src/parsers/hash_execs.rs`
  - New fn `find_preloaded_executables(root: &Path, preload_paths: &[String]) -> Vec<HashedExecutable>`
  - Reads hashed executables, intersects with preload path list
- `crates/parsers/issen-parser-uac/src/parsers/packages.rs`
  - New fn `find_unpackaged_paths(paths: &[String], pkg_db: &[InstalledPackage]) -> Vec<String>`
  - Returns entries in `paths` not owned by any installed package
- `crates/issen-cli/src/commands/analyse.rs`
  - Replace `p.contains("libymv")` block with:
    1. `find_preloaded_executables()` (Layer A)
    2. Call into ELF capability analyzer from `memf-linux` (Layer B — when dep is available)
    3. `find_unpackaged_paths()` (Layer C)

**TDD RED tests (hash_execs.rs):**
```rust
fn find_preloaded_empty_when_no_preload()
fn find_preloaded_matches_path_in_hash_list()
fn find_preloaded_no_match_when_paths_differ()
fn find_preloaded_returns_hash_for_matched_lib()
fn find_preloaded_ignores_unrelated_libs()
fn find_preloaded_matches_regardless_of_library_name()  // /tmp/evil.so == preloaded
```

**TDD RED tests (packages.rs):**
```rust
fn find_unpackaged_empty_when_all_owned()
fn find_unpackaged_returns_path_not_in_pkg_db()
fn find_unpackaged_case_insensitive_path_compare()
fn find_unpackaged_empty_pkg_db_flags_all_paths()
```

---

### Gap 6 — Thread Pool Name Intelligence Is Single-Pattern

**Manifestation in Father:** XMRig disguises as `top` with `libuv-worker` thread pool  
**Why it matters:** `build_evidence()` hard-codes `libuv-worker` as the miner thread
pattern. XMRig also uses `cn-pow`, `rx/0`, `RandomX`, and `persistent-thread` depending
on version and coin. Monero miners use `cpu-miner-*`. Other process-hollowing implants
use `worker-thread` or C2-specific names. A table-driven approach in `forensicnomicon`
makes all of these detectable without code changes.

**Evidence:** `pivot.rs` — `if t.contains("libuv-worker") { tags.push("miner_thread") }` (single hard-coded pattern)

**Files to change:**
- `forensicnomicon/src/heuristics/linux_rootkit.rs` (new — see `forensicnomicon/PLAN_LINUX_HEURISTICS.md`)
  - `MINER_THREAD_PATTERNS: &[(&str, &str)]` — `(pattern, malware_family)` pairs
  - `MINER_PORT_PAIRS: &[u16]` — Stratum and Monero pool ports beyond {3333}
- `crates/issen-cli/src/commands/pivot.rs`
  - Replace single `libuv-worker` check with `forensicnomicon::heuristics::linux_rootkit::classify_thread_name(name)`
  - Returns `Option<&'static str>` (malware family if known, else None)
  - Emit `miner_thread` evidence for any miner classification; add `family` attr when known

**TDD RED tests:**
```rust
fn classify_thread_libuv_worker_is_xmrig()
fn classify_thread_cn_pow_is_xmrig()
fn classify_thread_randomx_is_xmrig()
fn classify_thread_cpu_miner_is_generic_miner()
fn classify_thread_worker_thread_is_generic()
fn classify_thread_unknown_returns_none()
fn build_evidence_cn_pow_thread_tags_miner_thread()
fn build_evidence_randomx_thread_tags_miner_thread()
```

### Gap 7 — No Generic Malware Classification Engine

**Why it matters:** The current code does bespoke detection for individual malware
properties (KNOWN_ROOTKIT_LIBS name check, single libuv-worker thread pattern, etc.).
Every new malware family requires editing detection code. The correct architecture is:

1. Detection functions emit **signals** (observable atomic facts with string IDs)
2. A profile database defines which signals each malware family emits and at what weight
3. A scoring engine scores signals against every known profile simultaneously

This produces a ranked match list rather than a binary yes/no, correctly handles renamed
and recompiled variants (behavioral signals are name-agnostic), and lets new malware
families be added by writing a profile entry — not by changing detection code.

The full profile framework design is in `forensicnomicon/PLAN_LINUX_HEURISTICS.md`.
This gap covers the issen-side integration: signal collection + engine call.

**Files to change:**

- `crates/parsers/issen-parser-uac/src/parsers/rootkit.rs`
  - Refactor: existing findings translated to `DetectedSignal` emissions
  - `fn emit_signals_from_rootkit_findings(findings: &[RootkitFinding]) -> Vec<DetectedSignal>`
  - Each `RootkitFinding.check` value maps to one or more signal IDs from `forensicnomicon::threat_intel::signals`

- `crates/parsers/issen-parser-uac/src/parsers/mod.rs`
  - Add `fn emit_signals_from_hidden_processes(findings: &[HiddenProcessFinding]) -> Vec<DetectedSignal>`
  - Emits: `PROCESS_HIDDEN_FROM_PS`, `PROCESS_THREAD_MINER_XMRIG`, `PROCESS_THREAD_MINER_GENERIC`,
    `PROCESS_ANOMALOUS_THREAD_COUNT`, `PROCESS_MASQUERADE`, `NETWORK_STRATUM_CONNECTION`,
    `NETWORK_STRATUM_LISTEN`, `NETWORK_SSH_STRATUM_TUNNEL`, `PROCESS_SHELL_UPGRADE_CHAIN`

- `crates/issen-cli/src/commands/analyse.rs`
  - New fn `collect_all_signals(root, rootkit_findings, hidden_findings, elf_reports, pkg_db, cpu_pct) -> Vec<DetectedSignal>`
  - Calls `forensicnomicon::threat_intel::engine::score_all_profiles(&signals)`
  - Replaces ad-hoc findings display with structured profile match output
  - Shows top 3 matches (any with score > 0) with confidence band labels
  - Signals that fired are listed per match for analyst transparency

**Output format:**

```
MALWARE CLASSIFICATION
  Father          [CONFIRMED  score=92]  process-hiding + PAM + staging-file + string-artifacts
  Azazel          [CLASS_MATCH score=50] process-hiding + PAM (same capability class)
  Unknown LD_PRELOAD [CLASS_MATCH score=40] globally-loaded + process-hiding
  XMRig           [CONFIRMED  score=78]  libuv-worker threads + Stratum connection + CPU anomaly
```

**TDD RED tests:**
```rust
fn emit_signals_ld_preload_finding_emits_artifact_signal()
fn emit_signals_kernel_taint_emits_system_kernel_taint_signal()
fn emit_signals_hidden_process_emits_process_hidden_signal()
fn emit_signals_libuv_worker_thread_emits_miner_xmrig_signal()
fn emit_signals_stratum_connection_emits_network_stratum_signal()
fn collect_all_signals_combines_all_sources()
fn score_all_profiles_called_with_collected_signals()
fn analyse_output_shows_top_profile_match()
fn analyse_output_shows_fired_signals_per_match()
fn analyse_renamed_father_library_still_classifies_as_father_class()
```

---

## Implementation Order

Dependencies:

```
Gap 3 (year fix)      — no deps, touches auth_log.rs only
Gap 4 (verdict)       — no deps (can use empty findings as baseline)
Gap 1 (PAM staging)   — no deps; generalized to structural pattern
Gap 2 (shell upgrade) — depends on mod.rs hidden-process analysis
Gap 6 (thread names)  — depends on forensicnomicon new module (see that plan)
Gap 5 (ELF capability)— depends on memf-linux ELF analysis (see that plan);
                         Layers A+C are standalone and can ship before Layer B
Gap 7 (confidence score) — depends on Gap 1 (staging) + Gap 5 Layer B (ELF) + forensicnomicon
```

**Sprint order:**

| Sprint | Gap | Effort | Impact |
|--------|-----|--------|--------|
| 1 | Gap 3 — year fix | XS | Correctness: all auth.log timestamps across all engagements |
| 2 | Gap 1 — PAM credential staging (structural pattern) | S | Q3: content-based detection, survives rename |
| 3 | Gap 5 (Layers A+C) — preload cross-reference + provenance | S | Q3 robustness: name-agnostic |
| 4 | Gap 4 — verdict display | S | Q4: top-level COMPROMISE CONFIRMED output |
| 5 | Gap 2 — shell upgrade chain | M | Q1: auto-answer interpreter-agnostic pty.spawn |
| 6 | Gap 6 — thread pool name table | S | Miner detection beyond libuv-worker |
| 7 | Gap 5 (Layer B) — ELF capability analysis | M | Requires memf-linux ELF plan to land first |
| 8 | Gap 7 — Father-class confidence score + ELF string artifacts | M | Variant attribution; variant vs novel classification |

---

## TDD Commit Protocol (per gap)

Each gap = **two commits**:

```
RED:   test(<crate>): <gap name> — failing tests
GREEN: feat(<crate>): <gap name> — implementation
```

The RED commit must compile (stubs use `todo!()`). The GREEN commit makes all
RED tests pass without touching test code.

Run after each GREEN:
```bash
cargo test -p issen-parser-uac -p issen-parser-linux -p issen-correlation -p issen-cli
```

---

## Cross-Repo Dependencies

These gaps require changes in sibling repos before they can be fully closed:

| Gap | Sibling repo | Plan file |
|-----|-------------|-----------|
| Gap 2 — interpreter list | `forensicnomicon` | `PLAN_LINUX_HEURISTICS.md` |
| Gap 5 Layer B — ELF analysis | `memory-forensic` | `PLAN_LINUX_ELF_ANALYSIS.md` |
| Gap 5 Layer B — hook symbols | `forensicnomicon` | `PLAN_LINUX_HEURISTICS.md` |
| Gap 6 — thread name table | `forensicnomicon` | `PLAN_LINUX_HEURISTICS.md` |

Layers A and C of Gap 5 are self-contained in `issen-parser-uac` and can be
implemented immediately without waiting for the sibling repo plans.

---

## What `issen analyse` Produces After All Gaps Closed

```
VERDICT: COMPROMISE CONFIRMED
Evidence: 4 critical finding(s), 1 warning

ROOTKIT INDICATORS
  [CRITICAL] pam_credential_staging — /tmp/silly.txt
             PAM hook credential staging: 1 credential(s) captured
  [CRITICAL] preloaded_library_unpackaged — /lib/x86_64-linux-gnu/libymv.so.3
             Library in ld.so.preload not owned by any installed package
  [CRITICAL] preloaded_library_capability — /lib/x86_64-linux-gnu/libymv.so.3
             ELF imports: readdir64 (process hiding), pam_get_item (credential theft)
  [WARNING]  kernel_taint — taint=4, bit 2 set

HIDDEN PROCESSES
  6 PIDs visible in /proc, hidden from ps:

  PID 939  sh   192.168.4.22:22 → 192.168.4.35:48411
  PID 940  python3   192.168.4.22:22 → 192.168.4.35:48411
  PID 941  bash   192.168.4.22:22 → 192.168.4.35:48411
    ^ Shell upgrade via python3 — interactive PTY over SSH (T1059.006)

  PID 975  ssh   ::1:3333 LISTEN, 192.168.5.22:22 → 192.168.5.95:22
  PID 977  top [libuv-worker → XMRig]   127.0.0.1 → 127.0.0.1:3333
  PID 43168 (unknown — no memory dump)

CORRELATION FINDINGS
  [CRITICAL] Rootkit-concealed crypto miner (rule 010)
  [CRITICAL] LD_PRELOAD rootkit activation sequence (rule 070)
  [CRITICAL] Interactive shell upgrade via python3 — PTY over SSH (rule 080)
  [CRITICAL] Miner tunnelling Stratum via SSH (rule 020)
  [WARNING]  LD_PRELOAD rootkit persistence (rule 035)

SUSPICIOUS EXECUTABLES
  /lib/x86_64-linux-gnu/libymv.so.3 — SHA1: 0fd709f09c073df274e272aabcabe3e0f3487f9e
    ^ In ld.so.preload; not owned by any installed package

ATT&CK TECHNIQUES
  T1574.006  Hijack Execution Flow: LD_PRELOAD
  T1014      Rootkit
  T1496      Resource Hijacking (crypto mining)
  T1572      Protocol Tunneling (Stratum-over-SSH)
  T1059.006  Command and Scripting: Python (shell upgrade)
  T1078.003  Valid Accounts: Local Accounts
```
