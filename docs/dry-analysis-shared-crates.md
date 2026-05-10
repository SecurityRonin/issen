# DRY Analysis: Shared Code Between Issen and memory-forensic

**Date:** 2026-04-10  
**Scope:** `~/src/Issen` and `~/src/memory-forensic`  
**Method:** Static analysis of parsers, carvers, scanners, alert heuristics, and walker classifiers across both workspaces

---

## Executive Summary

Both repositories implement forensic analysis functionality that, in several cases, embeds identical or near-identical constants, predicates, and data structures. The duplication is not cosmetic — it means that an update to (say) a suspicious port list must be made in two places, and divergence between them is already visible. However, not all apparent similarity represents true duplication: the two repos operate at different layers of the forensic stack, and unifying logic that looks similar but serves different purposes would create wrong abstractions.

**Bottom line:** Create two small, dependency-free crates in the `memory-forensic` workspace — `forensic-patterns` and `forensic-types` — and migrate the four concrete duplications identified below. Do not merge walkers, YARA engines, severity enums, network connection models, timeline logic, or IOC management.

---

## Dependency Direction

Issen already depends on `memory-forensic` crates (e.g. `memf-core`, `memf-format`, `memf-linux`, `memf-windows`). Any shared crate must live in the `memory-forensic` workspace. Placing it in `Issen` would create a circular dependency: `memory-forensic → Issen → memory-forensic`.

```
memory-forensic workspace
  ├── memf-core
  ├── memf-linux
  ├── memf-windows
  ├── forensic-patterns    ← NEW (no deps except std)
  └── forensic-types       ← NEW (deps: serde only)

Issen workspace
  ├── rt-parser-uac        ← adds forensic-patterns, forensic-types as deps
  ├── rt-navigator         ← adds forensic-patterns as dep
  └── rt-mem               (no change needed)
```

---

## Category A: Concrete Duplications — Extract Immediately

### A1. Suspicious Port List (HIGH severity)

**Issen** — `crates/rt-navigator/src/investigation/alerts/types.rs`  
Defines `SUSPICIOUS_PORTS: &[u16]` with ~30 entries: 4444, 50050, 31337, 1337, 8888, 9999, 4445, and others widely associated with C2 frameworks (Metasploit, Cobalt Strike, Empire).

**memory-forensic** — Inline in multiple walker classifiers across `memf-linux/` and `memf-windows/`  
The same port numbers appear hardcoded in `if port == 4444 || port == 50050 …` guards scattered across at least four walker files.

**Impact of divergence:** If a new C2 port is added to the alert heuristic in `rt-navigator` but not to the walker classifier in `memf-linux`, the memory walker will miss it even though the higher-level triage layer would catch it — a false negative at the forensic evidence layer.

**Resolution:** Extract to `forensic-patterns::ports`:
```rust
pub const SUSPICIOUS_PORTS: &[u16] = &[4444, 50050, 31337, 1337, 8888, 9999, 4445, …];
pub fn is_suspicious_port(port: u16) -> bool {
    SUSPICIOUS_PORTS.contains(&port)
}
```

---

### A2. Trusted System Library Path Predicates (HIGH severity)

**Issen**  
- `crates/rt-parser-uac/src/parsers/rootkit.rs`: `is_trusted_system_lib_path(path: &str) -> bool` — checks `System32`, `SysWOW64`, `WinSxS` prefixes  
- `crates/rt-navigator/src/investigation/alerts/filesystem.rs`: a second, slightly different implementation of the same predicate

**memory-forensic**  
At least five separate inline implementations in:
- `memf-linux/src/pam_hooks.rs`
- `memf-linux/src/ld_preload.rs`
- `memf-linux/src/systemd_units.rs`
- `memf-linux/src/container_escape.rs`
- `memf-windows/` (PE validation walkers)

Each implementation differs slightly in which paths it considers trusted, introducing inconsistency: a library loaded from a path that one implementation considers trusted may be flagged by another.

**Resolution:** Extract to `forensic-patterns::paths`:
```rust
pub fn is_trusted_system_lib_path(path: &str) -> bool { … }
pub fn is_suspicious_temp_path(path: &str) -> bool { … }
```
The Linux and Windows predicates have different sets of trusted directories and should remain as `is_trusted_linux_lib_path` and `is_trusted_windows_lib_path` respectively — do not collapse them into one function with OS flags.

---

### A3. CrontabEntry Struct (HIGH severity)

**Issen** — `crates/rt-parser-uac/src/parsers/process.rs`  
```rust
pub struct CrontabEntry { pub schedule: String, pub command: String, pub user: String }
```

**memory-forensic** — `crates/memf-linux/src/crontab.rs`  
```rust
pub struct CrontabEntry { pub schedule: String, pub command: String, pub user: String }
```

These are byte-for-byte identical. The only reason they are separate is that neither workspace knew about the other's definition when each was written. Both derive `Debug`, `Clone`, `serde::Serialize`.

**Resolution:** Extract to `forensic-types::crontab`:
```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrontabEntry { pub schedule: String, pub command: String, pub user: String }
```
Both crates replace their local definition with `use forensic_types::crontab::CrontabEntry;`.

---

### A4. Reverse Shell Command Patterns (MODERATE severity)

**Issen** — `crates/rt-navigator/src/investigation/alerts/process.rs`  
Hardcoded slice of pattern strings: `"pty.spawn"`, `"bash -i"`, `"nc -e"`, `"/bin/sh -i"`, `"python -c"`, `"perl -e"`, `"ruby -e"`, `"lua -e"`.

**memory-forensic** — Multiple walker classifiers in `memf-linux/`  
The same patterns appear in process argument scanners, duplicated by string literal.

**Resolution:** Extract to `forensic-patterns::commands`:
```rust
pub const REVERSE_SHELL_PATTERNS: &[&str] = &["pty.spawn", "bash -i", "nc -e", …];
pub const SUSPICIOUS_DOWNLOAD_TOOLS: &[&str] = &["curl", "wget", "certutil", "bitsadmin", …];
```

---

## Category B: Same Concept, Different Implementation — Share Interface Only

### B1. YARA Scanner

Issen implements a YARA scanner that operates against **files and parsed artifact data** (LNK targets, prefetch paths, strings extracted from UAC collections). memory-forensic implements a YARA scanner that operates against **raw memory regions** (page-aligned byte slices, pool allocations). The scan targets, rule scoping, and error handling are necessarily different.

**Do not merge the implementations.** If a shared abstraction becomes valuable in the future, define a `trait YaraScanner` with a single `scan(&[u8]) -> Vec<YaraMatch>` method and let each crate provide its own implementation. Do not implement the trait in a shared crate.

### B2. Severity Enums

Issen defines `AlertSeverity { Critical, High, Medium, Low, Info }` tuned to triage alert presentation. memory-forensic walkers express severity as `ScanSeverity { Definite, Probable, Suspicious, Informational }` tuned to memory scan confidence levels. These are not the same taxonomy and should not be unified. Merging them would require either losing precision in one domain or adding meaningless variants to both.

### B3. NetworkConnection / Socket Models

Issen's `NetworkConnection` carries triage-layer fields: parsed timestamps, associated process name from UAC data, alert flags. memory-forensic's socket structures carry raw kernel fields: socket state machine values, struct offsets, kernel virtual addresses. The fields are different because the data sources are different. Do not unify; do not add a common base struct.

---

## Category C: Architecturally Distinct — Do Not Share

### C1. Timeline and Correlation Logic

`rt-navigator`'s correlation layer (C2 beacon detection, MFT/process cross-correlation, EventLog/network join) is Issen's primary value proposition over raw walker output. This logic belongs exclusively in `rt-navigator`. Placing it in `memory-forensic` would make the low-level forensic library aware of high-level triage concepts, inverting the dependency and polluting the library's scope.

### C2. IOC Feed Management

IOC (Indicator of Compromise) feed ingestion, deduplication, and TTL management live in `rt-navigator`. memory-forensic walkers have no mechanism for network or file-based feed updates and should not grow one. Feed management is a Issen concern.

### C3. Walker Implementation Code

Each OS walker (`walk_processes`, `walk_modules`, `walk_amsi_bypass`, etc.) is inherently tied to its kernel data structures and ISF symbol resolution. Even walkers that produce similarly named structs (e.g., `ProcessInfo` in both Linux and Windows walkers) parse different kernel structures via different ISF offsets. Sharing walker bodies would require abstraction layers that add complexity without correctness benefit.

---

## Proposed Crate Structure

```
memory-forensic/crates/
  forensic-patterns/
    Cargo.toml               # no deps except std
    src/
      lib.rs                 # pub mod ports; pub mod paths; pub mod commands; pub mod processes;
      ports.rs               # SUSPICIOUS_PORTS, is_suspicious_port()
      paths.rs               # is_trusted_linux_lib_path(), is_trusted_windows_lib_path(),
                             # is_suspicious_temp_path()
      commands.rs            # REVERSE_SHELL_PATTERNS, SUSPICIOUS_DOWNLOAD_TOOLS
      processes.rs           # KNOWN_MALWARE_PROCESS_NAMES
  forensic-types/
    Cargo.toml               # deps: serde (with derive feature)
    src/
      lib.rs                 # pub mod crontab; pub mod process;
      crontab.rs             # CrontabEntry { schedule, command, user }
      process.rs             # ProcessSummary (if needed after survey)
```

### Migration Checklist

| Step | File | Change |
|------|------|--------|
| 1 | `memory-forensic/Cargo.toml` workspace | Add `forensic-patterns`, `forensic-types` to `[workspace.members]` |
| 2 | `memf-linux/Cargo.toml` | Add `forensic-patterns` and `forensic-types` as deps |
| 3 | `memf-windows/Cargo.toml` | Add `forensic-patterns` as dep |
| 4 | `rt-parser-uac/Cargo.toml` | Add `forensic-patterns`, `forensic-types` as deps |
| 5 | `rt-navigator/Cargo.toml` | Add `forensic-patterns` as dep |
| 6 | Remove `SUSPICIOUS_PORTS` from `rt-navigator/alerts/types.rs` | Replace with `forensic_patterns::ports::SUSPICIOUS_PORTS` |
| 7 | Remove inline port checks from `memf-linux` walkers | Replace with `forensic_patterns::ports::is_suspicious_port(port)` |
| 8 | Remove duplicate `is_trusted_system_lib_path` from `rt-parser-uac` and `rt-navigator` | Replace with `forensic_patterns::paths::is_trusted_windows_lib_path` |
| 9 | Remove inline path checks from `memf-linux` walkers | Replace with `forensic_patterns::paths::is_trusted_linux_lib_path` |
| 10 | Remove `CrontabEntry` from `rt-parser-uac/parsers/process.rs` | Replace with `forensic_types::crontab::CrontabEntry` |
| 11 | Remove `CrontabEntry` from `memf-linux/src/crontab.rs` | Re-export `forensic_types::crontab::CrontabEntry` |
| 12 | Remove `REVERSE_SHELL_PATTERNS` from `rt-navigator/alerts/process.rs` | Replace with `forensic_patterns::commands::REVERSE_SHELL_PATTERNS` |
| 13 | Remove inline reverse-shell checks from `memf-linux` walkers | Replace with `forensic_patterns::commands::REVERSE_SHELL_PATTERNS` |

---

## What Not to Extract

| Candidate | Reason to Leave in Place |
|-----------|--------------------------|
| `NetworkConnection` / socket models | Different fields per OS/layer; unification loses precision |
| `AlertSeverity` vs `ScanSeverity` | Different taxonomies; a merged enum would be meaningless |
| YARA scanner implementation | Different scan targets (files vs. memory regions) |
| Walker bodies (`walk_*` functions) | Kernel-version-specific ISF offsets; cannot be shared |
| Timeline / correlation functions | Issen value-add; wrong abstraction layer for memory-forensic |
| IOC feed ingestion | Issen-only concern; memory-forensic has no feed infrastructure |
| `detect_alerts` / `anomalies_to_alerts` | Pure triage logic; no place in a forensic evidence library |

---

## Risk Assessment

**Low risk:** `forensic-patterns` has no external dependencies and exposes only constants and pure functions. A compilation failure is impossible at runtime, and migrating a constant is a mechanical substitution. Tests for the consuming crates cover the constants indirectly.

**Moderate risk:** `forensic-types` changes the canonical location of `CrontabEntry`. Any downstream code that serializes the struct to disk (e.g., JSON reports) will see no behavioral change since the field names are identical. Any code that pattern-matches on the module path (`forensic_types::crontab::CrontabEntry` vs. the previous paths) needs a `use` update.

**Mitigation:** Follow strict TDD per CLAUDE.md. RED commit: add failing tests in both workspaces that `use forensic_patterns::…` (these fail because the crate doesn't exist yet). GREEN commit: create the crates and migrate. Each workspace gets its own RED→GREEN commit pair.

---

## Conclusion

The duplication is real and consequential in four specific areas (ports, path predicates, CrontabEntry, reverse-shell patterns). The fix is small and low-risk: two new crates in the `memory-forensic` workspace, each under 200 lines of code. Everything else that looks similar across the two repos is similar by coincidence of domain, not by sharing the same data or logic — and should remain separate.
