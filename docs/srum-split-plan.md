# Split Plan: srum-forensic → RapidTriage

**Date:** 2026-05-04
**Status:** PROPOSED — not yet executed
**Source repo:** SecurityRonin/srum-forensic (public, MIT)
**Pattern:** identical to `usnjrnl-forensic` integration

---

## Findings from Codebase Audit

### Q1 — ArtifactType::Srum already exists

`rt-core::artifacts::types::ArtifactType::Srum` is already declared:

```rust
/// System Resource Usage Monitor (SRUM)
Srum,
```

No change needed to `rt-core`. The plumbing is ready.

### Q2 — srum-forensic crate structure

```
srum-forensic/
├── crates/
│   ├── ese-core/       ESE/JET Blue page reader: EseHeader, EseDatabase, EsePage
│   ├── srum-core/      Pure data types: NetworkUsageRecord, AppUsageRecord, IdMapEntry
│   ├── srum-parser/    parse_network_usage(path), parse_app_usage(path) [stub → active via ralph loop]
│   └── sr-cli/         Standalone `sr` binary (network/apps subcommands, JSON output)
```

**srum-parser status at time of writing**: ESE header validation complete; B-tree record extraction
in progress via ralph TDD loop (user stories: ese-page-header → ese-page-tags → ese-catalog →
ese-btree-walk → srum-network-parsing → srum-app-parsing → srum-idmap).

### Q3 — ese-core is a general ESE library

`ese-core` is not SRUM-specific. ESE (JET Blue) is also used by:
- `WebCacheV01.dat` — IE/Edge browser history
- `ntds.dit` — Active Directory database
- `Windows.edb` — Windows Search index
- `DataStore.edb` — Windows Update

`ese-core` has standalone value as a general ESE reader. For now it lives in
srum-forensic. Future consideration: extract as `ese-forensic` sibling workspace if
`rt-parser-webcache` or Active Directory analysis is added to RapidTriage.

### Q4 — Correlation rules gap

RapidTriage has zero SRUM-specific correlation rules in `rt-correlation/rules/`.
Network and process evidence from SRUM records is uniquely useful for:
- **Exfil detection** — large outbound from short-lived or background-only processes
- **C2 beacon fingerprinting** — regular fixed-size sends across multiple hourly intervals
- **Background CPU miner** — high background_cycles, no foreground_cycles, process not in signed allowlist
- **Stealth process** — AppUsageRecord entries with no corresponding EventLog 4688/Prefetch trace

These CANNOT be detected from any existing RapidTriage artifact source alone.
SRUM is the only Windows artifact with per-process hourly bandwidth accounting.

### Q5 — Dependency graph

`usnjrnl-forensic` is the reference pattern: path dep → wrapping parser crate:

```toml
# RapidTriage/Cargo.toml [workspace.dependencies]
usnjrnl-forensic = { path = "../usnjrnl-forensic" }
```

```
rt-parser-usnjrnl → usnjrnl-forensic (path)
```

SRUM follows the same shape.

---

## Architecture Decision: What Stays, What Moves

### srum-forensic stays as a standalone public library

`srum-forensic` is intentionally a public, standalone library/tool (MIT, on crates.io path).
It provides field value independently of RapidTriage — an investigator on a Linux workstation
can run `sr network SRUDB.dat | jq ...` without installing the full RapidTriage suite.
This mirrors the `usnjrnl-forensic` / `blazehash` pattern in the SecurityRonin ecosystem.

**Nothing leaves srum-forensic.** RapidTriage adds a consumption layer on top.

### What goes in RapidTriage (new)

| Component | Location | Description |
|-----------|----------|-------------|
| `rt-parser-srum` | `crates/parsers/rt-parser-srum/` | Wraps srum-parser; implements `ForensicParser`; emits `TimelineEvent` |
| SRUM correlation rules | `crates/rt-correlation/rules/srum/` | 4 YAML rule files (see below) |
| `rt srum` CLI subcommand | `crates/rt-cli/src/commands/srum.rs` | `rt srum <path>` → timeline ingest + JSON output |
| SRUM navigator view | `crates/rt-navigator/src/investigation/views/srum.rs` | TUI table of SRUM records (stretch) |

---

## Target State

### srum-forensic (unchanged public library)

```
srum-forensic/
├── crates/
│   ├── ese-core/          EseHeader, EseDatabase, read_page(), page_count()
│   │                      EsePageHeader (flags, prev_page, next_page)    ← ralph in progress
│   │                      EsePage::tags(), record_data()                 ← ralph in progress
│   │                      EseDatabase::catalog_entries(), find_table_page()  ← ralph queued
│   │                      EseDatabase::walk_leaf_pages()                 ← ralph queued
│   ├── srum-core/         NetworkUsageRecord, AppUsageRecord, IdMapEntry
│   ├── srum-parser/       parse_network_usage(), parse_app_usage()       ← ralph in progress
│   │                      parse_id_map()                                 ← ralph queued
│   └── sr-cli/            `sr network`, `sr apps`, `sr idmap`            standalone binary
```

**srum-forensic publishes to crates.io once ralph loop completes.**

### RapidTriage (additions only)

```
RapidTriage/
├── Cargo.toml
│   └── [workspace.dependencies]
│       srum-parser = { path = "../srum-forensic/crates/srum-parser" }   ← ADD
│       srum-core   = { path = "../srum-forensic/crates/srum-core" }     ← ADD
│
├── crates/
│   ├── parsers/
│   │   └── rt-parser-srum/                                              ← NEW CRATE
│   │       ├── Cargo.toml
│   │       └── src/
│   │           ├── lib.rs          SrumParser: ForensicParser impl
│   │           ├── network.rs      NetworkUsageRecord → TimelineEvent
│   │           └── app_usage.rs    AppUsageRecord → TimelineEvent
│   │
│   ├── rt-correlation/
│   │   └── rules/srum/                                                  ← NEW RULES
│   │       ├── srum-exfil-candidate.yaml
│   │       ├── srum-c2-beacon.yaml
│   │       ├── srum-background-miner.yaml
│   │       └── srum-stealth-process.yaml
│   │
│   └── rt-cli/
│       └── src/commands/srum.rs                                         ← NEW SUBCOMMAND
│
└── (rt-navigator SRUM view — stretch goal, not in this plan)
```

---

## What Moves Where (Concrete)

### Nothing moves out of srum-forensic

srum-forensic is a published public library. Moving code out would break the standalone
`sr` binary and any external consumers.

### New code goes into RapidTriage

#### 1. Workspace dependency additions (`RapidTriage/Cargo.toml`)

```toml
[workspace.dependencies]
# ADD after usnjrnl-forensic line:
srum-parser = { path = "../srum-forensic/crates/srum-parser" }
srum-core   = { path = "../srum-forensic/crates/srum-core" }
```

#### 2. `rt-parser-srum/Cargo.toml`

```toml
[package]
name = "rt-parser-srum"
version = "0.1.0"
edition.workspace = true

[dependencies]
srum-parser.workspace = true
srum-core.workspace = true
rt-core.workspace = true
chrono.workspace = true
anyhow.workspace = true
inventory.workspace = true
```

#### 3. `rt-parser-srum/src/lib.rs` — ForensicParser impl

```rust
use rt_core::plugin::traits::ForensicParser;
use rt_core::timeline::event::{EventType, TimelineEvent};
use rt_core::artifacts::types::ArtifactType;
use srum_core::{NetworkUsageRecord, AppUsageRecord};

inventory::submit! {
    rt_core::plugin::registry::ParserRegistration {
        artifact_type: ArtifactType::Srum,
        create: || Box::new(SrumParser),
    }
}

pub struct SrumParser;

impl ForensicParser for SrumParser {
    fn parse(&self, source: &dyn rt_core::vfs::DataSource,
             emitter: &mut dyn rt_core::plugin::traits::EventEmitter)
        -> anyhow::Result<rt_core::plugin::traits::ParseStats>
    {
        // 1. Write source to tempfile (DataSource → file path for srum-parser)
        // 2. parse_network_usage(path) → emit NetworkBandwidth events
        // 3. parse_app_usage(path) → emit ProcessExec events
        // 4. parse_id_map(path) → populate id→name lookup for event metadata
        todo!()  // Implementation written test-first via TDD
    }
}
```

#### 4. TimelineEvent mappings

**NetworkUsageRecord → TimelineEvent:**
```
event_type:     EventType::NetworkBandwidth     (add this variant if absent)
timestamp_ns:   record.timestamp as nanoseconds since epoch
artifact:       ArtifactType::Srum
description:    "{app_name} sent {bytes_sent}B / recv {bytes_recv}B"
metadata:       { "app_id", "user_id", "bytes_sent", "bytes_recv",
                  "app_name" (resolved from IdMap), "user_name" (resolved) }
```

**AppUsageRecord → TimelineEvent:**
```
event_type:     EventType::ProcessExec         (already exists)
timestamp_ns:   record.timestamp as nanoseconds since epoch
artifact:       ArtifactType::Srum
description:    "{app_name} fg:{foreground_cycles} bg:{background_cycles} cycles"
metadata:       { "app_id", "user_id", "foreground_cycles", "background_cycles",
                  "app_name", "user_name" }
```

#### 5. SRUM correlation rules (`rt-correlation/rules/srum/`)

**srum-exfil-candidate.yaml**
```yaml
id: srum.exfil-candidate
title: "SRUM: High outbound from background-only process"
severity: high
assertion_level: Inferred
default_confidence: 65
within_seconds: 7200  # 2-hour window
clauses:
  - source: Artifact
    required_tag: srum-network
    attr_predicates:
      - attr: bytes_sent_mb
        op: gte
        value: "100"
  - source: Artifact
    required_tag: srum-app
    attr_predicates:
      - attr: app_id
        op: eq
        value: "{app_id}"
      - attr: foreground_cycles
        op: eq
        value: "0"
summary_template: >
  {app_name} sent {bytes_sent_mb} MB with zero foreground CPU — possible exfiltration.
explanation_template: >
  SRUM recorded large outbound network activity from a process that had no foreground
  CPU cycles in the same interval. Legitimate user-facing applications typically
  accumulate foreground cycles. Zero foreground with high outbound is consistent
  with a background exfiltration agent.
```

**srum-c2-beacon.yaml**
```yaml
id: srum.c2-beacon
title: "SRUM: Regular fixed-size outbound (beacon pattern)"
severity: medium
assertion_level: Inferred
default_confidence: 55
within_seconds: 14400  # 4-hour window
clauses:
  - source: Artifact
    required_tag: srum-network
    attr_predicates:
      - attr: beacon_variance_pct
        op: lte
        value: "10"   # <10% variance in bytes_sent across intervals
      - attr: interval_count
        op: gte
        value: "3"    # at least 3 consecutive intervals
summary_template: >
  {app_name} sent {bytes_sent_avg}B ±{beacon_variance_pct}% per interval
  over {interval_count} hours — consistent with C2 beaconing.
```

**srum-background-miner.yaml**
```yaml
id: srum.background-miner
title: "SRUM: High background CPU, no foreground (crypto miner candidate)"
severity: high
assertion_level: Likely
default_confidence: 70
within_seconds: 3600
clauses:
  - source: Artifact
    required_tag: srum-app
    attr_predicates:
      - attr: background_cycles_billion
        op: gte
        value: "10"
      - attr: foreground_cycles
        op: eq
        value: "0"
  - source: Artifact
    required_tag: srum-network
    attr_predicates:
      - attr: app_id
        op: eq
        value: "{app_id}"
summary_template: >
  {app_name} consumed {background_cycles_billion}B background CPU cycles with
  no foreground activity while also generating network traffic.
```

**srum-stealth-process.yaml**
```yaml
id: srum.stealth-process
title: "SRUM: Process in SRUM with no EventLog 4688 or Prefetch trace"
severity: high
assertion_level: Correlated
default_confidence: 75
within_seconds: 3600
clauses:
  - source: Artifact
    required_tag: srum-app
    attr_predicates:
      - attr: app_name
        op: not_in_evtx_4688
        value: "true"
      - attr: app_name
        op: not_in_prefetch
        value: "true"
summary_template: >
  {app_name} appears in SRUM activity records but has no corresponding
  process creation event (EventLog 4688) or Prefetch file — consistent
  with process hollowing, LSASS injection, or living-off-the-land binary.
explanation_template: >
  SRUM records resource usage for all processes the OS scheduler touches.
  EventLog 4688 and Prefetch are easily disabled or deleted by an attacker.
  A process visible in SRUM but absent from both 4688 and Prefetch is a
  strong indicator of anti-forensic activity or process injection.
```

#### 6. `rt-cli` SRUM subcommand (`crates/rt-cli/src/commands/srum.rs`)

```rust
/// rt srum <PATH> — parse SRUDB.dat and emit network/app records as JSON
/// or ingest into the timeline database.

#[derive(clap::Args)]
pub struct SrumArgs {
    /// Path to SRUDB.dat (or forensic copy)
    path: std::path::PathBuf,
    /// Ingest into timeline instead of printing JSON
    #[arg(long)]
    ingest: bool,
}

pub fn run(args: SrumArgs) -> anyhow::Result<()> {
    // Implementation written test-first via TDD
    todo!()
}
```

---

## Execution Phases

### Phase 0 — Prerequisites (blocker)

**Wait for ralph loop to complete in srum-forensic.**

`srum-parser::parse_network_usage()` and `parse_app_usage()` currently return `vec![]`.
All RapidTriage integration work depends on these returning real records.

Track progress: `cat ~/src/srum-forensic/scripts/ralph/log.md`

Expected completion order:
1. `ese-page-header` — ✅/⏳ (ralph in progress, diagnostics show GREEN phase)
2. `ese-page-tags` — ⏳
3. `ese-catalog` — ⏳
4. `ese-btree-walk` — ⏳
5. `srum-network-parsing` — ⏳ (unblocks Phase 1)
6. `srum-app-parsing` — ⏳
7. `srum-idmap` — ⏳ (unblocks Phase 2)

---

### Phase 1 — Wire rt-parser-srum (depends on srum-network-parsing passing)

**User story:**

```json
{
  "description": "RapidTriage ingest command accepts SRUDB.dat as Srum artifact",
  "steps": [
    "Add srum-parser and srum-core path deps to RapidTriage/Cargo.toml",
    "Create crates/parsers/rt-parser-srum/",
    "Implement SrumParser implementing ForensicParser",
    "Map NetworkUsageRecord → TimelineEvent (NetworkBandwidth)",
    "Map AppUsageRecord → TimelineEvent (ProcessExec)",
    "Register via inventory::submit!",
    "rt ingest --artifact srum path/to/SRUDB.dat emits events into timeline",
    "cargo test -p rt-parser-srum passes"
  ],
  "passes": false
}
```

**TDD sequence (two commits each):**

1. RED: `rt-parser-srum` crate, failing tests for `SrumParser::parse()`
2. GREEN: minimal `SrumParser` implementation — network + app records → TimelineEvent
3. RED: tests for ID map resolution (app_id → app_name in event metadata)
4. GREEN: `parse_id_map()` integrated, metadata populated

---

### Phase 2 — Correlation rules (depends on Phase 1)

**User story:**

```json
{
  "description": "rt-correlation detects SRUM-based threat patterns",
  "steps": [
    "Add srum-exfil-candidate.yaml rule to rt-correlation/rules/srum/",
    "Add srum-c2-beacon.yaml",
    "Add srum-background-miner.yaml",
    "Add srum-stealth-process.yaml (requires cross-correlation with EventLog + Prefetch)",
    "rt-correlation loads SRUM rules from bundled rule pack",
    "evaluate() produces Findings for synthetic SRUM evidence matching each rule",
    "cargo test -p rt-correlation passes"
  ],
  "passes": false
}
```

**Note on srum-stealth-process:** This rule correlates SRUM evidence with `EventLog`
and `Prefetch` evidence. It requires cross-artifact correlation, meaning it can only
trigger when the timeline contains evidence from multiple artifact sources.
Implement the intra-SRUM rules first (exfil, beacon, miner), add stealth-process in
a follow-up iteration.

---

### Phase 3 — CLI subcommand (depends on Phase 1)

**User story:**

```json
{
  "description": "rt srum <path> parses SRUDB.dat and outputs JSON",
  "steps": [
    "rt srum path/to/SRUDB.dat prints JSON array of network + app records",
    "rt srum --ingest path/to/SRUDB.dat populates the DuckDB timeline",
    "rt srum nonexistent.dat exits non-zero with error message",
    "Integration tests in rt-cli/tests/ pass"
  ],
  "passes": false
}
```

---

### Phase 4 — Navigator view (stretch, not time-boxed)

- `rt-navigator`: `SrumView` showing network/app records in a sortable TUI table
- Columns: Timestamp · App name · User · Bytes sent · Bytes recv · FG cycles · BG cycles
- Filter by process name, user, time range

---

## Invariants (Do Not Break)

1. **srum-forensic builds and tests green independently** at all times.
   `cd ~/src/srum-forensic && cargo test --workspace` must always pass.

2. **`sr` binary remains usable standalone.** Users of `sr network SRUDB.dat`
   must not need to install RapidTriage.

3. **No circular deps.** srum-forensic must never import from RapidTriage.

4. **TDD on every change.** All new code in RapidTriage follows RED-GREEN-REFACTOR.
   Two commits per story: `test(red):` then `feat: GREEN —`.

5. **`ArtifactType::Srum` stays where it is.** It's in `rt-core` and already correct.
   Do not duplicate it in `rt-parser-srum`.

---

## Open Questions

| Question | Decision |
|----------|----------|
| Publish `srum-parser` to crates.io? | Yes, once ralph loop completes. Use as crates.io dep in production. Keep path dep during development. |
| Publish `ese-core` separately? | Future consideration if `rt-parser-webcache` (Edge/IE history) is added. ese-core is useful for WebCacheV01.dat and ntds.dit. |
| Should `rt-parser-srum` stream records or batch? | Batch (Vec return) matching srum-parser API. SRUDB.dat is small enough (typically < 50 MB). |
| EventLog 4688 + Prefetch required for srum-stealth? | Yes — implement as Phase 3 after Phase 1 is wired. Stealth rule requires multi-artifact timeline. |
| Add `EventType::NetworkBandwidth` to rt-core? | Yes in Phase 1. Check rt-core EventType enum before adding — avoid duplicates. |

---

## Reference

- srum-forensic repo: https://github.com/SecurityRonin/srum-forensic
- SRUM GUID reference: https://github.com/MarkBaggett/srum-dump (table schemas)
- ESE format: Microsoft MS-ESEDB open specification
- Ralph loop progress: `~/src/srum-forensic/scripts/ralph/log.md`
- usnjrnl-forensic integration (reference pattern): `crates/parsers/rt-parser-usnjrnl/`
