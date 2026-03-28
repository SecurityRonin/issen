# Investigation Workbench TUI: Design Spec

## Overview

Extend `rt-navigator` (`rt-nav`) into a **unified forensic workbench**. When the user passes a collection archive (Velociraptor `.zip`, UAC `.tar.gz`), `rt-nav` extracts it, parses ALL artifacts into an integrated view with a **unified supertimeline** that merges all temporal data sources and separate drill-in views for point-in-time snapshot data. One tool, one command, full investigation.

For UAC (Linux) collections without an MFT, the bodyfile timestamps drive the supertimeline. For Velociraptor (Windows) collections, MFT SI/FN timestamps + USN journal records + any bodyfile/evtx data all merge into the same supertimeline. The MFT tree browser is available as a separate navigational view alongside.

## Goals

- **One command** — `rt-nav collection.tar.gz` extracts, parses everything, opens the workbench
- **Unified supertimeline** — ALL intrinsically timestamped data merges into one chronological view via a common `TimelineEvent` type. This includes bodyfile MAC times, MFT SI/FN timestamps, USN journal records, login/logout times, process start times, and registry LastWriteTime. Only real timestamps — no synthetic acquisition-time padding
- **Dashboard landing** — summary counts, supertimeline sparkline, auto-detected alerts
- **Artifact drill-in views** — Network, Processes, Logins, Packages, Configs, Hashes, Chkrootkit have dedicated views for browsing/filtering. Artifacts with intrinsic timestamps (process start times, login/logout times) also feed the supertimeline
- **MFT tree integration** — Velociraptor zips contain $MFT/$UsnJrnl; extract and feed into existing tree view as a navigational tool
- **Alert detection** — lightweight pattern-matching surfaces suspicious findings on the dashboard
- **Zero new binaries** — extends existing `rt-nav`
- **CTF-ready** — solve Hal Pomeranz's Linux Forensic Scenario entirely from the TUI

## Non-Goals

- DuckDB supertimeline (parsed data stays in memory for TUI; use `rt ingest` + `rt timeline` for SQL queries)
- Report export from TUI (use `rt report` separately)
- Scan/signature engine integration in this phase (future: wire `--scan` into investigation mode)
- evtx parsing in this phase (timeline event source type exists for future use)

---

## Architecture

### Unified Mode Detection

```
rt-nav <path>
  ├── is directory or $MFT file?  → existing MFT tree mode (unchanged)
  ├── is file recognized by rt-unpack?
  │   ├── Velociraptor zip → extract → supertimeline + MFT tree + snapshot views
  │   └── UAC tar.gz → extract → supertimeline + snapshot views (no MFT tree)
  └── neither → error with usage hint
```

In `main.rs`, probe the input path with `rt_unpack`. If a collection is detected:
1. Extract via the provider's `open()` method
2. Parse all categories into typed structs
3. Convert all temporal data into `Vec<TimelineEvent>` (the supertimeline)
4. For Velociraptor: also look for `$MFT` and `$UsnJrnl` in extracted files, build `FileTree` if found, and emit MFT/USN timeline events into the supertimeline
5. Run alert detection on all parsed data
6. Launch unified workbench TUI

### Supertimeline Data Model

All temporal data sources are normalized into a single event type:

```rust
/// A single event in the unified supertimeline.
pub struct TimelineEvent {
    /// UTC timestamp of the event.
    pub timestamp: i64,
    /// What kind of timestamp this is.
    pub timestamp_type: TimestampType,
    /// Source that produced this event.
    pub source: TimelineSource,
    /// File path or entity name.
    pub path: String,
    /// Human-readable description of the event.
    pub description: String,
    /// Optional extra metadata (size, permissions, reason, etc.)
    pub extra: String,
}

/// Classification of what the timestamp represents.
pub enum TimestampType {
    Modified,       // mtime / SI Modified
    Accessed,       // atime / SI Accessed
    Changed,        // ctime / SI Changed (MFT entry)
    Created,        // crtime / SI Created / FN Created
    FnModified,     // $FILE_NAME Modified
    FnAccessed,     // $FILE_NAME Accessed
    FnChanged,      // $FILE_NAME Changed
    UsnChange,      // USN journal change record
    LoginTime,      // User login
    LogoutTime,     // User logout
    ProcessStart,   // Process start time (from ps STARTED column)
    RegLastWrite,   // Registry key LastWriteTime (future: Velociraptor reg artifacts)
    EventLog,       // Future: evtx event
}

/// Which parser/artifact produced this event.
pub enum TimelineSource {
    Bodyfile,       // UAC bodyfile (Linux stat)
    MftSi,          // MFT $STANDARD_INFORMATION
    MftFn,          // MFT $FILE_NAME
    UsnJournal,     // $UsnJrnl:$J
    LoginHistory,   // last/wtmp
    ProcessList,    // ps output (intrinsic start times only)
    Registry,       // Future: registry key LastWriteTime
    EventLog,       // Future: evtx
}
```

### Conversion Pipeline

Each data source has a `into_timeline_events()` converter:

**Intrinsic timestamps only** (the artifact's own recorded time — no synthetic acquisition-time padding):
- **BodyfileEntry** → up to 4 events per entry (mtime, atime, ctime, crtime when non-zero)
- **MFT FileNode** → up to 8 events per node (4 SI timestamps + 4 FN timestamps when present)
- **UsnRecordV2** → 1 event per record (timestamp + reason flags as description)
- **LoginRecord** → up to 2 events per record (login_time, logout_time when parseable)
- **ProcessInfo** → 1 event per process with a parseable `start_time` (from ps STARTED column)

Artifacts without intrinsic timestamps (network connections from netstat/ss, processes without start_time) do NOT generate timeline events — they live only in their dedicated drill-in views. The timeline contains only events where we know *when* something actually happened, not when the collection tool ran.

All events are collected into a single `Vec<TimelineEvent>`, sorted by timestamp. The supertimeline view displays this unified list with color-coded source indicators.

### Investigation Data Model

```rust
/// All parsed data from a collection, held in memory.
pub struct InvestigationData {
    // Collection metadata
    pub metadata: CollectionMetadata,
    pub alerts: Vec<Alert>,

    // === SUPERTIMELINE (unified temporal data) ===
    /// All temporal events merged and sorted chronologically.
    pub timeline: Vec<TimelineEvent>,

    // === MFT TREE (navigational, present for Velociraptor) ===
    pub mft_tree: Option<FileTree>,
    pub anomaly_index: Option<AnomalyIndex>,

    // === ARTIFACT DATA (also shown in dedicated drill-in views) ===
    // These are kept for the per-category drill-in views.
    // Their timestamped data ALSO feeds into the supertimeline above.
    pub network: Vec<NetworkConnection>,
    pub processes: Vec<ProcessInfo>,
    pub crontabs: Vec<CrontabEntry>,
    pub logins: Vec<LoginRecord>,
    pub packages: Vec<InstalledPackage>,
    pub hashes: Vec<HashedExecutable>,
    pub chkrootkit: Vec<ChkrootkitFinding>,
    pub configs: Vec<ConfigFile>,
    pub system_info: Option<SystemInfo>,
    pub hardware: Option<HardwareInfo>,
    pub mounts: Vec<MountInfo>,
}
```

Note: Raw bodyfile entries and MFT/USN records are consumed during timeline conversion — their temporal data lives in `timeline`. Artifact data like network, processes, logins is kept both in its original form (for drill-in views) and converted into timeline events (for the supertimeline).

### View System

Views are dynamically available based on what data was parsed:

```rust
pub enum WorkbenchView {
    Dashboard,          // always present
    Timeline,           // only if !timeline.is_empty() (the supertimeline)
    MftTree,            // only if mft_tree.is_some()
    Network,            // only if !network.is_empty()
    Processes,          // only if !processes.is_empty()
    Logins,             // only if !logins.is_empty()
    Packages,           // only if !packages.is_empty()
    Configs,            // only if !configs.is_empty()
    Hashes,             // only if !hashes.is_empty()
    Chkrootkit,         // only if !chkrootkit.is_empty()
}
```

Tab/Shift+Tab cycles only through views that have data. Empty categories are hidden. The supertimeline is the primary investigation view — it appears right after Dashboard.

### TUI State Machine

```rust
pub struct WorkbenchApp {
    pub data: InvestigationData,
    pub available_views: Vec<WorkbenchView>,  // populated based on data
    pub current_view_idx: usize,              // index into available_views
    pub selected: usize,                      // cursor in current list
    pub scroll_offset: usize,                 // virtual scrolling
    pub show_detail: bool,                    // right panel toggle
    pub search_mode: bool,
    pub search_query: String,
    pub search_matches: Vec<usize>,
    pub sort_ascending: bool,

    // Supertimeline filter state
    pub timeline_source_filter: HashSet<TimelineSource>,  // which sources to show (all by default)

    // MFT tree mode delegates to existing App when in MftTree view
    pub mft_app: Option<App>,
}
```

When `current_view == MftTree`, keyboard input delegates to the existing `App::handle_key()` and rendering delegates to the existing `ui::draw()`. This means the MFT tree view is the exact same experience as standalone `rt-nav` — zero reimplementation.

### Keyboard Map

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Next/prev available view |
| `1`-`9` | Jump to view by number |
| `j`/`k` or Up/Down | Navigate list |
| `Enter` | Dashboard: drill into selected. List: toggle detail |
| `Esc` | Return to Dashboard |
| `/` | Enter search mode |
| `n`/`N` | Next/prev search match |
| `s` | Cycle sort (per-view) |
| `f` | Timeline view: cycle source filter (All → Bodyfile → MFT → USN → Login → All) |
| `q` | Quit |
| `?` | Help modal |

When in MftTree view, all keys pass through to existing `App::handle_key()` except `Tab`/`Shift+Tab` (view switching) and `Esc` (back to dashboard).

### View Layouts

**Dashboard (landing page):**
```
+-----------------------------------------------------------+
| RT Investigation: vbox-linux   OS: Linux   UAC 2026-03-24 |
| Views: [Dashboard] Timeline  Network  Process  Pkg  ...  |
+------------------------+----------------------------------+
| SUMMARY                | SUPERTIMELINE ACTIVITY           |
|   Supertimeline: 47832 |  ...:...:X:X:::::...:X:X:X:::.  |
|     Bodyfile:  47,200   |  19:00---19:30---20:00---20:30   |
|     USN:       0        |                                  |
|     Login:     12       | ALERTS (3 critical, 2 warning)   |
|   Network:  23 conns   | [!] Reverse shell (python3 pty)  |
|   Processes: 142       | [!] Hidden high-CPU process      |
|   Packages: 1,204      | [!] Suspicious /tmp executable   |
|   Configs:  89         | [w] ld.so.preload present        |
|   Hashes:   2,341      | [w] Non-RFC1918 connection       |
|   Rootkit:  3 flags    |                                  |
+------------------------+----------------------------------+
| [Tab] switch view  [Enter] drill in  [/] search  [q] quit|
+-----------------------------------------------------------+
```

**Supertimeline view:**
```
+-----------------------------------------------------------+
| RT Investigation: vbox-linux   View: [Timeline]            |
| Filter: All sources (47,832 events)  [f] cycle filter     |
+-------------------------------------+---------------------+
| Time         Source  Type  Path     | Detail              |
|>2026-03-24T19:01 BF  M  /tmp/rev  | Source: Bodyfile    |
| 2026-03-24T19:01 BF  A  /tmp/rev  | Type: Modified      |
| 2026-03-24T19:02 BF  M  /bin/nc   | Path: /tmp/rev.sh   |
| 2026-03-24T19:05 LI  In user:root | Size: 1,234         |
| 2026-03-24T19:08 BF  C  /etc/ld.. | Perms: 755          |
|                                     | Description: ...    |
+-------------------------------------+---------------------+
| [Tab] next  [f] filter  [s] sort  [/] search  47832 evts |
+-----------------------------------------------------------+
```

Source column codes: `BF` (bodyfile), `SI` (MFT $SI), `FN` (MFT $FN), `USN`, `LI` (login), `EL` (evtx/future).

**Drill-in view (e.g., Network):**
```
+-----------------------------------------------------------+
| RT Investigation: vbox-linux   View: [Network]             |
+-------------------------------------+---------------------+
| Proto  Local            Remote  St  | Detail              |
| >tcp   0.0.0.0:22      *       LIS | Protocol: tcp       |
|  tcp   10.0.0.5:4444   ESTAB   EST | Local: 0.0.0.0:22   |
|  tcp   192.168.4.35:22 ESTAB   EST | Remote: *            |
|  udp   0.0.0.0:68      *       -   | State: LISTEN        |
|                                     | PID: 834 (sshd)     |
+-------------------------------------+---------------------+
| [Tab] next  [Esc] dashboard  [/] search  23 connections   |
+-----------------------------------------------------------+
```

**MFT Tree view (Velociraptor only):**
When Tab navigates to MftTree, the entire frame delegates to the existing `ui::draw()` from rt-navigator, with an added header showing it's part of the workbench. Pressing Tab/Esc returns to the workbench views.

### Alert Detection

Lightweight pattern-matching on ingest — no external rules:

```rust
pub struct Alert {
    pub severity: AlertSeverity,
    pub category: String,
    pub message: String,
    pub detail: String,
}

pub enum AlertSeverity { Critical, Warning, Info }
```

Built-in checks:
- **Network:** connections to non-RFC1918 IPs, reverse shell patterns (`pty.spawn`, `nc -e`, `/dev/tcp`)
- **Process:** high CPU with no visible name, processes from /tmp /dev/shm /var/tmp
- **Chkrootkit:** any "INFECTED" findings
- **Configs:** `ld.so.preload` present/non-empty, suspicious crontab entries (wget/curl/base64)
- **Bodyfile:** recently created executables in temp dirs, SUID files outside standard paths (checked against raw bodyfile data before timeline conversion)

### Timeline Sparkline

Dashboard sparkline from supertimeline timestamp distribution:
```rust
fn build_sparkline(events: &[TimelineEvent], width: usize) -> Vec<u64>
```
Bucket all timestamps into `width` bins, return counts for `ratatui::widgets::Sparkline`.

---

## File Structure

New files in `crates/rt-navigator/src/`:

```
investigation/
  mod.rs           -- WorkbenchApp state machine, handle_key, view switching
  data.rs          -- InvestigationData struct, CollectionMetadata, load/parse pipeline
  timeline.rs      -- TimelineEvent, TimelineSource, TimestampType, conversion functions
  alerts.rs        -- Alert detection heuristics (pattern matching)
  dashboard.rs     -- Dashboard view rendering (summary + sparkline + alerts)
  detail.rs        -- Detail panel rendering (right side, per-view)
  views/
    mod.rs         -- ViewRenderer trait, dispatch to per-view renderers
    supertimeline.rs -- Unified supertimeline view (sortable, filterable by source)
    network.rs     -- Network connections table
    process.rs     -- Process list + crontabs
    logins.rs      -- Login records
    packages.rs    -- Installed packages
    configs.rs     -- System configs
    hashes.rs      -- Executable hashes
    chkrootkit.rs  -- Rootkit scan findings
```

Modified files:
- `main.rs` — add collection detection, `run_workbench_loop()`, MFT extraction from Velociraptor
- `Cargo.toml` — add rt-unpack, rt-parser-uac, rt-parser-velociraptor deps

Existing files (untouched):
- `app.rs` — reused as-is when MftTree view is active
- `ui.rs` — reused as-is when MftTree view is active
- `search.rs` — reused as-is
- `sources.rs` — reused for Velociraptor MFT source resolution

---

## Dependencies

New workspace deps for rt-navigator:
```toml
rt-unpack = { workspace = true }
rt-parser-uac = { workspace = true }
rt-parser-velociraptor = { workspace = true }
inventory = { workspace = true }
```

Also need `extern crate` for inventory registration (same pattern as rt-cli):
```rust
extern crate rt_parser_velociraptor;
extern crate rt_parser_uac;
```

---

## Collection-Specific Behavior

### UAC (.tar.gz)

- Extract via UacProvider
- Parse all categories
- Convert all intrinsically timestamped data → supertimeline events:
  - Bodyfile entries (mtime, atime, ctime, crtime)
  - Login records (login_time, logout_time)
  - Process start times (when parseable from ps STARTED column)
- No MFT tree (Linux system)
- Available views: Dashboard, Timeline, Network, Processes, Logins, Packages, Configs, Hashes, Chkrootkit

### Velociraptor (.zip)

- Extract via VelociraptorProvider
- Look for $MFT in extracted `uploads/ntfs/` → build FileTree + AnomalyIndex
- Convert MFT timestamps → supertimeline events (SI + FN timestamps per node)
- Look for $UsnJrnl → enrich MFT tree AND convert USN records → supertimeline events
- Parse evtx → future phase (TimelineSource::EventLog exists for this)
- Available views: Dashboard, Timeline, MftTree, (plus any artifact views if present)

The supertimeline for a Velociraptor collection will contain MFT SI/FN timestamps + USN records + any additional artifact timestamps (registry LastWriteTime in future phases), giving a comprehensive temporal picture of filesystem activity alongside the navigational MFT tree view.

---

## Testing Strategy

- Unit tests for `TimelineEvent` conversion from each source (bodyfile, MFT, USN, login, process start times, acquisition-time observations)
- Unit tests for supertimeline sorting and source filtering
- Unit tests for alert detection patterns
- Unit tests for sparkline bucketing
- Unit tests for InvestigationData loading from synthetic dir
- Unit tests for view availability based on data
- Integration test: load real UAC test data, verify supertimeline event count and alerts
- Visual testing: manual verification of TUI layouts
