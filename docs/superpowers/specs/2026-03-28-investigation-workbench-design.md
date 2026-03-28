# Investigation Workbench TUI: Design Spec

## Overview

Extend `rt-navigator` (`rt-nav`) into a **unified forensic workbench**. When the user passes a collection archive (Velociraptor `.zip`, UAC `.tar.gz`), `rt-nav` extracts it, parses ALL artifacts into an integrated view: the existing MFT tree browser for NTFS navigation + new tabbed views for network, processes, logins, timeline, configs, etc. One tool, one command, full investigation.

For UAC (Linux) collections without an MFT, the MFT tree tab is absent and the dashboard + artifact views carry the investigation. For Velociraptor (Windows) collections, you get the MFT tree AND all the parsed evtx/registry/network artifacts unified together.

## Goals

- **One command** — `rt-nav collection.tar.gz` extracts, parses everything, opens the workbench
- **Unified workbench** — MFT tree (when available) + dashboard + artifact drill-in views, all Tab-switchable
- **Dashboard landing** — summary counts, timeline sparkline, auto-detected alerts
- **Interactive drill-in views** — Timeline, Network, Processes, Logins, Packages, Configs, Hashes, Chkrootkit
- **MFT tree integration** — Velociraptor zips contain $MFT/$UsnJrnl; extract and feed into existing tree view
- **Alert detection** — lightweight pattern-matching surfaces suspicious findings on the dashboard
- **Zero new binaries** — extends existing `rt-nav`
- **CTF-ready** — solve Hal Pomeranz's Linux Forensic Scenario entirely from the TUI

## Non-Goals

- DuckDB supertimeline (parsed data stays in memory for TUI; use `rt ingest` + `rt timeline` for SQL queries)
- Report export from TUI (use `rt report` separately)
- Scan/signature engine integration in this phase (future: wire `--scan` into investigation mode)

---

## Architecture

### Unified Mode Detection

```
rt-nav <path>
  ├── is directory or $MFT file?  → existing MFT tree mode (unchanged)
  ├── is file recognized by rt-unpack?
  │   ├── Velociraptor zip → extract → MFT tree + investigation views
  │   └── UAC tar.gz → extract → investigation views only (no MFT)
  └── neither → error with usage hint
```

In `main.rs`, probe the input path with `rt_unpack`. If a collection is detected:
1. Extract via the provider's `open()` method
2. Parse UAC-specific categories (bodyfile, network, process, etc.) into `InvestigationData`
3. For Velociraptor: also look for `$MFT` and `$UsnJrnl` in the extracted files, build `FileTree` if found
4. Launch unified workbench TUI

### Data Model

```rust
/// All parsed data from a collection, held in memory.
pub struct InvestigationData {
    // Collection metadata
    pub metadata: CollectionMetadata,
    pub alerts: Vec<Alert>,

    // MFT tree (present for Velociraptor, absent for UAC)
    pub mft_tree: Option<FileTree>,
    pub anomaly_index: Option<AnomalyIndex>,

    // UAC-parsed categories (present for UAC, partially for Velociraptor)
    pub bodyfile: Vec<BodyfileEntry>,
    pub network: Vec<NetworkConnection>,
    pub processes: Vec<ProcessInfo>,
    pub crontabs: Vec<CrontabEntry>,
    pub logins: Vec<LoginRecord>,
    pub system_info: Option<SystemInfo>,
    pub packages: Vec<InstalledPackage>,
    pub hashes: Vec<HashedExecutable>,
    pub chkrootkit: Vec<ChkrootkitFinding>,
    pub configs: Vec<ConfigFile>,
    pub hardware: Option<HardwareInfo>,
    pub mounts: Vec<MountInfo>,
}
```

### View System

Views are dynamically available based on what data was parsed:

```rust
pub enum WorkbenchView {
    Dashboard,          // always present
    MftTree,            // only if mft_tree.is_some()
    Timeline,           // only if !bodyfile.is_empty()
    Network,            // only if !network.is_empty()
    Processes,          // only if !processes.is_empty()
    Logins,             // only if !logins.is_empty()
    Packages,           // only if !packages.is_empty()
    Configs,            // only if !configs.is_empty()
    Hashes,             // only if !hashes.is_empty()
    Chkrootkit,         // only if !chkrootkit.is_empty()
}
```

Tab/Shift+Tab cycles only through views that have data. Empty categories are hidden.

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
| `q` | Quit |
| `?` | Help modal |

When in MftTree view, all keys pass through to existing `App::handle_key()` except `Tab`/`Shift+Tab` (view switching) and `Esc` (back to dashboard).

### View Layouts

**Dashboard (landing page):**
```
+-----------------------------------------------------------+
| RT Investigation: vbox-linux   OS: Linux   UAC 2026-03-24 |
| Views: [Dashboard] Timeline  Network  Process  Login  ... |
+------------------------+----------------------------------+
| SUMMARY                | TIMELINE ACTIVITY                |
|   Timeline: 47,832     |  ...:...:X:X:::::...:X:X:X:::.  |
|   Network:  23 conns   |  19:00---19:30---20:00---20:30   |
|   Processes: 142       |                                  |
|   Logins:   8          | ALERTS (3 critical, 2 warning)   |
|   Packages: 1,204      | [!] Reverse shell (python3 pty)  |
|   Configs:  89         | [!] Hidden high-CPU process      |
|   Hashes:   2,341      | [!] Suspicious /tmp executable   |
|   Rootkit:  3 flags    | [w] ld.so.preload present        |
|                        | [w] Non-RFC1918 connection       |
+------------------------+----------------------------------+
| [Tab] switch view  [Enter] drill in  [/] search  [q] quit|
+-----------------------------------------------------------+
```

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
- **Bodyfile:** recently created executables in temp dirs, SUID files outside standard paths

### Timeline Sparkline

Dashboard sparkline from bodyfile mtime distribution:
```rust
fn build_sparkline(entries: &[BodyfileEntry], width: usize) -> Vec<u64>
```
Bucket all mtimes into `width` bins, return counts for `ratatui::widgets::Sparkline`.

---

## File Structure

New files in `crates/rt-navigator/src/`:

```
investigation/
  mod.rs           -- WorkbenchApp state machine, handle_key, view switching
  data.rs          -- InvestigationData struct, load from manifest + parse categories
  alerts.rs        -- Alert detection heuristics (pattern matching)
  dashboard.rs     -- Dashboard view rendering (summary + sparkline + alerts)
  detail.rs        -- Detail panel rendering (right side, per-view)
  views/
    mod.rs         -- View trait, dispatch to per-view renderers
    timeline.rs    -- Bodyfile timeline view (sortable by time/path/size)
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
- Parse all categories → InvestigationData
- No MFT tree (Linux system)
- Dashboard + all UAC artifact views
- Available views: Dashboard, Timeline, Network, Processes, Logins, Packages, Configs, Hashes, Chkrootkit

### Velociraptor (.zip)

- Extract via VelociraptorProvider
- Look for $MFT in extracted `uploads/ntfs/` → build FileTree + AnomalyIndex
- Look for $UsnJrnl → enrich tree
- Parse evtx → future (not in this phase)
- MFT tree view available + Dashboard shows file count from MFT
- Available views: Dashboard, MftTree, (plus any UAC-style artifacts if present)

---

## Testing Strategy

- Unit tests for alert detection patterns
- Unit tests for sparkline bucketing
- Unit tests for InvestigationData loading from synthetic dir
- Unit tests for view availability based on data
- Integration test: load real UAC test data, verify all categories and alerts
- Visual testing: manual verification of TUI layouts
