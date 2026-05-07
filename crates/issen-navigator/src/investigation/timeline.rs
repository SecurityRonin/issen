//! Supertimeline event types and conversion functions.
//!
//! Converts heterogeneous forensic artifacts (bodyfile, MFT, USN journal,
//! login history, process list) into a unified `TimelineEvent` stream that
//! can be sorted, filtered, and displayed in the Investigation Workbench.

use chrono::{DateTime, Utc};
use issen_mft_tree::node::NtfsTimestamps;
use issen_mft_tree::tree::FileTree;
use issen_parser_uac::parsers::bodyfile::BodyfileEntry;
use issen_parser_uac::parsers::process::ProcessInfo;
use issen_parser_uac::parsers::system::LoginRecord;
use usnjrnl_forensic::usn::UsnRecord;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A single event on the supertimeline.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    /// Unix epoch seconds.
    pub timestamp: i64,
    /// What this timestamp represents (modified, accessed, etc.).
    pub timestamp_type: TimestampType,
    /// Which artifact source produced this event.
    pub source: TimelineSource,
    /// File path or entity name.
    pub path: String,
    /// Human-readable description of the event.
    pub description: String,
    /// Extra context (reason flags, user, etc.).
    pub extra: String,
}

/// The semantic meaning of a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampType {
    Modified,
    Accessed,
    Changed,
    Created,
    FnModified,
    FnAccessed,
    FnChanged,
    FnCreated,
    UsnChange,
    LoginTime,
    LogoutTime,
    ProcessStart,
    RegLastWrite,
    EventLog,
}

impl TimestampType {
    /// Short human-readable label for display in the timeline.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Modified => "M",
            Self::Accessed => "A",
            Self::Changed => "C",
            Self::Created => "B",
            Self::FnModified => "FN-M",
            Self::FnAccessed => "FN-A",
            Self::FnChanged => "FN-C",
            Self::FnCreated => "FN-B",
            Self::UsnChange => "USN",
            Self::LoginTime => "LOGIN",
            Self::LogoutTime => "LOGOUT",
            Self::ProcessStart => "PROC",
            Self::RegLastWrite => "REG",
            Self::EventLog => "EVT",
        }
    }
}

/// The artifact source that produced a timeline event.
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
    /// Short label for source column.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Bodyfile => "bodyfile",
            Self::MftSi => "MFT-SI",
            Self::MftFn => "MFT-FN",
            Self::UsnJournal => "USN",
            Self::LoginHistory => "login",
            Self::ProcessList => "ps",
            Self::Registry => "reg",
            Self::EventLog => "evtx",
        }
    }

    /// All defined source variants (useful for filter UIs).
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Bodyfile,
            Self::MftSi,
            Self::MftFn,
            Self::UsnJournal,
            Self::LoginHistory,
            Self::ProcessList,
            Self::Registry,
            Self::EventLog,
        ]
    }
}

// ---------------------------------------------------------------------------
// Conversion functions
// ---------------------------------------------------------------------------

/// Convert bodyfile entries into timeline events.
///
/// Produces up to 4 events per entry (mtime, atime, ctime, crtime) — only
/// for timestamps that are `Some` and non-zero.
#[must_use]
pub fn bodyfile_to_events(entries: &[BodyfileEntry]) -> Vec<TimelineEvent> {
    let mut events = Vec::with_capacity(entries.len() * 3);

    for entry in entries {
        if let Some(ts) = entry.mtime {
            events.push(TimelineEvent {
                timestamp: ts,
                timestamp_type: TimestampType::Modified,
                source: TimelineSource::Bodyfile,
                path: entry.path.clone(),
                description: "modified".into(),
                extra: String::new(),
            });
        }
        if let Some(ts) = entry.atime {
            events.push(TimelineEvent {
                timestamp: ts,
                timestamp_type: TimestampType::Accessed,
                source: TimelineSource::Bodyfile,
                path: entry.path.clone(),
                description: "accessed".into(),
                extra: String::new(),
            });
        }
        if let Some(ts) = entry.ctime {
            events.push(TimelineEvent {
                timestamp: ts,
                timestamp_type: TimestampType::Changed,
                source: TimelineSource::Bodyfile,
                path: entry.path.clone(),
                description: "changed".into(),
                extra: String::new(),
            });
        }
        if let Some(ts) = entry.crtime {
            events.push(TimelineEvent {
                timestamp: ts,
                timestamp_type: TimestampType::Created,
                source: TimelineSource::Bodyfile,
                path: entry.path.clone(),
                description: "created".into(),
                extra: String::new(),
            });
        }
    }

    events
}

/// Convert login records into timeline events.
///
/// Produces up to 2 events per record (login + logout) when the timestamp
/// strings can be parsed. `acquisition_time` is the Unix epoch of collection,
/// used as a fallback year hint for `last` output that omits the year.
#[must_use]
pub fn logins_to_events(records: &[LoginRecord], acquisition_time: i64) -> Vec<TimelineEvent> {
    let fallback_year = DateTime::from_timestamp(acquisition_time, 0).map_or(2024, |dt| {
        dt.format("%Y").to_string().parse().unwrap_or(2024)
    });

    let mut events = Vec::with_capacity(records.len() * 2);

    for record in records {
        if let Some(ref login_str) = record.login_time {
            if let Ok(ts) = parse_login_time(login_str, fallback_year) {
                events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: TimestampType::LoginTime,
                    source: TimelineSource::LoginHistory,
                    path: record.user.clone(),
                    description: format!("login {} from {}", record.terminal, record.source),
                    extra: String::new(),
                });
            }
        }
        if let Some(ref logout_str) = record.logout_time {
            if let Ok(ts) = parse_login_time(logout_str, fallback_year) {
                events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: TimestampType::LogoutTime,
                    source: TimelineSource::LoginHistory,
                    path: record.user.clone(),
                    description: format!("logout {} from {}", record.terminal, record.source),
                    extra: String::new(),
                });
            }
        }
    }

    events
}

/// Convert process list entries into timeline events.
///
/// Only processes with a parseable `staissen_time` produce events.
#[must_use]
pub fn processes_to_events(procs: &[ProcessInfo]) -> Vec<TimelineEvent> {
    let mut events = Vec::with_capacity(procs.len());

    for proc in procs {
        if let Some(ref staissen_str) = proc.staissen_time {
            if let Ok(ts) = parse_ps_staissen_time(staissen_str) {
                events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: TimestampType::ProcessStart,
                    source: TimelineSource::ProcessList,
                    path: proc.command.clone(),
                    description: format!("pid={} user={}", proc.pid, proc.user),
                    extra: String::new(),
                });
            }
        }
    }

    events
}

/// Convert a reconstructed MFT file tree into timeline events.
///
/// Produces up to 8 events per node: 4 from `$STANDARD_INFORMATION` and
/// 4 from `$FILE_NAME` (when present).
#[must_use]
pub fn mft_to_events(tree: &FileTree) -> Vec<TimelineEvent> {
    let count = tree.node_count();
    let mut events = Vec::with_capacity(count * 4);

    for idx in 0..count {
        let node = tree.node(idx);
        let path = tree.cached_path(idx).to_string();

        push_ntfs_timestamps(
            &mut events,
            &node.si_timestamps,
            TimelineSource::MftSi,
            &path,
            false,
        );

        if let Some(ref fn_ts) = node.fn_timestamps {
            push_ntfs_timestamps(&mut events, fn_ts, TimelineSource::MftFn, &path, true);
        }
    }

    events
}

/// Push 4 timeline events from an `NtfsTimestamps` set.
fn push_ntfs_timestamps(
    events: &mut Vec<TimelineEvent>,
    ts: &NtfsTimestamps,
    source: TimelineSource,
    path: &str,
    is_fn: bool,
) {
    let prefix = if is_fn { "FN " } else { "" };

    let pairs: [(TimestampType, &DateTime<Utc>, &str); 4] = if is_fn {
        [
            (TimestampType::FnModified, &ts.modified, "modified"),
            (TimestampType::FnAccessed, &ts.accessed, "accessed"),
            (
                TimestampType::FnChanged,
                &ts.entry_modified,
                "entry modified",
            ),
            (TimestampType::FnCreated, &ts.created, "created"),
        ]
    } else {
        [
            (TimestampType::Modified, &ts.modified, "modified"),
            (TimestampType::Accessed, &ts.accessed, "accessed"),
            (TimestampType::Changed, &ts.entry_modified, "entry modified"),
            (TimestampType::Created, &ts.created, "created"),
        ]
    };

    for (tt, dt, desc) in pairs {
        events.push(TimelineEvent {
            timestamp: dt.timestamp(),
            timestamp_type: tt,
            source,
            path: path.to_string(),
            description: format!("{prefix}{desc}"),
            extra: String::new(),
        });
    }
}

/// Convert USN journal records into timeline events.
///
/// Each record produces one event. The `DateTime<Utc>` timestamp is converted
/// directly to Unix epoch seconds.
#[must_use]
pub fn usn_to_events(records: &[UsnRecord]) -> Vec<TimelineEvent> {
    let mut events = Vec::with_capacity(records.len());

    for record in records {
        let unix_ts = record.timestamp.timestamp();
        let reason_desc = record.reason.to_string();

        events.push(TimelineEvent {
            timestamp: unix_ts,
            timestamp_type: TimestampType::UsnChange,
            source: TimelineSource::UsnJournal,
            path: record.filename.clone(),
            description: reason_desc,
            extra: format!("0x{:08X}", record.reason.bits()),
        });
    }

    events
}

// ---------------------------------------------------------------------------
// Sparkline builder
// ---------------------------------------------------------------------------

/// Bucket timeline events into `width` equal-time bins for sparkline display.
///
/// Returns a vector of length `width` where each element is the count of
/// events in that time bucket. Returns all zeros if `events` is empty.
#[must_use]
pub fn build_sparkline(events: &[TimelineEvent], width: usize) -> Vec<u64> {
    if events.is_empty() || width == 0 {
        return vec![0; width];
    }

    let (mut min_ts, mut max_ts) = (i64::MAX, i64::MIN);
    for ev in events {
        if ev.timestamp < min_ts {
            min_ts = ev.timestamp;
        }
        if ev.timestamp > max_ts {
            max_ts = ev.timestamp;
        }
    }

    // If all timestamps are identical, put everything in bin 0.
    if min_ts == max_ts {
        let mut bins = vec![0u64; width];
        bins[0] = events.len() as u64;
        return bins;
    }

    let range = max_ts - min_ts;
    let mut bins = vec![0u64; width];

    for ev in events {
        let offset = ev.timestamp - min_ts;
        // Map to [0, width-1]. The last timestamp lands in the last bin.
        // offset and range are guaranteed non-negative here (min_ts <= ev.timestamp <= max_ts).
        #[allow(clippy::cast_sign_loss)]
        let bucket = ((offset as u128 * (width as u128 - 1)) / range as u128) as usize;
        let bucket = bucket.min(width - 1);
        bins[bucket] += 1;
    }

    bins
}

// ---------------------------------------------------------------------------
// Timestamp parsing helpers
// ---------------------------------------------------------------------------

/// Best-effort parse of `last` command timestamp strings.
///
/// Handles formats like:
/// - `"Mon Jan  6 12:34"` (with fallback year)
/// - `"Mon Jan  6 12:34:56 2024"` (explicit year)
///
/// # Errors
///
/// Returns `Err(())` if the string cannot be parsed.
pub fn parse_login_time(s: &str, fallback_year: i64) -> Result<i64, ()> {
    let s = s.trim();
    if s.is_empty() || s == "still" || s.starts_with("still") || s == "gone" {
        return Err(());
    }

    // Try full datetime with year: "Mon Jan  6 12:34:56 2024"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%a %b %e %H:%M:%S %Y") {
        return Ok(dt.and_utc().timestamp());
    }

    // Try without seconds: "Mon Jan  6 12:34 2024"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%a %b %e %H:%M %Y") {
        return Ok(dt.and_utc().timestamp());
    }

    // Try without year: "Mon Jan  6 12:34" — append fallback year
    let with_year = format!("{s} {fallback_year}");
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&with_year, "%a %b %e %H:%M %Y") {
        return Ok(dt.and_utc().timestamp());
    }

    // Try without year with seconds: "Mon Jan  6 12:34:56"
    let with_year = format!("{s} {fallback_year}");
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&with_year, "%a %b %e %H:%M:%S %Y") {
        return Ok(dt.and_utc().timestamp());
    }

    Err(())
}

/// Best-effort parse of ps `STARTED` column timestamps.
///
/// Handles formats like:
/// - `"12:34"` or `"12:34:56"` — time-only (no date, returns `Err`)
/// - `"Mar24"` — abbreviated month + day (no year, no time — returns `Err`)
/// - `"Jan06"` — same
///
/// Since ps STARTED timestamps lack full date+time, most are not usable
/// for the timeline and this function is intentionally conservative.
///
/// # Errors
///
/// Returns `Err(())` if the string cannot be parsed into a full timestamp.
pub fn parse_ps_staissen_time(s: &str) -> Result<i64, ()> {
    let s = s.trim();
    if s.is_empty() {
        return Err(());
    }

    // ps typically shows "HH:MM" for today's processes or "MonDD" for older.
    // Neither carries enough info for a precise timestamp, so we reject them.
    // Only accept ISO-like formats that might appear in some ps implementations.
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Ok(dt.and_utc().timestamp());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(dt.and_utc().timestamp());
    }

    Err(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bodyfile_entry(
        path: &str,
        mtime: Option<i64>,
        atime: Option<i64>,
        ctime: Option<i64>,
        crtime: Option<i64>,
    ) -> BodyfileEntry {
        BodyfileEntry {
            md5: String::new(),
            path: path.to_string(),
            inode: 0,
            mode: String::new(),
            uid: 0,
            gid: 0,
            size: 0,
            atime,
            mtime,
            ctime,
            crtime,
        }
    }

    #[test]
    fn bodyfile_basic_three_events() {
        let entry = make_bodyfile_entry(
            "/etc/passwd",
            Some(1_700_000_000),
            Some(1_700_001_000),
            Some(1_700_002_000),
            None, // crtime=None → skipped
        );
        let events = bodyfile_to_events(&[entry]);
        asseissen_eq!(events.len(), 3);
        asseissen_eq!(events[0].timestamp_type, TimestampType::Modified);
        asseissen_eq!(events[1].timestamp_type, TimestampType::Accessed);
        asseissen_eq!(events[2].timestamp_type, TimestampType::Changed);
        asseissen_eq!(events[0].path, "/etc/passwd");
    }

    #[test]
    fn bodyfile_empty_input() {
        let events = bodyfile_to_events(&[]);
        assert!(events.is_empty());
    }

    #[test]
    fn bodyfile_all_none_timestamps() {
        let entry = make_bodyfile_entry("/tmp/none", None, None, None, None);
        let events = bodyfile_to_events(&[entry]);
        assert!(events.is_empty());
    }

    #[test]
    fn processes_no_staissen_time_empty_result() {
        let proc = ProcessInfo {
            pid: 1,
            ppid: 0,
            user: "root".into(),
            command: "/sbin/init".into(),
            cpu_pct: None,
            mem_pct: None,
            staissen_time: None,
        };
        let events = processes_to_events(&[proc]);
        assert!(events.is_empty());
    }

    #[test]
    fn processes_unparseable_staissen_time_empty_result() {
        let proc = ProcessInfo {
            pid: 42,
            ppid: 1,
            user: "user".into(),
            command: "bash".into(),
            cpu_pct: None,
            mem_pct: None,
            staissen_time: Some("Mar24".into()),
        };
        let events = processes_to_events(&[proc]);
        // "Mar24" is not a full timestamp, so should be empty.
        assert!(events.is_empty());
    }

    #[test]
    fn sparkline_empty_events() {
        let bins = build_sparkline(&[], 10);
        asseissen_eq!(bins.len(), 10);
        assert!(bins.iter().all(|&b| b == 0));
    }

    #[test]
    fn sparkline_single_event() {
        let events = vec![TimelineEvent {
            timestamp: 1_000_000,
            timestamp_type: TimestampType::Modified,
            source: TimelineSource::Bodyfile,
            path: String::new(),
            description: String::new(),
            extra: String::new(),
        }];
        let bins = build_sparkline(&events, 5);
        asseissen_eq!(bins.len(), 5);
        // Single event → all in bin 0
        asseissen_eq!(bins[0], 1);
        asseissen_eq!(bins.iter().sum::<u64>(), 1);
    }

    #[test]
    fn sparkline_distribution() {
        // Create 100 events spread from timestamp 0..99
        let events: Vec<TimelineEvent> = (0..100)
            .map(|i| TimelineEvent {
                timestamp: i,
                timestamp_type: TimestampType::Modified,
                source: TimelineSource::Bodyfile,
                path: String::new(),
                description: String::new(),
                extra: String::new(),
            })
            .collect();

        let bins = build_sparkline(&events, 10);
        asseissen_eq!(bins.len(), 10);
        // All 100 events should be distributed across the 10 bins
        asseissen_eq!(bins.iter().sum::<u64>(), 100);
        // Each bin should have some events (roughly 10 each)
        for bin in &bins {
            assert!(*bin > 0, "no bin should be empty for uniform data");
        }
    }

    #[test]
    fn timeline_source_all_has_eight_variants() {
        asseissen_eq!(TimelineSource::all().len(), 8);
    }

    #[test]
    fn usn_to_events_single_record() {
        use usnjrnl_forensic::usn::{FileAttributes, UsnReason};

        let record = UsnRecord {
            mft_entry: 12345,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn: 0,
            timestamp: chrono::DateTime::from_timestamp(1_705_276_800, 0).unwrap(),
            reason: UsnReason::FILE_CREATE,
            filename: "test.txt".into(),
            file_attributes: FileAttributes::empty(),
            source_info: 0,
            security_id: 0,
            major_version: 2,
        };

        let events = usn_to_events(&[record]);
        asseissen_eq!(events.len(), 1);
        asseissen_eq!(events[0].timestamp, 1_705_276_800);
        asseissen_eq!(events[0].timestamp_type, TimestampType::UsnChange);
        asseissen_eq!(events[0].source, TimelineSource::UsnJournal);
        asseissen_eq!(events[0].path, "test.txt");
    }

    #[test]
    fn timestamp_type_labels_are_nonempty() {
        let types = [
            TimestampType::Modified,
            TimestampType::Accessed,
            TimestampType::Changed,
            TimestampType::Created,
            TimestampType::FnModified,
            TimestampType::FnAccessed,
            TimestampType::FnChanged,
            TimestampType::FnCreated,
            TimestampType::UsnChange,
            TimestampType::LoginTime,
            TimestampType::LogoutTime,
            TimestampType::ProcessStart,
            TimestampType::RegLastWrite,
            TimestampType::EventLog,
        ];
        for tt in types {
            assert!(!tt.label().is_empty());
        }
    }

    #[test]
    fn source_labels_are_nonempty() {
        for src in TimelineSource::all() {
            assert!(!src.label().is_empty());
        }
    }
}
