//! Parser for macOS FSEvents text log exports.
//!
//! Expected line format:
//! `YYYY-MM-DD HH:MM:SS  path  flags...`

use std::io::{BufRead, BufReader};
use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Parse an FSEvents text export and return timeline events.
///
/// # Errors
/// Returns `anyhow::Error` only on I/O failures. Missing or empty files
/// return `Ok(vec![])`. Malformed lines are silently skipped.
pub fn parse_fsevents_log(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    if !path.exists() {
        return Ok(vec![]);
    }

    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(ev) = parse_fsevents_line(line, path, source_id) {
            events.push(ev);
        }
    }

    Ok(events)
}

/// Parse a single FSEvents log line.
///
/// Format: `YYYY-MM-DD HH:MM:SS  path  flags...`
/// Fields are separated by two or more spaces.
fn parse_fsevents_line(line: &str, artifact_path: &Path, source_id: &str) -> Option<TimelineEvent> {
    // Split on runs of 2+ spaces to get fields
    let fields: Vec<&str> = split_double_space(line);

    if fields.len() < 3 {
        return None;
    }

    let ts_str = fields[0].trim();
    let target_path = fields[1].trim();
    let flags_str = fields[2..].join(" ");

    // Validate timestamp looks like "YYYY-MM-DD HH:MM:SS"
    if ts_str.len() < 19 {
        return None;
    }

    let timestamp_ns = parse_fsevents_timestamp_ns(ts_str);

    // Determine event type based on flags (priority: Executable > Created > Modified)
    let event_type = if flags_str.contains("Executable") {
        EventType::ProcessExec
    } else if flags_str.contains("Created") {
        EventType::FileCreate
    } else {
        EventType::FileModify
    };

    let mut metadata = std::collections::HashMap::new();
    metadata.insert(
        "path".to_string(),
        serde_json::Value::String(target_path.to_string()),
    );
    metadata.insert(
        "flags".to_string(),
        serde_json::Value::String(flags_str.clone()),
    );

    let description = format!("FSEvents: {target_path} [{flags_str}]");

    let mut ev = TimelineEvent::new(
        timestamp_ns,
        ts_str.to_string(),
        event_type,
        ArtifactType::SystemInfo,
        artifact_path.to_string_lossy().into_owned(),
        description,
        source_id.to_string(),
    );
    ev.metadata = metadata;
    Some(ev)
}

/// Split a string on runs of 2 or more spaces, returning non-empty tokens.
fn split_double_space(s: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut in_sep = false;
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b' ' && i + 1 < bytes.len() && bytes[i + 1] == b' ' {
            // Two or more spaces — end of current token
            if !in_sep && i > start {
                result.push(&s[start..i]);
            }
            in_sep = true;
            i += 1;
        } else if in_sep && bytes[i] != b' ' {
            start = i;
            in_sep = false;
        }
        i += 1;
    }
    // Last token
    if !in_sep && start < bytes.len() {
        result.push(&s[start..]);
    }
    result
}

/// Parse `YYYY-MM-DD HH:MM:SS` (no timezone, treat as UTC) into nanoseconds.
fn parse_fsevents_timestamp_ns(s: &str) -> i64 {
    if s.len() < 19 {
        return 0;
    }
    let year: i64 = s[0..4].parse().unwrap_or(0);
    let month: i64 = s[5..7].parse().unwrap_or(0);
    let day: i64 = s[8..10].parse().unwrap_or(0);
    let hour: i64 = s[11..13].parse().unwrap_or(0);
    let min: i64 = s[14..16].parse().unwrap_or(0);
    let sec: i64 = s[17..19].parse().unwrap_or(0);

    if year == 0 || month == 0 || day == 0 {
        return 0;
    }

    let unix_days = days_since_unix_epoch(year, month, day);
    (unix_days * 86_400 + hour * 3_600 + min * 60 + sec) * 1_000_000_000
}

fn days_since_unix_epoch(year: i64, month: i64, day: i64) -> i64 {
    julian_day_number(year, month, day) - julian_day_number(1970, 1, 1)
}

fn julian_day_number(year: i64, month: i64, day: i64) -> i64 {
    let a = (14 - month) / 12;
    let y = year + 4800 - a;
    let m = month + 12 * a - 3;
    day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32_045
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    // ── Test 7: empty file → Ok(vec![]) ──────────────────────────────────────

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events =
            parse_fsevents_log(tmp.path(), "test-source").expect("must not Err on empty file");
        assert!(events.is_empty(), "expected empty vec for zero-byte file");
    }

    // ── Test 8: "Created" flag → EventType::FileCreate ───────────────────────

    #[test]
    fn created_flag_yields_file_create() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:25:00  /Users/alice/Documents/report.pdf  Created Modified"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_fsevents_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            issen_core::timeline::event::EventType::FileCreate,
            "Created flag should map to FileCreate"
        );
    }

    // ── Test 9: "Executable" flag → EventType::ProcessExec ───────────────────

    #[test]
    fn executable_flag_yields_process_start() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:25:01  /private/tmp/malware.sh  Created Executable"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_fsevents_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            issen_core::timeline::event::EventType::ProcessExec,
            "Executable flag should map to ProcessExec"
        );
    }

    // ── Test 10: malformed line → no panic ───────────────────────────────────

    #[test]
    fn malformed_line_skipped_without_panic() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "not-a-valid-fsevents-line").expect("write");
        writeln!(tmp, "").expect("write");
        tmp.flush().expect("flush");

        let result = parse_fsevents_log(tmp.path(), "test-source");
        assert!(result.is_ok(), "malformed lines must not cause Err");
    }
}
