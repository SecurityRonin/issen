//! Parser for bash_history files.

use std::path::Path;

use chrono::Utc;
use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

fn ts_display(timestamp_ns: i64) -> String {
    if timestamp_ns != 0 {
        let secs = timestamp_ns / 1_000_000_000;
        #[allow(clippy::cast_sign_loss)]
        let nanos = (timestamp_ns % 1_000_000_000) as u32;
        chrono::DateTime::from_timestamp(secs, nanos).map_or_else(
            || timestamp_ns.to_string(),
            |dt: chrono::DateTime<Utc>| dt.to_rfc3339(),
        )
    } else {
        "1970-01-01T00:00:00Z".to_string()
    }
}

fn make_event(
    timestamp_ns: i64,
    artifact_path: &str,
    command: &str,
    source_id: &str,
) -> TimelineEvent {
    TimelineEvent::new(
        timestamp_ns,
        ts_display(timestamp_ns),
        EventType::ProcessExec,
        ArtifactType::LoginHistory,
        artifact_path.to_string(),
        format!("Shell command: {command}"),
        source_id.to_string(),
    )
    .with_metadata("command", serde_json::json!(command))
}

/// Parse a bash_history file at `path` and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unexpected I/O failures. Missing files are
/// silently skipped (returns `Ok(vec![])`).
pub fn parse_bash_history(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };

    let path_str = path.to_string_lossy().into_owned();
    let mut events = Vec::new();
    let mut current_ts: i64 = 0;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Timestamp line: "#<unix_ts>"
        if let Some(rest) = line.strip_prefix('#') {
            if let Ok(unix_ts) = rest.trim().parse::<i64>() {
                current_ts = unix_ts * 1_000_000_000;
                continue;
            }
        }
        // Command line
        let ev = make_event(current_ts, &path_str, line, source_id);
        events.push(ev);
        // Reset so subsequent commands without a new timestamp use 0
        current_ts = 0;
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    use issen_core::timeline::event::EventType;

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_bash_history(tmp.path(), "test-src").expect("parse_bash_history");
        assert!(events.is_empty(), "empty file should produce no events");
    }

    #[test]
    fn missing_file_returns_empty_vec() {
        let events = parse_bash_history(Path::new("/nonexistent/.bash_history"), "test-src")
            .expect("missing file should return Ok(vec![])");
        assert!(events.is_empty());
    }

    #[test]
    fn timestamp_plus_command_emits_correct_ns() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Unix timestamp 1713171781 = 2024-04-15 07:03:01 UTC
        writeln!(tmp, "#1713171781").expect("write");
        writeln!(tmp, "ls -la").expect("write");
        tmp.flush().expect("flush");

        let events = parse_bash_history(tmp.path(), "test-src").expect("parse");
        asseissen_eq!(events.len(), 1, "expected 1 event");

        let ev = &events[0];
        // 1713171781 * 1_000_000_000
        asseissen_eq!(
            ev.timestamp_ns,
            1_713_171_781_i64 * 1_000_000_000,
            "timestamp_ns should match unix ts * 1e9"
        );
        asseissen_eq!(ev.event_type, EventType::ProcessExec);
        asseissen_eq!(
            ev.metadata.get("command").and_then(|v| v.as_str()),
            Some("ls -la"),
        );
    }

    #[test]
    fn command_without_timestamp_emits_event_with_zero_ns() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "whoami").expect("write");
        tmp.flush().expect("flush");

        let events = parse_bash_history(tmp.path(), "test-src").expect("parse");
        asseissen_eq!(events.len(), 1, "expected 1 event even without timestamp");

        let ev = &events[0];
        asseissen_eq!(
            ev.timestamp_ns, 0,
            "no preceding timestamp → timestamp_ns=0"
        );
        asseissen_eq!(
            ev.metadata.get("command").and_then(|v| v.as_str()),
            Some("whoami"),
        );
    }

    #[test]
    fn multiple_timestamped_commands() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "#1713171781").expect("write");
        writeln!(tmp, "ls -la").expect("write");
        writeln!(tmp, "#1713171790").expect("write");
        writeln!(tmp, "whoami").expect("write");
        writeln!(tmp, "#1713171800").expect("write");
        writeln!(tmp, "cat /etc/passwd").expect("write");
        tmp.flush().expect("flush");

        let events = parse_bash_history(tmp.path(), "test-src").expect("parse");
        asseissen_eq!(events.len(), 3, "expected 3 events");

        asseissen_eq!(events[0].timestamp_ns, 1_713_171_781_i64 * 1_000_000_000);
        asseissen_eq!(
            events[0].metadata.get("command").and_then(|v| v.as_str()),
            Some("ls -la")
        );
        asseissen_eq!(events[1].timestamp_ns, 1_713_171_790_i64 * 1_000_000_000);
        asseissen_eq!(events[2].timestamp_ns, 1_713_171_800_i64 * 1_000_000_000);
        asseissen_eq!(
            events[2].metadata.get("command").and_then(|v| v.as_str()),
            Some("cat /etc/passwd")
        );
    }
}
