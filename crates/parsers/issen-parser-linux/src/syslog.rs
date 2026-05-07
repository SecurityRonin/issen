//! Parser for Linux syslog files.

use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

use crate::auth_log::parse_syslog_ts;

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
    event_type: EventType,
    artifact_path: &str,
    description: &str,
    source_id: &str,
    metadata: HashMap<String, serde_json::Value>,
) -> TimelineEvent {
    let mut ev = TimelineEvent::new(
        timestamp_ns,
        ts_display(timestamp_ns),
        event_type,
        ArtifactType::SystemInfo,
        artifact_path.to_string(),
        description.to_string(),
        source_id.to_string(),
    );
    for (k, v) in metadata {
        ev = ev.with_metadata(k, v);
    }
    ev
}

/// Parse a syslog file at `path` and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unexpected I/O failures. Missing files and
/// unparseable lines are silently skipped (returns `Ok(vec![])`).
pub fn parse_syslog(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };

    let path_str = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Format: "Apr 15 10:02:00 hostname process[pid]: message"
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 6 {
            continue;
        }
        let (month, day, time) = (parts[0], parts[1], parts[2]);
        // parts[3] = hostname
        let proc_field = parts[4]; // "systemd[1]:" or "kernel:"
        let msg = parts[5];

        let timestamp_ns = parse_syslog_ts(month, day, time);

        // Extract process name and optional PID
        let (process, pid) = parse_proc_field(proc_field);

        let mut meta = HashMap::new();
        meta.insert("process".into(), serde_json::json!(process));
        if let Some(p) = pid {
            meta.insert("pid".into(), serde_json::json!(p));
        }
        meta.insert("message".into(), serde_json::json!(msg));

        // Classify: "Started ..." → ProcessExec, others → FileModify
        let event_type = if msg.starts_with("Started ") {
            EventType::ProcessExec
        } else {
            EventType::FileModify
        };

        let desc = format!("{process}: {msg}");
        let ev = make_event(timestamp_ns, event_type, &path_str, &desc, source_id, meta);
        events.push(ev);
    }

    Ok(events)
}

/// Split "systemd[1]:" into ("systemd", Some("1")) or "kernel:" into ("kernel", None).
fn parse_proc_field(field: &str) -> (&str, Option<&str>) {
    let field = field.trim_end_matches(':');
    if let Some(bracket) = field.find('[') {
        let process = &field[..bracket];
        let pid = field.get(bracket + 1..).and_then(|s| s.strip_suffix(']'));
        (process, pid)
    } else {
        (field, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    use issen_core::timeline::event::EventType;

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_syslog(tmp.path(), "test-src").expect("parse_syslog");
        assert!(events.is_empty(), "empty file should produce no events");
    }

    #[test]
    fn missing_file_returns_empty_vec() {
        let events = parse_syslog(Path::new("/nonexistent/syslog"), "test-src")
            .expect("missing file should return Ok(vec![])");
        assert!(events.is_empty());
    }

    #[test]
    fn systemd_started_emits_process_start() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:02:00 hostname systemd[1]: Started OpenSSH Server Daemon."
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_syslog(tmp.path(), "test-src").expect("parse");
        asseissen_eq!(events.len(), 1, "expected 1 event");

        let ev = &events[0];
        asseissen_eq!(
            ev.event_type,
            EventType::ProcessExec,
            "Started lines should emit ProcessExec"
        );
        asseissen_eq!(
            ev.metadata.get("process").and_then(|v| v.as_str()),
            Some("systemd"),
            "process field should be systemd"
        );
    }

    #[test]
    fn generic_syslog_line_emits_event_with_message() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:00:00 hostname kernel: [12345.678] iptables: DROPPED: ..."
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_syslog(tmp.path(), "test-src").expect("parse");
        asseissen_eq!(events.len(), 1, "expected 1 event for kernel line");

        let ev = &events[0];
        assert!(
            ev.metadata.contains_key("message"),
            "metadata should have 'message' key"
        );
        asseissen_eq!(
            ev.metadata.get("process").and_then(|v| v.as_str()),
            Some("kernel"),
        );
    }
}
