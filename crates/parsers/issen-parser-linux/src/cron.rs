//! Parser for Linux cron log files.

use std::collections::HashMap;
use std::path::Path;

use chrono::{Datelike, Utc};
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
    artifact_path: &str,
    description: &str,
    source_id: &str,
    metadata: HashMap<String, serde_json::Value>,
    user: Option<&str>,
) -> TimelineEvent {
    let mut ev = TimelineEvent::new(
        timestamp_ns,
        ts_display(timestamp_ns),
        EventType::ProcessExec,
        ArtifactType::CrontabConfig,
        artifact_path.to_string(),
        description.to_string(),
        source_id.to_string(),
    );
    for (k, v) in metadata {
        ev = ev.with_metadata(k, v);
    }
    if let Some(u) = user {
        ev = ev.with_user(u);
    }
    ev
}

/// Parse a cron log file at `path` and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unexpected I/O failures. Missing files and
/// unparseable lines are silently skipped (returns `Ok(vec![])`).
pub fn parse_cron_log(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
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

        // Format: "Apr 15 10:00:01 hostname CRON[9999]: (root) CMD (run-parts /etc/cron.daily)"
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 6 {
            continue;
        }
        let (month, day, time) = (parts[0], parts[1], parts[2]);
        // parts[3] = hostname, parts[4] = CRON[pid]:
        let msg = parts[5]; // "(root) CMD (run-parts /etc/cron.daily)"

        // Only process CMD lines
        if !msg.contains(") CMD (") {
            continue;
        }

        let timestamp_ns = parse_syslog_ts(month, day, time, Utc::now().year());

        // Extract user: "(root) CMD (...)" → "root"
        let user = msg.strip_prefix('(').and_then(|s| s.split(')').next());

        // Extract command: "(root) CMD (run-parts /etc/cron.daily)" → "run-parts /etc/cron.daily"
        let command = msg
            .split_once(") CMD (")
            .map(|x| x.1)
            .and_then(|s| s.strip_suffix(')'))
            .unwrap_or(msg);

        let mut meta = HashMap::new();
        if let Some(u) = user {
            meta.insert("user".into(), serde_json::json!(u));
        }
        meta.insert("command".into(), serde_json::json!(command));

        let desc = format!("Cron job by {}: {command}", user.unwrap_or("unknown"));
        let ev = make_event(timestamp_ns, &path_str, &desc, source_id, meta, user);
        events.push(ev);
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
        let events = parse_cron_log(tmp.path(), "test-src").expect("parse_cron_log");
        assert!(events.is_empty(), "empty file should produce no events");
    }

    #[test]
    fn cron_cmd_line_emits_process_start_with_user_and_command() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:00:01 hostname CRON[9999]: (root) CMD (run-parts /etc/cron.daily)"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_cron_log(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1, "expected 1 event for CRON CMD line");

        let ev = &events[0];
        assert_eq!(
            ev.event_type,
            EventType::ProcessExec,
            "should be ProcessExec"
        );
        assert_eq!(
            ev.metadata.get("user").and_then(|v| v.as_str()),
            Some("root"),
        );
        assert_eq!(
            ev.metadata.get("command").and_then(|v| v.as_str()),
            Some("run-parts /etc/cron.daily"),
        );
    }

    #[test]
    fn cron_cmd_line_alice_backup() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:05:00 hostname CRON[9998]: (alice) CMD (/home/alice/backup.sh)"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_cron_log(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1);

        let ev = &events[0];
        assert_eq!(
            ev.metadata.get("user").and_then(|v| v.as_str()),
            Some("alice"),
        );
        assert_eq!(
            ev.metadata.get("command").and_then(|v| v.as_str()),
            Some("/home/alice/backup.sh"),
        );
    }
}
