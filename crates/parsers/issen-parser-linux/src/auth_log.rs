//! Parser for Linux auth.log files.

use std::collections::HashMap;
use std::path::Path;

use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Parse the `"Apr 15 10:23:01"` prefix common to syslog-format files.
/// Returns nanoseconds since the Unix epoch, or 0 on any parse failure.
pub(crate) fn parse_syslog_ts(month: &str, day: &str, time: &str) -> i64 {
    let month_num = match month {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return 0,
    };
    let day_num: u32 = day.trim().parse().unwrap_or(0);
    if day_num == 0 {
        return 0;
    }
    let parts: Vec<&str> = time.splitn(3, ':').collect();
    if parts.len() != 3 {
        return 0;
    }
    let hour: u32 = parts[0].parse().unwrap_or(u32::MAX);
    let min: u32 = parts[1].parse().unwrap_or(u32::MAX);
    let sec: u32 = parts[2].parse().unwrap_or(u32::MAX);
    if hour > 23 || min > 59 || sec > 59 {
        return 0;
    }
    let Some(date) = NaiveDate::from_ymd_opt(2026, month_num, day_num) else {
        return 0;
    };
    let Some(time_of_day) = NaiveTime::from_hms_opt(hour, min, sec) else {
        return 0;
    };
    let dt = NaiveDateTime::new(date, time_of_day);
    match Utc.from_local_datetime(&dt).single() {
        Some(utc_dt) => utc_dt.timestamp_nanos_opt().unwrap_or(0),
        None => 0,
    }
}

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
    user: Option<&str>,
) -> TimelineEvent {
    let mut ev = TimelineEvent::new(
        timestamp_ns,
        ts_display(timestamp_ns),
        event_type,
        ArtifactType::LoginHistory,
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

/// Parse an auth.log file at `path` and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unexpected I/O failures. Missing files and
/// unparseable lines are silently skipped (returns `Ok(vec![])`).
pub fn parse_auth_log(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
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

        // Expected prefix: "Apr 15 10:23:01 hostname process[pid]: message"
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 6 {
            continue;
        }
        let (month, day, time) = (parts[0], parts[1], parts[2]);
        // parts[3] = hostname, parts[4] = process[pid]:, parts[5] = rest
        let msg = parts[5];

        let timestamp_ns = parse_syslog_ts(month, day, time);

        // Detect sshd: Accepted publickey/password for <user> from <ip>
        if parts[4].starts_with("sshd[") || parts[4] == "sshd:" {
            if msg.starts_with("Accepted ") {
                if let Some(user) = extract_ssh_user(msg, "Accepted") {
                    let ssh_ip = extract_ssh_ip(msg);
                    let mut meta = HashMap::new();
                    meta.insert("user".into(), serde_json::json!(user));
                    meta.insert("event_kind".into(), serde_json::json!("ssh_login"));
                    if let Some(ip) = ssh_ip {
                        meta.insert("source_ip".into(), serde_json::json!(ip));
                    }
                    let ev = make_event(
                        timestamp_ns,
                        EventType::ProcessExec,
                        &path_str,
                        &format!("SSH login accepted for {user}"),
                        source_id,
                        meta,
                        Some(user),
                    );
                    events.push(ev);
                }
                continue;
            }
            if msg.starts_with("Failed password for ") {
                let user = extract_failed_ssh_user(msg);
                let ssh_ip = extract_ssh_ip(msg);
                let mut meta = HashMap::new();
                meta.insert("event_kind".into(), serde_json::json!("ssh_failed"));
                if let Some(u) = user {
                    meta.insert("user".into(), serde_json::json!(u));
                }
                if let Some(ip) = ssh_ip {
                    meta.insert("source_ip".into(), serde_json::json!(ip));
                }
                let desc = format!("SSH login failed: {msg}");
                let ev = make_event(
                    timestamp_ns,
                    EventType::ProcessExec,
                    &path_str,
                    &desc,
                    source_id,
                    meta,
                    None,
                );
                events.push(ev);
                continue;
            }
        }

        // Detect sudo: "alice : TTY=pts/0 ; PWD=... ; USER=root ; COMMAND=/bin/bash"
        if parts[4].starts_with("sudo:") || parts[4] == "sudo:" {
            if let Some(sudo_user) = extract_sudo_user(msg) {
                let mut meta = HashMap::new();
                meta.insert("event_kind".into(), serde_json::json!("sudo"));
                meta.insert("user".into(), serde_json::json!(sudo_user));
                let ev = make_event(
                    timestamp_ns,
                    EventType::ProcessExec,
                    &path_str,
                    &format!("sudo by {sudo_user}"),
                    source_id,
                    meta,
                    Some(sudo_user),
                );
                events.push(ev);
            }
        }
    }

    Ok(events)
}

/// Extract the username from "Accepted publickey for <user> from ..."
fn extract_ssh_user<'a>(msg: &'a str, verb: &str) -> Option<&'a str> {
    let after = msg.strip_prefix(&format!("{verb} "))?;
    // skip "publickey " or "password " prefix up to " for "
    let after = after.split_once(" for ").map_or(after, |x| x.1);
    // "root from 192.168.1.100 ..."
    let user = after.split(' ').next()?;
    Some(user)
}

/// Extract source IP from "... from <ip> port ..."
fn extract_ssh_ip(msg: &str) -> Option<&str> {
    let after = msg.split(" from ").nth(1)?;
    let ip = after.split(' ').next()?;
    Some(ip)
}

/// Extract user from "Failed password for [invalid user] <user> from ..."
fn extract_failed_ssh_user(msg: &str) -> Option<&str> {
    let after = msg.strip_prefix("Failed password for ")?;
    let after = if after.starts_with("invalid user ") {
        after.strip_prefix("invalid user ")?
    } else {
        after
    };
    let user = after.split(' ').next()?;
    Some(user)
}

/// Extract user from sudo log message: "alice : TTY=pts/0 ; ..."
fn extract_sudo_user(msg: &str) -> Option<&str> {
    let user = msg.split(' ').next()?;
    if user.is_empty() {
        None
    } else {
        Some(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_auth_log(tmp.path(), "test-src").expect("parse_auth_log");
        assert!(events.is_empty(), "empty file should produce no events");
    }

    #[test]
    fn missing_file_returns_empty_vec() {
        let events = parse_auth_log(Path::new("/nonexistent/path/auth.log"), "test-src")
            .expect("missing file should return Ok(vec![])");
        assert!(events.is_empty());
    }

    #[test]
    fn ssh_accepted_emits_event_with_user_and_ip() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:23:01 hostname sshd[1234]: Accepted publickey for root from 192.168.1.100 port 52341 ssh2"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_auth_log(tmp.path(), "test-src").expect("parse");
        asseissen_eq!(events.len(), 1, "expected 1 event for ssh accepted line");

        let ev = &events[0];
        asseissen_eq!(
            ev.metadata.get("user").and_then(|v| v.as_str()),
            Some("root"),
            "user metadata should be 'root'"
        );
        asseissen_eq!(
            ev.metadata.get("source_ip").and_then(|v| v.as_str()),
            Some("192.168.1.100"),
            "source_ip should be parsed"
        );
        asseissen_eq!(
            ev.metadata.get("event_kind").and_then(|v| v.as_str()),
            Some("ssh_login"),
            "event_kind should be 'ssh_login'"
        );
    }

    #[test]
    fn sudo_line_emits_sudo_event() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:25:00 hostname sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_auth_log(tmp.path(), "test-src").expect("parse");
        asseissen_eq!(events.len(), 1, "expected 1 event for sudo line");

        let ev = &events[0];
        asseissen_eq!(
            ev.metadata.get("event_kind").and_then(|v| v.as_str()),
            Some("sudo"),
            "event_kind should be 'sudo'"
        );
        asseissen_eq!(
            ev.metadata.get("user").and_then(|v| v.as_str()),
            Some("alice"),
            "user should be alice"
        );
    }

    #[test]
    fn ssh_failed_emits_ssh_failed_event() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:30:00 hostname sshd[1235]: Failed password for invalid user admin from 192.168.1.50 port 48811 ssh2"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_auth_log(tmp.path(), "test-src").expect("parse");
        asseissen_eq!(events.len(), 1, "expected 1 event for failed password line");

        let ev = &events[0];
        asseissen_eq!(
            ev.metadata.get("event_kind").and_then(|v| v.as_str()),
            Some("ssh_failed"),
            "event_kind should be 'ssh_failed'"
        );
        asseissen_eq!(
            ev.metadata.get("source_ip").and_then(|v| v.as_str()),
            Some("192.168.1.50"),
        );
    }

    #[test]
    fn unparseable_lines_are_skipped() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "this is not a valid auth.log line at all").expect("write");
        writeln!(tmp, "neither is this one!").expect("write");
        tmp.flush().expect("flush");

        let events = parse_auth_log(tmp.path(), "test-src").expect("parse");
        assert!(events.is_empty(), "garbage lines should yield no events");
    }
}
