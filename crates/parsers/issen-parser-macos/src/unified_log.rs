//! Parser for macOS Unified Log text exports (`log show --style syslog`).
//!
//! Expected line format:
//! `YYYY-MM-DD HH:MM:SS.ffffff±HHMM  hostname process[pid]: message`

use std::io::{BufRead, BufReader};
use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Parse a Unified Log text export and return timeline events.
///
/// # Errors
/// Returns `anyhow::Error` only on I/O failures reading the file.
/// Malformed lines are silently skipped. Missing files return `Ok(vec![])`.
pub fn parse_unified_log(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
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
        if let Some(ev) = parse_line(line, path, source_id) {
            events.push(ev);
        }
    }

    Ok(events)
}

/// Parse a single Unified Log syslog-format line.
///
/// Format: `YYYY-MM-DD HH:MM:SS.ffffff±HHMM  hostname process[pid]: message`
fn parse_line(line: &str, artifact_path: &Path, source_id: &str) -> Option<TimelineEvent> {
    // Minimum: "YYYY-MM-DD HH:MM:SS.ffffff+HHMM" = 32 chars
    if line.len() < 32 {
        return None;
    }

    // Split timestamp from rest — timestamp ends at the timezone offset which
    // is at index: "YYYY-MM-DD HH:MM:SS.ffffff" = 26 chars, then ±HHMM = 5 chars → 31 chars total
    // But we parse it from the prefix up to the first double-space separator.
    let ts_end = line.find("  ")?;
    let ts_str = &line[..ts_end];
    let rest = line[ts_end..].trim_start();

    // Parse timestamp
    let timestamp_ns = parse_timestamp_ns(ts_str);

    // rest = "hostname process[pid]: message"
    // Drop hostname (first token), then parse "process[pid]: message"
    let after_hostname = rest.split_once(' ')?.1.trim_start();

    // after_hostname = "process[pid]: message"
    // or "process[pid] (subsystem): message"
    // Extract process name and pid from the "process[pid]" or "process[pid] (sub)" portion
    let (process, pid, message) = parse_process_pid_message(after_hostname)?;

    let event_type = classify_event(&process, &message);

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("process".to_string(), serde_json::Value::String(process));
    if let Some(p) = pid {
        metadata.insert("pid".to_string(), serde_json::Value::String(p));
    }
    let msg_truncated: String = message.chars().take(200).collect();
    metadata.insert(
        "message".to_string(),
        serde_json::Value::String(msg_truncated.clone()),
    );

    let timestamp_display = ts_str.to_string();
    let description = format!("Unified Log: {msg_truncated}");

    let mut ev = TimelineEvent::new(
        timestamp_ns,
        timestamp_display,
        event_type,
        ArtifactType::SystemInfo,
        artifact_path.to_string_lossy().into_owned(),
        description,
        source_id.to_string(),
    );
    ev.metadata = metadata;
    Some(ev)
}

/// Extract (process, Option<pid>, message) from "process[pid]: message" or
/// "process[pid] (subsystem): message".
fn parse_process_pid_message(s: &str) -> Option<(String, Option<String>, String)> {
    // Find the colon that ends the process+pid portion (followed by space)
    // It may look like:  "sshd[1234]: Accepted..."
    // or:               "com.apple.xpc.launchd[1] (com.apple.logind): Service exited..."

    // Find the first ": " which separates header from message
    let colon_pos = s.find(": ")?;
    let header = &s[..colon_pos];
    let message = s[colon_pos + 2..].to_string();

    // header = "process[pid]" or "process[pid] (subsystem)"
    // Strip optional " (subsystem)" suffix first
    let bracket_start = header.rfind('[').unwrap_or(header.len());
    let bracket_end = header.rfind(']').unwrap_or(header.len());

    let (process, pid) = if bracket_start < bracket_end {
        let proc_name = header[..bracket_start].trim().to_string();
        let pid_str = header[bracket_start + 1..bracket_end].trim().to_string();
        (proc_name, Some(pid_str))
    } else {
        (header.trim().to_string(), None)
    };

    if process.is_empty() {
        return None;
    }

    Some((process, pid, message))
}

/// Classify the event based on process name and message content.
fn classify_event(process: &str, message: &str) -> EventType {
    let proc_lower = process.to_lowercase();
    let msg_lower = message.to_lowercase();

    // launchd service events
    if proc_lower.contains("launchd")
        && (msg_lower.contains("service")
            || msg_lower.contains("exited")
            || msg_lower.contains("started"))
    {
        return EventType::ProcessExec;
    }
    // sshd accepted connections
    if proc_lower == "sshd" && msg_lower.contains("accepted") {
        return EventType::ProcessExec;
    }
    // Generic fallback
    EventType::FileModify
}

/// Parse `YYYY-MM-DD HH:MM:SS.ffffff±HHMM` into nanoseconds since Unix epoch.
/// Returns 0 on any parse failure.
fn parse_timestamp_ns(s: &str) -> i64 {
    // Expected length: at minimum "YYYY-MM-DD HH:MM:SS+HHMM" = 24
    // With fractional:  "YYYY-MM-DD HH:MM:SS.ffffff+HHMM" = 31
    let s = s.trim();
    if s.len() < 24 {
        return 0;
    }

    // Find the ± sign for the UTC offset — search from position 19 onwards
    let offset_pos = s[19..].find(['+', '-']).map(|p| p + 19);

    let (datetime_part, offset_str) = match offset_pos {
        Some(pos) => (&s[..pos], &s[pos..]),
        None => return 0,
    };

    // datetime_part = "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DD HH:MM:SS.ffffff"
    let parts: Vec<&str> = datetime_part.splitn(2, '.').collect();
    let base = parts[0]; // "YYYY-MM-DD HH:MM:SS"
    let frac = parts.get(1).copied().unwrap_or("0");

    if base.len() < 19 {
        return 0;
    }

    let year: i64 = base[0..4].parse().unwrap_or(0);
    let month: i64 = base[5..7].parse().unwrap_or(0);
    let day: i64 = base[8..10].parse().unwrap_or(0);
    let hour: i64 = base[11..13].parse().unwrap_or(0);
    let min: i64 = base[14..16].parse().unwrap_or(0);
    let sec: i64 = base[17..19].parse().unwrap_or(0);

    if year == 0 || month == 0 || day == 0 {
        return 0;
    }

    // Days since Unix epoch (1970-01-01) using a simple algorithm
    let unix_days = days_since_unix_epoch(year, month, day);
    let unix_secs = unix_days * 86_400 + hour * 3_600 + min * 60 + sec;

    // Fractional seconds — up to 6 digits (microseconds), pad or truncate to 6
    let frac_us: i64 = {
        let padded = format!("{:0<6}", &frac[..frac.len().min(6)]);
        padded.parse().unwrap_or(0)
    };
    let frac_nanoseconds = frac_us * 1_000;

    // UTC offset "±HHMM"
    let offset_ns = parse_offset_ns(offset_str);

    // Subtract offset to convert to UTC
    unix_secs * 1_000_000_000 + frac_nanoseconds - offset_ns
}

/// Returns number of days since 1970-01-01 for a given year/month/day.
fn days_since_unix_epoch(year: i64, month: i64, day: i64) -> i64 {
    // Julian Day Number approach
    let jdn = julian_day_number(year, month, day);
    let epoch_jdn = julian_day_number(1970, 1, 1);
    jdn - epoch_jdn
}

/// Compute the Julian Day Number for a calendar date.
fn julian_day_number(year: i64, month: i64, day: i64) -> i64 {
    let a = (14 - month) / 12;
    let y = year + 4800 - a;
    let m = month + 12 * a - 3;
    day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32_045
}

/// Parse UTC offset string "±HHMM" into nanoseconds.
fn parse_offset_ns(s: &str) -> i64 {
    if s.len() < 5 {
        return 0;
    }
    let sign: i64 = if s.starts_with('-') { -1 } else { 1 };
    let hh: i64 = s[1..3].parse().unwrap_or(0);
    let mm: i64 = s[3..5].parse().unwrap_or(0);
    sign * (hh * 3_600 + mm * 60) * 1_000_000_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    // ── Test 1: empty file → Ok(vec![]) ──────────────────────────────────────

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_unified_log(tmp.path(), "test-source")
            .expect("must not return Err on empty file");
        assert!(events.is_empty(), "expected empty vec for zero-byte file");
    }

    // ── Test 2: one well-formed line → 1 event with correct process metadata ─

    #[test]
    fn one_wellformed_line_emits_one_event_with_process_metadata() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:23:01.123456-0700  localhost kernel[0]: (AppleIntelCPU) Kernel connected"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events =
            parse_unified_log(tmp.path(), "test-source").expect("must not Err on well-formed line");
        assert_eq!(events.len(), 1, "expected exactly 1 event");
        let ev = &events[0];
        assert_eq!(
            ev.metadata.get("process").and_then(|v| v.as_str()),
            Some("kernel"),
            "process metadata should be 'kernel'"
        );
    }

    // ── Test 3: launchd "Service exited" → EventType::ProcessExec ───────────

    #[test]
    fn launchd_service_exited_yields_process_start() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:23:02.456789-0700  localhost com.apple.xpc.launchd[1] (com.apple.logind): Service exited with abnormal code: 1"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_unified_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            issen_core::timeline::event::EventType::ProcessExec,
            "launchd Service exited should map to ProcessExec"
        );
    }

    // ── Test 4: sshd "Accepted publickey" → ProcessExec + process="sshd" ────

    #[test]
    fn sshd_accepted_publickey_yields_process_start_with_sshd_process() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:23:03.111111-0700  localhost sshd[1234]: Accepted publickey for alice from 192.168.1.1"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_unified_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(
            ev.event_type,
            issen_core::timeline::event::EventType::ProcessExec,
            "sshd Accepted publickey should map to ProcessExec"
        );
        assert_eq!(
            ev.metadata.get("process").and_then(|v| v.as_str()),
            Some("sshd"),
            "process metadata should be 'sshd'"
        );
    }

    // ── Test 5: garbled line → Ok (no panic, no Err) ─────────────────────────

    #[test]
    fn garbled_line_returns_ok_no_panic() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "THIS IS NOT A VALID LOG LINE AT ALL !!!@#$%").expect("write");
        writeln!(tmp, "").expect("write");
        writeln!(tmp, "   ").expect("write");
        tmp.flush().expect("flush");

        let result = parse_unified_log(tmp.path(), "test-source");
        assert!(result.is_ok(), "garbled lines must not cause Err");
        let events = result.expect("ok");
        assert!(
            events.is_empty(),
            "garbled lines should be silently skipped"
        );
    }

    // ── Test 6: known timestamp → timestamp_ns is non-zero ───────────────────

    #[test]
    fn known_timestamp_yields_nonzero_timestamp_ns() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // 2026-04-15 10:23:01 UTC (offset +0000) → well-known Unix ts
        writeln!(
            tmp,
            "2026-04-15 10:23:01.000000+0000  localhost kernel[0]: Some message here"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_unified_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        assert_ne!(
            events[0].timestamp_ns, 0,
            "timestamp_ns must be non-zero for a valid timestamp"
        );
        // 2026-04-15 10:23:01 UTC = 1776248581 seconds since epoch
        let expected_ns: i64 = 1_776_248_581_000_000_000;
        assert_eq!(
            events[0].timestamp_ns, expected_ns,
            "timestamp_ns mismatch for 2026-04-15 10:23:01 UTC"
        );
    }
}
