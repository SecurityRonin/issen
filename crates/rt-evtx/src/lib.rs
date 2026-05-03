pub mod analyze;
pub mod session;

pub use analyze::EvtxAnalysisSummary;
pub use session::EvtxSessionSummary;

use std::path::{Path, PathBuf};

/// Find all .evtx files under `dir` recursively.
///
/// Returns an empty vec if `dir` doesn't exist or cannot be read.
pub fn find_evtx_files(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    walk_dir(dir, &mut result);
    result
}

fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, out);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("evtx"))
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
}

/// Parse EVTX files and run session correlation.
///
/// Files that cannot be parsed are silently skipped (best-effort).
pub fn analyse_evtx_sessions(evtx_files: &[PathBuf]) -> anyhow::Result<EvtxSessionSummary> {
    use evtx::{EvtxParser, ParserSettings};
    use winevt_core::EvtxEvent;
    use winevt_session::{correlate_sessions, extract_process_events, find_lateral_movement, link_processes_to_sessions};
    use winevt_analyze::{frequency_analysis, FrequencyKey};

    let settings = ParserSettings::default()
        .separate_json_attributes(true)
        .indent(false);

    let mut all_events: Vec<EvtxEvent> = Vec::new();

    for path in evtx_files {
        let mut parser = match EvtxParser::from_path(path) {
            Ok(p) => p.with_configuration(settings.clone()),
            Err(_) => continue, // skip files that can't be opened (e.g. zero-byte)
        };

        for record in parser.records_json_value() {
            let rec = match record {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Some(ev) = evtx_record_to_event(&rec.timestamp, &rec.data) {
                all_events.push(ev);
            }
        }
    }

    // Correlate logon sessions
    let mut sessions_map = correlate_sessions(&all_events);

    // Link process events to sessions
    let process_events = extract_process_events(&all_events);
    link_processes_to_sessions(&mut sessions_map, &process_events);

    // Run lateral movement detection
    let sessions_vec: Vec<_> = sessions_map.into_values().collect();
    let lateral = find_lateral_movement(&sessions_vec);

    // Frequency analysis for rare processes (cap=5)
    let anomalies = frequency_analysis(&all_events, FrequencyKey::ProcessImage, 5);
    let _rare_processes: Vec<String> = anomalies.into_iter().map(|a| a.key).collect();

    let session_count = sessions_vec.len();
    let lateral_movement_count = lateral.len();

    Ok(EvtxSessionSummary {
        session_count,
        lateral_movement_count,
        sessions: sessions_vec,
        lateral_movements: lateral,
    })
}

/// Convert a `serde_json::Value` EVTX record to an `EvtxEvent`.
///
/// Returns `None` if the record cannot be interpreted.
fn evtx_record_to_event(
    timestamp: &evtx::Timestamp,
    value: &serde_json::Value,
) -> Option<winevt_core::EvtxEvent> {
    use serde_json::Value;
    use std::collections::HashMap;

    let event = value.get("Event")?;
    let system = event.get("System")?;

    let event_id = system
        .get("EventID")
        .and_then(|v| match v {
            Value::Number(n) => n.as_u64(),
            Value::Object(o) => o.get("#text").and_then(Value::as_str).and_then(|s| s.parse().ok()),
            Value::String(s) => s.parse().ok(),
            _ => None,
        })
        .and_then(|n| u32::try_from(n).ok())?;

    // Filter to only the event IDs we care about
    const INTERESTING: &[u32] = &[4624, 4634, 4647, 4648, 4688, 4689];
    if !INTERESTING.contains(&event_id) {
        return None;
    }

    let channel = system
        .get("Channel")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_string();

    let computer = system
        .get("Computer")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // Convert evtx::Timestamp → nanoseconds since epoch
    let timestamp_ns = timestamp
        .as_second()
        .saturating_mul(1_000_000_000)
        .saturating_add(i64::from(timestamp.subsec_nanosecond()));

    let user_sid = system
        .get("Security")
        .and_then(|s| s.get("UserID"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from);

    let process_id = system
        .get("Execution")
        .and_then(|e| e.get("ProcessID"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());

    let thread_id = system
        .get("Execution")
        .and_then(|e| e.get("ThreadID"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());

    let mut data: HashMap<String, String> = HashMap::new();
    if let Some(event_data) = event.get("EventData") {
        collect_kv(event_data, &mut data);
    }
    if let Some(user_data) = event.get("UserData") {
        collect_kv(user_data, &mut data);
    }

    // Extract LogonID from common fields
    let mut logon_id: Option<u64> = None;
    for key in &["TargetLogonId", "SubjectLogonId", "LogonId"] {
        if let Some(val) = data.get(*key) {
            logon_id = parse_logon_id(val);
            if logon_id.is_some() {
                break;
            }
        }
    }

    Some(winevt_core::EvtxEvent {
        event_id,
        channel,
        timestamp_ns,
        computer,
        user_sid,
        logon_id,
        process_id,
        thread_id,
        data,
    })
}

fn collect_kv(value: &serde_json::Value, out: &mut std::collections::HashMap<String, String>) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if k.starts_with('#') {
                    continue;
                }
                match v {
                    Value::String(s) => {
                        out.insert(k.clone(), s.clone());
                    }
                    Value::Number(n) => {
                        out.insert(k.clone(), n.to_string());
                    }
                    Value::Bool(b) => {
                        out.insert(k.clone(), b.to_string());
                    }
                    Value::Null => {
                        out.insert(k.clone(), String::new());
                    }
                    Value::Object(_) | Value::Array(_) => {
                        collect_kv(v, out);
                    }
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_kv(item, out);
            }
        }
        _ => {}
    }
}

fn parse_logon_id(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() || s == "-" || s == "0x0000000000000000" {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── find_evtx_files tests ─────────────────────────────────────────────

    #[test]
    fn find_evtx_files_returns_empty_for_empty_dir() {
        let dir = TempDir::new().expect("tmpdir");
        let result = find_evtx_files(dir.path());
        assert!(result.is_empty(), "expected empty vec for empty dir");
    }

    #[test]
    fn find_evtx_files_finds_evtx_extension() {
        let dir = TempDir::new().expect("tmpdir");
        std::fs::write(dir.path().join("Security.evtx"), b"").expect("write file");
        let result = find_evtx_files(dir.path());
        assert_eq!(result.len(), 1, "expected 1 evtx file, got {}", result.len());
    }

    #[test]
    fn find_evtx_files_ignores_non_evtx() {
        let dir = TempDir::new().expect("tmpdir");
        std::fs::write(dir.path().join("system.log"), b"").expect("write log");
        std::fs::write(dir.path().join("Security.evtx"), b"").expect("write evtx");
        let result = find_evtx_files(dir.path());
        assert_eq!(result.len(), 1, "should only find .evtx files");
        assert!(
            result[0].extension().map(|e| e == "evtx").unwrap_or(false),
            "found file has wrong extension"
        );
    }

    // ── analyse_evtx_sessions tests ──────────────────────────────────────

    #[test]
    fn analyse_evtx_sessions_returns_ok_for_empty_slice() {
        let result = analyse_evtx_sessions(&[]);
        assert!(result.is_ok(), "empty slice should return Ok");
    }

    // ── EvtxSessionSummary struct tests ───────────────────────────────────

    #[test]
    fn session_summary_has_session_count() {
        let summary = EvtxSessionSummary {
            session_count: 3,
            ..Default::default()
        };
        assert_eq!(summary.session_count, 3);
    }

    #[test]
    fn session_summary_has_lateral_movement_count() {
        let summary = EvtxSessionSummary {
            lateral_movement_count: 2,
            ..Default::default()
        };
        assert_eq!(summary.lateral_movement_count, 2);
    }

    // ── EvtxAnalysisSummary struct tests ──────────────────────────────────

    #[test]
    fn analysis_summary_has_rare_processes() {
        let summary = EvtxAnalysisSummary {
            rare_processes: vec!["suspicious.exe".to_string()],
            ..Default::default()
        };
        assert_eq!(summary.rare_processes.len(), 1);
        assert_eq!(summary.rare_processes[0], "suspicious.exe");
    }
}
