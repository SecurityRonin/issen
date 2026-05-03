pub mod analyze;
pub mod session;

pub use analyze::EvtxAnalysisSummary;
pub use session::{EvtxSessionSummary, LateralMovementFinding};

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
    use crate::session::{correlate_sessions, extract_process_events, find_lateral_movement, link_processes_to_sessions};
    use crate::analyze::{frequency_analysis, FrequencyKey};

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

    Ok(crate::session::EvtxSessionSummary {
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

pub mod handlers;

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

    // ── analyze module tests (Phase 3 RED) ───────────────────────────────
    mod analyze_tests {
        use crate::analyze::{frequency_analysis, pivot_sessions_by_src_ip, FrequencyAnomaly, FrequencyKey};
        use winevt_core::{EvtxEvent, LogonSession};
        use std::collections::HashMap;

        fn make_event(event_id: u32, data: Vec<(&str, &str)>, ts: i64) -> EvtxEvent {
            let data: HashMap<String, String> = data
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            EvtxEvent {
                event_id,
                channel: "Security".into(),
                timestamp_ns: ts,
                computer: "WS01".into(),
                user_sid: None,
                logon_id: None,
                process_id: None,
                thread_id: None,
                data,
            }
        }

        #[test]
        fn frequency_key_variants_are_usable() {
            let _cmd = FrequencyKey::CommandLine;
            let _img = FrequencyKey::ProcessImage;
            let _usr = FrequencyKey::Username;
        }

        #[test]
        fn frequency_anomaly_has_key_and_count() {
            let anomaly = FrequencyAnomaly {
                key: "suspicious.exe".into(),
                count: 1,
                events: vec![100],
            };
            assert_eq!(anomaly.key, "suspicious.exe");
            assert_eq!(anomaly.count, 1);
        }

        #[test]
        fn frequency_analysis_flags_rare_command() {
            let events = vec![
                make_event(4688, vec![("CommandLine", "whoami")], 100),
                make_event(4688, vec![("CommandLine", "dir")], 200),
                make_event(4688, vec![("CommandLine", "dir")], 300),
                make_event(4688, vec![("CommandLine", "dir")], 400),
            ];
            let anomalies = frequency_analysis(&events, FrequencyKey::CommandLine, 2);
            assert_eq!(anomalies.len(), 1);
            assert_eq!(anomalies[0].key, "whoami");
        }

        #[test]
        fn frequency_analysis_empty_events() {
            let anomalies = frequency_analysis(&[], FrequencyKey::ProcessImage, 5);
            assert!(anomalies.is_empty());
        }

        #[test]
        fn pivot_sessions_by_src_ip_groups_correctly() {
            let sessions = vec![
                LogonSession {
                    logon_id: 1,
                    logon_type: 3,
                    username: "a".into(),
                    domain: "D".into(),
                    src_ip: Some("10.0.0.1".into()),
                    logon_time_ns: 100,
                    logoff_time_ns: None,
                    duration_secs: None,
                    processes: vec![],
                    is_orphaned: true,
                },
                LogonSession {
                    logon_id: 2,
                    logon_type: 3,
                    username: "b".into(),
                    domain: "D".into(),
                    src_ip: Some("10.0.0.1".into()),
                    logon_time_ns: 200,
                    logoff_time_ns: None,
                    duration_secs: None,
                    processes: vec![],
                    is_orphaned: true,
                },
            ];
            let pivot = pivot_sessions_by_src_ip(&sessions);
            assert_eq!(pivot.len(), 1);
            assert_eq!(pivot["10.0.0.1"].len(), 2);
        }
    }

    // ── session module tests (Phase 2 RED) ───────────────────────────────
    mod session_tests {
        use crate::session::{
            correlate_sessions, extract_process_events, find_lateral_movement,
            find_orphaned_sessions, link_processes_to_sessions, LateralMovementFinding,
        };
        use winevt_core::EvtxEvent;
        use std::collections::HashMap;

        fn make_logon(logon_id: u64) -> EvtxEvent {
            let mut data = HashMap::new();
            data.insert("TargetLogonId".into(), format!("0x{logon_id:016x}"));
            data.insert("LogonType".into(), "3".into());
            data.insert("TargetUserName".into(), "testuser".into());
            data.insert("TargetDomainName".into(), "DOM".into());
            data.insert("IpAddress".into(), "10.0.0.1".into());
            EvtxEvent {
                event_id: 4624,
                channel: "Security".into(),
                timestamp_ns: 1_000_000_000,
                computer: "WS01".into(),
                user_sid: None,
                logon_id: Some(logon_id),
                process_id: None,
                thread_id: None,
                data,
            }
        }

        #[test]
        fn correlate_sessions_from_evtx_events() {
            let events = vec![make_logon(0x1234)];
            let sessions = correlate_sessions(&events);
            assert_eq!(sessions.len(), 1);
            assert!(sessions.contains_key(&0x1234));
        }

        #[test]
        fn lateral_movement_finding_has_src_ip_field() {
            let finding = LateralMovementFinding {
                src_ip: "10.0.0.1".into(),
                sessions: vec![0x1234],
                reason: "test".into(),
            };
            assert_eq!(finding.src_ip, "10.0.0.1");
        }

        #[test]
        fn find_lateral_movement_detects_type3_logons() {
            let events = vec![make_logon(0x5678)];
            let sessions_map = correlate_sessions(&events);
            let sessions_vec: Vec<_> = sessions_map.into_values().collect();
            let findings = find_lateral_movement(&sessions_vec);
            assert!(!findings.is_empty(), "type-3 logon from remote IP should be detected");
        }

        #[test]
        fn extract_process_events_empty() {
            let events: Vec<EvtxEvent> = vec![];
            let procs = extract_process_events(&events);
            assert!(procs.is_empty());
        }

        #[test]
        fn find_orphaned_sessions_empty() {
            let sessions: Vec<winevt_core::LogonSession> = vec![];
            let orphans = find_orphaned_sessions(&sessions);
            assert!(orphans.is_empty());
        }

        #[test]
        fn link_processes_does_not_panic_on_empty() {
            let mut sessions = std::collections::HashMap::new();
            let procs: Vec<winevt_core::ProcessEvent> = vec![];
            link_processes_to_sessions(&mut sessions, &procs);
        }
    }

    // ── handlers module tests (Phase 1 RED) ──────────────────────────────
    mod handler_tests {
        use crate::handlers::all_handlers;

        #[test]
        fn all_handlers_returns_12_handlers() {
            let handlers = all_handlers();
            assert_eq!(handlers.len(), 12, "expected exactly 12 handlers");
        }

        #[test]
        fn handler_for_4624_exists() {
            let handlers = all_handlers();
            let found = handlers
                .iter()
                .any(|h| h.handles(4624, "Security"));
            assert!(found, "expected a handler that handles event 4624");
        }

        #[test]
        fn handler_for_1116_defender_exists() {
            let handlers = all_handlers();
            let found = handlers
                .iter()
                .any(|h| h.handles(1116, "Microsoft-Windows-Windows Defender/Operational"));
            assert!(found, "expected a handler that handles event 1116 (Defender)");
        }
    }
}
