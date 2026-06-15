//! `issen session` — correlate Windows logon sessions from EVTX files.

use std::path::PathBuf;

use anyhow::Context;
use issen_evtx::{find_evtx_files, session::EvtxSessionSummary};
use winevt_core::{logon_type_name, LogonSession};

/// Run session correlation against EVTX files from `dirs` and explicit `files`.
///
/// - Discovers `.evtx` files recursively in each directory in `dirs`.
/// - Also includes any explicitly listed paths in `files`.
/// - Calls `analyse_evtx_sessions` for session correlation.
/// - Outputs JSON to stdout (when `json == true`) or a summary table.
///
/// Returns `Ok(())` even when no EVTX files are found — callers should not
/// treat an empty evidence set as an error.
pub fn run(dirs: &[PathBuf], files: &[PathBuf], json: bool) -> anyhow::Result<()> {
    let mut evtx_files: Vec<PathBuf> = Vec::new();

    for dir in dirs {
        evtx_files.extend(find_evtx_files(dir));
    }
    for file in files {
        if file.exists() {
            evtx_files.push(file.clone());
        }
    }

    let summary = issen_evtx::analyse_evtx_sessions(&evtx_files)
        .with_context(|| "session correlation failed")?;

    if json {
        print_json(&summary)?;
    } else {
        print_summary(&summary);
    }

    Ok(())
}

/// Serialize a single `LogonSession` to a JSON object.
///
/// When `logon_type == 10` (RDP / RemoteInteractive) and `src_ip` is present,
/// a `src_ip_source` field is emitted with value `"IpAddress"` to document that
/// `WorkstationName` was intentionally ignored for this logon type (it contains
/// the destination, not the source). For all other logon types with a `src_ip`,
/// `src_ip_source` is `"WorkstationName"`.
pub(crate) fn session_to_json_value(s: &LogonSession) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "logon_id": format!("0x{:x}", s.logon_id),
        "username": s.username,
        "domain": s.domain,
        "logon_type": s.logon_type,
        "logon_type_name": logon_type_name(s.logon_type),
        "logon_time_ns": s.logon_time_ns,
        "process_count": s.processes.len(),
        "is_orphaned": s.is_orphaned,
    });
    if let Some(ip) = &s.src_ip {
        obj["src_ip"] = serde_json::json!(ip);
        let source = if s.logon_type == 10 {
            "IpAddress"
        } else {
            "WorkstationName"
        };
        obj["src_ip_source"] = serde_json::json!(source);
    }
    if let Some(logoff_ns) = s.logoff_time_ns {
        obj["logoff_time_ns"] = serde_json::json!(logoff_ns);
    }
    if let Some(dur) = s.duration_secs {
        obj["duration_secs"] = serde_json::json!(dur);
    }
    obj
}

fn print_json(summary: &EvtxSessionSummary) -> anyhow::Result<()> {
    let sessions_json: Vec<serde_json::Value> =
        summary.sessions.iter().map(session_to_json_value).collect();

    let lateral_json: Vec<serde_json::Value> = summary
        .lateral_movements
        .iter()
        .map(|lm| {
            serde_json::json!({
                "src_ip": lm.src_ip,
                "sessions": lm.sessions.iter().map(|id| format!("0x{id:x}")).collect::<Vec<_>>(),
                "reason": lm.reason,
            })
        })
        .collect();

    let out = serde_json::json!({
        "sessions": sessions_json,
        "lateral_movements": lateral_json,
        "orphaned_count": summary.sessions.iter().filter(|s| s.is_orphaned).count(),
        "total_sessions": summary.session_count,
    });

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn print_summary(summary: &EvtxSessionSummary) {
    println!("Sessions: {}", summary.session_count);
    println!(
        "Lateral movement indicators: {}",
        summary.lateral_movement_count
    );

    let orphaned: Vec<_> = summary.sessions.iter().filter(|s| s.is_orphaned).collect();
    if !orphaned.is_empty() {
        println!("\nOrphaned sessions ({}):", orphaned.len());
        for s in &orphaned {
            println!(
                "  0x{:x}  {}/{}  type:{}({})",
                s.logon_id,
                s.domain,
                s.username,
                s.logon_type,
                logon_type_name(s.logon_type),
            );
        }
    }

    if !summary.lateral_movements.is_empty() {
        println!("\nLateral movement findings:");
        for lm in &summary.lateral_movements {
            println!("  {}", lm.reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(logon_type: u8, src_ip: Option<&str>) -> LogonSession {
        LogonSession {
            logon_id: 0x1234,
            logon_type,
            username: "user".into(),
            domain: "DOMAIN".into(),
            src_ip: src_ip.map(str::to_owned),
            logon_time_ns: 0,
            logoff_time_ns: None,
            duration_secs: None,
            processes: Vec::new(),
            is_orphaned: false,
        }
    }

    #[test]
    fn rdp_type10_with_src_ip_emits_ip_address_provenance() {
        let s = make_session(10, Some("10.10.10.13"));
        let v = session_to_json_value(&s);
        assert_eq!(
            v["src_ip_source"].as_str(),
            Some("IpAddress"),
            "Type 10 must document src_ip came from IpAddress field"
        );
    }

    #[test]
    fn network_type3_with_src_ip_emits_workstation_name_provenance() {
        let s = make_session(3, Some("DESKTOP-SOURCE"));
        let v = session_to_json_value(&s);
        assert_eq!(
            v["src_ip_source"].as_str(),
            Some("WorkstationName"),
            "Type 3 must document src_ip came from WorkstationName field"
        );
    }

    #[test]
    fn session_without_src_ip_has_no_src_ip_source_field() {
        let s = make_session(10, None);
        let v = session_to_json_value(&s);
        assert!(
            v.get("src_ip_source").is_none(),
            "no src_ip means no src_ip_source field"
        );
    }

    #[test]
    fn session_to_json_value_contains_core_fields() {
        let s = make_session(3, None);
        let v = session_to_json_value(&s);
        assert!(v.get("logon_id").is_some());
        assert!(v.get("logon_type").is_some());
        assert!(v.get("logon_type_name").is_some());
        assert!(v.get("username").is_some());
    }
}
