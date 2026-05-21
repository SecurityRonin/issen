//! `issen session` — correlate Windows logon sessions from EVTX files.

use std::path::PathBuf;

use anyhow::Context;
use issen_evtx::{find_evtx_files, session::EvtxSessionSummary};
use winevt_core::logon_type_name;

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

fn print_json(summary: &EvtxSessionSummary) -> anyhow::Result<()> {
    let sessions_json: Vec<serde_json::Value> = summary
        .sessions
        .iter()
        .map(|s| {
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
            }
            if let Some(logoff_ns) = s.logoff_time_ns {
                obj["logoff_time_ns"] = serde_json::json!(logoff_ns);
            }
            if let Some(dur) = s.duration_secs {
                obj["duration_secs"] = serde_json::json!(dur);
            }
            obj
        })
        .collect();

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
    println!("Lateral movement indicators: {}", summary.lateral_movement_count);

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

