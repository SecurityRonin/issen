//! `issen processes` — list process creation events from EVTX files.

use std::path::PathBuf;

use anyhow::Context;
use issen_evtx::{find_evtx_files, session::extract_process_events};
use winevt_core::ProcessEvent;

/// Run process listing against EVTX files from `dirs` and explicit `files`.
///
/// - Discovers `.evtx` files recursively in each directory in `dirs`.
/// - Also includes any explicitly listed paths in `files`.
/// - When `link_sessions` is true, enriches each process with session context.
/// - Outputs JSON to stdout (when `json == true`) or a summary table.
///
/// Returns `Ok(())` even when no EVTX files are found.
pub fn run(
    dirs: &[PathBuf],
    files: &[PathBuf],
    json: bool,
    link_sessions: bool,
) -> anyhow::Result<()> {
    let mut evtx_files: Vec<PathBuf> = Vec::new();

    for dir in dirs {
        evtx_files.extend(find_evtx_files(dir));
    }
    for file in files {
        if file.exists() {
            evtx_files.push(file.clone());
        }
    }

    let mut processes: Vec<ProcessEvent> = Vec::new();
    for path in &evtx_files {
        processes.extend(extract_process_events(path));
    }

    // Sort chronologically for deterministic output.
    processes.sort_by_key(|p| p.timestamp_ns);

    if link_sessions {
        let summary = issen_evtx::analyse_evtx_sessions(&evtx_files)
            .with_context(|| "session correlation failed")?;
        let sessions = build_session_map(&summary);
        enrich_with_sessions(&mut processes, &sessions);
    }

    if json {
        print_json(&processes);
    } else {
        print_summary(&processes);
    }

    Ok(())
}

fn build_session_map(
    summary: &issen_evtx::session::EvtxSessionSummary,
) -> std::collections::HashMap<u64, &winevt_core::LogonSession> {
    summary.sessions.iter().map(|s| (s.logon_id, s)).collect()
}

fn enrich_with_sessions(
    processes: &mut [ProcessEvent],
    sessions: &std::collections::HashMap<u64, &winevt_core::LogonSession>,
) {
    for p in processes.iter_mut() {
        if let Some(lid) = p.logon_id {
            if let Some(session) = sessions.get(&lid) {
                p.user = Some(format!("{}/{}", session.domain, session.username));
            }
        }
    }
}

fn print_json(processes: &[ProcessEvent]) {
    let arr: Vec<serde_json::Value> = processes
        .iter()
        .map(|p| {
            let mut obj = serde_json::json!({
                "timestamp_ns": p.timestamp_ns,
                "pid": p.process_id,
                "image_path": p.image_path,
            });
            if let Some(ppid) = p.parent_pid {
                obj["parent_pid"] = serde_json::json!(ppid);
            }
            if let Some(ref cmdline) = p.command_line {
                obj["command_line"] = serde_json::json!(cmdline);
            }
            if let Some(ref user) = p.user {
                obj["user"] = serde_json::json!(user);
            }
            obj
        })
        .collect();

    let out = serde_json::json!({
        "processes": arr,
        "total_count": processes.len(),
    });
    // Serializing an in-memory `json!` value is infallible; `expect` documents
    // that and satisfies the `unwrap_used = deny` lint.
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serialize JSON value")
    );
}

fn print_summary(processes: &[ProcessEvent]) {
    println!("Processes: {}", processes.len());
    for p in processes {
        println!(
            "  {}  {}{}",
            p.image_path,
            p.command_line.as_deref().unwrap_or(""),
            p.user
                .as_ref()
                .map(|u| format!("  [{u}]"))
                .unwrap_or_default(),
        );
    }
}
