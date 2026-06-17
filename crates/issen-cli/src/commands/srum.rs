//! `rt srum` — parse a SRUDB.dat file and display SRUM records.

use std::path::Path;

use anyhow::Context;
use issen_core::timeline::event::TimelineEvent;
use issen_parser_srum::SrumParser;

/// Collect SRUM records from `path` as Issen [`TimelineEvent`]s via the
/// `issen-parser-srum` wrapper — the same seam the ingest parser registry uses.
///
/// This is the single bridge through which SRUM enters the Issen timeline: the
/// wrapper drives `srum-parser`'s real ESE B-tree leaf traversal and converts
/// each network-usage / app-usage row into a `TimelineEvent` (with `bytes_sent`,
/// `bytes_recv`, cycle counts, and ID-map keys preserved as metadata).
///
/// # Errors
///
/// Returns an error if the file cannot be opened as a valid ESE database.
pub fn collect_events(path: &Path) -> anyhow::Result<Vec<TimelineEvent>> {
    SrumParser.parse_path(path)
}

/// Run the SRUM parser against `path` and print results in `format`.
///
/// Accepts `"json"` or `"text"` (default) as output formats. SRUM rows are
/// surfaced into Issen [`TimelineEvent`]s through [`collect_events`]; the
/// detailed per-record tables are rendered from the same `srum-parser` decode.
///
/// # Errors
///
/// Returns an error if the path does not exist or cannot be opened as an ESE database.
pub fn run(path: &Path, format: &str) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    // Surface SRUM into the Issen timeline path via the issen-parser-srum wrapper.
    let timeline_events = collect_events(path)
        .with_context(|| format!("Failed to surface SRUM timeline from {}", path.display()))?;

    let network_records = srum_parser::parse_network_usage(path)
        .with_context(|| format!("Failed to parse SRUM network usage from {}", path.display()))?;

    let app_records = srum_parser::parse_app_usage(path)
        .with_context(|| format!("Failed to parse SRUM app usage from {}", path.display()))?;

    if format == "json" {
        let output = serde_json::json!({
            "timeline_event_count": timeline_events.len(),
            "network_usage": network_records,
            "app_usage": app_records,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Text format
        if network_records.is_empty() && app_records.is_empty() {
            println!("No SRUM records found.");
            return Ok(());
        }

        println!("Surfaced {} SRUM timeline event(s).", timeline_events.len());

        if !network_records.is_empty() {
            println!("Network Usage Records ({}):", network_records.len());
            println!(
                "{:<6} {:<8} {:<12} {:<12} {:<30}",
                "AppId", "UserId", "BytesSent", "BytesRecv", "Timestamp"
            );
            println!("{}", "-".repeat(70));
            for r in &network_records {
                println!(
                    "{:<6} {:<8} {:<12} {:<12} {:<30}",
                    r.app_id,
                    r.user_id,
                    r.bytes_sent,
                    r.bytes_recv,
                    r.timestamp.to_rfc3339(),
                );
            }
            println!();
        }

        if !app_records.is_empty() {
            println!("App Usage Records ({}):", app_records.len());
            println!(
                "{:<6} {:<8} {:<18} {:<18} {:<30}",
                "AppId", "UserId", "FgCycles", "BgCycles", "Timestamp"
            );
            println!("{}", "-".repeat(80));
            for r in &app_records {
                println!(
                    "{:<6} {:<8} {:<18} {:<18} {:<30}",
                    r.app_id,
                    r.user_id,
                    r.foreground_cycles,
                    r.background_cycles,
                    r.timestamp.to_rfc3339(),
                );
            }
        }
    }

    Ok(())
}
