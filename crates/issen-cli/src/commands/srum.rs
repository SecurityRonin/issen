//! `rt srum` — parse a SRUDB.dat file and display SRUM records.

use std::path::Path;

use anyhow::Context;

/// Run the SRUM parser against `path` and print results in `format`.
///
/// Accepts `"json"` or `"text"` (default) as output formats.
/// Returns `Ok(())` on empty results — the underlying `srum-parser` currently
/// returns `Ok(vec![])` for valid ESE databases while B-tree extraction is
/// in progress; that is handled gracefully here.
///
/// # Errors
///
/// Returns an error if the path does not exist or cannot be opened as an ESE database.
pub fn run(path: &Path, format: &str) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    let network_records = srum_parser::parse_network_usage(path)
        .with_context(|| format!("Failed to parse SRUM network usage from {}", path.display()))?;

    let app_records = srum_parser::parse_app_usage(path)
        .with_context(|| format!("Failed to parse SRUM app usage from {}", path.display()))?;

    match format {
        "json" => {
            let output = serde_json::json!({
                "network_usage": network_records,
                "app_usage": app_records,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            // Text format
            if network_records.is_empty() && app_records.is_empty() {
                println!("No SRUM records found (ESE B-tree extraction not yet implemented).");
                return Ok(());
            }

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
    }

    Ok(())
}
