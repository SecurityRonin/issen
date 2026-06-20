use std::path::Path;

use anyhow::{Context, Result};
use issen_timeline::findings;
use issen_timeline::store::TimelineStore;

/// Run the info command: display summary statistics about a timeline database.
pub fn run(db_path: &Path) -> Result<()> {
    let store = TimelineStore::open(db_path)
        .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

    let stats = store.stats().context("Failed to compute stats")?;

    println!("Timeline Database: {}", db_path.display());
    println!("Total events:      {}", stats.total_events);

    if stats.total_events > 0 {
        if let Some(earliest) = stats.earliest_timestamp_ns {
            println!("Earliest event:    {earliest}");
        }
        if let Some(latest) = stats.latest_timestamp_ns {
            println!("Latest event:      {latest}");
        }
    }

    if !stats.event_type_counts.is_empty() {
        println!("\nEvent Types:");
        let mut types: Vec<_> = stats.event_type_counts.iter().collect();
        types.sort_by_key(|x| std::cmp::Reverse(x.1));
        for (et, count) in types {
            println!("  {et:<20} {count}");
        }
    }

    if !stats.source_counts.is_empty() {
        println!("\nArtifact Sources:");
        let mut sources: Vec<_> = stats.source_counts.iter().collect();
        sources.sort_by_key(|x| std::cmp::Reverse(x.1));
        for (src, count) in sources {
            println!("  {src:<20} {count}");
        }
    }

    println!("\nEvidence sources:  {}", stats.evidence_source_count);

    // Show scan findings summary if the table exists and has findings.
    show_findings_summary(&store);

    Ok(())
}

/// Try to display a scan findings summary. Silently skips if the table
/// doesn't exist or there are no findings (graceful for older databases).
fn show_findings_summary(store: &TimelineStore) {
    let conn = store.connection();

    // Ensure the table exists (idempotent CREATE IF NOT EXISTS).
    if findings::create_findings_table(conn).is_err() {
        return;
    }

    let total = match findings::total_findings(conn) {
        Ok(t) => t,
        Err(_) => return,
    };

    if total == 0 {
        return;
    }

    println!("\nScan findings:    {total}");

    if let Ok(counts) = findings::count_by_severity(conn) {
        for (severity, count) in &counts {
            println!("  {severity}: {count}");
        }
    }
}
