//! `issen biome` — parse an Apple Biome `App.MenuItem` SEGB file and display the
//! macOS menu-bar selections it records.

use std::path::Path;

use anyhow::Context;
use issen_core::timeline::event::TimelineEvent;
use issen_parser_biome::BiomeParser;

/// Collect Biome `App.MenuItem` selections from `path` as Issen
/// [`TimelineEvent`]s via the `issen-parser-biome` wrapper — the same seam the
/// ingest parser registry uses.
///
/// This is the single bridge through which Biome menu activity enters the Issen
/// timeline: the wrapper drives `segb-core`'s SEGB decode and
/// `useract-forensic`'s `BiomeMenuItemSource` normalization, yielding one event
/// per Written menu selection.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn collect_events(path: &Path) -> anyhow::Result<Vec<TimelineEvent>> {
    BiomeParser.parse_path(path)
}

/// Run the Biome parser against `path` and print results in `format`.
///
/// Accepts `"json"` or `"text"` (default). Menu selections are surfaced into
/// Issen [`TimelineEvent`]s through [`collect_events`].
///
/// # Errors
///
/// Returns an error if the path does not exist or cannot be read.
pub fn run(path: &Path, format: &str) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    let events = collect_events(path)
        .with_context(|| format!("Failed to surface Biome timeline from {}", path.display()))?;

    if format == "json" {
        let rows: Vec<_> = events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp_display,
                    "description": e.description,
                })
            })
            .collect();
        let output = serde_json::json!({
            "timeline_event_count": events.len(),
            "events": rows,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if events.is_empty() {
            println!("No Biome App.MenuItem records found.");
            return Ok(());
        }
        println!("Surfaced {} Biome menu-selection event(s).", events.len());
        println!("{:<30} Selection", "Timestamp");
        println!("{}", "-".repeat(70));
        for e in &events {
            println!("{:<30} {}", e.timestamp_display, e.description);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal valid SEGB v1 file with one Written `App.MenuItem`
    /// record (application="Finder", menu_item="Move to Trash"). Mirrors the
    /// fixture in `issen-parser-biome`; the CLI test needs an on-disk file.
    fn synthetic_segb() -> Vec<u8> {
        let mut payload = Vec::new();
        let app = b"Finder";
        payload.push(0x0A);
        payload.push(u8::try_from(app.len()).expect("fits u8"));
        payload.extend_from_slice(app);
        let item = b"Move to Trash";
        payload.push(0x12);
        payload.push(u8::try_from(item.len()).expect("fits u8"));
        payload.extend_from_slice(item);

        let mut rec = Vec::new();
        rec.extend_from_slice(
            &i32::try_from(payload.len())
                .expect("fits i32")
                .to_le_bytes(),
        );
        rec.extend_from_slice(&1i32.to_le_bytes()); // Written
        rec.extend_from_slice(&721_692_800f64.to_le_bytes()); // unix 1_700_000_000
        rec.extend_from_slice(&721_692_800f64.to_le_bytes());
        rec.extend_from_slice(&0u32.to_le_bytes());
        rec.extend_from_slice(&0i32.to_le_bytes());

        let header_len = 56usize;
        let end_of_data = u32::try_from(header_len + rec.len() + payload.len()).expect("fits u32");
        let mut file = vec![0u8; header_len];
        file[0..4].copy_from_slice(&end_of_data.to_le_bytes());
        file[52..56].copy_from_slice(b"SEGB");
        file.extend_from_slice(&rec);
        file.extend_from_slice(&payload);
        while !file.len().is_multiple_of(8) {
            file.push(0);
        }
        file
    }

    #[test]
    fn collect_events_decodes_segb_file() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(&synthetic_segb()).expect("write");
        let events = collect_events(tmp.path()).expect("collect");
        assert_eq!(events.len(), 1, "one Written App.MenuItem -> one event");
        assert!(
            events[0].description.contains("Finder: Move to Trash"),
            "description was: {}",
            events[0].description
        );
    }

    #[test]
    fn run_errors_on_missing_path() {
        assert!(run(Path::new("/no/such/biome/local"), "text").is_err());
    }

    #[test]
    fn biome_parser_is_registered_in_the_ingest_inventory() {
        use issen_core::artifacts::ArtifactType;
        use issen_core::plugin::registry::all_parsers;
        // Force-linking issen-parser-biome into the CLI must make its parser
        // discoverable by the orchestrator's compile-time inventory.
        let registered = all_parsers().iter().any(|p| {
            p.supported_artifacts()
                .contains(&ArtifactType::BiomeMenuItem)
        });
        assert!(
            registered,
            "no registered parser advertises ArtifactType::BiomeMenuItem"
        );
    }
}
