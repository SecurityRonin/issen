//! SRUM (System Resource Usage Monitor) parser for Issen.
//!
//! Parses `SRUDB.dat` ESE database files, converting network usage and
//! application usage records into [`TimelineEvent`]s.
//!
//! Record extraction is performed by the `srum-parser`/`ese-core` ESE B-tree
//! leaf traversal. A valid SRUDB with no rows in a given table yields an empty
//! vector for that table (e.g. Windows Server omits several SRUM extensions),
//! which this parser handles gracefully.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use std::collections::HashMap;
use std::path::Path;

/// SRUM parser — ingests `SRUDB.dat` ESE database files.
pub struct SrumParser;

impl SrumParser {
    /// Returns `true` if `path`'s filename is `SRUDB.dat` (case-insensitive).
    pub fn can_parse(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("SRUDB.dat"))
    }

    /// Parse a SRUDB.dat file and return timeline events.
    ///
    /// Drives `srum-parser`'s real ESE B-tree leaf traversal for the network-
    /// usage and app-resource-usage tables and converts each row into a
    /// [`TimelineEvent`]. A table absent from the catalog yields no events.
    ///
    /// Returns `Err` if the file cannot be read or is not a valid ESE database.
    pub fn parse_path(&self, path: &Path) -> anyhow::Result<Vec<TimelineEvent>> {
        let evidence_source = path.to_string_lossy().into_owned();
        let mut events = Vec::new();

        // SruDbIdMapTable: app_id is an index, not a name — resolve it so an
        // analyst sees the application path, not `app_id=285`. Best-effort: a
        // missing/empty id passes through with no `app_name` (the raw id is always
        // retained), so an unresolvable id is valid output, never a failure.
        let id_map: std::collections::HashMap<i32, String> = srum_parser::parse_id_map(path)
            .unwrap_or_default()
            .into_iter()
            .map(|e| (e.id, e.name))
            .collect();
        let resolve = |id: i32| id_map.get(&id).filter(|n| !n.is_empty()).cloned();

        // Network usage records.
        let network_records = srum_parser::parse_network_usage(path)?;
        for record in network_records {
            let ts_ns = record.timestamp.timestamp_nanos_opt().unwrap_or(0);
            let ts_display = record.timestamp.to_rfc3339();
            let app_name = resolve(record.app_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={}", record.app_id));
            let description = format!(
                "SRUM NetworkUsage: {app_label} bytes_sent={} bytes_recv={}",
                record.bytes_sent, record.bytes_recv,
            );
            let mut event = TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::Other("NetworkBandwidth".into()),
                ArtifactType::Srum,
                evidence_source.clone(),
                description,
                evidence_source.clone(),
            )
            .with_activity_category(issen_core::ActivityCategory::NetworkActivity)
            .with_metadata("bytes_sent", serde_json::json!(record.bytes_sent))
            .with_metadata("bytes_recv", serde_json::json!(record.bytes_recv))
            .with_metadata("app_id", serde_json::json!(record.app_id))
            .with_metadata("user_id", serde_json::json!(record.user_id));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            events.push(event);
        }

        // App resource usage records.
        let app_records = srum_parser::parse_app_usage(path)?;
        for record in app_records {
            let ts_ns = record.timestamp.timestamp_nanos_opt().unwrap_or(0);
            let ts_display = record.timestamp.to_rfc3339();
            let app_name = resolve(record.app_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={}", record.app_id));
            let description = format!(
                "SRUM AppUsage: {app_label} foreground_cycles={} background_cycles={}",
                record.foreground_cycles, record.background_cycles,
            );
            let mut event = TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::ProcessExec,
                ArtifactType::Srum,
                evidence_source.clone(),
                description,
                evidence_source.clone(),
            )
            .with_activity_category(issen_core::ActivityCategory::Execution)
            .with_metadata(
                "foreground_cycles",
                serde_json::json!(record.foreground_cycles),
            )
            .with_metadata(
                "background_cycles",
                serde_json::json!(record.background_cycles),
            )
            .with_metadata("app_id", serde_json::json!(record.app_id))
            .with_metadata("user_id", serde_json::json!(record.user_id));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            events.push(event);
        }

        // Network connectivity records — when the host was attached to a network
        // and for how long (placement / timeline evidence).
        events.extend(connectivity_events(
            srum_parser::parse_network_connectivity(path)?,
            &id_map,
            &evidence_source,
        ));

        Ok(events)
    }
}

/// Resolve a `SruDbIdMapTable` index to a non-empty name (best-effort).
fn resolve_name(id_map: &HashMap<i32, String>, id: i32) -> Option<String> {
    id_map.get(&id).filter(|n| !n.is_empty()).cloned()
}

/// Map SRUM NetworkConnectivity rows (connection intervals) to `NetworkActivity`
/// events. `profile_id` resolves through the same id map (per `enrich_connectivity`).
fn connectivity_events(
    records: Vec<srum_core::NetworkConnectivityRecord>,
    id_map: &HashMap<i32, String>,
    evidence_source: &str,
) -> Vec<TimelineEvent> {
    records
        .into_iter()
        .map(|record| {
            let ts_ns = record.timestamp.timestamp_nanos_opt().unwrap_or(0);
            let app_name = resolve_name(id_map, record.app_id);
            let profile_name = resolve_name(id_map, record.profile_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={}", record.app_id));
            let mut event = TimelineEvent::new(
                ts_ns,
                record.timestamp.to_rfc3339(),
                EventType::Other("NetworkConnectivity".into()),
                ArtifactType::Srum,
                evidence_source.to_string(),
                format!(
                    "SRUM NetworkConnectivity: {app_label} connected {}s",
                    record.connected_time
                ),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::NetworkActivity)
            .with_metadata("connected_time", serde_json::json!(record.connected_time))
            .with_metadata("app_id", serde_json::json!(record.app_id))
            .with_metadata("profile_id", serde_json::json!(record.profile_id))
            .with_metadata("user_id", serde_json::json!(record.user_id));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            if let Some(name) = &profile_name {
                event = event.with_metadata("profile_name", serde_json::json!(name));
            }
            event
        })
        .collect()
}

impl ForensicParser for SrumParser {
    fn name(&self) -> &'static str {
        "SRUM Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Srum]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        // SRUM is an ESE database: the parser seeks across B-tree pages, so it
        // needs random-access *file* semantics, not the streaming byte view.
        // When the source exposes its path (the orchestrator's FileDataSource
        // does), drive the real ESE traversal through it; a byte-only source
        // (no path) yields no events rather than failing.
        let Some(path) = input.source_path() else {
            return Ok(ParseStats::new());
        };

        let events = self
            .parse_path(path)
            .map_err(|e| RtError::InvalidData(format!("SRUM parse failed: {e}")))?;
        let mut stats = ParseStats::new();
        stats.events_emitted = events.len() as u64;
        stats.bytes_processed = input.len();
        emitter.emit_batch(events)?;
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(256 * 1024 * 1024), // 256 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(SrumParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::Srum,
            matches: classify::srum,
            priority: 90,
            disk_sources: &[
                sel::DiskSource::Ntfs(sel::NtfsLoc::FixedPath(r"\Windows\System32\sru\SRUDB.dat")),
            ],
            cost: sel::CostTier::Default,
        } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn srum_parser_handles_srudb_dat_name() {
        let parser = SrumParser;
        assert!(parser.can_parse(Path::new("SRUDB.dat")));
    }

    #[test]
    fn srum_parser_handles_srudb_dat_case_insensitive() {
        let parser = SrumParser;
        assert!(parser.can_parse(Path::new("srudb.dat")));
        assert!(parser.can_parse(Path::new("SRUDB.DAT")));
        assert!(parser.can_parse(Path::new("Srudb.Dat")));
    }

    #[test]
    fn srum_parser_rejects_other_files() {
        let parser = SrumParser;
        assert!(!parser.can_parse(Path::new("system.log")));
        assert!(!parser.can_parse(Path::new("$MFT")));
        assert!(!parser.can_parse(Path::new("Security.evtx")));
        assert!(!parser.can_parse(Path::new("SRUDB.dat.bak")));
    }

    #[test]
    fn srum_parser_returns_empty_for_empty_file() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let parser = SrumParser;
        // empty file is not a valid ESE DB — parser must return Ok(vec![]) or Err
        // The srum-parser lib returns Err for invalid ESE; our wrapper must not panic.
        let result = parser.parse_path(tmp.path());
        // Acceptable: Ok(empty) or Err — must not panic.
        if let Ok(events) = result {
            assert!(events.is_empty(), "empty file should yield no events");
        } // Err is also acceptable — file is not a valid ESE DB
    }
}
