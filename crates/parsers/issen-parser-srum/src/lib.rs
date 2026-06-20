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
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
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

        // Network usage records.
        let network_records = srum_parser::parse_network_usage(path)?;
        for record in network_records {
            let ts_ns = record.timestamp.timestamp_nanos_opt().unwrap_or(0);
            let ts_display = record.timestamp.to_rfc3339();
            let description = format!(
                "SRUM NetworkUsage: bytes_sent={} bytes_recv={} app_id={}",
                record.bytes_sent, record.bytes_recv, record.app_id,
            );
            let event = TimelineEvent::new(
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
            events.push(event);
        }

        // App resource usage records.
        let app_records = srum_parser::parse_app_usage(path)?;
        for record in app_records {
            let ts_ns = record.timestamp.timestamp_nanos_opt().unwrap_or(0);
            let ts_display = record.timestamp.to_rfc3339();
            let description = format!(
                "SRUM AppUsage: foreground_cycles={} background_cycles={} app_id={}",
                record.foreground_cycles, record.background_cycles, record.app_id,
            );
            let event = TimelineEvent::new(
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
            events.push(event);
        }

        Ok(events)
    }
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
    ParserRegistration { create: || Box::new(SrumParser) }
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
