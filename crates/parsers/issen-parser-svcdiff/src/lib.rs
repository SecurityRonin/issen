//! Windows service install/modify parser for Issen.
//!
//! The SYSTEM hive's `CurrentControlSet\Services` subkeys describe every
//! installed service. A service whose image path is in a user-writable directory,
//! launches an interpreter, auto-starts with no description, or runs with no
//! configured account is a persistence signal (MITRE ATT&CK T1543.003 — Create
//! or Modify System Process: Windows Service).
//!
//! Decoding (service-key walking + anomaly classification) is delegated to our
//! own `winreg-artifacts::svc_diff` (over `winreg-core`) — the registry-artifact
//! home for the fleet — never third-party notatin.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    // `fn name(&self) -> &str` must match the `ForensicParser` trait signature.
    clippy::unnecessary_literal_bound,
    // DataSource lengths are bounded well under usize on supported targets.
    clippy::cast_possible_truncation
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

// ---------------------------------------------------------------------------
// Hive-level parsing
// ---------------------------------------------------------------------------

/// Parse a SYSTEM hive file for service install/modify entries.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_svcdiff(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let bytes = match std::fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(vec![]),
    };
    let hive_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("SYSTEM");
    Ok(events_from_bytes(&bytes, hive_name, source_id))
}

/// Build service [`TimelineEvent`]s from raw hive bytes — shared by
/// [`parse_svcdiff`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::svc_diff::parse(&hive)
        .into_iter()
        .map(|e| {
            // The service key's LastWriteTime ≈ the service install/modify time.
            let (ts_ns, ts_display) = e.last_written.map_or_else(
                || (0, "unknown".to_string()),
                |dt| (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339()),
            );
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::ServiceInstall,
                ArtifactType::Registry,
                format!("{hive_name}\\CurrentControlSet\\Services\\{}", e.name),
                format!(
                    "Service: {} ({}) -> {}",
                    e.name, e.display_name, e.image_path
                ),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Persistence)
            .with_metadata("name", serde_json::json!(e.name))
            .with_metadata("display_name", serde_json::json!(e.display_name))
            .with_metadata("image_path", serde_json::json!(e.image_path))
            .with_metadata("start_type", serde_json::json!(e.start_type))
            .with_metadata("service_type", serde_json::json!(e.service_type))
            .with_metadata("object_name", serde_json::json!(e.object_name))
            .with_metadata("description", serde_json::json!(e.description))
            .with_metadata("is_suspicious", serde_json::json!(e.is_suspicious))
            .with_metadata("suspicious_reason", serde_json::json!(e.suspicious_reason))
            .with_metadata("artifact", serde_json::json!("svc_diff"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// Windows service parser — reads the SYSTEM hive, where
/// `CurrentControlSet\Services` registrations live.
pub struct SvcDiffParser;

impl SvcDiffParser {
    /// Return `true` when `path`'s filename is `SYSTEM` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("system"))
    }
}

impl ForensicParser for SvcDiffParser {
    fn name(&self) -> &str {
        "Service Diff Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Registry]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, issen_core::error::RtError> {
        let mut stats = ParseStats::new();
        let len = input.len();
        if len == 0 {
            return Ok(stats);
        }
        let mut bytes = vec![0u8; len as usize];
        let mut off = 0u64;
        while off < len {
            let n = input.read_at(off, &mut bytes[off as usize..])?;
            if n == 0 {
                break;
            }
            off += n as u64;
        }
        stats.bytes_processed = off;
        let events = events_from_bytes(&bytes, "SYSTEM", "svcdiff-evidence");
        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
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
    ParserRegistration { create: || Box::new(SvcDiffParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn can_parse_system_hive() {
        assert!(SvcDiffParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SYSTEM"
        )));
    }

    #[test]
    fn can_parse_system_lowercase() {
        assert!(SvcDiffParser::can_parse(&PathBuf::from("/evidence/system")));
    }

    #[test]
    fn cannot_parse_software_hive() {
        assert!(!SvcDiffParser::can_parse(&PathBuf::from(
            "/evidence/SOFTWARE"
        )));
    }

    #[test]
    fn cannot_parse_sam_hive() {
        assert!(!SvcDiffParser::can_parse(&PathBuf::from("/evidence/SAM")));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_svcdiff(Path::new("/nonexistent/SYSTEM"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_svcdiff(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "SYSTEM", "test").is_empty());
    }
}
