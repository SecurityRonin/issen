//! AppCompatCache (Shimcache) parser for Issen.
//!
//! The Shimcache resides in the `SYSTEM` registry hive under
//! `…\Control\Session Manager\AppCompatCache` value `AppCompatCache`.
//! Presence of a path in Shimcache proves the binary existed on disk; it does
//! NOT prove execution (use Prefetch or AmCache for that).
//!
//! Decoding (ControlSet selection + AppCompatCache blob parsing across Win
//! versions) is delegated to our own `winreg-artifacts::shimcache` (over
//! `winreg-core`) — the registry-artifact home for the fleet — never
//! third-party notatin.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

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

/// Parse a SYSTEM hive file for AppCompatCache (Shimcache) entries.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_shimcache(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
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

/// Build Shimcache [`TimelineEvent`]s from raw SYSTEM-hive bytes — shared by
/// [`parse_shimcache`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };
    let artifact_path = format!("{hive_name}\\AppCompatCache");

    winreg_artifacts::shimcache::parse(&hive)
        .into_iter()
        .map(|e| {
            // Win8+ entries carry a per-entry last-modified ($SI mtime); older
            // formats may not, in which case it stays unknown.
            let (timestamp_ns, timestamp_display) = e
                .last_modified
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map_or((0, "unknown".to_string()), |dt| {
                    (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339())
                });

            TimelineEvent::new(
                timestamp_ns,
                timestamp_display,
                EventType::FileAccess,
                ArtifactType::Registry,
                artifact_path.clone(),
                format!("Shimcache: {}", e.path),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Execution)
            .with_metadata("path", serde_json::json!(e.path))
            .with_metadata("entry_index", serde_json::json!(e.entry_index))
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("artifact", serde_json::json!("shimcache"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// AppCompatCache (Shimcache) parser — reads from the SYSTEM hive.
pub struct ShimcacheParser;

impl ShimcacheParser {
    /// Return `true` when `path`'s filename is `SYSTEM` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "system"
    }
}

impl ForensicParser for ShimcacheParser {
    fn name(&self) -> &'static str {
        "Shimcache Parser"
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
        let events = events_from_bytes(&bytes, "SYSTEM", "shimcache-evidence");
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
    ParserRegistration { create: || Box::new(ShimcacheParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn can_parse_system_hive() {
        assert!(ShimcacheParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SYSTEM"
        )));
    }

    #[test]
    fn can_parse_system_hive_lowercase() {
        assert!(ShimcacheParser::can_parse(&PathBuf::from(
            "/evidence/system"
        )));
    }

    #[test]
    fn cannot_parse_software_hive() {
        assert!(!ShimcacheParser::can_parse(&PathBuf::from(
            "/evidence/SOFTWARE"
        )));
    }

    #[test]
    fn cannot_parse_amcache() {
        assert!(!ShimcacheParser::can_parse(&PathBuf::from(
            "/evidence/Amcache.hve"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_shimcache(Path::new("/nonexistent/SYSTEM"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_shimcache(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
