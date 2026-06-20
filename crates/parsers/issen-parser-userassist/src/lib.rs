//! UserAssist parser for Issen.
//!
//! The UserAssist key resides in the per-user `NTUSER.DAT` hive under
//! `…\Explorer\UserAssist\{GUID}\Count`. Entries are ROT13-obfuscated program
//! references carrying GUI execution evidence — run/focus counts and a last-run
//! time (MITRE T1204, User Execution).
//!
//! Decoding (GUID enumeration + ROT13 + FILETIME/Count-struct parsing) is
//! delegated to our own `winreg-artifacts::userassist` (over `winreg-core`) —
//! the registry-artifact home for the fleet — never third-party notatin.

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

/// Parse an NTUSER.DAT hive file for UserAssist execution entries.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_userassist(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let bytes = match std::fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(vec![]),
    };
    let hive_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("NTUSER.DAT");
    Ok(events_from_bytes(&bytes, hive_name, source_id))
}

/// Build UserAssist [`TimelineEvent`]s from raw NTUSER.DAT-hive bytes — shared by
/// [`parse_userassist`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::userassist::parse(&hive)
        .into_iter()
        .map(|e| {
            // UserAssist Count entries carry a last-run FILETIME; some entries
            // (or older formats) may not, in which case it stays unknown.
            let (timestamp_ns, timestamp_display) = e
                .last_run
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map_or((0, "unknown".to_string()), |dt| {
                    (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339())
                });

            TimelineEvent::new(
                timestamp_ns,
                timestamp_display,
                EventType::ProcessExec,
                ArtifactType::Registry,
                format!("{hive_name}\\UserAssist\\{}", e.guid),
                format!("UserAssist: {} (run_count={})", e.program, e.run_count),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Execution)
            .with_metadata("program", serde_json::json!(e.program))
            .with_metadata("run_count", serde_json::json!(e.run_count))
            .with_metadata("focus_count", serde_json::json!(e.focus_count))
            .with_metadata("focus_duration_ms", serde_json::json!(e.focus_duration_ms))
            .with_metadata("guid", serde_json::json!(e.guid))
            .with_metadata("artifact", serde_json::json!("userassist"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// UserAssist parser — reads from the per-user NTUSER.DAT hive.
pub struct UserAssistParser;

impl UserAssistParser {
    /// Return `true` when `path`'s filename is `ntuser.dat` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "ntuser.dat"
    }
}

impl ForensicParser for UserAssistParser {
    fn name(&self) -> &'static str {
        "UserAssist Parser"
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
        // Truncate to bytes actually read — a short read (FUSE/remote/interrupted)
        // must not feed trailing zeros downstream (mirror issen-parser-registry).
        let events = events_from_bytes(&bytes[..off as usize], "NTUSER.DAT", "userassist-evidence");
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
    ParserRegistration { create: || Box::new(UserAssistParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn can_parse_ntuser_dat() {
        assert!(UserAssistParser::can_parse(&PathBuf::from(
            "/evidence/C/Users/alice/NTUSER.DAT"
        )));
    }

    #[test]
    fn can_parse_ntuser_dat_lowercase() {
        assert!(UserAssistParser::can_parse(&PathBuf::from(
            "/evidence/ntuser.dat"
        )));
    }

    #[test]
    fn cannot_parse_system_hive() {
        assert!(!UserAssistParser::can_parse(&PathBuf::from(
            "/evidence/SYSTEM"
        )));
    }

    #[test]
    fn cannot_parse_sam_hive() {
        assert!(!UserAssistParser::can_parse(&PathBuf::from(
            "/evidence/SAM"
        )));
    }

    #[test]
    fn cannot_parse_amcache() {
        assert!(!UserAssistParser::can_parse(&PathBuf::from(
            "/evidence/Amcache.hve"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_userassist(Path::new("/nonexistent/NTUSER.DAT"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_userassist(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
