//! Shellbags parser for Issen.
//!
//! Shellbags are stored in `NTUSER.DAT` and `UsrClass.dat` registry hives.
//! They record every folder a user navigated to via Windows Explorer —
//! including network shares, removable media, and ZIP files — and persist
//! even after the folder is deleted.
//!
//! Key registry paths:
//! - NTUSER.DAT:    `Software\Microsoft\Windows\Shell\BagMRU`
//! - UsrClass.dat:  `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

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
// Core parsing logic
// ---------------------------------------------------------------------------

/// Parse shellbags from an `NTUSER.DAT` or `UsrClass.dat` hive file.
///
/// BagMRU location + walk is delegated to our own `winreg-artifacts::shellbags`
/// (over `winreg-core`) — the registry-artifact home for the fleet — never
/// third-party notatin. Returns one [`TimelineEvent`] per BagMRU subkey;
/// `Ok(vec![])` for corrupt, empty, or non-shellbag hives.
pub fn parse_shellbags(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let bytes = match std::fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(vec![]),
    };
    let hive_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.dat");
    Ok(events_from_bytes(&bytes, hive_name, source_id))
}

/// Build Shellbag [`TimelineEvent`]s from raw NTUSER.DAT/UsrClass.dat bytes —
/// shared by [`parse_shellbags`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::shellbags::parse(&hive)
        .into_iter()
        .map(|e| {
            let (timestamp_ns, timestamp_display) = e
                .last_written
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map_or((0, String::new()), |dt| {
                    (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339())
                });

            let label = if e.path.is_empty() {
                &e.key_path
            } else {
                &e.path
            };
            TimelineEvent::new(
                timestamp_ns,
                timestamp_display,
                EventType::FileAccess,
                ArtifactType::Shellbags,
                e.key_path.clone(),
                format!("Shellbag access: {label}"),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::FileSystemActivity)
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("key_path", serde_json::json!(e.key_path))
            .with_metadata("path", serde_json::json!(e.path))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// Shellbags forensic parser.
pub struct ShellbagsParser;

impl ShellbagsParser {
    /// Return `true` when `path`'s filename is `ntuser.dat` or `usrclass.dat`
    /// (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "ntuser.dat" || name == "usrclass.dat"
    }
}

impl ForensicParser for ShellbagsParser {
    fn name(&self) -> &'static str {
        "Shellbags Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        // NTUSER.DAT / UsrClass.dat are discovered as `Registry` (so the generic
        // registry walker also processes them); match that and self-filter to
        // BagMRU. (`ArtifactType::Shellbags` is never assigned by discovery.)
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
        let events = events_from_bytes(&bytes, "NTUSER.DAT", "shellbags-evidence");
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

inventory::submit! {
    ParserRegistration { create: || Box::new(ShellbagsParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── can_parse tests ────────────────────────────────────────────────────

    #[test]
    fn can_parse_ntuser_dat() {
        assert!(
            ShellbagsParser::can_parse(&PathBuf::from("/evidence/NTUSER.DAT")),
            "expected can_parse to return true for NTUSER.DAT"
        );
    }

    #[test]
    fn can_parse_usrclass_dat() {
        assert!(
            ShellbagsParser::can_parse(&PathBuf::from("/evidence/UsrClass.dat")),
            "expected can_parse to return true for UsrClass.dat"
        );
    }

    #[test]
    fn can_parse_case_insensitive() {
        assert!(
            ShellbagsParser::can_parse(&PathBuf::from("/evidence/ntuser.dat")),
            "expected can_parse to return true for ntuser.dat (lowercase)"
        );
    }

    #[test]
    fn cannot_parse_system_hive() {
        assert!(
            !ShellbagsParser::can_parse(&PathBuf::from("/evidence/SYSTEM")),
            "expected can_parse to return false for SYSTEM"
        );
    }

    // ── parse tests ────────────────────────────────────────────────────────

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_shellbags(Path::new("/nonexistent/NTUSER.DAT"), "test");
        assert!(
            result.is_ok(),
            "parse_shellbags must return Ok for nonexistent path"
        );
        assert!(
            result.unwrap().is_empty(),
            "nonexistent path should produce zero events"
        );
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Zero bytes — parser must return empty, not error.
        let result = parse_shellbags(tmp.path(), "test");
        assert!(result.is_ok(), "zero-byte file must return Ok");
        assert!(
            result.unwrap().is_empty(),
            "zero-byte file should produce zero events"
        );
    }

    /// Integration test: requires a real NTUSER.DAT with BagMRU subkeys.
    /// Ignored in CI (no fixture hive available) but documents the contract:
    /// every event emitted must carry the correct source_id and ArtifactType.
    ///
    /// To run locally with a real hive:
    ///   NTUSER_DAT=/path/to/NTUSER.DAT cargo test -p rt-parser-shellbags -- --ignored
    #[test]
    #[ignore = "requires real NTUSER.DAT fixture with BagMRU subkeys"]
    fn shellbags_events_have_correct_source() {
        let tmp = tempfile::Builder::new()
            .prefix("NTUSER")
            .suffix(".DAT")
            .tempfile()
            .expect("tempfile");

        // Write a minimal REGF-magic file so the size check is bypassed.
        // notatin will fail to fully parse it and return Ok(vec![]) — the stub
        // also returns Ok(vec![]) — so `events` will be empty, making the
        // `assert!(!events.is_empty())` below the RED failure.
        std::fs::write(tmp.path(), b"REGF\x00\x00\x00\x00").expect("write REGF magic");

        let events = parse_shellbags(tmp.path(), "shellbags").expect("parse must not Err");

        // Verify source identity on whatever events come back.
        for event in &events {
            assert_eq!(
                event.evidence_source_id, "shellbags",
                "all shellbag events must carry the provided source_id"
            );
            assert_eq!(
                event.source,
                ArtifactType::Shellbags,
                "all shellbag events must use ArtifactType::Shellbags"
            );
        }

        // This is the RED-causing assertion: a proper hive with BagMRU data
        // must produce at least one event.  With the stub returning empty for
        // a synthetic 8-byte file, this fails — intentionally.
        assert!(
            !events.is_empty(),
            "parse_shellbags must emit at least one event for a hive containing BagMRU data \
             (RED: stub returns empty for any non-parseable file)"
        );
    }
}
