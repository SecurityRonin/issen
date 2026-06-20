//! Run / RunOnce autostart-persistence parser for Issen.
//!
//! Run and RunOnce keys live in the `SOFTWARE` hive (HKLM) and every user's
//! `NTUSER.DAT` (HKCU) under `…\Microsoft\Windows\CurrentVersion\Run[Once]`.
//! A value there names a program executed automatically at logon — the most
//! common autostart-persistence mechanism (MITRE ATT&CK T1547.001).
//!
//! Decoding (Run/RunOnce key walking + suspicious-command heuristics) is
//! delegated to our own `winreg-artifacts::run_keys` (over `winreg-core`) —
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

/// Parse a SOFTWARE or NTUSER.DAT hive file for Run / RunOnce entries.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_runkeys(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let bytes = match std::fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(vec![]),
    };
    let hive_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("SOFTWARE");
    Ok(events_from_bytes(&bytes, hive_name, source_id))
}

/// Build Run-key [`TimelineEvent`]s from raw hive bytes — shared by
/// [`parse_runkeys`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::run_keys::parse(&hive)
        .into_iter()
        .map(|e| {
            // The Run key's LastWriteTime ≈ when the autostart value was set.
            let (ts_ns, ts_display) = e.last_written.map_or_else(
                || (0, "unknown".to_string()),
                |dt| (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339()),
            );
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::RegistryModify,
                ArtifactType::Registry,
                format!("{hive_name}\\{}", e.key_path),
                format!("Run key: {} = {}", e.value_name, e.command),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Persistence)
            .with_metadata("hive", serde_json::json!(e.hive))
            .with_metadata("key_path", serde_json::json!(e.key_path))
            .with_metadata("value_name", serde_json::json!(e.value_name))
            .with_metadata("command", serde_json::json!(e.command))
            .with_metadata("is_suspicious", serde_json::json!(e.is_suspicious))
            .with_metadata("suspicious_reason", serde_json::json!(e.suspicious_reason))
            .with_metadata("artifact", serde_json::json!("run_keys"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// Run / RunOnce parser — reads from the SOFTWARE (HKLM) and NTUSER.DAT (HKCU)
/// hives, where autostart-persistence values live.
pub struct RunKeysParser;

impl RunKeysParser {
    /// Return `true` when `path`'s filename is `SOFTWARE` or `NTUSER.DAT`
    /// (case-insensitive) — Run keys live in both HKLM and HKCU.
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "software" || name == "ntuser.dat"
    }
}

impl ForensicParser for RunKeysParser {
    fn name(&self) -> &'static str {
        "Run Keys Parser"
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
        let events = events_from_bytes(&bytes[..off as usize], "SOFTWARE", "runkeys-evidence");
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
    ParserRegistration { create: || Box::new(RunKeysParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn can_parse_software_hive() {
        assert!(RunKeysParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SOFTWARE"
        )));
    }

    #[test]
    fn can_parse_ntuser_hive() {
        assert!(RunKeysParser::can_parse(&PathBuf::from(
            "/evidence/C/Users/jdoe/NTUSER.DAT"
        )));
    }

    #[test]
    fn can_parse_software_lowercase() {
        assert!(RunKeysParser::can_parse(&PathBuf::from(
            "/evidence/software"
        )));
    }

    #[test]
    fn cannot_parse_sam_hive() {
        assert!(!RunKeysParser::can_parse(&PathBuf::from("/evidence/SAM")));
    }

    #[test]
    fn cannot_parse_amcache() {
        assert!(!RunKeysParser::can_parse(&PathBuf::from(
            "/evidence/Amcache.hve"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_runkeys(Path::new("/nonexistent/SOFTWARE"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_runkeys(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
