//! LSA / DCC2 cached-credential slot parser for Issen.
//!
//! The SECURITY hive's `Cache` subkey holds Domain Cached Credentials v2 (DCC2)
//! slots (`NL$1`..`NL$10`) — cached domain logon verifiers an attacker can crack
//! offline (MITRE ATT&CK T1003.005 — OS Credential Dumping: Cached Domain
//! Credentials). This parser enumerates slot *occupancy* (name, populated, size);
//! it does NOT decrypt — that needs the SYSTEM boot key and is out of scope.
//!
//! Decoding (DCC2 slot enumeration) is delegated to our own
//! `winreg-artifacts::lsadump` (over `winreg-core`) — the registry-artifact home
//! for the fleet — never third-party notatin.

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
use issen_core::classify;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

// ---------------------------------------------------------------------------
// Hive-level parsing
// ---------------------------------------------------------------------------

/// Parse a SECURITY hive file for DCC2 cached-credential cache slots.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_dcc2(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let bytes = match std::fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(vec![]),
    };
    let hive_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("SECURITY");
    Ok(events_from_bytes(&bytes, hive_name, source_id))
}

/// Build DCC2 slot [`TimelineEvent`]s from raw hive bytes — shared by
/// [`parse_dcc2`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::lsadump::parse_dcc2_slots(&hive)
        .into_iter()
        .map(|e| {
            // The cache slot key's LastWriteTime ≈ when the verifier was cached.
            let (ts_ns, ts_display) = e.last_written.map_or_else(
                || (0, "unknown".to_string()),
                |dt| (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339()),
            );
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::RegistryModify,
                ArtifactType::Registry,
                format!("{hive_name}\\Cache\\{}", e.slot_name),
                format!(
                    "DCC2 cache slot {} ({}, {} bytes)",
                    e.slot_name,
                    if e.is_populated { "populated" } else { "empty" },
                    e.data_size
                ),
                source_id.to_string(),
            )
            .with_metadata("slot_name", serde_json::json!(e.slot_name))
            .with_metadata("is_populated", serde_json::json!(e.is_populated))
            .with_metadata("data_size", serde_json::json!(e.data_size))
            .with_metadata("artifact", serde_json::json!("dcc2"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// LSA / DCC2 parser — reads the SECURITY hive, where the DCC2 cache slots
/// (`SECURITY\Cache\NL$n`) live.
pub struct Dcc2Parser;

impl Dcc2Parser {
    /// Return `true` when `path`'s filename is `SECURITY` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("security"))
    }
}

impl ForensicParser for Dcc2Parser {
    fn name(&self) -> &str {
        "LSA DCC2 Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Registry]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
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
        let events = events_from_bytes(&bytes, "SECURITY", "dcc2-evidence");
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
    ParserRegistration { create: || Box::new(Dcc2Parser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::Registry,
            matches: classify::registry_hive,
            priority: 96,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        } }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn can_parse_security_hive() {
        assert!(Dcc2Parser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SECURITY"
        )));
    }

    #[test]
    fn can_parse_security_lowercase() {
        assert!(Dcc2Parser::can_parse(&PathBuf::from("/evidence/security")));
    }

    #[test]
    fn cannot_parse_system_hive() {
        assert!(!Dcc2Parser::can_parse(&PathBuf::from("/evidence/SYSTEM")));
    }

    #[test]
    fn cannot_parse_ntuser_hive() {
        assert!(!Dcc2Parser::can_parse(&PathBuf::from(
            "/evidence/NTUSER.DAT"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_dcc2(Path::new("/nonexistent/SECURITY"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_dcc2(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "SECURITY", "test").is_empty());
    }
}
