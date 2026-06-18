//! LSA secrets parser for Issen.
//!
//! The SECURITY hive's `Policy\Secrets` subkey holds LSA secrets — service-account
//! passwords, the machine account (`$MACHINE.ACC`), the DPAPI system master-key
//! protector (`DPAPI_SYSTEM`), the DCC2 key (`NL$KM`), and auto-logon
//! (`DefaultPassword`) (MITRE ATT&CK T1003.004 — OS Credential Dumping: LSA
//! Secrets). This parser enumerates secret *names + sizes* (`CurrVal`/`OldVal`
//! presence); it does NOT decrypt — that needs the SYSTEM boot key and live LSA
//! crypto, which is out of scope for offline registry parsing.
//!
//! Decoding (secret enumeration) is delegated to our own
//! `winreg-artifacts::lsadump::parse_secrets` (over `winreg-core`) — the
//! registry-artifact home for the fleet — never third-party notatin. Sibling
//! parser `issen-parser-dcc2` covers the DCC2 cache (`SECURITY\Cache`, T1003.005).

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

/// Parse a SECURITY hive file for LSA secrets (`Policy\Secrets`).
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_lsasecrets(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
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

/// Build LSA-secret [`TimelineEvent`]s from raw hive bytes — shared by
/// [`parse_lsasecrets`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::lsadump::parse_secrets(&hive)
        .into_iter()
        .map(|e| {
            // LSA secrets carry no per-value timestamp.
            TimelineEvent::new(
                0,
                "unknown".to_string(),
                EventType::RegistryModify,
                ArtifactType::Registry,
                format!("{hive_name}\\Policy\\Secrets\\{}", e.name),
                format!(
                    "LSA secret {} (CurrVal {} bytes, OldVal {} bytes{})",
                    e.name,
                    e.curr_size,
                    e.old_size,
                    if e.is_interesting {
                        ", interesting"
                    } else {
                        ""
                    }
                ),
                source_id.to_string(),
            )
            .with_metadata("secret_name", serde_json::json!(e.name))
            .with_metadata("has_current", serde_json::json!(e.has_current))
            .with_metadata("has_old", serde_json::json!(e.has_old))
            .with_metadata("curr_size", serde_json::json!(e.curr_size))
            .with_metadata("old_size", serde_json::json!(e.old_size))
            .with_metadata("is_interesting", serde_json::json!(e.is_interesting))
            .with_metadata("artifact", serde_json::json!("lsa_secrets"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// LSA secrets parser — reads the SECURITY hive, where the LSA secrets
/// (`SECURITY\Policy\Secrets`) live.
pub struct LsaSecretsParser;

impl LsaSecretsParser {
    /// Return `true` when `path`'s filename is `SECURITY` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("security"))
    }
}

impl ForensicParser for LsaSecretsParser {
    fn name(&self) -> &str {
        "LSA Secrets Parser"
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
        let events = events_from_bytes(&bytes, "SECURITY", "lsasecrets-evidence");
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
    ParserRegistration { create: || Box::new(LsaSecretsParser) }
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
        assert!(LsaSecretsParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SECURITY"
        )));
    }

    #[test]
    fn cannot_parse_system_hive() {
        assert!(!LsaSecretsParser::can_parse(&PathBuf::from(
            "/evidence/SYSTEM"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_lsasecrets(Path::new("/nonexistent/SECURITY"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "SECURITY", "test").is_empty());
    }
}
