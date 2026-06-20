//! WSL (Lxss) distro-registration parser for Issen.
//!
//! `Software\Microsoft\Windows\CurrentVersion\Lxss` (in `NTUSER.DAT`) registers
//! every installed Windows Subsystem for Linux distribution — its GUID, name,
//! base path, version (WSL1/WSL2), and state. A WSL2 distro's `ext4.vhdx` is a
//! self-contained Linux filesystem that can hold attacker tooling outside the
//! reach of Windows-only EDR.
//!
//! Decoding (Lxss subkey walking) is delegated to our own
//! `winreg-artifacts::lxss` (over `winreg-core`) — the registry-artifact home for
//! the fleet — never third-party notatin. The `Lxss` key is hive-relative under
//! `Software\…`, so it resolves against per-user `NTUSER.DAT`; the parser accepts
//! the `SOFTWARE` filename too so it engages on either hive.

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
use issen_core::plugin::selector as sel;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

// ---------------------------------------------------------------------------
// Hive-level parsing
// ---------------------------------------------------------------------------

/// Parse an NTUSER.DAT (or SOFTWARE) hive file for WSL distro registrations.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_lxss(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
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

/// Build WSL distro [`TimelineEvent`]s from raw hive bytes — shared by
/// [`parse_lxss`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::lxss::parse(&hive)
        .into_iter()
        .map(|e| {
            // The Lxss subkey's LastWriteTime ≈ when the distro was registered.
            let (ts_ns, ts_display) = e.last_written.map_or_else(
                || (0, "unknown".to_string()),
                |dt| (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339()),
            );
            let vhdx = e.vhdx_path().map(|p| p.to_string_lossy().into_owned());
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::RegistryModify,
                ArtifactType::Registry,
                format!(
                    "{hive_name}\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss\\{}",
                    e.guid
                ),
                format!(
                    "WSL distro: {} ({:?}/{:?}) at {}",
                    e.distribution_name, e.version, e.state, e.base_path
                ),
                source_id.to_string(),
            )
            .with_metadata("guid", serde_json::json!(e.guid))
            .with_metadata("distribution_name", serde_json::json!(e.distribution_name))
            .with_metadata(
                "package_family_name",
                serde_json::json!(e.package_family_name),
            )
            .with_metadata("base_path", serde_json::json!(e.base_path))
            .with_metadata("state", serde_json::json!(e.state))
            .with_metadata("version", serde_json::json!(e.version))
            .with_metadata("default_uid", serde_json::json!(e.default_uid))
            .with_metadata("is_default", serde_json::json!(e.is_default))
            .with_metadata("vhdx_path", serde_json::json!(vhdx))
            .with_metadata("artifact", serde_json::json!("lxss"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// WSL (Lxss) parser — reads the NTUSER.DAT (HKCU) hive, where the
/// `Software\Microsoft\Windows\CurrentVersion\Lxss` distro registrations live.
pub struct LxssParser;

impl LxssParser {
    /// Return `true` when `path`'s filename is `NTUSER.DAT` or `SOFTWARE`
    /// (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "ntuser.dat" || name == "software"
    }
}

impl ForensicParser for LxssParser {
    fn name(&self) -> &str {
        "WSL Lxss Parser"
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
        let events = events_from_bytes(&bytes, "NTUSER.DAT", "lxss-evidence");
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
    ParserRegistration { create: || Box::new(LxssParser), selector: sel::ArtifactSelector {
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
    fn can_parse_ntuser_hive() {
        assert!(LxssParser::can_parse(&PathBuf::from(
            "/evidence/C/Users/jdoe/NTUSER.DAT"
        )));
    }

    #[test]
    fn can_parse_software_hive() {
        assert!(LxssParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SOFTWARE"
        )));
    }

    #[test]
    fn can_parse_ntuser_lowercase() {
        assert!(LxssParser::can_parse(&PathBuf::from(
            "/evidence/ntuser.dat"
        )));
    }

    #[test]
    fn cannot_parse_sam_hive() {
        assert!(!LxssParser::can_parse(&PathBuf::from("/evidence/SAM")));
    }

    #[test]
    fn cannot_parse_system_hive() {
        assert!(!LxssParser::can_parse(&PathBuf::from("/evidence/SYSTEM")));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_lxss(Path::new("/nonexistent/NTUSER.DAT"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_lxss(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "NTUSER.DAT", "test").is_empty());
    }
}
