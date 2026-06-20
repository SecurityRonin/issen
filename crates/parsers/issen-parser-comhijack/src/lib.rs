//! COM object-hijacking persistence parser for Issen.
//!
//! Malware can register a user-side `Software\Classes\CLSID\{guid}\InprocServer32`
//! in `NTUSER.DAT` (HKCU) that overrides the system-wide HKCR registration, so a
//! COM client loads an attacker DLL without admin rights (MITRE ATT&CK
//! T1546.015 — Event Triggered Execution: Component Object Model Hijacking).
//!
//! Decoding (CLSID `InprocServer32` walking + writable-path heuristics) is
//! delegated to our own `winreg-artifacts::com_hijacking` (over `winreg-core`) —
//! the registry-artifact home for the fleet — never third-party notatin.
//!
//! The user-side overrides live in `NTUSER.DAT`; the system-wide registrations
//! live in `SOFTWARE` (HKCR). This parser reads a single hive, so it surfaces the
//! HKCU-only view via `parse_hkcu_only` — the override candidates that matter for
//! persistence — and accepts both filenames so it engages on either hive.

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

/// Parse an NTUSER.DAT (or SOFTWARE) hive for COM-hijack CLSID overrides.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_com_hijacking(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
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

/// Build COM-hijack [`TimelineEvent`]s from raw hive bytes — shared by
/// [`parse_com_hijacking`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::com_hijacking::parse_hkcu_only(&hive)
        .into_iter()
        .map(|e| {
            // The CLSID key's LastWriteTime ≈ when the COM hijack was registered.
            let (ts_ns, ts_display) = e.last_written.map_or_else(
                || (0, "unknown".to_string()),
                |dt| (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339()),
            );
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::RegistryModify,
                ArtifactType::Registry,
                format!(
                    "{hive_name}\\Software\\Classes\\CLSID\\{}\\InprocServer32",
                    e.clsid
                ),
                format!("COM hijack: CLSID {} -> {}", e.clsid, e.hkcu_server),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Persistence)
            .with_metadata("clsid", serde_json::json!(e.clsid))
            .with_metadata("hkcu_server", serde_json::json!(e.hkcu_server))
            .with_metadata("hkcr_server", serde_json::json!(e.hkcr_server))
            .with_metadata("is_suspicious", serde_json::json!(e.is_suspicious))
            .with_metadata("suspicious_reason", serde_json::json!(e.suspicious_reason))
            .with_metadata("artifact", serde_json::json!("com_hijacking"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// COM-hijack parser — reads NTUSER.DAT (HKCU overrides) and SOFTWARE (HKCR
/// registrations), where COM object-hijacking persistence values live.
pub struct ComHijackParser;

impl ComHijackParser {
    /// Return `true` when `path`'s filename is `NTUSER.DAT`, `SOFTWARE`, or
    /// `UsrClass.dat` (case-insensitive) — COM CLSID registrations live in all
    /// three; on Win10 the per-user CLSID tree is in `UsrClass.dat`.
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "ntuser.dat" || name == "software" || name == "usrclass.dat"
    }
}

impl ForensicParser for ComHijackParser {
    fn name(&self) -> &str {
        "COM Hijack Parser"
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
        let events = events_from_bytes(&bytes, "NTUSER.DAT", "comhijack-evidence");
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
    ParserRegistration { create: || Box::new(ComHijackParser), selector: sel::ArtifactSelector {
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
        assert!(ComHijackParser::can_parse(&PathBuf::from(
            "/evidence/C/Users/jdoe/NTUSER.DAT"
        )));
    }

    #[test]
    fn can_parse_software_hive() {
        assert!(ComHijackParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SOFTWARE"
        )));
    }

    #[test]
    fn can_parse_ntuser_lowercase() {
        assert!(ComHijackParser::can_parse(&PathBuf::from(
            "/evidence/ntuser.dat"
        )));
    }

    #[test]
    fn can_parse_usrclass_hive() {
        // Win10 per-user CLSID lives in UsrClass.dat — comhijack must route it.
        assert!(ComHijackParser::can_parse(&PathBuf::from(
            "/evidence/C/Users/ricksanchez/AppData/Local/Microsoft/Windows/UsrClass.dat"
        )));
    }

    #[test]
    fn cannot_parse_sam_hive() {
        assert!(!ComHijackParser::can_parse(&PathBuf::from("/evidence/SAM")));
    }

    #[test]
    fn cannot_parse_security_hive() {
        assert!(!ComHijackParser::can_parse(&PathBuf::from(
            "/evidence/SECURITY"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_com_hijacking(Path::new("/nonexistent/NTUSER.DAT"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_com_hijacking(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "NTUSER.DAT", "test").is_empty());
    }
}
