//! SAM local-account parser for Issen.
//!
//! The SAM (`Security Account Manager`) registry hive holds local user
//! accounts under `SAM\Domains\Account\Users`. Each account contributes its
//! username, RID, last-login / password-last-set timestamps, login count, and
//! account-control flags (disabled / locked).
//!
//! Decoding (RID enumeration + `F`-record FILETIME / flag extraction) is
//! delegated to our own `winreg-artifacts::sam` (over `winreg-core`) — the
//! registry-artifact home for the fleet — never third-party notatin.

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

/// Parse a SAM hive file for local user accounts.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_sam(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let bytes = match std::fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(vec![]),
    };
    let hive_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("SAM");
    Ok(events_from_bytes(&bytes, hive_name, source_id))
}

/// Build SAM [`TimelineEvent`]s from raw SAM-hive bytes — shared by
/// [`parse_sam`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::sam::parse(&hive)
        .into_iter()
        .map(|e| {
            // Primary timestamp is the account's last interactive logon
            // (`F`-record FILETIME); accounts that never logged in stay unknown.
            let (timestamp_ns, timestamp_display) = e
                .last_login
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map_or((0, "unknown".to_string()), |dt| {
                    (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339())
                });

            TimelineEvent::new(
                timestamp_ns,
                timestamp_display,
                EventType::UserAccountChange,
                ArtifactType::Registry,
                format!("{hive_name}\\SAM\\Users\\{}", e.rid),
                format!("SAM account: {} (RID {})", e.username, e.rid),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::AccountActivity)
            .with_metadata("username", serde_json::json!(e.username))
            .with_metadata("rid", serde_json::json!(e.rid))
            .with_metadata("last_login", serde_json::json!(e.last_login))
            .with_metadata("password_last_set", serde_json::json!(e.password_last_set))
            .with_metadata("account_expires", serde_json::json!(e.account_expires))
            .with_metadata("login_count", serde_json::json!(e.login_count))
            .with_metadata("account_flags", serde_json::json!(e.account_flags))
            .with_metadata("is_disabled", serde_json::json!(e.is_disabled))
            .with_metadata("is_locked", serde_json::json!(e.is_locked))
            .with_metadata("artifact", serde_json::json!("sam"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// SAM local-account parser — reads from the SAM hive.
pub struct SamParser;

impl SamParser {
    /// Return `true` when `path`'s filename is `SAM` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "sam"
    }
}

impl ForensicParser for SamParser {
    fn name(&self) -> &'static str {
        "SAM Parser"
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
        let events = events_from_bytes(&bytes, "SAM", "sam-evidence");
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
    ParserRegistration { create: || Box::new(SamParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn can_parse_sam_hive() {
        assert!(SamParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SAM"
        )));
    }

    #[test]
    fn can_parse_sam_hive_lowercase() {
        assert!(SamParser::can_parse(&PathBuf::from("/evidence/sam")));
    }

    #[test]
    fn cannot_parse_system_hive() {
        assert!(!SamParser::can_parse(&PathBuf::from("/evidence/SYSTEM")));
    }

    #[test]
    fn cannot_parse_software_hive() {
        assert!(!SamParser::can_parse(&PathBuf::from("/evidence/SOFTWARE")));
    }

    #[test]
    fn cannot_parse_amcache() {
        assert!(!SamParser::can_parse(&PathBuf::from(
            "/evidence/Amcache.hve"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_sam(Path::new("/nonexistent/SAM"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_sam(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
