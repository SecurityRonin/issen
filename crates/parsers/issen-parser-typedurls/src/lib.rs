//! IE/Edge `TypedURLs` web-activity parser for Issen.
//!
//! `Software\Microsoft\Internet Explorer\TypedURLs` in `NTUSER.DAT` records URLs
//! typed directly into the IE/Edge address bar; the companion `TypedURLsTime` key
//! carries a FILETIME per URL. Typed URLs are a high-value web-activity artifact
//! (deliberate navigation, not a passive reference).
//!
//! Decoding (TypedURLs + TypedURLsTime walking, FILETIME → ISO 8601, suspicious-
//! domain heuristics) is delegated to our own `winreg-artifacts::typed_urls` (over
//! `winreg-core`) — the registry-artifact home for the fleet — never third-party
//! notatin. The decoder surfaces `last_visited` as an ISO-8601 string, which this
//! parser converts into a real `timestamp_ns` on the [`TimelineEvent`].

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

use chrono::{DateTime, Utc};
use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

/// Convert an ISO-8601 / RFC-3339 timestamp string (the `TypedURLsTime` FILETIME
/// rendered by the decoder, e.g. `2021-03-04T05:06:07Z`) into nanoseconds since
/// the Unix epoch. Returns `None` if the string is unparseable.
#[must_use]
pub fn iso8601_to_ns(s: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
        .and_then(|dt| dt.timestamp_nanos_opt())
}

// ---------------------------------------------------------------------------
// Hive-level parsing
// ---------------------------------------------------------------------------

/// Parse an NTUSER.DAT hive file for IE/Edge `TypedURLs` entries.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_typedurls(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
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

/// Build `TypedURLs` [`TimelineEvent`]s from raw hive bytes — shared by
/// [`parse_typedurls`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::typed_urls::parse(&hive)
        .into_iter()
        .map(|e| {
            // The companion TypedURLsTime FILETIME (when present) becomes the
            // event timestamp; otherwise fall back to 0 / "unknown".
            let ts_ns = e
                .last_visited
                .as_deref()
                .and_then(iso8601_to_ns)
                .unwrap_or(0);
            let ts_display = e
                .last_visited
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::RegistryModify,
                ArtifactType::Registry,
                format!("{hive_name}\\Software\\Microsoft\\Internet Explorer\\TypedURLs"),
                format!("TypedURL: {}", e.url),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::BrowserActivity)
            .with_metadata("url", serde_json::json!(e.url))
            .with_metadata("last_visited", serde_json::json!(e.last_visited))
            .with_metadata("is_suspicious", serde_json::json!(e.is_suspicious))
            .with_metadata("suspicious_reason", serde_json::json!(e.suspicious_reason))
            .with_metadata("artifact", serde_json::json!("typed_urls"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// IE/Edge TypedURLs parser — reads the NTUSER.DAT hive (HKCU), where the
/// address-bar typed-URL history lives.
pub struct TypedUrlsParser;

impl TypedUrlsParser {
    /// Return `true` when `path`'s filename is `NTUSER.DAT` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("ntuser.dat"))
    }
}

impl ForensicParser for TypedUrlsParser {
    fn name(&self) -> &str {
        "TypedURLs Parser"
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
        let events = events_from_bytes(&bytes, "NTUSER.DAT", "typedurls-evidence");
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
    ParserRegistration { create: || Box::new(TypedUrlsParser), selector: sel::ArtifactSelector {
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
        assert!(TypedUrlsParser::can_parse(&PathBuf::from(
            "/evidence/C/Users/jdoe/NTUSER.DAT"
        )));
    }

    #[test]
    fn can_parse_ntuser_lowercase() {
        assert!(TypedUrlsParser::can_parse(&PathBuf::from(
            "/evidence/ntuser.dat"
        )));
    }

    #[test]
    fn cannot_parse_software_hive() {
        assert!(!TypedUrlsParser::can_parse(&PathBuf::from(
            "/evidence/SOFTWARE"
        )));
    }

    #[test]
    fn cannot_parse_system_hive() {
        assert!(!TypedUrlsParser::can_parse(&PathBuf::from(
            "/evidence/SYSTEM"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_typedurls(Path::new("/nonexistent/NTUSER.DAT"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_typedurls(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "NTUSER.DAT", "test").is_empty());
    }

    #[test]
    fn iso8601_parses_to_timestamp_ns() {
        // The companion `TypedURLsTime` FILETIME is surfaced as ISO 8601 by the
        // decoder; the parser must convert it to a real `timestamp_ns`.
        let ns = iso8601_to_ns("2021-03-04T05:06:07Z").expect("valid ISO 8601");
        assert!(ns > 0);
    }

    #[test]
    fn iso8601_rejects_garbage() {
        assert!(iso8601_to_ns("not-a-date").is_none());
    }
}
