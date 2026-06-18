//! SetupAPI log parser for Issen.
//!
//! Parses `setupapi.dev.log` (Vista+) and `setupapi.log` (XP) files and
//! emits [`TimelineEvent`]s for each USB/device installation event.
//!
//! Forensic value: USB device first-connect timestamps survive even after
//! registry entries are wiped, as setupapi logs record the exact moment
//! every device driver was installed.
//!
//! Vista+ format:
//! ```text
//! [Device Install (Hardware initiated) - USB\VID_0781&PID_5583\... 2023/04/15 14:23:11.456]
//! ```
//!
//! XP format:
//! ```text
//! [2005/05/12 12:34:56 1234.5678] Device Install - ...
//! ```

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use std::path::Path;

use chrono::{NaiveDateTime, TimeZone, Utc};
use issen_core::artifacts::ArtifactType;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use regex::Regex;

// ---------------------------------------------------------------------------
// Timestamp parsing helpers
// ---------------------------------------------------------------------------

/// Parse a `YYYY/MM/DD HH:MM:SS.mmm` timestamp string to (nanoseconds,
/// display string), treating the timestamp as UTC.
///
/// Note: setupapi logs record local time with no embedded timezone offset.
/// Callers that know the system's local offset can correct after parsing.
fn parse_setupapi_timestamp(s: &str) -> Option<(i64, String)> {
    let fmt_ms = "%Y/%m/%d %H:%M:%S%.3f";
    let fmt_plain = "%Y/%m/%d %H:%M:%S";

    let naive = NaiveDateTime::parse_from_str(s.trim(), fmt_ms)
        .or_else(|_| NaiveDateTime::parse_from_str(s.trim(), fmt_plain))
        .ok()?;

    let dt = Utc.from_utc_datetime(&naive);
    let ns = dt.timestamp_nanos_opt()?;
    Some((ns, dt.to_rfc3339()))
}

// ---------------------------------------------------------------------------
// Core parsing logic
// ---------------------------------------------------------------------------

/// Parse a setupapi log file, returning one [`TimelineEvent`] per device
/// install section header line.
///
/// Handles both Vista+ (`setupapi.dev.log`) and XP (`setupapi.log`) formats.
/// Returns `Ok(vec![])` for nonexistent, empty, or non-matching files.
pub fn parse_setupapi(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    // Nonexistent / unreadable files — return empty without error.
    let Ok(raw) = std::fs::read(path) else {
        return Ok(vec![]);
    };
    let content = String::from_utf8_lossy(&raw);
    Ok(parse_setupapi_str(
        &content,
        &path.to_string_lossy(),
        source_id,
    ))
}

/// Parse SetupAPI log text into device-install timeline events.
///
/// The text-level core shared by the path-based [`parse_setupapi`] and the
/// `ForensicParser` trait impl (which reads bytes from a `DataSource` and has no
/// file path of its own). `artifact_path` labels the events; `source_id` tags
/// their source. The header regexes are constant and valid; on the impossible
/// compile failure this yields no events rather than panicking.
#[must_use]
pub fn parse_setupapi_str(
    content: &str,
    artifact_path: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    // Vista+ pattern: line starts with `[`, description first, timestamp last.
    //   group 1 — description; group 2 — timestamp (YYYY/MM/DD HH:MM:SS[.mmm]).
    let Ok(vista_re) =
        Regex::new(r"^\[(.+?)\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]")
    else {
        return Vec::new();
    };
    // XP pattern: timestamp first inside brackets.
    let Ok(xp_re) =
        Regex::new(r"^\[(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+[^\]]+\]\s*(.*)")
    else {
        return Vec::new();
    };

    let mut events: Vec<TimelineEvent> = Vec::new();
    let artifact_path = artifact_path.to_string();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('[') {
            continue;
        }

        // Try Vista+ format first (most common).
        if let Some(caps) = vista_re.captures(trimmed) {
            let description_raw = caps.get(1).map_or("", |m| m.as_str()).trim();
            let ts_str = caps.get(2).map_or("", |m| m.as_str());

            if let Some((timestamp_ns, timestamp_display)) = parse_setupapi_timestamp(ts_str) {
                let description = format!("Device install: {description_raw}");
                let event = TimelineEvent::new(
                    timestamp_ns,
                    timestamp_display,
                    EventType::Other("DeviceInstall".to_string()),
                    ArtifactType::Registry,
                    artifact_path.clone(),
                    description,
                    source_id.to_string(),
                )
                .with_metadata("log_line", serde_json::json!(trimmed))
                .with_metadata("log_format", serde_json::json!("vista"));

                events.push(event);
                continue;
            }
        }

        // Try XP format.
        if let Some(caps) = xp_re.captures(trimmed) {
            let ts_str = caps.get(1).map_or("", |m| m.as_str());
            let description_raw = caps.get(2).map_or("", |m| m.as_str()).trim();

            if let Some((timestamp_ns, timestamp_display)) = parse_setupapi_timestamp(ts_str) {
                let description = if description_raw.is_empty() {
                    "Device install (XP)".to_string()
                } else {
                    format!("Device install: {description_raw}")
                };
                let event = TimelineEvent::new(
                    timestamp_ns,
                    timestamp_display,
                    EventType::Other("DeviceInstall".to_string()),
                    ArtifactType::Registry,
                    artifact_path.clone(),
                    description,
                    source_id.to_string(),
                )
                .with_metadata("log_line", serde_json::json!(trimmed))
                .with_metadata("log_format", serde_json::json!("xp"));

                events.push(event);
            }
        }
    }

    events
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// SetupAPI log forensic parser.
pub struct SetupApiParser;

impl SetupApiParser {
    /// Return `true` when `path`'s filename is `setupapi.dev.log` or
    /// `setupapi.log` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "setupapi.dev.log" || name == "setupapi.log"
    }
}

impl ForensicParser for SetupApiParser {
    fn name(&self) -> &str {
        "SetupAPI Log Parser"
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
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        }

        // SetupAPI logs are plain text; read the whole log into memory.
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

        let content = String::from_utf8_lossy(&bytes[..off as usize]);
        let artifact_path = input.source_path().map_or_else(
            || "setupapi-evidence".to_string(),
            |p| p.to_string_lossy().into_owned(),
        );
        let events = parse_setupapi_str(&content, &artifact_path, "setupapi-evidence");
        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
        stats.completion = ParseCompletion::Complete;
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(64 * 1024 * 1024), // 64 MiB
            streaming: true,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(SetupApiParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// Drive the registered `ForensicParser::parse()` end-to-end via an
    /// in-memory source + emitter. The trait impl was a stub returning
    /// `Ok(ParseStats::new())`, so this registered, `Registry`-advertising
    /// parser silently emitted nothing — a "dark parser" (issen #114). This
    /// proves the trait actually emits.
    #[test]
    fn forensic_parser_parse_emits_via_emitter() {
        use issen_core::error::RtError;
        use std::sync::Mutex;

        struct MemSource(Vec<u8>);
        impl DataSource for MemSource {
            fn len(&self) -> u64 {
                self.0.len() as u64
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
                let off = offset as usize;
                let n = buf.len().min(self.0.len().saturating_sub(off));
                buf[..n].copy_from_slice(&self.0[off..off + n]);
                Ok(n)
            }
        }
        #[derive(Default)]
        struct Collector(Mutex<Vec<TimelineEvent>>);
        impl EventEmitter for Collector {
            fn emit(&self, e: TimelineEvent) -> Result<(), RtError> {
                self.0.lock().expect("lock").push(e);
                Ok(())
            }
            fn emit_batch(&self, mut e: Vec<TimelineEvent>) -> Result<(), RtError> {
                self.0.lock().expect("lock").append(&mut e);
                Ok(())
            }
        }

        let log = "[Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\1234567890AB 2023/04/15 14:23:11.456]\n";
        let source = MemSource(log.as_bytes().to_vec());
        let collector = Collector::default();
        let stats = SetupApiParser
            .parse(&source, &collector)
            .expect("parse must not Err on a valid log");

        assert_eq!(stats.events_emitted, 1, "one device-install event emitted");
        let events = collector.0.lock().expect("lock");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            EventType::Other("DeviceInstall".to_string())
        );
    }

    // ── can_parse tests ────────────────────────────────────────────────────

    #[test]
    fn can_parse_setupapi_dev_log() {
        assert!(
            SetupApiParser::can_parse(&PathBuf::from("C:/Windows/inf/setupapi.dev.log")),
            "expected can_parse to return true for setupapi.dev.log"
        );
    }

    #[test]
    fn can_parse_setupapi_log() {
        assert!(
            SetupApiParser::can_parse(&PathBuf::from("C:/Windows/setupapi.log")),
            "expected can_parse to return true for setupapi.log (XP)"
        );
    }

    #[test]
    fn can_parse_case_insensitive() {
        assert!(
            SetupApiParser::can_parse(&PathBuf::from("/evidence/SETUPAPI.DEV.LOG")),
            "expected can_parse to return true for SETUPAPI.DEV.LOG (uppercase)"
        );
    }

    #[test]
    fn cannot_parse_other_log() {
        assert!(
            !SetupApiParser::can_parse(&PathBuf::from("/var/log/system.log")),
            "expected can_parse to return false for system.log"
        );
    }

    // ── parse tests ────────────────────────────────────────────────────────

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_setupapi(Path::new("/nonexistent/setupapi.dev.log"), "test");
        assert!(
            result.is_ok(),
            "parse_setupapi must return Ok for nonexistent path"
        );
        assert!(
            result.unwrap().is_empty(),
            "nonexistent path should produce zero events"
        );
    }

    #[test]
    fn parse_empty_file_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_setupapi(tmp.path(), "test");
        assert!(result.is_ok(), "empty file must return Ok");
        assert!(
            result.unwrap().is_empty(),
            "empty file should produce zero events"
        );
    }

    /// GREEN test: write a tempfile with one valid Vista+ setupapi line and
    /// assert that exactly one event is emitted with the correct metadata.
    #[test]
    fn parse_usb_entry_emits_event() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "[Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\1234567890AB 2023/04/15 14:23:11.456]"
        )
        .expect("write test line");
        tmp.flush().expect("flush");

        let events = parse_setupapi(tmp.path(), "setupapi-test").expect("parse must not Err");

        assert!(
            !events.is_empty(),
            "parse_setupapi must emit at least one event for a valid device install line"
        );

        let ev = &events[0];
        assert_eq!(ev.evidence_source_id, "setupapi-test");
        assert_eq!(
            ev.event_type,
            EventType::Other("DeviceInstall".to_string()),
            "event type must be DeviceInstall"
        );
        assert!(
            ev.description.contains("Device Install"),
            "description must contain the device install text, got: {}",
            ev.description
        );
        assert_eq!(
            ev.metadata.get("log_format").and_then(|v| v.as_str()),
            Some("vista"),
            "log_format metadata must be 'vista'"
        );
    }

    /// Verify that non-section-header lines (indented content lines) are
    /// silently skipped and do not produce events.
    #[test]
    fn parse_skips_non_header_lines() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "     Section start").expect("write");
        writeln!(tmp, "     inf:  SetupCopyOEMInf ...").expect("write");
        writeln!(tmp, "     dvi:  {{XXXXXXXX-...}}").expect("write");
        tmp.flush().expect("flush");

        let events = parse_setupapi(tmp.path(), "test").expect("parse must not Err");
        assert!(
            events.is_empty(),
            "indented content lines must produce zero events"
        );
    }

    /// Verify the XP-format timestamp pattern is also handled.
    #[test]
    fn parse_xp_format_emits_event() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // XP format: timestamp first inside brackets
        writeln!(
            tmp,
            "[2005/05/12 12:34:56 1234.5678] Device Install - USB\\..."
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_setupapi(tmp.path(), "xp-test").expect("parse must not Err");

        assert!(
            !events.is_empty(),
            "XP-format setupapi.log lines must produce events"
        );
        assert_eq!(
            events[0]
                .metadata
                .get("log_format")
                .and_then(|v| v.as_str()),
            Some("xp"),
            "XP-format events must have log_format == 'xp'"
        );
    }
}
