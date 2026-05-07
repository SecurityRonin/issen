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

use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::Context;
use chrono::{NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use issen_core::artifacts::ArtifactType;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

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
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(vec![]),
    };

    let artifact_path = path.to_string_lossy().into_owned();

    // Vista+ pattern: line starts with `[`, description first, timestamp last.
    // Example: [Device Install (Hardware initiated) - USB\VID_... 2023/04/15 14:23:11.456]
    //
    // Regex captures:
    //   group 1 — description (everything between `[` and the timestamp)
    //   group 2 — timestamp string (YYYY/MM/DD HH:MM:SS with optional .mmm)
    let vista_re = Regex::new(
        r"^\[(.+?)\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]",
    )
    .context("compile Vista+ regex")?;

    // XP pattern: timestamp first inside brackets.
    // Example: [2005/05/12 12:34:56 1234.5678] Device Install - ...
    let xp_re = Regex::new(
        r"^\[(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+[^\]]+\]\s*(.*)",
    )
    .context("compile XP regex")?;

    let mut events: Vec<TimelineEvent> = Vec::new();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

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

    Ok(events)
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
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, issen_core::error::RtError> {
        Ok(ParseStats::new())
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
        assert!(result.is_ok(), "parse_setupapi must return Ok for nonexistent path");
        assert!(result.unwrap().is_empty(), "nonexistent path should produce zero events");
    }

    #[test]
    fn parse_empty_file_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_setupapi(tmp.path(), "test");
        assert!(result.is_ok(), "empty file must return Ok");
        assert!(result.unwrap().is_empty(), "empty file should produce zero events");
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
        asseissen_eq!(ev.evidence_source_id, "setupapi-test");
        asseissen_eq!(
            ev.event_type,
            EventType::Other("DeviceInstall".to_string()),
            "event type must be DeviceInstall"
        );
        assert!(
            ev.description.contains("Device Install"),
            "description must contain the device install text, got: {}",
            ev.description
        );
        asseissen_eq!(
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
        writeln!(tmp, "[2005/05/12 12:34:56 1234.5678] Device Install - USB\\...").expect("write");
        tmp.flush().expect("flush");

        let events = parse_setupapi(tmp.path(), "xp-test").expect("parse must not Err");

        assert!(
            !events.is_empty(),
            "XP-format setupapi.log lines must produce events"
        );
        asseissen_eq!(
            events[0].metadata.get("log_format").and_then(|v| v.as_str()),
            Some("xp"),
            "XP-format events must have log_format == 'xp'"
        );
    }
}
