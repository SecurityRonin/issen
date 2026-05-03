//! SetupAPI log parser for RapidTriage.
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

use rt_core::artifacts::ArtifactType;
use rt_core::plugin::registry::ParserRegistration;
use rt_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use rt_core::timeline::event::TimelineEvent;

// ---------------------------------------------------------------------------
// Core parsing logic (stub — GREEN will implement real line parsing)
// ---------------------------------------------------------------------------

/// Parse a setupapi log file, returning one [`TimelineEvent`] per device
/// install section header line.
///
/// Returns `Ok(vec![])` for nonexistent, empty, or non-matching files.
pub fn parse_setupapi(path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    // Nonexistent / unreadable files — return empty without error.
    if std::fs::metadata(path).is_err() {
        return Ok(vec![]);
    }
    // GREEN will implement real parsing here.
    Ok(vec![])
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
    ) -> Result<ParseStats, rt_core::error::RtError> {
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

    /// RED test: write a tempfile with one valid Vista+ setupapi line and assert
    /// that at least one event is emitted.  The stub returns Ok(vec![]) so this
    /// assertion fails — RED.  The GREEN implementation parses the line and emits
    /// an event.
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
            "parse_setupapi must emit at least one event for a valid device install line \
             (RED: stub returns empty)"
        );
    }
}
