//! macOS forensic artifact parsers for Issen.
//!
//! Parses Unified Log text exports and FSEvents log lines, emitting
//! [`TimelineEvent`]s via the [`ForensicParser`] trait.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unnecessary_literal_bound
)]

pub mod fsevents;
pub mod unified_log;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};

// ── MacosUnifiedLogParser ─────────────────────────────────────────────────────

/// Parser for macOS Unified Log text exports.
pub struct MacosUnifiedLogParser;

impl MacosUnifiedLogParser {
    /// Return `true` when `path` looks like a Unified Log export.
    ///
    /// Matches files named `system.log` or with the `.logarchive` extension.
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        name == "system.log" || ext.eq_ignore_ascii_case("logarchive")
    }
}

impl ForensicParser for MacosUnifiedLogParser {
    fn name(&self) -> &str {
        "macOS Unified Log Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::SystemInfo]
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        Ok(ParseStats::new())
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(512 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(MacosUnifiedLogParser) }
}

// ── MacosFsEventsParser ───────────────────────────────────────────────────────

/// Parser for macOS FSEvents text log exports.
pub struct MacosFsEventsParser;

impl MacosFsEventsParser {
    /// Return `true` when `path` looks like an FSEvents export.
    ///
    /// Matches paths containing `fseventsd` or files with `.fsevents` extension.
    pub fn can_parse(path: &Path) -> bool {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if ext.eq_ignore_ascii_case("fsevents") {
            return true;
        }
        // Check if any component of the path contains "fseventsd"
        path.components().any(|c| {
            c.as_os_str()
                .to_str()
                .is_some_and(|s| s.contains("fseventsd"))
        })
    }
}

impl ForensicParser for MacosFsEventsParser {
    fn name(&self) -> &str {
        "macOS FSEvents Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::SystemInfo]
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        Ok(ParseStats::new())
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(256 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(MacosFsEventsParser) }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── Test 11: MacosUnifiedLogParser::can_parse ─────────────────────────────

    #[test]
    fn unified_log_can_parse_matches_system_log() {
        let path = PathBuf::from("/var/log/system.log");
        assert!(
            MacosUnifiedLogParser::can_parse(&path),
            "should match system.log"
        );
    }

    #[test]
    fn unified_log_can_parse_matches_logarchive_extension() {
        let path = PathBuf::from("/cases/evidence/system.logarchive");
        assert!(
            MacosUnifiedLogParser::can_parse(&path),
            "should match .logarchive extension"
        );
    }

    #[test]
    fn unified_log_can_parse_rejects_ntuser_dat() {
        let path = PathBuf::from("/cases/NTUSER.DAT");
        assert!(
            !MacosUnifiedLogParser::can_parse(&path),
            "should not match NTUSER.DAT"
        );
    }

    // ── Test 12: MacosFsEventsParser::can_parse ───────────────────────────────

    #[test]
    fn fsevents_can_parse_matches_fseventsd_path() {
        let path = PathBuf::from("/.fseventsd/fseventsd-uuid");
        assert!(
            MacosFsEventsParser::can_parse(&path),
            "should match fseventsd in path"
        );
    }

    #[test]
    fn fsevents_can_parse_matches_fsevents_extension() {
        let path = PathBuf::from("/cases/evidence/00000000012345.fsevents");
        assert!(
            MacosFsEventsParser::can_parse(&path),
            "should match .fsevents extension"
        );
    }

    #[test]
    fn fsevents_can_parse_rejects_auth_log() {
        let path = PathBuf::from("/var/log/auth.log");
        assert!(
            !MacosFsEventsParser::can_parse(&path),
            "should not match auth.log"
        );
    }
}
