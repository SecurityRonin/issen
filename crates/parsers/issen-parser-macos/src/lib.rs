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
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod fsevents;
pub mod unified_log;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseOptions, ParseStats,
    ParserCapabilities,
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
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let Some(path) = input.source_path() else {
            // This parser reads by file path; a byte-only source can't be parsed.
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        };
        let events = unified_log::parse_unified_log(path, "macos-unifiedlog-evidence")
            .map_err(|e| RtError::InvalidData(e.to_string()))?;
        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
        stats.completion = ParseCompletion::Complete;
        Ok(stats)
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
    ParserRegistration { create: || Box::new(MacosUnifiedLogParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::SystemInfo,
            matches: classify::macos_log,
            priority: 50,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        } }
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
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let Some(path) = input.source_path() else {
            // This parser reads by file path; a byte-only source can't be parsed.
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        };
        let events = fsevents::parse_fsevents_log(path, "macos-fsevents-evidence")
            .map_err(|e| RtError::InvalidData(e.to_string()))?;
        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
        stats.completion = ParseCompletion::Complete;
        Ok(stats)
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
    ParserRegistration { create: || Box::new(MacosFsEventsParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::SystemInfo,
            matches: classify::fsevents,
            priority: 50,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        } }
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

    // ── #114 dark-parser wiring proofs (real temp-file source) ───────────────

    use issen_core::timeline::event::TimelineEvent;
    use std::io::Write as _;
    use std::sync::Mutex;

    struct FileSrc(PathBuf);
    impl DataSource for FileSrc {
        fn len(&self) -> u64 {
            std::fs::metadata(&self.0).map_or(0, |m| m.len())
        }
        fn read_at(&self, _o: u64, _b: &mut [u8]) -> Result<usize, RtError> {
            Ok(0)
        }
        fn source_path(&self) -> Option<&Path> {
            Some(&self.0)
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

    #[test]
    fn macos_unified_log_forensic_parser_emits_via_emitter() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tmp");
        writeln!(
            tmp,
            "2026-04-15 10:23:01.123456-0700  localhost kernel[0]: (AppleIntelCPU) Kernel connected"
        )
        .expect("w");
        tmp.flush().expect("flush");
        let src = FileSrc(tmp.path().to_path_buf());
        let collector = Collector::default();
        let stats = MacosUnifiedLogParser
            .parse(
                &src,
                &collector,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse");
        assert!(stats.events_emitted >= 1, "wired parser must emit");
        assert!(!collector.0.lock().expect("lock").is_empty());
    }

    #[test]
    fn macos_fsevents_forensic_parser_emits_via_emitter() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tmp");
        writeln!(
            tmp,
            "2026-04-15 10:25:00  /Users/alice/Documents/report.pdf  Created Modified"
        )
        .expect("w");
        tmp.flush().expect("flush");
        let src = FileSrc(tmp.path().to_path_buf());
        let collector = Collector::default();
        let stats = MacosFsEventsParser
            .parse(
                &src,
                &collector,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse");
        assert!(stats.events_emitted >= 1, "wired parser must emit");
        assert!(!collector.0.lock().expect("lock").is_empty());
    }
}
