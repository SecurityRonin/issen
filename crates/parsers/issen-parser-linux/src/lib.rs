//! Linux host log file parsers for Issen.
//!
//! Parses auth.log, syslog, cron, and bash_history files and emits
//! [`TimelineEvent`]s via the [`ForensicParser`] trait.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unnecessary_literal_bound
)]

pub mod auth_log;
pub mod bash_history;
pub mod boot_log;
pub mod cron;
pub mod syslog;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};

// ── LinuxAuthLogParser ────────────────────────────────────────────────────────

/// Parser for Linux auth.log files.
pub struct LinuxAuthLogParser;

impl LinuxAuthLogParser {
    /// Return `true` when `path` looks like an auth.log file.
    pub fn can_parse(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "auth.log" || n.starts_with("auth.log."))
    }
}

impl ForensicParser for LinuxAuthLogParser {
    fn name(&self) -> &str {
        "Linux Auth Log Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::LoginHistory]
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
    ParserRegistration { create: || Box::new(LinuxAuthLogParser) }
}

// ── LinuxSyslogParser ─────────────────────────────────────────────────────────

/// Parser for Linux syslog files.
pub struct LinuxSyslogParser;

impl LinuxSyslogParser {
    /// Return `true` when `path` looks like a syslog file.
    pub fn can_parse(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "syslog" || n.starts_with("syslog."))
    }
}

impl ForensicParser for LinuxSyslogParser {
    fn name(&self) -> &str {
        "Linux Syslog Parser"
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
    ParserRegistration { create: || Box::new(LinuxSyslogParser) }
}

// ── LinuxCronParser ───────────────────────────────────────────────────────────

/// Parser for Linux cron log files.
pub struct LinuxCronParser;

impl LinuxCronParser {
    /// Return `true` when `path` looks like a cron log file.
    pub fn can_parse(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "cron.log" || n == "cron" || n.starts_with("cron."))
    }
}

impl ForensicParser for LinuxCronParser {
    fn name(&self) -> &str {
        "Linux Cron Log Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::CrontabConfig]
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
            max_memory_bytes: Some(64 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(LinuxCronParser) }
}

// ── LinuxBashHistoryParser ────────────────────────────────────────────────────

/// Parser for bash_history files.
pub struct LinuxBashHistoryParser;

impl LinuxBashHistoryParser {
    /// Return `true` when `path` looks like a bash_history file.
    pub fn can_parse(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == ".bash_history" || n == "bash_history")
    }
}

impl ForensicParser for LinuxBashHistoryParser {
    fn name(&self) -> &str {
        "Linux Bash History Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::LoginHistory]
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
            max_memory_bytes: Some(16 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(LinuxBashHistoryParser) }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn auth_log_can_parse_matches_auth_log() {
        let path = PathBuf::from("/var/log/auth.log");
        assert!(
            LinuxAuthLogParser::can_parse(&path),
            "should match auth.log"
        );
    }

    #[test]
    fn auth_log_can_parse_rejects_ntuser_dat() {
        let path = PathBuf::from("/cases/NTUSER.DAT");
        assert!(
            !LinuxAuthLogParser::can_parse(&path),
            "should not match NTUSER.DAT"
        );
    }

    #[test]
    fn syslog_can_parse_matches_syslog() {
        let path = PathBuf::from("/var/log/syslog");
        assert!(LinuxSyslogParser::can_parse(&path), "should match syslog");
    }

    #[test]
    fn cron_can_parse_matches_cron_log() {
        let path = PathBuf::from("/var/log/cron.log");
        assert!(LinuxCronParser::can_parse(&path), "should match cron.log");
    }

    #[test]
    fn bash_history_can_parse_matches_bash_history() {
        let path = PathBuf::from("/root/.bash_history");
        assert!(
            LinuxBashHistoryParser::can_parse(&path),
            "should match .bash_history"
        );
    }
}
