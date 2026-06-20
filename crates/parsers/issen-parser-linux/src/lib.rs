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
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod auth_log;
pub mod bash_history;
pub mod boot_log;
pub mod cron;
pub mod fish_history;
pub mod syslog;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::plugin::selector as sel;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseStats, ParserCapabilities,
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
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let len = input.len();
        if len == 0 {
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        }

        // auth.log is plain text; read the whole log into memory.
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
            || "auth.log".to_string(),
            |p| p.to_string_lossy().into_owned(),
        );
        // year_hint = None → current year (syslog lines carry no year).
        let events =
            auth_log::parse_auth_log_str(&content, "linux-auth-evidence", &artifact_path, None);
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
    ParserRegistration { create: || Box::new(LinuxAuthLogParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::LoginHistory,
            matches: classify::auth_log,
            priority: 60,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        } }
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
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let Some(path) = input.source_path() else {
            // This parser reads by file path; a byte-only source can't be parsed.
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        };
        let events = syslog::parse_syslog(path, "linux-syslog-evidence")
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
    ParserRegistration { create: || Box::new(LinuxSyslogParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::SystemInfo,
            matches: classify::syslog,
            priority: 55,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        } }
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
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let Some(path) = input.source_path() else {
            // This parser reads by file path; a byte-only source can't be parsed.
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        };
        let events = cron::parse_cron_log(path, "linux-cron-evidence")
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
            max_memory_bytes: Some(64 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(LinuxCronParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::CrontabConfig,
            matches: classify::cron,
            priority: 55,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        } }
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
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let Some(path) = input.source_path() else {
            // This parser reads by file path; a byte-only source can't be parsed.
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        };
        let events = bash_history::parse_bash_history(path, "linux-bash-evidence")
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
            max_memory_bytes: Some(16 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(LinuxBashHistoryParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::LoginHistory,
            matches: classify::bash_history,
            priority: 60,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        } }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Drive the registered `LinuxAuthLogParser::parse()` end-to-end via an
    /// in-memory source + emitter. The trait impl was a stub returning
    /// `Ok(ParseStats::new())` even though `auth_log::parse_auth_log` already
    /// parses SSH login events — so discovered auth.logs emitted nothing (a
    /// "dark parser", issen #114). This proves the trait actually emits.
    #[test]
    fn auth_log_forensic_parser_emits_via_emitter() {
        use issen_core::timeline::event::TimelineEvent;
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

        let log = "Apr 15 14:23:11 myhost sshd[1234]: Accepted password for alice from 10.0.0.5 port 54321 ssh2\n";
        let source = MemSource(log.as_bytes().to_vec());
        let collector = Collector::default();
        let stats = LinuxAuthLogParser
            .parse(&source, &collector)
            .expect("parse must not Err on a valid auth.log");

        assert_eq!(stats.events_emitted, 1, "one SSH login event emitted");
        let events = collector.0.lock().expect("lock");
        assert_eq!(events.len(), 1);
        assert!(
            events[0].description.contains("alice"),
            "event must name the logged-in user, got: {}",
            events[0].description
        );
    }

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
    fn linux_syslog_forensic_parser_emits_via_emitter() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tmp");
        writeln!(
            tmp,
            "Apr 15 10:02:00 hostname systemd[1]: Started OpenSSH Server Daemon."
        )
        .expect("w");
        tmp.flush().expect("flush");
        let src = FileSrc(tmp.path().to_path_buf());
        let collector = Collector::default();
        let stats = LinuxSyslogParser.parse(&src, &collector).expect("parse");
        assert!(stats.events_emitted >= 1, "wired parser must emit");
        assert!(!collector.0.lock().expect("lock").is_empty());
    }

    #[test]
    fn linux_cron_forensic_parser_emits_via_emitter() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tmp");
        writeln!(
            tmp,
            "Apr 15 10:00:01 hostname CRON[9999]: (root) CMD (run-parts /etc/cron.daily)"
        )
        .expect("w");
        tmp.flush().expect("flush");
        let src = FileSrc(tmp.path().to_path_buf());
        let collector = Collector::default();
        let stats = LinuxCronParser.parse(&src, &collector).expect("parse");
        assert!(stats.events_emitted >= 1, "wired parser must emit");
        assert!(!collector.0.lock().expect("lock").is_empty());
    }

    #[test]
    fn linux_bash_history_forensic_parser_emits_via_emitter() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tmp");
        writeln!(tmp, "#1713171781").expect("w");
        writeln!(tmp, "ls -la").expect("w");
        tmp.flush().expect("flush");
        let src = FileSrc(tmp.path().to_path_buf());
        let collector = Collector::default();
        let stats = LinuxBashHistoryParser
            .parse(&src, &collector)
            .expect("parse");
        assert!(stats.events_emitted >= 1, "wired parser must emit");
        assert!(!collector.0.lock().expect("lock").is_empty());
    }
}
