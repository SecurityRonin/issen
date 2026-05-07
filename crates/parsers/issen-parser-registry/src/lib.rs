//! Windows Registry hive parser for Issen.
//!
//! Parses registry hive files (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, etc.)
//! using the `notatin` crate and emits [`TimelineEvent`]s via the
//! [`ForensicParser`] trait.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

pub mod parser;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};

/// Registry hive filenames (case-insensitive basename match) that this
/// parser can handle.
const REGISTRY_HIVE_NAMES: &[&str] = &[
    "system",
    "software",
    "ntuser.dat",
    "usrclass.dat",
    "sam",
    "security",
];

/// Windows Registry hive parser.
pub struct RegistryHiveParser;

impl RegistryHiveParser {
    /// Return `true` when `path`'s filename matches a known registry hive name
    /// (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        REGISTRY_HIVE_NAMES.contains(&name.as_str())
    }
}

impl ForensicParser for RegistryHiveParser {
    fn name(&self) -> &str {
        "Registry Hive Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Registry]
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        // Stub — GREEN implementation goes here.
        Ok(ParseStats::new())
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(512 * 1024 * 1024), // 512 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(RegistryHiveParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── Plugin matching tests ──────────────────────────────────────────────

    #[test]
    fn plugin_matches_ntuser_dat() {
        let path = PathBuf::from("/mnt/evidence/C/Users/jdoe/NTUSER.DAT");
        assert!(
            RegistryHiveParser::can_parse(&path),
            "expected can_parse to return true for NTUSER.DAT"
        );
    }

    #[test]
    fn plugin_matches_system_hive() {
        let path = PathBuf::from("/mnt/evidence/C/Windows/System32/config/SYSTEM");
        assert!(
            RegistryHiveParser::can_parse(&path),
            "expected can_parse to return true for SYSTEM"
        );
    }

    #[test]
    fn plugin_rejects_unknown_file() {
        let path = PathBuf::from("/mnt/evidence/foo.txt");
        assert!(
            !RegistryHiveParser::can_parse(&path),
            "expected can_parse to return false for foo.txt"
        );
    }

    // ── parse_hive tests ───────────────────────────────────────────────────

    #[test]
    fn parse_hive_returns_empty_for_empty_hive() {
        // A zero-byte file should not cause an Err — errors from notatin
        // on invalid input must be caught and converted to Ok(vec![]).
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parser::parse_hive(tmp.path(), "test-source");
        assert!(
            result.is_ok(),
            "parse_hive should return Ok for an empty/zero-byte file, got: {:?}",
            result
        );
    }

    #[test]
    fn parse_hive_events_have_correct_source() {
        // When events are returned, every event's source field must be Registry.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parser::parse_hive(tmp.path(), "test-source")
            .expect("parse_hive must not return Err");
        for event in &events {
            asseissen_eq!(
                event.source,
                ArtifactType::Registry,
                "event source must be Registry, got {:?}",
                event.source
            );
        }
    }
}
