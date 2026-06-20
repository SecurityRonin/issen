//! Windows Registry hive parser for Issen.
//!
//! Parses registry hive files (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, etc.)
//! using our `winreg-core` / `winreg-artifacts` fleet crates and emits
//! [`TimelineEvent`]s via the [`ForensicParser`] trait.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unnecessary_literal_bound
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
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let len = input.len();

        // Read the whole hive into memory (hives are bounded; capabilities cap at
        // 512 MiB) and feed it to winreg-core's `Hive::from_bytes`. The DataSource
        // exposes no path, so transaction-log replay isn't available here — the
        // primary hive is parsed (see `parser::parse_hive_bytes`).
        let mut bytes = vec![0u8; usize::try_from(len).unwrap_or(0)];
        let mut filled = 0usize;
        while (filled as u64) < len {
            let n = input.read_at(filled as u64, &mut bytes[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        bytes.truncate(filled);

        let events = parser::parse_hive_bytes(bytes, "registry-hive", "registry");
        stats.events_emitted = events.len() as u64;
        stats.bytes_processed = len;
        emitter.emit_batch(events)?;
        Ok(stats)
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

    // ── Trait parse() wiring (A2) ──────────────────────────────────────────

    use issen_core::timeline::event::TimelineEvent;

    struct BytesSource {
        data: Vec<u8>,
    }
    impl DataSource for BytesSource {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let off = offset as usize;
            if off >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }
    }

    #[derive(Default)]
    struct CountingEmitter {
        count: std::sync::atomic::AtomicU64,
    }
    impl EventEmitter for CountingEmitter {
        fn emit(&self, _event: TimelineEvent) -> Result<(), RtError> {
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
        fn emit_batch(&self, batch: Vec<TimelineEvent>) -> Result<(), RtError> {
            self.count
                .fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn parse_consumes_the_whole_source() {
        // The stub never reads the DataSource (bytes_processed stays 0). The wired
        // parser must consume the entire hive image and route it through winreg-core.
        // (4 KiB of non-hive bytes → Hive::from_bytes fails → 0 events, but no panic.)
        let data = vec![0xABu8; 4096];
        let src = BytesSource { data: data.clone() };
        let emitter = CountingEmitter::default();
        let stats = RegistryHiveParser
            .parse(&src, &emitter)
            .expect("parse returns Ok");
        assert_eq!(
            stats.bytes_processed,
            data.len() as u64,
            "wired parser must read the whole source"
        );
        assert_eq!(stats.events_emitted, 0, "invalid hive yields no events");
    }

    // ── parse_hive tests ───────────────────────────────────────────────────

    #[test]
    fn parse_hive_returns_empty_for_empty_hive() {
        // A zero-byte file should not cause an Err — errors from winreg-core
        // on invalid input must be caught and converted to Ok(vec![]).
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parser::parse_hive(tmp.path(), "test-source");
        assert!(
            result.is_ok(),
            "parse_hive should return Ok for an empty/zero-byte file, got: {result:?}"
        );
    }

    #[test]
    fn parse_hive_events_have_correct_source() {
        // When events are returned, every event's source field must be Registry.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events =
            parser::parse_hive(tmp.path(), "test-source").expect("parse_hive must not return Err");
        for event in &events {
            assert_eq!(
                event.source,
                ArtifactType::Registry,
                "event source must be Registry, got {:?}",
                event.source
            );
        }
    }
}
