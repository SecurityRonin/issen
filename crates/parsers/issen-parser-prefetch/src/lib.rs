//! Windows Prefetch file parser for Issen.
//!
//! Parses `.pf` Prefetch files and emits [`TimelineEvent`]s via the
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

/// Windows Prefetch file parser.
pub struct PrefetchParser;

impl PrefetchParser {
    /// Return `true` when `path` has a `.pf` extension (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("pf"))
            .unwrap_or(false)
    }
}

impl ForensicParser for PrefetchParser {
    fn name(&self) -> &str {
        "Prefetch Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Prefetch]
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
            max_memory_bytes: Some(64 * 1024 * 1024), // 64 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(PrefetchParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use std::path::PathBuf;

    // ── Extension matching tests ───────────────────────────────────────────

    #[test]
    fn can_parse_returns_true_for_pf_extension() {
        let path = PathBuf::from("/mnt/evidence/C/Windows/Prefetch/NOTEPAD.EXE-ABCD1234.pf");
        assert!(
            PrefetchParser::can_parse(&path),
            "expected can_parse to return true for .pf"
        );
    }

    #[test]
    fn can_parse_returns_true_for_uppercase_pf() {
        let path = PathBuf::from("/mnt/evidence/NOTEPAD.EXE-ABCD1234.PF");
        assert!(
            PrefetchParser::can_parse(&path),
            "expected can_parse to return true for .PF (upper-case)"
        );
    }

    #[test]
    fn can_parse_returns_false_for_exe() {
        let path = PathBuf::from("/mnt/evidence/notepad.exe");
        assert!(
            !PrefetchParser::can_parse(&path),
            "expected can_parse to return false for .exe"
        );
    }

    #[test]
    fn can_parse_returns_false_for_no_extension() {
        let path = PathBuf::from("/mnt/evidence/NOTEPAD");
        assert!(
            !PrefetchParser::can_parse(&path),
            "expected can_parse to return false for file with no extension"
        );
    }

    // ── parse_prefetch tests ───────────────────────────────────────────────

    #[test]
    fn parse_empty_file_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parser::parse_prefetch(tmp.path(), "test-source")
            .expect("parse_prefetch must not return Err on empty file");
        assert!(
            events.is_empty(),
            "expected empty vec for zero-byte file, got {} events",
            events.len()
        );
    }

    #[test]
    fn parse_bad_signature_returns_empty() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Write 84 bytes but with wrong signature ("JUNK" instead of "SCCA").
        let mut data = vec![0u8; 84];
        data[0..4].copy_from_slice(b"JUNK");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");

        let events = parser::parse_prefetch(tmp.path(), "test-source")
            .expect("parse_prefetch must not Err on bad signature");
        assert!(
            events.is_empty(),
            "expected empty vec for bad signature, got {} events",
            events.len()
        );
    }

    #[test]
    fn parse_valid_header_emits_one_event() {
        // Construct a minimal 84-byte SCCA prefetch header.
        // Layout (all little-endian):
        //   [0..4]   signature: "SCCA"
        //   [4..8]   version: 30 (Win10/11)
        //   [8..12]  file_size: 84
        //   [12..72] exe name: "NOTEPAD.EXE" in UTF-16LE, null-padded to 60 bytes
        //   [72..76] prefetch hash: 0xABCD1234
        //   [76..84] padding
        let mut data = vec![0u8; 84];
        data[0..4].copy_from_slice(b"SCCA");
        data[4..8].copy_from_slice(&30u32.to_le_bytes()); // version = Win10
        data[8..12].copy_from_slice(&84u32.to_le_bytes()); // file_size
        // "NOTEPAD.EXE" as UTF-16LE into bytes 12..72 (60 bytes = 30 UTF-16 code units)
        let exe = "NOTEPAD.EXE";
        for (i, c) in exe.encode_utf16().enumerate() {
            let off = 12 + i * 2;
            data[off..off + 2].copy_from_slice(&c.to_le_bytes());
        }
        data[72..76].copy_from_slice(&0xABCD_1234u32.to_le_bytes()); // hash

        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");

        let events = parser::parse_prefetch(tmp.path(), "test-source")
            .expect("parse_prefetch must not Err on valid header");

        assert_eq!(events.len(), 1, "expected exactly one event");
        let ev = &events[0];

        assert_eq!(
            ev.source,
            ArtifactType::Prefetch,
            "event source must be Prefetch"
        );
        assert!(
            ev.artifact_path.contains("NOTEPAD.EXE"),
            "artifact_path should contain exe name, got: {}",
            ev.artifact_path
        );
        assert!(
            ev.description.contains("NOTEPAD.EXE"),
            "description should contain exe name, got: {}",
            ev.description
        );
        assert!(
            ev.description.to_lowercase().contains("abcd1234"),
            "description should contain hash, got: {}",
            ev.description
        );
        assert_eq!(ev.timestamp_ns, 0, "timestamp_ns should be 0 (stub)");
        assert_eq!(
            ev.metadata.get("version").and_then(|v| v.as_u64()),
            Some(30),
            "metadata version should be 30"
        );
        assert_eq!(
            ev.metadata.get("file_size").and_then(|v| v.as_u64()),
            Some(84),
            "metadata file_size should be 84"
        );
    }
}
