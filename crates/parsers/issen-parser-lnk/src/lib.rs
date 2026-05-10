//! Windows LNK (Shell Link) shortcut file parser for Issen.
//!
//! Parses `.lnk` files and emits [`TimelineEvent`]s via the
//! [`ForensicParser`] trait.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unnecessary_literal_bound
)]

pub mod drive_type;
pub mod parser;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};

/// Windows LNK (Shell Link) shortcut file parser.
pub struct LnkParser;

impl LnkParser {
    /// Return `true` when `path` has a `.lnk` extension (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
    }
}

impl ForensicParser for LnkParser {
    fn name(&self) -> &str {
        "LNK Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Lnk]
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
    ParserRegistration { create: || Box::new(LnkParser) }
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
    fn can_parse_lnk_extension() {
        let path = PathBuf::from("/cases/evidence/Desktop/malware.lnk");
        assert!(
            LnkParser::can_parse(&path),
            "expected can_parse to return true for .lnk"
        );
    }

    #[test]
    fn can_parse_case_insensitive() {
        let path = PathBuf::from("/cases/evidence/Desktop/MALWARE.LNK");
        assert!(
            LnkParser::can_parse(&path),
            "expected can_parse to return true for .LNK (upper-case)"
        );
    }

    #[test]
    fn can_parse_rejects_exe() {
        let path = PathBuf::from("/cases/evidence/malware.exe");
        assert!(
            !LnkParser::can_parse(&path),
            "expected can_parse to return false for .exe"
        );
    }

    // ── parse_lnk tests ───────────────────────────────────────────────────

    #[test]
    fn parse_empty_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parser::parse_lnk(tmp.path(), "test-source")
            .expect("parse_lnk must not return Err on empty file");
        assert!(
            events.is_empty(),
            "expected empty vec for zero-byte file, got {} events",
            events.len()
        );
    }

    #[test]
    fn parse_bad_signature_returns_empty() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Write 80 bytes with wrong signature.
        let mut data = vec![0u8; 80];
        data[0..4].copy_from_slice(b"JUNK");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");

        let events = parser::parse_lnk(tmp.path(), "test-source")
            .expect("parse_lnk must not Err on bad signature");
        assert!(
            events.is_empty(),
            "expected empty vec for bad signature, got {} events",
            events.len()
        );
    }

    #[test]
    fn parse_valid_header_emits_events() {
        // Build an 80-byte LNK header:
        //   [0..4]   signature: 0x4C 0x00 0x00 0x00
        //   [4..20]  LinkCLSID: 16 bytes (zeroed)
        //   [20..24] LinkFlags: 0x00000001 (HasLinkTargetIDList)
        //   [24..28] FileAttributes: 0x00000020 (FILE_ATTRIBUTE_ARCHIVE)
        //   [28..36] CreationTime: 132000000000000000 (2019-02-01 ish)
        //   [36..44] AccessTime: 0 (should be skipped)
        //   [44..52] WriteTime: 133000000000000000
        //   [52..56] FileSize: 1234
        //   [56..60] IconIndex: 0
        //   [60..64] ShowCommand: 1
        //   [64..66] HotKey: 0
        //   [66..80] reserved/padding
        let mut data = vec![0u8; 80];
        // LNK signature
        data[0..4].copy_from_slice(&[0x4C, 0x00, 0x00, 0x00]);
        // LinkFlags
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        // FileAttributes
        data[24..28].copy_from_slice(&0x20u32.to_le_bytes());
        // CreationTime = 132000000000000000
        data[28..36].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
        // AccessTime = 0 (skip)
        // WriteTime = 133000000000000000
        data[44..52].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        // FileSize = 1234
        data[52..56].copy_from_slice(&1234u32.to_le_bytes());
        // ShowCommand = 1
        data[60..64].copy_from_slice(&1u32.to_le_bytes());

        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");

        let events = parser::parse_lnk(tmp.path(), "test-source")
            .expect("parse_lnk must not Err on valid header");

        // AccessTime=0 is skipped, so expect 2 events: CreationTime + WriteTime
        assert_eq!(events.len(), 2, "expected 2 events (skip zero AccessTime)");

        // First event: FileCreate from CreationTime
        let create_ev = events
            .iter()
            .find(|e| e.event_type == issen_core::timeline::event::EventType::FileCreate)
            .expect("expected a FileCreate event");

        // filetime_to_ns(132000000000000000) = ((132000000000000000 - 116444736000000000) * 100)
        // = (15555264000000000 * 100) = 1555526400000000000
        let expected_create_ns: i64 = 1_555_526_400_000_000_000;
        assert_eq!(
            create_ev.timestamp_ns, expected_create_ns,
            "CreationTime timestamp mismatch"
        );
        assert_eq!(create_ev.source, ArtifactType::Lnk);
        assert!(
            create_ev.description.contains("LNK shortcut"),
            "description should contain 'LNK shortcut'"
        );

        // Second event: FileModify from WriteTime
        let modify_ev = events
            .iter()
            .find(|e| e.event_type == issen_core::timeline::event::EventType::FileModify)
            .expect("expected a FileModify event");

        // filetime_to_ns(133000000000000000) = ((133000000000000000 - 116444736000000000) * 100)
        // = (16555264000000000 * 100) = 1655526400000000000
        let expected_write_ns: i64 = 1_655_526_400_000_000_000;
        assert_eq!(
            modify_ev.timestamp_ns, expected_write_ns,
            "WriteTime timestamp mismatch"
        );

        // Check metadata present
        assert_eq!(
            create_ev.metadata.get("file_size").and_then(|v| v.as_u64()),
            Some(1234),
            "metadata file_size should be 1234"
        );
    }
}
