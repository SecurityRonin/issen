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
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod drive_type;
pub mod jumplist;
pub mod parser;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseStats, ParserCapabilities,
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
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let len = input.len();
        if len == 0 {
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        }

        // LNK shortcuts are small; read the whole file into memory.
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

        // Use the source's real path for labelling when present; byte-only
        // sources (carved/in-memory) fall back to a generic label.
        let artifact_path = input.source_path().map_or_else(
            || "lnk-evidence".to_string(),
            |p| p.to_string_lossy().into_owned(),
        );
        let events =
            parser::parse_lnk_bytes(&bytes[..off as usize], &artifact_path, "lnk-evidence");
        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
        stats.completion = ParseCompletion::Complete;
        Ok(stats)
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
    ParserRegistration { create: || Box::new(LnkParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::Lnk,
            matches: classify::lnk,
            priority: 80,
            disk_sources: &[
                sel::DiskSource::Ntfs(sel::NtfsLoc::PerSubdirSweep { parent: r"\Users", rel: r"AppData\Roaming\Microsoft\Windows\Recent", name: sel::NameMatch::Suffix(".lnk") }),
                sel::DiskSource::Ntfs(sel::NtfsLoc::PerSubdirSweep { parent: r"\Users", rel: r"Desktop", name: sel::NameMatch::Suffix(".lnk") }),
            ],
            cost: sel::CostTier::Default,
        } }
}

/// Jump List parser — surfaces `*.{automatic,custom}Destinations-ms` recent/pinned
/// file history. Registered separately from [`LnkParser`] (a distinct artifact type
/// and file forms); both wrap the `lnk-core` reader family.
pub struct JumpListParser;

impl ForensicParser for JumpListParser {
    fn name(&self) -> &str {
        "Jump List Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::JumpLists]
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

        // The filename selects the Jump List form (auto vs custom); byte-only
        // sources fall back to a generic label (and parse to nothing).
        let (filename, source) = input.source_path().map_or_else(
            || {
                (
                    "jumplist-evidence".to_string(),
                    "jumplist-evidence".to_string(),
                )
            },
            |p| {
                let fname = p.file_name().map_or_else(
                    || "jumplist-evidence".to_string(),
                    |n| n.to_string_lossy().into_owned(),
                );
                (fname, p.to_string_lossy().into_owned())
            },
        );
        let events = jumplist::parse_jumplist_bytes(&bytes[..off as usize], &filename, &source);
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
    ParserRegistration { create: || Box::new(JumpListParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::JumpLists,
            matches: classify::jumplist,
            priority: 80,
            disk_sources: &[
                sel::DiskSource::Ntfs(sel::NtfsLoc::PerSubdirSweep { parent: r"\Users", rel: r"AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations", name: sel::NameMatch::Suffix(".automaticDestinations-ms") }),
                sel::DiskSource::Ntfs(sel::NtfsLoc::PerSubdirSweep { parent: r"\Users", rel: r"AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations", name: sel::NameMatch::Suffix(".customDestinations-ms") }),
            ],
            cost: sel::CostTier::Default,
        } }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use std::path::PathBuf;

    /// Drive the registered `ForensicParser::parse()` end-to-end via an
    /// in-memory source + emitter. The trait impl was a stub returning
    /// `Ok(ParseStats::new())`, so this registered, `Lnk`-advertising parser
    /// silently emitted nothing — a "dark parser" whose artifacts vanished from
    /// the timeline (issen #114). This proves the trait actually emits.
    #[test]
    fn forensic_parser_parse_emits_via_emitter() {
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

        // Valid 80-byte LNK header: CreationTime + WriteTime set, AccessTime 0
        // (the zero AccessTime must be skipped → 2 events, not 3).
        let mut data = vec![0u8; 80];
        data[0..4].copy_from_slice(&[0x4C, 0x00, 0x00, 0x00]);
        // Valid LNK LinkCLSID (00021401-0000-0000-C000-000000000046) — lnk-core
        // validates it; the old offset-reader did not.
        data[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[24..28].copy_from_slice(&0x20u32.to_le_bytes());
        data[28..36].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
        data[44..52].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        data[52..56].copy_from_slice(&1234u32.to_le_bytes());
        data[60..64].copy_from_slice(&1u32.to_le_bytes());

        let source = MemSource(data);
        let collector = Collector::default();
        let stats = LnkParser
            .parse(&source, &collector)
            .expect("parse must not Err on a valid header");

        assert_eq!(
            stats.events_emitted, 2,
            "creation+write emitted; zero access skipped"
        );
        assert_eq!(collector.0.lock().expect("lock").len(), 2);
    }

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
        // Valid LNK LinkCLSID (00021401-0000-0000-C000-000000000046) — lnk-core
        // validates it; the old offset-reader did not.
        data[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
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
            create_ev
                .metadata
                .get("file_size")
                .and_then(serde_json::Value::as_u64),
            Some(1234),
            "metadata file_size should be 1234"
        );
    }

    #[test]
    fn event_tagged_filesystem_activity() {
        // LNK target MACE timestamps are FileSystemActivity (CADET meaning axis).
        let mut data = vec![0u8; 80];
        data[0..4].copy_from_slice(&[0x4C, 0x00, 0x00, 0x00]);
        // Valid LNK LinkCLSID (00021401-0000-0000-C000-000000000046) — lnk-core
        // validates it; the old offset-reader did not.
        data[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[28..36].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes());

        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");

        let events = parser::parse_lnk(tmp.path(), "test-source").expect("parse_lnk must not Err");
        assert_eq!(
            events[0].activity_category,
            Some(issen_core::ActivityCategory::FileSystemActivity)
        );
    }
}
