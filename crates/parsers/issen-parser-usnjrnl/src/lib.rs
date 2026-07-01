#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::elidable_lifetime_names,
    clippy::match_same_arms,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::field_reassign_with_default,
    clippy::inefficient_to_string,
    clippy::manual_strip,
    clippy::redundant_else,
    clippy::trim_split_whitespace,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::unused_self,
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::missing_fields_in_debug,
    clippy::result_unit_err,
    clippy::unreadable_literal,
    clippy::manual_contains,
    clippy::unnecessary_literal_bound
)]
use chrono::DateTime;
use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseOptions, ParseStats,
    ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

/// USN_RECORD_V2 reason flags.
#[derive(Debug, Clone, Copy)]
pub struct UsnReasonFlags(pub u32);

impl UsnReasonFlags {
    pub const DATA_OVERWRITE: u32 = 0x0000_0001;
    pub const DATA_EXTEND: u32 = 0x0000_0002;
    pub const DATA_TRUNCATION: u32 = 0x0000_0004;
    pub const NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
    pub const NAMED_DATA_EXTEND: u32 = 0x0000_0020;
    pub const NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
    pub const FILE_CREATE: u32 = 0x0000_0100;
    pub const FILE_DELETE: u32 = 0x0000_0200;
    pub const EA_CHANGE: u32 = 0x0000_0400;
    pub const SECURITY_CHANGE: u32 = 0x0000_0800;
    pub const RENAME_OLD_NAME: u32 = 0x0000_1000;
    pub const RENAME_NEW_NAME: u32 = 0x0000_2000;
    pub const INDEXABLE_CHANGE: u32 = 0x0000_4000;
    pub const BASIC_INFO_CHANGE: u32 = 0x0000_8000;
    pub const HARD_LINK_CHANGE: u32 = 0x0001_0000;
    pub const COMPRESSION_CHANGE: u32 = 0x0002_0000;
    pub const ENCRYPTION_CHANGE: u32 = 0x0004_0000;
    pub const OBJECT_ID_CHANGE: u32 = 0x0008_0000;
    pub const REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
    pub const STREAM_CHANGE: u32 = 0x0020_0000;
    pub const CLOSE: u32 = 0x8000_0000;

    /// Map reason flags to the primary EventType.
    #[must_use]
    pub fn to_event_type(self) -> EventType {
        let r = self.0;
        if r & Self::FILE_CREATE != 0 {
            EventType::FileCreate
        } else if r & Self::FILE_DELETE != 0 {
            EventType::FileDelete
        } else if r & (Self::RENAME_OLD_NAME | Self::RENAME_NEW_NAME) != 0 {
            EventType::FileRename
        } else if r & (Self::DATA_OVERWRITE | Self::DATA_EXTEND | Self::DATA_TRUNCATION) != 0
            || r & Self::SECURITY_CHANGE != 0
        {
            EventType::FileModify
        } else {
            EventType::FileAccess
        }
    }

    /// Human-readable description of active flags.
    #[must_use]
    pub fn describe(self) -> String {
        let mut parts = Vec::new();
        let r = self.0;
        if r & Self::FILE_CREATE != 0 {
            parts.push("FILE_CREATE");
        }
        if r & Self::FILE_DELETE != 0 {
            parts.push("FILE_DELETE");
        }
        if r & Self::DATA_OVERWRITE != 0 {
            parts.push("DATA_OVERWRITE");
        }
        if r & Self::DATA_EXTEND != 0 {
            parts.push("DATA_EXTEND");
        }
        if r & Self::DATA_TRUNCATION != 0 {
            parts.push("DATA_TRUNCATION");
        }
        if r & Self::RENAME_OLD_NAME != 0 {
            parts.push("RENAME_OLD_NAME");
        }
        if r & Self::RENAME_NEW_NAME != 0 {
            parts.push("RENAME_NEW_NAME");
        }
        if r & Self::SECURITY_CHANGE != 0 {
            parts.push("SECURITY_CHANGE");
        }
        if r & Self::BASIC_INFO_CHANGE != 0 {
            parts.push("BASIC_INFO_CHANGE");
        }
        if r & Self::CLOSE != 0 {
            parts.push("CLOSE");
        }
        if parts.is_empty() {
            format!("0x{:08X}", self.0)
        } else {
            parts.join(" | ")
        }
    }
}

/// Parsed USN_RECORD_V2 structure.
#[derive(Debug)]
pub struct UsnRecordV2 {
    pub record_length: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_reference_number: u64,
    pub parent_file_reference_number: u64,
    pub usn: i64,
    pub timestamp: i64, // Windows FILETIME (100ns since 1601-01-01)
    pub reason: UsnReasonFlags,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub file_name: String,
}

impl UsnRecordV2 {
    /// Size of V2 fixed header (before filename).
    pub const HEADER_SIZE: usize = 60;
    /// Minimum valid record length.
    pub const MIN_RECORD_SIZE: u32 = 64;
    /// Maximum sane record length (guard against corrupt data).
    pub const MAX_RECORD_SIZE: u32 = 65536;

    /// Convert Windows FILETIME to Unix nanoseconds.
    #[must_use]
    pub fn filetime_to_unix_ns(filetime: i64) -> i64 {
        // Delegate the epoch arithmetic to the spec-cited timeglyph decoder (our
        // own fleet crate, [MS-DTYP]). Fall back to the saturating hand-rolled
        // math for values timeglyph cannot represent, preserving this site's
        // never-None `-> i64` contract.
        const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
        timeglyph::format("filetime")
            .ok()
            .and_then(|f| f.decode_int(filetime).ok())
            .and_then(|posix_ns| i64::try_from(posix_ns.0).ok())
            .unwrap_or_else(|| {
                filetime
                    .saturating_sub(EPOCH_DIFF_100NS)
                    .saturating_mul(100)
            })
    }

    /// Convert to ISO 8601 display string.
    #[must_use]
    pub fn filetime_to_display(filetime: i64) -> String {
        let unix_ns = Self::filetime_to_unix_ns(filetime);
        let secs = unix_ns / 1_000_000_000;
        let nsecs = (unix_ns % 1_000_000_000).unsigned_abs() as u32;
        match DateTime::from_timestamp(secs, nsecs) {
            Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string(),
            None => format!("INVALID_FILETIME({filetime})"),
        }
    }

    /// Parse a V2 record from a byte slice.
    ///
    /// Returns None if the data is too short or appears invalid.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE {
            return None;
        }

        let record_length = u32::from_le_bytes(data[0..4].try_into().ok()?);
        if !(Self::MIN_RECORD_SIZE..=Self::MAX_RECORD_SIZE).contains(&record_length) {
            return None;
        }
        if record_length as usize > data.len() {
            return None;
        }

        let major_version = u16::from_le_bytes(data[4..6].try_into().ok()?);
        let minor_version = u16::from_le_bytes(data[6..8].try_into().ok()?);

        // Only V2 supported for MVP.
        if major_version != 2 {
            return None;
        }

        let file_reference_number = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let parent_file_reference_number = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let usn = i64::from_le_bytes(data[24..32].try_into().ok()?);
        let timestamp = i64::from_le_bytes(data[32..40].try_into().ok()?);
        let reason = UsnReasonFlags(u32::from_le_bytes(data[40..44].try_into().ok()?));
        let source_info = u32::from_le_bytes(data[44..48].try_into().ok()?);
        let security_id = u32::from_le_bytes(data[48..52].try_into().ok()?);
        let file_attributes = u32::from_le_bytes(data[52..56].try_into().ok()?);
        let file_name_length = u16::from_le_bytes(data[56..58].try_into().ok()?) as usize;
        let file_name_offset = u16::from_le_bytes(data[58..60].try_into().ok()?) as usize;

        // Extract UTF-16LE filename.
        let name_end = file_name_offset + file_name_length;
        if name_end > record_length as usize || name_end > data.len() {
            return None;
        }

        let name_bytes = &data[file_name_offset..name_end];
        let file_name = decode_utf16le(name_bytes);

        Some(Self {
            record_length,
            major_version,
            minor_version,
            file_reference_number,
            parent_file_reference_number,
            usn,
            timestamp,
            reason,
            source_info,
            security_id,
            file_attributes,
            file_name,
        })
    }
}

/// Decode UTF-16LE bytes to a String.
fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// USN Journal parser — implements ForensicParser for Issen.
pub struct UsnJrnlParser;

impl ForensicParser for UsnJrnlParser {
    fn name(&self) -> &str {
        "USN Journal Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::UsnJournal]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        let start = std::time::Instant::now();
        let mut stats = ParseStats::new();
        let total_len = input.len();
        let mut offset = 0u64;
        let buf_size = 256 * 1024; // 256 KiB read chunks
        let mut buf = vec![0u8; buf_size];
        let mut batch = Vec::with_capacity(1000);

        while offset < total_len {
            let bytes_read = input.read_at(offset, &mut buf)?;
            if bytes_read == 0 {
                break;
            }

            let chunk = &buf[..bytes_read];
            let mut pos = 0;

            while pos < chunk.len() {
                // Skip zero-filled regions (common in USN journal).
                if chunk[pos] == 0 {
                    // Skip to next 8-byte aligned non-zero position.
                    while pos < chunk.len() && chunk[pos] == 0 {
                        pos += 1;
                    }
                    // Align to 8 bytes.
                    pos = (pos + 7) & !7;
                    if pos >= chunk.len() {
                        break;
                    }
                    continue;
                }

                match UsnRecordV2::parse(&chunk[pos..]) {
                    Some(record) => {
                        let event = record_to_event(&record, "usnjrnl-evidence");
                        batch.push(event);

                        if batch.len() >= 1000 {
                            stats.events_emitted += batch.len() as u64;
                            emitter.emit_batch(std::mem::take(&mut batch))?;
                        }

                        // Advance by record length (8-byte aligned).
                        let advance = ((record.record_length as usize) + 7) & !7;
                        pos += advance.max(8);
                    }
                    None => {
                        stats.errors_recovered += 1;
                        // Skip 8 bytes and try again.
                        pos += 8;
                    }
                }
            }

            offset += bytes_read as u64;
            stats.bytes_processed = offset;
        }

        // Flush remaining batch.
        if !batch.is_empty() {
            stats.events_emitted += batch.len() as u64;
            emitter.emit_batch(batch)?;
        }

        // Declare the terminal state for resumable ingestion (issen #115).
        stats.completion = if total_len == 0 {
            // Nothing to parse — not a journal.
            ParseCompletion::Unsupported
        } else if offset < total_len {
            // The read loop broke on a zero-length read before consuming the
            // declared length — a truncated / interrupted source.
            ParseCompletion::Incomplete {
                offset,
                reason: "short read before end of journal".to_string(),
            }
        } else if stats.errors_recovered > 0 {
            // Reached the end, but skipped some unparseable records.
            ParseCompletion::CompleteWithRecoveries
        } else {
            ParseCompletion::Complete
        };
        stats.duration = start.elapsed();
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(128 * 1024 * 1024), // 128 MiB
            streaming: true,
            deterministic: true,
        }
    }
}

/// Convert a parsed USN record to a TimelineEvent.
fn record_to_event(record: &UsnRecordV2, evidence_source_id: &str) -> TimelineEvent {
    let timestamp_ns = UsnRecordV2::filetime_to_unix_ns(record.timestamp);
    let timestamp_display = UsnRecordV2::filetime_to_display(record.timestamp);
    let event_type = record.reason.to_event_type();
    let reason_desc = record.reason.describe();

    // Include the USN sequence: it uniquely identifies the journal record, so
    // distinct writes to the same file in the same second (e.g. setupapi.dev.log
    // device-install churn) read as the distinct operations they are and carry
    // distinct record_hashes (correct cross-ingest dedup).
    let description = format!(
        "{}: {} ({}) [USN {}]",
        event_type, record.file_name, reason_desc, record.usn
    );

    TimelineEvent::new(
        timestamp_ns,
        timestamp_display,
        event_type,
        ArtifactType::UsnJournal,
        record.file_name.clone(),
        description,
        evidence_source_id.to_string(),
    )
    .with_activity_category(issen_core::ActivityCategory::FileSystemActivity)
    .with_metadata("usn", serde_json::json!(record.usn))
    .with_metadata(
        "reason_flags",
        serde_json::json!(format!("0x{:08X}", record.reason.0)),
    )
    .with_metadata(
        "file_reference",
        serde_json::json!(record.file_reference_number),
    )
    .with_metadata(
        "parent_reference",
        serde_json::json!(record.parent_file_reference_number),
    )
    .with_metadata("file_attributes", serde_json::json!(record.file_attributes))
    // FilePath correlation join key (carried over from the removed cli builtin).
    .with_entity_ref(issen_core::timeline::event::EntityRef::FilePath(
        record.file_name.clone(),
    ))
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(UsnJrnlParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::UsnJournal,
            matches: classify::usn,
            priority: 100,
            disk_sources: &[
                sel::DiskSource::Ntfs(sel::NtfsLoc::NamedStream { path: r"\$Extend\$UsnJrnl", stream: "$J" }),
            ],
            cost: sel::CostTier::Default,
        } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ── Test helpers ──────────────────────────────────────────

    struct CollectingEmitter {
        events: Mutex<Vec<TimelineEvent>>,
    }

    impl CollectingEmitter {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
        fn into_events(self) -> Vec<TimelineEvent> {
            self.events.into_inner().unwrap_or_default()
        }
    }

    impl EventEmitter for CollectingEmitter {
        fn emit(&self, event: TimelineEvent) -> Result<(), RtError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
        fn emit_batch(&self, events: Vec<TimelineEvent>) -> Result<(), RtError> {
            self.events.lock().unwrap().extend(events);
            Ok(())
        }
    }

    struct SliceSource(Vec<u8>);

    impl DataSource for SliceSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let off = offset as usize;
            if off >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - off);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            Ok(n)
        }
    }

    /// Build a synthetic USN_RECORD_V2 in binary form.
    fn build_usn_v2_record(
        file_name: &str,
        timestamp_filetime: i64,
        reason: u32,
        frn: u64,
        parent_frn: u64,
        usn: i64,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = file_name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let file_name_offset: u16 = 60;
        let record_length = (file_name_offset as usize + name_bytes_len) as u32;
        // Round up to 8-byte alignment.
        let padded_length = (record_length + 7) & !7;

        let mut data = vec![0u8; padded_length as usize];

        // RecordLength
        data[0..4].copy_from_slice(&padded_length.to_le_bytes());
        // MajorVersion = 2
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        // MinorVersion = 0
        data[6..8].copy_from_slice(&0u16.to_le_bytes());
        // FileReferenceNumber
        data[8..16].copy_from_slice(&frn.to_le_bytes());
        // ParentFileReferenceNumber
        data[16..24].copy_from_slice(&parent_frn.to_le_bytes());
        // Usn
        data[24..32].copy_from_slice(&usn.to_le_bytes());
        // TimeStamp (FILETIME)
        data[32..40].copy_from_slice(&timestamp_filetime.to_le_bytes());
        // Reason
        data[40..44].copy_from_slice(&reason.to_le_bytes());
        // SourceInfo
        data[44..48].copy_from_slice(&0u32.to_le_bytes());
        // SecurityId
        data[48..52].copy_from_slice(&0u32.to_le_bytes());
        // FileAttributes
        data[52..56].copy_from_slice(&0x20u32.to_le_bytes()); // ARCHIVE
                                                              // FileNameLength
        data[56..58].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        // FileNameOffset
        data[58..60].copy_from_slice(&file_name_offset.to_le_bytes());

        // Filename (UTF-16LE)
        for (i, &u) in name_utf16.iter().enumerate() {
            let off = 60 + i * 2;
            data[off..off + 2].copy_from_slice(&u.to_le_bytes());
        }

        data
    }

    // ── Tests ─────────────────────────────────────────────────

    #[test]
    fn test_parse_single_v2_record() {
        // 2023-11-14T22:13:20Z in FILETIME
        let filetime: i64 = 133_451_432_000_000_000;
        let data = build_usn_v2_record(
            "report.docx",
            filetime,
            UsnReasonFlags::FILE_CREATE,
            12345,
            67890,
            1024,
        );

        let record = UsnRecordV2::parse(&data).expect("parse record");
        assert_eq!(record.file_name, "report.docx");
        assert_eq!(record.major_version, 2);
        assert_eq!(record.reason.0, UsnReasonFlags::FILE_CREATE);
        assert_eq!(record.file_reference_number, 12345);
        assert_eq!(record.parent_file_reference_number, 67890);
        assert_eq!(record.usn, 1024);
    }

    #[test]
    fn test_filetime_to_unix_ns() {
        // 2023-11-14T22:13:20Z = 1700000000 seconds since Unix epoch
        // FILETIME = (unix_ns / 100) + EPOCH_DIFF = 17_000_000_000_000_000 + 116_444_736_000_000_000
        let filetime: i64 = 133_444_736_000_000_000;
        let unix_ns = UsnRecordV2::filetime_to_unix_ns(filetime);
        let expected_ns: i64 = 1_700_000_000 * 1_000_000_000;
        assert_eq!(unix_ns, expected_ns);
    }

    #[test]
    fn test_filetime_to_display() {
        let filetime: i64 = 133_444_736_000_000_000;
        let display = UsnRecordV2::filetime_to_display(filetime);
        assert!(display.starts_with("2023-11-14T22:13:20"), "Got: {display}");
    }

    #[test]
    fn test_reason_flags_to_event_type() {
        assert_eq!(
            UsnReasonFlags(UsnReasonFlags::FILE_CREATE).to_event_type(),
            EventType::FileCreate,
        );
        assert_eq!(
            UsnReasonFlags(UsnReasonFlags::FILE_DELETE).to_event_type(),
            EventType::FileDelete,
        );
        assert_eq!(
            UsnReasonFlags(UsnReasonFlags::RENAME_NEW_NAME).to_event_type(),
            EventType::FileRename,
        );
        assert_eq!(
            UsnReasonFlags(UsnReasonFlags::DATA_OVERWRITE).to_event_type(),
            EventType::FileModify,
        );
        assert_eq!(
            UsnReasonFlags(UsnReasonFlags::CLOSE).to_event_type(),
            EventType::FileAccess,
        );
    }

    #[test]
    fn test_reason_flags_describe() {
        let flags = UsnReasonFlags(UsnReasonFlags::FILE_CREATE | UsnReasonFlags::CLOSE);
        let desc = flags.describe();
        assert!(desc.contains("FILE_CREATE"));
        assert!(desc.contains("CLOSE"));
    }

    #[test]
    fn test_parser_trait_contract() {
        let parser = UsnJrnlParser;
        assert_eq!(parser.name(), "USN Journal Parser");
        assert_eq!(parser.supported_artifacts(), &[ArtifactType::UsnJournal]);
        assert!(parser.capabilities().streaming);
        assert!(parser.capabilities().deterministic);
    }

    #[test]
    fn test_parse_multiple_records() {
        let filetime1: i64 = 133_451_432_000_000_000;
        let filetime2: i64 = 133_451_432_100_000_000; // 10 seconds later

        let mut data = build_usn_v2_record(
            "file1.txt",
            filetime1,
            UsnReasonFlags::FILE_CREATE,
            100,
            1,
            1000,
        );
        data.extend(build_usn_v2_record(
            "file2.exe",
            filetime2,
            UsnReasonFlags::FILE_DELETE | UsnReasonFlags::CLOSE,
            200,
            1,
            2000,
        ));

        let source = SliceSource(data);
        let emitter = CollectingEmitter::new();
        let parser = UsnJrnlParser;

        let stats = parser
            .parse(
                &source,
                &emitter,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse");
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(stats.errors_recovered, 0);

        let events = emitter.into_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].source, ArtifactType::UsnJournal);
        assert!(events[0].description.contains("file1.txt"));
        assert!(events[1].description.contains("file2.exe"));
        assert_eq!(events[1].event_type, EventType::FileDelete);
    }

    #[test]
    fn usn_sequence_distinguishes_otherwise_identical_records() {
        // Two USN records identical in name / reason / timestamp but with
        // different USN sequence numbers are DISTINCT journal entries (e.g.
        // setupapi.dev.log extended twice in the same second). The event must
        // surface the USN so the rows read distinctly AND carry distinct
        // record_hashes (so a re-ingest dedups them correctly, but two real
        // writes stay two events).
        let mk = |usn: i64| UsnRecordV2 {
            record_length: 0,
            major_version: 2,
            minor_version: 0,
            file_reference_number: 1,
            parent_file_reference_number: 1,
            usn,
            timestamp: 130_000_000_000_000_000,
            reason: UsnReasonFlags(UsnReasonFlags::DATA_EXTEND),
            source_info: 0,
            security_id: 0,
            file_attributes: 0,
            file_name: "setupapi.dev.log".to_string(),
        };
        let a = record_to_event(&mk(1000), "src");
        let b = record_to_event(&mk(2000), "src");
        assert!(
            a.description.contains("1000") && b.description.contains("2000"),
            "the USN sequence must appear in the description: {:?} / {:?}",
            a.description,
            b.description
        );
        assert_ne!(
            a.description, b.description,
            "distinct USN records must read distinctly"
        );
        assert_ne!(
            a.record_hash, b.record_hash,
            "distinct USN records must carry distinct record_hashes"
        );
    }

    #[test]
    fn test_parse_with_zero_padding() {
        let filetime: i64 = 133_451_432_000_000_000;
        let record = build_usn_v2_record(
            "padded.txt",
            filetime,
            UsnReasonFlags::FILE_CREATE,
            100,
            1,
            500,
        );

        // Add 64 bytes of zero padding before the record.
        let mut data = vec![0u8; 64];
        data.extend(&record);

        let source = SliceSource(data);
        let emitter = CollectingEmitter::new();
        let parser = UsnJrnlParser;

        let stats = parser
            .parse(
                &source,
                &emitter,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse");
        assert_eq!(
            stats.events_emitted, 1,
            "Should skip padding and find the record"
        );
    }

    #[test]
    fn test_parse_empty_input() {
        let source = SliceSource(vec![]);
        let emitter = CollectingEmitter::new();
        let parser = UsnJrnlParser;

        let stats = parser
            .parse(
                &source,
                &emitter,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse");
        assert_eq!(stats.events_emitted, 0);
        assert_eq!(stats.bytes_processed, 0);
    }

    #[test]
    fn completion_status_reflects_terminal_state() {
        // issen #115 step 1.3: USN must declare a trustworthy terminal state.
        let parser = UsnJrnlParser;

        // Empty input is not a journal -> Unsupported (not a silent complete).
        let stats = parser
            .parse(
                &SliceSource(vec![]),
                &CollectingEmitter::new(),
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse");
        assert_eq!(stats.completion, ParseCompletion::Unsupported);

        // A valid journal consumed cleanly to the end -> Complete.
        let data = build_usn_v2_record(
            "f.txt",
            133_451_432_000_000_000,
            UsnReasonFlags::FILE_CREATE,
            100,
            1,
            1000,
        );
        let stats = parser
            .parse(
                &SliceSource(data),
                &CollectingEmitter::new(),
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse");
        assert_eq!(stats.errors_recovered, 0);
        assert_eq!(stats.completion, ParseCompletion::Complete);
    }

    #[test]
    fn test_parse_truncated_record() {
        // A record that claims to be 80 bytes but we only have 20 bytes.
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&80u32.to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());

        let result = UsnRecordV2::parse(&data);
        assert!(result.is_none(), "Truncated record should return None");
    }

    #[test]
    fn test_record_to_event_metadata() {
        let filetime: i64 = 133_451_432_000_000_000;
        let data = build_usn_v2_record(
            "test.txt",
            filetime,
            UsnReasonFlags::FILE_CREATE,
            42,
            1,
            999,
        );
        let record = UsnRecordV2::parse(&data).expect("parse");
        let event = record_to_event(&record, "evidence-001");

        assert_eq!(event.source, ArtifactType::UsnJournal);
        assert_eq!(event.event_type, EventType::FileCreate);
        assert_eq!(event.evidence_source_id, "evidence-001");
        assert!(event.metadata.contains_key("usn"));
        assert!(event.metadata.contains_key("reason_flags"));
        assert!(event.metadata.contains_key("file_reference"));
        assert_eq!(event.metadata["usn"], serde_json::json!(999));
        assert_eq!(event.metadata["file_reference"], serde_json::json!(42));
    }

    #[test]
    fn test_utf16le_decode() {
        // "test" in UTF-16LE
        let data = [0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        assert_eq!(decode_utf16le(&data), "test");
    }

    #[test]
    fn record_to_event_tags_filesystem_activity() {
        // $UsnJrnl records are filesystem change events — every emitted event
        // carries the CADET FileSystemActivity category (the meaning axis),
        // independent of the UsnJournal source (the routing axis).
        let data = build_usn_v2_record(
            "test.txt",
            133_451_432_000_000_000,
            UsnReasonFlags::FILE_CREATE,
            42,
            1,
            999,
        );
        let record = UsnRecordV2::parse(&data).expect("parse");
        let event = record_to_event(&record, "evidence-001");
        assert_eq!(
            event.activity_category,
            Some(issen_core::ActivityCategory::FileSystemActivity)
        );
    }

    #[test]
    fn record_to_event_carries_filepath_entity_ref() {
        // This plugin is the canonical USN parser (the issen-cli builtin is being
        // removed). It must carry the FilePath correlation join key the builtin
        // had (USN rename/move join keys).
        use issen_core::timeline::event::EntityRef;
        let data = build_usn_v2_record(
            "coreupdater.exe",
            133_451_432_000_000_000,
            UsnReasonFlags::FILE_CREATE,
            42,
            1,
            999,
        );
        let record = UsnRecordV2::parse(&data).expect("parse");
        let event = record_to_event(&record, "evidence-001");
        assert!(
            event
                .entity_refs
                .contains(&EntityRef::FilePath("coreupdater.exe".to_string())),
            "USN event must carry a FilePath entity ref for correlation"
        );
    }
}
