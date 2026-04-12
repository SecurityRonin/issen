//! MFT parser for `RapidTriage`.
//!
//! Wraps the `mft` crate to parse NTFS Master File Table (`$MFT`) files and
//! emit [`TimelineEvent`]s via the [`ForensicParser`] trait.  Each MFT entry
//! can produce up to four events (MACE timestamps): Modified, Accessed,
//! Created, and Entry-modified.

use chrono::{DateTime, Utc};
use mft::attribute::x10::StandardInfoAttr;
use mft::attribute::MftAttributeContent;
use mft::attribute::MftAttributeType;
use mft::MftParser;
use rt_core::artifacts::ArtifactType;
use rt_core::error::RtError;
use rt_core::plugin::registry::ParserRegistration;
use rt_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use rt_core::timeline::event::{EventType, TimelineEvent};
use tracing::warn;

/// NTFS Master File Table parser.
pub struct MftFileParser;

/// Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01) to
/// nanoseconds since the Unix epoch.
///
/// Returns `None` if `filetime` is zero (represents "not set") or if the
/// value predates the Unix epoch (1970-01-01T00:00:00Z, FILETIME
/// `116_444_736_000_000_000`).
#[must_use]
pub fn filetime_to_ns(filetime: u64) -> Option<i64> {
    /// 100-nanosecond ticks between 1601-01-01 (Windows epoch) and
    /// 1970-01-01 (Unix epoch).
    const FILETIME_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

    if filetime == 0 {
        return None;
    }
    // Reject FILETIMEs that predate the Unix epoch.
    let ticks_since_unix = filetime.checked_sub(FILETIME_EPOCH_OFFSET)?;
    // Each tick is 100 ns; convert to nanoseconds.
    // Use i128 to avoid overflow before casting to i64.
    let ns = i128::from(ticks_since_unix) * 100;
    // Clamp to i64 range — any realistic forensic timestamp fits easily.
    #[allow(clippy::cast_possible_truncation)]
    let result = ns.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    Some(result)
}

/// Convert a `chrono::DateTime<Utc>` to nanoseconds since the Unix epoch.
#[must_use]
pub fn datetime_to_ns(dt: &DateTime<Utc>) -> i64 {
    dt.timestamp_nanos_opt()
        .unwrap_or_else(|| dt.timestamp() * 1_000_000_000)
}

/// Convert a `chrono::DateTime<Utc>` to an ISO 8601 display string.
#[must_use]
pub fn datetime_to_display(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string()
}

/// Create a [`TimelineEvent`] from an MFT timestamp.
fn mace_event(
    timestamp: &DateTime<Utc>,
    event_type: EventType,
    entry_id: u64,
    full_path: &str,
    is_dir: bool,
    source_id: &str,
) -> TimelineEvent {
    let ts_ns = datetime_to_ns(timestamp);
    let ts_display = datetime_to_display(timestamp);
    let kind = if is_dir { "directory" } else { "file" };
    let description = format!("{event_type}: {full_path} (MFT entry {entry_id}, {kind})");

    TimelineEvent::new(
        ts_ns,
        ts_display,
        event_type,
        ArtifactType::Mft,
        full_path.to_string(),
        description,
        source_id.to_string(),
    )
    .with_metadata("mft_entry_id", serde_json::json!(entry_id))
    .with_metadata("is_directory", serde_json::json!(is_dir))
}

/// Extract the `$STANDARD_INFORMATION` attribute from an MFT entry.
fn extract_standard_info(entry: &mft::entry::MftEntry) -> Option<StandardInfoAttr> {
    entry
        .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
        .filter_map(std::result::Result::ok)
        .find_map(|attr| {
            if let MftAttributeContent::AttrX10(si) = attr.data {
                Some(si)
            } else {
                None
            }
        })
}

/// Minimum valid MFT size — at least one 1024-byte entry.
const MIN_MFT_SIZE: u64 = 1024;

/// Emit the four MACE timestamp events for a single MFT entry.
#[allow(clippy::too_many_arguments)]
fn emit_mace_timestamps(
    batch: &mut Vec<TimelineEvent>,
    modified: &DateTime<Utc>,
    accessed: &DateTime<Utc>,
    created: &DateTime<Utc>,
    mft_modified: &DateTime<Utc>,
    entry_id: u64,
    full_path: &str,
    is_dir: bool,
    source_id: &str,
) {
    batch.push(mace_event(
        modified,
        EventType::FileModify,
        entry_id,
        full_path,
        is_dir,
        source_id,
    ));
    batch.push(mace_event(
        accessed,
        EventType::FileAccess,
        entry_id,
        full_path,
        is_dir,
        source_id,
    ));
    batch.push(mace_event(
        created,
        EventType::FileCreate,
        entry_id,
        full_path,
        is_dir,
        source_id,
    ));
    batch.push(mace_event(
        mft_modified,
        EventType::Other("MftEntryModified".to_string()),
        entry_id,
        full_path,
        is_dir,
        source_id,
    ));
}

/// Read the full contents of a `DataSource` into a `Vec<u8>`.
#[allow(clippy::cast_possible_truncation)]
fn read_all(input: &dyn DataSource) -> Result<Vec<u8>, RtError> {
    let total_len = input.len();
    let mut buffer = vec![0u8; total_len as usize];
    let mut offset = 0u64;
    while offset < total_len {
        let bytes_read = input.read_at(offset, &mut buffer[offset as usize..])?;
        if bytes_read == 0 {
            break;
        }
        offset += bytes_read as u64;
    }
    Ok(buffer)
}

#[allow(clippy::unnecessary_literal_bound)]
impl ForensicParser for MftFileParser {
    fn name(&self) -> &str {
        "MFT Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Mft]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let start = std::time::Instant::now();
        let mut stats = ParseStats::new();

        let total_len = input.len();
        if total_len == 0 {
            stats.duration = start.elapsed();
            return Ok(stats);
        }

        if total_len < MIN_MFT_SIZE {
            warn!(
                len = total_len,
                "Input too small to be a valid MFT, skipping"
            );
            stats.duration = start.elapsed();
            return Ok(stats);
        }

        // Read the entire MFT into memory (required by the mft crate).
        let buffer = read_all(input)?;
        stats.bytes_processed = buffer.len() as u64;

        // Parse via the mft crate.
        let mut parser = match MftParser::from_buffer(buffer) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Failed to initialise MFT parser");
                stats.duration = start.elapsed();
                return Ok(stats);
            }
        };

        let source_id = "mft-evidence";
        let mut batch: Vec<TimelineEvent> = Vec::with_capacity(1000);
        let entry_count = parser.get_entry_count();

        for entry_idx in 0..entry_count {
            let entry = match parser.get_entry(entry_idx) {
                Ok(e) => e,
                Err(e) => {
                    if entry_idx > 24 {
                        stats.errors_recovered += 1;
                    }
                    tracing::trace!(entry = entry_idx, error = %e, "Skipping MFT entry");
                    continue;
                }
            };

            if !entry.is_allocated() {
                continue;
            }

            let Some(file_name) = entry.find_best_name_attribute() else {
                continue;
            };

            let full_path = match parser.get_full_path_for_entry(&entry) {
                Ok(Some(p)) => p.to_string_lossy().to_string(),
                _ => file_name.name.clone(),
            };

            let is_dir = entry.is_dir();
            let entry_id = entry.header.record_number;

            // Prefer $STANDARD_INFORMATION timestamps; fall back to $FILE_NAME.
            if let Some(si) = extract_standard_info(&entry) {
                emit_mace_timestamps(
                    &mut batch,
                    &si.modified,
                    &si.accessed,
                    &si.created,
                    &si.mft_modified,
                    entry_id,
                    &full_path,
                    is_dir,
                    source_id,
                );
            } else {
                emit_mace_timestamps(
                    &mut batch,
                    &file_name.modified,
                    &file_name.accessed,
                    &file_name.created,
                    &file_name.mft_modified,
                    entry_id,
                    &full_path,
                    is_dir,
                    source_id,
                );
            }

            if batch.len() >= 1000 {
                stats.events_emitted += batch.len() as u64;
                emitter.emit_batch(std::mem::take(&mut batch))?;
            }
        }

        if !batch.is_empty() {
            stats.events_emitted += batch.len() as u64;
            emitter.emit_batch(batch)?;
        }

        stats.duration = start.elapsed();
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(512 * 1024 * 1024), // 512 MiB — MFT loaded fully
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(MftFileParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -- Test helpers -------------------------------------------------------

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
            self.events
                .lock()
                .expect("CollectingEmitter lock poisoned")
                .push(event);
            Ok(())
        }
        fn emit_batch(&self, events: Vec<TimelineEvent>) -> Result<(), RtError> {
            self.events
                .lock()
                .expect("CollectingEmitter lock poisoned")
                .extend(events);
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

    // -- Trait contract tests -----------------------------------------------

    #[test]
    fn test_parser_trait_contract() {
        let parser = MftFileParser;
        assert_eq!(parser.name(), "MFT Parser");
        assert_eq!(parser.supported_artifacts(), &[ArtifactType::Mft]);
        let caps = parser.capabilities();
        assert!(!caps.streaming, "MFT parser loads entire file");
        assert!(caps.deterministic);
        assert!(caps.max_memory_bytes.is_some());
    }

    // -- FILETIME accuracy tests --------------------------------------------

    /// Windows FILETIME epoch offset: 100-ns ticks from 1601-01-01 to 1970-01-01.
    const FILETIME_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

    #[test]
    fn test_filetime_to_ns_known_value() {
        // FILETIME 132_000_000_000_000_000 is a known timestamp in the Windows era.
        // Formula: (filetime - 116_444_736_000_000_000) * 100
        let filetime: u64 = 132_000_000_000_000_000;
        let expected_ns: i64 = ((filetime - FILETIME_EPOCH_OFFSET) as i64) * 100;
        assert_eq!(filetime_to_ns(filetime), Some(expected_ns));
    }

    #[test]
    fn test_filetime_to_ns_unix_epoch() {
        // FILETIME 116_444_736_000_000_000 == Unix epoch 1970-01-01T00:00:00Z → 0 ns.
        let filetime: u64 = FILETIME_EPOCH_OFFSET;
        assert_eq!(filetime_to_ns(filetime), Some(0));
    }

    #[test]
    fn test_filetime_to_ns_zero_is_none() {
        // FILETIME 0 means "not set" in the Windows world — should return None.
        assert_eq!(filetime_to_ns(0), None);
    }

    #[test]
    fn test_filetime_to_ns_before_unix_epoch_is_none() {
        // A FILETIME before Unix epoch (e.g. 1601-01-01T00:00:00Z = FILETIME 1)
        // cannot be represented as a positive Unix timestamp.
        assert_eq!(filetime_to_ns(1), None);
        // Also test a value just below the epoch offset.
        assert_eq!(filetime_to_ns(FILETIME_EPOCH_OFFSET - 1), None);
    }

    // -- datetime_to_display round-trip accuracy ----------------------------

    #[test]
    fn test_datetime_to_display_known_filetime_roundtrip() {
        // FILETIME 132_000_000_000_000_000 corresponds to 2019-04-17T18:40:00Z.
        // (132_000_000_000_000_000 - 116_444_736_000_000_000) * 100 ns
        // = 15_555_264_000_000_000 * 100 = 1_555_526_400_000_000_000 ns
        // = 1_555_526_400 seconds = 2019-04-17T18:40:00Z
        let ns: i64 = 1_555_526_400_000_000_000;
        use chrono::TimeZone;
        let dt = Utc.timestamp_nanos(ns);
        let display = datetime_to_display(&dt);
        assert!(
            display.starts_with("2019-04-17T18:40:00"),
            "Expected date 2019-04-17T18:40:00, got: {display}"
        );
    }

    #[test]
    fn test_datetime_to_display_unix_epoch() {
        use chrono::TimeZone;
        let dt = Utc.timestamp_nanos(0);
        let display = datetime_to_display(&dt);
        assert!(
            display.starts_with("1970-01-01T00:00:00"),
            "Expected Unix epoch display, got: {display}"
        );
    }

    #[test]
    fn test_datetime_to_display_format_iso8601() {
        // Verify the format includes sub-second precision and trailing 'Z'.
        let dt = DateTime::parse_from_rfc3339("2019-02-22T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let display = datetime_to_display(&dt);
        // Should match "2019-02-22T00:00:00.000000000Z"
        assert_eq!(display, "2019-02-22T00:00:00.000000000Z");
    }

    // -- Timestamp helpers --------------------------------------------------

    #[test]
    fn test_datetime_to_ns() {
        let dt = DateTime::parse_from_rfc3339("2023-11-14T22:13:20Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let ns = datetime_to_ns(&dt);
        let expected = 1_700_000_000_i64 * 1_000_000_000;
        assert_eq!(ns, expected);
    }

    #[test]
    fn test_datetime_to_display() {
        let dt = DateTime::parse_from_rfc3339("2023-11-14T22:13:20Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let display = datetime_to_display(&dt);
        assert!(display.starts_with("2023-11-14T22:13:20"), "Got: {display}");
    }

    // -- mace_event unit tests ----------------------------------------------

    #[test]
    fn test_mace_event_file() {
        let dt = DateTime::parse_from_rfc3339("2023-06-15T10:30:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let event = mace_event(
            &dt,
            EventType::FileCreate,
            42,
            "Users/analyst/report.docx",
            false,
            "evidence-001",
        );
        assert_eq!(event.event_type, EventType::FileCreate);
        assert_eq!(event.source, ArtifactType::Mft);
        assert_eq!(event.evidence_source_id, "evidence-001");
        assert!(event.description.contains("report.docx"));
        assert!(event.description.contains("MFT entry 42"));
        assert!(event.description.contains("file"));
        assert_eq!(event.metadata["mft_entry_id"], serde_json::json!(42));
        assert_eq!(event.metadata["is_directory"], serde_json::json!(false));
    }

    #[test]
    fn test_mace_event_directory() {
        let dt = DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let event = mace_event(
            &dt,
            EventType::FileModify,
            5,
            "Windows/System32",
            true,
            "src-1",
        );
        assert!(event.description.contains("directory"));
        assert_eq!(event.metadata["is_directory"], serde_json::json!(true));
    }

    #[test]
    fn test_mace_event_entry_modified_type() {
        let dt = DateTime::parse_from_rfc3339("2023-06-15T10:30:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let event = mace_event(
            &dt,
            EventType::Other("MftEntryModified".to_string()),
            100,
            "test.txt",
            false,
            "ev-1",
        );
        assert_eq!(
            event.event_type,
            EventType::Other("MftEntryModified".to_string())
        );
    }

    // -- parse() with invalid inputs ----------------------------------------

    #[test]
    fn test_parse_empty_input() {
        let source = SliceSource(vec![]);
        let emitter = CollectingEmitter::new();
        let parser = MftFileParser;

        let stats = parser.parse(&source, &emitter).expect("parse empty input");
        assert_eq!(stats.events_emitted, 0);
        assert_eq!(stats.bytes_processed, 0);

        let events = emitter.into_events();
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_too_small() {
        // A buffer smaller than a single MFT entry (1024 bytes).
        let source = SliceSource(vec![0x46, 0x49, 0x4C, 0x45]); // "FILE" magic partial
        let emitter = CollectingEmitter::new();
        let parser = MftFileParser;

        let stats = parser.parse(&source, &emitter).expect("parse tiny input");
        assert_eq!(stats.events_emitted, 0);

        let events = emitter.into_events();
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_garbage_data() {
        // 2048 bytes of garbage that starts with enough data to pass the size
        // check but is not a valid MFT.
        let garbage: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let source = SliceSource(garbage);
        let emitter = CollectingEmitter::new();
        let parser = MftFileParser;

        let stats = parser
            .parse(&source, &emitter)
            .expect("parse garbage gracefully");
        // Should not crash; may produce 0 events or handle error gracefully.
        let events = emitter.into_events();
        assert_eq!(events.len(), stats.events_emitted as usize);
    }
}
