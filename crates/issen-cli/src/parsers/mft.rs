//! MFT parser — ForensicParser impl using the `mft` crate.
//!
//! Moved from `rt-parser-mft`. Registers via `inventory::submit!`.

use chrono::{DateTime, Utc};
use mft::attribute::x10::StandardInfoAttr;
use mft::attribute::MftAttributeContent;
use mft::attribute::MftAttributeType;
use mft::MftParser;
use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use tracing::warn;

/// NTFS Master File Table parser.
pub struct MftFileParser;

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

        let buffer = read_all(input)?;
        stats.bytes_processed = buffer.len() as u64;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
            self.events.lock().expect("lock").push(event);
            Ok(())
        }
        fn emit_batch(&self, events: Vec<TimelineEvent>) -> Result<(), RtError> {
            self.events.lock().expect("lock").extend(events);
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

    #[test]
    fn test_parser_trait_contract() {
        let parser = MftFileParser;
        assert_eq!(parser.name(), "MFT Parser");
        assert_eq!(parser.supported_artifacts(), &[ArtifactType::Mft]);
        let caps = parser.capabilities();
        assert!(!caps.streaming);
        assert!(caps.deterministic);
        assert!(caps.max_memory_bytes.is_some());
    }

    #[test]
    fn test_datetime_to_ns() {
        let dt = DateTime::parse_from_rfc3339("2023-11-14T22:13:20Z")
            .expect("valid")
            .with_timezone(&Utc);
        assert_eq!(datetime_to_ns(&dt), 1_700_000_000_i64 * 1_000_000_000);
    }

    #[test]
    fn test_datetime_to_display() {
        let dt = DateTime::parse_from_rfc3339("2023-11-14T22:13:20Z")
            .expect("valid")
            .with_timezone(&Utc);
        assert!(datetime_to_display(&dt).starts_with("2023-11-14T22:13:20"));
    }

    #[test]
    fn test_mace_event_file() {
        let dt = DateTime::parse_from_rfc3339("2023-06-15T10:30:00Z")
            .expect("valid")
            .with_timezone(&Utc);
        let ev = mace_event(
            &dt,
            EventType::FileCreate,
            42,
            "Users/analyst/report.docx",
            false,
            "ev-1",
        );
        assert_eq!(ev.event_type, EventType::FileCreate);
        assert!(ev.description.contains("report.docx"));
        assert!(ev.description.contains("MFT entry 42"));
        assert!(ev.description.contains("file"));
    }

    #[test]
    fn test_mace_event_directory() {
        let dt = DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
            .expect("valid")
            .with_timezone(&Utc);
        let ev = mace_event(
            &dt,
            EventType::FileModify,
            5,
            "Windows/System32",
            true,
            "src-1",
        );
        assert!(ev.description.contains("directory"));
    }

    #[test]
    fn test_parse_empty_input() {
        let source = SliceSource(vec![]);
        let emitter = CollectingEmitter::new();
        let stats = MftFileParser.parse(&source, &emitter).expect("parse");
        assert_eq!(stats.events_emitted, 0);
        assert!(emitter.into_events().is_empty());
    }

    #[test]
    fn test_parse_too_small() {
        let source = SliceSource(vec![0x46, 0x49, 0x4C, 0x45]);
        let emitter = CollectingEmitter::new();
        let stats = MftFileParser.parse(&source, &emitter).expect("parse");
        assert_eq!(stats.events_emitted, 0);
    }

    #[test]
    fn test_parse_garbage_data() {
        let garbage: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let source = SliceSource(garbage);
        let emitter = CollectingEmitter::new();
        let stats = MftFileParser.parse(&source, &emitter).expect("parse");
        assert_eq!(emitter.into_events().len(), stats.events_emitted as usize);
    }
}
