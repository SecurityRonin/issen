//! MFT parser — ForensicParser impl using the `mft` crate.
//!
//! Moved from `rt-parser-mft`. Registers via `inventory::submit!`.

use chrono::{DateTime, Utc};
use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};
use mft::attribute::x10::StandardInfoAttr;
use mft::attribute::x30::FileNameAttr;
use mft::attribute::MftAttributeContent;
use mft::attribute::MftAttributeType;
use mft::MftParser;
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
    // PRE-2: the file path as a typed correlation join key.
    .with_entity_ref(EntityRef::FilePath(full_path.to_string()))
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
///
/// `fn_attr` carries the `$FILE_NAME` attribute when it co-exists with the
/// `$STANDARD_INFORMATION` source of these timestamps. When present, its four
/// timestamps are surfaced onto the `FileCreate` event's metadata
/// (`fn_created` / `fn_modified` / `fn_accessed` / `fn_mft_modified`) so a
/// downstream timestomp detector can compare `$SI` vs `$FN`. Pass `None` when
/// only one of the two attributes exists — behavior is then unchanged.
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
    fn_attr: Option<&FileNameAttr>,
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
    let mut create_event = mace_event(
        created,
        EventType::FileCreate,
        entry_id,
        full_path,
        is_dir,
        source_id,
    );
    // Surface all four $SI MACE values (nanosecond-precise) onto the FileCreate
    // event so the timestomp FP gate (copy/volume-move) and the stronger
    // si_modified<fn_created ordering test can run from one event.
    create_event = create_event
        .with_metadata(
            "si_created",
            serde_json::json!(datetime_to_display(created)),
        )
        .with_metadata(
            "si_modified",
            serde_json::json!(datetime_to_display(modified)),
        )
        .with_metadata(
            "si_accessed",
            serde_json::json!(datetime_to_display(accessed)),
        )
        .with_metadata(
            "si_mft_changed",
            serde_json::json!(datetime_to_display(mft_modified)),
        );
    if let Some(fname) = fn_attr {
        create_event = create_event
            .with_metadata(
                "fn_created",
                serde_json::json!(datetime_to_display(&fname.created)),
            )
            .with_metadata(
                "fn_modified",
                serde_json::json!(datetime_to_display(&fname.modified)),
            )
            .with_metadata(
                "fn_accessed",
                serde_json::json!(datetime_to_display(&fname.accessed)),
            )
            .with_metadata(
                "fn_mft_modified",
                serde_json::json!(datetime_to_display(&fname.mft_modified)),
            );
    }
    batch.push(create_event);
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
                    Some(&file_name),
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
                    None,
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
    fn mace_event_carries_filepath_entity_ref() {
        // PRE-2: file events carry EntityRef::FilePath — the join key the
        // RELOCATE / COPY-DELETE / EXFIL-STAGE correlation rules need.
        use issen_core::timeline::event::EntityRef;
        let dt = DateTime::parse_from_rfc3339("2020-09-19T03:24:06Z")
            .expect("valid")
            .with_timezone(&Utc);
        let ev = mace_event(
            &dt,
            EventType::FileCreate,
            42,
            "Windows/System32/coreupdater.exe",
            false,
            "dc01",
        );
        assert!(
            ev.entity_refs.contains(&EntityRef::FilePath(
                "Windows/System32/coreupdater.exe".to_string()
            )),
            "{:?}",
            ev.entity_refs
        );
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

    // -- $FN timestamp surfacing (C1) ---------------------------------------

    /// Build a synthetic `$FILE_NAME` attribute with all four MACE timestamps
    /// set to the same FILETIME, distinct from any `$SI` set.
    fn build_file_name_attr(filetime: u64, name: &str) -> mft::attribute::x30::FileNameAttr {
        use std::io::Cursor;
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u64.to_le_bytes()); // parent MftReference
        for _ in 0..4 {
            buf.extend_from_slice(&filetime.to_le_bytes()); // created/mod/mft_mod/acc
        }
        buf.extend_from_slice(&0u64.to_le_bytes()); // logical_size
        buf.extend_from_slice(&0u64.to_le_bytes()); // physical_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // reparse_value
        let utf16: Vec<u16> = name.encode_utf16().collect();
        buf.push(utf16.len() as u8); // name_length
        buf.push(1u8); // namespace = Win32
        for code_unit in utf16 {
            buf.extend_from_slice(&code_unit.to_le_bytes());
        }
        mft::attribute::x30::FileNameAttr::from_stream(&mut Cursor::new(buf))
            .expect("valid synthetic $FN attribute")
    }

    #[test]
    fn test_fn_timestamps_surfaced_when_si_present() {
        use chrono::TimeZone;

        let si_created = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let si_modified = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 0).unwrap();
        let si_accessed = Utc.with_ymd_and_hms(2020, 1, 3, 0, 0, 0).unwrap();
        let si_mft_modified = Utc.with_ymd_and_hms(2020, 1, 4, 0, 0, 0).unwrap();

        let fn_unix = Utc
            .with_ymd_and_hms(2010, 6, 15, 12, 0, 0)
            .unwrap()
            .timestamp();
        let fn_filetime = (fn_unix as u64) * 10_000_000 + 116_444_736_000_000_000;
        let fn_attr = build_file_name_attr(fn_filetime, "report.docx");

        let mut batch: Vec<TimelineEvent> = Vec::new();
        emit_mace_timestamps(
            &mut batch,
            &si_modified,
            &si_accessed,
            &si_created,
            &si_mft_modified,
            42,
            "Users/analyst/report.docx",
            false,
            "evidence-001",
            Some(&fn_attr),
        );

        let create = batch
            .iter()
            .find(|e| e.event_type == EventType::FileCreate)
            .expect("FileCreate event emitted");

        assert_eq!(create.timestamp_ns, datetime_to_ns(&si_created));
        assert_eq!(
            create.metadata["fn_created"],
            serde_json::json!(datetime_to_display(&fn_attr.created)),
        );
        assert_eq!(
            create.metadata["fn_modified"],
            serde_json::json!(datetime_to_display(&fn_attr.modified)),
        );
        assert_eq!(
            create.metadata["fn_accessed"],
            serde_json::json!(datetime_to_display(&fn_attr.accessed)),
        );
        assert_eq!(
            create.metadata["fn_mft_modified"],
            serde_json::json!(datetime_to_display(&fn_attr.mft_modified)),
        );
    }

    #[test]
    fn test_si_mace_surfaced_on_file_create() {
        use chrono::TimeZone;

        // Four distinct $SI MACE values so each key is unambiguous.
        let si_created = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let si_modified = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 0).unwrap();
        let si_accessed = Utc.with_ymd_and_hms(2020, 1, 3, 0, 0, 0).unwrap();
        let si_mft_modified = Utc.with_ymd_and_hms(2020, 1, 4, 0, 0, 0).unwrap();

        let mut batch: Vec<TimelineEvent> = Vec::new();
        emit_mace_timestamps(
            &mut batch,
            &si_modified,
            &si_accessed,
            &si_created,
            &si_mft_modified,
            42,
            "Users/analyst/report.docx",
            false,
            "evidence-001",
            None,
        );

        let create = batch
            .iter()
            .find(|e| e.event_type == EventType::FileCreate)
            .expect("FileCreate event emitted");

        // All four $SI MACE must ride on the FileCreate event so the timestomp
        // FP gate (copy: si_created>si_modified; volume-move) and the stronger
        // ordering test (si_modified<fn_created) can run from one event.
        assert_eq!(
            create.metadata["si_created"],
            serde_json::json!(datetime_to_display(&si_created)),
        );
        assert_eq!(
            create.metadata["si_modified"],
            serde_json::json!(datetime_to_display(&si_modified)),
        );
        assert_eq!(
            create.metadata["si_accessed"],
            serde_json::json!(datetime_to_display(&si_accessed)),
        );
        assert_eq!(
            create.metadata["si_mft_changed"],
            serde_json::json!(datetime_to_display(&si_mft_modified)),
        );
    }

    #[test]
    fn test_no_fn_metadata_when_fn_absent() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();

        let mut batch: Vec<TimelineEvent> = Vec::new();
        emit_mace_timestamps(
            &mut batch,
            &ts,
            &ts,
            &ts,
            &ts,
            7,
            "test.txt",
            false,
            "evidence-001",
            None,
        );

        let create = batch
            .iter()
            .find(|e| e.event_type == EventType::FileCreate)
            .expect("FileCreate event emitted");
        assert!(!create.metadata.contains_key("fn_created"));
        assert!(!create.metadata.contains_key("fn_modified"));
        assert!(!create.metadata.contains_key("fn_accessed"));
        assert!(!create.metadata.contains_key("fn_mft_modified"));
    }
}
