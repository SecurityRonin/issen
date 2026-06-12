//! USN Journal parser — ForensicParser impl using ntfs_core::usn.
//!
//! Registers via `inventory::submit!` so the pipeline discovers it automatically.

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use ntfs_core::usn::{parse_usn_record_v2, UsnReason, UsnRecord};

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

                match parse_usn_record_v2(&chunk[pos..]) {
                    Ok(record) => {
                        let record_length = record_length_from_slice(&chunk[pos..]);
                        let event = record_to_event(&record, "usnjrnl-evidence");
                        batch.push(event);

                        if batch.len() >= 1000 {
                            stats.events_emitted += batch.len() as u64;
                            emitter.emit_batch(std::mem::take(&mut batch))?;
                        }

                        // Advance by record length (8-byte aligned).
                        let advance = ((record_length) + 7) & !7;
                        pos += advance.max(8);
                    }
                    Err(_) => {
                        stats.errors_recovered += 1;
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

/// Read record_length from the first 4 bytes of a USN record slice.
fn record_length_from_slice(data: &[u8]) -> usize {
    if data.len() < 4 {
        return 8;
    }
    u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize
}

/// Map UsnReason to the primary EventType.
fn reason_to_event_type(reason: UsnReason) -> EventType {
    if reason.contains(UsnReason::FILE_CREATE) {
        EventType::FileCreate
    } else if reason.contains(UsnReason::FILE_DELETE) {
        EventType::FileDelete
    } else if reason.contains(UsnReason::RENAME_NEW_NAME) {
        EventType::FileRename
    } else if reason.contains(UsnReason::DATA_OVERWRITE)
        || reason.contains(UsnReason::DATA_EXTEND)
        || reason.contains(UsnReason::DATA_TRUNCATION)
    {
        EventType::FileModify
    } else {
        EventType::Other("MetadataChange".to_string())
    }
}

/// Convert a parsed USN record to a TimelineEvent.
fn record_to_event(record: &UsnRecord, evidence_source_id: &str) -> TimelineEvent {
    let timestamp_ns = record
        .timestamp
        .timestamp_nanos_opt()
        .unwrap_or_else(|| record.timestamp.timestamp() * 1_000_000_000);
    let timestamp_display = record
        .timestamp
        .format("%Y-%m-%dT%H:%M:%S%.9fZ")
        .to_string();
    let event_type = reason_to_event_type(record.reason);
    let reason_desc = record.reason.to_string();

    let description = format!("{event_type}: {} ({reason_desc})", record.filename);

    TimelineEvent::new(
        timestamp_ns,
        timestamp_display,
        event_type,
        ArtifactType::UsnJournal,
        record.filename.clone(),
        description,
        evidence_source_id.to_string(),
    )
    .with_metadata("usn", serde_json::json!(record.usn))
    .with_metadata(
        "reason_flags",
        serde_json::json!(format!("0x{:08X}", record.reason.bits())),
    )
    .with_metadata("file_reference", serde_json::json!(record.mft_entry))
    .with_metadata(
        "parent_reference",
        serde_json::json!(record.parent_mft_entry),
    )
    .with_metadata(
        "file_attributes",
        serde_json::json!(record.file_attributes.bits()),
    )
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(UsnJrnlParser) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_to_event_type_file_create() {
        assert_eq!(
            reason_to_event_type(UsnReason::FILE_CREATE),
            EventType::FileCreate
        );
    }

    #[test]
    fn reason_to_event_type_file_delete() {
        assert_eq!(
            reason_to_event_type(UsnReason::FILE_DELETE),
            EventType::FileDelete
        );
    }

    #[test]
    fn reason_to_event_type_rename() {
        assert_eq!(
            reason_to_event_type(UsnReason::RENAME_NEW_NAME),
            EventType::FileRename
        );
    }

    #[test]
    fn reason_to_event_type_data_overwrite() {
        assert_eq!(
            reason_to_event_type(UsnReason::DATA_OVERWRITE),
            EventType::FileModify
        );
    }

    #[test]
    fn reason_to_event_type_fallback() {
        assert_eq!(
            reason_to_event_type(UsnReason::SECURITY_CHANGE),
            EventType::Other("MetadataChange".to_string())
        );
    }

    /// Build a minimal USN_RECORD_V2 byte buffer for `filename` with `reason`.
    fn build_usn_v2(filename: &str, filetime: i64, reason: u32) -> Vec<u8> {
        let name: Vec<u8> = filename.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let filename_offset = 0x3Cusize;
        let record_len = filename_offset + name.len();
        let mut d = vec![0u8; record_len];
        d[0x00..0x04].copy_from_slice(&(record_len as u32).to_le_bytes());
        d[0x04..0x06].copy_from_slice(&2u16.to_le_bytes()); // major version 2
        d[0x08..0x10].copy_from_slice(&5000u64.to_le_bytes()); // file reference
        d[0x10..0x18].copy_from_slice(&6000u64.to_le_bytes()); // parent reference
        d[0x18..0x20].copy_from_slice(&7000i64.to_le_bytes()); // usn
        d[0x20..0x28].copy_from_slice(&filetime.to_le_bytes());
        d[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
        d[0x38..0x3A].copy_from_slice(&(name.len() as u16).to_le_bytes());
        d[0x3A..0x3C].copy_from_slice(&(filename_offset as u16).to_le_bytes());
        d[0x3C..].copy_from_slice(&name);
        d
    }

    #[test]
    fn rename_record_surfaces_new_name_as_file_rename() {
        // Regression guard (A3): a RENAME_NEW_NAME USN record must surface end-to-end
        // (bytes → record → event) as a FileRename whose path is the *new* name — the
        // move target. This is the parser-level core of the Case-001 assertion
        // (coreupdater.exe renamed into \System32\). The full DC-E01 end-to-end check
        // is pending a completed ingest (DC USN captured 0 events when the run was
        // killed mid-stream; A0/A1 remove that hang so a re-ingest exercises this path).
        let filetime = 133_451_432_000_000_000i64;
        let reason = UsnReason::RENAME_NEW_NAME.bits() | UsnReason::CLOSE.bits();
        let data = build_usn_v2("coreupdater.exe", filetime, reason);

        let record = parse_usn_record_v2(&data).expect("parse rename record");
        let event = record_to_event(&record, "dc01-usn");

        assert_eq!(event.event_type, EventType::FileRename);
        assert_eq!(event.artifact_path, "coreupdater.exe");
        assert!(event.description.contains("coreupdater.exe"));
    }

    #[test]
    fn usn_event_carries_filepath_entity_ref() {
        // PRE-2: USN file events carry EntityRef::FilePath (the rename/move join
        // key for CORR-MALWARE-RELOCATE / CORR-COPY-DELETE).
        use issen_core::timeline::event::EntityRef;
        let data = build_usn_v2(
            "coreupdater.exe",
            133_451_432_000_000_000i64,
            UsnReason::RENAME_NEW_NAME.bits() | UsnReason::CLOSE.bits(),
        );
        let record = parse_usn_record_v2(&data).expect("parse");
        let event = record_to_event(&record, "dc01-usn");
        assert!(
            event
                .entity_refs
                .contains(&EntityRef::FilePath("coreupdater.exe".to_string())),
            "{:?}",
            event.entity_refs
        );
    }

    #[test]
    fn record_length_from_slice_too_short() {
        assert_eq!(record_length_from_slice(&[]), 8);
        assert_eq!(record_length_from_slice(&[0, 1]), 8);
    }

    #[test]
    fn record_length_from_slice_valid() {
        let bytes = 80u32.to_le_bytes();
        assert_eq!(record_length_from_slice(&bytes), 80);
    }
}
