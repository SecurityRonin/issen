//! USN Journal parser — ForensicParser impl using usnjrnl-forensic.
//!
//! Registers via `inventory::submit!` so the pipeline discovers it automatically.

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use usnjrnl_forensic::usn::{parse_usn_record_v2, UsnReason, UsnRecord};

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
