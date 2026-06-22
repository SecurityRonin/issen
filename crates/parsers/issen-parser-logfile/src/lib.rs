//! NTFS `$LogFile` transaction-journal integrity parser for Issen.
//!
//! Wraps `ntfs-forensic::audit_logfile`, which flags journal-clearing indicators
//! (missing restart areas / page gaps — consistent with `$LogFile` having been
//! wiped to destroy NTFS transaction history). Each finding becomes an Integrity
//! event. Findings are observations ("consistent with clearing"), never a tamper
//! verdict — the analyst/tribunal concludes.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Audit raw `$LogFile` bytes into Integrity [`TimelineEvent`]s — one per
/// journal-clearing finding `ntfs-forensic` reports. Bytes that parse cleanly
/// (no clearing indicators) yield no events.
pub fn parse_logfile_bytes(bytes: &[u8], source_id: &str) -> Vec<TimelineEvent> {
    ntfs_forensic::audit_logfile(bytes)
        .into_iter()
        .map(|anomaly| {
            TimelineEvent::new(
                0,
                String::new(),
                EventType::Other("integrity".into()),
                ArtifactType::LogFile,
                "$LogFile".to_string(),
                format!(
                    "$LogFile integrity: {} — consistent with the NTFS transaction \
                     journal having been cleared",
                    anomaly.code()
                ),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Integrity)
            .with_tag("integrity")
            .with_metadata("code", serde_json::json!(anomaly.code()))
            .with_metadata(
                "severity",
                serde_json::json!(format!("{:?}", anomaly.severity())),
            )
        })
        .collect()
}

/// `$LogFile` integrity parser.
pub struct LogFileParser;

impl ForensicParser for LogFileParser {
    // The trait mandates `-> &str`; the literal bound is unavoidable.
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "$LogFile Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::LogFile]
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
        let mut bytes = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
        let mut off = 0u64;
        while off < len {
            let n = input.read_at(off, &mut bytes[off as usize..])?;
            if n == 0 {
                break;
            }
            off += n as u64;
        }
        stats.bytes_processed = off;
        let events = parse_logfile_bytes(&bytes[..off as usize], "logfile-evidence");
        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
        stats.completion = ParseCompletion::Complete;
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            // $LogFile defaults to 64 MiB; allow headroom.
            max_memory_bytes: Some(128 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(LogFileParser), selector: sel::ArtifactSelector {
            artifact_type: ArtifactType::LogFile,
            matches: classify::logfile,
            priority: 95,
            disk_sources: &[sel::DiskSource::Ntfs(sel::NtfsLoc::FixedPath(r"\$LogFile"))],
            cost: sel::CostTier::Default,
        } }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn cleared_logfile_yields_integrity_event() {
        // A $LogFile with no restart area (degenerate case: empty) is consistent
        // with the journal having been cleared.
        let events = parse_logfile_bytes(&[], "ev");
        assert_eq!(events.len(), 1, "one clearing finding -> one event");
        let e = &events[0];
        assert_eq!(
            e.activity_category,
            Some(issen_core::ActivityCategory::Integrity),
            "a journal-clearing finding is an Integrity observation"
        );
        assert!(
            e.description.contains("NTFS-LOGFILE-CLEARED"),
            "got: {}",
            e.description
        );
        assert!(
            e.metadata.iter().any(|(k, _)| k == "code"),
            "must carry the finding code"
        );
    }

    #[test]
    fn valid_logfile_yields_no_events() {
        // A $LogFile with a real restart-area page (RSTR) is not cleared.
        let mut page = vec![0u8; 0x1000];
        page[0..4].copy_from_slice(b"RSTR");
        page[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        page[0x20..0x24].copy_from_slice(&4096u32.to_le_bytes());
        page[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        assert!(
            parse_logfile_bytes(&page, "ev").is_empty(),
            "a $LogFile with a restart area must not be flagged cleared"
        );
    }

    #[test]
    fn supported_artifact_is_logfile() {
        assert_eq!(
            LogFileParser.supported_artifacts(),
            &[ArtifactType::LogFile]
        );
    }

    // ── §B2: per-file-operation transaction replay ───────────────────────────
    //
    // These drive `replay_events`, the Transaction -> TimelineEvent mapping over
    // ntfs-core 0.8's `reconstruct_transactions`. The fixtures are synthetic
    // `LogRecord` streams built directly via `rec` below (the struct's fields are
    // public); the bytes -> records decode path is already validated inside
    // ntfs-core. A real-`$LogFile` end-to-end check is env-gated (see the last
    // test) so it runs against authentic bytes when a corpus is reachable.

    use ntfs_core::logfile::LogOp;

    /// Minimal [`LogRecord`] carrying the fields transaction reconstruction and
    /// the replay mapping read: LSN, transaction-table slot, redo/undo opcodes.
    fn rec(this_lsn: u64, slot: u32, redo: LogOp, undo: LogOp) -> LogRecord {
        LogRecord {
            page_offset: 0,
            this_lsn,
            client_previous_lsn: 0,
            client_undo_next_lsn: 0,
            record_type: 1,
            transaction_id: slot,
            redo_op: redo,
            undo_op: undo,
            target_attribute: 7,
            mft_cluster_index: 42,
            target_vcn: 0,
        }
    }

    #[test]
    fn committed_create_yields_filecreate_replay_event() {
        let records = vec![
            rec(100, 0x10, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(101, 0x10, LogOp::CommitTransaction, LogOp::Noop),
        ];
        let events = replay_events(&records, "ev");
        // The Create is a file op; the Commit is transaction control => no event.
        assert_eq!(events.len(), 1, "one file op, control record skipped");
        let e = &events[0];
        assert_eq!(e.event_type, EventType::FileCreate);
        assert_eq!(
            e.activity_category,
            Some(issen_core::ActivityCategory::FileSystemActivity),
            "a replayed file operation is FileSystemActivity"
        );
        // No fabricated filename: target is explicitly unknown.
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "target" && v == &serde_json::json!("unknown")),
            "target must be the explicit 'unknown' sentinel, never a fabricated name"
        );
        // LSN carried as the ordering key; no wall-clock fabricated.
        assert_eq!(e.timestamp_ns, 0, "no wall-clock time => sentinel 0");
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "lsn" && v == &serde_json::json!(100u64)),
            "lsn metadata preserves ordering in the absence of absolute time"
        );
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "transaction_id" && v == &serde_json::json!(0x10u32)),
            "transaction_id must be carried"
        );
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "transaction_state" && v == &serde_json::json!("Committed")),
            "committed state must be surfaced"
        );
    }

    #[test]
    fn aborted_operation_surfaces_state_and_is_not_dropped() {
        let records = vec![
            rec(200, 0x20, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(201, 0x20, LogOp::CompensationLogRecord, LogOp::Noop),
        ];
        let events = replay_events(&records, "ev");
        // The Create still surfaces; the compensation (control) record is skipped.
        assert_eq!(events.len(), 1, "rolled-back file op is not dropped");
        assert!(
            events[0]
                .metadata
                .iter()
                .any(|(k, v)| k == "transaction_state" && v == &serde_json::json!("Aborted")),
            "aborted/rolled-back disposition must be surfaced, not hidden"
        );
    }

    #[test]
    fn delete_and_rename_map_to_event_types() {
        let records = vec![
            rec(300, 0x30, LogOp::DeallocateFileRecordSegment, LogOp::Noop),
            rec(
                301,
                0x30,
                LogOp::UpdateFileNameAllocation,
                LogOp::UpdateFileNameAllocation,
            ),
            rec(
                302,
                0x30,
                LogOp::ForgetTransaction,
                LogOp::CompensationLogRecord,
            ),
        ];
        let events = replay_events(&records, "ev");
        assert_eq!(
            events.len(),
            2,
            "two file ops; the Forget control is skipped"
        );
        let types: Vec<&EventType> = events.iter().map(|e| &e.event_type).collect();
        assert!(
            types.contains(&&EventType::FileDelete),
            "Delete -> FileDelete"
        );
        assert!(
            types.contains(&&EventType::FileRename),
            "Rename -> FileRename"
        );
    }

    #[test]
    fn clearing_and_replay_events_coexist() {
        // Empty bytes are a clearing indicator; they must still yield the
        // integrity event even though the replay pass finds no records.
        let events = parse_logfile_bytes(&[], "ev");
        assert!(
            events
                .iter()
                .any(|e| e.activity_category == Some(issen_core::ActivityCategory::Integrity)),
            "clearing-integrity events must not be removed by the replay addition"
        );
    }

    #[test]
    fn real_logfile_fixture_replays_cleanly() {
        // Doer-Checker: when ISSEN_LOGFILE_FIXTURE points at a real $LogFile (or
        // a carved RCRD page), exercise the full bytes -> records ->
        // transactions -> events path on authentic data. Skips clean when no
        // corpus is reachable.
        //
        // The assertion is well-formedness, NOT a count: the only small real
        // fixture reachable in the fleet (ntfs-forensic's single CITADEL-DC01
        // RCRD page) holds exactly one CompensationLogRecord — transaction
        // control — which correctly yields zero file-operation events. Asserting
        // a positive count would be dishonest for control-only data; a full
        // multi-record $LogFile from the (gitignored) corpus exercises the
        // file-op path and still satisfies these well-formedness checks.
        let Ok(path) = std::env::var("ISSEN_LOGFILE_FIXTURE") else {
            return;
        };
        let bytes = std::fs::read(&path).expect("fixture path readable");
        let events = parse_logfile_bytes(&bytes, "ev");
        let replay: Vec<_> = events
            .iter()
            .filter(|e| {
                e.activity_category == Some(issen_core::ActivityCategory::FileSystemActivity)
            })
            .collect();
        for e in &replay {
            assert!(
                e.metadata.iter().any(|(k, _)| k == "lsn"),
                "every replay event carries its LSN ordering key"
            );
            assert!(
                e.metadata
                    .iter()
                    .any(|(k, v)| k == "target" && v == &serde_json::json!("unknown")),
                "no fabricated filename on real data"
            );
            assert_eq!(e.timestamp_ns, 0, "no fabricated wall-clock time");
        }
        eprintln!(
            "real $LogFile replay: {} file-operation event(s) from {} byte(s)",
            replay.len(),
            bytes.len()
        );
    }
}
