//! NTFS `$LogFile` transaction-journal parser for Issen.
//!
//! Two complementary passes over the raw `$LogFile` bytes:
//!
//! 1. **Clearing integrity** — `ntfs-forensic::audit_logfile` flags
//!    journal-clearing indicators (missing restart areas / page gaps —
//!    consistent with `$LogFile` having been wiped to destroy NTFS transaction
//!    history). Each finding becomes an `Integrity` event.
//! 2. **Transaction replay** (§B2) — `ntfs-core`'s LFS record decoder and
//!    transaction reconstruction (`read_record_pages` → `parse_log_records` →
//!    `reconstruct_transactions`) recover the per-file operations the journal
//!    logged. Each reconstructed [`FileOperation`] becomes one
//!    `FileSystemActivity` [`TimelineEvent`].
//!
//! Findings are observations ("consistent with …"), never a tamper verdict — the
//! analyst/tribunal concludes.
//!
//! ## Two forensic crux decisions (documented honestly)
//!
//! - **Target file is genuinely unrecoverable at this layer.** An LFS
//!   [`LogRecord`] names its target only by Open-Attribute-Table index
//!   (`target_attribute`), MFT cluster index, and VCN — it carries **no
//!   `$FILE_NAME`**, and `ntfs-core` does not resolve the open-attribute table to
//!   names. Rather than fabricate a filename, each event sets `target` to the
//!   explicit `"unknown"` sentinel and surfaces the raw locating values
//!   (`target_attribute` / `mft_cluster_index` / `target_vcn`) in metadata.
//! - **No wall-clock time exists in `$LogFile` records.** Records are ordered by
//!   LSN, not timestamped. We do **not** fabricate a time: `timestamp_ns` is the
//!   sentinel `0` and the record's `this_lsn` is carried in metadata (`lsn`) as
//!   the ordering key, with `timestamp_display` stating the absence explicitly.

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
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseOptions, ParseStats,
    ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use issen_core::ActivityCategory;
use ntfs_core::logfile::{
    parse_log_records, read_record_pages, reconstruct_transactions, FileOperation, LogRecord,
    Transaction, TransactionState,
};
use std::collections::HashMap;

/// Audit raw `$LogFile` bytes into Integrity [`TimelineEvent`]s — one per
/// journal-clearing finding `ntfs-forensic` reports. Bytes that parse cleanly
/// (no clearing indicators) yield no events.
pub fn parse_logfile_bytes(bytes: &[u8], source_id: &str) -> Vec<TimelineEvent> {
    // Pass 1 — journal-clearing integrity findings.
    let mut events: Vec<TimelineEvent> = ntfs_forensic::audit_logfile(bytes)
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
            .with_activity_category(ActivityCategory::Integrity)
            .with_tag("integrity")
            .with_metadata("code", serde_json::json!(anomaly.code()))
            .with_metadata(
                "severity",
                serde_json::json!(format!("{:?}", anomaly.severity())),
            )
        })
        .collect();

    // Pass 2 — per-file-operation transaction replay (§B2). Decode every RCRD
    // page's LFS records, then reconstruct and replay the transactions.
    let mut records: Vec<LogRecord> = Vec::new();
    for page in read_record_pages(bytes) {
        records.extend(parse_log_records(&page));
    }
    events.extend(replay_events(&records, source_id));
    events
}

/// Map a reconstructed `$LogFile` [`FileOperation`] to its timeline
/// [`EventType`] plus a stable, scheme-prefixed operation label.
///
/// Journal-bookkeeping classes — transaction control (commit / forget /
/// compensation / prepare / end-top-level), restart/table dumps, and no-ops —
/// record no on-disk file mutation and yield `None`; they are not surfaced as
/// file-activity events (their disposition is instead carried on every file
/// event of the same transaction via `transaction_state`). An unrecognised
/// `(redo, undo)` pair is surfaced verbatim (raw codes) rather than dropped.
fn op_to_event(op: FileOperation) -> Option<(EventType, String)> {
    use FileOperation as F;
    let mapped = match op {
        F::Create => (EventType::FileCreate, "FILE-CREATE".to_string()),
        F::Delete => (EventType::FileDelete, "FILE-DELETE".to_string()),
        F::Rename => (EventType::FileRename, "FILE-RENAME".to_string()),
        F::AttributeCreate => (EventType::FileModify, "ATTR-CREATE".to_string()),
        F::AttributeDelete => (EventType::FileModify, "ATTR-DELETE".to_string()),
        F::Resize => (EventType::FileModify, "FILE-RESIZE".to_string()),
        F::DataWrite => (EventType::FileModify, "DATA-WRITE".to_string()),
        F::IndexInsert => (
            EventType::Other("index-insert".into()),
            "INDEX-INSERT".to_string(),
        ),
        F::IndexDelete => (
            EventType::Other("index-delete".into()),
            "INDEX-DELETE".to_string(),
        ),
        F::BitmapAllocation => (
            EventType::Other("bitmap-allocation".into()),
            "BITMAP-ALLOC".to_string(),
        ),
        // Show-the-unrecognized-value: keep the raw redo/undo codes verbatim.
        F::Unknown(redo, undo) => (
            EventType::Other("logfile-op-unknown".into()),
            format!("LOGFILE-OP-UNKNOWN-{redo:#06x}-{undo:#06x}"),
        ),
        F::TransactionControl | F::TableDump | F::Noop => return None,
    };
    Some(mapped)
}

/// Per-operation-type roll-up of a `$LogFile`'s committed file operations.
#[derive(Default)]
struct CommittedAgg {
    count: u64,
    lsn_min: Option<u64>,
    lsn_max: Option<u64>,
}

/// Replay reconstructed `$LogFile` transactions into [`TimelineEvent`]s with
/// flood-safe volume tiering.
///
/// A DC01-scale `$LogFile` holds tens of thousands of transactions, so one event
/// per committed operation would flood the timeline with low-resolution
/// `target=unknown` noise. The tiering:
///
/// - **Committed** transactions are **aggregated** by operation-type — one event
///   per [`EventType`] carrying `operation_count`, the `lsn_min`/`lsn_max` range,
///   and the `committed_transaction_count`. (No per-parser flag exists in the
///   `ForensicParser` architecture, so aggregate is the default and only path for
///   committed operations.)
/// - **Aborted / Incomplete** transactions keep their **individual**
///   per-operation events: rolled-back and crash-residue operations are the
///   high-signal anomalies and are never aggregated away.
///
/// Every event keeps the honest target/timestamp handling: the target is the
/// explicit `"unknown"` sentinel (`$LogFile` records carry no `$FILE_NAME`) and
/// `timestamp_ns` is the sentinel `0` with the LSN carried as the ordering key.
fn replay_events(records: &[LogRecord], source_id: &str) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    let mut committed: HashMap<EventType, CommittedAgg> = HashMap::new();
    let mut committed_txn_count: u64 = 0;

    for txn in reconstruct_transactions(records) {
        let is_committed = txn.state == TransactionState::Committed;
        if is_committed {
            committed_txn_count += 1;
        }
        for (i, &op) in txn.operations.iter().enumerate() {
            let Some((event_type, op_label)) = op_to_event(op) else {
                continue;
            };
            let lsn = txn.lsns.get(i).copied().unwrap_or_default();
            if is_committed {
                let agg = committed.entry(event_type).or_default();
                agg.count += 1;
                agg.lsn_min = Some(agg.lsn_min.map_or(lsn, |m| m.min(lsn)));
                agg.lsn_max = Some(agg.lsn_max.map_or(lsn, |m| m.max(lsn)));
            } else {
                events.push(individual_event(
                    &txn, i, event_type, &op_label, op, records, source_id,
                ));
            }
        }
    }

    // Emit aggregates in a deterministic order (by LSN range), so the timeline
    // reads in log order regardless of HashMap iteration order.
    let mut aggregates: Vec<(EventType, CommittedAgg)> = committed.into_iter().collect();
    aggregates.sort_by_key(|(_, a)| (a.lsn_min.unwrap_or(0), a.lsn_max.unwrap_or(0)));
    for (event_type, agg) in aggregates {
        events.push(aggregate_event(
            event_type,
            &agg,
            committed_txn_count,
            source_id,
        ));
    }
    events
}

/// Build one **individual** replay event for an aborted / incomplete operation.
fn individual_event(
    txn: &Transaction,
    i: usize,
    event_type: EventType,
    op_label: &str,
    op: FileOperation,
    records: &[LogRecord],
    source_id: &str,
) -> TimelineEvent {
    let state = format!("{:?}", txn.state);
    let lsn = txn.lsns.get(i).copied().unwrap_or_default();
    let (attr, mft_idx, vcn) = txn
        .records
        .get(i)
        .and_then(|&idx| records.get(idx))
        .map_or((0u16, 0u16, 0u64), |r| {
            (r.target_attribute, r.mft_cluster_index, r.target_vcn)
        });
    let tid = txn.transaction_id;
    TimelineEvent::new(
        0, // sentinel: $LogFile records carry no wall-clock time
        format!("LSN {lsn} (no wall-clock time in $LogFile)"),
        event_type,
        ArtifactType::LogFile,
        "$LogFile".to_string(),
        format!(
            "$LogFile transaction replay: {op_label} (target file unknown — \
             record carries no $FILE_NAME; MFT cluster index {mft_idx}, \
             open-attribute index {attr}) — NTFS transaction {tid} {state}, \
             LSN {lsn}; consistent with a {op_label} file operation"
        ),
        source_id.to_string(),
    )
    .with_activity_category(ActivityCategory::FileSystemActivity)
    .with_tag("logfile-replay")
    .with_metadata("aggregated", serde_json::json!(false))
    .with_metadata("transaction_id", serde_json::json!(tid))
    .with_metadata("lsn", serde_json::json!(lsn))
    .with_metadata("transaction_state", serde_json::json!(state))
    .with_metadata("operation", serde_json::json!(format!("{op:?}")))
    .with_metadata("target", serde_json::json!("unknown"))
    .with_metadata("target_attribute", serde_json::json!(attr))
    .with_metadata("mft_cluster_index", serde_json::json!(mft_idx))
    .with_metadata("target_vcn", serde_json::json!(vcn))
}

/// Build one **aggregate** replay event summarizing all committed operations of a
/// single [`EventType`].
fn aggregate_event(
    event_type: EventType,
    agg: &CommittedAgg,
    committed_txn_count: u64,
    source_id: &str,
) -> TimelineEvent {
    let label = type_label(&event_type);
    let lsn_min = agg.lsn_min.unwrap_or_default();
    let lsn_max = agg.lsn_max.unwrap_or_default();
    let count = agg.count;
    TimelineEvent::new(
        0, // sentinel: $LogFile records carry no wall-clock time
        format!("LSN {lsn_min}..{lsn_max} ({count} committed op(s), no wall-clock time)"),
        event_type,
        ArtifactType::LogFile,
        "$LogFile".to_string(),
        format!(
            "$LogFile transaction replay (aggregated): {count} committed {label} \
             operation(s) across {committed_txn_count} committed transaction(s), \
             LSN {lsn_min}..{lsn_max}; targets unknown (records carry no $FILE_NAME)"
        ),
        source_id.to_string(),
    )
    .with_activity_category(ActivityCategory::FileSystemActivity)
    .with_tag("logfile-replay")
    .with_tag("aggregate")
    .with_metadata("aggregated", serde_json::json!(true))
    .with_metadata("operation_count", serde_json::json!(count))
    .with_metadata("lsn_min", serde_json::json!(lsn_min))
    .with_metadata("lsn_max", serde_json::json!(lsn_max))
    .with_metadata(
        "committed_transaction_count",
        serde_json::json!(committed_txn_count),
    )
    .with_metadata("transaction_state", serde_json::json!("Committed"))
    .with_metadata("target", serde_json::json!("unknown"))
}

/// A stable display label for an aggregated operation-[`EventType`].
fn type_label(event_type: &EventType) -> String {
    match event_type {
        EventType::FileCreate => "FILE-CREATE".to_string(),
        EventType::FileDelete => "FILE-DELETE".to_string(),
        EventType::FileRename => "FILE-RENAME".to_string(),
        EventType::FileModify => "FILE-MODIFY".to_string(),
        EventType::Other(kind) => kind.to_uppercase(),
        other => format!("{other:?}"),
    }
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
        _opts: &ParseOptions,
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
        // A committed Create is aggregated: one FileCreate roll-up (the Commit is
        // transaction control => no event).
        assert_eq!(events.len(), 1, "one aggregated file op, control skipped");
        let e = &events[0];
        assert_eq!(e.event_type, EventType::FileCreate);
        assert_eq!(
            e.activity_category,
            Some(issen_core::ActivityCategory::FileSystemActivity),
            "a replayed file operation is FileSystemActivity"
        );
        // No fabricated filename: target is explicitly unknown even aggregated.
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "target" && v == &serde_json::json!("unknown")),
            "target must be the explicit 'unknown' sentinel, never a fabricated name"
        );
        // No wall-clock fabricated; the LSN range is the ordering key.
        assert_eq!(e.timestamp_ns, 0, "no wall-clock time => sentinel 0");
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "aggregated" && v == &serde_json::json!(true)),
            "a committed operation is aggregated"
        );
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "operation_count" && v == &serde_json::json!(1u64)),
            "one committed create"
        );
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "lsn_min" && v == &serde_json::json!(100u64))
                && e.metadata
                    .iter()
                    .any(|(k, v)| k == "lsn_max" && v == &serde_json::json!(100u64)),
            "the LSN range preserves ordering in the absence of absolute time"
        );
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "committed_transaction_count" && v == &serde_json::json!(1u64)),
            "the committed-transaction count is carried"
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

    // ── §B2 volume tiering: flood-safe aggregation ───────────────────────────
    //
    // A DC01-scale $LogFile holds tens of thousands of transactions; one event
    // per committed operation would flood the timeline with low-resolution
    // target=unknown noise. Committed transactions are therefore aggregated by
    // operation-type; aborted / incomplete transactions (the high-signal
    // rolled-back / crash-residue anomalies) keep their per-operation events.

    #[test]
    fn committed_same_type_ops_aggregate_to_single_event() {
        let records = vec![
            rec(1, 0x50, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 0x50, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(3, 0x50, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(4, 0x50, LogOp::CommitTransaction, LogOp::Noop),
        ];
        let events = replay_events(&records, "ev");
        let creates: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == EventType::FileCreate)
            .collect();
        assert_eq!(
            creates.len(),
            1,
            "committed same-type ops aggregate to ONE event, not N"
        );
        let e = creates[0];
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "aggregated" && v == &serde_json::json!(true)),
            "the committed roll-up is marked aggregated"
        );
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "operation_count" && v == &serde_json::json!(3u64)),
            "carries the operation count"
        );
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "lsn_min" && v == &serde_json::json!(1u64)),
            "carries the min LSN of the range"
        );
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "lsn_max" && v == &serde_json::json!(3u64)),
            "carries the max LSN of the range"
        );
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "committed_transaction_count" && v == &serde_json::json!(1u64)),
            "carries the committed-transaction count"
        );
        // Target is still honestly unknown even when aggregated.
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "target" && v == &serde_json::json!("unknown")),
            "aggregation does not fabricate a target"
        );
        assert_eq!(e.timestamp_ns, 0, "no fabricated wall-clock time");
    }

    #[test]
    fn aborted_transaction_ops_emitted_individually() {
        let records = vec![
            rec(10, 0x60, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(11, 0x60, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(12, 0x60, LogOp::CompensationLogRecord, LogOp::Noop),
        ];
        let events = replay_events(&records, "ev");
        let creates: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == EventType::FileCreate)
            .collect();
        assert_eq!(
            creates.len(),
            2,
            "aborted ops stay individual — never aggregated away"
        );
        for e in &creates {
            assert!(
                e.metadata
                    .iter()
                    .any(|(k, v)| k == "aggregated" && v == &serde_json::json!(false)),
                "individual events are explicitly not aggregated"
            );
            assert!(
                e.metadata
                    .iter()
                    .any(|(k, v)| k == "transaction_state" && v == &serde_json::json!("Aborted")),
                "aborted disposition surfaced on each op"
            );
        }
        let lsns: Vec<_> = creates
            .iter()
            .filter_map(|e| {
                e.metadata
                    .iter()
                    .find(|(k, _)| *k == "lsn")
                    .map(|(_, v)| v.clone())
            })
            .collect();
        assert!(
            lsns.contains(&serde_json::json!(10u64)) && lsns.contains(&serde_json::json!(11u64)),
            "each aborted op keeps its own LSN"
        );
    }
}
