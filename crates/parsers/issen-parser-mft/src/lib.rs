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
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! MFT parser for `Issen`.
//!
//! Wraps the `mft` crate to parse NTFS Master File Table (`$MFT`) files and
//! emit [`TimelineEvent`]s via the [`ForensicParser`] trait.  Each MFT entry
//! can produce up to four events (MACE timestamps): Modified, Accessed,
//! Created, and Entry-modified.

use chrono::{DateTime, Utc};
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
use mft::attribute::x10::StandardInfoAttr;
use mft::attribute::x30::FileNameAttr;
use mft::attribute::MftAttributeContent;
use mft::attribute::MftAttributeType;
use mft::MftParser;
use ntfs_core::MftData;
use tracing::warn;

/// NTFS Master File Table parser.
pub struct MftFileParser;

/// The four `$FILE_NAME` MACE timestamps, decoupled from the `mft` crate's
/// `FileNameAttr` so full-precision (ntfs-core) values can be substituted for
/// the truncated ones. `From<&FileNameAttr>` preserves the mft-crate path.
#[derive(Clone, Copy)]
struct FnTimestamps {
    created: DateTime<Utc>,
    modified: DateTime<Utc>,
    accessed: DateTime<Utc>,
    mft_modified: DateTime<Utc>,
}

impl From<&FileNameAttr> for FnTimestamps {
    fn from(f: &FileNameAttr) -> Self {
        Self {
            created: f.created,
            modified: f.modified,
            accessed: f.accessed,
            mft_modified: f.mft_modified,
        }
    }
}

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
    .with_activity_category(issen_core::ActivityCategory::FileSystemActivity)
    .with_metadata("mft_entry_id", serde_json::json!(entry_id))
    .with_metadata("is_directory", serde_json::json!(is_dir))
    // FilePath correlation join key (carried over from the removed cli builtin).
    .with_entity_ref(issen_core::timeline::event::EntityRef::FilePath(
        full_path.to_string(),
    ))
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
    fn_ts: Option<FnTimestamps>,
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
    if let Some(fname) = fn_ts {
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
        _opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        let start = std::time::Instant::now();
        let mut stats = ParseStats::new();

        let total_len = input.len();
        if total_len == 0 {
            stats.completion = ParseCompletion::Unsupported;
            stats.duration = start.elapsed();
            return Ok(stats);
        }

        if total_len < MIN_MFT_SIZE {
            warn!(
                len = total_len,
                "Input too small to be a valid MFT, skipping"
            );
            stats.completion = ParseCompletion::Unsupported;
            stats.duration = start.elapsed();
            return Ok(stats);
        }

        // Read the entire MFT into memory (required by the mft crate).
        let buffer = read_all(input)?;
        stats.bytes_processed = buffer.len() as u64;

        // Full-precision $SI/$FN FILETIMEs. The mft crate converts via
        // winstructs (`ticks / 10`, 100 ns → µs, dropping the final tick);
        // ntfs-core preserves the full 100 ns. Parse the same buffer once and
        // override the timestamps per record, degrading to the mft-crate value
        // when a record is absent (no regression, just less precision).
        let precise = MftData::parse(&buffer).ok();

        // Parse via the mft crate.
        let mut parser = match MftParser::from_buffer(buffer) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Failed to initialise MFT parser");
                stats.completion = ParseCompletion::Unsupported;
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

            // On-disk MFT entry number (record header @ 0x2C). The mft crate's
            // `record_number` is the iteration index, which coincides with the
            // on-disk number only for a full, position-aligned $MFT; ntfs-core
            // keys `by_entry` by the on-disk number, so read it directly
            // (bounds-checked) to align the two parsers for any input.
            let ondisk_entry = entry
                .data
                .get(0x2C..0x30)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map_or(entry_id, |b| u64::from(u32::from_le_bytes(b)));
            let pe = precise.as_ref().and_then(|d| d.get_by_entry(ondisk_entry));

            // Full-precision $FN MACE (fall back to the mft crate per field).
            let fn_ts = FnTimestamps {
                created: pe.and_then(|e| e.fn_created).unwrap_or(file_name.created),
                modified: pe.and_then(|e| e.fn_modified).unwrap_or(file_name.modified),
                accessed: pe.and_then(|e| e.fn_accessed).unwrap_or(file_name.accessed),
                mft_modified: pe
                    .and_then(|e| e.fn_mft_modified)
                    .unwrap_or(file_name.mft_modified),
            };

            // Prefer $STANDARD_INFORMATION timestamps; fall back to $FILE_NAME.
            // When $SI drives the timestamps, surface the co-existing $FN
            // timestamps onto the FileCreate event so a timestomp detector can
            // compare $SI vs $FN.
            if let Some(si) = extract_standard_info(&entry) {
                emit_mace_timestamps(
                    &mut batch,
                    &pe.and_then(|e| e.si_modified).unwrap_or(si.modified),
                    &pe.and_then(|e| e.si_accessed).unwrap_or(si.accessed),
                    &pe.and_then(|e| e.si_created).unwrap_or(si.created),
                    &pe.and_then(|e| e.si_mft_modified)
                        .unwrap_or(si.mft_modified),
                    entry_id,
                    &full_path,
                    is_dir,
                    source_id,
                    Some(fn_ts),
                );
            } else {
                emit_mace_timestamps(
                    &mut batch,
                    &fn_ts.modified,
                    &fn_ts.accessed,
                    &fn_ts.created,
                    &fn_ts.mft_modified,
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

        // Reached the end of the MFT cleanly — this is a complete pass.
        stats.completion = ParseCompletion::Complete;
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
    ParserRegistration { create: || Box::new(MftFileParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::Mft,
            matches: classify::mft,
            priority: 99,
            disk_sources: &[
                sel::DiskSource::Ntfs(sel::NtfsLoc::FixedPath(r"\$MFT")),
                // $MFTMirr is collected (not parsed as an MFT — classify::mft
                // excludes it) so the cross-file $MFT/$MFTMirr integrity check
                // (issen_disk::mft_mirror_integrity_events) has both files.
                sel::DiskSource::Ntfs(sel::NtfsLoc::FixedPath(r"\$MFTMirr")),
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
        use chrono::TimeZone;
        let ns: i64 = 1_555_526_400_000_000_000;
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
    fn mace_event_carries_filepath_entity_ref() {
        // This plugin is the canonical MFT parser (the issen-cli builtin is being
        // removed). It must carry the FilePath correlation join key the builtin
        // had, so temporal rules can still join MFT events by path.
        use issen_core::timeline::event::EntityRef;
        let dt = DateTime::parse_from_rfc3339("2023-06-15T10:30:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let event = mace_event(
            &dt,
            EventType::FileCreate,
            42,
            "Windows/System32/coreupdater.exe",
            false,
            "evidence-001",
        );
        assert!(
            event.entity_refs.contains(&EntityRef::FilePath(
                "Windows/System32/coreupdater.exe".to_string()
            )),
            "MFT event must carry a FilePath entity ref for correlation"
        );
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

        let stats = parser
            .parse(
                &source,
                &emitter,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse empty input");
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

        let stats = parser
            .parse(
                &source,
                &emitter,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse tiny input");
        assert_eq!(stats.events_emitted, 0);

        let events = emitter.into_events();
        assert!(events.is_empty());
    }

    /// Real WinSxS component record (DC01 `$MFT` entry 74419) whose `$SI`
    /// Modified FILETIME ends in a non-zero 100 ns digit. TSK `istat`
    /// (independent oracle) reports `2013-06-18T15:02:18.305856600Z`; the
    /// `mft` crate's `winstructs` truncates 100 ns → µs, rendering
    /// `.305856000Z` in the timeline (the `bug1.jpg` report). Guards full
    /// precision on the ingested `FileModify` event.
    #[test]
    fn parse_preserves_100ns_si_precision() {
        const REC: &[u8] = include_bytes!("../tests/data/dc01_mft_record_74419.bin");
        let emitter = CollectingEmitter::new();
        MftFileParser
            .parse(
                &SliceSource(REC.to_vec()),
                &emitter,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse single record");

        let events = emitter.into_events();
        let fm = events
            .iter()
            .find(|e| e.event_type == EventType::FileModify)
            .expect("FileModify event present");
        assert_eq!(
            fm.timestamp_display, "2013-06-18T15:02:18.305856600Z",
            "timeline $SI Modified lost 100 ns precision (TSK istat oracle)"
        );
    }

    #[test]
    fn invalid_inputs_declare_unsupported_not_complete() {
        // issen #115 step 1: a lenient Ok on non-MFT input must declare
        // Unsupported, never look complete — else resumable ingestion would mark
        // the unit done and permanently skip a real artifact.
        use issen_core::plugin::traits::ParseCompletion;
        let parser = MftFileParser;
        for source in [
            SliceSource(vec![]),                       // empty
            SliceSource(vec![0x46, 0x49, 0x4C, 0x45]), // too small
        ] {
            let emitter = CollectingEmitter::new();
            let stats = parser
                .parse(
                    &source,
                    &emitter,
                    &issen_core::plugin::ParseOptions::default(),
                )
                .expect("Ok");
            assert_eq!(
                stats.completion,
                ParseCompletion::Unsupported,
                "non-MFT input must declare Unsupported, got {:?}",
                stats.completion
            );
            assert_ne!(stats.completion, ParseCompletion::Complete);
        }
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
            .parse(
                &source,
                &emitter,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse garbage gracefully");
        // Should not crash; may produce 0 events or handle error gracefully.
        let events = emitter.into_events();
        assert_eq!(events.len(), stats.events_emitted as usize);
    }

    // -- $FN timestamp surfacing (C1) ---------------------------------------

    /// Build a `$FILE_NAME` attribute with all four MACE timestamps set to the
    /// same FILETIME (one distinct value per call), so a test can construct a
    /// `$FN` whose timestamps differ from a `$SI` set.
    fn build_file_name_attr(filetime: u64, name: &str) -> mft::attribute::x30::FileNameAttr {
        use std::io::Cursor;
        let mut buf = Vec::new();
        // parent MftReference (8 bytes): entry 5, seq 1
        buf.extend_from_slice(&5u64.to_le_bytes());
        // created / modified / mft_modified / accessed — same FILETIME each.
        for _ in 0..4 {
            buf.extend_from_slice(&filetime.to_le_bytes());
        }
        buf.extend_from_slice(&0u64.to_le_bytes()); // logical_size
        buf.extend_from_slice(&0u64.to_le_bytes()); // physical_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // reparse_value
        let utf16: Vec<u16> = name.encode_utf16().collect();
        #[allow(clippy::cast_possible_truncation)]
        buf.push(utf16.len() as u8); // name_length
        buf.push(1u8); // namespace = Win32
        for code_unit in utf16 {
            buf.extend_from_slice(&code_unit.to_le_bytes());
        }
        mft::attribute::x30::FileNameAttr::from_stream(&mut Cursor::new(buf))
            .expect("valid synthetic $FN attribute")
    }

    /// When BOTH `$SI` and `$FN` are present, the `$FN` timestamps must be
    /// surfaced onto the FileCreate event's metadata (so the C2 timestomp
    /// detector can compare `$SI` vs `$FN`). The `$SI` timestamps still drive
    /// the event timestamps themselves.
    #[test]
    fn test_fn_timestamps_surfaced_when_si_present() {
        use chrono::TimeZone;

        // $SI create timestamp: 2020-01-01T00:00:00Z (drives the event ts).
        let si_created = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let si_modified = Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 0).unwrap();
        let si_accessed = Utc.with_ymd_and_hms(2020, 1, 3, 0, 0, 0).unwrap();
        let si_mft_modified = Utc.with_ymd_and_hms(2020, 1, 4, 0, 0, 0).unwrap();

        // $FN with a DISTINCT FILETIME: 2010-06-15T12:00:00Z.
        // FILETIME = (unix_seconds * 10_000_000) + 116_444_736_000_000_000.
        let fn_unix = Utc
            .with_ymd_and_hms(2010, 6, 15, 12, 0, 0)
            .unwrap()
            .timestamp();
        #[allow(clippy::cast_sign_loss)]
        let fn_filetime = (fn_unix as u64) * 10_000_000 + 116_444_736_000_000_000;
        let fn_attr = build_file_name_attr(fn_filetime, "report.docx");
        let fn_created_display = datetime_to_display(&fn_attr.created);

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
            Some((&fn_attr).into()),
        );

        let create = batch
            .iter()
            .find(|e| e.event_type == EventType::FileCreate)
            .expect("FileCreate event emitted");

        // The event timestamp is still driven by $SI.
        assert_eq!(create.timestamp_ns, datetime_to_ns(&si_created));

        // The $FN timestamps are surfaced into metadata as RFC3339 strings.
        assert_eq!(
            create.metadata["fn_created"],
            serde_json::json!(fn_created_display),
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

    /// All four `$SI` MACE values must ride on the FileCreate event so the
    /// timestomp FP gate (copy: `si_created>si_modified`; volume-move) and the
    /// stronger ordering test (`si_modified<fn_created`) can run from one event.
    #[test]
    fn test_si_mace_surfaced_on_file_create() {
        use chrono::TimeZone;

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

    /// When only `$SI` is present (no `$FN` overlay), no `fn_*` metadata keys
    /// are added — behavior is unchanged for single-attribute entries.
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

    /// MFT MACE events are FileSystemActivity (CADET meaning axis).
    #[test]
    fn event_tagged_filesystem_activity() {
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
        assert_eq!(
            create.activity_category,
            Some(issen_core::ActivityCategory::FileSystemActivity)
        );
    }
}
