//! Apple Biome `App.MenuItem` parser for Issen.
//!
//! Reads SEGB container files (the macOS Tahoe 26+ stream
//! `~/Library/Biome/streams/restricted/App.MenuItem/local`) and converts each
//! menu-bar selection into a [`TimelineEvent`].
//!
//! The raw SEGB container decode is performed by `segb-core`; normalization of
//! `App.MenuItem` records into user-activity events by `useract-forensic`'s
//! [`useract_forensic::BiomeMenuItemSource`]. This crate is the thin Issen
//! wrapper that maps those events onto the timeline model — mirroring the
//! `issen-parser-srum` pattern.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
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
    DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use segb::common::EntryState;
use std::io::Cursor;
use std::path::Path;
use useract_forensic::{ActivitySource, BiomeMenuItemSource, UserActivity};

/// Biome `App.MenuItem` parser — ingests SEGB stream files.
pub struct BiomeParser;

impl BiomeParser {
    /// Read a SEGB file from disk and convert its `App.MenuItem` records into
    /// timeline events.
    pub fn parse_path(&self, path: &Path) -> anyhow::Result<Vec<TimelineEvent>> {
        let bytes = std::fs::read(path)?;
        Ok(self.parse_bytes(&bytes, &path.to_string_lossy()))
    }

    /// Decode SEGB bytes and map menu selections to timeline events.
    ///
    /// Only `Written` records are decoded: a `Deleted` record's payload is wiped,
    /// so it carries no recoverable menu label (this mirrors the `segb-forensic`
    /// analyzer, which audits Written records only). Each record is decoded
    /// independently — one malformed payload is skipped rather than dropping the
    /// whole batch. Bytes that are not a valid SEGB container yield no events.
    pub fn parse_bytes(&self, bytes: &[u8], evidence_source: &str) -> Vec<TimelineEvent> {
        let mut cursor = Cursor::new(bytes);
        let Ok(records) = segb::read_segb(&mut cursor) else {
            return Vec::new();
        };
        let menu_items: Vec<segb::menuitem::AppMenuItemRecord> = records
            .iter()
            .filter(|r| r.state() == EntryState::Written)
            .filter_map(|r| {
                segb::menuitem::decode_app_menu_item(r.payload(), r.timestamp_unix()).ok()
            })
            .collect();
        let activities = BiomeMenuItemSource::new(&menu_items, None).activities();
        let mut events = activities_to_events(&activities, evidence_source);
        // Integrity dimension: surface segb-forensic's graded anomalies
        // (CRC-mismatch = tamper/corruption; timestamp-out-of-order = reordering)
        // as standalone Integrity events. Attribution to a specific menu event is
        // deliberately NOT attempted — two order-dropping filter stages
        // (Written+decodable, then menu_item-present) sit between records and menu
        // events, so a positional record->event link would be fragile. The
        // finding carries its record offset/index for correlation instead.
        events.extend(integrity_events(&records, evidence_source));
        events
    }
}

/// Map `segb-forensic`'s graded SEGB anomalies onto `Integrity`-category timeline
/// events (the tamper/corruption dimension, distinct from the menu-selection
/// activity). Pure over the decoded records (Humble Object).
fn integrity_events(records: &[segb::SegbRecord], evidence_source: &str) -> Vec<TimelineEvent> {
    segb_forensic::audit(records)
        .into_iter()
        .map(|a| {
            let code = a.code();
            let offset = a.kind.offset();
            let index = a.kind.index();
            let mut event = TimelineEvent::new(
                0,
                String::new(),
                EventType::Other("integrity".into()),
                ArtifactType::BiomeMenuItem,
                evidence_source.to_string(),
                format!("Biome SEGB integrity finding: {code} (record {index}, offset {offset})"),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Integrity)
            .with_tag("integrity")
            .with_metadata("code", serde_json::json!(code))
            .with_metadata("offset", serde_json::json!(offset))
            .with_metadata("record_index", serde_json::json!(index));
            if let segb_forensic::AnomalyKind::CrcMismatch {
                stored, computed, ..
            } = a.kind
            {
                event = event
                    .with_metadata("stored_crc", serde_json::json!(format!("0x{stored:08X}")))
                    .with_metadata(
                        "computed_crc",
                        serde_json::json!(format!("0x{computed:08X}")),
                    );
            }
            event
        })
        .collect()
}

/// Map normalized Biome menu-selection activities onto Issen timeline events.
///
/// Pure function (no I/O) so the mapping is unit-testable (Humble Object).
pub fn activities_to_events(
    activities: &[UserActivity],
    evidence_source: &str,
) -> Vec<TimelineEvent> {
    activities
        .iter()
        .map(|a| {
            let ts_ns = a.timestamp.map_or(0, |s| s.saturating_mul(1_000_000_000));
            let ts_display = a
                .timestamp
                .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
                .map_or_else(|| "unknown".to_string(), |dt| dt.to_rfc3339());
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::Other("MenuSelected".into()),
                ArtifactType::BiomeMenuItem,
                evidence_source.to_string(),
                format!("Biome App.MenuItem: {}", a.detail),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::UserActivity)
            .with_metadata("action", serde_json::json!("MenuSelected"))
            .with_metadata("subject", serde_json::json!(a.detail))
        })
        .collect()
}

impl ForensicParser for BiomeParser {
    // The `ForensicParser` trait mandates `-> &str`; the impl signature cannot
    // widen the return to `&'static str`, so the literal bound is unavoidable.
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "Biome App.MenuItem Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::BiomeMenuItem]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        // A SEGB read needs the whole container in hand. Prefer the file path
        // when the source exposes one (the orchestrator's FileDataSource does);
        // otherwise pull the byte stream into memory and decode that.
        let events = if let Some(path) = input.source_path() {
            self.parse_path(path)
                .map_err(|e| RtError::InvalidData(format!("Biome parse failed: {e}")))?
        } else {
            let len = usize::try_from(input.len()).unwrap_or(usize::MAX);
            let mut buf = vec![0u8; len];
            let n = input.read_at(0, &mut buf)?;
            buf.truncate(n);
            self.parse_bytes(&buf, "<memory>")
        };
        let mut stats = ParseStats::new();
        stats.events_emitted = events.len() as u64;
        stats.bytes_processed = input.len();
        emitter.emit_batch(events)?;
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

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(BiomeParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::BiomeMenuItem,
            matches: classify::segb,
            priority: 40,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use useract_forensic::{Action, SourceKind, Subject};

    /// A `DataSource` backed only by an in-memory byte buffer (no path).
    struct ByteSource(Vec<u8>);
    impl DataSource for ByteSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(self.0.len());
            let end = start.saturating_add(buf.len()).min(self.0.len());
            let n = end - start;
            buf[..n].copy_from_slice(&self.0[start..end]);
            Ok(n)
        }
    }

    /// An `EventEmitter` that collects emitted events for assertions.
    #[derive(Default)]
    struct CollectingEmitter {
        events: Mutex<Vec<TimelineEvent>>,
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

    /// Build a minimal valid SEGB v1 file holding one Written `App.MenuItem`
    /// record: `application`="Finder", `menu_item`="Move to Trash".
    ///
    /// Layout follows `segb-core`: 56-byte file header (magic `b"SEGB"` at
    /// offsets 52–55, `end_of_data_offset` u32LE at 0), then a 32-byte record
    /// header `<iiddIi>` (length, state, ts1, ts2, crc, unknown), then payload,
    /// 8-byte aligned. The stored CRC is the correct zlib CRC-32 of the payload,
    /// so the record is valid (no integrity finding).
    fn synthetic_segb_one_menu_item() -> Vec<u8> {
        build_menu_item_segb(true)
    }

    /// Same single-record SEGB but with a deliberately WRONG stored CRC (payload
    /// intact, so it still decodes) — exercises the SEGB-CRC-MISMATCH path.
    fn synthetic_segb_bad_crc() -> Vec<u8> {
        build_menu_item_segb(false)
    }

    /// zlib CRC-32 (identical to segb-core's `crc32_of`).
    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn build_menu_item_segb(valid_crc: bool) -> Vec<u8> {
        // Protobuf payload: field 1 (app) + field 2 (menu_item), both wire-type 2.
        let mut payload = Vec::new();
        let app = b"Finder";
        payload.push(0x0A); // (1 << 3) | 2
        payload.push(u8::try_from(app.len()).expect("app name fits u8"));
        payload.extend_from_slice(app);
        let item = b"Move to Trash";
        payload.push(0x12); // (2 << 3) | 2
        payload.push(u8::try_from(item.len()).expect("menu item fits u8"));
        payload.extend_from_slice(item);

        // Record header (32 bytes): struct "<iiddIi".
        let mut rec = Vec::new();
        let record_length = i32::try_from(payload.len()).expect("payload fits i32");
        rec.extend_from_slice(&record_length.to_le_bytes()); // 0: record_length
        rec.extend_from_slice(&1i32.to_le_bytes()); // 4: entry_state = 1 (Written)
                                                    // Cocoa time for unix 1_700_000_000 = 1_700_000_000 - 978_307_200.
        rec.extend_from_slice(&721_692_800f64.to_le_bytes()); // 8: timestamp1
        rec.extend_from_slice(&721_692_800f64.to_le_bytes()); // 16: timestamp2
        let stored_crc = if valid_crc { crc32(&payload) } else { 0 };
        rec.extend_from_slice(&stored_crc.to_le_bytes()); // 24: crc32
        rec.extend_from_slice(&0i32.to_le_bytes()); // 28: unknown

        let header_len = 56usize;
        let end_of_data =
            u32::try_from(header_len + rec.len() + payload.len()).expect("fixture fits u32");

        let mut file = vec![0u8; header_len];
        file[0..4].copy_from_slice(&end_of_data.to_le_bytes());
        file[52..56].copy_from_slice(b"SEGB");
        file.extend_from_slice(&rec);
        file.extend_from_slice(&payload);
        while !file.len().is_multiple_of(8) {
            file.push(0);
        }
        file
    }

    #[test]
    fn supported_artifacts_is_biome_menu_item() {
        assert_eq!(
            BiomeParser.supported_artifacts(),
            &[ArtifactType::BiomeMenuItem]
        );
    }

    #[test]
    fn activities_to_events_maps_one_activity() {
        let act = UserActivity {
            timestamp: Some(1_700_000_000),
            actor: None,
            action: Action::MenuSelected,
            subject: Subject::Command("Finder: Move to Trash".into()),
            source: SourceKind::BiomeMenuItem,
            detail: "Finder: Move to Trash".into(),
        };
        let events = activities_to_events(&[act], "/evidence/local");
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.source, ArtifactType::BiomeMenuItem);
        assert_eq!(e.timestamp_ns, 1_700_000_000i64 * 1_000_000_000);
        assert!(
            e.description.contains("Finder: Move to Trash"),
            "description was: {}",
            e.description
        );
    }

    #[test]
    fn parse_bytes_decodes_synthetic_segb() {
        let segb = synthetic_segb_one_menu_item();
        let events = BiomeParser.parse_bytes(&segb, "/x/local");
        assert_eq!(events.len(), 1, "one Written App.MenuItem -> one event");
        assert_eq!(events[0].source, ArtifactType::BiomeMenuItem);
        assert!(events[0].description.contains("Finder: Move to Trash"));
    }

    #[test]
    fn event_tagged_user_activity() {
        // A Biome App.MenuItem selection is a UserActivity (CADET meaning axis).
        let segb = synthetic_segb_one_menu_item();
        let events = BiomeParser.parse_bytes(&segb, "/x/local");
        assert_eq!(
            events[0].activity_category,
            Some(issen_core::ActivityCategory::UserActivity)
        );
    }

    /// Depth (integrity): a SEGB whose Written record fails CRC must surface a
    /// `SEGB-CRC-MISMATCH` Integrity event — the tamper/corruption evidence that
    /// segb-forensic::audit already grades but the wrapper dropped. The synthetic
    /// fixture stores crc=0 over a real protobuf payload, so its Written record's
    /// computed CRC differs → a genuine mismatch.
    #[test]
    fn parse_bytes_surfaces_crc_mismatch_integrity_event() {
        let segb = synthetic_segb_bad_crc();
        let events = BiomeParser.parse_bytes(&segb, "/x/local");
        let integ = events
            .iter()
            .find(|e| {
                e.activity_category == Some(issen_core::ActivityCategory::Integrity)
                    && (e.description.contains("SEGB-CRC-MISMATCH")
                        || e.metadata
                            .iter()
                            .any(|(_, v)| v.to_string().contains("SEGB-CRC-MISMATCH")))
            })
            .expect("a SEGB-CRC-MISMATCH Integrity event");
        // The integrity finding must carry its location (offset) for correlation.
        assert!(
            integ.metadata.iter().any(|(k, _)| k == "offset"),
            "integrity event must carry the record offset"
        );

        // Benign path: a record with the CORRECT stored CRC must NOT produce an
        // integrity event (also confirms the test's crc32 matches segb-core's).
        let valid = synthetic_segb_one_menu_item();
        let valid_events = BiomeParser.parse_bytes(&valid, "/x/local");
        assert!(
            !valid_events
                .iter()
                .any(|e| e.activity_category == Some(issen_core::ActivityCategory::Integrity)),
            "a CRC-valid record must yield no integrity event"
        );
    }

    /// Real-data validation (doer-checker): the integrity wiring is proven on a
    /// GENUINE Apple Biome SEGB stream, not only the synthetic builder. The
    /// fixture is a real `Device.Power.LowPowerMode.v1` SEGB (josh-hickman iOS
    /// Biome corpus) in which one Written record's stored CRC-32 was flipped — a
    /// real-data-derived tamper. `segb-forensic::audit` must catch exactly that
    /// record and the wrapper must surface it as a `SEGB-CRC-MISMATCH` Integrity
    /// event carrying the record index. See `tests/data/README.md`.
    #[test]
    fn real_segb_crc_tamper_surfaces_integrity_event() {
        const REAL: &[u8] =
            include_bytes!("../tests/data/Device.Power.LowPowerMode.v1.crc-tampered.segb");
        let events = BiomeParser.parse_bytes(REAL, "/var/db/biome/.../Device.Power.LowPowerMode");
        let crc: Vec<_> = events
            .iter()
            .filter(|e| {
                e.activity_category == Some(issen_core::ActivityCategory::Integrity)
                    && e.metadata
                        .iter()
                        .any(|(_, v)| v.to_string().contains("SEGB-CRC-MISMATCH"))
            })
            .collect();
        assert_eq!(
            crc.len(),
            1,
            "exactly the one tampered record fails CRC; the other real records stay valid"
        );
        let e = crc[0];
        assert!(
            e.metadata
                .iter()
                .any(|(k, v)| k == "record_index" && v.as_u64() == Some(12)),
            "the integrity event must locate the tampered record (index 12)"
        );
        assert!(
            e.metadata.iter().any(|(k, _)| k == "stored_crc")
                && e.metadata.iter().any(|(k, _)| k == "computed_crc"),
            "a CRC-mismatch integrity event must carry the stored vs computed CRC"
        );
    }

    #[test]
    fn parse_bytes_non_segb_yields_no_events() {
        let events = BiomeParser.parse_bytes(b"this is plainly not a SEGB file..", "/x");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_via_byte_datasource_emits_events() {
        let segb = synthetic_segb_one_menu_item();
        let src = ByteSource(segb);
        let sink = CollectingEmitter::default();
        let stats = BiomeParser
            .parse(&src, &sink, &issen_core::plugin::ParseOptions::default())
            .expect("parse ok");
        assert_eq!(stats.events_emitted, 1);
        assert_eq!(sink.events.lock().unwrap().len(), 1);
    }
}
