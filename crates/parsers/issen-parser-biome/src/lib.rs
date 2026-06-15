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
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::TimelineEvent;
use std::path::Path;
use useract_forensic::UserActivity;

/// Biome `App.MenuItem` parser — ingests SEGB stream files.
pub struct BiomeParser;

impl BiomeParser {
    /// Read a SEGB file from disk and convert its `App.MenuItem` records into
    /// timeline events.
    pub fn parse_path(&self, _path: &Path) -> anyhow::Result<Vec<TimelineEvent>> {
        // RED stub — implemented in GREEN.
        Ok(Vec::new())
    }

    /// Decode SEGB bytes and map menu selections to timeline events.
    pub fn parse_bytes(&self, _bytes: &[u8], _evidence_source: &str) -> Vec<TimelineEvent> {
        // RED stub — implemented in GREEN.
        Vec::new()
    }
}

/// Map normalized Biome menu-selection activities onto Issen timeline events.
///
/// Pure function (no I/O) so the mapping is unit-testable (Humble Object).
pub fn activities_to_events(
    _activities: &[UserActivity],
    _evidence_source: &str,
) -> Vec<TimelineEvent> {
    // RED stub — implemented in GREEN.
    Vec::new()
}

impl ForensicParser for BiomeParser {
    fn name(&self) -> &str {
        "" // RED stub
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[] // RED stub
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        // RED stub — implemented in GREEN.
        Ok(ParseStats::new())
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
    ParserRegistration { create: || Box::new(BiomeParser) }
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
            let start = usize::try_from(offset).unwrap_or(usize::MAX).min(self.0.len());
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
    /// record: application="Finder", menu_item="Move to Trash".
    ///
    /// Layout follows `segb-core`: 56-byte file header (magic `b"SEGB"` at
    /// offsets 52–55, `end_of_data_offset` u32LE at 0), then a 32-byte record
    /// header `<iiddIi>` (length, state, ts1, ts2, crc, unknown), then payload,
    /// 8-byte aligned. The parse path does not CRC-validate, so the stored CRC
    /// is left 0.
    fn synthetic_segb_one_menu_item() -> Vec<u8> {
        // Protobuf payload: field 1 (app) + field 2 (menu_item), both wire-type 2.
        let mut payload = Vec::new();
        let app = b"Finder";
        payload.push(0x0A); // (1 << 3) | 2
        payload.push(app.len() as u8);
        payload.extend_from_slice(app);
        let item = b"Move to Trash";
        payload.push(0x12); // (2 << 3) | 2
        payload.push(item.len() as u8);
        payload.extend_from_slice(item);

        // Record header (32 bytes): struct "<iiddIi".
        let mut rec = Vec::new();
        rec.extend_from_slice(&(payload.len() as i32).to_le_bytes()); // 0: record_length
        rec.extend_from_slice(&1i32.to_le_bytes()); // 4: entry_state = 1 (Written)
        // Cocoa time for unix 1_700_000_000 = 1_700_000_000 - 978_307_200.
        rec.extend_from_slice(&721_692_800f64.to_le_bytes()); // 8: timestamp1
        rec.extend_from_slice(&721_692_800f64.to_le_bytes()); // 16: timestamp2
        rec.extend_from_slice(&0u32.to_le_bytes()); // 24: crc32 (not validated)
        rec.extend_from_slice(&0i32.to_le_bytes()); // 28: unknown

        let header_len = 56usize;
        let end_of_data = (header_len + rec.len() + payload.len()) as u32;

        let mut file = vec![0u8; header_len];
        file[0..4].copy_from_slice(&end_of_data.to_le_bytes());
        file[52..56].copy_from_slice(b"SEGB");
        file.extend_from_slice(&rec);
        file.extend_from_slice(&payload);
        while file.len() % 8 != 0 {
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
    fn parse_bytes_non_segb_yields_no_events() {
        let events = BiomeParser.parse_bytes(b"this is plainly not a SEGB file..", "/x");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_via_byte_datasource_emits_events() {
        let segb = synthetic_segb_one_menu_item();
        let src = ByteSource(segb);
        let sink = CollectingEmitter::default();
        let stats = BiomeParser.parse(&src, &sink).expect("parse ok");
        assert_eq!(stats.events_emitted, 1);
        assert_eq!(sink.events.lock().unwrap().len(), 1);
    }
}
