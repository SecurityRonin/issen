//! Integration tests proving the `issen-parser-srum` wrapper surfaces REAL
//! SRUM rows — decoded by the sibling `srum-parser`/`ese-core` ESE B-tree
//! traversal — into Issen [`TimelineEvent`]s.
//!
//! These exercise the full wiring path that the CLI now depends on:
//! `SrumParser::parse_path` → `srum_parser::parse_network_usage` →
//! `ese_core` leaf-page walk → `TimelineEvent` with `bytes_sent` metadata.
//!
//! Ground truth (verified against the real third-party fixture, not a
//! self-built synthetic — see `srum-forensic/tests/data/srudb/SOURCES.md`):
//!   chainsaw_SRUDB.dat — WithSecure Labs / Chainsaw test suite
//!     MD5 c946eb4a2c6a3da2e62f98486de5e1b0
//!     96 network-usage records, 94 with non-zero BytesSent,
//!     single largest BytesSent = 8_507_778 bytes (the "exfil window").
//!
//! The fixture lives in the sibling `srum-forensic` repo (the fleet's single
//! SRUDB corpus home); the test skips gracefully when that checkout is absent
//! so a stand-alone Issen build still passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::{DataSource, EventEmitter, ForensicParser};
use issen_core::timeline::event::TimelineEvent;
use issen_parser_srum::SrumParser;

/// A path-bearing `DataSource` test double: reads the real file AND exposes its
/// path via `source_path()`, mirroring the orchestrator's `FileDataSource`. This
/// is what lets a random-access (ESE) parser reach the file in `parse()`.
struct PathDataSource {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl PathDataSource {
    fn open(path: &Path) -> Self {
        let bytes = std::fs::read(path).expect("read fixture");
        Self {
            path: path.to_path_buf(),
            bytes,
        }
    }
}

impl DataSource for PathDataSource {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let offset = offset as usize;
        if offset >= self.bytes.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.bytes.len() - offset);
        buf[..n].copy_from_slice(&self.bytes[offset..offset + n]);
        Ok(n)
    }

    fn source_path(&self) -> Option<&Path> {
        Some(&self.path)
    }
}

/// Collecting emitter for the trait-path test.
struct CollectingEmitter {
    events: Mutex<Vec<TimelineEvent>>,
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

/// Path to the real chainsaw SRUDB.dat in the sibling srum-forensic repo.
fn chainsaw_srudb() -> Option<PathBuf> {
    // From issen/crates/parsers/issen-parser-srum/, the sibling repo is
    // ../../../../srum-forensic relative to CARGO_MANIFEST_DIR.
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../srum-forensic/tests/data/srudb/chainsaw_SRUDB.dat");
    if p.exists() {
        Some(p)
    } else {
        eprintln!("SKIP — real SRUDB fixture not present: {}", p.display());
        eprintln!(
            "       (sibling srum-forensic checkout required; see its tests/data/srudb/SOURCES.md)"
        );
        None
    }
}

/// The wrapper must surface at least one network-usage event from the real DB.
#[test]
fn chainsaw_srudb_yields_network_events() {
    let Some(path) = chainsaw_srudb() else { return };
    let events = SrumParser
        .parse_path(&path)
        .expect("parse_path must succeed on a valid SRUDB.dat");
    let net_events: Vec<_> = events
        .iter()
        .filter(|e| e.description.starts_with("SRUM NetworkUsage"))
        .collect();
    assert_eq!(
        net_events.len(),
        96,
        "chainsaw SRUDB must surface exactly 96 network-usage events, got {}",
        net_events.len()
    );
}

/// The trait dispatch path the orchestrator actually uses: `parse()` (not
/// `parse_path`) must surface the same real network events. This requires the
/// `DataSource` to expose its file path so the ESE (random-access) reader can
/// open it — the wiring that turns SRUM from "command-only" into an ingest
/// stream.
#[test]
fn chainsaw_srudb_parse_trait_emits_network_events() {
    let Some(path) = chainsaw_srudb() else { return };
    let source = PathDataSource::open(&path);
    let emitter = CollectingEmitter {
        events: Mutex::new(Vec::new()),
    };
    let stats = SrumParser
        .parse(
            &source,
            &emitter,
            &issen_core::plugin::ParseOptions::default(),
        )
        .expect("parse() must succeed on a path-bearing DataSource");

    let events = emitter.events.into_inner().expect("lock");
    let net_events = events
        .iter()
        .filter(|e| e.description.starts_with("SRUM NetworkUsage"))
        .count();
    assert_eq!(
        net_events, 96,
        "parse() via DataSource::source_path must surface all 96 network events, got {net_events}"
    );
    assert_eq!(
        stats.events_emitted,
        events.len() as u64,
        "reported events_emitted must match what was emitted"
    );
}

/// The "exfil window" assertion: the wrapper must carry the real per-record
/// `bytes_sent` through to TimelineEvent metadata, with the largest transfer
/// matching the ground-truth value byte-for-byte.
#[test]
fn chainsaw_srudb_surfaces_nonzero_bytes_sent_in_exfil_window() {
    let Some(path) = chainsaw_srudb() else { return };
    let events = SrumParser.parse_path(&path).expect("parse_path ok");

    let bytes_sent: Vec<u64> = events
        .iter()
        .filter_map(|e| e.metadata.get("bytes_sent"))
        .filter_map(serde_json::Value::as_u64)
        .collect();

    assert!(
        !bytes_sent.is_empty(),
        "no event carried bytes_sent metadata — wrapper is not surfacing real SRUM rows"
    );
    let nonzero = bytes_sent.iter().filter(|&&b| b > 0).count();
    assert_eq!(
        nonzero, 94,
        "chainsaw SRUDB must have 94 records with non-zero bytes_sent, got {nonzero}"
    );
    let max = bytes_sent.iter().copied().max().unwrap_or(0);
    assert_eq!(
        max, 8_507_778,
        "largest bytes_sent (exfil window) must equal the ground-truth 8_507_778, got {max}"
    );
}
