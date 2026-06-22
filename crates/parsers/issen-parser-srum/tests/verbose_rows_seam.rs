//! Seam test: the per-parser [`ParseOptions`] control over SRUM's high-volume
//! tables (PushNotifications, EnergyUsage).
//!
//! By DEFAULT (`ParseOptions::default()`, `verbose_rows == false`) these tables
//! are AGGREGATED per-app — one summary event carrying an `occurrences` count —
//! so a 562-row push table does not flood the timeline. When a caller opts in
//! with `ParseOptions { verbose_rows: true }`, the SAME table is emitted as
//! full per-row events instead (one event per record), for an analyst who wants
//! every row.
//!
//! This exercises the real seam: `ParseOptions` is threaded through the
//! `ForensicParser::parse` trait method, not a SRUM-private back door.
//!
//! Ground truth (real third-party fixtures in the sibling `srum-forensic` repo,
//! see its `tests/data/srudb/SOURCES.md`):
//!   chainsaw_SRUDB.dat                — 562 PushNotifications rows
//!   museum_rathbunvm_win11_SRUDB.dat  — 13 EnergyUsage rows
//! Both tests skip gracefully when the corpus checkout is absent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::redundant_closure_for_method_calls
)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::{DataSource, EventEmitter, ForensicParser};
use issen_core::plugin::ParseOptions;
use issen_core::timeline::event::TimelineEvent;
use issen_parser_srum::SrumParser;

/// Path-bearing `DataSource` double (mirrors the orchestrator's `FileDataSource`):
/// an ESE/random-access parser reaches the file through `source_path()`.
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
        self.events.into_inner().expect("lock")
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

fn parse_with(path: &Path, opts: &ParseOptions) -> Vec<TimelineEvent> {
    let source = PathDataSource::open(path);
    let emitter = CollectingEmitter::new();
    SrumParser
        .parse(&source, &emitter, opts)
        .expect("parse() must succeed on a path-bearing DataSource");
    emitter.into_events()
}

fn occurrences(event: &TimelineEvent) -> u64 {
    event
        .metadata
        .iter()
        .find(|(k, _)| k.as_str() == "occurrences")
        .and_then(|(_, v)| v.as_u64())
        .unwrap_or(0)
}

fn fixture(name: &str) -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../srum-forensic/tests/data/srudb")
        .join(name);
    if p.exists() {
        Some(p)
    } else {
        eprintln!("SKIP — SRUDB fixture not present: {}", p.display());
        None
    }
}

/// PushNotifications (562 rows): default aggregates per-app (few events, each
/// carrying an `occurrences` count); `verbose_rows` emits one event per row.
#[test]
fn push_default_aggregates_but_verbose_emits_per_row() {
    let Some(path) = fixture("chainsaw_SRUDB.dat") else {
        return;
    };

    let default_push: Vec<_> = parse_with(&path, &ParseOptions::default())
        .into_iter()
        .filter(|e| e.description.starts_with("SRUM PushNotifications"))
        .collect();
    let verbose_push: Vec<_> = parse_with(&path, &ParseOptions::default().with_verbose_rows(true))
        .into_iter()
        .filter(|e| e.description.starts_with("SRUM PushNotifications"))
        .collect();

    assert!(!default_push.is_empty(), "default push must surface events");

    // Default is the aggregate: the rows collapse, so the summed occurrences
    // strictly exceed the number of aggregate events.
    let total_rows: u64 = default_push.iter().map(occurrences).sum();
    assert!(
        total_rows > default_push.len() as u64,
        "default must aggregate: {total_rows} rows collapsed into {} events",
        default_push.len()
    );

    // Verbose emits one event per row — exactly `total_rows` of them — strictly
    // more than the aggregate, and matching the row count the aggregate counted.
    assert_eq!(
        verbose_push.len() as u64,
        total_rows,
        "verbose_rows must emit one push event per row ({total_rows}), got {}",
        verbose_push.len()
    );
    assert!(
        verbose_push.len() > default_push.len(),
        "verbose must emit strictly more events than the aggregate"
    );

    // CADET tagging is preserved in verbose mode (push → NetworkActivity), and
    // app enrichment (app_id) still rides along.
    assert_eq!(
        verbose_push[0].activity_category.map(|c| c.code()),
        Some("network-activity"),
        "verbose push events keep the NetworkActivity CADET category"
    );
    assert!(
        verbose_push
            .iter()
            .all(|e| e.metadata.iter().any(|(k, _)| k == "app_id")),
        "verbose push events keep app_id metadata"
    );
}

/// EnergyUsage (13 rows): default aggregates per-app; `verbose_rows` emits one
/// `Execution` event per row.
#[test]
fn energy_default_aggregates_but_verbose_emits_per_row() {
    let Some(path) = fixture("museum_rathbunvm_win11_SRUDB.dat") else {
        return;
    };

    let default_energy: Vec<_> = parse_with(&path, &ParseOptions::default())
        .into_iter()
        .filter(|e| e.description.starts_with("SRUM EnergyUsage:"))
        .collect();
    let verbose_energy: Vec<_> =
        parse_with(&path, &ParseOptions::default().with_verbose_rows(true))
            .into_iter()
            .filter(|e| e.description.starts_with("SRUM EnergyUsage:"))
            .collect();

    assert!(
        !default_energy.is_empty(),
        "default energy must surface events"
    );

    let total_rows: u64 = default_energy.iter().map(occurrences).sum();
    assert!(
        total_rows > default_energy.len() as u64,
        "default must aggregate energy rows"
    );
    assert_eq!(
        verbose_energy.len() as u64,
        total_rows,
        "verbose_rows must emit one energy event per row ({total_rows}), got {}",
        verbose_energy.len()
    );
    assert_eq!(
        verbose_energy[0].activity_category.map(|c| c.code()),
        Some("execution"),
        "verbose energy events keep the Execution CADET category"
    );
}
