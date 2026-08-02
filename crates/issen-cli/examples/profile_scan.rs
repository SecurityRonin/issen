//! Throwaway profiling harness: break the scan stage into its sub-phases and
//! time each, to find whether the cost is DuckDB load, the scan compute, or the
//! findings insert.
//!   cargo build --release --example profile_scan -p issen-cli
//!   ./target/release/examples/profile_scan <case.duckdb>

// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::path::Path;
use std::time::Instant;

use issen_signatures::matching::engine::ScanEngine;
use issen_timeline::store::TimelineStore;

fn main() {
    let db = std::env::args().nth(1).expect("usage: profile_scan <db>");
    let store = TimelineStore::open(Path::new(&db)).expect("open db");

    let t = Instant::now();
    let events = store.load_timeline_events().expect("load");
    eprintln!(
        "1. load_timeline_events: {} events in {:.1}s",
        events.len(),
        t.elapsed().as_secs_f64()
    );

    let engine = ScanEngine::new();
    let t = Instant::now();
    let (findings, summary) =
        issen_cli::scanning::run_scan_phase(&events, &engine, Path::new("/nonexistent"));
    eprintln!(
        "2. run_scan_phase (compute): {} findings (timestomp {}) in {:.1}s",
        findings.len(),
        summary.timestomp_findings,
        t.elapsed().as_secs_f64()
    );

    let t = Instant::now();
    issen_timeline::findings::create_findings_table(store.connection()).expect("create table");
    issen_timeline::findings::insert_findings(store.connection(), &findings).expect("insert");
    eprintln!(
        "3. insert {} findings in {:.1}s",
        findings.len(),
        t.elapsed().as_secs_f64()
    );
}
