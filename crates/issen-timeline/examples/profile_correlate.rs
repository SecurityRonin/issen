//! Throwaway profiling harness: open a case DB and run the correlate pass,
//! timing it. Run under `sample` to find the hot path.
//!   cargo build --release --example profile_correlate -p issen-timeline
//!   ./target/release/examples/profile_correlate <case.duckdb>

// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::path::Path;
use std::time::Instant;

use issen_timeline::store::TimelineStore;

fn main() {
    let db = std::env::args()
        .nth(1)
        .expect("usage: profile_correlate <db>");
    let store = TimelineStore::open(Path::new(&db)).expect("open db");
    let t = Instant::now();
    let corrs = store.run_and_persist().expect("correlate");
    eprintln!(
        "correlate: {} findings in {:.1}s",
        corrs.len(),
        t.elapsed().as_secs_f64()
    );
}
