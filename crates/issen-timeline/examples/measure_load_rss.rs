//! Measure the in-RAM footprint of the correlate-stage full-timeline load.
//!
//! Grounds the audit claim that the correlate stage materializes the ENTIRE
//! timeline into a `Vec<StoredEvent>` (the only confirmed unbounded-RAM path).
//! Loads every event via the exact correlate query and reports RSS deltas, so
//! the extrapolated "bytes/event in RAM" becomes a measured number.
//!
//! Run:  cargo run --release --example measure_load_rss -- /tmp/case001.duckdb
//! For the true peak, wrap it:  /usr/bin/time -l cargo run ... (macOS)

// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use issen_timeline::events::EventQuery;
use issen_timeline::store::TimelineStore;

/// Resident-set size of THIS process, in KiB (portable via `ps`).
fn rss_kib() -> u64 {
    let pid = std::process::id().to_string();
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: measure_load_rss <case.duckdb>");
    let base = rss_kib();

    let store = TimelineStore::open(std::path::Path::new(&path)).expect("open case DB");
    let after_open = rss_kib();

    // The EXACT correlate-stage query: whole positive timeline, no row cap.
    let q = EventQuery::within(1, i64::MAX).limit(u64::MAX);
    let events = store.fetch_events(&q).expect("fetch full timeline");
    let after_load = rss_kib();

    let n = events.len().max(1);
    let load_delta_kib = after_load.saturating_sub(after_open);
    let bytes_per_event = (load_delta_kib * 1024) / n as u64;

    println!("events            = {}", events.len());
    println!("rss_base_kib      = {base}");
    println!("rss_after_open_kib= {after_open}");
    println!("rss_after_load_kib= {after_load}");
    println!("load_delta_mib    = {}", load_delta_kib / 1024);
    println!("bytes_per_event   = {bytes_per_event}  (in-RAM, Vec<StoredEvent>)");
    println!(
        "extrapolation     : 100M events ~= {} GiB RAM",
        (bytes_per_event * 100_000_000) / (1024 * 1024 * 1024)
    );

    // Keep the Vec live across the final measurement so it isn't optimized away.
    std::hint::black_box(&events);
}
