//! Prototype + measurement: bounded-memory streaming of the correlate timeline.
//!
//! The correlate stage today loads the ENTIRE timeline into a `Vec<StoredEvent>`
//! (measured 1564 B/event, 4.9 GB peak for 2.34M events). This probe streams the
//! timeline from DuckDB in time-ordered keyset batches and holds only a sliding
//! window sized to the MAX correlation rule window (24h: relocate/lateral_move),
//! evicting events that fall behind it. It reports the peak window occupancy —
//! the real RAM ceiling a windowed-streaming correlate would need — so the
//! "bounded by the densest window, not the whole timeline" claim is measured,
//! not assumed.
//!
//! Run: /usr/bin/time -l \
//!   target/release/examples/stream_window_probe /tmp/case001.duckdb
//!
//! NOTE: a faithful streaming correlate must keep the WINDOWLESS memory-leg
//! cross-product (proc_disk_match) resident separately — that set is the dump's
//! processes, bounded and small. This probe measures the relational-rule window.

// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::collections::VecDeque;

use issen_timeline::events::{EventQuery, StoredEvent};
use issen_timeline::store::TimelineStore;

/// 24h — the widest ordered-window rule (relocate, lateral_move) in nanoseconds.
const MAX_WINDOW_NS: i64 = 24 * 60 * 60 * 1_000_000_000;
/// Keyset page size: how many rows we pull from DuckDB per round-trip.
const BATCH: u64 = 50_000;

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
        .expect("usage: stream_window_probe <case.duckdb>");
    let store = TimelineStore::open(std::path::Path::new(&path)).expect("open case DB");

    let mut window: VecDeque<StoredEvent> = VecDeque::new();
    let mut from: i64 = 1;
    let mut last_id: u64 = u64::MAX; // boundary de-dup across keyset pages
    let mut total: usize = 0;
    let mut peak_window: usize = 0;
    let mut peak_rss_kib: u64 = 0;

    loop {
        // Keyset page: next BATCH events at/after `from`, time-ordered (the same
        // ORDER BY the correlate query already uses), WITHOUT materializing all.
        let page = store
            .fetch_events(&EventQuery::within(from, i64::MAX).limit(BATCH))
            .expect("fetch page");
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        let last_ts = page[page.len() - 1].timestamp_ns;

        for ev in page {
            // Skip the tie-boundary row(s) already consumed on the previous page.
            if ev.timestamp_ns == from && ev.id == last_id {
                continue;
            }
            // Evict everything that fell behind this event's 24h trailing window.
            let cutoff = ev.timestamp_ns - MAX_WINDOW_NS;
            while window.front().is_some_and(|f| f.timestamp_ns < cutoff) {
                window.pop_front();
            }
            last_id = ev.id;
            window.push_back(ev);
            peak_window = peak_window.max(window.len());
            total += 1;
        }
        peak_rss_kib = peak_rss_kib.max(rss_kib());

        if (page_len as u64) < BATCH {
            break;
        }
        from = last_ts; // advance to the last ts (its rows de-duped above)
    }

    let per_event = 1564u64; // measured in-RAM cost (measure_load_rss)
    println!("streamed_events    = {total}");
    println!("peak_window_events = {peak_window}");
    println!(
        "window_fraction    = {:.1}% of timeline",
        100.0 * peak_window as f64 / total.max(1) as f64
    );
    println!(
        "window_working_set ~= {} MiB (peak_window x 1564 B)",
        (peak_window as u64 * per_event) / (1024 * 1024)
    );
    println!("peak_rss_mib       = {}", peak_rss_kib / 1024);
    println!(
        "vs full-load       : full = {} MiB ({} events); streaming holds {:.1}x fewer",
        (total as u64 * per_event) / (1024 * 1024),
        total,
        total as f64 / peak_window.max(1) as f64
    );
}
