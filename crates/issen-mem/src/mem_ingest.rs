//! Map the live `memf` Windows dispatch output into the PRE-1 memory→timeline
//! converter and persist it into the case timeline.
//!
//! The dispatch layer ([`crate::dispatch`]) returns *flattened string rows*
//! (`(headers, Vec<Vec<String>>)`) — the same shape the `memf` CLI prints as a
//! table. This module is the adapter that lifts those string rows back into the
//! typed PRE-1 input structs ([`MemProcessRow`], [`MemTcpRow`], [`MemMalfindRow`])
//! so the converter can emit canonical [`TimelineEvent`]s.
//!
//! Columns are addressed **by header name, not by fixed index**, so a future
//! reorder of a dispatch function's column list cannot silently corrupt the
//! mapping — a renamed/removed column degrades to an omitted field, never to a
//! value read out of the wrong column. Numbers parse leniently: a bad or empty
//! cell (e.g. the `psscan`-fallback `"?"` PPID) yields the field's default (`0`)
//! rather than a panic.
//!
//! The exact dispatch→PRE-1 column mapping implemented here:
//!
//! | dispatch fn                | headers                                              | → PRE-1 struct + fields                                                              |
//! |----------------------------|------------------------------------------------------|-------------------------------------------------------------------------------------|
//! | `dispatch_windows_ps`      | `PID, PPID, Name, State`                             | `MemProcessRow { pid←PID, ppid←PPID, image_name←Name, thread_count=0 (not emitted) }`|
//! | `dispatch_windows_netstat` | `Proto, Local, Remote, State, PID, Process, Note`    | `MemTcpRow { pid←PID, process_name←Process, (local_addr,local_port)←Local "addr:port", (remote_addr,remote_port)←Remote "addr:port", state←State }` |
//! | `dispatch_windows_scan`    | `Type, Address, Size, Detail`                        | `MemMalfindRow` for `Type` starting `malfind:` only — `injection_class`←`Type` suffix, `pid`+`image_name`←parsed from `Detail` `"pid=<n> <image> <prot> private-RWX"` |
//!
//! `dispatch_windows_ps` does not emit a thread count, so `thread_count`
//! defaults to `0`. The dead-orphan Tier-C check keys on `0` threads, so a
//! process whose count is genuinely unknown is conservatively treated as
//! *not* a confirmed live process; this is documented rather than silently
//! synthesised. `dispatch_windows_scan` interleaves pool / mbr / pe-version
//! rows with malfind rows — only the `malfind:` rows are injection regions, so
//! the rest are skipped by construction.

use crate::timeline::{
    memory_events, persist_memory_events, MemMalfindRow, MemProcessRow, MemTcpRow,
};
use issen_timeline::store::{TimelineStore, TimelineStoreError};

/// Dispatch output shape: `(headers, rows)` exactly as the `dispatch_windows_*`
/// functions return it.
type DispatchOutput = (Vec<&'static str>, Vec<Vec<String>>);

/// Find the column index of `header` (case-insensitive) in a header row.
fn col_index(headers: &[&str], header: &str) -> Option<usize> {
    headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case(header))
}

/// Fetch a cell by header name, returning `""` when the column or cell is absent.
fn cell<'a>(headers: &[&str], row: &'a [String], header: &str) -> &'a str {
    col_index(headers, header)
        .and_then(|i| row.get(i))
        .map_or("", String::as_str)
}

/// Parse an unsigned integer leniently: a bad/empty cell yields `0`, never a
/// panic. Accepts a trailing/leading-whitespace cell and the `psscan`-fallback
/// `"?"` placeholder (both → `0`).
fn parse_u32(s: &str) -> u32 {
    s.trim().parse().unwrap_or(0)
}

/// Parse a `u16` port leniently (bad/empty → `0`).
fn parse_u16(s: &str) -> u16 {
    s.trim().parse().unwrap_or(0)
}

/// Split a dispatch `"addr:port"` endpoint cell into `(addr, port)`.
///
/// Splits on the **last** colon so an IPv6 literal (which itself contains
/// colons) keeps its address intact and only the trailing port is taken. A cell
/// with no colon yields `(cell, 0)`; an empty cell yields `("", 0)`.
fn split_endpoint(cell: &str) -> (String, u16) {
    match cell.rsplit_once(':') {
        Some((addr, port)) => (addr.to_string(), parse_u16(port)),
        None => (cell.to_string(), 0),
    }
}

/// Map `dispatch_windows_ps` output into PRE-1 [`MemProcessRow`]s.
///
/// Columns are matched by header name. `thread_count` is not emitted by the ps
/// dispatch, so it defaults to `0` (see module docs). A placeholder
/// symbols-unavailable / empty Name row maps through with an empty image (the
/// converter then falls back to a `pid:<n>` subject).
#[must_use]
pub fn ps_rows_to_process_rows(_output: &DispatchOutput) -> Vec<MemProcessRow> {
    todo!("RED: ps_rows_to_process_rows not yet implemented")
}

/// Map `dispatch_windows_netstat` output into PRE-1 [`MemTcpRow`]s.
///
/// The `Local` / `Remote` columns are `addr:port` strings (the dispatch layer
/// pre-joins them), split here on the last colon. The symbols-unavailable
/// placeholder row (`Proto == "n/a"`) carries no real endpoint and is skipped.
#[must_use]
pub fn netstat_rows_to_tcp_rows(_output: &DispatchOutput) -> Vec<MemTcpRow> {
    todo!("RED: netstat_rows_to_tcp_rows not yet implemented")
}

/// Extract `(pid, image_name)` from a `dispatch_windows_scan` malfind `Detail`
/// cell of the documented form `"pid=<n> <image> <prot> private-RWX"`.
///
/// Robust to a missing `pid=` token (→ pid `0`) and a missing image (→ empty):
/// the leading `pid=<n>` token is parsed if present, and the next whitespace
/// token is taken as the image name. Never panics on a malformed detail.
fn parse_malfind_detail(detail: &str) -> (u32, String) {
    let mut pid = 0;
    let mut image = String::new();
    let mut tokens = detail.split_whitespace();
    if let Some(first) = tokens.next() {
        if let Some(num) = first.strip_prefix("pid=") {
            pid = parse_u32(num);
            // The image name is the token immediately after `pid=<n>`.
            if let Some(img) = tokens.next() {
                image = img.to_string();
            }
        }
    }
    (pid, image)
}

/// Map `dispatch_windows_scan` output into PRE-1 [`MemMalfindRow`]s.
///
/// The scan dispatch interleaves `pool:` / `mbr` / `pe-version` rows with
/// `malfind:<class>` injection rows; only the latter are process-injection
/// regions, so non-`malfind:` rows are skipped by construction. The
/// `injection_class` is the suffix after `malfind:`; pid + image are parsed out
/// of the `Detail` cell.
#[must_use]
pub fn scan_rows_to_malfind_rows(_output: &DispatchOutput) -> Vec<MemMalfindRow> {
    todo!("RED: scan_rows_to_malfind_rows not yet implemented")
}

/// Map all three Windows dispatch outputs → PRE-1 events → persist into the
/// case timeline, returning the number of rows actually inserted (post-dedup).
///
/// This is the convenience seam the `correlate` CLI memory phase calls: it owns
/// the full dispatch→converter→persist pipeline for one dump so the CLI shell
/// stays thin.
///
/// # Errors
///
/// Returns [`TimelineStoreError`] if the underlying batch insert fails.
pub fn ingest_memory_dump(
    store: &TimelineStore,
    dump_stem: &str,
    acquired_at_ns: i64,
    ps: &DispatchOutput,
    netstat: &DispatchOutput,
    scan: &DispatchOutput,
) -> Result<u64, TimelineStoreError> {
    let processes = ps_rows_to_process_rows(ps);
    let tcp = netstat_rows_to_tcp_rows(netstat);
    let malfind = scan_rows_to_malfind_rows(scan);
    let events = memory_events(dump_stem, acquired_at_ns, &processes, &tcp, &malfind);
    persist_memory_events(store, dump_stem, &events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::timeline::event::EntityRef;
    use issen_correlation::evaluator::{EventSource, EventView};
    use issen_timeline::events::EventQuery;

    const ACQ_NS: i64 = 1_700_000_000_000_000_000; // 2023-11-14T22:13:20Z
    const STEM: &str = "WIN-CASE001";

    /// The exact `(headers, rows)` that `dispatch_windows_ps` produces.
    fn ps_output() -> DispatchOutput {
        (
            vec!["PID", "PPID", "Name", "State"],
            vec![
                vec![
                    "3644".into(),
                    "4".into(),
                    "coreupdater.exe".into(),
                    "Running".into(),
                ],
                vec![
                    "640".into(),
                    "508".into(),
                    "svchost.exe".into(),
                    "Running".into(),
                ],
            ],
        )
    }

    /// The exact `(headers, rows)` that `dispatch_windows_netstat` produces
    /// (Local/Remote pre-joined as `addr:port`).
    fn netstat_output() -> DispatchOutput {
        (
            vec!["Proto", "Local", "Remote", "State", "PID", "Process", "Note"],
            vec![vec![
                "TCP".into(),
                "10.0.0.5:49001".into(),
                "203.78.103.109:443".into(),
                "ESTABLISHED".into(),
                "3644".into(),
                "coreupdater.exe".into(),
                "external-established".into(),
            ]],
        )
    }

    /// The exact `(headers, rows)` that `dispatch_windows_scan` produces — a
    /// malfind row interleaved with a pool row (which must be skipped).
    fn scan_output() -> DispatchOutput {
        (
            vec!["Type", "Address", "Size", "Detail"],
            vec![
                vec![
                    "pool:_EPROCESS".into(),
                    "0x1a2b3c".into(),
                    "0x4d0".into(),
                    "tag=Proc type=NonPaged suspicious=false".into(),
                ],
                vec![
                    "malfind:injected-PE".into(),
                    "0x7ff000000000".into(),
                    "0x1000".into(),
                    "pid=3724 spoolsv.exe PAGE_EXECUTE_READWRITE private-RWX".into(),
                ],
            ],
        )
    }

    // ── ps mapping ───────────────────────────────────────────────────────────

    #[test]
    fn ps_rows_map_pid_ppid_image_by_header_name() {
        let rows = ps_rows_to_process_rows(&ps_output());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pid, 3644);
        assert_eq!(rows[0].ppid, 4);
        assert_eq!(rows[0].image_name, "coreupdater.exe");
        // ps dispatch emits no thread count → conservative default 0.
        assert_eq!(rows[0].thread_count, 0);
        assert_eq!(rows[1].pid, 640);
        assert_eq!(rows[1].image_name, "svchost.exe");
    }

    #[test]
    fn ps_mapping_is_robust_to_column_reorder() {
        // Same data, columns shuffled — header-name addressing must still work.
        let reordered: DispatchOutput = (
            vec!["Name", "State", "PPID", "PID"],
            vec![vec![
                "coreupdater.exe".into(),
                "Running".into(),
                "4".into(),
                "3644".into(),
            ]],
        );
        let rows = ps_rows_to_process_rows(&reordered);
        assert_eq!(rows[0].pid, 3644);
        assert_eq!(rows[0].ppid, 4);
        assert_eq!(rows[0].image_name, "coreupdater.exe");
    }

    #[test]
    fn ps_psscan_fallback_question_mark_ppid_parses_to_zero() {
        // The psscan fallback emits PPID as "?" — must not panic, → 0.
        let out: DispatchOutput = (
            vec!["PID", "PPID", "Name", "State"],
            vec![vec![
                "1234".into(),
                "?".into(),
                "evil.exe".into(),
                "scanned".into(),
            ]],
        );
        let rows = ps_rows_to_process_rows(&out);
        assert_eq!(rows[0].pid, 1234);
        assert_eq!(rows[0].ppid, 0);
    }

    // ── netstat mapping ──────────────────────────────────────────────────────

    #[test]
    fn netstat_rows_split_addr_port_and_map_pid_process_state() {
        let rows = netstat_rows_to_tcp_rows(&netstat_output());
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.pid, 3644);
        assert_eq!(r.process_name, "coreupdater.exe");
        assert_eq!(r.local_addr, "10.0.0.5");
        assert_eq!(r.local_port, 49001);
        assert_eq!(r.remote_addr, "203.78.103.109");
        assert_eq!(r.remote_port, 443);
        assert_eq!(r.state, "ESTABLISHED");
    }

    #[test]
    fn netstat_skips_symbols_unavailable_placeholder_row() {
        // dispatch_windows_netstat emits a Proto == "n/a" placeholder when the
        // tcpip symbols are missing — it has no real endpoint, so it is dropped.
        let out: DispatchOutput = (
            vec!["Proto", "Local", "Remote", "State", "PID", "Process", "Note"],
            vec![vec![
                "n/a".into(),
                String::new(),
                String::new(),
                "TCP pool symbols unavailable".into(),
                String::new(),
                String::new(),
                String::new(),
            ]],
        );
        let rows = netstat_rows_to_tcp_rows(&out);
        assert!(rows.is_empty(), "placeholder row must not map to a TCP row");
    }

    #[test]
    fn netstat_endpoint_with_no_colon_keeps_addr_and_zero_port() {
        let out: DispatchOutput = (
            vec!["Proto", "Local", "Remote", "State", "PID", "Process", "Note"],
            vec![vec![
                "TCP".into(),
                "0.0.0.0".into(),
                String::new(),
                "LISTEN".into(),
                "4".into(),
                "System".into(),
                String::new(),
            ]],
        );
        let rows = netstat_rows_to_tcp_rows(&out);
        assert_eq!(rows[0].local_addr, "0.0.0.0");
        assert_eq!(rows[0].local_port, 0);
        assert_eq!(rows[0].remote_addr, "");
        assert_eq!(rows[0].remote_port, 0);
    }

    // ── scan / malfind mapping ───────────────────────────────────────────────

    #[test]
    fn scan_rows_keep_only_malfind_rows_and_parse_pid_image_class() {
        let rows = scan_rows_to_malfind_rows(&scan_output());
        // The pool row is dropped; only the malfind row survives.
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.pid, 3724);
        assert_eq!(r.image_name, "spoolsv.exe");
        assert_eq!(r.injection_class, "injected-PE");
    }

    #[test]
    fn scan_malfind_detail_without_pid_token_degrades_to_zero_pid() {
        let out: DispatchOutput = (
            vec!["Type", "Address", "Size", "Detail"],
            vec![vec![
                "malfind:injected-code".into(),
                "0x10000".into(),
                "0x2000".into(),
                "malformed detail with no pid token".into(),
            ]],
        );
        let rows = scan_rows_to_malfind_rows(&out);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 0);
        assert_eq!(rows[0].injection_class, "injected-code");
    }

    // ── end-to-end ingest_memory_dump ────────────────────────────────────────

    #[test]
    fn ingest_memory_dump_persists_all_three_legs_as_memory_events() {
        let store = TimelineStore::in_memory().expect("store");
        let n = ingest_memory_dump(
            &store,
            STEM,
            ACQ_NS,
            &ps_output(),
            &netstat_output(),
            &scan_output(),
        )
        .expect("ingest");
        // 2 processes + 1 tcp + 1 malfind = 4 events.
        assert_eq!(n, 4);

        let back = store
            .fetch_events(&EventQuery::within(0, i64::MAX))
            .expect("fetch");
        assert_eq!(back.len(), 4);
        for ev in &back {
            assert_eq!(
                ev.source(),
                EventSource::Memory,
                "every ingested row must land on the Memory leg (token {})",
                ev.source
            );
        }
        // The C2 remote peer survives as an Ip entity ref.
        assert!(back
            .iter()
            .flat_map(|e| e.entity_refs.iter())
            .any(|r| *r == EntityRef::Ip("203.78.103.109".to_string())));
    }

    #[test]
    fn ingest_memory_dump_re_ingest_is_deduped() {
        let store = TimelineStore::in_memory().expect("store");
        let first = ingest_memory_dump(
            &store,
            STEM,
            ACQ_NS,
            &ps_output(),
            &netstat_output(),
            &scan_output(),
        )
        .expect("ingest");
        assert_eq!(first, 4);
        let again = ingest_memory_dump(
            &store,
            STEM,
            ACQ_NS,
            &ps_output(),
            &netstat_output(),
            &scan_output(),
        )
        .expect("ingest");
        assert_eq!(again, 0, "identical re-ingest of the same dump dedups");
    }
}
