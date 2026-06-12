//! Convert memory-forensic walker output into canonical [`TimelineEvent`]s.
//!
//! The memory leg of the case timeline is a *point-in-time* snapshot: every
//! process, connection, and injected region observed in a dump is true only at
//! the instant the dump was acquired. This module lifts the walker rows into the
//! fleet's one timeline vocabulary so the cross-artifact correlation rules
//! (Tier C) can join memory subjects (a process image, a remote IP) against disk
//! and log events on a shared [`EntityRef`].
//!
//! The input rows here are issen-owned, synthetically constructible structs —
//! the dispatch layer maps the OS-specific walker output (`WinProcessInfo`,
//! TCP endpoints, `WinMalfindInfo`, …) into them. Keeping the converter's input
//! decoupled from the `memf-windows` structs makes it unit-testable without a
//! real dump and insulated from churn in those structs.
//!
//! Every emitted event:
//! - is timestamped at `acquired_at_ns` (the dump acquisition instant),
//! - carries the `memory-acquired` and `point-in-time` tags so the report can
//!   distinguish it from a disk event with an intrinsic timestamp,
//! - carries a `source` [`ArtifactType`] whose Debug token maps to
//!   `EventSource::Memory` in the correlation evaluator
//!   (`ProcessList` / `NetworkState` / `RootkitScan`).

use chrono::{TimeZone, Utc};
use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};
use issen_timeline::store::{TimelineStore, TimelineStoreError};

/// A process observed by the process-list walker (`walk_processes` / `psscan`).
///
/// Feeds the Tier-C dead-orphan check (0 threads + an absent parent), so the
/// `thread_count` and `ppid` survive into the event metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemProcessRow {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Image file name (e.g. `coreupdater.exe`).
    pub image_name: String,
    /// Number of threads (0 = dead/terminated process still in the table).
    pub thread_count: u32,
}

/// A TCP endpoint observed by the netstat walker (`walk_tcp_endpoints`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemTcpRow {
    /// Owning process ID.
    pub pid: u32,
    /// Owning process image name (may be empty if unresolved).
    pub process_name: String,
    /// Local address.
    pub local_addr: String,
    /// Local port.
    pub local_port: u16,
    /// Remote address.
    pub remote_addr: String,
    /// Remote port.
    pub remote_port: u16,
    /// Connection state string (e.g. `ESTABLISHED`, `LISTEN`).
    pub state: String,
}

/// A suspicious memory region observed by the malfind / pool scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemMalfindRow {
    /// Owning process ID.
    pub pid: u32,
    /// Owning process image name.
    pub image_name: String,
    /// Injection classification (e.g. `injected-code`, `injected-PE`).
    pub injection_class: String,
}

/// The owning process subject for a process / region row: prefer the image
/// name, fall back to the PID when the image is unknown.
fn process_subject(image_name: &str, pid: u32) -> String {
    if image_name.is_empty() {
        format!("pid:{pid}")
    } else {
        image_name.to_string()
    }
}

/// Format a nanosecond Unix timestamp as an RFC3339 UTC instant for display.
///
/// Mirrors the workspace convention (`issen-cli` `commands::correlate::fmt_ns`):
/// out-of-range instants degrade to a raw `<n>ns` label rather than panicking.
/// The seconds derived from any `i64` nanosecond value (`ns / 1e9`, so at most
/// ~9.2e9 s ≈ year 2262) always fall within chrono's representable range, so the
/// degradation arm is a defence-in-depth guard, not a reachable path.
fn fmt_ns(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000) as u32;
    match Utc.timestamp_opt(secs, nanos).single() {
        Some(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        None => format!("{ns}ns"), // cov:unreachable: ns/1e9 secs is always in chrono range
    }
}

/// Stamp the point-in-time / memory-acquired provenance shared by every
/// memory event and set the host attribution.
fn memory_provenance(event: TimelineEvent, dump_stem: &str) -> TimelineEvent {
    event
        .with_hostname(dump_stem.to_string())
        .with_tag("memory-acquired")
        .with_tag("point-in-time")
}

/// Convert memory-forensic walker output into canonical [`TimelineEvent`]s.
///
/// All events are timestamped at `acquired_at_ns` (the dump acquisition
/// instant) and attributed to `dump_stem` (the host / evidence-source id).
#[must_use]
pub fn memory_events(
    dump_stem: &str,
    acquired_at_ns: i64,
    processes: &[MemProcessRow],
    tcp: &[MemTcpRow],
    malfind: &[MemMalfindRow],
) -> Vec<TimelineEvent> {
    let display = fmt_ns(acquired_at_ns);
    let mut events =
        Vec::with_capacity(processes.len() + tcp.len() + malfind.len());

    for p in processes {
        let subject = process_subject(&p.image_name, p.pid);
        let event = TimelineEvent::new(
            acquired_at_ns,
            display.clone(),
            EventType::ProcessExec,
            ArtifactType::ProcessList,
            format!("pid:{}", p.pid),
            format!(
                "Process {subject} (pid {}, ppid {}, {} thread(s)) resident in memory",
                p.pid, p.ppid, p.thread_count
            ),
            dump_stem.to_string(),
        )
        .with_entity_ref(EntityRef::Process(subject))
        .with_metadata("pid", serde_json::json!(p.pid))
        .with_metadata("ppid", serde_json::json!(p.ppid))
        .with_metadata("thread_count", serde_json::json!(p.thread_count));
        events.push(memory_provenance(event, dump_stem));
    }

    for c in tcp {
        let subject = process_subject(&c.process_name, c.pid);
        let mut event = TimelineEvent::new(
            acquired_at_ns,
            display.clone(),
            EventType::NetworkConnect,
            ArtifactType::NetworkState,
            format!("pid:{}", c.pid),
            format!(
                "{subject} (pid {}) {} {}:{} -> {}:{}",
                c.pid, c.state, c.local_addr, c.local_port, c.remote_addr, c.remote_port
            ),
            dump_stem.to_string(),
        )
        .with_entity_ref(EntityRef::Process(subject))
        .with_metadata("local_port", serde_json::json!(c.local_port))
        .with_metadata("remote_port", serde_json::json!(c.remote_port))
        .with_metadata("state", serde_json::json!(c.state));
        // Only attach an Ip ref for a real remote peer — a listening/wildcard
        // row has no peer to correlate against.
        if !c.remote_addr.is_empty() {
            event = event.with_entity_ref(EntityRef::Ip(c.remote_addr.clone()));
        }
        events.push(memory_provenance(event, dump_stem));
    }

    for m in malfind {
        let subject = process_subject(&m.image_name, m.pid);
        let event = TimelineEvent::new(
            acquired_at_ns,
            display.clone(),
            EventType::Other("MemoryInjection".to_string()),
            ArtifactType::RootkitScan,
            format!("pid:{}", m.pid),
            format!(
                "Injected region in {subject} (pid {}): {}",
                m.pid, m.injection_class
            ),
            dump_stem.to_string(),
        )
        .with_entity_ref(EntityRef::Process(subject))
        .with_metadata("pid", serde_json::json!(m.pid))
        .with_metadata("injection", serde_json::json!(m.injection_class));
        events.push(memory_provenance(event, dump_stem));
    }

    events
}

/// Persist memory events into the case timeline under a memory snapshot epoch.
///
/// Thin wrapper over the existing batch insert: the memory leg is a point-in-time
/// cohort, so it is tagged with a dump-scoped epoch (`mem:<dump_stem>`) rather
/// than the live epoch — re-ingesting the same dump dedups on `record_hash`
/// within that epoch, while a second dump of the same host is a distinct cohort.
/// Returns the number of rows actually inserted (post-dedup).
///
/// # Errors
///
/// Returns [`TimelineStoreError`] if the underlying batch insert fails.
pub fn persist_memory_events(
    store: &TimelineStore,
    dump_stem: &str,
    events: &[TimelineEvent],
) -> Result<u64, TimelineStoreError> {
    store.insert_batch_at_epoch(events, &format!("mem:{dump_stem}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_correlation::evaluator::{EventSource, EventView};
    use issen_timeline::events::EventQuery;
    use issen_timeline::store::TimelineStore;

    const ACQ_NS: i64 = 1_700_000_000_000_000_000; // 2023-11-14T22:13:20Z
    const STEM: &str = "WIN-CASE001";

    fn proc_row() -> MemProcessRow {
        MemProcessRow {
            pid: 3644,
            ppid: 4,
            image_name: "coreupdater.exe".to_string(),
            thread_count: 0,
        }
    }

    fn tcp_row() -> MemTcpRow {
        MemTcpRow {
            pid: 3644,
            process_name: "coreupdater.exe".to_string(),
            local_addr: "10.0.0.5".to_string(),
            local_port: 49001,
            remote_addr: "203.78.103.109".to_string(),
            remote_port: 443,
            state: "ESTABLISHED".to_string(),
        }
    }

    fn malfind_row() -> MemMalfindRow {
        MemMalfindRow {
            pid: 3724,
            image_name: "spoolsv.exe".to_string(),
            injection_class: "injected-PE".to_string(),
        }
    }

    // ── Process row → ProcessExec event ──────────────────────────────────────

    #[test]
    fn process_row_maps_to_process_exec_with_pid_ppid_threads() {
        let events = memory_events(STEM, ACQ_NS, &[proc_row()], &[], &[]);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, EventType::ProcessExec);
        assert_eq!(e.source, ArtifactType::ProcessList);
        assert_eq!(e.timestamp_ns, ACQ_NS);
        assert_eq!(e.hostname.as_deref(), Some(STEM));
        assert!(e.entity_refs.contains(&EntityRef::Process("coreupdater.exe".to_string())));
        assert_eq!(e.metadata.get("pid"), Some(&serde_json::json!(3644)));
        assert_eq!(e.metadata.get("ppid"), Some(&serde_json::json!(4)));
        assert_eq!(e.metadata.get("thread_count"), Some(&serde_json::json!(0)));
        assert!(e.tags.contains(&"memory-acquired".to_string()));
        assert!(e.tags.contains(&"point-in-time".to_string()));
    }

    // ── TCP row → NetworkConnect event ───────────────────────────────────────

    #[test]
    fn tcp_row_maps_to_network_connect_with_process_and_ip_refs() {
        let events = memory_events(STEM, ACQ_NS, &[], &[tcp_row()], &[]);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, EventType::NetworkConnect);
        assert_eq!(e.source, ArtifactType::NetworkState);
        assert!(e.entity_refs.contains(&EntityRef::Process("coreupdater.exe".to_string())));
        assert!(e.entity_refs.contains(&EntityRef::Ip("203.78.103.109".to_string())));
        assert_eq!(e.metadata.get("remote_port"), Some(&serde_json::json!(443)));
        assert_eq!(e.metadata.get("local_port"), Some(&serde_json::json!(49001)));
        assert_eq!(e.metadata.get("state"), Some(&serde_json::json!("ESTABLISHED")));
    }

    // ── Malfind row → MemoryInjection event ──────────────────────────────────

    #[test]
    fn malfind_row_maps_to_memory_injection_event() {
        let events = memory_events(STEM, ACQ_NS, &[], &[], &[malfind_row()]);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, EventType::Other("MemoryInjection".to_string()));
        assert_eq!(e.source, ArtifactType::RootkitScan);
        assert!(e.entity_refs.contains(&EntityRef::Process("spoolsv.exe".to_string())));
        assert_eq!(
            e.metadata.get("injection"),
            Some(&serde_json::json!("injected-PE"))
        );
    }

    #[test]
    fn process_subject_falls_back_to_pid_when_image_empty() {
        let row = MemProcessRow {
            pid: 99,
            ppid: 1,
            image_name: String::new(),
            thread_count: 1,
        };
        let events = memory_events(STEM, ACQ_NS, &[row], &[], &[]);
        assert!(events[0]
            .entity_refs
            .contains(&EntityRef::Process("pid:99".to_string())));
    }

    // ── Round-trip: ingest → fetch_events → EventSource::Memory ───────────────

    #[test]
    fn memory_events_round_trip_to_event_source_memory() {
        let events = memory_events(
            STEM,
            ACQ_NS,
            &[proc_row()],
            &[tcp_row()],
            &[malfind_row()],
        );
        let store = TimelineStore::in_memory().expect("store");
        store.inseissen_batch(&events).expect("ingest");

        let back = store
            .fetch_events(&EventQuery::within(0, i64::MAX))
            .expect("fetch");
        assert_eq!(back.len(), 3);
        for ev in &back {
            assert_eq!(
                ev.source(),
                EventSource::Memory,
                "every memory event must map to the Memory leg (source token {})",
                ev.source
            );
        }

        // Entity refs survive the DuckDB round trip.
        let process_refs: Vec<_> = back
            .iter()
            .flat_map(|e| e.entity_refs.iter())
            .filter(|r| matches!(r, EntityRef::Process(_)))
            .collect();
        assert!(process_refs
            .iter()
            .any(|r| **r == EntityRef::Process("coreupdater.exe".to_string())));
        assert!(back
            .iter()
            .flat_map(|e| e.entity_refs.iter())
            .any(|r| *r == EntityRef::Ip("203.78.103.109".to_string())));
    }

    #[test]
    fn persist_memory_events_inserts_and_dedups_within_epoch() {
        let events = memory_events(STEM, ACQ_NS, &[proc_row()], &[tcp_row()], &[malfind_row()]);
        let store = TimelineStore::in_memory().expect("store");

        let n = persist_memory_events(&store, STEM, &events).expect("persist");
        assert_eq!(n, 3, "all three rows persist on first ingest");

        // Re-ingesting the same dump dedups on record_hash within the epoch.
        let again = persist_memory_events(&store, STEM, &events).expect("persist");
        assert_eq!(again, 0, "identical re-ingest is fully deduped");

        let back = store
            .fetch_events(&EventQuery::within(0, i64::MAX))
            .expect("fetch");
        assert_eq!(back.len(), 3);
    }

    #[test]
    fn fmt_ns_renders_rfc3339_utc() {
        assert!(fmt_ns(ACQ_NS).starts_with("2023-11-14T22:13:20"));
        assert!(fmt_ns(ACQ_NS).ends_with('Z'));
    }
}
