//! Store-facing driver for the disk-leg correlation runner (capstone task #37,
//! plan v5 §7.1 phase 5).
//!
//! [`TimelineStore::run_and_persist`] fetches the timeline's events, identifies
//! the 4625 failed-logon bursts that anchor `CORR-BRUTEFORCE-LOGON`
//! ([`burst_windows`]), runs every disk-leg rule
//! ([`issen_correlation::runner::run_correlations`]), and persists each firing
//! back into the `correlations` tables — returning the firings so a caller can
//! render them without a second read.
//!
//! The pure rule logic lives in `issen-correlation`; this module is the thin
//! storage adapter (fetch → synthesize burst anchors → run → persist).

use std::time::Duration;

use issen_correlation::correlation::Correlation;
use issen_correlation::evaluator::{EventSource, EventView};
use issen_correlation::runner::run_correlations_with_memory;
use issen_correlation::tier_c::MemEvent;
use issen_core::timeline::event::EntityRef;

use crate::events::{burst_windows, EventQuery, StoredEvent};
use crate::store::{TimelineStore, TimelineStoreError};

/// The failed-logon burst threshold and window that seed a `LogonFailureBurst`
/// anchor (plan v4 §5.2: a 4625 burst preceding a 4624 success).
const BURST_THRESHOLD: usize = 4;
const BURST_WINDOW: Duration = Duration::from_secs(60);

/// A synthetic `LogonFailureBurst` anchor event, owned by the runner.
///
/// `burst_windows` groups raw `LogonFailure` rows into bursts; the brute-force
/// rule anchors on a single `LogonFailureBurst` event carrying the shared source
/// IP. We synthesize one per burst, keyed on the burst's *latest* member id (a
/// real `timeline.id`, so the persisted correlation member resolves to a row),
/// timestamped at the latest failure, carrying that group's source IP.
#[derive(Debug, Clone)]
struct BurstAnchor {
    id: u64,
    timestamp_ns: i64,
    entity_refs: Vec<EntityRef>,
    hostname: Option<String>,
}

impl EventView for BurstAnchor {
    fn id(&self) -> u64 {
        self.id
    }
    fn timestamp_ns(&self) -> i64 {
        self.timestamp_ns
    }
    fn event_type(&self) -> &str {
        "LogonFailureBurst"
    }
    fn entity_refs(&self) -> &[EntityRef] {
        &self.entity_refs
    }
    fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }
    fn source(&self) -> EventSource {
        EventSource::Evtx
    }
}

/// Adapter so a `StoredEvent` and a synthesized `BurstAnchor` can sit in one
/// homogeneous slice that the generic runner consumes.
#[derive(Debug, Clone)]
enum RunInput {
    Stored(StoredEvent),
    Burst(BurstAnchor),
}

impl EventView for RunInput {
    fn id(&self) -> u64 {
        match self {
            Self::Stored(e) => e.id(),
            Self::Burst(e) => e.id(),
        }
    }
    fn timestamp_ns(&self) -> i64 {
        match self {
            Self::Stored(e) => e.timestamp_ns(),
            Self::Burst(e) => e.timestamp_ns(),
        }
    }
    fn event_type(&self) -> &str {
        match self {
            Self::Stored(e) => e.event_type(),
            Self::Burst(e) => e.event_type(),
        }
    }
    fn entity_refs(&self) -> &[EntityRef] {
        match self {
            Self::Stored(e) => e.entity_refs(),
            Self::Burst(e) => e.entity_refs(),
        }
    }
    fn hostname(&self) -> Option<&str> {
        match self {
            Self::Stored(e) => e.hostname(),
            Self::Burst(e) => e.hostname(),
        }
    }
    fn source(&self) -> EventSource {
        match self {
            Self::Stored(e) => e.source(),
            Self::Burst(e) => e.source(),
        }
    }
    fn artifact_path(&self) -> &str {
        match self {
            Self::Stored(e) => e.artifact_path(),
            Self::Burst(e) => e.artifact_path(),
        }
    }
}

/// Project a stored *memory* event into the richer [`MemEvent`] the Tier-C
/// matchers consume; `None` for any non-memory (disk/log) event.
///
/// Only memory rows ([`EventSource::Memory`]) carry the `pid` / `ppid` /
/// `thread_count` / `injection` / `state` metadata the memory rules need. The
/// identity/ordering fields come straight off the row; the memory-specific
/// fields are parsed out of the `metadata` JSON object PRE-1 writes. A
/// missing or un-parseable field is simply left `None` — never a panic.
fn mem_event_from_stored(e: &StoredEvent) -> Option<MemEvent> {
    if EventView::source(e) != EventSource::Memory {
        return None;
    }

    let mut me = MemEvent {
        id: e.id,
        timestamp_ns: e.timestamp_ns,
        event_type: e.event_type.clone(),
        entity_refs: e.entity_refs.clone(),
        hostname: e.hostname.clone(),
        source: EventSource::Memory,
        pid: None,
        ppid: None,
        thread_count: None,
        injection: None,
        state: None,
    };

    if let Some(meta) = e
        .metadata
        .as_deref()
        .and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok())
    {
        me.pid = meta.get("pid").and_then(serde_json::Value::as_u64).and_then(|v| u32::try_from(v).ok());
        me.ppid = meta.get("ppid").and_then(serde_json::Value::as_u64).and_then(|v| u32::try_from(v).ok());
        me.thread_count = meta
            .get("thread_count")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        me.injection = meta.get("injection").and_then(serde_json::Value::as_str).map(ToString::to_string);
        me.state = meta.get("state").and_then(serde_json::Value::as_str).map(ToString::to_string);
    }

    Some(me)
}

/// The IP a `LogonFailure` event carries, if any (the brute-force join key).
fn ip_of(event: &StoredEvent) -> Option<EntityRef> {
    event
        .entity_refs
        .iter()
        .find(|e| matches!(e, EntityRef::Ip(_)))
        .cloned()
}

/// Synthesize a `LogonFailureBurst` anchor for each identified burst whose
/// members share one source IP.
fn burst_anchors(events: &[StoredEvent]) -> Vec<BurstAnchor> {
    let mut anchors = Vec::new();
    for group in burst_windows(events, BURST_THRESHOLD, BURST_WINDOW) {
        // The latest member fronts the burst (its id keys the persisted member).
        let Some(last) = group.iter().max_by_key(|e| e.timestamp_ns) else {
            continue; // cov:unreachable: burst_windows never emits an empty group
        };
        let Some(ip) = ip_of(last) else {
            continue;
        };
        anchors.push(BurstAnchor {
            id: last.id,
            timestamp_ns: last.timestamp_ns,
            entity_refs: vec![ip],
            hostname: last.hostname.clone(),
        });
    }
    anchors
}

impl TimelineStore {
    /// Fetch the timeline, run every disk-leg correlation rule, and persist each
    /// firing; returns the firings (each carrying its members).
    ///
    /// The fetch is bounded by the full positive-timestamp window. Memory-leg
    /// (Tier C) rules are not run here — the runner leaves an additive seam for
    /// them (see [`run_correlations`]).
    pub fn run_and_persist(&self) -> Result<Vec<Correlation>, TimelineStoreError> {
        let events = self.fetch_events(&EventQuery::within(1, i64::MAX))?;

        // Partition the fetched events: memory rows feed the Tier-C matchers as
        // projected MemEvents; everything else (disk/log) feeds the disk-leg
        // rules. Memory rows are deliberately kept *out* of `inputs` (the
        // disk-rule pass) — they have no flat-EventView rule — but the disk
        // events are passed to the memory pass too, since CORR-PROC-DISK-MATCH
        // joins a memory process to a disk FileCreate.
        let memory: Vec<MemEvent> = events.iter().filter_map(mem_event_from_stored).collect();
        let disk: Vec<&StoredEvent> = events
            .iter()
            .filter(|e| EventView::source(*e) != EventSource::Memory)
            .collect();

        let mut inputs: Vec<RunInput> = disk.iter().map(|e| RunInput::Stored((*e).clone())).collect();
        for anchor in burst_anchors(&events) {
            inputs.push(RunInput::Burst(anchor));
        }

        let correlations = run_correlations_with_memory(&inputs, &memory);
        for corr in &correlations {
            let members: Vec<(u64, &str)> = corr
                .members
                .iter()
                .map(|m| (m.timeline_id, m.role.as_str()))
                .collect();
            self.persist_correlation(corr, &members)?;
        }
        Ok(correlations)
    }
}

#[cfg(test)]
mod tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};

    use crate::store::TimelineStore;

    fn file_create(ts: i64, path: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            path.to_string(),
            "file create".to_string(),
            "DC01".to_string(),
        )
        .with_hostname("DC01")
    }

    fn service_install(ts: i64, image: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::ServiceInstall,
            ArtifactType::EventLog,
            image.to_string(),
            "service install".to_string(),
            "DC01".to_string(),
        )
        .with_hostname("DC01")
    }

    fn logon_failure(ts: i64, ip: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::LogonFailure,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            "failed logon".to_string(),
            "DC01".to_string(),
        )
        .with_hostname("DC01")
        .with_entity_ref(EntityRef::Ip(ip.to_string()))
    }

    fn logon_success(ts: i64, ip: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::LogonSuccess,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            "successful logon".to_string(),
            "DC01".to_string(),
        )
        .with_hostname("DC01")
        .with_entity_ref(EntityRef::Ip(ip.to_string()))
    }

    /// A memory `MemoryInjection` (malfind) row, persisted exactly as PRE-1's
    /// `issen-mem` `memory_events` builds it: `EventType::Other("MemoryInjection")`,
    /// `ArtifactType::RootkitScan` (→ `EventSource::Memory`), a `Process` ref, and
    /// `pid` / `injection` metadata.
    fn mem_injection(ts: i64, proc_name: &str, pid: u32, dump: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::Other("MemoryInjection".to_string()),
            ArtifactType::RootkitScan,
            format!("pid:{pid}"),
            "injected region".to_string(),
            dump.to_string(),
        )
        .with_hostname(dump)
        .with_entity_ref(EntityRef::Process(proc_name.to_string()))
        .with_metadata("pid", serde_json::json!(pid))
        .with_metadata("injection", serde_json::json!("injected-PE"))
    }

    /// A memory ESTABLISHED `NetworkConnect` (netstat) row, persisted exactly as
    /// PRE-1's `memory_events` builds it: `EventType::NetworkConnect`,
    /// `ArtifactType::NetworkState` (→ `EventSource::Memory`), `Process` + `Ip`
    /// refs, and `state` metadata.
    fn mem_netconn(ts: i64, proc_name: &str, remote_ip: &str, dump: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::NetworkConnect,
            ArtifactType::NetworkState,
            "pid:3724".to_string(),
            "established connection".to_string(),
            dump.to_string(),
        )
        .with_hostname(dump)
        .with_entity_ref(EntityRef::Process(proc_name.to_string()))
        .with_entity_ref(EntityRef::Ip(remote_ip.to_string()))
        .with_metadata("state", serde_json::json!("ESTABLISHED"))
    }

    fn store_with(events: &[TimelineEvent]) -> TimelineStore {
        let store = TimelineStore::in_memory().expect("store");
        store.inseissen_batch(events).expect("ingest");
        store
    }

    #[test]
    fn run_and_persist_fires_two_distinct_rules_and_reads_back() {
        // A persistence pair (FileCreate -> ServiceInstall on the same stem) AND
        // a brute-force pattern (a 4625 burst -> 4624 success from one IP).
        let secs = 1_000_000_000i64;
        let mut events = vec![
            file_create(secs, "C:\\Windows\\System32\\coreupdater.exe"),
            service_install(2 * secs, "C:\\Windows\\System32\\coreupdater.exe"),
        ];
        // Five failed logons within 60s from one IP -> a burst.
        for k in 0..5 {
            events.push(logon_failure(10 * secs + k * secs, "194.61.24.102"));
        }
        // A success from the same IP shortly after the burst.
        events.push(logon_success(16 * secs, "194.61.24.102"));

        let store = store_with(&events);
        let fired = store.run_and_persist().expect("run");

        let codes: std::collections::BTreeSet<&str> =
            fired.iter().map(|c| c.code.as_str()).collect();
        assert!(codes.contains("CORR-MALWARE-PERSIST"), "codes: {codes:?}");
        assert!(codes.contains("CORR-BRUTEFORCE-LOGON"), "codes: {codes:?}");
        assert!(codes.len() >= 2, "at least two distinct rule codes: {codes:?}");

        // Persisted firings read back with their members.
        for corr in &fired {
            assert!(!corr.members.is_empty(), "{} has members", corr.code);
        }
    }

    #[test]
    fn run_and_persist_fires_a_memory_leg_rule_end_to_end() {
        // A memory dump's injected process beaconing to C2: a MemoryInjection on
        // one process plus an ESTABLISHED NetworkConnect to an external IP from
        // the *same* process, both in one dump. This is the CORR-INJECTED-C2
        // Tier-C rule — it can only fire if the memory leg is wired into
        // run_and_persist (disk-only run_correlations never sees it).
        let secs = 1_000_000_000i64;
        let dump = "WIN-CASE001";
        let events = vec![
            mem_injection(20 * secs, "spoolsv.exe", 3724, dump),
            mem_netconn(20 * secs, "spoolsv.exe", "203.78.103.109", dump),
        ];

        let store = store_with(&events);
        let fired = store.run_and_persist().expect("run");

        let injected = fired
            .iter()
            .find(|c| c.code == "CORR-INJECTED-C2")
            .unwrap_or_else(|| panic!("CORR-INJECTED-C2 must fire; fired: {:?}",
                fired.iter().map(|c| c.code.as_str()).collect::<Vec<_>>()));
        assert_eq!(injected.members.len(), 2, "anchor + consequent members");

        // It persisted and reads back with its members. Scan the persisted ids
        // (1-based sequence) for the INJECTED-C2 row rather than assuming a fixed
        // id, since other rules may also have fired and persisted.
        let back = (1..=fired.len() as u64)
            .filter_map(|id| store.correlation(id).expect("read"))
            .find(|c| c.code == "CORR-INJECTED-C2")
            .expect("CORR-INJECTED-C2 persisted and reads back");
        assert_eq!(back.members.len(), 2);
    }

    #[test]
    fn run_and_persist_on_empty_timeline_is_clean() {
        let store = TimelineStore::in_memory().expect("store");
        assert!(store.run_and_persist().expect("run").is_empty());
    }

    #[test]
    fn correlation_query_scans_the_whole_timeline_unbounded() {
        // Regression for the real-data failure: on the Case-001 DC (691k events)
        // the default 100k row cap truncated the correlation fetch to the earliest
        // events — the entire attack window (ranks 368k–691k) was discarded and no
        // rule fired. The correlation pass MUST scan every event.
        assert!(
            super::correlation_query().is_unbounded(),
            "run_and_persist must fetch the whole timeline, not the first DEFAULT_LIMIT rows"
        );
    }
}
