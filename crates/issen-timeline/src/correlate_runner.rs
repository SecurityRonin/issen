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

use issen_core::timeline::event::EntityRef;
use issen_correlation::correlation::Correlation;
use issen_correlation::evaluator::{EventSource, EventView};
use issen_correlation::runner::run_correlations_with_memory_progress;
use issen_correlation::tier_c::MemEvent;

use crate::events::{burst_windows, EventQuery, StoredEvent};
use crate::store::{TimelineStore, TimelineStoreError};

/// The failed-logon burst threshold and window that seed a `LogonFailureBurst`
/// anchor (plan v4 §5.2: a 4625 burst preceding a 4624 success).
const BURST_THRESHOLD: usize = 4;
const BURST_WINDOW: Duration = Duration::from_mins(1);

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
        me.pid = meta
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        me.ppid = meta
            .get("ppid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        me.thread_count = meta
            .get("thread_count")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        me.injection = meta
            .get("injection")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        me.state = meta
            .get("state")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
    }

    Some(me)
}

/// The event query the correlation pass scans: the whole timeline, unbounded.
///
/// Cross-artifact rules must see every event — anchors and their consequents can
/// sit anywhere in the timeline (on the Case-001 DC the attack window is the last
/// half of 691k events). So this opts out of the default row cap explicitly,
/// rather than silently truncating to the earliest [`DEFAULT_LIMIT`] rows.
fn correlation_query() -> EventQuery {
    EventQuery::within(1, i64::MAX).limit(u64::MAX)
}

/// Synthesize a `LogonFailureBurst` anchor for each identified burst whose
/// members share one source IP.
fn burst_anchors(events: &[StoredEvent]) -> Vec<BurstAnchor> {
    let mut anchors = Vec::new();
    for group in burst_windows(events, BURST_THRESHOLD, BURST_WINDOW) {
        // Only a run of FAILED logons seeds a brute-force anchor. A dense run of
        // any other type (e.g. machine-account LogonSuccess over a link-local
        // address) must never masquerade as a LogonFailureBurst.
        if group.first().map(|e| e.event_type.as_str()) != Some("LogonFailure") {
            continue;
        }
        // The latest member fronts the burst (its id keys the persisted member).
        let Some(last) = group.iter().max_by_key(|e| e.timestamp_ns) else {
            continue; // cov:unreachable: burst_windows never emits an empty group
        };
        // Join on the entity every member shares: the source IP if present, else
        // the account. RDP brute-force is frequently logged with Session 0 and no
        // source IP, leaving the targeted account as the only shared join key.
        let Some(join) = burst_join_entity(&group) else {
            continue;
        };
        anchors.push(BurstAnchor {
            id: last.id,
            timestamp_ns: last.timestamp_ns,
            entity_refs: vec![join],
            hostname: last.hostname.clone(),
        });
    }
    anchors
}

/// The entity every member of a failed-logon burst shares — the brute-force join
/// key. Prefers a source IP; falls back to the targeted account when the burst
/// carries no IP (the Case-001 4625 shape: Session 0, account only).
fn burst_join_entity(group: &[&StoredEvent]) -> Option<EntityRef> {
    let shared = |want_ip: bool| -> Option<EntityRef> {
        let pick = |e: &StoredEvent| {
            e.entity_refs
                .iter()
                .find(|r| {
                    if want_ip {
                        matches!(r, EntityRef::Ip(_))
                    } else {
                        matches!(r, EntityRef::User(_))
                    }
                })
                .cloned()
        };
        let candidate = group.first().and_then(|e| pick(e))?;
        group
            .iter()
            .all(|m| m.entity_refs.contains(&candidate))
            .then_some(candidate)
    };
    shared(true).or_else(|| shared(false))
}

impl TimelineStore {
    /// Fetch the timeline, run every disk-leg correlation rule, and persist each
    /// firing; returns the firings (each carrying its members).
    ///
    /// The fetch is bounded by the full positive-timestamp window. Memory-leg
    /// (Tier C) rules are not run here — the runner leaves an additive seam for
    /// them (see [`run_correlations`]).
    pub fn run_and_persist(&self) -> Result<Vec<Correlation>, TimelineStoreError> {
        // Delegate with a no-op per-rule callback; the progress-aware variant
        // carries the only copy of the fetch → run → persist logic.
        self.run_and_persist_with_progress(&|_| ())
    }

    /// Like [`run_and_persist`], but reports each correlation rule to `start_rule`
    /// for the lifetime of its evaluation, so a caller (the CLI) can render a
    /// per-rule worker bar. `start_rule(name)` returns an opaque guard held only
    /// while that rule runs; the guard type is generic so this crate stays
    /// UI-free. The findings are identical to [`run_and_persist`].
    pub fn run_and_persist_with_progress<F, G>(
        &self,
        start_rule: &F,
    ) -> Result<Vec<Correlation>, TimelineStoreError>
    where
        F: Fn(&str) -> G + Sync,
        G: Send,
    {
        let events = self.fetch_events(&correlation_query())?;

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

        let mut inputs: Vec<RunInput> = disk
            .iter()
            .map(|e| RunInput::Stored((*e).clone()))
            .collect();
        for anchor in burst_anchors(&events) {
            inputs.push(RunInput::Burst(anchor));
        }

        let correlations = run_correlations_with_memory_progress(&inputs, &memory, start_rule);
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
        store.insert_batch(events).expect("ingest");
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
        assert!(
            codes.len() >= 2,
            "at least two distinct rule codes: {codes:?}"
        );

        // Persisted firings read back with their members.
        for corr in &fired {
            assert!(!corr.members.is_empty(), "{} has members", corr.code);
        }
    }

    #[test]
    fn run_and_persist_with_progress_reports_rules_and_matches_plain() {
        use std::sync::{Arc, Mutex};

        let secs = 1_000_000_000i64;
        let events = vec![
            file_create(secs, "C:\\Windows\\System32\\coreupdater.exe"),
            service_install(2 * secs, "C:\\Windows\\System32\\coreupdater.exe"),
        ];

        // run_and_persist persists into the store; use one store per call so the
        // progress and plain runs see the same fresh input (correlations table).
        let reported: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let reported_cb = Arc::clone(&reported);
        let with_progress = store_with(&events)
            .run_and_persist_with_progress(&move |name: &str| {
                reported_cb
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(name.to_string());
            })
            .expect("run with progress");
        let plain = store_with(&events).run_and_persist().expect("run plain");

        let p_codes: std::collections::BTreeSet<&str> =
            with_progress.iter().map(|c| c.code.as_str()).collect();
        let plain_codes: std::collections::BTreeSet<&str> =
            plain.iter().map(|c| c.code.as_str()).collect();
        assert_eq!(p_codes, plain_codes, "identical findings to the plain run");
        assert!(p_codes.contains("CORR-MALWARE-PERSIST"), "{p_codes:?}");

        let names: std::collections::BTreeSet<String> = reported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        assert!(names.contains("persist"), "rules announced: {names:?}");
        assert!(names.contains("memory"), "rules announced: {names:?}");
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
            .unwrap_or_else(|| {
                panic!(
                    "CORR-INJECTED-C2 must fire; fired: {:?}",
                    fired.iter().map(|c| c.code.as_str()).collect::<Vec<_>>()
                )
            });
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

    /// A failed logon carrying only an account (no source IP) — the shape the
    /// Case-001 RDP brute-force takes (95 Administrator 4625s, Session 0, no IP).
    fn logon_failure_acct(ts: i64, user: &str) -> TimelineEvent {
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
        .with_entity_ref(EntityRef::User(user.to_string()))
    }

    fn logon_success_acct(ts: i64, user: &str, ip: &str) -> TimelineEvent {
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
        .with_entity_ref(EntityRef::User(user.to_string()))
        .with_entity_ref(EntityRef::Ip(ip.to_string()))
    }

    #[test]
    fn bruteforce_fires_on_account_when_failures_lack_a_source_ip() {
        // Case-001 real-data shape: a dense run of Administrator failures that
        // carry NO IP, then a successful Administrator logon. The brute-force
        // burst must anchor on the shared ACCOUNT (the only shared join key) and
        // link to the success — not silently miss it because there is no IP.
        let store = TimelineStore::in_memory().expect("store");
        let mut events: Vec<TimelineEvent> = (1..=5)
            .map(|i| logon_failure_acct(i * 1_000_000_000, "Administrator"))
            .collect();
        events.push(logon_success_acct(
            6_000_000_000,
            "Administrator",
            "194.61.24.102",
        ));
        store.insert_batch(&events).expect("ingest");

        let fired = store.run_and_persist().expect("run");
        assert!(
            fired.iter().any(|c| c.code == "CORR-BRUTEFORCE-LOGON"),
            "account-keyed brute-force must fire; fired: {:?}",
            fired.iter().map(|c| c.code.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn dense_logon_success_run_is_not_a_bruteforce_anchor() {
        // FP guard: a dense run of LogonSuccess (e.g. a machine account over a
        // link-local address) is NOT a failed-logon burst and must never seed a
        // CORR-BRUTEFORCE-LOGON, even though the events share an IP.
        let store = TimelineStore::in_memory().expect("store");
        // A dense burst of 5 successes (1–5 s, the link-local IP), then a later
        // success at 200 s — past the 60 s burst window (so it is not swept into
        // the cluster) yet within the 30-min rule window. Pre-fix, the cluster
        // was synthesized into a bogus LogonFailureBurst that matched the later
        // success on the shared IP — the exact real-data false positive.
        let mut events: Vec<TimelineEvent> = (1..=5)
            .map(|i| logon_success(i * 1_000_000_000, "fe80::2dcf:e660:be73:d220"))
            .collect();
        events.push(logon_success(200_000_000_000, "fe80::2dcf:e660:be73:d220"));
        store.insert_batch(&events).expect("ingest");

        let fired = store.run_and_persist().expect("run");
        assert!(
            !fired.iter().any(|c| c.code == "CORR-BRUTEFORCE-LOGON"),
            "a LogonSuccess run must not anchor a brute-force; fired: {:?}",
            fired.iter().map(|c| c.code.as_str()).collect::<Vec<_>>()
        );
    }
}
