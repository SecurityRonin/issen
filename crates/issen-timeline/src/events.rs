//! Bounded event retrieval for the correlation engine.
//!
//! [`StoredEvent`] is a timeline row read back with its `entity_refs` parsed —
//! the input the DuckDB-free evaluator consumes. [`EventQuery`] is a query
//! builder that is **bounded by construction**: it cannot express an unbounded
//! full-table scan, because every constructor requires at least a time window
//! or an entity filter. [`burst_windows`] groups same-type events into bursts
//! (the 4625 failed-logon burst that anchors `CORR-BRUTEFORCE-LOGON`).

use std::time::Duration;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};

use crate::store::{TimelineStore, TimelineStoreError};

/// A timeline row read back for correlation, with its `entity_refs` parsed.
///
/// This is the input the DuckDB-free evaluator consumes; it carries everything a
/// rule needs to join events on a shared entity and order them in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    /// The persisted `timeline.id` (the correlation-member key).
    pub id: u64,
    /// Event time in nanoseconds since the Unix epoch.
    pub timestamp_ns: i64,
    /// `EventType` rendered as its debug token (e.g. `LogonFailure`).
    pub event_type: String,
    /// `ArtifactType` rendered as its debug token (e.g. `EventLog`).
    pub source: String,
    /// Path within the evidence source.
    pub artifact_path: String,
    /// Raw metadata JSON, if any.
    pub metadata: Option<String>,
    /// Entity references parsed from the `entity_refs` column.
    pub entity_refs: Vec<EntityRef>,
    /// Host attribution, if known.
    pub hostname: Option<String>,
    /// Evidence-source identifier (image/dump stem).
    pub evidence_source: String,
}

impl StoredEvent {
    /// `true` when this event carries the given entity reference.
    #[must_use]
    pub fn has_entity(&self, entity: &EntityRef) -> bool {
        self.entity_refs.iter().any(|e| e == entity)
    }
}

impl issen_correlation::evaluator::EventView for StoredEvent {
    fn id(&self) -> u64 {
        self.id
    }
    fn timestamp_ns(&self) -> i64 {
        self.timestamp_ns
    }
    fn event_type(&self) -> &str {
        &self.event_type
    }
    fn artifact_path(&self) -> &str {
        &self.artifact_path
    }
    fn entity_refs(&self) -> &[EntityRef] {
        &self.entity_refs
    }
    fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }
    fn source(&self) -> issen_correlation::evaluator::EventSource {
        use issen_correlation::evaluator::EventSource;
        // Map the persisted `ArtifactType` Debug token to a correlation leg.
        match self.source.as_str() {
            "EventLog" => EventSource::Evtx,
            "Registry" | "Shellbags" | "Amcache" | "Bam" => EventSource::Registry,
            "Mft" | "UsnJournal" | "Prefetch" | "Lnk" | "JumpLists" => EventSource::Disk,
            "ProcessList" | "NetworkState" | "RootkitScan" => EventSource::Memory,
            _ => EventSource::Other,
        }
    }
}

/// A bounded query over the timeline for correlation candidate retrieval.
///
/// **Bounded by construction:** the only two ways to build an `EventQuery` are
/// [`EventQuery::within`] (a time window) and [`EventQuery::for_entity`] (an
/// entity filter). There is no default/unbounded constructor, so a caller can
/// never accidentally issue a full-table scan — every query carries at least one
/// of the two cheap, indexed bounds. Optional filters (`event_types`, `host`,
/// further entities, `limit`) only narrow the result further.
#[derive(Debug, Clone)]
pub struct EventQuery {
    from_ns: Option<i64>,
    to_ns: Option<i64>,
    event_types: Vec<String>,
    host: Option<String>,
    entity: Option<EntityRef>,
    limit: u64,
}

/// The default row cap for a query that does not set its own `limit`.
const DEFAULT_LIMIT: u64 = 100_000;

impl EventQuery {
    /// A query bounded to the inclusive nanosecond window `[from_ns, to_ns]`.
    #[must_use]
    pub fn within(from_ns: i64, to_ns: i64) -> Self {
        Self {
            from_ns: Some(from_ns),
            to_ns: Some(to_ns),
            event_types: Vec::new(),
            host: None,
            entity: None,
            limit: DEFAULT_LIMIT,
        }
    }

    /// A query bounded to events carrying the given entity reference.
    #[must_use]
    pub fn for_entity(entity: EntityRef) -> Self {
        Self {
            from_ns: None,
            to_ns: None,
            event_types: Vec::new(),
            host: None,
            entity: Some(entity),
            limit: DEFAULT_LIMIT,
        }
    }

    /// Restrict to the given event-type debug tokens (e.g. `"LogonFailure"`).
    #[must_use]
    pub fn event_types<I, S>(mut self, types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.event_types = types.into_iter().map(Into::into).collect();
        self
    }

    /// Restrict to a single host.
    #[must_use]
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Add (or replace) the entity filter.
    #[must_use]
    pub fn with_entity(mut self, entity: EntityRef) -> Self {
        self.entity = Some(entity);
        self
    }

    /// Cap the number of rows returned.
    #[must_use]
    pub fn limit(mut self, limit: u64) -> Self {
        self.limit = limit;
        self
    }

    /// The lower time bound, if any.
    #[must_use]
    pub fn from_ns(&self) -> Option<i64> {
        self.from_ns
    }

    /// The upper time bound, if any.
    #[must_use]
    pub fn to_ns(&self) -> Option<i64> {
        self.to_ns
    }

    /// The host filter, if any.
    #[must_use]
    pub fn host_filter(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// The entity filter, if any.
    #[must_use]
    pub fn entity_filter(&self) -> Option<&EntityRef> {
        self.entity.as_ref()
    }

    /// The row cap.
    #[must_use]
    pub fn limit_value(&self) -> u64 {
        self.limit
    }

    /// True when the query opts out of the row cap entirely (`limit(u64::MAX)`).
    ///
    /// This is the explicit, greppable full-scan opt-in for the one caller that
    /// legitimately needs every row — the cross-artifact correlation pass. An
    /// ordinary query keeps [`DEFAULT_LIMIT`], so it can never accidentally
    /// full-scan; only this sentinel drops the `LIMIT` clause in
    /// [`TimelineStore::fetch_events`].
    #[must_use]
    pub fn is_unbounded(&self) -> bool {
        self.limit == u64::MAX
    }
}

/// A burst is a dense run of same-type events that exceeds a threshold count.
///
/// Bursts group only events of one `event_type`, ordered in time, where each
/// consecutive gap is within `window`. A group is emitted only when it has at
/// least `threshold` members — the shape that anchors `CORR-BRUTEFORCE-LOGON`
/// (a 4625 failed-logon burst). Events with a zero or negative timestamp never
/// seed a burst, mirroring the ordered-window evaluator's clock discipline.
#[must_use]
pub fn burst_windows(
    events: &[StoredEvent],
    threshold: usize,
    window: Duration,
) -> Vec<Vec<&StoredEvent>> {
    use std::collections::BTreeMap;

    let window_ns = i64::try_from(window.as_nanos()).unwrap_or(i64::MAX);

    // Group by event type, keeping only positively-timestamped events.
    let mut by_type: BTreeMap<&str, Vec<&StoredEvent>> = BTreeMap::new();
    for event in events {
        if event.timestamp_ns <= 0 {
            continue;
        }
        by_type
            .entry(event.event_type.as_str())
            .or_default()
            .push(event);
    }

    let mut bursts = Vec::new();
    for group in by_type.values_mut() {
        group.sort_by_key(|e| e.timestamp_ns);
        let mut current: Vec<&StoredEvent> = Vec::new();
        for &event in group.iter() {
            match current.last() {
                Some(prev) if event.timestamp_ns - prev.timestamp_ns <= window_ns => {
                    current.push(event);
                }
                Some(_) => {
                    if current.len() >= threshold {
                        bursts.push(std::mem::take(&mut current));
                    } else {
                        current.clear();
                    }
                    current.push(event);
                }
                None => current.push(event),
            }
        }
        if current.len() >= threshold {
            bursts.push(current);
        }
    }
    bursts
}

impl TimelineStore {
    /// Fetch the events matching a bounded [`EventQuery`], reconstructing each
    /// [`StoredEvent`] (entity refs parsed from the `entity_refs` column).
    ///
    /// The time window, event-type set, and host are pushed down to SQL. An
    /// entity filter is pushed down as a cheap substring prefilter on the
    /// serialized `entity_refs` JSON and then verified exactly in Rust (so a
    /// substring that happens to appear in a different entity kind cannot leak
    /// through).
    pub fn fetch_events(&self, q: &EventQuery) -> Result<Vec<StoredEvent>, TimelineStoreError> {
        let mut sql = String::from(
            "SELECT id, timestamp_ns, event_type, source, artifact_path,
                    metadata, entity_refs, hostname, evidence_source
             FROM timeline WHERE 1=1",
        );
        let mut params: Vec<Box<dyn duckdb::ToSql>> = Vec::new();

        if let Some(from) = q.from_ns {
            sql.push_str(" AND timestamp_ns >= ?");
            params.push(Box::new(from));
        }
        if let Some(to) = q.to_ns {
            sql.push_str(" AND timestamp_ns <= ?");
            params.push(Box::new(to));
        }
        if !q.event_types.is_empty() {
            let placeholders = vec!["?"; q.event_types.len()].join(", ");
            sql.push_str(&format!(" AND event_type IN ({placeholders})"));
            for et in &q.event_types {
                params.push(Box::new(et.clone()));
            }
        }
        if let Some(ref host) = q.host {
            sql.push_str(" AND hostname = ?");
            params.push(Box::new(host.clone()));
        }
        // Serialized fragment for the entity prefilter, e.g. {"Ip":"203.0.113.5"}.
        let entity_fragment =
            match q.entity.as_ref() {
                Some(entity) => Some(serde_json::to_string(entity).map_err(|e| {
                    TimelineStoreError::Query(format!("serialize entity filter: {e}"))
                })?),
                None => None,
            };
        if let Some(ref fragment) = entity_fragment {
            sql.push_str(" AND entity_refs LIKE ?");
            params.push(Box::new(format!("%{fragment}%")));
        }
        sql.push_str(" ORDER BY timestamp_ns ASC");
        // The unbounded sentinel (correlation full-scan) omits the cap entirely;
        // every other query keeps its row limit so it can never full-scan.
        if !q.is_unbounded() {
            sql.push_str(" LIMIT ?");
            params.push(Box::new(q.limit));
        }

        let param_refs: Vec<&dyn duckdb::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.connection().prepare(&sql)?;
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            let entity_refs_json: String = row.get(6)?;
            let entity_refs: Vec<EntityRef> =
                serde_json::from_str(&entity_refs_json).unwrap_or_default();
            Ok(StoredEvent {
                id: row.get(0)?,
                timestamp_ns: row.get(1)?,
                event_type: row.get(2)?,
                source: row.get(3)?,
                artifact_path: row.get(4)?,
                metadata: row.get(5)?,
                entity_refs,
                hostname: row.get(7)?,
                evidence_source: row.get(8)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            let event = row?;
            // Exact-match the entity filter in Rust — the SQL LIKE is only a
            // cheap prefilter; a substring hit is not an entity-equality hit.
            if let Some(entity) = q.entity.as_ref() {
                if !event.has_entity(entity) {
                    continue;
                }
            }
            results.push(event);
        }
        Ok(results)
    }

    /// Read every persisted row back into a canonical [`TimelineEvent`],
    /// reconstructing the `EventType` / `ArtifactType` enums (so their `Display`
    /// drives temporal-rule matching) and parsing the `entity_refs` JSON.
    ///
    /// This is the read substrate for the `timeline --narrative` view: parse
    /// once at ingest, then analyze the persisted timeline many ways. Rows are
    /// returned ordered by `timestamp_ns` for a deterministic chronological
    /// timeline.
    ///
    /// # Errors
    ///
    /// Returns an error if a row carries a `source` token this build's
    /// `ArtifactType` does not recognize — surfaced loudly rather than silently
    /// dropping the event from the timeline.
    pub fn load_timeline_events(&self) -> Result<Vec<TimelineEvent>, TimelineStoreError> {
        let mut stmt = self.connection().prepare(
            "SELECT id, timestamp_ns, timestamp_display, event_type, source,
                    artifact_path, description, user_account, hostname, tags,
                    evidence_source, entity_refs
             FROM timeline ORDER BY timestamp_ns ASC",
        )?;
        let raw_rows = stmt.query_map([], |row| {
            Ok(RawTimelineRow {
                id: row.get(0)?,
                timestamp_ns: row.get(1)?,
                timestamp_display: row.get(2)?,
                event_type: row.get(3)?,
                source: row.get(4)?,
                artifact_path: row.get(5)?,
                description: row.get(6)?,
                user_account: row.get(7)?,
                hostname: row.get(8)?,
                tags: row.get(9)?,
                evidence_source: row.get(10)?,
                entity_refs: row.get(11)?,
            })
        })?;

        let mut events = Vec::new();
        for raw in raw_rows {
            let r = raw?;
            let source = ArtifactType::from_debug_str(&r.source).ok_or_else(|| {
                TimelineStoreError::Query(format!(
                    "timeline row {}: unknown source token {:?}; cannot reconstruct event",
                    r.id, r.source
                ))
            })?;
            let entity_refs: Vec<EntityRef> =
                serde_json::from_str(&r.entity_refs).unwrap_or_default();
            let tags: Vec<String> =
                serde_json::from_str(r.tags.as_deref().unwrap_or("[]")).unwrap_or_default();
            let mut event = TimelineEvent::new(
                r.timestamp_ns,
                r.timestamp_display,
                EventType::from_debug_str(&r.event_type),
                source,
                r.artifact_path,
                r.description,
                r.evidence_source,
            );
            event.user = r.user_account;
            event.hostname = r.hostname;
            event.tags = tags;
            event.entity_refs = entity_refs;
            events.push(event);
        }
        Ok(events)
    }
}

/// A raw timeline row as read from DuckDB, before enum reconstruction.
struct RawTimelineRow {
    id: u64,
    timestamp_ns: i64,
    timestamp_display: String,
    event_type: String,
    source: String,
    artifact_path: String,
    description: String,
    user_account: Option<String>,
    hostname: Option<String>,
    tags: Option<String>,
    evidence_source: String,
    entity_refs: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};

    use crate::store::TimelineStore;

    fn logon_failure(ts: i64, ip: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::LogonFailure,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            "An account failed to log on".to_string(),
            "DC01".to_string(),
        )
        .with_hostname("DC01")
        .with_entity_ref(EntityRef::Ip(ip.to_string()))
    }

    fn store_with(events: &[TimelineEvent]) -> TimelineStore {
        let store = TimelineStore::in_memory().expect("store");
        store.inseissen_batch(events).expect("ingest");
        store
    }

    #[test]
    fn load_timeline_events_reconstructs_type_source_entities() {
        // The narrative-over-DB path (issen #110 Phase 1) reads persisted rows
        // back into real `TimelineEvent`s so the enum `Display` (e.g. "Event
        // Log") drives temporal-rule source matching, and entity refs survive.
        let store = TimelineStore::in_memory().expect("store");
        let exec = TimelineEvent::new(
            1_000,
            "2026-01-01T00:00:01Z".to_string(),
            EventType::ProcessExec,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            "powershell.exe started".to_string(),
            "DC01".to_string(),
        )
        .with_entity_ref(EntityRef::Process("powershell.exe".to_string()));
        let other = TimelineEvent::new(
            2_000,
            "2026-01-01T00:00:02Z".to_string(),
            EventType::Other("SrumNetUsage".to_string()),
            ArtifactType::Srum,
            "SRUDB.dat".to_string(),
            "net usage row".to_string(),
            "DC01".to_string(),
        );
        store.inseissen_batch(&[exec, other]).expect("ingest");

        let mut events = store.load_timeline_events().expect("load");
        events.sort_by_key(|e| e.timestamp_ns);
        assert_eq!(events.len(), 2);

        let pe = &events[0];
        assert_eq!(pe.event_type, EventType::ProcessExec);
        assert_eq!(format!("{}", pe.source), "Event Log");
        assert_eq!(
            pe.entity_refs,
            vec![EntityRef::Process("powershell.exe".to_string())]
        );
        assert_eq!(pe.description, "powershell.exe started");
        assert_eq!(pe.timestamp_ns, 1_000);

        let other = &events[1];
        assert_eq!(
            other.event_type,
            EventType::Other("SrumNetUsage".to_string())
        );
        assert_eq!(format!("{}", other.source), "SRUM");
    }

    #[test]
    fn activity_category_survives_db_round_trip() {
        // CADET tagging is only useful if it persists: a tagged event ingested to
        // DuckDB must reload with its category. A None-tagged event reloads None.
        use issen_core::ActivityCategory;
        let store = TimelineStore::in_memory().expect("store");
        let tagged = TimelineEvent::new(
            1_000,
            "2026-01-01T00:00:01Z".to_string(),
            EventType::ProcessExec,
            ArtifactType::Amcache,
            "Amcache.hve".to_string(),
            "evil.exe executed".to_string(),
            "DC01".to_string(),
        )
        .with_activity_category(ActivityCategory::Execution);
        let untagged = TimelineEvent::new(
            2_000,
            "2026-01-01T00:00:02Z".to_string(),
            EventType::RegistryModify,
            ArtifactType::Registry,
            "SOFTWARE".to_string(),
            "some config".to_string(),
            "DC01".to_string(),
        );
        store.inseissen_batch(&[tagged, untagged]).expect("ingest");

        let mut events = store.load_timeline_events().expect("load");
        events.sort_by_key(|e| e.timestamp_ns);
        assert_eq!(
            events[0].activity_category,
            Some(ActivityCategory::Execution),
            "tagged event must reload with its category"
        );
        assert_eq!(
            events[1].activity_category, None,
            "untagged event must reload as None"
        );
    }

    // ── EventQuery is bounded by construction ────────────────────────────────

    #[test]
    fn query_within_window_requires_no_extra_filter() {
        // A time window alone is a valid bound.
        let q = EventQuery::within(1_000, 2_000);
        assert_eq!(q.from_ns(), Some(1_000));
        assert_eq!(q.to_ns(), Some(2_000));
    }

    #[test]
    fn query_for_entity_is_bounded_without_a_time_window() {
        // An entity filter alone is a valid bound (no time window needed).
        let q = EventQuery::for_entity(EntityRef::Ip("203.0.113.5".to_string()));
        assert_eq!(q.from_ns(), None);
        assert!(q.entity_filter().is_some());
    }

    #[test]
    fn query_builders_add_optional_filters() {
        let q = EventQuery::within(0, 10_000)
            .event_types(["LogonFailure", "LogonSuccess"])
            .host("DC01")
            .with_entity(EntityRef::Ip("203.0.113.5".to_string()))
            .limit(500);
        assert_eq!(q.host_filter(), Some("DC01"));
        assert_eq!(q.limit_value(), 500);
        assert!(q.entity_filter().is_some());
    }

    #[test]
    fn unbounded_is_the_explicit_full_scan_opt_in() {
        // The correlation pass legitimately scans the whole timeline. limit(u64::MAX)
        // is the explicit, greppable opt-in; an ordinary query stays capped so it
        // can never accidentally full-scan.
        assert!(EventQuery::within(1, i64::MAX)
            .limit(u64::MAX)
            .is_unbounded());
        assert!(!EventQuery::within(1, i64::MAX).is_unbounded());
    }

    #[test]
    fn fetch_events_unbounded_does_not_apply_the_default_cap() {
        let store = store_with(&[
            logon_failure(1_000, "203.0.113.1"),
            logon_failure(2_000, "203.0.113.2"),
            logon_failure(3_000, "203.0.113.3"),
        ]);
        // A capped query honors the cap…
        assert_eq!(
            store
                .fetch_events(&EventQuery::within(0, i64::MAX).limit(2))
                .expect("fetch")
                .len(),
            2
        );
        // …the unbounded sentinel returns every row (no LIMIT clause).
        assert_eq!(
            store
                .fetch_events(&EventQuery::within(0, i64::MAX).limit(u64::MAX))
                .expect("fetch")
                .len(),
            3
        );
    }

    // ── fetch_events round-trips, including entity_refs ──────────────────────

    #[test]
    fn fetch_events_within_window_reconstructs_entity_refs() {
        let store = store_with(&[
            logon_failure(1_000, "203.0.113.5"),
            logon_failure(2_000, "203.0.113.5"),
            logon_failure(9_999_999, "10.0.0.1"), // outside window
        ]);
        let q = EventQuery::within(0, 5_000);
        let events = store.fetch_events(&q).expect("fetch");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].timestamp_ns, 1_000);
        assert_eq!(events[0].event_type, "LogonFailure");
        assert_eq!(events[0].source, "EventLog");
        assert_eq!(events[0].hostname.as_deref(), Some("DC01"));
        assert_eq!(events[0].evidence_source, "DC01");
        assert!(events[0].id > 0);
        assert_eq!(
            events[0].entity_refs,
            vec![EntityRef::Ip("203.0.113.5".to_string())]
        );
    }

    #[test]
    fn fetch_events_for_entity_filters_to_matching_rows() {
        let store = store_with(&[
            logon_failure(1_000, "203.0.113.5"),
            logon_failure(2_000, "10.0.0.1"),
        ]);
        let q = EventQuery::for_entity(EntityRef::Ip("203.0.113.5".to_string()));
        let events = store.fetch_events(&q).expect("fetch");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, 1_000);
    }

    #[test]
    fn fetch_events_filters_by_event_type_and_host() {
        let mut success = logon_failure(3_000, "203.0.113.5");
        success.event_type = EventType::LogonSuccess;
        let store = store_with(&[logon_failure(1_000, "203.0.113.5"), success]);
        let q = EventQuery::within(0, 10_000).event_types(["LogonSuccess"]);
        let events = store.fetch_events(&q).expect("fetch");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "LogonSuccess");
    }

    // ── burst_windows groups same-type events ────────────────────────────────

    #[test]
    fn burst_windows_groups_a_dense_run_into_one_burst() {
        // Five failed logons within 1s windows → a single burst of >= threshold.
        let store = store_with(&[
            logon_failure(1_000_000_000, "203.0.113.5"),
            logon_failure(1_100_000_000, "203.0.113.5"),
            logon_failure(1_200_000_000, "203.0.113.5"),
            logon_failure(1_300_000_000, "203.0.113.5"),
            logon_failure(1_400_000_000, "203.0.113.5"),
        ]);
        let q = EventQuery::within(0, 5_000_000_000);
        let events = store.fetch_events(&q).expect("fetch");
        let bursts = burst_windows(&events, 4, Duration::from_secs(2));
        assert_eq!(bursts.len(), 1, "one dense burst");
        assert_eq!(bursts[0].len(), 5);
    }

    #[test]
    fn burst_windows_splits_on_a_gap_and_drops_below_threshold() {
        // Two events, then a long gap, then two events. With threshold 3,
        // neither cluster reaches the threshold → no burst.
        let store = store_with(&[
            logon_failure(1_000_000_000, "203.0.113.5"),
            logon_failure(1_100_000_000, "203.0.113.5"),
            logon_failure(9_000_000_000, "203.0.113.5"),
            logon_failure(9_100_000_000, "203.0.113.5"),
        ]);
        let q = EventQuery::within(0, 20_000_000_000);
        let events = store.fetch_events(&q).expect("fetch");
        let bursts = burst_windows(&events, 3, Duration::from_secs(2));
        assert!(bursts.is_empty(), "no cluster reaches the threshold");
    }

    // ── End-to-end seam: fetch_events → StoredEvent → evaluator ──────────────

    #[test]
    fn stored_events_drive_the_ordered_evaluator() {
        use issen_correlation::evaluator::{evaluate, RuleSpec, ScopeRule};

        let mut success = logon_failure(2_000, "203.0.113.5");
        success.event_type = EventType::LogonSuccess;
        let store = store_with(&[logon_failure(1_000, "203.0.113.5"), success]);

        let anchors = store
            .fetch_events(&EventQuery::within(0, 10_000).event_types(["LogonFailure"]))
            .expect("anchors");
        let consequents = store
            .fetch_events(&EventQuery::within(0, 10_000).event_types(["LogonSuccess"]))
            .expect("consequents");

        let rule = RuleSpec {
            code: "CORR-BRUTEFORCE-LOGON",
            attack_technique: Some("T1110"),
            severity: forensicnomicon::report::Severity::High,
            anchor_event_type: "LogonFailure",
            consequent_event_type: "LogonSuccess",
            window_ns: 60_000_000_000,
            scope: ScopeRule::SameHost,
            guard: None,
            ordered: true,
            note:
                "Failed-logon burst then success from the same IP is consistent with brute force.",
        };

        let corr = evaluate(&rule, &anchors[0], &consequents).expect("a correlation");
        assert_eq!(corr.code, "CORR-BRUTEFORCE-LOGON");
        assert_eq!(corr.members.len(), 2);
        assert_eq!(corr.members[0].timeline_id, anchors[0].id);
        assert_eq!(corr.members[1].timeline_id, consequents[0].id);

        // And it persists + reads back through the timeline store.
        let id = store
            .persist_correlation(
                &corr,
                &[
                    (corr.members[0].timeline_id, corr.members[0].role.as_str()),
                    (corr.members[1].timeline_id, corr.members[1].role.as_str()),
                ],
            )
            .expect("persist");
        let back = store.correlation(id).expect("read").expect("present");
        assert_eq!(back.code, "CORR-BRUTEFORCE-LOGON");
        assert_eq!(back.members.len(), 2);
    }

    #[test]
    fn stored_event_source_leg_maps_eventlog_to_evtx() {
        use issen_correlation::evaluator::{EventSource, EventView};
        let store = store_with(&[logon_failure(1_000, "203.0.113.5")]);
        let events = store
            .fetch_events(&EventQuery::within(0, 5_000))
            .expect("fetch");
        assert_eq!(events[0].source(), EventSource::Evtx);
    }

    #[test]
    fn stored_event_exposes_real_artifact_path_via_eventview() {
        // The guarded rules (LOGON-MALWARE-WRITE, EXFIL-STAGE) read a candidate's
        // path at runtime via the EventView trait — it must return the real
        // persisted path, not the `""` trait default.
        use issen_correlation::evaluator::EventView;
        let store = store_with(&[logon_failure(1_000, "203.0.113.5")]);
        let events = store
            .fetch_events(&EventQuery::within(0, 5_000))
            .expect("fetch");
        assert_eq!(EventView::artifact_path(&events[0]), "Security.evtx");
    }

    #[test]
    fn burst_windows_separates_distinct_event_types() {
        // Same timestamps but different event types must not merge into a burst.
        let mut a = logon_failure(1_000_000_000, "203.0.113.5");
        a.event_type = EventType::LogonFailure;
        let mut b = logon_failure(1_050_000_000, "203.0.113.5");
        b.event_type = EventType::LogonSuccess;
        let mut c = logon_failure(1_100_000_000, "203.0.113.5");
        c.event_type = EventType::LogonFailure;
        let store = store_with(&[a, b, c]);
        let q = EventQuery::within(0, 5_000_000_000);
        let events = store.fetch_events(&q).expect("fetch");
        // Only two LogonFailure events → below threshold 3.
        let bursts = burst_windows(&events, 3, Duration::from_secs(2));
        assert!(bursts.is_empty());
    }
}
