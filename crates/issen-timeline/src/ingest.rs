use issen_core::timeline::event::TimelineEvent;
use sha2::{Digest, Sha256};

use crate::store::{TimelineStore, TimelineStoreError};

/// A resumable ingestion unit: one `(evidence, artifact-type, parser)` parse
/// whose events and completion marker commit atomically (issen #115).
///
/// The `unit_id` is the durable identity a resume keys on — to delete a
/// half-written unit's rows and re-parse it from scratch — so it must be
/// derived from the parse's structural coordinates (evidence key + artifact
/// path + parser), never from a counter that shifts between runs.
#[derive(Debug, Clone)]
pub struct IngestUnit {
    pub unit_id: String,
    pub evidence_key: String,
    pub artifact_type: String,
    pub parser: String,
    pub bytes: i64,
}

impl IngestUnit {
    /// Derive the durable `unit_id` from a parse's structural coordinates.
    ///
    /// SHA-256 hex (matching the fleet `record_hash` convention) over the four
    /// coordinates, each **NUL-separated** so the encoding is injective: a byte
    /// shifted across a field boundary cannot alias two distinct artifacts onto
    /// one id — which would make a resume's delete-first target the wrong unit's
    /// rows. NUL is not a valid path or identifier byte, so it is a safe domain
    /// separator.
    #[must_use]
    pub fn stable_id(
        evidence_key: &str,
        artifact_type: &str,
        artifact_path: &str,
        parser: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(evidence_key.as_bytes());
        hasher.update([0u8]);
        hasher.update(artifact_type.as_bytes());
        hasher.update([0u8]);
        hasher.update(artifact_path.as_bytes());
        hasher.update([0u8]);
        hasher.update(parser.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Construct a unit with its `unit_id` derived from the coordinates.
    ///
    /// The secure-by-default surface: the id is *always* derived via
    /// [`Self::stable_id`], so it can never be hand-set inconsistently with the
    /// coordinates a resume will recompute from.
    #[must_use]
    pub fn new(
        evidence_key: &str,
        artifact_type: &str,
        artifact_path: &str,
        parser: &str,
        bytes: i64,
    ) -> Self {
        Self {
            unit_id: Self::stable_id(evidence_key, artifact_type, artifact_path, parser),
            evidence_key: evidence_key.to_string(),
            artifact_type: artifact_type.to_string(),
            parser: parser.to_string(),
            bytes,
        }
    }
}

/// The resume decision (issen #115 step 6): which discovered units still need
/// parsing.
///
/// Returns the complement of `completed` — units whose `unit_id` is not yet
/// recorded `complete` — or, when `refresh` is set, *every* unit, so a
/// `--refresh` run re-parses from scratch. [`TimelineStore::commit_unit`]'s
/// delete-first then makes the re-parse idempotent. The interrupted unit of a
/// crashed run is absent from `completed` (its atomic commit rolled back), so it
/// is naturally included.
#[must_use]
pub fn units_to_ingest<'a, S: std::hash::BuildHasher>(
    discovered: &'a [IngestUnit],
    completed: &std::collections::HashSet<String, S>,
    refresh: bool,
) -> Vec<&'a IngestUnit> {
    discovered
        .iter()
        .filter(|u| refresh || !completed.contains(&u.unit_id))
        .collect()
}

/// An exclusive advisory lock for a case, so two concurrent ingests can't
/// corrupt the resumable-ingestion state (issen #115 step 5).
///
/// Backed by an `<case>.ingest.lock` file created atomically with `create_new`
/// (O_EXCL); the file is removed when the guard drops (RAII). This is advisory
/// and complements DuckDB's own single-writer file lock — it guards the whole
/// ingest *session*, not just open DB handles.
#[derive(Debug)]
pub struct CaseLock {
    path: std::path::PathBuf,
}

impl CaseLock {
    /// Acquire the ingest lock for `case_db`. Fails with
    /// [`TimelineStoreError::Locked`] if another holder already exists.
    pub fn acquire(case_db: &std::path::Path) -> Result<Self, TimelineStoreError> {
        let path = Self::lock_path(case_db);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write;
                // Best-effort holder hint; the lock's existence is what matters.
                let _ = writeln!(f, "{}", std::process::id());
                Ok(Self { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(TimelineStoreError::Locked(path.display().to_string()))
            }
            Err(e) => Err(TimelineStoreError::Locked(format!(
                "{}: {e}",
                path.display()
            ))),
        }
    }

    fn lock_path(case_db: &std::path::Path) -> std::path::PathBuf {
        let mut s = case_db.as_os_str().to_owned();
        s.push(".ingest.lock");
        std::path::PathBuf::from(s)
    }
}

impl Drop for CaseLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl TimelineStore {
    /// Insert a single event into the timeline.
    pub fn inseissen_event(&self, event: &TimelineEvent) -> Result<(), TimelineStoreError> {
        let metadata_json =
            serde_json::to_string(&event.metadata).unwrap_or_else(|_| "{}".to_string());
        let tags_json = serde_json::to_string(&event.tags).unwrap_or_else(|_| "[]".to_string());
        let entity_refs_json =
            serde_json::to_string(&event.entity_refs).unwrap_or_else(|_| "[]".to_string());

        self.connection().execute(
            "INSERT INTO timeline (
                timestamp_ns, timestamp_display, event_type, source,
                artifact_path, description, metadata, user_account,
                hostname, tags, record_hash, evidence_source, entity_refs
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![
                event.timestamp_ns,
                event.timestamp_display,
                format!("{:?}", event.event_type),
                format!("{:?}", event.source),
                event.artifact_path,
                event.description,
                metadata_json,
                event.user,
                event.hostname,
                tags_json,
                event.record_hash,
                event.evidence_source_id,
                entity_refs_json,
            ],
        )?;
        Ok(())
    }

    /// Insert a batch of events, deduplicating on `record_hash`.
    ///
    /// Wrapped in a single transaction with one prepared `INSERT … ON CONFLICT
    /// DO NOTHING` reused across the batch — no per-event `SELECT`, no per-row
    /// commit. Returns the number of events actually inserted (after dedup).
    pub fn inseissen_batch(&self, events: &[TimelineEvent]) -> Result<u64, TimelineStoreError> {
        self.insert_batch_at_epoch(events, "live")
    }

    /// Insert a batch of events tagged with a snapshot `epoch`, deduplicating on
    /// `record_hash` WITHIN that epoch. The same event observed at a *different*
    /// epoch is a distinct point in the temporal cohort and is kept — this is the
    /// two-level super-timeline (a cohort of per-snapshot timelines).
    pub fn insert_batch_at_epoch(
        &self,
        events: &[TimelineEvent],
        epoch: &str,
    ) -> Result<u64, TimelineStoreError> {
        if events.is_empty() {
            return Ok(0);
        }
        let conn = self.connection();
        // Stage the batch in a temp table via DuckDB's columnar Appender (the
        // fast bulk path), then dedup-insert in ONE set-based statement: within
        // the batch via row_number(), against existing rows via an anti-join on
        // record_hash. No per-event SELECT, no per-row index maintenance.
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS _ingest_stage (
                timestamp_ns BIGINT, timestamp_display VARCHAR, event_type VARCHAR,
                source VARCHAR, artifact_path VARCHAR, description VARCHAR,
                metadata VARCHAR, user_account VARCHAR, hostname VARCHAR,
                tags VARCHAR, record_hash VARCHAR, evidence_source VARCHAR,
                entity_refs VARCHAR
            );
            DELETE FROM _ingest_stage;",
        )?;
        {
            let mut appender = conn.appender("_ingest_stage")?;
            for event in events {
                let metadata_json =
                    serde_json::to_string(&event.metadata).unwrap_or_else(|_| "{}".to_string());
                let tags_json =
                    serde_json::to_string(&event.tags).unwrap_or_else(|_| "[]".to_string());
                let entity_refs_json =
                    serde_json::to_string(&event.entity_refs).unwrap_or_else(|_| "[]".to_string());
                appender.append_row(duckdb::params![
                    event.timestamp_ns,
                    event.timestamp_display,
                    format!("{:?}", event.event_type),
                    format!("{:?}", event.source),
                    event.artifact_path,
                    event.description,
                    metadata_json,
                    event.user,
                    event.hostname,
                    tags_json,
                    event.record_hash,
                    event.evidence_source_id,
                    entity_refs_json,
                ])?;
            }
            appender.flush()?;
        }
        let inserted = conn.execute(
            "INSERT INTO timeline (
                timestamp_ns, timestamp_display, event_type, source,
                artifact_path, description, metadata, user_account,
                hostname, tags, record_hash, evidence_source, entity_refs, epoch
            )
            SELECT timestamp_ns, timestamp_display, event_type, source,
                artifact_path, description, metadata, user_account,
                hostname, tags, record_hash, evidence_source, entity_refs, ?
            FROM (
                SELECT *, row_number() OVER (PARTITION BY record_hash) AS _rn
                FROM _ingest_stage
            ) q
            WHERE q._rn = 1
              AND q.record_hash NOT IN (SELECT record_hash FROM timeline WHERE epoch = ?)",
            duckdb::params![epoch, epoch],
        )?;
        conn.execute_batch("DELETE FROM _ingest_stage;")?;
        Ok(inserted as u64)
    }

    /// Update the tags column for events that have been enriched.
    ///
    /// Matches on `record_hash` and overwrites the tags JSON array.
    /// Returns the number of rows updated.
    pub fn update_tags(&self, events: &[TimelineEvent]) -> Result<u64, TimelineStoreError> {
        let mut updated = 0u64;
        let mut stmt = self
            .connection()
            .prepare("UPDATE timeline SET tags = ? WHERE record_hash = ?")?;
        for event in events {
            if event.tags.is_empty() {
                continue;
            }
            let tags_json = serde_json::to_string(&event.tags).unwrap_or_else(|_| "[]".to_string());
            let rows = stmt.execute(duckdb::params![tags_json, event.record_hash])?;
            updated += rows as u64;
        }
        Ok(updated)
    }

    /// Insert a batch tagged by a forensicnomicon `[H]` ordering key — the native
    /// `[H]`-aware ingest path (#43).
    ///
    /// The epoch label is derived from `lsn` via
    /// [`crate::epoch::epoch_label_for`], so a WAL commit's epoch is its salt-qualified
    /// position: a checkpoint reset (salt roll) yields a distinct epoch and never dedups
    /// against the prior generation. Thin wrapper over [`Self::insert_batch_at_epoch`].
    pub fn insert_batch_at_lsn(
        &self,
        events: &[TimelineEvent],
        lsn: &forensicnomicon::history::epoch::LsnKind,
    ) -> Result<u64, TimelineStoreError> {
        self.insert_batch_at_epoch(events, &crate::epoch::epoch_label_for(lsn))
    }

    /// Register an evidence source for chain-of-custody tracking.
    pub fn register_evidence_source(
        &self,
        source_id: &str,
        file_path: &str,
        sha256_hash: Option<&str>,
        file_size: Option<i64>,
    ) -> Result<(), TimelineStoreError> {
        // DuckDB uses INSERT OR REPLACE syntax.
        self.connection().execute(
            "INSERT OR REPLACE INTO evidence_sources (source_id, file_path, sha256_hash, file_size)
             VALUES (?, ?, ?, ?)",
            duckdb::params![source_id, file_path, sha256_hash, file_size],
        )?;
        Ok(())
    }

    /// Commit a unit's events and its `complete` marker in ONE transaction
    /// (issen #115 step 2.2).
    ///
    /// Resume-safe by construction: a crash mid-parse rolls the transaction
    /// back, leaving NO committed rows for the unit, so "events flushed" and
    /// "unit complete" can never disagree across a restart. Re-committing the
    /// same `unit_id` deletes its prior rows first, so a deterministic re-parse
    /// is idempotent (no duplication). Returns the number of events written.
    pub fn commit_unit(
        &self,
        unit: &IngestUnit,
        events: &[TimelineEvent],
    ) -> Result<u64, TimelineStoreError> {
        let conn = self.connection();
        conn.execute_batch("BEGIN TRANSACTION;")?;
        match self.commit_unit_body(unit, events) {
            Ok(n) => {
                conn.execute_batch("COMMIT;")?;
                Ok(n)
            }
            Err(e) => {
                // Best-effort rollback; surface the original error regardless.
                let _ = conn.execute_batch("ROLLBACK;");
                Err(e)
            }
        }
    }

    /// The set of `unit_id`s already flushed to completion for an evidence
    /// source — the resume skip-list (issen #115 step 4).
    ///
    /// A restart parses the *complement* of this set: any unit not listed here
    /// (including the one interrupted mid-parse, whose atomic [`Self::commit_unit`]
    /// rolled back and left no `complete` row) is re-parsed, and commit_unit's
    /// delete-first clears any partial rows before re-inserting.
    pub fn completed_units(
        &self,
        evidence_key: &str,
    ) -> Result<std::collections::HashSet<String>, TimelineStoreError> {
        let conn = self.connection();
        let mut stmt = conn.prepare(
            "SELECT unit_id FROM ingest_log WHERE evidence_key = ? AND status = 'complete'",
        )?;
        let rows = stmt.query_map([evidence_key], |row| row.get::<_, String>(0))?;
        let mut out = std::collections::HashSet::new();
        for row in rows {
            out.insert(row?);
        }
        Ok(out)
    }

    /// The mutating body of [`Self::commit_unit`], run inside the caller's
    /// transaction so any error aborts the whole unit.
    fn commit_unit_body(
        &self,
        unit: &IngestUnit,
        events: &[TimelineEvent],
    ) -> Result<u64, TimelineStoreError> {
        let conn = self.connection();
        // Delete-first: a resume re-parses a unit from scratch, so drop any rows
        // a prior partial attempt left tagged with this unit id.
        conn.execute(
            "DELETE FROM timeline WHERE ingest_unit_id = ?",
            duckdb::params![unit.unit_id],
        )?;
        {
            let mut stmt = conn.prepare(
                "INSERT INTO timeline (
                    timestamp_ns, timestamp_display, event_type, source,
                    artifact_path, description, metadata, user_account,
                    hostname, tags, record_hash, evidence_source, entity_refs,
                    ingest_unit_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )?;
            for event in events {
                let metadata_json =
                    serde_json::to_string(&event.metadata).unwrap_or_else(|_| "{}".to_string());
                let tags_json =
                    serde_json::to_string(&event.tags).unwrap_or_else(|_| "[]".to_string());
                let entity_refs_json =
                    serde_json::to_string(&event.entity_refs).unwrap_or_else(|_| "[]".to_string());
                stmt.execute(duckdb::params![
                    event.timestamp_ns,
                    event.timestamp_display,
                    format!("{:?}", event.event_type),
                    format!("{:?}", event.source),
                    event.artifact_path,
                    event.description,
                    metadata_json,
                    event.user,
                    event.hostname,
                    tags_json,
                    event.record_hash,
                    event.evidence_source_id,
                    entity_refs_json,
                    unit.unit_id,
                ])?;
            }
        }
        let count = events.len() as u64;
        // The completion marker lands in the SAME transaction as the events.
        conn.execute(
            "INSERT OR REPLACE INTO ingest_log (
                unit_id, evidence_key, artifact_type, parser, bytes,
                event_count, status, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'complete', current_timestamp)",
            duckdb::params![
                unit.unit_id,
                unit.evidence_key,
                unit.artifact_type,
                unit.parser,
                unit.bytes,
                count as i64,
            ],
        )?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};

    use super::{units_to_ingest, CaseLock, IngestUnit};
    use crate::store::TimelineStore;

    fn sample_event(ts: i64, desc: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2023-11-14T22:13:20.{ts:09}Z"),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            "C:/Users/analyst/report.docx".to_string(),
            desc.to_string(),
            "evidence-001".to_string(),
        )
    }

    #[test]
    fn test_inseissen_single_event() {
        let store = TimelineStore::in_memory().expect("store");
        let event = sample_event(1000, "File created");
        store.inseissen_event(&event).expect("insert");
        assert_eq!(store.event_count().expect("count"), 1);
    }

    #[test]
    fn test_inseissen_batch() {
        let store = TimelineStore::in_memory().expect("store");
        let events: Vec<TimelineEvent> = (0..10)
            .map(|i| sample_event(i * 1_000_000_000, &format!("Event {i}")))
            .collect();

        let inserted = store.inseissen_batch(&events).expect("batch");
        assert_eq!(inserted, 10);
        assert_eq!(store.event_count().expect("count"), 10);
    }

    #[test]
    fn commit_unit_writes_events_and_completion_idempotently() {
        // issen #115 step 2.2: a unit's events + its completion marker commit in
        // ONE transaction; re-committing the same unit deletes its prior rows
        // first (idempotent resume — no duplication).
        let store = TimelineStore::in_memory().expect("store");
        let unit = IngestUnit {
            unit_id: "CASE!/C/$MFT|mft".to_string(),
            evidence_key: "CASE".to_string(),
            artifact_type: "Mft".to_string(),
            parser: "MFT Parser".to_string(),
            bytes: 1024,
        };
        let events = vec![sample_event(100, "a"), sample_event(200, "b")];

        let n = store.commit_unit(&unit, &events).expect("commit");
        assert_eq!(n, 2);

        let conn = store.connection();
        let tagged: i64 = conn
            .prepare("SELECT count(*) FROM timeline WHERE ingest_unit_id = ?")
            .expect("prep")
            .query_row([&unit.unit_id], |r| r.get(0))
            .expect("q");
        assert_eq!(tagged, 2, "events tagged with the unit id");

        let status: String = conn
            .prepare("SELECT status FROM ingest_log WHERE unit_id = ?")
            .expect("prep")
            .query_row([&unit.unit_id], |r| r.get(0))
            .expect("q");
        assert_eq!(status, "complete", "completion marker written");

        // Idempotent re-commit: delete-first means no duplication.
        let n2 = store.commit_unit(&unit, &events).expect("recommit");
        assert_eq!(n2, 2);
        let total: i64 = conn
            .prepare("SELECT count(*) FROM timeline WHERE ingest_unit_id = ?")
            .expect("prep")
            .query_row([&unit.unit_id], |r| r.get(0))
            .expect("q");
        assert_eq!(total, 2, "re-commit must not duplicate the unit's rows");
    }

    #[test]
    fn completed_units_returns_only_flushed_units_scoped_to_evidence() {
        // issen #115 step 4 — the resume query. `completed_units` is the set a
        // restart skips; everything else (including the interrupted unit, whose
        // atomic commit_unit rolled back leaving no log row) is re-parsed. So a
        // resume = "parse the complement of completed", and commit_unit's
        // delete-first then cleans any partial rows of the re-parsed unit.
        let store = TimelineStore::in_memory().expect("store");
        let u1 = IngestUnit::new("CASE", "Mft", "/C/$MFT", "MFT Parser", 10);
        let u2 = IngestUnit::new("CASE", "UsnJournal", "/C/$J", "USN Parser", 20);
        store.commit_unit(&u1, &[sample_event(1, "a")]).expect("c1");
        store.commit_unit(&u2, &[sample_event(2, "b")]).expect("c2");

        // A unit from a DIFFERENT evidence must not leak into CASE's resume set.
        let other = IngestUnit::new("CASE2", "Mft", "/C/$MFT", "MFT Parser", 10);
        store
            .commit_unit(&other, &[sample_event(3, "c")])
            .expect("c3");

        let done = store.completed_units("CASE").expect("query");
        assert!(done.contains(&u1.unit_id), "u1 flushed");
        assert!(done.contains(&u2.unit_id), "u2 flushed");
        assert!(
            !done.contains(&other.unit_id),
            "scoped to evidence_key — CASE2 excluded"
        );
        assert_eq!(done.len(), 2);

        // A never-committed unit is simply absent → it will be (re)parsed.
        let pending = IngestUnit::new("CASE", "Prefetch", "/C/pf", "PF Parser", 5);
        assert!(!done.contains(&pending.unit_id));
    }

    #[test]
    fn units_to_ingest_skips_completed_unless_refresh() {
        // issen #115 step 6 (--refresh): the resume decision. Normally parse the
        // complement of `completed`; with refresh=true, re-parse everything.
        let u1 = IngestUnit::new("CASE", "Mft", "/C/$MFT", "MFT Parser", 1);
        let u2 = IngestUnit::new("CASE", "UsnJournal", "/C/$J", "USN Parser", 1);
        let u3 = IngestUnit::new("CASE", "Prefetch", "/C/pf", "PF Parser", 1);
        let units = vec![u1.clone(), u2.clone(), u3.clone()];
        let mut completed = std::collections::HashSet::new();
        completed.insert(u1.unit_id.clone());
        completed.insert(u2.unit_id.clone());

        let todo = units_to_ingest(&units, &completed, false);
        assert_eq!(
            todo.iter().map(|u| &u.unit_id).collect::<Vec<_>>(),
            vec![&u3.unit_id],
            "resume parses only the not-yet-completed unit"
        );

        let refreshed = units_to_ingest(&units, &completed, true);
        assert_eq!(refreshed.len(), 3, "--refresh re-parses everything");
    }

    #[test]
    fn case_lock_is_exclusive_and_releases() {
        // issen #115 step 5 (case-level lock): only one ingest at a time per case.
        let dir = tempfile::tempdir().expect("tmp");
        let case = dir.path().join("case.duckdb");
        let lock = CaseLock::acquire(&case).expect("first acquire");
        assert!(
            CaseLock::acquire(&case).is_err(),
            "a second acquire must fail while the lock is held"
        );
        drop(lock);
        let _again = CaseLock::acquire(&case).expect("re-acquire after release");
    }

    #[test]
    fn stable_id_is_deterministic_and_collision_resistant() {
        // issen #115 step 3: the unit_id MUST derive from the parse's structural
        // coordinates so a resume recomputes the SAME id (delete-first then
        // targets exactly the prior attempt's rows). Same coordinates -> same id;
        // any coordinate change -> a different id.
        let id = IngestUnit::stable_id("CASE", "Mft", "/C/$MFT", "MFT Parser");
        assert_eq!(
            id,
            IngestUnit::stable_id("CASE", "Mft", "/C/$MFT", "MFT Parser"),
            "deterministic across runs"
        );
        assert_eq!(id.len(), 64, "SHA-256 hex, matching record_hash convention");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

        // Every coordinate participates — vary any one and the id changes.
        assert_ne!(
            id,
            IngestUnit::stable_id("CASE2", "Mft", "/C/$MFT", "MFT Parser")
        );
        assert_ne!(
            id,
            IngestUnit::stable_id("CASE", "UsnJournal", "/C/$MFT", "MFT Parser")
        );
        assert_ne!(
            id,
            IngestUnit::stable_id("CASE", "Mft", "/D/$MFT", "MFT Parser")
        );
        assert_ne!(id, IngestUnit::stable_id("CASE", "Mft", "/C/$MFT", "Other"));

        // No delimiter-collision: shifting a byte across a field boundary must
        // NOT alias (this fails under naive concatenation, passes with NUL-sep).
        assert_ne!(
            IngestUnit::stable_id("a", "b", "c", "d"),
            IngestUnit::stable_id("a", "b", "cd", ""),
        );
    }

    #[test]
    fn new_derives_unit_id_from_coordinates() {
        // The constructor is the secure-by-default surface: the id is ALWAYS
        // derived, never hand-set inconsistently with the coordinates.
        let unit = IngestUnit::new("CASE", "Mft", "/C/$MFT", "MFT Parser", 1024);
        assert_eq!(
            unit.unit_id,
            IngestUnit::stable_id("CASE", "Mft", "/C/$MFT", "MFT Parser")
        );
        assert_eq!(unit.evidence_key, "CASE");
        assert_eq!(unit.artifact_type, "Mft");
        assert_eq!(unit.parser, "MFT Parser");
        assert_eq!(unit.bytes, 1024);
    }

    #[test]
    fn test_dedup_on_record_hash() {
        let store = TimelineStore::in_memory().expect("store");
        let event = sample_event(1000, "Duplicate event");

        store.inseissen_event(&event).expect("first insert");
        assert_eq!(store.event_count().expect("count"), 1);

        // inseissen_batch should skip the duplicate.
        let inserted = store.inseissen_batch(&[event]).expect("batch");
        assert_eq!(inserted, 0, "Duplicate should be skipped");
        assert_eq!(store.event_count().expect("count"), 1);
    }

    #[test]
    fn test_hash_exists_after_insert() {
        let store = TimelineStore::in_memory().expect("store");
        let event = sample_event(1000, "Test hash");

        assert!(!store.hash_exists(&event.record_hash).expect("check"));
        store.inseissen_event(&event).expect("insert");
        assert!(store.hash_exists(&event.record_hash).expect("check"));
    }

    #[test]
    fn test_inseissen_event_with_metadata_and_tags() {
        let store = TimelineStore::in_memory().expect("store");
        let event = sample_event(1000, "Rich event")
            .with_user("S-1-5-21-123-1001")
            .with_hostname("WORKSTATION01")
            .with_tag("suspicious")
            .with_metadata("reason", serde_json::json!("FILE_CREATE"));

        store.inseissen_event(&event).expect("insert");
        assert_eq!(store.event_count().expect("count"), 1);
    }

    #[test]
    fn test_update_tags_enriches_existing_events() {
        let store = TimelineStore::in_memory().expect("store");
        let event = sample_event(1000, "File created");
        store.inseissen_event(&event).expect("insert");

        // Enrich the event with sig: tags.
        let mut enriched = event.clone();
        enriched.tags.push("sig:YARA:detect_malware".to_string());
        enriched.tags.push("sig:Sigma:suspicious_file".to_string());

        let updated = store.update_tags(&[enriched]).expect("update_tags");
        assert_eq!(updated, 1);

        // Verify tags were written.
        let mut stmt = store
            .connection()
            .prepare("SELECT tags FROM timeline WHERE record_hash = ?")
            .expect("prepare");
        let tags_json: String = stmt
            .query_row([&event.record_hash], |row| row.get(0))
            .expect("query");
        assert!(tags_json.contains("sig:YARA:detect_malware"));
        assert!(tags_json.contains("sig:Sigma:suspicious_file"));
    }

    #[test]
    fn test_update_tags_skips_empty_tags() {
        let store = TimelineStore::in_memory().expect("store");
        let event = sample_event(1000, "File created");
        store.inseissen_event(&event).expect("insert");

        // Event with no tags — should be skipped.
        let updated = store.update_tags(&[event]).expect("update_tags");
        assert_eq!(updated, 0);
    }

    #[test]
    fn test_register_evidence_source() {
        let store = TimelineStore::in_memory().expect("store");
        store
            .register_evidence_source(
                "evidence-001",
                "/evidence/case42/kape-output",
                Some("abcdef1234567890"),
                Some(1_073_741_824),
            )
            .expect("register");

        // Verify it was stored.
        let mut stmt = store
            .connection()
            .prepare("SELECT source_id FROM evidence_sources WHERE source_id = ?")
            .expect("prepare");
        let exists = stmt.exists(["evidence-001"]).expect("check");
        assert!(exists);
    }

    #[test]
    fn test_insert_batch_of_50k_completes_promptly() {
        // Regression (A0): the original `insert_batch` did a per-event
        // `hash_exists` SELECT + single auto-committed `insert_event` — ~2
        // round-trips per event with no transaction. On Case 001 DC01 (369K
        // events) that never finished. A batched, transaction-wrapped insert
        // must ingest 50K events well under a generous bound and still dedup.
        let store = TimelineStore::in_memory().expect("store");
        let events: Vec<TimelineEvent> = (0..50_000)
            .map(|i| sample_event(i64::from(i) * 1_000, &format!("Event {i}")))
            .collect();

        let started = std::time::Instant::now();
        let inserted = store.inseissen_batch(&events).expect("batch");
        let elapsed = started.elapsed();

        assert_eq!(inserted, 50_000);
        assert_eq!(store.event_count().expect("count"), 50_000);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "50K-event insert_batch took {elapsed:?}; expected < 5s (batched insert)"
        );

        // Re-inserting the identical batch must dedup to zero new rows.
        let again = store.inseissen_batch(&events).expect("batch 2");
        assert_eq!(again, 0, "duplicate batch must be fully deduped");
        assert_eq!(store.event_count().expect("count"), 50_000);
    }

    #[test]
    fn test_epoch_dimension_super_timeline() {
        // P0b: the super-timeline tags each snapshot's timeline with its epoch.
        // The SAME events ingested at two different snapshot epochs must coexist
        // (they are distinct points in the cohort), but dedup WITHIN an epoch.
        let store = TimelineStore::in_memory().expect("store");
        let events: Vec<TimelineEvent> = (0..5)
            .map(|i| sample_event(i64::from(i) * 1_000, &format!("E{i}")))
            .collect();

        let a = store.insert_batch_at_epoch(&events, "snap-T1").expect("T1");
        let b = store.insert_batch_at_epoch(&events, "snap-T2").expect("T2");
        assert_eq!(a, 5);
        assert_eq!(
            b, 5,
            "identical events at a different epoch are NOT deduped"
        );
        assert_eq!(store.event_count().expect("count"), 10);

        // Point-in-time view: each epoch sees only its own snapshot's timeline.
        assert_eq!(store.event_count_at_epoch("snap-T1").expect("c"), 5);
        assert_eq!(store.event_count_at_epoch("snap-T2").expect("c"), 5);

        // Re-ingesting the same epoch dedups (within-epoch idempotence).
        let again = store.insert_batch_at_epoch(&events, "snap-T1").expect("re");
        assert_eq!(again, 0, "identical events at the same epoch dedup");
        assert_eq!(store.event_count().expect("count"), 10);

        // The cohort's distinct epochs are enumerable.
        let mut epochs = store.epochs().expect("epochs");
        epochs.sort();
        assert_eq!(epochs, vec!["snap-T1".to_string(), "snap-T2".to_string()]);

        // The plain inseissen_batch path tags events with the default "live" epoch.
        let live: Vec<TimelineEvent> = vec![sample_event(9_000, "live-event")];
        store.inseissen_batch(&live).expect("live");
        assert_eq!(store.event_count_at_epoch("live").expect("live-count"), 1);
    }

    #[test]
    fn insert_batch_at_lsn_tags_by_salt_qualified_wal_epoch() {
        use crate::epoch::epoch_label_for;
        use forensicnomicon::history::epoch::LsnKind;

        let store = TimelineStore::in_memory().expect("store");
        let events: Vec<TimelineEvent> = (0..3)
            .map(|i| sample_event(i64::from(i) * 1_000, &format!("E{i}")))
            .collect();

        let gen1 = LsnKind::SqliteWalFrame {
            salt1: 0x1111_1111,
            salt2: 0x2222_2222,
            frame_seq: 0,
            commit_seq: 0,
        };
        // A checkpoint reset rolls the salts: same commit position, NEW generation.
        let gen2 = LsnKind::SqliteWalFrame {
            salt1: 0x1111_1112,
            salt2: 0x9999_9999,
            frame_seq: 0,
            commit_seq: 0,
        };

        let a = store.insert_batch_at_lsn(&events, &gen1).expect("gen1");
        let b = store.insert_batch_at_lsn(&events, &gen2).expect("gen2");
        assert_eq!(a, 3);
        assert_eq!(b, 3, "a checkpoint reset is a distinct epoch — not deduped");
        assert_eq!(store.event_count().expect("count"), 6);

        // The stored epochs are exactly the salt-qualified labels for the two keys.
        let mut epochs = store.epochs().expect("epochs");
        epochs.sort();
        let mut expected = vec![epoch_label_for(&gen1), epoch_label_for(&gen2)];
        expected.sort();
        assert_eq!(epochs, expected);
    }

    #[test]
    fn entity_refs_persist_through_the_batch_path() {
        // PRE-4: correlation rules join events on shared entities (process, IP,
        // file, user, session). The in-memory event carries `entity_refs`; the
        // store must persist them so `fetch_events` can read them back. The batch
        // path (the production ingest) is the one that must carry the column.
        use issen_core::timeline::event::EntityRef;
        let store = TimelineStore::in_memory().expect("store");
        let event = sample_event(1000, "malware process beacon")
            .with_entity_ref(EntityRef::Process("coreupdater.exe".to_string()))
            .with_entity_ref(EntityRef::Ip("203.78.103.109".to_string()));
        store
            .inseissen_batch(&[event.clone()])
            .expect("batch insert");

        let mut stmt = store
            .connection()
            .prepare("SELECT entity_refs FROM timeline WHERE record_hash = ?")
            .expect("prepare");
        let json: String = stmt
            .query_row([&event.record_hash], |row| row.get(0))
            .expect("query entity_refs");
        assert!(
            json.contains("coreupdater.exe"),
            "process ref persisted: {json}"
        );
        assert!(json.contains("203.78.103.109"), "ip ref persisted: {json}");
    }

    #[test]
    fn entity_refs_default_empty_when_absent() {
        // An event with no entity_refs persists an empty JSON array, never NULL
        // garbage — the column is always a valid array for downstream parsing.
        let store = TimelineStore::in_memory().expect("store");
        let event = sample_event(2000, "plain event");
        store
            .inseissen_batch(&[event.clone()])
            .expect("batch insert");
        let mut stmt = store
            .connection()
            .prepare("SELECT entity_refs FROM timeline WHERE record_hash = ?")
            .expect("prepare");
        let json: String = stmt
            .query_row([&event.record_hash], |row| row.get(0))
            .expect("query");
        assert_eq!(json, "[]");
    }
}
