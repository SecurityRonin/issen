use issen_core::timeline::event::TimelineEvent;

use crate::store::{TimelineStore, TimelineStoreError};

impl TimelineStore {
    /// Insert a single event into the timeline.
    pub fn inseissen_event(&self, event: &TimelineEvent) -> Result<(), TimelineStoreError> {
        let metadata_json =
            serde_json::to_string(&event.metadata).unwrap_or_else(|_| "{}".to_string());
        let tags_json = serde_json::to_string(&event.tags).unwrap_or_else(|_| "[]".to_string());

        self.connection().execute(
            "INSERT INTO timeline (
                timestamp_ns, timestamp_display, event_type, source,
                artifact_path, description, metadata, user_account,
                hostname, tags, record_hash, evidence_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                tags VARCHAR, record_hash VARCHAR, evidence_source VARCHAR
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
                ])?;
            }
            appender.flush()?;
        }
        let inserted = conn.execute(
            "INSERT INTO timeline (
                timestamp_ns, timestamp_display, event_type, source,
                artifact_path, description, metadata, user_account,
                hostname, tags, record_hash, evidence_source, epoch
            )
            SELECT timestamp_ns, timestamp_display, event_type, source,
                artifact_path, description, metadata, user_account,
                hostname, tags, record_hash, evidence_source, ?
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
}

#[cfg(test)]
mod tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};

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
        assert_eq!(b, 5, "identical events at a different epoch are NOT deduped");
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
}
