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

    /// Insert a batch of events. Skips events whose record_hash already exists.
    ///
    /// Returns the number of events actually inserted (after dedup).
    pub fn inseissen_batch(&self, events: &[TimelineEvent]) -> Result<u64, TimelineStoreError> {
        let mut inserted = 0u64;
        for event in events {
            if !self.hash_exists(&event.record_hash)? {
                self.inseissen_event(event)?;
                inserted += 1;
            }
        }
        Ok(inserted)
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
}
