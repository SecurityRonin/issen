use std::path::Path;

use crate::query::TimelineQuery;
use crate::store::{TimelineStore, TimelineStoreError};

impl TimelineStore {
    /// Export the timeline to a SQLite database for portable case sharing.
    ///
    /// The SQLite file includes the full timeline, evidence source metadata,
    /// and is suitable for legal hold, archival, and case exchange.
    pub fn export_sqlite(&self, output_path: &Path) -> Result<u64, TimelineStoreError> {
        let rows = self.query(&TimelineQuery::new())?;
        let row_count = rows.len() as u64;

        let sqlite_conn = rusqlite::Connection::open(output_path)
            .map_err(|e| TimelineStoreError::SqliteExport(format!("Failed to open SQLite: {e}")))?;

        sqlite_conn
            .execute_batch(
                "
            CREATE TABLE IF NOT EXISTS timeline (
                id              INTEGER PRIMARY KEY,
                timestamp_ns    INTEGER NOT NULL,
                timestamp_display TEXT NOT NULL,
                event_type      TEXT NOT NULL,
                source          TEXT NOT NULL,
                artifact_path   TEXT NOT NULL,
                description     TEXT NOT NULL,
                metadata        TEXT,
                user_account    TEXT,
                hostname        TEXT,
                record_hash     TEXT NOT NULL,
                evidence_source TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ts ON timeline(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_type ON timeline(event_type);
            CREATE INDEX IF NOT EXISTS idx_source ON timeline(source);
            ",
            )
            .map_err(|e| TimelineStoreError::SqliteExport(format!("Schema error: {e}")))?;

        let mut inseissen_stmt = sqlite_conn
            .prepare(
                "INSERT INTO timeline (
                id, timestamp_ns, timestamp_display, event_type, source,
                artifact_path, description, metadata, user_account,
                hostname, record_hash, evidence_source
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .map_err(|e| TimelineStoreError::SqliteExport(format!("Prepare error: {e}")))?;

        for row in &rows {
            inseissen_stmt
                .execute(rusqlite::params![
                    row.id,
                    row.timestamp_ns,
                    row.timestamp_display,
                    row.event_type,
                    row.source,
                    row.artifact_path,
                    row.description,
                    row.metadata,
                    row.user_account,
                    row.hostname,
                    row.record_hash,
                    row.evidence_source,
                ])
                .map_err(|e| TimelineStoreError::SqliteExport(format!("Insert error: {e}")))?;
        }

        Ok(row_count)
    }
}

#[cfg(test)]
mod tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};

    use crate::store::TimelineStore;

    fn sample_events() -> Vec<TimelineEvent> {
        (0..5)
            .map(|i| {
                TimelineEvent::new(
                    (i + 1) * 1_000_000_000,
                    format!("2023-01-01T00:00:0{}Z", i + 1),
                    EventType::FileCreate,
                    ArtifactType::UsnJournal,
                    format!("C:/file{i}.txt"),
                    format!("Event {i}"),
                    "ev-001".to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn test_export_sqlite_creates_file() {
        let store = TimelineStore::in_memory().expect("store");
        for event in &sample_events() {
            store.inseissen_event(event).expect("insert");
        }

        let dir = tempfile::tempdir().expect("tmpdir");
        let sqlite_path = dir.path().join("export.sqlite");

        let exported = store.export_sqlite(&sqlite_path).expect("export");
        assert_eq!(exported, 5);
        assert!(sqlite_path.exists());
    }

    #[test]
    fn test_export_sqlite_roundtrip() {
        let store = TimelineStore::in_memory().expect("store");
        for event in &sample_events() {
            store.inseissen_event(event).expect("insert");
        }

        let dir = tempfile::tempdir().expect("tmpdir");
        let sqlite_path = dir.path().join("roundtrip.sqlite");
        store.export_sqlite(&sqlite_path).expect("export");

        // Verify SQLite contents.
        let sqlite_conn = rusqlite::Connection::open(&sqlite_path).expect("open sqlite");
        let count: i64 = sqlite_conn
            .query_row("SELECT COUNT(*) FROM timeline", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 5);

        // Verify ordering preserved.
        let first_ts: i64 = sqlite_conn
            .query_row(
                "SELECT timestamp_ns FROM timeline ORDER BY timestamp_ns ASC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("first");
        assert_eq!(first_ts, 1_000_000_000);
    }

    #[test]
    fn test_export_empty_timeline() {
        let store = TimelineStore::in_memory().expect("store");
        let dir = tempfile::tempdir().expect("tmpdir");
        let sqlite_path = dir.path().join("empty.sqlite");

        let exported = store.export_sqlite(&sqlite_path).expect("export");
        assert_eq!(exported, 0);
        assert!(sqlite_path.exists());
    }
}
