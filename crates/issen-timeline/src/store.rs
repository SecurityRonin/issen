use duckdb::Connection;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TimelineStoreError {
    #[error("DuckDB error: {0}")]
    DuckDb(#[from] duckdb::Error),

    #[error("SQLite export error: {0}")]
    SqliteExport(String),

    #[error("Query error: {0}")]
    Query(String),
}

/// Manages the DuckDB connection and schema for a forensic timeline.
///
/// Each `TimelineStore` represents a single case database.
/// In-memory by default for analysis; file-backed for persistence.
pub struct TimelineStore {
    conn: Connection,
}

impl TimelineStore {
    /// Create a new in-memory timeline store (for analysis and testing).
    pub fn in_memory() -> Result<Self, TimelineStoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Open or create a file-backed timeline store.
    pub fn open(path: &std::path::Path) -> Result<Self, TimelineStoreError> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Access the underlying DuckDB connection (for advanced queries).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Initialize the timeline schema (idempotent).
    fn initialize_schema(&self) -> Result<(), TimelineStoreError> {
        self.conn.execute_batch(
            "
            CREATE SEQUENCE IF NOT EXISTS timeline_seq START 1;

            CREATE TABLE IF NOT EXISTS timeline (
                id              UBIGINT PRIMARY KEY DEFAULT nextval('timeline_seq'),
                timestamp_ns    BIGINT NOT NULL,
                timestamp_display VARCHAR NOT NULL,
                event_type      VARCHAR NOT NULL,
                source          VARCHAR NOT NULL,
                artifact_path   VARCHAR NOT NULL,
                description     VARCHAR NOT NULL,
                metadata        VARCHAR,
                user_account    VARCHAR,
                hostname        VARCHAR,
                tags            VARCHAR,
                record_hash     VARCHAR NOT NULL,
                evidence_source VARCHAR NOT NULL,
                ingested_at     TIMESTAMP DEFAULT current_timestamp
            );

            CREATE TABLE IF NOT EXISTS evidence_sources (
                source_id       VARCHAR PRIMARY KEY,
                file_path       VARCHAR NOT NULL,
                sha256_hash     VARCHAR,
                file_size       BIGINT,
                ingested_at     TIMESTAMP DEFAULT current_timestamp
            );
            ",
        )?;
        Ok(())
    }

    /// Get the total number of events in the timeline.
    pub fn event_count(&self) -> Result<u64, TimelineStoreError> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM timeline")?;
        let count: u64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    /// Check if a record hash already exists (for deduplication).
    pub fn hash_exists(&self, record_hash: &str) -> Result<bool, TimelineStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM timeline WHERE record_hash = ? LIMIT 1")?;
        let exists = stmt.exists([record_hash])?;
        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_in_memory_store() {
        let store = TimelineStore::in_memory().expect("create store");
        assert_eq!(store.event_count().expect("count"), 0);
    }

    #[test]
    fn test_create_file_backed_store() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("test.duckdb");
        let store = TimelineStore::open(&path).expect("create store");
        assert_eq!(store.event_count().expect("count"), 0);
        assert!(path.exists());
    }

    #[test]
    fn test_schema_is_idempotent() {
        let store = TimelineStore::in_memory().expect("create store");
        // Calling initialize_schema again should not fail.
        store.initialize_schema().expect("re-initialize");
        assert_eq!(store.event_count().expect("count"), 0);
    }

    #[test]
    fn test_hash_exists_empty_store() {
        let store = TimelineStore::in_memory().expect("create store");
        assert!(
            !store.hash_exists("abc123").expect("hash check"),
            "Empty store should have no hashes"
        );
    }
}
