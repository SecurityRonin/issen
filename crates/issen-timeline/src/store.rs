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

    #[error("case is locked by another ingest: {0}")]
    Locked(String),
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

    /// Re-run the idempotent schema initialization (as on re-opening an existing
    /// case DB). Exposed for callers that need to ensure the correlation tables
    /// exist on a store that predates them.
    pub fn initialize_schema_public(&self) -> Result<(), TimelineStoreError> {
        self.initialize_schema()
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
                entity_refs     VARCHAR NOT NULL DEFAULT '[]',
                activity_category VARCHAR,
                epoch           VARCHAR NOT NULL DEFAULT 'live',
                ingested_at     TIMESTAMP DEFAULT current_timestamp
            );

            -- Backfill for timelines created before PRE-4 (additive migration;
            -- existing rows get the '[]' default, new ingests populate it).
            ALTER TABLE timeline ADD COLUMN IF NOT EXISTS entity_refs VARCHAR DEFAULT '[]';
            -- CADET activity category (kebab code, NULL = untagged); additive.
            ALTER TABLE timeline ADD COLUMN IF NOT EXISTS activity_category VARCHAR;

            CREATE TABLE IF NOT EXISTS evidence_sources (
                source_id       VARCHAR PRIMARY KEY,
                file_path       VARCHAR NOT NULL,
                sha256_hash     VARCHAR,
                file_size       BIGINT,
                ingested_at     TIMESTAMP DEFAULT current_timestamp
            );

            -- Cross-artifact correlation findings produced by the ordered
            -- evaluator. One row per finding; members live in
            -- correlation_members keyed on timeline.id.
            CREATE SEQUENCE IF NOT EXISTS correlation_seq START 1;

            CREATE TABLE IF NOT EXISTS correlations (
                id               UBIGINT PRIMARY KEY DEFAULT nextval('correlation_seq'),
                code             VARCHAR NOT NULL,
                attack_technique VARCHAR,
                severity         VARCHAR NOT NULL,
                first_ts         BIGINT NOT NULL,
                last_ts          BIGINT NOT NULL,
                scope            VARCHAR NOT NULL,
                note             VARCHAR NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS correlation_members (
                correlation_id   UBIGINT NOT NULL,
                timeline_id      UBIGINT NOT NULL,
                role             VARCHAR NOT NULL
            );

            -- Additive safety for case DBs created before the correlation
            -- engine landed (mirrors the PRE-4 entity_refs backfill).
            ALTER TABLE correlations ADD COLUMN IF NOT EXISTS attack_technique VARCHAR;
            ALTER TABLE correlations ADD COLUMN IF NOT EXISTS note VARCHAR DEFAULT '';

            -- Resumable ingestion (issen #115): the durable per-unit completion
            -- log + the per-event provenance column. Completion is written here
            -- in the SAME transaction as a unit's events, so 'events flushed' and
            -- 'unit complete' can never disagree across a crash. Additive: case
            -- DBs predating this get NULL ingest_unit_id (legacy rows are
            -- immutable and not eligible for resume).
            CREATE TABLE IF NOT EXISTS ingest_log (
                unit_id        VARCHAR PRIMARY KEY,
                evidence_key   VARCHAR NOT NULL,
                artifact_type  VARCHAR NOT NULL,
                parser         VARCHAR NOT NULL,
                bytes          BIGINT,
                event_count    BIGINT,
                status         VARCHAR NOT NULL,
                started_at     TIMESTAMP,
                completed_at   TIMESTAMP
            );
            ALTER TABLE timeline ADD COLUMN IF NOT EXISTS ingest_unit_id VARCHAR;
            CREATE INDEX IF NOT EXISTS idx_ingest_log_evidence_status
                ON ingest_log (evidence_key, status);
            CREATE INDEX IF NOT EXISTS idx_timeline_ingest_unit
                ON timeline (ingest_unit_id);

            -- Unified front door (resumable pipeline): per-stage completion state
            -- so a re-run of `issen <evidence>` can plan which stages to re-run.
            -- One row per stage, upserted on each stage attempt/completion.
            CREATE TABLE IF NOT EXISTS pipeline_state (
                stage        VARCHAR PRIMARY KEY,
                status       VARCHAR NOT NULL,
                fingerprint  VARCHAR NOT NULL,
                updated_at   TIMESTAMP DEFAULT current_timestamp
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

    /// Number of events recorded at a given snapshot `epoch` (point-in-time view
    /// over the super-timeline).
    pub fn event_count_at_epoch(&self, epoch: &str) -> Result<u64, TimelineStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM timeline WHERE epoch = ?")?;
        let count: u64 = stmt.query_row([epoch], |row| row.get(0))?;
        Ok(count)
    }

    /// The distinct snapshot epochs present in the cohort.
    pub fn epochs(&self) -> Result<Vec<String>, TimelineStoreError> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT epoch FROM timeline")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Record (upsert, keyed on stage) the completion state of a pipeline stage
    /// so the resumable front door can plan the next run. STUB (RED).
    pub fn record_stage_state(
        &self,
        stage: &str,
        status: &str,
        fingerprint: &str,
    ) -> Result<(), TimelineStoreError> {
        // Upsert keyed on the PRIMARY KEY `stage`: DELETE+INSERT is robust across
        // DuckDB versions (avoids ON CONFLICT quirks) and the table has one row
        // per stage, so this is a point operation.
        self.conn.execute(
            "DELETE FROM pipeline_state WHERE stage = ?",
            duckdb::params![stage],
        )?;
        self.conn.execute(
            "INSERT INTO pipeline_state (stage, status, fingerprint, updated_at)
             VALUES (?, ?, ?, current_timestamp)",
            duckdb::params![stage, status, fingerprint],
        )?;
        Ok(())
    }

    /// Load all persisted pipeline stage-state rows.
    pub fn load_stage_states(&self) -> Result<Vec<StoredStageState>, TimelineStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT stage, status, fingerprint FROM pipeline_state")?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredStageState {
                stage: row.get(0)?,
                status: row.get(1)?,
                fingerprint: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

/// A persisted pipeline stage-state row (string-typed). The pipeline-layer enums
/// (`Stage`/`Status`) live in `issen-cli` and map to/from these strings, keeping
/// the timeline store ignorant of pipeline semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredStageState {
    pub stage: String,
    pub status: String,
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_state_roundtrips() {
        let store = TimelineStore::in_memory().expect("store");
        store
            .record_stage_state("ingest", "done", "e1")
            .expect("record");
        let states = store.load_stage_states().expect("load");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0],
            StoredStageState {
                stage: "ingest".into(),
                status: "done".into(),
                fingerprint: "e1".into(),
            }
        );
    }

    #[test]
    fn record_stage_state_upserts_by_stage() {
        let store = TimelineStore::in_memory().expect("store");
        store
            .record_stage_state("scan", "incomplete", "f1")
            .expect("r1");
        store.record_stage_state("scan", "done", "f2").expect("r2");
        let states = store.load_stage_states().expect("load");
        assert_eq!(states.len(), 1, "upsert keeps one row per stage");
        assert_eq!(states[0].status, "done");
        assert_eq!(states[0].fingerprint, "f2");
    }

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
    fn schema_has_ingest_log_and_unit_id_for_resume() {
        // issen #115 step 2: resumable ingestion needs a durable `ingest_log`
        // (the per-unit completion record) and a per-event `ingest_unit_id`
        // provenance column on `timeline` (so a resume can delete a unit's
        // partial rows and re-parse idempotently).
        let store = TimelineStore::in_memory().expect("create store");
        let conn = store.connection();

        let mut stmt = conn
            .prepare("SELECT count(*) FROM ingest_log")
            .expect("ingest_log table must exist");
        let n: i64 = stmt.query_row([], |r| r.get(0)).expect("query ingest_log");
        assert_eq!(n, 0, "ingest_log starts empty");

        conn.prepare("SELECT ingest_unit_id FROM timeline LIMIT 0")
            .expect("timeline.ingest_unit_id column must exist");
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
