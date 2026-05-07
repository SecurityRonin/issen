use crate::store::{TimelineStore, TimelineStoreError};

/// A row from the timeline query results.
#[derive(Debug, Clone)]
pub struct TimelineRow {
    pub id: u64,
    pub timestamp_ns: i64,
    pub timestamp_display: String,
    pub event_type: String,
    pub source: String,
    pub artifact_path: String,
    pub description: String,
    pub metadata: Option<String>,
    pub user_account: Option<String>,
    pub hostname: Option<String>,
    pub record_hash: String,
    pub evidence_source: String,
}

/// Builder for timeline queries.
pub struct TimelineQuery {
    /// Start of time range (inclusive, nanoseconds).
    pub from_ns: Option<i64>,
    /// End of time range (inclusive, nanoseconds).
    pub to_ns: Option<i64>,
    /// Filter by event type.
    pub event_type: Option<String>,
    /// Filter by source artifact type.
    pub source: Option<String>,
    /// Filter by evidence source ID.
    pub evidence_source: Option<String>,
    /// Maximum number of results.
    pub limit: Option<u64>,
    /// Order ascending by timestamp (default true).
    pub ascending: bool,
}

impl Default for TimelineQuery {
    fn default() -> Self {
        Self {
            from_ns: None,
            to_ns: None,
            event_type: None,
            source: None,
            evidence_source: None,
            limit: None,
            ascending: true,
        }
    }
}

impl TimelineQuery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_ns(mut self, ns: i64) -> Self {
        self.from_ns = Some(ns);
        self
    }

    #[must_use]
    pub fn to_ns(mut self, ns: i64) -> Self {
        self.to_ns = Some(ns);
        self
    }

    #[must_use]
    pub fn event_type(mut self, et: impl Into<String>) -> Self {
        self.event_type = Some(et.into());
        self
    }

    #[must_use]
    pub fn source(mut self, s: impl Into<String>) -> Self {
        self.source = Some(s.into());
        self
    }

    #[must_use]
    pub fn evidence_source(mut self, es: impl Into<String>) -> Self {
        self.evidence_source = Some(es.into());
        self
    }

    #[must_use]
    pub fn limit(mut self, l: u64) -> Self {
        self.limit = Some(l);
        self
    }

    #[must_use]
    pub fn descending(mut self) -> Self {
        self.ascending = false;
        self
    }
}

impl TimelineStore {
    /// Execute a timeline query and return matching rows.
    pub fn query(&self, q: &TimelineQuery) -> Result<Vec<TimelineRow>, TimelineStoreError> {
        let mut sql = String::from(
            "SELECT id, timestamp_ns, timestamp_display, event_type, source,
                    artifact_path, description, metadata, user_account,
                    hostname, record_hash, evidence_source
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
        if let Some(ref et) = q.event_type {
            sql.push_str(" AND event_type = ?");
            params.push(Box::new(et.clone()));
        }
        if let Some(ref src) = q.source {
            sql.push_str(" AND source = ?");
            params.push(Box::new(src.clone()));
        }
        if let Some(ref es) = q.evidence_source {
            sql.push_str(" AND evidence_source = ?");
            params.push(Box::new(es.clone()));
        }

        let order = if q.ascending { "ASC" } else { "DESC" };
        sql.push_str(&format!(" ORDER BY timestamp_ns {order}"));

        if let Some(limit) = q.limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }

        let param_refs: Vec<&dyn duckdb::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.connection().prepare(&sql)?;
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(TimelineRow {
                id: row.get(0)?,
                timestamp_ns: row.get(1)?,
                timestamp_display: row.get(2)?,
                event_type: row.get(3)?,
                source: row.get(4)?,
                artifact_path: row.get(5)?,
                description: row.get(6)?,
                metadata: row.get(7)?,
                user_account: row.get(8)?,
                hostname: row.get(9)?,
                record_hash: row.get(10)?,
                evidence_source: row.get(11)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};

    use crate::query::TimelineQuery;
    use crate::store::TimelineStore;

    fn sample_events() -> Vec<TimelineEvent> {
        vec![
            TimelineEvent::new(
                1_000_000_000,
                "2023-01-01T00:00:01Z".to_string(),
                EventType::FileCreate,
                ArtifactType::UsnJournal,
                "C:/file1.txt".to_string(),
                "File created: file1.txt".to_string(),
                "ev-001".to_string(),
            ),
            TimelineEvent::new(
                2_000_000_000,
                "2023-01-01T00:00:02Z".to_string(),
                EventType::FileDelete,
                ArtifactType::UsnJournal,
                "C:/file2.txt".to_string(),
                "File deleted: file2.txt".to_string(),
                "ev-001".to_string(),
            ),
            TimelineEvent::new(
                3_000_000_000,
                "2023-01-01T00:00:03Z".to_string(),
                EventType::ProcessExec,
                ArtifactType::Prefetch,
                "C:/Windows/cmd.exe".to_string(),
                "Process executed: cmd.exe".to_string(),
                "ev-002".to_string(),
            ),
            TimelineEvent::new(
                4_000_000_000,
                "2023-01-01T00:00:04Z".to_string(),
                EventType::RegistryModify,
                ArtifactType::Registry,
                "HKLM/SOFTWARE/Test".to_string(),
                "Registry modified: Test key".to_string(),
                "ev-002".to_string(),
            ),
        ]
    }

    fn populated_store() -> TimelineStore {
        let store = TimelineStore::in_memory().expect("store");
        for event in &sample_events() {
            store.inseissen_event(event).expect("insert");
        }
        store
    }

    #[test]
    fn test_query_all() {
        let store = populated_store();
        let rows = store.query(&TimelineQuery::new()).expect("query");
        asseissen_eq!(rows.len(), 4);
        // Default ordering is ascending by timestamp.
        assert!(rows[0].timestamp_ns < rows[3].timestamp_ns);
    }

    #[test]
    fn test_query_time_range() {
        let store = populated_store();
        let rows = store
            .query(
                &TimelineQuery::new()
                    .from_ns(2_000_000_000)
                    .to_ns(3_000_000_000),
            )
            .expect("query");
        asseissen_eq!(rows.len(), 2);
        asseissen_eq!(rows[0].timestamp_ns, 2_000_000_000);
        asseissen_eq!(rows[1].timestamp_ns, 3_000_000_000);
    }

    #[test]
    fn test_query_by_event_type() {
        let store = populated_store();
        let rows = store
            .query(&TimelineQuery::new().event_type("FileCreate"))
            .expect("query");
        asseissen_eq!(rows.len(), 1);
        asseissen_eq!(rows[0].event_type, "FileCreate");
    }

    #[test]
    fn test_query_by_source() {
        let store = populated_store();
        let rows = store
            .query(&TimelineQuery::new().source("UsnJournal"))
            .expect("query");
        asseissen_eq!(rows.len(), 2);
    }

    #[test]
    fn test_query_by_evidence_source() {
        let store = populated_store();
        let rows = store
            .query(&TimelineQuery::new().evidence_source("ev-002"))
            .expect("query");
        asseissen_eq!(rows.len(), 2);
    }

    #[test]
    fn test_query_with_limit() {
        let store = populated_store();
        let rows = store.query(&TimelineQuery::new().limit(2)).expect("query");
        asseissen_eq!(rows.len(), 2);
    }

    #[test]
    fn test_query_descending() {
        let store = populated_store();
        let rows = store
            .query(&TimelineQuery::new().descending())
            .expect("query");
        asseissen_eq!(rows.len(), 4);
        assert!(rows[0].timestamp_ns > rows[3].timestamp_ns);
    }

    #[test]
    fn test_query_combined_filters() {
        let store = populated_store();
        let rows = store
            .query(
                &TimelineQuery::new()
                    .from_ns(1_000_000_000)
                    .to_ns(3_000_000_000)
                    .source("UsnJournal"),
            )
            .expect("query");
        asseissen_eq!(
            rows.len(),
            2,
            "Should match FileCreate + FileDelete from USN"
        );
    }

    #[test]
    fn test_query_empty_result() {
        let store = populated_store();
        let rows = store
            .query(&TimelineQuery::new().event_type("NonExistent"))
            .expect("query");
        assert!(rows.is_empty());
    }
}
