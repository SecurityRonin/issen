use crate::store::{TimelineStore, TimelineStoreError};

/// Summary statistics for the timeline.
#[derive(Debug, Clone)]
pub struct TimelineStats {
    pub total_events: u64,
    pub earliest_timestamp_ns: Option<i64>,
    pub latest_timestamp_ns: Option<i64>,
    pub event_type_counts: Vec<(String, u64)>,
    pub source_counts: Vec<(String, u64)>,
    pub evidence_source_count: u64,
}

impl TimelineStore {
    /// Compute summary statistics for the timeline.
    pub fn stats(&self) -> Result<TimelineStats, TimelineStoreError> {
        let total_events = self.event_count()?;

        let (earliest, latest) = if total_events == 0 {
            (None, None)
        } else {
            let mut stmt = self
                .connection()
                .prepare("SELECT MIN(timestamp_ns), MAX(timestamp_ns) FROM timeline")?;
            let (min, max): (i64, i64) =
                stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            (Some(min), Some(max))
        };

        let mut type_stmt = self.connection().prepare(
            "SELECT event_type, COUNT(*) as cnt FROM timeline GROUP BY event_type ORDER BY cnt DESC",
        )?;
        let event_type_counts: Vec<(String, u64)> = type_stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(Result::ok)
            .collect();

        let mut src_stmt = self.connection().prepare(
            "SELECT source, COUNT(*) as cnt FROM timeline GROUP BY source ORDER BY cnt DESC",
        )?;
        let source_counts: Vec<(String, u64)> = src_stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(Result::ok)
            .collect();

        let mut ev_stmt = self
            .connection()
            .prepare("SELECT COUNT(DISTINCT evidence_source) FROM timeline")?;
        let evidence_source_count: u64 = ev_stmt.query_row([], |row| row.get(0))?;

        Ok(TimelineStats {
            total_events,
            earliest_timestamp_ns: earliest,
            latest_timestamp_ns: latest,
            event_type_counts,
            source_counts,
            evidence_source_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};

    use crate::store::TimelineStore;

    #[test]
    fn test_stats_empty_store() {
        let store = TimelineStore::in_memory().expect("store");
        let stats = store.stats().expect("stats");
        assert_eq!(stats.total_events, 0);
        assert!(stats.earliest_timestamp_ns.is_none());
        assert!(stats.latest_timestamp_ns.is_none());
        assert!(stats.event_type_counts.is_empty());
        assert!(stats.source_counts.is_empty());
        assert_eq!(stats.evidence_source_count, 0);
    }

    #[test]
    fn test_stats_populated_store() {
        let store = TimelineStore::in_memory().expect("store");

        let events = vec![
            TimelineEvent::new(
                1_000,
                "ts1".into(),
                EventType::FileCreate,
                ArtifactType::UsnJournal,
                "p1".into(),
                "d1".into(),
                "ev-001".into(),
            ),
            TimelineEvent::new(
                2_000,
                "ts2".into(),
                EventType::FileCreate,
                ArtifactType::UsnJournal,
                "p2".into(),
                "d2".into(),
                "ev-001".into(),
            ),
            TimelineEvent::new(
                3_000,
                "ts3".into(),
                EventType::ProcessExec,
                ArtifactType::Prefetch,
                "p3".into(),
                "d3".into(),
                "ev-002".into(),
            ),
        ];
        for event in &events {
            store.inseissen_event(event).expect("insert");
        }

        let stats = store.stats().expect("stats");
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.earliest_timestamp_ns, Some(1_000));
        assert_eq!(stats.latest_timestamp_ns, Some(3_000));
        assert_eq!(stats.evidence_source_count, 2);

        // FileCreate should have count 2.
        let fc = stats
            .event_type_counts
            .iter()
            .find(|(t, _)| t == "FileCreate");
        assert_eq!(fc.map(|(_, c)| *c), Some(2));

        // UsnJournal should have count 2.
        let usn = stats.source_counts.iter().find(|(s, _)| s == "UsnJournal");
        assert_eq!(usn.map(|(_, c)| *c), Some(2));
    }
}
