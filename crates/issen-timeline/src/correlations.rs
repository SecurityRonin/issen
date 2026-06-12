//! Persistence for cross-artifact [`Correlation`] findings.
//!
//! Two tables join the correlation engine's output back to the timeline:
//!
//! - `correlations` — one row per finding (code, technique, severity, window,
//!   scope, note).
//! - `correlation_members` — the events that make up a finding, keyed on
//!   `timeline.id` and tagged with the member's role (anchor / consequent /
//!   supporting). `timeline.id` is chosen over `record_hash` because dedup is
//!   within-epoch only, so an id is the only stable per-row key.
//!
//! The DDL is created additively (`ADD COLUMN IF NOT EXISTS`-style safety like
//! PRE-4) so opening an older case DB is non-destructive.

use issen_correlation::correlation::{
    Correlation, CorrelationMember, CorrelationRole, CorrelationScope,
};
use forensicnomicon::report::Severity;

use crate::store::{TimelineStore, TimelineStoreError};

impl TimelineStore {
    /// The `timeline.id` of the row with the given `record_hash`, if present.
    ///
    /// Correlation members key on `timeline.id`; this resolves an in-memory
    /// event (which carries only its `record_hash`) to its persisted row id.
    pub fn timeline_id_for_hash(&self, record_hash: &str) -> Result<Option<u64>, TimelineStoreError> {
        let mut stmt = self
            .connection()
            .prepare("SELECT id FROM timeline WHERE record_hash = ? LIMIT 1")?;
        let mut rows = stmt.query([record_hash])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// Persist a [`Correlation`] and its members, returning the new
    /// `correlations.id`.
    ///
    /// Members are supplied as `(timeline_id, role)` pairs so the caller can use
    /// whichever ids it resolved (the [`Correlation`]'s own `members` field is
    /// the evaluator's view and is not re-read here — the persisted membership
    /// is exactly what is passed). The `role` string must be one of the
    /// [`CorrelationRole`] tokens; unknown tokens are stored verbatim and read
    /// back as [`CorrelationRole::Supporting`].
    pub fn persist_correlation(
        &self,
        correlation: &Correlation,
        members: &[(u64, &str)],
    ) -> Result<u64, TimelineStoreError> {
        let conn = self.connection();
        conn.execute(
            "INSERT INTO correlations
                (code, attack_technique, severity, first_ts, last_ts, scope, note)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![
                correlation.code,
                correlation.attack_technique,
                correlation.severity_str(),
                correlation.first_ts,
                correlation.last_ts,
                correlation.scope.as_str(),
                correlation.note,
            ],
        )?;
        let id: u64 = conn.query_row(
            "SELECT currval('correlation_seq')",
            [],
            |row| row.get(0),
        )?;

        if !members.is_empty() {
            let mut stmt = conn.prepare(
                "INSERT INTO correlation_members (correlation_id, timeline_id, role)
                 VALUES (?, ?, ?)",
            )?;
            for (timeline_id, role) in members {
                stmt.execute(duckdb::params![id, timeline_id, role])?;
            }
        }
        Ok(id)
    }

    /// Read a persisted correlation (with its members) back by id; `None` when
    /// no such correlation exists.
    pub fn correlation(&self, id: u64) -> Result<Option<Correlation>, TimelineStoreError> {
        let conn = self.connection();
        let mut stmt = conn.prepare(
            "SELECT code, attack_technique, severity, first_ts, last_ts, scope, note
             FROM correlations WHERE id = ?",
        )?;
        let mut rows = stmt.query([id])?;
        let row = match rows.next()? {
            Some(row) => row,
            None => return Ok(None),
        };

        let code: String = row.get(0)?;
        let attack_technique: Option<String> = row.get(1)?;
        let severity_str: String = row.get(2)?;
        let first_ts: i64 = row.get(3)?;
        let last_ts: i64 = row.get(4)?;
        let scope_str: String = row.get(5)?;
        let note: String = row.get(6)?;

        // Persisted tokens are written by `persist_correlation` from the model's
        // own `as_str`/`severity_str`, so a missing match would be a schema/code
        // contradiction; degrade rather than panic.
        let severity = Correlation::severity_from_str(&severity_str).unwrap_or(Severity::Info);
        let scope = CorrelationScope::from_str(&scope_str).unwrap_or(CorrelationScope::SameHost);

        let mut correlation = Correlation::new(code, severity)
            .with_window(first_ts, last_ts)
            .with_scope(scope)
            .with_note(note);
        if let Some(technique) = attack_technique {
            correlation = correlation.with_attack_technique(technique);
        }

        let mut member_stmt = conn.prepare(
            "SELECT timeline_id, role FROM correlation_members WHERE correlation_id = ?",
        )?;
        let member_rows = member_stmt.query_map([id], |row| {
            let timeline_id: u64 = row.get(0)?;
            let role_str: String = row.get(1)?;
            Ok((timeline_id, role_str))
        })?;
        for member in member_rows {
            let (timeline_id, role_str) = member?;
            let role = CorrelationRole::from_str(&role_str).unwrap_or(CorrelationRole::Supporting);
            correlation = correlation.with_member(CorrelationMember::new(timeline_id, role));
        }

        Ok(Some(correlation))
    }
}

#[cfg(test)]
mod tests {
    use forensicnomicon::report::Severity;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};
    use issen_correlation::correlation::{
        Correlation, CorrelationMember, CorrelationRole, CorrelationScope,
    };

    use crate::store::TimelineStore;

    fn sample_event(ts: i64, desc: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2023-11-14T22:13:20.{ts:09}Z"),
            EventType::LogonFailure,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            desc.to_string(),
            "evidence-001".to_string(),
        )
    }

    #[test]
    fn persist_correlation_returns_an_id_and_reads_back() {
        let store = TimelineStore::in_memory().expect("store");
        // Two real timeline rows so the members can key on their ids.
        let anchor = sample_event(1_000, "failed logon burst");
        let consequent = sample_event(2_000, "successful logon");
        store
            .inseissen_batch(&[anchor.clone(), consequent.clone()])
            .expect("ingest");
        let anchor_id = store
            .timeline_id_for_hash(&anchor.record_hash)
            .expect("query anchor id")
            .expect("anchor id present");
        let consequent_id = store
            .timeline_id_for_hash(&consequent.record_hash)
            .expect("query consequent id")
            .expect("consequent id present");

        let corr = Correlation::new("CORR-BRUTEFORCE-LOGON", Severity::High)
            .with_attack_technique("T1110")
            .with_scope(CorrelationScope::SameHost)
            .with_window(1_000, 2_000)
            .with_note("Failed-logon burst followed by success is consistent with brute force.");

        let id = store
            .persist_correlation(
                &corr,
                &[
                    (anchor_id, CorrelationRole::Anchor.as_str()),
                    (consequent_id, CorrelationRole::Consequent.as_str()),
                ],
            )
            .expect("persist");

        let stored = store.correlation(id).expect("read back").expect("present");
        assert_eq!(stored.code, "CORR-BRUTEFORCE-LOGON");
        assert_eq!(stored.attack_technique.as_deref(), Some("T1110"));
        assert_eq!(stored.severity, Severity::High);
        assert_eq!(stored.scope, CorrelationScope::SameHost);
        assert_eq!(stored.first_ts, 1_000);
        assert_eq!(stored.last_ts, 2_000);
        assert!(stored.note.contains("consistent with"));

        assert_eq!(stored.members.len(), 2);
        let anchor_member = stored
            .members
            .iter()
            .find(|m| m.role == CorrelationRole::Anchor)
            .expect("anchor member");
        assert_eq!(anchor_member.timeline_id, anchor_id);
        let consequent_member = stored
            .members
            .iter()
            .find(|m| m.role == CorrelationRole::Consequent)
            .expect("consequent member");
        assert_eq!(consequent_member.timeline_id, consequent_id);
    }

    #[test]
    fn correlation_read_back_absent_id_is_none() {
        let store = TimelineStore::in_memory().expect("store");
        assert!(store.correlation(999).expect("query").is_none());
    }

    #[test]
    fn persist_correlation_schema_is_idempotent_for_old_dbs() {
        // Re-initializing the schema (as on re-open of an existing case DB) must
        // not drop or error on the correlation tables.
        let store = TimelineStore::in_memory().expect("store");
        let corr = Correlation::new("CORR-X", Severity::Low).with_window(5, 9);
        let id = store.persist_correlation(&corr, &[]).expect("persist");
        store.initialize_schema_public().expect("re-init");
        assert!(store.correlation(id).expect("read back").is_some());
    }

    #[test]
    fn member_unused_import_guard() {
        // Touch CorrelationMember so the import is exercised in this module.
        let m = CorrelationMember::new(1, CorrelationRole::Supporting);
        assert_eq!(m.timeline_id, 1);
    }
}
