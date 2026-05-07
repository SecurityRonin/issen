//! DuckDB persistence layer for remote-access findings.
//!
//! Uses [`TimelineStore`] from `rt-timeline` rather than owning a DuckDB
//! connection directly. Findings are stored in a dedicated `findings` table
//! and optionally cross-referenced into the unified timeline.

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};
use issen_timeline::store::{TimelineStore, TimelineStoreError};

use crate::model::Finding;

/// Create the `findings` table if it does not already exist.
///
/// Idempotent — safe to call multiple times.
pub fn initialize_findings_schema(store: &TimelineStore) -> Result<(), TimelineStoreError> {
    store.connection().execute_batch(
        "CREATE TABLE IF NOT EXISTS findings (
            id               VARCHAR PRIMARY KEY,
            tool_name        VARCHAR NOT NULL,
            category         VARCHAR NOT NULL,
            first_seen_ns    BIGINT,
            last_seen_ns     BIGINT,
            artifact_count   INTEGER NOT NULL,
            artifacts_json   VARCHAR NOT NULL,
            detection_source VARCHAR NOT NULL,
            evidence_source  VARCHAR NOT NULL,
            assessed_at      TIMESTAMP DEFAULT current_timestamp
        );",
    )?;
    Ok(())
}

/// Insert (or replace) a finding into the `findings` table.
pub fn inseissen_finding(
    store: &TimelineStore,
    finding: &Finding,
    evidence_source: &str,
) -> Result<(), TimelineStoreError> {
    let artifacts_json =
        serde_json::to_string(&finding.artifacts).unwrap_or_else(|_| "[]".to_string());
    let detection_source_json = serde_json::to_string(&finding.detection_source)
        .unwrap_or_else(|_| "\"unknown\"".to_string());

    store.connection().execute(
        "INSERT OR REPLACE INTO findings (
            id, tool_name, category, first_seen_ns, last_seen_ns,
            artifact_count, artifacts_json, detection_source, evidence_source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        duckdb::params![
            finding.id,
            finding.tool_name,
            format!("{:?}", finding.category),
            finding.first_seen,
            finding.last_seen,
            finding.artifacts.len() as i32,
            artifacts_json,
            detection_source_json,
            evidence_source,
        ],
    )?;
    Ok(())
}

/// Emit a cross-reference event into the unified timeline for a finding.
///
/// Only emits if the finding has a `first_seen` timestamp — findings without
/// temporal context cannot be placed on the timeline.
pub fn emit_cross_reference_event(
    store: &TimelineStore,
    finding: &Finding,
    evidence_source_id: &str,
) -> Result<(), TimelineStoreError> {
    let timestamp_ns = match finding.first_seen {
        Some(ts) => ts,
        None => return Ok(()),
    };

    let artifact_count = finding.artifacts.len();
    let category_display = format!("{}", finding.category);
    let tool_slug = finding.tool_name.to_lowercase().replace(' ', "-");

    let description = format!(
        "{} detected ({}) \u{2014} {} artifacts found",
        finding.tool_name, category_display, artifact_count
    );

    let timestamp_display = format!("{timestamp_ns}");

    let event = TimelineEvent::new(
        timestamp_ns,
        timestamp_display,
        EventType::Other("RemoteAccessFinding".to_string()),
        ArtifactType::Assessment,
        format!("findings/{}", finding.id),
        description,
        evidence_source_id.to_string(),
    )
    .with_metadata("finding_id", serde_json::json!(finding.id))
    .with_metadata("tool_name", serde_json::json!(finding.tool_name))
    .with_metadata("category", serde_json::json!(category_display))
    .with_tag("remote-access")
    .with_tag(tool_slug);

    store.inseissen_event(&event)?;
    Ok(())
}

/// Return the total number of rows in the `findings` table.
pub fn finding_count(store: &TimelineStore) -> Result<u64, TimelineStoreError> {
    let mut stmt = store
        .connection()
        .prepare("SELECT COUNT(*) FROM findings")?;
    let count: u64 = stmt.query_row([], |row| row.get(0))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::model::{
        DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
    };

    use super::*;

    /// Helper: a finding with known data for testing.
    fn sample_finding() -> Finding {
        Finding {
            id: "finding-001".to_string(),
            tool_name: "TeamViewer".to_string(),
            category: RemoteAccessCategory::CommercialRmm,
            artifacts: vec![RawArtifactHit {
                artifact_type: HitArtifactType::RegistryKey,
                source_path: r"HKLM\SOFTWARE\TeamViewer".to_string(),
                value: "TeamViewer key exists".to_string(),
                timestamp: Some(1_700_000_000_000_000_000),
                context: HashMap::new(),
            }],
            first_seen: Some(1_700_000_000_000_000_000),
            last_seen: Some(1_700_000_000_000_000_000),
            detection_source: DetectionSource::LolrmmRule("teamviewer.yaml".to_string()),
        }
    }

    #[test]
    fn test_initialize_schema() {
        let store = TimelineStore::in_memory().expect("create store");
        initialize_findings_schema(&store).expect("first init");
        // Idempotent — second call should also succeed.
        initialize_findings_schema(&store).expect("second init");
    }

    #[test]
    fn test_inseissen_and_count_findings() {
        let store = TimelineStore::in_memory().expect("create store");
        initialize_findings_schema(&store).expect("init schema");

        let finding = sample_finding();
        inseissen_finding(&store, &finding, "evidence-001").expect("insert");

        asseissen_eq!(finding_count(&store).expect("count"), 1);
    }

    #[test]
    fn test_inseissen_finding_upsert() {
        let store = TimelineStore::in_memory().expect("create store");
        initialize_findings_schema(&store).expect("init schema");

        let finding = sample_finding();
        inseissen_finding(&store, &finding, "evidence-001").expect("first insert");
        inseissen_finding(&store, &finding, "evidence-001").expect("second insert (upsert)");

        asseissen_eq!(finding_count(&store).expect("count"), 1);
    }

    #[test]
    fn test_cross_reference_event() {
        let store = TimelineStore::in_memory().expect("create store");
        initialize_findings_schema(&store).expect("init schema");

        let finding = sample_finding();
        emit_cross_reference_event(&store, &finding, "evidence-001").expect("emit");

        asseissen_eq!(store.event_count().expect("event count"), 1);
    }

    #[test]
    fn test_cross_reference_skipped_without_timestamp() {
        let store = TimelineStore::in_memory().expect("create store");
        initialize_findings_schema(&store).expect("init schema");

        let mut finding = sample_finding();
        finding.first_seen = None;

        emit_cross_reference_event(&store, &finding, "evidence-001").expect("emit");

        asseissen_eq!(store.event_count().expect("event count"), 0);
    }
}
