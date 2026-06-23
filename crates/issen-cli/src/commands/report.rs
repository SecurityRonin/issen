use std::path::Path;

use anyhow::{Context, Result};
use issen_report::ReportConfig;
use issen_timeline::store::TimelineStore;

/// Run the report command: generate a self-contained HTML report.
pub fn run(
    db_path: &Path,
    output: &Path,
    case_id: Option<&str>,
    examiner: Option<&str>,
    max_events: Option<usize>,
) -> Result<()> {
    let store = TimelineStore::open(db_path)
        .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

    let config = ReportConfig {
        title: case_id.map_or_else(
            || "Issen Report".to_string(),
            |id| format!("Issen Report — {id}"),
        ),
        case_id: case_id.map(String::from),
        examiner: examiner.map(String::from),
        max_events: max_events.or(Some(10_000)),
    };

    issen_report::generate_report(&store, config, output)
        .with_context(|| format!("Failed to generate report: {}", output.display()))?;

    println!("Report written to {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_timeline::findings::{create_findings_table, inseissen_findings, FindingRow};

    #[test]
    fn attack_navigator_format_writes_layer_with_technique() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("case.duckdb");
        {
            let store = TimelineStore::open(&db).expect("open store");
            create_findings_table(store.connection()).expect("create findings table");
            inseissen_findings(
                store.connection(),
                &[FindingRow {
                    evidence_source_id: "case-001".into(),
                    artifact_path: "Security.evtx".into(),
                    engine: "Sigma".into(),
                    severity: "high".into(),
                    rule_name: "RDP-BRUTE".into(),
                    description: "Failed-logon burst".into(),
                    matched_indicator: None,
                    tags: r#"["attack.t1110"]"#.into(),
                }],
            )
            .expect("insert findings");
        }
        let out = dir.path().join("layer.json");
        run(&db, &out, Some("case-001"), None, None, "attack-navigator").expect("run report");
        let layer = std::fs::read_to_string(&out).expect("read layer");
        assert!(
            layer.contains(r#""techniqueID": "T1110""#),
            "layer missing technique: {layer}"
        );
    }
}
