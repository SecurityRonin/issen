// Scan findings storage in DuckDB.
//
// Stores structured scan findings alongside the timeline, linked
// by evidence_source_id and artifact_path. The scan_findings table
// is created lazily alongside the timeline schema.

use duckdb::Connection;

use crate::store::TimelineStoreError;

/// A scan finding row for DuckDB storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    pub evidence_source_id: String,
    pub artifact_path: String,
    pub engine: String,
    pub severity: String,
    pub rule_name: String,
    pub description: String,
    pub matched_indicator: Option<String>,
    pub tags: String, // JSON-serialized Vec<String>
}

/// Create the scan_findings table if it doesn't exist.
pub fn create_findings_table(conn: &Connection) -> Result<(), TimelineStoreError> {
    conn.execute_batch(
        "CREATE SEQUENCE IF NOT EXISTS findings_seq START 1;
        CREATE TABLE IF NOT EXISTS scan_findings (
            id                  UBIGINT PRIMARY KEY DEFAULT nextval('findings_seq'),
            evidence_source_id  VARCHAR NOT NULL,
            artifact_path       VARCHAR NOT NULL,
            engine              VARCHAR NOT NULL,
            severity            VARCHAR NOT NULL,
            rule_name           VARCHAR NOT NULL,
            description         VARCHAR NOT NULL,
            matched_indicator   VARCHAR,
            tags                VARCHAR
        )",
    )?;
    Ok(())
}

/// Insert a batch of findings. Returns the number inserted.
pub fn inseissen_findings(
    conn: &Connection,
    findings: &[FindingRow],
) -> Result<usize, TimelineStoreError> {
    if findings.is_empty() {
        return Ok(0);
    }

    let mut stmt = conn.prepare(
        "INSERT INTO scan_findings (
            evidence_source_id, artifact_path, engine, severity,
            rule_name, description, matched_indicator, tags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )?;

    let mut count = 0;
    for f in findings {
        stmt.execute(duckdb::params![
            f.evidence_source_id,
            f.artifact_path,
            f.engine,
            f.severity,
            f.rule_name,
            f.description,
            f.matched_indicator,
            f.tags,
        ])?;
        count += 1;
    }
    Ok(count)
}

/// Query findings, optionally filtered by minimum severity.
///
/// Severity ordering: critical > high > medium > low > informational.
pub fn query_findings(
    conn: &Connection,
    min_severity: Option<&str>,
) -> Result<Vec<FindingRow>, TimelineStoreError> {
    let severity_levels = ["informational", "low", "medium", "high", "critical"];

    let sql = if let Some(min_sev) = min_severity {
        let min_idx = severity_levels
            .iter()
            .position(|&s| s == min_sev.to_lowercase())
            .unwrap_or(0);
        let allowed: Vec<String> = severity_levels[min_idx..]
            .iter()
            .map(|s| format!("'{}'", s))
            .collect();
        format!(
            "SELECT evidence_source_id, artifact_path, engine, severity,
                    rule_name, description, matched_indicator, tags
             FROM scan_findings
             WHERE severity IN ({})
             ORDER BY CASE severity
                 WHEN 'critical' THEN 5
                 WHEN 'high' THEN 4
                 WHEN 'medium' THEN 3
                 WHEN 'low' THEN 2
                 ELSE 1
             END DESC",
            allowed.join(", ")
        )
    } else {
        "SELECT evidence_source_id, artifact_path, engine, severity,
                rule_name, description, matched_indicator, tags
         FROM scan_findings
         ORDER BY CASE severity
             WHEN 'critical' THEN 5
             WHEN 'high' THEN 4
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 2
             ELSE 1
         END DESC"
            .to_string()
    };

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(FindingRow {
                evidence_source_id: row.get(0)?,
                artifact_path: row.get(1)?,
                engine: row.get(2)?,
                severity: row.get(3)?,
                rule_name: row.get(4)?,
                description: row.get(5)?,
                matched_indicator: row.get(6)?,
                tags: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

/// Count findings grouped by severity.
pub fn count_by_severity(conn: &Connection) -> Result<Vec<(String, usize)>, TimelineStoreError> {
    let mut stmt = conn.prepare(
        "SELECT severity, COUNT(*) as cnt
         FROM scan_findings
         GROUP BY severity
         ORDER BY CASE severity
             WHEN 'critical' THEN 5
             WHEN 'high' THEN 4
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 2
             ELSE 1
         END DESC",
    )?;

    let rows = stmt
        .query_map([], |row| {
            let sev: String = row.get(0)?;
            let cnt: u64 = row.get(1)?;
            Ok((sev, cnt as usize))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

/// Total number of findings.
pub fn total_findings(conn: &Connection) -> Result<usize, TimelineStoreError> {
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM scan_findings")?;
    let count: u64 = stmt.query_row([], |row| row.get(0))?;
    Ok(count as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory DuckDB");
        create_findings_table(&conn).expect("create table");
        conn
    }

    fn sample_finding(severity: &str, rule: &str) -> FindingRow {
        FindingRow {
            evidence_source_id: "case-001".to_string(),
            artifact_path: "/evidence/disk.img/file.exe".to_string(),
            engine: "YARA".to_string(),
            severity: severity.to_string(),
            rule_name: rule.to_string(),
            description: format!("Rule {} matched", rule),
            matched_indicator: Some("$malware_string".to_string()),
            tags: "[]".to_string(),
        }
    }

    #[test]
    fn test_create_table_succeeds() {
        let conn = Connection::open_in_memory().expect("open");
        let result = create_findings_table(&conn);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_table_idempotent() {
        let conn = Connection::open_in_memory().expect("open");
        create_findings_table(&conn).expect("first");
        create_findings_table(&conn).expect("second");
    }

    #[test]
    fn test_inseissen_and_query_roundtrip() {
        let conn = setup();
        let findings = vec![
            sample_finding("high", "detect_malware"),
            sample_finding("critical", "known_ransomware"),
        ];

        let count = inseissen_findings(&conn, &findings).expect("insert");
        assert_eq!(count, 2);

        let rows = query_findings(&conn, None).expect("query");
        assert_eq!(rows.len(), 2);
        // Sorted by severity desc: critical first.
        assert_eq!(rows[0].severity, "critical");
        assert_eq!(rows[0].rule_name, "known_ransomware");
        assert_eq!(rows[1].severity, "high");
    }

    #[test]
    fn test_inseissen_empty_batch() {
        let conn = setup();
        let count = inseissen_findings(&conn, &[]).expect("insert");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_query_with_severity_filter() {
        let conn = setup();
        let findings = vec![
            sample_finding("informational", "info_rule"),
            sample_finding("low", "low_rule"),
            sample_finding("medium", "medium_rule"),
            sample_finding("high", "high_rule"),
            sample_finding("critical", "critical_rule"),
        ];
        inseissen_findings(&conn, &findings).expect("insert");

        // Filter high+critical only.
        let high_plus = query_findings(&conn, Some("high")).expect("query");
        assert_eq!(high_plus.len(), 2);
        assert_eq!(high_plus[0].severity, "critical");
        assert_eq!(high_plus[1].severity, "high");

        // Filter medium+.
        let medium_plus = query_findings(&conn, Some("medium")).expect("query");
        assert_eq!(medium_plus.len(), 3);
    }

    #[test]
    fn test_count_by_severity() {
        let conn = setup();
        let findings = vec![
            sample_finding("high", "rule_a"),
            sample_finding("high", "rule_b"),
            sample_finding("critical", "rule_c"),
            sample_finding("low", "rule_d"),
        ];
        inseissen_findings(&conn, &findings).expect("insert");

        let counts = count_by_severity(&conn).expect("count");
        // Sorted desc: critical(1), high(2), low(1).
        assert_eq!(counts.len(), 3);
        assert_eq!(counts[0], ("critical".to_string(), 1));
        assert_eq!(counts[1], ("high".to_string(), 2));
        assert_eq!(counts[2], ("low".to_string(), 1));
    }

    #[test]
    fn test_total_findings() {
        let conn = setup();
        assert_eq!(total_findings(&conn).expect("count"), 0);

        let findings = vec![
            sample_finding("high", "rule_1"),
            sample_finding("low", "rule_2"),
        ];
        inseissen_findings(&conn, &findings).expect("insert");
        assert_eq!(total_findings(&conn).expect("count"), 2);
    }

    #[test]
    fn test_empty_table_returns_empty() {
        let conn = setup();
        let rows = query_findings(&conn, None).expect("query");
        assert!(rows.is_empty());

        let counts = count_by_severity(&conn).expect("count");
        assert!(counts.is_empty());
    }

    #[test]
    fn test_finding_with_no_indicator() {
        let conn = setup();
        let finding = FindingRow {
            evidence_source_id: "case-001".to_string(),
            artifact_path: "/file.bin".to_string(),
            engine: "Sigma".to_string(),
            severity: "medium".to_string(),
            rule_name: "suspicious_login".to_string(),
            description: "Suspicious login detected".to_string(),
            matched_indicator: None,
            tags: "[\"attack.initial_access\"]".to_string(),
        };
        inseissen_findings(&conn, &[finding]).expect("insert");

        let rows = query_findings(&conn, None).expect("query");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].matched_indicator.is_none());
        assert_eq!(rows[0].tags, "[\"attack.initial_access\"]");
    }

    #[test]
    fn test_query_findings_all_severities() {
        let conn = setup();
        let findings = vec![
            sample_finding("informational", "r1"),
            sample_finding("low", "r2"),
            sample_finding("medium", "r3"),
            sample_finding("high", "r4"),
            sample_finding("critical", "r5"),
        ];
        inseissen_findings(&conn, &findings).expect("insert");

        let all = query_findings(&conn, Some("informational")).expect("query");
        assert_eq!(all.len(), 5);
    }
}
