//! ATT&CK Navigator layer output for a scan's findings.
//!
//! Renders the case's [`FindingRow`]s as a MITRE ATT&CK Navigator layer JSON —
//! a heatmap of every technique observed across the investigation, scored by
//! severity — by mapping each finding's `attack.t<id>` tags to technique IDs and
//! delegating to [`forensicnomicon::navigator`] (the shared, tested layer
//! builder).

use std::path::Path;

use forensicnomicon::report::{Category, Finding, Severity};

use crate::FindingRow;

/// Extract ATT&CK **technique** IDs from a finding's tags. A tag of the form
/// `attack.t1003` or `attack.t1003.001` (case-insensitive) yields `T1003` /
/// `T1003.001`. Tactic tags (`attack.execution`) and non-ATT&CK tags are ignored
/// — only techniques have a place on the matrix.
#[must_use]
pub fn technique_ids(tags: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for tag in tags {
        let lower = tag.to_lowercase();
        let Some(rest) = lower.strip_prefix("attack.") else {
            continue;
        };
        // A technique tag is `t` followed by digits, optionally `.` + digits.
        let bytes = rest.as_bytes();
        if bytes.first() == Some(&b't') && bytes.get(1).is_some_and(u8::is_ascii_digit) {
            let id = rest.to_uppercase();
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

/// Map an issen severity string to a `forensicnomicon` [`Severity`].
///
/// A persisted token is free text as far as this layer is concerned, so an
/// unrecognized one floors to `Info` rather than dropping the finding.
fn severity_of(s: &str) -> Severity {
    issen_core::severity::parse_lossy(s)
}

/// Convert a [`FindingRow`] into a `forensicnomicon` [`Finding`] carrying its
/// technique tags as MITRE refs, so the shared navigator builder can score it.
fn to_finding(f: &FindingRow) -> Finding {
    let mut builder = Finding::observation(
        severity_of(&f.severity),
        Category::Threat,
        f.rule_name.clone(),
    );
    for technique in technique_ids(&f.tags) {
        builder = builder.mitre(technique);
    }
    builder.build()
}

/// Render the findings as an ATT&CK Navigator layer JSON string. Findings with
/// no `attack.t<id>` technique tag contribute nothing (they have no matrix cell).
#[must_use]
pub fn findings_to_navigator_layer(findings: &[FindingRow], layer_name: &str) -> String {
    let converted: Vec<Finding> = findings.iter().map(to_finding).collect();
    forensicnomicon::navigator::findings_to_navigator_layer(&converted, layer_name)
}

/// Write the Navigator layer JSON for `findings` to `path`.
///
/// # Errors
/// Returns any I/O error from creating or writing the file.
pub fn write_navigator_layer(
    findings: &[FindingRow],
    layer_name: &str,
    path: &Path,
) -> std::io::Result<()> {
    std::fs::write(path, findings_to_navigator_layer(findings, layer_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: &str, tags: &[&str]) -> FindingRow {
        FindingRow {
            engine: "Sigma".to_string(),
            rule_name: "RULE-X".to_string(),
            severity: severity.to_string(),
            target: "Security.evtx".to_string(),
            description: "desc".to_string(),
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn technique_ids_extracts_techniques_skips_tactics() {
        let ids = technique_ids(&[
            "attack.t1003.001".to_string(),
            "attack.execution".to_string(), // tactic — skipped
            "ATTACK.T1059".to_string(),     // case-insensitive
            "malware".to_string(),          // non-attack — skipped
        ]);
        assert_eq!(ids, vec!["T1003.001".to_string(), "T1059".to_string()]);
    }

    #[test]
    fn layer_has_technique_scored_by_severity() {
        let layer =
            findings_to_navigator_layer(&[finding("critical", &["attack.t1003.001"])], "case-001");
        assert!(layer.contains(r#""name": "case-001""#));
        assert!(layer.contains(r#""techniqueID": "T1003.001""#));
        assert!(layer.contains(r#""score": 100"#)); // Critical
    }

    #[test]
    fn finding_without_technique_tag_is_absent() {
        let layer = findings_to_navigator_layer(&[finding("high", &["attack.execution"])], "x");
        assert!(!layer.contains("techniqueID"));
    }
}
