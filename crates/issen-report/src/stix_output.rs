//! STIX 2.1 Attack Flow bundle serialisation for `Issen` findings.

use std::path::Path;

use chrono::SecondsFormat;
use issen_correlation::model::Finding;
use serde_json::json;
use uuid::Uuid;

/// A STIX 2.1 bundle with Attack Flow SDOs.
pub struct StixBundle {
    pub id: String,
    pub objects: Vec<serde_json::Value>,
}

/// Map a severity string to an Attack Flow confidence value.
fn severity_to_confidence(severity: &str) -> u64 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 100,
        "high" => 75,
        "medium" => 50,
        _ => 25,
    }
}

/// Convert correlation findings to a STIX 2.1 Attack Flow bundle.
///
/// Each `Finding` becomes one `attack-action` SDO.
#[must_use]
pub fn findings_to_stix_bundle(
    findings: &[Finding],
    title: &str,
    _author: Option<&str>,
) -> StixBundle {
    let now = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

    // Static extension-definition object (always the same).
    let ext_def = json!({
        "type": "extension-definition",
        "id": "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4",
        "spec_version": "2.1",
        "created": "2022-08-02T19:34:35.143Z",
        "modified": "2022-08-02T19:34:35.143Z",
        "name": "Attack Flow",
        "schema": "https://center-for-threat-informed-defense.github.io/attack-flow/schema/attack-flow-schema-2.0.0.json",
        "version": "2.0.0",
        "extension_types": ["new-sdo"]
    });

    // Identity object.
    let identity_id = format!("identity--{}", Uuid::new_v4());
    let identity = json!({
        "type": "identity",
        "id": identity_id,
        "spec_version": "2.1",
        "created": now,
        "modified": now,
        "name": "Issen",
        "identity_class": "system",
        "contact_information": "https://github.com/SecurityRonin/issen"
    });

    // Build one attack-action per finding.
    let ext_key = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4";
    let mut action_ids: Vec<String> = Vec::new();
    let mut actions: Vec<serde_json::Value> = Vec::new();

    for finding in findings {
        let action_id = format!("attack-action--{}", Uuid::new_v4());
        let description = finding
            .explanation
            .as_deref()
            .or(finding.summary.as_deref())
            .unwrap_or("");
        let confidence = severity_to_confidence(&finding.severity);

        actions.push(json!({
            "type": "attack-action",
            "id": action_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": finding.title,
            "description": description,
            "confidence": confidence,
            "effect_refs": [],
            "extensions": {
                ext_key: { "extension_type": "new-sdo" }
            }
        }));
        action_ids.push(action_id);
    }

    let start_refs: Vec<&str> = action_ids
        .first()
        .map(|id| vec![id.as_str()])
        .unwrap_or_default();

    // Root attack-flow object.
    let flow_id = format!("attack-flow--{}", Uuid::new_v4());
    let flow = json!({
        "type": "attack-flow",
        "id": flow_id,
        "spec_version": "2.1",
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": title,
        "scope": "incident",
        "start_refs": start_refs,
        "extensions": {
            ext_key: { "extension_type": "new-sdo" }
        }
    });

    let mut objects = vec![ext_def, identity, flow];
    objects.extend(actions);

    StixBundle {
        id: format!("bundle--{}", Uuid::new_v4()),
        objects,
    }
}

/// Serialize the bundle to a JSON file (pretty-printed, 2-space indent).
///
/// # Errors
///
/// Returns an error if serialization or file I/O fails.
pub fn write_stix_bundle(bundle: &StixBundle, path: &Path) -> anyhow::Result<()> {
    let doc = json!({
        "type": "bundle",
        "id": bundle.id,
        "spec_version": "2.1",
        "objects": bundle.objects,
    });
    let buf = serde_json::to_string_pretty(&doc)?;
    std::fs::write(path, buf)?;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use issen_correlation::model::{AssertionLevel, Finding};

    fn make_finding(title: &str, severity: &str) -> Finding {
        Finding {
            rule_id: "test.rule".into(),
            title: title.into(),
            severity: severity.into(),
            evidence_ids: vec!["ev-1".into()],
            summary: Some("Summary text".into()),
            explanation: Some("Explanation text".into()),
            confidence: 80,
            assertion_level: AssertionLevel::Correlated,
            evidence_rendered: vec!["line one".into(), "line two".into()],
        }
    }

    #[test]
    fn empty_findings_bundle_has_spec_version() {
        let bundle = findings_to_stix_bundle(&[], "Test Flow", None);
        let json = serde_json::to_string(&serde_json::json!({
            "type": "bundle",
            "id": bundle.id,
            "objects": bundle.objects,
        }))
        .expect("serialize");
        assert!(
            json.contains("\"spec_version\""),
            "serialized bundle must contain spec_version"
        );
    }

    #[test]
    fn empty_findings_bundle_has_extension_definition() {
        let bundle = findings_to_stix_bundle(&[], "Test Flow", None);
        let has_ext_def = bundle
            .objects
            .iter()
            .any(|o| o.get("type").and_then(|t| t.as_str()) == Some("extension-definition"));
        assert!(has_ext_def, "bundle must contain an extension-definition object");
    }

    #[test]
    fn finding_becomes_attack_action() {
        let findings = vec![make_finding("Phishing Email", "high")];
        let bundle = findings_to_stix_bundle(&findings, "Test Flow", None);
        let has_action = bundle
            .objects
            .iter()
            .any(|o| o.get("type").and_then(|t| t.as_str()) == Some("attack-action"));
        assert!(has_action, "one finding must produce one attack-action object");
    }

    #[test]
    fn attack_action_name_matches_finding_title() {
        let findings = vec![make_finding("Lateral Movement via SMB", "high")];
        let bundle = findings_to_stix_bundle(&findings, "Test Flow", None);
        let action = bundle
            .objects
            .iter()
            .find(|o| o.get("type").and_then(|t| t.as_str()) == Some("attack-action"))
            .expect("attack-action must exist");
        assert_eq!(
            action.get("name").and_then(|n| n.as_str()),
            Some("Lateral Movement via SMB"),
            "action name must match finding title"
        );
    }

    #[test]
    fn severity_critical_maps_to_confidence_100() {
        let findings = vec![make_finding("Critical Finding", "critical")];
        let bundle = findings_to_stix_bundle(&findings, "Test Flow", None);
        let action = bundle
            .objects
            .iter()
            .find(|o| o.get("type").and_then(|t| t.as_str()) == Some("attack-action"))
            .expect("attack-action must exist");
        assert_eq!(
            action.get("confidence").and_then(|c| c.as_u64()),
            Some(100),
            "critical severity must map to confidence 100"
        );
    }

    #[test]
    fn write_stix_bundle_creates_file() {
        let bundle = findings_to_stix_bundle(&[], "Test Flow", None);
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("bundle.json");
        write_stix_bundle(&bundle, &path).expect("write_stix_bundle");
        assert!(path.exists(), "output file must be created");
    }
}
