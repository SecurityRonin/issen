//! Cross-artifact correlation rules operating on forensicnomicon catalog IDs.
//!
//! Unlike the stream-based [`crate::engine::CorrelationEngine`] which matches
//! live evidence items (Sigma/Zeek/Artifact tags), this module evaluates
//! rules against the *set of catalog artifact IDs that were collected* during
//! triage. Rules fire when a threshold of expected artifact IDs is present,
//! and record which were absent — absence is itself forensically significant.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────────

/// How many artifact IDs must be present for a rule to fire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactRequirement {
    /// Every listed artifact ID must be present.
    All,
    /// At least `n` of the listed artifact IDs must be present.
    AtLeastN { n: usize },
}

/// A cross-artifact correlation rule operating on forensicnomicon catalog IDs.
///
/// Rules are loaded from YAML files (see [`load_artifact_rule_file`]) and
/// evaluated with [`evaluate_artifacts`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCorrelationRule {
    /// Unique dotted identifier, e.g. `artifact.execution.triple-corroboration`.
    pub id: String,
    /// Short human-readable rule name.
    pub title: String,
    /// `critical` | `high` | `medium` | `low` | `info`.
    pub severity: String,
    /// Analyst-facing explanation of what the correlation indicates.
    #[serde(default)]
    pub description: Option<String>,
    /// Forensicnomicon catalog artifact IDs involved in this rule.
    pub artifact_ids: Vec<String>,
    /// How many of `artifact_ids` must be present to fire.
    pub requirement: ArtifactRequirement,
    /// MITRE ATT&CK technique IDs supported by this correlation.
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    /// Forensic significance of absent expected corroborators.
    #[serde(default)]
    pub absence_note: Option<String>,
    /// Authoritative references backing this correlation.
    #[serde(default)]
    pub references: Vec<String>,
}

/// A fired artifact correlation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactCorrelationFinding {
    /// Rule identifier.
    pub rule_id: String,
    /// Rule title.
    pub title: String,
    /// Rule severity.
    pub severity: String,
    /// Artifact IDs from the rule that were present.
    pub matched_artifacts: Vec<String>,
    /// Artifact IDs from the rule that were absent.
    pub absent_artifacts: Vec<String>,
    /// Analyst-facing description from the rule.
    pub description: Option<String>,
    /// Interpretation of absent corroborators.
    pub absence_note: Option<String>,
    /// ATT&CK technique IDs.
    pub mitre_techniques: Vec<String>,
}

// ── Evaluation ────────────────────────────────────────────────────────────────

/// Evaluate artifact correlation rules against a set of present artifact IDs.
///
/// Returns all rules whose [`ArtifactRequirement`] is satisfied by `present`.
/// Each [`ArtifactCorrelationFinding`] records both matched and absent IDs so
/// callers can surface absence as a secondary signal.
#[must_use]
pub fn evaluate_artifacts(
    rules: &[ArtifactCorrelationRule],
    present: &[impl AsRef<str>],
) -> Vec<ArtifactCorrelationFinding> {
    let present_set: std::collections::HashSet<&str> =
        present.iter().map(AsRef::as_ref).collect();

    let mut findings = Vec::new();

    for rule in rules {
        let matched: Vec<String> = rule
            .artifact_ids
            .iter()
            .filter(|id| present_set.contains(id.as_str()))
            .cloned()
            .collect();

        let absent: Vec<String> = rule
            .artifact_ids
            .iter()
            .filter(|id| !present_set.contains(id.as_str()))
            .cloned()
            .collect();

        let fires = match &rule.requirement {
            ArtifactRequirement::All => absent.is_empty(),
            ArtifactRequirement::AtLeastN { n } => matched.len() >= *n,
        };

        if fires {
            findings.push(ArtifactCorrelationFinding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity.clone(),
                matched_artifacts: matched,
                absent_artifacts: absent,
                description: rule.description.clone(),
                absence_note: rule.absence_note.clone(),
                mitre_techniques: rule.mitre_techniques.clone(),
            });
        }
    }

    findings
}

// ── Rule loading ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ArtifactRuleLoadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error in {path}: {source}")]
    Yaml {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
}

/// Load a single artifact correlation rule from a YAML file.
///
/// # Errors
/// Returns [`ArtifactRuleLoadError`] on I/O or parse failure.
pub fn load_artifact_rule_file(
    path: &Path,
) -> Result<ArtifactCorrelationRule, ArtifactRuleLoadError> {
    let raw = std::fs::read_to_string(path)?;
    serde_yaml::from_str(&raw).map_err(|source| ArtifactRuleLoadError::Yaml {
        path: path.display().to_string(),
        source,
    })
}

/// Load all `.yml`/`.yaml` artifact correlation rules from a directory,
/// sorted by filename.
///
/// # Errors
/// Returns [`ArtifactRuleLoadError`] if any file cannot be read or parsed.
pub fn load_artifact_rule_pack(
    dir: &Path,
) -> Result<Vec<ArtifactCorrelationRule>, ArtifactRuleLoadError> {
    let mut paths = std::fs::read_dir(dir)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| matches!(ext, "yml" | "yaml"))
        })
        .collect::<Vec<_>>();
    paths.sort();

    paths
        .into_iter()
        .map(|path| load_artifact_rule_file(&path))
        .collect()
}

/// Path to the bundled artifact correlation rules directory.
#[must_use]
pub fn bundled_artifact_rule_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/artifacts")
}

/// Load all bundled artifact correlation rules.
///
/// # Errors
/// Returns [`ArtifactRuleLoadError`] if any bundled rule fails to load.
pub fn load_bundled_artifact_rules() -> Result<Vec<ArtifactCorrelationRule>, ArtifactRuleLoadError>
{
    load_artifact_rule_pack(&bundled_artifact_rule_dir())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn all_rule(artifact_ids: &[&str]) -> ArtifactCorrelationRule {
        ArtifactCorrelationRule {
            id: "test.all".into(),
            title: "All rule".into(),
            severity: "high".into(),
            description: None,
            artifact_ids: artifact_ids.iter().map(|s| s.to_string()).collect(),
            requirement: ArtifactRequirement::All,
            mitre_techniques: vec![],
            absence_note: None,
            references: vec![],
        }
    }

    fn at_least_n_rule(artifact_ids: &[&str], n: usize) -> ArtifactCorrelationRule {
        ArtifactCorrelationRule {
            id: "test.at_least_n".into(),
            title: "At least N rule".into(),
            severity: "medium".into(),
            description: None,
            artifact_ids: artifact_ids.iter().map(|s| s.to_string()).collect(),
            requirement: ArtifactRequirement::AtLeastN { n },
            mitre_techniques: vec![],
            absence_note: None,
            references: vec![],
        }
    }

    // ── Requirement::All ──────────────────────────────────────────────────────

    #[test]
    fn all_rule_fires_when_every_artifact_present() {
        let rule = all_rule(&["userassist_exe", "prefetch_file", "shimcache"]);
        let present = &["userassist_exe", "prefetch_file", "shimcache"];
        let findings = evaluate_artifacts(&[rule], present);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "test.all");
    }

    #[test]
    fn all_rule_does_not_fire_when_one_artifact_absent() {
        let rule = all_rule(&["userassist_exe", "prefetch_file", "shimcache"]);
        let present = &["userassist_exe", "prefetch_file"]; // shimcache absent
        let findings = evaluate_artifacts(&[rule], present);
        assert!(findings.is_empty());
    }

    #[test]
    fn all_rule_does_not_fire_for_empty_present_set() {
        let rule = all_rule(&["userassist_exe", "prefetch_file"]);
        let findings = evaluate_artifacts(&[rule], &[] as &[&str]);
        assert!(findings.is_empty());
    }

    // ── Requirement::AtLeastN ─────────────────────────────────────────────────

    #[test]
    fn at_least_n_fires_when_exactly_n_present() {
        let rule = at_least_n_rule(&["userassist_exe", "prefetch_file", "shimcache"], 2);
        let present = &["userassist_exe", "prefetch_file"]; // exactly 2 of 3
        let findings = evaluate_artifacts(&[rule], present);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn at_least_n_fires_when_more_than_n_present() {
        let rule = at_least_n_rule(&["userassist_exe", "prefetch_file", "shimcache"], 2);
        let present = &["userassist_exe", "prefetch_file", "shimcache"]; // all 3
        let findings = evaluate_artifacts(&[rule], present);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn at_least_n_does_not_fire_below_threshold() {
        let rule = at_least_n_rule(&["userassist_exe", "prefetch_file", "shimcache"], 2);
        let present = &["userassist_exe"]; // only 1 of 3
        let findings = evaluate_artifacts(&[rule], present);
        assert!(findings.is_empty());
    }

    #[test]
    fn at_least_n_equal_to_len_behaves_like_all() {
        let rule = at_least_n_rule(&["userassist_exe", "prefetch_file"], 2);
        // Missing one → should not fire
        let findings = evaluate_artifacts(&[rule.clone()], &["userassist_exe"]);
        assert!(findings.is_empty());
        // All present → fires
        let findings = evaluate_artifacts(&[rule], &["userassist_exe", "prefetch_file"]);
        assert_eq!(findings.len(), 1);
    }

    // ── Finding contents ──────────────────────────────────────────────────────

    #[test]
    fn finding_records_matched_and_absent_artifacts() {
        let rule = all_rule(&["userassist_exe", "prefetch_file", "shimcache"]);
        // Force a non-firing case by using AtLeastN so it fires with 2 present
        let rule_n = at_least_n_rule(&["userassist_exe", "prefetch_file", "shimcache"], 2);
        let present = &["userassist_exe", "prefetch_file"]; // shimcache absent
        let findings = evaluate_artifacts(&[rule_n], present);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.matched_artifacts.contains(&"userassist_exe".to_string()));
        assert!(f.matched_artifacts.contains(&"prefetch_file".to_string()));
        assert!(f.absent_artifacts.contains(&"shimcache".to_string()));
    }

    #[test]
    fn finding_carries_rule_metadata() {
        let mut rule = all_rule(&["userassist_exe", "prefetch_file"]);
        rule.id = "artifact.execution.test".into();
        rule.title = "Execution test".into();
        rule.severity = "critical".into();
        rule.description = Some("Test description".into());
        rule.absence_note = Some("Absence note".into());
        rule.mitre_techniques = vec!["T1059".into()];
        let present = &["userassist_exe", "prefetch_file"];
        let findings = evaluate_artifacts(&[rule], present);
        let f = &findings[0];
        assert_eq!(f.rule_id, "artifact.execution.test");
        assert_eq!(f.title, "Execution test");
        assert_eq!(f.severity, "critical");
        assert_eq!(f.description.as_deref(), Some("Test description"));
        assert_eq!(f.absence_note.as_deref(), Some("Absence note"));
        assert_eq!(f.mitre_techniques, vec!["T1059"]);
    }

    // ── Multi-rule ────────────────────────────────────────────────────────────

    #[test]
    fn multiple_rules_can_fire_simultaneously() {
        let rule_a = all_rule(&["userassist_exe", "prefetch_file"]);
        let mut rule_b = all_rule(&["run_key_hkcu", "scheduled_tasks_dir"]);
        rule_b.id = "test.persistence".into();
        let present = &[
            "userassist_exe",
            "prefetch_file",
            "run_key_hkcu",
            "scheduled_tasks_dir",
        ];
        let findings = evaluate_artifacts(&[rule_a, rule_b], present);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn unrelated_present_artifacts_do_not_affect_rule_evaluation() {
        let rule = all_rule(&["userassist_exe", "prefetch_file"]);
        // Many extra artifacts present that are not in the rule
        let present = &[
            "userassist_exe",
            "prefetch_file",
            "evtx_security",
            "sam_users",
            "chrome_history",
        ];
        let findings = evaluate_artifacts(&[rule], present);
        assert_eq!(findings.len(), 1);
    }

    // ── Bundled rules ─────────────────────────────────────────────────────────

    #[test]
    fn bundled_artifact_rules_are_nonempty() {
        let rules = load_bundled_artifact_rules()
            .expect("bundled artifact rules should load without error");
        assert!(
            !rules.is_empty(),
            "bundled artifact rules must contain at least one rule"
        );
    }

    #[test]
    fn all_bundled_rules_have_nonempty_id_and_title() {
        let rules = load_bundled_artifact_rules().expect("bundled rules load");
        for rule in &rules {
            assert!(
                !rule.id.is_empty(),
                "rule has empty id: {:?}",
                rule.title
            );
            assert!(
                !rule.title.is_empty(),
                "rule has empty title: {:?}",
                rule.id
            );
        }
    }

    #[test]
    fn all_bundled_rules_have_nonempty_artifact_ids() {
        let rules = load_bundled_artifact_rules().expect("bundled rules load");
        for rule in &rules {
            assert!(
                !rule.artifact_ids.is_empty(),
                "rule {} has no artifact_ids",
                rule.id
            );
        }
    }

    #[test]
    fn execution_triple_corroboration_rule_exists_in_bundled() {
        let rules = load_bundled_artifact_rules().expect("bundled rules load");
        let found = rules
            .iter()
            .any(|r| r.id == "artifact.execution.triple-corroboration");
        assert!(
            found,
            "expected rule 'artifact.execution.triple-corroboration' in bundled rules"
        );
    }

    #[test]
    fn lateral_movement_rdp_rule_exists_in_bundled() {
        let rules = load_bundled_artifact_rules().expect("bundled rules load");
        let found = rules
            .iter()
            .any(|r| r.id == "artifact.lateral-movement.rdp");
        assert!(
            found,
            "expected rule 'artifact.lateral-movement.rdp' in bundled rules"
        );
    }

    #[test]
    fn persistence_multivector_rule_exists_in_bundled() {
        let rules = load_bundled_artifact_rules().expect("bundled rules load");
        let found = rules
            .iter()
            .any(|r| r.id == "artifact.persistence.multivector");
        assert!(
            found,
            "expected rule 'artifact.persistence.multivector' in bundled rules"
        );
    }

    #[test]
    fn execution_triple_corroboration_fires_on_expected_artifacts() {
        let rules = load_bundled_artifact_rules().expect("bundled rules load");
        let triple = rules
            .iter()
            .find(|r| r.id == "artifact.execution.triple-corroboration")
            .expect("rule exists");
        let present = &["userassist_exe", "prefetch_file", "shimcache"];
        let findings = evaluate_artifacts(std::slice::from_ref(triple), present);
        assert_eq!(
            findings.len(),
            1,
            "execution triple rule should fire when all three present"
        );
    }

    #[test]
    fn execution_triple_corroboration_does_not_fire_on_partial_match() {
        let rules = load_bundled_artifact_rules().expect("bundled rules load");
        let triple = rules
            .iter()
            .find(|r| r.id == "artifact.execution.triple-corroboration")
            .expect("rule exists");
        // Only two present — must not fire if requirement is All
        let present = &["userassist_exe", "prefetch_file"];
        let findings = evaluate_artifacts(std::slice::from_ref(triple), present);
        // This assertion depends on the rule's requirement; capture the intent
        // by checking the rule requirement before asserting
        if triple.requirement == ArtifactRequirement::All {
            assert!(
                findings.is_empty(),
                "All requirement must not fire with partial match"
            );
        }
    }
}
