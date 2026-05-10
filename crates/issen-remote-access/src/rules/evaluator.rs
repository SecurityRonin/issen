//! Detection rule evaluator.
//!
//! Checks [`DetectionRule`] conditions against an
//! [`ArtifactProvider`](crate::providers::ArtifactProvider), producing
//! [`Finding`] results when one or more conditions match.

use std::collections::HashMap;

use crate::model::{DetectionSource, Finding, HitArtifactType, RawArtifactHit};
use crate::providers::{ArtifactProvider, EventLogQuery, ProviderCapability};
use crate::rules::detection_rule::{DetectionCondition, DetectionRule};

// ---------------------------------------------------------------------------
// Condition evaluators (one per variant)
// ---------------------------------------------------------------------------

fn eval_registry_key_exists(
    path: &str,
    provider: &dyn ArtifactProvider,
    hits: &mut Vec<RawArtifactHit>,
) {
    if let Ok(true) = provider.registry_key_exists(path) {
        hits.push(RawArtifactHit {
            artifact_type: HitArtifactType::RegistryKey,
            source_path: path.to_owned(),
            value: format!("Registry key exists: {path}"),
            timestamp: None,
            context: HashMap::new(),
        });
    }
}

fn eval_registry_value_contains(
    path: &str,
    substring: &str,
    provider: &dyn ArtifactProvider,
    hits: &mut Vec<RawArtifactHit>,
) {
    if let Ok(values) = provider.registry_values(path) {
        for entry in values {
            if entry.value.contains(substring) {
                hits.push(RawArtifactHit {
                    artifact_type: HitArtifactType::RegistryValue,
                    source_path: entry.path.clone(),
                    value: format!("{}={}", entry.name, entry.value),
                    timestamp: entry.timestamp,
                    context: HashMap::new(),
                });
            }
        }
    }
}

fn eval_file_exists(
    pattern: &str,
    provider: &dyn ArtifactProvider,
    hits: &mut Vec<RawArtifactHit>,
) {
    if let Ok(files) = provider.file_exists(pattern) {
        for file in files {
            let timestamp = file.created.or(file.modified);
            hits.push(RawArtifactHit {
                artifact_type: HitArtifactType::FilePresence,
                source_path: file.path.clone(),
                value: format!("File found: {}", file.path),
                timestamp,
                context: HashMap::new(),
            });
        }
    }
}

fn eval_service_exists(
    name: &str,
    provider: &dyn ArtifactProvider,
    hits: &mut Vec<RawArtifactHit>,
) {
    if let Ok(services) = provider.services() {
        let name_lower = name.to_lowercase();
        for svc in services {
            if svc.name.to_lowercase() == name_lower
                || svc.display_name.to_lowercase() == name_lower
            {
                hits.push(RawArtifactHit {
                    artifact_type: HitArtifactType::Service,
                    source_path: svc.image_path.clone(),
                    value: format!("Service: {} ({})", svc.name, svc.display_name),
                    timestamp: None,
                    context: HashMap::new(),
                });
            }
        }
    }
}

fn eval_event_log_match(
    event_id: u32,
    provider_name: &str,
    log_file: &str,
    provider: &dyn ArtifactProvider,
    hits: &mut Vec<RawArtifactHit>,
) {
    let query = EventLogQuery {
        event_id: Some(event_id),
        provider_name: Some(provider_name.to_owned()),
        log_file: Some(log_file.to_owned()),
        keyword: None,
    };
    if let Ok(entries) = provider.event_log_search(&query) {
        for entry in entries {
            hits.push(RawArtifactHit {
                artifact_type: HitArtifactType::EventLog,
                source_path: entry.log_file.clone(),
                value: format!("EventID {} from {}", entry.event_id, entry.provider_name),
                timestamp: entry.timestamp,
                context: entry.data.clone(),
            });
        }
    }
}

fn eval_prefetch_match(
    executable: &str,
    provider: &dyn ArtifactProvider,
    hits: &mut Vec<RawArtifactHit>,
) {
    if let Ok(entries) = provider.prefetch_entries() {
        let exec_lower = executable.to_lowercase();
        for entry in entries {
            if entry.executable_name.to_lowercase().contains(&exec_lower) {
                hits.push(RawArtifactHit {
                    artifact_type: HitArtifactType::Prefetch,
                    source_path: entry.path.clone(),
                    value: format!(
                        "Prefetch: {} (run count: {})",
                        entry.executable_name, entry.run_count
                    ),
                    timestamp: entry.last_run,
                    context: HashMap::new(),
                });
            }
        }
    }
}

fn eval_amcache_match(
    program: &str,
    provider: &dyn ArtifactProvider,
    hits: &mut Vec<RawArtifactHit>,
) {
    if let Ok(entries) = provider.amcache_entries() {
        let prog_lower = program.to_lowercase();
        for entry in entries {
            if entry.program_name.to_lowercase().contains(&prog_lower) {
                let timestamp = entry.install_date.or(entry.link_date);
                hits.push(RawArtifactHit {
                    artifact_type: HitArtifactType::Amcache,
                    source_path: entry
                        .file_path
                        .clone()
                        .unwrap_or_else(|| "amcache".to_owned()),
                    value: format!("Amcache: {}", entry.program_name),
                    timestamp,
                    context: HashMap::new(),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Capability required for each condition
// ---------------------------------------------------------------------------

fn required_capability(condition: &DetectionCondition) -> Option<ProviderCapability> {
    match condition {
        DetectionCondition::RegistryKeyExists(_)
        | DetectionCondition::RegistryValueContains(_, _) => Some(ProviderCapability::RegistryKeys),
        DetectionCondition::FileExists(_) => Some(ProviderCapability::FilePresence),
        DetectionCondition::ServiceExists(_) => Some(ProviderCapability::Services),
        DetectionCondition::EventLogMatch { .. } => Some(ProviderCapability::EventLogs),
        DetectionCondition::PrefetchMatch(_) => Some(ProviderCapability::PrefetchEntries),
        DetectionCondition::AmcacheMatch(_) => Some(ProviderCapability::AmcacheEntries),
        DetectionCondition::NetworkIndicator { .. } => None, // informational only
    }
}

// ---------------------------------------------------------------------------
// Single-rule evaluation
// ---------------------------------------------------------------------------

/// Evaluate a single [`DetectionRule`] against a provider.
///
/// Returns `Some(Finding)` when at least one condition matches, `None`
/// otherwise.  Conditions whose required capability is not advertised by
/// the provider are silently skipped.
pub fn evaluate_rule(rule: &DetectionRule, provider: &dyn ArtifactProvider) -> Option<Finding> {
    let caps = provider.capabilities();
    let mut hits: Vec<RawArtifactHit> = Vec::new();

    for condition in &rule.conditions {
        // Skip conditions whose capability is not advertised.
        if let Some(cap) = required_capability(condition) {
            if !caps.contains(&cap) {
                continue;
            }
        }

        match condition {
            DetectionCondition::RegistryKeyExists(path) => {
                eval_registry_key_exists(path, provider, &mut hits);
            }
            DetectionCondition::RegistryValueContains(path, substring) => {
                eval_registry_value_contains(path, substring, provider, &mut hits);
            }
            DetectionCondition::FileExists(pattern) => {
                eval_file_exists(pattern, provider, &mut hits);
            }
            DetectionCondition::ServiceExists(name) => {
                eval_service_exists(name, provider, &mut hits);
            }
            DetectionCondition::EventLogMatch {
                event_id,
                provider: prov_name,
                log_file,
            } => {
                eval_event_log_match(*event_id, prov_name, log_file, provider, &mut hits);
            }
            DetectionCondition::PrefetchMatch(executable) => {
                eval_prefetch_match(executable, provider, &mut hits);
            }
            DetectionCondition::AmcacheMatch(program) => {
                eval_amcache_match(program, provider, &mut hits);
            }
            DetectionCondition::NetworkIndicator { domains, ports } => {
                tracing::debug!(
                    rule_id = %rule.id,
                    ?domains,
                    ?ports,
                    "network indicator condition (informational only)"
                );
            }
        }
    }

    if hits.is_empty() {
        return None;
    }

    let first_seen = hits.iter().filter_map(|h| h.timestamp).min();
    let last_seen = hits.iter().filter_map(|h| h.timestamp).max();

    Some(Finding {
        id: uuid::Uuid::new_v4().to_string(),
        tool_name: rule.tool_name.clone(),
        category: rule.category.clone(),
        artifacts: hits,
        first_seen,
        last_seen,
        detection_source: DetectionSource::LolrmmRule(rule.source_file.clone()),
    })
}

// ---------------------------------------------------------------------------
// Multi-rule evaluation
// ---------------------------------------------------------------------------

/// Evaluate all rules against a provider, returning findings for rules
/// that matched at least one condition.
pub fn evaluate_all(rules: &[DetectionRule], provider: &dyn ArtifactProvider) -> Vec<Finding> {
    rules
        .iter()
        .filter_map(|rule| evaluate_rule(rule, provider))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RemoteAccessCategory;
    use crate::providers::{FileEntry, MockArtifactProvider, ProviderCapability};
    use crate::rules::detection_rule::{DetectionCondition, DetectionRule};

    /// Helper: create a TeamViewer-like rule with registry + file + prefetch conditions.
    fn teamviewer_rule() -> DetectionRule {
        DetectionRule {
            id: "lolrmm:teamviewer".into(),
            tool_name: "TeamViewer".into(),
            category: RemoteAccessCategory::CommercialRmm,
            conditions: vec![
                DetectionCondition::RegistryKeyExists(r"HKLM\SOFTWARE\TeamViewer".into()),
                DetectionCondition::FileExists(r"C:\Program Files\TeamViewer\*".into()),
                DetectionCondition::PrefetchMatch("TEAMVIEWER.EXE".into()),
            ],
            source_file: "teamviewer.yaml".into(),
        }
    }

    #[test]
    fn test_evaluate_no_match() {
        let rule = teamviewer_rule();
        let mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::RegistryKeys,
                ProviderCapability::FilePresence,
                ProviderCapability::PrefetchEntries,
            ],
            ..MockArtifactProvider::default()
        };

        let result = evaluate_rule(&rule, &mock);
        assert!(result.is_none(), "empty mock should produce no finding");
    }

    #[test]
    fn test_evaluate_registry_match() {
        let rule = teamviewer_rule();
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::RegistryKeys,
                ProviderCapability::FilePresence,
                ProviderCapability::PrefetchEntries,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer", true);

        let result = evaluate_rule(&rule, &mock);
        assert!(result.is_some(), "should produce a finding");

        let finding = result.expect("already checked");
        assert_eq!(finding.tool_name, "TeamViewer");
        assert_eq!(finding.category, RemoteAccessCategory::CommercialRmm);
        assert_eq!(finding.artifacts.len(), 1);
        assert_eq!(
            finding.artifacts[0].artifact_type,
            HitArtifactType::RegistryKey
        );
        assert_eq!(
            finding.detection_source,
            DetectionSource::LolrmmRule("teamviewer.yaml".into())
        );
    }

    #[test]
    fn test_evaluate_multiple_hits() {
        let rule = teamviewer_rule();
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::RegistryKeys,
                ProviderCapability::FilePresence,
                ProviderCapability::PrefetchEntries,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer", true);
        mock.add_file(
            r"C:\Program Files\TeamViewer\*",
            FileEntry {
                path: r"C:\Program Files\TeamViewer\TeamViewer.exe".into(),
                size: Some(50_000_000),
                created: Some(1_700_000_000),
                modified: Some(1_700_100_000),
            },
        );

        let result = evaluate_rule(&rule, &mock);
        assert!(result.is_some(), "should produce a finding");

        let finding = result.expect("already checked");
        assert_eq!(finding.artifacts.len(), 2);

        // first_seen should come from the file's created timestamp.
        assert_eq!(finding.first_seen, Some(1_700_000_000));
        assert_eq!(finding.last_seen, Some(1_700_000_000));
    }

    #[test]
    fn test_evaluate_skips_unavailable_capabilities() {
        let rule = teamviewer_rule();
        // Only provide registry capability — file + prefetch should be skipped.
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer", true);

        let result = evaluate_rule(&rule, &mock);
        assert!(result.is_some(), "should still match via registry");

        let finding = result.expect("already checked");
        // Only registry hit — file and prefetch were skipped.
        assert_eq!(finding.artifacts.len(), 1);
        assert_eq!(
            finding.artifacts[0].artifact_type,
            HitArtifactType::RegistryKey
        );
    }

    #[test]
    fn test_evaluate_all_multiple_rules() {
        let tv_rule = teamviewer_rule();
        let anydesk_rule = DetectionRule {
            id: "lolrmm:anydesk".into(),
            tool_name: "AnyDesk".into(),
            category: RemoteAccessCategory::CommercialRmm,
            conditions: vec![DetectionCondition::RegistryKeyExists(
                r"HKLM\SOFTWARE\Clients\Media\AnyDesk".into(),
            )],
            source_file: "anydesk.yaml".into(),
        };

        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };
        // Only TeamViewer registry key exists.
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer", true);

        let findings = evaluate_all(&[tv_rule, anydesk_rule], &mock);
        assert_eq!(findings.len(), 1, "only TeamViewer should match");
        assert_eq!(findings[0].tool_name, "TeamViewer");
    }
}
