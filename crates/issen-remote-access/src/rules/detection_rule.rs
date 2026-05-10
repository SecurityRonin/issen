//! Detection rule compiler — transforms LOLRMM definitions into uniform
//! [`DetectionRule`] structs that the evaluator can execute.

use crate::model::RemoteAccessCategory;
use crate::rules::lolrmm::LolrmmDefinition;

// ---------------------------------------------------------------------------
// DetectionCondition
// ---------------------------------------------------------------------------

/// A single atomic condition that a detection rule can check.
#[derive(Debug, Clone)]
pub enum DetectionCondition {
    /// Registry key exists at the given path.
    RegistryKeyExists(String),
    /// Registry value at path contains the given substring.
    RegistryValueContains(String, String),
    /// File exists matching the given path/glob.
    FileExists(String),
    /// A Windows service with the given name exists.
    ServiceExists(String),
    /// An event log entry matches the given criteria.
    EventLogMatch {
        event_id: u32,
        provider: String,
        log_file: String,
    },
    /// A prefetch entry matching the given executable name.
    PrefetchMatch(String),
    /// An Amcache entry matching the given program name.
    AmcacheMatch(String),
    /// Network indicators (domains and/or ports).
    NetworkIndicator {
        domains: Vec<String>,
        ports: Vec<u16>,
    },
}

// ---------------------------------------------------------------------------
// DetectionRule
// ---------------------------------------------------------------------------

/// A compiled detection rule ready for evaluation against an
/// [`ArtifactProvider`](crate::providers::ArtifactProvider).
#[derive(Debug, Clone)]
pub struct DetectionRule {
    /// Unique rule identifier (e.g. `lolrmm:anydesk`).
    pub id: String,
    /// Human-readable tool name (e.g. "`AnyDesk`").
    pub tool_name: String,
    /// Detection category.
    pub category: RemoteAccessCategory,
    /// Conditions to evaluate — any match produces a hit.
    pub conditions: Vec<DetectionCondition>,
    /// Path to the source definition file.
    pub source_file: String,
}

// ---------------------------------------------------------------------------
// Compiler: LOLRMM -> DetectionRule
// ---------------------------------------------------------------------------

/// Compile a [`LolrmmDefinition`] into a [`DetectionRule`].
///
/// Extracts registry, disk, event-log, network, and installation-path
/// artifacts into uniform [`DetectionCondition`] variants.
#[must_use]
pub fn compile_lolrmm(def: &LolrmmDefinition, source_file: &str) -> DetectionRule {
    let mut conditions = Vec::new();

    // -- Artifacts block ----------------------------------------------------
    if let Some(ref artifacts) = def.artifacts {
        // Registry artifacts -> RegistryKeyExists
        if let Some(ref registry) = artifacts.registry {
            for reg in registry {
                if let Some(ref path) = reg.path {
                    if !path.is_empty() {
                        conditions.push(DetectionCondition::RegistryKeyExists(path.clone()));
                    }
                }
            }
        }

        // Disk artifacts -> FileExists
        if let Some(ref disk) = artifacts.disk {
            for d in disk {
                if let Some(ref file) = d.file {
                    if !file.is_empty() {
                        conditions.push(DetectionCondition::FileExists(file.clone()));
                    }
                }
            }
        }

        // Event log artifacts -> EventLogMatch (only when all three fields present)
        if let Some(ref event_logs) = artifacts.event_log {
            for el in event_logs {
                if let (Some(event_id), Some(ref provider), Some(ref log_file)) =
                    (el.event_id, &el.provider_name, &el.log_file)
                {
                    conditions.push(DetectionCondition::EventLogMatch {
                        event_id,
                        provider: provider.clone(),
                        log_file: log_file.clone(),
                    });
                }
            }
        }

        // Network artifacts -> NetworkIndicator (only when domains or ports non-empty)
        if let Some(ref network) = artifacts.network {
            for net in network {
                let domains = net
                    .domains
                    .as_ref()
                    .map(|d| {
                        d.iter()
                            .filter(|s| !s.is_empty())
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let ports: Vec<u16> = net
                    .ports
                    .as_ref()
                    .map(|p| p.iter().filter_map(|s| s.parse::<u16>().ok()).collect())
                    .unwrap_or_default();

                if !domains.is_empty() || !ports.is_empty() {
                    conditions.push(DetectionCondition::NetworkIndicator { domains, ports });
                }
            }
        }
    }

    // -- Details.InstallationPaths -> FileExists ----------------------------
    if let Some(ref details) = def.details {
        for path in &details.installation_paths {
            if !path.is_empty() {
                conditions.push(DetectionCondition::FileExists(path.clone()));
            }
        }
    }

    // -- Category mapping ---------------------------------------------------
    // LOLRMM definitions are always commercial RMM tools.
    let _ = &def.category; // acknowledge field
    let category = RemoteAccessCategory::CommercialRmm;

    // -- Rule ID: lolrmm:{name_lowercase_with_dashes} ----------------------
    let id = format!("lolrmm:{}", def.name.to_lowercase().replace(' ', "-"));

    DetectionRule {
        id,
        tool_name: def.name.clone(),
        category,
        conditions,
        source_file: source_file.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::lolrmm::load_lolrmm_file;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("lolrmm")
    }

    #[test]
    fn test_compile_lolrmm_anydesk() {
        let path = fixtures_dir().join("anydesk.yaml");
        if !path.exists() {
            eprintln!("Skipping test_compile_lolrmm_anydesk: fixture not found");
            return;
        }

        let def = load_lolrmm_file(&path).expect("should parse anydesk.yaml");
        let rule = compile_lolrmm(&def, "anydesk.yaml");

        assert_eq!(rule.id, "lolrmm:anydesk");
        assert_eq!(rule.tool_name, "AnyDesk");
        assert_eq!(rule.category, RemoteAccessCategory::CommercialRmm);
        assert_eq!(rule.source_file, "anydesk.yaml");

        // Should have conditions from registry, disk, event log, network, and installation paths.
        assert!(
            !rule.conditions.is_empty(),
            "AnyDesk should produce at least one condition"
        );

        // Verify we have at least one RegistryKeyExists
        let has_registry = rule.conditions.iter().any(
            |c| matches!(c, DetectionCondition::RegistryKeyExists(p) if p.contains("AnyDesk")),
        );
        assert!(has_registry, "should have AnyDesk registry condition");

        // Verify we have at least one FileExists
        let has_file = rule
            .conditions
            .iter()
            .any(|c| matches!(c, DetectionCondition::FileExists(_)));
        assert!(has_file, "should have file-exists conditions");

        // Verify we have at least one EventLogMatch
        let has_event_log = rule
            .conditions
            .iter()
            .any(|c| matches!(c, DetectionCondition::EventLogMatch { .. }));
        assert!(has_event_log, "should have event-log conditions");

        // Verify we have at least one NetworkIndicator
        let has_network = rule
            .conditions
            .iter()
            .any(|c| matches!(c, DetectionCondition::NetworkIndicator { .. }));
        assert!(has_network, "should have network-indicator conditions");
    }

    #[test]
    fn test_compile_empty_artifacts() {
        let def = LolrmmDefinition {
            name: "EmptyTool".into(),
            category: "RMM".into(),
            description: String::new(),
            details: None,
            artifacts: None,
            detections: None,
            references: None,
            author: None,
            created: None,
            last_modified: None,
            acknowledgement: None,
        };

        let rule = compile_lolrmm(&def, "empty.yaml");

        assert_eq!(rule.id, "lolrmm:emptytool");
        assert_eq!(rule.tool_name, "EmptyTool");
        assert_eq!(rule.category, RemoteAccessCategory::CommercialRmm);
        assert!(
            rule.conditions.is_empty(),
            "empty definition should produce no conditions"
        );
    }
}
