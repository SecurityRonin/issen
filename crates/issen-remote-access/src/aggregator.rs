//! Findings aggregator — deduplicates and merges raw findings by tool.
//!
//! When multiple detection rules fire for the same remote access tool,
//! this module collapses them into a single [`Finding`] per tool, combining
//! artifacts and recomputing temporal bounds.

use std::collections::HashMap;

use crate::model::Finding;

/// Merge duplicate findings that share the same tool and category.
///
/// Grouping key: `"{tool_name}:{category:?}"`.
///
/// For each group the merge:
/// - Combines all `artifacts` into one vec
/// - Recomputes `first_seen` as the minimum across all findings
/// - Recomputes `last_seen`  as the maximum across all findings
/// - Keeps the id and detection_source from the first finding in the group
pub fn merge_findings(findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return Vec::new();
    }

    let mut groups: HashMap<String, Finding> = HashMap::new();
    let mut insertion_order: Vec<String> = Vec::new();

    for finding in findings {
        let key = format!("{}:{:?}", finding.tool_name, finding.category);

        if let Some(existing) = groups.get_mut(&key) {
            // Merge artifacts
            existing.artifacts.extend(finding.artifacts);

            // Recompute first_seen (min)
            existing.first_seen = match (existing.first_seen, finding.first_seen) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };

            // Recompute last_seen (max)
            existing.last_seen = match (existing.last_seen, finding.last_seen) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
        } else {
            insertion_order.push(key.clone());
            groups.insert(key, finding);
        }
    }

    // Preserve stable ordering
    insertion_order
        .into_iter()
        .filter_map(|key| groups.remove(&key))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::model::{
        DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
    };

    use super::*;

    /// Helper: create a finding for a given tool with one artifact.
    fn make_finding(tool: &str, ts: Option<i64>, source: &str) -> Finding {
        Finding {
            id: format!("id-{tool}-{source}"),
            tool_name: tool.to_string(),
            category: RemoteAccessCategory::CommercialRmm,
            artifacts: vec![RawArtifactHit {
                artifact_type: HitArtifactType::RegistryKey,
                source_path: format!("HKLM\\SOFTWARE\\{tool}"),
                value: format!("{tool} key from {source}"),
                timestamp: ts,
                context: HashMap::new(),
            }],
            first_seen: ts,
            last_seen: ts,
            detection_source: DetectionSource::LolrmmRule(format!("{source}.yaml")),
        }
    }

    #[test]
    fn test_merge_same_tool() {
        let findings = vec![
            make_finding("TeamViewer", Some(1000), "rule-a"),
            make_finding("TeamViewer", Some(2000), "rule-b"),
        ];

        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);

        let f = &merged[0];
        assert_eq!(f.tool_name, "TeamViewer");
        assert_eq!(f.artifacts.len(), 2);
        assert_eq!(f.first_seen, Some(1000));
        assert_eq!(f.last_seen, Some(2000));
    }

    #[test]
    fn test_merge_different_tools() {
        let findings = vec![
            make_finding("TeamViewer", Some(1000), "rule-a"),
            make_finding("AnyDesk", Some(2000), "rule-b"),
        ];

        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].tool_name, "TeamViewer");
        assert_eq!(merged[1].tool_name, "AnyDesk");
    }

    #[test]
    fn test_merge_no_timestamps() {
        let findings = vec![
            make_finding("TeamViewer", None, "rule-a"),
            make_finding("TeamViewer", Some(5000), "rule-b"),
        ];

        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);

        let f = &merged[0];
        assert_eq!(f.first_seen, Some(5000));
        assert_eq!(f.last_seen, Some(5000));
    }

    #[test]
    fn test_merge_empty() {
        let merged = merge_findings(Vec::new());
        assert!(merged.is_empty());
    }
}
