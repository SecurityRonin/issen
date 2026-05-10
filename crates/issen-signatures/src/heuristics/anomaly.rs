//! Anomaly data model and index for forensic heuristic findings.

use std::collections::HashMap;
use std::fmt;

use crate::matching::results::Severity;

/// Category of forensic anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyCategory {
    Timestomping,
    SuspiciousLocation,
    ExtensionMismatch,
    HighEntropy,
    SecureDeletion,
    RansomwarePattern,
    JournalTampering,
    GhostFile,
    SuspiciousSize,
    MftIntegrity,
}

impl fmt::Display for AnomalyCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timestomping => write!(f, "Timestomping"),
            Self::SuspiciousLocation => write!(f, "Suspicious Location"),
            Self::ExtensionMismatch => write!(f, "Extension Mismatch"),
            Self::HighEntropy => write!(f, "High Entropy"),
            Self::SecureDeletion => write!(f, "Secure Deletion"),
            Self::RansomwarePattern => write!(f, "Ransomware Pattern"),
            Self::JournalTampering => write!(f, "Journal Tampering"),
            Self::GhostFile => write!(f, "Ghost File"),
            Self::SuspiciousSize => write!(f, "Suspicious Size"),
            Self::MftIntegrity => write!(f, "MFT Integrity"),
        }
    }
}

impl AnomalyCategory {
    /// String representation for serialization.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timestomping => "timestomping",
            Self::SuspiciousLocation => "suspicious_location",
            Self::ExtensionMismatch => "extension_mismatch",
            Self::HighEntropy => "high_entropy",
            Self::SecureDeletion => "secure_deletion",
            Self::RansomwarePattern => "ransomware_pattern",
            Self::JournalTampering => "journal_tampering",
            Self::GhostFile => "ghost_file",
            Self::SuspiciousSize => "suspicious_size",
            Self::MftIntegrity => "mft_integrity",
        }
    }
}

/// A single heuristic finding for a file or directory.
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub severity: Severity,
    pub category: AnomalyCategory,
    /// Stable rule identifier (e.g., "HEUR-TS-001").
    pub rule_id: &'static str,
    pub description: String,
    /// Specific values that triggered detection.
    pub evidence: String,
}

/// Optional configuration for heuristic checks.
#[derive(Default)]
pub struct HeuristicsConfig {
    /// If set, HEUR-TS-004 checks for `$SI` timestamps predating this date.
    pub volume_created: Option<chrono::DateTime<chrono::Utc>>,
}

/// Lookup structure for anomalies by arena index.
#[derive(Debug, Default)]
pub struct AnomalyIndex {
    entries: HashMap<usize, Vec<Anomaly>>,
}

impl AnomalyIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, idx: usize, anomaly: Anomaly) {
        self.entries.entry(idx).or_default().push(anomaly);
    }

    #[must_use]
    pub fn for_node(&self, idx: usize) -> &[Anomaly] {
        self.entries.get(&idx).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn max_severity(&self, idx: usize) -> Option<Severity> {
        self.entries
            .get(&idx)
            .and_then(|anomalies| anomalies.iter().map(|a| a.severity).max())
    }

    #[must_use]
    pub fn flagged_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn flagged_entries(&self) -> Vec<usize> {
        let mut entries: Vec<(usize, Severity)> = self
            .entries
            .iter()
            .filter_map(|(&idx, anomalies)| {
                anomalies.iter().map(|a| a.severity).max().map(|s| (idx, s))
            })
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries.into_iter().map(|(idx, _)| idx).collect()
    }

    pub fn merge(&mut self, other: Self) {
        for (idx, anomalies) in other.entries {
            self.entries.entry(idx).or_default().extend(anomalies);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_anomaly(severity: Severity, rule_id: &'static str) -> Anomaly {
        Anomaly {
            severity,
            category: AnomalyCategory::Timestomping,
            rule_id,
            description: format!("Test: {rule_id}"),
            evidence: String::new(),
        }
    }

    #[test]
    fn empty_index_has_no_flagged() {
        let idx = AnomalyIndex::new();
        assert_eq!(idx.flagged_count(), 0);
        assert!(idx.flagged_entries().is_empty());
    }

    #[test]
    fn for_node_returns_empty_slice_for_unknown() {
        let idx = AnomalyIndex::new();
        assert!(idx.for_node(42).is_empty());
    }

    #[test]
    fn add_and_retrieve_anomaly() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::High, "HEUR-TS-001"));
        assert_eq!(idx.for_node(10).len(), 1);
        assert_eq!(idx.for_node(10)[0].rule_id, "HEUR-TS-001");
    }

    #[test]
    fn multiple_anomalies_per_node() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::Low, "HEUR-TS-003"));
        idx.add(10, make_anomaly(Severity::High, "HEUR-TS-001"));
        assert_eq!(idx.for_node(10).len(), 2);
    }

    #[test]
    fn max_severity_returns_highest() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::Low, "HEUR-TS-003"));
        idx.add(10, make_anomaly(Severity::High, "HEUR-TS-001"));
        assert_eq!(idx.max_severity(10), Some(Severity::High));
    }

    #[test]
    fn max_severity_none_for_unflagged() {
        let idx = AnomalyIndex::new();
        assert!(idx.max_severity(99).is_none());
    }

    #[test]
    fn flagged_count_distinct_nodes() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::High, "HEUR-TS-001"));
        idx.add(10, make_anomaly(Severity::Low, "HEUR-TS-003"));
        idx.add(20, make_anomaly(Severity::Medium, "HEUR-LOC-001"));
        assert_eq!(idx.flagged_count(), 2);
    }

    #[test]
    fn flagged_entries_sorted_by_severity() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::Low, "r1"));
        idx.add(20, make_anomaly(Severity::Critical, "r2"));
        idx.add(30, make_anomaly(Severity::Medium, "r3"));
        let entries = idx.flagged_entries();
        assert_eq!(entries, vec![20, 30, 10]);
    }

    #[test]
    fn merge_combines_indices() {
        let mut a = AnomalyIndex::new();
        a.add(10, make_anomaly(Severity::High, "r1"));
        let mut b = AnomalyIndex::new();
        b.add(10, make_anomaly(Severity::Low, "r2"));
        b.add(20, make_anomaly(Severity::Medium, "r3"));
        a.merge(b);
        assert_eq!(a.for_node(10).len(), 2);
        assert_eq!(a.for_node(20).len(), 1);
        assert_eq!(a.flagged_count(), 2);
    }

    #[test]
    fn category_as_str() {
        assert_eq!(AnomalyCategory::Timestomping.as_str(), "timestomping");
        assert_eq!(
            AnomalyCategory::SuspiciousLocation.as_str(),
            "suspicious_location"
        );
        assert_eq!(AnomalyCategory::GhostFile.as_str(), "ghost_file");
    }

    #[test]
    fn default_config_has_no_volume_created() {
        let config = HeuristicsConfig::default();
        assert!(config.volume_created.is_none());
    }

    #[test]
    fn anomaly_category_display() {
        assert_eq!(format!("{}", AnomalyCategory::Timestomping), "Timestomping");
        assert_eq!(
            format!("{}", AnomalyCategory::SuspiciousLocation),
            "Suspicious Location"
        );
        assert_eq!(format!("{}", AnomalyCategory::GhostFile), "Ghost File");
    }
}
