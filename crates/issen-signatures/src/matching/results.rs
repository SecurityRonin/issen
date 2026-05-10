// Scan match results and aggregation.
//
// Provides a unified result type that normalizes matches from all engines
// (YARA, Sigma, Hash IOC, Network IOC, STIX) into a common format.

use std::fmt;

/// The engine that produced a scan result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchSource {
    Yara,
    Sigma,
    HashIoc,
    NetworkIoc,
    Stix,
}

impl fmt::Display for MatchSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yara => write!(f, "YARA"),
            Self::Sigma => write!(f, "Sigma"),
            Self::HashIoc => write!(f, "Hash IOC"),
            Self::NetworkIoc => write!(f, "Network IOC"),
            Self::Stix => write!(f, "STIX"),
        }
    }
}

/// Severity level for a scan finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parse a severity string (case-insensitive).
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Informational,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "informational"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// A single scan finding from any engine.
#[derive(Debug, Clone)]
pub struct ScanFinding {
    /// Which engine produced this finding.
    pub source: MatchSource,
    /// Severity of the finding.
    pub severity: Severity,
    /// Name of the rule or indicator that matched.
    pub rule_name: String,
    /// Human-readable description.
    pub description: String,
    /// The specific indicator value that matched (hash, IP, domain, etc.).
    pub matched_indicator: Option<String>,
    /// Tags associated with the finding (MITRE ATT&CK, etc.).
    pub tags: Vec<String>,
}

/// Aggregated scan results for a single target (file, event, etc.).
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// What was scanned (file path, event ID, etc.).
    pub target: String,
    /// All findings from all engines.
    pub findings: Vec<ScanFinding>,
}

impl ScanReport {
    /// Create a new empty report for a target.
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            findings: Vec::new(),
        }
    }

    /// Add a finding to the report.
    pub fn add_finding(&mut self, finding: ScanFinding) {
        self.findings.push(finding);
    }

    /// Total number of findings.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Whether any findings were detected.
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }

    /// The highest severity across all findings, or None if empty.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Filter findings by source engine.
    pub fn findings_by_source(&self, source: MatchSource) -> Vec<&ScanFinding> {
        self.findings
            .iter()
            .filter(|f| f.source == source)
            .collect()
    }

    /// Filter findings at or above a severity threshold.
    pub fn findings_at_or_above(&self, threshold: Severity) -> Vec<&ScanFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= threshold)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding(source: MatchSource, severity: Severity, name: &str) -> ScanFinding {
        ScanFinding {
            source,
            severity,
            rule_name: name.to_string(),
            description: format!("Test finding: {}", name),
            matched_indicator: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn test_empty_report() {
        let report = ScanReport::new("/tmp/test.bin");
        assert_eq!(report.target, "/tmp/test.bin");
        assert_eq!(report.finding_count(), 0);
        assert!(!report.has_findings());
        assert!(report.max_severity().is_none());
    }

    #[test]
    fn test_add_finding() {
        let mut report = ScanReport::new("test");
        report.add_finding(sample_finding(MatchSource::Yara, Severity::High, "rule1"));
        assert_eq!(report.finding_count(), 1);
        assert!(report.has_findings());
    }

    #[test]
    fn test_max_severity() {
        let mut report = ScanReport::new("test");
        report.add_finding(sample_finding(MatchSource::Yara, Severity::Low, "r1"));
        report.add_finding(sample_finding(MatchSource::Sigma, Severity::Critical, "r2"));
        report.add_finding(sample_finding(MatchSource::HashIoc, Severity::Medium, "r3"));
        assert_eq!(report.max_severity(), Some(Severity::Critical));
    }

    #[test]
    fn test_findings_by_source() {
        let mut report = ScanReport::new("test");
        report.add_finding(sample_finding(MatchSource::Yara, Severity::High, "yara1"));
        report.add_finding(sample_finding(MatchSource::Sigma, Severity::Low, "sigma1"));
        report.add_finding(sample_finding(MatchSource::Yara, Severity::Medium, "yara2"));

        let yara_findings = report.findings_by_source(MatchSource::Yara);
        assert_eq!(yara_findings.len(), 2);

        let sigma_findings = report.findings_by_source(MatchSource::Sigma);
        assert_eq!(sigma_findings.len(), 1);

        let hash_findings = report.findings_by_source(MatchSource::HashIoc);
        assert_eq!(hash_findings.len(), 0);
    }

    #[test]
    fn test_findings_at_or_above() {
        let mut report = ScanReport::new("test");
        report.add_finding(sample_finding(
            MatchSource::Yara,
            Severity::Informational,
            "r1",
        ));
        report.add_finding(sample_finding(MatchSource::Sigma, Severity::High, "r2"));
        report.add_finding(sample_finding(
            MatchSource::HashIoc,
            Severity::Critical,
            "r3",
        ));
        report.add_finding(sample_finding(MatchSource::NetworkIoc, Severity::Low, "r4"));
        report.add_finding(sample_finding(MatchSource::Stix, Severity::Medium, "r5"));

        let high_plus = report.findings_at_or_above(Severity::High);
        assert_eq!(high_plus.len(), 2); // High + Critical

        let all = report.findings_at_or_above(Severity::Informational);
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Informational);
    }

    #[test]
    fn test_severity_from_str_lossy() {
        assert_eq!(Severity::from_str_lossy("critical"), Severity::Critical);
        assert_eq!(Severity::from_str_lossy("HIGH"), Severity::High);
        assert_eq!(Severity::from_str_lossy("Medium"), Severity::Medium);
        assert_eq!(Severity::from_str_lossy("low"), Severity::Low);
        assert_eq!(
            Severity::from_str_lossy("informational"),
            Severity::Informational
        );
        assert_eq!(Severity::from_str_lossy("unknown"), Severity::Informational);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Critical), "critical");
        assert_eq!(format!("{}", Severity::Informational), "informational");
    }

    #[test]
    fn test_match_source_display() {
        assert_eq!(format!("{}", MatchSource::Yara), "YARA");
        assert_eq!(format!("{}", MatchSource::Sigma), "Sigma");
        assert_eq!(format!("{}", MatchSource::HashIoc), "Hash IOC");
        assert_eq!(format!("{}", MatchSource::NetworkIoc), "Network IOC");
        assert_eq!(format!("{}", MatchSource::Stix), "STIX");
    }

    #[test]
    fn test_finding_with_indicator_and_tags() {
        let finding = ScanFinding {
            source: MatchSource::HashIoc,
            severity: Severity::Critical,
            rule_name: "malware_hash".to_string(),
            description: "Known malware hash".to_string(),
            matched_indicator: Some("e3b0c44298fc1c14".to_string()),
            tags: vec!["malware".to_string(), "emotet".to_string()],
        };
        assert_eq!(
            finding.matched_indicator.as_deref(),
            Some("e3b0c44298fc1c14")
        );
        assert_eq!(finding.tags.len(), 2);
    }
}
