use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// Broad classification of what an intel item *is*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelKind {
    /// Byte/content matching (YARA, binary signatures)
    ContentSignature,
    /// Log/event matching (Sigma, Sigma correlation)
    EventRule,
    /// Packet/protocol signature (Suricata)
    NetworkSignature,
    /// IP, domain, URL, hash, email, mutex, JA3/JA4, etc.
    AtomicIndicator,
    /// Actor/malware/campaign/technique graph (STIX, ATT&CK, MISP events/galaxies)
    IntelGraph,
    /// False-positive suppression, taxonomies, forensic catalogs (MISP warninglists)
    ReferenceDataset,
    /// Proprietary `Issen` cross-artifact correlation rule
    CorrelationRule,
}

/// Fine-grained type for an `AtomicIndicator`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    IpAddr,
    Domain,
    Url,
    FileHash,
    Email,
    Mutex,
    Ja3Fingerprint,
    Ja4Fingerprint,
    TlsCertHash,
    Cve,
    RegistryKey,
    FilePath,
    /// Catch-all for unrecognised Zeek Intel types or future extensions.
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Sigma,
    Yara,
    Suricata,
    Zeek,
    Artifact,
    Memory,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Command,
    Network,
    Process,
    Artifact,
    Alert,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectRef {
    Host(String),
    Process(u32),
    Session(String),
    Socket(String),
    Artifact(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub source: EvidenceSource,
    pub kind: EvidenceKind,
    pub subject: Option<SubjectRef>,
    pub timestamp: Option<Timestamp>,
    pub attrs: BTreeMap<String, String>,
    pub tags: Vec<String>,
}

impl Evidence {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        source: EvidenceSource,
        kind: EvidenceKind,
        subject: Option<SubjectRef>,
    ) -> Self {
        Self {
            id: id.into(),
            source,
            kind,
            subject,
            timestamp: None,
            attrs: BTreeMap::new(),
            tags: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub fn with_timestamp(mut self, ts: Timestamp) -> Self {
        self.timestamp = Some(ts);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleClause {
    pub source: EvidenceSource,
    #[serde(default)]
    pub required_tag: String,
    #[serde(default)]
    pub attr_predicates: Vec<RuleAttrPredicate>,
}

impl RuleClause {
    #[must_use]
    pub fn tagged(source: EvidenceSource, required_tag: impl Into<String>) -> Self {
        Self {
            source,
            required_tag: required_tag.into(),
            attr_predicates: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleAttrPredicate {
    Equals { key: String, value: String },
    Contains { key: String, value: String },
    AnyOf { key: String, values: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PivotRule {
    pub id: String,
    pub title: String,
    pub severity: String,
    #[serde(default)]
    pub description: Option<String>,
    pub within_seconds: Option<i64>,
    #[serde(default)]
    pub references: Vec<String>,
    pub clauses: Vec<RuleClause>,
    /// Short one-line summary template (static string for now).
    #[serde(default)]
    pub summary_template: Option<String>,
    /// Explanation template for analyst context (static string for now).
    #[serde(default)]
    pub explanation_template: Option<String>,
    /// Default confidence 0–100 for findings from this rule.
    #[serde(default)]
    pub default_confidence: u8,
    /// Assertion level for findings from this rule.
    #[serde(default)]
    pub assertion_level: AssertionLevel,
}

pub type CorrelationRule = PivotRule;

/// How confidently the finding can be asserted based on the evidence type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AssertionLevel {
    /// Directly observed in artefacts — no inference required.
    Observed,
    /// Multiple independent evidence sources corroborate the finding.
    #[default]
    Correlated,
    /// Inferred from circumstantial evidence; lower certainty.
    Inferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub evidence_ids: Vec<String>,
    /// Short one-line human summary of the finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Calibrated explanation text for the analyst.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// Analyst confidence 0–100.
    #[serde(default)]
    pub confidence: u8,
    /// Assertion level reflecting how the finding was derived.
    #[serde(default)]
    pub assertion_level: AssertionLevel,
    /// Human-readable evidence lines for display.
    #[serde(default)]
    pub evidence_rendered: Vec<String>,
}

pub type CorrelatedFinding = Finding;

#[cfg(test)]
mod finding_model_tests {
    use super::*;

    // ── WS-1 RED: Finding must carry summary, explanation, confidence,
    //             assertion_level, and evidence_rendered ──────────────────────

    #[test]
    fn finding_has_summary_field() {
        let f = Finding {
            rule_id: "test.rule".into(),
            title: "Test".into(),
            severity: "high".into(),
            evidence_ids: vec![],
            summary: Some("Rootkit concealing XMRig miner".into()),
            explanation: None,
            confidence: 85,
            assertion_level: AssertionLevel::Correlated,
            evidence_rendered: vec![],
        };
        assert_eq!(f.summary.as_deref(), Some("Rootkit concealing XMRig miner"));
    }

    #[test]
    fn finding_has_confidence_field() {
        let f = Finding {
            rule_id: "test.rule".into(),
            title: "Test".into(),
            severity: "high".into(),
            evidence_ids: vec![],
            summary: None,
            explanation: None,
            confidence: 92,
            assertion_level: AssertionLevel::Observed,
            evidence_rendered: vec![],
        };
        assert_eq!(f.confidence, 92);
    }

    #[test]
    fn finding_has_assertion_level_field() {
        let f = Finding {
            rule_id: "test.rule".into(),
            title: "Test".into(),
            severity: "medium".into(),
            evidence_ids: vec![],
            summary: None,
            explanation: None,
            confidence: 60,
            assertion_level: AssertionLevel::Inferred,
            evidence_rendered: vec![],
        };
        assert!(matches!(f.assertion_level, AssertionLevel::Inferred));
    }

    #[test]
    fn assertion_level_variants_exist() {
        let _ = (
            AssertionLevel::Observed,
            AssertionLevel::Correlated,
            AssertionLevel::Inferred,
        );
    }

    #[test]
    fn finding_has_evidence_rendered_field() {
        let lines = vec![
            "LD_PRELOAD: /lib/x86_64-linux-gnu/libymv.so.3".to_string(),
            r#"PID 977 "top" [thread: libuv-worker]"#.to_string(),
        ];
        let f = Finding {
            rule_id: "test.rule".into(),
            title: "Test".into(),
            severity: "high".into(),
            evidence_ids: vec!["rk-1".into(), "proc-1".into()],
            summary: None,
            explanation: None,
            confidence: 90,
            assertion_level: AssertionLevel::Correlated,
            evidence_rendered: lines.clone(),
        };
        assert_eq!(f.evidence_rendered, lines);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    GitArchive,
    SuricataUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedSpec {
    pub name: String,
    pub kind: FeedKind,
    pub url: String,
}

impl FeedSpec {
    #[must_use]
    pub fn default_registry() -> Vec<Self> {
        vec![
            Self {
                name: "sigmahq/sigma".into(),
                kind: FeedKind::GitArchive,
                url: "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip".into(),
            },
            Self {
                name: "neo23x0/signature-base".into(),
                kind: FeedKind::GitArchive,
                url: "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
                    .into(),
            },
            Self {
                name: "et/open".into(),
                kind: FeedKind::SuricataUpdate,
                url: "https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz".into(),
            },
            Self {
                name: "zeek/packages".into(),
                kind: FeedKind::GitArchive,
                url: "https://github.com/zeek/packages/archive/refs/heads/master.zip".into(),
            },
        ]
    }
}
