use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// What kind of artifact source produced this hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HitArtifactType {
    RegistryKey,
    RegistryValue,
    FilePresence,
    FileContent,
    EventLog,
    Service,
    Prefetch,
    Amcache,
    ShimCache,
    ScheduledTask,
    NetworkIndicator,
    FirewallRule,
    LnkFile,
    JumplistEntry,
}

/// A single artifact observation — one registry key, one file, one event log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawArtifactHit {
    /// What kind of artifact.
    pub artifact_type: HitArtifactType,
    /// Where we found it (hive path, file path, log channel).
    pub source_path: String,
    /// What we found (key path, filename, event data).
    pub value: String,
    /// Nanosecond timestamp if available.
    pub timestamp: Option<i64>,
    /// Additional key-value context.
    pub context: HashMap<String, String>,
}

/// Detection categories for remote access findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RemoteAccessCategory {
    CommercialRmm,
    BuiltInRemoteAccess,
    VpnZtna,
    Tunneling,
    LateralMovement,
    C2Framework,
    WebShell,
    FirewallConfig,
    HardwareRemote,
}

impl std::fmt::Display for RemoteAccessCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommercialRmm => write!(f, "Commercial RMM"),
            Self::BuiltInRemoteAccess => write!(f, "Built-in Remote Access"),
            Self::VpnZtna => write!(f, "VPN/ZTNA"),
            Self::Tunneling => write!(f, "Tunneling"),
            Self::LateralMovement => write!(f, "Lateral Movement"),
            Self::C2Framework => write!(f, "C2 Framework"),
            Self::WebShell => write!(f, "Web Shell"),
            Self::FirewallConfig => write!(f, "Firewall Config"),
            Self::HardwareRemote => write!(f, "Hardware Remote"),
        }
    }
}

/// How was this finding detected?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionSource {
    /// Matched a LOLRMM or custom YAML rule definition.
    LolrmmRule(String),
    /// Matched a Sigma detection rule.
    SigmaRule(String),
    /// Matched a YARA detection rule.
    YaraRule(String),
    /// Detected by a behavioral category scanner.
    CategoryScanner(String),
}

/// An aggregated finding — one per detected tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Tool name (e.g., "`TeamViewer`", "`PsExec`").
    pub tool_name: String,
    /// Detection category.
    pub category: RemoteAccessCategory,
    /// All raw evidence for this tool.
    pub artifacts: Vec<RawArtifactHit>,
    /// Earliest timestamp across artifacts.
    pub first_seen: Option<i64>,
    /// Latest timestamp across artifacts.
    pub last_seen: Option<i64>,
    /// What found this.
    pub detection_source: DetectionSource,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_display() {
        assert_eq!(
            format!("{}", RemoteAccessCategory::CommercialRmm),
            "Commercial RMM"
        );
        assert_eq!(
            format!("{}", RemoteAccessCategory::LateralMovement),
            "Lateral Movement"
        );
        assert_eq!(format!("{}", RemoteAccessCategory::VpnZtna), "VPN/ZTNA");
    }

    #[test]
    fn test_finding_construction() {
        let finding = Finding {
            id: "test-uuid".into(),
            tool_name: "TeamViewer".into(),
            category: RemoteAccessCategory::CommercialRmm,
            artifacts: vec![RawArtifactHit {
                artifact_type: HitArtifactType::RegistryKey,
                source_path: r"HKLM\SOFTWARE\TeamViewer".into(),
                value: "TeamViewer key exists".into(),
                timestamp: None,
                context: HashMap::new(),
            }],
            first_seen: None,
            last_seen: None,
            detection_source: DetectionSource::LolrmmRule("teamviewer.yaml".into()),
        };
        assert_eq!(finding.tool_name, "TeamViewer");
        assert_eq!(finding.category, RemoteAccessCategory::CommercialRmm);
        assert_eq!(finding.artifacts.len(), 1);
    }

    #[test]
    fn test_finding_serde_roundtrip() {
        let finding = Finding {
            id: "uuid-001".into(),
            tool_name: "AnyDesk".into(),
            category: RemoteAccessCategory::CommercialRmm,
            artifacts: vec![RawArtifactHit {
                artifact_type: HitArtifactType::FilePresence,
                source_path: r"C:\Program Files\AnyDesk\AnyDesk.exe".into(),
                value: "AnyDesk executable found".into(),
                timestamp: Some(1_700_000_000_000_000_000),
                context: HashMap::from([("size".into(), "12345".into())]),
            }],
            first_seen: Some(1_700_000_000_000_000_000),
            last_seen: Some(1_700_000_000_000_000_000),
            detection_source: DetectionSource::LolrmmRule("anydesk.yaml".into()),
        };

        let json = serde_json::to_string(&finding).expect("serialize");
        let deserialized: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.tool_name, "AnyDesk");
        assert_eq!(deserialized.artifacts.len(), 1);
        assert_eq!(deserialized.first_seen, Some(1_700_000_000_000_000_000));
    }

    #[test]
    fn test_raw_artifact_hit_with_context() {
        let hit = RawArtifactHit {
            artifact_type: HitArtifactType::EventLog,
            source_path: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
                .into(),
            value: "EventID 21: Session logon".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            context: HashMap::from([
                ("event_id".into(), "21".into()),
                ("user".into(), r"DOMAIN\admin".into()),
                ("source_ip".into(), "10.0.0.5".into()),
            ]),
        };
        assert_eq!(hit.context.get("event_id"), Some(&"21".to_string()));
        assert_eq!(hit.context.get("source_ip"), Some(&"10.0.0.5".to_string()));
    }

    #[test]
    fn test_detection_source_variants() {
        let sources = vec![
            DetectionSource::LolrmmRule("teamviewer.yaml".into()),
            DetectionSource::SigmaRule("sigma-rule-123".into()),
            DetectionSource::YaraRule("webshell_detect".into()),
            DetectionSource::CategoryScanner("builtin_remote".into()),
        ];
        // All variants should serialize.
        for source in &sources {
            let json = serde_json::to_string(source).expect("serialize");
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_hit_artifact_type_equality() {
        assert_eq!(HitArtifactType::RegistryKey, HitArtifactType::RegistryKey);
        assert_ne!(HitArtifactType::RegistryKey, HitArtifactType::FilePresence);
    }
}
