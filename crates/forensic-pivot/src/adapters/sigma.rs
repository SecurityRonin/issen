//! Sigma alert adapter.
//!
//! Converts Sigma tool output (JSON format from sigmac/pySigma/hayabusa)
//! into `Evidence` objects for the `PivotEngine`.

use std::collections::HashMap;
use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;

use crate::evidence::{Evidence, EvidenceKind, EvidenceSource};

/// A parsed Sigma alert from hayabusa/pySigma JSON output.
#[derive(Debug, Clone)]
pub struct SigmaAlert {
    pub rule_id: String,
    pub title: String,
    pub level: String,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub timestamp: Option<String>,
    pub extra: HashMap<String, Value>,
}

#[derive(Deserialize)]
struct RawSigma {
    rule_id: String,
    title: String,
    level: String,
    process_name: Option<String>,
    command_line: Option<String>,
    timestamp: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl SigmaAlert {
    /// Parse a Sigma alert from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let raw: RawSigma = serde_json::from_str(json)?;
        Ok(Self {
            rule_id: raw.rule_id,
            title: raw.title,
            level: raw.level,
            process_name: raw.process_name,
            command_line: raw.command_line,
            timestamp: raw.timestamp,
            extra: raw.extra,
        })
    }
}

impl From<SigmaAlert> for Evidence {
    fn from(alert: SigmaAlert) -> Self {
        let kind = if alert.process_name.is_some() {
            EvidenceKind::ProcessName
        } else {
            EvidenceKind::Custom("Alert".to_string())
        };

        let value = alert
            .command_line
            .clone()
            .or_else(|| alert.process_name.clone())
            .unwrap_or_else(|| alert.title.clone());

        let mut attrs: HashMap<String, String> = HashMap::new();
        attrs.insert("title".to_string(), alert.title.clone());
        attrs.insert("level".to_string(), alert.level.clone());
        if let Some(ref pn) = alert.process_name {
            attrs.insert("process_name".to_string(), pn.clone());
        }
        if let Some(ref cl) = alert.command_line {
            attrs.insert("command_line".to_string(), cl.clone());
        }
        if let Some(ref ts) = alert.timestamp {
            attrs.insert("timestamp".to_string(), ts.clone());
        }

        Evidence {
            id: alert.rule_id,
            source: EvidenceSource::Sigma,
            kind,
            value,
            subject: None,
            timestamp_ns: None,
            confidence: 80,
            attrs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_JSON: &str = r#"{
        "rule_id": "proc_creation_win_xmrig",
        "title": "XMRig Miner",
        "level": "critical",
        "process_name": "xmrig.exe",
        "command_line": "xmrig --pool stratum+tcp://pool.example.com:3333",
        "timestamp": "2026-01-01T00:00:00Z"
    }"#;

    #[test]
    fn test_sigma_aleissen_parses_valid_json() {
        let alert = SigmaAlert::from_json(VALID_JSON).expect("should parse");
        assert_eq!(alert.rule_id, "proc_creation_win_xmrig");
        assert_eq!(alert.title, "XMRig Miner");
        assert_eq!(alert.level, "critical");
        assert_eq!(alert.process_name.as_deref(), Some("xmrig.exe"));
        assert_eq!(alert.command_line.as_deref(), Some("xmrig --pool stratum+tcp://pool.example.com:3333"));
        assert_eq!(alert.timestamp.as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn test_sigma_aleissen_converts_to_evidence_with_correct_source() {
        use crate::evidence::{Evidence, EvidenceSource};
        let alert = SigmaAlert::from_json(VALID_JSON).expect("should parse");
        let ev: Evidence = alert.into();
        assert_eq!(ev.source, EvidenceSource::Sigma);
        assert_eq!(ev.id, "proc_creation_win_xmrig");
    }

    #[test]
    fn test_sigma_aleissen_sets_process_kind_for_process_creation() {
        use crate::evidence::{Evidence, EvidenceKind};
        let alert = SigmaAlert::from_json(VALID_JSON).expect("should parse");
        let ev: Evidence = alert.into();
        assert_eq!(ev.kind, EvidenceKind::ProcessName);
    }

    #[test]
    fn test_sigma_aleissen_handles_missing_optional_fields() {
        use crate::evidence::{Evidence, EvidenceKind};
        let json = r#"{"rule_id": "generic_alert", "title": "Generic", "level": "medium"}"#;
        let alert = SigmaAlert::from_json(json).expect("should parse");
        assert!(alert.process_name.is_none());
        assert!(alert.command_line.is_none());
        assert!(alert.timestamp.is_none());
        let ev: Evidence = alert.into();
        // No process_name → falls back to Alert kind (Custom)
        assert_eq!(ev.kind, EvidenceKind::Custom("Alert".to_string()));
    }
}
