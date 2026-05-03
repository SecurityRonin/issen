//! Sigma alert adapter.
//!
//! Converts Sigma tool output (JSON format from sigmac/pySigma/hayabusa)
//! into `Evidence` objects for the `PivotEngine`.

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
    fn test_sigma_alert_parses_valid_json() {
        let alert = SigmaAlert::from_json(VALID_JSON).expect("should parse");
        assert_eq!(alert.rule_id, "proc_creation_win_xmrig");
        assert_eq!(alert.title, "XMRig Miner");
        assert_eq!(alert.level, "critical");
        assert_eq!(alert.process_name.as_deref(), Some("xmrig.exe"));
        assert_eq!(alert.command_line.as_deref(), Some("xmrig --pool stratum+tcp://pool.example.com:3333"));
        assert_eq!(alert.timestamp.as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn test_sigma_alert_converts_to_evidence_with_correct_source() {
        use crate::evidence::{Evidence, EvidenceSource};
        let alert = SigmaAlert::from_json(VALID_JSON).expect("should parse");
        let ev: Evidence = alert.into();
        assert_eq!(ev.source, EvidenceSource::Sigma);
        assert_eq!(ev.id, "proc_creation_win_xmrig");
    }

    #[test]
    fn test_sigma_alert_sets_process_kind_for_process_creation() {
        use crate::evidence::{Evidence, EvidenceKind};
        let alert = SigmaAlert::from_json(VALID_JSON).expect("should parse");
        let ev: Evidence = alert.into();
        assert_eq!(ev.kind, EvidenceKind::ProcessName);
    }

    #[test]
    fn test_sigma_alert_handles_missing_optional_fields() {
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
