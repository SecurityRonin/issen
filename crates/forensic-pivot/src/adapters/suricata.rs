//! Suricata EVE JSON adapter.
//!
//! Converts Suricata EVE JSON alert events into `Evidence` objects.

use std::collections::HashMap;
use anyhow::Result;
use serde::Deserialize;

use crate::evidence::{Evidence, EvidenceKind, EvidenceSource};

/// A parsed Suricata EVE alert event.
#[derive(Debug, Clone)]
pub struct EveAlert {
    pub timestamp: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub signature: String,
    pub signature_id: u64,
    pub action: String,
}

#[derive(Deserialize)]
struct RawEveEvent {
    event_type: String,
    timestamp: Option<String>,
    src_ip: Option<String>,
    src_port: Option<u16>,
    dest_ip: Option<String>,
    dest_port: Option<u16>,
    alert: Option<RawEveAlertInner>,
}

#[derive(Deserialize)]
struct RawEveAlertInner {
    action: Option<String>,
    signature_id: Option<u64>,
    signature: Option<String>,
}

impl EveAlert {
    /// Parse a single Suricata EVE JSON line.
    ///
    /// Returns `Ok(None)` for non-alert event types.
    pub fn from_json_line(line: &str) -> Result<Option<Self>> {
        let raw: RawEveEvent = serde_json::from_str(line)?;
        if raw.event_type != "alert" {
            return Ok(None);
        }
        let aleissen_inner = raw.alert.unwrap_or(RawEveAlertInner {
            action: None,
            signature_id: None,
            signature: None,
        });
        Ok(Some(Self {
            timestamp: raw.timestamp.unwrap_or_default(),
            src_ip: raw.src_ip.unwrap_or_default(),
            src_port: raw.src_port.unwrap_or(0),
            dest_ip: raw.dest_ip.unwrap_or_default(),
            dest_port: raw.dest_port.unwrap_or(0),
            signature: aleissen_inner.signature.unwrap_or_default(),
            signature_id: aleissen_inner.signature_id.unwrap_or(0),
            action: aleissen_inner.action.unwrap_or_default(),
        }))
    }
}

impl From<EveAlert> for Evidence {
    fn from(alert: EveAlert) -> Self {
        let id = format!("suricata-{}-{}", alert.signature_id, alert.timestamp);
        let value = alert.signature.clone();

        let mut attrs: HashMap<String, String> = HashMap::new();
        attrs.insert("src_ip".to_string(), alert.src_ip.clone());
        attrs.insert("src_port".to_string(), alert.src_port.to_string());
        attrs.insert("dest_ip".to_string(), alert.dest_ip.clone());
        attrs.insert("dest_port".to_string(), alert.dest_port.to_string());
        attrs.insert("signature".to_string(), alert.signature.clone());
        attrs.insert("signature_id".to_string(), alert.signature_id.to_string());
        attrs.insert("action".to_string(), alert.action.clone());
        attrs.insert("timestamp".to_string(), alert.timestamp.clone());

        Evidence {
            id,
            source: EvidenceSource::Suricata,
            kind: EvidenceKind::Custom("Network".to_string()),
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

    const VALID_EVE: &str = r#"{
        "event_type": "alert",
        "timestamp": "2026-01-01T00:00:00.000000+0000",
        "src_ip": "192.168.1.100",
        "src_port": 4444,
        "dest_ip": "10.0.0.1",
        "dest_port": 3333,
        "alert": {
            "action": "allowed",
            "signature_id": 12345,
            "signature": "ET MINING XMRig"
        }
    }"#;

    #[test]
    fn test_eve_aleissen_parses_valid_json() {
        let result = EveAlert::from_json_line(VALID_EVE).expect("should parse");
        let alert = result.expect("should be Some for alert event");
        assert_eq!(alert.src_ip, "192.168.1.100");
        assert_eq!(alert.src_port, 4444);
        assert_eq!(alert.dest_ip, "10.0.0.1");
        assert_eq!(alert.dest_port, 3333);
        assert_eq!(alert.signature, "ET MINING XMRig");
        assert_eq!(alert.signature_id, 12345);
        assert_eq!(alert.action, "allowed");
    }

    #[test]
    fn test_eve_aleissen_converts_to_evidence_with_suricata_source() {
        use crate::evidence::{Evidence, EvidenceSource};
        let alert = EveAlert::from_json_line(VALID_EVE)
            .expect("parse ok")
            .expect("is alert");
        let ev: Evidence = alert.into();
        assert_eq!(ev.source, EvidenceSource::Suricata);
    }

    #[test]
    fn test_eve_aleissen_sets_network_kind() {
        use crate::evidence::{Evidence, EvidenceKind};
        let alert = EveAlert::from_json_line(VALID_EVE)
            .expect("parse ok")
            .expect("is alert");
        let ev: Evidence = alert.into();
        assert_eq!(ev.kind, EvidenceKind::Custom("Network".to_string()));
    }

    #[test]
    fn test_eve_aleissen_captures_src_and_dest_ip_in_attrs() {
        use crate::evidence::Evidence;
        let alert = EveAlert::from_json_line(VALID_EVE)
            .expect("parse ok")
            .expect("is alert");
        let ev: Evidence = alert.into();
        assert_eq!(ev.attrs.get("src_ip").map(|s| s.as_str()), Some("192.168.1.100"));
        assert_eq!(ev.attrs.get("dest_ip").map(|s| s.as_str()), Some("10.0.0.1"));
        assert_eq!(ev.attrs.get("src_port").map(|s| s.as_str()), Some("4444"));
        assert_eq!(ev.attrs.get("dest_port").map(|s| s.as_str()), Some("3333"));
    }

    #[test]
    fn test_eve_non_aleissen_event_returns_none() {
        let dns_event = r#"{"event_type": "dns", "timestamp": "2026-01-01T00:00:00Z"}"#;
        let result = EveAlert::from_json_line(dns_event).expect("should parse");
        assert!(result.is_none(), "non-alert events should return None");
    }
}
