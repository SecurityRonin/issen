/// A single alert parsed from a Suricata EVE JSON log line.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SuricataAlert {
    pub timestamp: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub proto: String,
    pub alert: SuricataAlertDetail,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SuricataAlertDetail {
    pub signature: String,
    pub category: String,
    pub severity: u8,
    pub signature_id: u64,
}

/// Helper for EVE JSON deserialization — carries `event_type` for filtering.
#[derive(serde::Deserialize)]
struct EveRaw {
    event_type: String,
    #[serde(flatten)]
    alert: Option<SuricataAlert>,
}

/// Parse Suricata EVE JSON log lines. Only lines where `event_type == "alert"` are returned.
/// Lines that fail to parse are silently skipped.
pub fn parse_eve_json(input: &str) -> Vec<SuricataAlert> {
    input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let raw: EveRaw = serde_json::from_str(line).ok()?;
            if raw.event_type != "alert" {
                return None;
            }
            raw.alert
        })
        .collect()
}

/// Correlate Suricata alerts against timeline evidence.
/// Returns pairs of (alert, matching_evidence_ids) where dest_ip or src_ip
/// matches any value in an Evidence item's `attrs` map.
pub fn correlate_alerts<'a>(
    alerts: &'a [SuricataAlert],
    evidence: &[issen_correlation::model::Evidence],
) -> Vec<(&'a SuricataAlert, Vec<String>)> {
    alerts
        .iter()
        .filter_map(|alert| {
            let matching_ids: Vec<String> = evidence
                .iter()
                .filter(|ev| {
                    ev.attrs
                        .values()
                        .any(|v| v == &alert.dest_ip || v == &alert.src_ip)
                })
                .map(|ev| ev.id.clone())
                .collect();
            if matching_ids.is_empty() {
                None
            } else {
                Some((alert, matching_ids))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_correlation::model::{Evidence, EvidenceKind, EvidenceSource};

    const SAMPLE_EVE_ALERT: &str = r#"{"timestamp":"2024-01-15T10:23:45.000000+0000","event_type":"alert","src_ip":"192.168.1.50","src_port":49123,"dest_ip":"1.2.3.4","dest_port":3333,"proto":"TCP","alert":{"signature":"ET MINING Stratum Protocol","category":"Crypto Currency Mining","severity":1,"signature_id":2035234}}"#;
    const SAMPLE_EVE_DNS: &str = r#"{"timestamp":"2024-01-15T10:23:44.000000+0000","event_type":"dns","src_ip":"192.168.1.50","src_port":12345,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP"}"#;

    #[test]
    fn parse_empty_input_returns_empty() {
        let result = parse_eve_json("");
        assert!(result.is_empty(), "empty input should produce no alerts");
    }

    #[test]
    fn parse_eve_skips_non_aleissen_events() {
        let result = parse_eve_json(SAMPLE_EVE_DNS);
        assert!(
            result.is_empty(),
            "dns event_type should be skipped, got {} alerts",
            result.len()
        );
    }

    #[test]
    fn parse_eve_extracts_aleissen_fields() {
        let result = parse_eve_json(SAMPLE_EVE_ALERT);
        assert_eq!(result.len(), 1, "expected exactly one alert");
        let alert = &result[0];
        assert_eq!(alert.src_ip, "192.168.1.50");
        assert_eq!(alert.src_port, 49123);
        assert_eq!(alert.dest_ip, "1.2.3.4");
        assert_eq!(alert.dest_port, 3333);
        assert_eq!(alert.proto, "TCP");
        assert_eq!(alert.alert.signature, "ET MINING Stratum Protocol");
        assert_eq!(alert.alert.category, "Crypto Currency Mining");
        assert_eq!(alert.alert.severity, 1);
        assert_eq!(alert.alert.signature_id, 2035234);
        assert_eq!(alert.timestamp, "2024-01-15T10:23:45.000000+0000");
    }

    #[test]
    fn parse_eve_skips_malformed_lines() {
        let input = "not json at all\n{\"broken\":true}\n".to_string() + SAMPLE_EVE_ALERT;
        let result = parse_eve_json(&input);
        assert_eq!(
            result.len(),
            1,
            "malformed lines should be skipped, got {} alerts",
            result.len()
        );
    }

    #[test]
    fn correlate_finds_matching_ip() {
        let alerts = parse_eve_json(SAMPLE_EVE_ALERT);
        assert_eq!(alerts.len(), 1);
        // Evidence whose attrs contain dest_ip value "1.2.3.4"
        let ev = Evidence::new("ev-001", EvidenceSource::Artifact, EvidenceKind::Network, None)
            .with_attr("ip", "1.2.3.4");
        let results = correlate_alerts(&alerts, &[ev]);
        assert_eq!(results.len(), 1, "alert should match evidence with ip=1.2.3.4");
        assert_eq!(results[0].1, vec!["ev-001".to_string()]);
    }

    #[test]
    fn correlate_no_match_returns_empty() {
        let alerts = parse_eve_json(SAMPLE_EVE_ALERT);
        assert_eq!(alerts.len(), 1);
        // Evidence with unrelated IP
        let ev = Evidence::new("ev-002", EvidenceSource::Artifact, EvidenceKind::Network, None)
            .with_attr("ip", "10.0.0.1");
        let results = correlate_alerts(&alerts, &[ev]);
        // correlate_alerts returns only alerts that have at least one match
        // so with no matching evidence, the returned list is empty (or has empty vec)
        let matched_ids: Vec<_> = results
            .iter()
            .flat_map(|(_, ids)| ids.iter().cloned())
            .collect();
        assert!(
            matched_ids.is_empty(),
            "no evidence should match unrelated IP"
        );
    }
}
