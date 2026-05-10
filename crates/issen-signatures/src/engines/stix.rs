// STIX 2.1 indicator extraction.
//
// Parses STIX 2.1 JSON bundles and extracts indicators containing
// IOCs such as file hashes (SHA-256, SHA-1, MD5), IPv4/IPv6 addresses,
// domain names, and URLs from STIX patterns.

use std::path::Path;

use regex::Regex;
use serde::Deserialize;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from STIX parsing operations.
#[derive(Debug, Error)]
pub enum StixError {
    #[error("JSON parse error: {0}")]
    Json(String),

    #[error("Invalid STIX bundle: {0}")]
    InvalidBundle(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single extracted indicator of compromise from a STIX pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractedIoc {
    Sha256(String),
    Sha1(String),
    Md5(String),
    Ipv4(String),
    Ipv6(String),
    Domain(String),
    Url(String),
}

/// A parsed STIX 2.1 indicator with extracted IOCs.
#[derive(Debug, Clone)]
pub struct StixIndicator {
    /// The STIX `id` field (e.g. `"indicator--<uuid>"`).
    pub id: String,
    /// Optional human-readable name.
    pub name: Option<String>,
    /// Optional description.
    pub description: Option<String>,
    /// The raw STIX pattern string.
    pub pattern: String,
    /// Labels attached to the indicator.
    pub labels: Vec<String>,
    /// IOCs extracted from `pattern` via regex.
    pub iocs: Vec<ExtractedIoc>,
}

// ---------------------------------------------------------------------------
// Serde models (private) — only the fields we care about
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RawBundle {
    #[serde(rename = "type")]
    type_field: String,
    objects: Option<Vec<RawObject>>,
}

#[derive(Deserialize)]
struct RawObject {
    #[serde(rename = "type")]
    type_field: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    labels: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Stateless parser for STIX 2.1 bundles.
pub struct StixParser;

impl StixParser {
    /// Parse a STIX 2.1 JSON bundle string, returning all indicator objects
    /// with their IOCs extracted from the pattern field.
    ///
    /// # Errors
    ///
    /// Returns [`StixError::Json`] if the input is not valid JSON, or
    /// [`StixError::InvalidBundle`] if the top-level `type` is not `"bundle"`.
    pub fn parse_bundle(json: &str) -> Result<Vec<StixIndicator>, StixError> {
        let bundle: RawBundle =
            serde_json::from_str(json).map_err(|e| StixError::Json(e.to_string()))?;

        if bundle.type_field != "bundle" {
            return Err(StixError::InvalidBundle(format!(
                "expected type \"bundle\", got \"{}\"",
                bundle.type_field
            )));
        }

        let objects = bundle.objects.unwrap_or_default();

        let indicators = objects
            .into_iter()
            .filter(|obj| obj.type_field == "indicator")
            .filter_map(|obj| {
                let pattern = obj.pattern?;
                let iocs = Self::extract_iocs_from_pattern(&pattern);
                Some(StixIndicator {
                    id: obj.id.unwrap_or_default(),
                    name: obj.name,
                    description: obj.description,
                    pattern,
                    labels: obj.labels.unwrap_or_default(),
                    iocs,
                })
            })
            .collect();

        Ok(indicators)
    }

    /// Parse a STIX 2.1 JSON bundle from a file on disk.
    ///
    /// # Errors
    ///
    /// Returns [`StixError::Io`] on read failure, plus any parse errors from
    /// [`Self::parse_bundle`].
    pub fn parse_file(path: &Path) -> Result<Vec<StixIndicator>, StixError> {
        let contents = std::fs::read_to_string(path)?;
        Self::parse_bundle(&contents)
    }

    /// Extract IOCs from a raw STIX pattern string using regex matching.
    ///
    /// Handles SHA-256, SHA-1, MD5 file hashes, IPv4 and IPv6 addresses,
    /// domain names, and URLs. Compound patterns (using `OR` / `AND`) are
    /// supported because the regexes simply scan the full pattern text.
    #[must_use]
    pub fn extract_iocs_from_pattern(pattern: &str) -> Vec<ExtractedIoc> {
        let mut iocs = Vec::new();

        // SHA-256: file:hashes.'SHA-256' = '...' or file:hashes.SHA-256 = '...'
        let sha256_re =
            Regex::new(r"(?i)file:hashes\.'?SHA-?256'?\s*=\s*'([^']+)'").expect("valid regex");
        for cap in sha256_re.captures_iter(pattern) {
            if let Some(val) = cap.get(1) {
                iocs.push(ExtractedIoc::Sha256(val.as_str().to_string()));
            }
        }

        // SHA-1: file:hashes.'SHA-1' = '...'
        let sha1_re =
            Regex::new(r"(?i)file:hashes\.'?SHA-?1'?\s*=\s*'([^']+)'").expect("valid regex");
        for cap in sha1_re.captures_iter(pattern) {
            if let Some(val) = cap.get(1) {
                iocs.push(ExtractedIoc::Sha1(val.as_str().to_string()));
            }
        }

        // MD5: file:hashes.MD5 = '...' or file:hashes.'MD5' = '...'
        let md5_re = Regex::new(r"(?i)file:hashes\.'?MD5'?\s*=\s*'([^']+)'").expect("valid regex");
        for cap in md5_re.captures_iter(pattern) {
            if let Some(val) = cap.get(1) {
                iocs.push(ExtractedIoc::Md5(val.as_str().to_string()));
            }
        }

        // IPv4: ipv4-addr:value = '...'
        let ipv4_re = Regex::new(r"ipv4-addr:value\s*=\s*'([^']+)'").expect("valid regex");
        for cap in ipv4_re.captures_iter(pattern) {
            if let Some(val) = cap.get(1) {
                iocs.push(ExtractedIoc::Ipv4(val.as_str().to_string()));
            }
        }

        // IPv6: ipv6-addr:value = '...'
        let ipv6_re = Regex::new(r"ipv6-addr:value\s*=\s*'([^']+)'").expect("valid regex");
        for cap in ipv6_re.captures_iter(pattern) {
            if let Some(val) = cap.get(1) {
                iocs.push(ExtractedIoc::Ipv6(val.as_str().to_string()));
            }
        }

        // Domain: domain-name:value = '...'
        let domain_re = Regex::new(r"domain-name:value\s*=\s*'([^']+)'").expect("valid regex");
        for cap in domain_re.captures_iter(pattern) {
            if let Some(val) = cap.get(1) {
                iocs.push(ExtractedIoc::Domain(val.as_str().to_string()));
            }
        }

        // URL: url:value = '...'
        let url_re = Regex::new(r"url:value\s*=\s*'([^']+)'").expect("valid regex");
        for cap in url_re.captures_iter(pattern) {
            if let Some(val) = cap.get(1) {
                iocs.push(ExtractedIoc::Url(val.as_str().to_string()));
            }
        }

        iocs
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal STIX bundle JSON string with the given objects.
    fn bundle_json(objects_json: &str) -> String {
        format!(
            r#"{{
                "type": "bundle",
                "id": "bundle--test",
                "objects": [{objects_json}]
            }}"#
        )
    }

    // -- Parse valid bundles ------------------------------------------------

    #[test]
    fn test_parse_bundle_hash_indicator() {
        let json = bundle_json(
            r#"{
                "type": "indicator",
                "id": "indicator--1",
                "name": "Malicious hash",
                "pattern": "[file:hashes.'SHA-256' = 'abc123def456']",
                "pattern_type": "stix",
                "labels": ["malicious-activity"]
            }"#,
        );

        let indicators = StixParser::parse_bundle(&json).expect("parse");
        assert_eq!(indicators.len(), 1);

        let ind = &indicators[0];
        assert_eq!(ind.id, "indicator--1");
        assert_eq!(ind.name.as_deref(), Some("Malicious hash"));
        assert_eq!(ind.labels, vec!["malicious-activity"]);
        assert_eq!(ind.iocs, vec![ExtractedIoc::Sha256("abc123def456".into())]);
    }

    #[test]
    fn test_parse_bundle_ipv4_indicator() {
        let json = bundle_json(
            r#"{
                "type": "indicator",
                "id": "indicator--2",
                "pattern": "[ipv4-addr:value = '192.168.1.1']",
                "pattern_type": "stix"
            }"#,
        );

        let indicators = StixParser::parse_bundle(&json).expect("parse");
        assert_eq!(indicators.len(), 1);
        assert_eq!(
            indicators[0].iocs,
            vec![ExtractedIoc::Ipv4("192.168.1.1".into())]
        );
    }

    #[test]
    fn test_parse_bundle_domain_indicator() {
        let json = bundle_json(
            r#"{
                "type": "indicator",
                "id": "indicator--3",
                "pattern": "[domain-name:value = 'evil.example.com']",
                "pattern_type": "stix"
            }"#,
        );

        let indicators = StixParser::parse_bundle(&json).expect("parse");
        assert_eq!(indicators.len(), 1);
        assert_eq!(
            indicators[0].iocs,
            vec![ExtractedIoc::Domain("evil.example.com".into())]
        );
    }

    #[test]
    fn test_parse_bundle_url_indicator() {
        let json = bundle_json(
            r#"{
                "type": "indicator",
                "id": "indicator--4",
                "pattern": "[url:value = 'http://evil.com/payload']",
                "pattern_type": "stix"
            }"#,
        );

        let indicators = StixParser::parse_bundle(&json).expect("parse");
        assert_eq!(indicators.len(), 1);
        assert_eq!(
            indicators[0].iocs,
            vec![ExtractedIoc::Url("http://evil.com/payload".into())]
        );
    }

    // -- Compound patterns --------------------------------------------------

    #[test]
    fn test_extract_multiple_iocs_from_compound_pattern() {
        let pattern =
            "[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8' OR domain-name:value = 'bad.com']";
        let iocs = StixParser::extract_iocs_from_pattern(pattern);

        assert_eq!(iocs.len(), 3);
        assert!(iocs.contains(&ExtractedIoc::Ipv4("1.2.3.4".into())));
        assert!(iocs.contains(&ExtractedIoc::Ipv4("5.6.7.8".into())));
        assert!(iocs.contains(&ExtractedIoc::Domain("bad.com".into())));
    }

    // -- Mixed object types -------------------------------------------------

    #[test]
    fn test_skip_non_indicator_objects() {
        let json = bundle_json(
            r#"{
                "type": "malware",
                "id": "malware--1",
                "name": "Some malware"
            },
            {
                "type": "indicator",
                "id": "indicator--5",
                "pattern": "[ipv4-addr:value = '10.0.0.1']",
                "pattern_type": "stix"
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Phishing"
            }"#,
        );

        let indicators = StixParser::parse_bundle(&json).expect("parse");
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].id, "indicator--5");
    }

    // -- File parsing -------------------------------------------------------

    #[test]
    fn test_parse_bundle_from_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("bundle.json");

        let json = bundle_json(
            r#"{
                "type": "indicator",
                "id": "indicator--file",
                "pattern": "[file:hashes.'SHA-256' = 'deadbeef']",
                "pattern_type": "stix"
            }"#,
        );
        std::fs::write(&path, &json).expect("write");

        let indicators = StixParser::parse_file(&path).expect("parse file");
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].id, "indicator--file");
        assert_eq!(
            indicators[0].iocs,
            vec![ExtractedIoc::Sha256("deadbeef".into())]
        );
    }

    // -- Edge cases ---------------------------------------------------------

    #[test]
    fn test_empty_bundle_returns_empty_vec() {
        let json = r#"{"type": "bundle", "id": "bundle--empty", "objects": []}"#;
        let indicators = StixParser::parse_bundle(json).expect("parse");
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_bundle_without_objects_field() {
        let json = r#"{"type": "bundle", "id": "bundle--no-objects"}"#;
        let indicators = StixParser::parse_bundle(json).expect("parse");
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_invalid_json_returns_error() {
        let result = StixParser::parse_bundle("not json at all");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StixError::Json(_)));
    }

    #[test]
    fn test_invalid_bundle_type_returns_error() {
        let json = r#"{"type": "not-a-bundle", "id": "x"}"#;
        let result = StixParser::parse_bundle(json);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StixError::InvalidBundle(_)));
    }

    // -- Pattern extraction -------------------------------------------------

    #[test]
    fn test_extract_sha256_from_pattern() {
        let pattern = "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb924']";
        let iocs = StixParser::extract_iocs_from_pattern(pattern);
        assert_eq!(
            iocs,
            vec![ExtractedIoc::Sha256(
                "e3b0c44298fc1c149afbf4c8996fb924".into()
            )]
        );
    }

    #[test]
    fn test_extract_md5_from_pattern() {
        let pattern = "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']";
        let iocs = StixParser::extract_iocs_from_pattern(pattern);
        assert_eq!(
            iocs,
            vec![ExtractedIoc::Md5("d41d8cd98f00b204e9800998ecf8427e".into())]
        );
    }

    #[test]
    fn test_extract_sha1_from_pattern() {
        let pattern = "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']";
        let iocs = StixParser::extract_iocs_from_pattern(pattern);
        assert_eq!(
            iocs,
            vec![ExtractedIoc::Sha1(
                "da39a3ee5e6b4b0d3255bfef95601890afd80709".into()
            )]
        );
    }

    #[test]
    fn test_extract_ipv6_from_pattern() {
        let pattern = "[ipv6-addr:value = '2001:db8::1']";
        let iocs = StixParser::extract_iocs_from_pattern(pattern);
        assert_eq!(iocs, vec![ExtractedIoc::Ipv6("2001:db8::1".into())]);
    }

    // -- Multiple indicators ------------------------------------------------

    #[test]
    fn test_multiple_indicators_in_bundle() {
        let json = bundle_json(
            r#"{
                "type": "indicator",
                "id": "indicator--a",
                "pattern": "[file:hashes.'SHA-256' = 'aaa']",
                "pattern_type": "stix"
            },
            {
                "type": "indicator",
                "id": "indicator--b",
                "pattern": "[ipv4-addr:value = '10.0.0.1']",
                "pattern_type": "stix"
            },
            {
                "type": "indicator",
                "id": "indicator--c",
                "pattern": "[domain-name:value = 'bad.org']",
                "pattern_type": "stix"
            }"#,
        );

        let indicators = StixParser::parse_bundle(&json).expect("parse");
        assert_eq!(indicators.len(), 3);
        assert_eq!(indicators[0].id, "indicator--a");
        assert_eq!(indicators[1].id, "indicator--b");
        assert_eq!(indicators[2].id, "indicator--c");
    }

    // -- Missing optional fields --------------------------------------------

    #[test]
    fn test_handle_missing_optional_fields() {
        let json = bundle_json(
            r#"{
                "type": "indicator",
                "pattern": "[domain-name:value = 'minimal.com']",
                "pattern_type": "stix"
            }"#,
        );

        let indicators = StixParser::parse_bundle(&json).expect("parse");
        assert_eq!(indicators.len(), 1);

        let ind = &indicators[0];
        assert_eq!(ind.id, ""); // missing id defaults to empty
        assert!(ind.name.is_none());
        assert!(ind.description.is_none());
        assert!(ind.labels.is_empty());
        assert_eq!(ind.iocs, vec![ExtractedIoc::Domain("minimal.com".into())]);
    }

    // -- Compound hash patterns ---------------------------------------------

    #[test]
    fn test_compound_hash_pattern() {
        let pattern = "[file:hashes.'SHA-256' = 'sha256val' OR file:hashes.MD5 = 'md5val']";
        let iocs = StixParser::extract_iocs_from_pattern(pattern);

        assert_eq!(iocs.len(), 2);
        assert!(iocs.contains(&ExtractedIoc::Sha256("sha256val".into())));
        assert!(iocs.contains(&ExtractedIoc::Md5("md5val".into())));
    }

    // -- Indicator without pattern is skipped --------------------------------

    #[test]
    fn test_indicator_without_pattern_is_skipped() {
        let json = bundle_json(
            r#"{
                "type": "indicator",
                "id": "indicator--no-pattern",
                "name": "Missing pattern"
            }"#,
        );

        let indicators = StixParser::parse_bundle(&json).expect("parse");
        assert!(indicators.is_empty());
    }
}
