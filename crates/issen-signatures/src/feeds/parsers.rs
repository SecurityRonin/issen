// Feed format parsers for specific threat intelligence sources.
//
// Each parser reads a specific feed format and populates the appropriate
// IOC engine (hash store, network store, etc.).

use serde::Deserialize;
use thiserror::Error;

use crate::engines::ioc_hash::HashIocStore;
use crate::engines::ioc_network::NetworkIocStore;

/// Errors from feed parsing.
#[derive(Debug, Error)]
pub enum FeedParseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(String),

    #[error("CSV parse error: {0}")]
    Csv(String),
}

// ---------------------------------------------------------------------------
// Plain text parser (one indicator per line)
// ---------------------------------------------------------------------------

/// Parse a plain-text feed (one indicator per line) into a hash store.
/// Lines starting with '#' or ';' are comments. Empty lines are skipped.
/// Returns the number of indicators loaded.
pub fn parse_plaintext_hashes(
    data: &str,
    store: &mut HashIocStore,
) -> Result<usize, FeedParseError> {
    let mut count = 0;
    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // Take first whitespace-separated field (some feeds have trailing comments).
        let hash = trimmed.split_whitespace().next().unwrap_or(trimmed);
        if store.inseissen_bad(hash).is_ok() {
            count += 1;
        }
    }
    Ok(count)
}

/// Parse a plain-text feed into a network IOC store.
/// Auto-detects IPs, CIDRs, and domains.
pub fn parse_plaintext_network(
    data: &str,
    store: &mut NetworkIocStore,
) -> Result<usize, FeedParseError> {
    let mut count = 0;
    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // Take first whitespace-separated field.
        let indicator = trimmed.split_whitespace().next().unwrap_or(trimmed);

        if indicator.contains('/') {
            if store.inseissen_cidr(indicator).is_ok() {
                count += 1;
            }
        } else if indicator.parse::<std::net::IpAddr>().is_ok() {
            if store.inseissen_ip(indicator).is_ok() {
                count += 1;
            }
        } else {
            store.inseissen_domain(indicator);
            count += 1;
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// abuse.ch CSV parser
// ---------------------------------------------------------------------------

/// Parse an abuse.ch ThreatFox CSV export.
///
/// ThreatFox CSV format (after comment header):
/// ```text
/// "2024-01-01","ioc_type","ioc_value","threat_type","malware","confidence",...
/// ```
/// The ioc_value is in column index 2 (0-based).
pub fn parse_threatfox_csv(
    data: &str,
    hash_store: &mut HashIocStore,
    network_store: &mut NetworkIocStore,
) -> Result<usize, FeedParseError> {
    let mut count = 0;

    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Simple CSV parsing: split by comma, strip quotes.
        let fields: Vec<&str> = trimmed.split(',').collect();
        if fields.len() < 3 {
            continue;
        }

        let ioc_type = fields[1].trim().trim_matches('"');
        let ioc_value = fields[2].trim().trim_matches('"');

        match ioc_type {
            "sha256_hash" => {
                if hash_store.inseissen_bad(ioc_value).is_ok() {
                    count += 1;
                }
            }
            "md5_hash" => {
                if hash_store.inseissen_bad(ioc_value).is_ok() {
                    count += 1;
                }
            }
            "ip:port" => {
                // Extract IP from "ip:port" format.
                let ip = ioc_value.split(':').next().unwrap_or(ioc_value);
                if network_store.inseissen_ip(ip).is_ok() {
                    count += 1;
                }
            }
            "domain" => {
                network_store.inseissen_domain(ioc_value);
                count += 1;
            }
            "url" => {
                // Extract domain from URL and add it.
                let domain = extract_domain_from_url(ioc_value);
                if !domain.is_empty() {
                    network_store.inseissen_domain(&domain);
                    count += 1;
                }
            }
            _ => {
                // Unknown IOC type — try as hash or network indicator.
                if hash_store.inseissen_bad(ioc_value).is_ok() {
                    count += 1;
                }
            }
        }
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// CISA KEV JSON parser
// ---------------------------------------------------------------------------

/// A single vulnerability from the CISA KEV feed.
#[derive(Debug, Clone, Deserialize)]
pub struct KevVulnerability {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vendorProject")]
    pub vendor: String,
    pub product: String,
    #[serde(rename = "vulnerabilityName")]
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub description: Option<String>,
    #[serde(rename = "knownRansomwareCampaignUse")]
    pub ransomware_use: Option<String>,
}

#[derive(Deserialize)]
struct KevCatalog {
    vulnerabilities: Vec<KevVulnerability>,
}

/// Parse the CISA Known Exploited Vulnerabilities (KEV) JSON feed.
/// Returns the list of CVEs with active exploitation.
pub fn parse_cisa_kev(data: &str) -> Result<Vec<KevVulnerability>, FeedParseError> {
    let catalog: KevCatalog =
        serde_json::from_str(data).map_err(|e| FeedParseError::Json(e.to_string()))?;
    Ok(catalog.vulnerabilities)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the domain/host from a URL string.
fn extract_domain_from_url(url: &str) -> String {
    let after_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = if let Some(colon_pos) = host_port.rfind(':') {
        let after_colon = &host_port[colon_pos + 1..];
        if after_colon.chars().all(|c| c.is_ascii_digit()) && !after_colon.is_empty() {
            &host_port[..colon_pos]
        } else {
            host_port
        }
    } else {
        host_port
    };
    host.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Plain text hash parser ─────────────────────────────────────

    #[test]
    fn test_parse_plaintext_hashes() {
        let data = "# MalwareBazaar recent SHA256\n\
                     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                     d41d8cd98f00b204e9800998ecf8427e\n\
                     \n\
                     # end of list\n";

        let mut store = HashIocStore::new("test");
        let count = parse_plaintext_hashes(data, &mut store).expect("parse");

        assert_eq!(count, 2);
        assert!(store
            .lookup_bad("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .is_some());
        assert!(store
            .lookup_bad("d41d8cd98f00b204e9800998ecf8427e")
            .is_some());
    }

    #[test]
    fn test_parse_plaintext_hashes_with_trailing_comments() {
        let data = "d41d8cd98f00b204e9800998ecf8427e  # empty file hash\n";
        let mut store = HashIocStore::new("test");
        let count = parse_plaintext_hashes(data, &mut store).expect("parse");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_parse_plaintext_hashes_empty() {
        let data = "# just comments\n\n";
        let mut store = HashIocStore::new("test");
        let count = parse_plaintext_hashes(data, &mut store).expect("parse");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_parse_plaintext_hashes_semicolon_comments() {
        let data = "; Spamhaus-style comment\n\
                     d41d8cd98f00b204e9800998ecf8427e\n";
        let mut store = HashIocStore::new("test");
        let count = parse_plaintext_hashes(data, &mut store).expect("parse");
        assert_eq!(count, 1);
    }

    // ── Plain text network parser ──────────────────────────────────

    #[test]
    fn test_parse_plaintext_network_ips() {
        let data = "# Feodo Tracker\n10.0.0.1\n10.0.0.2\n";
        let mut store = NetworkIocStore::new("test");
        let count = parse_plaintext_network(data, &mut store).expect("parse");
        assert_eq!(count, 2);
        assert!(store.lookup_ip("10.0.0.1").is_some());
    }

    #[test]
    fn test_parse_plaintext_network_mixed() {
        let data = "10.0.0.1\n192.168.0.0/16\nevil.com\n";
        let mut store = NetworkIocStore::new("test");
        let count = parse_plaintext_network(data, &mut store).expect("parse");
        assert_eq!(count, 3);
        assert_eq!(store.ip_count(), 1);
        assert_eq!(store.cidr_count(), 1);
        assert_eq!(store.domain_count(), 1);
    }

    #[test]
    fn test_parse_plaintext_network_with_trailing_data() {
        // IPsum format: "IP\tcount"
        let data = "10.0.0.1\t5\n10.0.0.2\t3\n";
        let mut store = NetworkIocStore::new("test");
        let count = parse_plaintext_network(data, &mut store).expect("parse");
        assert_eq!(count, 2);
    }

    // ── ThreatFox CSV parser ───────────────────────────────────────

    #[test]
    fn test_parse_threatfox_csv() {
        let data = "# ThreatFox CSV export\n\
                     \"2024-01-01\",\"sha256_hash\",\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"botnet\",\"Emotet\",\"75\"\n\
                     \"2024-01-01\",\"ip:port\",\"10.0.0.1:4444\",\"c2\",\"CobaltStrike\",\"90\"\n\
                     \"2024-01-01\",\"domain\",\"evil.example.com\",\"c2\",\"Qakbot\",\"80\"\n";

        let mut hash_store = HashIocStore::new("threatfox");
        let mut network_store = NetworkIocStore::new("threatfox");
        let count = parse_threatfox_csv(data, &mut hash_store, &mut network_store).expect("parse");

        assert_eq!(count, 3);
        assert!(hash_store
            .lookup_bad("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .is_some());
        assert!(network_store.lookup_ip("10.0.0.1").is_some());
        assert!(network_store.lookup_domain("evil.example.com").is_some());
    }

    #[test]
    fn test_parse_threatfox_csv_url_type() {
        let data = "\"2024-01-01\",\"url\",\"http://malware.com/payload.exe\",\"payload\",\"Generic\",\"50\"\n";
        let mut hash_store = HashIocStore::new("test");
        let mut network_store = NetworkIocStore::new("test");
        let count = parse_threatfox_csv(data, &mut hash_store, &mut network_store).expect("parse");
        assert_eq!(count, 1);
        assert!(network_store.lookup_domain("malware.com").is_some());
    }

    #[test]
    fn test_parse_threatfox_csv_empty() {
        let data = "# just a header\n";
        let mut hash_store = HashIocStore::new("test");
        let mut network_store = NetworkIocStore::new("test");
        let count = parse_threatfox_csv(data, &mut hash_store, &mut network_store).expect("parse");
        assert_eq!(count, 0);
    }

    // ── CISA KEV JSON parser ───────────────────────────────────────

    #[test]
    fn test_parse_cisa_kev() {
        let data = r#"{
            "title": "CISA Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "2024.01.01",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "Microsoft",
                    "product": "Windows",
                    "vulnerabilityName": "Windows RCE",
                    "shortDescription": "A remote code execution vulnerability",
                    "knownRansomwareCampaignUse": "Known"
                },
                {
                    "cveID": "CVE-2024-5678",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "shortDescription": "Log4j JNDI injection",
                    "knownRansomwareCampaignUse": "Known"
                }
            ]
        }"#;

        let vulns = parse_cisa_kev(data).expect("parse");
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0].cve_id, "CVE-2024-1234");
        assert_eq!(vulns[0].vendor, "Microsoft");
        assert_eq!(vulns[0].ransomware_use.as_deref(), Some("Known"));
        assert_eq!(vulns[1].cve_id, "CVE-2024-5678");
    }

    #[test]
    fn test_parse_cisa_kev_empty() {
        let data = r#"{"vulnerabilities": []}"#;
        let vulns = parse_cisa_kev(data).expect("parse");
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_parse_cisa_kev_invalid_json() {
        let result = parse_cisa_kev("not json");
        assert!(result.is_err());
    }

    // ── Helper tests ───────────────────────────────────────────────

    #[test]
    fn test_extract_domain_from_url() {
        assert_eq!(extract_domain_from_url("http://evil.com/path"), "evil.com");
        assert_eq!(
            extract_domain_from_url("https://evil.com:8443/path"),
            "evil.com"
        );
        assert_eq!(extract_domain_from_url("evil.com/path"), "evil.com");
    }
}
