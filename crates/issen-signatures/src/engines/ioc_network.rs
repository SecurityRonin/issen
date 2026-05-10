// Network IOC matching (IP, domain, URL, CIDR).
//
// Supports loading indicator sets from text files (one indicator per line),
// with auto-detection of IP addresses, CIDR ranges, and domain names.
// Provides fast O(1) exact-match lookup for IPs and domains, plus linear
// CIDR containment checks.

use std::collections::HashSet;
use std::io::BufRead;
use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use thiserror::Error;

/// Errors from network IOC operations.
#[derive(Debug, Error)]
pub enum NetworkIocError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("Invalid CIDR range: {0}")]
    InvalidCidr(String),

    #[error("Invalid URL (no host found): {0}")]
    InvalidUrl(String),
}

/// The type of network indicator that was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorType {
    Ip,
    Cidr,
    Domain,
    Url,
}

/// A match result from the network IOC engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkMatch {
    /// The value that was looked up (e.g., the IP or domain queried).
    pub indicator: String,
    /// What kind of indicator triggered the match.
    pub indicator_type: IndicatorType,
    /// The stored indicator that matched (e.g., the CIDR range or parent domain).
    pub matched_against: String,
    /// Provenance label for this store.
    pub source: String,
}

/// Network IOC store: holds sets of known-bad IPs, CIDR ranges, and domains.
#[derive(Debug)]
pub struct NetworkIocStore {
    ips: HashSet<IpAddr>,
    cidrs: Vec<IpNet>,
    domains: HashSet<String>,
    source_label: String,
}

impl NetworkIocStore {
    /// Create an empty store with a source label.
    #[must_use]
    pub fn new(source_label: impl Into<String>) -> Self {
        Self {
            ips: HashSet::new(),
            cidrs: Vec::new(),
            domains: HashSet::new(),
            source_label: source_label.into(),
        }
    }

    /// Get the source label for this store.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.source_label
    }

    /// Parse and add an IP address (IPv4 or IPv6).
    pub fn inseissen_ip(&mut self, ip_str: &str) -> Result<(), NetworkIocError> {
        let ip: IpAddr = ip_str
            .trim()
            .parse()
            .map_err(|_| NetworkIocError::InvalidIp(ip_str.to_string()))?;
        self.ips.insert(ip);
        Ok(())
    }

    /// Parse and add a CIDR range (e.g., "192.168.1.0/24").
    pub fn inseissen_cidr(&mut self, cidr_str: &str) -> Result<(), NetworkIocError> {
        let net: IpNet = cidr_str
            .trim()
            .parse()
            .map_err(|_| NetworkIocError::InvalidCidr(cidr_str.to_string()))?;
        self.cidrs.push(net);
        Ok(())
    }

    /// Add a domain name (stored lowercased for case-insensitive matching).
    pub fn inseissen_domain(&mut self, domain: &str) {
        let normalized = domain.trim().to_lowercase();
        if !normalized.is_empty() {
            self.domains.insert(normalized);
        }
    }

    /// Check an IP address against the IP set and all CIDR ranges.
    ///
    /// Returns a [`NetworkMatch`] if the IP is found in the exact-match set
    /// or falls within any loaded CIDR range.
    #[must_use]
    pub fn lookup_ip(&self, ip_str: &str) -> Option<NetworkMatch> {
        let ip: IpAddr = ip_str.trim().parse().ok()?;

        // Exact IP match.
        if self.ips.contains(&ip) {
            return Some(NetworkMatch {
                indicator: ip.to_string(),
                indicator_type: IndicatorType::Ip,
                matched_against: ip.to_string(),
                source: self.source_label.clone(),
            });
        }

        // CIDR containment check.
        for net in &self.cidrs {
            if net.contains(&ip) {
                return Some(NetworkMatch {
                    indicator: ip.to_string(),
                    indicator_type: IndicatorType::Cidr,
                    matched_against: net.to_string(),
                    source: self.source_label.clone(),
                });
            }
        }

        None
    }

    /// Check a domain against the domain set.
    ///
    /// Performs exact matching first, then walks parent domains so that
    /// "sub.evil.com" will match an entry for "evil.com" but "notevil.com"
    /// will **not** match "evil.com".
    #[must_use]
    pub fn lookup_domain(&self, domain: &str) -> Option<NetworkMatch> {
        let normalized = domain.trim().to_lowercase();

        // Exact match.
        if self.domains.contains(&normalized) {
            return Some(NetworkMatch {
                indicator: normalized.clone(),
                indicator_type: IndicatorType::Domain,
                matched_against: normalized,
                source: self.source_label.clone(),
            });
        }

        // Walk parent domains: "a.b.evil.com" -> "b.evil.com" -> "evil.com"
        let mut remaining = normalized.as_str();
        while let Some(dot_pos) = remaining.find('.') {
            remaining = &remaining[dot_pos + 1..];
            if self.domains.contains(remaining) {
                return Some(NetworkMatch {
                    indicator: normalized.clone(),
                    indicator_type: IndicatorType::Domain,
                    matched_against: remaining.to_string(),
                    source: self.source_label.clone(),
                });
            }
        }

        None
    }

    /// Extract the domain from a URL and look it up against the domain set.
    ///
    /// Supports URLs with or without a scheme. For example:
    /// - `http://evil.com/path` -> domain `evil.com`
    /// - `https://sub.evil.com:8080/path` -> domain `sub.evil.com`
    #[must_use]
    pub fn lookup_url(&self, url: &str) -> Option<NetworkMatch> {
        let host = extract_host_from_url(url)?;

        let domain_match = self.lookup_domain(&host);
        domain_match.map(|mut m| {
            m.indicator = url.to_string();
            m.indicator_type = IndicatorType::Url;
            m
        })
    }

    /// Load indicators from a text file (one per line).
    ///
    /// Lines starting with `#` are treated as comments. Empty lines are
    /// skipped. Each non-comment line is auto-classified as an IP address,
    /// CIDR range, or domain name:
    ///
    /// - Contains `/` -> CIDR
    /// - Parses as `IpAddr` -> IP
    /// - Otherwise -> domain
    ///
    /// Returns the number of indicators successfully loaded.
    pub fn load_from_file(&mut self, path: &Path) -> Result<usize, NetworkIocError> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.contains('/') {
                // CIDR notation.
                if self.inseissen_cidr(trimmed).is_ok() {
                    count += 1;
                }
            } else if trimmed.parse::<IpAddr>().is_ok() {
                // IP address.
                if self.inseissen_ip(trimmed).is_ok() {
                    count += 1;
                }
            } else {
                // Domain name.
                self.inseissen_domain(trimmed);
                count += 1;
            }
        }

        Ok(count)
    }

    /// Number of individual IP addresses loaded.
    #[must_use]
    pub fn ip_count(&self) -> usize {
        self.ips.len()
    }

    /// Number of CIDR ranges loaded.
    #[must_use]
    pub fn cidr_count(&self) -> usize {
        self.cidrs.len()
    }

    /// Number of domain names loaded.
    #[must_use]
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }
}

/// Extract the host/domain portion from a URL string.
///
/// Handles URLs with and without a scheme, and strips port numbers.
fn extract_host_from_url(url: &str) -> Option<String> {
    // Strip scheme if present (e.g., "http://", "https://", "ftp://").
    let after_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };

    // Strip path, query, fragment.
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);

    // Strip userinfo (user:pass@host).
    let host_port = if let Some(at_pos) = host_port.rfind('@') {
        &host_port[at_pos + 1..]
    } else {
        host_port
    };

    // Strip port number. Be careful with IPv6 bracket notation [::1]:8080.
    let host = if host_port.starts_with('[') {
        // IPv6 bracket notation: [::1]:8080 -> ::1
        if let Some(bracket_end) = host_port.find(']') {
            &host_port[1..bracket_end]
        } else {
            host_port
        }
    } else if let Some(colon_pos) = host_port.rfind(':') {
        // Only strip if what follows the colon looks like a port number.
        let after_colon = &host_port[colon_pos + 1..];
        if after_colon.chars().all(|c| c.is_ascii_digit()) && !after_colon.is_empty() {
            &host_port[..colon_pos]
        } else {
            host_port
        }
    } else {
        host_port
    };

    let host = host.trim().to_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── IP exact match ─────────────────────────────────────────────

    #[test]
    fn test_ip_exact_match_hit() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_ip("10.0.0.1").unwrap();

        let m = store.lookup_ip("10.0.0.1").expect("should match");
        assert_eq!(m.indicator_type, IndicatorType::Ip);
        assert_eq!(m.matched_against, "10.0.0.1");
        assert_eq!(m.source, "test");
    }

    #[test]
    fn test_ip_exact_match_miss() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_ip("10.0.0.1").unwrap();

        assert!(store.lookup_ip("10.0.0.2").is_none());
    }

    // ── CIDR containment ───────────────────────────────────────────

    #[test]
    fn test_cidr_containment_hit() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_cidr("192.168.1.0/24").unwrap();

        let m = store.lookup_ip("192.168.1.100").expect("should match CIDR");
        assert_eq!(m.indicator_type, IndicatorType::Cidr);
        assert_eq!(m.matched_against, "192.168.1.0/24");
    }

    #[test]
    fn test_cidr_containment_miss() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_cidr("192.168.1.0/24").unwrap();

        assert!(store.lookup_ip("192.168.2.1").is_none());
    }

    #[test]
    fn test_cidr_boundary() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_cidr("10.0.0.0/30").unwrap(); // 10.0.0.0 - 10.0.0.3

        assert!(store.lookup_ip("10.0.0.0").is_some());
        assert!(store.lookup_ip("10.0.0.3").is_some());
        assert!(store.lookup_ip("10.0.0.4").is_none());
    }

    // ── Domain exact match ─────────────────────────────────────────

    #[test]
    fn test_domain_exact_match() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_domain("evil.com");

        let m = store.lookup_domain("evil.com").expect("should match");
        assert_eq!(m.indicator_type, IndicatorType::Domain);
        assert_eq!(m.matched_against, "evil.com");
    }

    #[test]
    fn test_domain_miss() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_domain("evil.com");

        assert!(store.lookup_domain("good.com").is_none());
    }

    // ── Subdomain matching ─────────────────────────────────────────

    #[test]
    fn test_subdomain_matches_parent() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_domain("evil.com");

        let m = store
            .lookup_domain("sub.evil.com")
            .expect("subdomain should match");
        assert_eq!(m.indicator, "sub.evil.com");
        assert_eq!(m.matched_against, "evil.com");
    }

    #[test]
    fn test_subdomain_deep_nesting() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_domain("evil.com");

        let m = store
            .lookup_domain("a.b.c.evil.com")
            .expect("deep subdomain should match");
        assert_eq!(m.matched_against, "evil.com");
    }

    #[test]
    fn test_subdomain_non_match() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_domain("evil.com");

        // "notevil.com" should NOT match "evil.com".
        assert!(store.lookup_domain("notevil.com").is_none());
    }

    // ── URL matching ───────────────────────────────────────────────

    #[test]
    fn test_url_domain_extraction_and_match() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_domain("evil.com");

        let m = store
            .lookup_url("http://evil.com/malware/payload.exe")
            .expect("URL should match");
        assert_eq!(m.indicator_type, IndicatorType::Url);
        assert_eq!(m.matched_against, "evil.com");
    }

    #[test]
    fn test_url_with_port() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_domain("evil.com");

        let m = store
            .lookup_url("https://evil.com:8443/path")
            .expect("URL with port should match");
        assert_eq!(m.indicator_type, IndicatorType::Url);
    }

    #[test]
    fn test_url_subdomain_match() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_domain("evil.com");

        let m = store
            .lookup_url("https://cdn.evil.com/script.js")
            .expect("URL subdomain should match");
        assert_eq!(m.matched_against, "evil.com");
    }

    // ── Case insensitivity ─────────────────────────────────────────

    #[test]
    fn test_domain_case_insensitive() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_domain("Evil.COM");

        let m = store
            .lookup_domain("evil.com")
            .expect("case-insensitive match");
        assert_eq!(m.matched_against, "evil.com");

        let m2 = store.lookup_domain("EVIL.COM").expect("uppercase lookup");
        assert_eq!(m2.matched_against, "evil.com");
    }

    // ── IPv6 support ───────────────────────────────────────────────

    #[test]
    fn test_ipv6_exact_match() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_ip("::1").unwrap();

        let m = store.lookup_ip("::1").expect("IPv6 loopback should match");
        assert_eq!(m.indicator_type, IndicatorType::Ip);
    }

    #[test]
    fn test_ipv6_cidr() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_cidr("fd00::/8").unwrap();

        let m = store
            .lookup_ip("fd12:3456:789a::1")
            .expect("IPv6 in CIDR should match");
        assert_eq!(m.indicator_type, IndicatorType::Cidr);
    }

    // ── Invalid input handling ─────────────────────────────────────

    #[test]
    fn test_invalid_ip() {
        let mut store = NetworkIocStore::new("test");
        assert!(store.inseissen_ip("not-an-ip").is_err());
    }

    #[test]
    fn test_invalid_cidr() {
        let mut store = NetworkIocStore::new("test");
        assert!(store.inseissen_cidr("not-a-cidr").is_err());
    }

    #[test]
    fn test_lookup_ip_with_invalid_input() {
        let store = NetworkIocStore::new("test");
        // Lookup with an invalid IP string returns None, not an error.
        assert!(store.lookup_ip("garbage").is_none());
    }

    // ── Load from file ─────────────────────────────────────────────

    #[test]
    fn test_load_from_file_mixed_types() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("indicators.txt");
        std::fs::write(
            &path,
            "# Threat intel feed\n\
             10.0.0.1\n\
             192.168.0.0/16\n\
             evil.com\n\
             bad-domain.org\n\
             \n\
             # Another IP\n\
             172.16.0.5\n\
             2001:db8::/32\n",
        )
        .expect("write");

        let mut store = NetworkIocStore::new("file-test");
        let count = store.load_from_file(&path).expect("load");

        assert_eq!(count, 6);
        assert_eq!(store.ip_count(), 2);
        assert_eq!(store.cidr_count(), 2);
        assert_eq!(store.domain_count(), 2);

        // Verify a sample from each type.
        assert!(store.lookup_ip("10.0.0.1").is_some());
        assert!(store.lookup_ip("192.168.50.1").is_some()); // CIDR
        assert!(store.lookup_domain("evil.com").is_some());
    }

    #[test]
    fn test_load_from_file_nonexistent() {
        let mut store = NetworkIocStore::new("test");
        assert!(store
            .load_from_file(Path::new("/no/such/file.txt"))
            .is_err());
    }

    // ── Count methods ──────────────────────────────────────────────

    #[test]
    fn test_count_methods() {
        let mut store = NetworkIocStore::new("test");
        assert_eq!(store.ip_count(), 0);
        assert_eq!(store.cidr_count(), 0);
        assert_eq!(store.domain_count(), 0);

        store.inseissen_ip("1.2.3.4").unwrap();
        store.inseissen_ip("5.6.7.8").unwrap();
        store.inseissen_cidr("10.0.0.0/8").unwrap();
        store.inseissen_domain("example.com");
        store.inseissen_domain("test.org");
        store.inseissen_domain("foo.bar");

        assert_eq!(store.ip_count(), 2);
        assert_eq!(store.cidr_count(), 1);
        assert_eq!(store.domain_count(), 3);
    }

    // ── Empty store lookups ────────────────────────────────────────

    #[test]
    fn test_empty_store_ip_lookup() {
        let store = NetworkIocStore::new("empty");
        assert!(store.lookup_ip("10.0.0.1").is_none());
    }

    #[test]
    fn test_empty_store_domain_lookup() {
        let store = NetworkIocStore::new("empty");
        assert!(store.lookup_domain("evil.com").is_none());
    }

    #[test]
    fn test_empty_store_url_lookup() {
        let store = NetworkIocStore::new("empty");
        assert!(store.lookup_url("http://evil.com/path").is_none());
    }

    // ── extract_host_from_url unit tests ───────────────────────────

    #[test]
    fn test_extract_host_various_formats() {
        assert_eq!(
            extract_host_from_url("http://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("https://example.com:443/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://user:pass@example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://[::1]:8080/path"),
            Some("::1".to_string())
        );
    }

    // ── IP preferred over CIDR ─────────────────────────────────────

    #[test]
    fn test_ip_exact_preferred_over_cidr() {
        let mut store = NetworkIocStore::new("test");
        store.inseissen_ip("192.168.1.1").unwrap();
        store.inseissen_cidr("192.168.1.0/24").unwrap();

        // Should prefer exact IP match.
        let m = store.lookup_ip("192.168.1.1").expect("should match");
        assert_eq!(m.indicator_type, IndicatorType::Ip);
    }
}
