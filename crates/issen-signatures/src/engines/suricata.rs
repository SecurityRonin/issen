// Suricata/ET Open rule parser for network IOC extraction.
//
// We do NOT execute Suricata rules — we mine them for threat intelligence
// indicators (IPs, CIDRs, domains) that can be matched against artifacts
// found during triage.

use std::path::Path;

use thiserror::Error;
use tracing::{debug, warn};

use crate::engines::ioc_network::NetworkIocStore;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the Suricata rule parser.
#[derive(Debug, Error)]
pub enum SuricataError {
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// IOC / Rule types
// ---------------------------------------------------------------------------

/// A single network indicator extracted from a Suricata rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuricataIoc {
    /// A literal IP address (v4 or v6).
    Ip(String),
    /// A CIDR network range.
    Network(String),
    /// A domain name (extracted from `content` or `dns.query` options).
    Domain(String),
}

/// A parsed Suricata rule with the fields we care about.
#[derive(Debug, Clone)]
pub struct SuricataRule {
    /// The rule's unique `sid`.
    pub sid: u64,
    /// The `msg` string from the rule options.
    pub msg: String,
    /// Network IOCs extracted from the header and options.
    pub iocs: Vec<SuricataIoc>,
    /// The optional `classtype` value.
    pub classtype: Option<String>,
    /// Any `reference` values (e.g. `url,example.com/foo`).
    pub references: Vec<String>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Stateless parser that extracts [`SuricataRule`]s from rule text.
pub struct SuricataParser;

impl SuricataParser {
    // -- public API --------------------------------------------------------

    /// Parse a single Suricata rule line.
    ///
    /// Returns `Ok(None)` for comment lines (starting with `#`) and blank
    /// lines. Returns `Err` if the line looks like a rule but cannot be
    /// parsed.
    pub fn parse_rule(line: &str) -> Result<Option<SuricataRule>, SuricataError> {
        let trimmed = line.trim();

        // Skip blanks and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(None);
        }

        // Split header from options at the first '('.
        let (header_part, options_part) = match trimmed.find('(') {
            Some(idx) => {
                let header = trimmed[..idx].trim();
                // Strip the surrounding parens.
                let opts_raw = &trimmed[idx + 1..];
                let opts = opts_raw.trim_end().trim_end_matches(')').trim();
                (header, opts)
            }
            None => {
                return Err(SuricataError::Parse(
                    "rule line has no options section (missing '(')".into(),
                ));
            }
        };

        // -- Parse header --------------------------------------------------
        let header_tokens: Vec<&str> = header_part.split_whitespace().collect();
        if header_tokens.len() < 7 {
            return Err(SuricataError::Parse(format!(
                "header has {} tokens, expected at least 7",
                header_tokens.len()
            )));
        }

        // tokens: action protocol src_ip src_port direction dst_ip dst_port
        let src_ip_raw = header_tokens[2];
        let dst_ip_raw = header_tokens[5];

        let mut iocs: Vec<SuricataIoc> = Vec::new();
        Self::collect_header_iocs(src_ip_raw, &mut iocs);
        Self::collect_header_iocs(dst_ip_raw, &mut iocs);

        // -- Parse options -------------------------------------------------
        let mut sid: Option<u64> = None;
        let mut msg = String::new();
        let mut classtype: Option<String> = None;
        let mut references: Vec<String> = Vec::new();
        let mut is_dns_context = false;

        for opt in Self::split_options(options_part) {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }

            if let Some((key, value)) = Self::parse_option(opt) {
                match key {
                    "sid" => {
                        sid = value.parse::<u64>().ok();
                    }
                    "msg" => {
                        msg = Self::unquote(value).to_string();
                    }
                    "classtype" => {
                        classtype = Some(value.to_string());
                    }
                    "reference" => {
                        references.push(value.to_string());
                    }
                    "dns.query" | "dns_query" => {
                        is_dns_context = true;
                    }
                    "content" => {
                        let unquoted = Self::unquote(value);
                        if is_dns_context {
                            // In dns.query context, content is always a domain.
                            if !unquoted.is_empty() {
                                iocs.push(SuricataIoc::Domain(unquoted.to_string()));
                            }
                            is_dns_context = false;
                        } else {
                            Self::maybe_add_domain(&unquoted, &mut iocs);
                        }
                    }
                    _ => {}
                }
            } else {
                // Keyword without value — could be a sticky buffer.
                let keyword = opt.trim_end_matches(';').trim();
                if keyword == "dns.query" || keyword == "dns_query" {
                    is_dns_context = true;
                }
            }
        }

        let sid = sid.ok_or_else(|| SuricataError::Parse("missing sid".into()))?;

        Ok(Some(SuricataRule {
            sid,
            msg,
            iocs,
            classtype,
            references,
        }))
    }

    /// Parse a multi-line string of rules. Silently skips failures and
    /// blank / comment lines.
    pub fn parse_rules(data: &str) -> Vec<SuricataRule> {
        data.lines()
            .filter_map(|line| match Self::parse_rule(line) {
                Ok(Some(rule)) => Some(rule),
                Ok(None) => None,
                Err(e) => {
                    warn!(error = %e, line, "skipping unparseable Suricata rule");
                    None
                }
            })
            .collect()
    }

    /// Read a rule file from disk and parse all rules.
    pub fn parse_file(path: &Path) -> Result<Vec<SuricataRule>, SuricataError> {
        let data = std::fs::read_to_string(path)?;
        Ok(Self::parse_rules(&data))
    }

    /// Load IOCs from parsed rules into a [`NetworkIocStore`].
    ///
    /// Returns the number of IOCs successfully inserted.
    pub fn extract_to_network_store(rules: &[SuricataRule], store: &mut NetworkIocStore) -> usize {
        let mut count = 0usize;
        for rule in rules {
            for ioc in &rule.iocs {
                let ok = match ioc {
                    SuricataIoc::Ip(ip) => store.inseissen_ip(ip).is_ok(),
                    SuricataIoc::Network(cidr) => store.inseissen_cidr(cidr).is_ok(),
                    SuricataIoc::Domain(domain) => {
                        store.inseissen_domain(domain);
                        true
                    }
                };
                if ok {
                    count += 1;
                } else {
                    debug!(ioc = ?ioc, sid = rule.sid, "failed to insert IOC into store");
                }
            }
        }
        count
    }

    // -- private helpers ---------------------------------------------------

    /// Collect IOCs from a single header IP field.
    fn collect_header_iocs(raw: &str, iocs: &mut Vec<SuricataIoc>) {
        // Skip Suricata variables and the `any` keyword.
        if raw.starts_with('$') || raw == "any" {
            return;
        }

        // Handle IP groups: [10.0.0.1,10.0.0.2]
        let stripped = raw.trim_start_matches('[').trim_end_matches(']');
        for part in stripped.split(',') {
            let part = part.trim();
            if part.is_empty() || part.starts_with('$') || part == "any" {
                continue;
            }
            // Strip negation prefix.
            let clean = part.trim_start_matches('!');

            if clean.contains('/') {
                iocs.push(SuricataIoc::Network(clean.to_string()));
            } else {
                iocs.push(SuricataIoc::Ip(clean.to_string()));
            }
        }
    }

    /// Split the options string on `;` while respecting quoted values.
    fn split_options(options: &str) -> Vec<&str> {
        // Suricata options are semicolon-delimited. Quoted strings may
        // contain semicolons, but in ET Open rules that's exceedingly rare
        // and content escapes them. A simple split works for the IOC
        // extraction use-case.
        options.split(';').collect()
    }

    /// Split a single option into key and optional value at the first `:`.
    fn parse_option(opt: &str) -> Option<(&str, &str)> {
        let opt = opt.trim();
        let colon = opt.find(':')?;
        let key = opt[..colon].trim();
        let value = opt[colon + 1..].trim();
        Some((key, value))
    }

    /// Strip surrounding double-quotes from a value.
    fn unquote(s: &str) -> &str {
        s.trim_matches('"')
    }

    /// If `value` looks like a domain (contains `.`, no spaces, not all
    /// hex/punctuation), add it as a `Domain` IOC.
    fn maybe_add_domain(value: &str, iocs: &mut Vec<SuricataIoc>) {
        let v = value.trim_matches(|c: char| c == '|' || c == '"');
        if v.is_empty() || !v.contains('.') || v.contains(' ') {
            return;
        }
        // Quick sanity: must have at least one alphabetic character.
        if !v.chars().any(|c| c.is_ascii_alphabetic()) {
            return;
        }
        // Reject things that look like IP addresses (all digits and dots).
        if v.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return;
        }
        iocs.push(SuricataIoc::Domain(v.to_string()));
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // --- Helpers ----------------------------------------------------------

    fn basic_rule() -> &'static str {
        r#"alert tcp 192.168.1.100 any -> 10.0.0.1 443 (msg:"Evil traffic"; content:"malware.com"; sid:1000001; rev:1; classtype:trojan-activity;)"#
    }

    // 1. Basic rule with literal IPs.
    #[test]
    fn test_parse_basic_rule() {
        let rule = SuricataParser::parse_rule(basic_rule())
            .unwrap()
            .expect("should parse");
        assert_eq!(rule.sid, 1_000_001);
        assert_eq!(rule.msg, "Evil traffic");
        assert!(rule.iocs.contains(&SuricataIoc::Ip("192.168.1.100".into())));
        assert!(rule.iocs.contains(&SuricataIoc::Ip("10.0.0.1".into())));
        assert!(rule
            .iocs
            .contains(&SuricataIoc::Domain("malware.com".into())));
    }

    // 2. Variables ($HOME_NET) should NOT produce IOCs.
    #[test]
    fn test_parse_rule_with_variables() {
        let line =
            r#"alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Test"; sid:2000001; rev:1;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();
        // No IP/Network IOCs from variables.
        let ip_net_iocs: Vec<_> = rule
            .iocs
            .iter()
            .filter(|i| matches!(i, SuricataIoc::Ip(_) | SuricataIoc::Network(_)))
            .collect();
        assert!(ip_net_iocs.is_empty(), "variables must not become IOCs");
    }

    // 3. Content with a domain.
    #[test]
    fn test_parse_rule_with_content_domain() {
        let line = r#"alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET domain"; content:"evil.com"; sid:3000001; rev:1;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();
        assert!(rule.iocs.contains(&SuricataIoc::Domain("evil.com".into())));
    }

    // 4. CIDR in header.
    #[test]
    fn test_parse_rule_with_cidr() {
        let line = r#"alert ip 192.168.0.0/24 any -> 10.0.0.0/8 any (msg:"CIDR test"; sid:4000001; rev:1;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();
        assert!(rule
            .iocs
            .contains(&SuricataIoc::Network("192.168.0.0/24".into())));
        assert!(rule
            .iocs
            .contains(&SuricataIoc::Network("10.0.0.0/8".into())));
    }

    // 5. SID and msg extraction.
    #[test]
    fn test_parse_rule_sid_msg() {
        let line = r#"alert tcp any any -> any any (msg:"Hello World"; sid:99; rev:1;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();
        assert_eq!(rule.sid, 99);
        assert_eq!(rule.msg, "Hello World");
    }

    // 6. Classtype and reference extraction.
    #[test]
    fn test_parse_rule_classtype_reference() {
        let line = r#"alert tcp any any -> any any (msg:"Ref test"; sid:100; rev:1; classtype:trojan-activity; reference:url,example.com/report;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();
        assert_eq!(rule.classtype.as_deref(), Some("trojan-activity"));
        assert_eq!(rule.references, vec!["url,example.com/report"]);
    }

    // 7. Comment lines should be skipped.
    #[test]
    fn test_skip_comment_lines() {
        let result = SuricataParser::parse_rule("# this is a comment").unwrap();
        assert!(result.is_none());
    }

    // 8. Empty / whitespace lines should be skipped.
    #[test]
    fn test_skip_empty_lines() {
        assert!(SuricataParser::parse_rule("").unwrap().is_none());
        assert!(SuricataParser::parse_rule("   ").unwrap().is_none());
        assert!(SuricataParser::parse_rule("\t\n").unwrap().is_none());
    }

    // 9. Multi-line parse.
    #[test]
    fn test_parse_rules_multiple() {
        let data = format!(
            "{}\n# comment\n{}\n\n",
            r#"alert tcp 1.2.3.4 any -> 5.6.7.8 80 (msg:"R1"; sid:1; rev:1;)"#,
            r#"alert udp 9.8.7.6 any -> 3.2.1.0 53 (msg:"R2"; sid:2; rev:1;)"#,
        );
        let rules = SuricataParser::parse_rules(&data);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].sid, 1);
        assert_eq!(rules[1].sid, 2);
    }

    // 10. Parse from a temp file.
    #[test]
    fn test_parse_file() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"alert tcp 1.1.1.1 any -> 2.2.2.2 443 (msg:"File rule"; sid:42; rev:1;)"#
        )
        .unwrap();
        f.flush().unwrap();

        let rules = SuricataParser::parse_file(f.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 42);
    }

    // 11. Extract IOCs into a NetworkIocStore.
    #[test]
    fn test_extract_to_network_store() {
        let line = r#"alert tcp 1.2.3.4 any -> 10.0.0.0/24 80 (msg:"Store test"; content:"bad.example.org"; sid:500; rev:1;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();

        let mut store = NetworkIocStore::new("suricata-test");
        let n = SuricataParser::extract_to_network_store(&[rule], &mut store);
        // 1 IP + 1 CIDR + 1 domain = 3
        assert_eq!(n, 3);
        assert!(store.lookup_ip("1.2.3.4").is_some());
        assert!(store.lookup_ip("10.0.0.5").is_some()); // inside the /24
        assert!(store.lookup_domain("bad.example.org").is_some());
    }

    // 12. `any` keyword in IP fields must not produce IOCs.
    #[test]
    fn test_parse_rule_any_keyword() {
        let line = r#"alert tcp any any -> any any (msg:"Any test"; sid:600; rev:1;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();
        let ip_net: Vec<_> = rule
            .iocs
            .iter()
            .filter(|i| matches!(i, SuricataIoc::Ip(_) | SuricataIoc::Network(_)))
            .collect();
        assert!(ip_net.is_empty());
    }

    // 13. Negated IP — strip the `!` prefix.
    #[test]
    fn test_parse_rule_negated_ip() {
        let line =
            r#"alert tcp !10.0.0.0/8 any -> 172.16.0.1 443 (msg:"Negated"; sid:700; rev:1;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();
        assert!(rule
            .iocs
            .contains(&SuricataIoc::Network("10.0.0.0/8".into())));
        assert!(rule.iocs.contains(&SuricataIoc::Ip("172.16.0.1".into())));
    }

    // 14. IP group with brackets.
    #[test]
    fn test_parse_rule_ip_group() {
        let line =
            r#"alert tcp [10.0.0.1,10.0.0.2] any -> 192.168.1.1 80 (msg:"Group"; sid:800; rev:1;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();
        assert!(rule.iocs.contains(&SuricataIoc::Ip("10.0.0.1".into())));
        assert!(rule.iocs.contains(&SuricataIoc::Ip("10.0.0.2".into())));
        assert!(rule.iocs.contains(&SuricataIoc::Ip("192.168.1.1".into())));
    }

    // 15. dns.query sticky buffer → content as domain.
    #[test]
    fn test_parse_rule_dns_query() {
        let line = r#"alert dns $HOME_NET any -> any any (msg:"DNS query"; dns.query; content:"evil.example.net"; sid:900; rev:1;)"#;
        let rule = SuricataParser::parse_rule(line).unwrap().unwrap();
        assert!(rule
            .iocs
            .contains(&SuricataIoc::Domain("evil.example.net".into())));
    }
}
