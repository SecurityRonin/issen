//! YARA scanning engine using yara-x.
//!
//! Provides a high-level wrapper around the `yara-x` crate for compiling
//! YARA rules and scanning byte buffers or files on disk.

use std::path::Path;

use thiserror::Error;

/// Errors that can occur during YARA rule compilation or scanning.
#[derive(Debug, Error)]
pub enum YaraError {
    /// A YARA rule failed to compile.
    #[error("YARA compilation error: {0}")]
    Compile(String),

    /// A scan operation failed.
    #[error("YARA scan error: {0}")]
    Scan(String),

    /// An I/O error occurred (e.g. reading a rule file or scan target).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A single match result from a YARA scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraMatch {
    /// The identifier of the rule that matched.
    pub rule_name: String,
    /// The namespace the rule belongs to.
    pub namespace: String,
    /// Tags attached to the matched rule.
    pub tags: Vec<String>,
    /// Identifiers of the string patterns that matched (e.g. `$a`, `$hex1`).
    pub strings_matched: Vec<String>,
}

/// High-level YARA scanning engine backed by `yara-x`.
///
/// Holds a compiled [`yara_x::Rules`] object that can be used to scan
/// arbitrary data or files.
pub struct YaraEngine {
    rules: yara_x::Rules,
}

impl std::fmt::Debug for YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraEngine")
            .field("rule_count", &self.rules.iter().len())
            .finish()
    }
}

impl YaraEngine {
    // ── Constructors ────────────────────────────────────────────────

    /// Compile a single YARA rule source string.
    pub fn from_source(rule_source: &str) -> Result<Self, YaraError> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(rule_source)
            .map_err(|e| YaraError::Compile(e.to_string()))?;
        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Compile multiple YARA rule source strings.
    ///
    /// All sources are fed into a single compiler so cross-rule references
    /// and deduplication work as expected.
    pub fn from_sources(sources: &[&str]) -> Result<Self, YaraError> {
        let mut compiler = yara_x::Compiler::new();
        for src in sources {
            compiler
                .add_source(*src)
                .map_err(|e| YaraError::Compile(e.to_string()))?;
        }
        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Compile YARA rules from a `.yar` file on disk.
    pub fn from_file(path: &Path) -> Result<Self, YaraError> {
        let source = std::fs::read_to_string(path)?;
        Self::from_source(&source)
    }

    // ── Scanning ────────────────────────────────────────────────────

    /// Scan an in-memory byte buffer and return all matching rules.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>, YaraError> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| YaraError::Scan(e.to_string()))?;

        Ok(Self::collect_matches(&results))
    }

    /// Scan a file on disk and return all matching rules.
    ///
    /// The file is loaded by `yara-x` internally (memory-mapped when
    /// possible).
    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, YaraError> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan_file(path)
            .map_err(|e| YaraError::Scan(e.to_string()))?;

        Ok(Self::collect_matches(&results))
    }

    // ── Metadata ────────────────────────────────────────────────────

    /// Returns the number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.iter().len()
    }

    // ── Internals ───────────────────────────────────────────────────

    /// Convert `ScanResults` into our owned `Vec<YaraMatch>`.
    fn collect_matches(results: &yara_x::ScanResults<'_, '_>) -> Vec<YaraMatch> {
        results
            .matching_rules()
            .map(|rule| {
                let tags: Vec<String> = rule.tags().map(|t| t.identifier().to_owned()).collect();

                let strings_matched: Vec<String> = rule
                    .patterns()
                    .filter(|p| p.matches().len() > 0)
                    .map(|p| p.identifier().to_owned())
                    .collect();

                YaraMatch {
                    rule_name: rule.identifier().to_owned(),
                    namespace: rule.namespace().to_owned(),
                    tags,
                    strings_matched,
                }
            })
            .collect()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Helper: a simple rule that matches the literal string "malware".
    const RULE_MALWARE: &str = r#"
        rule detect_malware {
            strings:
                $a = "malware"
            condition:
                $a
        }
    "#;

    // 1. Compile a valid rule and verify rule_count.
    #[test]
    fn compile_valid_rule() {
        let engine = YaraEngine::from_source(RULE_MALWARE).unwrap();
        assert_eq!(engine.rule_count(), 1);
    }

    // 2. Compile an invalid rule and expect an error.
    #[test]
    fn compile_invalid_rule_returns_error() {
        let bad = "rule broken {{{{{ nope }}}}}";
        let result = YaraEngine::from_source(bad);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, YaraError::Compile(_)));
    }

    // 3. Scan matching bytes.
    #[test]
    fn scan_matching_bytes() {
        let engine = YaraEngine::from_source(RULE_MALWARE).unwrap();
        let matches = engine.scan_bytes(b"this contains malware inside").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "detect_malware");
        assert!(matches[0].strings_matched.contains(&"$a".to_owned()));
    }

    // 4. Scan non-matching bytes.
    #[test]
    fn scan_non_matching_bytes() {
        let engine = YaraEngine::from_source(RULE_MALWARE).unwrap();
        let matches = engine.scan_bytes(b"totally benign content").unwrap();
        assert!(matches.is_empty());
    }

    // 5. Multiple rules, only one matches.
    #[test]
    fn multiple_rules_one_matches() {
        let rules = r#"
            rule alpha {
                strings:
                    $s = "alpha"
                condition:
                    $s
            }
            rule beta {
                strings:
                    $s = "beta"
                condition:
                    $s
            }
        "#;
        let engine = YaraEngine::from_source(rules).unwrap();
        assert_eq!(engine.rule_count(), 2);

        let matches = engine.scan_bytes(b"only alpha here").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "alpha");
    }

    // 6. Rule with tags — verify tags appear in YaraMatch.
    #[test]
    fn rule_with_tags() {
        let rule = r#"
            rule tagged_rule : trojan dropper {
                strings:
                    $s = "payload"
                condition:
                    $s
            }
        "#;
        let engine = YaraEngine::from_source(rule).unwrap();
        let matches = engine.scan_bytes(b"deliver the payload now").unwrap();
        assert_eq!(matches.len(), 1);
        assert!(matches[0].tags.contains(&"trojan".to_owned()));
        assert!(matches[0].tags.contains(&"dropper".to_owned()));
    }

    // 7. Scan empty data — no matches expected.
    #[test]
    fn scan_empty_data() {
        let engine = YaraEngine::from_source(RULE_MALWARE).unwrap();
        let matches = engine.scan_bytes(b"").unwrap();
        assert!(matches.is_empty());
    }

    // 8. Scan a file from disk.
    #[test]
    fn scan_file_from_disk() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"file with malware payload").unwrap();
        tmp.flush().unwrap();

        let engine = YaraEngine::from_source(RULE_MALWARE).unwrap();
        let matches = engine.scan_file(tmp.path()).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "detect_malware");
    }

    // 9. Compile from multiple sources.
    #[test]
    fn from_multiple_sources() {
        let src1 = r#"
            rule first {
                strings:
                    $x = "one"
                condition:
                    $x
            }
        "#;
        let src2 = r#"
            rule second {
                strings:
                    $y = "two"
                condition:
                    $y
            }
        "#;
        let engine = YaraEngine::from_sources(&[src1, src2]).unwrap();
        assert_eq!(engine.rule_count(), 2);

        let matches = engine.scan_bytes(b"one and two").unwrap();
        assert_eq!(matches.len(), 2);
    }

    // 10. Rule with hex strings.
    #[test]
    fn rule_with_hex_strings() {
        let rule = r#"
            rule hex_detect {
                strings:
                    $hex = { 4D 5A 90 00 }
                condition:
                    $hex
            }
        "#;
        let engine = YaraEngine::from_source(rule).unwrap();

        // Data that contains the hex pattern (MZ header).
        let data: &[u8] = &[0x4D, 0x5A, 0x90, 0x00, 0xFF, 0xFF];
        let matches = engine.scan_bytes(data).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "hex_detect");
        assert!(matches[0].strings_matched.contains(&"$hex".to_owned()));

        // Data that does NOT contain the hex pattern.
        let no_match = engine.scan_bytes(b"no PE here").unwrap();
        assert!(no_match.is_empty());
    }

    // 11. Compile from a .yar file on disk.
    #[test]
    fn from_yar_file() {
        let mut tmp = tempfile::Builder::new().suffix(".yar").tempfile().unwrap();
        writeln!(
            tmp,
            r#"rule from_file {{ strings: $s = "disk" condition: $s }}"#
        )
        .unwrap();
        tmp.flush().unwrap();

        let engine = YaraEngine::from_file(tmp.path()).unwrap();
        assert_eq!(engine.rule_count(), 1);

        let matches = engine.scan_bytes(b"read from disk").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "from_file");
    }

    // 12. Namespace defaults to "default".
    #[test]
    fn default_namespace() {
        let engine = YaraEngine::from_source(RULE_MALWARE).unwrap();
        let matches = engine.scan_bytes(b"malware").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].namespace, "default");
    }
}
