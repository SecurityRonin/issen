use forensic_pivot::{
    load_rules_from_yaml_str, load_rules_from_dir, bundled_rules,
    Severity, AssertionLevel, PivotRule,
};
use std::io::Write as IoWrite;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// 1. Parse a minimal YAML rule document
// ---------------------------------------------------------------------------
#[test]
fn load_rules_from_yaml_string_returns_rule_with_correct_id() {
    let yaml = r#"
id: test-001
name: Test Rule
description: Test
severity: High
assertion_level: Observed
default_confidence: 75
clauses: []
"#;
    let rules = load_rules_from_yaml_str(yaml).expect("parse should succeed");
    assert_eq!(rules.len(), 1);
    let r = &rules[0];
    assert_eq!(r.id, "test-001");
    assert_eq!(r.name, "Test Rule");
    assert_eq!(r.severity, Severity::High);
    assert_eq!(r.assertion_level, AssertionLevel::Observed);
    assert_eq!(r.default_confidence, 75);
    assert!(r.clauses.is_empty());
}

// ---------------------------------------------------------------------------
// 2. Parse multiple rules from one YAML document (--- separator)
// ---------------------------------------------------------------------------
#[test]
fn load_rules_from_yaml_string_parses_multiple_docs() {
    let yaml = r#"
id: rule-a
name: Rule A
description: First
severity: Low
assertion_level: Inferred
default_confidence: 30
clauses: []
---
id: rule-b
name: Rule B
description: Second
severity: Critical
assertion_level: Correlated
default_confidence: 90
clauses: []
"#;
    let rules = load_rules_from_yaml_str(yaml).expect("parse should succeed");
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].id, "rule-a");
    assert_eq!(rules[1].id, "rule-b");
}

// ---------------------------------------------------------------------------
// 3. Nonexistent directory returns empty, not error
// ---------------------------------------------------------------------------
#[test]
fn load_rules_from_dir_returns_empty_for_nonexistent_dir() {
    let rules = load_rules_from_dir(std::path::Path::new("/no/such/directory/abc123"));
    assert!(rules.is_empty());
}

// ---------------------------------------------------------------------------
// 4. Directory with one .yml file loads its rules
// ---------------------------------------------------------------------------
#[test]
fn load_rules_from_dir_finds_yml_files() {
    let dir = TempDir::new().expect("tempdir");
    let rule_path = dir.path().join("my-rule.yml");
    let mut f = std::fs::File::create(&rule_path).expect("create file");
    f.write_all(b"id: dir-rule-001\nname: Dir Rule\ndescription: From dir\nseverity: Medium\nassertion_level: Observed\ndefault_confidence: 50\nclauses: []\n")
        .expect("write");

    let rules = load_rules_from_dir(dir.path());
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "dir-rule-001");
}

// ---------------------------------------------------------------------------
// 5. Bundled rules are non-empty
// ---------------------------------------------------------------------------
#[test]
fn bundled_rules_are_nonempty() {
    let rules = bundled_rules();
    assert!(!rules.is_empty(), "bundled_rules() must return at least one rule");
}

// ---------------------------------------------------------------------------
// 6. Round-trip: PivotRule serializes to YAML and back
// ---------------------------------------------------------------------------
#[test]
fn pivot_rule_yaml_roundtrip() {
    let original = PivotRule {
        id: "round-trip-001".to_string(),
        name: "Round Trip".to_string(),
        description: "Test roundtrip".to_string(),
        severity: Severity::Medium,
        assertion_level: AssertionLevel::Correlated,
        default_confidence: 60,
        clauses: vec![],
        time_window_secs: Some(300),
    };

    let yaml = serde_yaml::to_string(&original).expect("serialize");
    let restored: PivotRule = serde_yaml::from_str(&yaml).expect("deserialize");

    assert_eq!(restored.id, original.id);
    assert_eq!(restored.name, original.name);
    assert_eq!(restored.severity, original.severity);
    assert_eq!(restored.assertion_level, original.assertion_level);
    assert_eq!(restored.default_confidence, original.default_confidence);
    assert_eq!(restored.time_window_secs, original.time_window_secs);
}
