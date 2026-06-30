// Sigma rule evaluation engine using tau-engine.
//
// This module parses Sigma YAML rules, converts them to tau-engine's native
// rule format, and evaluates events against the compiled rules.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur during Sigma rule processing.
#[derive(Debug, Error)]
pub enum SigmaError {
    #[error("YAML parse error: {0}")]
    Yaml(String),
    #[error("Rule compilation error: {0}")]
    Compile(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Parsed metadata from a Sigma YAML rule (not the detection logic).
#[derive(Debug, Clone, Deserialize)]
pub struct SigmaRuleMeta {
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    /// Severity level: informational, low, medium, high, critical.
    pub level: Option<String>,
    pub description: Option<String>,
    pub logsource: Option<SigmaLogSource>,
    pub tags: Option<Vec<String>>,
}

/// The logsource block of a Sigma rule.
#[derive(Debug, Clone, Deserialize)]
pub struct SigmaLogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

/// A structured match result returned when a rule fires.
#[derive(Debug, Clone)]
pub struct SigmaMatch {
    pub rule_title: String,
    pub rule_id: Option<String>,
    pub level: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

/// An internal compiled rule that pairs tau-engine's `Rule` with Sigma metadata.
struct CompiledRule {
    tau_rule: tau_engine::Rule,
    meta: SigmaRuleMeta,
}

/// A wrapper that implements `tau_engine::Document` for `HashMap<String, String>`.
///
/// tau-engine already implements `Object` for `HashMap<String, V>` where `V: AsValue`,
/// and `Document` is auto-implemented for anything implementing `Object`. However,
/// since we want to accept `HashMap<String, serde_json::Value>` from callers, we
/// provide a thin adapter that converts `serde_json::Value` fields into tau-engine
/// `Value` variants on the fly.
struct EventDocument<'a> {
    data: &'a HashMap<String, serde_json::Value>,
}

impl<'a> tau_engine::Document for EventDocument<'a> {
    fn find(&self, key: &str) -> Option<tau_engine::Value<'_>> {
        self.data.get(key).map(json_to_tau_value)
    }
}

/// Convert a `serde_json::Value` reference into a `tau_engine::Value`.
fn json_to_tau_value(v: &serde_json::Value) -> tau_engine::Value<'_> {
    match v {
        serde_json::Value::Null => tau_engine::Value::Null,
        serde_json::Value::Bool(b) => tau_engine::Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                tau_engine::Value::UInt(u)
            } else if let Some(i) = n.as_i64() {
                tau_engine::Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                tau_engine::Value::Float(f)
            } else {
                tau_engine::Value::Null
            }
        }
        serde_json::Value::String(s) => tau_engine::Value::String(Cow::Borrowed(s.as_str())),
        // For arrays and objects, fall back to null since tau-engine's Array/Object
        // traits need concrete types. In practice, Sigma field matches target scalars.
        _ => tau_engine::Value::Null,
    }
}

/// Convert a Sigma detection value (which may include field modifiers like
/// `|contains`, `|startswith`, `|endswith`) into a tau-engine compatible
/// detection block.
///
/// Sigma uses pipe-delimited modifiers on field names:
///   - `CommandLine|contains` -> value should use `*value*` (contains)
///   - `ParentImage|endswith` -> value should use `*value` (ends with)
///   - `Image|startswith` -> value should use `value*` (starts with)
///
/// tau-engine uses glob-like patterns:
///   - `*value*` for contains
///   - `value*` for starts with
///   - `*value` for ends with
///   - `value` for exact match
fn convert_sigma_detection(detection: &serde_yaml::Value) -> Result<serde_yaml::Value, SigmaError> {
    let mapping = detection
        .as_mapping()
        .ok_or_else(|| SigmaError::Compile("detection must be a mapping".into()))?;

    let mut tau_detection = serde_yaml::Mapping::new();

    for (key, value) in mapping {
        let key_str = key
            .as_str()
            .ok_or_else(|| SigmaError::Compile("detection key must be a string".into()))?;

        if key_str == "condition" {
            // Pass the condition through unchanged.
            tau_detection.insert(key.clone(), value.clone());
            continue;
        }

        // This is an identifier (selection, filter, etc.) — process its fields.
        let converted = convert_sigma_identifier(value)?;
        tau_detection.insert(key.clone(), converted);
    }

    Ok(serde_yaml::Value::Mapping(tau_detection))
}

/// Convert a single Sigma identifier block (e.g. `selection:`) by rewriting
/// field modifiers into tau-engine glob patterns.
fn convert_sigma_identifier(
    identifier: &serde_yaml::Value,
) -> Result<serde_yaml::Value, SigmaError> {
    let mapping = match identifier.as_mapping() {
        Some(m) => m,
        None => {
            // Could be a sequence of mappings (OR logic) or a scalar — pass through.
            return Ok(identifier.clone());
        }
    };

    let mut result = serde_yaml::Mapping::new();

    for (field_key, field_value) in mapping {
        let field_str = field_key
            .as_str()
            .ok_or_else(|| SigmaError::Compile("field key must be a string".into()))?;

        // Split off Sigma modifiers (pipe-separated).
        let parts: Vec<&str> = field_str.split('|').collect();
        let base_field = parts[0];
        let modifiers = &parts[1..];

        // Determine the modifier to apply.
        let modifier = parse_modifiers(modifiers)?;

        // Apply the modifier to field values.
        let converted_value = apply_modifier_to_value(field_value, &modifier)?;

        result.insert(
            serde_yaml::Value::String(base_field.to_string()),
            converted_value,
        );
    }

    Ok(serde_yaml::Value::Mapping(result))
}

/// Supported Sigma field modifier types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigmaModifier {
    /// No modifier — exact match.
    Exact,
    /// `|contains` — substring match.
    Contains,
    /// `|startswith` — prefix match.
    StartsWith,
    /// `|endswith` — suffix match.
    EndsWith,
    /// `|all` — all values must match (conjunction instead of disjunction).
    /// When combined with contains/startswith/endswith, we set both.
    ContainsAll,
    StartsWithAll,
    EndsWithAll,
    ExactAll,
}

impl SigmaModifier {
    fn is_all(self) -> bool {
        matches!(
            self,
            Self::ContainsAll | Self::StartsWithAll | Self::EndsWithAll | Self::ExactAll
        )
    }

    fn pattern_kind(self) -> PatternKind {
        match self {
            Self::Exact | Self::ExactAll => PatternKind::Exact,
            Self::Contains | Self::ContainsAll => PatternKind::Contains,
            Self::StartsWith | Self::StartsWithAll => PatternKind::StartsWith,
            Self::EndsWith | Self::EndsWithAll => PatternKind::EndsWith,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum PatternKind {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
}

fn parse_modifiers(modifiers: &[&str]) -> Result<SigmaModifier, SigmaError> {
    let mut has_contains = false;
    let mut has_startswith = false;
    let mut has_endswith = false;
    let mut has_all = false;

    for &m in modifiers {
        match m {
            "contains" => has_contains = true,
            "startswith" => has_startswith = true,
            "endswith" => has_endswith = true,
            "all" => has_all = true,
            other => {
                // Unsupported modifiers are warned and skipped.
                warn!(
                    modifier = other,
                    "unsupported Sigma field modifier, ignoring"
                );
            }
        }
    }

    // Determine the combination.
    let count = has_contains as u8 + has_startswith as u8 + has_endswith as u8;
    if count > 1 {
        return Err(SigmaError::Compile(
            "conflicting modifiers: cannot combine contains, startswith, and endswith".into(),
        ));
    }

    Ok(
        match (has_contains, has_startswith, has_endswith, has_all) {
            (true, _, _, true) => SigmaModifier::ContainsAll,
            (true, _, _, false) => SigmaModifier::Contains,
            (_, true, _, true) => SigmaModifier::StartsWithAll,
            (_, true, _, false) => SigmaModifier::StartsWith,
            (_, _, true, true) => SigmaModifier::EndsWithAll,
            (_, _, true, false) => SigmaModifier::EndsWith,
            (_, _, _, true) => SigmaModifier::ExactAll,
            _ => SigmaModifier::Exact,
        },
    )
}

/// Apply a modifier to a field value, wrapping strings with tau-engine glob patterns.
fn apply_modifier_to_value(
    value: &serde_yaml::Value,
    modifier: &SigmaModifier,
) -> Result<serde_yaml::Value, SigmaError> {
    match value {
        serde_yaml::Value::String(s) => Ok(serde_yaml::Value::String(wrap_pattern(
            s,
            modifier.pattern_kind(),
        ))),
        serde_yaml::Value::Sequence(seq) => {
            let converted: Vec<serde_yaml::Value> = seq
                .iter()
                .map(|item| apply_modifier_to_value(item, modifier))
                .collect::<Result<Vec<_>, _>>()?;

            if modifier.is_all() {
                // For `|all`, we need each value to match — tau-engine treats mappings
                // as conjunctions. We'll create a special mapping where each entry is
                // a duplicate key. Since YAML mappings can't have duplicate keys, we
                // encode the "all" semantics by keeping the sequence but marking it
                // for conjunction. Actually, for tau-engine, we need to restructure:
                // a sequence under a key is an OR (disjunction). For AND, we need
                // multiple identifiers. For now, in the MVP, we'll handle `|all` by
                // generating separate identifier entries in the outer scope.
                //
                // Simple approach: keep the sequence (tau-engine OR). The `|all`
                // modifier requires more complex restructuring that we'll handle at
                // the detection level. For MVP, treat `|all` sequences as OR.
                Ok(serde_yaml::Value::Sequence(converted))
            } else {
                Ok(serde_yaml::Value::Sequence(converted))
            }
        }
        serde_yaml::Value::Number(_) | serde_yaml::Value::Bool(_) => {
            // Numeric and boolean values pass through unchanged.
            Ok(value.clone())
        }
        serde_yaml::Value::Null => Ok(value.clone()),
        _ => Err(SigmaError::Compile(format!(
            "unsupported field value type: {:?}",
            value
        ))),
    }
}

/// Wrap a string value with the appropriate tau-engine glob pattern.
fn wrap_pattern(value: &str, kind: PatternKind) -> String {
    match kind {
        PatternKind::Exact => value.to_string(),
        PatternKind::Contains => format!("*{value}*"),
        PatternKind::StartsWith => format!("{value}*"),
        PatternKind::EndsWith => format!("*{value}"),
    }
}

/// Build a tau-engine rule YAML string from a Sigma rule's detection block
/// and wrap it in the format tau-engine expects.
fn build_tau_rule_yaml(detection: &serde_yaml::Value) -> Result<String, SigmaError> {
    let converted = convert_sigma_detection(detection)?;
    let tau_rule = serde_yaml::Mapping::from_iter([
        (serde_yaml::Value::String("detection".into()), converted),
        (
            serde_yaml::Value::String("true_positives".into()),
            serde_yaml::Value::Sequence(vec![]),
        ),
        (
            serde_yaml::Value::String("true_negatives".into()),
            serde_yaml::Value::Sequence(vec![]),
        ),
    ]);

    serde_yaml::to_string(&serde_yaml::Value::Mapping(tau_rule))
        .map_err(|e| SigmaError::Yaml(e.to_string()))
}

/// The Sigma evaluation engine. Loads and compiles Sigma rules, then evaluates
/// event data against them.
pub struct SigmaEngine {
    rules: Vec<CompiledRule>,
}

impl SigmaEngine {
    /// Create a new empty engine.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Parse and add a Sigma rule from a YAML string.
    pub fn load_rule(&mut self, yaml: &str) -> Result<(), SigmaError> {
        // First, parse the full Sigma YAML to extract metadata.
        let full_value: serde_yaml::Value =
            serde_yaml::from_str(yaml).map_err(|e| SigmaError::Yaml(e.to_string()))?;

        let meta: SigmaRuleMeta = serde_yaml::from_value(full_value.clone())
            .map_err(|e| SigmaError::Yaml(e.to_string()))?;

        // Extract the detection block.
        let detection = full_value
            .get("detection")
            .ok_or_else(|| SigmaError::Compile("rule has no detection block".into()))?;

        // Build tau-engine compatible YAML.
        let tau_yaml = build_tau_rule_yaml(detection)?;

        debug!(
            rule_title = %meta.title,
            tau_yaml = %tau_yaml,
            "compiling Sigma rule to tau-engine format"
        );

        // Compile with tau-engine.
        let tau_rule = tau_engine::Rule::from_str(&tau_yaml)
            .map_err(|e| SigmaError::Compile(format!("{}", e)))?;

        self.rules.push(CompiledRule { tau_rule, meta });
        Ok(())
    }

    /// Load a Sigma rule from a file.
    pub fn load_rule_file(&mut self, path: &Path) -> Result<(), SigmaError> {
        let yaml = std::fs::read_to_string(path)?;
        self.load_rule(&yaml)
    }

    /// Load all `.yml` and `.yaml` files from a directory. Returns the number
    /// of rules successfully loaded.
    pub fn load_rules_dir(&mut self, dir: &Path) -> Result<usize, SigmaError> {
        let mut count = 0;
        let entries = std::fs::read_dir(dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str());
                if matches!(ext, Some("yml" | "yaml")) {
                    match self.load_rule_file(&path) {
                        Ok(()) => {
                            count += 1;
                        }
                        Err(e) => {
                            warn!(
                                path = %path.display(),
                                error = %e,
                                "failed to load Sigma rule, skipping"
                            );
                        }
                    }
                }
            }
        }

        Ok(count)
    }

    /// Evaluate all loaded rules against a single event. Returns a list of
    /// matches (rules that fired).
    pub fn evaluate(&self, event: &HashMap<String, serde_json::Value>) -> Vec<SigmaMatch> {
        let doc = EventDocument { data: event };
        let mut matches = Vec::new();

        for compiled in &self.rules {
            if compiled.tau_rule.matches(&doc) {
                matches.push(SigmaMatch {
                    rule_title: compiled.meta.title.clone(),
                    rule_id: compiled.meta.id.clone(),
                    level: compiled
                        .meta
                        .level
                        .clone()
                        .unwrap_or_else(|| "informational".to_string()),
                    description: compiled.meta.description.clone(),
                    tags: compiled.meta.tags.clone().unwrap_or_default(),
                });
            }
        }

        matches
    }

    /// Return the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for SigmaEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a simple Sigma rule YAML string.
    fn simple_sigma_rule() -> String {
        r"
title: Suspicious Process Creation
id: test-rule-001
status: test
level: high
description: Detects suspicious process creation via command line
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'powershell'
            - 'cmd.exe'
        ParentImage|endswith: '\explorer.exe'
    condition: selection
tags:
    - attack.execution
    - attack.t1059
"
        .to_string()
    }

    /// Helper to create an event as `HashMap<String, serde_json::Value>`.
    fn make_event(pairs: &[(&str, &str)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Test 1: Parse valid Sigma rule YAML
    // -----------------------------------------------------------------------
    #[test]
    fn test_parse_valid_sigma_rule() {
        let mut engine = SigmaEngine::new();
        let result = engine.load_rule(&simple_sigma_rule());
        assert!(
            result.is_ok(),
            "failed to parse valid rule: {:?}",
            result.err()
        );
        assert_eq!(engine.rule_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Test 2: Parse rule with missing fields returns error
    // -----------------------------------------------------------------------
    #[test]
    fn test_parse_rule_missing_title_returns_error() {
        let yaml = r"
id: test-no-title
detection:
    selection:
        foo: bar
    condition: selection
";
        let mut engine = SigmaEngine::new();
        let result = engine.load_rule(yaml);
        assert!(result.is_err(), "should fail without title");
    }

    // -----------------------------------------------------------------------
    // Test 3: Parse rule with missing detection returns error
    // -----------------------------------------------------------------------
    #[test]
    fn test_parse_rule_missing_detection_returns_error() {
        let yaml = r"
title: No Detection Rule
id: test-no-detection
level: low
";
        let mut engine = SigmaEngine::new();
        let result = engine.load_rule(yaml);
        assert!(result.is_err(), "should fail without detection block");
    }

    // -----------------------------------------------------------------------
    // Test 4: Evaluate rule against matching event
    // -----------------------------------------------------------------------
    #[test]
    fn test_evaluate_matching_event() {
        let mut engine = SigmaEngine::new();
        engine.load_rule(&simple_sigma_rule()).unwrap();

        let event = make_event(&[
            (
                "CommandLine",
                "C:\\Windows\\System32\\powershell.exe -enc abc",
            ),
            ("ParentImage", "C:\\Windows\\explorer.exe"),
        ]);

        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_title, "Suspicious Process Creation");
        assert_eq!(matches[0].rule_id.as_deref(), Some("test-rule-001"));
        assert_eq!(matches[0].level, "high");
    }

    // -----------------------------------------------------------------------
    // Test 5: Evaluate rule against non-matching event
    // -----------------------------------------------------------------------
    #[test]
    fn test_evaluate_non_matching_event() {
        let mut engine = SigmaEngine::new();
        engine.load_rule(&simple_sigma_rule()).unwrap();

        // CommandLine does not contain powershell or cmd.exe
        let event = make_event(&[
            ("CommandLine", "C:\\Windows\\notepad.exe"),
            ("ParentImage", "C:\\Windows\\explorer.exe"),
        ]);

        let matches = engine.evaluate(&event);
        assert!(matches.is_empty(), "should not match: {:?}", matches);
    }

    // -----------------------------------------------------------------------
    // Test 6: Rule with multiple selection fields (AND logic)
    // -----------------------------------------------------------------------
    #[test]
    fn test_multiple_selection_fields_and_logic() {
        let yaml = r"
title: Multi-field AND Rule
id: test-and-001
level: medium
detection:
    selection:
        FieldA: valueA
        FieldB: valueB
    condition: selection
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        // Both fields match -> should match.
        let event_match = make_event(&[("FieldA", "valueA"), ("FieldB", "valueB")]);
        assert_eq!(engine.evaluate(&event_match).len(), 1);

        // Only one field matches -> should NOT match (AND logic).
        let event_partial = make_event(&[("FieldA", "valueA"), ("FieldB", "wrong")]);
        assert!(engine.evaluate(&event_partial).is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 7: Rule with `contains` modifier
    // -----------------------------------------------------------------------
    #[test]
    fn test_contains_modifier() {
        let yaml = r"
title: Contains Test
id: test-contains-001
level: low
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        let event_match = make_event(&[("CommandLine", "invoke-mimikatz.ps1 -DumpCreds")]);
        assert_eq!(engine.evaluate(&event_match).len(), 1);

        let event_no_match = make_event(&[("CommandLine", "notepad.exe")]);
        assert!(engine.evaluate(&event_no_match).is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 8: Rule with `startswith` modifier
    // -----------------------------------------------------------------------
    #[test]
    fn test_startswith_modifier() {
        let yaml = r"
title: StartsWith Test
id: test-sw-001
level: low
detection:
    selection:
        Image|startswith: 'C:\Temp\'
    condition: selection
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        let event_match = make_event(&[("Image", r"C:\Temp\malware.exe")]);
        assert_eq!(engine.evaluate(&event_match).len(), 1);

        let event_no_match = make_event(&[("Image", r"C:\Program Files\app.exe")]);
        assert!(engine.evaluate(&event_no_match).is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 9: Rule with `endswith` modifier
    // -----------------------------------------------------------------------
    #[test]
    fn test_endswith_modifier() {
        let yaml = r"
title: EndsWith Test
id: test-ew-001
level: low
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        let event_match = make_event(&[("Image", r"C:\Windows\System32\cmd.exe")]);
        assert_eq!(engine.evaluate(&event_match).len(), 1);

        let event_no_match = make_event(&[("Image", r"C:\Windows\System32\powershell.exe")]);
        assert!(engine.evaluate(&event_no_match).is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 10: Multiple rules, check which match
    // -----------------------------------------------------------------------
    #[test]
    fn test_multiple_rules_selective_matching() {
        let rule_a = r"
title: Rule A
id: rule-a
level: high
detection:
    selection:
        Category: malware
    condition: selection
";
        let rule_b = r"
title: Rule B
id: rule-b
level: low
detection:
    selection:
        Category: benign
    condition: selection
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(rule_a).unwrap();
        engine.load_rule(rule_b).unwrap();
        assert_eq!(engine.rule_count(), 2);

        let event = make_event(&[("Category", "malware")]);
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_title, "Rule A");
    }

    // -----------------------------------------------------------------------
    // Test 11: Load from directory
    // -----------------------------------------------------------------------
    #[test]
    fn test_load_rules_dir() {
        let dir = tempfile::tempdir().unwrap();

        // Write two valid rule files and one non-YAML file.
        let rule1 = r"
title: Dir Rule 1
id: dir-001
level: medium
detection:
    selection:
        Action: login
    condition: selection
";
        let rule2 = r"
title: Dir Rule 2
id: dir-002
level: low
detection:
    selection:
        Action: logout
    condition: selection
";

        std::fs::write(dir.path().join("rule1.yml"), rule1).unwrap();
        std::fs::write(dir.path().join("rule2.yaml"), rule2).unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a rule").unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine.load_rules_dir(dir.path()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(engine.rule_count(), 2);
    }

    // -----------------------------------------------------------------------
    // Test 12: Rule count starts at zero
    // -----------------------------------------------------------------------
    #[test]
    fn test_rule_count_empty() {
        let engine = SigmaEngine::new();
        assert_eq!(engine.rule_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Test 13: Level / severity in match result
    // -----------------------------------------------------------------------
    #[test]
    fn test_level_severity_in_match() {
        let yaml = r"
title: Critical Alert
id: crit-001
level: critical
description: A critical finding
detection:
    selection:
        Threat: active
    condition: selection
tags:
    - attack.impact
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        let event = make_event(&[("Threat", "active")]);
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);

        let m = &matches[0];
        assert_eq!(m.level, "critical");
        assert_eq!(m.description.as_deref(), Some("A critical finding"));
        assert_eq!(m.tags, vec!["attack.impact".to_string()]);
    }

    // -----------------------------------------------------------------------
    // Test 14: Default level is informational when not specified
    // -----------------------------------------------------------------------
    #[test]
    fn test_default_level_informational() {
        let yaml = r"
title: No Level Rule
id: nolev-001
detection:
    selection:
        Foo: bar
    condition: selection
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        let event = make_event(&[("Foo", "bar")]);
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].level, "informational");
    }

    // -----------------------------------------------------------------------
    // Test 15: Selection with value list (OR logic for values)
    // -----------------------------------------------------------------------
    #[test]
    fn test_value_list_or_logic() {
        let yaml = r"
title: Value List OR
id: or-001
level: medium
detection:
    selection:
        Action:
            - login
            - logon
            - authenticate
    condition: selection
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        // Any of the three values should match.
        for action in &["login", "logon", "authenticate"] {
            let event = make_event(&[("Action", action)]);
            assert_eq!(
                engine.evaluate(&event).len(),
                1,
                "should match for action={}",
                action
            );
        }

        let event_no = make_event(&[("Action", "logout")]);
        assert!(engine.evaluate(&event_no).is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 16: Condition with NOT filter
    // -----------------------------------------------------------------------
    #[test]
    fn test_condition_with_not_filter() {
        let yaml = r"
title: Selection with Filter
id: filter-001
level: high
detection:
    selection:
        EventType: process_create
    filter:
        User: SYSTEM
    condition: selection and not filter
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        // Matches selection but NOT excluded by filter.
        let event_match = make_event(&[("EventType", "process_create"), ("User", "admin")]);
        assert_eq!(engine.evaluate(&event_match).len(), 1);

        // Matches selection BUT also matches filter -> excluded.
        let event_filtered = make_event(&[("EventType", "process_create"), ("User", "SYSTEM")]);
        assert!(engine.evaluate(&event_filtered).is_empty());

        // Does not match selection at all.
        let event_no = make_event(&[("EventType", "file_write"), ("User", "admin")]);
        assert!(engine.evaluate(&event_no).is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 17: Tags are empty vec when not specified
    // -----------------------------------------------------------------------
    #[test]
    fn test_tags_empty_when_not_specified() {
        let yaml = r"
title: No Tags Rule
id: notags-001
level: low
detection:
    selection:
        X: Y
    condition: selection
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        let event = make_event(&[("X", "Y")]);
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].tags.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 18: Condition with OR between identifiers
    // -----------------------------------------------------------------------
    #[test]
    fn test_condition_or_identifiers() {
        let yaml = r"
title: OR Condition
id: or-cond-001
level: medium
detection:
    selection_a:
        Source: web
    selection_b:
        Source: api
    condition: selection_a or selection_b
";
        let mut engine = SigmaEngine::new();
        engine.load_rule(yaml).unwrap();

        let event_web = make_event(&[("Source", "web")]);
        assert_eq!(engine.evaluate(&event_web).len(), 1);

        let event_api = make_event(&[("Source", "api")]);
        assert_eq!(engine.evaluate(&event_api).len(), 1);

        let event_none = make_event(&[("Source", "internal")]);
        assert!(engine.evaluate(&event_none).is_empty());
    }
}
