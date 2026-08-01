//! `forensic-pivot` must not define its own `Severity`.
//!
//! `rule::Severity` was `Critical/High/Medium/Low/Info` — the exact variant set
//! of `forensicnomicon::report::Severity`, only declared highest-first and
//! without the canonical type's `Ord`/`Display`. A pure duplicate, so it
//! migrates onto the canonical type; nothing here is a distinct native scale
//! that would warrant an ADR-0007 boundary conversion instead.
//!
//! The identity assertion is spelled through `type_name` so it compiles both
//! before and after the migration and fails at runtime naming the clone.

use forensic_pivot::{PivotRule, Severity};

#[test]
fn severity_is_the_canonical_forensicnomicon_type() {
    let name = std::any::type_name::<Severity>();
    assert!(
        name.starts_with("forensicnomicon"),
        "forensic-pivot must re-export forensicnomicon's Severity, not clone it \
         (got `{name}`)"
    );
}

#[test]
fn rule_yaml_still_deserializes_every_severity_word() {
    // The bundled rule packs spell severity with the variant name; the canonical
    // enum uses the same five words, so existing YAML keeps parsing.
    for word in ["Critical", "High", "Medium", "Low", "Info"] {
        let yaml = format!(
            r"
id: R-1
name: test rule
description: d
severity: {word}
assertion_level: Observed
default_confidence: 50
clauses: []
"
        );
        let rule: PivotRule =
            serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("`{word}` must parse: {e}"));
        assert_eq!(format!("{:?}", rule.severity), word);
    }
}
