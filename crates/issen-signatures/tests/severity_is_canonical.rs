//! `issen-signatures` must not define its own `Severity`.
//!
//! Its enum was `Informational/Low/Medium/High/Critical` — the canonical
//! `forensicnomicon::report::Severity` scale under a different spelling of the
//! bottom tier, plus a private `from_str_lossy` and a private lowercase
//! `Display`. That is a duplicate, not a distinct scale (contrast
//! `srum-analysis`, whose `Clean/Informational/Suspicious/Critical` is a real
//! native scale and correctly normalizes at its boundary per ADR-0007), so it
//! migrates onto the canonical type rather than converting at a boundary.

use forensicnomicon::report::Severity as Canonical;
use issen_signatures::matching::results::{MatchSource, ScanFinding, ScanReport, Severity};

/// The migration test. Written in constructs that compile both before and
/// after, so the failure is a runtime one naming the offending type rather
/// than a build break.
#[test]
fn severity_is_the_canonical_forensicnomicon_type() {
    assert_eq!(
        std::any::type_name::<Severity>(),
        std::any::type_name::<Canonical>(),
        "issen-signatures must re-export forensicnomicon's Severity, not clone it"
    );
}

/// Behaviour that must survive the migration: `Ord` drives `max_severity` and
/// the `--min-severity` threshold filter.
#[test]
fn ordering_and_threshold_filtering_survive_the_migration() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);

    let mut report = ScanReport::new("target");
    report.add_finding(ScanFinding {
        source: MatchSource::Yara,
        severity: Severity::High,
        rule_name: "hi".to_string(),
        description: String::new(),
        matched_indicator: None,
        tags: Vec::new(),
    });
    assert_eq!(report.max_severity(), Some(Severity::High));
    assert_eq!(report.findings_at_or_above(Severity::Medium).len(), 1);
    assert_eq!(report.findings_at_or_above(Severity::Critical).len(), 0);
}
