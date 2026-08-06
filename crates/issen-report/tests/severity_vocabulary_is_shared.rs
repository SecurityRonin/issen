// An integration test is its own crate, so the workspace's `cfg(test)`-scoped
// allow does not reach it and the attribute has to be repeated here. In these
// tests the unwrap/expect IS the assertion.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The HTML report's severity vocabulary must come from the one shared source.
//!
//! `severity_rank`/`severity_token` in `issen-report` were copies of the pair in
//! `issen-correlation` (and the parse half was copied a third time into
//! `navigator_output::severity_of`). The copies drifted, and the drift shipped:
//! `render_html` emits `class="severity-{token}"` — `severity-info` for the
//! bottom tier — while the stylesheet only ever defined
//! `.severity-informational`, so Info findings render unstyled.

use issen_core::severity::{self, SeverityExt};
use issen_report::{render_html, FindingRow, ReportConfig, ReportData, ReportSummary};

fn report_with_findings(findings: Vec<FindingRow>) -> ReportData {
    let total_findings = findings.len();
    ReportData {
        config: ReportConfig::default(),
        generated_at: "2026-08-01T00:00:00Z".to_string(),
        events: Vec::new(),
        summary: ReportSummary {
            total_events: 0,
            events_by_source: Vec::new(),
            events_by_type: Vec::new(),
            time_range: None,
            total_findings,
        },
        findings,
        correlations: Vec::new(),
        member_events: std::collections::HashMap::new(),
        provenance: Vec::new(),
    }
}

fn finding(severity: &str) -> FindingRow {
    FindingRow {
        engine: "Timestomp".to_string(),
        rule_name: format!("R-{severity}"),
        severity: severity.to_string(),
        target: "C:/x".to_string(),
        description: "d".to_string(),
        tags: Vec::new(),
    }
}

/// Every severity class the renderer can emit must have a stylesheet rule.
/// This is the drift that actually shipped.
#[test]
fn every_emitted_severity_class_has_a_matching_css_rule() {
    let findings = severity::TOKENS.iter().map(|t| finding(t)).collect();
    let html = render_html(&report_with_findings(findings));

    for token in severity::TOKENS {
        assert!(
            html.contains(&format!("class=\"severity-{token}\"")),
            "renderer must emit severity-{token}"
        );
        assert!(
            html.contains(&format!(".severity-{token} ")),
            "stylesheet is missing a `.severity-{token}` rule, so that tier \
             renders unstyled"
        );
    }
}

/// The stylesheet must not carry a rule for a token the renderer never emits.
#[test]
fn the_stylesheet_has_no_orphan_severity_rule() {
    let html = render_html(&report_with_findings(vec![finding("info")]));
    assert!(
        !html.contains(".severity-informational"),
        "`informational` is not a token the shared vocabulary emits; the \
         canonical bottom tier is `info`"
    );
}

/// The renderer's tier→class mapping must agree with the shared token fn.
#[test]
fn the_rendered_class_is_the_shared_token() {
    for token in severity::TOKENS {
        let sev = severity::parse(token).expect("shared token parses");
        let html = render_html(&report_with_findings(vec![finding(token)]));
        assert!(
            html.contains(&format!("class=\"severity-{}\"", sev.token())),
            "tier {sev:?} must render as its shared token"
        );
    }
}

/// A legacy `"informational"` row (written before the consolidation) must still
/// map onto the canonical Info tier rather than falling through to a default.
#[test]
fn a_legacy_informational_row_renders_as_info() {
    let html = render_html(&report_with_findings(vec![finding("informational")]));
    assert!(html.contains("class=\"severity-info\""));
}
