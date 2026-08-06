// An integration test is its own crate, so the workspace's `cfg(test)`-scoped
// allow does not reach it and the top-level attribute has to be repeated here.
// The expect below IS the assertion — every TOKENS entry must parse — and
// rewriting it as a match would only obscure which entry failed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The severity rank/token vocabulary must have exactly ONE definition.
//!
//! `severity_rank` / `severity_token` were copy-pasted into `issen-report` and
//! `issen-correlation` (and the parse half into `issen-report::navigator_output`
//! and `issen-signatures`). Divergence between the copies is not hypothetical:
//! the report's stylesheet shipped a `.severity-informational` rule while its
//! own token function emitted `info`, so the Info tier rendered unstyled.
//!
//! Interim home: `issen_core::severity`. The upstream fix is
//! `forensicnomicon::report::Severity::rank()` / `::token()` — once those land,
//! the inherent methods shadow `SeverityExt` and this module can be deleted
//! without touching a single call site.

use forensicnomicon::report::Severity;
use issen_core::severity::{self, SeverityExt};

#[test]
fn rank_orders_info_lowest_and_critical_highest() {
    assert_eq!(Severity::Info.rank(), 0);
    assert_eq!(Severity::Low.rank(), 1);
    assert_eq!(Severity::Medium.rank(), 2);
    assert_eq!(Severity::High.rank(), 3);
    assert_eq!(Severity::Critical.rank(), 4);
}

#[test]
fn rank_agrees_with_the_derived_ord() {
    // `Severity` already derives `Ord`; `rank` must never disagree with it.
    let ordered = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for pair in ordered.windows(2) {
        assert!(pair[0] < pair[1], "{:?} < {:?}", pair[0], pair[1]);
        assert!(
            pair[0].rank() < pair[1].rank(),
            "rank must track Ord: {:?} vs {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn token_is_the_lowercase_persisted_form() {
    assert_eq!(Severity::Info.token(), "info");
    assert_eq!(Severity::Low.token(), "low");
    assert_eq!(Severity::Medium.token(), "medium");
    assert_eq!(Severity::High.token(), "high");
    assert_eq!(Severity::Critical.token(), "critical");
}

#[test]
fn tokens_constant_is_ordered_lowest_to_highest_and_matches_token() {
    assert_eq!(
        severity::TOKENS,
        ["info", "low", "medium", "high", "critical"]
    );
    for (idx, tok) in severity::TOKENS.iter().enumerate() {
        let parsed = severity::parse(tok).expect("every TOKENS entry must parse");
        assert_eq!(usize::from(parsed.rank()), idx, "TOKENS[{idx}] = {tok}");
        assert_eq!(parsed.token(), *tok);
    }
}

#[test]
fn parse_is_case_insensitive_and_round_trips() {
    for tok in severity::TOKENS {
        let upper = tok.to_uppercase();
        assert_eq!(
            severity::parse(&upper),
            severity::parse(tok),
            "parse must be case-insensitive for {tok}"
        );
    }
    // The canonical `Display` is UPPERCASE — it must feed straight back in.
    for sev in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        assert_eq!(severity::parse(&sev.to_string()), Some(sev));
    }
}

#[test]
fn parse_accepts_informational_as_a_legacy_alias_for_info() {
    // Pre-consolidation rows persisted by `issen-signatures` carry
    // "informational"; they must keep reading back as `Info`.
    assert_eq!(severity::parse("informational"), Some(Severity::Info));
    assert_eq!(severity::parse("Informational"), Some(Severity::Info));
}

#[test]
fn parse_rejects_an_unknown_token_and_shows_it_lossily_as_info() {
    assert_eq!(severity::parse("catastrophic"), None);
    assert_eq!(severity::parse(""), None);
    // The lossy half (what `--min-severity` and the Sigma level field need)
    // degrades to the lowest tier rather than failing.
    assert_eq!(severity::parse_lossy("catastrophic"), Severity::Info);
    assert_eq!(severity::parse_lossy("CRITICAL"), Severity::Critical);
    assert_eq!(severity::parse_lossy("informational"), Severity::Info);
}
