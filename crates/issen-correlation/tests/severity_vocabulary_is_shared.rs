//! `Correlation`'s severity token/parse pair must come from the one shared
//! vocabulary, not a third hand-rolled copy.
//!
//! `severity_str`/`severity_from_str` here duplicated `severity_token`/
//! `severity_from_finding_str` in `issen-report`. The copies had already
//! drifted: this one parses case-sensitively (`"Info"` → `None`) while the
//! report's is case-insensitive — and `issen-disk` writes a capitalised
//! `"High"` into event metadata.

use forensicnomicon::report::Severity;
use issen_core::severity::{self, SeverityExt};
use issen_correlation::correlation::Correlation;

const LADDER: [Severity; 5] = [
    Severity::Info,
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

#[test]
fn severity_str_is_the_shared_token() {
    for sev in LADDER {
        let c = Correlation::new("CORR-X", sev);
        assert_eq!(
            c.severity_str(),
            sev.token(),
            "Correlation must render the shared token for {sev:?}"
        );
    }
}

#[test]
fn severity_from_str_is_the_shared_parser_and_round_trips() {
    for sev in LADDER {
        let token = sev.token();
        assert_eq!(Correlation::severity_from_str(token), Some(sev));
        assert_eq!(
            Correlation::severity_from_str(token),
            severity::parse(token)
        );
    }
}

#[test]
fn severity_from_str_accepts_the_capitalised_form_issen_disk_writes() {
    // `issen-disk` persists `severity` metadata as `"High"`; a case-sensitive
    // parser silently drops it.
    assert_eq!(Correlation::severity_from_str("High"), Some(Severity::High));
    assert_eq!(Correlation::severity_from_str("Info"), Some(Severity::Info));
    assert_eq!(
        Correlation::severity_from_str("CRITICAL"),
        Some(Severity::Critical)
    );
}

#[test]
fn severity_from_str_still_rejects_a_non_severity() {
    assert_eq!(Correlation::severity_from_str("catastrophic"), None);
    assert_eq!(Correlation::severity_from_str(""), None);
}
