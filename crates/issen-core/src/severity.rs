//! The single source of truth for issen's severity rank / token / parse
//! vocabulary over [`forensicnomicon::report::Severity`].
//!
//! The canonical enum already carries the *ordering* (`Ord`) and the
//! *human-facing* rendering (`Display`, uppercase). What it does not yet carry
//! is the **persisted** form: the lowercase token issen writes into
//! `scan_findings.severity`, the `correlations.severity` column, and the report
//! stylesheet's `.severity-<token>` classes — plus the parse back.
//!
//! Those were hand-rolled three times (`issen-report`, `issen-correlation`, and
//! the parse half again in `issen-report::navigator_output` and
//! `issen-signatures`) and had already drifted apart. One definition lives here.
//!
//! **Interim home.** The right owner is `forensicnomicon` itself —
//! `Severity::rank()` and `Severity::token()` as inherent methods. Once those
//! land upstream they *shadow* [`SeverityExt`], so this module can be deleted
//! without touching a single call site.

use forensicnomicon::report::Severity;

/// The canonical lowercase tokens, ordered lowest severity to highest.
///
/// Index into this array is the tier's [`SeverityExt::rank`].
pub const TOKENS: [&str; 5] = ["info", "low", "medium", "high", "critical"];

/// The pre-consolidation spelling of the bottom tier, still accepted on read.
///
/// `issen-signatures` persisted `Informational`/`"informational"` before it
/// migrated onto the canonical enum, so case DBs written by earlier runs carry
/// that token in `scan_findings.severity`.
const LEGACY_INFO_ALIAS: &str = "informational";

/// Rank and token accessors for [`Severity`].
///
/// Deliberately a trait rather than free functions so the eventual upstream
/// inherent methods shadow it and the migration is a pure deletion.
pub trait SeverityExt {
    /// Total-ordering rank, `Info` = 0 through `Critical` = 4.
    ///
    /// Always consistent with the enum's derived `Ord`.
    fn rank(self) -> u8;

    /// The lowercase token persisted in `DuckDB` and emitted as a CSS class.
    fn token(self) -> &'static str;
}

impl SeverityExt for Severity {
    fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
            // `Severity` is `#[non_exhaustive]`; an unknown future variant ranks
            // above the known set rather than masquerading as Info.
            _ => 5, // cov:unreachable: Severity has exactly five known variants today
        }
    }

    fn token(self) -> &'static str {
        match self {
            Severity::Info => TOKENS[0],
            Severity::Low => TOKENS[1],
            Severity::Medium => TOKENS[2],
            Severity::High => TOKENS[3],
            Severity::Critical => TOKENS[4],
            // A future variant gets a distinct sentinel rather than
            // masquerading as a known severity.
            _ => "unknown", // cov:unreachable: Severity has exactly five known variants today
        }
    }
}

/// Parse a severity token, case-insensitively. `None` for anything that is not
/// a severity — the caller decides whether that is an error or a default.
///
/// Accepts the canonical `Display` form (`"HIGH"`), the persisted token
/// (`"high"`), and the legacy `"informational"` spelling of `Info`.
#[must_use]
pub fn parse(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" | LEGACY_INFO_ALIAS => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// [`parse`], degrading an unrecognized token to the lowest tier.
///
/// For inputs where refusing is worse than under-grading: a `--min-severity`
/// flag, or a Sigma rule whose `level` field is absent or non-standard.
#[must_use]
pub fn parse_lossy(s: &str) -> Severity {
    parse(s).unwrap_or(Severity::Info)
}

#[cfg(test)]
mod tests {
    use super::{parse, parse_lossy, SeverityExt, TOKENS};
    use forensicnomicon::report::Severity;

    const LADDER: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    #[test]
    fn rank_and_token_agree_with_tokens_order() {
        for (idx, sev) in LADDER.iter().enumerate() {
            assert_eq!(usize::from(sev.rank()), idx);
            assert_eq!(sev.token(), TOKENS[idx]);
        }
    }

    #[test]
    fn rank_never_disagrees_with_ord() {
        for pair in LADDER.windows(2) {
            assert!(pair[0] < pair[1]);
            assert!(pair[0].rank() < pair[1].rank());
        }
    }

    #[test]
    fn parse_round_trips_token_and_display() {
        for sev in LADDER {
            assert_eq!(parse(sev.token()), Some(sev));
            assert_eq!(parse(&sev.to_string()), Some(sev));
        }
    }

    #[test]
    fn parse_accepts_the_legacy_informational_alias() {
        assert_eq!(parse("informational"), Some(Severity::Info));
        assert_eq!(parse("Informational"), Some(Severity::Info));
    }

    #[test]
    fn parse_rejects_a_non_severity_and_parse_lossy_floors_it() {
        assert_eq!(parse("catastrophic"), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse_lossy("catastrophic"), Severity::Info);
        assert_eq!(parse_lossy(""), Severity::Info);
    }
}
