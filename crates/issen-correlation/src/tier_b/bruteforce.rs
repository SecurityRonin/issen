//! `CORR-BRUTEFORCE-LOGON` (plan v4 §5.2).
//!
//! A 4625 failed-logon *burst* (identified upstream by
//! `issen_timeline::burst_windows`) followed by a 4624 success from the **same
//! source IP** within a window — RDP/network brute force leading to a valid
//! session. The evaluator is storage-free, so the already-identified burst is
//! passed in as the anchor event (carrying the source-IP join entity); the
//! success rows are the candidate consequents. Join on [`EntityRef::Ip`].
//! Ordered: the burst strictly before the success, within ≤ 30 min, same host.
//! ATT&CK: T1110 (brute force) → T1021.001 (RDP).
//!
//! [`EntityRef::Ip`]: issen_core::timeline::event::EntityRef::Ip

use chrono::DateTime;

use crate::correlation::Correlation;
use crate::evaluator::{evaluate, EventView, RuleSpec, ScopeRule};

/// Examiner-facing note — an observation, never a verdict. The generic phrasing
/// used when the anchor carries no burst summary; [`bruteforce_note`] supersedes
/// it with the concrete failure count + window when the summary is present.
pub const BRUTEFORCE_NOTE: &str =
    "A failed-logon burst followed by a successful logon linked to the same source \
     IP or targeted account is consistent with a successful brute-force attempt \
     (T1110).";

/// One second in nanoseconds — the granularity at which a burst's first/last
/// failures count as the "same instant" (so a same-second burst shows one time,
/// not a spurious from→to range).
const NS_PER_SEC: i64 = 1_000_000_000;

/// Render a nanosecond instant as `YYYY-MM-DD HH:MM:SS UTC`. An out-of-range
/// value (beyond chrono's representable span) falls back to the raw nanoseconds
/// rather than panicking.
fn fmt_instant(ns: i64) -> String {
    DateTime::from_timestamp_nanos(ns)
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

/// The concrete brute-force note: how many failures, over what window, then a
/// success from the same source IP. A burst whose failures all land in one
/// wall-clock second collapses to a single instant ("at T") instead of a range
/// ("between T1 and T2"). Stays an observation — "consistent with", never a
/// verdict.
#[must_use]
pub fn bruteforce_note(failure_count: usize, first_ns: i64, last_ns: i64) -> String {
    let when = if first_ns.div_euclid(NS_PER_SEC) == last_ns.div_euclid(NS_PER_SEC) {
        format!("at {}", fmt_instant(first_ns))
    } else {
        format!(
            "between {} and {}",
            fmt_instant(first_ns),
            fmt_instant(last_ns)
        )
    };
    format!(
        "A burst of {failure_count} failed logons {when}, followed by a successful \
         logon linked to the same source IP or targeted account, is consistent \
         with a successful brute-force attempt (T1110)."
    )
}

/// 30 minutes in nanoseconds — the burst→success window (plan v4 §5.2).
pub const BRUTEFORCE_WINDOW_NS: i64 = 30 * 60 * 1_000_000_000;

/// The ordered-window rule. The anchor is the identified 4625 burst
/// (`LogonFailureBurst`), the consequent a 4624 `LogonSuccess`; both carry the
/// source IP as their [`EntityRef::Ip`] join entity, so the engine joins on the
/// shared source address.
///
/// [`EntityRef::Ip`]: issen_core::timeline::event::EntityRef::Ip
#[must_use]
pub fn bruteforce_rule() -> RuleSpec {
    RuleSpec {
        code: "CORR-BRUTEFORCE-LOGON",
        attack_technique: Some("T1110"),
        severity: forensicnomicon::report::Severity::High,
        anchor_event_type: "LogonFailureBurst",
        consequent_event_type: "LogonSuccess",
        window_ns: BRUTEFORCE_WINDOW_NS,
        scope: ScopeRule::SameHost,
        note: BRUTEFORCE_NOTE,
        ordered: true,
        guard: None,
    }
}

/// Evaluate the brute-force rule against an identified burst anchor and
/// `LogonSuccess` candidates. Thin wrapper over the generic engine; both sides
/// must carry the source IP as their join entity.
#[must_use]
pub fn evaluate_bruteforce<A, C>(burst: &A, successes: &[C]) -> Option<Correlation>
where
    A: EventView,
    C: EventView,
{
    let correlation = evaluate(&bruteforce_rule(), burst, successes)?;
    // When the anchor carries a burst summary (the runner's synthesized
    // LogonFailureBurst does), supersede the generic note with the concrete
    // failure count + window. An anchor without one keeps the static note.
    Some(match burst.burst_summary() {
        Some((count, first_ns, last_ns)) => {
            correlation.with_note(bruteforce_note(count, first_ns, last_ns))
        }
        None => correlation,
    })
}

#[cfg(test)]
mod tests {
    use super::super::testkit::TestEvent;
    use super::*;
    use crate::correlation::{CorrelationRole, CorrelationScope};
    use crate::evaluator::EventSource;
    use forensicnomicon::report::Severity;
    use issen_core::timeline::event::EntityRef;

    fn burst(id: u64, ts: i64, ip: &str) -> TestEvent {
        TestEvent::new(id, ts, "LogonFailureBurst", "DC01", EventSource::Evtx)
            .with_entity(EntityRef::Ip(ip.to_string()))
    }

    fn success(id: u64, ts: i64, ip: &str) -> TestEvent {
        TestEvent::new(id, ts, "LogonSuccess", "DC01", EventSource::Evtx)
            .with_entity(EntityRef::Ip(ip.to_string()))
    }

    #[test]
    fn fires_for_burst_then_success_from_same_ip() {
        let anchor = burst(1, 1_000, "194.61.24.102");
        let cands = vec![success(2, 2_000, "194.61.24.102")];

        let corr = evaluate_bruteforce(&anchor, &cands).expect("a correlation");
        assert_eq!(corr.code, "CORR-BRUTEFORCE-LOGON");
        assert_eq!(corr.attack_technique.as_deref(), Some("T1110"));
        assert_eq!(corr.severity, Severity::High);
        assert_eq!(corr.scope, CorrelationScope::SameHost);
        assert_eq!(corr.members.len(), 2);
        assert_eq!(corr.members[0].timeline_id, 1);
        assert_eq!(corr.members[0].role, CorrelationRole::Anchor);
        assert_eq!(corr.members[1].timeline_id, 2);
        assert_eq!(corr.members[1].role, CorrelationRole::Consequent);
        assert!(corr.note.contains("consistent with"));
    }

    /// `1_750_000_000` s and `1_750_000_225` s are 3m45s apart → a true range.
    const T1_NS: i64 = 1_750_000_000 * 1_000_000_000;
    const T2_NS: i64 = 1_750_000_225 * 1_000_000_000;

    #[test]
    fn note_states_the_failure_count_and_window_when_burst_summary_is_present() {
        // The runner synthesizes the anchor at the latest failure (T2) and tags
        // it with the burst's count + span; the note must surface both.
        let anchor = burst(1, T2_NS, "194.61.24.102").with_burst_summary(37, T1_NS, T2_NS);
        let cands = vec![success(2, T2_NS + 1_000_000_000, "194.61.24.102")];

        let corr = evaluate_bruteforce(&anchor, &cands).expect("a correlation");
        assert!(
            corr.note.contains("37"),
            "note must state the failure count, got: {}",
            corr.note
        );
        assert!(
            corr.note.contains("between"),
            "a multi-second burst must show a from→to range, got: {}",
            corr.note
        );
        // Still an observation, never a verdict.
        assert!(corr.note.contains("consistent with"));
    }

    #[test]
    fn note_collapses_a_same_second_burst_to_one_instant() {
        // All failures land in the same wall-clock second → no spurious range.
        let same = T1_NS + 250_000_000; // +0.25 s, still second T1
        let anchor = burst(1, same, "194.61.24.102").with_burst_summary(5, T1_NS, same);
        let cands = vec![success(2, same + 1_000_000_000, "194.61.24.102")];

        let corr = evaluate_bruteforce(&anchor, &cands).expect("a correlation");
        assert!(corr.note.contains('5'), "count, got: {}", corr.note);
        assert!(
            !corr.note.contains("between"),
            "a same-second burst must not show a range, got: {}",
            corr.note
        );
        assert!(corr.note.contains("consistent with"));
    }

    #[test]
    fn renders_the_real_case001_administrator_burst() {
        // Grounded in the actual Case-001 DC01 burst (derived from the stored
        // timeline): 95 failed logons 03:21:25 → 03:21:46 UTC against the
        // Administrator account (Session 0, no source IP — joined on the account,
        // which is exactly why the note can't claim "source IP" alone).
        use chrono::{TimeZone, Utc};
        let first = Utc
            .with_ymd_and_hms(2020, 9, 19, 3, 21, 25)
            .single()
            .and_then(|t| t.timestamp_nanos_opt())
            .expect("a representable instant");
        let last = Utc
            .with_ymd_and_hms(2020, 9, 19, 3, 21, 46)
            .single()
            .and_then(|t| t.timestamp_nanos_opt())
            .expect("a representable instant");
        assert_eq!(
            bruteforce_note(95, first, last),
            "A burst of 95 failed logons between 2020-09-19 03:21:25 UTC and \
             2020-09-19 03:21:46 UTC, followed by a successful logon linked to the \
             same source IP or targeted account, is consistent with a successful \
             brute-force attempt (T1110)."
        );
    }

    // ── Negative controls ────────────────────────────────────────────────────

    #[test]
    fn does_not_fire_for_success_from_a_different_ip() {
        // The success comes from a *different* IP than the burst — the join must
        // keep the rule silent (the canonical brute-force negative control).
        let anchor = burst(1, 1_000, "194.61.24.102");
        let cands = vec![success(2, 2_000, "10.0.0.50")];
        assert!(evaluate_bruteforce(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_success_precedes_the_burst() {
        let anchor = burst(1, 5_000, "194.61.24.102");
        let cands = vec![success(2, 1_000, "194.61.24.102")];
        assert!(evaluate_bruteforce(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_outside_the_30min_window() {
        let anchor = burst(1, 1_000, "194.61.24.102");
        let late = 1_000 + BRUTEFORCE_WINDOW_NS + 1;
        let cands = vec![success(2, late, "194.61.24.102")];
        assert!(evaluate_bruteforce(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_across_hosts() {
        let anchor = burst(1, 1_000, "194.61.24.102");
        let mut other = success(2, 2_000, "194.61.24.102");
        other.host = Some("WS01".to_string());
        let cands = vec![other];
        assert!(evaluate_bruteforce(&anchor, &cands).is_none());
    }
}
