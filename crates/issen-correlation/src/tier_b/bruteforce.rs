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

use crate::correlation::Correlation;
use crate::evaluator::{evaluate, EventView, RuleSpec, ScopeRule};

/// Examiner-facing note — an observation, never a verdict.
pub const BRUTEFORCE_NOTE: &str =
    "A failed-logon burst followed by a successful logon from the same source IP \
     is consistent with a successful brute-force attempt (T1110).";

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
    evaluate(&bruteforce_rule(), burst, successes)
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
