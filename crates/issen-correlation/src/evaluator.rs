//! Ordered-window correlation evaluator (`DuckDB`-free).
//!
//! Given an *anchor* event and a slice of candidate *consequent* events
//! (already fetched from the store), a [`RuleSpec`] decides whether they form a
//! [`Correlation`]: the anchor must satisfy the anchor predicate, a consequent
//! must satisfy the consequent predicate, the two must share a join entity, and
//! the consequent must fall strictly *after* the anchor within the rule's time
//! window. Ordering is point-in-time: a missing or non-positive timestamp never
//! satisfies the window, and an anchor never matches a consequent at the same
//! instant.
//!
//! The evaluator is generic over [`EventView`] so it stays free of any storage
//! type — `issen-timeline::events::StoredEvent` implements it; the unit tests
//! use a synthetic event. This is the seam that keeps `issen-correlation`
//! `DuckDB`-free while still consuming events read back from `DuckDB`.

use forensicnomicon::report::Severity;
use issen_core::timeline::event::EntityRef;

use crate::correlation::{Correlation, CorrelationMember, CorrelationRole, CorrelationScope};

/// Which artifact leg an event was reconstructed from.
///
/// The evaluator uses this for point-in-time / `SameDump` reasoning over the
/// memory rules (a process-migration chain must stay within one dump). Disk and
/// log legs are persistent; the `Memory` leg is a single acquisition snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSource {
    /// Filesystem artifacts (MFT, USN, `$LogFile`, files on disk).
    Disk,
    /// Windows event log (EVTX) records.
    Evtx,
    /// Registry hive values.
    Registry,
    /// A point-in-time memory dump.
    Memory,
    /// Any other / unclassified leg.
    Other,
}

impl EventSource {
    /// The stable lowercase token for this leg.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disk => "disk",
            Self::Evtx => "evtx",
            Self::Registry => "registry",
            Self::Memory => "memory",
            Self::Other => "other",
        }
    }

    /// Parse a leg token; `None` for an unknown token.
    #[allow(clippy::should_implement_trait)] // Option-returning parser, not std FromStr (Result)
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "disk" => Some(Self::Disk),
            "evtx" => Some(Self::Evtx),
            "registry" => Some(Self::Registry),
            "memory" => Some(Self::Memory),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

/// The minimal read-only view the evaluator needs over an event.
///
/// `issen-timeline::events::StoredEvent` implements this; unit tests use a
/// synthetic struct. Keeping the evaluator generic over this trait is the seam
/// that lets `issen-correlation` consume `DuckDB`-read events without depending on
/// the storage crate (which would also be a dependency cycle).
pub trait EventView {
    /// The persisted `timeline.id` (the correlation-member key).
    fn id(&self) -> u64;
    /// Event time in nanoseconds; non-positive is treated as "no clock".
    fn timestamp_ns(&self) -> i64;
    /// The event-type token (e.g. `"LogonFailure"`).
    fn event_type(&self) -> &str;
    /// The entity references this event carries.
    fn entity_refs(&self) -> &[EntityRef];
    /// Host attribution, if known.
    fn hostname(&self) -> Option<&str>;
    /// Which artifact leg this event came from.
    fn source(&self) -> EventSource;
    /// The full artifact path the event concerns (e.g. the file an MFT/USN
    /// event touched). Defaults to `""` so existing implementations need no
    /// change; path-aware guards (e.g. user-writable-drop checks) read it.
    ///
    /// A size accessor is deliberately *not* part of this trait: `StoredEvent`
    /// has no first-class byte-size column (size lives in artifact-specific
    /// metadata JSON), so a generic `size()` hook would have nothing to return.
    /// Rules needing size pass it alongside the event (see Tier-A `FileFacts`).
    // The default body returns a `'static` literal, but overriding impls
    // (e.g. `StoredEvent`) borrow from `&self`, so the signature must stay tied
    // to the receiver lifetime — not narrowed to `&'static str`.
    #[allow(clippy::unnecessary_literal_bound)]
    fn artifact_path(&self) -> &str {
        ""
    }

    /// For a synthesized failed-logon *burst* anchor: `(failure_count,
    /// first_failure_ns, last_failure_ns)` — how many failures the burst gathered
    /// and the span they covered. `None` for every ordinary event (the default);
    /// only a brute-force burst anchor overrides it, so the brute-force note can
    /// state "N failed logons between T1 and T2" instead of a generic phrase.
    fn burst_summary(&self) -> Option<(usize, i64, i64)> {
        None
    }

    /// The Windows 4624 logon type (RDP = 10, network = 3, interactive = 2, …)
    /// for a `LogonSuccess` event, surfaced by the storage layer from its
    /// metadata. `None` for every non-logon event and any implementation that
    /// does not carry it (the default). A typed semantic accessor like
    /// [`burst_summary`](Self::burst_summary): the pure engine classifies a
    /// remote-interactive logon without parsing storage metadata itself.
    fn logon_type(&self) -> Option<u64> {
        None
    }

    /// The host's own bound interface address, surfaced from a network-config
    /// (`system-info`) event's metadata. `None` for every event that carries no
    /// interface binding (the default). This is the host's *own* address
    /// inventory — distinct from the source IP a logon carries — and is what
    /// lets the lateral-move guard test host-B's source IP ∈ host-A's inventory.
    fn interface_ip(&self) -> Option<String> {
        None
    }

    /// The evidence-source (image/dump) identifier this event was ingested
    /// from — the per-host scope key, since one image is one host. Registry
    /// interface events carry **no hostname**, so the evidence source (not the
    /// hostname) is the reliable key that ties a host's interface inventory to
    /// its logons. `None` for synthetic/test events without source attribution.
    fn evidence_source(&self) -> Option<&str> {
        None
    }
}

/// An optional per-pair guard predicate for a [`RuleSpec`]: a candidate
/// consequent matches only when this returns `true`. Applied in addition to the
/// engine's entity-equality, ordering, window and scope checks.
pub type GuardFn = fn(anchor: &dyn EventView, consequent: &dyn EventView) -> bool;

/// How the host/dump scope constrains an anchor↔consequent pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRule {
    /// Anchor and consequent must be attributed to the same host.
    SameHost,
    /// Anchor and consequent must be attributed to *different* hosts (a
    /// lateral-move signal).
    CrossHost,
    /// Anchor and consequent must come from the same point-in-time dump
    /// (identity proxied here by the host/dump label).
    SameDump,
}

impl ScopeRule {
    /// `true` when the pair's host attribution satisfies this scope rule.
    fn admits(self, anchor_host: Option<&str>, consequent_host: Option<&str>) -> bool {
        match self {
            // Same-host / same-dump: two known labels must be equal, but an
            // unknown (None) host on either side is admitted — disk artifacts
            // (MFT/USN) carry no hostname, and within one image every event is the
            // same host. The entity + time-window join still constrains the pair;
            // requiring a known label here silently dropped every disk-to-log
            // correlation (the Case-001 PERSIST/RELOCATE miss).
            Self::SameHost | Self::SameDump => match (anchor_host, consequent_host) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            },
            // Cross-host requires two known, distinct labels.
            Self::CrossHost => {
                matches!((anchor_host, consequent_host), (Some(a), Some(b)) if a != b)
            }
        }
    }

    /// The persisted [`CorrelationScope`] this rule produces.
    fn to_scope(self) -> CorrelationScope {
        match self {
            Self::SameHost => CorrelationScope::SameHost,
            Self::CrossHost => CorrelationScope::CrossHost,
            Self::SameDump => CorrelationScope::SameDump,
        }
    }
}

/// A declarative ordered-window correlation rule.
///
/// Static `&'static str` fields keep the bundled rule set allocation-free; the
/// produced [`Correlation`] owns its strings.
#[derive(Debug, Clone)]
pub struct RuleSpec {
    /// Stable scheme-prefixed code (e.g. `CORR-BRUTEFORCE-LOGON`).
    pub code: &'static str,
    /// ATT&CK technique the pattern is consistent with, if any.
    pub attack_technique: Option<&'static str>,
    /// Severity of an emitted finding.
    pub severity: Severity,
    /// Event-type token the anchor must match.
    pub anchor_event_type: &'static str,
    /// Event-type token a consequent must match.
    pub consequent_event_type: &'static str,
    /// Maximum (consequent − anchor) gap in nanoseconds (inclusive).
    pub window_ns: i64,
    /// Host/dump scope constraint.
    pub scope: ScopeRule,
    /// Examiner-facing note — "consistent with", never a verdict.
    pub note: &'static str,
    /// When `true` (the default for existing rules), a consequent must fall
    /// strictly *after* the anchor. When `false`, the pair may occur in either
    /// order within the window — the finding's window still spans earlier→later.
    pub ordered: bool,
    /// Optional per-pair guard predicate, applied *in addition to* entity
    /// equality, ordering, window and scope: a candidate matches only when the
    /// guard returns `true`. `None` (the default) imposes no extra constraint,
    /// so rules that don't set it behave exactly as before.
    pub guard: Option<GuardFn>,
}

/// Evaluate `rule` against `anchor` and a slice of candidate `consequents`.
///
/// Returns a [`Correlation`] (anchor + earliest matching consequent) when the
/// rule fires, or `None`. Matching is strict and ordered:
///
/// - the anchor must have a positive timestamp and match `anchor_event_type`;
/// - a consequent must match `consequent_event_type`, have a positive timestamp
///   *strictly after* the anchor and within `window_ns`, share at least one join
///   entity with the anchor, and satisfy the scope rule;
/// - the earliest such consequent wins.
#[must_use]
pub fn evaluate<A, C>(rule: &RuleSpec, anchor: &A, consequents: &[C]) -> Option<Correlation>
where
    A: EventView,
    C: EventView,
{
    let anchor_ts = anchor.timestamp_ns();
    if anchor_ts <= 0 || anchor.event_type() != rule.anchor_event_type {
        return None;
    }

    let mut best: Option<&C> = None;
    for candidate in consequents {
        let ts = candidate.timestamp_ns();
        if ts <= 0 || candidate.event_type() != rule.consequent_event_type {
            continue;
        }
        // Window check. Strict mode requires the consequent strictly after the
        // anchor; either-order mode accepts |Δ| within the window (a
        // simultaneous pair is still rejected — Δ == 0 is no temporal evidence).
        let within_window = if rule.ordered {
            ts > anchor_ts && ts - anchor_ts <= rule.window_ns
        } else {
            ts != anchor_ts && (ts - anchor_ts).abs() <= rule.window_ns
        };
        if !within_window {
            continue;
        }
        if !rule.scope.admits(anchor.hostname(), candidate.hostname()) {
            continue;
        }
        if !shares_entity(anchor.entity_refs(), candidate.entity_refs()) {
            continue;
        }
        if let Some(guard) = rule.guard {
            if !guard(anchor, candidate) {
                continue;
            }
        }
        // Pick the consequent nearest the anchor in time (earliest in strict
        // mode, smallest |Δ| in either-order mode).
        let nearer = match best {
            Some(current) => (ts - anchor_ts).abs() < (current.timestamp_ns() - anchor_ts).abs(),
            None => true,
        };
        if nearer {
            best = Some(candidate);
        }
    }

    let consequent = best?;
    let cons_ts = consequent.timestamp_ns();
    let (first_ts, last_ts) = if anchor_ts <= cons_ts {
        (anchor_ts, cons_ts)
    } else {
        (cons_ts, anchor_ts)
    };
    let correlation = Correlation::new(rule.code, rule.severity)
        .with_scope(rule.scope.to_scope())
        .with_window(first_ts, last_ts)
        .with_note(rule.note)
        .with_member(CorrelationMember::new(anchor.id(), CorrelationRole::Anchor))
        .with_member(CorrelationMember::new(
            consequent.id(),
            CorrelationRole::Consequent,
        ));
    let correlation = match rule.attack_technique {
        Some(technique) => correlation.with_attack_technique(technique),
        None => correlation,
    };
    Some(correlation)
}

/// `true` when the two entity-ref slices share at least one identical entity.
fn shares_entity(a: &[EntityRef], b: &[EntityRef]) -> bool {
    a.iter().any(|x| b.iter().any(|y| x == y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::report::Severity;

    /// A synthetic event for evaluator unit tests — proves the evaluator needs
    /// no storage type.
    #[derive(Debug, Clone)]
    struct TestEvent {
        id: u64,
        ts: i64,
        event_type: String,
        entity_refs: Vec<EntityRef>,
        host: Option<String>,
        source: EventSource,
    }

    impl EventView for TestEvent {
        fn id(&self) -> u64 {
            self.id
        }
        fn timestamp_ns(&self) -> i64 {
            self.ts
        }
        fn event_type(&self) -> &str {
            &self.event_type
        }
        fn entity_refs(&self) -> &[EntityRef] {
            &self.entity_refs
        }
        fn hostname(&self) -> Option<&str> {
            self.host.as_deref()
        }
        fn source(&self) -> EventSource {
            self.source
        }
    }

    fn ev(id: u64, ts: i64, et: &str, ip: &str, host: &str, src: EventSource) -> TestEvent {
        TestEvent {
            id,
            ts,
            event_type: et.to_string(),
            entity_refs: vec![EntityRef::Ip(ip.to_string())],
            host: Some(host.to_string()),
            source: src,
        }
    }

    /// The example rule: a failed-logon burst (anchor) followed by a success
    /// from the same IP (consequent), within a window.
    fn brute_force_rule() -> RuleSpec {
        RuleSpec {
            code: "CORR-BRUTEFORCE-LOGON",
            attack_technique: Some("T1110"),
            severity: Severity::High,
            anchor_event_type: "LogonFailure",
            consequent_event_type: "LogonSuccess",
            window_ns: 60_000_000_000, // 60s
            scope: ScopeRule::SameHost,
            note:
                "Failed-logon burst then success from the same IP is consistent with brute force.",
            ordered: true,
            guard: None,
        }
    }

    #[test]
    fn matches_an_ordered_same_entity_pair() {
        let anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        let result = evaluate(&brute_force_rule(), &anchor, &consequents);
        let corr = result.expect("a correlation");
        assert_eq!(corr.code, "CORR-BRUTEFORCE-LOGON");
        assert_eq!(corr.attack_technique.as_deref(), Some("T1110"));
        assert_eq!(corr.severity, Severity::High);
        assert_eq!(corr.first_ts, 1_000);
        assert_eq!(corr.last_ts, 2_000);
        assert_eq!(corr.scope, CorrelationScope::SameHost);
        assert_eq!(corr.members.len(), 2);
        assert_eq!(corr.members[0].timeline_id, 1);
        assert_eq!(corr.members[0].role, CorrelationRole::Anchor);
        assert_eq!(corr.members[1].timeline_id, 2);
        assert_eq!(corr.members[1].role, CorrelationRole::Consequent);
    }

    #[test]
    fn rejects_a_reversed_pair() {
        // Consequent BEFORE the anchor — ordering must reject it.
        let anchor = ev(
            1,
            5_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            1_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn rejects_a_simultaneous_pair() {
        // Same instant — strictly-after means no match.
        let anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            1_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn rejects_out_of_window_consequent() {
        let anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            999_000_000_000, // way past the 60s window
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn rejects_different_entity() {
        let anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "10.0.0.9",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn rejects_wrong_anchor_type() {
        let anchor = ev(
            1,
            1_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn same_host_scope_rejects_cross_host_pair() {
        let anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "203.0.113.5",
            "WS01",
            EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn non_positive_anchor_timestamp_never_matches() {
        let anchor = ev(
            1,
            0,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn same_dump_scope_requires_same_evidence_leg() {
        // Point-in-time semantics seam: a SameDump rule must reject members from
        // different memory dumps even when entity + ordering align. Modeled here
        // via the EventSource leg + the SameDump scope rule's same-host proxy.
        let rule = RuleSpec {
            scope: ScopeRule::SameDump,
            ..brute_force_rule()
        };
        let anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "DUMP-A",
            EventSource::Memory,
        );
        // Different host label stands in for a different dump identity.
        let consequents = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "203.0.113.5",
            "DUMP-B",
            EventSource::Memory,
        )];
        assert!(evaluate(&rule, &anchor, &consequents).is_none());

        let same_dump = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "203.0.113.5",
            "DUMP-A",
            EventSource::Memory,
        )];
        assert!(evaluate(&rule, &anchor, &same_dump).is_some());
    }

    #[test]
    fn first_matching_consequent_wins() {
        let anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![
            ev(
                2,
                2_000,
                "LogonSuccess",
                "203.0.113.5",
                "DC01",
                EventSource::Evtx,
            ),
            ev(
                3,
                3_000,
                "LogonSuccess",
                "203.0.113.5",
                "DC01",
                EventSource::Evtx,
            ),
        ];
        let corr = evaluate(&brute_force_rule(), &anchor, &consequents).expect("match");
        assert_eq!(corr.members[1].timeline_id, 2, "earliest consequent");
        assert_eq!(corr.last_ts, 2_000);
    }

    #[test]
    fn event_source_round_trips_its_token() {
        for src in [
            EventSource::Disk,
            EventSource::Evtx,
            EventSource::Registry,
            EventSource::Memory,
            EventSource::Other,
        ] {
            assert_eq!(EventSource::from_str(src.as_str()), Some(src));
        }
        assert_eq!(EventSource::from_str("nope"), None);
    }

    #[test]
    fn unused_member_ctor_guard() {
        let m = CorrelationMember::new(1, CorrelationRole::Supporting);
        assert_eq!(m.timeline_id, 1);
    }

    // ── Part A: engine guard-hook + either-order mode ────────────────────────

    /// A guard that only admits a consequent whose host label is exactly
    /// `"WANTED"` — proves the per-pair guard predicate gates a candidate the
    /// entity/window/scope checks would otherwise accept.
    fn host_must_be_wanted(_anchor: &dyn EventView, consequent: &dyn EventView) -> bool {
        consequent.hostname() == Some("WANTED")
    }

    #[test]
    fn guard_rejects_a_candidate_it_fails_even_when_entity_and_window_match() {
        // Entity, ordering, window and scope all match; only the guard differs.
        let rule = RuleSpec {
            guard: Some(host_must_be_wanted),
            ..brute_force_rule()
        };
        let anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        // SameHost scope means both sides must share a host; use "DC01" which the
        // guard rejects, then "WANTED" which it accepts.
        let rejected = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(
            evaluate(&rule, &anchor, &rejected).is_none(),
            "guard must reject a candidate it fails"
        );

        let wanted_anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "WANTED",
            EventSource::Evtx,
        );
        let accepted = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "203.0.113.5",
            "WANTED",
            EventSource::Evtx,
        )];
        assert!(
            evaluate(&rule, &wanted_anchor, &accepted).is_some(),
            "guard must admit a candidate it passes"
        );
    }

    #[test]
    fn either_order_mode_fires_for_a_reversed_pair_that_strict_mode_misses() {
        // Consequent BEFORE the anchor: strict mode rejects (see
        // `rejects_a_reversed_pair`); either-order mode must accept it.
        let strict = brute_force_rule();
        let either = RuleSpec {
            ordered: false,
            ..brute_force_rule()
        };
        let anchor = ev(
            1,
            5_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            1_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(
            evaluate(&strict, &anchor, &consequents).is_none(),
            "strict mode must miss the reversed pair"
        );
        let corr = evaluate(&either, &anchor, &consequents).expect("either-order match");
        // Window spans earlier→later regardless of which is anchor.
        assert_eq!(corr.first_ts, 1_000);
        assert_eq!(corr.last_ts, 5_000);
    }

    #[test]
    fn either_order_mode_still_honors_the_window() {
        // Reversed but outside the window: even either-order must reject.
        let either = RuleSpec {
            ordered: false,
            ..brute_force_rule()
        };
        let anchor = ev(
            1,
            999_000_000_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        let consequents = vec![ev(
            2,
            1_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(evaluate(&either, &anchor, &consequents).is_none());
    }

    #[test]
    fn default_rulespec_fields_preserve_strict_no_guard_behavior() {
        // A rule literal that omits the new fields via `..` of brute_force_rule
        // must behave exactly as before: strict ordering, no guard.
        let rule = brute_force_rule();
        assert!(rule.guard.is_none());
        assert!(rule.ordered, "default is strict ordered");
    }

    #[test]
    fn event_view_artifact_path_defaults_to_empty() {
        // The new accessor has a default so existing impls need no change.
        let anchor = ev(
            1,
            1_000,
            "LogonFailure",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        );
        assert_eq!(anchor.artifact_path(), "");
    }
}
