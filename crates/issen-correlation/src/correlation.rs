//! Correlation findings — the DuckDB-free model for a cross-artifact match.
//!
//! A [`Correlation`] is an *observation*: a set of timeline events that, taken
//! together, are *consistent with* a named behavior (an ATT&CK technique, a
//! lateral-move, a brute-force-then-success). It is never a verdict — the
//! analyst and the tribunal conclude; the engine only reports what it observed.
//!
//! These types are pure data with no storage dependency, so the ordered
//! evaluator (and its unit tests) can produce them without touching `DuckDB`.
//! The `issen-timeline` crate persists them into the `correlations` and
//! `correlation_members` tables, keyed on `timeline.id`.

use forensicnomicon::report::Severity;

/// The host/dump scope a correlation's members share.
///
/// Ordered-window rules join events on a shared entity; the scope records
/// *where* that sharing held — within one host, deliberately across hosts (a
/// lateral-move signal), or within one memory dump (point-in-time process
/// rules). Cross-scope matches that should not correlate are rejected by the
/// evaluator before a [`Correlation`] is ever built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorrelationScope {
    /// All members are attributed to the same host.
    SameHost,
    /// Members span two hosts (e.g. a lateral-move chain).
    CrossHost,
    /// Members come from a single point-in-time memory dump.
    SameDump,
}

impl CorrelationScope {
    /// The stable lowercase token persisted in the `scope` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameHost => "same_host",
            Self::CrossHost => "cross_host",
            Self::SameDump => "same_dump",
        }
    }

    /// Parse a persisted token back into a scope; `None` for an unknown token.
    #[allow(clippy::should_implement_trait)] // Option-returning parser, not std FromStr (Result)
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "same_host" => Some(Self::SameHost),
            "cross_host" => Some(Self::CrossHost),
            "same_dump" => Some(Self::SameDump),
            _ => None,
        }
    }
}

/// The part a member event plays in its correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorrelationRole {
    /// The triggering event the rule anchored on (point-in-time earliest).
    Anchor,
    /// An event that followed the anchor within the rule's window.
    Consequent,
    /// A corroborating event that is neither anchor nor strict consequent.
    Supporting,
}

impl CorrelationRole {
    /// The stable lowercase token persisted in the member `role` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anchor => "anchor",
            Self::Consequent => "consequent",
            Self::Supporting => "supporting",
        }
    }

    /// Parse a persisted token back into a role; `None` for an unknown token.
    #[allow(clippy::should_implement_trait)] // Option-returning parser, not std FromStr (Result)
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "anchor" => Some(Self::Anchor),
            "consequent" => Some(Self::Consequent),
            "supporting" => Some(Self::Supporting),
            _ => None,
        }
    }
}

/// One event participating in a correlation, identified by its `timeline.id`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CorrelationMember {
    /// The `timeline.id` of the participating event.
    pub timeline_id: u64,
    /// The part this event plays in the correlation.
    pub role: CorrelationRole,
}

impl CorrelationMember {
    /// A member keyed on its `timeline.id` with the given role.
    #[must_use]
    pub fn new(timeline_id: u64, role: CorrelationRole) -> Self {
        Self { timeline_id, role }
    }
}

/// A cross-artifact correlation finding — an observation that a set of timeline
/// events is *consistent with* a named behavior. Never a verdict.
///
/// Built by the ordered evaluator (DuckDB-free) and persisted by `issen-timeline`
/// into the `correlations` + `correlation_members` tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correlation {
    /// Stable scheme-prefixed code (e.g. `CORR-BRUTEFORCE-LOGON`).
    pub code: String,
    /// MITRE ATT&CK technique id this pattern is consistent with, if any.
    pub attack_technique: Option<String>,
    /// Canonical severity of the finding.
    pub severity: Severity,
    /// Earliest member timestamp (nanoseconds).
    pub first_ts: i64,
    /// Latest member timestamp (nanoseconds).
    pub last_ts: i64,
    /// Host/dump scope the members share.
    pub scope: CorrelationScope,
    /// Examiner-facing narration — "consistent with", never a verdict.
    pub note: String,
    /// The participating events, keyed on `timeline.id`.
    pub members: Vec<CorrelationMember>,
}

impl Correlation {
    /// A new correlation with the given code and severity; all other fields
    /// default (empty technique/note, `SameHost` scope, zero window, no members).
    #[must_use]
    pub fn new(code: impl Into<String>, severity: Severity) -> Self {
        Self {
            code: code.into(),
            attack_technique: None,
            severity,
            first_ts: 0,
            last_ts: 0,
            scope: CorrelationScope::SameHost,
            note: String::new(),
            members: Vec::new(),
        }
    }

    /// Tag the finding with the ATT&CK technique it is consistent with.
    #[must_use]
    pub fn with_attack_technique(mut self, technique: impl Into<String>) -> Self {
        self.attack_technique = Some(technique.into());
        self
    }

    /// Set the host/dump scope.
    #[must_use]
    pub fn with_scope(mut self, scope: CorrelationScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set the time window (earliest, latest) in nanoseconds.
    #[must_use]
    pub fn with_window(mut self, first_ts: i64, last_ts: i64) -> Self {
        self.first_ts = first_ts;
        self.last_ts = last_ts;
        self
    }

    /// Set the examiner-facing note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }

    /// Append a member event.
    #[must_use]
    pub fn with_member(mut self, member: CorrelationMember) -> Self {
        self.members.push(member);
        self
    }

    /// The stable lowercase severity token persisted in the `severity` column.
    #[must_use]
    pub fn severity_str(&self) -> &'static str {
        match self.severity {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
            // `forensicnomicon::report::Severity` is `#[non_exhaustive]`; a future
            // variant maps to a distinct sentinel rather than masquerading as info.
            _ => "unknown", // cov:unreachable: Severity has exactly five known variants today
        }
    }

    /// Parse a persisted severity token back into a [`Severity`].
    #[must_use]
    pub fn severity_from_str(s: &str) -> Option<Severity> {
        match s {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::report::Severity;

    #[test]
    fn correlation_carries_code_and_window() {
        let c = Correlation::new("CORR-BRUTEFORCE-LOGON", Severity::High)
            .with_attack_technique("T1110")
            .with_scope(CorrelationScope::SameHost)
            .with_window(1_000, 2_000)
            .with_note("Failed-logon burst is consistent with a brute-force attempt.");

        assert_eq!(c.code, "CORR-BRUTEFORCE-LOGON");
        assert_eq!(c.severity, Severity::High);
        assert_eq!(c.attack_technique.as_deref(), Some("T1110"));
        assert_eq!(c.scope, CorrelationScope::SameHost);
        assert_eq!(c.first_ts, 1_000);
        assert_eq!(c.last_ts, 2_000);
        assert!(c.note.contains("consistent with"));
    }

    #[test]
    fn correlation_defaults_are_empty() {
        let c = Correlation::new("CORR-X", Severity::Low);
        assert!(c.attack_technique.is_none());
        assert_eq!(c.scope, CorrelationScope::SameHost);
        assert_eq!(c.first_ts, 0);
        assert_eq!(c.last_ts, 0);
        assert!(c.note.is_empty());
        assert!(c.members.is_empty());
    }

    #[test]
    fn members_record_their_timeline_id_and_role() {
        let c = Correlation::new("CORR-X", Severity::Medium)
            .with_member(CorrelationMember::new(7, CorrelationRole::Anchor))
            .with_member(CorrelationMember::new(9, CorrelationRole::Consequent));

        assert_eq!(c.members.len(), 2);
        assert_eq!(c.members[0].timeline_id, 7);
        assert_eq!(c.members[0].role, CorrelationRole::Anchor);
        assert_eq!(c.members[1].timeline_id, 9);
        assert_eq!(c.members[1].role, CorrelationRole::Consequent);
    }

    #[test]
    fn role_str_is_a_stable_lowercase_token() {
        assert_eq!(CorrelationRole::Anchor.as_str(), "anchor");
        assert_eq!(CorrelationRole::Consequent.as_str(), "consequent");
        assert_eq!(CorrelationRole::Supporting.as_str(), "supporting");
    }

    #[test]
    fn scope_str_round_trips() {
        for scope in [
            CorrelationScope::SameHost,
            CorrelationScope::CrossHost,
            CorrelationScope::SameDump,
        ] {
            let s = scope.as_str();
            assert_eq!(CorrelationScope::from_str(s), Some(scope));
        }
        assert_eq!(CorrelationScope::from_str("nonsense"), None);
    }

    #[test]
    fn severity_str_maps_to_canonical_token() {
        let c = Correlation::new("CORR-X", Severity::Critical);
        assert_eq!(c.severity_str(), "critical");
    }
}
