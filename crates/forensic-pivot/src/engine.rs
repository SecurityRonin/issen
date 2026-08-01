use crate::evidence::Evidence;
use crate::rule::{AssertionLevel, MatchClause, PivotRule, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub assertion_level: AssertionLevel,
    pub confidence: u8,
    pub matched_evidence: Vec<String>,
    pub description: String,
}

pub struct PivotEngine {
    rules: Vec<PivotRule>,
}

impl PivotEngine {
    #[must_use]
    pub fn new(rules: Vec<PivotRule>) -> Self {
        Self { rules }
    }

    /// Evaluate all rules against the provided evidence slice.
    #[must_use]
    pub fn evaluate(&self, evidence: &[Evidence]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            if let Some(finding) = Self::try_match_rule(rule, evidence) {
                findings.push(finding);
            }
        }

        findings
    }

    fn try_match_rule(rule: &PivotRule, evidence: &[Evidence]) -> Option<Finding> {
        // For each clause we must find at least one evidence item that satisfies it.
        // All clauses must be satisfied (AND semantics).
        let mut matched_ids: Vec<String> = Vec::new();

        for clause in &rule.clauses {
            let candidates: Vec<&Evidence> = evidence
                .iter()
                .filter(|e| Self::evidence_matches_clause(e, clause))
                .collect();

            if candidates.is_empty() {
                return None;
            }

            // Pick the first matching candidate for this clause.
            let chosen = candidates[0];
            if !matched_ids.contains(&chosen.id) {
                matched_ids.push(chosen.id.clone());
            }
        }

        // Apply time-window check if specified.
        if let Some(window_secs) = rule.time_window_secs {
            let timestamps: Vec<i64> = matched_ids
                .iter()
                .filter_map(|id| {
                    evidence
                        .iter()
                        .find(|e| &e.id == id)
                        .and_then(|e| e.timestamp_ns)
                })
                .collect();

            // If we have any timestamps, ensure they all fit within the window.
            if timestamps.len() > 1 {
                let min_ts = timestamps.iter().copied().min().unwrap_or(0);
                let max_ts = timestamps.iter().copied().max().unwrap_or(0);
                let span_ns = max_ts - min_ts;
                let window_ns = i64::try_from(window_secs)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000_000_000);
                if span_ns > window_ns {
                    return None;
                }
            }
        }

        Some(Finding {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.severity,
            assertion_level: rule.assertion_level.clone(),
            confidence: rule.default_confidence,
            matched_evidence: matched_ids,
            description: rule.description.clone(),
        })
    }

    fn evidence_matches_clause(ev: &Evidence, clause: &MatchClause) -> bool {
        if let Some(ref required_source) = clause.source {
            if &ev.source != required_source {
                return false;
            }
        }
        if let Some(ref required_kind) = clause.kind {
            if &ev.kind != required_kind {
                return false;
            }
        }
        if let Some(ref substring) = clause.value_contains {
            if !ev.value.contains(substring.as_str()) {
                return false;
            }
        }
        for (key, expected) in &clause.attr_eq {
            match ev.attrs.get(key) {
                Some(actual) if actual == expected => {}
                _ => return false,
            }
        }
        true
    }
}
