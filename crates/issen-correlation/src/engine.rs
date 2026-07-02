use crate::model::{CorrelatedFinding, CorrelationRule, Evidence, Finding, RuleAttrPredicate};
use crate::render::render_evidence_line;

#[derive(Debug, Default)]
pub struct CorrelationEngine;

impl CorrelationEngine {
    #[must_use]
    pub fn evaluate(
        &self,
        rules: &[CorrelationRule],
        evidence: &[Evidence],
    ) -> Vec<CorrelatedFinding> {
        let mut findings = Vec::new();

        for rule in rules {
            let mut matched = Vec::new();
            let mut anchor_subject = None;
            let mut anchor_timestamp = None;
            let mut satisfied = true;

            for clause in &rule.clauses {
                let candidate = evidence.iter().find(|item| {
                    item.source == clause.source
                        && clause_matches(item, clause)
                        && subject_matches(anchor_subject.as_ref(), item.subject.as_ref())
                        && within_window(anchor_timestamp, item.timestamp, rule.within_seconds)
                });

                if let Some(item) = candidate {
                    if anchor_subject.is_none() {
                        anchor_subject = item.subject.clone();
                    }
                    if anchor_timestamp.is_none() {
                        anchor_timestamp = item.timestamp;
                    }
                    matched.push(item.id.clone());
                } else {
                    satisfied = false;
                    break;
                }
            }

            if satisfied {
                // Collect matched Evidence objects for rendering.
                let matched_evidence: Vec<&Evidence> = matched
                    .iter()
                    .filter_map(|id| evidence.iter().find(|e| &e.id == id))
                    .collect();
                let evidence_rendered = matched_evidence
                    .iter()
                    .map(|e| render_evidence_line(e))
                    .collect();

                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: rule.severity.clone(),
                    evidence_ids: matched,
                    summary: rule.summary_template.clone(),
                    explanation: rule
                        .explanation_template
                        .clone()
                        .or_else(|| rule.description.clone()),
                    confidence: rule.default_confidence,
                    assertion_level: rule.assertion_level.clone(),
                    evidence_rendered,
                });
            }
        }

        findings
    }
}

fn clause_matches(item: &Evidence, clause: &crate::model::RuleClause) -> bool {
    let tag_ok =
        clause.required_tag.is_empty() || item.tags.iter().any(|tag| tag == &clause.required_tag);
    let attrs_ok = clause
        .attr_predicates
        .iter()
        .all(|predicate| attr_predicate_matches(item, predicate));
    tag_ok && attrs_ok
}

fn attr_predicate_matches(item: &Evidence, predicate: &RuleAttrPredicate) -> bool {
    match predicate {
        RuleAttrPredicate::Equals { key, value } => item.attrs.get(key) == Some(value),
        RuleAttrPredicate::Contains { key, value } => item
            .attrs
            .get(key)
            .is_some_and(|candidate| candidate.contains(value)),
        RuleAttrPredicate::AnyOf { key, values } => item
            .attrs
            .get(key)
            .is_some_and(|candidate| values.iter().any(|value| value == candidate)),
    }
}

pub type PivotEngine = CorrelationEngine;

fn subject_matches(
    anchor_subject: Option<&crate::model::SubjectRef>,
    candidate_subject: Option<&crate::model::SubjectRef>,
) -> bool {
    match anchor_subject {
        Some(anchor) => candidate_subject == Some(anchor),
        None => true,
    }
}

fn within_window(
    anchor_timestamp: Option<jiff::Timestamp>,
    candidate_timestamp: Option<jiff::Timestamp>,
    within_seconds: Option<i64>,
) -> bool {
    match (anchor_timestamp, candidate_timestamp, within_seconds) {
        (Some(anchor), Some(candidate), Some(window)) => {
            candidate.duration_since(anchor).as_secs().abs() <= window
        }
        (None, _, Some(_)) | (_, _, None) => true,
        _ => false,
    }
}
