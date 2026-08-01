use crate::evidence::{EvidenceKind, EvidenceSource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Rule severity — the canonical fleet scale.
///
/// This was a local `Critical/High/Medium/Low/Info` clone: the exact variant set
/// of [`forensicnomicon::report::Severity`], declared highest-first and deriving
/// only `PartialEq`, so pivot findings could not be ranked or thresholded at
/// all. Adopting the canonical type brings `Ord` and `Display` with it; the
/// five variant names are unchanged, so bundled rule YAML keeps parsing.
pub use forensicnomicon::report::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AssertionLevel {
    Observed,
    Correlated,
    Inferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchClause {
    pub source: Option<EvidenceSource>,
    pub kind: Option<EvidenceKind>,
    pub value_contains: Option<String>,
    #[serde(default)]
    pub attr_eq: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub assertion_level: AssertionLevel,
    pub default_confidence: u8,
    pub clauses: Vec<MatchClause>,
    pub time_window_secs: Option<u64>,
}
