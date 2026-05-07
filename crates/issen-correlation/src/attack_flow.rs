//! Attack Flow STIX 2.1 bundle ingestion for `rt-correlation`.
//!
//! Parses STIX bundles containing Attack Flow custom SDOs and converts them
//! to [`CorrelationRule`] objects for the engine, as well as [`FlowGraph`]
//! for Mermaid rendering.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
#[cfg(feature = "remote")]
use std::path::PathBuf;

use crate::model::{CorrelationRule, EvidenceSource, RuleAttrPredicate, RuleClause};

// ── Public structs ────────────────────────────────────────────────────────────

/// Parsed Attack Flow STIX custom SDO: `attack-action`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackAction {
    pub id: String,
    pub name: String,
    pub tactic_id: Option<String>,
    pub technique_id: Option<String>,
    pub description: Option<String>,
    pub confidence: Option<u8>,
    pub effect_refs: Vec<String>,
}

/// Parsed Attack Flow STIX custom SDO: `attack-operator`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackOperator {
    pub id: String,
    pub operator: String,
    pub effect_refs: Vec<String>,
}

/// Parsed Attack Flow STIX custom SDO: `attack-asset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackAsset {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

/// Parsed Attack Flow STIX custom SDO: `attack-flow` (the root object).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackFlowRoot {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
    pub staissen_refs: Vec<String>,
}

/// Full parsed Attack Flow STIX 2.1 bundle.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttackFlowBundle {
    pub flow: Option<AttackFlowRoot>,
    pub actions: Vec<AttackAction>,
    pub operators: Vec<AttackOperator>,
    pub assets: Vec<AttackAsset>,
}

/// Simplified graph node for rendering (avoids importing `rt-report` types).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowNode {
    pub id: String,
    pub label: String,
    pub tactic_id: Option<String>,
    pub technique_id: Option<String>,
}

/// Directed edge in a [`FlowGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEdge {
    pub from: String,
    pub to: String,
}

/// Simplified directed graph for Mermaid rendering or display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowGraph {
    pub title: String,
    pub nodes: Vec<FlowNode>,
    pub edges: Vec<FlowEdge>,
}

// ── Private serde structs ─────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct RawBundle {
    #[serde(rename = "type")]
    type_: String,
    objects: Option<Vec<RawObject>>,
}

#[derive(serde::Deserialize)]
struct RawObject {
    id: Option<String>,
    #[serde(rename = "type")]
    type_: Option<String>,
    name: Option<String>,
    operator: Option<String>,
    tactic_id: Option<String>,
    technique_id: Option<String>,
    description: Option<String>,
    confidence: Option<serde_json::Value>,
    scope: Option<String>,
    #[serde(default)]
    effect_refs: Option<Vec<String>>,
    #[serde(default)]
    staissen_refs: Option<Vec<String>>,
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Parse a STIX 2.1 bundle JSON string into an [`AttackFlowBundle`].
///
/// Returns `Ok(bundle)` with only attack-flow custom SDOs populated.
/// Ignores identity, extension-definition, relationship, malware, tool, etc.
///
/// # Errors
///
/// Returns `Err` if the JSON is invalid or the root object is not a bundle.
pub fn parse_attack_flow_bundle(json: &str) -> anyhow::Result<AttackFlowBundle> {
    let raw: RawBundle = serde_json::from_str(json)
        .map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;

    if raw.type_ != "bundle" {
        return Err(anyhow::anyhow!(
            "expected STIX bundle, got type {:?}",
            raw.type_
        ));
    }

    let mut bundle = AttackFlowBundle::default();
    let objects = raw.objects.unwrap_or_default();

    for obj in objects {
        match obj.type_.as_deref() {
            Some("attack-flow") => {
                bundle.flow = Some(AttackFlowRoot {
                    id: obj.id.unwrap_or_default(),
                    name: obj.name.unwrap_or_default(),
                    description: obj.description,
                    scope: obj.scope.unwrap_or_default(),
                    staissen_refs: obj.staissen_refs.unwrap_or_default(),
                });
            }
            Some("attack-action") => {
                let confidence = obj.confidence.and_then(|v| match v {
                    serde_json::Value::Number(n) => {
                        n.as_u64().map(|u| u.min(100) as u8)
                    }
                    _ => None,
                });
                bundle.actions.push(AttackAction {
                    id: obj.id.unwrap_or_default(),
                    name: obj.name.unwrap_or_default(),
                    tactic_id: obj.tactic_id,
                    technique_id: obj.technique_id,
                    description: obj.description,
                    confidence,
                    effect_refs: obj.effect_refs.unwrap_or_default(),
                });
            }
            Some("attack-operator") => {
                bundle.operators.push(AttackOperator {
                    id: obj.id.unwrap_or_default(),
                    operator: obj.operator.unwrap_or_default(),
                    effect_refs: obj.effect_refs.unwrap_or_default(),
                });
            }
            Some("attack-asset") => {
                bundle.assets.push(AttackAsset {
                    id: obj.id.unwrap_or_default(),
                    name: obj.name.unwrap_or_default(),
                    description: obj.description,
                });
            }
            _ => {} // ignore identity, extension-definition, relationship, etc.
        }
    }

    Ok(bundle)
}

/// Convert an [`AttackFlowBundle`] into [`CorrelationRule`] objects.
///
/// Walks the DAG via `effect_refs` (BFS from `staissen_refs`).
/// Each action with a `technique_id` becomes a [`RuleClause`].
/// Returns an empty vec if no actions have a `technique_id`.
pub fn bundle_to_correlation_rules(bundle: &AttackFlowBundle) -> Vec<CorrelationRule> {
    // Short-circuit: no technique IDs → no rules
    if !bundle.actions.iter().any(|a| a.technique_id.is_some()) {
        return vec![];
    }

    // Build lookup maps
    let action_map: HashMap<&str, &AttackAction> =
        bundle.actions.iter().map(|a| (a.id.as_str(), a)).collect();

    let operator_map: HashMap<&str, &AttackOperator> =
        bundle.operators.iter().map(|o| (o.id.as_str(), o)).collect();

    // Determine start nodes
    let staissen_ids: Vec<&str> = if let Some(flow) = &bundle.flow {
        flow.staissen_refs.iter().map(String::as_str).collect()
    } else {
        // No flow root: use actions not referenced by any other action's effect_refs
        let referenced: HashSet<&str> = bundle
            .actions
            .iter()
            .flat_map(|a| a.effect_refs.iter().map(String::as_str))
            .collect();
        bundle
            .actions
            .iter()
            .filter(|a| !referenced.contains(a.id.as_str()))
            .map(|a| a.id.as_str())
            .collect()
    };

    // BFS to collect ordered list of actions with technique_ids
    let mut visited: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<&str> = staissen_ids.into_iter().collect();
    let mut ordered_actions: Vec<&AttackAction> = Vec::new();

    while let Some(current_id) = queue.pop_front() {
        if visited.contains(current_id) {
            continue;
        }
        visited.insert(current_id);

        // Could be an action or an operator
        if let Some(action) = action_map.get(current_id) {
            if action.technique_id.is_some() {
                ordered_actions.push(action);
            }
            for next_id in &action.effect_refs {
                if !visited.contains(next_id.as_str()) {
                    queue.push_back(next_id.as_str());
                }
            }
        } else if let Some(op) = operator_map.get(current_id) {
            // Operator is a pass-through: enqueue its effect_refs
            for next_id in &op.effect_refs {
                if !visited.contains(next_id.as_str()) {
                    queue.push_back(next_id.as_str());
                }
            }
        }
    }

    if ordered_actions.is_empty() {
        return vec![];
    }

    // Build clauses
    let clauses: Vec<RuleClause> = ordered_actions
        .iter()
        .map(|action| {
            let required_tag = format!(
                "technique:{}",
                action.technique_id.as_deref().unwrap_or("")
            );
            let mut clause = RuleClause::tagged(
                EvidenceSource::Custom("attack-flow".into()),
                required_tag,
            );
            if let Some(tactic_id) = &action.tactic_id {
                clause.attr_predicates.push(RuleAttrPredicate::Equals {
                    key: "tactic_id".into(),
                    value: tactic_id.clone(),
                });
            }
            clause
        })
        .collect();

    let (flow_id, flow_name) = if let Some(flow) = &bundle.flow {
        (flow.id.as_str(), flow.name.as_str())
    } else {
        ("unknown", "Attack Flow")
    };

    vec![CorrelationRule {
        id: format!("attack-flow.{flow_id}"),
        title: flow_name.to_string(),
        severity: "high".into(),
        description: None,
        within_seconds: None,
        references: vec![],
        clauses,
        summary_template: None,
        explanation_template: None,
        default_confidence: 0,
        assertion_level: crate::model::AssertionLevel::default(),
    }]
}

/// Convert an [`AttackFlowBundle`] to a [`FlowGraph`] for rendering.
///
/// Actions become nodes. `effect_refs` become edges.
/// Node IDs are sequential short strings: A, B, C…Z, AA, AB…
/// Operators are pass-through (not represented as nodes).
#[must_use]
pub fn bundle_to_flow_graph(bundle: &AttackFlowBundle) -> FlowGraph {
    let title = bundle
        .flow
        .as_ref()
        .map_or_else(|| "Attack Flow".to_string(), |f| f.name.clone());

    // Assign short IDs to actions
    let action_shoissen_ids: HashMap<&str, String> = bundle
        .actions
        .iter()
        .enumerate()
        .map(|(i, a)| (a.id.as_str(), shoissen_id(i)))
        .collect();

    let nodes: Vec<FlowNode> = bundle
        .actions
        .iter()
        .enumerate()
        .map(|(i, action)| FlowNode {
            id: shoissen_id(i),
            label: action.name.clone(),
            tactic_id: action.tactic_id.clone(),
            technique_id: action.technique_id.clone(),
        })
        .collect();

    // Build edges from effect_refs (action → action only; skip operators)
    let mut edges: Vec<FlowEdge> = Vec::new();
    for action in &bundle.actions {
        let Some(from_short) = action_shoissen_ids.get(action.id.as_str()) else {
            continue;
        };
        for target_id in &action.effect_refs {
            if let Some(to_short) = action_shoissen_ids.get(target_id.as_str()) {
                edges.push(FlowEdge {
                    from: from_short.clone(),
                    to: to_short.clone(),
                });
            }
            // If target is an operator, follow through to its effect_refs
            else if let Some(op) = bundle.operators.iter().find(|o| &o.id == target_id) {
                for op_target in &op.effect_refs {
                    if let Some(to_short) = action_shoissen_ids.get(op_target.as_str()) {
                        edges.push(FlowEdge {
                            from: from_short.clone(),
                            to: to_short.clone(),
                        });
                    }
                }
            }
        }
    }

    FlowGraph { title, nodes, edges }
}

/// Extract and parse all STIX bundles from a corpus zip file.
///
/// Looks for `*.json` files in the zip that are STIX 2.1 bundles containing
/// `attack-flow` objects. Skips schema files and non-STIX JSON.
///
/// # Errors
///
/// Returns `Err` if the zip file cannot be opened or read.
pub fn extract_bundles_from_zip(zip_path: &Path) -> anyhow::Result<Vec<AttackFlowBundle>> {
    use std::io::Read;

    let file = std::fs::File::open(zip_path)
        .map_err(|e| anyhow::anyhow!("cannot open zip {}: {e}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| anyhow::anyhow!("invalid zip: {e}"))?;

    let mut bundles = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)
            .map_err(|e| anyhow::anyhow!("zip entry error: {e}"))?;

        let name = entry.name().to_string();
        if !std::path::Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            continue;
        }

        let mut content = String::new();
        if entry.read_to_string(&mut content).is_err() {
            continue;
        }

        // Quick check: must be STIX 2.1 bundle with attack-flow objects
        if !content.contains("\"spec_version\": \"2.1\"")
            && !content.contains("\"spec_version\":\"2.1\"")
        {
            continue;
        }
        if !content.contains("\"attack-flow\"") && !content.contains("attack-action") {
            continue;
        }

        if let Ok(bundle) = parse_attack_flow_bundle(&content) {
            let has_attack_flow_objects = bundle.flow.is_some()
                || !bundle.actions.is_empty()
                || !bundle.operators.is_empty()
                || !bundle.assets.is_empty();
            if has_attack_flow_objects {
                bundles.push(bundle);
            }
        }
    }

    Ok(bundles)
}

/// Download the Attack Flow v3.0.0 corpus zip from GitHub and save to
/// `cache_dir`. Returns the path to the downloaded zip.
#[cfg(feature = "remote")]
pub fn download_attack_flow_corpus_zip(cache_dir: &Path) -> anyhow::Result<PathBuf> {
    const URL: &str =
        "https://github.com/center-for-threat-informed-defense/attack-flow/archive/refs/tags/v3.0.0.zip";

    std::fs::create_dir_all(cache_dir)
        .map_err(|e| anyhow::anyhow!("cannot create cache dir: {e}"))?;

    let dest = cache_dir.join("attack-flow-v3.0.0.zip");
    let mut response = reqwest::blocking::get(URL)
        .map_err(|e| anyhow::anyhow!("download failed: {e}"))?;

    let mut file = std::fs::File::create(&dest)
        .map_err(|e| anyhow::anyhow!("cannot create file: {e}"))?;

    std::io::copy(&mut response, &mut file)
        .map_err(|e| anyhow::anyhow!("copy failed: {e}"))?;

    Ok(dest)
}

/// Generate a short node ID from an index (0→"A", 25→"Z", 26→"AA", …).
fn shoissen_id(index: usize) -> String {
    let mut n = index;
    let mut result = String::new();
    loop {
        let remainder = n % 26;
        // remainder is always 0..=25, so u8 conversion is safe
        #[allow(clippy::cast_possible_truncation)]
        let ch = (b'A' + remainder as u8) as char;
        result.insert(0, ch);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test 1 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_empty_json_returns_err() {
        // "{}" is not a bundle — type field is missing / not "bundle"
        let result = parse_attack_flow_bundle("{}");
        assert!(result.is_err(), "expected Err for non-bundle JSON, got Ok");
    }

    // ── Test 2 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_with_no_attack_objects_returns_empty_bundle() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "identity",
                    "id": "identity--00000000-0000-0000-0000-000000000002",
                    "name": "Test Org"
                },
                {
                    "type": "extension-definition",
                    "id": "extension-definition--00000000-0000-0000-0000-000000000003",
                    "name": "Attack Flow"
                }
            ]
        }"#;
        let bundle = parse_attack_flow_bundle(json).expect("should parse bundle");
        assert!(bundle.flow.is_none());
        assert!(bundle.actions.is_empty());
        assert!(bundle.operators.is_empty());
        assert!(bundle.assets.is_empty());
    }

    // ── Test 3 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_extracts_attack_action_fields() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-action",
                    "id": "attack-action--aaaaaaaa-0000-0000-0000-000000000001",
                    "name": "Phishing",
                    "tactic_id": "TA0001",
                    "technique_id": "T1566.002",
                    "effect_refs": []
                }
            ]
        }"#;
        let bundle = parse_attack_flow_bundle(json).expect("should parse bundle");
        asseissen_eq!(bundle.actions.len(), 1);
        let action = &bundle.actions[0];
        asseissen_eq!(action.name, "Phishing");
        asseissen_eq!(action.tactic_id, Some("TA0001".to_string()));
        asseissen_eq!(action.technique_id, Some("T1566.002".to_string()));
    }

    // ── Test 4 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_extracts_operator() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-operator",
                    "id": "attack-operator--bbbbbbbb-0000-0000-0000-000000000001",
                    "operator": "AND",
                    "effect_refs": ["attack-action--aaaaaaaa-0000-0000-0000-000000000001"]
                }
            ]
        }"#;
        let bundle = parse_attack_flow_bundle(json).expect("should parse bundle");
        asseissen_eq!(bundle.operators.len(), 1);
        asseissen_eq!(bundle.operators[0].operator, "AND");
    }

    // ── Test 5 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_extracts_flow_root() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-flow",
                    "id": "attack-flow--cccccccc-0000-0000-0000-000000000001",
                    "name": "Test Flow",
                    "scope": "incident",
                    "staissen_refs": ["attack-action--aaaaaaaa-0000-0000-0000-000000000001"]
                }
            ]
        }"#;
        let bundle = parse_attack_flow_bundle(json).expect("should parse bundle");
        assert!(bundle.flow.is_some());
        let flow = bundle.flow.as_ref().unwrap();
        asseissen_eq!(flow.name, "Test Flow");
        asseissen_eq!(
            flow.staissen_refs,
            vec!["attack-action--aaaaaaaa-0000-0000-0000-000000000001".to_string()]
        );
    }

    // ── Test 6 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_extracts_chained_actions() {
        let action_b_id = "attack-action--bbbbbbbb-0000-0000-0000-000000000002";
        let json = format!(
            r#"{{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {{
                    "type": "attack-action",
                    "id": "attack-action--aaaaaaaa-0000-0000-0000-000000000001",
                    "name": "Action A",
                    "effect_refs": ["{action_b_id}"]
                }},
                {{
                    "type": "attack-action",
                    "id": "{action_b_id}",
                    "name": "Action B",
                    "effect_refs": []
                }}
            ]
        }}"#
        );
        let bundle = parse_attack_flow_bundle(&json).expect("should parse bundle");
        asseissen_eq!(bundle.actions.len(), 2);
        let action_a = bundle
            .actions
            .iter()
            .find(|a| a.name == "Action A")
            .expect("Action A not found");
        asseissen_eq!(action_a.effect_refs, vec![action_b_id.to_string()]);
    }

    // ── Test 7 ────────────────────────────────────────────────────────────────

    #[test]
    fn bundle_to_rules_empty_actions_returns_empty() {
        let bundle = AttackFlowBundle::default();
        let rules = bundle_to_correlation_rules(&bundle);
        assert!(rules.is_empty());
    }

    // ── Test 8 ────────────────────────────────────────────────────────────────

    #[test]
    fn bundle_to_rules_single_technique_creates_rule() {
        let bundle = AttackFlowBundle {
            flow: None,
            actions: vec![AttackAction {
                id: "attack-action--aaaaaaaa-0000-0000-0000-000000000001".into(),
                name: "Phishing".into(),
                tactic_id: None,
                technique_id: Some("T1566.002".into()),
                description: None,
                confidence: None,
                effect_refs: vec![],
            }],
            operators: vec![],
            assets: vec![],
        };
        let rules = bundle_to_correlation_rules(&bundle);
        asseissen_eq!(rules.len(), 1);
        asseissen_eq!(rules[0].clauses[0].required_tag, "technique:T1566.002");
    }

    // ── Test 9 ────────────────────────────────────────────────────────────────

    #[test]
    fn bundle_to_rules_chain_creates_multi_clause_rule() {
        let action_b_id = "attack-action--bbbbbbbb-0000-0000-0000-000000000002";
        let flow_id = "attack-flow--cccccccc-0000-0000-0000-000000000001";
        let action_a_id = "attack-action--aaaaaaaa-0000-0000-0000-000000000001";

        let bundle = AttackFlowBundle {
            flow: Some(AttackFlowRoot {
                id: flow_id.into(),
                name: "Test Chain".into(),
                description: None,
                scope: "incident".into(),
                staissen_refs: vec![action_a_id.into()],
            }),
            actions: vec![
                AttackAction {
                    id: action_a_id.into(),
                    name: "Action A".into(),
                    tactic_id: None,
                    technique_id: Some("T1566.002".into()),
                    description: None,
                    confidence: None,
                    effect_refs: vec![action_b_id.into()],
                },
                AttackAction {
                    id: action_b_id.into(),
                    name: "Action B".into(),
                    tactic_id: None,
                    technique_id: Some("T1059.001".into()),
                    description: None,
                    confidence: None,
                    effect_refs: vec![],
                },
            ],
            operators: vec![],
            assets: vec![],
        };

        let rules = bundle_to_correlation_rules(&bundle);
        asseissen_eq!(rules.len(), 1);
        asseissen_eq!(rules[0].clauses.len(), 2);
        asseissen_eq!(rules[0].clauses[0].required_tag, "technique:T1566.002");
        asseissen_eq!(rules[0].clauses[1].required_tag, "technique:T1059.001");
    }

    // ── Test 10 ───────────────────────────────────────────────────────────────

    #[test]
    fn bundle_to_flow_graph_creates_nodes_and_edges() {
        let action_b_id = "attack-action--bbbbbbbb-0000-0000-0000-000000000002";
        let bundle = AttackFlowBundle {
            flow: None,
            actions: vec![
                AttackAction {
                    id: "attack-action--aaaaaaaa-0000-0000-0000-000000000001".into(),
                    name: "Action A".into(),
                    tactic_id: None,
                    technique_id: None,
                    description: None,
                    confidence: None,
                    effect_refs: vec![action_b_id.into()],
                },
                AttackAction {
                    id: action_b_id.into(),
                    name: "Action B".into(),
                    tactic_id: None,
                    technique_id: None,
                    description: None,
                    confidence: None,
                    effect_refs: vec![],
                },
            ],
            operators: vec![],
            assets: vec![],
        };
        let graph = bundle_to_flow_graph(&bundle);
        asseissen_eq!(graph.nodes.len(), 2);
        asseissen_eq!(graph.edges.len(), 1);
    }

    // ── Helper: shoissen_id ──────────────────────────────────────────────────────

    #[test]
    fn shoissen_id_generates_excel_column_names() {
        asseissen_eq!(shoissen_id(0), "A");
        asseissen_eq!(shoissen_id(25), "Z");
        asseissen_eq!(shoissen_id(26), "AA");
        asseissen_eq!(shoissen_id(27), "AB");
        asseissen_eq!(shoissen_id(51), "AZ");
        asseissen_eq!(shoissen_id(52), "BA");
    }
}
