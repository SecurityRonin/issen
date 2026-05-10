//! Attack Flow Builder `.afb` JSON file serialisation.

use std::collections::{HashMap, VecDeque};
use std::path::Path;

use issen_correlation::model::Finding;
use uuid::Uuid;

/// Auto-layout algorithm for DAG nodes.
///
/// Returns a `HashMap` of `instance_id -> [x, y]` coordinates.
/// Uses BFS layering: `x = layer * x_spacing`, `y` centred per layer.
#[must_use]
pub fn auto_layout_dag(
    node_ids: &[&str],
    edges: &[(&str, &str)],
    x_spacing: f64,
    y_spacing: f64,
) -> HashMap<String, [f64; 2]> {
    if node_ids.is_empty() {
        return HashMap::new();
    }

    // Build in-degree map and adjacency list.
    let mut in_degree: HashMap<&str, usize> = node_ids.iter().map(|&n| (n, 0)).collect();
    let mut adj: HashMap<&str, Vec<&str>> = node_ids.iter().map(|&n| (n, vec![])).collect();
    for &(from, to) in edges {
        *in_degree.entry(to).or_insert(0) += 1;
        adj.entry(from).or_default().push(to);
    }

    // BFS from roots (nodes with in-degree == 0).
    let mut layer: HashMap<&str, usize> = HashMap::new();
    let roots: Vec<&str> = node_ids
        .iter()
        .copied()
        .filter(|&n| in_degree.get(n).copied().unwrap_or(0) == 0)
        .collect();
    let mut queue: VecDeque<&str> = if roots.is_empty() {
        // Cycle fallback: start from first node.
        VecDeque::from([node_ids[0]])
    } else {
        VecDeque::from(roots.clone())
    };
    for &root in &queue {
        layer.insert(root, 0);
    }
    while let Some(node) = queue.pop_front() {
        let node_layer = layer.get(node).copied().unwrap_or(0);
        for &next in adj.get(node).map_or(&[] as &[&str], Vec::as_slice) {
            let entry = layer.entry(next).or_insert(0);
            if *entry < node_layer + 1 {
                *entry = node_layer + 1;
                queue.push_back(next);
            }
        }
    }

    // Group nodes by layer.
    let mut by_layer: HashMap<usize, Vec<&str>> = HashMap::new();
    for &node in node_ids {
        by_layer
            .entry(layer.get(node).copied().unwrap_or(0))
            .or_default()
            .push(node);
    }

    // Assign coordinates. Layout only requires display-level precision.
    assign_layer_coords(&by_layer, x_spacing, y_spacing)
}

/// Assign `[x, y]` coordinates to nodes grouped by layer index.
///
/// `x = layer * x_spacing`, `y` is centred within each layer.
// Layout coordinates only need display-level precision; the usize→f64 casts
// are safe for any realistic number of nodes/layers.
#[allow(clippy::cast_precision_loss)]
fn assign_layer_coords(
    by_layer: &HashMap<usize, Vec<&str>>,
    x_spacing: f64,
    y_spacing: f64,
) -> HashMap<String, [f64; 2]> {
    let mut coords: HashMap<String, [f64; 2]> = HashMap::new();
    for (&layer_idx, nodes) in by_layer {
        let count = nodes.len() as f64;
        for (i, &node) in nodes.iter().enumerate() {
            let x = layer_idx as f64 * x_spacing;
            let y = (i as f64 - (count - 1.0) / 2.0) * y_spacing;
            coords.insert(node.to_string(), [x, y]);
        }
    }
    coords
}

/// A camera position for an `AfbDocument`.
#[derive(serde::Serialize)]
pub struct AfbCamera {
    pub x: f64,
    pub y: f64,
    pub k: f64,
}

/// A single object in an `AfbDocument`.
#[derive(serde::Serialize)]
pub struct AfbObject {
    pub id: String,
    pub instance: String,
    pub properties: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects: Option<Vec<String>>,
}

/// An Attack Flow Builder document.
#[derive(serde::Serialize)]
pub struct AfbDocument {
    pub schema: String,
    pub theme: String,
    pub objects: Vec<AfbObject>,
    pub layout: HashMap<String, [f64; 2]>,
    pub camera: AfbCamera,
}

/// Convert a slice of `Finding`s to an `AfbDocument`.
///
/// Creates one "flow" object containing all action instances, and one "action"
/// per finding. Applies `auto_layout_dag` with a linear sequence layout.
#[must_use]
pub fn findings_to_afb(findings: &[Finding], title: &str) -> AfbDocument {
    let flow_instance = Uuid::new_v4().to_string();

    // Build action objects and collect their instance IDs.
    let mut action_instances: Vec<String> = Vec::new();
    let mut afb_objects: Vec<AfbObject> = Vec::new();

    for finding in findings {
        let instance = Uuid::new_v4().to_string();
        let description = finding
            .explanation
            .as_deref()
            .unwrap_or("");
        afb_objects.push(AfbObject {
            id: "action".to_string(),
            instance: instance.clone(),
            properties: vec![
                serde_json::json!(["name", finding.title]),
                serde_json::json!(["description", description]),
            ],
            objects: None,
        });
        action_instances.push(instance);
    }

    // Auto-layout: linear chain A[0] → A[1] → A[2] …
    let node_refs: Vec<&str> = action_instances.iter().map(String::as_str).collect();
    let edge_pairs: Vec<(&str, &str)> = node_refs
        .windows(2)
        .map(|w| (w[0], w[1]))
        .collect();
    let layout = auto_layout_dag(&node_refs, &edge_pairs, 300.0, 200.0);

    // Flow object (container).
    let flow_object = AfbObject {
        id: "flow".to_string(),
        instance: flow_instance,
        properties: vec![
            serde_json::json!(["name", title]),
            serde_json::json!(["scope", "incident"]),
            serde_json::json!(["description", ""]),
        ],
        objects: Some(action_instances),
    };

    // Prepend the flow object.
    let mut objects = vec![flow_object];
    objects.extend(afb_objects);

    AfbDocument {
        schema: "attack_flow_v2".to_string(),
        theme: "dark_theme".to_string(),
        objects,
        layout,
        camera: AfbCamera {
            x: 0.0,
            y: 0.0,
            k: 0.8,
        },
    }
}

/// Write `AfbDocument` to a `.afb` file (pretty JSON, 2-space indent).
///
/// # Errors
///
/// Returns an error if serialization or file I/O fails.
pub fn write_afb(doc: &AfbDocument, path: &Path) -> anyhow::Result<()> {
    let buf = serde_json::to_string_pretty(doc)?;
    std::fs::write(path, buf)?;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use issen_correlation::model::{AssertionLevel, Finding};

    fn make_finding(title: &str) -> Finding {
        Finding {
            rule_id: "test.rule".into(),
            title: title.into(),
            severity: "medium".into(),
            evidence_ids: vec![],
            summary: None,
            explanation: Some("Some explanation".into()),
            confidence: 70,
            assertion_level: AssertionLevel::Correlated,
            evidence_rendered: vec![],
        }
    }

    #[test]
    fn afb_schema_is_attack_flow_v2() {
        let doc = findings_to_afb(&[], "Test Flow");
        assert_eq!(doc.schema, "attack_flow_v2");
    }

    #[test]
    fn afb_has_dark_theme() {
        let doc = findings_to_afb(&[], "Test Flow");
        assert_eq!(doc.theme, "dark_theme");
    }

    #[test]
    fn auto_layout_single_node_at_origin() {
        let coords = auto_layout_dag(&["A"], &[], 300.0, 200.0);
        let pos = coords.get("A").expect("node A must be in layout");
        assert_eq!(*pos, [0.0, 0.0], "single node must be at origin");
    }

    #[test]
    fn auto_layout_linear_chain_increasing_x() {
        let coords = auto_layout_dag(&["A", "B", "C"], &[("A", "B"), ("B", "C")], 300.0, 200.0);
        let xa = coords.get("A").expect("node A")[0];
        let xb = coords.get("B").expect("node B")[0];
        let xc = coords.get("C").expect("node C")[0];
        assert_eq!(xa, 0.0, "root node A must have x=0");
        assert_eq!(xb, 300.0, "node B must have x=300");
        assert_eq!(xc, 600.0, "node C must have x=600");
    }

    #[test]
    fn auto_layout_parallel_nodes_different_y() {
        // A -> B and A -> C: B and C are in the same layer but different rows
        let coords =
            auto_layout_dag(&["A", "B", "C"], &[("A", "B"), ("A", "C")], 300.0, 200.0);
        let yb = coords.get("B").expect("node B")[1];
        let yc = coords.get("C").expect("node C")[1];
        let xb = coords.get("B").expect("node B")[0];
        let xc = coords.get("C").expect("node C")[0];
        assert_eq!(xb, xc, "parallel nodes B and C must have the same x");
        assert_ne!(yb, yc, "parallel nodes B and C must have different y");
    }

    #[test]
    fn write_afb_creates_file() {
        let doc = findings_to_afb(&[make_finding("Test Finding")], "Test Flow");
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("output.afb");
        write_afb(&doc, &path).expect("write_afb");
        assert!(path.exists(), "output .afb file must be created");
    }
}
