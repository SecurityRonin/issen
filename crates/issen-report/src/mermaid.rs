//! Mermaid diagram generators for `Issen` reports.
//!
//! Provides two pure string-generation functions:
//! - [`render_attack_chain`]: color-coded `flowchart LR` by [`AttackTactic`]
//! - [`render_defenses`]: `flowchart TD` with PREVENT/DETECT/HUNT/GAPS subgraphs

use std::fmt::Write as FmtWrite;

// ---------------------------------------------------------------------------
// Attack chain types
// ---------------------------------------------------------------------------

/// Tactic classification for an attack chain node; controls node colour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackTactic {
    InitialAccess,
    Execution,
    Persistence,
    DefenseEvasion,
    CommandAndControl,
    Impact,
    Unknown,
}

/// A single node in the attack chain diagram.
#[derive(Debug, Clone)]
pub struct AttackChainNode {
    /// Short identifier used in Mermaid edges (e.g. `"A"`, `"B"`).
    pub id: String,
    /// Human-readable label shown inside the node box.
    pub label: String,
    /// Tactic category — determines node colour via `classDef`.
    pub tactic: AttackTactic,
}

/// A directed edge between two nodes in the attack chain.
#[derive(Debug, Clone)]
pub struct AttackChainEdge {
    /// Source node id.
    pub from: String,
    /// Destination node id.
    pub to: String,
}

/// Full input for [`render_attack_chain`].
#[derive(Debug, Clone, Default)]
pub struct AttackChainInput {
    pub nodes: Vec<AttackChainNode>,
    pub edges: Vec<AttackChainEdge>,
}

// ---------------------------------------------------------------------------
// Defense types
// ---------------------------------------------------------------------------

/// Category for a defense recommendation item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefenseCategory {
    Prevent,
    Detect,
    Hunt,
    Gap,
}

/// A single defense recommendation item.
#[derive(Debug, Clone)]
pub struct DefenseItem {
    /// Node text shown inside the diagram box.
    pub label: String,
    /// Which subgraph this item belongs to.
    pub category: DefenseCategory,
}

/// Full input for [`render_defenses`].
#[derive(Debug, Clone, Default)]
pub struct DefenseInput {
    pub items: Vec<DefenseItem>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

impl AttackTactic {
    fn class_name(&self) -> &'static str {
        match self {
            Self::InitialAccess => "initial",
            Self::Execution => "exec",
            Self::Persistence => "persist",
            Self::DefenseEvasion => "evasion",
            Self::CommandAndControl => "c2",
            Self::Impact => "impact",
            Self::Unknown => "unknown",
        }
    }
}

/// Escape double-quotes in a Mermaid node label as `#quot;`.
fn mermaid_escape(s: &str) -> String {
    s.replace('"', "#quot;")
}

fn emit_subgraph(
    out: &mut String,
    subgraph_id: &str,
    subgraph_label: &str,
    prefix: &str,
    class: &str,
    items: &[&DefenseItem],
) {
    if items.is_empty() {
        return;
    }
    let _ = write!(out, "\n    subgraph {subgraph_id}[\"{subgraph_label}\"]\n");
    for (i, item) in items.iter().enumerate() {
        let label = mermaid_escape(&item.label);
        let _ = writeln!(out, "        {prefix}{i}[\"{label}\"]:::{class}");
    }
    out.push_str("    end\n");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Render an attack chain as a color-coded Mermaid `flowchart LR` diagram.
///
/// Each node is styled by its [`AttackTactic`] via a `classDef`. Edges are
/// rendered as `A --> B` arrows. An empty input returns only the header and
/// `classDef` lines (no nodes or edges).
#[must_use]
pub fn render_attack_chain(input: &AttackChainInput) -> String {
    let mut out = String::new();
    out.push_str("flowchart LR\n");
    out.push_str(
        "    classDef initial  fill:#1a5276,stroke:#154360,color:#fff,font-weight:bold\n",
    );
    out.push_str(
        "    classDef exec     fill:#d35400,stroke:#a04000,color:#fff,font-weight:bold\n",
    );
    out.push_str(
        "    classDef persist  fill:#7d3c98,stroke:#6c3483,color:#fff,font-weight:bold\n",
    );
    out.push_str(
        "    classDef evasion  fill:#1e8449,stroke:#196f3d,color:#fff,font-weight:bold\n",
    );
    out.push_str(
        "    classDef c2       fill:#0e6655,stroke:#0b5345,color:#fff,font-weight:bold\n",
    );
    out.push_str(
        "    classDef impact   fill:#922b21,stroke:#7b241c,color:#fff,font-weight:bold\n",
    );
    out.push_str(
        "    classDef unknown  fill:#5d6d7e,stroke:#4d5d6e,color:#fff,font-weight:bold\n",
    );

    for node in &input.nodes {
        let label = mermaid_escape(&node.label);
        let class = node.tactic.class_name();
        let id = &node.id;
        let _ = writeln!(out, "\n    {id}[\"{label}\"]:::{class}");
    }

    for edge in &input.edges {
        let from = &edge.from;
        let to = &edge.to;
        let _ = writeln!(out, "    {from} --> {to}");
    }

    out
}

/// Render a defense recommendations diagram as a Mermaid `flowchart TD`
/// with PREVENT / DETECT / HUNT / GAPS subgraphs.
///
/// Returns an empty string when `input.items` is empty.
#[must_use]
pub fn render_defenses(input: &DefenseInput) -> String {
    if input.items.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str("flowchart TD\n");
    out.push_str("    classDef detect  fill:#1a5276,stroke:#154360,color:#fff\n");
    out.push_str("    classDef prevent fill:#1e8449,stroke:#196f3d,color:#fff\n");
    out.push_str("    classDef hunt    fill:#7d3c98,stroke:#6c3483,color:#fff\n");
    out.push_str(
        "    classDef gap     fill:#922b21,stroke:#7b241c,color:#fff,font-style:italic\n",
    );

    let prevents: Vec<_> = input
        .items
        .iter()
        .filter(|i| i.category == DefenseCategory::Prevent)
        .collect();
    let detects: Vec<_> = input
        .items
        .iter()
        .filter(|i| i.category == DefenseCategory::Detect)
        .collect();
    let hunts: Vec<_> = input
        .items
        .iter()
        .filter(|i| i.category == DefenseCategory::Hunt)
        .collect();
    let gaps: Vec<_> = input
        .items
        .iter()
        .filter(|i| i.category == DefenseCategory::Gap)
        .collect();

    emit_subgraph(&mut out, "PREVENT", "PREVENT", "P", "prevent", &prevents);
    emit_subgraph(&mut out, "DETECT", "DETECT", "D", "detect", &detects);
    emit_subgraph(&mut out, "HUNT", "HUNT", "H", "hunt", &hunts);
    emit_subgraph(&mut out, "GAP", "GAPS", "G", "gap", &gaps);

    out
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── render_attack_chain ────────────────────────────────────────────────

    #[test]
    fn empty_attack_chain_returns_just_classdefs() {
        let input = AttackChainInput::default();
        let out = render_attack_chain(&input);

        assert!(out.starts_with("flowchart LR\n"), "must start with flowchart LR");
        assert!(out.contains("classDef initial"), "must have initial classDef");
        assert!(out.contains("classDef exec"), "must have exec classDef");
        assert!(out.contains("classDef persist"), "must have persist classDef");
        assert!(out.contains("classDef evasion"), "must have evasion classDef");
        assert!(out.contains("classDef c2"), "must have c2 classDef");
        assert!(out.contains("classDef impact"), "must have impact classDef");
        assert!(out.contains("classDef unknown"), "must have unknown classDef");
        assert!(!out.contains("-->"), "empty input must produce no edges");
    }

    #[test]
    fn single_node_attack_chain_has_correct_class() {
        let input = AttackChainInput {
            nodes: vec![AttackChainNode {
                id: "A".to_string(),
                label: "Phishing email".to_string(),
                tactic: AttackTactic::InitialAccess,
            }],
            edges: vec![],
        };
        let out = render_attack_chain(&input);

        assert!(out.contains("A[\"Phishing email\"]:::initial"), "node must have :::initial class");
        assert!(!out.contains(":::exec"));
        assert!(!out.contains(":::persist"));
    }

    #[test]
    fn node_label_quotes_are_escaped() {
        let input = AttackChainInput {
            nodes: vec![AttackChainNode {
                id: "X".to_string(),
                label: r#"cmd.exe /c "whoami""#.to_string(),
                tactic: AttackTactic::Execution,
            }],
            edges: vec![],
        };
        let out = render_attack_chain(&input);

        assert!(
            out.contains("cmd.exe /c #quot;whoami#quot;"),
            "double-quotes in labels must be escaped as #quot;"
        );
        let node_line = out
            .lines()
            .find(|l| l.contains("X["))
            .expect("node line must exist");
        let raw_quote_count = node_line.chars().filter(|&c| c == '"').count();
        assert_eq!(raw_quote_count, 2, "only the two wrapping quotes should remain in the node line");
    }

    #[test]
    fn attack_chain_edges_connect_nodes() {
        let input = AttackChainInput {
            nodes: vec![
                AttackChainNode {
                    id: "A".to_string(),
                    label: "SSH login".to_string(),
                    tactic: AttackTactic::InitialAccess,
                },
                AttackChainNode {
                    id: "B".to_string(),
                    label: "python3 pty".to_string(),
                    tactic: AttackTactic::Execution,
                },
            ],
            edges: vec![AttackChainEdge {
                from: "A".to_string(),
                to: "B".to_string(),
            }],
        };
        let out = render_attack_chain(&input);

        assert!(out.contains("A --> B"), "edge A → B must appear");
        assert!(out.contains("A[\"SSH login\"]:::initial"));
        assert!(out.contains("B[\"python3 pty\"]:::exec"));
    }

    // ── render_defenses ───────────────────────────────────────────────────

    #[test]
    fn empty_defense_input_returns_empty_string() {
        let input = DefenseInput::default();
        assert_eq!(render_defenses(&input), "", "empty input must return empty string");
    }

    #[test]
    fn prevent_items_go_in_prevent_subgraph() {
        let input = DefenseInput {
            items: vec![
                DefenseItem {
                    label: "Disable SSH password auth".to_string(),
                    category: DefenseCategory::Prevent,
                },
                DefenseItem {
                    label: "Immutable ld.so.preload".to_string(),
                    category: DefenseCategory::Prevent,
                },
            ],
        };
        let out = render_defenses(&input);

        assert!(out.starts_with("flowchart TD\n"), "must start with flowchart TD");
        assert!(out.contains("subgraph PREVENT"), "must have PREVENT subgraph");
        assert!(out.contains("P0[\"Disable SSH password auth\"]:::prevent"));
        assert!(out.contains("P1[\"Immutable ld.so.preload\"]:::prevent"));
        assert!(!out.contains("subgraph DETECT"));
        assert!(!out.contains("subgraph HUNT"));
        assert!(!out.contains("subgraph GAP"));
    }

    #[test]
    fn mixed_categories_produce_correct_subgraphs() {
        let input = DefenseInput {
            items: vec![
                DefenseItem {
                    label: "Egress firewall".to_string(),
                    category: DefenseCategory::Prevent,
                },
                DefenseItem {
                    label: "CPU anomaly alert".to_string(),
                    category: DefenseCategory::Detect,
                },
                DefenseItem {
                    label: "Hidden-PID correlation".to_string(),
                    category: DefenseCategory::Hunt,
                },
                DefenseItem {
                    label: "No memory data for PID 999".to_string(),
                    category: DefenseCategory::Gap,
                },
            ],
        };
        let out = render_defenses(&input);

        assert!(out.contains("subgraph PREVENT"), "PREVENT subgraph");
        assert!(out.contains("subgraph DETECT"), "DETECT subgraph");
        assert!(out.contains("subgraph HUNT"), "HUNT subgraph");
        assert!(out.contains("subgraph GAP"), "GAP subgraph");

        assert!(out.contains("P0[\"Egress firewall\"]:::prevent"));
        assert!(out.contains("D0[\"CPU anomaly alert\"]:::detect"));
        assert!(out.contains("H0[\"Hidden-PID correlation\"]:::hunt"));
        assert!(out.contains("G0[\"No memory data for PID 999\"]:::gap"));
    }

    #[test]
    fn subgraphs_omitted_when_no_items_in_category() {
        let input = DefenseInput {
            items: vec![DefenseItem {
                label: "Thread-name analysis".to_string(),
                category: DefenseCategory::Hunt,
            }],
        };
        let out = render_defenses(&input);

        assert!(out.contains("subgraph HUNT"), "HUNT subgraph must be present");
        assert!(!out.contains("subgraph PREVENT"), "PREVENT must be absent when empty");
        assert!(!out.contains("subgraph DETECT"), "DETECT must be absent when empty");
        assert!(!out.contains("subgraph GAP"), "GAP must be absent when empty");
    }
}
