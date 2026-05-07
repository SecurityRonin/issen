//! Graphviz DOT format generation and PNG rendering for attack chains.

use std::io::Write as IoWrite;
use std::path::Path;
use std::process::Command;

use crate::{AttackChainInput, AttackTactic};

/// Map an `AttackTactic` to a fill colour hex string.
fn tactic_color(tactic: &AttackTactic) -> &'static str {
    match tactic {
        AttackTactic::InitialAccess => "#1a5276",
        AttackTactic::Execution => "#d35400",
        AttackTactic::Persistence => "#7d3c98",
        AttackTactic::DefenseEvasion => "#1e8449",
        AttackTactic::CommandAndControl => "#0e6655",
        AttackTactic::Impact => "#922b21",
        AttackTactic::Unknown => "#5d6d7e",
    }
}

/// Generate a Graphviz DOT string from an `AttackChainInput`.
///
/// Uses `rankdir=LR` (left-to-right), filled boxes, white font, tactic colours.
#[must_use]
pub fn render_attack_chain_dot(input: &AttackChainInput) -> String {
    let mut lines: Vec<String> = vec![
        "digraph attack_chain {".to_string(),
        r"  rankdir=LR;".to_string(),
        "  node [fontname=\"Helvetica\" fontcolor=\"white\" shape=\"box\" style=\"filled\"];".to_string(),
    ];

    for node in &input.nodes {
        let color = tactic_color(&node.tactic);
        let escaped = node.label.replace('"', "\\\"");
        lines.push(format!(
            r#"  {} [label="{}" fillcolor="{}"];"#,
            node.id, escaped, color
        ));
    }

    for edge in &input.edges {
        lines.push(format!("  {} -> {};", edge.from, edge.to));
    }

    lines.push("}".to_string());
    lines.join("\n")
}

/// Write DOT to a temp file, then shell out to `dot -Tpng -o <output>`.
///
/// # Errors
///
/// Returns `Err` if `dot` is not found or if the conversion fails.
pub fn render_attack_chain_png(input: &AttackChainInput, output: &Path) -> anyhow::Result<()> {
    let dot_src = render_attack_chain_dot(input);
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(dot_src.as_bytes())?;
    tmp.flush()?;

    let status = Command::new("dot")
        .args([
            "-Tpng",
            "-o",
            output.to_str().unwrap_or_default(),
            tmp.path().to_str().unwrap_or_default(),
        ])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("dot exited with non-zero status: {status}"))
    }
}

/// Generate Mermaid syntax and render via `mmdc -i <input> -o <output>`.
///
/// # Errors
///
/// Returns `Err` if `mmdc` is not found or conversion fails.
pub fn render_mermaid_png(mermaid_src: &str, output: &Path) -> anyhow::Result<()> {
    let mut tmp = tempfile::NamedTempFile::with_suffix(".mmd")?;
    tmp.write_all(mermaid_src.as_bytes())?;
    tmp.flush()?;

    let status = Command::new("mmdc")
        .args([
            "-i",
            tmp.path().to_str().unwrap_or_default(),
            "-o",
            output.to_str().unwrap_or_default(),
        ])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("mmdc exited with non-zero status: {status}"))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackChainEdge, AttackChainInput, AttackChainNode, AttackTactic};

    fn two_node_input() -> AttackChainInput {
        AttackChainInput {
            nodes: vec![
                AttackChainNode {
                    id: "A".into(),
                    label: "Phishing".into(),
                    tactic: AttackTactic::InitialAccess,
                },
                AttackChainNode {
                    id: "B".into(),
                    label: "PowerShell".into(),
                    tactic: AttackTactic::Execution,
                },
            ],
            edges: vec![AttackChainEdge {
                from: "A".into(),
                to: "B".into(),
            }],
        }
    }

    #[test]
    fn dot_output_contains_digraph() {
        let dot = render_attack_chain_dot(&two_node_input());
        assert!(dot.contains("digraph"), "DOT output must contain 'digraph'");
    }

    #[test]
    fn dot_includes_all_node_ids() {
        let input = two_node_input();
        let dot = render_attack_chain_dot(&input);
        for node in &input.nodes {
            assert!(
                dot.contains(&node.id),
                "DOT output must contain node id '{}'",
                node.id
            );
        }
    }

    #[test]
    fn dot_includes_edges() {
        let dot = render_attack_chain_dot(&two_node_input());
        assert!(
            dot.contains("A -> B"),
            "DOT output must contain edge 'A -> B'"
        );
    }
}
