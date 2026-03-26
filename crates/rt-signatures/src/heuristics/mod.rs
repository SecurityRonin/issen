pub mod anomaly;
pub mod content_checks;
pub mod entry_checks;
pub mod file_reader;
pub mod magic_table;
pub mod tree_checks;
pub mod usn_analysis;

pub use anomaly::{Anomaly, AnomalyCategory, AnomalyIndex, HeuristicsConfig};
pub use content_checks::run_tier2;
pub use entry_checks::check_entry;
pub use file_reader::{FileReader, FsFileReader, NoFileReader};
pub use tree_checks::check_tree;
pub use usn_analysis::check_usn_stream;

use rt_mft_tree::tree::FileTree;

/// Run all Tier 1 checks (entry-level + tree-level).
///
/// USN stream analysis is not included here — call `check_usn_stream()`
/// separately when USN records are available, then merge with `index.merge()`.
#[must_use]
pub fn run_tier1(tree: &FileTree, config: &HeuristicsConfig) -> AnomalyIndex {
    // Tree-level checks
    let mut index = tree_checks::check_tree(tree);

    // Entry-level checks for every node
    for idx in 0..tree.allocated_entries {
        let node = tree.node(idx);
        if node.is_dir {
            continue;
        }
        let anomalies = entry_checks::check_entry(node, config);
        for anomaly in anomalies {
            index.add(idx, anomaly);
        }
    }

    index
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use rt_mft_tree::node::{FileNode, NtfsTimestamps};
    use rt_mft_tree::tree::FileTree;

    fn ts(y: i32, m: u32, d: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn default_ts() -> NtfsTimestamps {
        NtfsTimestamps {
            modified: ts(2024, 1, 1),
            accessed: ts(2024, 1, 1),
            created: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        }
    }

    fn dir(name: &str, entry: u64, parent: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry: entry,
            parent_entry: parent,
            is_dir: true,
            size: 0,
            si_timestamps: default_ts(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        }
    }

    fn file(name: &str, entry: u64, parent: u64, size: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry: entry,
            parent_entry: parent,
            is_dir: false,
            size,
            si_timestamps: default_ts(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        }
    }

    #[test]
    fn run_tier1_combines_entry_and_tree_checks() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Temp", 10, 5),
            // Timestomped exe in temp -> triggers HEUR-TS-001 + HEUR-LOC-001
            FileNode {
                name: "payload.exe".to_string(),
                mft_entry: 100,
                parent_entry: 10,
                is_dir: false,
                size: 5000,
                si_timestamps: NtfsTimestamps {
                    created: ts(2024, 6, 1),
                    modified: ts(2024, 1, 1),
                    accessed: ts(2024, 1, 1),
                    entry_modified: ts(2024, 1, 1),
                },
                fn_timestamps: None,
                file_attributes: 0,
                usn_change_count: 0,
            },
            // Normal file
            file("readme.txt", 200, 5, 1024),
        ];
        let tree = FileTree::from_nodes(nodes);
        let config = HeuristicsConfig::default();
        let index = run_tier1(&tree, &config);

        // payload.exe should have both entry-level and tree-level findings
        let payload_idx = *tree.entry_to_idx(100).unwrap();
        let anomalies = index.for_node(payload_idx);
        let rule_ids: Vec<&str> = anomalies.iter().map(|a| a.rule_id).collect();
        assert!(
            rule_ids.contains(&"HEUR-TS-001"),
            "expected timestomping flag"
        );
        assert!(
            rule_ids.contains(&"HEUR-LOC-001"),
            "expected suspicious location flag"
        );

        // readme.txt should be clean
        let readme_idx = *tree.entry_to_idx(200).unwrap();
        assert!(index.for_node(readme_idx).is_empty());
    }

    #[test]
    fn run_tier1_clean_tree() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Users", 10, 5),
            file("document.docx", 100, 10, 52_000),
        ];
        let tree = FileTree::from_nodes(nodes);
        let config = HeuristicsConfig::default();
        let index = run_tier1(&tree, &config);
        assert_eq!(index.flagged_count(), 0);
    }
}
