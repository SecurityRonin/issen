//! Tree-level heuristic checks requiring resolved paths (Tier 1).

use rt_mft_tree::tree::FileTree;

use super::anomaly::{Anomaly, AnomalyCategory, AnomalyIndex};
use crate::matching::results::Severity;

/// Run all tree-level checks. Returns an `AnomalyIndex`.
#[must_use]
pub fn check_tree(tree: &FileTree) -> AnomalyIndex {
    let mut index = AnomalyIndex::new();
    let max_entry = tree.allocated_entries as u64;
    let high_entry_threshold = max_entry * 9 / 10; // top 10%

    for idx in 0..tree.allocated_entries {
        let node = tree.node(idx);
        if node.is_dir {
            continue;
        }
        let path_lower = tree.cached_path(idx).to_lowercase();

        check_loc_001(idx, node, &path_lower, &mut index);
        check_loc_002(idx, node, &path_lower, high_entry_threshold, &mut index);
        check_loc_003(idx, node, &mut index);
    }

    index
}

const EXECUTABLE_EXTS: &[&str] = &[
    ".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".cmd", ".com",
];

const SUSPICIOUS_PATHS: &[&str] = &[
    "temp",
    "$recycle.bin",
    "appdata/local/temp",
    "appdata/roaming/temp",
    "windows/temp",
    "tmp",
];

fn has_executable_ext(name: &str) -> bool {
    let lower = name.to_lowercase();
    EXECUTABLE_EXTS.iter().any(|ext| lower.ends_with(ext))
}

fn check_loc_001(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    path_lower: &str,
    index: &mut AnomalyIndex,
) {
    if !has_executable_ext(&node.name) {
        return;
    }
    if SUSPICIOUS_PATHS.iter().any(|p| path_lower.contains(p)) {
        index.add(
            idx,
            Anomaly {
                severity: Severity::Medium,
                category: AnomalyCategory::SuspiciousLocation,
                rule_id: "HEUR-LOC-001",
                description: "Executable in temporary or recycled path".to_string(),
                evidence: format!("path={path_lower}"),
            },
        );
    }
}

fn check_loc_002(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    path_lower: &str,
    high_entry_threshold: u64,
    index: &mut AnomalyIndex,
) {
    if !path_lower.contains("/windows/system32/") && !path_lower.starts_with("/windows/system32") {
        return;
    }
    if node.mft_entry >= high_entry_threshold {
        index.add(
            idx,
            Anomaly {
                severity: Severity::Medium,
                category: AnomalyCategory::SuspiciousLocation,
                rule_id: "HEUR-LOC-002",
                description: "High MFT entry number in system directory".to_string(),
                evidence: format!(
                    "mft_entry={}, threshold={high_entry_threshold}, path={path_lower}",
                    node.mft_entry,
                ),
            },
        );
    }
}

const SUSPICIOUS_FILENAMES: &[&str] = &[
    "mimikatz",
    "pwdump",
    "procdump",
    "lazagne",
    "rubeus",
    "sharphound",
    "psexec",
    "wce",
    "gsecdump",
    "sekurlsa",
    "lsass_dump",
    "ntdsutil",
    "covenant",
    "cobalt",
    "meterpreter",
];

fn check_loc_003(idx: usize, node: &rt_mft_tree::node::FileNode, index: &mut AnomalyIndex) {
    let name_lower = node.name.to_lowercase();
    for &suspicious in SUSPICIOUS_FILENAMES {
        if name_lower.contains(suspicious) {
            index.add(
                idx,
                Anomaly {
                    severity: Severity::High,
                    category: AnomalyCategory::SuspiciousLocation,
                    rule_id: "HEUR-LOC-003",
                    description: "Known suspicious tool filename".to_string(),
                    evidence: format!("name={}, matched={suspicious}", node.name),
                },
            );
            return; // One match is enough per file
        }
    }
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
    fn loc_001_exe_in_temp() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Temp", 10, 5),
            file("malware.exe", 100, 10, 5000),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert!(index
            .for_node(2)
            .iter()
            .any(|a| a.rule_id == "HEUR-LOC-001"));
    }

    #[test]
    fn loc_001_no_flag_for_exe_in_program_files() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Program Files", 10, 5),
            file("app.exe", 100, 10, 5000),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert_eq!(index.flagged_count(), 0);
    }

    #[test]
    fn loc_001_no_flag_for_txt_in_temp() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Temp", 10, 5),
            file("notes.txt", 100, 10, 512),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert_eq!(index.flagged_count(), 0);
    }

    #[test]
    fn loc_002_high_entry_in_system32() {
        // allocated_entries = 5, so threshold = 5 * 9/10 = 4
        // entry 900 >> 4
        let nodes = vec![
            dir(".", 5, 5),
            dir("Windows", 6, 5),
            dir("System32", 7, 6),
            file("suspicious.dll", 900, 7, 1024),
            file("normal.dll", 3, 7, 2048),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        // suspicious.dll (entry 900) should be flagged
        let suspicious_idx = *tree.entry_to_idx(900).unwrap();
        assert!(index
            .for_node(suspicious_idx)
            .iter()
            .any(|a| a.rule_id == "HEUR-LOC-002"));
        // normal.dll (entry 3) should NOT be flagged for LOC-002
        let normal_idx = *tree.entry_to_idx(3).unwrap();
        assert!(!index
            .for_node(normal_idx)
            .iter()
            .any(|a| a.rule_id == "HEUR-LOC-002"));
    }

    #[test]
    fn loc_003_mimikatz_detected() {
        let nodes = vec![dir(".", 5, 5), file("mimikatz.exe", 100, 5, 1024)];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert!(index
            .for_node(1)
            .iter()
            .any(|a| a.rule_id == "HEUR-LOC-003"));
    }

    #[test]
    fn loc_003_case_insensitive() {
        let nodes = vec![dir(".", 5, 5), file("MIMIKATZ.EXE", 100, 5, 1024)];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert!(index
            .for_node(1)
            .iter()
            .any(|a| a.rule_id == "HEUR-LOC-003"));
    }

    #[test]
    fn loc_003_no_flag_for_normal_file() {
        let nodes = vec![dir(".", 5, 5), file("notepad.exe", 100, 5, 1024)];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert_eq!(index.flagged_count(), 0);
    }

    #[test]
    fn clean_tree_no_flags() {
        // Use low MFT entry numbers so nothing exceeds the 90% threshold.
        // With 7 nodes, threshold = 7 * 9 / 10 = 6; all file entries must be < 6.
        let nodes = vec![
            dir(".", 5, 5),
            dir("Windows", 1, 5),
            dir("System32", 2, 1),
            file("cmd.exe", 3, 2, 289_000),
            file("notepad.exe", 4, 2, 201_000),
            dir("Users", 0, 5),
            file("readme.txt", 6, 0, 4096),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert_eq!(index.flagged_count(), 0);
    }
}
