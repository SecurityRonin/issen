//! MFT → in-memory file tree reconstruction.

use std::collections::HashMap;

use crate::node::FileNode;

const ROOT_MFT_ENTRY: u64 = 5;

/// Arena-style file tree built from MFT nodes.
pub struct FileTree {
    nodes: Vec<FileNode>,
    children: Vec<Vec<usize>>,
    entry_map: HashMap<u64, usize>,
    root_idx: Option<usize>,
    /// Pre-computed full paths for every node (parallel to `nodes`).
    paths: Vec<String>,
    /// Pre-computed lowercased paths for O(0-alloc) search.
    paths_lower: Vec<String>,
    pub total_mft_entries: u64,
    pub allocated_entries: usize,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl FileTree {
    /// Build a tree from pre-collected nodes (used by `from_mft` and tests).
    #[must_use]
    pub fn from_nodes(nodes: Vec<FileNode>) -> Self {
        let allocated = nodes.len();
        let mut entry_map: HashMap<u64, usize> = HashMap::with_capacity(allocated);
        for (idx, node) in nodes.iter().enumerate() {
            entry_map.insert(node.mft_entry, idx);
        }

        let mut children: Vec<Vec<usize>> = vec![Vec::new(); allocated];
        for (idx, node) in nodes.iter().enumerate() {
            if let Some(&parent_idx) = entry_map.get(&node.parent_entry) {
                if parent_idx != idx {
                    children[parent_idx].push(idx);
                }
            }
        }

        for child_list in &mut children {
            let n = &nodes;
            child_list.sort_by(|&a, &b| {
                n[b].is_dir
                    .cmp(&n[a].is_dir)
                    .then_with(|| n[a].name.to_lowercase().cmp(&n[b].name.to_lowercase()))
            });
        }

        let root_idx = entry_map.get(&ROOT_MFT_ENTRY).copied();

        // BFS path building from root
        let mut paths = vec![String::new(); allocated];
        if let Some(root) = root_idx {
            paths[root] = "/".to_string();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(root);
            while let Some(parent) = queue.pop_front() {
                for &child in &children[parent] {
                    let parent_path = &paths[parent];
                    paths[child] = if parent_path == "/" {
                        format!("/{}", nodes[child].name)
                    } else {
                        format!("{}/{}", parent_path, nodes[child].name)
                    };
                    queue.push_back(child);
                }
            }
        }

        // Orphan fallback: any node still without a path gets one via parent chain
        for (idx, path_slot) in paths.iter_mut().enumerate() {
            if path_slot.is_empty() {
                let mut parts = Vec::new();
                let mut current = idx;
                let mut visited = std::collections::HashSet::new();
                loop {
                    if !visited.insert(current) {
                        break;
                    }
                    let node = &nodes[current];
                    if node.mft_entry == ROOT_MFT_ENTRY {
                        break;
                    }
                    parts.push(node.name.as_str());
                    match entry_map.get(&node.parent_entry) {
                        Some(&pi) if pi != current => current = pi,
                        _ => break,
                    }
                }
                parts.reverse();
                *path_slot = if parts.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{}", parts.join("/"))
                };
            }
        }

        let paths_lower: Vec<String> = paths.iter().map(|p| p.to_lowercase()).collect();

        Self {
            nodes,
            children,
            entry_map,
            root_idx,
            paths,
            paths_lower,
            total_mft_entries: allocated as u64,
            allocated_entries: allocated,
        }
    }
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

impl FileTree {
    /// Number of nodes in the tree (files + directories).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn root_idx(&self) -> Option<usize> {
        self.root_idx
    }

    #[must_use]
    pub fn node(&self, idx: usize) -> &FileNode {
        &self.nodes[idx]
    }

    /// Mutable reference to a node by arena index.
    pub fn node_mut(&mut self, idx: usize) -> &mut FileNode {
        &mut self.nodes[idx]
    }

    #[must_use]
    pub fn entry_to_idx(&self, mft_entry: u64) -> Option<&usize> {
        self.entry_map.get(&mft_entry)
    }

    #[must_use]
    pub fn children(&self, idx: usize) -> &[usize] {
        &self.children[idx]
    }

    #[must_use]
    pub fn cached_path(&self, idx: usize) -> &str {
        &self.paths[idx]
    }

    /// Maximum search results to return (avoids huge allocations for short queries).
    const MAX_SEARCH_RESULTS: usize = 10_000;

    #[must_use]
    pub fn search(&self, query: &str) -> Vec<usize> {
        let query_lower = query.to_lowercase();
        (0..self.nodes.len())
            .filter(|&idx| {
                if self.nodes[idx].mft_entry == ROOT_MFT_ENTRY {
                    return false;
                }
                self.paths_lower[idx].contains(&query_lower)
            })
            .take(Self::MAX_SEARCH_RESULTS)
            .collect()
    }

    /// Pre-computed lowercase path for an arena index (useful for sorting).
    #[must_use]
    pub fn cached_path_lower(&self, idx: usize) -> &str {
        &self.paths_lower[idx]
    }

    #[must_use]
    pub fn dir_stats(&self, idx: usize) -> (usize, usize, u64) {
        let children = &self.children[idx];
        let dirs = children.iter().filter(|&&c| self.nodes[c].is_dir).count();
        let files = children.len() - dirs;
        let total_size: u64 = children
            .iter()
            .filter(|&&c| !self.nodes[c].is_dir)
            .map(|&c| self.nodes[c].size)
            .sum();
        (dirs, files, total_size)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{FileNode, NtfsTimestamps};
    use chrono::{DateTime, TimeZone, Utc};

    fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    fn default_timestamps() -> NtfsTimestamps {
        NtfsTimestamps {
            modified: ts(2024, 1, 1),
            accessed: ts(2024, 1, 1),
            created: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        }
    }

    /// Helper: create a directory `FileNode`.
    fn dir_node(name: &str, mft_entry: u64, parent_entry: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry,
            parent_entry,
            is_dir: true,
            size: 0,
            si_timestamps: default_timestamps(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        }
    }

    /// Helper: create a file `FileNode`.
    fn file_node(name: &str, mft_entry: u64, parent_entry: u64, size: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry,
            parent_entry,
            is_dir: false,
            size,
            si_timestamps: NtfsTimestamps {
                modified: ts(2024, 6, 15),
                accessed: ts(2024, 6, 15),
                created: ts(2024, 1, 1),
                entry_modified: ts(2024, 6, 15),
            },
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        }
    }

    /// Helper: build a sample tree for tests.
    ///
    /// Structure:
    /// ```text
    /// / (root, MFT#5)
    /// ├── Windows/ (MFT#30)
    /// │   ├── System32/ (MFT#31)
    /// │   │   ├── cmd.exe (MFT#100, 289K)
    /// │   │   └── notepad.exe (MFT#101, 201K)
    /// │   └── explorer.exe (MFT#102, 4.7M)
    /// ├── Users/ (MFT#40)
    /// │   └── admin/ (MFT#41)
    /// │       └── Desktop/ (MFT#42)
    /// │           └── report.docx (MFT#200, 52K)
    /// └── pagefile.sys (MFT#10, 2G)
    /// ```
    fn sample_nodes() -> Vec<FileNode> {
        vec![
            dir_node(".", 5, 5), // root (self-referencing)
            dir_node("Windows", 30, 5),
            dir_node("System32", 31, 30),
            file_node("cmd.exe", 100, 31, 289_000),
            file_node("notepad.exe", 101, 31, 201_000),
            file_node("explorer.exe", 102, 30, 4_700_000),
            dir_node("Users", 40, 5),
            dir_node("admin", 41, 40),
            dir_node("Desktop", 42, 41),
            file_node("report.docx", 200, 42, 52_000),
            file_node("pagefile.sys", 10, 5, 2_000_000_000),
        ]
    }

    // -- Construction tests --------------------------------------------------

    #[test]
    fn from_nodes_builds_tree_with_correct_entry_count() {
        let nodes = sample_nodes();
        let tree = FileTree::from_nodes(nodes);
        assert_eq!(tree.allocated_entries, 11);
    }

    #[test]
    fn from_nodes_finds_root_at_entry_5() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().expect("should have root");
        assert_eq!(tree.node(root).mft_entry, ROOT_MFT_ENTRY);
    }

    #[test]
    fn empty_nodes_produces_no_root() {
        let tree = FileTree::from_nodes(vec![]);
        assert!(tree.root_idx().is_none());
    }

    // -- Children tests ------------------------------------------------------

    #[test]
    fn root_has_three_children() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        // Windows/, Users/, pagefile.sys
        assert_eq!(tree.children(root).len(), 3);
    }

    #[test]
    fn children_sorted_dirs_before_files() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        let kids = tree.children(root);

        // First two should be dirs (Users, Windows alphabetically), last is file
        assert!(tree.node(kids[0]).is_dir, "first child should be a dir");
        assert!(tree.node(kids[1]).is_dir, "second child should be a dir");
        assert!(
            !tree.node(kids[kids.len() - 1]).is_dir,
            "last child should be a file"
        );
    }

    #[test]
    fn children_dirs_sorted_case_insensitive() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        let kids = tree.children(root);

        let dir_names: Vec<&str> = kids
            .iter()
            .filter(|&&i| tree.node(i).is_dir)
            .map(|&i| tree.node(i).name.as_str())
            .collect();
        // Users before Windows (alphabetical)
        assert_eq!(dir_names, vec!["Users", "Windows"]);
    }

    #[test]
    fn system32_has_two_files() {
        let tree = FileTree::from_nodes(sample_nodes());
        let sys32 = tree.entry_to_idx(31).expect("System32 should exist");
        assert_eq!(tree.children(*sys32).len(), 2);
    }

    // -- cached_path tests ---------------------------------------------------

    #[test]
    fn cached_path_of_root_is_slash() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        assert_eq!(tree.cached_path(root), "/");
    }

    #[test]
    fn cached_path_of_direct_child() {
        let tree = FileTree::from_nodes(sample_nodes());
        let idx = *tree.entry_to_idx(30).unwrap();
        assert_eq!(tree.cached_path(idx), "/Windows");
    }

    #[test]
    fn cached_path_of_deeply_nested_file() {
        let tree = FileTree::from_nodes(sample_nodes());
        let idx = *tree.entry_to_idx(200).unwrap();
        assert_eq!(tree.cached_path(idx), "/Users/admin/Desktop/report.docx");
    }

    #[test]
    fn cached_path_of_system32_exe() {
        let tree = FileTree::from_nodes(sample_nodes());
        let idx = *tree.entry_to_idx(100).unwrap();
        assert_eq!(tree.cached_path(idx), "/Windows/System32/cmd.exe");
    }

    // -- search tests --------------------------------------------------------

    #[test]
    fn search_finds_file_by_name() {
        let tree = FileTree::from_nodes(sample_nodes());
        let results = tree.search("cmd.exe");
        assert_eq!(results.len(), 1);
        assert_eq!(tree.node(results[0]).name, "cmd.exe");
    }

    #[test]
    fn search_matches_directory_path() {
        let tree = FileTree::from_nodes(sample_nodes());
        let results = tree.search("System32");
        // Should match System32 dir, plus cmd.exe and notepad.exe (path contains System32)
        assert!(results.len() >= 3);
    }

    #[test]
    fn search_is_case_insensitive() {
        let tree = FileTree::from_nodes(sample_nodes());
        let lower = tree.search("windows");
        let upper = tree.search("WINDOWS");
        assert_eq!(lower.len(), upper.len());
        assert!(!lower.is_empty());
    }

    #[test]
    fn search_anywhere_in_path() {
        let tree = FileTree::from_nodes(sample_nodes());
        // "admin/Desktop" spans two path components
        let results = tree.search("admin/Desktop");
        assert!(!results.is_empty());
        // Should find Desktop dir and report.docx
        assert!(results.len() >= 2);
    }

    #[test]
    fn search_with_no_match_returns_empty() {
        let tree = FileTree::from_nodes(sample_nodes());
        let results = tree.search("nonexistent_file.txt");
        assert!(results.is_empty());
    }

    #[test]
    fn search_excludes_root_node() {
        let tree = FileTree::from_nodes(sample_nodes());
        let results = tree.search("/");
        // Every path starts with /, so we'd get all non-root nodes, but NOT root itself
        for &idx in &results {
            assert_ne!(tree.node(idx).mft_entry, ROOT_MFT_ENTRY);
        }
    }

    // -- dir_stats tests -----------------------------------------------------

    #[test]
    fn dir_stats_for_root() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        let (dirs, files, size) = tree.dir_stats(root);
        assert_eq!(dirs, 2); // Windows, Users
        assert_eq!(files, 1); // pagefile.sys
        assert_eq!(size, 2_000_000_000);
    }

    #[test]
    fn dir_stats_for_system32() {
        let tree = FileTree::from_nodes(sample_nodes());
        let sys32 = *tree.entry_to_idx(31).unwrap();
        let (dirs, files, size) = tree.dir_stats(sys32);
        assert_eq!(dirs, 0);
        assert_eq!(files, 2); // cmd.exe, notepad.exe
        assert_eq!(size, 289_000 + 201_000);
    }

    #[test]
    fn dir_stats_for_empty_dir() {
        // Desktop has one file (report.docx)
        let tree = FileTree::from_nodes(sample_nodes());
        let desktop = *tree.entry_to_idx(42).unwrap();
        let (dirs, files, size) = tree.dir_stats(desktop);
        assert_eq!(dirs, 0);
        assert_eq!(files, 1);
        assert_eq!(size, 52_000);
    }

    // -- entry_to_idx tests --------------------------------------------------

    #[test]
    fn entry_to_idx_known_entry() {
        let tree = FileTree::from_nodes(sample_nodes());
        assert!(tree.entry_to_idx(30).is_some());
    }

    #[test]
    fn entry_to_idx_unknown_entry() {
        let tree = FileTree::from_nodes(sample_nodes());
        assert!(tree.entry_to_idx(99999).is_none());
    }

    // -- Cached path index tests ---------------------------------------------

    #[test]
    fn cached_path_all_start_with_slash() {
        let tree = FileTree::from_nodes(sample_nodes());
        for idx in 0..tree.allocated_entries {
            let path = tree.cached_path(idx);
            assert!(
                path.starts_with('/'),
                "path at index {idx} should start with /: {path}"
            );
        }
    }

    #[test]
    fn cached_path_root_is_slash() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        assert_eq!(tree.cached_path(root), "/");
    }

    #[test]
    fn cached_path_deeply_nested() {
        let tree = FileTree::from_nodes(sample_nodes());
        let idx = *tree.entry_to_idx(200).unwrap();
        assert_eq!(tree.cached_path(idx), "/Users/admin/Desktop/report.docx");
    }

    #[test]
    fn cached_path_empty_tree() {
        let tree = FileTree::from_nodes(vec![]);
        assert_eq!(tree.allocated_entries, 0);
        // No paths to check — just ensure it doesn't panic
    }

    #[test]
    fn search_uses_cached_paths_same_results() {
        let tree = FileTree::from_nodes(sample_nodes());
        // search should return the same results as before (now backed by cache)
        let results = tree.search("System32");
        assert!(results.len() >= 3); // dir + 2 files
        for &idx in &results {
            assert!(
                tree.cached_path(idx).to_lowercase().contains("system32"),
                "result path should contain 'system32'"
            );
        }
    }
}
