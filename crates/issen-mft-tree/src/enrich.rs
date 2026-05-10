//! USN journal enrichment for `FileTree` nodes.

use crate::tree::FileTree;

impl FileTree {
    /// Enrich nodes with USN journal change counts.
    ///
    /// Each tuple is `(mft_entry_number, filename)`. Matching is done
    /// solely by MFT entry number.
    pub fn enrich_usn(&mut self, records: &[(u64, String)]) {
        for &(mft_entry, _) in records {
            if let Some(&idx) = self.entry_to_idx(mft_entry) {
                self.node_mut(idx).usn_change_count += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::node::{FileNode, NtfsTimestamps};
    use crate::tree::FileTree;
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
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
        }
    }

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
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
        }
    }

    fn sample_nodes() -> Vec<FileNode> {
        vec![
            dir_node(".", 5, 5),
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

    #[test]
    fn enrich_usn_increments_change_count() {
        let mut tree = FileTree::from_nodes(sample_nodes());
        let usn_records = vec![
            (100_u64, "cmd.exe".to_string()),
            (100, "cmd.exe".to_string()),
            (100, "cmd.exe".to_string()),
        ];
        tree.enrich_usn(&usn_records);
        let idx = *tree.entry_to_idx(100).unwrap();
        assert_eq!(tree.node(idx).usn_change_count, 3);
    }

    #[test]
    fn enrich_usn_ignores_unknown_entries() {
        let mut tree = FileTree::from_nodes(sample_nodes());
        let usn_records = vec![(99999_u64, "phantom.txt".to_string())];
        tree.enrich_usn(&usn_records); // should not panic
    }

    #[test]
    fn enrich_usn_multiple_files() {
        let mut tree = FileTree::from_nodes(sample_nodes());
        let usn_records = vec![
            (100_u64, "cmd.exe".to_string()),
            (101, "notepad.exe".to_string()),
            (101, "notepad.exe".to_string()),
            (200, "report.docx".to_string()),
        ];
        tree.enrich_usn(&usn_records);
        assert_eq!(
            tree.node(*tree.entry_to_idx(100).unwrap()).usn_change_count,
            1
        );
        assert_eq!(
            tree.node(*tree.entry_to_idx(101).unwrap()).usn_change_count,
            2
        );
        assert_eq!(
            tree.node(*tree.entry_to_idx(200).unwrap()).usn_change_count,
            1
        );
    }

    #[test]
    fn enrich_usn_leaves_unenriched_at_zero() {
        let mut tree = FileTree::from_nodes(sample_nodes());
        let usn_records = vec![(100_u64, "cmd.exe".to_string())];
        tree.enrich_usn(&usn_records);
        let idx = *tree.entry_to_idx(101).unwrap();
        assert_eq!(tree.node(idx).usn_change_count, 0);
    }
}
