//! USN journal stream analysis (Tier 1, operates on parsed records).

use std::collections::HashMap;

use rt_mft_tree::tree::FileTree;
use rt_parser_usnjrnl::{UsnReasonFlags, UsnRecordV2};

use super::anomaly::{Anomaly, AnomalyCategory, AnomalyIndex};
use crate::matching::results::Severity;

/// Run all USN stream analysis checks.
///
/// `records` must be sorted by `usn` (ascending). Provide `tree` to enable
/// ghost file detection (HEUR-USN-004) and to attach findings to tree nodes.
/// Findings for entries not in the tree are attached to the root node (idx 0).
#[must_use]
pub fn check_usn_stream(records: &[UsnRecordV2], tree: Option<&FileTree>) -> AnomalyIndex {
    let mut index = AnomalyIndex::new();
    check_usn_001(records, tree, &mut index);
    check_usn_002(records, tree, &mut index);
    check_usn_003(records, &mut index);
    if let Some(t) = tree {
        check_usn_004(records, t, &mut index);
    }
    index
}

/// Mask a file reference number to 48-bit MFT entry number (strip sequence).
const FRN_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Resolve a file reference number to a tree index, falling back to root (0).
fn resolve_idx(frn: u64, tree: Option<&FileTree>) -> usize {
    tree.and_then(|t| t.entry_to_idx(frn & FRN_MASK).copied())
        .unwrap_or(0)
}

/// HEUR-USN-001: Secure deletion pattern (`SDelete` / `CCleaner`).
///
/// Looks for rename chains where the new filename is all the same character
/// repeated (e.g. "AAAAAAAAAAAA.AAA"), followed by a delete — all within
/// a 30-second window on the same file reference number.
fn check_usn_001(records: &[UsnRecordV2], tree: Option<&FileTree>, index: &mut AnomalyIndex) {
    // Group records by file_reference_number.
    let mut by_frn: HashMap<u64, Vec<&UsnRecordV2>> = HashMap::new();
    for rec in records {
        by_frn
            .entry(rec.file_reference_number)
            .or_default()
            .push(rec);
    }

    for (frn, recs) in &by_frn {
        let mut rename_count = 0u32;
        let mut has_delete = false;
        let mut first_ts: Option<i64> = None;
        let mut last_ts: Option<i64> = None;

        for rec in recs {
            let r = rec.reason.0;
            if r & UsnReasonFlags::RENAME_NEW_NAME != 0 && is_wipe_name(&rec.file_name) {
                rename_count += 1;
                if first_ts.is_none() {
                    first_ts = Some(rec.timestamp);
                }
                last_ts = Some(rec.timestamp);
            }
            if r & UsnReasonFlags::FILE_DELETE != 0 {
                has_delete = true;
                last_ts = Some(rec.timestamp);
            }
        }

        // Need at least 2 renames + delete within 30 seconds.
        if rename_count >= 2 && has_delete {
            if let (Some(first), Some(last)) = (first_ts, last_ts) {
                let window_ticks = (last - first).unsigned_abs();
                let thirty_seconds_ticks: u64 = 30 * 10_000_000; // FILETIME is 100ns
                if window_ticks <= thirty_seconds_ticks {
                    let idx = resolve_idx(*frn, tree);
                    index.add(
                        idx,
                        Anomaly {
                            severity: Severity::High,
                            category: AnomalyCategory::SecureDeletion,
                            rule_id: "HEUR-USN-001",
                            description: "Secure deletion pattern: rename chain + delete"
                                .to_string(),
                            evidence: format!(
                                "frn={frn}, renames={rename_count}, window_ms={}",
                                window_ticks / 10_000
                            ),
                        },
                    );
                }
            }
        }
    }
}

/// Check if a filename looks like a wipe tool rename (all same character).
fn is_wipe_name(name: &str) -> bool {
    let base = name.replace('.', "");
    if base.is_empty() {
        return false;
    }
    let first = base.as_bytes()[0];
    base.bytes().all(|b| b == first)
}

/// HEUR-USN-002: Rapid mass rename (ransomware indicator).
///
/// Flags when >50 distinct files are renamed within a 60-second window.
fn check_usn_002(records: &[UsnRecordV2], tree: Option<&FileTree>, index: &mut AnomalyIndex) {
    // Collect rename records sorted by timestamp.
    let mut renames: Vec<&UsnRecordV2> = records
        .iter()
        .filter(|r| r.reason.0 & UsnReasonFlags::RENAME_NEW_NAME != 0)
        .collect();
    renames.sort_by_key(|r| r.timestamp);

    if renames.len() <= 50 {
        return;
    }

    let sixty_seconds_ticks: i64 = 60 * 10_000_000;
    let mut start = 0usize;

    for end in 0..renames.len() {
        // Shrink window from the left.
        while renames[end].timestamp - renames[start].timestamp > sixty_seconds_ticks {
            start += 1;
        }
        let window = &renames[start..=end];
        // Count distinct file references in window.
        let mut seen = std::collections::HashSet::new();
        for r in window {
            seen.insert(r.file_reference_number);
        }
        if seen.len() > 50 {
            // Flag all files in this window.
            for frn in &seen {
                let idx = resolve_idx(*frn, tree);
                // Avoid duplicate flagging: check if already flagged.
                if index
                    .for_node(idx)
                    .iter()
                    .any(|a| a.rule_id == "HEUR-USN-002")
                {
                    continue;
                }
                index.add(
                    idx,
                    Anomaly {
                        severity: Severity::High,
                        category: AnomalyCategory::RansomwarePattern,
                        rule_id: "HEUR-USN-002",
                        description: "Rapid mass rename — possible ransomware activity".to_string(),
                        evidence: format!(
                            "frn={frn}, distinct_renames={}, window_start={}, window_end={}",
                            seen.len(),
                            renames[start].timestamp,
                            renames[end].timestamp
                        ),
                    },
                );
            }
            return; // One detection is enough.
        }
    }
}

/// HEUR-USN-003: Journal gap / truncation.
///
/// Checks for discontinuities in USN sequence numbers that are too large
/// to be explained by normal record sizes (gap > 1MB suggests clearing).
fn check_usn_003(records: &[UsnRecordV2], index: &mut AnomalyIndex) {
    const GAP_THRESHOLD: i64 = 1_048_576; // 1MB in bytes

    if records.len() < 2 {
        return;
    }

    for pair in records.windows(2) {
        let gap = pair[1].usn - pair[0].usn;
        if gap > GAP_THRESHOLD {
            // Attach to root node (journal-level finding).
            index.add(
                0,
                Anomaly {
                    severity: Severity::Medium,
                    category: AnomalyCategory::JournalTampering,
                    rule_id: "HEUR-USN-003",
                    description: "Large gap in USN journal sequence numbers".to_string(),
                    evidence: format!(
                        "prev_usn={}, next_usn={}, gap_bytes={}",
                        pair[0].usn, pair[1].usn, gap
                    ),
                },
            );
        }
    }
}

/// HEUR-USN-004: Ghost file (USN references non-existent MFT entry).
fn check_usn_004(records: &[UsnRecordV2], tree: &FileTree, index: &mut AnomalyIndex) {
    let mut seen = std::collections::HashSet::new();

    for rec in records {
        let mft_entry = rec.file_reference_number & FRN_MASK;
        if seen.contains(&mft_entry) {
            continue;
        }
        seen.insert(mft_entry);

        if tree.entry_to_idx(mft_entry).is_none() {
            // File no longer in MFT — attach to parent if possible, else root.
            let parent_idx = tree
                .entry_to_idx(rec.parent_file_reference_number & FRN_MASK)
                .copied()
                .unwrap_or(0);
            index.add(
                parent_idx,
                Anomaly {
                    severity: Severity::Medium,
                    category: AnomalyCategory::GhostFile,
                    rule_id: "HEUR-USN-004",
                    description: "USN record references deleted/reallocated MFT entry".to_string(),
                    evidence: format!(
                        "ghost_entry={mft_entry}, file_name={}, parent_frn={}",
                        rec.file_name,
                        rec.parent_file_reference_number & FRN_MASK
                    ),
                },
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use rt_mft_tree::node::{FileNode, NtfsTimestamps};

    /// Windows FILETIME for 2024-06-01 00:00:00 UTC.
    const BASE_FILETIME: i64 = 133_620_192_000_000_000;
    /// One second in FILETIME ticks (100ns units).
    const ONE_SEC: i64 = 10_000_000;

    fn make_usn_record(
        file_name: &str,
        frn: u64,
        parent_frn: u64,
        reason: u32,
        timestamp: i64,
        usn: i64,
    ) -> UsnRecordV2 {
        UsnRecordV2 {
            record_length: 72 + (file_name.len() as u32 * 2),
            major_version: 2,
            minor_version: 0,
            file_reference_number: frn,
            parent_file_reference_number: parent_frn,
            usn,
            timestamp,
            reason: UsnReasonFlags(reason),
            source_info: 0,
            security_id: 0,
            file_attributes: 0,
            file_name: file_name.to_string(),
        }
    }

    fn default_ts() -> NtfsTimestamps {
        let t = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        NtfsTimestamps {
            modified: t,
            accessed: t,
            created: t,
            entry_modified: t,
        }
    }

    fn make_tree() -> FileTree {
        let nodes = vec![
            FileNode {
                name: ".".to_string(),
                mft_entry: 5,
                parent_entry: 5,
                is_dir: true,
                size: 0,
                si_timestamps: default_ts(),
                fn_timestamps: None,
                file_attributes: 0,
                usn_change_count: 0,
            },
            FileNode {
                name: "Users".to_string(),
                mft_entry: 10,
                parent_entry: 5,
                is_dir: true,
                size: 0,
                si_timestamps: default_ts(),
                fn_timestamps: None,
                file_attributes: 0,
                usn_change_count: 0,
            },
            FileNode {
                name: "report.docx".to_string(),
                mft_entry: 100,
                parent_entry: 10,
                is_dir: false,
                size: 50_000,
                si_timestamps: default_ts(),
                fn_timestamps: None,
                file_attributes: 0,
                usn_change_count: 0,
            },
        ];
        FileTree::from_nodes(nodes)
    }

    // --- is_wipe_name ---

    #[test]
    fn wipe_name_detects_sdelete_pattern() {
        assert!(is_wipe_name("AAAAAAAAAAAA.AAA"));
        assert!(is_wipe_name("ZZZZZZZZ.ZZZ"));
        assert!(is_wipe_name("BBBB.B"));
    }

    #[test]
    fn wipe_name_rejects_normal_names() {
        assert!(!is_wipe_name("report.docx"));
        assert!(!is_wipe_name("AABBB.AAA"));
        assert!(!is_wipe_name(""));
    }

    // --- HEUR-USN-001 ---

    #[test]
    fn usn_001_triggers_on_sdelete_pattern() {
        let records = vec![
            make_usn_record(
                "AAAAAA.AAA",
                100,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME,
                1000,
            ),
            make_usn_record(
                "BBBBBB.BBB",
                100,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME + ONE_SEC,
                1100,
            ),
            make_usn_record(
                "CCCCCC.CCC",
                100,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME + 2 * ONE_SEC,
                1200,
            ),
            make_usn_record(
                "CCCCCC.CCC",
                100,
                10,
                UsnReasonFlags::FILE_DELETE,
                BASE_FILETIME + 3 * ONE_SEC,
                1300,
            ),
        ];
        let tree = make_tree();
        let index = check_usn_stream(&records, Some(&tree));
        let entry_idx = *tree.entry_to_idx(100).unwrap();
        assert!(index
            .for_node(entry_idx)
            .iter()
            .any(|a| a.rule_id == "HEUR-USN-001"));
    }

    #[test]
    fn usn_001_does_not_trigger_normal_rename() {
        let records = vec![
            make_usn_record(
                "old_name.txt",
                100,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME,
                1000,
            ),
            make_usn_record(
                "new_name.txt",
                100,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME + ONE_SEC,
                1100,
            ),
        ];
        let tree = make_tree();
        let index = check_usn_stream(&records, Some(&tree));
        let entry_idx = *tree.entry_to_idx(100).unwrap();
        assert!(!index
            .for_node(entry_idx)
            .iter()
            .any(|a| a.rule_id == "HEUR-USN-001"));
    }

    #[test]
    fn usn_001_does_not_trigger_without_delete() {
        let records = vec![
            make_usn_record(
                "AAAAAA.AAA",
                100,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME,
                1000,
            ),
            make_usn_record(
                "BBBBBB.BBB",
                100,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME + ONE_SEC,
                1100,
            ),
        ];
        let index = check_usn_stream(&records, None);
        assert_eq!(index.flagged_count(), 0);
    }

    // --- HEUR-USN-002 ---

    #[test]
    fn usn_002_triggers_on_mass_rename() {
        let mut records = Vec::new();
        for i in 0..55u64 {
            records.push(make_usn_record(
                &format!("file{i}.locked"),
                1000 + i,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME + (i as i64) * (ONE_SEC / 10), // all within ~5.5 seconds
                (i as i64) * 100,
            ));
        }
        let index = check_usn_stream(&records, None);
        assert!(index.flagged_count() > 0);
        // Check at least one node has HEUR-USN-002
        let has_002 = (0..56).any(|idx| {
            index
                .for_node(idx)
                .iter()
                .any(|a| a.rule_id == "HEUR-USN-002")
        });
        assert!(has_002);
    }

    #[test]
    fn usn_002_does_not_trigger_below_threshold() {
        let mut records = Vec::new();
        for i in 0..30u64 {
            records.push(make_usn_record(
                &format!("file{i}.locked"),
                1000 + i,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME + (i as i64) * ONE_SEC,
                (i as i64) * 100,
            ));
        }
        let index = check_usn_stream(&records, None);
        let has_002 = (0..31).any(|idx| {
            index
                .for_node(idx)
                .iter()
                .any(|a| a.rule_id == "HEUR-USN-002")
        });
        assert!(!has_002);
    }

    // --- HEUR-USN-003 ---

    #[test]
    fn usn_003_triggers_on_journal_gap() {
        let records = vec![
            make_usn_record(
                "a.txt",
                100,
                10,
                UsnReasonFlags::FILE_CREATE,
                BASE_FILETIME,
                1000,
            ),
            make_usn_record(
                "b.txt",
                200,
                10,
                UsnReasonFlags::FILE_CREATE,
                BASE_FILETIME + ONE_SEC,
                2_000_000,
            ), // 2MB gap
        ];
        let index = check_usn_stream(&records, None);
        assert!(index
            .for_node(0)
            .iter()
            .any(|a| a.rule_id == "HEUR-USN-003"));
    }

    #[test]
    fn usn_003_does_not_trigger_normal_sequence() {
        let records = vec![
            make_usn_record(
                "a.txt",
                100,
                10,
                UsnReasonFlags::FILE_CREATE,
                BASE_FILETIME,
                1000,
            ),
            make_usn_record(
                "b.txt",
                200,
                10,
                UsnReasonFlags::FILE_CREATE,
                BASE_FILETIME + ONE_SEC,
                1200,
            ),
        ];
        let index = check_usn_stream(&records, None);
        assert!(!index
            .for_node(0)
            .iter()
            .any(|a| a.rule_id == "HEUR-USN-003"));
    }

    // --- HEUR-USN-004 ---

    #[test]
    fn usn_004_detects_ghost_file() {
        let tree = make_tree();
        // FRN 999 does not exist in tree — ghost file.
        let records = vec![make_usn_record(
            "deleted.exe",
            999,
            10,
            UsnReasonFlags::FILE_DELETE,
            BASE_FILETIME,
            1000,
        )];
        let index = check_usn_stream(&records, Some(&tree));
        // Should be attached to parent (FRN 10 -> Users dir).
        let parent_idx = *tree.entry_to_idx(10).unwrap();
        assert!(index
            .for_node(parent_idx)
            .iter()
            .any(|a| a.rule_id == "HEUR-USN-004"));
    }

    #[test]
    fn usn_004_does_not_trigger_for_existing_entries() {
        let tree = make_tree();
        let records = vec![make_usn_record(
            "report.docx",
            100,
            10,
            UsnReasonFlags::FILE_CREATE,
            BASE_FILETIME,
            1000,
        )];
        let index = check_usn_stream(&records, Some(&tree));
        let has_004 = (0..3).any(|idx| {
            index
                .for_node(idx)
                .iter()
                .any(|a| a.rule_id == "HEUR-USN-004")
        });
        assert!(!has_004);
    }

    #[test]
    fn usn_004_skipped_when_no_tree() {
        let records = vec![make_usn_record(
            "deleted.exe",
            999,
            10,
            UsnReasonFlags::FILE_DELETE,
            BASE_FILETIME,
            1000,
        )];
        let index = check_usn_stream(&records, None);
        assert_eq!(index.flagged_count(), 0);
    }

    // --- FRN masking (sequence number in upper 16 bits) ---

    #[test]
    fn resolve_idx_masks_frn_to_48_bits() {
        let tree = make_tree();
        // FRN 100 exists in tree. Add sequence number in upper bits.
        let frn_with_seq = 0x0003_0000_0000_0064; // entry 100, seq 3
        let records = vec![make_usn_record(
            "report.docx",
            frn_with_seq,
            10,
            UsnReasonFlags::FILE_CREATE,
            BASE_FILETIME,
            1000,
        )];
        let index = check_usn_stream(&records, Some(&tree));
        // Should NOT be flagged as ghost — entry 100 exists in tree.
        let has_004 = (0..3).any(|idx| {
            index
                .for_node(idx)
                .iter()
                .any(|a| a.rule_id == "HEUR-USN-004")
        });
        assert!(
            !has_004,
            "existing entry with sequence bits should not be a ghost"
        );
    }

    #[test]
    fn usn_004_ghost_with_sequence_bits() {
        let tree = make_tree();
        // FRN 999 does NOT exist in tree, even after masking.
        let frn_with_seq = 0x0005_0000_0000_03E7; // entry 999, seq 5
        let parent_with_seq = 0x0002_0000_0000_000A; // entry 10, seq 2
        let records = vec![make_usn_record(
            "deleted.exe",
            frn_with_seq,
            parent_with_seq,
            UsnReasonFlags::FILE_DELETE,
            BASE_FILETIME,
            1000,
        )];
        let index = check_usn_stream(&records, Some(&tree));
        // Parent entry 10 (Users dir) exists — ghost should attach there.
        let parent_idx = *tree.entry_to_idx(10).unwrap();
        assert!(
            index
                .for_node(parent_idx)
                .iter()
                .any(|a| a.rule_id == "HEUR-USN-004"),
            "ghost with sequence bits should resolve parent via masked FRN"
        );
    }
}
