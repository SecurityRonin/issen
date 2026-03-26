//! Content-aware heuristic checks (Tier 2, conditional on file access).

use rt_mft_tree::tree::FileTree;

use super::anomaly::{Anomaly, AnomalyCategory, AnomalyIndex};
use super::file_reader::FileReader;
use super::magic_table::{extension_known, identify_format};
use crate::matching::results::Severity;

/// Maximum bytes to read per file for content checks.
const MAX_READ_BYTES: usize = 4096;

/// Run Tier 2 checks on specific entries. Results are merged into `index`.
pub fn run_tier2(
    tree: &FileTree,
    entries: &[usize],
    reader: &dyn FileReader,
    index: &mut AnomalyIndex,
) {
    if !reader.is_available() {
        return;
    }
    for &idx in entries {
        let node = tree.node(idx);
        if node.is_dir || node.size == 0 {
            continue;
        }
        let Some(data) = reader.read_first_bytes(idx, MAX_READ_BYTES) else {
            continue;
        };

        check_mg_001(idx, node, &data, index);
        check_mg_002(idx, node, &data, index);
        check_en_001(idx, node, &data, index);
        check_en_002(idx, node, &data, index);
    }
}

/// Shannon entropy of a byte buffer (0.0 = uniform, 8.0 = random).
#[allow(clippy::cast_precision_loss)]
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn file_extension(name: &str) -> Option<String> {
    let dot_pos = name.rfind('.')?;
    if dot_pos == 0 {
        return None; // ".hidden" has no extension
    }
    Some(name[dot_pos + 1..].to_lowercase())
}

fn check_mg_001(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    data: &[u8],
    index: &mut AnomalyIndex,
) {
    let Some(ext) = file_extension(&node.name) else {
        return;
    };
    if !extension_known(&ext) {
        return;
    }
    let Some(detected) = identify_format(data) else {
        return; // Unknown format — can't confirm mismatch
    };
    // Check if the file's extension matches the detected format
    if !detected.extensions.iter().any(|&e| e == ext) {
        index.add(
            idx,
            Anomaly {
                severity: Severity::Medium,
                category: AnomalyCategory::ExtensionMismatch,
                rule_id: "HEUR-MG-001",
                description: format!(
                    "Magic bytes indicate {} but extension is .{}",
                    detected.description, ext
                ),
                evidence: format!("detected={}, extension={}", detected.description, ext),
            },
        );
    }
}

const DOCUMENT_EXTS: &[&str] = &[
    "docx", "doc", "xlsx", "xls", "pptx", "ppt", "pdf", "txt", "csv", "rtf", "odt", "ods", "jpg",
    "jpeg", "png", "gif", "bmp", "mp3", "mp4", "wav", "avi",
];

fn check_mg_002(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    data: &[u8],
    index: &mut AnomalyIndex,
) {
    let Some(ext) = file_extension(&node.name) else {
        return;
    };
    if !DOCUMENT_EXTS.iter().any(|&e| e == ext) {
        return; // Only check document/media extensions
    }
    let is_executable = data.starts_with(b"MZ") || data.starts_with(b"\x7FELF");
    if is_executable {
        index.add(
            idx,
            Anomaly {
                severity: Severity::High,
                category: AnomalyCategory::ExtensionMismatch,
                rule_id: "HEUR-MG-002",
                description: format!("Executable disguised as .{ext}"),
                evidence: format!(
                    "header={}, extension={}",
                    if data.starts_with(b"MZ") {
                        "PE/MZ"
                    } else {
                        "ELF"
                    },
                    ext
                ),
            },
        );
    }
}

const LOW_ENTROPY_EXTS: &[&str] = &[
    "txt", "csv", "log", "ini", "xml", "html", "json", "cfg", "conf",
];

fn check_en_001(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    data: &[u8],
    index: &mut AnomalyIndex,
) {
    let Some(ext) = file_extension(&node.name) else {
        return;
    };
    if !LOW_ENTROPY_EXTS.iter().any(|&e| e == ext) {
        return;
    }
    let entropy = shannon_entropy(data);
    if entropy > 7.5 {
        index.add(
            idx,
            Anomaly {
                severity: Severity::Medium,
                category: AnomalyCategory::HighEntropy,
                rule_id: "HEUR-EN-001",
                description: format!("High entropy ({entropy:.2}) in .{ext} file"),
                evidence: format!("entropy={entropy:.4}, extension={ext}"),
            },
        );
    }
}

const LUKS_MAGIC: &[u8] = b"LUKS\xBA\xBE";

fn check_en_002(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    data: &[u8],
    index: &mut AnomalyIndex,
) {
    // Check for known crypto container signatures
    if data.len() >= 6 && data[..6] == *LUKS_MAGIC {
        index.add(
            idx,
            Anomaly {
                severity: Severity::High,
                category: AnomalyCategory::HighEntropy,
                rule_id: "HEUR-EN-002",
                description: "LUKS encrypted container detected".to_string(),
                evidence: format!("name={}, magic=LUKS", node.name),
            },
        );
        return;
    }

    // Heuristic: file with size multiple of 512, high entropy, no recognized header
    if node.size >= 1024 && node.size % 512 == 0 && identify_format(data).is_none() {
        let entropy = shannon_entropy(data);
        if entropy > 7.9 {
            index.add(
                idx,
                Anomaly {
                    severity: Severity::High,
                    category: AnomalyCategory::HighEntropy,
                    rule_id: "HEUR-EN-002",
                    description:
                        "Possible encrypted container (512-byte aligned, high entropy, no header)"
                            .to_string(),
                    evidence: format!(
                        "name={}, size={}, entropy={entropy:.4}",
                        node.name, node.size
                    ),
                },
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::file_reader::MockFileReader;
    use super::*;
    use chrono::{TimeZone, Utc};
    use rt_mft_tree::node::{FileNode, NtfsTimestamps};
    use rt_mft_tree::tree::FileTree;
    use std::collections::HashMap;

    fn ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()
    }

    fn default_ts() -> NtfsTimestamps {
        NtfsTimestamps {
            modified: ts(),
            accessed: ts(),
            created: ts(),
            entry_modified: ts(),
        }
    }

    fn make_file(name: &str, entry: u64, size: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry: entry,
            parent_entry: 5,
            is_dir: false,
            size,
            si_timestamps: default_ts(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        }
    }

    fn build_tree_and_reader(files: Vec<(FileNode, Vec<u8>)>) -> (FileTree, MockFileReader) {
        let mut nodes = vec![FileNode {
            name: ".".to_string(),
            mft_entry: 5,
            parent_entry: 5,
            is_dir: true,
            size: 0,
            si_timestamps: default_ts(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        }];
        let mut data_map = HashMap::new();
        for (i, (node, data)) in files.into_iter().enumerate() {
            nodes.push(node);
            data_map.insert(i + 1, data); // idx 0 is root, files start at 1
        }
        (FileTree::from_nodes(nodes), MockFileReader(data_map))
    }

    // --- HEUR-MG-001 ---

    #[test]
    fn mg_001_jpg_with_pe_header() {
        let (tree, reader) = build_tree_and_reader(vec![(
            make_file("photo.jpg", 100, 5000),
            b"MZ\x90\x00\x03\x00\x00\x00rest".to_vec(),
        )]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-MG-001"));
    }

    #[test]
    fn mg_001_no_flag_matching_extension() {
        let (tree, reader) = build_tree_and_reader(vec![(
            make_file("photo.jpg", 100, 5000),
            b"\xFF\xD8\xFF\xE0real jpeg".to_vec(),
        )]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(!index.for_node(1).iter().any(|a| a.rule_id == "HEUR-MG-001"));
    }

    // --- HEUR-MG-002 ---

    #[test]
    fn mg_002_exe_disguised_as_pdf() {
        let (tree, reader) = build_tree_and_reader(vec![(
            make_file("invoice.pdf", 100, 5000),
            b"MZ\x90\x00pe data".to_vec(),
        )]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-MG-002"));
    }

    #[test]
    fn mg_002_no_flag_real_pdf() {
        let (tree, reader) = build_tree_and_reader(vec![(
            make_file("invoice.pdf", 100, 5000),
            b"%PDF-1.4 real pdf".to_vec(),
        )]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(!index.for_node(1).iter().any(|a| a.rule_id == "HEUR-MG-002"));
    }

    // --- HEUR-EN-001 ---

    #[test]
    fn en_001_high_entropy_txt() {
        // Generate high-entropy data (all 256 byte values equally distributed)
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let (tree, reader) =
            build_tree_and_reader(vec![(make_file("secret.txt", 100, 4096), data)]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-001"));
    }

    #[test]
    fn en_001_no_flag_normal_txt() {
        let data = b"Hello world, this is normal text content.\n".to_vec();
        let (tree, reader) = build_tree_and_reader(vec![(
            make_file("readme.txt", 100, data.len() as u64),
            data.clone(),
        )]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(!index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-001"));
    }

    #[test]
    fn en_001_no_flag_high_entropy_zip() {
        // High entropy is expected for zip files
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let (tree, reader) =
            build_tree_and_reader(vec![(make_file("archive.zip", 100, 4096), data)]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(!index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-001"));
    }

    // --- HEUR-EN-002 ---

    #[test]
    fn en_002_luks_header() {
        let mut data = b"LUKS\xBA\xBE\x00\x01".to_vec();
        data.resize(512, 0);
        let (tree, reader) =
            build_tree_and_reader(vec![(make_file("container.img", 100, 1048576), data)]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-002"));
    }

    #[test]
    fn en_002_512_aligned_high_entropy_no_header() {
        // Random-like data, 512-byte aligned, no recognized header
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("suspicious.dat", 100, 1048576), data), // 1MB, 512-aligned
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-002"));
    }

    // --- Shannon entropy ---

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_uniform_is_zero() {
        assert!(shannon_entropy(&[42; 1000]) < 0.01);
    }

    #[test]
    fn entropy_random_is_high() {
        let mut data = Vec::new();
        for _ in 0..16 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        assert!(shannon_entropy(&data) > 7.9);
    }

    // --- file_extension ---

    #[test]
    fn file_extension_normal() {
        assert_eq!(file_extension("report.docx"), Some("docx".to_string()));
        assert_eq!(file_extension("PHOTO.JPG"), Some("jpg".to_string()));
    }

    #[test]
    fn file_extension_no_dot() {
        assert_eq!(file_extension("Makefile"), None);
        assert_eq!(file_extension("README"), None);
    }

    #[test]
    fn file_extension_hidden_file() {
        assert_eq!(file_extension(".gitignore"), None);
    }

    #[test]
    fn file_extension_double_ext() {
        assert_eq!(file_extension("archive.tar.gz"), Some("gz".to_string()));
    }

    // --- Tier 2 gate ---

    #[test]
    fn tier2_skipped_when_reader_unavailable() {
        let nodes = vec![FileNode {
            name: ".".to_string(),
            mft_entry: 5,
            parent_entry: 5,
            is_dir: true,
            size: 0,
            si_timestamps: default_ts(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        }];
        let tree = FileTree::from_nodes(nodes);
        let reader = super::super::file_reader::NoFileReader;
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[0], &reader, &mut index);
        assert_eq!(index.flagged_count(), 0);
    }
}
