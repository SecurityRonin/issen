//! Per-entry heuristic checks (Tier 1, streaming-compatible).

use issen_mft_tree::node::FileNode;

use super::anomaly::{Anomaly, AnomalyCategory, HeuristicsConfig};
use crate::matching::results::Severity;

/// Run all entry-level heuristic checks on a single node.
#[must_use]
pub fn check_entry(node: &FileNode, config: &HeuristicsConfig) -> Vec<Anomaly> {
    let mut results = Vec::new();
    check_ts_001(node, &mut results);
    check_ts_002(node, &mut results);
    check_ts_003(node, &mut results);
    check_ts_004(node, config, &mut results);
    check_sz_001(node, &mut results);
    check_at_001(node, &mut results);
    check_mg_003(node, &mut results);
    results
}

fn check_ts_001(node: &FileNode, results: &mut Vec<Anomaly>) {
    // SI created > SI modified
    if node.si_timestamps.created > node.si_timestamps.modified {
        results.push(Anomaly {
            severity: Severity::High,
            category: AnomalyCategory::Timestomping,
            rule_id: "HEUR-TS-001",
            description: "$SI created timestamp is after modified timestamp".to_string(),
            evidence: format!(
                "created={}, modified={}",
                node.si_timestamps.created, node.si_timestamps.modified
            ),
        });
    }
}

fn check_ts_002(node: &FileNode, results: &mut Vec<Anomaly>) {
    // SI/FN timestamp divergence > 24 hours
    let Some(fn_ts) = &node.fn_timestamps else {
        return;
    };
    let diff = (node.si_timestamps.created - fn_ts.created)
        .num_hours()
        .abs();
    if diff > 24 {
        results.push(Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::Timestomping,
            rule_id: "HEUR-TS-002",
            description: "$SI/$FN created timestamps diverge by more than 24 hours".to_string(),
            evidence: format!(
                "si.created={}, fn.created={}, diff={diff}h",
                node.si_timestamps.created, fn_ts.created
            ),
        });
    }
}

fn check_ts_003(node: &FileNode, results: &mut Vec<Anomaly>) {
    // Zeroed subseconds in SI while FN has subseconds
    let Some(fn_ts) = &node.fn_timestamps else {
        return;
    };
    let si_zeroed = node.si_timestamps.created.timestamp_subsec_nanos() == 0
        && node.si_timestamps.modified.timestamp_subsec_nanos() == 0;
    let fn_has_subsec =
        fn_ts.created.timestamp_subsec_nanos() != 0 || fn_ts.modified.timestamp_subsec_nanos() != 0;
    if si_zeroed && fn_has_subsec {
        results.push(Anomaly {
            severity: Severity::Low,
            category: AnomalyCategory::Timestomping,
            rule_id: "HEUR-TS-003",
            description: "$SI timestamps have zeroed subseconds while $FN retains precision"
                .to_string(),
            evidence: format!(
                "si.created_nanos=0, fn.created_nanos={}",
                fn_ts.created.timestamp_subsec_nanos()
            ),
        });
    }
}

fn check_ts_004(node: &FileNode, config: &HeuristicsConfig, results: &mut Vec<Anomaly>) {
    let Some(vol_created) = config.volume_created else {
        return;
    };
    if node.si_timestamps.created < vol_created {
        results.push(Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::Timestomping,
            rule_id: "HEUR-TS-004",
            description: "$SI created predates volume creation".to_string(),
            evidence: format!(
                "si.created={}, volume_created={}",
                node.si_timestamps.created, vol_created
            ),
        });
    }
}

fn check_sz_001(node: &FileNode, results: &mut Vec<Anomaly>) {
    if node.is_dir {
        return;
    }
    let name_lower = node.name.to_lowercase();
    let ext = std::path::Path::new(&name_lower)
        .extension()
        .and_then(|e| e.to_str());
    let suspicious = match ext {
        Some("txt" | "log" | "csv") => node.size > 10 * 1024 * 1024, // > 10MB
        Some("exe" | "dll") => node.size == 0,
        Some("jpg" | "png") => node.size < 100 && node.size > 0,
        _ => false,
    };
    if suspicious {
        results.push(Anomaly {
            severity: Severity::Low,
            category: AnomalyCategory::SuspiciousSize,
            rule_id: "HEUR-SZ-001",
            description: "File size is suspicious for its extension".to_string(),
            evidence: format!("name={}, size={}", node.name, node.size),
        });
    }
}

/// NTFS attribute flag constants.
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;

/// NTFS metafiles and well-known Windows system files that legitimately
/// carry Hidden+System attributes.
///
/// Matched **case-insensitively** because NTFS is a case-insensitive
/// filesystem — you cannot create `$mft` alongside `$MFT` in the same
/// directory.  If we add support for case-sensitive filesystems (ext4,
/// APFS) in the future, this must become filesystem-aware.
///
/// All entries are already 8.3-compliant, so short-name aliases are
/// identical to long names — no truncated `~1` variants to worry about.
/// The MFT parser's `find_best_name_attribute()` also prefers Win32
/// long names over DOS short names.
const KNOWN_HS_FILES: &[&str] = &[
    // NTFS metafiles (always H+S in volume root, special inodes)
    "$mft",
    "$mftmirr",
    "$logfile",
    "$volume",
    "$attrdef",
    "$bitmap",
    "$boot",
    "$badclus",
    "$secure",
    "$upcase",
    "$extend",
    // Windows boot / power-management files (all 8.3-compliant)
    "hiberfil.sys",
    "pagefile.sys",
    "swapfile.sys",
    "bootmgr",
    "bootnxt",
    "bootsect.bak",
    "ntldr",
    "ntdetect.com",
    "io.sys",
    "msdos.sys",
];

fn is_known_hs_file(name: &str) -> bool {
    let lower = name.to_lowercase();
    KNOWN_HS_FILES.iter().any(|&known| lower == known)
}

fn check_at_001(node: &FileNode, results: &mut Vec<Anomaly>) {
    if node.is_dir {
        return;
    }
    let both = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    if node.file_attributes & both != both {
        return;
    }
    if is_known_hs_file(&node.name) {
        return;
    }
    results.push(Anomaly {
        severity: Severity::Low,
        category: AnomalyCategory::SuspiciousLocation,
        rule_id: "HEUR-AT-001",
        description: "Hidden and system attributes set on non-system file".to_string(),
        evidence: format!(
            "name={}, attributes=0x{:X}",
            node.name, node.file_attributes
        ),
    });
}

fn check_mg_003(node: &FileNode, results: &mut Vec<Anomaly>) {
    if node.is_dir {
        return;
    }
    let executable_exts = [
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".com", ".pif",
    ];
    let name_lower = node.name.to_lowercase();
    // Find the last extension
    let Some(last_dot) = name_lower.rfind('.') else {
        return;
    };
    let last_ext = &name_lower[last_dot..];
    if !executable_exts.contains(&last_ext) {
        return;
    }
    // Check if there's a second extension before the last one
    let before_last = &name_lower[..last_dot];
    if before_last.contains('.') {
        results.push(Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::ExtensionMismatch,
            rule_id: "HEUR-MG-003",
            description: "Double extension with executable suffix".to_string(),
            evidence: format!("name={}", node.name),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike, Utc};
    use issen_mft_tree::node::NtfsTimestamps;

    fn ts(year: i32, month: u32, day: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    fn ts_with_nanos(year: i32, month: u32, day: u32, nanos: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 12, 0, 0)
            .unwrap()
            .with_nanosecond(nanos)
            .unwrap()
    }

    fn default_ts() -> NtfsTimestamps {
        NtfsTimestamps {
            modified: ts(2024, 1, 1),
            accessed: ts(2024, 1, 1),
            created: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        }
    }

    fn default_node() -> FileNode {
        FileNode {
            name: "file.txt".to_string(),
            mft_entry: 100,
            parent_entry: 5,
            is_dir: false,
            size: 1024,
            si_timestamps: default_ts(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: false,
            ads_names: vec![],
            owner_id: 0,
            security_id: 0,
            usn: 0,
        }
    }

    fn default_config() -> HeuristicsConfig {
        HeuristicsConfig::default()
    }

    // --- HEUR-TS-001 ---

    #[test]
    fn ts_001_triggers_when_created_after_modified() {
        let node = FileNode {
            si_timestamps: NtfsTimestamps {
                created: ts(2024, 6, 1),
                modified: ts(2024, 1, 1),
                ..default_ts()
            },
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-TS-001"));
    }

    #[test]
    fn ts_001_does_not_trigger_normal_timestamps() {
        let node = FileNode {
            si_timestamps: NtfsTimestamps {
                created: ts(2024, 1, 1),
                modified: ts(2024, 6, 1),
                ..default_ts()
            },
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-001"));
    }

    // --- HEUR-TS-002 ---

    #[test]
    fn ts_002_triggers_on_large_si_fn_divergence() {
        let node = FileNode {
            si_timestamps: NtfsTimestamps {
                created: ts(2024, 6, 1),
                ..default_ts()
            },
            fn_timestamps: Some(NtfsTimestamps {
                created: ts(2023, 1, 1),
                ..default_ts()
            }),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-TS-002"));
    }

    #[test]
    fn ts_002_skipped_when_no_fn_timestamps() {
        let node = FileNode {
            fn_timestamps: None,
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-002"));
    }

    #[test]
    fn ts_002_does_not_trigger_within_24h() {
        let si = NtfsTimestamps {
            created: ts(2024, 1, 2),
            ..default_ts()
        };
        let node = FileNode {
            si_timestamps: si,
            fn_timestamps: Some(NtfsTimestamps {
                created: ts(2024, 1, 1),
                ..default_ts()
            }),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-002"));
    }

    // --- HEUR-TS-003 ---

    #[test]
    fn ts_003_triggers_zeroed_subseconds() {
        let si = NtfsTimestamps {
            created: ts(2024, 1, 1), // zero nanos (whole second)
            modified: ts(2024, 1, 1),
            accessed: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        };
        let fn_ts = NtfsTimestamps {
            created: ts_with_nanos(2024, 1, 1, 123_456_789),
            modified: ts_with_nanos(2024, 1, 1, 987_654_321),
            accessed: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        };
        let node = FileNode {
            si_timestamps: si,
            fn_timestamps: Some(fn_ts),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-TS-003"));
    }

    #[test]
    fn ts_003_does_not_trigger_when_both_have_subseconds() {
        let si = NtfsTimestamps {
            created: ts_with_nanos(2024, 1, 1, 111_111_111),
            modified: ts_with_nanos(2024, 1, 1, 222_222_222),
            accessed: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        };
        let fn_ts = NtfsTimestamps {
            created: ts_with_nanos(2024, 1, 1, 123_456_789),
            modified: ts_with_nanos(2024, 1, 1, 987_654_321),
            accessed: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        };
        let node = FileNode {
            si_timestamps: si,
            fn_timestamps: Some(fn_ts),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-003"));
    }

    // --- HEUR-TS-004 ---

    #[test]
    fn ts_004_triggers_when_si_predates_volume() {
        let config = HeuristicsConfig {
            volume_created: Some(ts(2023, 1, 1)),
        };
        let node = FileNode {
            si_timestamps: NtfsTimestamps {
                created: ts(2020, 1, 1),
                ..default_ts()
            },
            ..default_node()
        };
        let anomalies = check_entry(&node, &config);
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-TS-004"));
    }

    #[test]
    fn ts_004_skipped_when_no_volume_date() {
        let anomalies = check_entry(&default_node(), &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-004"));
    }

    // --- HEUR-SZ-001 ---

    #[test]
    fn sz_001_triggers_large_txt() {
        let node = FileNode {
            name: "data.txt".to_string(),
            size: 20 * 1024 * 1024,
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-SZ-001"));
    }

    #[test]
    fn sz_001_triggers_zero_byte_exe() {
        let node = FileNode {
            name: "empty.exe".to_string(),
            size: 0,
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-SZ-001"));
    }

    #[test]
    fn sz_001_does_not_trigger_normal_txt() {
        let node = FileNode {
            name: "readme.txt".to_string(),
            size: 4096,
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-SZ-001"));
    }

    // --- HEUR-AT-001 ---

    #[test]
    fn at_001_triggers_hidden_system() {
        let node = FileNode {
            name: "secret.dat".to_string(),
            file_attributes: 0x6, // hidden + system
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"));
    }

    #[test]
    fn at_001_does_not_trigger_hidden_only() {
        let node = FileNode {
            file_attributes: 0x2, // hidden only
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"));
    }

    #[test]
    fn at_001_does_not_trigger_on_directories() {
        let node = FileNode {
            is_dir: true,
            file_attributes: 0x6, // hidden + system
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"));
    }

    // --- HEUR-MG-003 ---

    #[test]
    fn mg_003_triggers_double_extension() {
        let node = FileNode {
            name: "report.pdf.exe".to_string(),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-MG-003"));
    }

    #[test]
    fn mg_003_triggers_jpg_scr() {
        let node = FileNode {
            name: "image.jpg.scr".to_string(),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-MG-003"));
    }

    #[test]
    fn mg_003_does_not_trigger_single_extension() {
        let node = FileNode {
            name: "program.exe".to_string(),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-MG-003"));
    }

    #[test]
    fn mg_003_does_not_trigger_non_executable_double() {
        let node = FileNode {
            name: "archive.tar.gz".to_string(),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-MG-003"));
    }

    #[test]
    fn at_001_does_not_trigger_on_ntfs_metafiles() {
        for name in [
            "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", "$Bitmap", "$Boot", "$BadClus",
            "$Secure", "$UpCase", "$Extend",
        ] {
            let node = FileNode {
                name: name.to_string(),
                file_attributes: 0x6,
                ..default_node()
            };
            let anomalies = check_entry(&node, &default_config());
            assert!(
                !anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"),
                "HEUR-AT-001 should not fire on NTFS metafile {name}"
            );
        }
    }

    #[test]
    fn at_001_does_not_trigger_on_known_system_files() {
        for name in [
            "hiberfil.sys",
            "pagefile.sys",
            "swapfile.sys",
            "bootmgr",
            "BOOTNXT",
            "BOOTSECT.BAK",
            "ntldr",
            "NTDETECT.COM",
            "IO.SYS",
            "MSDOS.SYS",
        ] {
            let node = FileNode {
                name: name.to_string(),
                file_attributes: 0x6,
                ..default_node()
            };
            let anomalies = check_entry(&node, &default_config());
            assert!(
                !anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"),
                "HEUR-AT-001 should not fire on known system file {name}"
            );
        }
    }

    #[test]
    fn at_001_case_insensitive_for_ntfs() {
        // NTFS is case-insensitive — you cannot create `$mft` alongside `$MFT`.
        // All casing variants of known system files must be whitelisted.
        for name in [
            "$Mft",
            "$MFT",
            "$mft",
            "HIBERFIL.SYS",
            "PageFile.Sys",
            "BOOTMGR",
        ] {
            let node = FileNode {
                name: name.to_string(),
                file_attributes: 0x6,
                ..default_node()
            };
            let anomalies = check_entry(&node, &default_config());
            assert!(
                !anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"),
                "HEUR-AT-001 should not fire on NTFS casing variant {name}"
            );
        }
    }

    #[test]
    fn at_001_still_triggers_on_unknown_hidden_system_file() {
        let node = FileNode {
            name: "secret.dat".to_string(),
            file_attributes: 0x6,
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"));
    }

    // --- Combined false-positive test ---

    #[test]
    fn normal_file_triggers_nothing() {
        let anomalies = check_entry(&default_node(), &default_config());
        assert!(anomalies.is_empty());
    }
}
