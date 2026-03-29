//! Rootkit indicator detection from UAC collection artifacts.
//!
//! Implements static-artifact versions of checks inspired by chkrootkit:
//! - `ld.so.preload` library injection (chkLD_PRELOAD)
//! - Kernel module analysis for known rootkit modules (chk_lkm)
//! - Kernel taint flag analysis (out-of-tree/unsigned modules)
//! - Environment variable checks for LD_PRELOAD / LD_LIBRARY_PATH

use serde::Serialize;

/// Severity of a rootkit finding.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum RootkitSeverity {
    /// Strong rootkit indicator (e.g. known rootkit module loaded).
    Critical,
    /// Suspicious but could be legitimate (e.g. unknown library in ld.so.preload).
    Warning,
    /// Informational (e.g. kernel tainted by out-of-tree module).
    Info,
}

/// A single rootkit indicator finding.
#[derive(Debug, Clone, Serialize)]
pub struct RootkitFinding {
    pub severity: RootkitSeverity,
    /// Short category tag (e.g. "ld_preload", "kernel_module", "taint").
    pub check: String,
    /// Human-readable description of the finding.
    pub description: String,
    /// The suspicious artifact value (path, module name, etc.).
    pub evidence: String,
}

/// Known rootkit kernel module names.
///
/// Sources: chkrootkit, Volatility, MITRE ATT&CK T1014.
const KNOWN_ROOTKIT_MODULES: &[&str] = &[
    "diamorphine",
    "reptile",
    "reptile_module",
    "suterusu",
    "bdvl",
    "knark",
    "adore",
    "adore-ng",
    "azazel",
    "jynx",
    "jynx2",
    "brootus",
    "beurk",
    "madvise",
    "hiding",
    "rootkit",
    "rt_rootkit",
    "kovid",
    "khook",
    "toor",
];

/// Known rootkit shared library substrings in ld.so.preload paths.
///
/// If any of these appear in a library path, elevate to Critical.
/// Sources: chkrootkit chk_ldsopreload, known rootkit IOCs.
const KNOWN_ROOTKIT_LIBS: &[&str] = &["jynx", "azazel", "bdvl", "libshow.so", "libproc.a"];

/// Parse `/etc/ld.so.preload` content for suspicious library injection.
///
/// Any non-empty, non-comment line in this file causes the dynamic linker
/// to load the specified library into every process — a classic userspace
/// rootkit technique (Jynx, Azazel, bdvl).
///
/// Returns a finding for each library path found.
#[must_use]
pub fn parse_ld_preload(content: &str) -> Vec<RootkitFinding> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let lower = trimmed.to_lowercase();
            let severity = if KNOWN_ROOTKIT_LIBS.iter().any(|k| lower.contains(k)) {
                RootkitSeverity::Critical
            } else {
                RootkitSeverity::Warning
            };
            Some(RootkitFinding {
                severity,
                check: "ld_preload".to_string(),
                description: "Library found in ld.so.preload — loaded into every process"
                    .to_string(),
                evidence: trimmed.to_string(),
            })
        })
        .collect()
}

/// Check environment variables for LD_PRELOAD or LD_LIBRARY_PATH.
///
/// Parses `env` command output (KEY=value lines). LD_PRELOAD in the
/// environment of the collection user (usually root) is highly suspicious.
/// LD_LIBRARY_PATH can indicate library path manipulation.
#[must_use]
pub fn check_env_injection(content: &str) -> Vec<RootkitFinding> {
    let mut findings = Vec::new();
    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "LD_PRELOAD" => findings.push(RootkitFinding {
                    severity: RootkitSeverity::Critical,
                    check: "env_injection".to_string(),
                    description: "LD_PRELOAD set in environment — forces library loading"
                        .to_string(),
                    evidence: value.to_string(),
                }),
                "LD_LIBRARY_PATH" => findings.push(RootkitFinding {
                    severity: RootkitSeverity::Warning,
                    check: "env_injection".to_string(),
                    description: "LD_LIBRARY_PATH set — library search path manipulation"
                        .to_string(),
                    evidence: value.to_string(),
                }),
                _ => {}
            }
        }
    }
    findings
}

/// Analyze `lsmod` output for known rootkit kernel modules.
///
/// Compares loaded module names against a list of known rootkit modules
/// from chkrootkit, Volatility, and MITRE ATT&CK T1014.
#[must_use]
pub fn check_kernel_modules(content: &str) -> Vec<RootkitFinding> {
    content
        .lines()
        .filter_map(|line| {
            let module_name = line.split_whitespace().next()?;
            let lower = module_name.to_lowercase();
            if KNOWN_ROOTKIT_MODULES.contains(&lower.as_str()) {
                Some(RootkitFinding {
                    severity: RootkitSeverity::Critical,
                    check: "kernel_module".to_string(),
                    description: format!("Known rootkit kernel module '{}' loaded", module_name),
                    evidence: module_name.to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Analyze the kernel taint flag from `/proc/sys/kernel/tainted`.
///
/// The taint flag is a bitmask:
/// - Bit 0 (1): Proprietary module loaded
/// - Bit 12 (4096): Unsigned module loaded
/// - Bit 13 (8192): Out-of-tree module without MODULE_VERSION
///
/// Non-zero taint with unsigned/out-of-tree bits set is suspicious.
#[must_use]
pub fn check_kernel_taint(content: &str) -> Vec<RootkitFinding> {
    let value: u64 = match content.trim().parse() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    if value == 0 {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Bit 0 (1): proprietary module — common (nvidia, VirtualBox host modules)
    if value & 1 != 0 {
        findings.push(RootkitFinding {
            severity: RootkitSeverity::Info,
            check: "kernel_taint".to_string(),
            description: "Proprietary kernel module loaded".to_string(),
            evidence: format!("taint={value}, bit 0 set"),
        });
    }

    // Bit 2 (4): out-of-tree module — common (VirtualBox Guest Additions, DKMS)
    if value & 4 != 0 {
        findings.push(RootkitFinding {
            severity: RootkitSeverity::Info,
            check: "kernel_taint".to_string(),
            description: "Out-of-tree kernel module loaded".to_string(),
            evidence: format!("taint={value}, bit 2 set"),
        });
    }

    // Bit 12 (4096): unsigned module — suspicious, could indicate rootkit LKM
    if value & 4096 != 0 {
        findings.push(RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "kernel_taint".to_string(),
            description: "Unsigned kernel module loaded — possible rootkit LKM".to_string(),
            evidence: format!("taint={value}, bit 12 set"),
        });
    }

    // Bit 13 (8192): out-of-tree module without MODULE_VERSION
    if value & 8192 != 0 {
        findings.push(RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "kernel_taint".to_string(),
            description: "Out-of-tree module without MODULE_VERSION loaded".to_string(),
            evidence: format!("taint={value}, bit 13 set"),
        });
    }

    findings
}

/// Scan all rootkit-relevant artifacts from a UAC collection root.
///
/// Checks: chkrootkit/etc_ld_so_preload.txt, live_response/system/lsmod.txt,
/// live_response/system/cat_proc_sys_kernel_tainted.txt, live_response/system/env.txt.
#[must_use]
pub fn scan_rootkit_indicators(root: &std::path::Path) -> Vec<RootkitFinding> {
    let mut findings = Vec::new();

    // ld.so.preload — chkrootkit stores this as chkrootkit/etc_ld_so_preload.txt
    let ld_preload_path = root.join("chkrootkit/etc_ld_so_preload.txt");
    if let Ok(content) = std::fs::read_to_string(&ld_preload_path) {
        findings.extend(parse_ld_preload(&content));
    }

    // lsmod output
    let lsmod_path = root.join("live_response/system/lsmod.txt");
    if let Ok(content) = std::fs::read_to_string(&lsmod_path) {
        findings.extend(check_kernel_modules(&content));
    }

    // Kernel taint flag
    let taint_path = root.join("live_response/system/cat_proc_sys_kernel_tainted.txt");
    if let Ok(content) = std::fs::read_to_string(&taint_path) {
        findings.extend(check_kernel_taint(&content));
    }

    // Environment variables
    let env_path = root.join("live_response/system/env.txt");
    if let Ok(content) = std::fs::read_to_string(&env_path) {
        findings.extend(check_env_injection(&content));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // parse_ld_preload — contract:
    //   Input: content of /etc/ld.so.preload
    //   Output: Vec<RootkitFinding> — one per library path found
    //   Rules:
    //     - Empty/comment-only → no findings
    //     - Each non-empty, non-comment line → Warning finding
    //     - Known rootkit libraries (jynx, azazel, bdvl) → Critical
    // =====================================================================

    #[test]
    fn ld_preload_empty() {
        assert!(parse_ld_preload("").is_empty());
        assert!(parse_ld_preload("  \n\n").is_empty());
    }

    #[test]
    fn ld_preload_comment_only() {
        let content = "# This file is managed by libfaketime\n# nothing to see here\n";
        assert!(parse_ld_preload(content).is_empty());
    }

    #[test]
    fn ld_preload_single_unknown_library() {
        let content = "/lib/x86_64-linux-gnu/libymv.so.3\n";
        let findings = parse_ld_preload(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Warning);
        assert_eq!(findings[0].check, "ld_preload");
        assert!(findings[0].evidence.contains("libymv.so.3"));
    }

    #[test]
    fn ld_preload_known_rootkit_library() {
        // jynx2 rootkit uses ld.so.preload
        let content = "/usr/local/lib/libjynx.so\n";
        let findings = parse_ld_preload(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Critical);
    }

    #[test]
    fn ld_preload_azazel_rootkit() {
        let content = "/lib/libazazel.so\n";
        let findings = parse_ld_preload(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Critical);
    }

    #[test]
    fn ld_preload_bdvl_rootkit() {
        let content = "/lib/x86_64-linux-gnu/libbdvl.so\n";
        let findings = parse_ld_preload(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Critical);
    }

    #[test]
    fn ld_preload_multiple_entries() {
        let content = "/lib/libfoo.so\n\
                        # comment\n\
                        /lib/libbar.so\n";
        let findings = parse_ld_preload(content);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn ld_preload_legitimate_libfaketime() {
        // libfaketime is commonly in ld.so.preload — still a Warning
        // because any entry here is unusual, but not Critical
        let content = "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1\n";
        let findings = parse_ld_preload(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Warning);
    }

    // =====================================================================
    // check_env_injection — contract:
    //   Input: content of `env` command output (KEY=value per line)
    //   Output: Vec<RootkitFinding>
    //   Rules:
    //     - LD_PRELOAD present → Critical
    //     - LD_LIBRARY_PATH present → Warning
    //     - Neither → no findings
    // =====================================================================

    #[test]
    fn env_no_injection() {
        let content = "HOME=/root\nPATH=/usr/bin:/bin\nSHELL=/bin/bash\n";
        assert!(check_env_injection(content).is_empty());
    }

    #[test]
    fn env_ld_preload_present() {
        let content = "HOME=/root\nLD_PRELOAD=/lib/evil.so\nSHELL=/bin/bash\n";
        let findings = check_env_injection(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Critical);
        assert_eq!(findings[0].check, "env_injection");
        assert!(findings[0].evidence.contains("/lib/evil.so"));
    }

    #[test]
    fn env_ld_library_path_present() {
        let content = "LD_LIBRARY_PATH=/opt/custom/lib\nHOME=/root\n";
        let findings = check_env_injection(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Warning);
    }

    #[test]
    fn env_both_ld_vars() {
        let content = "LD_PRELOAD=/lib/evil.so\nLD_LIBRARY_PATH=/tmp/libs\n";
        let findings = check_env_injection(content);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn env_partial_match_not_triggered() {
        // SUDO_LD_PRELOAD or MY_LD_PRELOAD shouldn't match
        let content = "SUDO_GID=1000\nPATH=/usr/bin\n";
        assert!(check_env_injection(content).is_empty());
    }

    // =====================================================================
    // check_kernel_modules — contract:
    //   Input: lsmod output (header + "module size used_by" lines)
    //   Output: Vec<RootkitFinding>
    //   Rules:
    //     - Known rootkit module name → Critical
    //     - Header line and normal modules → no findings
    //     - Empty input → no findings
    // =====================================================================

    #[test]
    fn kernel_modules_clean() {
        let content = "Module                  Size  Used by\n\
                        ext4                 1142784  1\n\
                        vboxguest              53248  0\n\
                        e1000                 180224  0\n";
        assert!(check_kernel_modules(content).is_empty());
    }

    #[test]
    fn kernel_modules_diamorphine() {
        let content = "Module                  Size  Used by\n\
                        ext4                 1142784  1\n\
                        diamorphine            16384  0\n\
                        e1000                 180224  0\n";
        let findings = check_kernel_modules(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Critical);
        assert_eq!(findings[0].check, "kernel_module");
        assert!(findings[0].evidence.contains("diamorphine"));
    }

    #[test]
    fn kernel_modules_reptile() {
        let content = "Module                  Size  Used by\n\
                        reptile_module         28672  0\n";
        let findings = check_kernel_modules(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Critical);
    }

    #[test]
    fn kernel_modules_multiple_rootkits() {
        let content = "Module                  Size  Used by\n\
                        diamorphine            16384  0\n\
                        kovid                  24576  0\n";
        let findings = check_kernel_modules(content);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn kernel_modules_empty() {
        assert!(check_kernel_modules("").is_empty());
    }

    #[test]
    fn kernel_modules_case_insensitive() {
        // Module names in lsmod are lowercase, but check case-insensitively
        let content = "Module                  Size  Used by\n\
                        Diamorphine            16384  0\n";
        let findings = check_kernel_modules(content);
        assert_eq!(findings.len(), 1);
    }

    // =====================================================================
    // check_kernel_taint — contract:
    //   Input: content of /proc/sys/kernel/tainted (single number)
    //   Output: Vec<RootkitFinding>
    //   Rules:
    //     - 0 → no findings (clean kernel)
    //     - Bit 12 set (4096) → Warning: unsigned module loaded
    //     - Bit 13 set (8192) → Warning: out-of-tree module w/o version
    //     - Bit 0 set (1) → Info: proprietary module (common, e.g. nvidia)
    //     - Non-numeric → no findings
    // =====================================================================

    #[test]
    fn kernel_taint_clean() {
        assert!(check_kernel_taint("0\n").is_empty());
    }

    #[test]
    fn kernel_taint_proprietary_only() {
        // Bit 0 = proprietary module (nvidia, etc.) — Info severity
        let findings = check_kernel_taint("1\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Info);
        assert_eq!(findings[0].check, "kernel_taint");
    }

    #[test]
    fn kernel_taint_out_of_tree() {
        // Value 4 = bit 2 (staging driver) — this is actually bit 2
        // Let me use the correct bitmask. Value 4096 = bit 12 (unsigned module)
        let findings = check_kernel_taint("4096\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Warning);
    }

    #[test]
    fn kernel_taint_multiple_bits() {
        // 4097 = bit 0 (proprietary) + bit 12 (unsigned) → two findings
        let findings = check_kernel_taint("4097\n");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn kernel_taint_vbox_common() {
        // Value 4 from the test data — this is bit 2 (out-of-tree module)
        // VirtualBox Guest Additions are out-of-tree
        let findings = check_kernel_taint("4\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Info);
    }

    #[test]
    fn kernel_taint_empty() {
        assert!(check_kernel_taint("").is_empty());
    }

    #[test]
    fn kernel_taint_non_numeric() {
        assert!(check_kernel_taint("not a number\n").is_empty());
    }

    // =====================================================================
    // scan_rootkit_indicators — integration test
    //   Input: UAC collection root path
    //   Output: all findings from all checks combined
    // =====================================================================

    #[test]
    fn scan_rootkit_indicators_with_ld_preload() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path();

        std::fs::create_dir_all(root.join("chkrootkit")).expect("mkdir");
        std::fs::write(
            root.join("chkrootkit/etc_ld_so_preload.txt"),
            "/lib/x86_64-linux-gnu/libymv.so.3\n",
        )
        .expect("write");

        let findings = scan_rootkit_indicators(root);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.check == "ld_preload"));
    }

    #[test]
    fn scan_rootkit_indicators_with_diamorphine() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path();

        std::fs::create_dir_all(root.join("live_response/system")).expect("mkdir");
        std::fs::write(
            root.join("live_response/system/lsmod.txt"),
            "Module                  Size  Used by\n\
             diamorphine            16384  0\n\
             ext4                 1142784  1\n",
        )
        .expect("write");

        let findings = scan_rootkit_indicators(root);
        assert!(findings.iter().any(|f| f.check == "kernel_module"));
    }

    #[test]
    fn scan_rootkit_indicators_clean_system() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path();

        std::fs::create_dir_all(root.join("live_response/system")).expect("mkdir");
        std::fs::write(
            root.join("live_response/system/lsmod.txt"),
            "Module                  Size  Used by\n\
             ext4                 1142784  1\n",
        )
        .expect("write");
        std::fs::write(
            root.join("live_response/system/cat_proc_sys_kernel_tainted.txt"),
            "0\n",
        )
        .expect("write");
        std::fs::write(
            root.join("live_response/system/env.txt"),
            "HOME=/root\nPATH=/usr/bin\n",
        )
        .expect("write");

        let findings = scan_rootkit_indicators(root);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_rootkit_indicators_empty_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        assert!(scan_rootkit_indicators(dir.path()).is_empty());
    }
}
