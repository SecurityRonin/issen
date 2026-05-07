//! Filesystem and bodyfile alert detection heuristics.

use issen_parser_uac::parsers::bodyfile::BodyfileEntry;

use super::types::{Alert, AlertSeverity};

/// Standard directories where SUID binaries are expected.
const SUID_SAFE_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
];

/// Check bodyfile for executables in temp dirs and unexpected SUID binaries.
pub(super) fn check_bodyfile_alerts(entries: &[BodyfileEntry], alerts: &mut Vec<Alert>) {
    let temp_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"];

    for entry in entries {
        let mode = parse_octal_mode(&entry.mode);

        // Executable in temp directory (mode & 0o111 != 0)
        if mode & 0o111 != 0 {
            for prefix in &temp_prefixes {
                if entry.path.starts_with(prefix) {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: "filesystem".into(),
                        message: format!("Executable in temp directory: {}", entry.path),
                        detail: format!("mode={} size={}", entry.mode, entry.size),
                    });
                    break;
                }
            }
        }

        // SUID outside standard paths (mode & 0o4000 != 0)
        if mode & 0o4000 != 0 {
            let in_safe_dir = SUID_SAFE_PREFIXES
                .iter()
                .any(|prefix| entry.path.starts_with(prefix));

            if !in_safe_dir {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "filesystem".into(),
                    message: format!("SUID binary outside standard path: {}", entry.path),
                    detail: format!("mode={} uid={} gid={}", entry.mode, entry.uid, entry.gid),
                });
            }
        }
    }
}

/// Parse an octal mode string (e.g. "100755") into a numeric value.
fn parse_octal_mode(mode_str: &str) -> u32 {
    u32::from_str_radix(mode_str.trim(), 8).unwrap_or(0)
}

/// Generalized file permission auditor from bodyfile mode bits.
///
/// Detects world-writable system directories, world-writable library files,
/// world-writable non-temp files in sensitive paths, and SGID binaries
/// outside standard locations.
pub(super) fn check_permission_anomalies(bodyfile: &[BodyfileEntry], alerts: &mut Vec<Alert>) {
    // Critical system directories (Linux + macOS)
    const CRITICAL_SYSTEM_DIRS: &[&str] = &[
        "/",
        "/usr",
        "/etc",
        "/opt",
        "/var",
        "/home",
        "/root",
        "/bin",
        "/sbin",
        "/lib",
        // macOS
        "/System",
        "/Library",
        "/Applications",
        "/private",
    ];

    // Expected world-writable dirs to exclude
    const EXPECTED_WORLD_WRITABLE: &[&str] = &[
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        // macOS
        "/private/tmp",
        "/private/var/tmp",
    ];

    // Sensitive paths for world-writable file checks
    const SENSITIVE_PREFIXES: &[&str] = &[
        "/etc/",
        "/usr/",
        "/lib/",
        "/opt/",
        "/System/",
        "/Library/",
        "/Windows/",
        "/Program Files/",
    ];

    // Standard SGID paths to exclude
    const STANDARD_SGID_PATHS: &[&str] = &[
        "/usr/bin/",
        "/bin/",
        "/usr/sbin/",
        "/sbin/",
        "/usr/lib/",
        "/usr/libexec/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
    ];

    fn is_in_temp_dir(path: &str) -> bool {
        let lower = path.to_lowercase();
        lower.starts_with("/tmp/")
            || lower.starts_with("/var/tmp/")
            || lower.starts_with("/dev/shm/")
            || lower.starts_with("/private/tmp/")
            || lower.starts_with("/private/var/tmp/")
            || lower.contains("/temp/")
            || lower.contains("/tmp/")
    }

    for entry in bodyfile {
        let mode = parse_octal_mode(&entry.mode);
        let is_world_writable = mode & 0o002 != 0;
        let is_directory = mode & 0o040000 != 0;

        // World-writable system directories
        if is_world_writable && is_directory {
            let path = entry.path.as_str();
            // Trim trailing slash for comparison
            let trimmed = path.trim_end_matches('/');
            let is_critical = CRITICAL_SYSTEM_DIRS.iter().any(|d| trimmed == *d);
            let is_expected = EXPECTED_WORLD_WRITABLE.iter().any(|d| trimmed == *d);

            if is_critical && !is_expected {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "permissions".into(),
                    message: format!("World-writable system directory: {}", entry.path),
                    detail: format!("mode={} uid={} gid={}", entry.mode, entry.uid, entry.gid),
                });
            }
        }

        // World-writable library files outside temp dirs
        if is_world_writable && !is_directory {
            let lower_path = entry.path.to_lowercase();
            let is_library = lower_path.ends_with(".so")
                || lower_path.ends_with(".dylib")
                || lower_path.ends_with(".dll");

            if is_library && !is_in_temp_dir(&entry.path) {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "permissions".into(),
                    message: format!("World-writable library file: {}", entry.path),
                    detail: format!("mode={} size={}", entry.mode, entry.size),
                });
            }
        }

        // World-writable non-temp files in sensitive paths
        if is_world_writable && !is_directory && !is_in_temp_dir(&entry.path) {
            let in_sensitive = SENSITIVE_PREFIXES
                .iter()
                .any(|prefix| entry.path.starts_with(prefix));
            if in_sensitive {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "permissions".into(),
                    message: format!("World-writable file in sensitive path: {}", entry.path),
                    detail: format!("mode={} uid={} gid={}", entry.mode, entry.uid, entry.gid),
                });
            }
        }

        // SGID binaries outside standard paths
        let is_sgid = mode & 0o2000 != 0;
        if is_sgid && !is_directory {
            let in_standard = STANDARD_SGID_PATHS
                .iter()
                .any(|prefix| entry.path.starts_with(prefix));
            if !in_standard {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "permissions".into(),
                    message: format!("SGID binary outside standard path: {}", entry.path),
                    detail: format!("mode={} path={}", entry.mode, entry.path),
                });
            }
        }
    }
}

/// Temporal clustering from bodyfile timestamps.
///
/// Groups file modifications by hour, identifies burst activity using
/// statistical outlier detection (mean + 3 * stddev), and flags sustained
/// modification campaigns.
pub(super) fn check_temporal_patterns(bodyfile: &[BodyfileEntry], alerts: &mut Vec<Alert>) {
    // Skip if bodyfile is too small for statistical analysis
    if bodyfile.len() < 50 {
        return;
    }

    // Collect all mtime values, group by hour
    let mut hour_counts: std::collections::HashMap<i64, Vec<&str>> =
        std::collections::HashMap::new();

    for entry in bodyfile {
        if let Some(mtime) = entry.mtime {
            let hour = mtime / 3600;
            hour_counts.entry(hour).or_default().push(&entry.path);
        }
    }

    if hour_counts.is_empty() {
        return;
    }

    // Calculate mean and standard deviation
    let counts: Vec<f64> = hour_counts.values().map(|v| v.len() as f64).collect();
    let n = counts.len() as f64;
    let mean = counts.iter().sum::<f64>() / n;

    let variance = counts.iter().map(|c| (c - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();

    let threshold = mean + 3.0 * stddev;

    // Find burst hours
    let mut burst_hours: Vec<(i64, &Vec<&str>)> = hour_counts
        .iter()
        .filter(|(_, paths)| {
            let count = paths.len() as f64;
            count > threshold && paths.len() >= 10
        })
        .map(|(hour, paths)| (*hour, paths))
        .collect();

    burst_hours.soissen_by_key(|(hour, _)| *hour);

    for (hour, paths) in &burst_hours {
        let count = paths.len();
        let utc_start = hour * 3600;
        let utc_end = utc_start + 3599;

        // Sample up to 3 paths
        let samples: Vec<&str> = paths.iter().take(3).copied().collect();

        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "temporal".into(),
            message: format!("Modification burst: {count} files modified in 1-hour window"),
            detail: format!(
                "UTC range: {} to {} | samples: {}",
                utc_start,
                utc_end,
                samples.join(", ")
            ),
        });
    }

    // Sustained modification activity
    if burst_hours.len() >= 3 {
        alerts.push(Alert {
            severity: AlertSeverity::Critical,
            category: "temporal".into(),
            message: format!(
                "Sustained modification activity across {} hours",
                burst_hours.len()
            ),
            detail: format!(
                "burst hours detected: {} (threshold: {:.1} files/hour, mean: {:.1}, stddev: {:.1})",
                burst_hours.len(),
                threshold,
                mean,
                stddev
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::engine::detect_alerts;
    use super::super::types::AlertInput;
    use super::super::types::AlertSeverity;
    use super::*;

    fn bf(path: &str, mode: &str) -> BodyfileEntry {
        BodyfileEntry {
            md5: String::new(),
            path: path.into(),
            inode: 0,
            mode: mode.into(),
            uid: 0,
            gid: 0,
            size: 100,
            atime: None,
            mtime: None,
            ctime: None,
            crtime: None,
        }
    }

    fn empty_input() -> AlertInput<'static> {
        AlertInput {
            bodyfile: &[],
            network: &[],
            processes: &[],
            crontabs: &[],
            chkrootkit: &[],
            rootkit_findings: &[],
            configs: &[],
            hashes: &[],
            packages: &[],
            logins: &[],
            windows_events: &[],
            mft_entries: &[],
            connection_log: &[],
        }
    }

    #[test]
    fn perm_world_writable_system_dir_critical() {
        // /etc as world-writable directory: mode 040777 (dir + rwxrwxrwx)
        let entries = vec![bf("/etc", "040777")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "permissions"
                && a.message.contains("World-writable system directory")
                && a.message.contains("/etc")),
            "expected critical alert for world-writable /etc, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_expected_world_writable_dir_not_flagged() {
        // /tmp is expected to be world-writable — should not trigger
        let entries = vec![bf("/tmp", "041777")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.category == "permissions"
                && a.message.contains("World-writable system directory")
                && a.message.contains("/tmp")),
            "expected /tmp not flagged as anomalous, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_world_writable_library_critical() {
        // .so file outside temp with world-writable bits
        let entries = vec![bf("/usr/lib/evil.so", "100666")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "permissions"
                && a.message.contains("World-writable library")),
            "expected critical alert for world-writable .so, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_world_writable_dylib_critical() {
        let entries = vec![bf("/Library/Frameworks/evil.dylib", "100666")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.message.contains("World-writable library")),
            "expected critical alert for world-writable .dylib, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_world_writable_library_in_tmp_not_flagged() {
        // .so in /tmp should not trigger the library check
        let entries = vec![bf("/tmp/build/test.so", "100666")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(
                |a| a.category == "permissions" && a.message.contains("World-writable library")
            ),
            "library in /tmp should not trigger, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_world_writable_sensitive_file_warning() {
        // Non-library file in /etc with world-writable bits
        let entries = vec![bf("/etc/shadow", "100666")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "permissions"
                && a.message.contains("World-writable file in sensitive path")),
            "expected warning for world-writable /etc/shadow, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_world_writable_windows_sensitive_path() {
        let entries = vec![bf("/Windows/System32/drivers/evil.sys", "100666")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "permissions"
                && a.message.contains("World-writable file in sensitive path")),
            "expected warning for world-writable Windows path, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_sgid_outside_standard_path_warning() {
        // SGID bit set (02000) on file outside standard bin dirs
        let entries = vec![bf("/opt/custom/suid_helper", "102755")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "permissions"
                && a.message.contains("SGID binary outside standard path")),
            "expected SGID warning for non-standard path, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_sgid_in_standard_path_not_flagged() {
        // SGID in /usr/bin/ is normal (e.g. wall, write)
        let entries = vec![bf("/usr/bin/wall", "102755")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.category == "permissions"
                && a.message.contains("SGID")
                && a.message.contains("/usr/bin/wall")),
            "SGID in /usr/bin should not trigger, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_normal_file_not_flagged() {
        // Normal 644 file in /etc — no world-writable, no SGID
        let entries = vec![bf("/etc/hostname", "100644")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "permissions" && a.message.contains("/etc/hostname")),
            "normal permissions should not trigger, got: {alerts:?}"
        );
    }

    #[test]
    fn perm_macos_system_dir_world_writable() {
        let entries = vec![bf("/System", "040777")];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.message.contains("World-writable system directory")
                && a.message.contains("/System")),
            "expected critical for world-writable /System, got: {alerts:?}"
        );
    }

    #[test]
    fn temporal_small_bodyfile_skipped() {
        // < 50 entries — engine should skip entirely
        let entries: Vec<BodyfileEntry> = (0..49)
            .map(|i| {
                let mut e = bf(&format!("/file_{i}"), "100644");
                e.mtime = Some(1_700_000_000 + i * 3600);
                e
            })
            .collect();
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.category == "temporal"),
            "< 50 entries should not trigger temporal analysis, got: {alerts:?}"
        );
    }

    #[test]
    fn temporal_burst_detection_warning() {
        // 60 entries: 50 spread evenly across different hours, 10 clustered in one hour
        // The clustered hour should be a statistical outlier
        let base_time = 1_700_000_000_i64;
        let mut entries: Vec<BodyfileEntry> = Vec::new();

        // 50 entries each in their own hour (1 per hour)
        for i in 0..50 {
            let mut e = bf(&format!("/normal/file_{i}"), "100644");
            e.mtime = Some(base_time + i * 3600);
            entries.push(e);
        }
        // 15 entries all in the same hour (burst)
        let burst_hour = base_time + 100 * 3600;
        for i in 0..15 {
            let mut e = bf(&format!("/burst/file_{i}"), "100644");
            e.mtime = Some(burst_hour + i * 60); // same hour, different minutes
            entries.push(e);
        }

        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "temporal"
                && a.message.contains("Modification burst")),
            "expected temporal burst warning, got: {alerts:?}"
        );
    }

    #[test]
    fn temporal_sustained_activity_critical() {
        // Create bursts across 4 different hours (≥ 3 needed for sustained)
        let base_time = 1_700_000_000_i64;
        let mut entries: Vec<BodyfileEntry> = Vec::new();

        // Background: 50 entries, 1 per hour
        for i in 0..50 {
            let mut e = bf(&format!("/bg/file_{i}"), "100644");
            e.mtime = Some(base_time + i * 3600);
            entries.push(e);
        }
        // 4 burst hours, each with 15 files
        for burst_idx in 0..4 {
            let burst_hour = base_time + (200 + burst_idx) * 3600;
            for i in 0..15 {
                let mut e = bf(&format!("/burst_{burst_idx}/file_{i}"), "100644");
                e.mtime = Some(burst_hour + i * 60);
                entries.push(e);
            }
        }

        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "temporal"
                && a.message.contains("Sustained modification activity")),
            "expected sustained activity critical alert, got: {alerts:?}"
        );
    }

    #[test]
    fn temporal_uniform_distribution_no_bursts() {
        // 60 entries, each in their own hour — no outliers
        let base_time = 1_700_000_000_i64;
        let entries: Vec<BodyfileEntry> = (0..60)
            .map(|i| {
                let mut e = bf(&format!("/uniform/file_{i}"), "100644");
                e.mtime = Some(base_time + i * 3600);
                e
            })
            .collect();
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.category == "temporal"),
            "uniform distribution should not trigger bursts, got: {alerts:?}"
        );
    }
}
