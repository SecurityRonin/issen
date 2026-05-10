//! Attacker staging area detection and anti-forensic indicator checks.
//!
//! ## /dev/shm and /run/shm staging
//!
//! Attackers commonly stage tools in /dev/shm (tmpfs, survives until reboot,
//! not written to disk swap). The Father rootkit used /dev/shm/kit/ to store
//! its components before deployment. Files here deserve elevated suspicion.
//!
//! ## /run/utmp absence as anti-forensic indicator
//!
//! UAC normally collects /run/utmp (active sessions). Its absence from a UAC
//! collection indicates deliberate deletion to hide active login sessions —
//! a classic anti-forensic pattern seen when attackers wipe utmp/wtmp to
//! remove evidence of their active SSH sessions.

/// Returns `true` if `path` is under a known attacker staging area.
///
/// Staging areas: `/dev/shm`, `/run/shm` (and their root entries themselves).
#[must_use]
pub fn is_staging_path(path: &str) -> bool {
    path.starts_with("/dev/shm/")
        || path.starts_with("/run/shm/")
        || path == "/dev/shm"
        || path == "/run/shm"
}

/// Returns a human-readable label for the staging area containing `path`.
///
/// Returns `"unknown"` if the path is not under a known staging area.
#[must_use]
pub fn staging_area_label(path: &str) -> &'static str {
    if path.starts_with("/dev/shm/") || path == "/dev/shm" {
        "/dev/shm"
    } else if path.starts_with("/run/shm/") || path == "/run/shm" {
        "/run/shm"
    } else {
        "unknown"
    }
}

/// Returns `true` if `/run/utmp` (or a UAC-collected equivalent) is present
/// in the list of collected file paths.
///
/// UAC normally collects utmp as `live_response/run/utmp` or encodes the
/// path separator as underscore: `run_utmp`. Either form counts.
#[must_use]
pub fn check_utmp_present(collected_files: &[&str]) -> bool {
    collected_files
        .iter()
        .any(|f| f.contains("run/utmp") || f.contains("run_utmp"))
}

/// Returns `true` when `/run/utmp` is **absent** from the collection —
/// indicating a likely anti-forensic wipe of active session records.
#[must_use]
pub fn utmp_absent_is_antiforensic(collected_files: &[&str]) -> bool {
    !check_utmp_present(collected_files)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_staging_path ───────────────────────────────────────────────────

    #[test]
    fn staging_path_dev_shm_file() {
        assert!(is_staging_path("/dev/shm/kit/xmrig"));
    }

    #[test]
    fn staging_path_dev_shm_root() {
        assert!(is_staging_path("/dev/shm"));
    }

    #[test]
    fn staging_path_run_shm_file() {
        assert!(is_staging_path("/run/shm/evil.so"));
    }

    #[test]
    fn staging_path_run_shm_root() {
        assert!(is_staging_path("/run/shm"));
    }

    #[test]
    fn staging_path_tmp_not_staging() {
        assert!(!is_staging_path("/tmp/kit"));
    }

    #[test]
    fn staging_path_var_tmp_not_staging() {
        assert!(!is_staging_path("/var/tmp/evil"));
    }

    #[test]
    fn staging_path_dev_only_not_staging() {
        // /dev alone (not /dev/shm) is not a staging area
        assert!(!is_staging_path("/dev"));
    }

    #[test]
    fn staging_path_empty_not_staging() {
        assert!(!is_staging_path(""));
    }

    // ── staging_area_label ────────────────────────────────────────────────

    #[test]
    fn staging_label_dev_shm() {
        assert_eq!(staging_area_label("/dev/shm/kit/xmrig"), "/dev/shm");
    }

    #[test]
    fn staging_label_run_shm() {
        assert_eq!(staging_area_label("/run/shm/evil.so"), "/run/shm");
    }

    // ── check_utmp_present ────────────────────────────────────────────────

    #[test]
    fn utmp_present_with_full_path() {
        assert!(check_utmp_present(&["live_response/run/utmp", "other.txt"]));
    }

    #[test]
    fn utmp_present_with_underscore_form() {
        assert!(check_utmp_present(&["run_utmp"]));
    }

    #[test]
    fn utmp_absent_returns_false() {
        assert!(!check_utmp_present(&["passwd", "shadow"]));
    }

    #[test]
    fn utmp_present_in_mixed_list() {
        assert!(check_utmp_present(&["passwd", "live_response/run/utmp", "shadow"]));
    }

    #[test]
    fn utmp_absent_from_empty_list() {
        assert!(!check_utmp_present(&[]));
    }

    // ── utmp_absent_is_antiforensic ───────────────────────────────────────

    #[test]
    fn antiforensic_when_utmp_absent() {
        assert!(utmp_absent_is_antiforensic(&["passwd"]));
    }

    #[test]
    fn not_antiforensic_when_utmp_present_underscore() {
        assert!(!utmp_absent_is_antiforensic(&["run_utmp"]));
    }

    #[test]
    fn not_antiforensic_when_utmp_present_path() {
        assert!(!utmp_absent_is_antiforensic(&["live_response/run/utmp"]));
    }

    #[test]
    fn antiforensic_when_list_empty() {
        assert!(utmp_absent_is_antiforensic(&[]));
    }
}
