//! Temporal helper functions for born-before-OS-install detection.
//!
//! These helpers support the `temporal.file-born-before-os-install` correlation
//! rule (MITRE T1070.006 — Timestomp). They convert Windows timestamp formats
//! and evaluate whether a file birth time predates the OS installation date by
//! more than a configurable threshold.

/// Returns `true` if a file's birth time predates OS installation by more than
/// the threshold.
///
/// All timestamps must be in nanoseconds since the Unix epoch (positive = after
/// 1970-01-01 00:00:00 UTC).
///
/// # Arguments
/// - `file_born_ns` — file `$STANDARD_INFORMATION` birth time, nanoseconds
/// - `os_install_ns` — OS install date, nanoseconds
/// - `threshold_ns` — minimum gap required to fire (e.g. `86_400_000_000_000` = 24 h)
#[must_use]
pub fn is_born_before_install(file_born_ns: i64, os_install_ns: i64, threshold_ns: i64) -> bool {
    file_born_ns < os_install_ns - threshold_ns
}

/// Convert a Windows FILETIME (100-ns intervals since 1601-01-01 UTC) to
/// nanoseconds since the Unix epoch.
///
/// Windows epoch offset: 11 644 473 600 seconds = `11_644_473_600_000_000_000` ns.
#[must_use]
pub fn filetime_to_unix_ns(filetime: u64) -> i64 {
    // Delegate the epoch arithmetic to the spec-cited timeglyph decoder (our own
    // fleet crate, [MS-DTYP]). Fall back to the saturating hand-rolled i128 math
    // for values timeglyph cannot represent (or a u64 above i64::MAX), preserving
    // this site's never-None `-> i64` saturating contract.
    const EPOCH_DIFF_100NS: i128 = 116_444_736_000_000_000;
    let saturating = || {
        let unix_100ns = i128::from(filetime) - EPOCH_DIFF_100NS;
        i64::try_from(unix_100ns * 100).unwrap_or(i64::MAX)
    };
    match i64::try_from(filetime) {
        Ok(ft) => timeglyph::format("filetime")
            .ok()
            .and_then(|f| f.decode_int(ft).ok())
            .and_then(|posix_ns| i64::try_from(posix_ns.0).ok())
            .unwrap_or_else(saturating),
        Err(_) => saturating(),
    }
}

/// Convert a Windows registry `InstallDate` value (Unix timestamp, seconds,
/// stored as a `u32`) to nanoseconds since the Unix epoch.
#[must_use]
pub fn install_date_to_ns(install_date_secs: u32) -> i64 {
    i64::from(install_date_secs) * 1_000_000_000
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_born_before_install_by_more_than_threshold_returns_true() {
        // file born 2 days before install, threshold 1 day
        let install_ns = 1_000_000_000_000i64; // arbitrary
        let file_born_ns = install_ns - 2 * 86_400_000_000_000i64; // 2 days before
        let threshold_ns = 86_400_000_000_000i64; // 1 day
        assert!(is_born_before_install(
            file_born_ns,
            install_ns,
            threshold_ns
        ));
    }

    #[test]
    fn file_born_after_install_returns_false() {
        let install_ns = 1_000_000_000_000i64;
        let file_born_ns = install_ns + 86_400_000_000_000i64;
        assert!(!is_born_before_install(
            file_born_ns,
            install_ns,
            86_400_000_000_000i64
        ));
    }

    #[test]
    fn file_born_within_threshold_returns_false() {
        // born 12h before install, threshold 24h → not suspicious
        let install_ns = 1_000_000_000_000_000i64;
        let file_born_ns = install_ns - 12 * 3_600_000_000_000i64;
        let threshold_ns = 24 * 3_600_000_000_000i64;
        assert!(!is_born_before_install(
            file_born_ns,
            install_ns,
            threshold_ns
        ));
    }

    #[test]
    fn filetime_to_unix_ns_known_value() {
        // Windows FILETIME for 2020-01-01 00:00:00 UTC = 132_223_104_000_000_000
        // Unix timestamp: 1_577_836_800 s = 1_577_836_800_000_000_000 ns
        let filetime: u64 = 132_223_104_000_000_000;
        let unix_ns = filetime_to_unix_ns(filetime);
        assert_eq!(unix_ns, 1_577_836_800_000_000_000i64);
    }

    #[test]
    fn install_date_to_ns_converts_seconds() {
        assert_eq!(install_date_to_ns(1), 1_000_000_000i64);
        assert_eq!(install_date_to_ns(0), 0i64);
    }
}
