//! Basic `$LogFile` validation -- restart area parsing.
//!
//! The NTFS `$LogFile` is a transaction journal. Its structure begins with
//! two restart area pages (at offset 0 and at offset `system_page_size`).
//! Each restart page carries a magic signature, version information, and
//! flags that indicate whether the volume was cleanly shut down.

use std::path::Path;

/// Magic signature for a valid restart page: `"RSTR"`.
const RSTR_MAGIC: &[u8; 4] = b"RSTR";

/// Magic signature written by `chkdsk` when it modifies the log.
const CHKD_MAGIC: &[u8; 4] = b"CHKD";

/// Minimum number of bytes needed to parse a restart page header.
const MIN_HEADER_SIZE: usize = 32;

/// Parsed restart page header from `$LogFile`.
#[derive(Debug, Clone)]
pub struct RestartPageInfo {
    /// Whether the magic signature `"RSTR"` was found (false if `"CHKD"`).
    pub valid_magic: bool,
    /// Whether the `"CHKD"` signature was found (chkdsk-modified log).
    pub chkd_magic: bool,
    /// System page size (bytes).
    pub system_page_size: u32,
    /// Log page size (bytes).
    pub log_page_size: u32,
    /// Major version from restart area.
    pub major_version: u16,
    /// Minor version from restart area.
    pub minor_version: u16,
    /// Raw flags from restart area.
    pub flags: u16,
    /// Checkpoint LSN (Log Sequence Number).
    pub checkpoint_lsn: u64,
}

/// Validation result for `$LogFile`.
#[derive(Debug, Clone)]
pub struct LogFileValidation {
    /// First restart page (at offset 0).
    pub restart_page_1: Option<RestartPageInfo>,
    /// Second restart page (at offset = `system_page_size` from page 1).
    pub restart_page_2: Option<RestartPageInfo>,
}

impl LogFileValidation {
    /// True if at least one restart page has a valid magic signature.
    #[must_use]
    pub fn has_valid_header(&self) -> bool {
        let p1_valid = self
            .restart_page_1
            .as_ref()
            .is_some_and(|p| p.valid_magic || p.chkd_magic);
        let p2_valid = self
            .restart_page_2
            .as_ref()
            .is_some_and(|p| p.valid_magic || p.chkd_magic);
        p1_valid || p2_valid
    }

    /// Summary string for display.
    #[must_use]
    pub fn summary(&self) -> String {
        match (&self.restart_page_1, &self.restart_page_2) {
            (Some(p1), Some(_p2)) => {
                let magic_label = if p1.chkd_magic { "CHKD" } else { "RSTR" };
                format!(
                    "valid ({magic_label}), v{}.{}, flags=0x{:04X}, checkpoint_lsn={}",
                    p1.major_version, p1.minor_version, p1.flags, p1.checkpoint_lsn,
                )
            }
            (Some(p1), None) => {
                let magic_label = if p1.chkd_magic { "CHKD" } else { "RSTR" };
                format!(
                    "page 1 valid ({magic_label}), v{}.{}, page 2 missing/invalid",
                    p1.major_version, p1.minor_version,
                )
            }
            (None, Some(p2)) => {
                format!(
                    "page 1 invalid, page 2 valid v{}.{}",
                    p2.major_version, p2.minor_version,
                )
            }
            (None, None) => "invalid (no valid restart pages found)".to_string(),
        }
    }
}

/// Parse a single restart page from a byte slice.
///
/// Returns `None` if the magic signature is not recognized or the data
/// is too short to contain a valid header.
fn parse_restart_page(data: &[u8]) -> Option<RestartPageInfo> {
    if data.len() < MIN_HEADER_SIZE {
        return None;
    }

    let magic = &data[0..4];
    let is_rstr = magic == RSTR_MAGIC;
    let is_chkd = magic == CHKD_MAGIC;

    if !is_rstr && !is_chkd {
        return None;
    }

    let system_page_size = u32::from_le_bytes(data[16..20].try_into().ok()?);
    let log_page_size = u32::from_le_bytes(data[20..24].try_into().ok()?);
    let restart_area_offset = u16::from_le_bytes(data[24..26].try_into().ok()?) as usize;
    let checkpoint_lsn = u64::from_le_bytes(data[8..16].try_into().ok()?);

    // Parse restart area fields if we have enough data.
    let (major_version, minor_version, flags) =
        if restart_area_offset > 0 && restart_area_offset + 20 <= data.len() {
            let ra = &data[restart_area_offset..];
            // Restart area layout:
            //   +0  u64 current_lsn
            //   +8  u16 log_clients
            //  +10  u16 client_free_list
            //  +12  u16 client_in_use_list
            //  +14  u16 flags
            //  +16  u16 major_version  (within restart area -- NOT header)
            //  +18  u16 minor_version
            let flags_val = u16::from_le_bytes(
                ra.get(14..16)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 2]),
            );
            let major = u16::from_le_bytes(
                ra.get(16..18)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 2]),
            );
            let minor = u16::from_le_bytes(
                ra.get(18..20)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 2]),
            );
            (major, minor, flags_val)
        } else {
            (0, 0, 0)
        };

    Some(RestartPageInfo {
        valid_magic: is_rstr,
        chkd_magic: is_chkd,
        system_page_size,
        log_page_size,
        major_version,
        minor_version,
        flags,
        checkpoint_lsn,
    })
}

/// Validate a `$LogFile` from raw bytes.
///
/// Parses restart page 1 at offset 0, then (if valid) restart page 2
/// at offset `system_page_size`.
#[must_use]
pub fn validate_logfile_from_bytes(data: &[u8]) -> LogFileValidation {
    let page1 = parse_restart_page(data);

    let page2 = page1.as_ref().and_then(|p1| {
        let offset = p1.system_page_size as usize;
        if offset > 0 && offset < data.len() {
            parse_restart_page(&data[offset..])
        } else {
            None
        }
    });

    LogFileValidation {
        restart_page_1: page1,
        restart_page_2: page2,
    }
}

/// Validate a `$LogFile` on disk.
///
/// Reads the file fully into memory and parses both restart pages.
///
/// # Errors
///
/// Returns an I/O error if the file cannot be read.
pub fn validate_logfile(path: &Path) -> std::io::Result<LogFileValidation> {
    let data = std::fs::read(path)?;
    Ok(validate_logfile_from_bytes(&data))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::trivially_copy_pass_by_ref
)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Default system page size used by test helpers (4096 bytes).
    const TEST_PAGE_SIZE: u32 = 4096;

    /// Default restart area offset (placed right after the 32-byte header).
    const TEST_RA_OFFSET: u16 = 32;

    /// Build a minimal restart page with the given magic and field values.
    fn build_restart_page(
        magic: &[u8; 4],
        system_page_size: u32,
        log_page_size: u32,
        checkpoint_lsn: u64,
        ra_offset: u16,
        ra_flags: u16,
        ra_major: u16,
        ra_minor: u16,
    ) -> Vec<u8> {
        let page_len = system_page_size.max(256) as usize;
        let mut buf = vec![0u8; page_len];

        // Magic (offset 0)
        buf[0..4].copy_from_slice(magic);

        // Update sequence offset (offset 4) -- unused but present
        buf[4..6].copy_from_slice(&30u16.to_le_bytes());
        // Update sequence count (offset 6)
        buf[6..8].copy_from_slice(&1u16.to_le_bytes());

        // Checkpoint LSN (offset 8)
        buf[8..16].copy_from_slice(&checkpoint_lsn.to_le_bytes());

        // System page size (offset 16)
        buf[16..20].copy_from_slice(&system_page_size.to_le_bytes());

        // Log page size (offset 20)
        buf[20..24].copy_from_slice(&log_page_size.to_le_bytes());

        // Restart area offset (offset 24)
        buf[24..26].copy_from_slice(&ra_offset.to_le_bytes());

        // Restart area at ra_offset:
        let ra = ra_offset as usize;
        if ra + 20 <= buf.len() {
            // current_lsn (8 bytes) -- set to checkpoint_lsn
            buf[ra..ra + 8].copy_from_slice(&checkpoint_lsn.to_le_bytes());
            // log_clients (2 bytes)
            buf[ra + 8..ra + 10].copy_from_slice(&1u16.to_le_bytes());
            // client_free_list (2 bytes)
            buf[ra + 10..ra + 12].copy_from_slice(&0xFFFFu16.to_le_bytes());
            // client_in_use_list (2 bytes)
            buf[ra + 12..ra + 14].copy_from_slice(&0u16.to_le_bytes());
            // flags (2 bytes)
            buf[ra + 14..ra + 16].copy_from_slice(&ra_flags.to_le_bytes());
            // major_version (2 bytes)
            buf[ra + 16..ra + 18].copy_from_slice(&ra_major.to_le_bytes());
            // minor_version (2 bytes)
            buf[ra + 18..ra + 20].copy_from_slice(&ra_minor.to_le_bytes());
        }

        buf
    }

    /// Build a default RSTR restart page with typical NTFS 3.1 values.
    fn default_rstr_page() -> Vec<u8> {
        build_restart_page(
            b"RSTR",
            TEST_PAGE_SIZE,
            TEST_PAGE_SIZE,
            0x0000_0001_0000_0042,
            TEST_RA_OFFSET,
            0x0000, // clean flags
            1,      // major
            1,      // minor
        )
    }

    /// Write data to a temporary file and return the handle.
    fn write_temp(data: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        f
    }

    // -------------------------------------------------------------------
    // Pure-logic tests (via parse_restart_page / validate_logfile_from_bytes)
    // -------------------------------------------------------------------

    #[test]
    fn test_valid_restart_page() {
        let page = default_rstr_page();
        let info = parse_restart_page(&page).unwrap();

        assert!(info.valid_magic);
        assert!(!info.chkd_magic);
        assert_eq!(info.system_page_size, TEST_PAGE_SIZE);
        assert_eq!(info.log_page_size, TEST_PAGE_SIZE);
        assert_eq!(info.major_version, 1);
        assert_eq!(info.minor_version, 1);
        assert_eq!(info.flags, 0x0000);
        assert_eq!(info.checkpoint_lsn, 0x0000_0001_0000_0042);
    }

    #[test]
    fn test_chkd_magic() {
        let page = build_restart_page(
            b"CHKD",
            TEST_PAGE_SIZE,
            TEST_PAGE_SIZE,
            100,
            TEST_RA_OFFSET,
            0x0002,
            1,
            1,
        );
        let info = parse_restart_page(&page).unwrap();

        assert!(!info.valid_magic);
        assert!(info.chkd_magic);
        assert_eq!(info.flags, 0x0002);
    }

    #[test]
    fn test_invalid_magic() {
        let mut page = default_rstr_page();
        page[0..4].copy_from_slice(b"JUNK");

        assert!(parse_restart_page(&page).is_none());
    }

    #[test]
    fn test_truncated_data() {
        // Fewer than MIN_HEADER_SIZE bytes.
        let tiny = vec![0x52, 0x53, 0x54, 0x52]; // "RSTR" but only 4 bytes
        assert!(parse_restart_page(&tiny).is_none());

        // Exactly at the boundary.
        let short = vec![0u8; MIN_HEADER_SIZE - 1];
        assert!(parse_restart_page(&short).is_none());
    }

    #[test]
    fn test_two_restart_pages() {
        let page1 = default_rstr_page();
        let page2 = build_restart_page(
            b"RSTR",
            TEST_PAGE_SIZE,
            TEST_PAGE_SIZE,
            0x0000_0001_0000_0099,
            TEST_RA_OFFSET,
            0x0000,
            1,
            1,
        );

        // Concatenate: page1 at offset 0, page2 at offset TEST_PAGE_SIZE.
        let mut data = page1;
        data.extend_from_slice(&page2);

        let validation = validate_logfile_from_bytes(&data);

        assert!(validation.restart_page_1.is_some());
        assert!(validation.restart_page_2.is_some());

        let p1 = validation.restart_page_1.unwrap();
        assert_eq!(p1.checkpoint_lsn, 0x0000_0001_0000_0042);

        let p2 = validation.restart_page_2.unwrap();
        assert_eq!(p2.checkpoint_lsn, 0x0000_0001_0000_0099);
    }

    #[test]
    fn test_has_valid_header_both_pages() {
        let page = default_rstr_page();
        let mut data = page.clone();
        data.extend_from_slice(&page);

        let v = validate_logfile_from_bytes(&data);
        assert!(v.has_valid_header());
    }

    #[test]
    fn test_has_valid_header_page1_only() {
        // Single page, no room for page 2.
        let page = default_rstr_page();
        let v = validate_logfile_from_bytes(&page);

        assert!(v.has_valid_header());
        assert!(v.restart_page_1.is_some());
        assert!(v.restart_page_2.is_none());
    }

    #[test]
    fn test_has_valid_header_none() {
        let data = vec![0u8; 8192];
        let v = validate_logfile_from_bytes(&data);

        assert!(!v.has_valid_header());
        assert!(v.restart_page_1.is_none());
        assert!(v.restart_page_2.is_none());
    }

    #[test]
    fn test_has_valid_header_chkd() {
        let page = build_restart_page(
            b"CHKD",
            TEST_PAGE_SIZE,
            TEST_PAGE_SIZE,
            50,
            TEST_RA_OFFSET,
            0,
            1,
            1,
        );
        let v = validate_logfile_from_bytes(&page);
        assert!(v.has_valid_header());
    }

    #[test]
    fn test_summary_both_valid() {
        let page = default_rstr_page();
        let mut data = page.clone();
        data.extend_from_slice(&page);

        let v = validate_logfile_from_bytes(&data);
        let s = v.summary();

        assert!(s.contains("RSTR"));
        assert!(s.contains("v1.1"));
        assert!(s.contains("flags=0x0000"));
    }

    #[test]
    fn test_summary_chkd() {
        let page = build_restart_page(
            b"CHKD",
            TEST_PAGE_SIZE,
            TEST_PAGE_SIZE,
            50,
            TEST_RA_OFFSET,
            0,
            1,
            1,
        );
        let mut data = page.clone();
        data.extend_from_slice(&page);

        let v = validate_logfile_from_bytes(&data);
        let s = v.summary();
        assert!(s.contains("CHKD"));
    }

    #[test]
    fn test_summary_no_valid_pages() {
        let data = vec![0u8; 8192];
        let v = validate_logfile_from_bytes(&data);
        assert!(v.summary().contains("invalid"));
    }

    #[test]
    fn test_summary_page1_only() {
        let page = default_rstr_page();
        let v = validate_logfile_from_bytes(&page);
        let s = v.summary();
        assert!(s.contains("page 1 valid"));
        assert!(s.contains("page 2 missing"));
    }

    #[test]
    fn test_nonzero_flags() {
        let page = build_restart_page(
            b"RSTR",
            TEST_PAGE_SIZE,
            TEST_PAGE_SIZE,
            100,
            TEST_RA_OFFSET,
            0x0002, // non-zero flags
            1,
            1,
        );
        let info = parse_restart_page(&page).unwrap();
        assert_eq!(info.flags, 0x0002);
    }

    #[test]
    fn test_version_2_0() {
        let page = build_restart_page(
            b"RSTR",
            TEST_PAGE_SIZE,
            TEST_PAGE_SIZE,
            100,
            TEST_RA_OFFSET,
            0,
            2, // major version 2
            0, // minor version 0
        );
        let info = parse_restart_page(&page).unwrap();
        assert_eq!(info.major_version, 2);
        assert_eq!(info.minor_version, 0);
    }

    #[test]
    fn test_restart_area_offset_beyond_data() {
        // Valid magic but restart area offset points beyond the data.
        let mut page = vec![0u8; 64];
        page[0..4].copy_from_slice(b"RSTR");
        page[16..20].copy_from_slice(&4096u32.to_le_bytes());
        page[20..24].copy_from_slice(&4096u32.to_le_bytes());
        // Restart area offset = 200, but buffer is only 64 bytes.
        page[24..26].copy_from_slice(&200u16.to_le_bytes());

        let info = parse_restart_page(&page).unwrap();
        // Should still parse but with zeroed version/flags.
        assert!(info.valid_magic);
        assert_eq!(info.major_version, 0);
        assert_eq!(info.minor_version, 0);
        assert_eq!(info.flags, 0);
    }

    // -------------------------------------------------------------------
    // File-based test (via validate_logfile, exercises I/O path)
    // -------------------------------------------------------------------

    #[test]
    fn test_validate_logfile_from_file() {
        let page = default_rstr_page();
        let mut data = page.clone();
        data.extend_from_slice(&page);

        let tmp = write_temp(&data);
        let result = validate_logfile(tmp.path()).unwrap();

        assert!(result.has_valid_header());
        assert!(result.restart_page_1.is_some());
        assert!(result.restart_page_2.is_some());
    }

    #[test]
    fn test_validate_logfile_missing_file() {
        let result = validate_logfile(Path::new("/nonexistent/$LogFile"));
        assert!(result.is_err());
    }
}
