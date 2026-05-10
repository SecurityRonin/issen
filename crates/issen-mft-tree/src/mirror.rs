//! `$MFTMirr` validation — compare first 4 MFT entries against mirror.
//!
//! `$MFTMirr` is an NTFS metadata file that backs up MFT entries 0-3
//! (`$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`). Byte-for-byte comparison
//! detects corruption or tampering.

use std::path::Path;

/// Standard MFT entry size in bytes.
const MFT_ENTRY_SIZE: usize = 1024;

/// Number of entries mirrored by `$MFTMirr`.
const MIRROR_ENTRY_COUNT: usize = 4;

/// Result of comparing one MFT entry against its mirror copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryMatch {
    /// Byte-for-byte identical.
    Match,
    /// Differs — `first_diff_offset` is the byte offset within the 1024-byte
    /// entry where the first difference was found.
    Mismatch {
        /// Byte offset (0-based, within the entry) of the first difference.
        first_diff_offset: usize,
    },
    /// Mirror file is too short to contain this entry.
    MirrorTruncated,
    /// MFT file is too short to contain this entry.
    MftTruncated,
}

/// Validation result for the `$MFTMirr` file.
#[derive(Debug, Clone)]
pub struct MirrorValidation {
    /// Per-entry comparison results (indices 0-3).
    pub entries: [EntryMatch; MIRROR_ENTRY_COUNT],
}

impl MirrorValidation {
    /// Returns `true` if all 4 entries match byte-for-byte.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.entries.iter().all(|e| *e == EntryMatch::Match)
    }

    /// Count of entries that are mismatched or truncated (i.e. not `Match`).
    #[must_use]
    pub fn mismatch_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| **e != EntryMatch::Match)
            .count()
    }
}

/// Compare the first 4 entries of `$MFT` against `$MFTMirr`.
///
/// Reads both files fully into memory and compares entry-by-entry
/// (each entry is 1024 bytes).
///
/// # Errors
///
/// Returns an I/O error if either file cannot be read.
pub fn validate_mirror(mft_path: &Path, mirror_path: &Path) -> std::io::Result<MirrorValidation> {
    let mft_data = std::fs::read(mft_path)?;
    let mirror_data = std::fs::read(mirror_path)?;
    Ok(validate_mirror_from_bytes(&mft_data, &mirror_data))
}

/// Compare the first 4 entries from raw byte slices.
///
/// This is the pure logic, separated from I/O for testability.
#[must_use]
pub fn validate_mirror_from_bytes(mft_data: &[u8], mirror_data: &[u8]) -> MirrorValidation {
    let entries = std::array::from_fn(|i| {
        let offset = i * MFT_ENTRY_SIZE;
        let end = offset + MFT_ENTRY_SIZE;

        if end > mft_data.len() {
            return EntryMatch::MftTruncated;
        }
        if end > mirror_data.len() {
            return EntryMatch::MirrorTruncated;
        }

        let mft_slice = &mft_data[offset..end];
        let mirror_slice = &mirror_data[offset..end];

        if mft_slice == mirror_slice {
            EntryMatch::Match
        } else {
            let first_diff_offset = mft_slice
                .iter()
                .zip(mirror_slice.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            EntryMatch::Mismatch { first_diff_offset }
        }
    });

    MirrorValidation { entries }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Total bytes needed for `count` MFT entries.
    const fn entry_bytes(count: usize) -> usize {
        count * MFT_ENTRY_SIZE
    }

    /// Create a byte vector of `count` MFT entries filled with `fill`.
    fn make_entries(count: usize, fill: u8) -> Vec<u8> {
        vec![fill; entry_bytes(count)]
    }

    /// Write data to a temporary file and return the handle.
    fn write_temp(data: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        f
    }

    // -----------------------------------------------------------------------
    // Pure-logic tests (via validate_mirror_from_bytes)
    // -----------------------------------------------------------------------

    #[test]
    fn test_matching_mirror() {
        let data = make_entries(MIRROR_ENTRY_COUNT, 0xAA);
        let result = validate_mirror_from_bytes(&data, &data);

        assert!(result.is_valid());
        assert_eq!(result.mismatch_count(), 0);
        for entry in &result.entries {
            assert_eq!(*entry, EntryMatch::Match);
        }
    }

    #[test]
    fn test_mismatched_entry() {
        let mft = make_entries(MIRROR_ENTRY_COUNT, 0x00);
        let mut mirror = mft.clone();

        // Alter byte 42 in entry 2 (offset = 2*1024 + 42 = 2090).
        mirror[2 * MFT_ENTRY_SIZE + 42] = 0xFF;

        let result = validate_mirror_from_bytes(&mft, &mirror);

        assert!(!result.is_valid());
        assert_eq!(result.entries[0], EntryMatch::Match);
        assert_eq!(result.entries[1], EntryMatch::Match);
        assert_eq!(
            result.entries[2],
            EntryMatch::Mismatch {
                first_diff_offset: 42
            }
        );
        assert_eq!(result.entries[3], EntryMatch::Match);
    }

    #[test]
    fn test_truncated_mirror() {
        let mft = make_entries(MIRROR_ENTRY_COUNT, 0x00);
        // Mirror has only 2 entries (2048 bytes).
        let mirror = make_entries(2, 0x00);

        let result = validate_mirror_from_bytes(&mft, &mirror);

        assert_eq!(result.entries[0], EntryMatch::Match);
        assert_eq!(result.entries[1], EntryMatch::Match);
        assert_eq!(result.entries[2], EntryMatch::MirrorTruncated);
        assert_eq!(result.entries[3], EntryMatch::MirrorTruncated);
        assert_eq!(result.mismatch_count(), 2);
    }

    #[test]
    fn test_truncated_mft() {
        // MFT has only 1 entry.
        let mft = make_entries(1, 0x00);
        let mirror = make_entries(MIRROR_ENTRY_COUNT, 0x00);

        let result = validate_mirror_from_bytes(&mft, &mirror);

        assert_eq!(result.entries[0], EntryMatch::Match);
        assert_eq!(result.entries[1], EntryMatch::MftTruncated);
        assert_eq!(result.entries[2], EntryMatch::MftTruncated);
        assert_eq!(result.entries[3], EntryMatch::MftTruncated);
        assert_eq!(result.mismatch_count(), 3);
    }

    #[test]
    fn test_mismatch_count() {
        let mft = make_entries(MIRROR_ENTRY_COUNT, 0x00);
        let mut mirror = mft.clone();

        // Alter entry 1 and entry 3.
        mirror[MFT_ENTRY_SIZE] = 0xFF;
        mirror[3 * MFT_ENTRY_SIZE + 100] = 0xFF;

        let result = validate_mirror_from_bytes(&mft, &mirror);

        assert_eq!(result.mismatch_count(), 2);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_all_different() {
        let mft = make_entries(MIRROR_ENTRY_COUNT, 0x00);
        let mirror = make_entries(MIRROR_ENTRY_COUNT, 0xFF);

        let result = validate_mirror_from_bytes(&mft, &mirror);

        assert_eq!(result.mismatch_count(), 4);
        assert!(!result.is_valid());
        for entry in &result.entries {
            assert_eq!(
                *entry,
                EntryMatch::Mismatch {
                    first_diff_offset: 0
                }
            );
        }
    }

    // -----------------------------------------------------------------------
    // File-based test (via validate_mirror, exercises I/O path)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_mirror_from_files() {
        let data = make_entries(MIRROR_ENTRY_COUNT, 0xBB);
        let mft_file = write_temp(&data);
        let mirror_file = write_temp(&data);

        let result = validate_mirror(mft_file.path(), mirror_file.path()).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_validate_mirror_missing_file() {
        let data = make_entries(MIRROR_ENTRY_COUNT, 0x00);
        let mft_file = write_temp(&data);

        let result = validate_mirror(mft_file.path(), Path::new("/nonexistent/$MFTMirr"));
        assert!(result.is_err());
    }
}
