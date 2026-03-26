//! NTFS file node and timestamp types for MFT tree construction.

use chrono::{DateTime, Utc};

/// Four NTFS timestamps from a single attribute ($SI or $FN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsTimestamps {
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub created: DateTime<Utc>,
    pub entry_modified: DateTime<Utc>,
}

/// A single file or directory extracted from the MFT.
#[derive(Debug, Clone)]
pub struct FileNode {
    pub name: String,
    pub mft_entry: u64,
    pub parent_entry: u64,
    pub is_dir: bool,
    pub size: u64,
    /// `$STANDARD_INFORMATION` timestamps (user-visible, modifiable by tools).
    pub si_timestamps: NtfsTimestamps,
    /// `$FILE_NAME` timestamps (kernel-managed, harder to tamper).
    /// `None` if identical to `si_timestamps`.
    pub fn_timestamps: Option<NtfsTimestamps>,
    /// NTFS file attribute flags (from `$STANDARD_INFORMATION`).
    /// Common: 0x1 = read-only, 0x2 = hidden, 0x4 = system, 0x20 = archive.
    pub file_attributes: u32,
    /// Number of USN journal change records referencing this entry.
    pub usn_change_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

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

    #[test]
    fn ntfs_timestamps_equality() {
        let a = default_timestamps();
        let b = default_timestamps();
        assert_eq!(a, b);
    }

    #[test]
    fn ntfs_timestamps_copy_semantics() {
        let a = default_timestamps();
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn file_node_with_fn_timestamps() {
        let si = default_timestamps();
        let fn_ts = NtfsTimestamps {
            created: ts(2023, 6, 15),
            ..si
        };
        let node = FileNode {
            name: "test.exe".to_string(),
            mft_entry: 100,
            parent_entry: 5,
            is_dir: false,
            size: 1024,
            si_timestamps: si,
            fn_timestamps: Some(fn_ts),
            file_attributes: 0,
            usn_change_count: 0,
        };
        assert!(node.fn_timestamps.is_some());
        assert_ne!(
            node.si_timestamps.created,
            node.fn_timestamps.unwrap().created
        );
    }

    #[test]
    fn file_node_without_fn_timestamps() {
        let node = FileNode {
            name: "normal.txt".to_string(),
            mft_entry: 200,
            parent_entry: 5,
            is_dir: false,
            size: 512,
            si_timestamps: default_timestamps(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        };
        assert!(node.fn_timestamps.is_none());
    }

    #[test]
    fn file_node_directory() {
        let node = FileNode {
            name: "Windows".to_string(),
            mft_entry: 30,
            parent_entry: 5,
            is_dir: true,
            size: 0,
            si_timestamps: default_timestamps(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        };
        assert!(node.is_dir);
        assert_eq!(node.size, 0);
    }
}
