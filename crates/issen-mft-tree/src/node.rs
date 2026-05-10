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
    /// MFT sequence number (incremented each time an entry is reused).
    pub sequence_number: u16,
    /// Number of hard links pointing to this entry.
    pub hard_link_count: u16,
    /// `true` if the default data stream is resident in the MFT entry itself.
    pub is_resident: bool,
    /// Security descriptor ID (from `$STANDARD_INFORMATION`).
    pub security_id: u32,
    /// Owner ID (from `$STANDARD_INFORMATION`).
    pub owner_id: u32,
    /// USN of the last change journal record for this entry.
    pub usn: u64,
    /// Names of Alternate Data Streams attached to this file (empty if none).
    pub ads_names: Vec<String>,
}

// NTFS file attribute flag constants.
const ATTR_READONLY: u32 = 0x0001;
const ATTR_HIDDEN: u32 = 0x0002;
const ATTR_SYSTEM: u32 = 0x0004;
const ATTR_ARCHIVE: u32 = 0x0020;
const ATTR_COMPRESSED: u32 = 0x0800;
const ATTR_ENCRYPTED: u32 = 0x4000;

impl FileNode {
    /// Format NTFS file attribute flags as a compact string.
    ///
    /// Each flag is a single letter: `R`ead-only, `H`idden, `S`ystem,
    /// `A`rchive, `C`ompressed, `E`ncrypted. Absent flags show as `-`.
    ///
    /// Example: `--S-C-` means System + Compressed.
    #[must_use]
    pub fn format_attributes(&self) -> String {
        let a = self.file_attributes;
        let mut s = String::with_capacity(6);
        s.push(if a & ATTR_READONLY != 0 { 'R' } else { '-' });
        s.push(if a & ATTR_HIDDEN != 0 { 'H' } else { '-' });
        s.push(if a & ATTR_SYSTEM != 0 { 'S' } else { '-' });
        s.push(if a & ATTR_ARCHIVE != 0 { 'A' } else { '-' });
        s.push(if a & ATTR_COMPRESSED != 0 { 'C' } else { '-' });
        s.push(if a & ATTR_ENCRYPTED != 0 { 'E' } else { '-' });
        s
    }

    /// Returns `true` if the Hidden flag is set.
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        self.file_attributes & ATTR_HIDDEN != 0
    }

    /// Returns `true` if the System flag is set.
    #[must_use]
    pub fn is_system(&self) -> bool {
        self.file_attributes & ATTR_SYSTEM != 0
    }

    /// Returns `true` if this file has one or more Alternate Data Streams.
    #[must_use]
    pub fn has_ads(&self) -> bool {
        !self.ads_names.is_empty()
    }

    /// Returns `true` if the file has a Zone.Identifier ADS, indicating it
    /// was downloaded from the internet (mark-of-the-web).
    #[must_use]
    pub fn is_downloaded(&self) -> bool {
        self.ads_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case("Zone.Identifier"))
    }
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
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
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
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
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
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
        };
        assert!(node.is_dir);
        assert_eq!(node.size, 0);
    }

    // -- Attribute flags tests ------------------------------------------------

    fn node_with_attrs(attrs: u32) -> FileNode {
        FileNode {
            name: "test".to_string(),
            mft_entry: 1,
            parent_entry: 5,
            is_dir: false,
            size: 100,
            si_timestamps: default_timestamps(),
            fn_timestamps: None,
            file_attributes: attrs,
            usn_change_count: 0,
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
        }
    }

    #[test]
    fn format_attributes_none() {
        assert_eq!(node_with_attrs(0).format_attributes(), "------");
    }

    #[test]
    fn format_attributes_all() {
        let attrs = 0x0001 | 0x0002 | 0x0004 | 0x0020 | 0x0800 | 0x4000;
        assert_eq!(node_with_attrs(attrs).format_attributes(), "RHSACE");
    }

    #[test]
    fn format_attributes_hidden_system() {
        assert_eq!(
            node_with_attrs(0x0002 | 0x0004).format_attributes(),
            "-HS---"
        );
    }

    #[test]
    fn format_attributes_archive_only() {
        assert_eq!(node_with_attrs(0x0020).format_attributes(), "---A--");
    }

    #[test]
    fn is_hidden_flag() {
        assert!(!node_with_attrs(0).is_hidden());
        assert!(node_with_attrs(0x0002).is_hidden());
    }

    #[test]
    fn is_system_flag() {
        assert!(!node_with_attrs(0).is_system());
        assert!(node_with_attrs(0x0004).is_system());
    }
}
