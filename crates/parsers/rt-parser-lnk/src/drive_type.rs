/// Drive type classification for LNK target volumes.
/// Mirrors Windows DRIVE_TYPE constants from the LNK spec.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LnkDriveType {
    Unknown,
    NoRootDir,
    Fixed,     // local hard disk
    Removable, // USB, floppy, SD card
    Network,   // mapped network drive, UNC path
    CdRom,
    RamDisk,
}

impl LnkDriveType {
    /// Parse from the drive_type u32 value in an LNK VolumeID structure.
    ///
    /// Windows DRIVE_TYPE constants:
    /// 0 = DRIVE_UNKNOWN, 1 = DRIVE_NO_ROOT_DIR, 2 = DRIVE_REMOVABLE,
    /// 3 = DRIVE_FIXED, 4 = DRIVE_REMOTE, 5 = DRIVE_CDROM, 6 = DRIVE_RAMDISK
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::NoRootDir,
            2 => Self::Removable,
            3 => Self::Fixed,
            4 => Self::Network,
            5 => Self::CdRom,
            6 => Self::RamDisk,
            _ => Self::Unknown, // covers 0 (DRIVE_UNKNOWN) and unrecognised values
        }
    }

    /// Parse from LECmd CSV "Drive Type" string values.
    pub fn from_lecmd_str(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "NOROOTDIR" | "NO_ROOT_DIR" => Self::NoRootDir,
            "FIXED" => Self::Fixed,
            "REMOVABLE" => Self::Removable,
            "NETWORK" => Self::Network,
            "CDROM" | "CD-ROM" | "CD_ROM" => Self::CdRom,
            "RAMDISK" | "RAM_DISK" | "RAM DISK" => Self::RamDisk,
            _ => Self::Unknown, // covers "Unknown", unrecognised, and empty strings
        }
    }

    /// Returns the tag string to embed in a TimelineEvent.
    pub fn as_tag(&self) -> &'static str {
        match self {
            Self::Unknown => "drive_type:unknown",
            Self::NoRootDir => "drive_type:no_root_dir",
            Self::Fixed => "drive_type:fixed",
            Self::Removable => "drive_type:removable",
            Self::Network => "drive_type:network",
            Self::CdRom => "drive_type:cdrom",
            Self::RamDisk => "drive_type:ramdisk",
        }
    }

    /// Returns true if this drive type indicates removable/USB media.
    pub fn is_removable(&self) -> bool {
        matches!(self, Self::Removable)
    }

    /// Returns true if this drive type indicates network access.
    pub fn is_network(&self) -> bool {
        matches!(self, Self::Network)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u32_fixed_is_3() {
        assert_eq!(LnkDriveType::from_u32(3), LnkDriveType::Fixed);
    }

    #[test]
    fn from_u32_removable_is_2() {
        assert_eq!(LnkDriveType::from_u32(2), LnkDriveType::Removable);
    }

    #[test]
    fn from_u32_network_is_4() {
        assert_eq!(LnkDriveType::from_u32(4), LnkDriveType::Network);
    }

    #[test]
    fn from_u32_unknown_on_unrecognised() {
        assert_eq!(LnkDriveType::from_u32(99), LnkDriveType::Unknown);
    }

    #[test]
    fn from_lecmd_str_fixed() {
        assert_eq!(LnkDriveType::from_lecmd_str("Fixed"), LnkDriveType::Fixed);
    }

    #[test]
    fn from_lecmd_str_removable() {
        assert_eq!(
            LnkDriveType::from_lecmd_str("Removable"),
            LnkDriveType::Removable
        );
    }

    #[test]
    fn from_lecmd_str_network() {
        assert_eq!(
            LnkDriveType::from_lecmd_str("Network"),
            LnkDriveType::Network
        );
    }

    #[test]
    fn from_lecmd_str_case_insensitive() {
        assert_eq!(LnkDriveType::from_lecmd_str("FIXED"), LnkDriveType::Fixed);
    }

    #[test]
    fn as_tag_removable() {
        assert_eq!(LnkDriveType::Removable.as_tag(), "drive_type:removable");
    }

    #[test]
    fn as_tag_fixed() {
        assert_eq!(LnkDriveType::Fixed.as_tag(), "drive_type:fixed");
    }

    #[test]
    fn as_tag_network() {
        assert_eq!(LnkDriveType::Network.as_tag(), "drive_type:network");
    }

    #[test]
    fn is_removable_true_for_removable() {
        assert!(LnkDriveType::Removable.is_removable());
    }

    #[test]
    fn is_removable_false_for_fixed() {
        assert!(!LnkDriveType::Fixed.is_removable());
    }

    #[test]
    fn is_network_true_for_network() {
        assert!(LnkDriveType::Network.is_network());
    }
}
