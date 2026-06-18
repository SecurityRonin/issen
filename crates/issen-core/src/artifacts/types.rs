use serde::{Deserialize, Serialize};

/// Forensic artifact types recognized by `Issen` parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactType {
    /// NTFS USN Change Journal ($UsnJrnl:$J)
    UsnJournal,
    /// NTFS Master File Table ($MFT)
    Mft,
    /// Windows Event Log (.evtx)
    EventLog,
    /// Windows Prefetch (.pf)
    Prefetch,
    /// Windows Registry hive
    Registry,
    /// Windows Shellbags
    Shellbags,
    /// Windows LNK shortcut files
    Lnk,
    /// Application Compatibility Cache (Amcache.hve)
    Amcache,
    /// Background Activity Moderator
    Bam,
    /// Browser history (Chrome, Firefox, Edge)
    BrowserHistory,
    /// Windows Jump Lists
    JumpLists,
    /// System Resource Usage Monitor (SRUM)
    Srum,
    /// Apple Biome `App.MenuItem` stream (macOS menu-bar selections, SEGB).
    BiomeMenuItem,
    /// Assessment or derived finding (not a raw artifact).
    Assessment,
    /// Mactime bodyfile (filesystem timeline from UAC)
    Bodyfile,
    /// Network state snapshot (netstat, ss, arp)
    NetworkState,
    /// Running process list (ps, lsof)
    ProcessList,
    /// Installed package inventory (dpkg, rpm, pip)
    PackageList,
    /// System information (hostname, uname, uptime)
    SystemInfo,
    /// Login/logout history (last, loginctl)
    LoginHistory,
    /// Crontab / scheduled task configuration
    CrontabConfig,
    /// Hash manifest of executables
    HashManifest,
    /// Rootkit scan results (chkrootkit, rkhunter)
    RootkitScan,
    /// System configuration files (/etc)
    SystemConfig,
    /// Windows device/driver install log (setupapi.dev.log)
    DeviceInstall,
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UsnJournal => write!(f, "USN Journal"),
            Self::Mft => write!(f, "MFT"),
            Self::EventLog => write!(f, "Event Log"),
            Self::Prefetch => write!(f, "Prefetch"),
            Self::Registry => write!(f, "Registry"),
            Self::Shellbags => write!(f, "Shellbags"),
            Self::Lnk => write!(f, "LNK"),
            Self::Amcache => write!(f, "Amcache"),
            Self::Bam => write!(f, "BAM"),
            Self::BrowserHistory => write!(f, "Browser History"),
            Self::JumpLists => write!(f, "Jump Lists"),
            Self::Srum => write!(f, "SRUM"),
            Self::BiomeMenuItem => write!(f, "Biome MenuItem"),
            Self::Assessment => write!(f, "Assessment"),
            Self::Bodyfile => write!(f, "Bodyfile"),
            Self::NetworkState => write!(f, "Network State"),
            Self::ProcessList => write!(f, "Process List"),
            Self::PackageList => write!(f, "Package List"),
            Self::SystemInfo => write!(f, "System Info"),
            Self::LoginHistory => write!(f, "Login History"),
            Self::CrontabConfig => write!(f, "Crontab"),
            Self::HashManifest => write!(f, "Hash Manifest"),
            Self::RootkitScan => write!(f, "Rootkit Scan"),
            Self::SystemConfig => write!(f, "System Config"),
            Self::DeviceInstall => write!(f, "Device Install"),
        }
    }
}

impl ArtifactType {
    /// Reconstruct an `ArtifactType` from the `format!("{:?}", _)` string that
    /// `TimelineStore` persists in the `source` column (the inverse of the
    /// store's serialization). Returns `None` for an unrecognized string — the
    /// enum has no catch-all variant, so callers handle the (in practice
    /// impossible — every row was written from a real variant) miss explicitly
    /// rather than silently mis-tagging the source.
    #[must_use]
    pub fn from_debug_str(s: &str) -> Option<Self> {
        Some(match s {
            "UsnJournal" => Self::UsnJournal,
            "Mft" => Self::Mft,
            "EventLog" => Self::EventLog,
            "Prefetch" => Self::Prefetch,
            "Registry" => Self::Registry,
            "Shellbags" => Self::Shellbags,
            "Lnk" => Self::Lnk,
            "Amcache" => Self::Amcache,
            "Bam" => Self::Bam,
            "BrowserHistory" => Self::BrowserHistory,
            "JumpLists" => Self::JumpLists,
            "Srum" => Self::Srum,
            "BiomeMenuItem" => Self::BiomeMenuItem,
            "Assessment" => Self::Assessment,
            "Bodyfile" => Self::Bodyfile,
            "NetworkState" => Self::NetworkState,
            "ProcessList" => Self::ProcessList,
            "PackageList" => Self::PackageList,
            "SystemInfo" => Self::SystemInfo,
            "LoginHistory" => Self::LoginHistory,
            "CrontabConfig" => Self::CrontabConfig,
            "HashManifest" => Self::HashManifest,
            "RootkitScan" => Self::RootkitScan,
            "SystemConfig" => Self::SystemConfig,
            "DeviceInstall" => Self::DeviceInstall,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_artifact_types_display() {
        assert_eq!(format!("{}", ArtifactType::Bodyfile), "Bodyfile");
        assert_eq!(format!("{}", ArtifactType::NetworkState), "Network State");
        assert_eq!(format!("{}", ArtifactType::ProcessList), "Process List");
        assert_eq!(format!("{}", ArtifactType::PackageList), "Package List");
        assert_eq!(format!("{}", ArtifactType::SystemInfo), "System Info");
        assert_eq!(format!("{}", ArtifactType::LoginHistory), "Login History");
        assert_eq!(format!("{}", ArtifactType::CrontabConfig), "Crontab");
        assert_eq!(format!("{}", ArtifactType::HashManifest), "Hash Manifest");
        assert_eq!(format!("{}", ArtifactType::RootkitScan), "Rootkit Scan");
        assert_eq!(format!("{}", ArtifactType::SystemConfig), "System Config");
    }

    #[test]
    fn test_biome_menu_item_display() {
        assert_eq!(format!("{}", ArtifactType::BiomeMenuItem), "Biome MenuItem");
    }

    #[test]
    fn test_artifact_type_serde_roundtrip() {
        let original = ArtifactType::Bodyfile;
        let json = serde_json::to_string(&original).expect("serialize");
        let back: ArtifactType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, back);
    }

    #[test]
    fn artifact_type_from_debug_str_roundtrips_all_variants() {
        // `TimelineStore` persists `source` as `format!("{:?}", _)`; the
        // narrative-over-DB path reconstructs the enum via `from_debug_str`,
        // whose Display (e.g. "Event Log") is what the temporal rules match.
        for at in [
            ArtifactType::UsnJournal,
            ArtifactType::Mft,
            ArtifactType::EventLog,
            ArtifactType::Prefetch,
            ArtifactType::Registry,
            ArtifactType::Shellbags,
            ArtifactType::Lnk,
            ArtifactType::Amcache,
            ArtifactType::Bam,
            ArtifactType::BrowserHistory,
            ArtifactType::JumpLists,
            ArtifactType::Srum,
            ArtifactType::BiomeMenuItem,
            ArtifactType::Assessment,
            ArtifactType::Bodyfile,
            ArtifactType::NetworkState,
            ArtifactType::ProcessList,
            ArtifactType::PackageList,
            ArtifactType::SystemInfo,
            ArtifactType::LoginHistory,
            ArtifactType::CrontabConfig,
            ArtifactType::HashManifest,
            ArtifactType::RootkitScan,
            ArtifactType::SystemConfig,
            ArtifactType::DeviceInstall,
        ] {
            let debug = format!("{at:?}");
            assert_eq!(
                ArtifactType::from_debug_str(&debug),
                Some(at),
                "round-trip failed for {debug}"
            );
        }
    }

    #[test]
    fn artifact_type_from_debug_str_unknown_is_none() {
        assert_eq!(ArtifactType::from_debug_str("NotARealArtifact"), None);
    }
}
