//! Investigation data model and UAC collection loader.
//!
//! `InvestigationData` aggregates all parsed forensic artifacts, the
//! supertimeline, and alert detections into a single struct that drives
//! the Investigation Workbench UI.

use std::collections::HashMap;
use std::path::Path;

use rt_mft_tree::tree::FileTree;
use rt_parser_uac::parsers::bodyfile;
use rt_parser_uac::parsers::bodyfile::BodyfileEntry;
use rt_parser_uac::parsers::chkrootkit;
use rt_parser_uac::parsers::chkrootkit::ChkrootkitFinding;
use rt_parser_uac::parsers::configs;
use rt_parser_uac::parsers::configs::ConfigFile;
use rt_parser_uac::parsers::hash_execs;
use rt_parser_uac::parsers::hash_execs::HashedExecutable;
use rt_parser_uac::parsers::network;
use rt_parser_uac::parsers::network::NetworkConnection;
use rt_parser_uac::parsers::packages;
use rt_parser_uac::parsers::packages::InstalledPackage;
use rt_parser_uac::parsers::process;
use rt_parser_uac::parsers::process::{CrontabEntry, ProcessInfo};
use rt_parser_uac::parsers::system;
use rt_parser_uac::parsers::system::LoginRecord;
use rt_signatures::heuristics::AnomalyIndex;

use super::alerts::{detect_alerts, Alert, AlertInput};
use super::timeline::{
    bodyfile_to_events, logins_to_events, processes_to_events, TimelineEvent, TimelineSource,
};

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// Basic metadata extracted from the UAC collection directory name.
#[derive(Debug, Clone, Default)]
pub struct CollectionMetadata {
    pub hostname: String,
    pub os: String,
    pub collection_tool: String,
    pub acquisition_time: i64,
}

// ---------------------------------------------------------------------------
// Investigation data
// ---------------------------------------------------------------------------

/// The top-level container for all forensic data loaded from a collection.
///
/// Implements `Debug` with summary counts (not full data dumps) for
/// practical debuggability without overwhelming output.
#[derive(Default)]
pub struct InvestigationData {
    pub metadata: CollectionMetadata,
    pub alerts: Vec<Alert>,
    pub timeline: Vec<TimelineEvent>,
    pub mft_tree: Option<FileTree>,
    pub anomaly_index: Option<AnomalyIndex>,
    pub network: Vec<NetworkConnection>,
    pub processes: Vec<ProcessInfo>,
    pub crontabs: Vec<CrontabEntry>,
    pub logins: Vec<LoginRecord>,
    pub packages: Vec<InstalledPackage>,
    pub hashes: Vec<HashedExecutable>,
    pub chkrootkit: Vec<ChkrootkitFinding>,
    pub configs: Vec<ConfigFile>,
    /// Artifact inventory from collection manifest (label → count).
    /// Populated for Velociraptor collections where the manifest classifies
    /// each extracted file by `ArtifactType`.
    pub artifact_counts: HashMap<String, usize>,
}

impl std::fmt::Debug for InvestigationData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvestigationData")
            .field("hostname", &self.metadata.hostname)
            .field("timeline", &self.timeline.len())
            .field("alerts", &self.alerts.len())
            .field("network", &self.network.len())
            .field("processes", &self.processes.len())
            .field("logins", &self.logins.len())
            .field("packages", &self.packages.len())
            .field("hashes", &self.hashes.len())
            .field("chkrootkit", &self.chkrootkit.len())
            .field("configs", &self.configs.len())
            .field("artifact_types", &self.artifact_counts.len())
            .finish()
    }
}

impl InvestigationData {
    /// Count timeline events grouped by source label.
    ///
    /// Returns `(label, count)` pairs for each `TimelineSource` variant that
    /// has at least one event.
    #[must_use]
    pub fn timeline_source_counts(&self) -> Vec<(&'static str, usize)> {
        let mut counts: Vec<(&'static str, usize)> = TimelineSource::all()
            .iter()
            .map(|src| {
                let count = self.timeline.iter().filter(|ev| ev.source == *src).count();
                (src.label(), count)
            })
            .filter(|(_label, count)| *count > 0)
            .collect();

        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts
    }
}

// ---------------------------------------------------------------------------
// UAC collection loader
// ---------------------------------------------------------------------------

/// Load and parse all artifacts from an extracted UAC collection directory.
///
/// Parses bodyfile, network state, process list, crontabs, login history,
/// packages, hashed executables, chkrootkit findings, and system configs.
/// Builds a supertimeline and runs alert heuristics on the raw data.
///
/// When `manifest_meta` is `Some`, metadata is populated from the manifest
/// (which was parsed during extraction). When `None` (e.g. standalone use),
/// falls back to parsing metadata from the directory name.
#[must_use]
pub fn load_uac_collection(
    extracted_root: &Path,
    manifest_meta: Option<&rt_unpack::CollectionMetadata>,
) -> InvestigationData {
    let metadata = if let Some(m) = manifest_meta {
        convert_manifest_metadata(m)
    } else {
        parse_uac_metadata(extracted_root)
    };

    // ----- Parse all artifact categories -----

    let bodyfile_entries = load_bodyfile(extracted_root);
    let network_conns = load_network(extracted_root);
    let processes = load_processes(extracted_root);
    let crontabs = load_crontabs(extracted_root);
    let logins = load_logins(extracted_root);
    let packages = load_packages(extracted_root);
    let hashes = load_hashes(extracted_root);
    let chkrootkit_findings = load_chkrootkit(extracted_root);
    let config_files = load_configs(extracted_root);

    // ----- Build supertimeline -----

    let mut timeline = bodyfile_to_events(&bodyfile_entries);
    timeline.extend(logins_to_events(&logins, metadata.acquisition_time));
    timeline.extend(processes_to_events(&processes));
    timeline.sort_by_key(|ev| ev.timestamp);

    // ----- Run alert detection -----

    let alert_input = AlertInput {
        bodyfile: &bodyfile_entries,
        network: &network_conns,
        processes: &processes,
        crontabs: &crontabs,
        chkrootkit: &chkrootkit_findings,
        configs: &config_files,
    };
    let alerts = detect_alerts(&alert_input);

    InvestigationData {
        metadata,
        alerts,
        timeline,
        mft_tree: None,
        anomaly_index: None,
        network: network_conns,
        processes,
        crontabs,
        logins,
        packages,
        hashes,
        chkrootkit: chkrootkit_findings,
        configs: config_files,
        artifact_counts: HashMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Velociraptor collection loader
// ---------------------------------------------------------------------------

/// Load investigation data from a Velociraptor collection.
///
/// Uses the manifest's pre-classified artifact entries to build an artifact
/// inventory. MFT and USN journal timeline events are added separately by
/// `try_load_mft` in main.rs after this function returns.
///
/// Individual Windows artifact parsers (evtx, registry, prefetch) will be
/// wired in as they become available — for now we build the artifact inventory
/// and metadata so the dashboard can display what was collected.
#[must_use]
pub fn load_velociraptor_collection(
    _extracted_root: &Path,
    artifacts: &[rt_unpack::ManifestEntry],
    manifest_meta: &rt_unpack::CollectionMetadata,
) -> InvestigationData {
    let metadata = convert_manifest_metadata(manifest_meta);

    // Build artifact type inventory from manifest entries
    let mut artifact_counts: HashMap<String, usize> = HashMap::new();
    for entry in artifacts {
        if let Some(ref artifact_type) = entry.artifact_type {
            let label = format!("{artifact_type:?}");
            *artifact_counts.entry(label).or_insert(0) += 1;
        }
    }

    InvestigationData {
        metadata,
        alerts: Vec::new(),
        timeline: Vec::new(),
        mft_tree: None,
        anomaly_index: None,
        network: Vec::new(),
        processes: Vec::new(),
        crontabs: Vec::new(),
        logins: Vec::new(),
        packages: Vec::new(),
        hashes: Vec::new(),
        chkrootkit: Vec::new(),
        configs: Vec::new(),
        artifact_counts,
    }
}

// ---------------------------------------------------------------------------
// Metadata parser
// ---------------------------------------------------------------------------

/// Convert `rt_unpack::CollectionMetadata` to our local `CollectionMetadata`.
fn convert_manifest_metadata(m: &rt_unpack::CollectionMetadata) -> CollectionMetadata {
    let os = match m.os_type {
        rt_unpack::OsType::Linux => "Linux",
        rt_unpack::OsType::MacOS => "macOS",
        rt_unpack::OsType::Windows => "Windows",
        rt_unpack::OsType::Unknown => "",
    };
    CollectionMetadata {
        hostname: m.hostname.clone().unwrap_or_default(),
        os: os.to_string(),
        collection_tool: m.tool_version.clone().unwrap_or_default(),
        acquisition_time: m.collection_time.map(|dt| dt.timestamp()).unwrap_or(0),
    }
}

/// Extract hostname and acquisition timestamp from the UAC directory name.
///
/// Expected format: `uac-HOSTNAME-YYYYMMDDHHMMSS` where the timestamp is
/// always the last 14 digits. The hostname may contain hyphens (e.g.
/// `uac-vbox-linux-20260101120000`).
#[must_use]
pub fn parse_uac_metadata(path: &Path) -> CollectionMetadata {
    let dirname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    let mut meta = CollectionMetadata {
        collection_tool: "UAC".into(),
        ..CollectionMetadata::default()
    };

    let Some(after_uac) = dirname.strip_prefix("uac-") else {
        return meta;
    };

    // The timestamp is always the last 14 characters after the last hyphen,
    // but only if those 14 chars are all digits.
    if let Some(last_hyphen) = after_uac.rfind('-') {
        let candidate_ts = &after_uac[last_hyphen + 1..];
        if candidate_ts.len() == 14 && candidate_ts.chars().all(|c| c.is_ascii_digit()) {
            meta.hostname = after_uac[..last_hyphen].to_string();
            meta.acquisition_time = parse_uac_timestamp(candidate_ts);
        } else {
            // No valid timestamp suffix — treat entire thing as hostname
            meta.hostname = after_uac.to_string();
        }
    } else {
        meta.hostname = after_uac.to_string();
    }

    meta
}

/// Parse a UAC timestamp string (YYYYMMDDHHMMSS) into Unix epoch seconds.
fn parse_uac_timestamp(ts: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%d%H%M%S")
        .map(|dt| dt.and_utc().timestamp())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Individual loaders
// ---------------------------------------------------------------------------

fn load_bodyfile(root: &Path) -> Vec<BodyfileEntry> {
    let path = root.join("bodyfile/bodyfile.txt");
    bodyfile::parse_bodyfile_path(&path).unwrap_or_default()
}

fn load_network(root: &Path) -> Vec<NetworkConnection> {
    let dir = root.join("live_response/network");
    if dir.is_dir() {
        network::parse_network_dir(&dir)
    } else {
        Vec::new()
    }
}

fn load_processes(root: &Path) -> Vec<ProcessInfo> {
    let proc_dir = root.join("live_response/process");
    let mut all = Vec::new();
    for name in &["ps_auxwww.txt", "ps-auxwww.txt", "ps.txt"] {
        let path = proc_dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(process::parse_ps_output(&content));
        }
    }
    all
}

fn load_crontabs(root: &Path) -> Vec<CrontabEntry> {
    let proc_dir = root.join("live_response/process");
    let mut all = Vec::new();
    for name in &["crontab.txt", "crontab-l.txt"] {
        let path = proc_dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(process::parse_crontab(&content, "root"));
        }
    }
    all
}

fn load_logins(root: &Path) -> Vec<LoginRecord> {
    let sys_dir = root.join("live_response/system");
    let mut all = Vec::new();
    for name in &["last.txt", "last-a.txt"] {
        let path = sys_dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(system::parse_last_output(&content));
        }
    }
    all
}

fn load_packages(root: &Path) -> Vec<InstalledPackage> {
    let dir = root.join("live_response/packages");
    if dir.is_dir() {
        packages::parse_packages_dir(&dir)
    } else {
        Vec::new()
    }
}

fn load_hashes(root: &Path) -> Vec<HashedExecutable> {
    let dir = root.join("hash_executables");
    if dir.is_dir() {
        hash_execs::parse_hash_dir(&dir)
    } else {
        Vec::new()
    }
}

fn load_chkrootkit(root: &Path) -> Vec<ChkrootkitFinding> {
    let path = root.join("chkrootkit/chkrootkit.log");
    std::fs::read_to_string(&path)
        .map(|content| chkrootkit::parse_chkrootkit_log(&content))
        .unwrap_or_default()
}

fn load_configs(root: &Path) -> Vec<ConfigFile> {
    let dir = root.join("system");
    if dir.is_dir() {
        configs::collect_configs(&dir)
    } else {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uac_metadata_valid_dirname() {
        let path = Path::new("/evidence/uac-webserver01-20260315143000");
        let meta = parse_uac_metadata(path);
        assert_eq!(meta.hostname, "webserver01");
        assert_eq!(meta.collection_tool, "UAC");
        assert!(meta.acquisition_time > 0, "should have parsed timestamp");
    }

    #[test]
    fn parse_uac_metadata_multi_part_hostname() {
        let path = Path::new("/evidence/uac-vbox-linux-20260101120000");
        let meta = parse_uac_metadata(path);
        assert_eq!(meta.hostname, "vbox-linux");
        assert!(meta.acquisition_time > 0);
    }

    #[test]
    fn parse_uac_metadata_unknown_dirname() {
        let path = Path::new("/evidence/some-random-dir");
        let meta = parse_uac_metadata(path);
        assert!(meta.hostname.is_empty());
        assert_eq!(meta.acquisition_time, 0);
    }

    #[test]
    fn load_uac_collection_empty_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let data = load_uac_collection(dir.path(), None);
        assert!(data.timeline.is_empty());
        assert!(data.alerts.is_empty());
        assert!(data.network.is_empty());
        assert!(data.processes.is_empty());
    }

    #[test]
    fn timeline_source_counts_empty_data() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let data = load_uac_collection(dir.path(), None);
        let counts = data.timeline_source_counts();
        assert!(counts.is_empty(), "empty data should have no source counts");
    }

    #[test]
    fn load_velociraptor_collection_with_manifest_metadata() {
        use rt_unpack::{CollectionMetadata as ManifestMeta, ManifestEntry, OsType};

        let dir = tempfile::tempdir().expect("tmpdir");
        let meta = ManifestMeta {
            hostname: Some("WORKSTATION01".into()),
            collection_time: Some(
                chrono::NaiveDateTime::parse_from_str("2025-08-10 03:41:20", "%Y-%m-%d %H:%M:%S")
                    .unwrap()
                    .and_utc(),
            ),
            os_type: OsType::Windows,
            tool_version: Some("Velociraptor".into()),
        };
        let artifacts = vec![];

        let data = load_velociraptor_collection(dir.path(), &artifacts, &meta);

        assert_eq!(data.metadata.hostname, "WORKSTATION01");
        assert_eq!(data.metadata.os, "Windows");
        assert_eq!(data.metadata.collection_tool, "Velociraptor");
        assert!(data.metadata.acquisition_time > 0);
    }

    #[test]
    fn load_velociraptor_collection_counts_artifact_types() {
        use rt_core::artifacts::ArtifactType;
        use rt_unpack::{CollectionMetadata as ManifestMeta, ManifestEntry, OsType};
        use std::path::PathBuf;

        let dir = tempfile::tempdir().expect("tmpdir");
        let meta = ManifestMeta {
            hostname: Some("TEST".into()),
            collection_time: None,
            os_type: OsType::Windows,
            tool_version: Some("Velociraptor".into()),
        };
        let artifacts = vec![
            ManifestEntry {
                path: PathBuf::from("$MFT"),
                artifact_type: Some(ArtifactType::Mft),
            },
            ManifestEntry {
                path: PathBuf::from("Windows/System32/winevt/Logs/Security.evtx"),
                artifact_type: Some(ArtifactType::EventLog),
            },
            ManifestEntry {
                path: PathBuf::from("Windows/System32/winevt/Logs/System.evtx"),
                artifact_type: Some(ArtifactType::EventLog),
            },
            ManifestEntry {
                path: PathBuf::from("Windows/System32/config/SYSTEM"),
                artifact_type: Some(ArtifactType::Registry),
            },
            ManifestEntry {
                path: PathBuf::from("Windows/Prefetch/CMD.EXE-1234.pf"),
                artifact_type: Some(ArtifactType::Prefetch),
            },
            ManifestEntry {
                path: PathBuf::from("Users/admin/Recent/foo.lnk"),
                artifact_type: Some(ArtifactType::Lnk),
            },
            ManifestEntry {
                path: PathBuf::from("Windows/Temp/random.tmp"),
                artifact_type: None,
            },
        ];

        let data = load_velociraptor_collection(dir.path(), &artifacts, &meta);

        // Should report artifact counts in summary
        let counts = data.artifact_counts;
        assert_eq!(*counts.get("EventLog").unwrap_or(&0), 2);
        assert_eq!(*counts.get("Registry").unwrap_or(&0), 1);
        assert_eq!(*counts.get("Prefetch").unwrap_or(&0), 1);
        assert_eq!(*counts.get("Lnk").unwrap_or(&0), 1);
        assert_eq!(*counts.get("Mft").unwrap_or(&0), 1);
    }

    #[test]
    fn load_velociraptor_collection_empty_artifacts() {
        use rt_unpack::{CollectionMetadata as ManifestMeta, OsType};

        let dir = tempfile::tempdir().expect("tmpdir");
        let meta = ManifestMeta {
            hostname: None,
            collection_time: None,
            os_type: OsType::Windows,
            tool_version: Some("Velociraptor".into()),
        };

        let data = load_velociraptor_collection(dir.path(), &[], &meta);

        assert!(data.timeline.is_empty());
        assert!(data.alerts.is_empty());
        assert!(data.artifact_counts.is_empty());
    }

    #[test]
    fn load_velociraptor_collection_metadata_defaults() {
        use rt_unpack::{CollectionMetadata as ManifestMeta, OsType};

        let meta = ManifestMeta {
            hostname: None,
            collection_time: None,
            os_type: OsType::Unknown,
            tool_version: None,
        };
        let data = load_velociraptor_collection(std::path::Path::new("/tmp/fake"), &[], &meta);
        assert!(data.timeline.is_empty());
        assert!(data.alerts.is_empty());
        assert!(data.artifact_counts.is_empty());
        assert!(data.metadata.hostname.is_empty());
    }

    #[test]
    fn timeline_source_counts_with_mixed_sources() {
        use crate::investigation::timeline::{TimelineEvent, TimelineSource, TimestampType};
        let data = InvestigationData {
            metadata: CollectionMetadata::default(),
            alerts: Vec::new(),
            timeline: vec![
                TimelineEvent {
                    timestamp: 100,
                    timestamp_type: TimestampType::Modified,
                    source: TimelineSource::Bodyfile,
                    path: "/a".into(),
                    description: String::new(),
                    extra: String::new(),
                },
                TimelineEvent {
                    timestamp: 200,
                    timestamp_type: TimestampType::Modified,
                    source: TimelineSource::Bodyfile,
                    path: "/b".into(),
                    description: String::new(),
                    extra: String::new(),
                },
                TimelineEvent {
                    timestamp: 300,
                    timestamp_type: TimestampType::Accessed,
                    source: TimelineSource::MftSi,
                    path: "/c".into(),
                    description: String::new(),
                    extra: String::new(),
                },
            ],
            mft_tree: None,
            anomaly_index: None,
            network: Vec::new(),
            processes: Vec::new(),
            crontabs: Vec::new(),
            logins: Vec::new(),
            packages: Vec::new(),
            hashes: Vec::new(),
            chkrootkit: Vec::new(),
            configs: Vec::new(),
            artifact_counts: std::collections::HashMap::new(),
        };
        let counts = data.timeline_source_counts();
        // Should have bodyfile=2, MFT-SI=1
        let bodyfile_count = counts
            .iter()
            .find(|(l, _)| l.contains("bodyfile"))
            .map(|(_, c)| *c);
        assert_eq!(bodyfile_count, Some(2));
    }

    #[test]
    fn collection_metadata_default() {
        let meta = CollectionMetadata::default();
        assert!(meta.hostname.is_empty());
        assert_eq!(meta.acquisition_time, 0);
    }

    #[test]
    fn investigation_data_debug_shows_counts() {
        let data = InvestigationData::default();
        let debug = format!("{data:?}");
        assert!(debug.contains("InvestigationData"));
        assert!(debug.contains("timeline: 0"));
        assert!(debug.contains("alerts: 0"));
    }
}
