use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rt_core::artifacts::ArtifactType;
use rt_core::error::RtError;
use rt_core::plugin::registry::all_parsers;
use rt_core::plugin::traits::EventEmitter;
use rt_core::timeline::event::TimelineEvent;

use crate::layers::layer0_storage::FileDataSource;
use crate::progress::ProgressReporter;

/// Discovered artifact in the evidence tree.
#[derive(Debug)]
pub struct DiscoveredArtifact {
    pub path: PathBuf,
    pub artifact_type: ArtifactType,
}

/// Result from running the pipeline on a collection of evidence.
#[derive(Debug)]
pub struct IngestResult {
    pub artifacts_found: usize,
    pub artifacts_parsed: usize,
    pub total_events: u64,
    pub total_bytes: u64,
    pub errors: Vec<String>,
}

/// Collecting emitter that gathers events in a thread-safe Vec.
pub struct CollectingEmitter {
    events: Mutex<Vec<TimelineEvent>>,
}

impl CollectingEmitter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    /// Consume the emitter and return all collected events.
    pub fn into_events(self) -> Vec<TimelineEvent> {
        self.events.into_inner().unwrap_or_default()
    }
}

impl Default for CollectingEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl EventEmitter for CollectingEmitter {
    fn emit(&self, event: TimelineEvent) -> Result<(), RtError> {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
        Ok(())
    }

    fn emit_batch(&self, batch: Vec<TimelineEvent>) -> Result<(), RtError> {
        if let Ok(mut events) = self.events.lock() {
            events.extend(batch);
        }
        Ok(())
    }
}

/// Detect artifact type from file path heuristics.
///
/// This is the MVP artifact detection — matches well-known KAPE output paths.
/// More sophisticated detection (magic bytes, directory structure) comes later.
#[must_use]
pub fn detect_artifact_type(path: &Path) -> Option<ArtifactType> {
    let name = path.file_name()?.to_str()?.to_lowercase();
    let full = path.to_str().unwrap_or_default().to_lowercase();

    // USN Journal: $UsnJrnl:$J or $J file in KAPE output
    if name == "$j" || name.contains("usnjrnl") || name.contains("$usnjrnl") {
        return Some(ArtifactType::UsnJournal);
    }

    // MFT: $MFT file
    if name == "$mft" || name.contains("mft") && !name.contains("prefetch") {
        return Some(ArtifactType::Mft);
    }

    // Event Logs: .evtx files
    if name.ends_with(".evtx") {
        return Some(ArtifactType::EventLog);
    }

    // Prefetch: .pf files
    if name.ends_with(".pf") {
        return Some(ArtifactType::Prefetch);
    }

    // Registry hives
    if name == "system"
        || name == "software"
        || name == "sam"
        || name == "security"
        || name == "ntuser.dat"
        || name == "usrclass.dat"
    {
        // Only if they're in a registry-related directory
        if full.contains("registry") || full.contains("config") {
            return Some(ArtifactType::Registry);
        }
    }

    // Amcache
    if name == "amcache.hve" {
        return Some(ArtifactType::Amcache);
    }

    // SRUM
    if name == "srudb.dat" {
        return Some(ArtifactType::Srum);
    }

    None
}

/// Walk a directory tree and discover artifacts that can be parsed.
pub fn discover_artifacts(root: &Path) -> Result<Vec<DiscoveredArtifact>, RtError> {
    let mut artifacts = Vec::new();
    walk_directory(root, &mut artifacts)?;
    Ok(artifacts)
}

fn walk_directory(dir: &Path, artifacts: &mut Vec<DiscoveredArtifact>) -> Result<(), RtError> {
    if !dir.is_dir() {
        // Single file — check if it's an artifact.
        if let Some(artifact_type) = detect_artifact_type(dir) {
            artifacts.push(DiscoveredArtifact {
                path: dir.to_path_buf(),
                artifact_type,
            });
        }
        return Ok(());
    }

    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_directory(&path, artifacts)?;
        } else if let Some(artifact_type) = detect_artifact_type(&path) {
            artifacts.push(DiscoveredArtifact {
                path,
                artifact_type,
            });
        }
    }
    Ok(())
}

/// Run the pipeline: discover artifacts, match parsers, execute, collect events.
///
/// Returns the collected events and an `IngestResult` summary.
pub fn run_pipeline(
    evidence_path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    let artifacts = discover_artifacts(evidence_path)?;
    let parsers = all_parsers();
    let emitter = CollectingEmitter::new();
    let mut result = IngestResult {
        artifacts_found: artifacts.len(),
        artifacts_parsed: 0,
        total_events: 0,
        total_bytes: 0,
        errors: Vec::new(),
    };

    for artifact in &artifacts {
        // Find a parser that supports this artifact type.
        let parser = parsers
            .iter()
            .find(|p| p.supported_artifacts().contains(&artifact.artifact_type));

        let Some(parser) = parser else {
            continue;
        };

        match FileDataSource::open(&artifact.path) {
            Ok(source) => match parser.parse(&source, &emitter) {
                Ok(stats) => {
                    result.artifacts_parsed += 1;
                    result.total_events += stats.events_emitted;
                    result.total_bytes += stats.bytes_processed;
                    progress.add_events(stats.events_emitted);
                    progress.add_bytes(stats.bytes_processed);
                    progress.complete_artifact();
                }
                Err(e) => {
                    let msg = format!("Parse error on {}: {e}", artifact.path.display());
                    result.errors.push(msg);
                    progress.record_error();
                }
            },
            Err(e) => {
                let msg = format!("Failed to open {}: {e}", artifact.path.display());
                result.errors.push(msg);
                progress.record_error();
            }
        }
    }

    let events = emitter.into_events();
    Ok((events, result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_usnjrnl() {
        assert_eq!(
            detect_artifact_type(Path::new("/evidence/C/\\$Extend/\\$J")),
            None, // escaped paths won't match, but real KAPE paths will
        );
        assert_eq!(
            detect_artifact_type(Path::new("/evidence/$J")),
            Some(ArtifactType::UsnJournal),
        );
        assert_eq!(
            detect_artifact_type(Path::new("/kape/C/$UsnJrnl_$J")),
            Some(ArtifactType::UsnJournal),
        );
    }

    #[test]
    fn test_detect_evtx() {
        assert_eq!(
            detect_artifact_type(Path::new("/logs/Security.evtx")),
            Some(ArtifactType::EventLog),
        );
        assert_eq!(
            detect_artifact_type(Path::new("/logs/System.evtx")),
            Some(ArtifactType::EventLog),
        );
    }

    #[test]
    fn test_detect_prefetch() {
        assert_eq!(
            detect_artifact_type(Path::new("/Prefetch/CMD.EXE-12345.pf")),
            Some(ArtifactType::Prefetch),
        );
    }

    #[test]
    fn test_detect_mft() {
        assert_eq!(
            detect_artifact_type(Path::new("/evidence/$MFT")),
            Some(ArtifactType::Mft),
        );
    }

    #[test]
    fn test_detect_unknown_file() {
        assert_eq!(
            detect_artifact_type(Path::new("/evidence/readme.txt")),
            None,
        );
    }

    #[test]
    fn test_detect_amcache() {
        assert_eq!(
            detect_artifact_type(Path::new("/registry/Amcache.hve")),
            Some(ArtifactType::Amcache),
        );
    }

    #[test]
    fn test_discover_artifacts_in_directory() {
        let dir = tempfile::tempdir().expect("tmpdir");

        // Create some fake artifact files.
        std::fs::write(dir.path().join("$J"), b"fake usn data").expect("write");
        std::fs::write(dir.path().join("Security.evtx"), b"fake evtx").expect("write");
        std::fs::write(dir.path().join("readme.txt"), b"not an artifact").expect("write");

        let artifacts = discover_artifacts(dir.path()).expect("discover");
        assert_eq!(artifacts.len(), 2);

        let types: Vec<ArtifactType> = artifacts.iter().map(|a| a.artifact_type).collect();
        assert!(types.contains(&ArtifactType::UsnJournal));
        assert!(types.contains(&ArtifactType::EventLog));
    }

    #[test]
    fn test_discover_nested_directory() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let sub = dir.path().join("C").join("Windows").join("Prefetch");
        std::fs::create_dir_all(&sub).expect("mkdirs");
        std::fs::write(sub.join("CMD.EXE-1234.pf"), b"fake prefetch").expect("write");

        let artifacts = discover_artifacts(dir.path()).expect("discover");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_type, ArtifactType::Prefetch);
    }

    #[test]
    fn test_run_pipeline_no_parsers_registered() {
        // With no parsers linked, the pipeline should find artifacts but parse none.
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("$J"), b"fake data").expect("write");

        let progress = ProgressReporter::new();
        let (events, result) = run_pipeline(dir.path(), &progress).expect("pipeline");

        assert_eq!(result.artifacts_found, 1);
        // No parsers registered in this test binary, so nothing parsed.
        assert_eq!(result.artifacts_parsed, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn test_collecting_emitter() {
        let emitter = CollectingEmitter::new();
        let event = TimelineEvent::new(
            1000,
            "ts".into(),
            rt_core::timeline::event::EventType::FileCreate,
            ArtifactType::UsnJournal,
            "p".into(),
            "d".into(),
            "ev".into(),
        );
        emitter.emit(event).expect("emit");
        assert_eq!(emitter.into_events().len(), 1);
    }
}
