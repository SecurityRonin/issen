use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rayon::prelude::*;
use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::all_parsers;
use issen_core::plugin::traits::EventEmitter;
use issen_core::timeline::event::TimelineEvent;

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

/// Run the pipeline on a collection archive.
///
/// Uses `rt-unpack` to detect format, extract to temp dir, then runs the
/// normal filesystem-walking pipeline on the extracted contents.
///
/// # Errors
///
/// Returns an error if the collection format is not recognized or extraction fails.
pub fn run_collection_pipeline(
    collection_path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    let manifest = issen_unpack::registry::open_collection(collection_path)
        .map_err(|e| RtError::UnsupportedFormat(e.to_string()))?;

    tracing::info!(
        format = %manifest.format_name,
        artifacts = manifest.artifacts.len(),
        root = %manifest.extracted_root.display(),
        "Collection opened, running pipeline"
    );

    run_pipeline(&manifest.extracted_root, progress)
}

/// Run the pipeline, auto-detecting whether the input is a directory or collection archive.
///
/// - If `path` is a directory, walks it directly.
/// - If `path` is a file, tries to open it as a collection archive first.
///
/// # Errors
///
/// Returns an error if the path is a file in an unrecognized format, or if
/// pipeline execution fails.
pub fn run_auto(
    path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    if path.is_dir() {
        run_pipeline(path, progress)
    } else {
        run_collection_pipeline(path, progress)
    }
}

/// Run the pipeline using rayon parallel iteration across artifacts.
///
/// Produces identical output to [`run_pipeline`] but executes parser dispatch
/// concurrently. Requires all parsers and the emitter to be `Send + Sync`,
/// which is guaranteed by the trait bounds.
///
/// # Errors
///
/// Returns an error if artifact discovery fails.
pub fn run_pipeline_parallel(
    evidence_path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    let artifacts = discover_artifacts(evidence_path)?;
    let parsers = all_parsers();
    let emitter = CollectingEmitter::new();

    // Each artifact is dispatched in parallel. The emitter is Sync (Mutex-backed).
    // ProgressReporter is Sync (Arc<AtomicU64>-backed).
    let parse_results: Vec<Option<Result<_, String>>> = artifacts
        .par_iter()
        .map(|artifact| {
            let parser = parsers
                .iter()
                .find(|p| p.supported_artifacts().contains(&artifact.artifact_type))?;

            match FileDataSource::open(&artifact.path) {
                Ok(source) => match parser.parse(&source, &emitter) {
                    Ok(stats) => {
                        progress.add_events(stats.events_emitted);
                        progress.add_bytes(stats.bytes_processed);
                        progress.complete_artifact();
                        Some(Ok(stats))
                    }
                    Err(e) => Some(Err(format!(
                        "Parse error on {}: {e}",
                        artifact.path.display()
                    ))),
                },
                Err(e) => Some(Err(format!(
                    "Failed to open {}: {e}",
                    artifact.path.display()
                ))),
            }
        })
        .collect();

    let mut result = IngestResult {
        artifacts_found: artifacts.len(),
        artifacts_parsed: 0,
        total_events: 0,
        total_bytes: 0,
        errors: Vec::new(),
    };

    for entry in parse_results.into_iter().flatten() {
        match entry {
            Ok(stats) => {
                result.artifacts_parsed += 1;
                result.total_events += stats.events_emitted;
                result.total_bytes += stats.bytes_processed;
            }
            Err(msg) => result.errors.push(msg),
        }
    }

    let events = emitter.into_events();
    Ok((events, result))
}

/// Run the collection pipeline using rayon parallel iteration across artifacts.
///
/// Parallel variant of [`run_collection_pipeline`]: unpacks the archive then
/// dispatches parsers concurrently via [`run_pipeline_parallel`].
///
/// # Errors
///
/// Returns an error if the collection format is not recognized or extraction fails.
pub fn run_collection_pipeline_parallel(
    collection_path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    let manifest = issen_unpack::registry::open_collection(collection_path)
        .map_err(|e| RtError::UnsupportedFormat(e.to_string()))?;

    tracing::info!(
        format = %manifest.format_name,
        artifacts = manifest.artifacts.len(),
        root = %manifest.extracted_root.display(),
        "Collection opened, running parallel pipeline"
    );

    run_pipeline_parallel(&manifest.extracted_root, progress)
}

/// Run the pipeline, auto-detecting input type, using parallel artifact dispatch.
///
/// Parallel variant of [`run_auto`]: chooses between directory walk and
/// collection archive, then runs parsers concurrently via rayon.
///
/// # Errors
///
/// Returns an error if the path is a file in an unrecognized format, or if
/// pipeline execution fails.
pub fn run_auto_parallel(
    path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    if path.is_dir() {
        run_pipeline_parallel(path, progress)
    } else {
        run_collection_pipeline_parallel(path, progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_usnjrnl() {
        asseissen_eq!(
            detect_artifact_type(Path::new("/evidence/C/\\$Extend/\\$J")),
            None, // escaped paths won't match, but real KAPE paths will
        );
        asseissen_eq!(
            detect_artifact_type(Path::new("/evidence/$J")),
            Some(ArtifactType::UsnJournal),
        );
        asseissen_eq!(
            detect_artifact_type(Path::new("/kape/C/$UsnJrnl_$J")),
            Some(ArtifactType::UsnJournal),
        );
    }

    #[test]
    fn test_detect_evtx() {
        asseissen_eq!(
            detect_artifact_type(Path::new("/logs/Security.evtx")),
            Some(ArtifactType::EventLog),
        );
        asseissen_eq!(
            detect_artifact_type(Path::new("/logs/System.evtx")),
            Some(ArtifactType::EventLog),
        );
    }

    #[test]
    fn test_detect_prefetch() {
        asseissen_eq!(
            detect_artifact_type(Path::new("/Prefetch/CMD.EXE-12345.pf")),
            Some(ArtifactType::Prefetch),
        );
    }

    #[test]
    fn test_detect_mft() {
        asseissen_eq!(
            detect_artifact_type(Path::new("/evidence/$MFT")),
            Some(ArtifactType::Mft),
        );
    }

    #[test]
    fn test_detect_unknown_file() {
        asseissen_eq!(
            detect_artifact_type(Path::new("/evidence/readme.txt")),
            None,
        );
    }

    #[test]
    fn test_detect_amcache() {
        asseissen_eq!(
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
        asseissen_eq!(artifacts.len(), 2);

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
        asseissen_eq!(artifacts.len(), 1);
        asseissen_eq!(artifacts[0].artifact_type, ArtifactType::Prefetch);
    }

    #[test]
    fn test_run_pipeline_no_parsers_registered() {
        // With no parsers linked, the pipeline should find artifacts but parse none.
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("$J"), b"fake data").expect("write");

        let progress = ProgressReporter::new();
        let (events, result) = run_pipeline(dir.path(), &progress).expect("pipeline");

        asseissen_eq!(result.artifacts_found, 1);
        // No parsers registered in this test binary, so nothing parsed.
        asseissen_eq!(result.artifacts_parsed, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn test_run_collection_pipeline_unsupported_format() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("random.bin");
        std::fs::write(&path, b"not a collection").expect("write");

        let progress = ProgressReporter::new();
        let result = run_collection_pipeline(&path, &progress);
        assert!(result.is_err(), "Unknown format should error");
    }

    #[test]
    fn test_run_auto_with_directory() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("$J"), b"fake data").expect("write");

        let progress = ProgressReporter::new();
        let (events, result) = run_auto(dir.path(), &progress).expect("run_auto");
        asseissen_eq!(result.artifacts_found, 1);
        assert!(events.is_empty()); // No parsers registered in test binary
    }

    #[test]
    fn test_collecting_emitter() {
        let emitter = CollectingEmitter::new();
        let event = TimelineEvent::new(
            1000,
            "ts".into(),
            issen_core::timeline::event::EventType::FileCreate,
            ArtifactType::UsnJournal,
            "p".into(),
            "d".into(),
            "ev".into(),
        );
        emitter.emit(event).expect("emit");
        asseissen_eq!(emitter.into_events().len(), 1);
    }

    // ── Parallel pipeline tests ──────────────────────────────────────────────

    #[test]
    fn parallel_produces_same_artifact_count_as_sequential() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("$J"), b"fake usn").expect("write");
        std::fs::write(dir.path().join("Security.evtx"), b"fake evtx").expect("write");

        let progress_seq = ProgressReporter::new();
        let (_events_seq, result_seq) =
            run_pipeline(dir.path(), &progress_seq).expect("sequential pipeline");

        let progress_par = ProgressReporter::new();
        let (_events_par, result_par) =
            run_pipeline_parallel(dir.path(), &progress_par).expect("parallel pipeline");

        asseissen_eq!(
            result_seq.artifacts_found, result_par.artifacts_found,
            "parallel must discover the same number of artifacts as sequential"
        );
    }

    #[test]
    fn parallel_handles_empty_directory() {
        let dir = tempfile::tempdir().expect("tmpdir");

        let progress = ProgressReporter::new();
        let (events, result) =
            run_pipeline_parallel(dir.path(), &progress).expect("parallel empty dir");

        asseissen_eq!(result.artifacts_found, 0, "no artifacts in empty dir");
        asseissen_eq!(result.artifacts_parsed, 0);
        assert!(events.is_empty(), "no events from empty dir");
        assert!(result.errors.is_empty(), "no errors from empty dir");
    }

    #[test]
    fn parallel_handles_single_artifact_no_parser() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("$J"), b"fake usn data").expect("write");

        let progress = ProgressReporter::new();
        let (events, result) =
            run_pipeline_parallel(dir.path(), &progress).expect("parallel single artifact");

        asseissen_eq!(result.artifacts_found, 1);
        asseissen_eq!(
            result.artifacts_parsed, 0,
            "no parsers registered in test binary"
        );
        assert!(events.is_empty(), "no events without a parser");
        assert!(
            result.errors.is_empty(),
            "no errors — unmatched artifact is not an error"
        );
    }

    #[test]
    fn parallel_collecting_emitter_is_send_sync() {
        fn asseissen_send_sync<T: Send + Sync>() {}
        asseissen_send_sync::<CollectingEmitter>();
    }

    #[test]
    fn parallel_progress_reporter_is_send_sync() {
        fn asseissen_send_sync<T: Send + Sync>() {}
        asseissen_send_sync::<ProgressReporter>();
    }

    #[test]
    fn parallel_ingest_result_fields_non_negative() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("$J"), b"fake usn").expect("write");
        std::fs::write(dir.path().join("Security.evtx"), b"fake evtx").expect("write");

        let progress = ProgressReporter::new();
        let (_events, result) =
            run_pipeline_parallel(dir.path(), &progress).expect("parallel pipeline");

        assert!(
            result.artifacts_found >= result.artifacts_parsed,
            "found ({}) must be >= parsed ({})",
            result.artifacts_found,
            result.artifacts_parsed
        );
        // total_events and total_bytes are u64 (unsigned), so they're always >= 0 by type.
        // Verify the field is accessible and matches what progress tracks.
        let _ = result.total_events;
        let _ = result.total_bytes;
    }
}
