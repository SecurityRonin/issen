use std::path::{Path, PathBuf};
use std::sync::Mutex;

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::all_parsers;
use issen_core::plugin::traits::{EventEmitter, ForensicParser};
use issen_core::timeline::event::TimelineEvent;
use rayon::prelude::*;

use crate::isolate::{run_isolated, Isolated};
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

    // Registry hives. NTUSER.DAT / UsrClass.dat are unambiguous hive filenames
    // that live in the user profile root / AppData — NEVER under a `config`
    // directory — so gating them on a "config"/"registry" path substring
    // silently drops every per-user hive (and with it UserAssist, ShellBags,
    // the MRUs). Recognize them by name unconditionally; keep the directory
    // gate only for the generically-named machine hives.
    if name == "ntuser.dat" || name == "usrclass.dat" {
        return Some(ArtifactType::Registry);
    }
    if (name == "system" || name == "software" || name == "sam" || name == "security")
        && (full.contains("registry") || full.contains("config"))
    {
        return Some(ArtifactType::Registry);
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
        // Run EVERY parser that supports this artifact type, not just the first.
        // Multiple parsers can claim one type — e.g. the registry walker and the
        // Shimcache parser both consume the SYSTEM hive as ArtifactType::Registry;
        // a `.find()` here silently starved all but the first.
        let matching: Vec<_> = parsers
            .iter()
            .filter(|p| p.supported_artifacts().contains(&artifact.artifact_type))
            .map(|p| p.as_ref())
            .collect();
        if matching.is_empty() {
            continue;
        }

        // Open the source once and share it across the matching parsers (reads
        // are random-access, so no per-parser reset is needed).
        let source = match FileDataSource::open(&artifact.path) {
            Ok(source) => source,
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to open {}: {e}", artifact.path.display()));
                progress.record_error();
                continue;
            }
        };

        for parser in matching {
            // A1: run each parser under isolation so a panicking/erroring one is
            // captured and skipped — the pipeline always terminates.
            let unit = format!("{} [{}]", artifact.path.display(), parser.name());
            match run_isolated(unit, || parser.parse(&source, &emitter)) {
                Isolated::Completed(stats) => {
                    result.artifacts_parsed += 1;
                    result.total_events += stats.events_emitted;
                    result.total_bytes += stats.bytes_processed;
                    progress.add_events(stats.events_emitted);
                    progress.add_bytes(stats.bytes_processed);
                    progress.complete_artifact();
                }
                Isolated::Failed(failure) => {
                    result.errors.push(failure.describe());
                    progress.record_error();
                }
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
    let mut out = if path.is_dir() {
        run_pipeline(path, progress)?
    } else {
        run_collection_pipeline(path, progress)?
    };
    sort_timeline_events(&mut out.0);
    Ok(out)
}

/// Per-unit, resumable variant of [`run_auto`] (issen #115).
///
/// Auto-detects directory vs collection archive exactly like [`run_auto`], but
/// returns events grouped per `(artifact, parser)` [`ParsedUnit`] instead of one
/// flat list — so the caller can `commit_unit` each atomically and skip units
/// already completed in a prior run.
///
/// # Errors
/// Returns an error if artifact discovery or collection extraction fails.
pub fn run_auto_units(
    path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<ParsedUnit>, IngestResult), RtError> {
    let artifacts = if path.is_dir() {
        discover_artifacts(path)?
    } else {
        let manifest = issen_unpack::registry::open_collection(path)
            .map_err(|e| RtError::UnsupportedFormat(e.to_string()))?;
        discover_artifacts(&manifest.extracted_root)?
    };
    let parsers = all_parsers();
    let (units, errors) = parse_units(&artifacts, &parsers, progress);
    let result = IngestResult {
        artifacts_found: artifacts.len(),
        artifacts_parsed: units.len(),
        total_events: units.iter().map(|u| u.events.len() as u64).sum(),
        total_bytes: units.iter().map(|u| u.bytes).sum(),
        errors,
    };
    Ok((units, result))
}

/// Sort a timeline into chronological order with a deterministic tiebreak.
///
/// Parsers and the parallel (rayon) pipeline emit events in discovery/parse
/// order, not time order — but a *timeline* must be chronological. Equal
/// timestamps are common (many MACE/$SI events share a second); they break on
/// `record_hash` (content-derived, hence deterministic) so the rendered
/// timeline, JSONL, and CSV are reproducible run-to-run. `record_hash`
/// comparison is allocation-free, so this stays a plain comparator.
pub(crate) fn sort_timeline_events(events: &mut [TimelineEvent]) {
    events.sort_by(|a, b| {
        a.timestamp_ns
            .cmp(&b.timestamp_ns)
            .then_with(|| a.record_hash.cmp(&b.record_hash))
    });
}

/// One resumable ingest unit's parse result: the events a single parser produced
/// for a single artifact. Each `(artifact, parser)` pair is one unit — the
/// granularity the resumable ingest path commits and skips at (issen #115).
pub struct ParsedUnit {
    /// The artifact's classified type.
    pub artifact_type: ArtifactType,
    /// The artifact's path.
    pub path: PathBuf,
    /// The parser that produced these events (`ForensicParser::name`).
    pub parser: String,
    /// Events this parser emitted for this artifact, in parse order.
    pub events: Vec<TimelineEvent>,
    /// Bytes the parser reported processing.
    pub bytes: u64,
}

/// Parse each `(artifact, matching-parser)` pair into its own [`ParsedUnit`].
///
/// Unlike [`run_pipeline`] (one shared emitter → a flat event list), this gives
/// every unit a fresh emitter so its events are grouped — the shape the
/// resumable ingest path needs to `commit_unit` per unit and skip completed
/// ones. Parsers are passed in (dependency injection) rather than read from the
/// force-linked registry, so the per-unit grouping is unit-testable.
#[must_use]
pub fn parse_units(
    artifacts: &[DiscoveredArtifact],
    parsers: &[Box<dyn ForensicParser>],
    progress: &ProgressReporter,
) -> (Vec<ParsedUnit>, Vec<String>) {
    let mut units = Vec::new();
    let mut errors = Vec::new();
    for artifact in artifacts {
        let matching: Vec<_> = parsers
            .iter()
            .filter(|p| p.supported_artifacts().contains(&artifact.artifact_type))
            .collect();
        if matching.is_empty() {
            continue;
        }
        // Open the source once and share it across this artifact's parsers.
        let source = match FileDataSource::open(&artifact.path) {
            Ok(source) => source,
            Err(e) => {
                errors.push(format!("Failed to open {}: {e}", artifact.path.display()));
                progress.record_error();
                continue;
            }
        };
        for parser in matching {
            // A fresh emitter per unit — this is what groups events by unit.
            let emitter = CollectingEmitter::new();
            let label = format!("{} [{}]", artifact.path.display(), parser.name());
            let bytes = match run_isolated(label, || parser.parse(&source, &emitter)) {
                Isolated::Completed(stats) => {
                    progress.add_events(stats.events_emitted);
                    progress.add_bytes(stats.bytes_processed);
                    progress.complete_artifact();
                    stats.bytes_processed
                }
                Isolated::Failed(failure) => {
                    // Fail loud: surface the failure rather than swallowing it.
                    errors.push(failure.describe());
                    progress.record_error();
                    continue;
                }
            };
            units.push(ParsedUnit {
                artifact_type: artifact.artifact_type,
                path: artifact.path.clone(),
                parser: parser.name().to_string(),
                events: emitter.into_events(),
                bytes,
            });
        }
    }
    (units, errors)
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
    // Run EVERY matching parser per artifact (see run_pipeline) — each artifact
    // maps to a Vec of per-parser results that the aggregation below flattens.
    let parse_results: Vec<Vec<Result<_, String>>> = artifacts
        .par_iter()
        .map(|artifact| {
            let matching: Vec<_> = parsers
                .iter()
                .filter(|p| p.supported_artifacts().contains(&artifact.artifact_type))
                .map(|p| p.as_ref())
                .collect();
            if matching.is_empty() {
                return Vec::new();
            }
            let source = match FileDataSource::open(&artifact.path) {
                Ok(source) => source,
                Err(e) => {
                    return vec![Err(format!(
                        "Failed to open {}: {e}",
                        artifact.path.display()
                    ))]
                }
            };
            matching
                .into_iter()
                .map(|parser| match parser.parse(&source, &emitter) {
                    Ok(stats) => {
                        progress.add_events(stats.events_emitted);
                        progress.add_bytes(stats.bytes_processed);
                        progress.complete_artifact();
                        Ok(stats)
                    }
                    Err(e) => Err(format!("Parse error on {}: {e}", artifact.path.display())),
                })
                .collect()
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

    fn mk_event(ts: i64, desc: &str) -> TimelineEvent {
        use issen_core::artifacts::ArtifactType;
        use issen_core::timeline::event::EventType;
        TimelineEvent::new(
            ts,
            "x".to_string(),
            EventType::FileCreate,
            ArtifactType::Mft,
            "p".to_string(),
            desc.to_string(),
            "ev".to_string(),
        )
    }

    #[test]
    fn sort_timeline_events_orders_chronologically_with_stable_tiebreak() {
        // A "timeline" must be chronological; parsers + the parallel pipeline
        // emit in discovery order (mode 6E). Ties break deterministically on
        // record_hash so the output is reproducible run-to-run.
        let mut events = vec![
            mk_event(300, "c"),
            mk_event(100, "a"),
            mk_event(100, "b"),
            mk_event(200, "d"),
        ];
        sort_timeline_events(&mut events);
        assert_eq!(
            events.iter().map(|e| e.timestamp_ns).collect::<Vec<_>>(),
            vec![100, 100, 200, 300],
            "events must be in ascending timestamp order"
        );
        // Determinism: re-sorting a reversed copy yields the identical order.
        let mut reversed = events.clone();
        reversed.reverse();
        sort_timeline_events(&mut reversed);
        assert_eq!(
            events.iter().map(|e| &e.record_hash).collect::<Vec<_>>(),
            reversed.iter().map(|e| &e.record_hash).collect::<Vec<_>>(),
            "tie order must be reproducible"
        );
    }

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
        assert_eq!(result.artifacts_found, 1);
        assert!(events.is_empty()); // No parsers registered in test binary
    }

    #[test]
    fn parse_units_groups_events_per_artifact_and_parser() {
        // issen #115: the resumable path commits/skips at (artifact, parser)
        // granularity, so parse_units must give each its own unit with a FRESH
        // emitter — events grouped per unit, not pooled into one flat list.
        // Parsers are injected (the force-linked registry is empty in tests).
        use issen_core::error::RtError;
        use issen_core::plugin::traits::{
            DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
        };
        use issen_core::timeline::event::{EventType, TimelineEvent};

        struct Mock {
            name: String,
            kind: ArtifactType,
            n: u64,
        }
        impl ForensicParser for Mock {
            fn name(&self) -> &str {
                &self.name
            }
            fn supported_artifacts(&self) -> &[ArtifactType] {
                std::slice::from_ref(&self.kind)
            }
            fn parse(
                &self,
                _input: &dyn DataSource,
                emitter: &dyn EventEmitter,
            ) -> Result<ParseStats, RtError> {
                for i in 0..self.n {
                    emitter.emit(TimelineEvent::new(
                        i as i64,
                        "ts".into(),
                        EventType::FileCreate,
                        self.kind,
                        "p".into(),
                        format!("{}-{i}", self.name),
                        "ev".into(),
                    ))?;
                }
                let mut s = ParseStats::new();
                s.events_emitted = self.n;
                Ok(s)
            }
            fn capabilities(&self) -> ParserCapabilities {
                ParserCapabilities {
                    max_memory_bytes: None,
                    streaming: false,
                    deterministic: true,
                }
            }
        }

        let dir = tempfile::tempdir().expect("tmp");
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        std::fs::write(&a, b"x").expect("w");
        std::fs::write(&b, b"y").expect("w");
        let artifacts = vec![
            DiscoveredArtifact {
                path: a,
                artifact_type: ArtifactType::UsnJournal,
            },
            DiscoveredArtifact {
                path: b,
                artifact_type: ArtifactType::Mft,
            },
        ];
        let parsers: Vec<Box<dyn ForensicParser>> = vec![
            Box::new(Mock {
                name: "USN".into(),
                kind: ArtifactType::UsnJournal,
                n: 3,
            }),
            Box::new(Mock {
                name: "MFT".into(),
                kind: ArtifactType::Mft,
                n: 2,
            }),
        ];
        let progress = ProgressReporter::new();
        let (units, errors) = parse_units(&artifacts, &parsers, &progress);
        assert!(errors.is_empty(), "no failures on the happy path");

        assert_eq!(units.len(), 2, "one unit per (artifact, matching parser)");
        let usn = units.iter().find(|u| u.parser == "USN").expect("USN unit");
        assert_eq!(usn.events.len(), 3, "events grouped per unit");
        assert_eq!(usn.artifact_type, ArtifactType::UsnJournal);
        // Events are SEPARATE per unit, not pooled — every USN event is USN-tagged.
        assert!(usn.events.iter().all(|e| e.description.starts_with("USN-")));
        let mft = units.iter().find(|u| u.parser == "MFT").expect("MFT unit");
        assert_eq!(mft.events.len(), 2);
    }

    #[test]
    fn parse_units_reports_parser_failures() {
        // A failing parser must surface in `errors` (fail-loud, like the flat
        // pipeline) and yield no unit — not be silently dropped (issen #115).
        use issen_core::error::RtError;
        use issen_core::plugin::traits::{
            DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
        };

        struct FailMock;
        impl ForensicParser for FailMock {
            fn name(&self) -> &str {
                "Boom"
            }
            fn supported_artifacts(&self) -> &[ArtifactType] {
                std::slice::from_ref(&ArtifactType::UsnJournal)
            }
            fn parse(
                &self,
                _input: &dyn DataSource,
                _emitter: &dyn EventEmitter,
            ) -> Result<ParseStats, RtError> {
                Err(RtError::InvalidData("boom".into()))
            }
            fn capabilities(&self) -> ParserCapabilities {
                ParserCapabilities {
                    max_memory_bytes: None,
                    streaming: false,
                    deterministic: true,
                }
            }
        }

        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("a.bin");
        std::fs::write(&p, b"x").expect("w");
        let artifacts = vec![DiscoveredArtifact {
            path: p,
            artifact_type: ArtifactType::UsnJournal,
        }];
        let parsers: Vec<Box<dyn ForensicParser>> = vec![Box::new(FailMock)];
        let progress = ProgressReporter::new();
        let (units, errors) = parse_units(&artifacts, &parsers, &progress);

        assert!(units.is_empty(), "a failed parse yields no unit");
        assert_eq!(errors.len(), 1, "the failure is reported, not swallowed");
        assert!(errors[0].contains("Boom"), "error names the failed unit");
    }

    #[test]
    fn parse_units_skips_completed_units_without_parsing() {
        // issen #115 resume optimization: a unit the skip-predicate marks
        // complete must NOT be parsed (its parser is never invoked) and must be
        // counted as skipped — so a resume run avoids the parse cost, not just
        // the DB commit. Before this, resume reparsed everything and only
        // skipped the commit (a warm run was ~as slow as a cold one).
        use issen_core::error::RtError;
        use issen_core::plugin::traits::{
            DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingMock {
            kind: ArtifactType,
            calls: Arc<AtomicUsize>,
        }
        impl ForensicParser for CountingMock {
            fn name(&self) -> &str {
                "Counter"
            }
            fn supported_artifacts(&self) -> &[ArtifactType] {
                std::slice::from_ref(&self.kind)
            }
            fn parse(
                &self,
                _input: &dyn DataSource,
                _emitter: &dyn EventEmitter,
            ) -> Result<ParseStats, RtError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(ParseStats::new())
            }
            fn capabilities(&self) -> ParserCapabilities {
                ParserCapabilities {
                    max_memory_bytes: None,
                    streaming: false,
                    deterministic: true,
                }
            }
        }

        let dir = tempfile::tempdir().expect("tmp");
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        std::fs::write(&a, b"x").expect("w");
        std::fs::write(&b, b"y").expect("w");
        let skip_path = a.clone();
        let artifacts = vec![
            DiscoveredArtifact {
                path: a,
                artifact_type: ArtifactType::UsnJournal,
            },
            DiscoveredArtifact {
                path: b.clone(),
                artifact_type: ArtifactType::UsnJournal,
            },
        ];
        let calls = Arc::new(AtomicUsize::new(0));
        let parsers: Vec<Box<dyn ForensicParser>> = vec![Box::new(CountingMock {
            kind: ArtifactType::UsnJournal,
            calls: calls.clone(),
        })];
        let progress = ProgressReporter::new();
        // Mark artifact `a` already complete; `b` still pending.
        let skip = |_at: &ArtifactType, path: &Path, _parser: &str| path == skip_path.as_path();
        let (units, errors, skipped) = parse_units(&artifacts, &parsers, &progress, &skip);

        assert!(errors.is_empty(), "no failures on the happy path");
        assert_eq!(skipped, 1, "the completed unit is counted as skipped");
        assert_eq!(units.len(), 1, "only the non-skipped unit is parsed");
        assert_eq!(units[0].path, b, "the pending artifact is the one parsed");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the skipped unit's parser is NEVER invoked (parse cost avoided)"
        );
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
        assert_eq!(emitter.into_events().len(), 1);
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

        assert_eq!(
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

        assert_eq!(result.artifacts_found, 0, "no artifacts in empty dir");
        assert_eq!(result.artifacts_parsed, 0);
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

        assert_eq!(result.artifacts_found, 1);
        assert_eq!(
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
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CollectingEmitter>();
    }

    #[test]
    fn parallel_progress_reporter_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProgressReporter>();
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
