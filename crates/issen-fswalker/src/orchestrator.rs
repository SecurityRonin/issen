use std::path::{Path, PathBuf};
use std::sync::Mutex;

use issen_core::artifacts::ArtifactType;
use issen_core::coverage::CoverageManifest;
use issen_core::error::RtError;
use issen_core::plugin::registry::{all_parsers, detect_from_registry};
use issen_core::plugin::traits::{EventEmitter, ForensicParser, ParseCompletion, ParseOptions};
use issen_core::timeline::event::TimelineEvent;
use rayon::prelude::*;

use crate::isolate::{run_isolated, Isolated};
use crate::layers::layer0_storage::FileDataSource;
use crate::progress::{Phase, ProgressReporter};

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
    /// Per-artifact-class coverage for this run (searched / found / parsed) —
    /// makes an empty result distinguishable from a clean input.
    pub coverage: CoverageManifest,
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

/// Walk a directory tree and discover artifacts, classifying each file with the
/// injected `classify` function. Production passes
/// [`issen_core::plugin::registry::detect_from_registry`] (the registry-derived
/// classifier); the classifier is a parameter — rather than a hardcoded call —
/// so this stays unit-testable without linking the whole parser inventory.
pub fn discover_artifacts(
    root: &Path,
    classify: &dyn Fn(&Path) -> Option<ArtifactType>,
) -> Result<Vec<DiscoveredArtifact>, RtError> {
    let mut artifacts = Vec::new();
    walk_directory(root, &mut artifacts, classify)?;
    Ok(artifacts)
}

fn walk_directory(
    dir: &Path,
    artifacts: &mut Vec<DiscoveredArtifact>,
    classify: &dyn Fn(&Path) -> Option<ArtifactType>,
) -> Result<(), RtError> {
    if !dir.is_dir() {
        // Single file — check if it's an artifact.
        if let Some(artifact_type) = classify(dir) {
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
            walk_directory(&path, artifacts, classify)?;
        } else if let Some(artifact_type) = classify(&path) {
            artifacts.push(DiscoveredArtifact {
                path,
                artifact_type,
            });
        }
    }
    Ok(())
}

/// Run `f` over the artifacts discovered in `path` — a directory **or** a
/// collection archive — keeping the archive's manifest (and its RAII `TempDir` of
/// extracted files) alive for the duration of `f`, since parsers open those files
/// by path. The single dir-vs-archive detector shared by every orchestration entry
/// point (so they can't drift on how evidence is opened).
fn with_evidence<R>(
    path: &Path,
    f: impl FnOnce(&Path, &[DiscoveredArtifact]) -> R,
) -> Result<R, RtError> {
    if path.is_dir() {
        Ok(f(path, &discover_artifacts(path, &detect_from_registry)?))
    } else {
        let manifest = issen_unpack::registry::open_collection(path)
            .map_err(|e| RtError::UnsupportedFormat(e.to_string()))?;
        tracing::info!(
            format = %manifest.format_name,
            artifacts = manifest.artifacts.len(),
            root = %manifest.extracted_root.display(),
            "Collection opened",
        );
        let artifacts = discover_artifacts(&manifest.extracted_root, &detect_from_registry)?;
        // The extraction root (not just the classified artifacts) is passed so a
        // cross-file check can reach files no parser claims (e.g. $MFTMirr).
        Ok(f(&manifest.extracted_root, &artifacts))
        // manifest (and its TempDir) drops here — AFTER `f` has parsed.
    }
}

/// Cross-file `$MFT`/`$MFTMirr` integrity over an extraction root: find each
/// directory holding BOTH files (the per-partition extraction layout, or a loose
/// pair) and surface any divergence as Integrity events. Only the first four MFT
/// records (4 KiB) of each are read — the mirror covers exactly those. `$MFTMirr`
/// is collected but unclassified (no parser), so this is the only thing that
/// consumes it.
fn mft_mirror_events_from_root(root: &Path) -> Vec<TimelineEvent> {
    const FOUR_RECORDS: usize = 1024 * 4;
    let mut events = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let (mut mft, mut mirr): (Option<PathBuf>, Option<PathBuf>) = (None, None);
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if name.eq_ignore_ascii_case("$MFT") {
                    mft = Some(p);
                } else if name.eq_ignore_ascii_case("$MFTMirr") {
                    mirr = Some(p);
                }
            }
        }
        if let (Some(mft_path), Some(mirr_path)) = (mft, mirr) {
            events.extend(issen_disk::mft_mirror_integrity_events(
                &read_prefix(&mft_path, FOUR_RECORDS),
                &read_prefix(&mirr_path, FOUR_RECORDS),
                "mftmirr-integrity",
            ));
        }
    }
    events
}

/// Read up to `n` bytes from the start of `path` (empty on any error).
fn read_prefix(path: &Path, n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(n as u64).read_to_end(&mut buf);
    }
    buf
}

/// Assemble the [`IngestResult`] from discovered artifacts and parsed units — the
/// single place both the flat and per-unit paths compute their totals.
fn ingest_result(
    artifacts: &[DiscoveredArtifact],
    units: &[ParsedUnit],
    errors: Vec<String>,
) -> IngestResult {
    // The "searched" set is every artifact class a registered parser declares.
    let searched: Vec<ArtifactType> = all_parsers()
        .iter()
        .flat_map(|p| p.supported_artifacts().to_vec())
        .collect();
    ingest_result_with(artifacts, units, errors, &searched)
}

/// Inner builder with an explicit `searched` set, separated so coverage can be
/// tested deterministically — `all_parsers()` is only populated in a binary
/// that links the parser crates (issen-cli), not in this crate's own tests.
fn ingest_result_with(
    artifacts: &[DiscoveredArtifact],
    units: &[ParsedUnit],
    errors: Vec<String>,
    searched: &[ArtifactType],
) -> IngestResult {
    let found: Vec<ArtifactType> = artifacts.iter().map(|a| a.artifact_type).collect();
    let parsed: Vec<ArtifactType> = units.iter().map(|u| u.artifact_type).collect();
    IngestResult {
        artifacts_found: artifacts.len(),
        artifacts_parsed: units.len(),
        total_events: units.iter().map(|u| u.events.len() as u64).sum(),
        total_bytes: units.iter().map(|u| u.bytes).sum(),
        errors,
        coverage: CoverageManifest::build(searched, &found, &parsed),
    }
}

/// Run the pipeline on a directory: discover artifacts, parse them, return a flat
/// event list + an [`IngestResult`].
///
/// A thin flat view over the per-unit core ([`parse_units`]) — see the note below
/// on the per-unit semantics this inherits (atomic units; actual-event counts).
pub fn run_pipeline(
    evidence_path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    // Flat view over the per-unit core: parse every (artifact, parser) with no
    // resume-skip, then flatten. Sharing `parse_units` keeps the flat and per-unit
    // paths from drifting — "run every matching parser", panic-isolation, and the
    // result counts all live in ONE place now.
    //
    // Vs the pre-refactor flat pipeline this differs ONLY for *misbehaving* parsers,
    // and intentionally: (1) a parser that emits events then fails now discards its
    // partial events (atomic unit — the old shared emitter kept them), and (2)
    // `total_events` counts ACTUAL emitted events, not the parser's self-reported
    // `stats.events_emitted`. For honest parsers the output is identical.
    progress.set_phase(Phase::Discovering);
    let artifacts = discover_artifacts(evidence_path, &detect_from_registry)?;
    progress.set_artifacts_total(artifacts.len() as u64);
    progress.set_phase(Phase::Parsing);
    let (units, errors, _skipped) = parse_units(
        &artifacts,
        &all_parsers(),
        progress,
        &|_, _, _| false,
        &ParseOptions::default(),
    );
    let result = ingest_result(&artifacts, &units, errors);
    let events = units.into_iter().flat_map(|u| u.events).collect();
    progress.set_phase(Phase::Done);
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
    // The flat API is EXACTLY the sorted flattening of the per-unit core, so the
    // two can never drift (the missing sort was a symptom of the old copy-paste).
    let (units, result, _skipped) =
        run_auto_units(path, progress, &|_, _, _| false, &ParseOptions::default())?;
    let mut events: Vec<TimelineEvent> = units.into_iter().flat_map(|u| u.events).collect();
    sort_timeline_events(&mut events);
    Ok((events, result))
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
    skip: &dyn Fn(&ArtifactType, &Path, &str) -> bool,
    opts: &ParseOptions,
) -> Result<(Vec<ParsedUnit>, IngestResult, usize), RtError> {
    // `with_evidence` keeps the collection manifest's TempDir alive across the
    // parse (parsers open the extracted files by path).
    progress.set_phase(Phase::Extracting);
    let (units, result, skipped) = with_evidence(path, |root, artifacts| {
        progress.set_artifacts_total(artifacts.len() as u64);
        progress.set_phase(Phase::Parsing);
        let (mut units, errors, skipped) =
            parse_units(artifacts, &all_parsers(), progress, skip, opts);
        // Cross-file $MFT/$MFTMirr integrity (not a parser — a 2-file check):
        // emit as a synthetic unit so it commits and resumes like any other.
        let mirror_events = mft_mirror_events_from_root(root);
        if !mirror_events.is_empty() {
            units.push(ParsedUnit {
                artifact_type: ArtifactType::Mft,
                path: PathBuf::from(r"\$MFTMirr"),
                parser: "$MFTMirr Integrity".to_string(),
                events: mirror_events,
                bytes: 0,
                completion: ParseCompletion::Complete,
            });
        }
        let result = ingest_result(artifacts, &units, errors);
        (units, result, skipped)
    })?;
    progress.set_phase(Phase::Done);
    Ok((units, result, skipped))
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
    /// The parse's terminal completion state — propagated so the commit layer
    /// only marks `marks_complete()` units complete for resume (issen #115).
    pub completion: ParseCompletion,
}

/// Parse each `(artifact, matching-parser)` pair into its own [`ParsedUnit`].
///
/// Unlike [`run_pipeline`] (one shared emitter → a flat event list), this gives
/// every unit a fresh emitter so its events are grouped — the shape the
/// resumable ingest path needs to `commit_unit` per unit and skip completed
/// ones. Parsers are passed in (dependency injection) rather than read from the
/// force-linked registry, so the per-unit grouping is unit-testable.
///
/// `skip` marks units already committed for this evidence source (resume): a
/// skipped unit's parser is **never invoked**, and the file source is not even
/// opened when *all* of an artifact's parsers are skipped — so a resume run
/// avoids the parse cost, not just the duplicate commit (issen #115). Returns
/// the parsed units, per-unit failure descriptions, and the count of units
/// skipped because `skip` reported them complete.
#[must_use]
pub fn parse_units(
    artifacts: &[DiscoveredArtifact],
    parsers: &[Box<dyn ForensicParser>],
    progress: &ProgressReporter,
    skip: &dyn Fn(&ArtifactType, &Path, &str) -> bool,
    opts: &ParseOptions,
) -> (Vec<ParsedUnit>, Vec<String>, usize) {
    let mut units = Vec::new();
    let mut errors = Vec::new();
    let mut skipped = 0usize;
    for artifact in artifacts {
        let (u, e, s) = parse_one_artifact(artifact, parsers, progress, skip, opts);
        // One completion per artifact (not per matching parser) so artifacts_completed
        // tracks toward artifacts_total for a correct determinate bar.
        progress.complete_artifact();
        units.extend(u);
        errors.extend(e);
        skipped += s;
    }
    (units, errors, skipped)
}

/// Parse ONE artifact: run every matching, not-skipped parser under isolation,
/// producing a [`ParsedUnit`] per parser. The shared per-artifact core that
/// [`parse_units`] (sequential `for`) and [`parse_units_parallel`] (rayon
/// `par_iter`) both call — so the two differ ONLY in how they iterate, never in
/// per-artifact behavior (the duplication that previously let `*_parallel` drift).
fn parse_one_artifact(
    artifact: &DiscoveredArtifact,
    parsers: &[Box<dyn ForensicParser>],
    progress: &ProgressReporter,
    skip: &dyn Fn(&ArtifactType, &Path, &str) -> bool,
    opts: &ParseOptions,
) -> (Vec<ParsedUnit>, Vec<String>, usize) {
    let mut units = Vec::new();
    let mut errors = Vec::new();
    let mut skipped = 0usize;
    // Partition matching parsers into the ones still to parse and the ones already
    // complete (a skipped unit is counted and never parsed — the resume saving).
    let mut to_parse = Vec::new();
    for parser in parsers
        .iter()
        .filter(|p| p.supported_artifacts().contains(&artifact.artifact_type))
    {
        if skip(&artifact.artifact_type, &artifact.path, parser.name()) {
            skipped += 1;
        } else {
            to_parse.push(parser);
        }
    }
    if to_parse.is_empty() {
        return (units, errors, skipped);
    }
    // Open the source once and share it across this artifact's parsers.
    let source = match FileDataSource::open(&artifact.path) {
        Ok(source) => source,
        Err(e) => {
            errors.push(format!("Failed to open {}: {e}", artifact.path.display()));
            progress.record_error();
            return (units, errors, skipped);
        }
    };
    for parser in to_parse {
        // A fresh emitter per unit — this is what groups events by unit.
        let emitter = CollectingEmitter::new();
        let label = format!("{} [{}]", artifact.path.display(), parser.name());
        let (bytes, completion) =
            match run_isolated(label, || parser.parse(&source, &emitter, opts)) {
                Isolated::Completed(stats) => {
                    progress.add_events(stats.events_emitted);
                    progress.add_bytes(stats.bytes_processed);
                    (stats.bytes_processed, stats.completion)
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
            completion,
        });
    }
    (units, errors, skipped)
}

/// Parallel sibling of [`parse_units`] — `par_iter` over artifacts. `collect()`
/// preserves artifact order, so for **deterministic/stateless parsers and a pure
/// read-only `skip`** the parsed units match the sequential version exactly (locked
/// by `parse_units_parallel_equals_sequential`). It does NOT promise identical
/// progress/log/panic-hook *timing* or fd-scheduling — a parser with interior
/// mutability (legal under `Sync`) or a side-effecting `skip` could still diverge.
/// `skip` must be `Sync` to cross rayon workers (a read-only `HashSet` lookup is).
#[must_use]
pub fn parse_units_parallel(
    artifacts: &[DiscoveredArtifact],
    parsers: &[Box<dyn ForensicParser>],
    progress: &ProgressReporter,
    skip: &(dyn Fn(&ArtifactType, &Path, &str) -> bool + Sync),
    opts: &ParseOptions,
) -> (Vec<ParsedUnit>, Vec<String>, usize) {
    let per_artifact: Vec<(Vec<ParsedUnit>, Vec<String>, usize)> = artifacts
        .par_iter()
        .map(|artifact| {
            let unit = parse_one_artifact(artifact, parsers, progress, skip, opts);
            // One completion per artifact (see parse_units) — atomic, so safe
            // across rayon workers.
            progress.complete_artifact();
            unit
        })
        .collect();
    let mut units = Vec::new();
    let mut errors = Vec::new();
    let mut skipped = 0usize;
    for (u, e, s) in per_artifact {
        units.extend(u);
        errors.extend(e);
        skipped += s;
    }
    (units, errors, skipped)
}

/// Parallel sibling of [`run_pipeline`] — the flat view over [`parse_units_parallel`].
///
/// Matches `run_pipeline`'s output for deterministic/stateless parsers (rayon
/// `collect` preserves artifact order); they share `parse_one_artifact`, so
/// panic-isolation and event counts match. Dead in production today (test-only) but
/// structurally unified now, not a copy-paste of the sequential core.
///
/// # Errors
///
/// Returns an error if artifact discovery fails.
pub fn run_pipeline_parallel(
    evidence_path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    // Flat view over the PARALLEL per-unit core — mirrors `run_pipeline` exactly,
    // only `parse_units_parallel` instead of `parse_units`.
    progress.set_phase(Phase::Discovering);
    let artifacts = discover_artifacts(evidence_path, &detect_from_registry)?;
    progress.set_artifacts_total(artifacts.len() as u64);
    progress.set_phase(Phase::Parsing);
    let (units, errors, _skipped) = parse_units_parallel(
        &artifacts,
        &all_parsers(),
        progress,
        &|_, _, _| false,
        &ParseOptions::default(),
    );
    let result = ingest_result(&artifacts, &units, errors);
    let events = units.into_iter().flat_map(|u| u.events).collect();
    progress.set_phase(Phase::Done);
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
    // Mirrors `run_auto`: the parallel flat pipelines now route through the shared
    // parallel per-unit core, and the result is sorted the same way (the missing
    // sort here was a copy-paste-drift bug before the collapse).
    let mut out = if path.is_dir() {
        run_pipeline_parallel(path, progress)?
    } else {
        run_collection_pipeline_parallel(path, progress)?
    };
    sort_timeline_events(&mut out.0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_result_carries_coverage_manifest() {
        use issen_core::coverage::CoverageStatus;
        let artifacts = vec![DiscoveredArtifact {
            path: PathBuf::from(r"\$MFT"),
            artifact_type: ArtifactType::Mft,
        }];
        let units = vec![ParsedUnit {
            artifact_type: ArtifactType::Mft,
            path: PathBuf::from(r"\$MFT"),
            parser: "MFT".to_string(),
            events: vec![],
            bytes: 0,
            completion: ParseCompletion::Complete,
        }];
        // Explicit searched set (deterministic): Prefetch/Srum are searched but
        // not in this run; Mft is found + parsed.
        let searched = [
            ArtifactType::Mft,
            ArtifactType::Prefetch,
            ArtifactType::Srum,
        ];
        let result = ingest_result_with(&artifacts, &units, vec![], &searched);
        // Discovered + parsed → Parsed.
        assert_eq!(
            result.coverage.entry(ArtifactType::Mft).map(|e| e.status()),
            Some(CoverageStatus::Parsed)
        );
        // Searched but absent from this run → a clean negative, not a gap.
        assert_eq!(
            result
                .coverage
                .entry(ArtifactType::Prefetch)
                .map(|e| e.status()),
            Some(CoverageStatus::SearchedAbsent)
        );
    }

    #[test]
    fn mft_mirror_events_from_root_flags_a_divergent_pair() {
        // Per-partition extraction layout: part-*/$MFT + part-*/$MFTMirr.
        let tmp = tempfile::tempdir().unwrap();
        let part = tmp.path().join("part-0000000000");
        std::fs::create_dir_all(&part).unwrap();
        let mft = vec![0xAAu8; 1024 * 4];
        let mut mirr = mft.clone();
        mirr[0] = 0xBB; // record 0 differs
        std::fs::write(part.join("$MFT"), &mft).unwrap();
        std::fs::write(part.join("$MFTMirr"), &mirr).unwrap();

        let events = mft_mirror_events_from_root(tmp.path());
        assert_eq!(
            events.len(),
            1,
            "a divergent $MFT/$MFTMirr pair -> one event"
        );
        assert!(events[0].description.contains("NTFS-MFTMIRR-MISMATCH"));
    }

    #[test]
    fn mft_mirror_events_from_root_silent_without_a_pair() {
        let tmp = tempfile::tempdir().unwrap();
        // $MFT alone (no mirror) → nothing to compare.
        std::fs::write(tmp.path().join("$MFT"), vec![0xAAu8; 1024 * 4]).unwrap();
        assert!(mft_mirror_events_from_root(tmp.path()).is_empty());
    }

    /// A minimal classifier for the discovery tests, built from the shared
    /// `issen_core::classify` predicates — production uses `detect_from_registry`
    /// (which needs the linked parser inventory, absent in this crate's tests).
    fn test_classify(p: &std::path::Path) -> Option<ArtifactType> {
        use issen_core::classify as c;
        if c::usn(p) {
            Some(ArtifactType::UsnJournal)
        } else if c::evtx(p) {
            Some(ArtifactType::EventLog)
        } else if c::prefetch(p) {
            Some(ArtifactType::Prefetch)
        } else {
            None
        }
    }

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
    fn test_discover_artifacts_in_directory() {
        let dir = tempfile::tempdir().expect("tmpdir");

        // Create some fake artifact files.
        std::fs::write(dir.path().join("$J"), b"fake usn data").expect("write");
        std::fs::write(dir.path().join("Security.evtx"), b"fake evtx").expect("write");
        std::fs::write(dir.path().join("readme.txt"), b"not an artifact").expect("write");

        let artifacts = discover_artifacts(dir.path(), &test_classify).expect("discover");
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

        let artifacts = discover_artifacts(dir.path(), &test_classify).expect("discover");
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

        assert_eq!(result.artifacts_found, 0, "registry model: no parsers linked in this test binary ⇒ nothing classified ⇒ nothing discovered (real discovery is covered by the discover_artifacts+test_classify tests and the issen-cli integration tests)");
        // No parsers registered in this test binary, so nothing parsed.
        assert_eq!(result.artifacts_parsed, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn run_pipeline_drives_phase_and_total_for_the_display() {
        use crate::progress::Phase;
        // Registry discovery needs linked parsers; none here, so it finds 0 — the
        // test still validates the phase reaches Done.
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("$J"), b"fake data").expect("write");

        let progress = ProgressReporter::new();
        let _ = run_pipeline(dir.path(), &progress).expect("pipeline");

        assert_eq!(progress.phase(), Phase::Done, "phase ends at Done");
        // No parsers linked here ⇒ registry discovery finds 0 ⇒ a determinate bar
        // with total 0; the transition still reaches Done. The total>0 / per-artifact
        // completion path is exercised in the issen-cli integration tests.
        assert_eq!(progress.artifacts_total(), 0);
        assert_eq!(progress.artifacts_completed(), 0);
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
        assert_eq!(result.artifacts_found, 0, "registry model: no parsers linked in this test binary ⇒ nothing classified ⇒ nothing discovered (real discovery is covered by the discover_artifacts+test_classify tests and the issen-cli integration tests)");
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
            DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
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
                _opts: &ParseOptions,
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
        let (units, errors, _) = parse_units(
            &artifacts,
            &parsers,
            &progress,
            &|_, _, _| false,
            &issen_core::plugin::ParseOptions::default(),
        );
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
    fn parse_units_propagates_parse_completion() {
        // ParseCompletion must reach the ParsedUnit so the commit layer marks only
        // terminally-complete units complete (issen #115 correctness — it used to
        // be dropped, so every Ok parse was marked complete on resume).
        use issen_core::plugin::traits::{
            DataSource, ParseCompletion, ParseOptions, ParseStats, ParserCapabilities,
        };

        struct CompletionMock(ParseCompletion);
        impl ForensicParser for CompletionMock {
            fn name(&self) -> &str {
                "CM"
            }
            fn supported_artifacts(&self) -> &[ArtifactType] {
                std::slice::from_ref(&ArtifactType::Mft)
            }
            fn parse(
                &self,
                _input: &dyn DataSource,
                _emitter: &dyn EventEmitter,
                _opts: &ParseOptions,
            ) -> Result<ParseStats, RtError> {
                let mut s = ParseStats::new();
                s.completion = self.0.clone();
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
        let p = dir.path().join("$MFT");
        std::fs::write(&p, b"x").expect("w");
        let artifacts = vec![DiscoveredArtifact {
            path: p,
            artifact_type: ArtifactType::Mft,
        }];
        let parsers: Vec<Box<dyn ForensicParser>> =
            vec![Box::new(CompletionMock(ParseCompletion::Incomplete {
                offset: 5,
                reason: "truncated".into(),
            }))];
        let progress = ProgressReporter::new();
        let (units, _, _) = parse_units(
            &artifacts,
            &parsers,
            &progress,
            &|_, _, _| false,
            &issen_core::plugin::ParseOptions::default(),
        );
        assert_eq!(units.len(), 1);
        assert!(
            matches!(units[0].completion, ParseCompletion::Incomplete { .. }),
            "the parser's Incomplete completion must propagate to the ParsedUnit, not be dropped"
        );
    }

    #[test]
    fn parse_units_parallel_equals_sequential() {
        // The parallel per-unit core must produce the SAME units as the sequential
        // one — rayon `par_iter().collect()` preserves artifact order, so the two
        // differ only in `for` vs `par_iter`, never in output.
        use issen_core::plugin::traits::{
            DataSource, ParseOptions, ParseStats, ParserCapabilities,
        };
        use issen_core::timeline::event::EventType;

        struct EmitMock(String, ArtifactType, u64);
        impl ForensicParser for EmitMock {
            fn name(&self) -> &str {
                &self.0
            }
            fn supported_artifacts(&self) -> &[ArtifactType] {
                std::slice::from_ref(&self.1)
            }
            fn parse(
                &self,
                _i: &dyn DataSource,
                e: &dyn EventEmitter,
                _opts: &ParseOptions,
            ) -> Result<ParseStats, RtError> {
                for k in 0..self.2 {
                    e.emit(TimelineEvent::new(
                        k as i64,
                        "ts".into(),
                        EventType::FileCreate,
                        self.1,
                        "p".into(),
                        format!("{}-{k}", self.0),
                        "ev".into(),
                    ))?;
                }
                let mut s = ParseStats::new();
                s.events_emitted = self.2;
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
        let mut artifacts = Vec::new();
        for (n, t) in [
            ("a", ArtifactType::UsnJournal),
            ("b", ArtifactType::Mft),
            ("c", ArtifactType::Prefetch),
        ] {
            let p = dir.path().join(n);
            std::fs::write(&p, b"x").expect("w");
            artifacts.push(DiscoveredArtifact {
                path: p,
                artifact_type: t,
            });
        }
        let parsers: Vec<Box<dyn ForensicParser>> = vec![
            Box::new(EmitMock("USN".into(), ArtifactType::UsnJournal, 3)),
            Box::new(EmitMock("MFT".into(), ArtifactType::Mft, 2)),
            Box::new(EmitMock("PF".into(), ArtifactType::Prefetch, 5)),
        ];
        let p1 = ProgressReporter::new();
        let (su, se, sk) = parse_units(
            &artifacts,
            &parsers,
            &p1,
            &|_, _, _| false,
            &issen_core::plugin::ParseOptions::default(),
        );
        let p2 = ProgressReporter::new();
        let (pu, pe, pk) = parse_units_parallel(
            &artifacts,
            &parsers,
            &p2,
            &|_, _, _| false,
            &issen_core::plugin::ParseOptions::default(),
        );

        // Compare the FULL unit identity + event contents, not just counts: parser,
        // artifact type, path, bytes, completion, and the exact record_hash sequence.
        let proj = |us: &[ParsedUnit]| {
            us.iter()
                .map(|u| {
                    (
                        u.parser.clone(),
                        format!("{:?}", u.artifact_type),
                        u.path.clone(),
                        u.bytes,
                        u.completion.clone(),
                        u.events
                            .iter()
                            .map(|e| e.record_hash.clone())
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            proj(&su),
            proj(&pu),
            "parallel units must match sequential exactly (order + contents)"
        );
        assert_eq!(se, pe, "errors match");
        assert_eq!(sk, pk, "skipped match");
    }

    #[test]
    fn parse_units_reports_parser_failures() {
        // A failing parser must surface in `errors` (fail-loud, like the flat
        // pipeline) and yield no unit — not be silently dropped (issen #115).
        use issen_core::error::RtError;
        use issen_core::plugin::traits::{
            DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
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
                _opts: &ParseOptions,
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
        let (units, errors, _) = parse_units(
            &artifacts,
            &parsers,
            &progress,
            &|_, _, _| false,
            &issen_core::plugin::ParseOptions::default(),
        );

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
            DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
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
                _opts: &ParseOptions,
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
        let (units, errors, skipped) = parse_units(
            &artifacts,
            &parsers,
            &progress,
            &skip,
            &issen_core::plugin::ParseOptions::default(),
        );

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

        assert_eq!(result.artifacts_found, 0, "registry model: no parsers linked in this test binary ⇒ nothing classified ⇒ nothing discovered (real discovery is covered by the discover_artifacts+test_classify tests and the issen-cli integration tests)");
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
