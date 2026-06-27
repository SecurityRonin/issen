//! `issen <evidence…>` — the resumable bare front door.
//!
//! Classifies evidence (disk vs memory), computes per-stage input fingerprints,
//! opens the deterministic case DB, and drives [`crate::pipeline::run_bare`] with
//! a [`RealExecutor`] that calls the existing ingest / memory / correlate stages.
//! Re-running on the same evidence resumes from the first incomplete/stale stage.
//!
//! Each stage prints a labelled banner and a live spinner with an elapsed timer,
//! on top of the underlying commands' own progress, so a long stage never reads
//! as stalled. See `docs/cli-unified-frontdoor-spec.md`.

use std::collections::{HashMap, HashSet};
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use indicatif::{ProgressBar, ProgressStyle};
use issen_timeline::store::TimelineStore;

use crate::commands;
use crate::pipeline::{self, EvidenceKind, Flags, RunReport, Stage, StageExecutor};

/// Worker bars to show during the correlate stage: one per concurrently-running
/// correlation rule — the 8 disk-leg rules plus the memory-leg group (see
/// `issen_correlation::runner::run_correlations_with_memory_progress`).
const CORRELATE_RULE_SLOTS: usize = 9;

/// Human label for a stage banner.
fn stage_label(stage: Stage) -> &'static str {
    match stage {
        Stage::Ingest => "Ingest — parse disk artifacts into the timeline",
        Stage::Memory => "Memory — parse dumps into the timeline",
        Stage::Correlate => "Correlate — cross-artifact rules over the timeline",
        Stage::Scan => "Scan — match the timeline against threat-intel feeds",
    }
}

/// A cheap snapshot of the threat-intel feed cache, so `scan` re-runs when feeds
/// change. Placeholder for the prototype: a stable token (use `--rerun` to force
/// a re-scan after `issen feed update`).
fn feed_snapshot() -> String {
    "v0".to_string()
}

/// Run the resumable pipeline over `evidence`.
///
/// # Errors
/// Fails if no usable evidence is given, the case DB cannot be opened, or a
/// stage errors (a failed stage stays resumable).
pub fn run(evidence: &[PathBuf], output: Option<&Path>, verbose: bool) -> anyhow::Result<()> {
    if evidence.is_empty() {
        anyhow::bail!(
            "no evidence given — pass disk images, a collection, or memory dumps, \
             e.g. `issen DC01.E01 dump.mem` (see `issen --help`)"
        );
    }

    // Classify + size each input.
    let mut disk: Vec<(PathBuf, u64)> = Vec::new();
    let mut mem: Vec<(PathBuf, u64)> = Vec::new();
    for p in evidence {
        let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        match pipeline::classify(&p.to_string_lossy()) {
            Some(EvidenceKind::Disk) => disk.push((p.clone(), size)),
            Some(EvidenceKind::Memory) => mem.push((p.clone(), size)),
            None if p.is_dir() => disk.push((p.clone(), 0)), // a collection directory
            None => eprintln!(
                "warning: unrecognized evidence type, skipping: {}",
                p.display()
            ),
        }
    }
    let has_disk = !disk.is_empty();
    let has_memory = !mem.is_empty();
    if !has_disk && !has_memory {
        anyhow::bail!("no usable evidence among the given paths");
    }

    // Per-stage input fingerprints.
    let disk_fp_in = sized_paths(&disk);
    let mem_fp_in = sized_paths(&mem);
    let ruleset = env!("CARGO_PKG_VERSION");
    let feeds = feed_snapshot();
    let mut current_fp: HashMap<Stage, String> = HashMap::new();
    if has_disk {
        current_fp.insert(Stage::Ingest, pipeline::ingest_fingerprint(&disk_fp_in));
        current_fp.insert(Stage::Correlate, pipeline::correlate_fingerprint(ruleset));
        current_fp.insert(Stage::Scan, pipeline::scan_fingerprint(ruleset, &feeds));
    }
    if has_memory {
        current_fp.insert(Stage::Memory, pipeline::memory_fingerprint(&mem_fp_in));
    }

    // Deterministic case DB per evidence set, so a re-run finds it and resumes.
    let mut all = disk_fp_in.clone();
    all.extend(mem_fp_in.clone());
    let full = pipeline::ingest_fingerprint(&all);
    let case_id = full.get(..12).unwrap_or(full.as_str());
    let db_path = match output {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()
            .context("resolving current directory for the case DB")?
            .join(format!("issen-case-{case_id}.duckdb")),
    };

    // Stage-state lives in the case DB's pipeline_state table; the recorder opens
    // the DB only briefly per read/write, so it never holds the handle while a
    // stage executor opens the same file (DuckDB permits one handle per file).
    let recorder = DbStateRecorder {
        db_path: db_path.clone(),
    };

    let flags = Flags::default();
    let applicable = pipeline::applicable_stages(has_disk, has_memory, &flags);

    println!(
        "issen: {} stage(s) for this case → {}",
        applicable.len(),
        db_path.display()
    );

    let executor = RealExecutor {
        disk: disk.iter().map(|(p, _)| p.clone()).collect(),
        mem: mem.iter().map(|(p, _)| p.clone()).collect(),
        db_path: db_path.clone(),
        verbose,
        total: applicable.len(),
        step: std::cell::Cell::new(0),
    };

    let report = pipeline::run_bare(&applicable, &flags, &current_fp, &recorder, &executor)?;
    print_summary(&report, &db_path);
    Ok(())
}

fn sized_paths(items: &[(PathBuf, u64)]) -> Vec<(String, u64)> {
    items
        .iter()
        .map(|(p, n)| (p.to_string_lossy().into_owned(), *n))
        .collect()
}

fn print_summary(report: &RunReport, db_path: &Path) {
    println!(
        "\nPipeline complete: {} stage(s) ran, {} skipped → {}",
        report.ran.len(),
        report.skipped.len(),
        db_path.display()
    );
    for stage in &report.skipped {
        println!("  · {} (up to date)", stage.as_str());
    }
}

/// Persists stage-state in the case DB's `pipeline_state` table, opening the DB
/// only briefly per call so it never contends with a stage executor's handle.
struct DbStateRecorder {
    db_path: PathBuf,
}

impl pipeline::StateRecorder for DbStateRecorder {
    fn load(&self) -> anyhow::Result<Vec<pipeline::StageRecord>> {
        let store = TimelineStore::open(&self.db_path)
            .with_context(|| format!("opening {} for stage-state", self.db_path.display()))?;
        pipeline::load_prior(&store)
    }

    fn record(
        &self,
        stage: Stage,
        status: pipeline::Status,
        fingerprint: &str,
    ) -> anyhow::Result<()> {
        let store = TimelineStore::open(&self.db_path)
            .with_context(|| format!("opening {} to record stage-state", self.db_path.display()))?;
        store
            .record_stage_state(stage.as_str(), status.as_str(), fingerprint)
            .map_err(|e| anyhow::anyhow!("record stage-state: {e}"))
    }
}

/// Drives the real stage commands against one shared case DB.
struct RealExecutor {
    disk: Vec<PathBuf>,
    mem: Vec<PathBuf>,
    db_path: PathBuf,
    verbose: bool,
    total: usize,
    step: std::cell::Cell<usize>,
}

impl RealExecutor {
    /// A live spinner with a frequent tick, so a quiet stage never looks stalled.
    fn spinner(&self, stage: Stage) -> ProgressBar {
        let n = self.step.get() + 1;
        self.step.set(n);
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner} [{prefix}] {wide_msg} ({elapsed})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb.set_prefix(format!("{n}/{}", self.total));
        pb.set_message(stage_label(stage).to_string());
        pb.enable_steady_tick(Duration::from_millis(120));
        pb
    }
}

impl StageExecutor for RealExecutor {
    fn execute(&self, stage: Stage) -> anyhow::Result<()> {
        let started = Instant::now();
        match stage {
            Stage::Ingest => {
                // ingest prints its own indicatif progress; no extra spinner.
                let n = self.step.get() + 1;
                self.step.set(n);
                println!("▶ [{n}/{}] {}", self.total, stage_label(stage));
                // Scan is its own stage, not folded into ingest: enabling ingest
                // --scan re-tags every event (O(n) DuckDB updates) — pathological
                // on a multi-million-event timeline and pointless with no feeds.
                commands::ingest::run(
                    &self.disk,
                    &self.db_path,
                    None,
                    None,
                    false,
                    None,
                    None,
                    None,
                    None,
                    false,
                    self.verbose,
                    false,
                )?;
            }
            Stage::Memory => {
                let pb = self.spinner(stage);
                let dirs: HashSet<PathBuf> = self
                    .mem
                    .iter()
                    .filter_map(|p| p.parent().map(Path::to_path_buf))
                    .collect();
                let store = TimelineStore::open(&self.db_path).with_context(|| {
                    format!("opening {} for memory leg", self.db_path.display())
                })?;
                let mut events = 0u64;
                for dir in dirs {
                    pb.set_message(format!("memory leg: {}", dir.display()));
                    events += commands::correlate_mem::ingest_memory_leg(&store, &dir);
                }
                pb.finish_and_clear();
                println!("  memory events: {events}");
            }
            Stage::Correlate => {
                let n = self.step.get() + 1;
                self.step.set(n);
                println!("▶ [{n}/{}] {}", self.total, stage_label(stage));
                let store = TimelineStore::open(&self.db_path).with_context(|| {
                    format!("opening {} for correlation", self.db_path.display())
                })?;
                // One worker bar per concurrently-claimable rule (see
                // CORRELATE_RULE_SLOTS): the 8 disk-leg rules plus the memory-leg
                // group. Each rule claims a slot for its duration, so the live
                // display names the rules in flight.
                let render = crate::progress_view::should_render_bar(
                    std::io::stderr().is_terminal(),
                    self.verbose,
                );
                let mp = indicatif::MultiProgress::new();
                let cp = crate::correlate_progress::CorrelateProgress::start(
                    &mp,
                    CORRELATE_RULE_SLOTS,
                    render,
                );
                let reporter = cp.reporter().clone();
                let corrs = store
                    .run_and_persist_with_progress(&move |name: &str| reporter.claim_worker(name))
                    .map_err(|e| anyhow::anyhow!("correlation: {e}"))?;
                cp.finish();
                println!("  correlated findings: {}", corrs.len());
            }
            Stage::Scan => {
                // Run the event-level detection pass over the persisted timeline:
                // Sigma / native-ATT&CK / network-IOC matching against the cached
                // feeds PLUS the feed-independent $SI/$FN timestomp detector. The
                // findings land in `scan_findings` (surfaced by `report` /
                // `timeline --flagged`); full-timeline tag enrichment is skipped to
                // avoid the O(n) DuckDB re-tag that split scan out of ingest.
                let pb = self.spinner(stage);
                let store = TimelineStore::open(&self.db_path)
                    .with_context(|| format!("opening {} for scan", self.db_path.display()))?;
                let cache_dir = commands::ingest::default_feed_cache_dir();
                let engine = crate::scanning::engine_from_cached_feeds(&cache_dir);
                let scan_root = self
                    .disk
                    .first()
                    .map_or(self.db_path.as_path(), |p| p.as_path());
                let summary = crate::scanning::scan_persisted(&store, &engine, scan_root)?;
                pb.finish_and_clear();
                println!(
                    "  scan findings: {} (timestomp {}, native {}, sigma {}, network {})",
                    summary.total_findings,
                    summary.timestomp_findings,
                    summary.native_findings,
                    summary.sigma_findings,
                    summary.network_findings,
                );
            }
        }
        println!(
            "✔ {} ({:.1}s)",
            short_label(stage),
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }
}

fn short_label(stage: Stage) -> &'static str {
    match stage {
        Stage::Ingest => "ingest",
        Stage::Memory => "memory",
        Stage::Correlate => "correlate",
        Stage::Scan => "scan",
    }
}
