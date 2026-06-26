//! The thin, untested indicatif draw shell for the live ingest display (Humble
//! Object). All display *decisions* live in [`crate::progress_view`] (pure,
//! tested); this only spawns a render thread that maps `ProgressReporter`
//! snapshots to an indicatif bar ~10×/s.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use issen_fswalker::progress::ProgressReporter;

use crate::progress_view::status_line;

/// Install a one-shot SIGINT (Ctrl-C) handler that clears the live bars before
/// exiting, so an interrupted ingest leaves a clean terminal (not a half-drawn
/// bar or hidden cursor) instead of corrupting the prompt. Exits `130`
/// (128 + SIGINT); per-unit commits are atomic, so the partial DB is consistent
/// and resumable. Best-effort and idempotent — a second install (e.g. a nested
/// correlate→ingest) is ignored. Untestable signal shell.
pub fn install_sigint_cleanup(mp: &MultiProgress) {
    let mp = mp.clone();
    let _ = ctrlc::set_handler(move || {
        let _ = mp.clear();
        let _ = std::io::Write::flush(&mut std::io::stderr());
        std::process::exit(130);
    });
}

/// A live per-source progress surface. Owns the `ProgressReporter` the pipeline
/// updates; a background thread renders its snapshots. With `render == false`
/// (non-terminal or `--verbose`) it draws nothing but still hands back a working
/// reporter, so the caller's plain-output path is unchanged.
pub struct SourceProgress {
    reporter: ProgressReporter,
    bar: Option<ProgressBar>,
    /// One child bar per worker slot, grouped under `bar`; each names the
    /// artifact its slot is currently parsing (empty when not rendering).
    worker_bars: Vec<ProgressBar>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SourceProgress {
    /// Start a source's display. When `render`, adds a bar to `mp` and spawns the
    /// render thread; otherwise it's an inert holder of the reporter.
    #[must_use]
    pub fn start(mp: &MultiProgress, label: &str, render: bool) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        if !render {
            return Self {
                reporter: ProgressReporter::new(),
                bar: None,
                worker_bars: Vec::new(),
                stop,
                handle: None,
            };
        }

        // One worker slot/bar per parsing thread (capped so the display stays
        // readable). The reporter's slot count must match the bar count.
        let workers = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1)
            .clamp(1, 6);
        let reporter = ProgressReporter::with_workers(workers);

        let bar = mp.add(ProgressBar::new_spinner());
        let style = ProgressStyle::with_template(
            "{spinner:.green} {prefix:.bold} {bar:24.cyan/blue} {wide_msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_spinner())
        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ");
        bar.set_style(style);
        bar.set_prefix(label.to_string());
        bar.enable_steady_tick(Duration::from_millis(100));

        // Child worker bars, inserted right after the parent so each source's
        // workers stay grouped under it even while other sources render too.
        let worker_style = ProgressStyle::with_template("    {prefix:.dim} {wide_msg:.dim}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner());
        let mut worker_bars = Vec::with_capacity(workers);
        let mut prev = bar.clone();
        for i in 0..workers {
            let wb = mp.insert_after(&prev, ProgressBar::new_spinner());
            wb.set_style(worker_style.clone());
            let connector = if i + 1 == workers { "└" } else { "├" };
            wb.set_prefix(format!("{connector} worker {}", i + 1));
            wb.set_message("idle");
            prev = wb.clone();
            worker_bars.push(wb);
        }

        let handle = {
            let stop = Arc::clone(&stop);
            let reporter = reporter.clone();
            let bar = bar.clone();
            let worker_bars = worker_bars.clone();
            let start = Instant::now();
            thread::spawn(move || loop {
                let snap = reporter.snapshot();
                // Becomes a determinate bar once discovery sets the total.
                if snap.artifacts_total > 0 {
                    bar.set_length(snap.artifacts_total);
                    bar.set_position(snap.artifacts_completed);
                }
                bar.set_message(status_line(&snap, start.elapsed()));
                // Name what each worker slot is currently parsing.
                let labels = reporter.worker_labels();
                for (wb, label) in worker_bars.iter().zip(&labels) {
                    match label {
                        Some(name) => wb.set_message(format!("parsing {name}")),
                        None => wb.set_message("idle".to_string()),
                    }
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            })
        };

        Self {
            reporter,
            bar: Some(bar),
            worker_bars,
            stop,
            handle: Some(handle),
        }
    }

    /// The reporter to hand to the pipeline for this source.
    #[must_use]
    pub fn reporter(&self) -> &ProgressReporter {
        &self.reporter
    }

    /// Stop the render thread and replace the live bar with a final summary line.
    pub fn finish(mut self, summary: &str) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // Clear the per-worker child bars; the parent keeps the final summary.
        for wb in self.worker_bars.drain(..) {
            wb.finish_and_clear();
        }
        if let Some(bar) = self.bar.take() {
            bar.finish_with_message(summary.to_string());
        }
    }
}
