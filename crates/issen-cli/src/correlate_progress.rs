//! The thin, untested indicatif draw shell for the live correlate display
//! (Humble Object), mirroring [`crate::ingest_progress::SourceProgress`].
//!
//! The correlate stage runs its ~9 rules in parallel; this surface shows a
//! parent spinner plus one child "worker" bar per claimable slot, each naming
//! the rule it is currently evaluating ("correlating: persist"). All the
//! decisions live in `issen-correlation`/`issen-timeline` (pure, tested); this
//! only maps `ProgressReporter::worker_labels()` snapshots to indicatif bars.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use issen_fswalker::progress::ProgressReporter;

/// A live per-rule progress surface for the correlate stage. Owns the
/// `ProgressReporter` whose worker slots the rules claim; a background thread
/// renders the slot labels. With `render == false` (non-terminal or
/// `--verbose`) it draws nothing but still hands back a working reporter.
pub struct CorrelateProgress {
    reporter: ProgressReporter,
    bar: Option<ProgressBar>,
    /// One child bar per worker slot, grouped under `bar`; each names the rule
    /// its slot is currently evaluating (empty when not rendering).
    worker_bars: Vec<ProgressBar>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl CorrelateProgress {
    /// Start the correlate display with `slots` worker bars (one per rule that
    /// can run concurrently). When `render`, adds bars to `mp` and spawns the
    /// render thread; otherwise it's an inert holder of the reporter.
    #[must_use]
    pub fn start(mp: &MultiProgress, slots: usize, render: bool) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        if !render {
            return Self {
                reporter: ProgressReporter::with_workers(slots),
                bar: None,
                worker_bars: Vec::new(),
                stop,
                handle: None,
            };
        }

        let reporter = ProgressReporter::with_workers(slots);

        let bar = mp.add(ProgressBar::new_spinner());
        let style = ProgressStyle::with_template("{spinner:.green} {prefix:.bold} {wide_msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ");
        bar.set_style(style);
        bar.set_prefix("Correlate");
        bar.set_message("running correlation rules");
        bar.enable_steady_tick(Duration::from_millis(100));

        // Child rule bars, inserted right after the parent so they stay grouped.
        let worker_style = ProgressStyle::with_template("    {prefix:.dim} {wide_msg:.dim}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner());
        let mut worker_bars = Vec::with_capacity(slots);
        let mut prev = bar.clone();
        for i in 0..slots {
            let wb = mp.insert_after(&prev, ProgressBar::new_spinner());
            wb.set_style(worker_style.clone());
            let connector = if i + 1 == slots { "└" } else { "├" };
            wb.set_prefix(format!("{connector} rule {}", i + 1));
            wb.set_message("idle");
            prev = wb.clone();
            worker_bars.push(wb);
        }

        let handle = {
            let stop = Arc::clone(&stop);
            let reporter = reporter.clone();
            let worker_bars = worker_bars.clone();
            thread::spawn(move || loop {
                let labels = reporter.worker_labels();
                for (wb, label) in worker_bars.iter().zip(&labels) {
                    match label {
                        Some(name) => wb.set_message(format!("correlating: {name}")),
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

    /// The reporter to hand to the correlation runner; rules claim its slots.
    #[must_use]
    pub fn reporter(&self) -> &ProgressReporter {
        &self.reporter
    }

    /// Stop the render thread and clear the live bars.
    pub fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        for wb in self.worker_bars.drain(..) {
            wb.finish_and_clear();
        }
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
    }
}
