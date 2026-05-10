use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Thread-safe progress tracking for pipeline operations.
#[derive(Debug, Clone)]
pub struct ProgressReporter {
    events_emitted: Arc<AtomicU64>,
    bytes_processed: Arc<AtomicU64>,
    artifacts_completed: Arc<AtomicU64>,
    errors_encountered: Arc<AtomicU64>,
}

impl ProgressReporter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events_emitted: Arc::new(AtomicU64::new(0)),
            bytes_processed: Arc::new(AtomicU64::new(0)),
            artifacts_completed: Arc::new(AtomicU64::new(0)),
            errors_encountered: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn add_events(&self, count: u64) {
        self.events_emitted.fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, count: u64) {
        self.bytes_processed.fetch_add(count, Ordering::Relaxed);
    }

    pub fn complete_artifact(&self) {
        self.artifacts_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors_encountered.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn events_emitted(&self) -> u64 {
        self.events_emitted.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn artifacts_completed(&self) -> u64 {
        self.artifacts_completed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn errors_encountered(&self) -> u64 {
        self.errors_encountered.load(Ordering::Relaxed)
    }
}

impl Default for ProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_reporter_initial_state() {
        let progress = ProgressReporter::new();
        assert_eq!(progress.events_emitted(), 0);
        assert_eq!(progress.bytes_processed(), 0);
        assert_eq!(progress.artifacts_completed(), 0);
        assert_eq!(progress.errors_encountered(), 0);
    }

    #[test]
    fn test_progress_reporter_tracking() {
        let progress = ProgressReporter::new();
        progress.add_events(100);
        progress.add_events(50);
        progress.add_bytes(1024);
        progress.complete_artifact();
        progress.complete_artifact();
        progress.record_error();

        assert_eq!(progress.events_emitted(), 150);
        assert_eq!(progress.bytes_processed(), 1024);
        assert_eq!(progress.artifacts_completed(), 2);
        assert_eq!(progress.errors_encountered(), 1);
    }

    #[test]
    fn test_progress_reporter_clone_shares_state() {
        let progress1 = ProgressReporter::new();
        let progress2 = progress1.clone();

        progress1.add_events(10);
        assert_eq!(progress2.events_emitted(), 10, "Clone shares Arc state");

        progress2.add_events(5);
        assert_eq!(progress1.events_emitted(), 15);
    }
}
