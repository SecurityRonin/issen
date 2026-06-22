use crate::artifacts::ArtifactType;
use crate::error::RtError;
use crate::timeline::event::TimelineEvent;

// Re-exported so impls that `use issen_core::plugin::traits::{...}` can name the
// options type alongside the trait. Canonical path: `issen_core::plugin::ParseOptions`.
pub use crate::plugin::options::ParseOptions;

/// Capabilities advertised by a parser for orchestration decisions.
#[derive(Debug, Clone)]
pub struct ParserCapabilities {
    /// Maximum expected memory usage in bytes (None = unbounded).
    pub max_memory_bytes: Option<u64>,
    /// Whether the parser supports streaming (required for large artifacts).
    pub streaming: bool,
    /// Whether the parser is deterministic (same input => same output).
    pub deterministic: bool,
}

/// Channel for emitting timeline events during parsing.
///
/// Parsers call `emit` or `emit_batch` to send events downstream.
/// Implementations may buffer, write to DuckDB, or forward to channels.
pub trait EventEmitter: Send + Sync {
    /// Emit a single timeline event.
    fn emit(&self, event: TimelineEvent) -> Result<(), RtError>;

    /// Emit a batch of events (preferred for performance).
    fn emit_batch(&self, events: Vec<TimelineEvent>) -> Result<(), RtError>;
}

/// Abstraction over evidence data (file, memory-mapped region, or byte slice).
///
/// Provides random-access reads for parser implementations.
pub trait DataSource: Send + Sync {
    /// Total size in bytes.
    fn len(&self) -> u64;

    /// Whether the source is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read bytes at the given offset into `buf`. Returns bytes read.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError>;

    /// Filesystem path this source was opened from, if any.
    ///
    /// Defaults to `None` — most parsers consume the byte stream via `read_at`
    /// and need no path. A parser that requires random-access *file* semantics
    /// (e.g. an ESE/SQLite reader that seeks across B-tree pages, or registry
    /// transaction-log replay) uses this to reach the underlying file. Sources
    /// backed only by bytes return `None`, so such parsers degrade gracefully.
    fn source_path(&self) -> Option<&std::path::Path> {
        None
    }
}

/// Terminal state of a parse — whether the parser consumed its input to a clean
/// end, or stopped early / declined it.
///
/// Resumable ingestion (issen #115) marks a unit complete **only** on
/// `Complete` / `CompleteWithRecoveries`; every other state means "not done"
/// (redo on resume) or "skip" (`Unsupported`). The default is [`Undeclared`]
/// (secure-by-default): a parser that returns `Ok(ParseStats)` without
/// explicitly declaring completion is **never** treated as complete, so a
/// lenient `Ok` on truncated/invalid input cannot silently mark a resume unit
/// done and lose evidence.
///
/// [`Undeclared`]: ParseCompletion::Undeclared
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ParseCompletion {
    /// The parser did not declare a terminal state. Treated as NOT complete.
    #[default]
    Undeclared,
    /// Reached a clean end of input; all events emitted.
    Complete,
    /// Reached the end, but skipped/recovered some records (count in
    /// `errors_recovered`). Still a complete pass over the input.
    CompleteWithRecoveries,
    /// Stopped before the end (truncated / interrupted source). `offset` is the
    /// last byte parsed cleanly; `reason` describes why it stopped.
    Incomplete { offset: u64, reason: String },
    /// The input is not a valid instance of this parser's format — a *skip*,
    /// not an error (e.g. an empty or wrong-magic file). Distinct from a clean
    /// zero-event completion.
    Unsupported,
    /// The input is a valid instance but irrecoverably corrupt at a structural
    /// level (cannot be meaningfully parsed at all).
    CorruptFatal { reason: String },
}

impl ParseCompletion {
    /// Whether this terminal state is eligible for resume's "complete" marker.
    ///
    /// Only a genuine full pass — [`Complete`](Self::Complete) or
    /// [`CompleteWithRecoveries`](Self::CompleteWithRecoveries) — counts. Every
    /// other state (Undeclared / Incomplete / Unsupported / CorruptFatal) must be
    /// re-parsed on resume rather than silently skipped (secure-by-default, #115).
    #[must_use]
    pub fn marks_complete(&self) -> bool {
        matches!(self, Self::Complete | Self::CompleteWithRecoveries)
    }
}

/// Parse statistics returned after a successful parse.
#[derive(Debug, Clone)]
pub struct ParseStats {
    /// Number of timeline events emitted.
    pub events_emitted: u64,
    /// Total bytes of source data processed.
    pub bytes_processed: u64,
    /// Number of recoverable errors encountered (logged but not fatal).
    pub errors_recovered: u64,
    /// Wall-clock duration of the parse operation.
    pub duration: std::time::Duration,
    /// Terminal completion state — the trustworthy "did this finish?" signal for
    /// resumable ingestion. Defaults to [`ParseCompletion::Undeclared`]; a parser
    /// must set it explicitly to be eligible for resume's "complete" marker.
    pub completion: ParseCompletion,
}

impl ParseStats {
    /// Create empty stats (starting point for a parse operation).
    #[must_use]
    pub fn new() -> Self {
        Self {
            events_emitted: 0,
            bytes_processed: 0,
            errors_recovered: 0,
            duration: std::time::Duration::ZERO,
            completion: ParseCompletion::Undeclared,
        }
    }
}

impl Default for ParseStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Core trait that all forensic parsers must implement.
///
/// Parsers are registered at compile time via the `inventory` crate.
/// The pipeline discovers and dispatches to them based on `supported_artifacts()`.
pub trait ForensicParser: Send + Sync {
    /// Human-readable parser name (e.g., "USN Journal Parser").
    fn name(&self) -> &str;

    /// Artifact types this parser can handle.
    fn supported_artifacts(&self) -> &[ArtifactType];

    /// Parse the data source, emitting events through the emitter.
    ///
    /// `opts` carries parser-agnostic [`ParseOptions`] (e.g. `verbose_rows`).
    /// Most parsers ignore it — they have one natural output shape — but a parser
    /// with a high-volume table consults it to choose between an aggregate
    /// summary and full per-row events.
    ///
    /// # Errors
    /// Returns `RtError` on unrecoverable parse failures.
    /// Recoverable errors should be logged and counted in `ParseStats`.
    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        opts: &ParseOptions,
    ) -> Result<ParseStats, RtError>;

    /// Advertise parser capabilities for orchestration decisions.
    fn capabilities(&self) -> ParserCapabilities;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::event::EventType;
    use std::sync::Mutex;

    #[test]
    fn parse_stats_defaults_to_undeclared_not_complete() {
        // Secure-by-default (issen #115 step 1): a parser that does not EXPLICITLY
        // declare completion must never be treated as complete — otherwise resume
        // would mark a partial/skipped unit done and silently lose evidence.
        // `Ok(ParseStats)` must NOT imply Complete.
        let stats = ParseStats::new();
        assert_eq!(stats.completion, ParseCompletion::Undeclared);
        assert_ne!(stats.completion, ParseCompletion::Complete);
    }

    #[test]
    fn marks_complete_only_for_terminal_complete_states() {
        // Resume's "complete" marker may be written ONLY for a genuine full pass.
        // Every non-terminal-complete state must re-parse on resume (secure-by-default).
        assert!(ParseCompletion::Complete.marks_complete());
        assert!(ParseCompletion::CompleteWithRecoveries.marks_complete());
        assert!(!ParseCompletion::Undeclared.marks_complete());
        assert!(!ParseCompletion::Unsupported.marks_complete());
        assert!(!ParseCompletion::Incomplete {
            offset: 0,
            reason: String::new()
        }
        .marks_complete());
        assert!(!ParseCompletion::CorruptFatal {
            reason: String::new()
        }
        .marks_complete());
    }

    // ── Test doubles ──────────────────────────────────────────

    /// In-memory DataSource for testing.
    struct MemorySource {
        data: Vec<u8>,
    }

    impl MemorySource {
        fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
    }

    impl DataSource for MemorySource {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let offset = offset as usize;
            if offset >= self.data.len() {
                return Ok(0);
            }
            let available = self.data.len() - offset;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
            Ok(to_read)
        }
    }

    /// Collecting EventEmitter for testing — stores all emitted events.
    struct CollectingEmitter {
        events: Mutex<Vec<TimelineEvent>>,
    }

    impl CollectingEmitter {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }

        fn into_events(self) -> Vec<TimelineEvent> {
            self.events.into_inner().expect("mutex poisoned")
        }
    }

    impl EventEmitter for CollectingEmitter {
        fn emit(&self, event: TimelineEvent) -> Result<(), RtError> {
            self.events.lock().expect("mutex poisoned").push(event);
            Ok(())
        }

        fn emit_batch(&self, events: Vec<TimelineEvent>) -> Result<(), RtError> {
            self.events.lock().expect("mutex poisoned").extend(events);
            Ok(())
        }
    }

    /// Trivial parser that emits one event per byte in the source.
    struct StubParser;

    impl ForensicParser for StubParser {
        fn name(&self) -> &'static str {
            "Stub Parser"
        }

        fn supported_artifacts(&self) -> &[ArtifactType] {
            &[ArtifactType::UsnJournal]
        }

        fn parse(
            &self,
            input: &dyn DataSource,
            emitter: &dyn EventEmitter,
            _opts: &ParseOptions,
        ) -> Result<ParseStats, RtError> {
            let start = std::time::Instant::now();
            let mut stats = ParseStats::new();
            let len = input.len();

            for i in 0..len {
                let event = TimelineEvent::new(
                    i as i64,
                    format!("stub-ts-{i}"),
                    EventType::FileCreate,
                    ArtifactType::UsnJournal,
                    "stub/path".to_string(),
                    format!("Stub event {i}"),
                    "stub-evidence".to_string(),
                );
                emitter.emit(event)?;
                stats.events_emitted += 1;
            }

            stats.bytes_processed = len;
            stats.duration = start.elapsed();
            Ok(stats)
        }

        fn capabilities(&self) -> ParserCapabilities {
            ParserCapabilities {
                max_memory_bytes: Some(1024),
                streaming: true,
                deterministic: true,
            }
        }
    }

    // ── Tests ─────────────────────────────────────────────────

    #[test]
    fn test_data_source_empty() {
        let source = MemorySource::new(vec![]);
        assert_eq!(source.len(), 0);
        assert!(source.is_empty());
    }

    #[test]
    fn test_data_source_source_path_defaults_to_none() {
        // A byte-backed source advertises no path, so path-needing parsers
        // (ESE/SQLite) degrade gracefully instead of misreading the stream.
        let source = MemorySource::new(vec![1, 2, 3]);
        assert!(source.source_path().is_none());
    }

    #[test]
    fn test_data_source_read_at() {
        let source = MemorySource::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(source.len(), 4);
        assert!(!source.is_empty());

        let mut buf = [0u8; 2];
        let n = source.read_at(0, &mut buf).expect("read");
        assert_eq!(n, 2);
        assert_eq!(buf, [0xDE, 0xAD]);

        let n = source.read_at(2, &mut buf).expect("read");
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBE, 0xEF]);
    }

    #[test]
    fn test_data_source_read_past_end() {
        let source = MemorySource::new(vec![0xAA]);
        let mut buf = [0u8; 4];
        let n = source.read_at(0, &mut buf).expect("read");
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xAA);

        let n = source.read_at(10, &mut buf).expect("read past end");
        assert_eq!(n, 0);
    }

    #[test]
    fn test_collecting_emitter_single() {
        let emitter = CollectingEmitter::new();
        let event = TimelineEvent::new(
            1000,
            "ts".to_string(),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            "path".to_string(),
            "test".to_string(),
            "ev-1".to_string(),
        );
        emitter.emit(event).expect("emit");
        let events = emitter.into_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, 1000);
    }

    #[test]
    fn test_collecting_emitter_batch() {
        let emitter = CollectingEmitter::new();
        let batch: Vec<TimelineEvent> = (0..5)
            .map(|i| {
                TimelineEvent::new(
                    i,
                    format!("ts-{i}"),
                    EventType::FileCreate,
                    ArtifactType::UsnJournal,
                    "path".to_string(),
                    format!("event {i}"),
                    "ev-1".to_string(),
                )
            })
            .collect();
        emitter.emit_batch(batch).expect("emit_batch");
        assert_eq!(emitter.into_events().len(), 5);
    }

    #[test]
    fn test_stub_parser_trait_contract() {
        let parser = StubParser;
        assert_eq!(parser.name(), "Stub Parser");
        assert_eq!(parser.supported_artifacts(), &[ArtifactType::UsnJournal]);
        assert!(parser.capabilities().deterministic);
        assert!(parser.capabilities().streaming);
        assert_eq!(parser.capabilities().max_memory_bytes, Some(1024));
    }

    #[test]
    fn test_stub_parser_emits_events() {
        let parser = StubParser;
        let source = MemorySource::new(vec![0; 3]);
        let emitter = CollectingEmitter::new();

        let stats = parser
            .parse(&source, &emitter, &ParseOptions::default())
            .expect("parse");
        assert_eq!(stats.events_emitted, 3);
        assert_eq!(stats.bytes_processed, 3);
        assert_eq!(stats.errors_recovered, 0);

        let events = emitter.into_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].timestamp_ns, 0);
        assert_eq!(events[2].timestamp_ns, 2);
    }

    #[test]
    fn test_parser_trait_is_object_safe() {
        // Ensure ForensicParser can be used as a trait object.
        let parser: Box<dyn ForensicParser> = Box::new(StubParser);
        assert_eq!(parser.name(), "Stub Parser");
    }

    #[test]
    fn test_parse_stats_default() {
        let stats = ParseStats::default();
        assert_eq!(stats.events_emitted, 0);
        assert_eq!(stats.bytes_processed, 0);
        assert_eq!(stats.errors_recovered, 0);
    }
}
