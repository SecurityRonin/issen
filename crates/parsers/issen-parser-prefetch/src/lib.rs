//! Windows Prefetch file parser for Issen.
//!
//! Parses `.pf` Prefetch files and emits [`TimelineEvent`]s via the
//! [`ForensicParser`] trait.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

pub mod parser;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseStats, ParserCapabilities,
};

/// Windows Prefetch file parser.
pub struct PrefetchParser;

impl PrefetchParser {
    /// Return `true` when `path` has a `.pf` extension (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("pf"))
    }
}

impl ForensicParser for PrefetchParser {
    fn name(&self) -> &'static str {
        "Prefetch Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Prefetch]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let len = input.len();
        if len == 0 {
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        }
        // Read the whole `.pf` into memory (prefetch files are small, ≤ tens of KB).
        let mut bytes = vec![0u8; len as usize];
        let mut off = 0u64;
        while off < len {
            let n = input.read_at(off, &mut bytes[off as usize..])?;
            if n == 0 {
                break;
            }
            off += n as u64;
        }
        stats.bytes_processed = off;

        // Truncate to bytes actually read (mode 6D); never feed trailing zeros.
        let events = parser::events_from_bytes(&bytes[..off as usize], "prefetch-evidence");
        let event_count = events.len() as u64;
        stats.events_emitted = event_count;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }

        // Declare the terminal state for resumable ingestion (issen #115).
        stats.completion = if off < len {
            ParseCompletion::Incomplete {
                offset: off,
                reason: "short read before end of prefetch file".to_string(),
            }
        } else if event_count == 0 {
            // A valid .pf always emits at least its run event; zero events from a
            // non-empty, fully-read file means it is not a parseable prefetch
            // (bad signature / wrong format).
            ParseCompletion::Unsupported
        } else {
            ParseCompletion::Complete
        };
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(64 * 1024 * 1024), // 64 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(PrefetchParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use std::path::PathBuf;

    // ── Extension matching tests ───────────────────────────────────────────

    #[test]
    fn can_parse_returns_true_for_pf_extension() {
        let path = PathBuf::from("/mnt/evidence/C/Windows/Prefetch/NOTEPAD.EXE-ABCD1234.pf");
        assert!(
            PrefetchParser::can_parse(&path),
            "expected can_parse to return true for .pf"
        );
    }

    #[test]
    fn can_parse_returns_true_for_uppercase_pf() {
        let path = PathBuf::from("/mnt/evidence/NOTEPAD.EXE-ABCD1234.PF");
        assert!(
            PrefetchParser::can_parse(&path),
            "expected can_parse to return true for .PF (upper-case)"
        );
    }

    #[test]
    fn can_parse_returns_false_for_exe() {
        let path = PathBuf::from("/mnt/evidence/notepad.exe");
        assert!(
            !PrefetchParser::can_parse(&path),
            "expected can_parse to return false for .exe"
        );
    }

    #[test]
    fn can_parse_returns_false_for_no_extension() {
        let path = PathBuf::from("/mnt/evidence/NOTEPAD");
        assert!(
            !PrefetchParser::can_parse(&path),
            "expected can_parse to return false for file with no extension"
        );
    }

    // ── parse_prefetch tests ───────────────────────────────────────────────

    #[test]
    fn parse_empty_file_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parser::parse_prefetch(tmp.path(), "test-source")
            .expect("parse_prefetch must not return Err on empty file");
        assert!(
            events.is_empty(),
            "expected empty vec for zero-byte file, got {} events",
            events.len()
        );
    }

    #[test]
    fn parse_bad_signature_returns_empty() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Write 84 bytes but with wrong signature ("JUNK" instead of "SCCA").
        let mut data = vec![0u8; 84];
        data[0..4].copy_from_slice(b"JUNK");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");

        let events = parser::parse_prefetch(tmp.path(), "test-source")
            .expect("parse_prefetch must not Err on bad signature");
        assert!(
            events.is_empty(),
            "expected empty vec for bad signature, got {} events",
            events.len()
        );
    }

    #[test]
    fn completion_status_reflects_terminal_state() {
        // issen #115 step 1.5: prefetch must declare a trustworthy terminal state.
        use issen_core::error::RtError;
        use issen_core::plugin::traits::{DataSource, EventEmitter, ParseCompletion};
        use issen_core::timeline::event::TimelineEvent;

        struct Bytes(Vec<u8>);
        impl DataSource for Bytes {
            fn len(&self) -> u64 {
                self.0.len() as u64
            }
            fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize, RtError> {
                let o = off as usize;
                if o >= self.0.len() {
                    return Ok(0);
                }
                let n = buf.len().min(self.0.len() - o);
                buf[..n].copy_from_slice(&self.0[o..o + n]);
                Ok(n)
            }
        }
        struct Noop;
        impl EventEmitter for Noop {
            fn emit(&self, _: TimelineEvent) -> Result<(), RtError> {
                Ok(())
            }
            fn emit_batch(&self, _: Vec<TimelineEvent>) -> Result<(), RtError> {
                Ok(())
            }
        }

        let parser = PrefetchParser;
        // Empty -> Unsupported.
        let s = parser.parse(&Bytes(vec![]), &Noop).expect("ok");
        assert_eq!(s.completion, ParseCompletion::Unsupported);
        // Bad signature (non-empty, zero events) -> Unsupported.
        let mut junk = vec![0u8; 84];
        junk[0..4].copy_from_slice(b"JUNK");
        let s = parser.parse(&Bytes(junk), &Noop).expect("ok");
        assert_eq!(s.completion, ParseCompletion::Unsupported);
        // A valid SCCA consumed cleanly -> Complete.
        let scca = minimal_scca("NOTEPAD.EXE", 132_449_604_494_103_203, 3);
        let s = parser.parse(&Bytes(scca), &Noop).expect("ok");
        assert_eq!(s.completion, ParseCompletion::Complete);
    }

    /// A minimal valid Win10 (v30) SCCA payload: `[u32 version][b"SCCA"]`, the
    /// executable name at offset 16, one last-run FILETIME, and a run count.
    /// Empty filename/volume blocks (offsets 0) decode gracefully to nothing.
    fn minimal_scca(exe: &str, run_time: i64, run_count: u32) -> Vec<u8> {
        let mut p = vec![0u8; 84 + 224];
        p[0..4].copy_from_slice(&30u32.to_le_bytes());
        p[4..8].copy_from_slice(b"SCCA");
        for (i, c) in exe.encode_utf16().enumerate() {
            p[16 + i * 2..16 + i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        let fi = 84;
        p[fi + 44..fi + 52].copy_from_slice(&run_time.to_le_bytes()); // run time[0]
        p[fi + 124..fi + 128].copy_from_slice(&run_count.to_le_bytes()); // old-format run count
        p
    }

    #[test]
    fn parse_real_layout_scca_emits_run_event() {
        // FILETIME 2020-09-19 (the Stolen Szechuan Sauce era).
        let data = minimal_scca("NOTEPAD.EXE", 132_449_604_494_103_203, 3);
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");

        let events = parser::parse_prefetch(tmp.path(), "test-source")
            .expect("parse_prefetch must not Err on a valid SCCA");

        assert_eq!(events.len(), 1, "one run time → one event");
        let ev = &events[0];
        assert_eq!(ev.source, ArtifactType::Prefetch);
        assert!(ev.description.contains("NOTEPAD.EXE"), "{}", ev.description);
        assert!(
            ev.timestamp_ns > 0,
            "run time must be decoded, not stubbed to 0"
        );
        assert_eq!(
            ev.metadata
                .get("run_count")
                .and_then(serde_json::Value::as_u64),
            Some(3)
        );
        assert_eq!(
            ev.metadata
                .get("executable")
                .and_then(serde_json::Value::as_str),
            Some("NOTEPAD.EXE")
        );
    }

    #[test]
    fn prefetch_event_tagged_execution() {
        // Prefetch records program execution — emitted events carry the CADET
        // Execution category (meaning axis), distinct from the Prefetch source.
        let data = minimal_scca("NOTEPAD.EXE", 132_449_604_494_103_203, 3);
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");
        let events = parser::parse_prefetch(tmp.path(), "test-source").expect("parse");
        assert_eq!(
            events[0].activity_category,
            Some(issen_core::ActivityCategory::Execution)
        );
    }

    /// Drive the `ForensicParser::parse` ingest path (the one the orchestrator
    /// calls) end-to-end over an in-memory `.pf`, proving it actually emits —
    /// the wiring that was previously a stub returning `Ok(ParseStats::new())`.
    #[test]
    fn forensic_parser_parse_emits_via_emitter() {
        use issen_core::error::RtError;
        use issen_core::plugin::traits::DataSource;
        use issen_core::timeline::event::TimelineEvent;
        use std::sync::Mutex;

        struct MemSource(Vec<u8>);
        impl DataSource for MemSource {
            fn len(&self) -> u64 {
                self.0.len() as u64
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
                let off = offset as usize;
                let n = buf.len().min(self.0.len().saturating_sub(off));
                buf[..n].copy_from_slice(&self.0[off..off + n]);
                Ok(n)
            }
        }
        #[derive(Default)]
        struct Collector(Mutex<Vec<TimelineEvent>>);
        impl EventEmitter for Collector {
            fn emit(&self, e: TimelineEvent) -> Result<(), RtError> {
                self.0.lock().unwrap().push(e);
                Ok(())
            }
            fn emit_batch(&self, mut e: Vec<TimelineEvent>) -> Result<(), RtError> {
                self.0.lock().unwrap().append(&mut e);
                Ok(())
            }
        }

        let data = tests::minimal_scca("NOTEPAD.EXE", 132_449_604_494_103_203, 5);
        let source = MemSource(data);
        let collector = Collector::default();
        let stats = PrefetchParser
            .parse(&source, &collector)
            .expect("parse must not Err");

        assert_eq!(stats.events_emitted, 1);
        let events = collector.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].description.contains("NOTEPAD.EXE"));
        assert!(events[0].timestamp_ns > 0);
    }
}
