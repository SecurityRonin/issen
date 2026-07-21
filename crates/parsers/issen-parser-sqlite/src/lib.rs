//! File-level SQLite deleted-row carver for Issen (ADR 0018 tier 1).
//!
//! Recovers deleted rows from a *located* SQLite database's own free space — its
//! freelist pages, dropped-table pages, and in-page free blocks — via our
//! published fleet crates (`sqlite-core` reader + `sqlite-forensic` analyzer). The
//! recovery is bounded by the file already in hand (marginal cost on top of the
//! parse), so it runs in the default triage path per ADR 0018. Whole-disk
//! unallocated carving (the `--deleted` tier) is out of scope here.
//!
//! ## Interaction with `issen-browser` (additive, no conflict)
//!
//! The carved rows are emitted as **deleted/carved** [`TimelineEvent`]s with
//! `source = ArtifactType::SqliteCarved`, clearly distinct from `issen-browser`'s
//! live-row events (`source = BrowserHistory`). Issen classifies each file to ONE
//! artifact type (highest-priority selector) and then runs *every* parser whose
//! `supported_artifacts()` contains that type. So this carver:
//!
//! - declares [`ArtifactType::SqliteCarved`] **and** [`ArtifactType::BrowserHistory`]
//!   in `supported_artifacts()`, and registers a magic-byte selector at a priority
//!   **below** `issen-browser`'s (80). A browser database therefore still classifies
//!   as `BrowserHistory` (browser's live-row parse runs) **and** this carver co-runs
//!   on it, adding the deleted rows — additive, never a replacement.
//! - catches any other SQLite file (by the `SQLite format 3\0` magic) that no
//!   higher-priority selector claims, classifying it `SqliteCarved`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod parser;

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseOptions, ParseStats,
    ParserCapabilities,
};

/// File-level SQLite deleted-row carver.
pub struct SqliteCarveParser;

impl ForensicParser for SqliteCarveParser {
    fn name(&self) -> &'static str {
        "SQLite Carve Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        // BrowserHistory so this co-runs with issen-browser on browser SQLite
        // (adding deleted rows to its live rows); SqliteCarved for any other
        // SQLite file the magic selector classifies.
        &[ArtifactType::SqliteCarved, ArtifactType::BrowserHistory]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let len = input.len();
        if len == 0 {
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        }
        let Ok(cap) = usize::try_from(len) else {
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        };
        let mut bytes = vec![0u8; cap];
        let mut off = 0u64;
        while off < len {
            let n = input.read_at(off, &mut bytes[off as usize..])?;
            if n == 0 {
                break;
            }
            off += n as u64;
        }
        stats.bytes_processed = off;

        let events = parser::events_from_bytes(&bytes[..off as usize], "sqlite-evidence");
        let event_count = events.len() as u64;
        stats.events_emitted = event_count;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }

        // Terminal state for resumable ingestion (issen #115). Zero carved rows
        // from a fully-read SQLite file is a legitimate Complete (no deletions in
        // free space), NOT Unsupported — the file parsed fine, it simply had
        // nothing to recover.
        stats.completion = if off < len {
            ParseCompletion::Incomplete {
                offset: off,
                reason: "short read before end of SQLite file".to_string(),
            }
        } else {
            ParseCompletion::Complete
        };
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(1024 * 1024 * 1024), // 1 GiB (matches MAX_CARVE_BYTES)
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory. Priority 40 is BELOW
// issen-browser's 80, so a browser database still classifies as BrowserHistory
// (browser's live-row parse runs) while this carver co-runs on it; a non-browser
// SQLite file with no higher-priority claimant classifies as SqliteCarved.
// Empty `disk_sources`: browser/other selectors already pull the high-value
// SQLite databases off the image; this carver co-runs on whatever is extracted
// and additionally catches loose-file SQLite (honest — no bespoke image extractor
// of its own).
inventory::submit! {
    ParserRegistration {
        create: || Box::new(SqliteCarveParser),
        selector: sel::ArtifactSelector {
            artifact_type: ArtifactType::SqliteCarved,
            matches: classify::sqlite,
            priority: 40,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Build a real SQLite database with a distinctively-marked row, DELETE it,
    /// and return the file bytes — the deleted row's content survives in free
    /// space (SQLite `secure_delete` is OFF by default), so the carver must
    /// recover it.
    fn db_with_deleted_row() -> Vec<u8> {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_path_buf();
        {
            let conn = Connection::open(&path).expect("open");
            conn.execute_batch("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT);")
                .expect("create");
            // A spread of ordinary rows so the table spans real cells...
            for i in 0..40 {
                conn.execute(
                    "INSERT INTO notes(body) VALUES (?1)",
                    [format!("ordinary note number {i} with some filler text")],
                )
                .expect("insert");
            }
            // ...then the target row with a unique, distinctive marker.
            conn.execute(
                "INSERT INTO notes(body) VALUES (?1)",
                ["DELETED_SECRET_ROW_marker_payload_xyzzy_recover_me"],
            )
            .expect("insert secret");
            conn.execute(
                "DELETE FROM notes WHERE body = ?1",
                ["DELETED_SECRET_ROW_marker_payload_xyzzy_recover_me"],
            )
            .expect("delete secret");
            conn.close().expect("close");
        }
        std::fs::read(&path).expect("read db bytes")
    }

    #[test]
    fn carves_deleted_row_marker() {
        let bytes = db_with_deleted_row();
        let events = parser::events_from_bytes(&bytes, "sqlite-evidence");
        assert!(
            !events.is_empty(),
            "expected the carver to recover at least one deleted row"
        );
        let recovered_the_secret = events.iter().any(|e| {
            e.description.contains("DELETED_SECRET_ROW_marker_payload")
                || e.metadata
                    .values()
                    .any(|v| v.to_string().contains("DELETED_SECRET_ROW_marker_payload"))
        });
        assert!(
            recovered_the_secret,
            "expected the deleted secret row's text among the carved events; got {} events: {:?}",
            events.len(),
            events.iter().map(|e| &e.description).collect::<Vec<_>>()
        );
    }

    #[test]
    fn carved_events_are_marked_deleted_and_sourced_sqlitecarved() {
        let events = parser::events_from_bytes(&db_with_deleted_row(), "sqlite-evidence");
        let carved = events.first().expect("at least one carved event");
        assert_eq!(carved.source, ArtifactType::SqliteCarved);
        assert!(carved.tags.iter().any(|t| t == "deleted"));
        assert!(carved.tags.iter().any(|t| t == "carved"));
        assert_eq!(
            carved.metadata.get("deleted"),
            Some(&serde_json::json!(true))
        );
    }

    #[test]
    fn non_sqlite_bytes_yield_no_events() {
        let events = parser::events_from_bytes(b"not a sqlite database at all", "s");
        assert!(events.is_empty());
    }

    #[test]
    fn supported_artifacts_covers_browser_and_sqlitecarved() {
        // The additive-with-browser contract: co-run on BrowserHistory files AND
        // classify loose SQLite as SqliteCarved.
        let s = SqliteCarveParser.supported_artifacts();
        assert!(s.contains(&ArtifactType::SqliteCarved));
        assert!(s.contains(&ArtifactType::BrowserHistory));
    }
}
