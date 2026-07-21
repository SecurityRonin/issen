//! File-level SQLite deleted-row carver for Issen (ADR 0018 tier 1).
//!
//! Recovers deleted rows from a *located* SQLite database's own free space — its
//! freelist pages and in-page free blocks — via our published fleet crates
//! (`sqlite-core` reader + `sqlite-forensic` analyzer). The recovery is bounded by
//! the file already in hand (marginal cost on top of the parse), so it runs in the
//! default triage path per ADR 0018. Whole-disk unallocated carving (the
//! `--deleted` tier) is out of scope here.
//!
//! The carved rows are emitted as **deleted/carved** [`TimelineEvent`]s with
//! `source = ArtifactType::SqliteCarved`, additive to and clearly distinct from
//! `issen-browser`'s live-row events — the two co-run on the same browser SQLite
//! databases without conflict (see the wiring note in the crate README / task).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod parser;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Build a real SQLite database with a distinctively-marked row, DELETE it,
    /// and return the file bytes — the deleted row's content survives in free
    /// space (SQLite `secure_delete` is OFF by default), so the carver must
    /// recover it. This is the RED assertion the stub fails.
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
}
