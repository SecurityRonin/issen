//! Windows Recycle Bin `$I` index file parser for Issen.
//!
//! Reads a `$I` index file (deleted-file metadata) via [`trash-core`] and
//! emits one [`TimelineEvent`] per deleted file — an [`EventType::FileDelete`]
//! tagged [`ArtifactType::RecycleBin`] at the recorded deletion time, carrying
//! the recovered ORIGINAL path. Sending a file to the Recycle Bin is the user
//! intentionally removing it, so the event is tagged
//! [`ActivityCategory::AntiForensics`].
//!
//! [`trash-core`]: https://docs.rs/trash-core

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unnecessary_literal_bound
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseOptions, ParseStats,
    ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Windows Recycle Bin `$I` index file parser.
pub struct RecycleBinParser;

impl ForensicParser for RecycleBinParser {
    fn name(&self) -> &str {
        "Recycle Bin Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::RecycleBin]
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

        // `$I` index files are tiny (header + one path); read the whole thing.
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

        let artifact_path = input.source_path().map_or_else(
            || "recyclebin-evidence".to_string(),
            |p| p.to_string_lossy().into_owned(),
        );

        // A malformed/truncated $I is not fatal to the ingest: decline it (no
        // events, Unsupported) rather than aborting the whole run.
        let Ok(index) = trash_core::parse_index(&bytes[..off as usize]) else {
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        };

        // Recover the paired `$R` content file (B7). The disk-collection sweep
        // places `$R…` beside `$I…` in the extracted tree, so when this `$I` was
        // opened from a real path we can read its sibling and surface the
        // deleted file's content. A bytes-only source (no path) degrades to
        // index-only, exactly as before.
        let recovered = input
            .source_path()
            .and_then(|p| recover_sibling(p, index.original_size));

        let mut events = Vec::with_capacity(1);
        if let Some(event) = delete_event(&index, &artifact_path, recovered.as_ref()) {
            events.push(event);
        }

        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
        stats.completion = ParseCompletion::Complete;
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(16 * 1024 * 1024), // 16 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

/// Recovered `$R` content paired with a `$I` index (B7 — "recover the original
/// file"). `preview` is a sanitized, bounded UTF-8 rendering for text content;
/// binary content yields `None`.
struct RecoveredContent {
    size: u64,
    size_matches: bool,
    preview: Option<String>,
}

/// Read the `$R` content file paired with a `$I` index at `i_path` and
/// summarize it. Windows pairs them by swapping the `$I`/`$R` prefix in the
/// same directory. Returns `None` when the name is not a `$I` index, the
/// sibling `$R` is absent, or it cannot be read.
fn recover_sibling(i_path: &Path, original_size: u64) -> Option<RecoveredContent> {
    let r_name = sibling_r_name(i_path.file_name()?.to_str()?)?;
    let bytes = std::fs::read(i_path.with_file_name(r_name)).ok()?;
    let size = bytes.len() as u64;
    Some(RecoveredContent {
        size,
        size_matches: size == original_size,
        preview: text_preview(&bytes),
    })
}

/// Map a `$I…` filename to its paired `$R…` filename, preserving the prefix
/// case as it sits on disk. `None` when the name is not a `$I` index name.
fn sibling_r_name(i_name: &str) -> Option<String> {
    i_name
        .strip_prefix("$I")
        .map(|rest| format!("$R{rest}"))
        .or_else(|| i_name.strip_prefix("$i").map(|rest| format!("$r{rest}")))
}

/// A bounded, sanitized UTF-8 preview of recovered content, or `None` when the
/// bytes are not valid UTF-8 (binary content). Control characters other than
/// tab/newline are stripped, and the preview is capped to keep the event small.
fn text_preview(bytes: &[u8]) -> Option<String> {
    const MAX_CHARS: usize = 256;
    let text = std::str::from_utf8(bytes).ok()?;
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(MAX_CHARS)
        .collect();
    (!cleaned.trim().is_empty()).then_some(cleaned)
}

/// Build a `FileDelete` [`TimelineEvent`] from a decoded `$I` index, enriched
/// with the recovered `$R` content when its sibling was available.
///
/// Returns `None` when the recorded deletion `FILETIME` is zero/out of range
/// (`deleted_at == None`): without a deletion timestamp there is no timeline
/// anchor for the event, so it is dropped rather than emitted at epoch 0.
fn delete_event(
    index: &trash_core::RecycleBinIndex,
    artifact_path: &str,
    recovered: Option<&RecoveredContent>,
) -> Option<TimelineEvent> {
    let ts_ns = index.deleted_at?.timestamp_nanos_opt()?;

    let mut description = format!(
        "Deleted file: {} ({} bytes)",
        index.original_path, index.original_size
    );
    if recovered.is_some() {
        description.push_str(" — content recovered from $R");
    }

    let mut event = TimelineEvent::new(
        ts_ns,
        String::new(),
        EventType::FileDelete,
        ArtifactType::RecycleBin,
        artifact_path.to_string(),
        description,
        "recyclebin-evidence".to_string(),
    )
    .with_activity_category(issen_core::ActivityCategory::AntiForensics)
    .with_metadata("original_size", serde_json::json!(index.original_size))
    .with_metadata(
        "original_path",
        serde_json::json!(index.original_path.clone()),
    )
    .with_metadata(
        "index_version",
        serde_json::json!(format!("{:?}", index.version)),
    );

    if let Some(rc) = recovered {
        event = event
            .with_metadata("recovered_content_size", serde_json::json!(rc.size))
            .with_metadata("content_size_matches", serde_json::json!(rc.size_matches));
        if let Some(preview) = &rc.preview {
            event = event.with_metadata("recovered_content_preview", serde_json::json!(preview));
        }
    }

    Some(event)
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(RecycleBinParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::RecycleBin,
            matches: classify::recycle_i,
            priority: 80,
            disk_sources: &[
                sel::DiskSource::Ntfs(sel::NtfsLoc::PerSubdirSweep { parent: r"\$Recycle.Bin", rel: r"", name: sel::NameMatch::Prefix("$i") }),
                // Collect the paired `$R` content files too, so they land beside
                // their `$I` index in the extracted tree for sibling recovery
                // (B7). `classify::recycle_i` matches only `$i`, so a `$R` is
                // never parsed standalone — it is read via its `$I`'s source_path.
                sel::DiskSource::Ntfs(sel::NtfsLoc::PerSubdirSweep { parent: r"\$Recycle.Bin", rel: r"", name: sel::NameMatch::Prefix("$r") }),
            ],
            cost: sel::CostTier::Default,
        } }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
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
            self.0.lock().expect("lock").push(e);
            Ok(())
        }
        fn emit_batch(&self, mut e: Vec<TimelineEvent>) -> Result<(), RtError> {
            self.0.lock().expect("lock").append(&mut e);
            Ok(())
        }
    }

    /// A file-backed `DataSource` that reports its `source_path` — exercises the
    /// `$R` sibling-recovery path (which reads the paired content file from the
    /// `$I` file's directory).
    struct FileSource {
        bytes: Vec<u8>,
        path: std::path::PathBuf,
    }
    impl DataSource for FileSource {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let off = offset as usize;
            let n = buf.len().min(self.bytes.len().saturating_sub(off));
            buf[..n].copy_from_slice(&self.bytes[off..off + n]);
            Ok(n)
        }
        fn source_path(&self) -> Option<&std::path::Path> {
            Some(&self.path)
        }
    }

    /// Build a valid version-2 `$I` index file:
    ///   [0..8]   version = 2 (LE u64)
    ///   [8..16]  original size (LE u64)
    ///   [16..24] deletion FILETIME (LE u64)
    ///   [24..28] name length in chars incl. NUL (LE u32)
    ///   [28..]   UTF-16LE path, NUL-terminated
    fn build_v2_index(original_path: &str, size: u64, filetime: u64) -> Vec<u8> {
        let mut utf16: Vec<u16> = original_path.encode_utf16().collect();
        utf16.push(0); // NUL terminator
        let chars = utf16.len() as u32;

        let mut data = Vec::new();
        data.extend_from_slice(&2u64.to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(&filetime.to_le_bytes());
        data.extend_from_slice(&chars.to_le_bytes());
        for unit in utf16 {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data
    }

    #[test]
    fn recovers_dollar_r_content_from_sibling() {
        // B7: with the paired `$R` content file present beside the `$I` index
        // (as the disk-collection sweep now places them), the parser recovers the
        // deleted file's content — answering "recover the original file" (the
        // Szechuan `SECRET_beth.txt` → "Earth beth is the real beth.").
        let dir = tempfile::tempdir().expect("tempdir");
        let i_path = dir.path().join("$IU2L112.txt");
        let r_path = dir.path().join("$RU2L112.txt");
        let content = b"Earth beth is the real beth."; // 28 bytes
        let idx = build_v2_index(
            r"C:\FileShare\Secret\SECRET_beth.txt",
            content.len() as u64,
            132_000_000_000_000_000u64,
        );
        std::fs::write(&i_path, &idx).expect("write $I");
        std::fs::write(&r_path, content).expect("write $R");

        let source = FileSource {
            bytes: idx,
            path: i_path,
        };
        let collector = Collector::default();
        RecycleBinParser
            .parse(
                &source,
                &collector,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse");

        let events = collector.0.lock().expect("lock");
        assert_eq!(events.len(), 1);
        let m = &events[0].metadata;
        assert_eq!(
            m.get("recovered_content_size")
                .and_then(serde_json::Value::as_u64),
            Some(28),
            "the recovered $R content length must be surfaced"
        );
        assert_eq!(
            m.get("content_size_matches")
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "$R length must match the $I-recorded original size"
        );
        assert_eq!(
            m.get("recovered_content_preview")
                .and_then(serde_json::Value::as_str),
            Some("Earth beth is the real beth."),
            "the recovered text content must be surfaced as a preview"
        );
        assert!(
            events[0].description.contains("recovered"),
            "the FileDelete description must note content was recovered: {}",
            events[0].description
        );
    }

    #[test]
    fn parse_v2_index_emits_one_delete_event() {
        // FILETIME 132000000000000000 = 2019-02-04T22:40:00Z.
        // unix_ns = (132000000000000000 - 116444736000000000) * 100
        //         = 15555264000000000 * 100 = 1_555_526_400_000_000_000
        let path = r"C:\Users\beth\Documents\secret.docx";
        let data = build_v2_index(path, 4096, 132_000_000_000_000_000u64);

        let source = MemSource(data);
        let collector = Collector::default();
        let stats = RecycleBinParser
            .parse(
                &source,
                &collector,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("parse must not Err on a valid $I file");

        assert_eq!(stats.events_emitted, 1, "one deleted-file event expected");

        let events = collector.0.lock().expect("lock");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event_type, EventType::FileDelete);
        assert_eq!(ev.source, ArtifactType::RecycleBin);
        assert_eq!(
            ev.activity_category,
            Some(issen_core::ActivityCategory::AntiForensics)
        );
        assert_eq!(ev.timestamp_ns, 1_555_526_400_000_000_000);
        assert!(
            ev.description.contains(path),
            "description must carry the recovered original path, got: {}",
            ev.description
        );
        assert!(
            ev.description.contains("4096"),
            "description must carry the original size, got: {}",
            ev.description
        );
        assert_eq!(
            ev.metadata
                .get("original_size")
                .and_then(serde_json::Value::as_u64),
            Some(4096),
            "original_size metadata must be present"
        );
        assert_eq!(
            ev.metadata
                .get("original_path")
                .and_then(serde_json::Value::as_str),
            Some(path),
            "original_path metadata must be present"
        );
    }

    #[test]
    fn parse_empty_is_unsupported() {
        let source = MemSource(Vec::new());
        let collector = Collector::default();
        let stats = RecycleBinParser
            .parse(
                &source,
                &collector,
                &issen_core::plugin::ParseOptions::default(),
            )
            .expect("empty source must not Err");
        assert_eq!(stats.events_emitted, 0);
        assert_eq!(stats.completion, ParseCompletion::Unsupported);
    }
}
