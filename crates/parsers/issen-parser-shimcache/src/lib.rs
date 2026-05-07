//! AppCompatCache (Shimcache) parser for Issen.
//!
//! The Shimcache resides in the `SYSTEM` registry hive under:
//! `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
//! value `AppCompatCache`.
//!
//! Presence of a path in Shimcache proves the binary existed on disk; it does
//! NOT prove execution (use Prefetch or AmCache for that).
//!
//! Binary format (Win8/10 — most common):
//! - Bytes 0..4: signature `[0x30, 0x00, 0x00, 0x00]`
//! - Bytes 4..8: entry count (u32 LE)
//! - Entries from offset 8, each: magic `b"10ts"`, data_len (u16), path_len (u16),
//!   path (UTF-16LE), last-modified FILETIME (u64), optional flags.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

// ---------------------------------------------------------------------------
// Known shimcache signatures (first 4 bytes of AppCompatCache value)
// ---------------------------------------------------------------------------

/// Win XP   — `[0xEE, 0x0F, 0xDC, 0xBA]`
const SIG_XP: [u8; 4] = [0xEE, 0x0F, 0xDC, 0xBA];
/// Win 5.2 / Server 2003 — `[0x30, 0x10, 0x00, 0x00]`
const SIG_WIN52: [u8; 4] = [0x30, 0x10, 0x00, 0x00];
/// Win 7 / 2008 R2 — `[0x00, 0x00, 0x00, 0x80]`
const SIG_WIN7: [u8; 4] = [0x00, 0x00, 0x00, 0x80];
/// Win 8+ / 10 — `[0x30, 0x00, 0x00, 0x00]`
const SIG_WIN8: [u8; 4] = [0x30, 0x00, 0x00, 0x00];

/// Entry magic for Win8/10 entries.
const ENTRY_MAGIC: &[u8; 4] = b"10ts";

// ---------------------------------------------------------------------------
// Binary blob parser
// ---------------------------------------------------------------------------

/// Read a little-endian u16 from `data` at `offset`, returning `None` if out
/// of range.
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Decode a UTF-16LE byte slice into a `String`, replacing invalid code units
/// with the Unicode replacement character.
fn decode_utf16le(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&words).to_owned()
}

/// Parse Win8/10 shimcache entries from `data` starting at `offset`.
///
/// Each entry layout:
/// ```text
/// [4 bytes magic "10ts"][2 bytes data_len][2 bytes path_len]
/// [path_len bytes UTF-16LE path][8 bytes FILETIME][... data_len - path_len - 8 bytes padding]
/// ```
fn parse_win8_entries(data: &[u8], start: usize) -> Vec<String> {
    let mut paths = Vec::new();
    let mut pos = start;

    while pos + 8 <= data.len() {
        // Each entry starts with the "10ts" magic.
        if data.get(pos..pos + 4) != Some(ENTRY_MAGIC.as_ref()) {
            // Scan forward one byte looking for the next entry.
            pos += 1;
            continue;
        }

        let data_len = match read_u16_le(data, pos + 4) {
            Some(v) => v as usize,
            None => break,
        };
        let path_len = match read_u16_le(data, pos + 6) {
            Some(v) => v as usize,
            None => break,
        };

        let path_start = pos + 8;
        let path_end = path_start + path_len;

        if path_end > data.len() {
            break;
        }

        let path = decode_utf16le(&data[path_start..path_end]);
        if !path.is_empty() {
            paths.push(path);
        }

        // Advance past: magic(4) + data_len_field(2) + path_len_field(2) + data_len bytes
        let next = pos + 4 + 2 + 2 + data_len;
        if next <= pos {
            // Protect against zero-length infinite loop.
            break;
        }
        pos = next;
    }

    paths
}

/// Parse paths out of a raw shimcache binary blob.
///
/// Returns a (possibly empty) list of executable path strings.
/// Never fails — unknown or malformed data returns an empty vec.
pub fn parse_shimcache_blob(data: &[u8]) -> Vec<String> {
    if data.len() < 8 {
        return vec![];
    }

    let sig: [u8; 4] = match data.get(0..4) {
        Some(s) => [s[0], s[1], s[2], s[3]],
        None => return vec![],
    };

    match sig {
        SIG_WIN8 => {
            // Bytes 4..8 = entry count (informational; we scan by magic instead).
            // Entries start at offset 8.
            parse_win8_entries(data, 8)
        }
        SIG_WIN7 | SIG_WIN52 | SIG_XP => {
            // Complex, version-specific formats — return empty rather than
            // risk misidentification.  Can be expanded in future iterations.
            vec![]
        }
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Hive-level parsing
// ---------------------------------------------------------------------------

/// ControlSet key names to try, in preference order.
const CONTROL_SETS: &[&str] = &["ControlSet001", "ControlSet002", "CurrentControlSet"];

/// Registry path suffix for the AppCompatCache value.
const APPCOMPAT_KEY_SUFFIX: &str =
    "Control\\Session Manager\\AppCompatCache";

/// Parse a SYSTEM hive file for AppCompatCache (Shimcache) entries.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_shimcache(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    use notatin::cell_value::CellValue;
    use notatin::parser_builder::ParserBuilder;

    // Nonexistent / zero-byte → empty without error.
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Ok(vec![]);
    }

    let owned = path.to_path_buf();
    let mut parser = match ParserBuilder::from_path(owned).build() {
        Ok(p) => p,
        Err(_) => return Ok(vec![]),
    };

    let hive_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("SYSTEM");

    // Try each ControlSet in order until we find the AppCompatCache key.
    let mut raw_blob: Option<Vec<u8>> = None;

    'outer: for control_set in CONTROL_SETS {
        let key_path = format!("{control_set}\\{APPCOMPAT_KEY_SUFFIX}");
        let key = match parser.get_key(&key_path, false) {
            Ok(Some(k)) => k,
            _ => continue,
        };

        if let Some(value) = key.get_value("AppCompatCache") {
            let (cv, _) = value.get_content();
            if let CellValue::Binary(bytes) = cv {
                raw_blob = Some(bytes);
                break 'outer;
            }
        }
    }

    let blob = match raw_blob {
        Some(b) => b,
        None => return Ok(vec![]),
    };

    let paths = parse_shimcache_blob(&blob);

    let artifact_path = format!("{hive_name}\\AppCompatCache");
    let events = paths
        .into_iter()
        .map(|exe_path| {
            let description = format!("Shimcache: {exe_path}");
            TimelineEvent::new(
                0, // Shimcache entries carry no reliable per-entry timestamp.
                "unknown".to_string(),
                EventType::FileAccess,
                ArtifactType::Registry,
                artifact_path.clone(),
                description,
                source_id.to_string(),
            )
            .with_metadata("path", serde_json::json!(exe_path))
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("artifact", serde_json::json!("shimcache"))
        })
        .collect();

    Ok(events)
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// AppCompatCache (Shimcache) parser — reads from the SYSTEM hive.
pub struct ShimcacheParser;

impl ShimcacheParser {
    /// Return `true` when `path`'s filename is `SYSTEM` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "system"
    }
}

impl ForensicParser for ShimcacheParser {
    fn name(&self) -> &str {
        "Shimcache Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Registry]
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, issen_core::error::RtError> {
        Ok(ParseStats::new())
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(256 * 1024 * 1024), // 256 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(ShimcacheParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── can_parse tests ────────────────────────────────────────────────────

    #[test]
    fn can_parse_system_hive() {
        assert!(
            ShimcacheParser::can_parse(&PathBuf::from(
                "/evidence/C/Windows/System32/config/SYSTEM"
            )),
            "expected can_parse to return true for SYSTEM"
        );
    }

    #[test]
    fn can_parse_system_hive_lowercase() {
        assert!(
            ShimcacheParser::can_parse(&PathBuf::from("/evidence/system")),
            "expected can_parse to return true for lowercase 'system'"
        );
    }

    #[test]
    fn cannot_parse_software_hive() {
        assert!(
            !ShimcacheParser::can_parse(&PathBuf::from("/evidence/SOFTWARE")),
            "expected can_parse to return false for SOFTWARE"
        );
    }

    #[test]
    fn cannot_parse_amcache() {
        assert!(
            !ShimcacheParser::can_parse(&PathBuf::from("/evidence/Amcache.hve")),
            "expected can_parse to return false for Amcache.hve"
        );
    }

    // ── parse tests ────────────────────────────────────────────────────────

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_shimcache(Path::new("/nonexistent/SYSTEM"), "test");
        assert!(
            result.is_ok(),
            "parse_shimcache must return Ok for a nonexistent path, got: {result:?}"
        );
        assert!(
            result.unwrap().is_empty(),
            "nonexistent path should produce zero events"
        );
    }

    /// Verifies that a zero-byte / empty hive returns Ok(vec![]).
    #[test]
    fn parse_system_hive_without_appcompat_key_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Empty file — no valid hive, no AppCompatCache key.
        let result = parse_shimcache(tmp.path(), "test");
        assert!(
            result.is_ok(),
            "parse_shimcache must return Ok for an empty/invalid hive"
        );
        assert!(
            result.unwrap().is_empty(),
            "empty hive must produce zero events"
        );
    }

    // ── parse_shimcache_blob tests ─────────────────────────────────────────

    #[test]
    fn blob_empty_returns_empty() {
        assert!(parse_shimcache_blob(&[]).is_empty());
    }

    #[test]
    fn blob_garbage_returns_empty() {
        // Random bytes with no known signature must not panic and return empty.
        assert!(parse_shimcache_blob(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]).is_empty());
    }

    /// GREEN test: a minimal Win8+ shimcache blob should produce at least one path.
    #[test]
    fn blob_win8_signature_yields_paths() {
        // Win8+ magic: [0x30, 0x00, 0x00, 0x00]
        // Followed by 4-byte entry count, then entries.
        // Each entry: magic "10ts" (0x74733031), u16 data_len, u16 path_len, UTF-16LE path.
        // Construct a minimal blob with one entry: path = "C:\foo.exe"
        let path_utf16: Vec<u8> = "C:\\foo.exe"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let path_len = path_utf16.len() as u16;

        // data_len covers: path + 8-byte FILETIME (no extra flags in this minimal blob)
        let data_len = path_len + 8;

        let mut blob = Vec::new();
        // Header: Win8+ signature
        blob.extend_from_slice(&[0x30, 0x00, 0x00, 0x00]);
        // Entry count (1)
        blob.extend_from_slice(&1u32.to_le_bytes());
        // Entry magic "10ts"
        blob.extend_from_slice(ENTRY_MAGIC);
        // data_len (u16 LE)
        blob.extend_from_slice(&data_len.to_le_bytes());
        // path_len (u16 LE)
        blob.extend_from_slice(&path_len.to_le_bytes());
        // path bytes (UTF-16LE)
        blob.extend_from_slice(&path_utf16);
        // last-modified FILETIME (8 bytes)
        blob.extend_from_slice(&0u64.to_le_bytes());

        let paths = parse_shimcache_blob(&blob);

        assert!(
            !paths.is_empty(),
            "Win8+ shimcache blob must yield at least one path"
        );
        assert!(
            paths.iter().any(|p| p.contains("foo.exe")),
            "expected 'foo.exe' in extracted paths, got: {paths:?}"
        );
    }
}
