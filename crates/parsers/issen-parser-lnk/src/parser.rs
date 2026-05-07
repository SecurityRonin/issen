//! LNK (Shell Link) header parsing for Windows `.lnk` files.
//!
//! Parses the fixed 76-byte Shell Link header and emits up to three
//! [`TimelineEvent`]s (one per non-zero FILETIME timestamp).
//!
//! Header layout (all values little-endian):
//!
//! | Offset | Size | Field          |
//! |--------|------|----------------|
//! | 0      | 4    | Signature      | `0x4C 0x00 0x00 0x00`
//! | 4      | 16   | LinkCLSID      | (skipped)
//! | 20     | 4    | LinkFlags      |
//! | 24     | 4    | FileAttributes |
//! | 28     | 8    | CreationTime   | FILETIME (u64 LE)
//! | 36     | 8    | AccessTime     | FILETIME (u64 LE)
//! | 44     | 8    | WriteTime      | FILETIME (u64 LE)
//! | 52     | 4    | FileSize       |
//! | 56     | 4    | IconIndex      |
//! | 60     | 4    | ShowCommand    |
//! | 64     | 2    | HotKey         |

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Minimum byte count needed to parse the Shell Link header.
const HEADER_LEN: usize = 76;
/// Expected four-byte signature at offset 0 (`L\0\0\0` = 0x0000004C LE).
const LNK_SIG: &[u8; 4] = &[0x4C, 0x00, 0x00, 0x00];

/// Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to a
/// nanosecond-precision Unix timestamp.
///
/// Returns 0 if the FILETIME predates the Unix epoch (should not happen for
/// valid forensic timestamps).
pub fn filetime_to_ns(ft: u64) -> i64 {
    let ns = (i128::from(ft) - 116_444_736_000_000_000_i128) * 100;
    // Valid forensic timestamps fit within i64 nanoseconds; saturate on overflow.
    i64::try_from(ns).unwrap_or(i64::MAX)
}

/// Parse a Windows LNK (Shell Link) file and return [`TimelineEvent`]s.
///
/// Emits up to three events:
/// - [`EventType::FileCreate`] from `CreationTime` (skipped if zero)
/// - [`EventType::FileAccess`] from `AccessTime` (skipped if zero)
/// - [`EventType::FileModify`] from `WriteTime` (skipped if zero)
///
/// Returns `Ok(vec![])` for:
/// - Files shorter than 76 bytes.
/// - Files whose first four bytes are not the LNK signature.
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failures.
pub fn parse_lnk(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };

    if raw.len() < HEADER_LEN {
        return Ok(vec![]);
    }

    // Validate LNK signature.
    if &raw[0..4] != LNK_SIG {
        return Ok(vec![]);
    }

    // Parse fixed fields.
    let link_flags = u32::from_le_bytes(raw[20..24].try_into().expect("4 bytes"));
    let file_attributes = u32::from_le_bytes(raw[24..28].try_into().expect("4 bytes"));
    let creation_time = u64::from_le_bytes(raw[28..36].try_into().expect("8 bytes"));
    let access_time = u64::from_le_bytes(raw[36..44].try_into().expect("8 bytes"));
    let write_time = u64::from_le_bytes(raw[44..52].try_into().expect("8 bytes"));
    let file_size = u32::from_le_bytes(raw[52..56].try_into().expect("4 bytes"));

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.lnk");
    let description = format!("LNK shortcut: {filename}");
    let artifact_path = path.to_string_lossy().into_owned();

    let link_flags_str = format!("0x{link_flags:08X}");
    let file_attributes_str = format!("0x{file_attributes:08X}");

    let mut events = Vec::with_capacity(3);

    let timestamps: &[(u64, EventType)] = &[
        (creation_time, EventType::FileCreate),
        (access_time, EventType::FileAccess),
        (write_time, EventType::FileModify),
    ];

    for (ft, event_type) in timestamps {
        if *ft == 0 {
            continue;
        }
        let ts_ns = filetime_to_ns(*ft);
        let event = TimelineEvent::new(
            ts_ns,
            String::new(),
            event_type.clone(),
            ArtifactType::Lnk,
            artifact_path.clone(),
            description.clone(),
            source_id.to_string(),
        )
        .with_metadata("file_size", serde_json::json!(file_size))
        .with_metadata("link_flags", serde_json::json!(link_flags_str.clone()))
        .with_metadata(
            "file_attributes",
            serde_json::json!(file_attributes_str.clone()),
        );
        events.push(event);
    }

    Ok(events)
}
