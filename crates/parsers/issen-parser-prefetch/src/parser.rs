//! Prefetch header parsing for Windows `.pf` files.
//!
//! Parses the fixed 84-byte SCCA header and emits one [`TimelineEvent`] per
//! file.  Timestamps require deeper parsing (MAM/format-specific offsets) and
//! are stubbed to 0.
//!
//! Header layout (all values little-endian):
//!
//! | Offset | Size | Field         |
//! |--------|------|---------------|
//! | 0      | 4    | Signature     | "SCCA"
//! | 4      | 4    | Version       | 17=XP, 23=7, 26=8, 30=10/11
//! | 8      | 4    | File size     |
//! | 12     | 60   | Exe name      | UTF-16LE, null-terminated
//! | 72     | 4    | Prefetch hash |
//! | 76     | 8    | (padding)     |

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Minimum number of bytes needed to parse the SCCA header.
const HEADER_LEN: usize = 84;
/// Expected four-byte signature at offset 0.
const SCCA_SIG: &[u8; 4] = b"SCCA";
/// Byte length of the UTF-16LE executable name field.
const EXE_NAME_BYTES: usize = 60;

/// Parse a Windows Prefetch file and return [`TimelineEvent`]s.
///
/// Returns `Ok(vec![])` for:
/// - Files shorter than [`HEADER_LEN`] bytes.
/// - Files whose first four bytes are not `"SCCA"`.
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failures.
pub fn parse_prefetch(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    // Read the raw file bytes; avoid reading more than needed.
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };

    if raw.len() < HEADER_LEN {
        return Ok(vec![]);
    }

    // Validate signature.
    if &raw[0..4] != SCCA_SIG {
        return Ok(vec![]);
    }

    // Parse fixed fields.
    let version = u32::from_le_bytes(raw[4..8].try_into().expect("4 bytes"));
    let file_size = u32::from_le_bytes(raw[8..12].try_into().expect("4 bytes"));
    let hash = u32::from_le_bytes(raw[72..76].try_into().expect("4 bytes"));

    // Decode UTF-16LE executable name (60 bytes = up to 30 UTF-16 code units).
    let exe_name = decode_utf16le_name(&raw[12..12 + EXE_NAME_BYTES]);

    let description = format!("Prefetch: {exe_name} (hash: {hash:08x})");

    let event = TimelineEvent::new(
        0, // timestamps require deeper parsing; stub with 0
        String::new(),
        EventType::ProcessExec,
        ArtifactType::Prefetch,
        exe_name.clone(),
        description,
        source_id.to_string(),
    )
    .with_metadata("version", serde_json::json!(version))
    .with_metadata("file_size", serde_json::json!(file_size))
    .with_metadata("hash", serde_json::json!(format!("0x{hash:08X}")));

    Ok(vec![event])
}

/// Decode a null-terminated UTF-16LE byte slice into a `String`.
///
/// Stops at the first null code unit (0x0000). Invalid surrogates are replaced
/// with U+FFFD.
fn decode_utf16le_name(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&w| w != 0)
        .collect();
    char::decode_utf16(words)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}
