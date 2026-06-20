//! Jump List parsing for Issen — `*.automaticDestinations-ms` (OLE/CFB, a DestList
//! MRU of recent items + embedded LNK sub-streams) and `*.customDestinations-ms`
//! (flat, pinned/custom items). Decoding is delegated to `lnk-core`'s readers; each
//! entry becomes a `FileSystemActivity` [`TimelineEvent`] — the per-application
//! recent/pinned file history that survives the target file's deletion.

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Parse Jump List bytes (dispatching on the filename suffix) into timeline
/// events. Unrecognized / unparseable input yields an empty vec.
#[must_use]
pub fn parse_jumplist_bytes(_raw: &[u8], _filename: &str, _source_id: &str) -> Vec<TimelineEvent> {
    // stub — RED
    let _ = (EventType::FileAccess, ArtifactType::JumpLists);
    Vec::new()
}
