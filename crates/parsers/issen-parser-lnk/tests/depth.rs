//! Parser-depth regression (Track 2): the LNK parser must surface WHAT the
//! shortcut points to (the target path) and the USB-origin fields the owned
//! `lnk-core` already decodes — not just the `.lnk`'s own filename.
//!
//! Fixture `removable_media.lnk` targets `E:\payload.exe` on a REMOVABLE volume
//! "KINGSTON USB" (drive serial 0xDEADBEEF). The `.lnk` is labelled `Secret.lnk`
//! here, so "payload.exe" can ONLY appear if the target path is surfaced.

use issen_parser_lnk::parser::parse_lnk_bytes;

const REMOVABLE: &[u8] = include_bytes!("data/removable_media.lnk");

fn searchable(events: &[issen_core::timeline::event::TimelineEvent]) -> String {
    events
        .iter()
        .flat_map(|e| {
            std::iter::once(e.description.clone())
                .chain(e.metadata.iter().map(|(k, v)| format!("{k}={v}")))
        })
        .collect::<Vec<_>>()
        .join("  ")
}

#[test]
fn surfaces_target_path_for_usb_origin() {
    let events = parse_lnk_bytes(REMOVABLE, "/Users/beth/Recent/Secret.lnk", "ev");
    assert!(!events.is_empty(), "the .lnk parses to at least one event");
    let blob = searchable(&events);
    assert!(
        blob.contains("payload.exe"),
        "must surface the TARGET the shortcut points to (E:\\payload.exe), not just \
         the .lnk's own name; got: {blob}"
    );
}

#[test]
fn surfaces_drive_serial_join_key() {
    let events = parse_lnk_bytes(REMOVABLE, "/Users/beth/Recent/Secret.lnk", "ev");
    let blob = searchable(&events).to_lowercase();
    assert!(
        blob.contains("deadbeef") || blob.contains("3735928559"),
        "must surface the drive serial (the USB-origin join key to a peripheral \
         device); got: {blob}"
    );
}

/// Fixture `network_share.lnk` targets a UNC share `\\SERVER\share` mapped to
/// device `Z:` via a `CommonNetworkRelativeLink`. The UNC origin is the
/// lateral-movement / network-share join key the wrapper previously dropped
/// (it surfaced only the local `VolumeID`, never the network link).
const NETWORK: &[u8] = include_bytes!("data/network_share.lnk");

#[test]
fn surfaces_unc_network_share_target() {
    let events = parse_lnk_bytes(NETWORK, "/Users/beth/Recent/Share.lnk", "ev");
    assert!(
        !events.is_empty(),
        "the network .lnk parses to at least one event"
    );
    let blob = searchable(&events).to_uppercase();
    assert!(
        blob.contains(r"\\SERVER\SHARE"),
        "must surface the UNC network share the shortcut points to \
         (\\\\SERVER\\share); got: {blob}"
    );
}

#[test]
fn surfaces_mapped_network_device() {
    let events = parse_lnk_bytes(NETWORK, "/Users/beth/Recent/Share.lnk", "ev");
    let blob = searchable(&events).to_uppercase();
    assert!(
        blob.contains("Z:"),
        "must surface the local device the share was mapped to (Z:); got: {blob}"
    );
}
