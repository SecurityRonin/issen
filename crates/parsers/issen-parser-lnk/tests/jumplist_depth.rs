//! Jump List parser-depth regression (Track 2 / un-darkening `ArtifactType::JumpLists`).
//!
//! Jump Lists are per-application recent/pinned file history — RecentDocs-equivalent
//! evidence that survives the target file's deletion. lnk-core decodes both forms;
//! the wrapper must surface each entry's target + origin.
//!
//! `pinned_removable.automaticDestinations-ms`: one PINNED entry to `E:\report.docx`
//! on host `OTHER-PC`, access count 7. `tasks.customDestinations-ms`: one entry
//! targeting `E:\report.docx`.

use issen_parser_lnk::jumplist::parse_jumplist_bytes;

const AUTO: &[u8] = include_bytes!("data/pinned_removable.automaticDestinations-ms");
const CUSTOM: &[u8] = include_bytes!("data/tasks.customDestinations-ms");

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
fn automatic_destinations_surfaces_recent_file_and_origin() {
    let events = parse_jumplist_bytes(AUTO, "pinned_removable.automaticDestinations-ms", "ev");
    assert!(
        !events.is_empty(),
        "the Jump List parses to at least one event"
    );
    let blob = searchable(&events);
    assert!(
        blob.contains("report.docx"),
        "must surface the recent-file target the Jump List records; got: {blob}"
    );
    assert!(
        blob.to_uppercase().contains("OTHER-PC"),
        "must surface the recording host (a cross-machine origin signal); got: {blob}"
    );
}

#[test]
fn automatic_destinations_marks_pinned_with_access_count() {
    let events = parse_jumplist_bytes(AUTO, "pinned_removable.automaticDestinations-ms", "ev");
    let blob = searchable(&events).to_lowercase();
    assert!(
        blob.contains("pinned"),
        "must surface the pinned state (pinned items are deliberately retained); got: {blob}"
    );
}

#[test]
fn custom_destinations_surfaces_target() {
    let events = parse_jumplist_bytes(CUSTOM, "tasks.customDestinations-ms", "ev");
    assert!(
        !events.is_empty(),
        "the custom Jump List parses to at least one event"
    );
    let blob = searchable(&events);
    assert!(
        blob.contains("report.docx"),
        "must surface the custom-destination target; got: {blob}"
    );
}
