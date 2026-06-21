//! Disk-collection completeness gate (issen #114).
//!
//! `selector_gate` proves every parser declares a consistent selector;
//! `classifier_differential` proves the registry classifier is correct. Neither
//! checks the COLLECTION layer — the step that pulls artifact bytes off a raw
//! NTFS disk image. This gate closes that gap: every `ArtifactType` the registry
//! classifier can produce must also be COLLECTED by `issen_disk::extract_triage`
//! — or be on an explicit EXEMPT list with a stated reason.
//!
//! A classified-but-uncollected type is the dark-on-disk bug class: live on
//! loose-file / KAPE ingest (the walker classifies every file) yet silently
//! producing nothing on a raw E01, because the hand-maintained `WINDOWS_*`
//! extraction lists never pulled its bytes. That is exactly how `.lnk`, `$I`,
//! and `setupapi.dev.log` went dark on disk images while their parsers existed,
//! were registered, anchored, and classified.
//!
//! Method: the COLLECTED set is derived at runtime by running the real
//! `WINDOWS_*` extraction targets through `detect_from_registry`; the CLASSIFIED
//! set is each linked parser's declared selector type. The diff, minus EXEMPT,
//! must be empty.

use std::collections::BTreeSet;

use issen_cli as _;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector::CostTier;

/// Types the filename classifier can discover but that disk-image triage
/// intentionally does NOT collect — each with the reason it is exempt:
/// - `Pe`: cost policy — carving every executable off an image is too expensive;
///   PE collection is opt-in, not part of default triage.
/// - `SystemInfo` / `LoginHistory` / `CrontabConfig`: Linux/macOS artifacts.
///   `extract_triage` walks NTFS only; there is no ext4/APFS extraction path yet.
/// - `BiomeMenuItem`: a macOS Biome SEGB artifact — likewise not on NTFS, and
///   reachable via the dedicated `issen biome` command.
const EXEMPT: &[&str] = &[
    "Pe",
    "SystemInfo",
    "LoginHistory",
    "CrontabConfig",
    "BiomeMenuItem",
];

/// The `ArtifactType`s the registry classifier can produce — i.e. the type each
/// linked parser declares on its selector (force-linked via `use issen_cli`).
fn classified_types() -> BTreeSet<String> {
    inventory::iter::<ParserRegistration>
        .into_iter()
        .map(|r| format!("{:?}", r.selector.artifact_type))
        .collect()
}

/// The `ArtifactType`s actually COLLECTED off an NTFS image. Collection is now
/// fully selector-driven (`extract_triage` → `collect_sources(triage_ntfs_sources())`),
/// so a type is collected iff its selector declares at least one Default-cost NTFS
/// `disk_source`. Deriving the set from the selectors — the single source of truth —
/// rather than the legacy `WINDOWS_*` consts removes the const-drift this gate
/// previously risked (the consts are now only a test oracle for `issen-disk`).
fn collected_types() -> BTreeSet<String> {
    inventory::iter::<ParserRegistration>
        .into_iter()
        .filter(|r| r.selector.cost == CostTier::Default && !r.selector.disk_sources.is_empty())
        .map(|r| format!("{:?}", r.selector.artifact_type))
        .collect()
}

#[test]
fn every_classified_windows_artifact_is_collected_on_the_disk_path() {
    let classified = classified_types();
    let collected = collected_types();
    let exempt: BTreeSet<String> = EXEMPT.iter().map(|s| (*s).to_string()).collect();

    let dark: Vec<String> = classified
        .difference(&collected)
        .filter(|t| !exempt.contains(*t))
        .cloned()
        .collect();

    assert!(
        dark.is_empty(),
        "ArtifactType(s) the classifier discovers but `extract_triage` never \
         collects off an NTFS image, and which are not on the EXEMPT list: {dark:?}.\n\
         These parsers are LIVE on loose-file ingest but DARK on raw disk images. \
         Either add the artifact's path/glob to the WINDOWS_* lists in \
         crates/issen-disk/src/lib.rs, or add the type to EXEMPT with a reason."
    );
}
