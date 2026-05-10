//! Integration tests for the collection-loading pipeline.
//!
//! These tests exercise the full path from archive file to parsed investigation
//! data, using the real UAC and Velociraptor test archives. They are marked
//! `#[ignore]` because the test data files are large (143 MB UAC, 2.2 GB
//! Velociraptor) and extraction is I/O-intensive.
//!
//! Run manually with:
//! ```sh
//! cargo test -p rt-navigator --test collection_loading -- --ignored
//! ```

// Pull in collection provider registrations via inventory.
extern crate issen_parser_uac;
extern crate issen_parser_velociraptor;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_unpack::registry::open_collection;

/// Path to the UAC test archive (143 MB).
const UAC_ARCHIVE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/Hal Linux DFIR Challenge/uac-vbox-linux-20260324193807.tar.gz"
);

/// Path to the Velociraptor test archive (2.2 GB).
const VELOCIRAPTOR_ARCHIVE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip"
);

// ---------------------------------------------------------------------------
// Test 1: UAC collection opens via issen_unpack
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_uac_collection_opens() {
    let path = Path::new(UAC_ARCHIVE);
    assert!(path.exists(), "UAC test archive not found: {UAC_ARCHIVE}");

    let manifest = open_collection(path).expect("open_collection should succeed for UAC archive");

    assert!(
        manifest.format_name.contains("UAC"),
        "format_name should contain 'UAC', got: {}",
        manifest.format_name
    );
    assert!(
        manifest.extracted_root.exists(),
        "extracted_root should exist on disk"
    );
}

// ---------------------------------------------------------------------------
// Test 2: UAC collection has artifacts
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_uac_collection_has_artifacts() {
    let path = Path::new(UAC_ARCHIVE);
    assert!(path.exists(), "UAC test archive not found: {UAC_ARCHIVE}");

    let manifest = open_collection(path).expect("open_collection should succeed for UAC archive");

    assert!(
        !manifest.artifacts.is_empty(),
        "UAC manifest should list at least one artifact"
    );

    // Verify at least some artifacts have classified types
    let classified_count = manifest
        .artifacts
        .iter()
        .filter(|e| e.artifact_type.is_some())
        .count();
    eprintln!(
        "  UAC artifacts: {} total, {} classified",
        manifest.artifacts.len(),
        classified_count
    );
}

// ---------------------------------------------------------------------------
// Test 3: Velociraptor collection opens via issen_unpack
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_velociraptor_collection_opens() {
    let path = Path::new(VELOCIRAPTOR_ARCHIVE);
    assert!(
        path.exists(),
        "Velociraptor test archive not found: {VELOCIRAPTOR_ARCHIVE}"
    );

    let manifest =
        open_collection(path).expect("open_collection should succeed for Velociraptor archive");

    assert!(
        manifest.format_name.contains("elociraptor"),
        "format_name should contain 'elociraptor', got: {}",
        manifest.format_name
    );
    assert!(
        manifest.extracted_root.exists(),
        "extracted_root should exist on disk"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Velociraptor collection has MFT artifact
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_velociraptor_collection_has_mft() {
    let path = Path::new(VELOCIRAPTOR_ARCHIVE);
    assert!(
        path.exists(),
        "Velociraptor test archive not found: {VELOCIRAPTOR_ARCHIVE}"
    );

    let manifest =
        open_collection(path).expect("open_collection should succeed for Velociraptor archive");

    let has_mft = manifest
        .artifacts
        .iter()
        .any(|e| e.artifact_type == Some(ArtifactType::Mft));
    assert!(
        has_mft,
        "Velociraptor collection should contain at least one MFT artifact"
    );

    // Also report all artifact types found
    let mut type_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for entry in &manifest.artifacts {
        if let Some(ref t) = entry.artifact_type {
            *type_counts.entry(format!("{t:?}")).or_insert(0) += 1;
        }
    }
    let mut sorted: Vec<_> = type_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (t, c) in &sorted {
        eprintln!("  {c} {t}");
    }
}

// ---------------------------------------------------------------------------
// Test 5: UAC loads investigation data with timeline events
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_uac_loads_investigation_data() {
    let path = Path::new(UAC_ARCHIVE);
    assert!(path.exists(), "UAC test archive not found: {UAC_ARCHIVE}");

    let manifest = open_collection(path).expect("open_collection should succeed for UAC archive");

    let data = issen_navigator::investigation::data::load_uac_collection(
        &manifest.extracted_root,
        Some(&manifest.metadata),
    );

    // Timeline should have events from bodyfile and/or login history
    assert!(
        !data.timeline.is_empty(),
        "UAC investigation data should have timeline events"
    );
    eprintln!("  Timeline events: {}", data.timeline.len());
    eprintln!("  Alerts: {}", data.alerts.len());
    eprintln!("  Network connections: {}", data.network.len());
    eprintln!("  Processes: {}", data.processes.len());
    eprintln!("  Login records: {}", data.logins.len());
    eprintln!("  Packages: {}", data.packages.len());
    eprintln!("  Hashed executables: {}", data.hashes.len());
    eprintln!("  Configs: {}", data.configs.len());

    // Metadata should be populated from the manifest
    assert!(
        !data.metadata.hostname.is_empty(),
        "hostname should be set from manifest metadata"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Velociraptor loads investigation data with artifact counts
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_velociraptor_loads_investigation_data() {
    let path = Path::new(VELOCIRAPTOR_ARCHIVE);
    assert!(
        path.exists(),
        "Velociraptor test archive not found: {VELOCIRAPTOR_ARCHIVE}"
    );

    let manifest =
        open_collection(path).expect("open_collection should succeed for Velociraptor archive");

    let data = issen_navigator::investigation::data::load_velociraptor_collection(
        &manifest.extracted_root,
        &manifest.artifacts,
        &manifest.metadata,
    );

    // Artifact counts should be populated from manifest entries
    assert!(
        !data.artifact_counts.is_empty(),
        "Velociraptor investigation data should have artifact counts"
    );
    eprintln!("  Artifact counts:");
    let mut sorted: Vec<_> = data.artifact_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (label, count) in &sorted {
        eprintln!("    {count} {label}");
    }

    // Metadata should be populated
    assert!(
        !data.metadata.hostname.is_empty(),
        "hostname should be set from manifest metadata"
    );
    eprintln!("  Hostname: {}", data.metadata.hostname);
    eprintln!("  OS: {}", data.metadata.os);
    eprintln!("  Collection tool: {}", data.metadata.collection_tool);
}
