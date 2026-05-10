use std::path::Path;

use issen_unpack::{CollectionProvider, Confidence};

#[test]
fn test_probe_real_velociraptor_collection() {
    let path = Path::new("../../tests/data/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = issen_parser_velociraptor::VelociraptorProvider;
    let confidence = provider.probe(path).expect("probe should succeed");
    assert_eq!(
        confidence,
        Confidence::High,
        "Should detect Velociraptor zip"
    );
}

#[test]
fn test_open_real_velociraptor_collection() {
    let path = Path::new("../../tests/data/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = issen_parser_velociraptor::VelociraptorProvider;
    let manifest = provider.open(path).expect("open should succeed");

    assert_eq!(manifest.format_name, "Velociraptor");
    assert_eq!(
        manifest.metadata.hostname.as_deref(),
        Some("A380_localdomain")
    );
    assert!(!manifest.artifacts.is_empty(), "Should discover artifacts");

    // Check that key artifacts were found
    let has_mft = manifest
        .artifacts
        .iter()
        .any(|e| e.artifact_type == Some(issen_core::artifacts::ArtifactType::Mft));
    let has_evtx = manifest
        .artifacts
        .iter()
        .any(|e| e.artifact_type == Some(issen_core::artifacts::ArtifactType::EventLog));

    assert!(has_mft, "Should find $MFT");
    assert!(has_evtx, "Should find event logs");

    // Verify files were actually extracted
    assert!(manifest.extracted_root.exists());
}
