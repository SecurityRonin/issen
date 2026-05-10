use std::path::Path;

use issen_unpack::{CollectionProvider, Confidence};

#[test]
fn test_probe_real_uac_collection() {
    let path = Path::new("../../tests/data/Hal Linux DFIR Challenge/uac-vbox-linux-20260324193807.tar.gz");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = issen_parser_uac::UacProvider;
    let confidence = provider.probe(path).expect("probe should succeed");
    assert_eq!(confidence, Confidence::High, "Should detect UAC tar.gz");
}

#[test]
fn test_open_real_uac_collection() {
    let path = Path::new("../../tests/data/Hal Linux DFIR Challenge/uac-vbox-linux-20260324193807.tar.gz");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = issen_parser_uac::UacProvider;
    let manifest = provider.open(path).expect("open should succeed");

    assert_eq!(manifest.format_name, "UAC");
    assert_eq!(manifest.metadata.hostname.as_deref(), Some("vbox-linux"));
    assert_eq!(manifest.metadata.os_type, issen_unpack::OsType::Linux);
    assert!(!manifest.artifacts.is_empty(), "Should discover artifacts");

    // Verify extracted files exist
    assert!(manifest
        .extracted_root
        .join("bodyfile/bodyfile.txt")
        .exists());
    assert!(manifest.extracted_root.join("uac.log").exists());
}

#[test]
fn test_parse_real_uac_categories() {
    let path = Path::new("../../tests/data/Hal Linux DFIR Challenge/uac-vbox-linux-20260324193807.tar.gz");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = issen_parser_uac::UacProvider;
    let manifest = provider.open(path).expect("open should succeed");

    // Parse all categories
    let result = issen_parser_uac::parsers::parse_all_categories(&manifest.extracted_root);

    assert!(result.bodyfile_entries > 0, "Should parse bodyfile entries");
    eprintln!("UAC parse results: bodyfile={}, network={}, processes={}, packages={}, logins={}, hashes={}, chkrootkit={}, configs={}",
        result.bodyfile_entries,
        result.network_connections,
        result.processes,
        result.packages,
        result.login_records,
        result.hashed_executables,
        result.chkrootkit_findings,
        result.config_files,
    );
}
