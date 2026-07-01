//! Tests for the AD1 collection provider.
//!
//! Fixtures are crafted in-memory via `ad1::testfix` (independent flate2 zlib +
//! RustCrypto hashes as ground truth) — no real 48 GiB corpus required.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use ad1::testfix;
use std::path::PathBuf;

fn write_tmp(bytes: &[u8], name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

#[test]
fn probes_high_for_ad1_and_none_for_others() {
    let built = testfix::build(testfix::sample_tree());
    let (_d, p) = write_tmp(&built.bytes, "img.ad1");
    assert_eq!(Ad1Provider.probe(&p).unwrap(), Confidence::High);

    let (_d2, junk) = write_tmp(b"not an ad1 file at all........", "x.bin");
    assert_eq!(Ad1Provider.probe(&junk).unwrap(), Confidence::None);
}

#[test]
fn probes_high_but_open_refuses_encrypted() {
    let mut bytes = vec![0u8; 512];
    bytes[0..8].copy_from_slice(b"ADCRYPT\0");
    let (_d, p) = write_tmp(&bytes, "enc.ad1");
    assert_eq!(Ad1Provider.probe(&p).unwrap(), Confidence::High);
    match Ad1Provider.open(&p) {
        Err(RtError::UnsupportedFormat(m)) => assert!(m.contains("ADCRYPT"), "{m}"),
        other => panic!("expected UnsupportedFormat(ADCRYPT), got {other:?}"),
    }
}

#[test]
fn open_extracts_the_file_tree_byte_identical() {
    let built = testfix::build(testfix::sample_tree());
    let (_d, p) = write_tmp(&built.bytes, "img.ad1");

    let manifest = Ad1Provider.open(&p).expect("open AD1");
    assert_eq!(manifest.format_name, "AD1");
    let root = &manifest.extracted_root;

    for exp in &built.expected {
        let dest = root.join(&exp.path);
        if exp.is_dir {
            assert!(dest.is_dir(), "dir missing: {}", exp.path);
        } else {
            let got = std::fs::read(&dest).unwrap_or_else(|e| panic!("read {}: {e}", exp.path));
            assert_eq!(got.len() as u64, exp.size, "size mismatch: {}", exp.path);
            if let Some(want) = &exp.data {
                assert_eq!(&got, want, "bytes mismatch: {}", exp.path);
            }
        }
    }
}

#[test]
fn ad1_provider_registered_in_inventory() {
    use issen_unpack::registry::ProviderRegistration;
    let names: Vec<String> = inventory::iter::<ProviderRegistration>
        .into_iter()
        .map(|r| (r.create)().name().to_string())
        .collect();
    assert!(
        names.contains(&"AD1".to_string()),
        "Ad1Provider must be registered; got: {names:?}"
    );
}

/// End-to-end via the registry: `open_collection` picks the AD1 provider by
/// probe and extracts it.
#[test]
fn registry_dispatches_ad1_to_this_provider() {
    let built = testfix::build(testfix::sample_tree());
    let (_d, p) = write_tmp(&built.bytes, "img.ad1");
    let manifest = issen_unpack::registry::open_collection(&p).expect("registry open");
    assert_eq!(manifest.format_name, "AD1");
    assert!(manifest.extracted_root.join("root/hello.txt").is_file());
}
