//! `open_collection` must recurse into a disk-image container that an archive
//! extracted, cracking it through the disk pipeline — so `issen ingest
//! evidence.zip` works on a zipped disk image, not only on loose-artifact zips.
//!
//! Hermetic: this integration-test binary links only `issen-unpack`, so the
//! provider inventory contains exactly the two mocks registered below (the real
//! EwfProvider / ArchiveProvider live in other crates and are not linked here).
//! The real-provider path is validated end-to-end against `DC01-E01.zip` in
//! `docs/validation.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// `fn name(&self) -> &str` is the trait signature; returning a literal can't be
// `&'static str` here. The lib allows this same lint for the same reason.
#![allow(clippy::unnecessary_literal_bound)]

use std::path::Path;

use issen_unpack::registry::{open_collection, ProviderRegistration};
use issen_unpack::{
    CollectionManifest, CollectionMetadata, CollectionProvider, Confidence, OsType,
};

fn metadata() -> CollectionMetadata {
    CollectionMetadata {
        hostname: None,
        collection_time: None,
        os_type: OsType::Unknown,
        tool_version: None,
    }
}

/// Stands in for an archive provider: "extracts" by writing a disk-image
/// first-segment (`inner.E01`) plus a benign sidecar into a fresh dir, exactly
/// the shape an archive wrapping a split E01 leaves behind.
struct MockArchiveProvider;

impl CollectionProvider for MockArchiveProvider {
    fn name(&self) -> &str {
        "MockArchive"
    }
    fn probe(&self, path: &Path) -> Result<Confidence, issen_core::error::RtError> {
        Ok(if path.extension().is_some_and(|e| e == "mockzip") {
            Confidence::High
        } else {
            Confidence::None
        })
    }
    fn open(&self, _path: &Path) -> Result<CollectionManifest, issen_core::error::RtError> {
        let tempdir = tempfile::tempdir().map_err(issen_core::error::RtError::Io)?;
        // A split set + sidecar — only the .E01 first segment should be recursed.
        std::fs::write(tempdir.path().join("inner.E01"), b"EVF-stub").map_err(RtErr)?;
        std::fs::write(tempdir.path().join("inner.E02"), b"cont").map_err(RtErr)?;
        std::fs::write(tempdir.path().join("inner.E01.txt"), b"acq").map_err(RtErr)?;
        Ok(CollectionManifest::new(
            self.name().into(),
            tempdir,
            Vec::new(),
            metadata(),
        ))
    }
}

/// Stands in for the EWF disk provider: claims a `.E01` first segment and returns
/// a distinctively-named "cracked" manifest (its own fresh extraction dir).
struct MockEwfProvider;

impl CollectionProvider for MockEwfProvider {
    fn name(&self) -> &str {
        "MockEWF"
    }
    fn probe(&self, path: &Path) -> Result<Confidence, issen_core::error::RtError> {
        Ok(if path.extension().is_some_and(|e| e == "E01") {
            Confidence::High
        } else {
            Confidence::None
        })
    }
    fn open(&self, _path: &Path) -> Result<CollectionManifest, issen_core::error::RtError> {
        let tempdir = tempfile::tempdir().map_err(issen_core::error::RtError::Io)?;
        // The "cracked filesystem": a forensic artifact, NOT another container.
        std::fs::write(tempdir.path().join("$MFT"), b"mft").map_err(RtErr)?;
        Ok(CollectionManifest::new(
            self.name().into(),
            tempdir,
            Vec::new(),
            metadata(),
        ))
    }
}

#[allow(non_snake_case)]
fn RtErr(e: std::io::Error) -> issen_core::error::RtError {
    issen_core::error::RtError::Io(e)
}

inventory::submit! { ProviderRegistration { create: || Box::new(MockArchiveProvider) } }
inventory::submit! { ProviderRegistration { create: || Box::new(MockEwfProvider) } }

#[test]
fn archive_wrapping_a_disk_image_is_cracked_through_the_disk_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("evidence.mockzip");
    std::fs::write(&archive, b"stub").unwrap();

    let manifest = open_collection(&archive).expect("open archive");

    // Recursion fired: the returned manifest is the EWF-cracked filesystem, NOT
    // the archive's raw extraction. Before the fix this was "MockArchive".
    assert_eq!(
        manifest.format_name, "MockEWF",
        "a disk image inside an archive must crack through the disk pipeline"
    );
    // And it exposes the cracked tree (the $MFT), not the raw .E01.
    assert!(
        manifest.extracted_root.join("$MFT").exists(),
        "the cracked filesystem's $MFT should be present"
    );
    assert!(
        !manifest.extracted_root.join("inner.E01").exists(),
        "the returned root is the cracked FS, not the archive's raw extraction"
    );
}

#[test]
fn a_bare_disk_image_opens_without_spurious_recursion() {
    // Opening a .E01 directly hits MockEwfProvider; its cracked tree holds no
    // nested container, so there is nothing to recurse into — the manifest is
    // returned as-is.
    let dir = tempfile::tempdir().unwrap();
    let e01 = dir.path().join("image.E01");
    std::fs::write(&e01, b"stub").unwrap();

    let manifest = open_collection(&e01).expect("open e01");
    assert_eq!(manifest.format_name, "MockEWF");
}
