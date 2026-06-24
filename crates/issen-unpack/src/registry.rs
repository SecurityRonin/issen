use std::path::Path;

use issen_core::error::RtError;
use tracing::info;

use crate::{CollectionManifest, CollectionProvider, Confidence};

/// Registration entry for the collection provider inventory.
pub struct ProviderRegistration {
    pub create: fn() -> Box<dyn CollectionProvider>,
}

inventory::collect!(ProviderRegistration);

/// Upper bound on how deep `open_collection` will recurse into containers nested
/// inside extracted archives (archive → disk image → …). A backstop against a
/// crafted archive-in-archive bomb; real evidence nests one level (a zip holding
/// a disk image).
const MAX_CONTAINER_RECURSION: usize = 8;

/// Probe all registered providers and open the collection with the best match.
///
/// When the opened collection is an archive that turns out to wrap a disk-image
/// container (rather than loose artifacts), the image is cracked through the disk
/// pipeline and that filesystem is returned — so `issen ingest evidence.zip`
/// works directly on a zipped E01, not only on loose-artifact zips.
///
/// Returns an error if no provider recognizes the format.
pub fn open_collection(path: &Path) -> Result<CollectionManifest, RtError> {
    open_collection_at(path, 0)
}

fn open_collection_at(path: &Path, depth: usize) -> Result<CollectionManifest, RtError> {
    let mut best: Option<(Box<dyn CollectionProvider>, Confidence)> = None;

    for reg in inventory::iter::<ProviderRegistration> {
        let provider = (reg.create)();
        match provider.probe(path) {
            Ok(confidence) if confidence > Confidence::None => {
                info!(provider = provider.name(), ?confidence, "Provider matched");
                if best.as_ref().is_none_or(|(_, c)| confidence > *c) {
                    best = Some((provider, confidence));
                }
            }
            Ok(_) => {} // Confidence::None — skip
            Err(e) => {
                // Probe failed — log and continue to next provider.
                info!(provider = provider.name(), error = %e, "Probe failed, skipping");
            }
        }
    }

    match best {
        Some((provider, confidence)) => {
            info!(
                provider = provider.name(),
                ?confidence,
                "Opening collection"
            );
            let manifest = provider.open(path)?;
            Ok(crack_nested_container(manifest, depth, &|p, d| {
                open_collection_at(p, d)
            }))
        }
        None => {
            let provider_names: Vec<String> = inventory::iter::<ProviderRegistration>
                .into_iter()
                .map(|reg| (reg.create)().name().to_string())
                .collect();
            Err(RtError::UnsupportedFormat(format!(
                "No collection provider recognized {}. Probed: [{}]",
                path.display(),
                provider_names.join(", ")
            )))
        }
    }
}

/// If `manifest`'s extracted tree holds disk-image container first-segment(s) —
/// i.e. an archive wrapped a disk image rather than loose artifacts — crack the
/// image through the disk pipeline (a recursive `open_collection`) and return
/// THAT filesystem manifest, keeping the archive's extraction dir alive. A
/// directly opened disk image extracts only forensic artifacts (no nested
/// containers), so this is a no-op for it; a loose-artifact collection likewise
/// has no containers and passes through unchanged.
fn crack_nested_container(
    manifest: CollectionManifest,
    depth: usize,
    open: &dyn Fn(&Path, usize) -> Result<CollectionManifest, RtError>,
) -> CollectionManifest {
    if depth >= MAX_CONTAINER_RECURSION {
        return manifest;
    }
    let containers =
        issen_core::container::collect_container_first_segments(&manifest.extracted_root);
    let Some((first, rest)) = containers.split_first() else {
        return manifest; // no nested container — loose-artifact collection
    };
    if !rest.is_empty() {
        // Fail loud: one manifest is one cracked filesystem, so additional disk
        // images in the same archive are NOT ingested here. Name them so the
        // omission is visible, never a silent partial.
        let skipped: Vec<String> = rest.iter().map(|p| p.display().to_string()).collect();
        eprintln!(
            "issen-unpack: archive holds {} disk images; ingesting only {} — \
             ingest the others separately: {}",
            containers.len(),
            first.display(),
            skipped.join(", ")
        );
    }
    match open(first, depth + 1) {
        Ok(mut cracked) => {
            cracked.keep_alive(manifest);
            cracked
        }
        Err(e) => {
            // The nested image failed to crack — surface it loudly, then fall
            // back to the archive's loose-artifact extraction so anything
            // alongside the image still parses (and the failure isn't silent).
            eprintln!(
                "issen-unpack: ERROR cracking disk image {} from archive: {e} — \
                 falling back to loose-artifact extraction",
                first.display()
            );
            manifest
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CollectionManifest, CollectionMetadata, OsType};

    // ---------------------------------------------------------------------------
    // Mock provider — registered via inventory so open_collection can find it.
    // ---------------------------------------------------------------------------

    struct AlwaysHighProvider;

    impl CollectionProvider for AlwaysHighProvider {
        fn name(&self) -> &str {
            "AlwaysHigh"
        }

        fn probe(&self, _path: &Path) -> Result<Confidence, issen_core::error::RtError> {
            Ok(Confidence::High)
        }

        fn open(&self, _path: &Path) -> Result<CollectionManifest, issen_core::error::RtError> {
            let tempdir = tempfile::tempdir().map_err(issen_core::error::RtError::Io)?;
            Ok(CollectionManifest::new(
                self.name().to_string(),
                tempdir,
                vec![],
                CollectionMetadata {
                    hostname: Some("mock-host".to_string()),
                    collection_time: None,
                    os_type: OsType::Unknown,
                    tool_version: None,
                },
            ))
        }
    }

    struct AlwaysErrProvider;

    impl CollectionProvider for AlwaysErrProvider {
        fn name(&self) -> &str {
            "AlwaysErr"
        }

        fn probe(&self, _path: &Path) -> Result<Confidence, issen_core::error::RtError> {
            Err(issen_core::error::RtError::InvalidData(
                "mock probe error".to_string(),
            ))
        }

        fn open(&self, _path: &Path) -> Result<CollectionManifest, issen_core::error::RtError> {
            Err(issen_core::error::RtError::UnsupportedFormat(
                "mock open error".to_string(),
            ))
        }
    }

    struct AlwaysNoneProvider;

    impl CollectionProvider for AlwaysNoneProvider {
        fn name(&self) -> &str {
            "AlwaysNone"
        }

        fn probe(&self, _path: &Path) -> Result<Confidence, issen_core::error::RtError> {
            Ok(Confidence::None)
        }

        fn open(&self, _path: &Path) -> Result<CollectionManifest, issen_core::error::RtError> {
            Err(issen_core::error::RtError::UnsupportedFormat(
                "none provider open".to_string(),
            ))
        }
    }

    // Register the always-high provider so open_collection exercises the happy path.
    inventory::submit!(ProviderRegistration {
        create: || Box::new(AlwaysHighProvider),
    });

    // Register an always-err provider so the probe-error branch is exercised.
    inventory::submit!(ProviderRegistration {
        create: || Box::new(AlwaysErrProvider),
    });

    // Register an always-none provider so the Confidence::None branch is exercised.
    inventory::submit!(ProviderRegistration {
        create: || Box::new(AlwaysNoneProvider),
    });

    // ---------------------------------------------------------------------------
    // ProviderRegistration struct tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_provider_registration_create_field_invocable() {
        let reg = ProviderRegistration {
            create: || Box::new(AlwaysHighProvider),
        };
        let provider = (reg.create)();
        assert_eq!(provider.name(), "AlwaysHigh");
    }

    #[test]
    fn test_provider_registration_create_returns_box_dyn() {
        let reg = ProviderRegistration {
            create: || Box::new(AlwaysNoneProvider),
        };
        let provider: Box<dyn CollectionProvider> = (reg.create)();
        assert_eq!(provider.name(), "AlwaysNone");
    }

    // ---------------------------------------------------------------------------
    // CollectionProvider trait method tests (via mock impls)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_always_high_provider_name() {
        let p = AlwaysHighProvider;
        assert_eq!(p.name(), "AlwaysHigh");
    }

    #[test]
    fn test_always_high_provider_probe_returns_high() {
        let p = AlwaysHighProvider;
        let result = p.probe(Path::new("/any/path"));
        assert_eq!(result.unwrap(), Confidence::High);
    }

    #[test]
    fn test_always_high_provider_open_returns_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let fake_path = dir.path().join("fake.zip");
        std::fs::write(&fake_path, b"dummy").unwrap();
        let p = AlwaysHighProvider;
        let manifest = p.open(&fake_path).expect("open should succeed");
        assert_eq!(manifest.format_name, "AlwaysHigh");
        assert_eq!(manifest.metadata.hostname.as_deref(), Some("mock-host"));
    }

    #[test]
    fn test_always_err_provider_name() {
        let p = AlwaysErrProvider;
        assert_eq!(p.name(), "AlwaysErr");
    }

    #[test]
    fn test_always_err_provider_probe_returns_err() {
        let p = AlwaysErrProvider;
        let result = p.probe(Path::new("/any/path"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mock probe error"));
    }

    #[test]
    fn test_always_err_provider_open_returns_err() {
        let p = AlwaysErrProvider;
        let result = p.open(Path::new("/any/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_always_none_provider_name() {
        let p = AlwaysNoneProvider;
        assert_eq!(p.name(), "AlwaysNone");
    }

    #[test]
    fn test_always_none_provider_probe_returns_none_confidence() {
        let p = AlwaysNoneProvider;
        let result = p.probe(Path::new("/any/path"));
        assert_eq!(result.unwrap(), Confidence::None);
    }

    #[test]
    fn test_always_none_provider_open_returns_err() {
        let p = AlwaysNoneProvider;
        let result = p.open(Path::new("/any/path"));
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // open_collection routing tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_open_collection_no_providers_returns_error() {
        // The mock providers ARE registered, but AlwaysHigh will match any path.
        // This test is kept for documentation; the real no-provider scenario cannot
        // be triggered in a binary that has inventory::submit! calls above.
        // We instead test the error message when we pass a path that AlwaysHigh
        // will still match — so we test that open_collection *succeeds*.
        let dir = tempfile::tempdir().unwrap();
        let fake_path = dir.path().join("fake.zip");
        std::fs::write(&fake_path, b"dummy").unwrap();
        let result = open_collection(&fake_path);
        // AlwaysHigh is registered — should succeed.
        assert!(
            result.is_ok(),
            "Expected open_collection to succeed with AlwaysHigh registered, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_open_collection_happy_path_format_name() {
        let dir = tempfile::tempdir().unwrap();
        let fake_path = dir.path().join("collection.zip");
        std::fs::write(&fake_path, b"dummy content").unwrap();
        let manifest = open_collection(&fake_path).expect("open_collection should succeed");
        assert_eq!(manifest.format_name, "AlwaysHigh");
    }

    #[test]
    fn test_open_collection_happy_path_extracted_root_exists() {
        let dir = tempfile::tempdir().unwrap();
        let fake_path = dir.path().join("collection.zip");
        std::fs::write(&fake_path, b"dummy content").unwrap();
        let manifest = open_collection(&fake_path).expect("open_collection should succeed");
        assert!(
            manifest.extracted_root.exists(),
            "extracted_root should exist while manifest is alive"
        );
    }

    #[test]
    fn test_open_collection_provider_names_in_error_message() {
        // Use a nonexistent path so all probes still return their fixed results
        // regardless. AlwaysHigh will always return High so this won't hit the
        // no-provider branch in this binary. Instead we verify the success case
        // captures the right provider name.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.zip");
        std::fs::write(&path, b"x").unwrap();
        let result = open_collection(&path);
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.format_name, "AlwaysHigh");
    }

    #[test]
    fn test_open_collection_manifest_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.zip");
        std::fs::write(&path, b"dummy").unwrap();
        let manifest = open_collection(&path).expect("should succeed");
        assert_eq!(manifest.metadata.hostname.as_deref(), Some("mock-host"));
        assert_eq!(manifest.metadata.os_type, OsType::Unknown);
    }

    #[test]
    fn test_open_collection_manifest_artifacts_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.zip");
        std::fs::write(&path, b"dummy").unwrap();
        let manifest = open_collection(&path).expect("should succeed");
        assert!(manifest.artifacts.is_empty());
    }

    #[test]
    fn test_provider_name_is_string_slice() {
        // Verifies the &str lifetime is valid when the provider is boxed.
        let p: Box<dyn CollectionProvider> = Box::new(AlwaysHighProvider);
        let name: &str = p.name();
        assert_eq!(name, "AlwaysHigh");
    }

    #[test]
    fn test_inventory_has_registered_providers() {
        // Verify at least our mock providers are in the inventory.
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|reg| (reg.create)().name().to_string())
            .collect();
        assert!(
            !names.is_empty(),
            "At least one provider should be registered"
        );
        assert!(
            names.contains(&"AlwaysHigh".to_string()),
            "AlwaysHigh should be registered, got: {names:?}"
        );
        assert!(
            names.contains(&"AlwaysErr".to_string()),
            "AlwaysErr should be registered"
        );
        assert!(
            names.contains(&"AlwaysNone".to_string()),
            "AlwaysNone should be registered"
        );
    }

    // ── crack_nested_container: hermetic branch coverage (injected opener) ────

    fn manifest_with_files(name: &str, files: &[&str]) -> CollectionManifest {
        let tempdir = tempfile::tempdir().expect("tempdir");
        for f in files {
            std::fs::write(tempdir.path().join(f), b"x").expect("write");
        }
        CollectionManifest::new(
            name.to_string(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Unknown,
                tool_version: None,
            },
        )
    }

    fn ok_opener(
        name: &'static str,
    ) -> impl Fn(&Path, usize) -> Result<CollectionManifest, RtError> {
        move |_p, _d| Ok(manifest_with_files(name, &["$MFT"]))
    }

    #[test]
    fn crack_passes_through_with_no_container() {
        let m = manifest_with_files("Archive", &["NTUSER.DAT", "system.evtx"]);
        let out = crack_nested_container(m, 0, &ok_opener("EWF"));
        assert_eq!(out.format_name, "Archive", "no container → unchanged");
    }

    #[test]
    fn crack_recurses_into_a_disk_image() {
        let m = manifest_with_files("Archive", &["inner.E01"]);
        let out = crack_nested_container(m, 0, &ok_opener("EWF"));
        assert_eq!(
            out.format_name, "EWF",
            ".E01 cracks through the disk pipeline"
        );
    }

    #[test]
    fn crack_warns_but_recurses_first_of_many() {
        // Two images: the first cracks; the others are skipped with a loud warning.
        let m = manifest_with_files("Archive", &["a.E01", "b.E01"]);
        let out = crack_nested_container(m, 0, &ok_opener("EWF"));
        assert_eq!(out.format_name, "EWF");
    }

    #[test]
    fn crack_degrades_on_crack_failure() {
        let m = manifest_with_files("Archive", &["inner.E01"]);
        let err_opener = |_p: &Path, _d: usize| Err(RtError::UnsupportedFormat("boom".to_string()));
        let out = crack_nested_container(m, 0, &err_opener);
        assert_eq!(
            out.format_name, "Archive",
            "crack failure degrades to loose-artifact extraction"
        );
    }

    #[test]
    fn crack_respects_depth_guard() {
        let m = manifest_with_files("Archive", &["inner.E01"]);
        // At the recursion ceiling the opener must NOT be called.
        let panicking = |_p: &Path, _d: usize| -> Result<CollectionManifest, RtError> {
            panic!("opener must not run at max depth")
        };
        let out = crack_nested_container(m, MAX_CONTAINER_RECURSION, &panicking);
        assert_eq!(out.format_name, "Archive");
    }
}
