#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::elidable_lifetime_names,
    clippy::match_same_arms,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::field_reassign_with_default,
    clippy::inefficient_to_string,
    clippy::manual_strip,
    clippy::redundant_else,
    clippy::trim_split_whitespace,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::unused_self,
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::missing_fields_in_debug,
    clippy::result_unit_err,
    clippy::unreadable_literal,
    clippy::manual_contains,
    clippy::unnecessary_literal_bound
)]
pub mod extract;
pub mod path_decoder;
pub mod probe;

use std::path::Path;

use issen_core::error::RtError;
use issen_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// Velociraptor collection format handler.
pub struct VelociraptorProvider;

impl CollectionProvider for VelociraptorProvider {
    fn name(&self) -> &'static str {
        "Velociraptor"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        probe::probe_velociraptor(path)
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        let tempdir = issen_unpack::tempdir::create_extraction_dir()?;
        let (entries, metadata) = extract::extract_velociraptor(path, tempdir.path())?;
        Ok(CollectionManifest::new(
            "Velociraptor".into(),
            tempdir,
            entries,
            metadata,
        ))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(VelociraptorProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_velociraptor_provider_name() {
        let provider = VelociraptorProvider;
        assert_eq!(provider.name(), "Velociraptor");
    }

    #[test]
    fn test_velociraptor_provider_probe_and_open() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let zip_path = dir.path().join("Collection-HOST-2025-01-01T00_00_00Z.zip");

        let file = std::fs::File::create(&zip_path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("uploads/ntfs/%5C%5C.%5CC%3A/$MFT", opts)
            .expect("add");
        zip.write_all(b"mft").expect("write");
        zip.finish().expect("finish");

        let provider = VelociraptorProvider;
        let confidence = provider.probe(&zip_path).expect("probe");
        assert_eq!(confidence, Confidence::High);

        let manifest = provider.open(&zip_path).expect("open");
        assert_eq!(manifest.format_name, "Velociraptor");
        assert_eq!(manifest.metadata.hostname.as_deref(), Some("HOST"));
        assert!(!manifest.artifacts.is_empty());
    }
}
