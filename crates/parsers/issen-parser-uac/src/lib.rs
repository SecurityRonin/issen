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
pub mod parsers;
pub mod probe;

use std::path::Path;

use issen_core::error::RtError;
use issen_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// UAC (Unix Artifact Collector) collection format handler.
///
/// Recognizes `.tar.gz` files containing `uac.log` and standard UAC directories.
pub struct UacProvider;

impl CollectionProvider for UacProvider {
    fn name(&self) -> &'static str {
        "UAC"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        probe::probe_uac(path)
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        let tempdir = issen_unpack::tempdir::create_extraction_dir()?;
        let (entries, metadata) = extract::extract_uac(path, tempdir.path())?;
        Ok(CollectionManifest::new(
            "UAC".into(),
            tempdir,
            entries,
            metadata,
        ))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(UacProvider),
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uac_provider_name() {
        asseissen_eq!(UacProvider.name(), "UAC");
    }
}
