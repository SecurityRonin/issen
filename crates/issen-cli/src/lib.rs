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
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! rt-cli library entry point.
//!
//! Exposes the built-in parser modules so that integration test binaries
//! can link them and trigger their `inventory::submit!` registrations.

// Force-link the external parser crates so their `inventory::submit!`
// registrations are pulled into the binary AND the lib test harness — without
// these the linker drops the registrations and pipeline tests see zero events.
extern crate issen_parser_amcache as _;
extern crate issen_parser_comhijack as _;
extern crate issen_parser_dcc2 as _;
extern crate issen_parser_evtx as _;
extern crate issen_parser_linux as _;
extern crate issen_parser_lnk as _;
extern crate issen_parser_lsasecrets as _;
extern crate issen_parser_lxss as _;
extern crate issen_parser_macos as _;
extern crate issen_parser_mft as _;
extern crate issen_parser_pe as _;
extern crate issen_parser_prefetch as _;
extern crate issen_parser_regcatalog as _;
extern crate issen_parser_registry as _;
extern crate issen_parser_runkeys as _;
extern crate issen_parser_sam as _;
extern crate issen_parser_setupapi as _;
extern crate issen_parser_shellbags as _;
extern crate issen_parser_shimcache as _;
extern crate issen_parser_srum as _;
extern crate issen_parser_svcdiff as _;
extern crate issen_parser_typedurls as _;
extern crate issen_parser_uac as _;
extern crate issen_parser_userassist as _;
extern crate issen_parser_usnjrnl as _;
extern crate issen_parser_velociraptor as _;

pub mod commands;
pub mod parsers;
pub mod scanning;

#[cfg(test)]
mod parser_registration_tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::plugin::registry::all_parsers;

    #[test]
    fn all_parsers_includes_a_registry_parser() {
        // issen-parser-registry must be linked + inventory-registered so registry
        // hives are actually parsed during ingest (A2 link).
        let has_registry = all_parsers()
            .iter()
            .any(|p| p.supported_artifacts().contains(&ArtifactType::Registry));
        assert!(
            has_registry,
            "no registered parser supports ArtifactType::Registry — the crate is not linked"
        );
    }
}
