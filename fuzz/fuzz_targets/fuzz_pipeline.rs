#![no_main]
//! Broadest entry point: a single buffer of unknown bytes fanned out across
//! every issen-side wrapper byte parser at once — the way an unrecognized
//! artifact hits the dispatch surface. No single parser may panic regardless of
//! which (or none) of them recognizes the bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = issen_signatures::heuristics::magic_table::identify_format(data);
    let _ = issen_parser_pe::parse_pe(data);
    let _ = issen_parser_usnjrnl::UsnRecordV2::parse(data);
    let _ = issen_parser_logfile::parse_logfile_bytes(data, "fuzz");
    let _ = issen_mft_tree::logfile::validate_logfile_from_bytes(data);
    let _ = issen_wsl::fish_history::parse_fish_history(data);

    let split = data.len() / 2;
    let (a, b) = data.split_at(split);
    let _ = issen_mft_tree::mirror::validate_mirror_from_bytes(a, b);
});
