#![no_main]
//! Issen's `$LogFile` restart-page validator (`validate_logfile_from_bytes`):
//! parses restart page 1 at offset 0, then page 2 at the page-size offset the
//! first page declares. Attacker-controlled bytes must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = issen_mft_tree::logfile::validate_logfile_from_bytes(data);
});
