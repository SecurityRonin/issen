#![no_main]
//! Issen's `$LogFile` wrapper: raw journal bytes drive the clearing-integrity
//! pass plus the per-file transaction-replay reconstruction loop issen runs over
//! the ntfs-core LFS record decode. The bytes are fully attacker-controlled —
//! the wrapper must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = issen_parser_logfile::parse_logfile_bytes(data, "fuzz");
});
