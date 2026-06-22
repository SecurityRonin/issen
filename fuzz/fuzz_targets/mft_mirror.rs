#![no_main]
//! Issen's $MFT/$MFTMirr first-four-entries comparator
//! (`validate_mirror_from_bytes`). Two independent attacker-controlled buffers:
//! split the fuzz input so both sides vary in length. Must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let (mft, mirror) = data.split_at(split);
    let _ = issen_mft_tree::mirror::validate_mirror_from_bytes(mft, mirror);
});
