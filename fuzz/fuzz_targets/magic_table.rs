#![no_main]
//! Issen's magic-byte format identifier (`identify_format`): offset + magic
//! comparison against the static table. Arbitrary (incl. very short) buffers
//! must never panic on the bounds arithmetic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = issen_signatures::heuristics::magic_table::identify_format(data);
});
