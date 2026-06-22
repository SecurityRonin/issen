#![no_main]
//! Issen's PE parser: over goblin's structural parse it does its own section
//! slicing (`bytes.get(offset..offset+size)`), Shannn-entropy computation, and
//! ASCII/UTF-16 string extraction. Arbitrary bytes must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = issen_parser_pe::parse_pe(data);
});
