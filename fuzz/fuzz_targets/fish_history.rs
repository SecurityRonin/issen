#![no_main]
//! Issen's fish-shell `fish_history` parser — a pure issen-side line/state-machine
//! decode of the YAML-like history format (no *-core delegation). Arbitrary bytes
//! (incl. invalid UTF-8, ragged indentation) must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = issen_wsl::fish_history::parse_fish_history(data);
});
