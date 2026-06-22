#![no_main]
//! Issen's own USN_RECORD_V2 decoder (`UsnRecordV2::parse`) — manual
//! little-endian offset reads with length/offset bounds checks over arbitrary
//! `$UsnJrnl:$J` bytes. Must never panic on a truncated or hostile record.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = issen_parser_usnjrnl::UsnRecordV2::parse(data);
});
