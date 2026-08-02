// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Corpus integration tests for DdDataSource against a real raw disk image.
///
/// ext4.raw is from the log2timeline/dfvfs project (Apache-2.0):
///   https://github.com/log2timeline/dfvfs/raw/main/test_data/ext4.raw
/// SHA-256: d88dd5f6774526a94ad74e061c6a4245fef302e03c917277fb4043e30ed8b434
///
/// It contains a real ext4 filesystem and was created by the dfvfs project
/// — an independent implementation from our DD reader. Since a DD/raw DataSource
/// is a flat pass-through, read_at must return bytes identical to reading the
/// file directly.
use issen_core::plugin::traits::DataSource;
use issen_dd::DdDataSource;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

fn corpus(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

/// Verify DdDataSource::len() matches the file size.
#[test]
fn corpus_ext4_raw_len_matches_file_size() {
    let path = corpus("ext4.raw");
    if !path.exists() {
        return;
    }
    let src = DdDataSource::open(&path).expect("open");
    let file_len = std::fs::metadata(&path).expect("metadata").len();
    assert_eq!(
        src.len(),
        file_len,
        "DdDataSource::len() must equal file size"
    );
}

/// Verify read_at returns byte-identical data to reading the file directly.
///
/// A raw/dd image has no format layer — read_at is a pure pass-through.
/// Any discrepancy indicates a bug in the DdDataSource wrapper.
#[test]
fn corpus_ext4_raw_read_at_matches_direct_file_reads() {
    let path = corpus("ext4.raw");
    if !path.exists() {
        return;
    }
    let src = DdDataSource::open(&path).expect("open");
    let file_len = src.len() as usize;
    let mut ref_file = File::open(&path).expect("open reference");

    // Full stride scan + near-end check.
    let step = 65536usize;
    let mut offset = 0usize;
    while offset < file_len {
        let len = 512.min(file_len - offset);
        let mut src_buf = vec![0u8; len];
        let mut ref_buf = vec![0u8; len];

        src.read_at(offset as u64, &mut src_buf).expect("read_at");
        ref_file.seek(SeekFrom::Start(offset as u64)).expect("seek");
        ref_file.read_exact(&mut ref_buf).expect("read reference");

        assert_eq!(
            src_buf, ref_buf,
            "byte mismatch at offset {offset:#x} in ext4.raw"
        );
        offset += step;
    }

    // Near-end check.
    if file_len >= 512 {
        let end = file_len - 512;
        let mut src_buf = vec![0u8; 512];
        let mut ref_buf = vec![0u8; 512];
        src.read_at(end as u64, &mut src_buf)
            .expect("read_at near-end");
        ref_file
            .seek(SeekFrom::Start(end as u64))
            .expect("seek near-end");
        ref_file
            .read_exact(&mut ref_buf)
            .expect("read near-end reference");
        assert_eq!(src_buf, ref_buf, "byte mismatch near end of ext4.raw");
    }
}
