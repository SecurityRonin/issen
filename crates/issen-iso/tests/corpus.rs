// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Corpus integration tests for IsoDataSource against a real Ubuntu ISO.
///
/// The Ubuntu 20.04 (Focal) netboot mini.iso is created by Canonical using
/// genisoimage — an independent tool from our ISO parser (hadris-iso). It
/// exercises that:
/// 1. hadris-iso can validate a real-world ISO 9660 image (not just synthetic)
/// 2. IsoDataSource::read_at returns byte-identical results to reading the
///    file directly (since ISO is a raw-sector format, no transformation occurs)
///
/// Download the corpus file if missing:
///   curl -L http://archive.ubuntu.com/ubuntu/dists/focal/main/installer-amd64/current/legacy-images/netboot/mini.iso \
///        -o crates/issen-iso/tests/data/ubuntu-20.04-mini.iso
/// SHA-256: 0e79e00bf844929d40825b1f0e8634415cda195ba23bae0b041911fde4dfe018
use issen_core::plugin::traits::DataSource;
use issen_iso::IsoDataSource;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

fn corpus(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

/// Open the Ubuntu mini ISO and verify IsoDataSource reports the correct file size.
#[test]
fn corpus_ubuntu_mini_iso_open_and_len() {
    let path = corpus("ubuntu-20.04-mini.iso");
    if !path.exists() {
        return;
    }
    let src =
        IsoDataSource::open(&path).expect("IsoDataSource::open must succeed on Ubuntu mini ISO");
    let file_len = std::fs::metadata(&path).expect("metadata").len();
    assert_eq!(
        src.len(),
        file_len,
        "IsoDataSource::len() must equal file size for Ubuntu mini ISO"
    );
}

/// Verify read_at returns byte-identical data to direct file reads.
///
/// ISO 9660 is a raw-sector format — IsoDataSource does no compression or
/// transformation. Every byte read must exactly match the raw file bytes.
#[test]
fn corpus_ubuntu_mini_iso_read_at_matches_direct_file_reads() {
    let path = corpus("ubuntu-20.04-mini.iso");
    if !path.exists() {
        return;
    }
    let src = IsoDataSource::open(&path).expect("open");
    let file_len = src.len() as usize;

    let mut ref_file = File::open(&path).expect("open reference file");

    // Sample every 2 MiB across the image, plus the PVD sector (offset 32768)
    // and near-end 512 bytes.
    let mut offsets = vec![0usize, 32768]; // start and PVD
    let step = 2 * 1024 * 1024usize;
    let mut off = step;
    while off < file_len {
        offsets.push(off);
        off += step;
    }
    if file_len >= 512 {
        offsets.push(file_len - 512);
    }

    for &offset in &offsets {
        let len = 512.min(file_len - offset);
        let mut src_buf = vec![0u8; len];
        let mut ref_buf = vec![0u8; len];

        src.read_at(offset as u64, &mut src_buf).expect("read_at");
        ref_file.seek(SeekFrom::Start(offset as u64)).expect("seek");
        ref_file.read_exact(&mut ref_buf).expect("read reference");

        assert_eq!(
            src_buf, ref_buf,
            "byte mismatch at offset {offset:#x} in Ubuntu mini ISO"
        );
    }
}
