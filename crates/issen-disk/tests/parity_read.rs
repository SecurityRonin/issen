//! Content-read parity gate (doer-checker): read a real file's bytes through
//! the full pipeline — EWF container → partition detection → NTFS filesystem →
//! `$DATA` — and compare to TSK's `icat`.
//!
//! ```bash
//! icat -o <ntfs_lba> disk.E01 <inode> > ref.bin
//! NTFS_FORENSIC_E01=disk.E01 NTFS_FORENSIC_REF=ref.bin \
//!   cargo test -p issen-disk --test parity_read -- --ignored --nocapture
//! ```
//!
//! The default path is the Windows `hosts` file; override with NTFS_FORENSIC_PATH.

// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::path::Path;

use issen_disk::{extract_files, find_ntfs_partitions};
use issen_ewf::EwfDataSource;

#[test]
#[ignore = "requires NTFS_FORENSIC_E01 (disk image) + NTFS_FORENSIC_REF (icat bytes)"]
fn read_file_matches_icat() {
    let (Ok(e01), Ok(reference)) = (
        std::env::var("NTFS_FORENSIC_E01"),
        std::env::var("NTFS_FORENSIC_REF"),
    ) else {
        return;
    };
    let path = std::env::var("NTFS_FORENSIC_PATH")
        .unwrap_or_else(|_| r"\Windows\System32\drivers\etc\hosts".to_string());

    let expected = std::fs::read(&reference).expect("read reference");
    let source = EwfDataSource::open(Path::new(&e01)).expect("open E01");

    let partitions = find_ntfs_partitions(&source).expect("find NTFS partitions");
    assert!(!partitions.is_empty(), "no NTFS partition found");

    // Read the file from whichever NTFS partition holds it.
    let mut got: Option<Vec<u8>> = None;
    for window in &partitions {
        let files = extract_files(&source, *window, &[path.as_str()]).expect("extract");
        if let Some(file) = files.into_iter().next() {
            got = Some(file.data);
            break;
        }
    }
    let got = got.unwrap_or_else(|| panic!("{path} not found on any NTFS partition"));

    println!(
        "ntfs-forensic read {} bytes; icat {} bytes",
        got.len(),
        expected.len()
    );
    assert_eq!(got.len(), expected.len(), "length mismatch vs icat");
    assert_eq!(
        got, expected,
        "content mismatch vs icat — read path is wrong"
    );
    println!("byte-for-byte match vs TSK icat ✓");
}
