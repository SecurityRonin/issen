//! G1 diagnostic probe: list every NTFS partition window in a disk image and
//! the byte length `NtfsFs::read_file(r"\$MFT")` returns for each — ground
//! truth for the Desktop $MFT under-parse investigation (capstone gate G1).
//!
//! Usage: cargo run --release -p issen-disk --example probe_mft -- <image.E01>

use issen_disk::{find_ntfs_partitions, DataSourceReader};
use issen_ewf::EwfDataSource;
use ntfs_core::{NtfsFs, OffsetReader};

fn main() {
    let path = std::env::args().nth(1).expect("usage: probe_mft <image.E01>");
    let source = EwfDataSource::open(std::path::Path::new(&path)).expect("open EWF");
    println!("image: {path}");
    println!("logical size: {} bytes", source.total_size());

    let windows = find_ntfs_partitions(&source).expect("find_ntfs_partitions");
    println!("NTFS windows found: {}", windows.len());

    for (i, w) in windows.iter().enumerate() {
        println!(
            "\n[{i}] offset={} ({:.2} GiB)  length={} ({:.2} GiB)",
            w.offset,
            w.offset as f64 / (1u64 << 30) as f64,
            w.length,
            w.length as f64 / (1u64 << 30) as f64
        );
        let reader = DataSourceReader::new(&source);
        let part = match OffsetReader::new(reader, w.offset, w.length) {
            Ok(p) => p,
            Err(e) => {
                println!("    OffsetReader error: {e}");
                continue;
            }
        };
        let mut fs = match NtfsFs::open(part) {
            Ok(fs) => fs,
            Err(e) => {
                println!("    NtfsFs::open error: {e}");
                continue;
            }
        };
        match fs.read_file(r"\$MFT") {
            Ok(data) => println!(
                "    $MFT: {} bytes ({:.2} MiB) = {} records @1024B",
                data.len(),
                data.len() as f64 / (1u64 << 20) as f64,
                data.len() / 1024
            ),
            Err(e) => println!("    $MFT read error: {e}"),
        }
    }
}
