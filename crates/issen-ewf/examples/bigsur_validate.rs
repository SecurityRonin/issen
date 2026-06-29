//! Validate the `ewf` reader + zran (DeflateSeekReader) backing on Josh Hickman's
//! macOS Big Sur image — a real 22-segment Deflated E01-in-zip.
//!
//! Smoke (default): open the zip (builds 22 zran indexes — decodes the image
//! once), check the image length + the GPT header that a real macOS disk carries
//! at LBA 1, proving bounded-RAM segment reads land on correct bytes.
//!
//! Tier-1 (`BIGSUR_DUMP=1`): stream the whole decompressed image to stdout so it
//! can be piped to `md5` and reconciled against FTK's documented image hash
//! `768785635426d008df76200fbc421063`.
//!
//! Run: `cargo run --release -p issen-ewf --example bigsur_validate`

use std::io::Write as _;
use std::path::Path;

use issen_core::plugin::traits::DataSource;
use issen_ewf::EwfDataSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = "tests/data/josh-hickman-mac-bigsur/macOS - BigSur.zip";
    let t0 = std::time::Instant::now();
    let src = EwfDataSource::open_zip(Path::new(path))?;
    let len = src.len();
    eprintln!(
        "opened via ewf + zran in {:.1?}; image len = {len} bytes ({} sectors)",
        t0.elapsed(),
        len / 512
    );
    // FTK documented the source as 167,772,160 × 512-byte sectors = 80 GiB.
    eprintln!(
        "  expected 85,899,345,920 bytes: {}",
        if len == 85_899_345_920 {
            "MATCH"
        } else {
            "MISMATCH"
        }
    );

    // Structural smoke: a macOS disk is GPT — LBA 1 holds the "EFI PART" header.
    let mut sec = vec![0u8; 512];
    src.read_at(0, &mut sec)?;
    let mbr_ok = sec.get(510..512) == Some(&[0x55, 0xAA][..]);
    src.read_at(512, &mut sec)?;
    let gpt = String::from_utf8_lossy(sec.get(0..8).unwrap_or_default()).to_string();
    eprintln!("  MBR sig @510 = 0x55AA: {mbr_ok}");
    eprintln!(
        "  GPT header @LBA1 = {gpt:?} ({})",
        if gpt == "EFI PART" { "MATCH" } else { "?" }
    );

    if std::env::var("BIGSUR_DUMP").is_ok() {
        eprintln!("streaming full decompressed image to stdout (pipe to `md5 -q`)...");
        let t1 = std::time::Instant::now();
        let mut out = std::io::BufWriter::with_capacity(8 << 20, std::io::stdout().lock());
        let mut off = 0u64;
        let mut buf = vec![0u8; 8 << 20];
        while off < len {
            let want = ((len - off).min(buf.len() as u64)) as usize;
            let n = src.read_at(off, &mut buf[..want])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            off += n as u64;
        }
        out.flush()?;
        eprintln!("streamed {off} bytes in {:.1?}", t1.elapsed());
    }
    Ok(())
}
