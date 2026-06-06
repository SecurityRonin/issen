//! Disk-image orchestration: bridge a container [`DataSource`] (VMDK, EWF, raw
//! image, …) to the partition table and the NTFS filesystem inside it, then
//! extract the artifacts a triage pipeline needs.
//!
//! The pipeline is: container `DataSource` → [`DataSourceReader`] (`Read + Seek`)
//! → partition detection → NTFS filesystem → files by path.

use std::io::{Read, Seek, SeekFrom};

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// A byte window of a partition within the whole-disk image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionWindow {
    /// Byte offset of the partition from the start of the disk.
    pub offset: u64,
    /// Byte length of the partition.
    pub length: u64,
}

/// Errors from disk-image orchestration.
#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    /// The partition-table analysis failed.
    #[error("disk analysis failed: {0}")]
    Disk(#[from] disk_forensic::Error),
    /// An I/O error while reading the image.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The runtime data source reported an error.
    #[error("data source error: {0}")]
    Source(String),
}

/// Find the NTFS partitions in the disk image behind `source`.
///
/// Detects the partition scheme (MBR/GPT/APM) via `disk-forensic`, then
/// confirms each candidate partition really is NTFS by parsing its boot sector
/// — so a mislabelled partition type can't produce a false positive.
///
/// # Errors
///
/// [`DiskError::Disk`] if the partition table can't be analysed, or
/// [`DiskError::Io`] on a read failure.
pub fn find_ntfs_partitions(source: &dyn DataSource) -> Result<Vec<PartitionWindow>, DiskError> {
    let _ = (source, PartitionWindow { offset: 0, length: 0 });
    todo!("find_ntfs_partitions — GREEN step")
}

/// `true` if the 512-byte boot sector at `window.offset` parses as NTFS.
#[allow(dead_code)]
fn window_is_ntfs(source: &dyn DataSource, window: PartitionWindow) -> Result<bool, DiskError> {
    let mut sector = [0u8; 512];
    let n = source
        .read_at(window.offset, &mut sector)
        .map_err(|e| DiskError::Source(e.to_string()))?;
    Ok(n >= 512 && ntfs_forensic::BootSector::parse(&sector).is_ok())
}

/// A `Read + Seek` view over a [`DataSource`].
///
/// `DataSource` exposes random access (`read_at(offset, buf)`); the forensic
/// partition and filesystem parsers want a positional `Read + Seek`. This
/// adapter tracks a cursor and forwards each read to `read_at`.
pub struct DataSourceReader<'a> {
    source: &'a dyn DataSource,
    pos: u64,
}

impl<'a> DataSourceReader<'a> {
    /// Create a reader positioned at the start of `source`.
    #[must_use]
    pub fn new(source: &'a dyn DataSource) -> Self {
        Self { source, pos: 0 }
    }
}

impl Read for DataSourceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.source.read_at(self.pos, buf).map_err(rt_to_io)?;
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

impl Seek for DataSourceReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let target: i128 = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(d) => i128::from(self.pos) + i128::from(d),
            SeekFrom::End(d) => i128::from(self.source.len()) + i128::from(d),
        };
        if target < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start of data source",
            ));
        }
        self.pos = u64::try_from(target).unwrap_or(u64::MAX);
        Ok(self.pos)
    }
}

/// Map an [`RtError`] into a `std::io::Error` for the `Read`/`Seek` contract.
fn rt_to_io(e: RtError) -> std::io::Error {
    match e {
        RtError::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory [`DataSource`] over a byte vector.
    struct VecSource(Vec<u8>);

    impl DataSource for VecSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let start = offset as usize;
            if start >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - start);
            buf[..n].copy_from_slice(&self.0[start..start + n]);
            Ok(n)
        }
    }

    #[test]
    fn reads_sequentially() {
        let src = VecSource((0u8..32).collect());
        let mut r = DataSourceReader::new(&src);
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0, 1, 2, 3]);
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [4, 5, 6, 7]);
    }

    #[test]
    fn seek_from_start_and_current() {
        let src = VecSource((0u8..32).collect());
        let mut r = DataSourceReader::new(&src);
        r.seek(SeekFrom::Start(10)).unwrap();
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [10, 11]);
        r.seek(SeekFrom::Current(-1)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [11, 12]);
    }

    #[test]
    fn seek_from_end_is_relative_to_len() {
        let src = VecSource((0u8..32).collect());
        let mut r = DataSourceReader::new(&src);
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), 32);
        assert_eq!(r.seek(SeekFrom::End(-4)).unwrap(), 28);
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [28, 29, 30, 31]);
    }

    #[test]
    fn rejects_seek_before_start() {
        let src = VecSource(vec![0u8; 8]);
        let mut r = DataSourceReader::new(&src);
        assert!(r.seek(SeekFrom::Current(-1)).is_err());
    }

    // ── Partition detection ───────────────────────────────────────────────────

    const SECTOR: usize = 512;

    /// A minimal valid NTFS boot sector (parses via ntfs-forensic).
    fn ntfs_boot() -> [u8; SECTOR] {
        let mut b = [0u8; SECTOR];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // bytes/sector
        b[0x0D] = 8; // sectors/cluster
        b[0x30..0x38].copy_from_slice(&4u64.to_le_bytes()); // $MFT LCN
        b[0x38..0x40].copy_from_slice(&104u64.to_le_bytes()); // $MFTMirr LCN
        b[0x40] = 0xF6; // clusters-per-record −10 ⇒ 1024-byte records
        b[0x44] = 0x01; // clusters-per-index
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    /// A 512-byte MBR with one NTFS partition (type 0x07) at `lba_start`.
    fn mbr_one_ntfs(lba_start: u32, lba_count: u32) -> [u8; SECTOR] {
        let mut m = [0u8; SECTOR];
        let p = 0x1BE; // first partition entry
        m[p] = 0x80; // bootable
        m[p + 4] = 0x07; // type: NTFS/exFAT
        m[p + 8..p + 12].copy_from_slice(&lba_start.to_le_bytes());
        m[p + 12..p + 16].copy_from_slice(&lba_count.to_le_bytes());
        m[510] = 0x55;
        m[511] = 0xAA;
        m
    }

    /// Assemble a disk: MBR at sector 0, NTFS boot sector at `lba_start`.
    fn disk_with_ntfs(lba_start: u32, lba_count: u32) -> VecSource {
        let total = (lba_start + lba_count) as usize * SECTOR;
        let mut disk = vec![0u8; total];
        disk[..SECTOR].copy_from_slice(&mbr_one_ntfs(lba_start, lba_count));
        let off = lba_start as usize * SECTOR;
        disk[off..off + SECTOR].copy_from_slice(&ntfs_boot());
        VecSource(disk)
    }

    #[test]
    fn finds_single_ntfs_partition() {
        let src = disk_with_ntfs(2048, 2048); // 1 MiB in, 1 MiB long
        let parts = find_ntfs_partitions(&src).expect("analyse");
        assert_eq!(
            parts,
            vec![PartitionWindow {
                offset: 2048 * 512,
                length: 2048 * 512,
            }]
        );
    }

    #[test]
    fn ignores_partition_that_is_not_really_ntfs() {
        // MBR claims an NTFS partition, but the boot sector there is blank.
        let mut disk = vec![0u8; 4096 * SECTOR];
        disk[..SECTOR].copy_from_slice(&mbr_one_ntfs(2048, 2048));
        // (no NTFS boot sector written at the partition offset)
        let src = VecSource(disk);
        assert!(find_ntfs_partitions(&src).expect("analyse").is_empty());
    }
}
