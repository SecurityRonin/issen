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
    /// Reading the NTFS filesystem failed.
    #[error("ntfs error: {0}")]
    Ntfs(String),
}

impl From<DiskError> for RtError {
    fn from(e: DiskError) -> Self {
        match e {
            DiskError::Io(io) => Self::Io(io),
            other => Self::InvalidData(other.to_string()),
        }
    }
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
    use disk_forensic::DiskReport;

    let mut reader = DataSourceReader::new(source);
    let report = match disk_forensic::analyse_disk(&mut reader, source.len()) {
        Ok(report) => report,
        // No partition table at all — nothing to triage, not a hard failure.
        Err(disk_forensic::Error::UnknownScheme) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    // Candidate windows from whichever partition table was found.
    let candidates: Vec<PartitionWindow> = match &report {
        DiskReport::Mbr(m) | DiskReport::Gpt(m) => match m.gpt.as_ref() {
            // GPT: every in-use entry; NTFS isn't fingerprinted by type GUID, so
            // the boot-sector check below is what confirms it.
            Some(gpt) => gpt
                .partitions
                .iter()
                .map(|p| PartitionWindow {
                    offset: p.first_lba.saturating_mul(gpt.sector_size),
                    length: (p.last_lba.saturating_add(1))
                        .saturating_sub(p.first_lba)
                        .saturating_mul(gpt.sector_size),
                })
                .collect(),
            // Classic MBR: non-empty primary/logical partitions.
            None => m
                .partitions
                .iter()
                .filter(|p| p.byte_size > 0)
                .map(|p| PartitionWindow {
                    offset: p.byte_offset,
                    length: p.byte_size,
                })
                .collect(),
        },
        // NTFS on an Apple Partition Map does not occur in practice.
        DiskReport::Apm(_) => Vec::new(),
    };

    let mut out = Vec::new();
    for w in candidates {
        if window_is_ntfs(source, w)? {
            out.push(w);
        }
    }
    Ok(out)
}

/// `true` if the 512-byte boot sector at `window.offset` parses as NTFS.
fn window_is_ntfs(source: &dyn DataSource, window: PartitionWindow) -> Result<bool, DiskError> {
    let mut sector = [0u8; 512];
    let n = source
        .read_at(window.offset, &mut sector)
        .map_err(|e| DiskError::Source(e.to_string()))?;
    Ok(n >= 512 && ntfs_forensic::BootSector::parse(&sector).is_ok())
}

/// The standard high-value Windows triage artifacts, by NTFS path.
///
/// Fixed paths only (no per-user hives or wildcards, which need directory
/// enumeration); [`extract_triage`] returns whichever are present.
pub const WINDOWS_TRIAGE_PATHS: &[&str] = &[
    r"\$MFT",
    r"\$LogFile",
    r"\Windows\System32\config\SYSTEM",
    r"\Windows\System32\config\SOFTWARE",
    r"\Windows\System32\config\SAM",
    r"\Windows\System32\config\SECURITY",
    r"\Windows\System32\config\DEFAULT",
    r"\Windows\System32\winevt\Logs\Security.evtx",
    r"\Windows\System32\winevt\Logs\System.evtx",
    r"\Windows\System32\winevt\Logs\Application.evtx",
    r"\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
    r"\Windows\System32\sru\SRUDB.dat",
    r"\Windows\AppCompat\Programs\Amcache.hve",
];

/// Extract the standard Windows triage artifacts ([`WINDOWS_TRIAGE_PATHS`]) from
/// every NTFS partition in the disk image.
///
/// # Errors
///
/// [`DiskError`] if the partition table or a volume can't be read.
pub fn extract_triage(source: &dyn DataSource) -> Result<Vec<ExtractedFile>, DiskError> {
    let mut out = Vec::new();
    for window in find_ntfs_partitions(source)? {
        out.extend(extract_files(source, window, WINDOWS_TRIAGE_PATHS)?);
    }
    Ok(out)
}

/// Extract the Windows triage artifacts from `source` into a temp directory and
/// return a [`CollectionManifest`] the Issen ingest pipeline can parse.
///
/// This is the entry point a disk-image [`CollectionProvider`] (VMDK, EWF, …)
/// calls in its `open()`.
///
/// [`CollectionManifest`]: issen_unpack::CollectionManifest
/// [`CollectionProvider`]: issen_unpack::CollectionProvider
///
/// # Errors
///
/// [`DiskError`] if the disk can't be read, or [`DiskError::Io`] while writing
/// the extracted files.
pub fn triage_manifest(
    source: &dyn DataSource,
    format_name: &str,
) -> Result<issen_unpack::CollectionManifest, DiskError> {
    use issen_unpack::{CollectionManifest, CollectionMetadata, ManifestEntry, OsType};

    let files = extract_triage(source)?;
    let tempdir = tempfile::tempdir()?;

    let mut artifacts = Vec::new();
    for file in &files {
        let rel = sanitize_ntfs_path(&file.path);
        let dest = tempdir.path().join(&rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &file.data)?;
        artifacts.push(ManifestEntry {
            path: rel,
            artifact_type: None, // let the fswalker classify by content
        });
    }

    Ok(CollectionManifest::new(
        format_name.to_string(),
        tempdir,
        artifacts,
        CollectionMetadata {
            hostname: None,
            collection_time: None,
            os_type: OsType::Windows, // an NTFS volume implies a Windows host
            tool_version: None,
        },
    ))
}

/// Turn an NTFS path (`\Windows\System32\config\SYSTEM`) into a safe relative
/// path under the extraction root, dropping the leading separator, any drive/ADS
/// colon, and `.`/`..` components.
fn sanitize_ntfs_path(path: &str) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for part in path.split(['\\', '/']) {
        let part = part.split(':').next().unwrap_or(part); // strip ADS suffix
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        out.push(part);
    }
    out
}

/// A file extracted from an NTFS partition.
#[derive(Debug, Clone)]
pub struct ExtractedFile {
    /// The NTFS path it was read from (e.g. `\\$MFT`).
    pub path: String,
    /// The file's unnamed `$DATA` contents.
    pub data: Vec<u8>,
}

/// Read each of `paths` from the NTFS partition at `window`.
///
/// Best-effort: a path that is absent (`NotFound` / not a directory) is skipped,
/// so a triage manifest can list more artifacts than any one image contains.
///
/// # Errors
///
/// [`DiskError`] if the volume can't be opened, or a read fails for a reason
/// other than the path being absent.
pub fn extract_files(
    source: &dyn DataSource,
    window: PartitionWindow,
    paths: &[&str],
) -> Result<Vec<ExtractedFile>, DiskError> {
    use ntfs_forensic::{NtfsError, NtfsFs, OffsetReader};

    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());
    let reader = DataSourceReader::new(source);
    let part = OffsetReader::new(reader, window.offset, window.length).map_err(to_disk)?;
    let mut fs = NtfsFs::open(part).map_err(to_disk)?;

    let mut out = Vec::new();
    for &path in paths {
        match fs.read_file(path) {
            Ok(data) => out.push(ExtractedFile {
                path: path.to_string(),
                data,
            }),
            // The artifact simply isn't on this image — expected during triage.
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => {}
            Err(e) => return Err(to_disk(e)),
        }
    }
    Ok(out)
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
    fn disk_without_partition_table_yields_no_partitions() {
        // A blank disk (no MBR/GPT/APM) is not an error — there's just no NTFS.
        let src = VecSource(vec![0u8; 64 * SECTOR]);
        assert!(find_ntfs_partitions(&src).expect("no error").is_empty());
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

    // ── A complete synthetic NTFS volume (ported from ntfs-forensic) ───────────
    // Cluster = sector = 512; 1024-byte MFT records; $MFT at LCN 4. Holds one
    // file, \test.txt = "hello world".

    mod vol {
        const CLUSTER: usize = 512;
        const REC: usize = 1024;
        const MFT_LCN: u64 = 4;

        fn boot() -> [u8; 512] {
            let mut b = [0u8; 512];
            b[3..11].copy_from_slice(b"NTFS    ");
            b[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
            b[0x0D] = 1; // sectors/cluster ⇒ cluster = 512
            b[0x30..0x38].copy_from_slice(&MFT_LCN.to_le_bytes());
            b[0x38..0x40].copy_from_slice(&(MFT_LCN + 100).to_le_bytes());
            b[0x40] = 0xF6; // 1024-byte records
            b[0x44] = 0x01;
            b[510] = 0x55;
            b[511] = 0xAA;
            b
        }

        fn record(flags: u16, attrs: &[u8]) -> Vec<u8> {
            let mut r = vec![0u8; REC];
            r[0..4].copy_from_slice(b"FILE");
            let usa_off = 0x30u16;
            let usa_count = (REC / 512 + 1) as u16;
            r[0x04..0x06].copy_from_slice(&usa_off.to_le_bytes());
            r[0x06..0x08].copy_from_slice(&usa_count.to_le_bytes());
            let first = 0x38usize;
            r[0x14..0x16].copy_from_slice(&(first as u16).to_le_bytes());
            r[0x16..0x18].copy_from_slice(&flags.to_le_bytes());
            r[0x18..0x1C].copy_from_slice(&((first + attrs.len() + 4) as u32).to_le_bytes());
            r[0x1C..0x20].copy_from_slice(&(REC as u32).to_le_bytes());
            r[first..first + attrs.len()].copy_from_slice(attrs);
            r[first + attrs.len()..first + attrs.len() + 4]
                .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            let usn = 0x0001u16;
            let uo = usa_off as usize;
            r[uo..uo + 2].copy_from_slice(&usn.to_le_bytes());
            for i in 0..(usa_count as usize - 1) {
                let tail = (i + 1) * 512 - 2;
                let orig = [r[tail], r[tail + 1]];
                let pos = uo + 2 + i * 2;
                r[pos..pos + 2].copy_from_slice(&orig);
                r[tail..tail + 2].copy_from_slice(&usn.to_le_bytes());
            }
            r
        }

        fn attr_resident(type_code: u32, name: Option<&str>, content: &[u8]) -> Vec<u8> {
            let nu: Vec<u16> = name.map(|n| n.encode_utf16().collect()).unwrap_or_default();
            let name_off = 0x18usize;
            let con_off = (name_off + nu.len() * 2 + 7) & !7;
            let len = (con_off + content.len() + 7) & !7;
            let mut a = vec![0u8; len];
            a[0..4].copy_from_slice(&type_code.to_le_bytes());
            a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
            a[0x09] = nu.len() as u8;
            a[0x0A..0x0C].copy_from_slice(&(name_off as u16).to_le_bytes());
            a[0x10..0x14].copy_from_slice(&(content.len() as u32).to_le_bytes());
            a[0x14..0x16].copy_from_slice(&(con_off as u16).to_le_bytes());
            for (i, u) in nu.iter().enumerate() {
                a[name_off + i * 2..name_off + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
            }
            a[con_off..con_off + content.len()].copy_from_slice(content);
            a
        }

        fn nonresident_data(runs: &[u8], real: u64) -> Vec<u8> {
            let ro = 0x40usize;
            let len = (ro + runs.len() + 7) & !7;
            let mut a = vec![0u8; len];
            a[0..4].copy_from_slice(&0x80u32.to_le_bytes());
            a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
            a[0x08] = 1;
            a[0x0A..0x0C].copy_from_slice(&(ro as u16).to_le_bytes());
            a[0x20..0x22].copy_from_slice(&(ro as u16).to_le_bytes());
            a[0x28..0x30].copy_from_slice(&real.to_le_bytes());
            a[0x30..0x38].copy_from_slice(&real.to_le_bytes());
            a[ro..ro + runs.len()].copy_from_slice(runs);
            a
        }

        fn fname(parent: u64, name: &str) -> Vec<u8> {
            let u: Vec<u16> = name.encode_utf16().collect();
            let mut c = vec![0u8; 0x42 + u.len() * 2];
            c[0..8].copy_from_slice(&((1u64 << 48) | parent).to_le_bytes());
            c[0x40] = u.len() as u8;
            c[0x41] = 1; // Win32
            for (i, ch) in u.iter().enumerate() {
                c[0x42 + i * 2..0x42 + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
            }
            c
        }

        fn index_entry(target: u64, name: &str) -> Vec<u8> {
            let fnc = fname(5, name);
            let len = (0x10 + fnc.len() + 7) & !7;
            let mut e = vec![0u8; len];
            e[0..8].copy_from_slice(&((1u64 << 48) | target).to_le_bytes());
            e[0x08..0x0A].copy_from_slice(&(len as u16).to_le_bytes());
            e[0x0A..0x0C].copy_from_slice(&(fnc.len() as u16).to_le_bytes());
            e[0x10..0x10 + fnc.len()].copy_from_slice(&fnc);
            e
        }

        fn index_end() -> Vec<u8> {
            let mut e = vec![0u8; 0x10];
            e[0x08..0x0A].copy_from_slice(&0x10u16.to_le_bytes());
            e[0x0C] = 0x02;
            e
        }

        fn index_root(entries: &[Vec<u8>]) -> Vec<u8> {
            let blob: Vec<u8> = entries.concat();
            let mut c = vec![0u8; 0x10 + 0x10 + blob.len()];
            c[0x00..0x04].copy_from_slice(&0x30u32.to_le_bytes());
            c[0x10..0x14].copy_from_slice(&0x10u32.to_le_bytes());
            c[0x14..0x18].copy_from_slice(&((0x10 + blob.len()) as u32).to_le_bytes());
            c[0x20..0x20 + blob.len()].copy_from_slice(&blob);
            attr_resident(0x90, Some("$I30"), &c)
        }

        /// Build the full volume bytes; `\test.txt` = "hello world".
        pub fn build() -> Vec<u8> {
            let num = 7usize;
            let mft_clusters = (num * REC / CLUSTER) as u64; // 14
            let total = MFT_LCN + mft_clusters + 2;
            let mut v = vec![0u8; total as usize * CLUSTER];
            v[0..512].copy_from_slice(&boot());

            let runs = [0x11u8, mft_clusters as u8, MFT_LCN as u8, 0x00];
            let rec0 = record(
                0x0001,
                &nonresident_data(&runs, mft_clusters * CLUSTER as u64),
            );
            let rec5 = record(
                0x0003,
                &index_root(&[
                    index_entry(0, "$MFT"),
                    index_entry(6, "test.txt"),
                    index_end(),
                ]),
            );
            let mut a6 = Vec::new();
            a6.extend_from_slice(&attr_resident(0x10, None, &[0u8; 0x30]));
            a6.extend_from_slice(&attr_resident(0x30, None, &fname(5, "test.txt")));
            a6.extend_from_slice(&attr_resident(0x80, None, b"hello world"));
            let rec6 = record(0x0001, &a6);

            let mft_off = MFT_LCN as usize * CLUSTER;
            for (idx, rec) in [(0usize, &rec0), (5, &rec5), (6, &rec6)] {
                let o = mft_off + idx * REC;
                v[o..o + rec.len()].copy_from_slice(rec);
            }
            v
        }
    }

    /// Place the synthetic NTFS volume at a partition offset inside an MBR disk.
    fn disk_with_volume(lba_start: u32) -> VecSource {
        let v = vol::build();
        let count = v.len().div_ceil(SECTOR) as u32 + 1;
        let total = (lba_start + count) as usize * SECTOR;
        let mut disk = vec![0u8; total];
        disk[..SECTOR].copy_from_slice(&mbr_one_ntfs(lba_start, count));
        let off = lba_start as usize * SECTOR;
        disk[off..off + v.len()].copy_from_slice(&v);
        VecSource(disk)
    }

    #[test]
    fn extracts_a_file_from_an_ntfs_partition() {
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        assert_eq!(parts.len(), 1);
        let files = extract_files(&src, parts[0], &["\\test.txt"]).expect("extract");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "\\test.txt");
        assert_eq!(files[0].data, b"hello world");
    }

    #[test]
    fn missing_paths_are_skipped() {
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        let files = extract_files(&src, parts[0], &["\\test.txt", "\\nope.txt"]).expect("extract");
        assert_eq!(files.len(), 1); // only the present file
        assert_eq!(files[0].path, "\\test.txt");
    }

    #[test]
    fn triage_paths_cover_key_artifacts() {
        assert!(WINDOWS_TRIAGE_PATHS.contains(&r"\$MFT"));
        assert!(WINDOWS_TRIAGE_PATHS.contains(&r"\Windows\System32\config\SYSTEM"));
        assert!(WINDOWS_TRIAGE_PATHS.contains(&r"\Windows\System32\winevt\Logs\Security.evtx"));
    }

    #[test]
    fn extract_triage_collects_present_artifacts() {
        // The synthetic volume exposes \$MFT in its root index.
        let src = disk_with_volume(2048);
        let files = extract_triage(&src).expect("triage");
        let mft = files
            .iter()
            .find(|f| f.path == r"\$MFT")
            .expect("$MFT present");
        assert!(!mft.data.is_empty());
    }

    #[test]
    fn sanitize_ntfs_path_is_safe_and_relative() {
        assert_eq!(sanitize_ntfs_path(r"\$MFT"), std::path::Path::new("$MFT"));
        assert_eq!(
            sanitize_ntfs_path(r"\Windows\System32\config\SYSTEM"),
            std::path::Path::new("Windows/System32/config/SYSTEM")
        );
        // Drops ADS suffix, leading separators, and traversal components.
        assert_eq!(
            sanitize_ntfs_path(r"\..\x\$UsnJrnl:$J"),
            std::path::Path::new("x/$UsnJrnl")
        );
    }

    #[test]
    fn triage_manifest_writes_artifacts_to_tempdir() {
        let src = disk_with_volume(2048);
        let manifest = triage_manifest(&src, "TEST").expect("manifest");
        assert_eq!(manifest.format_name, "TEST");
        assert!(matches!(
            manifest.metadata.os_type,
            issen_unpack::OsType::Windows
        ));
        let entry = manifest
            .artifacts
            .iter()
            .find(|e| e.path.file_name() == Some(std::ffi::OsStr::new("$MFT")))
            .expect("$MFT artifact");
        let data = std::fs::read(manifest.extracted_root.join(&entry.path)).expect("read file");
        assert!(!data.is_empty());
    }
}
