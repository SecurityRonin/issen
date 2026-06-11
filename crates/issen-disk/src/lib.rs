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
    Ok(n >= 512 && ntfs_core::BootSector::parse(&sector).is_ok())
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

/// A directory whose children matching a suffix should all be collected — for
/// artifact families with per-host names (every `.evtx`, every `.pf`).
#[derive(Debug, Clone, Copy)]
pub struct TriageGlob {
    /// Directory to enumerate (not recursed).
    pub dir: &'static str,
    /// Case-insensitive filename suffix to match.
    pub suffix: &'static str,
}

/// Directory globs swept in addition to [`WINDOWS_TRIAGE_PATHS`].
pub const WINDOWS_TRIAGE_GLOBS: &[TriageGlob] = &[
    TriageGlob {
        dir: r"\Windows\System32\winevt\Logs",
        suffix: ".evtx",
    },
    TriageGlob {
        dir: r"\Windows\Prefetch",
        suffix: ".pf",
    },
];

/// Per-user files collected from each subdirectory of `\Users` (relative paths).
pub const WINDOWS_USER_FILES: &[&str] = &[
    "NTUSER.DAT",
    r"AppData\Local\Microsoft\Windows\UsrClass.dat",
];

/// Extract the standard Windows triage artifacts — the fixed
/// [`WINDOWS_TRIAGE_PATHS`] plus the [`WINDOWS_TRIAGE_GLOBS`] directory sweeps —
/// from every NTFS partition in the disk image.
///
/// # Errors
///
/// [`DiskError`] if the partition table or a volume can't be read.
pub fn extract_triage(source: &dyn DataSource) -> Result<Vec<ExtractedFile>, DiskError> {
    let mut out = Vec::new();
    for window in find_ntfs_partitions(source)? {
        out.extend(extract_files(source, window, WINDOWS_TRIAGE_PATHS)?);
        for glob in WINDOWS_TRIAGE_GLOBS {
            out.extend(extract_dir_suffix(source, window, glob.dir, glob.suffix)?);
        }
        for child in WINDOWS_USER_FILES {
            out.extend(extract_per_subdir(source, window, r"\Users", child)?);
        }
        out.extend(extract_named_streams(
            source,
            window,
            WINDOWS_TRIAGE_STREAMS,
        )?);
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
        // Namespace by source partition: every NTFS volume on a disk carries
        // same-named files (`\$MFT`, hives on a recovery volume), so a layout
        // keyed by NTFS path alone lets the last partition overwrite the rest.
        let rel = std::path::PathBuf::from(format!("part-{:010x}", file.partition_offset))
            .join(sanitize_ntfs_path(&file.path));
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
    /// Byte offset of the source partition within the disk image. Same-named
    /// files exist on every NTFS volume of a multi-partition disk (`\$MFT`,
    /// hives on a recovery volume), so the partition is part of the file's
    /// identity — extraction layouts must namespace by it or volumes overwrite
    /// each other.
    pub partition_offset: u64,
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
    use ntfs_core::{NtfsError, NtfsFs, OffsetReader};

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
                partition_offset: window.offset,
            }),
            // The artifact simply isn't on this image — expected during triage.
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => {}
            Err(e) => return Err(to_disk(e)),
        }
    }
    Ok(out)
}

/// Extract every file directly under NTFS directory `dir` whose name ends with
/// `suffix` (case-insensitive) — e.g. every `.evtx` in the event-log folder.
///
/// Best-effort: an absent directory yields an empty list (not an error), so a
/// fixed glob set works across images. Sub-directories are not recursed.
///
/// # Errors
///
/// [`DiskError`] if the volume can't be opened, or a read fails for a reason
/// other than the directory or a child being absent.
pub fn extract_dir_suffix(
    source: &dyn DataSource,
    window: PartitionWindow,
    dir: &str,
    suffix: &str,
) -> Result<Vec<ExtractedFile>, DiskError> {
    use ntfs_core::{NtfsError, NtfsFs, OffsetReader};

    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());
    let reader = DataSourceReader::new(source);
    let part = OffsetReader::new(reader, window.offset, window.length).map_err(to_disk)?;
    let mut fs = NtfsFs::open(part).map_err(to_disk)?;

    // Resolve the directory; if it isn't on this image, there's nothing to do.
    let dir_record = match fs.resolve_path(dir) {
        Ok(n) => n,
        Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => return Ok(Vec::new()),
        Err(e) => return Err(to_disk(e)),
    };
    let record = fs.read_record(dir_record).map_err(to_disk)?;
    let entries = fs.directory_entries(&record).map_err(to_disk)?;

    let suffix_lc = suffix.to_ascii_lowercase();
    let base = dir.trim_end_matches('\\');
    let mut out = Vec::new();
    for entry in entries {
        let Some(name) = entry.file_name.map(|f| f.name) else {
            continue;
        };
        if !name.to_ascii_lowercase().ends_with(&suffix_lc) {
            continue;
        }
        let path = format!("{base}\\{name}");
        match fs.read_file(&path) {
            Ok(data) => out.push(ExtractedFile {
                path,
                data,
                partition_offset: window.offset,
            }),
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => {}
            Err(e) => return Err(to_disk(e)),
        }
    }
    Ok(out)
}

/// For each immediate subdirectory of `parent`, extract the file at `child`
/// (relative to that subdirectory) — used for per-user hives, e.g. `parent =
/// \Users`, `child = NTUSER.DAT` collects every user's registry hive.
///
/// Best-effort: an absent `parent`, a non-directory entry, or a missing `child`
/// is skipped.
///
/// # Errors
///
/// [`DiskError`] if the volume can't be opened, or a read fails for a reason
/// other than a path being absent.
pub fn extract_per_subdir(
    source: &dyn DataSource,
    window: PartitionWindow,
    parent: &str,
    child: &str,
) -> Result<Vec<ExtractedFile>, DiskError> {
    use ntfs_core::{NtfsError, NtfsFs, OffsetReader};

    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());
    let reader = DataSourceReader::new(source);
    let part = OffsetReader::new(reader, window.offset, window.length).map_err(to_disk)?;
    let mut fs = NtfsFs::open(part).map_err(to_disk)?;

    let parent_record = match fs.resolve_path(parent) {
        Ok(n) => n,
        Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => return Ok(Vec::new()),
        Err(e) => return Err(to_disk(e)),
    };
    let record = fs.read_record(parent_record).map_err(to_disk)?;
    let entries = fs.directory_entries(&record).map_err(to_disk)?;

    let base = parent.trim_end_matches('\\');
    let mut out = Vec::new();
    for entry in entries {
        let Some(name) = entry.file_name.map(|f| f.name) else {
            continue;
        };
        // Try `<parent>\<name>\<child>`; non-directory entries resolve to
        // NotADirectory and are skipped, so we needn't pre-check the type.
        let path = format!("{base}\\{name}\\{child}");
        match fs.read_file(&path) {
            Ok(data) => out.push(ExtractedFile {
                path,
                data,
                partition_offset: window.offset,
            }),
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => {}
            Err(e) => return Err(to_disk(e)),
        }
    }
    Ok(out)
}

/// Named ADS streams collected during triage: `(path, stream)`.
///
/// The USN change journal lives in the named stream `$UsnJrnl:$J`, not a plain
/// file — reading it needs a named-stream read, not `read_file`.
pub const WINDOWS_TRIAGE_STREAMS: &[(&str, &str)] = &[(r"\$Extend\$UsnJrnl", "$J")];

/// Extract each named `$DATA` stream (ADS) in `streams` from the NTFS partition.
///
/// Best-effort: an absent path or stream is skipped.
///
/// # Errors
///
/// [`DiskError`] if the volume can't be opened, or a read fails for a reason
/// other than the path or stream being absent.
pub fn extract_named_streams(
    source: &dyn DataSource,
    window: PartitionWindow,
    streams: &[(&str, &str)],
) -> Result<Vec<ExtractedFile>, DiskError> {
    use ntfs_core::{NtfsError, NtfsFs, OffsetReader};

    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());
    let reader = DataSourceReader::new(source);
    let part = OffsetReader::new(reader, window.offset, window.length).map_err(to_disk)?;
    let mut fs = NtfsFs::open(part).map_err(to_disk)?;

    let mut out = Vec::new();
    for &(path, stream) in streams {
        match fs.read_named_stream(path, stream) {
            Ok(data) => out.push(ExtractedFile {
                path: format!("{path}:{stream}"),
                data,
                partition_offset: window.offset,
            }),
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

        /// Build the full volume bytes. Root holds `\test.txt` = "hello world"
        /// and a subdirectory `\homes` containing `data.bin` = "user data".
        pub fn build() -> Vec<u8> {
            let num = 9usize;
            let mft_clusters = (num * REC / CLUSTER) as u64; // 18
            let total = MFT_LCN + mft_clusters + 2;
            let mut v = vec![0u8; total as usize * CLUSTER];
            v[0..512].copy_from_slice(&boot());

            let runs = [0x11u8, mft_clusters as u8, MFT_LCN as u8, 0x00];
            let rec0 = record(
                0x0001,
                &nonresident_data(&runs, mft_clusters * CLUSTER as u64),
            );
            // Record 5: root directory → $MFT, test.txt, homes/.
            let rec5 = record(
                0x0003,
                &index_root(&[
                    index_entry(0, "$MFT"),
                    index_entry(6, "test.txt"),
                    index_entry(7, "homes"),
                    index_end(),
                ]),
            );
            let mut a6 = Vec::new();
            a6.extend_from_slice(&attr_resident(0x10, None, &[0u8; 0x30]));
            a6.extend_from_slice(&attr_resident(0x30, None, &fname(5, "test.txt")));
            a6.extend_from_slice(&attr_resident(0x80, None, b"hello world"));
            // A named $DATA stream (alternate data stream).
            a6.extend_from_slice(&attr_resident(
                0x80,
                Some("Zone.Identifier"),
                b"[ZoneTransfer]",
            ));
            let rec6 = record(0x0001, &a6);

            // Record 7: subdirectory `homes` → data.bin.
            let rec7 = record(
                0x0003,
                &index_root(&[index_entry(8, "data.bin"), index_end()]),
            );
            // Record 8: file `homes\data.bin`.
            let mut a8 = Vec::new();
            a8.extend_from_slice(&attr_resident(0x10, None, &[0u8; 0x30]));
            a8.extend_from_slice(&attr_resident(0x30, None, &fname(7, "data.bin")));
            a8.extend_from_slice(&attr_resident(0x80, None, b"user data"));
            let rec8 = record(0x0001, &a8);

            let mft_off = MFT_LCN as usize * CLUSTER;
            for (idx, rec) in [
                (0usize, &rec0),
                (5, &rec5),
                (6, &rec6),
                (7, &rec7),
                (8, &rec8),
            ] {
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

    /// A 512-byte MBR with two NTFS partitions (type 0x07).
    fn mbr_two_ntfs(lba1: u32, count1: u32, lba2: u32, count2: u32) -> [u8; SECTOR] {
        let mut m = mbr_one_ntfs(lba1, count1);
        let p = 0x1CE; // second partition entry
        m[p + 4] = 0x07;
        m[p + 8..p + 12].copy_from_slice(&lba2.to_le_bytes());
        m[p + 12..p + 16].copy_from_slice(&count2.to_le_bytes());
        m
    }

    /// Two synthetic NTFS volumes on one MBR disk — the Case 001 Desktop shape
    /// (a Windows volume plus a recovery volume). The second volume's $MFT bytes
    /// are made distinct so an extraction collision is detectable as content
    /// loss, not just a path clash.
    fn disk_with_two_volumes() -> VecSource {
        let v1 = vol::build();
        let mut v2 = vol::build();
        let probe = b"hello world";
        let pos = v2
            .windows(probe.len())
            .position(|w| w == probe)
            .expect("synthetic volume carries the probe content");
        v2[pos..pos + probe.len()].copy_from_slice(b"HELLO WORLD");

        let lba1 = 2048u32;
        let count1 = v1.len().div_ceil(SECTOR) as u32 + 1;
        let lba2 = lba1 + count1;
        let count2 = v2.len().div_ceil(SECTOR) as u32 + 1;
        let total = (lba2 + count2) as usize * SECTOR;
        let mut disk = vec![0u8; total];
        disk[..SECTOR].copy_from_slice(&mbr_two_ntfs(lba1, count1, lba2, count2));
        disk[lba1 as usize * SECTOR..][..v1.len()].copy_from_slice(&v1);
        disk[lba2 as usize * SECTOR..][..v2.len()].copy_from_slice(&v2);
        VecSource(disk)
    }

    /// The G1 root-cause regression (Case 001 Desktop): every NTFS partition
    /// carries a `\$MFT`, and `triage_manifest` must keep them ALL — flattening
    /// per-partition files into one temp dir keyed by NTFS path alone lets the
    /// last partition's $MFT overwrite the Windows volume's (104,960 records
    /// silently replaced by the recovery volume's 256).
    #[test]
    fn triage_manifest_keeps_same_named_artifacts_from_every_partition() {
        let src = disk_with_two_volumes();
        assert_eq!(
            find_ntfs_partitions(&src).expect("find").len(),
            2,
            "fixture sanity: two NTFS partitions"
        );

        let manifest = triage_manifest(&src, "TEST").expect("manifest");
        let mfts: Vec<_> = manifest
            .artifacts
            .iter()
            .filter(|e| e.path.file_name() == Some(std::ffi::OsStr::new("$MFT")))
            .collect();
        assert_eq!(mfts.len(), 2, "one $MFT artifact per NTFS partition");
        assert_ne!(
            mfts[0].path, mfts[1].path,
            "same-named artifacts from different partitions must not collide"
        );
        let d0 = std::fs::read(manifest.extracted_root.join(&mfts[0].path)).expect("read first");
        let d1 = std::fs::read(manifest.extracted_root.join(&mfts[1].path)).expect("read second");
        assert_ne!(
            d0, d1,
            "each partition's own $MFT bytes survive (no overwrite)"
        );
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
    fn extract_dir_suffix_collects_matching_children() {
        // Root holds test.txt; a ".txt" glob on the root directory finds it.
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        let files = extract_dir_suffix(&src, parts[0], "\\", ".TXT").expect("glob");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "\\test.txt");
        assert_eq!(files[0].data, b"hello world");
    }

    #[test]
    fn extract_dir_suffix_on_absent_directory_is_empty() {
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        let files = extract_dir_suffix(&src, parts[0], r"\Windows\System32\winevt\Logs", ".evtx")
            .expect("glob");
        assert!(files.is_empty());
    }

    #[test]
    fn extract_per_subdir_reads_child_in_each_subdirectory() {
        // Root has the subdirectory `homes` containing `data.bin`.
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        let files = extract_per_subdir(&src, parts[0], "\\", "data.bin").expect("per-subdir");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, r"\homes\data.bin");
        assert_eq!(files[0].data, b"user data");
    }

    #[test]
    fn extract_per_subdir_on_absent_parent_is_empty() {
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        let files =
            extract_per_subdir(&src, parts[0], r"\Users", "NTUSER.DAT").expect("per-subdir");
        assert!(files.is_empty());
    }

    #[test]
    fn extract_named_streams_reads_ads() {
        // test.txt carries a Zone.Identifier ADS.
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        let files = extract_named_streams(&src, parts[0], &[("\\test.txt", "Zone.Identifier")])
            .expect("ads");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "\\test.txt:Zone.Identifier");
        assert_eq!(files[0].data, b"[ZoneTransfer]");
    }

    #[test]
    fn extract_named_streams_skips_missing() {
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        let files =
            extract_named_streams(&src, parts[0], &[("\\test.txt", "NoStream")]).expect("ads");
        assert!(files.is_empty());
    }

    #[test]
    fn triage_streams_cover_usn_journal() {
        assert!(WINDOWS_TRIAGE_STREAMS
            .iter()
            .any(|(p, s)| p.ends_with("$UsnJrnl") && *s == "$J"));
    }

    #[test]
    fn triage_user_files_cover_ntuser_hive() {
        assert!(WINDOWS_USER_FILES.contains(&"NTUSER.DAT"));
        assert!(WINDOWS_USER_FILES
            .iter()
            .any(|f| f.ends_with("UsrClass.dat")));
    }

    #[test]
    fn triage_globs_cover_evtx_and_prefetch() {
        let dirs: Vec<&str> = WINDOWS_TRIAGE_GLOBS.iter().map(|g| g.dir).collect();
        assert!(dirs.contains(&r"\Windows\System32\winevt\Logs"));
        assert!(dirs.contains(&r"\Windows\Prefetch"));
        assert!(WINDOWS_TRIAGE_GLOBS
            .iter()
            .any(|g| g.suffix.eq_ignore_ascii_case(".evtx")));
    }

    #[test]
    fn extract_triage_runs_globs_without_breaking_fixed_paths() {
        // The synthetic volume lacks the glob dirs, so they add nothing — but the
        // glob loop must not disturb the fixed-path extraction (\$MFT).
        let src = disk_with_volume(2048);
        let files = extract_triage(&src).expect("triage");
        assert!(files.iter().any(|f| f.path == r"\$MFT"));
    }

    #[test]
    fn extract_dir_suffix_ignores_non_matching_children() {
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        let files = extract_dir_suffix(&src, parts[0], "\\", ".evtx").expect("glob");
        assert!(files.is_empty()); // root has no .evtx
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
