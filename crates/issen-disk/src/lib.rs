#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Disk-image orchestration: bridge a container [`DataSource`] (VMDK, EWF, raw
//! image, …) to the partition table and the NTFS filesystem inside it, then
//! extract the artifacts a triage pipeline needs.
//!
//! The pipeline is: container `DataSource` → [`DataSourceReader`] (`Read + Seek`)
//! → partition detection → NTFS filesystem → files by path.

use std::io::{Read, Seek, SeekFrom};

use issen_core::error::RtError;
use issen_core::plugin::selector::NtfsLoc;
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
    // Device-install / setup history (USB & driver provenance). Parsed to
    // DeviceInstall; the current logs live in \Windows\INF (rotated
    // setupapi.dev.*.log are a future prefix-glob enhancement).
    r"\Windows\INF\setupapi.dev.log",
    r"\Windows\INF\setupapi.setup.log",
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

/// Per-user directories swept for `.lnk` shortcuts, relative to `\Users\<user>`.
///
/// Recent tracks files the user opened; Desktop holds pinned/placed shortcuts
/// (e.g. the Loot/Secret shortcuts on the Szechuan workstation). Each shortcut
/// embeds its target path and the target's MAC times.
pub const WINDOWS_USER_LNK_DIRS: &[&str] =
    &[r"AppData\Roaming\Microsoft\Windows\Recent", "Desktop"];

/// Extract the standard Windows triage artifacts — the fixed
/// [`WINDOWS_TRIAGE_PATHS`] plus the [`WINDOWS_TRIAGE_GLOBS`] directory sweeps —
/// from every NTFS partition in the disk image.
///
/// # Errors
///
/// [`DiskError`] if the partition table or a volume can't be read.
pub fn extract_triage(source: &dyn DataSource) -> Result<Vec<ExtractedFile>, DiskError> {
    // Registry-driven: the artifacts to collect are whatever the linked parsers
    // declare via their `ArtifactSelector::disk_sources` (gathered here), not a
    // hand-maintained list — so collection can no longer drift from the parsers.
    // The `WINDOWS_*` consts remain as the spec the `collection_differential`
    // test proves this set reproduces.
    let outcome = collect_sources(source, &issen_core::plugin::registry::triage_ntfs_sources())?;
    for limit in &outcome.limits {
        eprintln!("Warning: triage extraction was bounded: {limit}");
    }
    Ok(outcome.files)
}

/// Collect `sources` from every NTFS partition in `source`. The shared core of
/// the registry-driven [`extract_triage`] and [`triage_manifest`]; tests drive it
/// with an explicit source list since the parser inventory is empty outside the
/// linked binary.
fn collect_sources(
    source: &dyn DataSource,
    sources: &[NtfsLoc],
) -> Result<ExtractOutcome, DiskError> {
    collect_with_caps(source, sources, ExtractCaps::default())
}

/// Collect `sources` from every NTFS partition in `source`, enforcing `caps`.
///
/// The capped collection core: returns the extracted files together with any
/// [`ExtractionLimit`]s that were hit. A non-empty `limits` is a forensic
/// completeness gap the caller MUST surface — the files are a bounded partial,
/// not a complete result.
///
/// # Errors
///
/// [`DiskError`] if the partition table or a volume can't be read.
pub fn collect_with_caps(
    source: &dyn DataSource,
    sources: &[NtfsLoc],
    caps: ExtractCaps,
) -> Result<ExtractOutcome, DiskError> {
    let mut acc = Accumulator::new(caps);
    for window in find_ntfs_partitions(source)? {
        if acc.global_full() {
            // The global cap is exhausted with partitions still unread — a
            // bounded partial, recorded loudly rather than returned as a silent
            // "complete" empty/short result.
            acc.record(ExtractionLimit::TooManyFiles {
                pattern: "<global>".to_string(),
                cap: acc.caps.max_files_global,
            });
            break;
        }
        let mut fs = open_volume(source, window)?;
        extract_sources_into(&mut fs, window, sources, &mut acc)?;
    }
    Ok(acc.out)
}

/// Dispatch each [`NtfsLoc`] to its capped worker over one open volume.
fn extract_sources_into(
    fs: &mut ntfs_core::NtfsFs<OffsetReaderT<'_>>,
    window: PartitionWindow,
    sources: &[NtfsLoc],
    acc: &mut Accumulator,
) -> Result<(), DiskError> {
    for loc in sources {
        if acc.global_full() {
            break;
        }
        match *loc {
            NtfsLoc::FixedPath(path) => extract_files_into(fs, window, &[path], acc)?,
            NtfsLoc::DirSuffix { dir, suffix } => {
                extract_dir_suffix_into(fs, window, dir, suffix, acc)?;
            }
            NtfsLoc::PerUserFile(child) => {
                extract_per_subdir_into(fs, window, r"\Users", child, acc)?;
            }
            NtfsLoc::PerSubdirSweep { parent, rel, name } => {
                extract_subdir_sweep_into(fs, window, parent, rel, &|n| name.matches(n), acc)?;
            }
            NtfsLoc::NamedStream { path, stream } => {
                extract_named_streams_into(fs, window, &[(path, stream)], acc)?;
            }
        }
    }
    Ok(())
}

/// Extract every artifact named by `sources` from one NTFS partition window,
/// dispatching each [`NtfsLoc`] to the matching `extract_*` primitive.
///
/// The registry-driven collection core. `extract_triage` gathers the sources
/// from the parser registry and drives extraction through here; a caller with a
/// bespoke source list (e.g. a future selective collection) can call it directly.
///
/// # Errors
///
/// [`DiskError`] if the volume can't be opened or a read fails for a reason other
/// than the artifact being absent.
pub fn extract_ntfs_sources(
    source: &dyn DataSource,
    window: PartitionWindow,
    sources: &[NtfsLoc],
) -> Result<Vec<ExtractedFile>, DiskError> {
    let mut fs = open_volume(source, window)?;
    let mut acc = Accumulator::new(ExtractCaps::default());
    extract_sources_into(&mut fs, window, sources, &mut acc)?;
    for limit in &acc.out.limits {
        eprintln!("Warning: extraction cap hit: {limit}");
    }
    Ok(acc.out.files)
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
    triage_manifest_from(
        source,
        format_name,
        &issen_core::plugin::registry::triage_ntfs_sources(),
    )
}

/// Build a triage manifest from an explicit NTFS source list (rather than the
/// parser registry). The collection core of [`triage_manifest`]; lets tests and
/// selective-collection callers drive extraction without the linked inventory.
///
/// # Errors
///
/// [`DiskError`] if a volume can't be opened or a read/write fails.
pub fn triage_manifest_from(
    source: &dyn DataSource,
    format_name: &str,
    sources: &[NtfsLoc],
) -> Result<issen_unpack::CollectionManifest, DiskError> {
    use issen_unpack::{CollectionManifest, CollectionMetadata, ManifestEntry, OsType};

    let outcome = collect_sources(source, sources)?;
    // Fail LOUD on any cap hit: a truncated collection is a forensic
    // completeness gap, surfaced as a visible warning here (and structurally on
    // the outcome via `collect_with_caps`), never a silent partial.
    for limit in &outcome.limits {
        eprintln!("Warning: triage extraction was bounded: {limit}");
    }
    let files = outcome.files;
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
/// path under the extraction root, dropping the leading separator and `.`/`..`
/// components.
///
/// An alternate-data-stream suffix (`\$Extend\$UsnJrnl:$J`) is preserved by
/// folding the stream name into the final component as `<file>~<stream>`, so two
/// streams of one file (`:$J` and `:$Max`) map to DISTINCT output paths and
/// cannot overwrite each other. The leading `:` of the colon is what makes a
/// raw stream path unsafe on disk; `~` keeps the distinction without it.
fn sanitize_ntfs_path(path: &str) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for part in path.split(['\\', '/']) {
        // Fold an ADS suffix into the filename rather than dropping it, so
        // distinct streams of one file stay distinct on disk.
        let safe = match part.split_once(':') {
            Some((file, stream)) if !stream.is_empty() => {
                format!("{}~{}", file, stream.replace(':', "_"))
            }
            Some((file, _)) => file.to_string(),
            None => part.to_string(),
        };
        if safe.is_empty() || safe == "." || safe == ".." {
            continue;
        }
        out.push(safe);
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

/// Hard limits enforced while extracting from an untrusted disk image, so a
/// malicious or corrupt volume cannot OOM or hang the responder.
///
/// The defaults are deliberately well above any legitimate triage artifact — a
/// real `$MFT` reaches ~85 MB and a real volume has far fewer than a million
/// matching files — so a genuine collection never trips them. Hitting a cap is
/// a forensic event: it is recorded as an [`ExtractionLimit`] on the
/// [`ExtractOutcome`] and surfaced loudly, never a silent partial result.
#[derive(Debug, Clone, Copy)]
pub struct ExtractCaps {
    /// Maximum bytes for a single extracted file/stream. A file larger than
    /// this is rejected (not truncated) and a [`ExtractionLimit::FileTooLarge`]
    /// is recorded. Default 4 GiB — far above the ~85 MB real-world `$MFT`.
    pub max_file_bytes: u64,
    /// Maximum files collected for one source pattern (one [`NtfsLoc`]).
    pub max_files_per_pattern: usize,
    /// Maximum files collected across the whole extraction.
    pub max_files_global: usize,
    /// Maximum directory entries examined in one directory.
    pub max_dir_entries: usize,
    /// Maximum directory-nesting depth descended by a subdirectory sweep — a
    /// backstop paired with the per-record cycle guard.
    pub max_depth: usize,
}

impl Default for ExtractCaps {
    fn default() -> Self {
        Self {
            // 4 GiB: ~50x the ~85 MB real-world $MFT ceiling, so the legitimate
            // large system files always read while a pathological multi-GB
            // file is rejected loudly.
            max_file_bytes: 4 * 1024 * 1024 * 1024,
            max_files_per_pattern: 100_000,
            max_files_global: 1_000_000,
            max_dir_entries: 1_000_000,
            max_depth: 64,
        }
    }
}

/// A cap that was hit during extraction — a LOUD truncation diagnostic. Carries
/// the offending value (size/count/path) so an investigator sees exactly what
/// was bounded, never a bare "truncated".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractionLimit {
    /// A file exceeded [`ExtractCaps::max_file_bytes`] and was rejected.
    FileTooLarge {
        /// NTFS path (or `path:stream`) of the rejected file.
        path: String,
        /// Actual size in bytes that exceeded the cap.
        size: u64,
        /// The cap that was exceeded.
        cap: u64,
    },
    /// The per-pattern or global file count cap stopped collection.
    TooManyFiles {
        /// The source pattern (`NtfsLoc`) being collected, for context.
        pattern: String,
        /// The cap that was reached.
        cap: usize,
    },
    /// A directory held more entries than [`ExtractCaps::max_dir_entries`].
    TooManyDirEntries {
        /// The directory whose enumeration was bounded.
        dir: String,
        /// The cap that was reached.
        cap: usize,
    },
    /// A subdirectory sweep exceeded [`ExtractCaps::max_depth`].
    DepthExceeded {
        /// The directory at which descent was stopped.
        dir: String,
        /// The depth cap that was reached.
        cap: usize,
    },
    /// A looping/self-referential MFT reference was detected and skipped.
    CycleDetected {
        /// The directory whose record had already been visited on this path.
        dir: String,
        /// The MFT record number that repeated.
        record: u64,
    },
    /// A partition holds a filesystem issen recognizes but does not triage
    /// (e.g. APFS, ext, HFS+). Recorded ONLY when the disk has no NTFS volume,
    /// so a zero-artifact result on a macOS/Linux image is distinguishable from
    /// a clean NTFS image rather than a silent empty result.
    UnsupportedFilesystem {
        /// The detected filesystem (`APFS`, `ext`, `HFS+`).
        filesystem: String,
        /// Byte offset of the partition on the source.
        offset: u64,
    },
}

impl std::fmt::Display for ExtractionLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileTooLarge { path, size, cap } => write!(
                f,
                "file {path} is {size} bytes, exceeds the {cap}-byte extraction cap — REJECTED"
            ),
            Self::TooManyFiles { pattern, cap } => {
                write!(
                    f,
                    "pattern {pattern} hit the {cap}-file cap — collection truncated"
                )
            }
            Self::TooManyDirEntries { dir, cap } => {
                write!(
                    f,
                    "directory {dir} hit the {cap}-entry cap — enumeration truncated"
                )
            }
            Self::DepthExceeded { dir, cap } => {
                write!(
                    f,
                    "sweep stopped at {dir}: exceeded the {cap}-level depth cap"
                )
            }
            Self::CycleDetected { dir, record } => write!(
                f,
                "cycle detected at {dir}: MFT record {record} already visited — sweep stopped"
            ),
            Self::UnsupportedFilesystem { filesystem, offset } => write!(
                f,
                "{filesystem} filesystem at offset {offset} is not triaged — issen extracts \
                 NTFS artifacts only, so this disk produced no events (NOT a clean image)"
            ),
        }
    }
}

/// The result of a capped extraction: the files plus any [`ExtractionLimit`]s
/// that were hit. A non-empty `limits` means the collection is a bounded
/// partial — the caller MUST surface it (it is a forensic completeness gap),
/// never treat the files as a complete result.
#[derive(Debug, Default)]
pub struct ExtractOutcome {
    /// Files successfully extracted within the caps.
    pub files: Vec<ExtractedFile>,
    /// Caps that were hit — empty iff the collection is complete.
    pub limits: Vec<ExtractionLimit>,
}

/// Caps-enforcing accumulator threaded through the extraction primitives.
///
/// Owns the running file/byte counts and the global file cap; every primitive
/// pushes accepted files and recorded limits here. Centralising the bookkeeping
/// keeps the cap rules general (one place, applied to every source) rather than
/// special-cased per pattern.
struct Accumulator {
    caps: ExtractCaps,
    out: ExtractOutcome,
}

impl Accumulator {
    fn new(caps: ExtractCaps) -> Self {
        Self {
            caps,
            out: ExtractOutcome::default(),
        }
    }

    /// `true` once the global file cap has been reached — collection must stop.
    fn global_full(&self) -> bool {
        self.out.files.len() >= self.caps.max_files_global
    }

    fn record(&mut self, limit: ExtractionLimit) {
        self.out.limits.push(limit);
    }

    /// Accept `file` unless it exceeds the per-file byte cap or the global file
    /// cap. Returns `false` once the global cap is hit so the caller can stop.
    fn accept(&mut self, file: ExtractedFile) -> bool {
        if self.global_full() {
            self.record(ExtractionLimit::TooManyFiles {
                pattern: "<global>".to_string(),
                cap: self.caps.max_files_global,
            });
            return false;
        }
        let size = file.data.len() as u64;
        if size > self.caps.max_file_bytes {
            self.record(ExtractionLimit::FileTooLarge {
                path: file.path,
                size,
                cap: self.caps.max_file_bytes,
            });
            return true; // over-size is a per-file skip, not a stop
        }
        self.out.files.push(file);
        !self.global_full()
    }
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
    capped_single(source, window, ExtractCaps::default(), |acc, fs| {
        extract_files_into(fs, window, paths, acc)
    })
}

/// Run one capped extraction over a freshly opened volume, emitting any
/// recorded limits loudly to stderr (the granular pub helpers return only the
/// files, so this is where a cap hit is surfaced).
fn capped_single(
    source: &dyn DataSource,
    window: PartitionWindow,
    caps: ExtractCaps,
    body: impl FnOnce(
        &mut Accumulator,
        &mut ntfs_core::NtfsFs<OffsetReaderT<'_>>,
    ) -> Result<(), DiskError>,
) -> Result<Vec<ExtractedFile>, DiskError> {
    let mut fs = open_volume(source, window)?;
    let mut acc = Accumulator::new(caps);
    body(&mut acc, &mut fs)?;
    for limit in &acc.out.limits {
        eprintln!("Warning: extraction cap hit: {limit}");
    }
    Ok(acc.out.files)
}

/// The `OffsetReader` type parameter used across the extraction primitives.
type OffsetReaderT<'a> = ntfs_core::OffsetReader<DataSourceReader<'a>>;

/// Open the NTFS volume at `window` over `source`.
fn open_volume(
    source: &dyn DataSource,
    window: PartitionWindow,
) -> Result<ntfs_core::NtfsFs<OffsetReaderT<'_>>, DiskError> {
    use ntfs_core::{NtfsFs, OffsetReader};
    let to_disk = |e: ntfs_core::NtfsError| DiskError::Ntfs(e.to_string());
    let reader = DataSourceReader::new(source);
    let part = OffsetReader::new(reader, window.offset, window.length).map_err(to_disk)?;
    NtfsFs::open(part).map_err(to_disk)
}

/// Read each of `paths` into `acc`, enforcing the per-file byte and global
/// file caps. Stops early once the global cap is reached.
fn extract_files_into(
    fs: &mut ntfs_core::NtfsFs<OffsetReaderT<'_>>,
    window: PartitionWindow,
    paths: &[&str],
    acc: &mut Accumulator,
) -> Result<(), DiskError> {
    use ntfs_core::NtfsError;
    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());
    let mut collected = 0usize;
    for &path in paths {
        if acc.global_full() {
            acc.record(ExtractionLimit::TooManyFiles {
                pattern: "<global>".to_string(),
                cap: acc.caps.max_files_global,
            });
            break;
        }
        if collected >= acc.caps.max_files_per_pattern {
            acc.record(ExtractionLimit::TooManyFiles {
                pattern: format!("FixedPath set ({} paths)", paths.len()),
                cap: acc.caps.max_files_per_pattern,
            });
            break;
        }
        match fs.read_file(path) {
            Ok(data) => {
                collected += 1;
                if !acc.accept(ExtractedFile {
                    path: path.to_string(),
                    data,
                    partition_offset: window.offset,
                }) {
                    break;
                }
            }
            // The artifact simply isn't on this image — expected during triage.
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => {}
            Err(e) => return Err(to_disk(e)),
        }
    }
    Ok(())
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
    capped_single(source, window, ExtractCaps::default(), |acc, fs| {
        extract_dir_suffix_into(fs, window, dir, suffix, acc)
    })
}

/// Capped worker for [`extract_dir_suffix`].
fn extract_dir_suffix_into(
    fs: &mut ntfs_core::NtfsFs<OffsetReaderT<'_>>,
    window: PartitionWindow,
    dir: &str,
    suffix: &str,
    acc: &mut Accumulator,
) -> Result<(), DiskError> {
    use ntfs_core::NtfsError;
    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());

    // Resolve the directory; if it isn't on this image, there's nothing to do.
    let dir_record = match fs.resolve_path(dir) {
        Ok(n) => n,
        Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => return Ok(()),
        Err(e) => return Err(to_disk(e)),
    };
    let record = fs.read_record(dir_record).map_err(to_disk)?;
    let entries = fs.directory_entries(&record).map_err(to_disk)?;

    let suffix_lc = suffix.to_ascii_lowercase();
    let base = dir.trim_end_matches('\\');
    let mut collected = 0usize;
    for (seen, entry) in entries.into_iter().enumerate() {
        if seen >= acc.caps.max_dir_entries {
            acc.record(ExtractionLimit::TooManyDirEntries {
                dir: dir.to_string(),
                cap: acc.caps.max_dir_entries,
            });
            break;
        }
        let Some(name) = entry.file_name.map(|f| f.name) else {
            continue;
        };
        if !name.to_ascii_lowercase().ends_with(&suffix_lc) {
            continue;
        }
        if collected >= acc.caps.max_files_per_pattern {
            acc.record(ExtractionLimit::TooManyFiles {
                pattern: format!("DirSuffix {dir}\\*{suffix}"),
                cap: acc.caps.max_files_per_pattern,
            });
            break;
        }
        let path = format!("{base}\\{name}");
        match fs.read_file(&path) {
            Ok(data) => {
                collected += 1;
                if !acc.accept(ExtractedFile {
                    path,
                    data,
                    partition_offset: window.offset,
                }) {
                    break;
                }
            }
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => {}
            Err(e) => return Err(to_disk(e)),
        }
    }
    Ok(())
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
    capped_single(source, window, ExtractCaps::default(), |acc, fs| {
        extract_per_subdir_into(fs, window, parent, child, acc)
    })
}

/// Capped worker for [`extract_per_subdir`].
fn extract_per_subdir_into(
    fs: &mut ntfs_core::NtfsFs<OffsetReaderT<'_>>,
    window: PartitionWindow,
    parent: &str,
    child: &str,
    acc: &mut Accumulator,
) -> Result<(), DiskError> {
    use ntfs_core::NtfsError;
    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());

    let parent_record = match fs.resolve_path(parent) {
        Ok(n) => n,
        Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => return Ok(()),
        Err(e) => return Err(to_disk(e)),
    };
    let record = fs.read_record(parent_record).map_err(to_disk)?;
    let entries = fs.directory_entries(&record).map_err(to_disk)?;

    let base = parent.trim_end_matches('\\');
    let mut collected = 0usize;
    for (seen, entry) in entries.into_iter().enumerate() {
        if seen >= acc.caps.max_dir_entries {
            acc.record(ExtractionLimit::TooManyDirEntries {
                dir: parent.to_string(),
                cap: acc.caps.max_dir_entries,
            });
            break;
        }
        let Some(name) = entry.file_name.map(|f| f.name) else {
            continue;
        };
        if collected >= acc.caps.max_files_per_pattern {
            acc.record(ExtractionLimit::TooManyFiles {
                pattern: format!("PerUserFile {parent}\\*\\{child}"),
                cap: acc.caps.max_files_per_pattern,
            });
            break;
        }
        // Try `<parent>\<name>\<child>`; non-directory entries resolve to
        // NotADirectory and are skipped, so we needn't pre-check the type.
        let path = format!("{base}\\{name}\\{child}");
        match fs.read_file(&path) {
            Ok(data) => {
                collected += 1;
                if !acc.accept(ExtractedFile {
                    path,
                    data,
                    partition_offset: window.offset,
                }) {
                    break;
                }
            }
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => {}
            Err(e) => return Err(to_disk(e)),
        }
    }
    Ok(())
}

/// NTFS `$FILE_NAME` attribute flag marking the entry as a directory.
///
/// In the `$FILE_NAME` `FileAttributes` field NTFS sets bit `0x1000_0000` for
/// directories (libfsntfs `FILE_ATTRIBUTE_FLAG_DIRECTORY`; the Win32 `0x10`
/// directory bit is *not* used here). Checking it lets the per-subdir sweep
/// descend only into real directories, skipping stray files such as
/// `$Recycle.Bin\desktop.ini` without an extra record read.
const FN_ATTR_DIRECTORY: u32 = 0x1000_0000;

/// NTFS `$FILE_NAME` namespace code for a DOS 8.3 short name.
///
/// A name in this namespace (e.g. `S-1-5-~1` for a long SID directory) is an
/// alias of a separate Win32 entry for the same record, so sweeping it would
/// double-count the artifact. Skipping namespace 2 dedups by construction; a
/// record carrying *only* a short name uses the combined Win32&DOS namespace
/// (3), not 2, so nothing is lost.
const FN_NAMESPACE_DOS: u8 = 2;

/// For each immediate **subdirectory** `<sub>` of `parent`, sweep the directory
/// `<parent>\<sub>` (or `<parent>\<sub>\<rel>` when `rel` is non-empty) and
/// extract every file whose name satisfies `matches`.
///
/// This collects per-principal artifacts whose container directory is keyed by
/// a variable name that the fixed-path and fixed-suffix sweeps cannot express:
/// per-user `Recent\*.lnk` / `Desktop\*.lnk` (keyed by the user folder) and
/// per-SID `$Recycle.Bin\<SID>\$I*` (keyed by the SID). `matches` takes a name
/// predicate rather than a suffix so a prefix rule (`$I…`) needs no special case.
///
/// Tolerant by construction: a missing `parent`, a non-directory child, or a
/// subtree lacking `rel` each contribute nothing rather than erroring — triage
/// expects most artifacts to be absent on any given image.
///
/// # Errors
///
/// [`DiskError`] if the volume can't be opened, or a read fails for a reason
/// other than the path being absent / not a directory.
pub fn extract_subdir_sweep(
    source: &dyn DataSource,
    window: PartitionWindow,
    parent: &str,
    rel: &str,
    matches: &dyn Fn(&str) -> bool,
) -> Result<Vec<ExtractedFile>, DiskError> {
    capped_single(source, window, ExtractCaps::default(), |acc, fs| {
        extract_subdir_sweep_into(fs, window, parent, rel, matches, acc)
    })
}

/// Capped worker for [`extract_subdir_sweep`], with the MFT-reference cycle
/// guard: a subdirectory whose record number is the sweep parent (a
/// self-referential / looping reference) is recorded and skipped rather than
/// descended, so a crafted index that points back at an ancestor terminates.
fn extract_subdir_sweep_into(
    fs: &mut ntfs_core::NtfsFs<OffsetReaderT<'_>>,
    window: PartitionWindow,
    parent: &str,
    rel: &str,
    matches: &dyn Fn(&str) -> bool,
    acc: &mut Accumulator,
) -> Result<(), DiskError> {
    use ntfs_core::NtfsError;
    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());

    let parent_record = match fs.resolve_path(parent) {
        Ok(n) => n,
        Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => return Ok(()),
        Err(e) => return Err(to_disk(e)),
    };
    let record = fs.read_record(parent_record).map_err(to_disk)?;
    let subdirs = fs.directory_entries(&record).map_err(to_disk)?;

    // Records seen on the descent path (the parent itself); any subdir entry
    // pointing back to one is a loop and must not be descended.
    let mut visited = std::collections::HashSet::new();
    visited.insert(parent_record);

    let parent_base = parent.trim_end_matches('\\');
    let rel = rel.trim_matches('\\');
    let mut collected = 0usize;
    for (seen, sub) in subdirs.into_iter().enumerate() {
        if seen >= acc.caps.max_dir_entries {
            acc.record(ExtractionLimit::TooManyDirEntries {
                dir: parent.to_string(),
                cap: acc.caps.max_dir_entries,
            });
            break;
        }
        let Some(fname) = sub.file_name else {
            continue; // terminal index entry — no name
        };
        if fname.namespace == FN_NAMESPACE_DOS {
            continue; // 8.3 alias of a Win32 subdir name — skip to avoid double-counting
        }
        if fname.flags & FN_ATTR_DIRECTORY == 0 {
            continue; // a file (e.g. $Recycle.Bin\desktop.ini), never a sweep root
        }
        let sweep_dir = if rel.is_empty() {
            format!("{parent_base}\\{}", fname.name)
        } else {
            format!("{parent_base}\\{}\\{rel}", fname.name)
        };
        // Depth backstop: never descend a sweep path deeper than the cap (the
        // path component count of the resolved sweep dir).
        let depth = sweep_dir.split('\\').filter(|c| !c.is_empty()).count();
        if depth > acc.caps.max_depth {
            acc.record(ExtractionLimit::DepthExceeded {
                dir: sweep_dir,
                cap: acc.caps.max_depth,
            });
            continue;
        }
        // Cycle guard: a subdirectory entry whose target record is one already
        // on the descent path is a looping/self-referential reference.
        let sub_record = sub.file_reference.record_number;
        if !visited.insert(sub_record) {
            acc.record(ExtractionLimit::CycleDetected {
                dir: sweep_dir,
                record: sub_record,
            });
            continue;
        }
        // Resolve the (possibly nested) sweep directory; absent on this user is fine.
        let dir_record = match fs.resolve_path(&sweep_dir) {
            Ok(n) => n,
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => continue,
            Err(e) => return Err(to_disk(e)),
        };
        if sweep_one_dir(
            fs,
            window,
            dir_record,
            &sweep_dir,
            parent,
            rel,
            matches,
            &mut collected,
            acc,
        )? == SweepFlow::Stop
        {
            return Ok(());
        }
    }
    Ok(())
}

/// Whether the caller should keep sweeping further subdirectories or stop
/// (a per-pattern or global cap was reached).
#[derive(PartialEq, Eq)]
enum SweepFlow {
    Continue,
    Stop,
}

/// Sweep one resolved directory (`dir_record`) for files matching `matches`,
/// reading each into `acc` under the caps. Bumps `collected` (the per-pattern
/// count). Returns [`SweepFlow::Stop`] when a per-pattern/global cap is hit.
#[allow(clippy::too_many_arguments)]
fn sweep_one_dir(
    fs: &mut ntfs_core::NtfsFs<OffsetReaderT<'_>>,
    window: PartitionWindow,
    dir_record: u64,
    sweep_dir: &str,
    parent: &str,
    rel: &str,
    matches: &dyn Fn(&str) -> bool,
    collected: &mut usize,
    acc: &mut Accumulator,
) -> Result<SweepFlow, DiskError> {
    use ntfs_core::NtfsError;
    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());

    let dir_rec = fs.read_record(dir_record).map_err(to_disk)?;
    let entries = fs.directory_entries(&dir_rec).map_err(to_disk)?;
    for (dseen, entry) in entries.into_iter().enumerate() {
        if dseen >= acc.caps.max_dir_entries {
            acc.record(ExtractionLimit::TooManyDirEntries {
                dir: sweep_dir.to_string(),
                cap: acc.caps.max_dir_entries,
            });
            break;
        }
        let Some(fname) = entry.file_name else {
            continue;
        };
        if fname.namespace == FN_NAMESPACE_DOS {
            continue; // 8.3 alias of a Win32 file name — skip to avoid double-counting
        }
        let name = fname.name;
        if !matches(&name) {
            continue;
        }
        if *collected >= acc.caps.max_files_per_pattern {
            acc.record(ExtractionLimit::TooManyFiles {
                pattern: format!("PerSubdirSweep {parent}\\*\\{rel}"),
                cap: acc.caps.max_files_per_pattern,
            });
            return Ok(SweepFlow::Stop);
        }
        let path = format!("{sweep_dir}\\{name}");
        match fs.read_file(&path) {
            Ok(data) => {
                *collected += 1;
                if !acc.accept(ExtractedFile {
                    path,
                    data,
                    partition_offset: window.offset,
                }) {
                    return Ok(SweepFlow::Stop);
                }
            }
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => {}
            Err(e) => return Err(to_disk(e)),
        }
    }
    Ok(SweepFlow::Continue)
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
    capped_single(source, window, ExtractCaps::default(), |acc, fs| {
        extract_named_streams_into(fs, window, streams, acc)
    })
}

/// Capped worker for [`extract_named_streams`].
fn extract_named_streams_into(
    fs: &mut ntfs_core::NtfsFs<OffsetReaderT<'_>>,
    window: PartitionWindow,
    streams: &[(&str, &str)],
    acc: &mut Accumulator,
) -> Result<(), DiskError> {
    use ntfs_core::NtfsError;
    let to_disk = |e: NtfsError| DiskError::Ntfs(e.to_string());

    let mut collected = 0usize;
    for &(path, stream) in streams {
        if collected >= acc.caps.max_files_per_pattern {
            acc.record(ExtractionLimit::TooManyFiles {
                pattern: format!("NamedStream set ({} streams)", streams.len()),
                cap: acc.caps.max_files_per_pattern,
            });
            break;
        }
        match fs.read_named_stream(path, stream) {
            Ok(data) => {
                collected += 1;
                if !acc.accept(ExtractedFile {
                    path: format!("{path}:{stream}"),
                    data,
                    partition_offset: window.offset,
                }) {
                    break;
                }
            }
            Err(NtfsError::NotFound(_) | NtfsError::NotADirectory(_)) => {}
            Err(e) => return Err(to_disk(e)),
        }
    }
    Ok(())
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

/// Compare `$MFT` against its `$MFTMirr` (the first four system records NTFS
/// mirrors: `$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`) and surface any divergence
/// as an Integrity event. A mismatch is consistent with metadata tampering OR
/// ordinary corruption — an observation, never a verdict (the analyst/tribunal
/// concludes). This is a CROSS-FILE check (both files required), so it lives over
/// the extracted set here rather than in a single-file parser.
#[must_use]
pub fn mft_mirror_integrity_events(
    mft: &[u8],
    mftmirr: &[u8],
    source_id: &str,
) -> Vec<issen_core::timeline::event::TimelineEvent> {
    use issen_core::timeline::event::{EventType, TimelineEvent};
    ntfs_forensic::audit_mft_mirror(mft, mftmirr)
        .into_iter()
        .map(|anomaly| {
            TimelineEvent::new(
                0,
                String::new(),
                EventType::Other("integrity".into()),
                issen_core::artifacts::ArtifactType::Mft,
                r"\$MFTMirr".to_string(),
                format!(
                    "$MFTMirr integrity: {} — {}",
                    anomaly.code(),
                    anomaly.note()
                ),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Integrity)
            .with_tag("integrity")
            .with_metadata("code", serde_json::json!(anomaly.code()))
            .with_metadata(
                "severity",
                serde_json::json!(format!("{:?}", anomaly.severity())),
            )
        })
        .collect()
}

// ── $Boot vs backup-$Boot consistency ────────────────────────────────────────
//
// NTFS stores the volume boot record (VBR/BPB) at the partition's first sector
// and a backup copy at the last sector the BPB accounts for: byte offset
// `total_sectors * bytes_per_sector` into the partition (the backup sits at
// sector index `total_sectors`). Both carry the same geometry; a divergence is
// a CONSISTENCY ANOMALY — consistent with tampering OR ordinary corruption /
// imaging artifacts (a resized or partially-acquired volume) — never a verdict.
// This is the $Boot sibling of `mft_mirror_integrity_events`.
//
// The eventual canonical home for the graded `Anomaly` is `ntfs-forensic`
// (alongside `audit_mft_mirror`); until that ships, the comparison + grading
// live here, reusing `ntfs_core::BootSector::parse` for both copies.

/// The comparable geometry of an NTFS boot sector — the subset the primary and
/// its backup must agree on. Derived from [`ntfs_core::BootSector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootGeometry {
    /// Bytes per logical sector.
    pub bytes_per_sector: u16,
    /// Logical sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Total sectors the BPB accounts for (the backup boot sits at this index).
    pub total_sectors: u64,
    /// Cluster number (LCN) of the `$MFT`.
    pub mft_lcn: u64,
    /// Cluster number (LCN) of the `$MFTMirr`.
    pub mftmirr_lcn: u64,
    /// 64-bit volume serial number.
    pub volume_serial: u64,
}

impl From<&ntfs_core::BootSector> for BootGeometry {
    fn from(b: &ntfs_core::BootSector) -> Self {
        Self {
            bytes_per_sector: b.bytes_per_sector,
            sectors_per_cluster: b.sectors_per_cluster,
            total_sectors: b.total_sectors,
            mft_lcn: b.mft_lcn,
            mftmirr_lcn: b.mftmirr_lcn,
            volume_serial: b.volume_serial,
        }
    }
}

impl BootGeometry {
    /// Byte offset of the backup boot sector, relative to the partition start.
    #[must_use]
    fn backup_offset(self) -> u64 {
        self.total_sectors
            .saturating_mul(u64::from(self.bytes_per_sector))
    }

    /// Human-readable names of the geometry fields that differ between `self`
    /// (primary) and `backup`. Empty when the two agree.
    #[must_use]
    fn diverging_fields(self, backup: BootGeometry) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.bytes_per_sector != backup.bytes_per_sector {
            out.push("bytes/sector");
        }
        if self.sectors_per_cluster != backup.sectors_per_cluster {
            out.push("sectors/cluster");
        }
        if self.total_sectors != backup.total_sectors {
            out.push("total sectors");
        }
        if self.mft_lcn != backup.mft_lcn {
            out.push("$MFT LCN");
        }
        if self.mftmirr_lcn != backup.mftmirr_lcn {
            out.push("$MFTMirr LCN");
        }
        if self.volume_serial != backup.volume_serial {
            out.push("volume serial");
        }
        out
    }
}

/// Read and parse the primary NTFS boot sector at the start of `window`.
///
/// Reuses [`ntfs_core::BootSector`] — no re-implementation of BPB parsing.
///
/// # Errors
///
/// [`DiskError::Source`] if the sector cannot be read, or [`DiskError::Ntfs`]
/// if it does not parse as an NTFS boot sector.
pub fn read_boot_geometry(
    source: &dyn DataSource,
    window: PartitionWindow,
) -> Result<BootGeometry, DiskError> {
    let bs = parse_boot_at(source, window.offset)?;
    Ok(BootGeometry::from(&bs))
}

/// Parse the boot sector at absolute disk byte `offset`.
fn parse_boot_at(source: &dyn DataSource, offset: u64) -> Result<ntfs_core::BootSector, DiskError> {
    let mut sector = [0u8; 512];
    let n = source
        .read_at(offset, &mut sector)
        .map_err(|e| DiskError::Source(e.to_string()))?;
    if n < 512 {
        return Err(DiskError::Source(format!(
            "short read for boot sector at offset {offset}: got {n} of 512 bytes"
        )));
    }
    ntfs_core::BootSector::parse(&sector)
        .map_err(|e| DiskError::Ntfs(format!("boot sector at offset {offset}: {e}")))
}

/// Compare the primary `$Boot` against its backup copy at the last sector of the
/// volume and surface any geometry divergence as an Integrity event. A mismatch
/// is consistent with boot-record tampering OR ordinary corruption / a partially
/// acquired or resized volume — an observation, never a verdict (the analyst /
/// tribunal concludes). This is a CROSS-COPY check, so it lives over the volume
/// here rather than in a single-file parser.
///
/// # Errors
///
/// Returns a loud [`DiskError`] when the primary or the **backup** boot sector
/// cannot be read or parsed — emphatically NOT an empty "consistent" result.
/// A sparse acquisition that never stored the backup sector degrades here, so an
/// absent backup is never misreported as a tamper mismatch.
pub fn boot_backup_integrity_events(
    source: &dyn DataSource,
    window: PartitionWindow,
    source_id: &str,
) -> Result<Vec<issen_core::timeline::event::TimelineEvent>, DiskError> {
    use issen_core::timeline::event::{EventType, TimelineEvent};

    let primary = read_boot_geometry(source, window)?;

    let backup_off = window.offset.saturating_add(primary.backup_offset());
    let backup = BootGeometry::from(&parse_boot_at(source, backup_off)?);

    let diverging = primary.diverging_fields(backup);
    if diverging.is_empty() {
        return Ok(Vec::new());
    }

    let fields = diverging.join(", ");
    let note = format!(
        "$Boot differs from its backup copy for {fields} \
         — consistent with boot-record tampering or corruption"
    );
    let event = TimelineEvent::new(
        0,
        String::new(),
        EventType::Other("integrity".into()),
        issen_core::artifacts::ArtifactType::Mft,
        r"\$Boot".to_string(),
        format!("$Boot integrity: NTFS-BOOT-BACKUP-MISMATCH — {note}"),
        source_id.to_string(),
    )
    .with_activity_category(issen_core::ActivityCategory::Integrity)
    .with_tag("integrity")
    .with_metadata("code", serde_json::json!("NTFS-BOOT-BACKUP-MISMATCH"))
    .with_metadata("severity", serde_json::json!("High"))
    .with_metadata("diverging_fields", serde_json::json!(diverging))
    .with_metadata("backup_offset", serde_json::json!(primary.backup_offset()));

    Ok(vec![event])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mft_mirror_mismatch_yields_integrity_event() {
        // Four 1024-byte system records; flip record 0 ($MFT) and record 2
        // ($LogFile) in the mirror so they diverge from $MFT.
        let mft = vec![0xAAu8; 1024 * 4];
        let mut mirr = mft.clone();
        mirr[0] = 0xBB;
        mirr[1024 * 2] = 0xCC;
        let events = mft_mirror_integrity_events(&mft, &mirr, "ev");
        assert_eq!(
            events.len(),
            1,
            "a $MFTMirr divergence -> one integrity event"
        );
        let e = &events[0];
        assert_eq!(
            e.activity_category,
            Some(issen_core::ActivityCategory::Integrity),
            "a $MFTMirr mismatch is an Integrity observation"
        );
        assert!(
            e.description.contains("NTFS-MFTMIRR-MISMATCH"),
            "got: {}",
            e.description
        );
    }

    #[test]
    fn mft_mirror_consistent_yields_no_events() {
        let mft = vec![0xAAu8; 1024 * 4];
        assert!(mft_mirror_integrity_events(&mft, &mft, "ev").is_empty());
    }

    // ── $Boot vs backup-$Boot consistency ─────────────────────────────────────

    /// Build a disk whose NTFS partition carries a primary boot sector at its
    /// start AND a backup copy at the last sector (`total_sectors` into the
    /// partition), optionally diverging one BPB field in the backup.
    ///
    /// `flip` is applied to the backup's `bytes_per_sector` low byte when set, so
    /// the primary and backup geometry disagree on exactly one comparable field.
    fn disk_with_backup_boot(flip_serial: Option<u64>) -> (VecSource, PartitionWindow) {
        const PART_LBA: u64 = 2048;
        // 64 partition sectors: primary at 0, backup at total_sectors = 60.
        const TOTAL_SECTORS: u64 = 60;
        const PART_SECTORS: u64 = 64;

        let mut primary = ntfs_boot();
        primary[0x28..0x30].copy_from_slice(&TOTAL_SECTORS.to_le_bytes());
        primary[0x48..0x50].copy_from_slice(&0xDEAD_BEEF_CAFE_F00Du64.to_le_bytes());

        let mut backup = primary;
        if let Some(serial) = flip_serial {
            backup[0x48..0x50].copy_from_slice(&serial.to_le_bytes());
        }

        let total_bytes = ((PART_LBA + PART_SECTORS) as usize) * SECTOR;
        let mut disk = vec![0u8; total_bytes];
        disk[..SECTOR].copy_from_slice(&mbr_one_ntfs(PART_LBA as u32, PART_SECTORS as u32));
        let part_off = PART_LBA as usize * SECTOR;
        disk[part_off..part_off + SECTOR].copy_from_slice(&primary);
        let backup_off = part_off + (TOTAL_SECTORS as usize) * SECTOR;
        disk[backup_off..backup_off + SECTOR].copy_from_slice(&backup);

        let window = PartitionWindow {
            offset: part_off as u64,
            length: PART_SECTORS * SECTOR as u64,
        };
        (VecSource(disk), window)
    }

    #[test]
    fn boot_backup_consistent_yields_no_events() {
        let (src, window) = disk_with_backup_boot(None);
        let events = boot_backup_integrity_events(&src, window, "ev").expect("read boot");
        assert!(
            events.is_empty(),
            "matching primary/backup boot -> no integrity event, got {events:?}"
        );
    }

    #[test]
    fn boot_backup_mismatch_yields_one_integrity_event() {
        // Backup volume serial diverges from the primary by one field.
        let (src, window) = disk_with_backup_boot(Some(0x0102_0304_0506_0708));
        let events = boot_backup_integrity_events(&src, window, "ev").expect("read boot");
        assert_eq!(
            events.len(),
            1,
            "a $Boot/backup divergence -> exactly one integrity event"
        );
        let e = &events[0];
        assert_eq!(
            e.activity_category,
            Some(issen_core::ActivityCategory::Integrity),
            "a $Boot backup mismatch is an Integrity observation"
        );
        assert!(
            e.description.contains("NTFS-BOOT-BACKUP-MISMATCH"),
            "got: {}",
            e.description
        );
        assert!(
            e.description.contains("volume serial"),
            "the diverging field is named; got: {}",
            e.description
        );
        // Consistency anomaly, never a verdict.
        assert!(
            e.description.contains("consistent with"),
            "graded as an observation; got: {}",
            e.description
        );
    }

    #[test]
    fn boot_backup_unreadable_is_not_a_mismatch() {
        // Primary present, but the backup sector falls outside the data we have
        // (sparse acquisition). That must degrade loud — NOT be reported as a
        // tamper mismatch.
        let (src, window) = disk_with_backup_boot(None);
        // Truncate the source so the backup sector is unreadable.
        let truncated = {
            let part_off = window.offset as usize;
            VecSource(src.0[..part_off + SECTOR].to_vec())
        };
        let err = boot_backup_integrity_events(&truncated, window, "ev").unwrap_err();
        match err {
            DiskError::Source(_) | DiskError::Io(_) | DiskError::Ntfs(_) => {}
            DiskError::Disk(_) => panic!("unreadable backup must be a read/parse error, not Disk"),
        }
    }

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

        /// `$FILE_NAME` content. `flags` are the `FILE_ATTRIBUTE_*` bits at
        /// content offset 0x38 — set `0x1000_0000` to mark a directory so a
        /// subdirectory sweep will descend into it.
        fn fname_flags(parent: u64, name: &str, flags: u32) -> Vec<u8> {
            let u: Vec<u16> = name.encode_utf16().collect();
            let mut c = vec![0u8; 0x42 + u.len() * 2];
            c[0..8].copy_from_slice(&((1u64 << 48) | parent).to_le_bytes());
            c[0x38..0x3C].copy_from_slice(&flags.to_le_bytes());
            c[0x40] = u.len() as u8;
            c[0x41] = 1; // Win32
            for (i, ch) in u.iter().enumerate() {
                c[0x42 + i * 2..0x42 + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
            }
            c
        }

        fn fname(parent: u64, name: &str) -> Vec<u8> {
            fname_flags(parent, name, 0)
        }

        fn index_entry(target: u64, name: &str) -> Vec<u8> {
            index_entry_flags(target, name, 0)
        }

        /// An index entry whose embedded `$FILE_NAME` carries `flags` (use the
        /// directory bit `0x1000_0000` for subdirectories).
        fn index_entry_flags(target: u64, name: &str, flags: u32) -> Vec<u8> {
            let fnc = fname_flags(5, name, flags);
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

        /// A directory record whose `$INDEX_ROOT` lists `children`
        /// (`(target_record, name, is_dir)`), terminated by the end marker. A
        /// child with `is_dir = true` carries the directory attribute so a
        /// subdirectory sweep descends into it.
        fn dir_record(children: &[(u64, &str, bool)]) -> Vec<u8> {
            const DIR: u32 = 0x1000_0000;
            let mut entries: Vec<Vec<u8>> = children
                .iter()
                .map(|(t, n, is_dir)| index_entry_flags(*t, n, if *is_dir { DIR } else { 0 }))
                .collect();
            entries.push(index_end());
            record(0x0003, &index_root(&entries))
        }

        /// A resident file record holding `data` as its unnamed `$DATA`.
        fn file_record(parent: u64, name: &str, data: &[u8]) -> Vec<u8> {
            let mut a = Vec::new();
            a.extend_from_slice(&attr_resident(0x10, None, &[0u8; 0x30]));
            a.extend_from_slice(&attr_resident(0x30, None, &fname(parent, name)));
            a.extend_from_slice(&attr_resident(0x80, None, data));
            record(0x0001, &a)
        }

        /// Lay `records` (`(record_number, bytes)`) into a fresh volume, sizing
        /// the MFT data run to cover the highest record number used.
        fn assemble(records: &[(u64, Vec<u8>)]) -> Vec<u8> {
            let max_rec = records.iter().map(|(n, _)| *n).max().unwrap_or(5);
            let count = (max_rec + 1) as usize;
            let mft_clusters = (count * REC).div_ceil(CLUSTER) as u64;
            let total = MFT_LCN + mft_clusters + 2;
            let mut v = vec![0u8; total as usize * CLUSTER];
            v[0..512].copy_from_slice(&boot());

            let runs = [0x11u8, mft_clusters as u8, MFT_LCN as u8, 0x00];
            let rec0 = record(
                0x0001,
                &nonresident_data(&runs, mft_clusters * CLUSTER as u64),
            );
            let mft_off = MFT_LCN as usize * CLUSTER;
            let o0 = mft_off; // record 0
            v[o0..o0 + rec0.len()].copy_from_slice(&rec0);
            for (idx, rec) in records {
                let o = mft_off + *idx as usize * REC;
                v[o..o + rec.len()].copy_from_slice(rec);
            }
            v
        }

        /// A volume exercising the per-SID `$Recycle.Bin` sweep with a
        /// self-referential MFT reference: the SID "subdirectory" entry points
        /// back at the `$Recycle.Bin` record itself, so a sweep that descends by
        /// record number without a visited-set re-enters the same record
        /// forever.
        ///
        /// Record map: 5=root, 6=`$Recycle.Bin` whose index lists a child named
        /// like a SID but targeting record 6 (itself).
        pub fn build_cycle() -> Vec<u8> {
            let root = dir_record(&[(6, "$Recycle.Bin", true)]);
            // The child "S-1-5-21-1001" (a directory) targets record 6 — the
            // $Recycle.Bin directory itself. Descending into it re-enters
            // record 6 absent a cycle guard.
            let recycle = dir_record(&[(6, "S-1-5-21-1001", true)]);
            assemble(&[(5, root), (6, recycle)])
        }

        /// A volume carrying all three Phase-2 sweep targets:
        /// `\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\open.lnk`,
        /// `\$Recycle.Bin\S-1-5-21-1001\$IABCDE`, and the `\$Extend\$UsnJrnl:$J`
        /// ADS. Used by the end-to-end extraction test.
        pub fn build_full() -> Vec<u8> {
            // Record numbering (5 = root):
            //  6 Users  7 alice  8 AppData  9 Local-unused? -> use linear chain
            //  We build the Recent chain: Users(6)->alice(7)->AppData(8)->
            //  Roaming(9)->Microsoft(10)->Windows(11)->Recent(12)->open.lnk(13)
            //  $Recycle.Bin(14)->SID(15)->$IABCDE(16)
            //  $Extend(17)->$UsnJrnl(18, with a $J ADS)
            let root = dir_record(&[
                (6, "Users", true),
                (14, "$Recycle.Bin", true),
                (17, "$Extend", true),
            ]);
            let users = dir_record(&[(7, "alice", true)]);
            let alice = dir_record(&[(8, "AppData", true)]);
            let appdata = dir_record(&[(9, "Roaming", true)]);
            let roaming = dir_record(&[(10, "Microsoft", true)]);
            let microsoft = dir_record(&[(11, "Windows", true)]);
            let windows = dir_record(&[(12, "Recent", true)]);
            let recent = dir_record(&[(13, "open.lnk", false)]);
            let lnk = file_record(12, "open.lnk", b"LNK-TARGET:C:\\loot.txt");

            let recycle = dir_record(&[(15, "S-1-5-21-1001", true)]);
            let sid = dir_record(&[(16, "$IABCDE", false)]);
            let idx_i = file_record(15, "$IABCDE", b"$I-DELETED:C:\\secret.docx");

            let extend = dir_record(&[(18, "$UsnJrnl", false)]);
            // $UsnJrnl record: an unnamed $DATA (the $Max metadata stand-in) plus
            // a named "$J" $DATA stream — the change journal.
            let mut usn = Vec::new();
            usn.extend_from_slice(&attr_resident(0x10, None, &[0u8; 0x30]));
            usn.extend_from_slice(&attr_resident(0x30, None, &fname(17, "$UsnJrnl")));
            usn.extend_from_slice(&attr_resident(0x80, None, b"$Max"));
            usn.extend_from_slice(&attr_resident(0x80, Some("$J"), b"USN-JOURNAL-DATA"));
            let usn_rec = record(0x0001, &usn);

            assemble(&[
                (5, root),
                (6, users),
                (7, alice),
                (8, appdata),
                (9, roaming),
                (10, microsoft),
                (11, windows),
                (12, recent),
                (13, lnk),
                (14, recycle),
                (15, sid),
                (16, idx_i),
                (17, extend),
                (18, usn_rec),
            ])
        }

        /// Place [`build_cycle`] at a partition offset inside an MBR disk.
        pub fn disk_with_cycle(lba_start: u32) -> super::VecSource {
            super::place_volume(lba_start, &build_cycle())
        }

        /// Place [`build_full`] at a partition offset inside an MBR disk.
        pub fn disk_full(lba_start: u32) -> super::VecSource {
            super::place_volume(lba_start, &build_full())
        }
    }

    /// Place an already-built NTFS volume `v` at a partition offset inside an
    /// MBR disk.
    fn place_volume(lba_start: u32, v: &[u8]) -> VecSource {
        let count = v.len().div_ceil(SECTOR) as u32 + 1;
        let total = (lba_start + count) as usize * SECTOR;
        let mut disk = vec![0u8; total];
        disk[..SECTOR].copy_from_slice(&mbr_one_ntfs(lba_start, count));
        let off = lba_start as usize * SECTOR;
        disk[off..off + v.len()].copy_from_slice(v);
        VecSource(disk)
    }

    /// Place the synthetic NTFS volume at a partition offset inside an MBR disk.
    fn disk_with_volume(lba_start: u32) -> VecSource {
        place_volume(lba_start, &vol::build())
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

        let manifest =
            triage_manifest_from(&src, "TEST", &[NtfsLoc::FixedPath(r"\$MFT")]).expect("manifest");
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

    /// An MBR disk whose partition carries an APFS container superblock (NXSB
    /// magic at offset 32) instead of an NTFS boot sector — a macOS image.
    fn disk_with_apfs(lba_start: u32, lba_count: u32) -> VecSource {
        let total = (lba_start + lba_count) as usize * SECTOR;
        let mut disk = vec![0u8; total];
        disk[..SECTOR].copy_from_slice(&mbr_one_ntfs(lba_start, lba_count));
        let off = lba_start as usize * SECTOR;
        disk[off + 32..off + 36].copy_from_slice(b"NXSB"); // nx_superblock_t.nx_magic
        VecSource(disk)
    }

    #[test]
    fn apfs_disk_records_unsupported_filesystem() {
        // The Big Sur "✔ 0 events" gap: a macOS/APFS disk yields no NTFS
        // artifacts, but that empty result must be LOUD (distinguishable from a
        // clean image), not a silent zero.
        let src = disk_with_apfs(2048, 64);
        assert!(
            find_ntfs_partitions(&src).expect("find").is_empty(),
            "fixture sanity: APFS partition is not NTFS"
        );
        let outcome = collect_with_caps(
            &src,
            &[NtfsLoc::FixedPath(r"\$MFT")],
            ExtractCaps::default(),
        )
        .expect("collect");
        assert!(
            outcome.limits.iter().any(|l| matches!(
                l,
                ExtractionLimit::UnsupportedFilesystem { filesystem, .. } if filesystem == "APFS"
            )),
            "an APFS-only disk must record an UnsupportedFilesystem diagnostic, got {:?}",
            outcome.limits
        );
    }

    #[test]
    fn ntfs_disk_records_no_unsupported_filesystem() {
        // The supported case must stay quiet — no false "unsupported" alarm.
        let src = disk_with_volume(2048);
        let outcome = collect_with_caps(
            &src,
            &[NtfsLoc::FixedPath(r"\$MFT")],
            ExtractCaps::default(),
        )
        .expect("collect");
        assert!(
            !outcome
                .limits
                .iter()
                .any(|l| matches!(l, ExtractionLimit::UnsupportedFilesystem { .. })),
            "a supported NTFS disk must not raise an unsupported-filesystem warning, got {:?}",
            outcome.limits
        );
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
        // The synthetic volume lacks the glob dir, so it adds nothing — but the
        // glob source must not disturb the fixed-path extraction (\$MFT).
        // (extract_triage itself is registry-driven and empty here; the dispatch
        // core takes explicit sources.)
        let src = disk_with_volume(2048);
        let parts = find_ntfs_partitions(&src).expect("find");
        let sources = [
            NtfsLoc::FixedPath(r"\$MFT"),
            NtfsLoc::DirSuffix {
                dir: r"\Windows\System32\winevt\Logs",
                suffix: ".evtx",
            },
        ];
        let files = extract_ntfs_sources(&src, parts[0], &sources).expect("extract");
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
        let parts = find_ntfs_partitions(&src).expect("find");
        let files =
            extract_ntfs_sources(&src, parts[0], &[NtfsLoc::FixedPath(r"\$MFT")]).expect("extract");
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
        // Folds the ADS suffix into the filename (collision-safe), drops
        // leading separators and traversal components.
        assert_eq!(
            sanitize_ntfs_path(r"\..\x\$UsnJrnl:$J"),
            std::path::Path::new("x/$UsnJrnl~$J")
        );
    }

    #[test]
    fn triage_manifest_writes_artifacts_to_tempdir() {
        let src = disk_with_volume(2048);
        let manifest =
            triage_manifest_from(&src, "TEST", &[NtfsLoc::FixedPath(r"\$MFT")]).expect("manifest");
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

    // ── Phase-2 extraction hardening: caps, cycle guard, ADS guard ─────────────
    //
    // A malicious/huge image must not OOM or hang the responder. The caps below
    // are enforced as a general rule (no per-pattern special case) and FAIL LOUD
    // on truncation — a hit is recorded as an `ExtractionLimit` on the outcome
    // and (in the CLI path) surfaced as a visible warning, never a silent
    // partial result that reads as complete.

    /// A per-file byte cap below the synthetic file size rejects the oversized
    /// file and records a LOUD truncation diagnostic (not a silent drop).
    #[test]
    fn caps_reject_oversized_file_and_record_limit() {
        let src = disk_with_volume(2048);
        let caps = ExtractCaps {
            max_file_bytes: 5, // \test.txt = "hello world" (11 bytes) exceeds this
            ..ExtractCaps::default()
        };
        let outcome =
            collect_with_caps(&src, &[NtfsLoc::FixedPath(r"\test.txt")], caps).expect("collect");
        assert!(
            outcome.files.is_empty(),
            "an over-cap file must NOT be emitted as a (truncated) partial"
        );
        assert!(
            outcome
                .limits
                .iter()
                .any(|l| matches!(l, ExtractionLimit::FileTooLarge { .. })),
            "hitting the byte cap must record a LOUD FileTooLarge limit, got {:?}",
            outcome.limits
        );
    }

    /// The default byte cap is well ABOVE the legitimate large system files
    /// (`$MFT` reaches ~85 MB on a real volume) — so a real triage never trips
    /// it. This guards against a too-low cap silently truncating evidence.
    #[test]
    fn default_byte_cap_is_well_above_system_file_sizes() {
        // 85 MB is the documented real-world $MFT ceiling; the cap must clear it
        // with a wide margin (we use multiple GiB).
        assert!(
            ExtractCaps::default().max_file_bytes >= 1 << 31,
            "default per-file cap must be >= 2 GiB so the legit ~85 MB $MFT reads"
        );
    }

    /// A per-pattern file cap stops collection at the limit and records it.
    #[test]
    fn caps_limit_files_per_pattern() {
        let src = disk_with_volume(2048);
        // The root `.` suffix glob would match test.txt; cap at 0 forces a hit.
        let caps = ExtractCaps {
            max_files_per_pattern: 0,
            ..ExtractCaps::default()
        };
        let outcome = collect_with_caps(
            &src,
            &[NtfsLoc::DirSuffix {
                dir: "\\",
                suffix: ".txt",
            }],
            caps,
        )
        .expect("collect");
        assert!(
            outcome
                .limits
                .iter()
                .any(|l| matches!(l, ExtractionLimit::TooManyFiles { .. })),
            "a per-pattern cap hit must record TooManyFiles, got {:?}",
            outcome.limits
        );
    }

    /// A global file cap stops the whole collection.
    #[test]
    fn caps_limit_files_global() {
        let src = disk_with_volume(2048);
        let caps = ExtractCaps {
            max_files_global: 0,
            ..ExtractCaps::default()
        };
        let outcome =
            collect_with_caps(&src, &[NtfsLoc::FixedPath(r"\$MFT")], caps).expect("collect");
        assert!(outcome.files.is_empty(), "a global cap of 0 emits nothing");
        assert!(
            outcome
                .limits
                .iter()
                .any(|l| matches!(l, ExtractionLimit::TooManyFiles { .. })),
            "a global cap hit must record TooManyFiles, got {:?}",
            outcome.limits
        );
    }

    /// A directory with more entries than the cap is bounded, recording a hit.
    #[test]
    fn caps_limit_directory_entries() {
        let src = disk_with_volume(2048);
        // The root has 3 named children; cap at 1 forces the dir-entry cap.
        let caps = ExtractCaps {
            max_dir_entries: 1,
            ..ExtractCaps::default()
        };
        let outcome = collect_with_caps(
            &src,
            &[NtfsLoc::DirSuffix {
                dir: "\\",
                suffix: ".txt",
            }],
            caps,
        )
        .expect("collect");
        assert!(
            outcome
                .limits
                .iter()
                .any(|l| matches!(l, ExtractionLimit::TooManyDirEntries { .. })),
            "a dir-entry cap hit must record TooManyDirEntries, got {:?}",
            outcome.limits
        );
    }

    /// A directory tree with a self-referential / looping MFT reference must
    /// terminate (cycle guard), never recurse forever.
    #[test]
    fn cycle_guard_terminates_on_self_referential_directory() {
        // `vol::build_with_cycle` makes a `$Recycle.Bin` whose SID subdirectory's
        // index points back at itself — a sweep without a visited-set would loop.
        let src = vol::disk_with_cycle(2048);
        let caps = ExtractCaps::default();
        // Must return (not hang); a cycle is recorded as a LOUD limit.
        let outcome = collect_with_caps(
            &src,
            &[NtfsLoc::PerSubdirSweep {
                parent: r"\$Recycle.Bin",
                rel: "",
                name: issen_core::plugin::selector::NameMatch::Prefix("$I"),
            }],
            caps,
        )
        .expect("collect terminates");
        assert!(
            outcome
                .limits
                .iter()
                .any(|l| matches!(l, ExtractionLimit::CycleDetected { .. })),
            "a looping MFT ref must record CycleDetected, got {:?}",
            outcome.limits
        );
    }

    /// 2.3 ADS non-regression: `$UsnJrnl:$J` (here the test.txt Zone.Identifier
    /// ADS stands in for the journal stream) still extracts after the caps
    /// change, and its `ExtractedFile.path` keeps the `path:stream` form.
    #[test]
    fn ads_stream_still_extracts_after_caps() {
        let src = disk_with_volume(2048);
        let outcome = collect_with_caps(
            &src,
            &[NtfsLoc::NamedStream {
                path: r"\test.txt",
                stream: "Zone.Identifier",
            }],
            ExtractCaps::default(),
        )
        .expect("collect");
        assert_eq!(outcome.files.len(), 1, "the ADS must survive caps");
        assert_eq!(outcome.files[0].path, r"\test.txt:Zone.Identifier");
        assert_eq!(outcome.files[0].data, b"[ZoneTransfer]");
        assert!(outcome.limits.is_empty(), "a small ADS trips no cap");
    }

    /// 2.3 output-name collision guard: two streams of one file (`:$J` and
    /// `:$Max`) must not sanitize to the SAME output path and overwrite. Today
    /// only `:$J` is collected so there is no live collision — this guards the
    /// invariant that distinct streams map to distinct manifest paths.
    #[test]
    fn distinct_streams_get_distinct_manifest_paths() {
        // Two named streams on the same file. The synthetic test.txt only has
        // Zone.Identifier, so we assert the sanitizer mapping directly: a
        // sanitized output path must encode the stream, so two streams of one
        // file cannot collapse onto one file.
        let a = sanitize_ntfs_path(r"\$Extend\$UsnJrnl:$J");
        let b = sanitize_ntfs_path(r"\$Extend\$UsnJrnl:$Max");
        assert_ne!(
            a, b,
            "distinct ADS of one file must map to distinct output paths (no overwrite)"
        );
    }

    /// 2.4 end-to-end: a synthetic NTFS volume carrying a Recent `*.lnk`, a
    /// `$Recycle.Bin\<SID>\$IABC` index file, and a `$UsnJrnl:$J` ADS survives
    /// extract → manifest, with all three artifacts present and distinct.
    #[test]
    fn e2e_lnk_recycle_and_usn_ads_all_extract() {
        let src = vol::disk_full(2048);
        let sources = [
            NtfsLoc::PerSubdirSweep {
                parent: r"\Users",
                rel: r"AppData\Roaming\Microsoft\Windows\Recent",
                name: issen_core::plugin::selector::NameMatch::Suffix(".lnk"),
            },
            NtfsLoc::PerSubdirSweep {
                parent: r"\$Recycle.Bin",
                rel: "",
                name: issen_core::plugin::selector::NameMatch::Prefix("$I"),
            },
            NtfsLoc::NamedStream {
                path: r"\$Extend\$UsnJrnl",
                stream: "$J",
            },
        ];
        let outcome = collect_with_caps(&src, &sources, ExtractCaps::default()).expect("collect");
        let names: Vec<&str> = outcome.files.iter().map(|f| f.path.as_str()).collect();
        assert!(
            names
                .iter()
                .any(|p| p.to_ascii_lowercase().ends_with(".lnk")),
            "the Recent .lnk must extract; got {names:?}"
        );
        assert!(
            names.iter().any(|p| p.contains("$I")),
            "the $Recycle.Bin $I index must extract; got {names:?}"
        );
        assert!(
            names.iter().any(|p| p.ends_with(":$J")),
            "the $UsnJrnl:$J ADS must extract; got {names:?}"
        );
        assert!(
            outcome.limits.is_empty(),
            "no caps tripped on a small volume"
        );
    }
}
