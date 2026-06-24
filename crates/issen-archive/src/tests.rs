#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use issen_unpack::{CollectionProvider, Confidence};

use super::extract::{
    cap_for_archive_size, extract_7z, extract_tar_gz, extract_zip, safe_join, MAX_EXPANSION_RATIO,
    MAX_TOTAL_UNCOMPRESSED,
};
use super::{detect_kind, ArchiveKind, ArchiveProvider};

const DFIRMADNESS_ZIP: &str =
    "/Users/4n6h4x0r/src/issen/tests/data/dfirmadness-szechuan-sauce/DC01-autorunsc.zip";
const SYSTEM_7Z: &str = "/opt/homebrew/bin/7z";

// ── helpers ───────────────────────────────────────────────────────────

fn write_minimal_tar_gz(path: &Path, files: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).unwrap();
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(enc);
    for (name, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, *data).unwrap();
    }
    builder
        .into_inner()
        .unwrap()
        .finish()
        .unwrap()
        .sync_all()
        .unwrap();
}

/// Build a single raw 512-byte `ustar` header + padded data block for `name`,
/// writing the name verbatim (so a hostile `..` path that the tar crate's
/// builder would reject can still be emitted, as a malicious archive does).
fn raw_tar_entry(name: &str, data: &[u8]) -> Vec<u8> {
    let mut block = vec![0u8; 512];
    let nb = name.as_bytes();
    block[..nb.len()].copy_from_slice(nb); // name field: bytes 0..100
    block[100..108].copy_from_slice(b"0000644\0"); // mode
    block[108..116].copy_from_slice(b"0000000\0"); // uid
    block[116..124].copy_from_slice(b"0000000\0"); // gid
                                                   // size (octal, 11 digits + NUL) at 124..136
    let size_oct = format!("{:011o}\0", data.len());
    block[124..136].copy_from_slice(size_oct.as_bytes());
    block[136..148].copy_from_slice(b"00000000000\0"); // mtime
    block[156] = b'0'; // typeflag: regular file
    block[257..263].copy_from_slice(b"ustar\0"); // magic
    block[263..265].copy_from_slice(b"00"); // version
                                            // checksum: 8 spaces, sum, then "NNNNNN\0 "
    for b in &mut block[148..156] {
        *b = b' ';
    }
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    let chk = format!("{sum:06o}\0 ");
    block[148..156].copy_from_slice(chk.as_bytes());

    let mut out = block;
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

fn make_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default();
    for (name, data) in entries {
        zip.start_file(*name, opts).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
}

fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.is_dir() {
        for entry in walk(root) {
            if entry.is_file() {
                out.push(entry.strip_prefix(root).unwrap().to_path_buf());
            }
        }
    }
    out.sort();
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

// ── magic detection ───────────────────────────────────────────────────

#[test]
fn detect_zip_local_file_header() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.zip");
    make_zip(&p, &[("x.txt", b"hi")]);
    assert_eq!(detect_kind(&p), Some(ArchiveKind::Zip));
}

#[test]
fn detect_7z_magic() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.7z");
    std::fs::write(&p, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0]).unwrap();
    assert_eq!(detect_kind(&p), Some(ArchiveKind::SevenZ));
}

#[test]
fn detect_gzip_as_targz() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.tar.gz");
    write_minimal_tar_gz(&p, &[("f.txt", b"data")]);
    assert_eq!(detect_kind(&p), Some(ArchiveKind::TarGz));
}

#[test]
fn detect_posix_tar_ustar_at_257() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("plain.tar");
    let file = std::fs::File::create(&p).unwrap();
    let mut builder = tar::Builder::new(file);
    let data = b"hello";
    let mut header = tar::Header::new_ustar();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "h.txt", &data[..])
        .unwrap();
    builder.into_inner().unwrap().sync_all().unwrap();
    assert_eq!(detect_kind(&p), Some(ArchiveKind::Tar));
}

#[test]
fn detect_unknown_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("random.bin");
    std::fs::write(&p, b"not an archive at all, just bytes").unwrap();
    assert_eq!(detect_kind(&p), None);
}

#[test]
fn detect_unreadable_returns_none() {
    assert_eq!(detect_kind(Path::new("/tmp/nope_archive_99999.zip")), None);
}

// ── provider probe ────────────────────────────────────────────────────

#[test]
fn provider_name_is_archive() {
    assert_eq!(ArchiveProvider.name(), "Archive");
}

#[test]
fn probe_zip_returns_medium() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.zip");
    make_zip(&p, &[("x.txt", b"hi")]);
    assert_eq!(ArchiveProvider.probe(&p).unwrap(), Confidence::Medium);
}

#[test]
fn probe_7z_returns_medium() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.7z");
    std::fs::write(&p, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0]).unwrap();
    assert_eq!(ArchiveProvider.probe(&p).unwrap(), Confidence::Medium);
}

#[test]
fn probe_targz_returns_medium() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.tar.gz");
    write_minimal_tar_gz(&p, &[("f.txt", b"data")]);
    assert_eq!(ArchiveProvider.probe(&p).unwrap(), Confidence::Medium);
}

#[test]
fn probe_unknown_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("random.bin");
    std::fs::write(&p, b"plain text content here").unwrap();
    assert_eq!(ArchiveProvider.probe(&p).unwrap(), Confidence::None);
}

#[test]
fn probe_nonexistent_returns_none() {
    assert_eq!(
        ArchiveProvider
            .probe(Path::new("/tmp/nope_99999.zip"))
            .unwrap(),
        Confidence::None
    );
}

/// Medium beats the raw-image Low and loses to UAC/Velociraptor High.
#[test]
fn probe_confidence_ordering() {
    assert!(Confidence::Medium > Confidence::Low);
    assert!(Confidence::Medium < Confidence::High);
}

/// A UAC-shaped tar.gz probes Medium here, but the SPECIFIC UAC provider claims
/// it High — so in the registry the UAC provider wins, never this generic one.
#[test]
fn probe_uac_shaped_targz_is_only_medium_here() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("uac-host.tar.gz");
    write_minimal_tar_gz(
        &p,
        &[
            ("uac.log", b"UAC run"),
            ("bodyfile/bodyfile.txt", b"0|/etc/passwd|..."),
        ],
    );
    // Generic provider: it's a gzip → Medium (not High). Ordering ensures the
    // UAC provider's High wins in open_collection.
    assert_eq!(ArchiveProvider.probe(&p).unwrap(), Confidence::Medium);
}

// ── provider open / round-trip ────────────────────────────────────────

#[test]
fn open_targz_round_trips_contents() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("generic.tar.gz");
    write_minimal_tar_gz(
        &p,
        &[
            ("notes/readme.txt", b"hello world"),
            ("data.bin", b"\x00\x01\x02"),
        ],
    );
    let manifest = ArchiveProvider.open(&p).unwrap();
    assert_eq!(manifest.format_name, "TarGz");
    let root = &manifest.extracted_root;
    assert_eq!(
        std::fs::read(root.join("notes/readme.txt")).unwrap(),
        b"hello world"
    );
    assert_eq!(
        std::fs::read(root.join("data.bin")).unwrap(),
        b"\x00\x01\x02"
    );
    // Generic archives let the fswalker detect — artifacts empty.
    assert!(manifest.artifacts.is_empty());
}

// ── 1. ZIP real data ──────────────────────────────────────────────────

#[test]
fn extract_real_dfirmadness_zip() {
    if !Path::new(DFIRMADNESS_ZIP).exists() {
        eprintln!("skip: {DFIRMADNESS_ZIP} absent");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let report = extract_zip(Path::new(DFIRMADNESS_ZIP), dir.path()).unwrap();
    assert_eq!(report.refused.len(), 0, "real zip has no traversal entries");
    assert!(report.written >= 1);
    let csv = dir.path().join("autorunsc-citadel-dc01.csv");
    assert!(csv.exists(), "expected the autorunsc csv under the root");
    let meta = std::fs::metadata(&csv).unwrap();
    assert_eq!(
        meta.len(),
        1_068_150,
        "uncompressed size must match the oracle"
    );
}

#[test]
fn open_real_dfirmadness_zip_via_provider() {
    if !Path::new(DFIRMADNESS_ZIP).exists() {
        eprintln!("skip: {DFIRMADNESS_ZIP} absent");
        return;
    }
    assert_eq!(
        detect_kind(Path::new(DFIRMADNESS_ZIP)),
        Some(ArchiveKind::Zip)
    );
    let manifest = ArchiveProvider.open(Path::new(DFIRMADNESS_ZIP)).unwrap();
    assert_eq!(manifest.format_name, "Zip");
    assert!(manifest
        .extracted_root
        .join("autorunsc-citadel-dc01.csv")
        .exists());
}

// ── 3. 7z independent oracle ──────────────────────────────────────────

#[test]
fn extract_7z_matches_system_oracle() {
    if !Path::new(SYSTEM_7Z).exists() {
        eprintln!("skip: system 7z absent at {SYSTEM_7Z}");
        return;
    }
    // Build a known fileset, compress with the system 7z (oracle), then compare
    // sevenz-rust's extraction byte-for-byte with the oracle's extraction.
    let work = tempfile::tempdir().unwrap();
    let src = work.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("alpha.txt"), b"alpha contents\n").unwrap();
    std::fs::write(src.join("sub/beta.bin"), [0u8, 1, 2, 3, 255, 128]).unwrap();
    std::fs::write(src.join("gamma.csv"), b"a,b,c\n1,2,3\n").unwrap();

    let archive = work.path().join("known.7z");
    let status = Command::new(SYSTEM_7Z)
        .arg("a")
        .arg("-bso0")
        .arg("-bsp0")
        .arg(&archive)
        .arg(".")
        .current_dir(&src)
        .status()
        .unwrap();
    assert!(status.success(), "system 7z compression failed");

    // sevenz-rust extraction (the code under test).
    let ours = work.path().join("ours");
    std::fs::create_dir_all(&ours).unwrap();
    let report = extract_7z(&archive, &ours).unwrap();
    assert_eq!(report.refused.len(), 0);

    // Oracle extraction.
    let oracle = work.path().join("oracle");
    std::fs::create_dir_all(&oracle).unwrap();
    let status = Command::new(SYSTEM_7Z)
        .arg("x")
        .arg("-bso0")
        .arg("-bsp0")
        .arg("-y")
        .arg(format!("-o{}", oracle.display()))
        .arg(&archive)
        .status()
        .unwrap();
    assert!(status.success(), "system 7z extraction failed");

    let ours_files = collect_files(&ours);
    let oracle_files = collect_files(&oracle);
    assert_eq!(ours_files, oracle_files, "extracted tree must match oracle");
    assert!(!ours_files.is_empty());
    for rel in &ours_files {
        let a = std::fs::read(ours.join(rel)).unwrap();
        let b = std::fs::read(oracle.join(rel)).unwrap();
        assert_eq!(a, b, "byte mismatch for {rel:?}");
    }
}

// ── 4. ZIP-SLIP (load-bearing security) ───────────────────────────────

#[test]
fn safe_join_rejects_parent_traversal() {
    let dest = Path::new("/tmp/extract-root");
    assert!(safe_join(dest, Path::new("../../../etc/passwd")).is_none());
    assert!(safe_join(dest, Path::new("a/../../b")).is_none());
}

#[test]
fn safe_join_rejects_absolute() {
    let dest = Path::new("/tmp/extract-root");
    assert!(safe_join(dest, Path::new("/etc/passwd")).is_none());
}

#[test]
fn safe_join_accepts_normal_relative() {
    let dest = Path::new("/tmp/extract-root");
    let joined = safe_join(dest, Path::new("a/b/c.txt")).unwrap();
    assert!(joined.starts_with(dest));
    assert!(joined.ends_with("a/b/c.txt"));
}

#[test]
fn zip_slip_does_not_escape_extraction_dir() {
    // Parent dir contains the extraction dir plus a sentinel sibling. A hostile
    // zip with `../../sentinel-escaped` and an absolute entry must NOT touch the
    // parent: the sentinel-escaped file must never appear outside the dest.
    let parent = tempfile::tempdir().unwrap();
    let dest = parent.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();

    let zip_path = parent.path().join("evil.zip");
    make_zip(
        &zip_path,
        &[
            ("../../sentinel-escaped.txt", b"PWNED"),
            ("/etc/abs-escaped.txt", b"PWNED-ABS"),
            ("safe/ok.txt", b"good"),
        ],
    );

    let before: Vec<PathBuf> = walk(parent.path());
    let report = extract_zip(&zip_path, &dest).unwrap();

    // Traversal entries refused and recorded (fail-loud, not silent).
    assert!(
        report
            .refused
            .iter()
            .any(|n| n.contains("sentinel-escaped")),
        "must record the refused traversal entry; got {:?}",
        report.refused
    );

    // The only NEW file under the parent must be inside dest.
    let after: Vec<PathBuf> = walk(parent.path());
    for p in &after {
        if !before.contains(p) {
            assert!(
                p.starts_with(&dest),
                "extraction escaped the dest dir: {p:?}"
            );
        }
    }
    // Sentinel never written anywhere outside dest.
    assert!(!parent.path().join("sentinel-escaped.txt").exists());
    assert!(!parent
        .path()
        .parent()
        .unwrap()
        .join("sentinel-escaped.txt")
        .exists());
    // The genuinely-safe entry was written.
    assert_eq!(std::fs::read(dest.join("safe/ok.txt")).unwrap(), b"good");
}

#[test]
fn tar_slip_does_not_escape_extraction_dir() {
    let parent = tempfile::tempdir().unwrap();
    let dest = parent.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();

    // Hand-craft a tar.gz with a `..` traversal entry plus a safe entry.
    // The tar crate's append_data() refuses a `..` path, so for the hostile
    // entry we emit the raw 512-byte ustar header ourselves (writing the name
    // field directly) — exactly how a malicious archive is built in the wild.
    let archive = parent.path().join("evil.tar.gz");
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());

        // Hostile entry, raw.
        enc.write_all(&raw_tar_entry("../../tar-escaped.txt", b"PWNED"))
            .unwrap();

        // Safe entry via the normal builder path, into the same gzip stream.
        let mut builder = tar::Builder::new(&mut enc);
        let data = &b"good"[..];
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "safe/inside.txt", data)
            .unwrap();
        builder.into_inner().unwrap();

        enc.finish().unwrap();
    }

    let before: Vec<PathBuf> = walk(parent.path());
    let report = extract_tar_gz(&archive, &dest).unwrap();
    assert!(
        report.refused.iter().any(|n| n.contains("tar-escaped")),
        "must record the refused tar traversal entry; got {:?}",
        report.refused
    );
    let after: Vec<PathBuf> = walk(parent.path());
    for p in &after {
        if !before.contains(p) {
            assert!(p.starts_with(&dest), "tar extraction escaped dest: {p:?}");
        }
    }
    assert!(!parent.path().join("tar-escaped.txt").exists());
    assert_eq!(
        std::fs::read(dest.join("safe/inside.txt")).unwrap(),
        b"good"
    );
}

// ── 5. Decompression bomb ─────────────────────────────────────────────

#[test]
fn zip_bomb_errors_with_bound_no_oom() {
    // A tiny zip whose single entry expands far past a small cap. We extract
    // with the production cap but the entry (highly-compressible zeros) exceeds
    // it; extraction must error with a bound, never OOM.
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("bomb.zip");
    // 64 MiB of zeros compresses to a few KiB; with the real 4 GiB cap that's
    // fine, so to keep the test fast+deterministic we assert the *mechanism*:
    // the cap constant is enforced via extract_zip_capped.
    let huge = vec![0u8; 64 * 1024 * 1024];
    make_zip(&zip_path, &[("zeros.bin", &huge)]);

    let dest = dir.path().join("out");
    std::fs::create_dir_all(&dest).unwrap();
    // Use a deliberately tiny cap (1 MiB) to trigger the bound without minting a
    // multi-GiB archive.
    let err = super::extract::extract_zip_capped(&zip_path, &dest, 1024 * 1024)
        .expect_err("must error on exceeding the cap");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("uncompressed")
            || msg.to_lowercase().contains("cap")
            || msg.to_lowercase().contains("bound")
            || msg.to_lowercase().contains("limit"),
        "error must name the size bound; got: {msg}"
    );
}

#[test]
fn default_cap_is_sane() {
    const { assert!(MAX_TOTAL_UNCOMPRESSED >= 1024 * 1024 * 1024) };
}

// ── inventory registration ────────────────────────────────────────────

#[test]
fn archive_provider_registered_in_inventory() {
    use issen_unpack::registry::ProviderRegistration;
    let names: Vec<String> = inventory::iter::<ProviderRegistration>
        .into_iter()
        .map(|r| (r.create)().name().to_string())
        .collect();
    assert!(
        names.contains(&"Archive".to_string()),
        "ArchiveProvider must be registered; got: {names:?}"
    );
}

// ── bomb cap: ratio-based, disk-image-friendly ───────────────────────────

#[test]
fn cap_is_floor_for_small_archives() {
    // 100× a 1 MiB archive is 100 MiB, below the 4 GiB floor → floor governs, so
    // small triage collections are never falsely flagged.
    assert_eq!(cap_for_archive_size(1024 * 1024), MAX_TOTAL_UNCOMPRESSED);
    assert_eq!(cap_for_archive_size(0), MAX_TOTAL_UNCOMPRESSED);
}

#[test]
fn cap_scales_by_ratio_for_large_archives() {
    // The real case: DC01-E01.zip is ~4.5 GB compressed and ~4.87 GB uncompressed
    // (a split E01, ratio ~1.1×). The ratio term must lift the cap above that so
    // the disk image extracts, while a bomb's far higher ratio still trips.
    let compressed = 4_500_000_000u64;
    assert_eq!(
        cap_for_archive_size(compressed),
        compressed * MAX_EXPANSION_RATIO
    );
    assert!(
        cap_for_archive_size(compressed) > 4_870_000_000,
        "cap must clear the ~4.87 GB uncompressed disk image"
    );
}

#[test]
fn cap_saturates_without_overflow() {
    // A pathologically huge compressed size must not overflow u64.
    assert_eq!(cap_for_archive_size(u64::MAX), u64::MAX);
}
