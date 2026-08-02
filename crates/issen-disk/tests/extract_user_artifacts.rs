//! Real-data validation: the per-user `.lnk` and per-SID `$Recycle.Bin\$I`
//! sweeps must actually pull those artifacts off genuine Windows images.
//!
//! Ground truth — the DFIRMadness "Szechuan Sauce" case:
//! * the workstation `DESKTOP-SDN1RPT` carries live Recent/Desktop shortcuts;
//! * the domain controller `CDrive` recycle bin holds the Administrator's
//!   deleted `$IU2L112.txt`, whose original path is
//!   `\FileShare\Secret\SECRET_beth.txt` — Beth's stolen recipe.
//!
//! These artifacts were *dark* (0 parsed events) because `extract_triage` never
//! collected the files. The two images decompose the validation honestly: the
//! WS recycle bins were emptied (so deleted-file evidence there is carve-only),
//! while the DC bin still holds the deletion record live.
//!
//! The images are large and gitignored; each test resolves its image from an
//! env var or the in-repo corpus path and skips cleanly when absent (CI), like
//! `parity_read.rs`.

// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::path::PathBuf;

use issen_disk::{extract_subdir_sweep, find_ntfs_partitions};
use issen_ewf::EwfDataSource;

const WS_DEFAULT: &str =
    "../../tests/data/dfirmadness-szechuan-sauce/extracted/20200918_0417_DESKTOP-SDN1RPT.E01";
const DC_DEFAULT: &str =
    "../../tests/data/dfirmadness-szechuan-sauce/extracted/E01-DC01/20200918_0347_CDrive.E01";

fn image(env_key: &str, default_rel: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env_key) {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(default_rel);
    p.exists().then_some(p)
}

#[test]
fn recent_desktop_lnk_sweep_recovers_live_shortcuts() {
    let Some(img) = image("ISSEN_SZECHUAN_WS", WS_DEFAULT) else {
        eprintln!("skipping: WS image absent (set ISSEN_SZECHUAN_WS)");
        return;
    };
    let source = EwfDataSource::open(&img).expect("open WS E01");

    let mut lnks = Vec::new();
    for window in find_ntfs_partitions(&source).expect("find NTFS partitions") {
        for rel in [r"AppData\Roaming\Microsoft\Windows\Recent", "Desktop"] {
            lnks.extend(
                extract_subdir_sweep(&source, window, r"\Users", rel, &|n| {
                    n.to_ascii_lowercase().ends_with(".lnk")
                })
                .expect("sweep .lnk"),
            );
        }
    }

    assert!(
        !lnks.is_empty(),
        "WS image must yield live Recent/Desktop .lnk shortcuts (got 0)"
    );
    assert!(
        lnks.iter()
            .all(|f| f.path.to_ascii_lowercase().ends_with(".lnk")),
        "every swept file must be a .lnk"
    );
}

#[test]
fn recycle_bin_sweep_recovers_beths_deleted_secret() {
    let Some(img) = image("ISSEN_SZECHUAN_DC", DC_DEFAULT) else {
        eprintln!("skipping: DC image absent (set ISSEN_SZECHUAN_DC)");
        return;
    };
    let source = EwfDataSource::open(&img).expect("open DC E01");

    let mut recycle = Vec::new();
    for window in find_ntfs_partitions(&source).expect("find NTFS partitions") {
        recycle.extend(
            extract_subdir_sweep(&source, window, r"\$Recycle.Bin", "", &|n| {
                n.to_ascii_lowercase().starts_with("$i")
            })
            .expect("sweep $I"),
        );
    }

    assert!(
        !recycle.is_empty(),
        "DC recycle bin must yield $I deletion records (got 0)"
    );
    assert!(
        recycle.iter().all(|f| {
            f.path
                .rsplit('\\')
                .next()
                .is_some_and(|n| n.to_ascii_lowercase().starts_with("$i"))
        }),
        "every swept recycle file must be a $I record"
    );
    // Ground truth: exactly one recovered $I record is Beth's deleted secret.
    // The original path is stored as UTF-16LE in the $I tail; assert its bytes
    // are present without re-implementing the parser (that runs end-to-end).
    // "Exactly one" guards against the NTFS 8.3 short-name alias of the SID
    // directory (`S-1-5-…-500` and `S-1-5-~1` are the same dir) double-counting
    // the deletion.
    let needle: Vec<u8> = "SECRET_beth.txt"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let beth_hits = recycle
        .iter()
        .filter(|f| f.data.windows(needle.len()).any(|w| w == needle))
        .count();
    assert_eq!(
        beth_hits, 1,
        "Beth's deleted \\FileShare\\Secret\\SECRET_beth.txt $I must be recovered exactly once \
         (no DOS 8.3 short-name duplicate)"
    );
}

/// 2.4 oracle reconciliation: the `$I` records issen extracts from the DC
/// recycle bin must match the independent Sleuth Kit `fls` enumeration of the
/// same `$Recycle.Bin` subtree (an independent tool, not records we deleted
/// ourselves). Skips loud when the E01 or `fls` is absent.
#[test]
fn recycle_bin_extraction_reconciles_with_tsk_fls() {
    // The DC's main Windows volume starts at LBA 718848 (mmls slot 003).
    const PART_LBA: &str = "718848";

    let Some(img) = image("ISSEN_SZECHUAN_DC", DC_DEFAULT) else {
        eprintln!("skipping: DC image absent (set ISSEN_SZECHUAN_DC)");
        return;
    };

    // Oracle: `fls -o <lba> -r -p <image>` over the $Recycle.Bin subtree, the
    // set of `$I*` allocated file records (their base names).
    let fls = std::process::Command::new("fls")
        .args(["-o", PART_LBA, "-r", "-p"])
        .arg(&img)
        .output();
    let out = match fls {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            eprintln!(
                "skipping: fls exited {:?}: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            );
            return;
        }
        Err(e) => {
            eprintln!("skipping: TSK `fls` not available ({e})");
            return;
        }
    };
    let listing = String::from_utf8_lossy(&out.stdout);
    let mut oracle: Vec<String> = listing
        .lines()
        .filter(|l| l.to_ascii_lowercase().contains("recycle.bin"))
        .filter_map(|l| l.rsplit('/').next())
        .map(|n| n.split(':').next().unwrap_or(n).trim().to_string())
        .filter(|n| n.to_ascii_lowercase().starts_with("$i"))
        .collect();
    oracle.sort();
    oracle.dedup();

    // issen's own extraction of the same $I records.
    let source = EwfDataSource::open(&img).expect("open DC E01");
    let mut ours: Vec<String> = Vec::new();
    for window in find_ntfs_partitions(&source).expect("find NTFS partitions") {
        for f in extract_subdir_sweep(&source, window, r"\$Recycle.Bin", "", &|n| {
            n.to_ascii_lowercase().starts_with("$i")
        })
        .expect("sweep $I")
        {
            if let Some(name) = f.path.rsplit('\\').next() {
                ours.push(name.to_string());
            }
        }
    }
    ours.sort();
    ours.dedup();

    assert!(
        !oracle.is_empty(),
        "fls must enumerate at least one $I record in the recycle bin"
    );
    assert_eq!(
        ours, oracle,
        "issen's extracted $I record set must match the TSK fls oracle\n  issen: {ours:?}\n  fls:   {oracle:?}"
    );
}
