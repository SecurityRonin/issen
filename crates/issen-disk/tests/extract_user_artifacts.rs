//! Real-data validation: the per-user `.lnk` and per-SID `$Recycle.Bin\$I`
//! sweeps must actually pull those artifacts off a genuine Windows image.
//!
//! Ground truth: the DFIRMadness "Szechuan Sauce" workstation image
//! (`DESKTOP-SDN1RPT`) contains Recent/Desktop shortcuts and a recycle bin
//! holding Beth's deleted `SECRET_beth.txt` — documented case evidence. These
//! artifacts were *dark* (0 parsed events) because `extract_triage` never
//! collected the files; this test fails until the sweep does.
//!
//! The image is large and gitignored; the test resolves it from
//! `ISSEN_SZECHUAN_WS` or the in-repo corpus path and skips cleanly when absent
//! (CI), exactly like `parity_read.rs`.

use std::path::PathBuf;

use issen_disk::{extract_subdir_sweep, find_ntfs_partitions};
use issen_ewf::EwfDataSource;

fn ws_image() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ISSEN_SZECHUAN_WS") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../tests/data/dfirmadness-szechuan-sauce/extracted/20200918_0417_DESKTOP-SDN1RPT.E01",
    );
    p.exists().then_some(p)
}

#[test]
fn real_ws_image_yields_recent_lnks_and_recycle_bin_i_files() {
    let Some(image) = ws_image() else {
        eprintln!("skipping: Szechuan WS image not present (set ISSEN_SZECHUAN_WS)");
        return;
    };
    let source = EwfDataSource::open(&image).expect("open WS E01");
    let windows = find_ntfs_partitions(&source).expect("find NTFS partitions");
    assert!(!windows.is_empty(), "no NTFS partition on WS image");

    let is_lnk = |n: &str| n.to_ascii_lowercase().ends_with(".lnk");
    let is_i = |n: &str| {
        let lc = n.to_ascii_lowercase();
        lc.starts_with("$i")
    };

    let mut lnks = Vec::new();
    let mut recycle = Vec::new();
    for window in windows {
        lnks.extend(
            extract_subdir_sweep(
                &source,
                window,
                r"\Users",
                r"AppData\Roaming\Microsoft\Windows\Recent",
                &is_lnk,
            )
            .expect("sweep Recent .lnk"),
        );
        recycle.extend(
            extract_subdir_sweep(&source, window, r"\$Recycle.Bin", "", &is_i)
                .expect("sweep $Recycle.Bin $I"),
        );
    }

    assert!(
        !lnks.is_empty(),
        "real WS image must yield Recent .lnk shortcuts (got 0)"
    );
    assert!(
        lnks.iter()
            .all(|f| f.path.to_ascii_lowercase().ends_with(".lnk")),
        "every swept file must be a .lnk"
    );
    assert!(
        !recycle.is_empty(),
        "real WS image must yield $Recycle.Bin $I metadata files (got 0)"
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
}
