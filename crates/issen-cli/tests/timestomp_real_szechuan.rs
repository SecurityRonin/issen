//! Real-data validation (Doer-Checker): the `$SI`/`$FN` timestomp detector must
//! flag the genuine back-dated file on the DFIRMadness "Szechuan Sauce" domain
//! controller, not just synthetic fixtures.
//!
//! Ground truth — DFIRMadness "Szechuan Sauce", host CITADEL-DC01 (`CDrive`):
//! the attacker (Meterpreter) timestomped `\FileShare\Secret\Beth_Secret.txt`
//! ($MFT entry 87111), back-dating its `$STANDARD_INFORMATION` birth time to a
//! WHOLE second (`2020-09-19 07:33:54.000000000 HKT`) so it would sit beside the
//! other staged secrets, while the kernel-set `$FILE_NAME` birth time still
//! carries true 100 ns precision (`2020-09-19 11:34:56.970445200 HKT`). The
//! back-date is only ~4 h — well inside a one-day clock-skew tolerance — but the
//! zeroed `$SI` sub-second against the non-zeroed `$FN` is the classic naive-stomp
//! tell. This is the DC analogue of the writeup's `n_Secret.txt` story.
//!
//! Independent oracle: TSK `istat` shows both attribute sets and the
//! whole-second `$SI` vs sub-second `$FN` split; we reuse TSK `icat` to pull the
//! raw `$MFT`, then drive it through the *issen* parser + detector — so the
//! detector (not issen's own `$MFT` self-extraction) is what is under test.
//!
//! The image is large and gitignored; the test resolves it from an env var or
//! the in-repo corpus path, requires `icat`/`mmls` on PATH, and skips cleanly
//! (skip-loud) when either is absent — like `extract_user_artifacts.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::{DataSource, EventEmitter, ForensicParser};
use issen_core::timeline::event::{EventType, TimelineEvent};
use issen_correlation::timestomp::{detect_timestomp, TIMESTOMP_CODE};
use issen_parser_mft::MftFileParser;

const DC_DEFAULT: &str =
    "../../tests/data/dfirmadness-szechuan-sauce/extracted/E01-DC01/20200918_0347_CDrive.E01";

/// One day in nanoseconds — the clock-skew tolerance the CLI scan path uses.
const ONE_DAY_NS: i64 = 86_400_000_000_000;

fn dc_image() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ISSEN_SZECHUAN_DC") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DC_DEFAULT);
    p.exists().then_some(p)
}

/// `true` when a named binary resolves on PATH.
fn have(bin: &str) -> bool {
    Command::new(bin)
        .arg("-V")
        .output()
        .map(|_| true)
        .unwrap_or(false)
}

/// Byte offset (in 512-byte sectors) of the largest NTFS partition, via `mmls`.
fn ntfs_lba(img: &std::path::Path) -> Option<u64> {
    let out = Command::new("mmls").arg(img).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut best: Option<(u64, u64)> = None; // (start, length)
    for line in text.lines() {
        if !line.to_lowercase().contains("ntfs") {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        // mmls columns: slot start end length description...
        if cols.len() < 4 {
            continue;
        }
        let start = cols[2].parse::<u64>().ok();
        let length = cols[4].parse::<u64>().ok();
        if let (Some(start), Some(length)) = (start, length) {
            if best.map_or(true, |(_, bl)| length > bl) {
                best = Some((start, length));
            }
        }
    }
    best.map(|(start, _)| start)
}

/// Pull the raw `$MFT` (inode 0) from the NTFS partition at `lba` via TSK `icat`.
fn icat_mft(img: &std::path::Path, lba: u64) -> Option<Vec<u8>> {
    let out = Command::new("icat")
        .args(["-o", &lba.to_string()])
        .arg(img)
        .arg("0")
        .output()
        .ok()?;
    (out.status.success() && out.stdout.len() > 1024).then_some(out.stdout)
}

struct Collect(Mutex<Vec<TimelineEvent>>);
impl EventEmitter for Collect {
    fn emit(&self, e: TimelineEvent) -> Result<(), RtError> {
        self.0.lock().unwrap().push(e);
        Ok(())
    }
    fn emit_batch(&self, e: Vec<TimelineEvent>) -> Result<(), RtError> {
        self.0.lock().unwrap().extend(e);
        Ok(())
    }
}

struct Bytes(Vec<u8>);
impl DataSource for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let off = off as usize;
        if off >= self.0.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        Ok(n)
    }
}

#[test]
fn detector_flags_beth_secret_timestomp_on_real_dc_mft() {
    let Some(img) = dc_image() else {
        eprintln!("skipping: DC image absent (set ISSEN_SZECHUAN_DC)");
        return;
    };
    if !have("icat") || !have("mmls") {
        eprintln!("skipping: TSK icat/mmls not on PATH");
        return;
    }
    let Some(lba) = ntfs_lba(&img) else {
        eprintln!("skipping: no NTFS partition found via mmls");
        return;
    };
    let Some(mft) = icat_mft(&img, lba) else {
        eprintln!("skipping: icat could not extract $MFT");
        return;
    };

    // Parse the real $MFT through the issen MFT parser → timeline events.
    let emitter = Collect(Mutex::new(Vec::new()));
    MftFileParser
        .parse(&Bytes(mft), &emitter)
        .expect("parse real $MFT");
    let events = emitter.0.into_inner().unwrap();
    assert!(
        events.len() > 1000,
        "real DC $MFT must yield a full timeline (got {} events) — \
         a truncated extract would silently hide the stomped record",
        events.len()
    );

    // The stomped record: \FileShare\Secret\Beth_Secret.txt FileCreate event.
    let beth = events
        .iter()
        .find(|e| {
            e.event_type == EventType::FileCreate
                && e.artifact_path.to_lowercase().ends_with("beth_secret.txt")
        })
        .expect("Beth_Secret.txt FileCreate event must be present in the real MFT");

    let finding = detect_timestomp(beth, ONE_DAY_NS).expect(
        "detector must flag Beth_Secret.txt: $SI.created is a whole second ~4 h \
         BEFORE the non-zeroed $FN.created — the naive-stomp tell, below tolerance",
    );
    assert_eq!(finding.code, TIMESTOMP_CODE);
    // Info-grade LEAD — single-event $SI/$FN tier is FP-prone; never graded High here.
    assert_eq!(
        finding.severity,
        Some(forensicnomicon::report::Severity::Info),
        "single-event $SI<$FN timestomp is an Info lead, not a verdict"
    );
    assert!(
        finding
            .context
            .external_refs
            .iter()
            .any(|r| r.id.contains("T1070.006")),
        "lead must carry MITRE T1070.006 (consistent-with, never a verdict)"
    );

    // True negative on the same image: PortalGunPlans.txt is NOT stomped
    // ($SI == $FN, both with sub-second precision) — the detector must stay silent.
    if let Some(portal) = events.iter().find(|e| {
        e.event_type == EventType::FileCreate
            && e.artifact_path
                .to_lowercase()
                .ends_with("portalgunplans.txt")
    }) {
        assert!(
            detect_timestomp(portal, ONE_DAY_NS).is_none(),
            "PortalGunPlans.txt ($SI == $FN) must not be flagged — would be a false positive"
        );
    }
}
