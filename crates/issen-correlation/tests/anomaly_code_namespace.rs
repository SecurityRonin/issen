//! issen must not mint finding codes inside another crate's `code` namespace.
//!
//! `ntfs-forensic` owns the `NTFS-` scheme and already publishes
//! `NTFS-TIMESTOMP`, `NTFS-ADS`, `NTFS-DELETED-RECORD`, `NTFS-SLACK-RESIDUE`,
//! `NTFS-MFTMIRR-MISMATCH` and `NTFS-LOGFILE-CLEARED` (see its `AnomalyKind` /
//! `ArtifactAnomaly` `code()` methods). issen *consumes* those codes, which
//! makes it exactly the crate that must not also mint into the namespace.
//!
//! The sharp case is `NTFS-TIMESTOMP-SI-FN-MISMATCH`: it is a strict string
//! prefix-extension of ntfs-forensic's shipped `NTFS-TIMESTOMP`, so any
//! consumer grouping by code prefix conflates a correlation-layer Info lead
//! with a filesystem-layer High anomaly. The two detections are related but
//! genuinely different (different inputs, signal sets, and confidence models),
//! so they stay distinct codes — the issen one moves to a prefix issen owns.

use issen_correlation::timestomp::TIMESTOMP_CODE;

#[test]
fn timestomp_code_is_not_in_the_ntfs_forensic_namespace() {
    assert!(
        !TIMESTOMP_CODE.starts_with("NTFS-"),
        "`NTFS-` is ntfs-forensic's scheme; issen must mint under a prefix it \
         owns (got `{TIMESTOMP_CODE}`)"
    );
}

#[test]
fn timestomp_code_does_not_shadow_ntfs_forensics_shipped_code() {
    // ntfs-forensic/forensic/src/lib.rs: `AnomalyKind::Timestomp { .. } => "NTFS-TIMESTOMP"`.
    const NTFS_FORENSIC_TIMESTOMP: &str = "NTFS-TIMESTOMP";
    assert_ne!(TIMESTOMP_CODE, NTFS_FORENSIC_TIMESTOMP);
    assert!(
        !TIMESTOMP_CODE.starts_with(NTFS_FORENSIC_TIMESTOMP),
        "a prefix-extension of a shipped code makes one detection look like two \
         under prefix grouping (got `{TIMESTOMP_CODE}`)"
    );
}

#[test]
fn timestomp_code_is_minted_under_an_issen_owned_prefix() {
    // issen owns `CORR-` (cross-event correlations) and `HEUR-` (its own rule
    // layer — timestomping, location, entropy, size, magic, USN). This detector
    // is a single-event heuristic lead, so `HEUR-`.
    assert!(
        TIMESTOMP_CODE.starts_with("HEUR-") || TIMESTOMP_CODE.starts_with("CORR-"),
        "expected an issen-owned prefix, got `{TIMESTOMP_CODE}`"
    );
    assert!(
        TIMESTOMP_CODE.contains("TIMESTOMP"),
        "the code must still name the phenomenon (got `{TIMESTOMP_CODE}`)"
    );
}
