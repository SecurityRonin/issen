//! The clone in `forensic-pivot::rule` derived only `PartialEq`, so pivot rules
//! could not be ranked or thresholded at all. The canonical
//! `forensicnomicon::report::Severity` derives `Ord`; adopting it is what makes
//! these comparisons compile.

use forensic_pivot::Severity;

#[test]
fn severity_is_totally_ordered() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn findings_can_be_ranked_by_severity() {
    let mut tiers = [
        Severity::Low,
        Severity::Critical,
        Severity::Info,
        Severity::High,
        Severity::Medium,
    ];
    tiers.sort_unstable();
    assert_eq!(
        tiers,
        [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical
        ]
    );
}
