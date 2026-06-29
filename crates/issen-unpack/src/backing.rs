//! Centralized bounded backing for a disk-image container that may live loose on
//! disk OR inside an archive (zip / 7z / tar.gz / tar.bz2 / dar).
//!
//! The RAM-vs-temp spill decision for a *compressed* image entry is governed by
//! an adaptive budget (this module's pure core, [`ram_threshold`]) plus a
//! streaming spooled buffer that rolls over on the *actual* decompressed bytes
//! (bomb-safe, independent of the entry's declared size). A `zip` `Stored` entry
//! never reaches the spill path — it is read in place (zero copy).

/// One mebibyte, in bytes.
const MIB: u64 = 1024 * 1024;
/// One gibibyte, in bytes.
const GIB: u64 = 1024 * 1024 * 1024;

/// Floor on the per-image RAM-residency threshold: below this, spilling a tiny
/// entry costs more in filesystem overhead than the RAM it would save.
const THRESHOLD_FLOOR: u64 = 64 * MIB;
/// Ceiling: above the parser's typical working set, holding more of an image
/// resident buys nothing (a multi-GB image is read in scattered fragments), so
/// spill instead of committing more RAM.
const THRESHOLD_CEILING: u64 = GIB;
/// Denominator of the fraction of *available* RAM we commit to resident images;
/// the remaining 3/4 is left for issen's own growth (DuckDB / correlate) + OS.
const RAM_COMMIT_DENOMINATOR: u64 = 4;

/// Resource snapshot gathered once per ingest, used to size the per-image
/// RAM-residency threshold. All byte counts are bytes. The platform probing that
/// fills this in is a thin shell ([`probe_spill_plan`]); this struct keeps the
/// budget math pure and testable.
#[derive(Debug, Clone, Copy)]
pub struct SpillPlan {
    /// Currently available (free + reclaimable) RAM, in bytes.
    pub available_ram: u64,
    /// Planned concurrent decompressions (sources × worker cap). Treated as 1 if
    /// zero.
    pub concurrency: usize,
    /// Explicit operator override (`ISSEN_ARCHIVE_SPILL_THRESHOLD`), in bytes;
    /// when set it wins outright, unclamped, for deterministic environments.
    pub env_override: Option<u64>,
}

/// Per-image RAM-residency threshold in bytes: a decompressed image strictly
/// smaller than this stays in a RAM buffer; at or above it, it spills to a
/// disk-backed temp file.
///
/// The budget is `1/4 of available RAM`, split across the planned concurrency,
/// clamped to `[64 MiB, 1 GiB]`. An `env_override` bypasses the formula entirely.
#[must_use]
pub fn ram_threshold(plan: &SpillPlan) -> u64 {
    // An explicit operator override wins outright (deterministic environments).
    if let Some(n) = plan.env_override {
        return n;
    }
    let concurrency = plan.concurrency.max(1) as u64;
    // 1/4 of available RAM, split across the planned concurrent decompressions.
    // Divide before multiplying is unnecessary here (denominator only), and the
    // budget can't overflow u64 for any real RAM size.
    let budget = plan.available_ram / RAM_COMMIT_DENOMINATOR;
    let per_image = budget / concurrency;
    per_image.clamp(THRESHOLD_FLOOR, THRESHOLD_CEILING)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(available_ram: u64, concurrency: usize) -> SpillPlan {
        SpillPlan {
            available_ram,
            concurrency,
            env_override: None,
        }
    }

    #[test]
    fn env_override_wins_unclamped() {
        // Override is an explicit operator choice — honored literally, even
        // outside the [floor, ceiling] band, regardless of RAM/concurrency.
        let p = SpillPlan {
            available_ram: 64 * GIB,
            concurrency: 100,
            env_override: Some(5 * GIB),
        };
        assert_eq!(ram_threshold(&p), 5 * GIB);
        let p2 = SpillPlan {
            available_ram: 1 * GIB,
            concurrency: 1,
            env_override: Some(16 * MIB),
        };
        assert_eq!(ram_threshold(&p2), 16 * MIB);
    }

    #[test]
    fn shrinks_as_concurrency_grows() {
        // 8 GiB available: /4 = 2 GiB budget; ÷concurrency lands in-band.
        let four = ram_threshold(&plan(8 * GIB, 4)); // 512 MiB
        let eight = ram_threshold(&plan(8 * GIB, 8)); // 256 MiB
        assert_eq!(four, 512 * MIB);
        assert_eq!(eight, 256 * MIB);
        assert!(eight < four, "more sources → smaller per-image budget");
    }

    #[test]
    fn grows_with_available_ram() {
        let lo = ram_threshold(&plan(2 * GIB, 2)); // 0.25*2G/2 = 256 MiB
        let hi = ram_threshold(&plan(8 * GIB, 2)); // 0.25*8G/2 = 1 GiB (ceiling)
        assert_eq!(lo, 256 * MIB);
        assert_eq!(hi, GIB);
        assert!(hi > lo, "more available RAM → larger per-image budget");
    }

    #[test]
    fn clamps_to_floor_on_scarce_ram() {
        // 1 GiB available, 4 sources: 0.25*1G/4 = 64 MiB exactly; 512 MiB box
        // would compute 32 MiB → clamped up to the 64 MiB floor.
        assert_eq!(ram_threshold(&plan(1 * GIB, 4)), 64 * MIB);
        assert_eq!(ram_threshold(&plan(512 * MIB, 4)), 64 * MIB);
    }

    #[test]
    fn clamps_to_ceiling_on_abundant_ram() {
        // 64 GiB available, single source: 16 GiB budget → capped at 1 GiB.
        assert_eq!(ram_threshold(&plan(64 * GIB, 1)), GIB);
    }

    #[test]
    fn zero_concurrency_treated_as_one() {
        assert_eq!(
            ram_threshold(&plan(8 * GIB, 0)),
            ram_threshold(&plan(8 * GIB, 1))
        );
    }
}
