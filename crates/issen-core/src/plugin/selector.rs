//! `ArtifactSelector` — a parser's single declaration of what it consumes.
//!
//! Each parser attaches one of these to its
//! [`ParserRegistration`](crate::plugin::registry::ParserRegistration). The
//! pipeline derives both classification (which parser reads a file) and disk
//! collection (which files to pull off an image) from this one registry, so the
//! two can no longer drift apart by hand. Stage 1 only *declares* selectors —
//! nothing reads them yet.

use std::path::Path;

use crate::artifacts::ArtifactType;

/// Everything a parser declares about the artifact it consumes.
pub struct ArtifactSelector {
    /// The type this parser produces — the routing label.
    pub artifact_type: ArtifactType,

    /// Medium-agnostic match: does a file at this path belong to this artifact?
    /// Drives the loose-file walker AND classification, on any OS/filesystem.
    /// See [`crate::classify`] for the shared predicates.
    pub matches: fn(&Path) -> bool,

    /// Precedence when more than one selector matches a path; higher wins.
    /// Mirrors the old classifier's if-ladder order (earlier arm ⇒ higher).
    pub priority: u8,

    /// How to pull this artifact off a RAW disk image, keyed by filesystem.
    /// Empty ⇒ collected only via loose-file/UAC/KAPE ingest (no image
    /// extractor for its filesystem yet) — honest, not silently dark.
    pub disk_sources: &'static [DiskSource],

    /// Whether default triage collects it, or it is opt-in (e.g. PE carving).
    pub cost: CostTier,
}

/// Whether an artifact is collected by default triage or only on explicit opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostTier {
    /// Collected by default disk triage.
    Default,
    /// Excluded from default triage; collected only when explicitly requested
    /// (e.g. PE carving, which is too expensive to run over every binary).
    OptIn,
}

/// How to locate an artifact on a raw disk image, keyed by filesystem.
///
/// Only `Ntfs` exists today; `Ext4`/`Apfs` variants are added when those image
/// extractors exist. A Linux/macOS parser therefore declares empty
/// `disk_sources` for now — loose-file-only until its extractor lands.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum DiskSource {
    /// A location on an NTFS volume.
    Ntfs(NtfsLoc),
}

/// An NTFS collection shape — one variant per `issen_disk::extract_*` primitive,
/// so the derived extractor (Stage 3) is a thin dispatch over trusted code.
#[derive(Debug, Clone, Copy)]
pub enum NtfsLoc {
    /// A fixed path, e.g. `\$MFT` or `\Windows\System32\config\SYSTEM`.
    FixedPath(&'static str),
    /// Every file in `dir` ending with `suffix`, e.g. (`\Windows\Prefetch`, `.pf`).
    DirSuffix {
        /// Directory to sweep.
        dir: &'static str,
        /// Case-insensitive filename suffix.
        suffix: &'static str,
    },
    /// A fixed file under each `\Users\<user>\`, e.g. `NTUSER.DAT`.
    PerUserFile(&'static str),
    /// Under each subdirectory of `parent`, sweep `rel` for files matching `name`.
    /// Covers per-user `Recent\*.lnk` and per-SID `$Recycle.Bin\<SID>\$I*`.
    PerSubdirSweep {
        /// Directory whose subdirectories are iterated.
        parent: &'static str,
        /// Relative directory under each subdirectory (`""` = the subdir itself).
        rel: &'static str,
        /// Filename rule applied within the swept directory.
        name: NameMatch,
    },
    /// A named ADS stream, e.g. (`\$Extend\$UsnJrnl`, `$J`).
    NamedStream {
        /// File path carrying the stream.
        path: &'static str,
        /// Stream name.
        stream: &'static str,
    },
}

/// Filename rule for a [`NtfsLoc::PerSubdirSweep`].
#[derive(Debug, Clone, Copy)]
pub enum NameMatch {
    /// Case-insensitive suffix, e.g. `.lnk`.
    Suffix(&'static str),
    /// Case-insensitive prefix, e.g. `$i`.
    Prefix(&'static str),
}

impl NameMatch {
    /// Does `name` (any case) satisfy this rule?
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        let lc = name.to_ascii_lowercase();
        match self {
            Self::Suffix(s) => lc.ends_with(&s.to_ascii_lowercase()),
            Self::Prefix(p) => lc.starts_with(&p.to_ascii_lowercase()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_match_suffix_and_prefix_are_case_insensitive() {
        assert!(NameMatch::Suffix(".lnk").matches("Recent.LNK"));
        assert!(!NameMatch::Suffix(".lnk").matches("file.txt"));
        assert!(NameMatch::Prefix("$i").matches("$IABC.txt"));
        assert!(!NameMatch::Prefix("$i").matches("$RABC.txt"));
    }

    #[test]
    fn selector_is_constructible_and_matches_runs() {
        let sel = ArtifactSelector {
            artifact_type: ArtifactType::Lnk,
            matches: crate::classify::lnk,
            priority: 80,
            disk_sources: &[DiskSource::Ntfs(NtfsLoc::PerSubdirSweep {
                parent: r"\Users",
                rel: "Desktop",
                name: NameMatch::Suffix(".lnk"),
            })],
            cost: CostTier::Default,
        };
        assert_eq!(sel.artifact_type, ArtifactType::Lnk);
        assert!((sel.matches)(Path::new("/x/a.lnk")));
        assert_eq!(sel.cost, CostTier::Default);
        assert_eq!(sel.disk_sources.len(), 1);
    }
}
