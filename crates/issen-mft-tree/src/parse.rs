//! MFT binary parsing into `FileTree`.

use std::path::Path;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use mft::attribute::header::ResidentialHeader;
use mft::attribute::{MftAttributeContent, MftAttributeType};
use mft::MftParser;
use ntfs_core::MftData;

use crate::node::{FileNode, NtfsTimestamps};
use crate::tree::FileTree;

/// Convert a Unix-nanosecond count (as produced by the `mft` and `ntfs-core`
/// crates' timestamp accessors) into a [`jiff::Timestamp`]. Out-of-range or
/// absent values degrade to the Unix epoch so parsing untrusted MFT input
/// never panics.
fn ns_to_ts(nanos: Option<i64>) -> jiff::Timestamp {
    nanos
        .and_then(|n| jiff::Timestamp::from_nanosecond(i128::from(n)).ok())
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
}

impl FileTree {
    /// Parse an `$MFT` file on disk and build the tree.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or is not a valid MFT image.
    ///
    /// # Panics
    ///
    /// Panics if the internal progress bar template is invalid (statically verified).
    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    pub fn from_mft(path: &Path) -> Result<Self> {
        let buffer =
            std::fs::read(path).with_context(|| format!("Failed to read: {}", path.display()))?;

        // Full-precision $SI/$FN timestamps. The `mft` crate converts FILETIME
        // through winstructs, which does `ticks / 10` (100 ns → µs) and silently
        // drops the final 100 ns tick. ntfs-core preserves the full 100 ns, so
        // parse the same buffer once and override the timestamps per record. A
        // parse failure (or a record ntfs-core skips) degrades to the `mft`
        // crate's value rather than erroring — no regression, just less precision.
        let precise = MftData::parse(&buffer).ok();

        let mut parser =
            MftParser::from_buffer(buffer).context("Failed to initialise MFT parser")?;

        let total = parser.get_entry_count();
        let capacity = (total as usize) / 2;
        let mut nodes = Vec::with_capacity(capacity);

        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "  Parsing MFT [{bar:40.cyan/dim}] {pos}/{len} entries ({percent}%)",
            )
            // The bar is cosmetic; a malformed template must not take the MFT
            // parse down with it. Fall back to indicatif's default styling.
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("##-"),
        );

        for i in 0..total {
            pb.set_position(i);

            let Ok(entry) = parser.get_entry(i) else {
                continue;
            };

            if !entry.is_allocated() {
                continue;
            }

            let Some(fname) = entry.find_best_name_attribute() else {
                continue;
            };

            let is_dir = entry.is_dir();
            let entry_id = entry.header.record_number;
            let parent_entry = fname.parent.entry;

            // On-disk MFT entry number (record header @ 0x2C). The `mft` crate's
            // `record_number` is just the iteration index, which coincides with
            // the on-disk number only for a full, position-aligned $MFT;
            // ntfs-core keys `by_entry` by the on-disk number, so read it
            // directly (bounds-checked) to align the two parsers for any input.
            let ondisk_entry = entry
                .data
                .get(0x2C..0x30)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map_or(entry_id, |b| u64::from(u32::from_le_bytes(b)));
            let precise_entry = precise.as_ref().and_then(|d| d.get_by_entry(ondisk_entry));

            // $FILE_NAME timestamps (kernel-managed). Prefer ntfs-core's
            // full-precision FILETIME; fall back to the `mft` crate per field.
            let fn_ts = NtfsTimestamps {
                modified: ns_to_ts(
                    precise_entry
                        .and_then(|e| e.fn_modified)
                        .unwrap_or(fname.modified)
                        .timestamp_nanos_opt(),
                ),
                accessed: ns_to_ts(
                    precise_entry
                        .and_then(|e| e.fn_accessed)
                        .unwrap_or(fname.accessed)
                        .timestamp_nanos_opt(),
                ),
                created: ns_to_ts(
                    precise_entry
                        .and_then(|e| e.fn_created)
                        .unwrap_or(fname.created)
                        .timestamp_nanos_opt(),
                ),
                entry_modified: ns_to_ts(
                    precise_entry
                        .and_then(|e| e.fn_mft_modified)
                        .unwrap_or(fname.mft_modified)
                        .timestamp_nanos_opt(),
                ),
            };

            // $STANDARD_INFORMATION timestamps (user-visible, preferred). The
            // `mft` crate values are the fallback base when ntfs-core is absent
            // for a record; ntfs-core's full-precision values override per field.
            let si_fallback = entry
                .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
                .filter_map(std::result::Result::ok)
                .find_map(|attr| {
                    if let MftAttributeContent::AttrX10(si) = attr.data {
                        Some(NtfsTimestamps {
                            modified: ns_to_ts(si.modified.timestamp_nanos_opt()),
                            accessed: ns_to_ts(si.accessed.timestamp_nanos_opt()),
                            created: ns_to_ts(si.created.timestamp_nanos_opt()),
                            entry_modified: ns_to_ts(si.mft_modified.timestamp_nanos_opt()),
                        })
                    } else {
                        None
                    }
                })
                .unwrap_or(fn_ts);
            let si_ts = NtfsTimestamps {
                modified: precise_entry
                    .and_then(|e| e.si_modified)
                    .map_or(si_fallback.modified, |dt| {
                        ns_to_ts(dt.timestamp_nanos_opt())
                    }),
                accessed: precise_entry
                    .and_then(|e| e.si_accessed)
                    .map_or(si_fallback.accessed, |dt| {
                        ns_to_ts(dt.timestamp_nanos_opt())
                    }),
                created: precise_entry
                    .and_then(|e| e.si_created)
                    .map_or(si_fallback.created, |dt| ns_to_ts(dt.timestamp_nanos_opt())),
                entry_modified: precise_entry
                    .and_then(|e| e.si_mft_modified)
                    .map_or(si_fallback.entry_modified, |dt| {
                        ns_to_ts(dt.timestamp_nanos_opt())
                    }),
            };

            // Only store fn_timestamps if they differ from si_timestamps.
            let fn_timestamps = if fn_ts == si_ts { None } else { Some(fn_ts) };

            // Read file size from $DATA attribute (accurate), falling back to
            // $FILENAME logical_size (often stale/zero in NTFS).
            let size = if is_dir {
                0
            } else {
                entry
                    .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
                    .filter_map(std::result::Result::ok)
                    .find(|a| a.header.name.is_empty()) // default $DATA stream only
                    .map_or(fname.logical_size, |attr| {
                        match &attr.header.residential_header {
                            ResidentialHeader::Resident(r) => u64::from(r.data_size),
                            ResidentialHeader::NonResident(nr) => nr.file_size,
                        }
                    })
            };

            // Extract file attribute flags from $STANDARD_INFORMATION.
            let file_attributes = entry
                .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
                .filter_map(std::result::Result::ok)
                .find_map(|attr| {
                    if let MftAttributeContent::AttrX10(si) = attr.data {
                        Some(si.file_flags.bits())
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            nodes.push(FileNode {
                name: fname.name.clone(),
                mft_entry: entry_id,
                parent_entry,
                is_dir,
                size,
                si_timestamps: si_ts,
                fn_timestamps,
                file_attributes,
                usn_change_count: 0,
                sequence_number: 0,
                hard_link_count: 1,
                is_resident: false,
                security_id: 0,
                owner_id: 0,
                usn: 0,
                ads_names: Vec::new(),
            });
        }

        pb.finish_and_clear();
        let allocated = nodes.len();
        eprintln!("  Parsed {allocated} allocated entries from {total} MFT records.");

        let pb2 = ProgressBar::new_spinner();
        pb2.set_style(
            ProgressStyle::with_template("  {spinner:.cyan} Building directory tree...")
                // Cosmetic, as above.
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb2.enable_steady_tick(std::time::Duration::from_millis(80));

        let mut tree = Self::from_nodes(nodes);
        tree.total_mft_entries = total;

        pb2.finish_and_clear();
        Ok(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_mft_rejects_nonexistent_file() {
        let result = FileTree::from_mft(Path::new("/nonexistent/$MFT"));
        assert!(result.is_err());
    }

    #[test]
    fn from_mft_rejects_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let result = FileTree::from_mft(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn from_mft_rejects_garbage_data() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"this is not an MFT file at all").unwrap();
        let result = FileTree::from_mft(tmp.path());
        assert!(result.is_err());
    }

    /// Real WinSxS component record (DC01 `$MFT` entry 74419) whose `$SI`
    /// Modified FILETIME ends in a non-zero 100 ns digit. TSK `istat`
    /// (independent oracle) reports `2013-06-18T15:02:18.305856600Z`; the
    /// `mft` crate's `winstructs` truncates 100 ns → µs, silently dropping the
    /// trailing 600 ns and rendering `.305856000`. This guards full precision.
    #[test]
    fn from_mft_preserves_100ns_filetime_precision() {
        const REC: &[u8] = include_bytes!("../tests/data/dc01_mft_record_74419.bin");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), REC).unwrap();

        let tree = FileTree::from_mft(tmp.path()).unwrap();
        let node = (0..tree.node_count())
            .map(|i| tree.node(i))
            .find(|n| n.name.contains("37E2F32E"))
            .expect("settingcontent record present");

        let expected: jiff::Timestamp = "2013-06-18T15:02:18.305856600Z".parse().unwrap();
        assert_eq!(
            node.si_timestamps.modified, expected,
            "$SI Modified lost 100 ns precision: got {}, want {} (TSK istat)",
            node.si_timestamps.modified, expected
        );
    }
}
