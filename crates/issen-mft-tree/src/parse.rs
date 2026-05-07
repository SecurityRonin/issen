//! MFT binary parsing into `FileTree`.

use std::path::Path;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use mft::attribute::header::ResidentialHeader;
use mft::attribute::{MftAttributeContent, MftAttributeType};
use mft::MftParser;

use crate::node::{FileNode, NtfsTimestamps};
use crate::tree::FileTree;

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
            .expect("valid template")
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

            // $FILE_NAME timestamps (kernel-managed).
            let fn_ts = NtfsTimestamps {
                modified: fname.modified,
                accessed: fname.accessed,
                created: fname.created,
                entry_modified: fname.mft_modified,
            };

            // $STANDARD_INFORMATION timestamps (user-visible, preferred).
            let si_ts = entry
                .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
                .filter_map(std::result::Result::ok)
                .find_map(|attr| {
                    if let MftAttributeContent::AttrX10(si) = attr.data {
                        Some(NtfsTimestamps {
                            modified: si.modified,
                            accessed: si.accessed,
                            created: si.created,
                            entry_modified: si.mft_modified,
                        })
                    } else {
                        None
                    }
                })
                .unwrap_or(fn_ts);

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
                .expect("valid template"),
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
}
