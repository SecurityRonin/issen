//! Trigram index for fast substring search across file paths.
//!
//! Maps each 3-byte sequence to a sorted list of node indices containing that trigram.
//! For queries >= 3 chars, intersects posting lists to quickly narrow candidates.

use std::collections::{HashMap, HashSet};

/// Trigram index mapping 3-byte sequences to sorted node indices.
#[derive(Clone)]
pub struct TrigramIndex {
    postings: HashMap<[u8; 3], Vec<usize>>,
}

impl TrigramIndex {
    /// Build a trigram index from pre-computed lowercase paths.
    #[must_use]
    pub fn build(paths_lower: &[String]) -> Self {
        let mut postings: HashMap<[u8; 3], Vec<usize>> = HashMap::new();
        for (idx, path) in paths_lower.iter().enumerate() {
            let bytes = path.as_bytes();
            if bytes.len() < 3 {
                continue;
            }
            let mut seen = HashSet::new();
            for window in bytes.windows(3) {
                let tri: [u8; 3] = [window[0], window[1], window[2]];
                if seen.insert(tri) {
                    postings.entry(tri).or_default().push(idx);
                }
            }
        }
        Self { postings }
    }

    /// Find candidate indices matching all trigrams of the query.
    ///
    /// Returns `None` if the query is too short (< 3 bytes) for trigram lookup.
    /// Candidates still need verification with `.contains()` — trigram intersection
    /// eliminates most non-matches but can have false positives.
    #[must_use]
    pub fn candidates(&self, query_lower: &str) -> Option<Vec<usize>> {
        let bytes = query_lower.as_bytes();
        if bytes.len() < 3 {
            return None;
        }

        // Extract unique trigrams from query
        let mut trigrams: Vec<[u8; 3]> = Vec::new();
        let mut seen = HashSet::new();
        for window in bytes.windows(3) {
            let tri: [u8; 3] = [window[0], window[1], window[2]];
            if seen.insert(tri) {
                trigrams.push(tri);
            }
        }

        // Sort by posting list size (smallest first for fastest intersection)
        trigrams.sort_by_key(|tri| self.postings.get(tri).map_or(0, Vec::len));

        let mut result: Option<Vec<usize>> = None;
        for tri in &trigrams {
            let Some(posting) = self.postings.get(tri) else {
                return Some(Vec::new()); // Trigram not in index = no matches
            };
            result = Some(match result {
                None => posting.clone(),
                Some(prev) => intersect_sorted(&prev, posting),
            });
        }
        result
    }

    /// Number of unique trigrams indexed.
    #[must_use]
    pub fn trigram_count(&self) -> usize {
        self.postings.len()
    }
}

/// Intersect two sorted slices, returning sorted result.
fn intersect_sorted(a: &[usize], b: &[usize]) -> Vec<usize> {
    let mut result = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                result.push(a[i]);
                i += 1;
                j += 1;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_index(paths: &[&str]) -> TrigramIndex {
        let lower: Vec<String> = paths.iter().map(|s| s.to_lowercase()).collect();
        TrigramIndex::build(&lower)
    }

    // -- build tests ---------------------------------------------------------

    #[test]
    fn build_empty_paths() {
        let index = build_index(&[]);
        assert_eq!(index.trigram_count(), 0);
    }

    #[test]
    fn build_short_paths_ignored() {
        let index = build_index(&["ab", "x"]);
        assert_eq!(index.trigram_count(), 0);
    }

    #[test]
    fn build_creates_trigrams_for_3_char_path() {
        let index = build_index(&["abc"]);
        assert!(index.trigram_count() > 0);
        // "abc" has one trigram: [a,b,c]
        assert_eq!(index.trigram_count(), 1);
    }

    #[test]
    fn build_longer_path_has_multiple_trigrams() {
        let index = build_index(&["/windows/system32"]);
        // "/wi", "win", "ind", "ndo", "dow", "ows", "ws/", "s/s", "/sy", "sys", "yst", "ste", "tem", "em3", "m32"
        assert!(index.trigram_count() >= 10);
    }

    #[test]
    fn build_deduplicates_trigrams_per_path() {
        // "aaa" has only one unique trigram: [a,a,a]
        let index = build_index(&["aaa"]);
        assert_eq!(index.trigram_count(), 1);
        // And the posting list has only one entry
        let candidates = index.candidates("aaa").unwrap();
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn build_multiple_paths_share_trigrams() {
        let index = build_index(&["/windows/cmd.exe", "/windows/notepad.exe"]);
        // Both contain "win" trigram — posting list should have 2 entries
        // Indirectly test: searching "win" should return both
        let candidates = index.candidates("win").unwrap();
        assert_eq!(candidates.len(), 2);
    }

    // -- candidates tests ----------------------------------------------------

    #[test]
    fn candidates_returns_none_for_short_query() {
        let index = build_index(&["/windows/system32/cmd.exe"]);
        assert!(index.candidates("ab").is_none());
        assert!(index.candidates("a").is_none());
        assert!(index.candidates("").is_none());
    }

    #[test]
    fn candidates_returns_some_for_3_char_query() {
        let index = build_index(&["/windows/system32/cmd.exe"]);
        assert!(index.candidates("win").is_some());
    }

    #[test]
    fn candidates_finds_matching_path() {
        let index = build_index(&[
            "/windows/system32/cmd.exe",
            "/users/admin/desktop/report.docx",
        ]);
        let results = index.candidates("system32").unwrap();
        assert_eq!(results, vec![0]); // Only first path contains "system32"
    }

    #[test]
    fn candidates_no_match_returns_empty() {
        let index = build_index(&["/windows/cmd.exe"]);
        let results = index.candidates("zzzzzzz").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn candidates_multiple_matches() {
        let index = build_index(&[
            "/windows/system32/cmd.exe",
            "/windows/system32/notepad.exe",
            "/users/admin/notes.txt",
        ]);
        let results = index.candidates("system32").unwrap();
        assert_eq!(results, vec![0, 1]); // First two paths
    }

    #[test]
    fn candidates_intersects_multiple_trigrams() {
        let index = build_index(&[
            "/windows/system32/cmd.exe",     // has "cmd" and "exe"
            "/windows/system32/notepad.exe", // has "exe" but not "cmd"
            "/users/admin/cmd_history.txt",  // has "cmd" but not "exe"
        ]);
        // "cmd.exe" has trigrams "cmd", "md.", "d.e", ".ex", "exe"
        // Only index 0 has ALL of them
        let results = index.candidates("cmd.exe").unwrap();
        assert_eq!(results, vec![0]);
    }

    // -- intersect_sorted tests -----------------------------------------------

    #[test]
    fn intersect_empty_slices() {
        assert!(intersect_sorted(&[], &[]).is_empty());
    }

    #[test]
    fn intersect_one_empty() {
        assert!(intersect_sorted(&[1, 2, 3], &[]).is_empty());
        assert!(intersect_sorted(&[], &[1, 2, 3]).is_empty());
    }

    #[test]
    fn intersect_no_overlap() {
        assert!(intersect_sorted(&[1, 3, 5], &[2, 4, 6]).is_empty());
    }

    #[test]
    fn intersect_full_overlap() {
        assert_eq!(intersect_sorted(&[1, 2, 3], &[1, 2, 3]), vec![1, 2, 3]);
    }

    #[test]
    fn intersect_partial_overlap() {
        assert_eq!(intersect_sorted(&[1, 3, 5, 7], &[2, 3, 5, 8]), vec![3, 5]);
    }

    // -- Unicode / multi-byte tests -------------------------------------------

    #[test]
    fn candidates_finds_cjk_filename() {
        // Chinese characters are 3 bytes each in UTF-8.
        // "中文" = [0xe4,0xb8,0xad, 0xe6,0x96,0x87] — 6 bytes, 4 byte-trigrams.
        let index = build_index(&["/users/docs/中文报告.docx", "/users/docs/report.docx"]);
        let results = index.candidates("中文").unwrap();
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn candidates_finds_mixed_ascii_cjk() {
        let index = build_index(&["/users/admin/文件backup.zip", "/users/admin/backup.zip"]);
        // Query spans ASCII-CJK boundary — byte trigrams still align
        let results = index.candidates("文件backup").unwrap();
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn candidates_single_cjk_char_falls_back() {
        // Single CJK char = 3 bytes = exactly 1 trigram
        let index = build_index(&["/users/报告.txt", "/users/report.txt"]);
        let results = index.candidates("报").unwrap();
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn candidates_two_byte_chars_below_threshold() {
        // Accented chars like "é" are 2 bytes in UTF-8.
        // Query "éé" = 4 bytes = 2 byte-trigrams, works fine.
        let index = build_index(&["/users/café/menu.txt", "/users/office/menu.txt"]);
        let results = index.candidates("café").unwrap();
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn candidates_emoji_4byte_chars() {
        // Emoji like "🔍" are 4 bytes in UTF-8.
        // "🔍🔍" = 8 bytes = 6 byte-trigrams.
        let index = build_index(&["/notes/🔍search.md", "/notes/search.md"]);
        let results = index.candidates("🔍search").unwrap();
        assert_eq!(results, vec![0]);
    }
}
