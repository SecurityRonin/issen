//! Trigram index for fast substring search across file paths.
//!
//! Maps each 3-byte sequence to a sorted list of node indices containing that trigram.
//! For queries >= 3 chars, intersects posting lists to quickly narrow candidates.

use std::collections::{HashMap, HashSet};

/// Trigram index mapping 3-byte sequences to sorted node indices.
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
}
