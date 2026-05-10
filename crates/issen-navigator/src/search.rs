//! Background search engine with debounce and incremental narrowing.

use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use issen_mft_tree::tree::FileTree;
use issen_mft_tree::trigram::TrigramIndex;

/// Search-relevant data owned by the background thread.
///
/// Searches match against **filenames only** (last path segment),
/// not full paths — so searching "pamela" won't match a parent directory name.
struct SearchData {
    /// Lowercase filename (last path segment) for each node.
    names_lower: Vec<String>,
    /// Path depth for each node (number of `/` separators).
    depths: Vec<usize>,
    /// Trigram index built from filenames only.
    name_trigram_index: TrigramIndex,
    is_root: Vec<bool>,
    max_results: usize,
}

impl SearchData {
    fn extract(tree: &FileTree) -> Self {
        let node_count = tree.node_count();
        let is_root: Vec<bool> = (0..node_count).map(|i| tree.is_root(i)).collect();

        let paths = tree.paths_lower();

        // Extract lowercase filenames (last path segment) for search matching.
        let names_lower: Vec<String> = paths
            .iter()
            .map(|path| path.rsplit('/').next().unwrap_or(path.as_str()).to_string())
            .collect();

        // Path depth = number of '/' separators (shallower = more relevant).
        let depths: Vec<usize> = paths.iter().map(|p| p.matches('/').count()).collect();

        let name_trigram_index = TrigramIndex::build(&names_lower);

        Self {
            names_lower,
            depths,
            name_trigram_index,
            is_root,
            max_results: 10_000,
        }
    }

    /// Full search using trigram index + linear fallback.
    ///
    /// Results are sorted by name length (shortest first = most relevant).
    fn search(&self, query: &str) -> Vec<usize> {
        let query_lower = query.to_lowercase();

        let mut results: Vec<usize> = if let Some(candidates) =
            self.name_trigram_index.candidates(&query_lower)
        {
            candidates
                .into_iter()
                .filter(|&idx| !self.is_root[idx] && self.names_lower[idx].contains(&query_lower))
                .take(self.max_results)
                .collect()
        } else {
            // Fallback for short queries
            (0..self.names_lower.len())
                .filter(|&idx| !self.is_root[idx] && self.names_lower[idx].contains(&query_lower))
                .take(self.max_results)
                .collect()
        };

        // Sort: exact name match first, then shallowest path depth first.
        results.sort_by(|&a, &b| {
            let a_exact = self.names_lower[a] == query_lower;
            let b_exact = self.names_lower[b] == query_lower;
            b_exact
                .cmp(&a_exact)
                .then_with(|| self.depths[a].cmp(&self.depths[b]))
        });

        results
    }

    /// Narrow from previous results (incremental).
    ///
    /// Results are sorted: exact match first, then shallowest depth first.
    fn narrow(&self, query: &str, prev_results: &[usize]) -> Vec<usize> {
        let query_lower = query.to_lowercase();
        let mut results: Vec<usize> = prev_results
            .iter()
            .copied()
            .filter(|&idx| self.names_lower[idx].contains(&query_lower))
            .take(self.max_results)
            .collect();

        results.sort_by(|&a, &b| {
            let a_exact = self.names_lower[a] == query_lower;
            let b_exact = self.names_lower[b] == query_lower;
            b_exact
                .cmp(&a_exact)
                .then_with(|| self.depths[a].cmp(&self.depths[b]))
        });

        results
    }
}

enum Request {
    Search(String),
    Narrow {
        query: String,
        prev_results: Vec<usize>,
    },
}

/// Result returned from the background search thread.
pub struct SearchResult {
    pub query: String,
    pub matches: Vec<usize>,
}

/// Background search engine.
///
/// Sends search requests to a dedicated thread, receives results via channel.
/// The thread drains stale requests and only processes the latest one.
pub struct SearchEngine {
    tx: mpsc::Sender<Request>,
    rx: mpsc::Receiver<SearchResult>,
    _handle: JoinHandle<()>,
}

impl SearchEngine {
    /// Create a new search engine with a background thread.
    pub fn new(tree: &FileTree) -> Self {
        let data = SearchData::extract(tree);
        let (req_tx, req_rx) = mpsc::channel::<Request>();
        let (res_tx, res_rx) = mpsc::channel::<SearchResult>();

        let handle = thread::spawn(move || {
            while let Ok(mut latest) = req_rx.recv() {
                // Drain stale requests, keep only the latest
                while let Ok(newer) = req_rx.try_recv() {
                    latest = newer;
                }

                let result = match latest {
                    Request::Search(ref query) => SearchResult {
                        query: query.clone(),
                        matches: data.search(query),
                    },
                    Request::Narrow {
                        ref query,
                        ref prev_results,
                    } => SearchResult {
                        query: query.clone(),
                        matches: data.narrow(query, prev_results),
                    },
                };

                if res_tx.send(result).is_err() {
                    break; // Receiver dropped
                }
            }
        });

        Self {
            tx: req_tx,
            rx: res_rx,
            _handle: handle,
        }
    }

    /// Send a full search request to the background thread.
    pub fn search(&self, query: String) {
        let _ = self.tx.send(Request::Search(query));
    }

    /// Send a narrowing request (filter from previous results).
    pub fn narrow(&self, query: String, prev_results: Vec<usize>) {
        let _ = self.tx.send(Request::Narrow {
            query,
            prev_results,
        });
    }

    /// Try to receive a search result (non-blocking).
    pub fn try_recv(&self) -> Option<SearchResult> {
        self.rx.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use issen_mft_tree::node::{FileNode, NtfsTimestamps};

    fn ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    fn timestamps() -> NtfsTimestamps {
        NtfsTimestamps {
            modified: ts(),
            accessed: ts(),
            created: ts(),
            entry_modified: ts(),
        }
    }

    fn dir_node(name: &str, mft: u64, parent: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry: mft,
            parent_entry: parent,
            is_dir: true,
            size: 0,
            si_timestamps: timestamps(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
        }
    }

    fn file_node(name: &str, mft: u64, parent: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry: mft,
            parent_entry: parent,
            is_dir: false,
            size: 1000,
            si_timestamps: timestamps(),
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
        }
    }

    fn test_tree() -> FileTree {
        FileTree::from_nodes(vec![
            dir_node(".", 5, 5),
            dir_node("Windows", 30, 5),
            file_node("cmd.exe", 100, 30),
            file_node("notepad.exe", 101, 30),
            dir_node("Users", 40, 5),
            file_node("report.docx", 200, 40),
        ])
    }

    #[test]
    fn search_data_search_finds_matches() {
        let tree = test_tree();
        let data = SearchData::extract(&tree);
        let results = data.search("cmd");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_data_search_excludes_root() {
        let tree = test_tree();
        let data = SearchData::extract(&tree);
        // "report" matches filename "report.docx", should not include root
        let results = data.search("report");
        for &idx in &results {
            assert!(!data.is_root[idx]);
        }
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_matches_filename_not_path() {
        let tree = test_tree();
        let data = SearchData::extract(&tree);
        // "windows" is a directory name in the path, not a filename
        // cmd.exe lives at /Windows/cmd.exe — searching "windows" should NOT match it
        let results = data.search("windows");
        // Only the "Windows" directory itself should match (its name is "windows")
        assert!(results
            .iter()
            .all(|&idx| data.names_lower[idx].contains("windows")));
    }

    #[test]
    fn search_data_narrow_filters_from_previous() {
        let tree = test_tree();
        let data = SearchData::extract(&tree);
        // First find all "exe" matches
        let broad = data.search("exe");
        assert!(broad.len() >= 2); // cmd.exe + notepad.exe
                                   // Narrow to "cmd.exe"
        let narrow = data.narrow("cmd.exe", &broad);
        assert_eq!(narrow.len(), 1);
    }

    #[test]
    fn search_data_narrow_empty_prev_returns_empty() {
        let tree = test_tree();
        let data = SearchData::extract(&tree);
        let results = data.narrow("anything", &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn engine_async_search_returns_results() {
        let tree = test_tree();
        let engine = SearchEngine::new(&tree);
        engine.search("cmd".to_string());

        // Wait for result with timeout
        let result = loop {
            if let Some(r) = engine.try_recv() {
                break r;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };

        assert_eq!(result.query, "cmd");
        assert_eq!(result.matches.len(), 1);
    }

    #[test]
    fn engine_async_narrow_returns_results() {
        let tree = test_tree();
        let engine = SearchEngine::new(&tree);

        // First get broad results
        engine.search("exe".to_string());
        let broad = loop {
            if let Some(r) = engine.try_recv() {
                break r;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };

        // Now narrow
        engine.narrow("cmd.exe".to_string(), broad.matches);
        let narrow = loop {
            if let Some(r) = engine.try_recv() {
                break r;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };

        assert_eq!(narrow.query, "cmd.exe");
        assert_eq!(narrow.matches.len(), 1);
    }

    #[test]
    fn engine_drains_stale_requests() {
        let tree = test_tree();
        let engine = SearchEngine::new(&tree);

        // Send multiple requests rapidly
        engine.search("a".to_string());
        engine.search("ab".to_string());
        engine.search("cmd".to_string());

        // Should eventually get result for "cmd" (latest)
        let mut last_query = String::new();
        for _ in 0..200 {
            if let Some(r) = engine.try_recv() {
                last_query = r.query;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            if last_query == "cmd" {
                break;
            }
        }
        // The last result we see should be "cmd"
        assert_eq!(last_query, "cmd");
    }
}
