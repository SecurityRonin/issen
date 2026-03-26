//! Application state and keyboard-driven navigation.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use rt_mft_tree::tree::FileTree;
use rt_signatures::heuristics::AnomalyIndex;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// What the event loop should do after handling a key.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Continue,
    Quit,
}

/// Column to sort by (press `s` to cycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    Name,
    Size,
    Modified,
    Created,
}

impl SortMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Size => "Size",
            Self::Modified => "Modified",
            Self::Created => "Created",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Name => Self::Size,
            Self::Size => Self::Modified,
            Self::Modified => Self::Created,
            Self::Created => Self::Name,
        }
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub tree: FileTree,
    pub anomaly_index: AnomalyIndex,
    /// Arena index of the directory currently displayed.
    pub current_dir: usize,
    /// Cursor position within `entries`.
    pub selected: usize,
    /// Cached, sorted child indices for the current directory.
    pub entries: Vec<usize>,
    /// Stack of (`dir_idx`, cursor) for `Backspace` navigation.
    path_stack: Vec<(usize, usize)>,
    pub sort_mode: SortMode,
    /// Active search query (empty = no filter).
    pub search_query: String,
    /// Whether the search input bar is active.
    pub searching: bool,
    /// Whether to show only flagged entries.
    pub flagged_filter: bool,
    /// Whether to show the anomaly detail panel.
    pub show_detail_panel: bool,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl App {
    pub fn new(tree: FileTree, anomaly_index: AnomalyIndex) -> anyhow::Result<Self> {
        let root = tree
            .root_idx()
            .ok_or_else(|| anyhow::anyhow!("MFT contains no root directory (entry 5)"))?;

        let mut app = Self {
            tree,
            anomaly_index,
            current_dir: root,
            selected: 0,
            entries: Vec::new(),
            path_stack: Vec::new(),
            sort_mode: SortMode::Name,
            search_query: String::new(),
            searching: false,
            flagged_filter: false,
            show_detail_panel: false,
        };
        app.refresh_entries();
        Ok(app)
    }

    /// Path string for the current directory.
    pub fn current_path(&self) -> &str {
        self.tree.cached_path(self.current_dir)
    }

    // -- navigation ---------------------------------------------------------

    fn navigate_into(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let target = self.entries[self.selected];

        // If search is active, jump to the item's parent dir and highlight it.
        if !self.search_query.is_empty() {
            let node = self.tree.node(target);
            let parent_entry = node.parent_entry;
            if let Some(&parent_idx) = self.tree.entry_to_idx(parent_entry) {
                self.path_stack.clear();
                self.current_dir = parent_idx;
                self.search_query.clear();
                self.refresh_entries();
                self.selected = self.entries.iter().position(|&e| e == target).unwrap_or(0);
            }
            return;
        }

        if self.tree.node(target).is_dir {
            self.path_stack.push((self.current_dir, self.selected));
            self.current_dir = target;
            self.selected = 0;
            self.search_query.clear();
            self.refresh_entries();
        }
    }

    fn navigate_back(&mut self) {
        if let Some((prev_dir, prev_selected)) = self.path_stack.pop() {
            self.current_dir = prev_dir;
            self.selected = prev_selected;
            self.search_query.clear();
            self.refresh_entries();
        }
    }

    fn refresh_entries(&mut self) {
        if self.search_query.is_empty() {
            self.entries = self.tree.children(self.current_dir).to_vec();
            if self.flagged_filter {
                self.entries
                    .retain(|&idx| !self.anomaly_index.for_node(idx).is_empty());
            }
            self.sort_entries();
        } else {
            self.entries = self.tree.search(&self.search_query);
            let tree = &self.tree;
            self.entries
                .sort_by(|&a, &b| tree.cached_path_lower(a).cmp(tree.cached_path_lower(b)));
        }
        if self.entries.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.entries.len() {
            self.selected = self.entries.len() - 1;
        }
    }

    fn sort_entries(&mut self) {
        let tree = &self.tree;
        let mode = self.sort_mode;
        self.entries.sort_by(|&a, &b| {
            let na = tree.node(a);
            let nb = tree.node(b);
            nb.is_dir.cmp(&na.is_dir).then_with(|| match mode {
                SortMode::Name => na.name.to_lowercase().cmp(&nb.name.to_lowercase()),
                SortMode::Size => na.size.cmp(&nb.size),
                SortMode::Modified => nb.si_timestamps.modified.cmp(&na.si_timestamps.modified),
                SortMode::Created => nb.si_timestamps.created.cmp(&na.si_timestamps.created),
            })
        });
    }

    // -- key handling -------------------------------------------------------

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if self.searching {
            return self.handle_search_key(key);
        }
        self.handle_normal_key(key)
    }

    fn handle_normal_key(&mut self, key: KeyEvent) -> Action {
        let count = self.entries.len();

        match key.code {
            // Quit
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Action::Quit;
            }

            // Movement
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if count > 0 {
                    self.selected = (self.selected + 1).min(count - 1);
                }
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.selected = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                if count > 0 {
                    self.selected = count - 1;
                }
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.selected = self.selected.saturating_sub(30);
            }
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if count > 0 {
                    self.selected = (self.selected + 30).min(count - 1);
                }
            }
            KeyCode::PageUp => {
                self.selected = self.selected.saturating_sub(30);
            }
            KeyCode::PageDown => {
                if count > 0 {
                    self.selected = (self.selected + 30).min(count - 1);
                }
            }

            // Navigation
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                self.navigate_into();
            }
            KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                self.navigate_back();
            }

            // Sort
            KeyCode::Char('s') => {
                self.sort_mode = self.sort_mode.next();
                self.sort_entries();
            }

            // Search
            KeyCode::Char('/') => {
                self.searching = true;
                self.search_query.clear();
            }

            // Flagged filter
            KeyCode::Char('f') => {
                self.flagged_filter = !self.flagged_filter;
                self.refresh_entries();
            }

            // Anomaly detail panel
            KeyCode::Char('a') => {
                self.show_detail_panel = !self.show_detail_panel;
            }

            _ => {}
        }

        Action::Continue
    }

    fn handle_search_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Enter => {
                self.searching = false;
            }
            KeyCode::Esc => {
                self.searching = false;
                self.search_query.clear();
                self.refresh_entries();
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.selected = 0;
                self.refresh_entries();
            }
            KeyCode::Char(c) => {
                self.search_query.push(c);
                self.selected = 0;
                self.refresh_entries();
            }
            _ => {}
        }
        Action::Continue
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use rt_mft_tree::node::{FileNode, NtfsTimestamps};
    use rt_mft_tree::tree::FileTree;

    fn ts(y: i32, m: u32, d: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn dir_node(name: &str, mft: u64, parent: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry: mft,
            parent_entry: parent,
            is_dir: true,
            size: 0,
            si_timestamps: NtfsTimestamps {
                modified: ts(2024, 1, 1),
                accessed: ts(2024, 1, 1),
                created: ts(2024, 1, 1),
                entry_modified: ts(2024, 1, 1),
            },
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        }
    }

    fn file_node(name: &str, mft: u64, parent: u64, size: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry: mft,
            parent_entry: parent,
            is_dir: false,
            size,
            si_timestamps: NtfsTimestamps {
                modified: ts(2024, 6, 15),
                accessed: ts(2024, 6, 15),
                created: ts(2024, 1, 1),
                entry_modified: ts(2024, 6, 15),
            },
            fn_timestamps: None,
            file_attributes: 0,
            usn_change_count: 0,
        }
    }

    /// Build a test tree and App.
    ///
    /// ```text
    /// / (root, MFT#5)
    /// ├── docs/ (MFT#10)
    /// │   ├── readme.txt (MFT#20, 1K)
    /// │   └── notes.txt (MFT#21, 500)
    /// ├── src/ (MFT#11)
    /// │   └── main.rs (MFT#30, 2K)
    /// └── config.toml (MFT#12, 300)
    /// ```
    fn test_app() -> App {
        let nodes = vec![
            dir_node(".", 5, 5),
            dir_node("docs", 10, 5),
            file_node("readme.txt", 20, 10, 1000),
            file_node("notes.txt", 21, 10, 500),
            dir_node("src", 11, 5),
            file_node("main.rs", 30, 11, 2000),
            file_node("config.toml", 12, 5, 300),
        ];
        let tree = FileTree::from_nodes(nodes);
        App::new(tree, AnomalyIndex::new()).unwrap()
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn key_ctrl(c: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(c),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    // -- Initial state -------------------------------------------------------

    #[test]
    fn initial_state_at_root() {
        let app = test_app();
        assert_eq!(app.selected, 0);
        assert_eq!(app.current_path(), "/");
        assert!(!app.searching);
        assert!(app.search_query.is_empty());
        assert_eq!(app.sort_mode, SortMode::Name);
    }

    #[test]
    fn root_has_correct_entries() {
        let app = test_app();
        // 2 dirs (docs, src) + 1 file (config.toml) = 3
        assert_eq!(app.entries.len(), 3);
    }

    // -- Movement tests ------------------------------------------------------

    #[test]
    fn j_moves_down() {
        let mut app = test_app();
        assert_eq!(app.selected, 0);
        app.handle_key(key(KeyCode::Char('j')));
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn k_moves_up() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('j'))); // go to 1
        app.handle_key(key(KeyCode::Char('k'))); // back to 0
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn k_at_top_stays_at_zero() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn j_at_bottom_clamps() {
        let mut app = test_app();
        for _ in 0..100 {
            app.handle_key(key(KeyCode::Char('j')));
        }
        assert_eq!(app.selected, app.entries.len() - 1);
    }

    #[test]
    fn down_arrow_moves_down() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn up_arrow_moves_up() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn g_jumps_to_top() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('j')));
        app.handle_key(key(KeyCode::Char('j')));
        app.handle_key(key(KeyCode::Char('g')));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn shift_g_jumps_to_bottom() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('G')));
        assert_eq!(app.selected, app.entries.len() - 1);
    }

    #[test]
    fn page_down_moves_30() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::PageDown));
        // Only 3 entries, so clamps to last
        assert_eq!(app.selected, app.entries.len() - 1);
    }

    #[test]
    fn ctrl_n_pages_down() {
        let mut app = test_app();
        app.handle_key(key_ctrl('n'));
        assert_eq!(app.selected, app.entries.len() - 1);
    }

    #[test]
    fn ctrl_p_pages_up() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('G'))); // go to bottom
        app.handle_key(key_ctrl('p'));
        assert_eq!(app.selected, 0); // 3 items - 30 = clamps to 0
    }

    // -- Navigation tests ----------------------------------------------------

    #[test]
    fn enter_navigates_into_dir() {
        let mut app = test_app();
        // First entry should be a dir (docs or src, alphabetically)
        assert!(app.tree.node(app.entries[0]).is_dir);
        app.handle_key(key(KeyCode::Enter));
        // Should now be inside that directory
        assert_ne!(app.current_path(), "/");
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn l_navigates_into_dir() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('l')));
        assert_ne!(app.current_path(), "/");
    }

    #[test]
    fn backspace_navigates_back() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Enter)); // go into first dir
        let inner_path = app.current_path();
        assert_ne!(inner_path, "/");

        app.handle_key(key(KeyCode::Backspace)); // back
        assert_eq!(app.current_path(), "/");
    }

    #[test]
    fn h_navigates_back() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('l'))); // go in
        app.handle_key(key(KeyCode::Char('h'))); // go back
        assert_eq!(app.current_path(), "/");
    }

    #[test]
    fn backspace_at_root_is_noop() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.current_path(), "/");
    }

    #[test]
    fn navigate_back_restores_cursor() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('j'))); // select index 1
        let saved_pos = app.selected;
        app.handle_key(key(KeyCode::Char('l'))); // go into dir at pos 1
        app.handle_key(key(KeyCode::Char('h'))); // go back
        assert_eq!(app.selected, saved_pos);
    }

    #[test]
    fn enter_on_file_is_noop() {
        let mut app = test_app();
        // Navigate to the file entry (last item = config.toml)
        app.handle_key(key(KeyCode::Char('G'))); // jump to last
        let path_before = app.current_path().to_string();
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.current_path(), path_before);
    }

    // -- Sort tests ----------------------------------------------------------

    #[test]
    fn s_cycles_sort_mode() {
        let mut app = test_app();
        assert_eq!(app.sort_mode, SortMode::Name);
        app.handle_key(key(KeyCode::Char('s')));
        assert_eq!(app.sort_mode, SortMode::Size);
        app.handle_key(key(KeyCode::Char('s')));
        assert_eq!(app.sort_mode, SortMode::Modified);
        app.handle_key(key(KeyCode::Char('s')));
        assert_eq!(app.sort_mode, SortMode::Created);
        app.handle_key(key(KeyCode::Char('s')));
        assert_eq!(app.sort_mode, SortMode::Name);
    }

    // -- Quit tests ----------------------------------------------------------

    #[test]
    fn q_returns_quit() {
        let mut app = test_app();
        assert_eq!(app.handle_key(key(KeyCode::Char('q'))), Action::Quit);
    }

    #[test]
    fn esc_returns_quit() {
        let mut app = test_app();
        assert_eq!(app.handle_key(key(KeyCode::Esc)), Action::Quit);
    }

    #[test]
    fn ctrl_c_returns_quit() {
        let mut app = test_app();
        assert_eq!(app.handle_key(key_ctrl('c')), Action::Quit);
    }

    #[test]
    fn j_returns_continue() {
        let mut app = test_app();
        assert_eq!(app.handle_key(key(KeyCode::Char('j'))), Action::Continue);
    }

    // -- Search tests --------------------------------------------------------

    #[test]
    fn slash_enters_search_mode() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        assert!(app.searching);
        assert!(app.search_query.is_empty());
    }

    #[test]
    fn typing_in_search_filters_globally() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        // Type "main" — should find src/main.rs
        for c in "main".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert!(!app.entries.is_empty());
        // All results should have "main" in their path
        for &idx in &app.entries {
            let path = app.tree.cached_path(idx).to_lowercase();
            assert!(path.contains("main"), "path {path} should contain 'main'");
        }
    }

    #[test]
    fn search_matches_path_not_just_name() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        // Search for "docs/readme" — matches path, not just filename
        for c in "docs/readme".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.entries.len(), 1);
        assert_eq!(app.tree.node(app.entries[0]).name, "readme.txt");
    }

    #[test]
    fn esc_in_search_cancels_and_clears() {
        let mut app = test_app();
        let original_count = app.entries.len();
        app.handle_key(key(KeyCode::Char('/')));
        for c in "main".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Esc));
        assert!(!app.searching);
        assert!(app.search_query.is_empty());
        assert_eq!(app.entries.len(), original_count);
    }

    #[test]
    fn enter_in_search_accepts_filter() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        for c in "main".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        let filtered_count = app.entries.len();
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.searching);
        assert_eq!(app.search_query, "main"); // filter preserved
        assert_eq!(app.entries.len(), filtered_count);
    }

    #[test]
    fn backspace_in_search_removes_char() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        for c in "main".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.search_query, "main");
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.search_query, "mai");
    }

    #[test]
    fn enter_on_search_result_jumps_to_parent_dir() {
        let mut app = test_app();
        // Search for main.rs
        app.handle_key(key(KeyCode::Char('/')));
        for c in "main.rs".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter)); // accept filter
                                             // Now Enter on the result should jump to its parent dir
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.current_path(), "/src");
        assert!(app.search_query.is_empty()); // search cleared
                                              // main.rs should be selected
        let selected_node = app.tree.node(app.entries[app.selected]);
        assert_eq!(selected_node.name, "main.rs");
    }

    #[test]
    fn navigate_into_dir_clears_search() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        for c in "docs".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter)); // accept
                                             // Find docs dir in results and enter it
        let docs_idx = app
            .entries
            .iter()
            .position(|&i| app.tree.node(i).is_dir && app.tree.node(i).name == "docs");
        if let Some(pos) = docs_idx {
            app.selected = pos;
            app.handle_key(key(KeyCode::Enter));
            assert!(app.search_query.is_empty());
        }
    }

    #[test]
    fn esc_outside_search_quits() {
        let mut app = test_app();
        assert_eq!(app.handle_key(key(KeyCode::Esc)), Action::Quit);
    }

    #[test]
    fn f_key_toggles_flagged_filter() {
        let mut app = test_app();
        assert!(!app.flagged_filter);
        app.handle_key(key(KeyCode::Char('f')));
        assert!(app.flagged_filter);
        app.handle_key(key(KeyCode::Char('f')));
        assert!(!app.flagged_filter);
    }

    #[test]
    fn a_key_toggles_detail_panel() {
        let mut app = test_app();
        assert!(!app.show_detail_panel);
        app.handle_key(key(KeyCode::Char('a')));
        assert!(app.show_detail_panel);
        app.handle_key(key(KeyCode::Char('a')));
        assert!(!app.show_detail_panel);
    }

    #[test]
    fn flagged_filter_shows_only_flagged_entries() {
        use rt_signatures::heuristics::anomaly::{Anomaly, AnomalyCategory};
        use rt_signatures::matching::results::Severity;

        let nodes = vec![
            dir_node(".", 5, 5),
            file_node("clean.txt", 100, 5, 1000),
            file_node("flagged.exe", 200, 5, 5000),
        ];
        let tree = FileTree::from_nodes(nodes);
        let mut anomaly_index = AnomalyIndex::new();
        // Flag the second file (arena idx 2)
        anomaly_index.add(
            2,
            Anomaly {
                severity: Severity::High,
                category: AnomalyCategory::Timestomping,
                rule_id: "HEUR-TS-001",
                description: "test".to_string(),
                evidence: "test".to_string(),
            },
        );
        let mut app = App::new(tree, anomaly_index).unwrap();
        assert_eq!(app.entries.len(), 2); // both files visible
        app.handle_key(key(KeyCode::Char('f')));
        assert_eq!(app.entries.len(), 1); // only flagged
        assert_eq!(app.tree.node(app.entries[0]).name, "flagged.exe");
    }
}
