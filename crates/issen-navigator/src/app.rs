//! Application state and keyboard-driven navigation.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;

use issen_mft_tree::tree::FileTree;
use issen_signatures::heuristics::AnomalyIndex;

use crate::search::SearchEngine;

const DEBOUNCE_MS: u64 = 150;

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
    /// Flattened, depth-first list of visible node indices.
    pub entries: Vec<usize>,
    /// Indentation depth for each entry (parallel to `entries`).
    pub depths: Vec<usize>,
    /// Set of collapsed folder arena indices (expanded by default).
    pub collapsed: HashSet<usize>,
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
    /// Arena indices of global search matches.
    pub search_results: Vec<usize>,
    /// Position within `search_results`.
    pub search_cursor: usize,
    /// Saved `current_dir` before entering search mode.
    pre_search_dir: usize,
    /// Saved `selected` before entering search mode.
    pre_search_selected: usize,
    /// Saved `path_stack` before entering search mode.
    pre_search_path_stack: Vec<(usize, usize)>,
    /// Saved `collapsed` set before entering search mode.
    pre_search_collapsed: HashSet<usize>,
    /// Background search engine.
    search_engine: SearchEngine,
    /// Whether a search query is pending (waiting for debounce).
    pub pending_search: bool,
    /// When the last search keystroke was typed (for debounce).
    last_keystroke: Option<Instant>,
    /// Previous search query (for incremental narrowing).
    prev_search_query: String,
    /// Scroll offset for virtual scrolling (first visible row index).
    pub scroll_offset: usize,
    /// Number of visible rows (set by renderer for page up/down).
    pub visible_height: usize,
    /// Whether the keyboard-shortcut help modal is visible.
    pub show_help: bool,
    /// Screen area occupied by the file list (updated each render frame).
    pub file_list_area: Rect,
    /// Reference timestamp used for age-based file colouring (set at startup).
    pub reference_time: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl App {
    pub fn new(tree: FileTree, anomaly_index: AnomalyIndex) -> anyhow::Result<Self> {
        let root = tree
            .root_idx()
            .ok_or_else(|| anyhow::anyhow!("MFT contains no root directory (entry 5)"))?;

        let search_engine = SearchEngine::new(&tree);

        let collapsed = (0..tree.node_count())
            .filter(|&i| tree.node(i).is_dir)
            .collect();

        let mut app = Self {
            tree,
            anomaly_index,
            current_dir: root,
            selected: 0,
            entries: Vec::new(),
            depths: Vec::new(),
            collapsed,
            path_stack: Vec::new(),
            sort_mode: SortMode::Name,
            search_query: String::new(),
            searching: false,
            flagged_filter: false,
            show_detail_panel: false,
            search_results: Vec::new(),
            search_cursor: 0,
            pre_search_dir: root,
            pre_search_selected: 0,
            pre_search_path_stack: Vec::new(),
            pre_search_collapsed: HashSet::new(),
            search_engine,
            pending_search: false,
            last_keystroke: None,
            prev_search_query: String::new(),
            scroll_offset: 0,
            visible_height: 40,
            show_help: false,
            file_list_area: Rect::default(),
            reference_time: Utc::now(),
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

        if self.tree.node(target).is_dir {
            self.path_stack.push((self.current_dir, self.selected));
            self.current_dir = target;
            self.selected = 0;
            self.refresh_entries();
        }
    }

    fn navigate_back(&mut self) {
        let came_from = self.current_dir;
        if let Some((prev_dir, ..)) = self.path_stack.pop() {
            self.current_dir = prev_dir;
        } else {
            // No path_stack (e.g. after search jump) — go to parent of current_dir.
            let parent_entry = self.tree.node(self.current_dir).parent_entry;
            if let Some(&parent_idx) = self.tree.entry_to_idx(parent_entry) {
                if parent_idx == self.current_dir {
                    return; // Already at root
                }
                self.current_dir = parent_idx;
            } else {
                return; // No parent found
            }
        }
        self.search_query.clear();
        self.refresh_entries();
        // Place cursor on the folder we just backed out of.
        self.selected = self
            .entries
            .iter()
            .position(|&e| e == came_from)
            .unwrap_or(0);
    }

    fn refresh_entries(&mut self) {
        self.entries.clear();
        self.depths.clear();

        // Stack-based DFS: (node_idx, depth). Push in reverse sorted order
        // so that the first child is popped first.
        let mut stack: Vec<(usize, usize)> = Vec::new();

        let mut root_children = self.tree.children(self.current_dir).to_vec();
        sort_children_by(&self.tree, self.sort_mode, &mut root_children);
        for &child in root_children.iter().rev() {
            stack.push((child, 0));
        }

        while let Some((idx, depth)) = stack.pop() {
            let node = self.tree.node(idx);

            // In flagged mode, skip non-flagged files (keep dirs for structure).
            if self.flagged_filter && !node.is_dir && self.anomaly_index.for_node(idx).is_empty() {
                continue;
            }

            self.entries.push(idx);
            self.depths.push(depth);

            if node.is_dir && !self.collapsed.contains(&idx) {
                let mut children = self.tree.children(idx).to_vec();
                sort_children_by(&self.tree, self.sort_mode, &mut children);
                for &child in children.iter().rev() {
                    stack.push((child, depth + 1));
                }
            }
        }

        if self.entries.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.entries.len() {
            self.selected = self.entries.len() - 1;
        }
    }

    /// Collapse the selected folder if expanded, otherwise jump to parent.
    /// At depth 0 on a file or collapsed folder, falls back to `navigate_back()`.
    fn jump_to_parent_in_tree(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let idx = self.entries[self.selected];
        // If on an expanded folder, collapse it.
        if self.tree.node(idx).is_dir && !self.collapsed.contains(&idx) {
            self.collapsed.insert(idx);
            self.refresh_entries();
            return;
        }
        let current_depth = self.depths[self.selected];
        if current_depth == 0 {
            self.navigate_back();
            return;
        }
        // Walk backwards to find the nearest entry at a shallower depth.
        for i in (0..self.selected).rev() {
            if self.depths[i] < current_depth {
                self.selected = i;
                return;
            }
        }
    }

    /// Toggle expand/collapse on the selected folder.
    fn toggle_collapse(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let target = self.entries[self.selected];
        if self.tree.node(target).is_dir {
            if !self.collapsed.remove(&target) {
                self.collapsed.insert(target);
            }
            self.refresh_entries();
        }
    }

    /// Expand all ancestor folders between `current_dir` and `target` so
    /// `target` becomes visible in the flat tree.
    fn ensure_expanded_to(&mut self, target: usize) {
        let mut node_idx = target;
        for _ in 0..1000 {
            let parent_entry = self.tree.node(node_idx).parent_entry;
            if let Some(&parent_idx) = self.tree.entry_to_idx(parent_entry) {
                if parent_idx == self.current_dir || self.tree.is_root(parent_idx) {
                    break;
                }
                self.collapsed.remove(&parent_idx);
                node_idx = parent_idx;
            } else {
                break;
            }
        }
    }

    // -- key handling -------------------------------------------------------

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if self.searching {
            return self.handle_search_key(key);
        }
        self.handle_normal_key(key)
    }

    /// Handle pure navigation keys (arrows, page, Ctrl-B/F).
    /// Shared between normal mode and search mode.
    fn handle_nav_key(&mut self, key: KeyEvent) -> Action {
        let count = self.entries.len();
        match key.code {
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
            KeyCode::Char('b') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.selected = self.selected.saturating_sub(self.visible_height);
            }
            KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if count > 0 {
                    self.selected = (self.selected + self.visible_height).min(count - 1);
                }
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Action::Quit;
            }
            KeyCode::PageUp => {
                self.selected = self.selected.saturating_sub(self.visible_height);
            }
            KeyCode::PageDown => {
                if count > 0 {
                    self.selected = (self.selected + self.visible_height).min(count - 1);
                }
            }
            // Tree-style arrows in search: expand/collapse to reveal context
            KeyCode::Right => {
                if !self.entries.is_empty() {
                    let idx = self.entries[self.selected];
                    if self.tree.node(idx).is_dir && self.collapsed.contains(&idx) {
                        self.collapsed.remove(&idx);
                        self.refresh_entries();
                    }
                }
            }
            KeyCode::Left => {
                self.jump_to_parent_in_tree();
            }
            _ => {}
        }
        Action::Continue
    }

    fn handle_normal_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            // Quit
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Action::Quit;
            }

            // Movement (delegate to shared nav handler)
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Left => {
                return self.handle_nav_key(key);
            }
            KeyCode::Char('k' | 'j' | 'g' | 'G') => {
                return self.handle_nav_key(key);
            }
            KeyCode::Char('b' | 'f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return self.handle_nav_key(key);
            }

            // Navigation
            KeyCode::Enter => {
                self.navigate_into();
            }
            KeyCode::Backspace => {
                self.navigate_back();
            }
            // Tree-style h/l: collapse/expand, fall through to navigate
            KeyCode::Char('l') | KeyCode::Right => {
                if !self.entries.is_empty() {
                    let idx = self.entries[self.selected];
                    if self.tree.node(idx).is_dir && self.collapsed.contains(&idx) {
                        self.collapsed.remove(&idx);
                        self.refresh_entries();
                    } else {
                        self.navigate_into();
                    }
                }
            }
            KeyCode::Char('h') => {
                self.jump_to_parent_in_tree();
            }

            // Sort
            KeyCode::Char('s') => {
                self.sort_mode = self.sort_mode.next();
                self.refresh_entries();
            }

            // Expand / collapse folder
            KeyCode::Char(' ') => {
                self.toggle_collapse();
            }

            // Search
            KeyCode::Char('/') => {
                self.begin_search();
                self.searching = true;
            }

            // Cycle search matches
            KeyCode::Char('n') => {
                self.next_match();
            }
            KeyCode::Char('N') => {
                self.prev_match();
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
                self.pending_search = false;
            }
            KeyCode::Esc => {
                self.searching = false;
                self.pending_search = false;
                self.cancel_search();
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.schedule_search();
            }
            // Navigation keys pass through to normal handler while searching.
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Home
            | KeyCode::End => {
                return self.handle_nav_key(key);
            }
            KeyCode::Char(c) => {
                // Ctrl-B / Ctrl-F pass through as page up/down.
                if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(c, 'b' | 'f' | 'c') {
                    return self.handle_nav_key(key);
                }
                self.search_query.push(c);
                self.schedule_search();
            }
            _ => {}
        }
        Action::Continue
    }

    // -- search (find-and-jump) -----------------------------------------------

    /// Save position before entering search mode.
    fn begin_search(&mut self) {
        self.pre_search_dir = self.current_dir;
        self.pre_search_selected = self.selected;
        self.pre_search_path_stack = self.path_stack.clone();
        self.pre_search_collapsed = self.collapsed.clone();
        self.search_query.clear();
        self.search_results.clear();
        self.search_cursor = 0;
    }

    /// Cancel search and restore pre-search position (including collapse state).
    fn cancel_search(&mut self) {
        self.current_dir = self.pre_search_dir;
        self.selected = self.pre_search_selected;
        self.path_stack = std::mem::take(&mut self.pre_search_path_stack);
        self.collapsed = std::mem::take(&mut self.pre_search_collapsed);
        self.search_query.clear();
        self.search_results.clear();
        self.refresh_entries();
    }

    /// Rebuild search results and jump to nearest match (synchronous, used in tests).
    #[cfg(test)]
    fn incremental_search(&mut self) {
        self.search_results.clear();

        if self.search_query.is_empty() {
            // Restore pre-search view (including collapse state).
            self.current_dir = self.pre_search_dir;
            self.selected = self.pre_search_selected;
            self.path_stack = self.pre_search_path_stack.clone();
            self.collapsed = self.pre_search_collapsed.clone();
            self.refresh_entries();
            return;
        }

        self.search_results = self.tree.search(&self.search_query);

        if !self.search_results.is_empty() {
            self.search_cursor = 0;
            self.jump_to_search_result();
        }
    }

    /// Mark a search as pending (will fire after debounce period).
    fn schedule_search(&mut self) {
        self.pending_search = true;
        self.last_keystroke = Some(Instant::now());
    }

    /// Fire the debounced search if the timer has expired.
    /// Called from the event loop.
    pub fn fire_debounced_search(&mut self) {
        if !self.pending_search {
            return;
        }
        let Some(last) = self.last_keystroke else {
            return;
        };
        if last.elapsed() < Duration::from_millis(DEBOUNCE_MS) {
            return;
        }

        self.pending_search = false;
        let query = self.search_query.clone();

        if query.is_empty() {
            self.current_dir = self.pre_search_dir;
            self.selected = self.pre_search_selected;
            self.path_stack = self.pre_search_path_stack.clone();
            self.collapsed = self.pre_search_collapsed.clone();
            self.refresh_entries();
            self.search_results.clear();
            return;
        }

        // Incremental narrowing: if new query extends previous and we have results
        if !self.search_results.is_empty()
            && !self.prev_search_query.is_empty()
            && query.starts_with(&self.prev_search_query)
        {
            self.search_engine
                .narrow(query.clone(), self.search_results.clone());
        } else {
            self.search_engine.search(query.clone());
        }
        self.prev_search_query = query;
    }

    /// Poll for results from the background search thread.
    /// Called from the event loop.
    pub fn poll_search_results(&mut self) {
        while let Some(result) = self.search_engine.try_recv() {
            // Only accept results matching the current query
            if result.query == self.search_query {
                self.search_results = result.matches;
                self.search_cursor = 0;
                if !self.search_results.is_empty() {
                    self.jump_to_search_result();
                }
            }
        }
    }

    /// Jump the view to the current search result.
    ///
    /// Expands all ancestor folders from `current_dir` down to the target
    /// so the match becomes visible in the tree, then moves the cursor.
    /// Does NOT change `current_dir` — the user stays in the same root.
    fn jump_to_search_result(&mut self) {
        if self.search_results.is_empty() {
            return;
        }
        let target = self.search_results[self.search_cursor];
        self.ensure_expanded_to(target);
        self.refresh_entries();
        self.selected = self.entries.iter().position(|&e| e == target).unwrap_or(0);
    }

    /// Jump to next search match.
    pub fn next_match(&mut self) {
        if self.search_results.is_empty() {
            return;
        }
        self.search_cursor = (self.search_cursor + 1) % self.search_results.len();
        self.jump_to_search_result();
    }

    /// Jump to previous search match.
    pub fn prev_match(&mut self) {
        if self.search_results.is_empty() {
            return;
        }
        self.search_cursor = if self.search_cursor == 0 {
            self.search_results.len() - 1
        } else {
            self.search_cursor - 1
        };
        self.jump_to_search_result();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sort a list of sibling node indices: directories first, then by sort mode.
fn sort_children_by(tree: &FileTree, mode: SortMode, children: &mut [usize]) {
    children.sort_by(|&a, &b| {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use issen_mft_tree::node::{FileNode, NtfsTimestamps};
    use issen_mft_tree::tree::FileTree;

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
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
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
            sequence_number: 0,
            hard_link_count: 1,
            is_resident: true,
            security_id: 0,
            owner_id: 0,
            usn: 0,
            ads_names: Vec::new(),
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
        // Folders default collapsed: docs/, src/, config.toml = 3 top-level items
        assert_eq!(app.entries.len(), 3);
    }

    #[test]
    fn depths_parallel_entries() {
        let app = test_app();
        assert_eq!(app.entries.len(), app.depths.len());
        // All collapsed: only top-level items at depth 0
        assert_eq!(app.depths[0], 0); // docs/
        assert_eq!(app.depths[1], 0); // src/
        assert_eq!(app.depths[2], 0); // config.toml
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
    fn page_down_moves_by_visible_height() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::PageDown));
        // Only 6 entries in tree mode, visible_height=40 > 6, so clamps to last
        assert_eq!(app.selected, app.entries.len() - 1);
    }

    #[test]
    fn ctrl_f_pages_down() {
        let mut app = test_app();
        app.handle_key(key_ctrl('f'));
        assert_eq!(app.selected, app.entries.len() - 1);
    }

    #[test]
    fn ctrl_b_pages_up() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('G'))); // go to bottom
        app.handle_key(key_ctrl('b'));
        assert_eq!(app.selected, 0); // 6 items, visible_height=40 > 6, clamps to 0
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
    fn backspace_navigates_back() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Enter)); // go into first dir
        let inner_path = app.current_path();
        assert_ne!(inner_path, "/");

        app.handle_key(key(KeyCode::Backspace)); // back
        assert_eq!(app.current_path(), "/");
    }

    #[test]
    fn h_on_nested_file_jumps_to_parent_folder() {
        let mut app = test_app();
        // Expand docs/ so we can see its children
        app.collapsed.remove(&app.entries[0]);
        app.refresh_entries();
        // Now: docs/(0), notes.txt(1), readme.txt(1), src/(0), ...
        app.selected = 1;
        assert!(!app.tree.node(app.entries[1]).is_dir);
        assert_eq!(app.depths[1], 1);
        app.handle_key(key(KeyCode::Char('h'))); // jump to parent (docs/ at index 0)
        assert_eq!(app.selected, 0);
        assert!(app.tree.node(app.entries[0]).is_dir);
        assert_eq!(app.current_path(), "/"); // didn't change root
    }

    #[test]
    fn h_at_depth0_navigates_back() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Enter)); // go into first dir
        assert_ne!(app.current_path(), "/");
        // At depth 0 in inner dir, h falls back to navigate_back
        assert_eq!(app.depths[app.selected], 0);
        app.handle_key(key(KeyCode::Char('h')));
        assert_eq!(app.current_path(), "/");
    }

    #[test]
    fn h_on_expanded_folder_collapses_it() {
        let mut app = test_app();
        // Expand docs/ first
        app.collapsed.remove(&app.entries[0]);
        app.refresh_entries();
        let expanded_count = app.entries.len(); // docs/ + children + src/ + config.toml
        assert!(expanded_count > 3);
        // Cursor on docs/ (expanded folder)
        app.selected = 0;
        assert!(app.tree.node(app.entries[0]).is_dir);
        assert!(!app.collapsed.contains(&app.entries[0]));
        // h should collapse it, not jump to parent
        app.handle_key(key(KeyCode::Char('h')));
        assert!(app.collapsed.contains(&app.entries[0]));
        assert_eq!(app.entries.len(), 3); // back to all collapsed
        assert_eq!(app.selected, 0); // cursor stays on docs/
        assert_eq!(app.current_path(), "/"); // didn't navigate away
    }

    #[test]
    fn left_on_expanded_folder_collapses_it() {
        let mut app = test_app();
        // Expand src/
        let src_idx = app.entries[1]; // src/ is index 1 when all collapsed
        app.collapsed.remove(&src_idx);
        app.refresh_entries();
        app.selected = 1; // cursor on src/
        assert!(!app.collapsed.contains(&app.entries[1]));
        app.handle_key(key(KeyCode::Left));
        assert!(app.collapsed.contains(&src_idx));
    }

    #[test]
    fn l_expands_collapsed_folder() {
        let mut app = test_app();
        // Collapse docs/ first
        let idx = app.entries[0];
        app.collapsed.insert(idx);
        app.refresh_entries();
        let entries_collapsed = app.entries.len();

        // l on collapsed folder expands it (doesn't navigate into)
        app.handle_key(key(KeyCode::Char('l')));
        assert!(!app.collapsed.contains(&idx));
        assert!(app.entries.len() > entries_collapsed);
        // Still at root
        assert_eq!(app.current_path(), "/");
    }

    #[test]
    fn l_on_expanded_folder_navigates_into() {
        let mut app = test_app();
        // Expand docs/ first (folders default collapsed)
        app.collapsed.remove(&app.entries[0]);
        app.refresh_entries();
        // docs/ is now expanded, l should navigate into it
        app.handle_key(key(KeyCode::Char('l')));
        assert_ne!(app.current_path(), "/");
    }

    #[test]
    fn backspace_at_root_is_noop() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.current_path(), "/");
    }

    #[test]
    fn navigate_back_restores_cursor_to_folder() {
        let mut app = test_app();
        // All collapsed: 0=docs/, 1=src/, 2=config.toml
        // Navigate to src/ (index 1) and enter it
        app.selected = 1;
        assert_eq!(app.tree.node(app.entries[1]).name, "src");
        app.handle_key(key(KeyCode::Enter)); // go into src/
        assert_eq!(app.current_path(), "/src");
        app.handle_key(key(KeyCode::Backspace)); // go back
        assert_eq!(app.current_path(), "/");
        // Cursor should land on src/ in the tree
        assert_eq!(app.tree.node(app.entries[app.selected]).name, "src");
    }

    #[test]
    fn enter_on_file_is_noop() {
        let mut app = test_app();
        // Navigate to a file entry (config.toml at index 5 in tree mode)
        app.handle_key(key(KeyCode::Char('G'))); // jump to last (index 5 = config.toml)
        assert!(!app.tree.node(app.entries[app.selected]).is_dir);
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
        assert!(app.search_results.is_empty());
    }

    #[test]
    fn search_populates_results_and_jumps() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        for c in "main.rs".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.incremental_search(); // Synchronous fallback for tests
        assert!(!app.search_results.is_empty());
        // Stays at root — ancestors expanded in-place, cursor on match
        assert_eq!(app.current_path(), "/");
        assert_eq!(app.tree.node(app.entries[app.selected]).name, "main.rs");
        // src/ should have been expanded to reveal main.rs
        let src_idx = app
            .entries
            .iter()
            .find(|&&i| app.tree.node(i).name == "src")
            .unwrap();
        assert!(!app.collapsed.contains(src_idx));
    }

    #[test]
    fn search_matches_path_not_just_name() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        // Search for "docs/readme" — matches path, not just filename
        for c in "docs/readme".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.incremental_search(); // Synchronous fallback for tests
        assert_eq!(app.search_results.len(), 1);
        // Stays at root — docs/ expanded to reveal readme.txt
        assert_eq!(app.current_path(), "/");
        assert_eq!(app.tree.node(app.entries[app.selected]).name, "readme.txt");
    }

    #[test]
    fn search_esc_restores_position() {
        let mut app = test_app();
        let orig_dir = app.current_dir;
        let orig_selected = app.selected;
        let orig_entries_len = app.entries.len(); // all collapsed = 3
        app.handle_key(key(KeyCode::Char('/')));
        for c in "main.rs".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.incremental_search(); // Synchronous fallback for tests
                                  // Search expanded src/ to reveal main.rs
        assert!(app.entries.len() > orig_entries_len);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.current_dir, orig_dir);
        assert_eq!(app.selected, orig_selected);
        assert!(app.search_query.is_empty());
        assert!(app.search_results.is_empty());
        // Collapse state restored — back to original entry count
        assert_eq!(app.entries.len(), orig_entries_len);
    }

    #[test]
    fn search_enter_confirms_position() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        for c in "main.rs".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.incremental_search(); // Synchronous fallback for tests
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.searching);
        // Stays at root with main.rs selected (src/ expanded in-place)
        assert_eq!(app.current_path(), "/");
        assert_eq!(app.search_query, "main.rs");
        assert_eq!(app.tree.node(app.entries[app.selected]).name, "main.rs");
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
    fn arrow_keys_work_during_search() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        app.handle_key(key(KeyCode::Char('a')));
        assert!(app.searching);
        assert_eq!(app.selected, 0);
        // Down arrow should move cursor even while searching
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected, 1);
        assert!(app.searching); // still in search mode
        assert_eq!(app.search_query, "a"); // query unchanged
                                           // Up arrow
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn ctrl_f_works_during_search() {
        let mut app = test_app();
        app.visible_height = 2;
        app.handle_key(key(KeyCode::Char('/')));
        app.handle_key(key(KeyCode::Char('x')));
        assert!(app.searching);
        // Ctrl-F should page down
        app.handle_key(key_ctrl('f'));
        assert_eq!(app.selected, 2); // moved by visible_height
        assert!(app.searching);
        assert_eq!(app.search_query, "x"); // query unchanged (not 'xf')
    }

    #[test]
    fn ctrl_b_works_during_search() {
        let mut app = test_app();
        app.visible_height = 2;
        app.selected = 2;
        app.handle_key(key(KeyCode::Char('/')));
        // Ctrl-B should page up
        app.handle_key(key_ctrl('b'));
        assert_eq!(app.selected, 0);
        assert!(app.searching);
    }

    #[test]
    fn n_cycles_to_next_match() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        // Search for ".txt" — matches notes.txt and readme.txt
        for c in ".txt".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.incremental_search(); // Synchronous fallback for tests
        app.handle_key(key(KeyCode::Enter)); // confirm
        assert!(app.search_results.len() >= 2);
        let first_selected = app.selected;
        app.handle_key(key(KeyCode::Char('n')));
        // Cursor should move to a different entry
        assert_ne!(app.selected, first_selected);
    }

    #[test]
    fn shift_n_cycles_to_prev_match() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        for c in ".txt".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.incremental_search(); // Synchronous fallback for tests
        app.handle_key(key(KeyCode::Enter));
        app.handle_key(key(KeyCode::Char('n'))); // go to second match
        assert_eq!(app.search_cursor, 1);
        app.handle_key(key(KeyCode::Char('N'))); // back to first
        assert_eq!(app.search_cursor, 0);
    }

    #[test]
    fn search_no_matches_stays_put() {
        let mut app = test_app();
        let orig_dir = app.current_dir;
        app.handle_key(key(KeyCode::Char('/')));
        for c in "zzzzzzz".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.incremental_search(); // Synchronous fallback for tests
        assert!(app.search_results.is_empty());
        // Should still be in original dir
        assert_eq!(app.current_dir, orig_dir);
    }

    #[test]
    fn navigate_into_dir_after_search() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        for c in "docs".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.incremental_search(); // Synchronous fallback for tests
        app.handle_key(key(KeyCode::Enter)); // confirm search
                                             // docs/ is a search result; find and navigate into it
        let docs_pos = app
            .entries
            .iter()
            .position(|&i| app.tree.node(i).is_dir && app.tree.node(i).name == "docs");
        assert!(docs_pos.is_some());
        app.selected = docs_pos.unwrap();
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.current_path(), "/docs");
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
        use issen_signatures::heuristics::anomaly::{Anomaly, AnomalyCategory};
        use issen_signatures::matching::results::Severity;

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
        assert_eq!(app.entries.len(), 2); // both files visible (flat, no subdirs)
        app.handle_key(key(KeyCode::Char('f')));
        assert_eq!(app.entries.len(), 1); // only flagged
        assert_eq!(app.tree.node(app.entries[0]).name, "flagged.exe");
    }

    // -- Collapse / expand tests ----------------------------------------------

    #[test]
    fn space_collapses_folder() {
        let mut app = test_app();
        // Folders default collapsed: docs/, src/, config.toml = 3
        assert_eq!(app.entries.len(), 3);
        // Expand docs/ first
        app.handle_key(key(KeyCode::Char(' '))); // toggle docs/ → expanded
        assert_eq!(app.entries.len(), 5); // docs/, notes.txt, readme.txt, src/, config.toml
        assert!(!app.collapsed.contains(&app.entries[0]));
        // Collapse it again
        app.handle_key(key(KeyCode::Char(' '))); // toggle docs/ → collapsed
        assert_eq!(app.entries.len(), 3);
        assert!(app.collapsed.contains(&app.entries[0]));
    }

    #[test]
    fn space_expands_collapsed_folder() {
        let mut app = test_app();
        // Folders default collapsed: 3 entries
        assert_eq!(app.entries.len(), 3);
        app.handle_key(key(KeyCode::Char(' '))); // expand docs/
        assert_eq!(app.entries.len(), 5); // docs/ + 2 children + src/ + config.toml
    }

    #[test]
    fn space_on_file_is_noop() {
        let mut app = test_app();
        // Move to config.toml (index 2 when collapsed)
        app.selected = 2;
        assert!(!app.tree.node(app.entries[2]).is_dir);
        let before = app.entries.len();
        app.handle_key(key(KeyCode::Char(' ')));
        assert_eq!(app.entries.len(), before); // no change
    }

    #[test]
    fn collapse_state_preserved_after_navigate_back() {
        let mut app = test_app();
        // All collapsed: docs/, src/, config.toml = 3
        assert_eq!(app.entries.len(), 3);
        // Expand docs/
        app.handle_key(key(KeyCode::Char(' ')));
        assert_eq!(app.entries.len(), 5);
        // Navigate into src/ (now at index 3 after expanding docs/)
        app.selected = 3;
        assert_eq!(app.tree.node(app.entries[3]).name, "src");
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.current_path(), "/src");
        // Navigate back
        app.handle_key(key(KeyCode::Backspace));
        // docs/ should still be expanded, src/ still collapsed = 5 entries
        assert_eq!(app.entries.len(), 5);
    }

    #[test]
    fn search_expands_ancestors_to_reveal_match() {
        let mut app = test_app();
        // Folders default collapsed: docs/, src/, config.toml = 3
        assert_eq!(app.entries.len(), 3);
        // Search for readme.txt (inside collapsed docs/)
        app.handle_key(key(KeyCode::Char('/')));
        for c in "readme".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.incremental_search();
        assert!(!app.search_results.is_empty());
        // Stays at root — docs/ expanded in-place to reveal readme.txt
        assert_eq!(app.current_path(), "/");
        assert_eq!(app.tree.node(app.entries[app.selected]).name, "readme.txt");
        // docs/ should be expanded now
        let docs_idx = app
            .entries
            .iter()
            .find(|&&i| app.tree.node(i).name == "docs")
            .unwrap();
        assert!(!app.collapsed.contains(docs_idx));
        // More entries visible (docs/ expanded)
        assert!(app.entries.len() > 3);
    }

    // -- Debounce / schedule tests --------------------------------------------

    #[test]
    fn schedule_search_sets_pending() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        app.handle_key(key(KeyCode::Char('a')));
        assert!(app.pending_search);
        assert!(app.last_keystroke.is_some());
    }

    #[test]
    fn fire_debounced_search_respects_timer() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        app.handle_key(key(KeyCode::Char('c')));
        // Should not fire immediately (debounce not expired)
        app.fire_debounced_search();
        assert!(app.pending_search); // still pending
    }

    #[test]
    fn enter_clears_pending_search() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        app.handle_key(key(KeyCode::Char('c')));
        assert!(app.pending_search);
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.pending_search);
    }

    #[test]
    fn esc_clears_pending_search() {
        let mut app = test_app();
        app.handle_key(key(KeyCode::Char('/')));
        app.handle_key(key(KeyCode::Char('c')));
        app.handle_key(key(KeyCode::Esc));
        assert!(!app.pending_search);
    }
}
