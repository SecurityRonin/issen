pub mod alerts;
pub mod analysis;
pub mod dashboard;
pub mod data;
pub mod detail;
#[cfg(test)]
mod test_helpers;
pub mod timeline;
pub mod views;
pub mod workbench_ui;

use std::collections::HashSet;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{Action, App};
use data::InvestigationData;
use timeline::TimelineSource;

/// Which view is currently active in the workbench.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkbenchView {
    Dashboard,
    Timeline,
    MftTree,
    Network,
    Processes,
    Logins,
    Packages,
    Configs,
    Hashes,
    Chkrootkit,
}

impl WorkbenchView {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Timeline => "Timeline",
            Self::MftTree => "MFT Tree",
            Self::Network => "Network",
            Self::Processes => "Processes",
            Self::Logins => "Logins",
            Self::Packages => "Packages",
            Self::Configs => "Configs",
            Self::Hashes => "Hashes",
            Self::Chkrootkit => "Chkrootkit",
        }
    }

    /// How many items in the list for this view.
    pub fn item_count(self, data: &InvestigationData) -> usize {
        match self {
            Self::Dashboard => {
                let mut count = 0;
                if !data.timeline.is_empty() {
                    count += 1;
                }
                if !data.network.is_empty() {
                    count += 1;
                }
                if !data.processes.is_empty() {
                    count += 1;
                }
                if !data.logins.is_empty() {
                    count += 1;
                }
                if !data.packages.is_empty() {
                    count += 1;
                }
                if !data.configs.is_empty() {
                    count += 1;
                }
                if !data.hashes.is_empty() {
                    count += 1;
                }
                if !data.chkrootkit.is_empty() {
                    count += 1;
                }
                count
            }
            Self::Timeline => data.timeline.len(),
            Self::MftTree => 0,
            Self::Network => data.network.len(),
            Self::Processes => data.processes.len(),
            Self::Logins => data.logins.len(),
            Self::Packages => data.packages.len(),
            Self::Configs => data.configs.len(),
            Self::Hashes => data.hashes.len(),
            Self::Chkrootkit => data.chkrootkit.len(),
        }
    }
}

impl std::fmt::Display for WorkbenchView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Main state machine for the investigation workbench TUI.
pub struct WorkbenchApp {
    pub data: InvestigationData,
    pub available_views: Vec<WorkbenchView>,
    pub current_view_idx: usize,
    pub selected: usize,
    pub scroll_offset: usize,
    pub show_detail: bool,
    pub search_mode: bool,
    pub search_query: String,
    pub sort_ascending: bool,

    /// Supertimeline source filter (show all by default).
    pub timeline_source_filter: HashSet<TimelineSource>,
    /// Filtered timeline indices (indices into data.timeline matching current filter).
    pub filtered_timeline: Vec<usize>,

    /// Existing MFT tree app (delegation target when in MftTree view).
    pub mft_app: Option<App>,
}

impl std::fmt::Debug for WorkbenchApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkbenchApp")
            .field("view", &self.current_view().label())
            .field("views", &self.available_views.len())
            .field("selected", &self.selected)
            .field("scroll_offset", &self.scroll_offset)
            .field("search_mode", &self.search_mode)
            .field("search_query", &self.search_query)
            .field("sort_ascending", &self.sort_ascending)
            .field("filtered_timeline", &self.filtered_timeline.len())
            .field("has_mft", &self.mft_app.is_some())
            .finish()
    }
}

impl WorkbenchApp {
    /// Create a new workbench from parsed investigation data and optional MFT app.
    pub fn new(data: InvestigationData, mft_app: Option<App>) -> Self {
        let mut available_views = vec![WorkbenchView::Dashboard];

        if !data.timeline.is_empty() {
            available_views.push(WorkbenchView::Timeline);
        }
        if mft_app.is_some() {
            available_views.push(WorkbenchView::MftTree);
        }
        if !data.network.is_empty() {
            available_views.push(WorkbenchView::Network);
        }
        if !data.processes.is_empty() {
            available_views.push(WorkbenchView::Processes);
        }
        if !data.logins.is_empty() {
            available_views.push(WorkbenchView::Logins);
        }
        if !data.packages.is_empty() {
            available_views.push(WorkbenchView::Packages);
        }
        if !data.configs.is_empty() {
            available_views.push(WorkbenchView::Configs);
        }
        if !data.hashes.is_empty() {
            available_views.push(WorkbenchView::Hashes);
        }
        if !data.chkrootkit.is_empty() {
            available_views.push(WorkbenchView::Chkrootkit);
        }

        let filter: HashSet<TimelineSource> = TimelineSource::all().iter().copied().collect();
        let filtered_timeline: Vec<usize> = (0..data.timeline.len()).collect();

        Self {
            data,
            available_views,
            current_view_idx: 0,
            selected: 0,
            scroll_offset: 0,
            show_detail: true,
            search_mode: false,
            search_query: String::new(),
            sort_ascending: true,
            timeline_source_filter: filter,
            filtered_timeline,
            mft_app,
        }
    }

    pub fn current_view(&self) -> WorkbenchView {
        self.available_views[self.current_view_idx]
    }

    /// Number of items in the currently active view (respecting filters).
    pub fn current_item_count(&self) -> usize {
        if self.current_view() == WorkbenchView::Timeline {
            self.filtered_timeline.len()
        } else {
            self.current_view().item_count(&self.data)
        }
    }

    /// Handle a key event. Returns `Action::Quit` to exit.
    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        // If in MftTree view, delegate (except Tab/Esc)
        if self.current_view() == WorkbenchView::MftTree {
            match key.code {
                KeyCode::Tab => self.next_view(),
                KeyCode::BackTab => self.prev_view(),
                KeyCode::Esc => self.go_to_dashboard(),
                _ => {
                    if let Some(ref mut mft) = self.mft_app {
                        return mft.handle_key(key);
                    }
                }
            }
            return Action::Continue;
        }

        // Search mode input
        if self.search_mode {
            match key.code {
                KeyCode::Esc => {
                    self.search_mode = false;
                    self.search_query.clear();
                }
                KeyCode::Enter => {
                    self.search_mode = false;
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                }
                _ => {}
            }
            return Action::Continue;
        }

        // Normal mode
        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Tab => self.next_view(),
            KeyCode::BackTab => self.prev_view(),
            KeyCode::Esc => self.go_to_dashboard(),
            KeyCode::Char('j') | KeyCode::Down => self.move_down(),
            KeyCode::Char('k') | KeyCode::Up => self.move_up(),
            KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::NONE) => {
                self.selected = 0;
                self.scroll_offset = 0;
            }
            KeyCode::Char('G') => {
                let count = self.current_item_count();
                if count > 0 {
                    self.selected = count - 1;
                }
            }
            KeyCode::Enter => self.handle_enter(),
            KeyCode::Char('/') => {
                self.search_mode = true;
                self.search_query.clear();
            }
            KeyCode::Char('s') => {
                self.sort_ascending = !self.sort_ascending;
            }
            KeyCode::Char('f') => {
                if self.current_view() == WorkbenchView::Timeline {
                    self.cycle_timeline_filter();
                }
            }
            KeyCode::Char(c) if c.is_ascii_digit() => {
                let idx = (c as u8 - b'0') as usize;
                if idx > 0 && idx <= self.available_views.len() {
                    self.switch_to_view(idx - 1);
                }
            }
            _ => {}
        }

        Action::Continue
    }

    fn next_view(&mut self) {
        self.current_view_idx = (self.current_view_idx + 1) % self.available_views.len();
        self.reset_cursor();
    }

    fn prev_view(&mut self) {
        if self.current_view_idx == 0 {
            self.current_view_idx = self.available_views.len() - 1;
        } else {
            self.current_view_idx -= 1;
        }
        self.reset_cursor();
    }

    fn switch_to_view(&mut self, idx: usize) {
        if idx < self.available_views.len() {
            self.current_view_idx = idx;
            self.reset_cursor();
        }
    }

    fn go_to_dashboard(&mut self) {
        self.current_view_idx = 0;
        self.reset_cursor();
    }

    fn reset_cursor(&mut self) {
        self.selected = 0;
        self.scroll_offset = 0;
        self.search_mode = false;
        self.search_query.clear();
    }

    fn move_down(&mut self) {
        let count = self.current_item_count();
        if count > 0 && self.selected < count - 1 {
            self.selected += 1;
        }
    }

    fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn handle_enter(&mut self) {
        if self.current_view() == WorkbenchView::Dashboard {
            let target_idx = self.selected + 1;
            if target_idx < self.available_views.len() {
                self.switch_to_view(target_idx);
            }
        } else {
            self.show_detail = !self.show_detail;
        }
    }

    fn cycle_timeline_filter(&mut self) {
        use TimelineSource::*;
        let cycle: [Option<TimelineSource>; 7] = [
            None, // All sources
            Some(Bodyfile),
            Some(MftSi),
            Some(MftFn),
            Some(UsnJournal),
            Some(LoginHistory),
            Some(ProcessList),
        ];

        let current_single = if self.timeline_source_filter.len() == 1 {
            self.timeline_source_filter.iter().next().copied()
        } else {
            None
        };

        let current_idx = cycle.iter().position(|&c| c == current_single).unwrap_or(0);
        let next_idx = (current_idx + 1) % cycle.len();

        match cycle[next_idx] {
            None => self.timeline_source_filter = TimelineSource::all().iter().copied().collect(),
            Some(src) => {
                self.timeline_source_filter.clear();
                self.timeline_source_filter.insert(src);
            }
        }

        self.rebuild_filtered_timeline();
        self.selected = 0;
        self.scroll_offset = 0;
    }

    fn rebuild_filtered_timeline(&mut self) {
        self.filtered_timeline = self
            .data
            .timeline
            .iter()
            .enumerate()
            .filter(|(_, e)| self.timeline_source_filter.contains(&e.source))
            .map(|(i, _)| i)
            .collect();
    }

    /// Get the filter label for the supertimeline view header.
    pub fn timeline_filter_label(&self) -> &'static str {
        if self.timeline_source_filter.len() > 1 {
            "All sources"
        } else if let Some(src) = self.timeline_source_filter.iter().next() {
            src.label()
        } else {
            "None"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data::InvestigationData;
    use timeline::{TimelineEvent, TimelineSource, TimestampType};

    fn make_test_data(n_timeline: usize, n_network: usize) -> InvestigationData {
        let timeline: Vec<TimelineEvent> = (0..n_timeline)
            .map(|i| TimelineEvent {
                timestamp: i as i64 * 100,
                timestamp_type: TimestampType::Modified,
                source: TimelineSource::Bodyfile,
                path: format!("/file{i}"),
                description: String::new(),
                extra: String::new(),
            })
            .collect();

        let network = (0..n_network)
            .map(|_| issen_parser_uac::parsers::network::NetworkConnection {
                protocol: "tcp".to_string(),
                local_addr: String::new(),
                remote_addr: String::new(),
                state: String::new(),
                pid: None,
                program: None,
            })
            .collect();

        InvestigationData {
            timeline,
            network,
            ..Default::default()
        }
    }

    #[test]
    fn test_available_views_dashboard_always_present() {
        let app = WorkbenchApp::new(make_test_data(0, 0), None);
        assert_eq!(app.available_views, vec![WorkbenchView::Dashboard]);
    }

    #[test]
    fn test_available_views_with_data() {
        let app = WorkbenchApp::new(make_test_data(10, 5), None);
        assert!(app.available_views.contains(&WorkbenchView::Timeline));
        assert!(app.available_views.contains(&WorkbenchView::Network));
        assert!(!app.available_views.contains(&WorkbenchView::MftTree));
    }

    #[test]
    fn test_view_cycling() {
        let mut app = WorkbenchApp::new(make_test_data(10, 5), None);
        assert_eq!(app.current_view(), WorkbenchView::Dashboard);
        app.next_view();
        assert_eq!(app.current_view(), WorkbenchView::Timeline);
        app.next_view();
        assert_eq!(app.current_view(), WorkbenchView::Network);
        app.next_view();
        assert_eq!(app.current_view(), WorkbenchView::Dashboard); // wraps
    }

    #[test]
    fn test_go_to_dashboard() {
        let mut app = WorkbenchApp::new(make_test_data(10, 5), None);
        app.next_view();
        app.next_view();
        app.go_to_dashboard();
        assert_eq!(app.current_view(), WorkbenchView::Dashboard);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_cursor_movement() {
        let mut app = WorkbenchApp::new(make_test_data(10, 0), None);
        app.next_view(); // go to Timeline
        assert_eq!(app.selected, 0);
        app.move_down();
        assert_eq!(app.selected, 1);
        app.move_down();
        assert_eq!(app.selected, 2);
        app.move_up();
        assert_eq!(app.selected, 1);
        app.move_up();
        assert_eq!(app.selected, 0);
        app.move_up(); // can't go below 0
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_quit_key() {
        let mut app = WorkbenchApp::new(make_test_data(0, 0), None);
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(app.handle_key(key), Action::Quit);
    }

    #[test]
    fn test_mft_tree_view_available_when_mft_app_present() {
        use issen_mft_tree::tree::FileTree;
        use issen_signatures::heuristics::AnomalyIndex;

        let tree = FileTree::test_single_node("test.exe");
        let mft_app = crate::app::App::new(tree, AnomalyIndex::new()).unwrap();
        let app = WorkbenchApp::new(make_test_data(0, 0), Some(mft_app));
        assert!(app.available_views.contains(&WorkbenchView::MftTree));
    }

    #[test]
    fn test_timeline_filter_cycle() {
        let mut app = WorkbenchApp::new(make_test_data(10, 0), None);
        app.next_view(); // Timeline
        assert_eq!(app.timeline_filter_label(), "All sources");
        app.cycle_timeline_filter();
        assert_eq!(app.timeline_filter_label(), "bodyfile");
        app.cycle_timeline_filter();
        assert_eq!(app.timeline_filter_label(), "MFT-SI");
    }

    #[test]
    fn test_enter_on_dashboard_navigates_to_view() {
        let mut app = WorkbenchApp::new(make_test_data(10, 5), None);
        assert_eq!(app.current_view(), WorkbenchView::Dashboard);
        app.selected = 0; // First dashboard item
        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        app.handle_key(key);
        // Should have moved to first non-dashboard view
        assert_ne!(app.current_view(), WorkbenchView::Dashboard);
    }

    #[test]
    fn test_search_mode_captures_chars() {
        let mut app = WorkbenchApp::new(make_test_data(10, 5), None);
        // Enter search mode with '/'
        let slash = KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE);
        app.handle_key(slash);
        assert!(app.search_mode);
        assert!(app.search_query.is_empty());

        // Type characters to build query
        let key_a = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        let key_b = KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE);
        let key_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE);
        app.handle_key(key_a);
        app.handle_key(key_b);
        app.handle_key(key_c);
        assert_eq!(app.search_query, "abc");
        assert!(app.search_mode);

        // Esc exits search mode and clears query
        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        app.handle_key(esc);
        assert!(!app.search_mode);
        assert!(app.search_query.is_empty());
    }

    #[test]
    fn test_number_key_switches_view() {
        let mut app = WorkbenchApp::new(make_test_data(10, 5), None);
        // '1' goes to view index 0 (Dashboard)
        let key_1 = KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE);
        app.handle_key(key_1);
        assert_eq!(app.current_view_idx, 0);

        // '2' goes to view index 1 (Timeline)
        let key_2 = KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE);
        app.handle_key(key_2);
        assert_eq!(app.current_view_idx, 1);
        assert_eq!(app.current_view(), WorkbenchView::Timeline);

        // '3' goes to view index 2 (Network)
        let key_3 = KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE);
        app.handle_key(key_3);
        assert_eq!(app.current_view_idx, 2);
        assert_eq!(app.current_view(), WorkbenchView::Network);
    }

    #[test]
    fn test_sort_toggle() {
        let mut app = WorkbenchApp::new(make_test_data(10, 5), None);
        assert!(app.sort_ascending); // default
        let key_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE);
        app.handle_key(key_s);
        assert!(!app.sort_ascending);
        app.handle_key(key_s);
        assert!(app.sort_ascending);
    }

    #[test]
    fn test_cursor_bounds_at_end() {
        let mut app = WorkbenchApp::new(make_test_data(10, 0), None);
        app.next_view(); // Timeline with 10 items
                         // Move to last item
        for _ in 0..20 {
            app.move_down();
        }
        assert_eq!(app.selected, 9); // last item (0-indexed)
                                     // Moving down again stays at last
        app.move_down();
        assert_eq!(app.selected, 9);
    }

    #[test]
    fn test_g_key_goes_to_top() {
        let mut app = WorkbenchApp::new(make_test_data(10, 0), None);
        app.next_view(); // Timeline
        app.selected = 7;
        let key_g = KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE);
        app.handle_key(key_g);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_shift_g_goes_to_bottom() {
        let mut app = WorkbenchApp::new(make_test_data(10, 0), None);
        app.next_view(); // Timeline with 10 items
        assert_eq!(app.selected, 0);
        let key_shift_g = KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE);
        app.handle_key(key_shift_g);
        assert_eq!(app.selected, 9);
    }

    #[test]
    fn test_prev_view_wraps() {
        let mut app = WorkbenchApp::new(make_test_data(10, 5), None);
        assert_eq!(app.current_view(), WorkbenchView::Dashboard);
        assert_eq!(app.current_view_idx, 0);
        // prev_view from dashboard should wrap to last view
        app.prev_view();
        assert_eq!(app.current_view_idx, app.available_views.len() - 1);
        assert_ne!(app.current_view(), WorkbenchView::Dashboard);
    }

    #[test]
    fn workbench_view_display() {
        assert_eq!(format!("{}", WorkbenchView::Dashboard), "Dashboard");
        assert_eq!(format!("{}", WorkbenchView::Timeline), "Timeline");
        assert_eq!(format!("{}", WorkbenchView::MftTree), "MFT Tree");
    }

    #[test]
    fn workbench_app_debug_shows_state() {
        let app = WorkbenchApp::new(make_test_data(10, 5), None);
        let debug = format!("{app:?}");
        assert!(debug.contains("WorkbenchApp"));
        assert!(debug.contains("view: \"Dashboard\""));
        assert!(debug.contains("selected: 0"));
    }
}
