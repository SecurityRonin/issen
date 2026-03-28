pub mod alerts;
pub mod data;
pub mod timeline;

use std::collections::HashSet;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{Action, App};
use data::InvestigationData;
use timeline::TimelineSource;

/// Which view is currently active in the workbench.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl WorkbenchApp {
    /// Create a new workbench from parsed investigation data and optional MFT app.
    pub fn new(data: InvestigationData, mft_app: Option<App>) -> Self {
        let mut available_views = vec![WorkbenchView::Dashboard];

        if !data.timeline.is_empty() {
            available_views.push(WorkbenchView::Timeline);
        }
        if data.mft_tree.is_some() {
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
    use data::{CollectionMetadata, InvestigationData};
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
            .map(|_| rt_parser_uac::parsers::network::NetworkConnection {
                protocol: "tcp".to_string(),
                local_addr: String::new(),
                remote_addr: String::new(),
                state: String::new(),
                pid: None,
                program: None,
            })
            .collect();

        InvestigationData {
            metadata: CollectionMetadata::default(),
            alerts: Vec::new(),
            timeline,
            mft_tree: None,
            anomaly_index: None,
            network,
            processes: Vec::new(),
            crontabs: Vec::new(),
            logins: Vec::new(),
            packages: Vec::new(),
            hashes: Vec::new(),
            chkrootkit: Vec::new(),
            configs: Vec::new(),
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
    fn test_timeline_filter_cycle() {
        let mut app = WorkbenchApp::new(make_test_data(10, 0), None);
        app.next_view(); // Timeline
        assert_eq!(app.timeline_filter_label(), "All sources");
        app.cycle_timeline_filter();
        assert_eq!(app.timeline_filter_label(), "bodyfile");
        app.cycle_timeline_filter();
        assert_eq!(app.timeline_filter_label(), "MFT-SI");
    }
}
