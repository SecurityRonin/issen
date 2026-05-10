//! WSL session detection — correlates EVTX events into session lifetimes.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEventKind {
    Start,
    Stop,
}

#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub kind: SessionEventKind,
    pub timestamp_ns: i64,
    pub windows_pid: u32,
    pub distro: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WslSession {
    pub distro: String,
    pub windows_pid: u32,
    pub start_ns: i64,
    pub end_ns: Option<i64>,
    pub user: Option<String>,
}

impl WslSession {
    pub fn duration_ns(&self) -> Option<i64> {
        self.end_ns.map(|end| end - self.start_ns)
    }
}

/// Correlate a slice of `SessionEvent`s into `WslSession`s by PID.
pub fn build_sessions(_events: &[SessionEvent]) -> Vec<WslSession> {
    todo!("implement build_sessions")
}
