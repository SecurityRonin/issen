//! WSL session detection — correlates EVTX events into session lifetimes by PID.

use std::collections::HashMap;

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
///
/// Events must be pre-sorted by timestamp (or at least: starts before stops).
/// An orphaned Stop (no preceding Start for that PID) is silently ignored.
pub fn build_sessions(events: &[SessionEvent]) -> Vec<WslSession> {
    let mut open: HashMap<u32, WslSession> = HashMap::new();
    let mut finished: Vec<WslSession> = Vec::new();

    for ev in events {
        match ev.kind {
            SessionEventKind::Start => {
                open.insert(ev.windows_pid, WslSession {
                    distro: ev.distro.clone().unwrap_or_default(),
                    windows_pid: ev.windows_pid,
                    start_ns: ev.timestamp_ns,
                    end_ns: None,
                    user: ev.user.clone(),
                });
            }
            SessionEventKind::Stop => {
                if let Some(mut session) = open.remove(&ev.windows_pid) {
                    session.end_ns = Some(ev.timestamp_ns);
                    finished.push(session);
                }
                // Orphaned stop: no open session for this PID → ignore.
            }
        }
    }

    // Remaining open sessions (no stop seen).
    finished.extend(open.into_values());
    finished.sort_by_key(|s| s.start_ns);
    finished
}
