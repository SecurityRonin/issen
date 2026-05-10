//! RED tests for WslSession — correlating EVTX events into WSL sessions.

use issen_wsl::session::{WslSession, build_sessions, SessionEvent, SessionEventKind};

fn make_event(kind: SessionEventKind, ts_ns: i64, pid: u32, distro: Option<&str>) -> SessionEvent {
    SessionEvent {
        kind,
        timestamp_ns: ts_ns,
        windows_pid: pid,
        distro: distro.map(str::to_string),
        user: None,
    }
}

// ── Test 1: single start+stop → one session ───────────────────────────────────

#[test]
fn single_start_stop_one_session() {
    let events = vec![
        make_event(SessionEventKind::Start, 1_000_000_000, 100, Some("Ubuntu")),
        make_event(SessionEventKind::Stop,  2_000_000_000, 100, Some("Ubuntu")),
    ];
    let sessions = build_sessions(&events);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].distro, "Ubuntu");
    assert_eq!(sessions[0].windows_pid, 100);
    assert_eq!(sessions[0].start_ns, 1_000_000_000);
    assert_eq!(sessions[0].end_ns, Some(2_000_000_000));
}

// ── Test 2: start with no stop → open session ────────────────────────────────

#[test]
fn start_without_stop_is_open() {
    let events = vec![
        make_event(SessionEventKind::Start, 1_000_000_000, 42, Some("Debian")),
    ];
    let sessions = build_sessions(&events);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].end_ns, None, "unclosed session should have end_ns=None");
}

// ── Test 3: two sessions, different PIDs ──────────────────────────────────────

#[test]
fn two_pids_two_sessions() {
    let events = vec![
        make_event(SessionEventKind::Start, 1_000, 10, Some("Ubuntu")),
        make_event(SessionEventKind::Start, 2_000, 20, Some("Debian")),
        make_event(SessionEventKind::Stop,  3_000, 10, None),
        make_event(SessionEventKind::Stop,  4_000, 20, None),
    ];
    let sessions = build_sessions(&events);
    assert_eq!(sessions.len(), 2);
    let ubuntu = sessions.iter().find(|s| s.distro == "Ubuntu").expect("Ubuntu session");
    let debian  = sessions.iter().find(|s| s.distro == "Debian").expect("Debian session");
    assert_eq!(ubuntu.end_ns, Some(3_000));
    assert_eq!(debian.end_ns, Some(4_000));
}

// ── Test 4: stop event without preceding start is ignored ─────────────────────

#[test]
fn orphan_stop_ignored() {
    let events = vec![
        make_event(SessionEventKind::Stop, 1_000, 99, None),
    ];
    let sessions = build_sessions(&events);
    assert!(sessions.is_empty(), "orphan stop should produce no session");
}

// ── Test 5: distro propagated from start event ───────────────────────────────

#[test]
fn distro_from_start_event() {
    let events = vec![
        make_event(SessionEventKind::Start, 1_000, 7, Some("kali-linux")),
        make_event(SessionEventKind::Stop,  2_000, 7, None),
    ];
    let sessions = build_sessions(&events);
    assert_eq!(sessions[0].distro, "kali-linux");
}

// ── Test 6: session duration is end - start ──────────────────────────────────

#[test]
fn session_duration() {
    let events = vec![
        make_event(SessionEventKind::Start, 1_000_000_000, 1, Some("Ubuntu")),
        make_event(SessionEventKind::Stop,  4_000_000_000, 1, None),
    ];
    let sessions = build_sessions(&events);
    assert_eq!(sessions[0].duration_ns(), Some(3_000_000_000));
}

// ── Test 7: open session has no duration ─────────────────────────────────────

#[test]
fn open_session_no_duration() {
    let events = vec![
        make_event(SessionEventKind::Start, 1_000, 1, Some("Ubuntu")),
    ];
    let sessions = build_sessions(&events);
    assert_eq!(sessions[0].duration_ns(), None);
}

// ── Test 8: empty events → no sessions ───────────────────────────────────────

#[test]
fn empty_events_no_sessions() {
    let sessions = build_sessions(&[]);
    assert!(sessions.is_empty());
}
