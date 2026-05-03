use winevt_core::LogonSession;
use winevt_session::LateralMovementFinding;

/// Summary of session correlation results.
#[derive(Debug, Default)]
pub struct EvtxSessionSummary {
    pub session_count: usize,
    pub lateral_movement_count: usize,
    pub sessions: Vec<LogonSession>,
    pub lateral_movements: Vec<LateralMovementFinding>,
}
