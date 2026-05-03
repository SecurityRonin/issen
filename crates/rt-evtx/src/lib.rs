pub mod analyze;
pub mod session;

pub use analyze::EvtxAnalysisSummary;
pub use session::EvtxSessionSummary;

/// Find all .evtx files under `dir` recursively.
pub fn find_evtx_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    todo!()
}

/// Parse EVTX files and run session correlation.
pub fn analyse_evtx_sessions(
    evtx_files: &[std::path::PathBuf],
) -> anyhow::Result<EvtxSessionSummary> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── find_evtx_files tests ─────────────────────────────────────────────

    #[test]
    fn find_evtx_files_returns_empty_for_empty_dir() {
        let dir = TempDir::new().expect("tmpdir");
        let result = find_evtx_files(dir.path());
        assert!(result.is_empty(), "expected empty vec for empty dir");
    }

    #[test]
    fn find_evtx_files_finds_evtx_extension() {
        let dir = TempDir::new().expect("tmpdir");
        std::fs::write(dir.path().join("Security.evtx"), b"").expect("write file");
        let result = find_evtx_files(dir.path());
        assert_eq!(result.len(), 1, "expected 1 evtx file, got {}", result.len());
    }

    #[test]
    fn find_evtx_files_ignores_non_evtx() {
        let dir = TempDir::new().expect("tmpdir");
        std::fs::write(dir.path().join("system.log"), b"").expect("write log");
        std::fs::write(dir.path().join("Security.evtx"), b"").expect("write evtx");
        let result = find_evtx_files(dir.path());
        assert_eq!(result.len(), 1, "should only find .evtx files");
        assert!(
            result[0].extension().map(|e| e == "evtx").unwrap_or(false),
            "found file has wrong extension"
        );
    }

    // ── analyse_evtx_sessions tests ──────────────────────────────────────

    #[test]
    fn analyse_evtx_sessions_returns_ok_for_empty_slice() {
        let result = analyse_evtx_sessions(&[]);
        assert!(result.is_ok(), "empty slice should return Ok");
    }

    // ── EvtxSessionSummary struct tests ───────────────────────────────────

    #[test]
    fn session_summary_has_session_count() {
        let summary = EvtxSessionSummary {
            session_count: 3,
            ..Default::default()
        };
        assert_eq!(summary.session_count, 3);
    }

    #[test]
    fn session_summary_has_lateral_movement_count() {
        let summary = EvtxSessionSummary {
            lateral_movement_count: 2,
            ..Default::default()
        };
        assert_eq!(summary.lateral_movement_count, 2);
    }

    // ── EvtxAnalysisSummary struct tests ──────────────────────────────────

    #[test]
    fn analysis_summary_has_rare_processes() {
        let summary = EvtxAnalysisSummary {
            rare_processes: vec!["suspicious.exe".to_string()],
            ..Default::default()
        };
        assert_eq!(summary.rare_processes.len(), 1);
        assert_eq!(summary.rare_processes[0], "suspicious.exe");
    }
}
