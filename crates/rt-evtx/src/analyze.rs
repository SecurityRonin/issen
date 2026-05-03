/// Summary of frequency analysis results.
#[derive(Debug, Default)]
pub struct EvtxAnalysisSummary {
    pub rare_processes: Vec<String>,
    pub total_events_analyzed: usize,
}
