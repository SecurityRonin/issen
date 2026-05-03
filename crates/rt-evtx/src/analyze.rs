//! Frequency analysis and aggregation for Windows Event Log forensics.

use std::collections::HashMap;
use winevt_core::{EvtxEvent, LogonSession};

/// Summary of frequency analysis results.
#[derive(Debug, Default)]
pub struct EvtxAnalysisSummary {
    pub rare_processes: Vec<String>,
    pub total_events_analyzed: usize,
}

/// Key to group events by for frequency analysis.
#[derive(Debug, Clone, Copy)]
pub enum FrequencyKey {
    /// Group by `data["CommandLine"]`.
    CommandLine,
    /// Group by `data["NewProcessName"]`.
    ProcessImage,
    /// Group by `data["TargetUserName"]`.
    Username,
}

/// A frequency anomaly: a value that appeared at most `cap` times.
#[derive(Debug, Clone)]
pub struct FrequencyAnomaly {
    pub key: String,
    pub count: usize,
    pub events: Vec<i64>,
}

/// Frequency analysis: events whose group-by key appears at most `cap` times
/// are returned as anomalies. Port of Events Ripper posh600.pl cap=5 logic.
pub fn frequency_analysis(
    events: &[EvtxEvent],
    group_by: FrequencyKey,
    cap: usize,
) -> Vec<FrequencyAnomaly> {
    let data_key = match group_by {
        FrequencyKey::CommandLine => "CommandLine",
        FrequencyKey::ProcessImage => "NewProcessName",
        FrequencyKey::Username => "TargetUserName",
    };

    // Count occurrences and collect timestamps per key value
    let mut groups: HashMap<String, Vec<i64>> = HashMap::new();
    for ev in events {
        if let Some(val) = ev.data.get(data_key) {
            if !val.is_empty() {
                groups
                    .entry(val.clone())
                    .or_default()
                    .push(ev.timestamp_ns);
            }
        }
    }

    groups
        .into_iter()
        .filter(|(_, ts)| ts.len() <= cap)
        .map(|(key, events)| FrequencyAnomaly {
            count: events.len(),
            key,
            events,
        })
        .collect()
}

/// Pivot table: group sessions by source IP for lateral movement analysis.
pub fn pivot_sessions_by_src_ip<'a>(
    sessions: &'a [LogonSession],
) -> HashMap<String, Vec<&'a LogonSession>> {
    let mut result: HashMap<String, Vec<&'a LogonSession>> = HashMap::new();
    for s in sessions {
        let ip = s
            .src_ip
            .as_deref()
            .unwrap_or("(unknown)")
            .to_string();
        result.entry(ip).or_default().push(s);
    }
    result
}
