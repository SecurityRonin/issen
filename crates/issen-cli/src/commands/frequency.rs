//! `issen frequency` — rare-event frequency analysis over EVTX files.

use std::path::PathBuf;

use issen_evtx::{
    analyze::{frequency_analysis, FrequencyAnomaly, FrequencyKey},
    find_evtx_files, parse_evtx_to_events,
};

/// Run frequency analysis against EVTX files from `dirs` and explicit `files`.
///
/// Groups events by `key` and reports entries whose key appears at most `cap`
/// times — a port of the Events Ripper posh600.pl technique.
///
/// Returns `Ok(())` even when no EVTX files are found.
#[allow(clippy::unnecessary_wraps)] // Result<()> matches the command-dispatch signature
pub fn run(
    dirs: &[PathBuf],
    files: &[PathBuf],
    cap: usize,
    key: FrequencyKey,
    json: bool,
) -> anyhow::Result<()> {
    let mut evtx_files: Vec<PathBuf> = Vec::new();

    for dir in dirs {
        evtx_files.extend(find_evtx_files(dir));
    }
    for file in files {
        if file.exists() {
            evtx_files.push(file.clone());
        }
    }

    let events = parse_evtx_to_events(&evtx_files);
    let total_analyzed = events.len();
    let mut anomalies = frequency_analysis(&events, key, cap);
    anomalies.sort_by_key(|a| a.count);

    if json {
        print_json(&anomalies, total_analyzed);
    } else {
        print_summary(&anomalies, total_analyzed);
    }

    Ok(())
}

fn print_json(anomalies: &[FrequencyAnomaly], total_analyzed: usize) {
    let arr: Vec<serde_json::Value> = anomalies
        .iter()
        .map(|a| {
            serde_json::json!({
                "key": a.key,
                "count": a.count,
                "timestamps_ns": a.events,
            })
        })
        .collect();

    let out = serde_json::json!({
        "anomalies": arr,
        "total_analyzed": total_analyzed,
    });
    // Serializing an in-memory `json!` value is infallible; `expect` documents
    // that and satisfies the `unwrap_used = deny` lint.
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serialize JSON value")
    );
}

fn print_summary(anomalies: &[FrequencyAnomaly], total_analyzed: usize) {
    println!("Events analyzed: {total_analyzed}");
    println!("Rare entries ({}):", anomalies.len());
    for a in anomalies {
        println!("  [{}x]  {}", a.count, a.key);
    }
}

/// Parse a `--key` CLI string into `FrequencyKey`.
pub fn parse_key(s: &str) -> Result<FrequencyKey, String> {
    match s.to_ascii_lowercase().as_str() {
        "cmdline" | "commandline" | "process" => Ok(FrequencyKey::CommandLine),
        "image" | "processimage" | "exe" => Ok(FrequencyKey::ProcessImage),
        "user" | "username" => Ok(FrequencyKey::Username),
        other => Err(format!(
            "unknown key '{other}'; valid: cmdline, image, user"
        )),
    }
}
