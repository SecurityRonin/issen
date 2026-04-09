use std::path::PathBuf;

use anyhow::Result;
use rt_memf::cmd_memf::{MemfArgs, MemfCommand};
use rt_memf::output::OutputFormat;

/// Parse the CLI `--format` string into an [`OutputFormat`].
fn parse_output_format(s: &str) -> OutputFormat {
    match s.to_ascii_lowercase().as_str() {
        "json" => OutputFormat::Json,
        "bodyfile" => OutputFormat::Bodyfile,
        _ => OutputFormat::Text,
    }
}

/// Parse the CLI `--command` string into a [`MemfCommand`].
fn parse_memf_command(s: &str) -> MemfCommand {
    match s.to_ascii_lowercase().as_str() {
        "ps" => MemfCommand::Ps,
        "modules" => MemfCommand::Modules,
        "netstat" => MemfCommand::Netstat,
        "check" => MemfCommand::Check,
        "timeline" => MemfCommand::Timeline,
        "scan" => MemfCommand::Scan,
        "creds" => MemfCommand::Creds,
        _ => MemfCommand::All,
    }
}

/// Run the `rt memf` subcommand.
pub fn run(
    dump_path: &PathBuf,
    profile: Option<&str>,
    command: &str,
    format: &str,
    pid: Option<u32>,
) -> Result<()> {
    let args = MemfArgs {
        dump_path: dump_path.clone(),
        profile: profile.map(str::to_string),
        command: parse_memf_command(command),
        output: parse_output_format(format),
        pid_filter: pid,
    };
    rt_memf::run_memf_command(&args)
}
