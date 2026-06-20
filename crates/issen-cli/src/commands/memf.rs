use std::path::Path;

use anyhow::Result;
use issen_mem::cmd_memf::{MemfArgs, MemfCommand};
use issen_mem::output::OutputFormat;

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

/// Parse a `--cr3` hex value from the CLI.
///
/// Accepts both `0x`-prefixed (e.g. `0xdeadbeef`) and bare hex (e.g. `deadbeef`).
/// Returns `Err(String)` with a human-readable message on parse failure.
pub fn parse_cr3_hex(s: &str) -> Result<u64, String> {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(hex, 16)
        .map_err(|_| format!("invalid hex address '{s}': expected e.g. 0x1a2000 or 1a2000"))
}

/// Run the `rt memf` subcommand.
pub fn run(
    dump_path: &Path,
    profile: Option<&str>,
    command: &str,
    format: &str,
    pid: Option<u32>,
    cr3: Option<u64>,
) -> Result<()> {
    let args = MemfArgs {
        dump_path: dump_path.to_path_buf(),
        profile: profile.map(str::to_string),
        command: parse_memf_command(command),
        output: parse_output_format(format),
        pid_filter: pid,
        cr3,
    };
    issen_mem::run_memf_command(&args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cr3_hex_valid_with_prefix() {
        let result = parse_cr3_hex("0x1a2b3c");
        assert_eq!(
            result,
            Ok(0x1a2b3c),
            "0x-prefixed hex should parse correctly"
        );
    }

    #[test]
    fn parse_cr3_hex_valid_bare() {
        let result = parse_cr3_hex("deadbeef");
        assert_eq!(result, Ok(0xdeadbeef), "bare hex should parse correctly");
    }

    #[test]
    fn parse_cr3_hex_invalid() {
        let result = parse_cr3_hex("not-hex");
        assert!(result.is_err(), "invalid hex should return Err");
    }
}
