use std::path::PathBuf;

use anyhow::Context;

use crate::open::detect_format;
use crate::output::{print_table, OutputFormat};

/// The memory forensic sub-command to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemfCommand {
    /// Enumerate running processes (walk_processes).
    Ps,
    /// Enumerate loaded kernel modules / drivers.
    Modules,
    /// Enumerate active network connections.
    Netstat,
    /// Run all hook / rootkit integrity checks.
    Check,
    /// Dump all timestamped events into a bodyfile-compatible timeline.
    Timeline,
    /// Pool scanner / malfind injection detector.
    Scan,
    /// Extract credential material (hashes, tickets, keys).
    Creds,
    /// Run every sub-command above in sequence.
    All,
}

impl std::fmt::Display for MemfCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ps => write!(f, "ps"),
            Self::Modules => write!(f, "modules"),
            Self::Netstat => write!(f, "netstat"),
            Self::Check => write!(f, "check"),
            Self::Timeline => write!(f, "timeline"),
            Self::Scan => write!(f, "scan"),
            Self::Creds => write!(f, "creds"),
            Self::All => write!(f, "all"),
        }
    }
}

/// Arguments for the `memf` command.
pub struct MemfArgs {
    /// Path to the memory dump file.
    pub dump_path: PathBuf,
    /// Optional ISF JSON symbol profile path, or `"auto"` to auto-detect.
    pub profile: Option<String>,
    /// Sub-command to execute.
    pub command: MemfCommand,
    /// Output format.
    pub output: OutputFormat,
    /// Optional PID filter (process-level commands only).
    pub pid_filter: Option<u32>,
}

/// Execute the requested memory forensic command.
///
/// # Errors
///
/// Returns an error if the dump file does not exist, cannot be read, or the
/// requested operation fails.
pub fn run_memf_command(args: &MemfArgs) -> anyhow::Result<()> {
    // Verify the dump file exists before doing anything else.
    if !args.dump_path.exists() {
        anyhow::bail!("dump file not found: {}", args.dump_path.display());
    }

    let fmt = detect_format(&args.dump_path)
        .with_context(|| format!("detecting format of {}", args.dump_path.display()))?;

    eprintln!(
        "[rt-memf] dump={} format={fmt} command={}",
        args.dump_path.display(),
        args.command,
    );

    // Dispatch — the memf-linux / memf-windows walkers require kernel symbol
    // resolution (ISF / BTF / PDB) which is wired up in the walker crates.
    // For now we emit a structured placeholder that exercises the output
    // pipeline so integration tests can verify formatting, and the actual
    // walker calls can be added incrementally without changing the interface.
    let headers: &[&str] = match args.command {
        MemfCommand::Ps => &["PID", "PPID", "Name", "State"],
        MemfCommand::Modules => &["Base", "Size", "Name", "Path"],
        MemfCommand::Netstat => &["Proto", "Local", "Remote", "State", "PID"],
        MemfCommand::Check => &["Check", "Status", "Detail"],
        MemfCommand::Timeline => &["Time", "Event", "Detail"],
        MemfCommand::Scan => &["Offset", "Tag", "Size", "Detail"],
        MemfCommand::Creds => &["Type", "User", "Hash"],
        MemfCommand::All => &["Command", "Status"],
    };

    let rows: Vec<Vec<String>> = if args.command == MemfCommand::All {
        // For "all" emit a row per sub-command showing it was dispatched.
        [
            MemfCommand::Ps,
            MemfCommand::Modules,
            MemfCommand::Netstat,
            MemfCommand::Check,
            MemfCommand::Timeline,
            MemfCommand::Scan,
            MemfCommand::Creds,
        ]
        .iter()
        .map(|cmd| vec![cmd.to_string(), "dispatched".into()])
        .collect()
    } else {
        // Placeholder — real walker data will replace this.
        vec![vec![
            format!(
                "(no data — walker for {fmt}/{} not yet wired)",
                args.command
            ),
            String::new(),
        ][..headers.len().min(2)]
            .to_vec()]
    };

    print_table(headers, &rows, args.output);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn missing_file_args(cmd: MemfCommand) -> MemfArgs {
        MemfArgs {
            dump_path: PathBuf::from("/nonexistent/does_not_exist.lime"),
            profile: None,
            command: cmd,
            output: OutputFormat::Text,
            pid_filter: None,
        }
    }

    #[test]
    fn memf_command_ps_on_missing_file_returns_error() {
        let args = missing_file_args(MemfCommand::Ps);
        let result = run_memf_command(&args);
        assert!(result.is_err(), "expected error for missing dump file");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("dump file not found"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn memf_command_all_on_missing_file_returns_error() {
        let args = missing_file_args(MemfCommand::All);
        let result = run_memf_command(&args);
        assert!(result.is_err());
    }

    #[test]
    fn memf_command_all_variants_are_display() {
        // Ensure every variant has a Display impl (compilation check +
        // spot-check a few values).
        assert_eq!(MemfCommand::Ps.to_string(), "ps");
        assert_eq!(MemfCommand::Modules.to_string(), "modules");
        assert_eq!(MemfCommand::Netstat.to_string(), "netstat");
        assert_eq!(MemfCommand::Check.to_string(), "check");
        assert_eq!(MemfCommand::Timeline.to_string(), "timeline");
        assert_eq!(MemfCommand::Scan.to_string(), "scan");
        assert_eq!(MemfCommand::Creds.to_string(), "creds");
        assert_eq!(MemfCommand::All.to_string(), "all");
    }

    #[test]
    fn memf_command_runs_on_existing_lime_dump() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // Write LiME magic + padding.
        f.write_all(&[0x45, 0x4D, 0x69, 0x4C, 0x00, 0x00, 0x00, 0x01])
            .unwrap();
        let args = MemfArgs {
            dump_path: f.path().to_path_buf(),
            profile: None,
            command: MemfCommand::Ps,
            output: OutputFormat::Text,
            pid_filter: None,
        };
        // Should succeed (placeholder output) for an existing file.
        assert!(run_memf_command(&args).is_ok());
    }

    #[test]
    fn memf_command_all_runs_on_existing_file() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0xFF; 8]).unwrap();
        let args = MemfArgs {
            dump_path: f.path().to_path_buf(),
            profile: None,
            command: MemfCommand::All,
            output: OutputFormat::Json,
            pid_filter: None,
        };
        assert!(run_memf_command(&args).is_ok());
    }
}
