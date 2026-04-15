//! Parse `live_response/process/hidden_pids_for_ps_command.txt`.
//!
//! UAC compares the PID list from `/proc` with the PID list from `ps` and
//! records any PIDs present in `/proc` but absent from `ps` — the classic
//! sign of a userland rootkit hiding processes via `readdir()` hooking.

/// Parse the contents of `hidden_pids_for_ps_command.txt`.
///
/// Each non-empty line is expected to be a decimal PID.
/// Invalid or blank lines are silently skipped.
#[must_use]
pub fn parse_hidden_pids(content: &str) -> Vec<u32> {
    content
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .collect()
}

/// Read and parse `live_response/process/hidden_pids_for_ps_command.txt`
/// from a UAC collection root directory.
///
/// Returns an empty vec if the file is absent (collection predates the check).
#[must_use]
pub fn read_hidden_pids(root: &std::path::Path) -> Vec<u32> {
    let path = root.join("live_response/process/hidden_pids_for_ps_command.txt");
    std::fs::read_to_string(path)
        .map(|c| parse_hidden_pids(&c))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_empty() {
        assert!(parse_hidden_pids("").is_empty());
    }

    #[test]
    fn whitespace_only_returns_empty() {
        assert!(parse_hidden_pids("   \n\n  \n").is_empty());
    }

    #[test]
    fn single_pid() {
        let result = parse_hidden_pids("42\n");
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn multiple_pids_from_ctf_collection() {
        // Actual PIDs from the CTF UAC collection hidden_pids file.
        let content = "43168\n939\n940\n941\n975\n977\n";
        let result = parse_hidden_pids(content);
        assert_eq!(result, vec![43168, 939, 940, 941, 975, 977]);
    }

    #[test]
    fn invalid_lines_skipped() {
        let content = "123\nnot-a-pid\n456\n\n";
        let result = parse_hidden_pids(content);
        assert_eq!(result, vec![123, 456]);
    }

    #[test]
    fn read_hidden_pids_missing_file_returns_empty() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let result = read_hidden_pids(dir.path());
        assert!(result.is_empty(), "missing file should yield empty vec");
    }

    #[test]
    fn read_hidden_pids_reads_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let proc_dir = dir.path().join("live_response/process");
        std::fs::create_dir_all(&proc_dir).expect("mkdir");
        std::fs::write(
            proc_dir.join("hidden_pids_for_ps_command.txt"),
            "939\n940\n977\n",
        )
        .expect("write");

        let result = read_hidden_pids(dir.path());
        assert_eq!(result, vec![939, 940, 977]);
    }
}
