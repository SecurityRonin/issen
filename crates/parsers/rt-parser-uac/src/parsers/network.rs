use serde::Serialize;

/// A parsed network connection from netstat or ss output.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<u32>,
    pub program: Option<String>,
}

/// Parse ss (socket statistics) output.
///
/// Expected format (header + data lines):
/// `State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process`
#[must_use]
pub fn parse_ss_output(content: &str) -> Vec<NetworkConnection> {
    let mut results = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }

        let state = fields[0].to_string();
        let local_addr = fields[3].to_string();
        let remote_addr = fields[4].to_string();

        let (pid, program) = if fields.len() > 5 {
            parse_pid_program(&fields[5..].join(" "))
        } else {
            (None, None)
        };

        results.push(NetworkConnection {
            protocol: String::new(),
            local_addr,
            remote_addr,
            state,
            pid,
            program,
        });
    }

    results
}

/// Parse netstat output.
///
/// Expected format:
/// `Proto Recv-Q Send-Q Local Address  Foreign Address  State  PID/Program`
#[must_use]
pub fn parse_netstat_output(content: &str) -> Vec<NetworkConnection> {
    let mut results = Vec::new();

    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }

        let proto = fields[0].to_lowercase();
        if !proto.starts_with("tcp") && !proto.starts_with("udp") {
            continue;
        }

        let local_addr = fields[3].to_string();
        let remote_addr = fields[4].to_string();
        let state = if fields.len() > 5 && !fields[5].contains('/') {
            fields[5].to_string()
        } else {
            String::new()
        };

        let pid_field = fields.last().copied().unwrap_or("-");
        let (pid, program) = parse_pid_program(pid_field);

        results.push(NetworkConnection {
            protocol: proto,
            local_addr,
            remote_addr,
            state,
            pid,
            program,
        });
    }

    results
}

/// Parse PID/Program field (format: `1234/program` or `users:(("prog",pid=1234,...))`)
fn parse_pid_program(field: &str) -> (Option<u32>, Option<String>) {
    if let Some((pid_str, prog)) = field.split_once('/') {
        let pid = pid_str.trim().parse::<u32>().ok();
        let program = if prog.is_empty() {
            None
        } else {
            Some(prog.to_string())
        };
        return (pid, program);
    }

    if field.contains("pid=") {
        let pid = field
            .split("pid=")
            .nth(1)
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|s| s.parse::<u32>().ok());
        let program = field
            .split("((\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(String::from);
        return (pid, program);
    }

    (None, None)
}

/// Parse all network-related files in a UAC network directory.
#[must_use]
pub fn parse_network_dir(dir: &std::path::Path) -> Vec<NetworkConnection> {
    let mut all = Vec::new();

    for name in &["ss.txt", "ss-tlnp.txt", "ss-anp.txt"] {
        let path = dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(parse_ss_output(&content));
        }
    }

    for name in &["netstat.txt", "netstat-tlnp.txt", "netstat-anp.txt"] {
        let path = dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(parse_netstat_output(&content));
        }
    }

    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss_output() {
        let content = "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n\
                        LISTEN  0       128     0.0.0.0:22         0.0.0.0:*          users:((\"sshd\",pid=1234,fd=3))\n\
                        ESTAB   0       0       10.0.0.1:22        10.0.0.2:54321\n";
        let conns = parse_ss_output(content);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].state, "LISTEN");
        assert_eq!(conns[0].local_addr, "0.0.0.0:22");
        assert_eq!(conns[0].pid, Some(1234));
        assert_eq!(conns[0].program.as_deref(), Some("sshd"));
        assert_eq!(conns[1].state, "ESTAB");
        assert!(conns[1].pid.is_none());
    }

    #[test]
    fn test_parse_netstat_output() {
        let content = "Active Internet connections\n\
                        Proto Recv-Q Send-Q Local Address     Foreign Address   State       PID/Program\n\
                        tcp   0      0      0.0.0.0:22        0.0.0.0:*         LISTEN      1234/sshd\n\
                        tcp   0      0      10.0.0.1:22       10.0.0.2:54321    ESTABLISHED -\n";
        let conns = parse_netstat_output(content);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].protocol, "tcp");
        assert_eq!(conns[0].pid, Some(1234));
        assert_eq!(conns[0].program.as_deref(), Some("sshd"));
    }

    #[test]
    fn test_parse_pid_program_netstat() {
        let (pid, prog) = parse_pid_program("1234/nginx");
        assert_eq!(pid, Some(1234));
        assert_eq!(prog.as_deref(), Some("nginx"));
    }

    #[test]
    fn test_parse_pid_program_ss() {
        let (pid, prog) = parse_pid_program("users:((\"sshd\",pid=1234,fd=3))");
        assert_eq!(pid, Some(1234));
        assert_eq!(prog.as_deref(), Some("sshd"));
    }

    #[test]
    fn test_parse_pid_program_dash() {
        let (pid, prog) = parse_pid_program("-");
        assert!(pid.is_none());
        assert!(prog.is_none());
    }
}
