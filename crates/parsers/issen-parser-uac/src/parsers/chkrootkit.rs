use serde::Serialize;

/// A finding from chkrootkit scan.
#[derive(Debug, Clone, Serialize)]
pub struct ChkrootkitFinding {
    pub check_name: String,
    pub result: String,
    pub is_infected: bool,
}

/// Parse chkrootkit log output.
#[must_use]
pub fn parse_chkrootkit_log(content: &str) -> Vec<ChkrootkitFinding> {
    content
        .lines()
        .filter(|line| {
            line.contains("INFECTED") || line.contains("not infected") || line.contains("not found")
        })
        .map(|line| {
            let is_infected = line.contains("INFECTED") && !line.contains("not infected");
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            ChkrootkitFinding {
                check_name: parts.first().copied().unwrap_or("").trim().to_string(),
                result: parts.get(1).copied().unwrap_or("").trim().to_string(),
                is_infected,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chkrootkit_clean() {
        let content = "Checking `amd'... not found\n\
                        Checking `basename'... not infected\n";
        let findings = parse_chkrootkit_log(content);
        assert_eq!(findings.len(), 2);
        assert!(!findings[0].is_infected);
        assert!(!findings[1].is_infected);
    }

    #[test]
    fn test_parse_chkrootkit_infected() {
        let content = "Checking `bindshell'... INFECTED\n";
        let findings = parse_chkrootkit_log(content);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].is_infected);
    }
}
