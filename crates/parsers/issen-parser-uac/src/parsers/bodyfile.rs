use serde::Serialize;

/// A parsed entry from a mactime bodyfile.
///
/// Format: `md5|path|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`
#[derive(Debug, Clone, Serialize)]
pub struct BodyfileEntry {
    pub md5: String,
    pub path: String,
    pub inode: u64,
    pub mode: String,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Option<i64>,
    pub mtime: Option<i64>,
    pub ctime: Option<i64>,
    pub crtime: Option<i64>,
}

/// Parse a single bodyfile line into a `BodyfileEntry`.
///
/// Returns `None` if the line is malformed or a comment/header.
#[must_use]
pub fn parse_bodyfile_line(line: &str) -> Option<BodyfileEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let fields: Vec<&str> = line.splitn(11, '|').collect();
    if fields.len() < 11 {
        return None;
    }

    let parse_ts = |s: &str| -> Option<i64> {
        let n: i64 = s.trim().parse().ok()?;
        if n == 0 {
            None
        } else {
            Some(n)
        }
    };

    Some(BodyfileEntry {
        md5: fields[0].to_string(),
        path: fields[1].to_string(),
        inode: fields[2].parse().unwrap_or(0),
        mode: fields[3].to_string(),
        uid: fields[4].parse().unwrap_or(0),
        gid: fields[5].parse().unwrap_or(0),
        size: fields[6].parse().unwrap_or(0),
        atime: parse_ts(fields[7]),
        mtime: parse_ts(fields[8]),
        ctime: parse_ts(fields[9]),
        crtime: parse_ts(fields[10]),
    })
}

/// Parse an entire bodyfile (file contents as string).
#[must_use]
pub fn parse_bodyfile(content: &str) -> Vec<BodyfileEntry> {
    content.lines().filter_map(parse_bodyfile_line).collect()
}

/// Parse a bodyfile from a file path.
///
/// # Errors
///
/// Returns `std::io::Error` if the file cannot be read.
pub fn parse_bodyfile_path(path: &std::path::Path) -> Result<Vec<BodyfileEntry>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_bodyfile(&content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bodyfile_line_valid() {
        let line = "d41d8cd98f00b204e9800998ecf8427e|/bin/ls|1234|100755|0|0|12345|1711111111|1711111112|1711111113|0";
        let entry = parse_bodyfile_line(line).expect("should parse");
        assert_eq!(entry.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(entry.path, "/bin/ls");
        assert_eq!(entry.inode, 1234);
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.size, 12345);
        assert_eq!(entry.atime, Some(1_711_111_111));
        assert_eq!(entry.mtime, Some(1_711_111_112));
        assert_eq!(entry.ctime, Some(1_711_111_113));
        assert_eq!(entry.crtime, None); // 0 → None
    }

    #[test]
    fn test_parse_bodyfile_line_comment() {
        assert!(parse_bodyfile_line("# header comment").is_none());
    }

    #[test]
    fn test_parse_bodyfile_line_empty() {
        assert!(parse_bodyfile_line("").is_none());
        assert!(parse_bodyfile_line("   ").is_none());
    }

    #[test]
    fn test_parse_bodyfile_line_too_few_fields() {
        assert!(parse_bodyfile_line("a|b|c").is_none());
    }

    #[test]
    fn test_parse_bodyfile_multiple_lines() {
        let content = "0|/bin/ls|1|100755|0|0|100|1000|2000|3000|0\n\
                        # comment\n\
                        0|/bin/cat|2|100755|0|0|200|4000|5000|6000|0\n\
                        \n";
        let entries = parse_bodyfile(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/bin/ls");
        assert_eq!(entries[1].path, "/bin/cat");
    }

    #[test]
    fn test_parse_bodyfile_zero_timestamps() {
        let line = "0|/tmp/file|0|100644|1000|1000|0|0|0|0|0";
        let entry = parse_bodyfile_line(line).expect("parse");
        assert!(entry.atime.is_none(), "0 timestamp should be None");
        assert!(entry.mtime.is_none());
    }

    #[test]
    fn test_parse_bodyfile_path_with_pipes() {
        let line = "0|/home/user/my file (copy)|99|100644|1000|1000|50|1000|2000|3000|0";
        let entry = parse_bodyfile_line(line).expect("parse");
        assert_eq!(entry.path, "/home/user/my file (copy)");
    }
}
