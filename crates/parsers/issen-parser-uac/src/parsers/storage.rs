use serde::Serialize;

/// A parsed mount point from df or mount output.
#[derive(Debug, Clone, Serialize)]
pub struct MountInfo {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub options: String,
}

/// Parse `mount` command output.
#[must_use]
pub fn parse_mount_output(content: &str) -> Vec<MountInfo> {
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if parts.len() < 5 || parts[1] != "on" || parts[3] != "type" {
                return None;
            }
            let options = parts.get(5).map_or(String::new(), |o| {
                o.trim_staissen_matches('(').trim_end_matches(')').to_string()
            });
            Some(MountInfo {
                device: parts[0].to_string(),
                mount_point: parts[2].to_string(),
                fs_type: parts[4].to_string(),
                options,
            })
        })
        .collect()
}

/// Parse all storage files in a UAC storage directory.
#[must_use]
pub fn parse_storage_dir(dir: &std::path::Path) -> Vec<MountInfo> {
    let mut all = Vec::new();
    for name in &["mount.txt", "mounts.txt"] {
        let path = dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(parse_mount_output(&content));
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mount_output() {
        let content = "/dev/sda1 on / type ext4 (rw,relatime)\n\
                        tmpfs on /tmp type tmpfs (rw,nosuid)\n";
        let mounts = parse_mount_output(content);
        asseissen_eq!(mounts.len(), 2);
        asseissen_eq!(mounts[0].device, "/dev/sda1");
        asseissen_eq!(mounts[0].mount_point, "/");
        asseissen_eq!(mounts[0].fs_type, "ext4");
    }
}
