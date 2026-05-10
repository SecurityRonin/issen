use std::io::Read;
use std::path::Path;

/// Detected dump format based on file magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpFormat {
    /// Linux LiME module dump ("EMiL" magic at offset 0).
    Lime,
    /// Microsoft AVML dump ("avml" magic at offset 0).
    Avml,
    /// Windows crash dump ("PAGE" magic at offset 0).
    WindowsCrashDump,
    /// Raw/flat physical memory dump (no recognisable magic).
    Raw,
}

impl std::fmt::Display for DumpFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lime => write!(f, "LiME"),
            Self::Avml => write!(f, "AVML"),
            Self::WindowsCrashDump => write!(f, "WindowsCrashDump"),
            Self::Raw => write!(f, "Raw"),
        }
    }
}

/// Detect the format of a memory dump by inspecting its first 8 magic bytes.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the file cannot be opened or read.
pub fn detect_format(path: &Path) -> std::io::Result<DumpFormat> {
    let mut f = std::fs::File::open(path)?;
    let mut magic = [0u8; 8];
    // A valid dump must supply at least 8 bytes; truncated files fall through
    // to Raw rather than returning an error.
    let _ = f.read(&mut magic)?;
    Ok(match &magic[..4] {
        // LiME: "EMiL" (0x45 0x4D 0x69 0x4C)
        [0x45, 0x4D, 0x69, 0x4C] => DumpFormat::Lime,
        // AVML: "avml" (0x61 0x76 0x6D 0x6C)
        [0x61, 0x76, 0x6D, 0x6C] => DumpFormat::Avml,
        // Windows crash dump: "PAGE" (0x50 0x41 0x47 0x45)
        [0x50, 0x41, 0x47, 0x45] => DumpFormat::WindowsCrashDump,
        _ => DumpFormat::Raw,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn write_magic(magic: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(magic).expect("write magic");
        // Pad to 8 bytes so the reader always gets enough bytes.
        if magic.len() < 8 {
            f.write_all(&[0u8; 8][..8 - magic.len()]).expect("pad");
        }
        f
    }

    #[test]
    fn detect_lime_format() {
        let f = write_magic(&[0x45, 0x4D, 0x69, 0x4C, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(detect_format(f.path()).unwrap(), DumpFormat::Lime);
    }

    #[test]
    fn detect_avml_format() {
        let f = write_magic(&[0x61, 0x76, 0x6D, 0x6C, 0x00, 0x00, 0x00, 0x02]);
        assert_eq!(detect_format(f.path()).unwrap(), DumpFormat::Avml);
    }

    #[test]
    fn detect_windows_crash_dump() {
        let f = write_magic(&[0x50, 0x41, 0x47, 0x45, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            detect_format(f.path()).unwrap(),
            DumpFormat::WindowsCrashDump
        );
    }

    #[test]
    fn detect_raw_format() {
        let f = write_magic(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(detect_format(f.path()).unwrap(), DumpFormat::Raw);
    }

    #[test]
    fn detect_nonexistent_file_returns_io_error() {
        let result = detect_format(std::path::Path::new("/nonexistent/does_not_exist.lime"));
        assert!(result.is_err());
    }

    #[test]
    fn dump_format_display() {
        assert_eq!(DumpFormat::Lime.to_string(), "LiME");
        assert_eq!(DumpFormat::Avml.to_string(), "AVML");
        assert_eq!(DumpFormat::WindowsCrashDump.to_string(), "WindowsCrashDump");
        assert_eq!(DumpFormat::Raw.to_string(), "Raw");
    }
}
