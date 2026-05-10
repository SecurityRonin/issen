//! Static file signature table for magic byte detection.

/// A file signature entry mapping extensions to magic bytes.
pub struct MagicEntry {
    pub extensions: &'static [&'static str],
    pub magic: &'static [u8],
    pub offset: usize,
    pub description: &'static str,
}

/// Static table of known file signatures (~40 entries).
pub static MAGIC_TABLE: &[MagicEntry] = &[
    // Images
    MagicEntry {
        extensions: &["jpg", "jpeg"],
        magic: b"\xFF\xD8\xFF",
        offset: 0,
        description: "JPEG",
    },
    MagicEntry {
        extensions: &["png"],
        magic: b"\x89PNG\r\n\x1a\n",
        offset: 0,
        description: "PNG",
    },
    MagicEntry {
        extensions: &["gif"],
        magic: b"GIF87a",
        offset: 0,
        description: "GIF87a",
    },
    MagicEntry {
        extensions: &["gif"],
        magic: b"GIF89a",
        offset: 0,
        description: "GIF89a",
    },
    MagicEntry {
        extensions: &["bmp"],
        magic: b"BM",
        offset: 0,
        description: "BMP",
    },
    MagicEntry {
        extensions: &["tif", "tiff"],
        magic: b"II\x2A\x00",
        offset: 0,
        description: "TIFF (little-endian)",
    },
    MagicEntry {
        extensions: &["tif", "tiff"],
        magic: b"MM\x00\x2A",
        offset: 0,
        description: "TIFF (big-endian)",
    },
    MagicEntry {
        extensions: &["ico"],
        magic: b"\x00\x00\x01\x00",
        offset: 0,
        description: "ICO",
    },
    MagicEntry {
        extensions: &["webp"],
        magic: b"RIFF",
        offset: 0,
        description: "WebP/RIFF",
    },
    // Documents
    MagicEntry {
        extensions: &["pdf"],
        magic: b"%PDF",
        offset: 0,
        description: "PDF",
    },
    MagicEntry {
        extensions: &["docx", "xlsx", "pptx", "zip", "jar", "odt", "ods"],
        magic: b"PK\x03\x04",
        offset: 0,
        description: "ZIP/OOXML/ODF",
    },
    MagicEntry {
        extensions: &["doc", "xls", "ppt", "msg"],
        magic: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        offset: 0,
        description: "OLE2 Compound",
    },
    MagicEntry {
        extensions: &["rtf"],
        magic: b"{\\rtf",
        offset: 0,
        description: "RTF",
    },
    // Executables
    MagicEntry {
        extensions: &["exe", "dll", "scr", "sys", "ocx", "drv"],
        magic: b"MZ",
        offset: 0,
        description: "PE executable",
    },
    MagicEntry {
        extensions: &["elf", "so", "o"],
        magic: b"\x7FELF",
        offset: 0,
        description: "ELF",
    },
    MagicEntry {
        extensions: &["class"],
        magic: b"\xCA\xFE\xBA\xBE",
        offset: 0,
        description: "Java class",
    },
    MagicEntry {
        extensions: &["dex"],
        magic: b"dex\n",
        offset: 0,
        description: "Dalvik DEX",
    },
    // Archives
    MagicEntry {
        extensions: &["gz", "tgz"],
        magic: b"\x1F\x8B",
        offset: 0,
        description: "gzip",
    },
    MagicEntry {
        extensions: &["bz2"],
        magic: b"BZ",
        offset: 0,
        description: "bzip2",
    },
    MagicEntry {
        extensions: &["xz"],
        magic: b"\xFD7zXZ\x00",
        offset: 0,
        description: "xz",
    },
    MagicEntry {
        extensions: &["7z"],
        magic: b"7z\xBC\xAF\x27\x1C",
        offset: 0,
        description: "7-Zip",
    },
    MagicEntry {
        extensions: &["rar"],
        magic: b"Rar!\x1A\x07",
        offset: 0,
        description: "RAR",
    },
    MagicEntry {
        extensions: &["cab"],
        magic: b"MSCF",
        offset: 0,
        description: "MS Cabinet",
    },
    MagicEntry {
        extensions: &["tar"],
        magic: b"ustar",
        offset: 257,
        description: "tar (POSIX)",
    },
    // Audio/Video
    MagicEntry {
        extensions: &["mp3"],
        magic: b"ID3",
        offset: 0,
        description: "MP3 (ID3)",
    },
    MagicEntry {
        extensions: &["mp4", "m4a", "m4v"],
        magic: b"ftyp",
        offset: 4,
        description: "MP4/M4A",
    },
    MagicEntry {
        extensions: &["avi"],
        magic: b"RIFF",
        offset: 0,
        description: "AVI/RIFF",
    },
    MagicEntry {
        extensions: &["flv"],
        magic: b"FLV",
        offset: 0,
        description: "Flash Video",
    },
    MagicEntry {
        extensions: &["ogg"],
        magic: b"OggS",
        offset: 0,
        description: "Ogg",
    },
    MagicEntry {
        extensions: &["wav"],
        magic: b"RIFF",
        offset: 0,
        description: "WAV/RIFF",
    },
    // Database
    MagicEntry {
        extensions: &["sqlite", "db", "sqlite3"],
        magic: b"SQLite format 3\x00",
        offset: 0,
        description: "SQLite",
    },
    // Disk images & forensic
    MagicEntry {
        extensions: &["vmdk"],
        magic: b"KDMV",
        offset: 0,
        description: "VMDK",
    },
    MagicEntry {
        extensions: &["vhd"],
        magic: b"conectix",
        offset: 0,
        description: "VHD",
    },
    MagicEntry {
        extensions: &["iso"],
        magic: b"CD001",
        offset: 32769,
        description: "ISO 9660",
    },
    MagicEntry {
        extensions: &["e01", "E01"],
        magic: b"EVF\x09\x0D\x0A\xFF\x00",
        offset: 0,
        description: "EnCase EWF",
    },
    // Crypto containers (used by HEUR-EN-002)
    MagicEntry {
        extensions: &["luks"],
        magic: b"LUKS\xBA\xBE",
        offset: 0,
        description: "LUKS",
    },
    // Scripts
    MagicEntry {
        extensions: &["ps1", "py", "sh", "bash", "pl", "rb"],
        magic: b"#!",
        offset: 0,
        description: "Shebang script",
    },
    // XML-based
    MagicEntry {
        extensions: &["xml", "svg", "html", "xhtml"],
        magic: b"<?xml",
        offset: 0,
        description: "XML",
    },
];

/// Look up what format a byte buffer actually is, based on magic bytes.
#[must_use]
pub fn identify_format(data: &[u8]) -> Option<&'static MagicEntry> {
    MAGIC_TABLE.iter().find(|entry| {
        if data.len() < entry.offset + entry.magic.len() {
            return false;
        }
        data[entry.offset..entry.offset + entry.magic.len()] == *entry.magic
    })
}

/// Check if a file extension matches any entry in the magic table.
#[must_use]
pub fn extension_known(ext: &str) -> bool {
    let ext_lower = ext.to_lowercase();
    MAGIC_TABLE
        .iter()
        .any(|entry| entry.extensions.iter().any(|&e| e == ext_lower))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn identify_jpeg() {
        let data = b"\xFF\xD8\xFF\xE0rest of jpeg data";
        let entry = identify_format(data).unwrap();
        assert_eq!(entry.description, "JPEG");
    }

    #[test]
    fn identify_pe() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00";
        let entry = identify_format(data).unwrap();
        assert_eq!(entry.description, "PE executable");
    }

    #[test]
    fn identify_pdf() {
        let data = b"%PDF-1.4 blah blah";
        let entry = identify_format(data).unwrap();
        assert_eq!(entry.description, "PDF");
    }

    #[test]
    fn identify_unknown_returns_none() {
        let data = b"\x00\x01\x02\x03unknown data";
        assert!(identify_format(data).is_none());
    }

    #[test]
    fn extension_known_jpg() {
        assert!(extension_known("jpg"));
        assert!(extension_known("JPG"));
    }

    #[test]
    fn extension_unknown() {
        assert!(!extension_known("xyz123"));
    }

    #[test]
    fn magic_table_has_entries() {
        assert!(MAGIC_TABLE.len() >= 30);
    }
}
