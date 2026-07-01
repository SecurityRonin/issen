//! AccessData **AD1** logical-image collection provider for the Issen pipeline.
//!
//! AD1 (FTK Imager "Custom Content Image") is a LOGICAL container — a tree of
//! files + metadata + zlib-compressed data — not a sector image. So it plugs in
//! as a [`CollectionProvider`] (like zip/tar), NOT the disk→partition→filesystem
//! pipeline: [`open`](Ad1Provider::open) extracts the file tree to a temp dir and
//! the fswalker then classifies the extracted files directly.
//!
//! Probing is by leading magic bytes only (never the extension) and returns
//! [`Confidence::High`] — the `ADSEGMENTEDFILE` / `ADCRYPT` signatures are
//! unambiguous. Extraction is SAFE by construction: every output path is
//! validated to stay inside the extraction directory (path-traversal guard).

use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use ad1::{Ad1Error, Ad1Reader};
use issen_core::error::RtError;
use issen_unpack::{
    CollectionManifest, CollectionMetadata, CollectionProvider, Confidence, OsType,
};

/// Bytes read from the head for magic detection (marker is 16 bytes).
const HEADER_LEN: usize = 16;
/// Streaming buffer for per-file decompression during extraction.
const READ_BUF: usize = 1 << 20; // 1 MiB

/// AD1 logical-image collection provider.
#[derive(Debug, Default)]
pub struct Ad1Provider;

/// The AD1 flavor recognised from the leading signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ad1Kind {
    /// Normal segmented AD1 (`ADSEGMENTEDFILE`).
    Segmented,
    /// Encrypted variant (`ADCRYPT`) — recognised but not extractable in v1.
    Encrypted,
}

/// Recognise the AD1 flavor from the leading magic bytes; `None` if not AD1.
fn detect_kind(path: &Path) -> Option<Ad1Kind> {
    let mut head = [0u8; HEADER_LEN];
    let read = read_head(path, &mut head)?;
    let head = &head[..read];
    if head.len() >= 15 && &head[..15] == b"ADSEGMENTEDFILE" {
        return Some(Ad1Kind::Segmented);
    }
    if head.len() >= 7 && &head[..7] == b"ADCRYPT" {
        return Some(Ad1Kind::Encrypted);
    }
    None
}

/// Read up to `buf.len()` leading bytes; `None` if the file can't be opened.
fn read_head(path: &Path, buf: &mut [u8]) -> Option<usize> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).ok()?;
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    Some(filled)
}

impl CollectionProvider for Ad1Provider {
    fn name(&self) -> &'static str {
        "AD1"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        // Magic-only: both signatures are definitive AD1 markers → High.
        // (An encrypted image is still recognised as AD1; `open` refuses it
        // loudly rather than pretending it isn't AD1.)
        match detect_kind(path) {
            Some(_) => Ok(Confidence::High),
            None => Ok(Confidence::None),
        }
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        match detect_kind(path) {
            Some(Ad1Kind::Encrypted) => {
                return Err(RtError::UnsupportedFormat(format!(
                    "AD1: {} is ADCRYPT-encrypted; decryption is out of scope",
                    path.display()
                )));
            }
            Some(Ad1Kind::Segmented) => {}
            None => {
                return Err(RtError::UnsupportedFormat(format!(
                    "AD1: {} is not an AD1 image",
                    path.display()
                )));
            }
        }

        let reader = Ad1Reader::open(path).map_err(map_err)?;
        let tempdir = issen_unpack::tempdir::create_extraction_dir()?;
        let root = tempdir.path();
        let mut buf = vec![0u8; READ_BUF];
        let mut refused = Vec::new();

        for entry in reader.entries() {
            let Some(dest) = safe_join(root, &entry.path) else {
                // Path-traversal guard: an entry that would escape the root is
                // refused (surfaced below), never written.
                refused.push(entry.path.clone());
                continue;
            };
            if entry.is_dir {
                std::fs::create_dir_all(&dest)?;
                continue;
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out = std::fs::File::create(&dest)?;
            let mut offset = 0u64;
            loop {
                let n = reader.read_at(entry, offset, &mut buf).map_err(map_err)?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n])?;
                offset += n as u64;
            }
        }

        if !refused.is_empty() {
            // Fail-loud: extraction continued (the dir is safe), but the
            // investigator must know which hostile entries were dropped.
            for name in &refused {
                eprintln!("issen-ad1: refused path-traversal entry (not extracted): {name}");
            }
        }

        Ok(CollectionManifest::new(
            "AD1".into(),
            tempdir,
            // Empty: let the fswalker classify the extracted tree.
            Vec::new(),
            default_metadata(),
        ))
    }
}

/// Join `rel` under `root`, rejecting any component that would escape it
/// (`..`, absolute, root/prefix). Returns `None` for an unsafe path.
fn safe_join(root: &Path, rel: &str) -> Option<PathBuf> {
    let mut out = root.to_path_buf();
    let mut pushed = false;
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => {
                out.push(c);
                pushed = true;
            }
            // Ignore a leading `.`; reject anything that could climb out.
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if pushed {
        Some(out)
    } else {
        None
    }
}

/// Map an [`Ad1Error`] onto the pipeline's [`RtError`].
fn map_err(e: Ad1Error) -> RtError {
    match e {
        Ad1Error::Io(io) => RtError::Io(io),
        Ad1Error::Unsupported(m) | Ad1Error::NotAd1(m) => {
            RtError::UnsupportedFormat(format!("AD1: {m}"))
        }
        Ad1Error::Malformed(m) => RtError::Parse {
            offset: 0,
            message: format!("AD1: {m}"),
        },
    }
}

/// AD1 carries per-file metadata but no reliable host/OS banner — leave the
/// collection metadata at its neutral default (the fswalker infers the rest).
fn default_metadata() -> CollectionMetadata {
    CollectionMetadata {
        hostname: None,
        collection_time: None,
        os_type: OsType::Unknown,
        tool_version: None,
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(Ad1Provider),
});

#[cfg(test)]
mod tests;
