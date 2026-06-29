//! Seekable bzip2 — block index + independent per-block decode.
//!
//! A read of a few scattered ranges decodes only the ~900 KB blocks that cover
//! them, instead of inflating the whole stream. bzip2's blocks carry their own
//! CRC and share no inter-block dictionary, so a single block can be rebuilt into
//! a standalone one-block stream and decoded in isolation — the `bzip2recover`
//! technique — with no decoder-state injection. (gzip and solid 7z cannot do
//! this; see `docs/selective-decompression-triage.md`.)
//!
//! Economics: the index records every block's bit range; learning each block's
//! *decompressed* length needs one decode (bzip2 stores no output length), so
//! building the offset map costs one full decode (parallelizable, no temp
//! writes). Subsequent scattered reads then decode only covering blocks. The win
//! over decode-once-and-spill is avoiding the full temp write/read-back when the
//! working set is sparse; the caller gates on coverage.

use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bzip2_rs::DecoderReader;

use crate::backing::ReadSeekSend;

/// 48-bit bzip2 block-start magic (BCD digits of pi).
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
/// 48-bit bzip2 end-of-stream magic (BCD digits of sqrt(pi)).
const EOS_MAGIC: u64 = 0x1772_4538_5090;
/// 48-bit mask for the rolling magic window.
const MAGIC_MASK: u64 = 0xFFFF_FFFF_FFFF;
/// Decoded blocks kept resident (LRU); a block is ≤ level·100 KB.
const DEFAULT_CACHE_BLOCKS: usize = 8;

/// One bzip2 block located in the compressed bitstream.
#[derive(Debug, Clone, Copy)]
struct BlockEntry {
    /// Bit offset of this block's magic in the compressed stream.
    bit_start: u64,
    /// Bit offset of the next block's magic / the EOS magic (exclusive).
    bit_end: u64,
    /// This block's CRC32 — also the combined CRC of a one-block stream.
    crc: u32,
    /// First decompressed byte this block contributes.
    decomp_start: u64,
    /// Decompressed bytes this block contributes.
    decomp_len: u64,
}

/// A `Read + Seek` view over a bzip2 stream that inflates only the blocks a read
/// touches. Construct with [`Bzip2SeekReader::open`]; use [`read_at`] for
/// positioned reads or the `Read`/`Seek` impls for a cursor.
///
/// [`read_at`]: Bzip2SeekReader::read_at
pub struct Bzip2SeekReader {
    inner: Mutex<Box<dyn ReadSeekSend>>,
    level: u8,
    blocks: Vec<BlockEntry>,
    total: u64,
    cache: Mutex<Vec<(usize, Arc<Vec<u8>>)>>,
    cache_cap: usize,
    pos: u64,
    decodes: AtomicU64,
}

impl std::fmt::Debug for Bzip2SeekReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bzip2SeekReader")
            .field("level", &self.level)
            .field("blocks", &self.blocks.len())
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}

impl Bzip2SeekReader {
    /// Build the block index over a bzip2 stream and return a seekable reader.
    ///
    /// # Errors
    /// Not a bzip2 stream, a truncated/corrupt block, or an underlying I/O error.
    pub fn open(mut inner: Box<dyn ReadSeekSend>) -> io::Result<Self> {
        // Header: "BZh" + a level digit '1'..'9'.
        inner.seek(SeekFrom::Start(0))?;
        let mut hdr = [0u8; 4];
        inner
            .read_exact(&mut hdr)
            .map_err(|_| io::Error::other("bzseek: too short for a bzip2 header"))?;
        if &hdr[..3] != b"BZh" || !(b'1'..=b'9').contains(&hdr[3]) {
            return Err(io::Error::other(format!(
                "bzseek: not a bzip2 stream (header {hdr:02x?})"
            )));
        }
        let level = hdr[3] - b'0';

        // One streaming bit-scan locates every block magic and the EOS magic.
        inner.seek(SeekFrom::Start(0))?;
        let (starts, eos) = scan_blocks(&mut *inner)?;
        if starts.is_empty() {
            return Err(io::Error::other("bzseek: no bzip2 blocks found"));
        }
        let eos = eos.ok_or_else(|| io::Error::other("bzseek: missing end-of-stream marker"))?;

        // Per block: bit range + stored CRC + decompressed length (one decode —
        // bzip2 stores no output length, so the offset map costs one full decode).
        let mut blocks = Vec::with_capacity(starts.len());
        let mut decomp_start = 0u64;
        for (i, &bit_start) in starts.iter().enumerate() {
            let bit_end = starts.get(i + 1).copied().unwrap_or(eos);
            let crc = read_crc(&mut *inner, bit_start)?;
            let mut entry = BlockEntry {
                bit_start,
                bit_end,
                crc,
                decomp_start,
                decomp_len: 0,
            };
            let bytes = decode_block(&mut *inner, level, &entry)?;
            entry.decomp_len = bytes.len() as u64;
            decomp_start = decomp_start.saturating_add(entry.decomp_len);
            blocks.push(entry);
        }
        let block_count = blocks.len() as u64;

        Ok(Self {
            inner: Mutex::new(inner),
            level,
            blocks,
            total: decomp_start,
            cache: Mutex::new(Vec::new()),
            cache_cap: DEFAULT_CACHE_BLOCKS,
            pos: 0,
            // The build already decoded every block once for its length.
            decodes: AtomicU64::new(block_count),
        })
    }

    /// Decompressed bytes of block `k`, from the LRU cache or a fresh decode.
    fn block_bytes(&self, k: usize) -> io::Result<Arc<Vec<u8>>> {
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| io::Error::other("bzseek: cache poisoned"))?;
            if let Some(pos) = cache.iter().position(|(idx, _)| *idx == k) {
                let hit = cache.remove(pos);
                let bytes = Arc::clone(&hit.1);
                cache.insert(0, hit); // move-to-front
                return Ok(bytes);
            }
        }
        let entry = self
            .blocks
            .get(k)
            .ok_or_else(|| io::Error::other("bzseek: block index out of range"))?;
        let bytes = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| io::Error::other("bzseek: inner poisoned"))?;
            decode_block(&mut **guard, self.level, entry)?
        };
        self.decodes.fetch_add(1, Ordering::Relaxed);
        let arc = Arc::new(bytes);
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| io::Error::other("bzseek: cache poisoned"))?;
            cache.insert(0, (k, Arc::clone(&arc)));
            cache.truncate(self.cache_cap);
        }
        Ok(arc)
    }

    /// Total decompressed length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.total
    }

    /// True if the stream decompresses to nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Number of bzip2 blocks in the stream.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Total per-block decodes performed so far (test/telemetry instrumentation;
    /// a cache hit does not increment it).
    #[must_use]
    pub fn decode_count(&self) -> u64 {
        self.decodes.load(Ordering::Relaxed)
    }

    /// Read into `buf` starting at decompressed byte `offset`, decoding only the
    /// blocks that cover `[offset, offset + buf.len())`. Returns the number of
    /// bytes read (short only at end of stream).
    ///
    /// # Errors
    /// A decode or underlying I/O failure.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.total || buf.is_empty() {
            return Ok(0);
        }
        let end = offset.saturating_add(buf.len() as u64).min(self.total);
        // First block whose decompressed range reaches past `offset`.
        let start_idx = self
            .blocks
            .partition_point(|e| e.decomp_start + e.decomp_len <= offset);
        let mut written = 0usize;
        for (k, entry) in self.blocks.iter().enumerate().skip(start_idx) {
            if entry.decomp_start >= end {
                break;
            }
            let bytes = self.block_bytes(k)?;
            let from = offset.max(entry.decomp_start);
            let to = end.min(entry.decomp_start + entry.decomp_len);
            let src_lo = (from - entry.decomp_start) as usize;
            let src_hi = (to - entry.decomp_start) as usize;
            let dst_lo = (from - offset) as usize;
            let slice = bytes
                .get(src_lo..src_hi)
                .ok_or_else(|| io::Error::other("bzseek: block shorter than indexed"))?;
            let dst = buf
                .get_mut(dst_lo..dst_lo + slice.len())
                .ok_or_else(|| io::Error::other("bzseek: destination overflow"))?;
            dst.copy_from_slice(slice);
            written += slice.len();
        }
        Ok(written)
    }
}

impl Read for Bzip2SeekReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Bzip2SeekReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i128,
            SeekFrom::End(o) => self.total as i128 + o as i128,
            SeekFrom::Current(o) => self.pos as i128 + o as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

// ── bit-level helpers + the bzip2recover single-block extractor ─────────────

/// MSB-first bit reader over a byte slice.
struct BitReader<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> BitReader<'a> {
    fn at(data: &'a [u8], bit: usize) -> Self {
        Self { data, bit }
    }
    fn read_bit(&mut self) -> Option<u8> {
        let byte = self.data.get(self.bit / 8)?;
        let shift = 7 - (self.bit % 8);
        self.bit += 1;
        Some((byte >> shift) & 1)
    }
    fn read_bits(&mut self, n: u32) -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | u64::from(self.read_bit()?);
        }
        Some(v)
    }
}

/// MSB-first bit writer; `finish` zero-pads the final partial byte.
struct BitWriter {
    out: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            cur: 0,
            nbits: 0,
        }
    }
    fn write_bit(&mut self, bit: u8) {
        self.cur = (self.cur << 1) | (bit & 1);
        self.nbits += 1;
        if self.nbits == 8 {
            self.out.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }
    fn write_bits(&mut self, v: u64, n: u32) {
        for i in (0..n).rev() {
            self.write_bit(((v >> i) & 1) as u8);
        }
    }
    fn write_byte(&mut self, b: u8) {
        self.write_bits(u64::from(b), 8);
    }
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.cur <<= 8 - self.nbits;
            self.out.push(self.cur);
        }
        self.out
    }
}

/// Stream the whole compressed source one byte at a time, recording the bit
/// offset of every block magic and the EOS magic (rolling 48-bit window).
fn scan_blocks(r: &mut dyn Read) -> io::Result<(Vec<u64>, Option<u64>)> {
    let mut window = 0u64;
    let mut bitpos = 0u64;
    let mut starts = Vec::new();
    let mut eos = None;
    let mut buf = [0u8; 8192];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for &byte in buf.get(..n).unwrap_or(&[]) {
            for k in (0..8).rev() {
                window = ((window << 1) | u64::from((byte >> k) & 1)) & MAGIC_MASK;
                bitpos += 1;
                if bitpos < 48 {
                    continue;
                }
                if window == BLOCK_MAGIC {
                    starts.push(bitpos - 48);
                } else if window == EOS_MAGIC {
                    eos = Some(bitpos - 48);
                }
            }
        }
    }
    Ok((starts, eos))
}

/// Read a block's stored CRC32 — the 32 bits immediately after its 48-bit magic.
fn read_crc(inner: &mut dyn ReadSeekSend, bit_start: u64) -> io::Result<u32> {
    let crc_bit = bit_start + 48;
    let byte_lo = crc_bit / 8;
    inner.seek(SeekFrom::Start(byte_lo))?;
    let mut b = [0u8; 5]; // 32 bits span at most 5 bytes once bit-shifted
    let n = inner.read(&mut b)?;
    let mut rd = BitReader::at(b.get(..n).unwrap_or(&[]), (crc_bit - byte_lo * 8) as usize);
    rd.read_bits(32)
        .map(|v| v as u32)
        .ok_or_else(|| io::Error::other("bzseek: truncated block CRC"))
}

/// Rebuild block `entry` as a standalone one-block bzip2 stream and decode it.
/// The footer's combined CRC equals the block CRC (a one-block stream's combined
/// CRC is just that block's), so no CRC recomputation is needed.
fn decode_block(
    inner: &mut dyn ReadSeekSend,
    level: u8,
    entry: &BlockEntry,
) -> io::Result<Vec<u8>> {
    let byte_lo = entry.bit_start / 8;
    let byte_hi = entry.bit_end.div_ceil(8);
    let span = usize::try_from(byte_hi - byte_lo).unwrap_or(0);
    inner.seek(SeekFrom::Start(byte_lo))?;
    let mut comp = vec![0u8; span];
    inner.read_exact(&mut comp)?;

    let start_in = usize::try_from(entry.bit_start - byte_lo * 8).unwrap_or(0);
    let nbits = entry.bit_end - entry.bit_start;

    let mut w = BitWriter::new();
    w.write_byte(b'B');
    w.write_byte(b'Z');
    w.write_byte(b'h');
    w.write_byte(b'0' + level);
    let mut rd = BitReader::at(&comp, start_in);
    for _ in 0..nbits {
        let bit = rd
            .read_bit()
            .ok_or_else(|| io::Error::other("bzseek: truncated block payload"))?;
        w.write_bit(bit);
    }
    w.write_bits(EOS_MAGIC, 48);
    w.write_bits(u64::from(entry.crc), 32);

    let mut out = Vec::new();
    DecoderReader::new(Cursor::new(w.finish())).read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn pattern(len: usize) -> Vec<u8> {
        (0u8..=255).cycle().take(len).collect()
    }

    /// A real multi-block bzip2 stream: level 1 = 100 KB input blocks, so a
    /// payload over 100 KB spans several blocks. banzai is a pure-Rust encoder.
    fn multiblock_bz2(payload: &[u8]) -> Vec<u8> {
        let mut bz = Vec::new();
        banzai::encode(Cursor::new(payload), io::BufWriter::new(&mut bz), 1).unwrap();
        bz
    }

    /// The oracle: full sequential decode via bzip2-rs.
    fn full_decode(bz: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        DecoderReader::new(Cursor::new(bz))
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    fn reader(bz: Vec<u8>) -> Bzip2SeekReader {
        Bzip2SeekReader::open(Box::new(Cursor::new(bz))).unwrap()
    }

    #[test]
    fn builds_multiblock_index() {
        let payload = pattern(250_000);
        let bz = multiblock_bz2(&payload);
        let r = reader(bz);
        assert_eq!(r.len(), 250_000);
        assert!(
            r.block_count() >= 2,
            "level-1 250 KB should span multiple blocks, got {}",
            r.block_count()
        );
    }

    #[test]
    fn read_at_matches_full_decode_across_boundaries() {
        let payload = pattern(250_000);
        let bz = multiblock_bz2(&payload);
        let want = full_decode(&bz);
        assert_eq!(want, payload, "fixture sanity: oracle == payload");
        let r = reader(bz);
        // Ranges that straddle the 100 KB / 200 KB block boundaries.
        for (off, len) in [(0usize, 16), (99_990, 40), (150_000, 1000), (249_000, 1000)] {
            let mut buf = vec![0u8; len];
            let n = r.read_at(off as u64, &mut buf).unwrap();
            assert_eq!(n, len, "short read at {off}");
            assert_eq!(buf, want[off..off + len], "byte mismatch at {off}");
        }
    }

    #[test]
    fn scattered_read_decodes_only_covering_blocks() {
        let payload = pattern(300_000); // ~3 blocks at level 1
        let bz = multiblock_bz2(&payload);
        let r = reader(bz);
        assert!(
            r.block_count() >= 3,
            "need several blocks to show selectivity"
        );
        let base = r.decode_count();
        // Single-byte reads can't straddle a block boundary, so each touches
        // exactly one block — the point being it is NOT all of them.
        let mut b = [0u8; 1];
        r.read_at(0, &mut b).unwrap(); // first block only
        assert_eq!(r.decode_count() - base, 1, "one block for the first read");
        let after_first = r.decode_count();
        r.read_at(0, &mut b).unwrap(); // cached → no decode
        assert_eq!(r.decode_count(), after_first, "cache hit decodes nothing");
        r.read_at((payload.len() - 1) as u64, &mut b).unwrap(); // last block only
        assert_eq!(
            r.decode_count() - after_first,
            1,
            "one block for the last read, not the whole stream"
        );
    }

    #[test]
    fn read_past_end_is_short() {
        let payload = pattern(120_000);
        let r = reader(multiblock_bz2(&payload));
        let mut buf = [0u8; 100];
        let n = r.read_at(119_950, &mut buf).unwrap();
        assert_eq!(n, 50, "only 50 bytes remain");
    }

    #[test]
    fn read_seek_cursor_matches_read_at() {
        let payload = pattern(250_000);
        let bz = multiblock_bz2(&payload);
        let want = full_decode(&bz);
        let mut r = reader(bz);
        r.seek(SeekFrom::Start(199_000)).unwrap();
        let mut buf = vec![0u8; 2000];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, want[199_000..201_000]);
    }

    #[test]
    fn open_rejects_non_bzip2() {
        let err = Bzip2SeekReader::open(Box::new(Cursor::new(b"not bzip2".to_vec())));
        assert!(err.is_err());
    }
}
