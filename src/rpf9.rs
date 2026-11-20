//! RPF9 (`9FPR` on disk): header parsing and a zlib stream scanner.
//!
//! RPF9 is the next archive version after RDR2's RPF8. Its table of contents
//! is encrypted, and this crate does not decrypt it: [`Rpf9Header`] parses the
//! plaintext header only. The file bodies are mostly plain zlib streams, and
//! [`scan_zlib_streams`] pulls those out without the TOC.
//!
//! The header test vectors are synthetic: every field except the magic,
//! version and alignment invariants is invented, so no bytes come from a
//! real archive.
//!
//! # Header layout
//!
//! The plaintext header is 0x40 bytes, all little-endian. What each field
//! means is a hypothesis: the encrypted TOC is not decrypted, so the roles
//! below are inferred from the layout and from cross-archive comparisons
//! (aggregate relations only). The docs on [`Rpf9Header`] record each field's
//! evidence, and everything not confirmed by the synthetic tests in this
//! crate is marked unverified.
//!
//! ```text
//! 0x00  u32  magic           0x52504639 ("9FPR" on disk)
//! 0x04  u32  toc_end         end of the encrypted TOC; zero padding or file data follows
//! 0x08  u32  field_08        unknown; trails toc_end by a small, archive-dependent amount
//! 0x0C  u32  field_0c        unknown (names length?)
//! 0x10  u64  archive_id      different in every archive checked (per-archive hash, IV or key seed?)
//! 0x18  u32  field_18        same value in every archive checked (unverified)
//! 0x1C  u32  field_1c        same value in every archive checked (unverified)
//! 0x20  u16  field_20        small values seen (3..7); meaning unknown
//! 0x22  u16  field_22        1 (2 seen once); meaning unknown
//! 0x24  u32  field_24        entry count of this archive; see below
//! 0x28  u32  key_hash        shared between some distinct archives (key or platform selector?)
//! 0x2C  u8   field_2c        small value (1 or 2 seen); likely the lookup-table index width k
//! 0x2D  u8   field_2d        same value in every archive checked (unverified)
//! 0x2E  u8   field_2e        same value in every archive checked (unverified)
//! 0x2F  u8   field_2f        zero in every archive checked
//! 0x30  u32  field_30        same value in every archive checked (data alignment?)
//! 0x34  ...  zero up to 0x40
//! 0x40  ...  encrypted TOC up to toc_end (high entropy, close to 8 bits/byte)
//! ```
//!
//! # Entry count and nested archives
//!
//! `field_24` (0x24) is the number of entries in *this* archive. An RPF9
//! archive can contain other RPF9 archives, stored uncompressed: the nested
//! header (`9FPR`) sits at a 4 KiB-aligned offset in the parent's data
//! area. A count that looks too small for the number of zlib streams in a
//! file usually means most of the streams belong to a nested archive.
//! Use [`find_nested_headers`] to list the direct children.
//!
//! The region `[field_08, toc_end)` matches `n x (8 + k)` bytes rounded up
//! to 16 (n = `field_24`, k = `flags[0]`) on many headers, but not on all:
//! some nested headers are larger than predicted, and the excess is
//! high-entropy, so that region is most likely encrypted along with the TOC
//! rather than a plaintext index. This is an open question; publish only
//! aggregate relations about it.
//!
//! # What the archive body looks like
//!
//! - Data usually starts on a 4 KiB boundary, sometimes 0x10 past it, with
//!   zero padding before it. In small archives the data follows `toc_end`
//!   straight away.
//! - Payloads are zlib streams (`78 DA` is the usual header). A file bigger
//!   than 64 KiB is a chain of separate zlib streams, each inflating to
//!   exactly 65536 bytes, packed one after another on 16-byte boundaries.
//!   The last stream of a chain is shorter.
//! - Some payloads are not zlib. They are probably encrypted, and the
//!   scanner skips them.
//! - Wrapped records (a name ending in `_Wrapped\0`, four u32s, then a
//!   **raw deflate** stream with no `78 xx` header, wbits -15) are invisible
//!   to [`scan_zlib_streams`]. TODO: raw-deflate scanning keyed on
//!   `_Wrapped\0`.
//!

use anyhow::{bail, Result};
use flate2::{Decompress, FlushDecompress, Status};

pub const RPF9_MAGIC: u32 = 0x52504639; // "9FPR" on disk

/// Size of the plaintext RPF9 header; the encrypted TOC starts here.
pub const RPF9_HEADER_SIZE: usize = 0x40;

/// Smallest prefix [`Rpf9Header::parse`] accepts: magic plus three u32s.
pub const RPF9_MIN_HEADER_SIZE: usize = 0x10;

/// Decompressed size of every block in a multi-block chain except the last.
pub const RPF9_CHUNK_SIZE: usize = 0x10000;

// ─── Header ──────────────────────────────────────────────────────────────────

/// The RPF9 header. Every field past the first four bytes is a guess at its
/// meaning, based on layout and cross-archive comparison only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rpf9Header {
    /// 0x04. End offset of the header plus encrypted TOC. On many archives
    /// zero padding starts here and runs to the next 4 KiB boundary; on
    /// others, data follows right away.
    pub toc_end : u32,
    /// 0x08. Unknown. Trails `toc_end` by a small, archive-dependent amount.
    /// Might be the size of a TOC sub-table.
    pub field_08: u32,
    /// 0x0C. Unknown. Grows with the archive. Maybe the names table length
    /// (RPF7 keeps that at 0x08).
    pub field_0c: u32,
    /// The rest of the 0x40-byte header, if the input was that long.
    pub ext     : Option<Rpf9HeaderExt>,
}

/// Header fields 0x10 to 0x40, parsed when the full header is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rpf9HeaderExt {
    /// 0x10. Different in every archive checked, so likely a per-archive
    /// hash, IV or key seed.
    pub archive_id: u64,
    /// 0x18. Same value in every archive checked (unverified).
    pub field_18  : u32,
    /// 0x1C. Same value in every archive checked (unverified).
    pub field_1c  : u32,
    /// 0x20. Small values seen (3..7). Meaning unknown.
    pub field_20  : u16,
    /// 0x22. Usually 1. Meaning unknown.
    pub field_22  : u16,
    /// 0x24. Number of entries in this archive. It counts direct entries
    /// only, which may themselves be nested RPF9 archives.
    pub field_24  : u32,
    /// 0x28. Some distinct archives share this value, so it may select a
    /// key or platform.
    pub key_hash  : u32,
    /// 0x2C..0x30. `flags[0]` is small (1 or 2 seen) and is probably the
    /// width in bytes of a lookup-table index (see module docs).
    pub flags     : [u8; 4],
    /// 0x30. Same value in every archive checked; possibly the data
    /// alignment.
    pub field_30  : u32,
    /// True when 0x34..0x40 are all zero, as in every archive checked.
    pub reserved_zero: bool,
}

impl Rpf9Header {
    /// Parse the header from the start of an archive. Needs at least
    /// [`RPF9_MIN_HEADER_SIZE`] bytes. [`Rpf9Header::ext`] is filled in only
    /// when [`RPF9_HEADER_SIZE`] bytes are present.
    pub fn parse(d: &[u8]) -> Result<Self> {
        if d.len() < RPF9_MIN_HEADER_SIZE { bail!("RPF9 header too short ({} bytes)", d.len()); }
        let magic = le32(d, 0);
        if magic != RPF9_MAGIC { bail!("not an RPF9 archive (magic {:#010x})", magic); }

        let toc_end  = le32(d, 0x04);
        let field_08 = le32(d, 0x08);
        let field_0c = le32(d, 0x0C);

        let ext = (d.len() >= RPF9_HEADER_SIZE).then(|| Rpf9HeaderExt {
            archive_id: u64::from_le_bytes(d[0x10..0x18].try_into().unwrap()),
            field_18  : le32(d, 0x18),
            field_1c  : le32(d, 0x1C),
            field_20  : u16::from_le_bytes([d[0x20], d[0x21]]),
            field_22  : u16::from_le_bytes([d[0x22], d[0x23]]),
            field_24  : le32(d, 0x24),
            key_hash  : le32(d, 0x28),
            flags     : [d[0x2C], d[0x2D], d[0x2E], d[0x2F]],
            field_30  : le32(d, 0x30),
            reserved_zero: d[0x34..0x40].iter().all(|&b| b == 0),
        });

        Ok(Self { toc_end, field_08, field_0c, ext })
    }

    /// Byte range of the encrypted TOC, `0x40..toc_end`.
    pub fn toc_range(&self) -> std::ops::Range<usize> {
        RPF9_HEADER_SIZE..(self.toc_end as usize).max(RPF9_HEADER_SIZE)
    }

    /// Length of the encrypted TOC in bytes.
    pub fn toc_len(&self) -> usize {
        self.toc_range().len()
    }

    /// Checks that the header fields hold together for an archive of
    /// `file_len` bytes. Returns every problem found.
    pub fn validate(&self, file_len: usize) -> Vec<String> {
        let mut problems = Vec::new();
        let toc_end = self.toc_end as usize;
        if toc_end < RPF9_HEADER_SIZE {
            problems.push(format!("toc_end {:#x} is inside the 0x40-byte header", toc_end));
        }
        if toc_end > file_len {
            problems.push(format!("toc_end {:#x} is past the end of the file ({:#x})", toc_end, file_len));
        }
        if toc_end % 16 != 0 {
            problems.push(format!("toc_end {:#x} is not 16-byte aligned", toc_end));
        }
        if self.field_08 as usize > toc_end {
            problems.push(format!("field_08 {:#x} is larger than toc_end {:#x}", self.field_08, toc_end));
        }
        if let Some(ext) = &self.ext {
            if !ext.reserved_zero { problems.push("header bytes 0x34..0x40 are not zero".into()); }
        }
        problems
    }

    /// Number of direct entries in this archive (header field 0x24), when
    /// the full header was parsed. Entries can be nested RPF9 archives.
    pub fn entry_count(&self) -> Option<u32> {
        self.ext.as_ref().map(|e| e.field_24)
    }
}

/// Alignment of nested RPF9 archives inside their parent's data area.
pub const RPF9_NESTED_ALIGN: usize = 0x1000;

fn align_up(x: usize, align: usize) -> usize {
    x.div_ceil(align) * align
}

/// Finds the RPF9 archives nested (uncompressed) *directly* inside `data`,
/// which is the whole parent archive. Looks at every
/// [`RPF9_NESTED_ALIGN`]-aligned offset past 0 for a full header that
/// [`Rpf9Header::validate`]s against the bytes that follow it. After a
/// match at `off`, the scan skips the child's header and encrypted TOC
/// range `[off, off + toc_end)`, so grandchildren are not reported here:
/// call this function again on a child's own bytes to go one level deeper.
pub fn find_nested_headers(data: &[u8]) -> Vec<(usize, Rpf9Header)> {
    let mut out = Vec::new();
    let mut off = RPF9_NESTED_ALIGN;
    while off + RPF9_HEADER_SIZE <= data.len() {
        if data[off..off + 4] == *b"9FPR" {
            if let Ok(h) = Rpf9Header::parse(&data[off..]) {
                if h.ext.is_some() && h.validate(data.len() - off).is_empty() {
                    out.push((off, h.clone()));
                    // Skip the child's header + TOC; nested archives can only
                    // live past its toc_end.
                    off = align_up(off + h.toc_end as usize, RPF9_NESTED_ALIGN);
                    continue;
                }
            }
        }
        off += RPF9_NESTED_ALIGN;
    }
    out
}

fn le32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(d[off..off + 4].try_into().unwrap())
}

// ─── Zlib stream scanner ─────────────────────────────────────────────────────

/// One payload found by [`scan_zlib_streams`]. With `join_chains` on, this
/// can be several back-to-back zlib streams joined into one file.
#[derive(Debug, Clone)]
pub struct CarvedStream {
    /// Byte offset of the first zlib header, from the start of the scanned data.
    pub offset         : usize,
    /// Compressed bytes taken up by all blocks, not counting the padding between them.
    pub compressed_size: usize,
    /// Number of zlib streams in the payload.
    pub blocks         : usize,
    /// The decompressed payload.
    pub data           : Vec<u8>,
}

impl CarvedStream {
    /// File extension guessed from the payload's first bytes.
    pub fn kind(&self) -> &'static str {
        sniff_kind(&self.data)
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Join 64 KiB blocks that follow each other on 16-byte boundaries into
    /// one payload.
    pub join_chains: bool,
    /// Give up on a candidate stream that inflates past this many bytes.
    pub max_stream_output: usize,
    /// Drop payloads smaller than this.
    pub min_size: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { join_chains: true, max_stream_output: 64 << 20, min_size: 0 }
    }
}

/// Second bytes of the zlib headers the scanner accepts after 0x78: fastest
/// (01), fast (5E), default (9C) and best (DA) compression.
const ZLIB_FLG: [u8; 4] = [0x01, 0x5E, 0x9C, 0xDA];

/// True if `d[i..]` begins with a zlib header the scanner accepts.
pub fn is_zlib_header(d: &[u8], i: usize) -> bool {
    d.len() >= i + 2 && d[i] == 0x78 && ZLIB_FLG.contains(&d[i + 1])
}

/// Inflate one complete zlib stream at the start of `input`. Returns the
/// output and the number of input bytes used, or `None` if the data is not a
/// valid stream: bad header, corrupt deflate data, Adler-32 mismatch,
/// truncated input, or more than `max_output` bytes of output.
pub fn inflate_zlib_stream(input: &[u8], max_output: usize) -> Option<(Vec<u8>, usize)> {
    let mut dec = Decompress::new(true);
    // Start small: most candidates in a scan are false positives that fail
    // within a few bytes.
    let mut out: Vec<u8> = Vec::with_capacity(max_output.min(16 << 10));
    loop {
        if out.len() == out.capacity() {
            if out.len() >= max_output { return None; }
            let grow = out.len().max(4096).min(max_output - out.len());
            out.reserve_exact(grow);
        }
        let consumed = dec.total_in() as usize;
        let before_out = dec.total_out();
        let status = dec.decompress_vec(&input[consumed..], &mut out, FlushDecompress::None).ok()?;
        match status {
            Status::StreamEnd => return Some((out, dec.total_in() as usize)),
            Status::Ok | Status::BufError => {
                // No progress with room left in `out` means the input ran out.
                if dec.total_out() == before_out
                    && dec.total_in() as usize == consumed
                    && out.len() < out.capacity()
                {
                    return None;
                }
            }
        }
    }
}

/// Find every complete zlib stream in `data`, for archives such as RPF9
/// whose TOC can't be read.
///
/// Each byte pair `78 01`, `78 5E`, `78 9C` or `78 DA` is a candidate.
/// A candidate is kept only if it inflates to the end of the stream and the
/// Adler-32 checksum matches, so whatever comes back is intact. After a hit
/// the scan continues past the stream it found.
///
/// With `opts.join_chains`, a block that inflates to exactly 64 KiB and is
/// followed, at the next 16-byte boundary, by another valid stream is joined
/// with it into one payload. This is how RPF9 stores files over 64 KiB.
pub fn scan_zlib_streams(data: &[u8], opts: &ScanOptions) -> Vec<CarvedStream> {
    let mut found = Vec::new();
    let mut chain: Option<(CarvedStream, usize)> = None; // (payload, expected next offset)
    let mut i = 0usize;

    let flush = |c: CarvedStream, found: &mut Vec<CarvedStream>| {
        if c.data.len() >= opts.min_size { found.push(c); }
    };

    while i + 2 <= data.len() {
        let Some(rel) = data[i..].iter().position(|&b| b == 0x78) else { break };
        let j = i + rel;
        if !is_zlib_header(data, j) { i = j + 1; continue; }

        let Some((out, used)) = inflate_zlib_stream(&data[j..], opts.max_stream_output) else {
            i = j + 1;
            continue;
        };

        let full_block = out.len() == RPF9_CHUNK_SIZE;
        let next = (j + used + 15) & !15;

        match chain.take() {
            Some((mut c, expect)) if opts.join_chains && expect == j => {
                c.data.extend_from_slice(&out);
                c.blocks += 1;
                c.compressed_size += used;
                chain = Some((c, next));
            }
            prev => {
                if let Some((c, _)) = prev { flush(c, &mut found); }
                chain = Some((CarvedStream { offset: j, compressed_size: used, blocks: 1, data: out }, next));
            }
        }

        // A short block, or chaining off, ends the payload.
        if !opts.join_chains || !full_block {
            if let Some((c, _)) = chain.take() { flush(c, &mut found); }
        }
        i = j + used;
    }
    if let Some((c, _)) = chain.take() { flush(c, &mut found); }
    found
}

/// Guess a file extension from a payload's first bytes.
pub fn sniff_kind(b: &[u8]) -> &'static str {
    const SIGS: &[(&[u8], &str)] = &[
        (b"RSC",           "rsc"),
        (b"9FPR",          "rpf"),
        (b"\x89PNG",       "png"),
        (b"DDS ",          "dds"),
        (b"\xEF\xBB\xBF<?xml", "xml"),
        (b"<?xml",         "xml"),
        (b"PSIN",          "psin"),
        (b"RDS5",          "rds5"),
        (b"PK\x03\x04",    "zip"),
        (b"MZ",            "pe"),
        (b"OggS",          "ogg"),
        (b"RIFF",          "riff"),
        (b"BIK",           "bik"),
        (b"KB2",           "bk2"),
    ];
    for (sig, ext) in SIGS {
        if b.starts_with(sig) { return ext; }
    }
    let head = &b[..b.len().min(4096)];
    if !head.is_empty() {
        let printable = head.iter().filter(|&&c| (32..127).contains(&c) || matches!(c, 9 | 10 | 13)).count();
        if printable * 100 > head.len() * 97 {
            let has_tag = head.windows(2).any(|w| w == b"</" || w == b"/>");
            return if has_tag { "xml" } else { "txt" };
        }
    }
    "bin"
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    /// Builds a fully synthetic 0x40-byte header: only the magic and the
    /// layout invariants documented in the module docs are format-defined;
    /// every field value is invented for the tests. The three built-in
    /// vectors below exercise different shapes (small TOC, wide index,
    /// shared key selector).
    #[allow(clippy::too_many_arguments)] // one parameter per header field keeps the vectors readable
    fn synth_header(toc_end: u32, field_08: u32, field_0c: u32, archive_id: u64,
                    entries: u32, key_hash: u32, index_width: u8, field_20: u16,
                    field_22: u16) -> [u8; 0x40] {
        assert!(toc_end % 16 == 0 && (field_08 as usize) <= toc_end as usize && index_width <= 2);
        let mut h = [0u8; 0x40];
        h[0x00..0x04].copy_from_slice(&RPF9_MAGIC.to_le_bytes());
        h[0x04..0x08].copy_from_slice(&toc_end.to_le_bytes());
        h[0x08..0x0C].copy_from_slice(&field_08.to_le_bytes());
        h[0x0C..0x10].copy_from_slice(&field_0c.to_le_bytes());
        h[0x10..0x18].copy_from_slice(&archive_id.to_le_bytes());
        // Invented constants for the "same everywhere (unverified)" fields.
        h[0x18..0x1C].copy_from_slice(&0x0031_9C40u32.to_le_bytes());
        h[0x1C..0x20].copy_from_slice(&0x0000_01C0u32.to_le_bytes());
        h[0x20..0x22].copy_from_slice(&field_20.to_le_bytes());
        h[0x22..0x24].copy_from_slice(&field_22.to_le_bytes());
        h[0x24..0x28].copy_from_slice(&entries.to_le_bytes());
        h[0x28..0x2C].copy_from_slice(&key_hash.to_le_bytes());
        h[0x2C] = index_width;
        h[0x2D] = 0x0D; // invented flag bytes, distinct from anything observed
        h[0x2E] = 0x07;
        h[0x2F] = 0x00;
        h[0x30..0x34].copy_from_slice(&0x10u32.to_le_bytes());
        h // 0x34..0x40 stay zero
    }

    /// Small archive: tiny TOC, 5 direct entries, 1-byte index width. All
    /// field values invented (the format only fixes the magic and alignment
    /// invariants).
    fn small_hdr() -> [u8; 0x40] {
        synth_header(0x05A0, 0x04E0, 0x00C0, 0x4455_6677_8899_AABB, 5, 0x1122_3344, 1, 3, 1)
    }
    /// Large archive: wide 2-byte index, many entries.
    fn wide_hdr() -> [u8; 0x40] {
        synth_header(0xB440, 0xA980, 0x2E60, 0x0102_0304_0506_0708, 507, 0x5E6F_7081, 2, 6, 1)
    }
    /// Medium archive sharing `wide_hdr`'s key selector (the "key or
    /// platform selector" hypothesis).
    fn shared_key_hdr() -> [u8; 0x40] {
        synth_header(0x0820, 0x0740, 0x00A0, 0x9988_7766_5544_3322, 3, 0x5E6F_7081, 1, 5, 1)
    }

    fn first16(h: &[u8; 0x40]) -> [u8; 16] {
        h[..16].try_into().unwrap()
    }

    fn zlib(data: &[u8], level: u32) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::new(level));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Fill bytes from a fixed LCG, so the "encrypted" TOC is high entropy
    /// and the test is deterministic.
    fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..len).map(|_| { x = x.wrapping_mul(1664525).wrapping_add(1013904223); (x >> 24) as u8 }).collect()
    }

    fn pad_to(buf: &mut Vec<u8>, align: usize) {
        while buf.len() % align != 0 { buf.push(0); }
    }

    /// A made-up RPF9 archive: a synthetic header, a noise TOC, then the
    /// body layout: a small XML file at 0x1000, a 3-block chained file at
    /// 0x2000, and a non-zlib (encrypted) blob.
    fn synthetic_rpf9() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<catalog>\n  <file name=\"sample\"/>\n</catalog>\n".to_vec();
        // 2.5 chunks: two full 64 KiB blocks and a shorter last one.
        let big: Vec<u8> = (0..RPF9_CHUNK_SIZE * 5 / 2).map(|i| (i % 251) as u8 ^ (i >> 9) as u8).collect();

        let mut f = small_hdr().to_vec();
        f.extend(noise(0x5A0 - 0x40, 0x1234));
        pad_to(&mut f, 0x1000);

        assert_eq!(f.len(), 0x1000);
        f.extend(zlib(&xml, 9));
        pad_to(&mut f, 0x1000);

        assert_eq!(f.len(), 0x2000);
        for chunk in big.chunks(RPF9_CHUNK_SIZE) {
            f.extend(zlib(chunk, 9));
            pad_to(&mut f, 16);
        }
        pad_to(&mut f, 0x1000);
        f.extend(noise(0x800, 0x9876));
        (f, xml, big)
    }

    // ── Header ──

    #[test]
    fn header_vectors_first_16_bytes() {
        let cases: [(&[u8; 16], u32, u32, u32); 3] = [
            (&first16(&small_hdr()),      0x05A0, 0x04E0, 0x00C0),
            (&first16(&wide_hdr()),       0xB440, 0xA980, 0x2E60),
            (&first16(&shared_key_hdr()), 0x0820, 0x0740, 0x00A0),
        ];
        for (bytes, toc_end, f08, f0c) in cases {
            assert_eq!(&bytes[0..4], b"9FPR");
            let h = Rpf9Header::parse(bytes).unwrap();
            assert_eq!(h.toc_end, toc_end);
            assert_eq!(h.field_08, f08);
            assert_eq!(h.field_0c, f0c);
            assert!(h.ext.is_none(), "16 bytes should not fill the extended header");
            assert_eq!(h.toc_range(), 0x40..toc_end as usize);
        }
    }

    #[test]
    fn header_vectors_full() {
        let s = Rpf9Header::parse(&small_hdr()).unwrap();
        let e = s.ext.as_ref().unwrap();
        assert_eq!(e.archive_id, 0x4455_6677_8899_AABB);
        assert_eq!(e.field_18, 0x0031_9C40);
        assert_eq!(e.field_1c, 0x1C0);
        assert_eq!((e.field_20, e.field_22), (3, 1));
        assert_eq!(e.field_24, 5);
        assert_eq!(e.key_hash, 0x1122_3344);
        assert_eq!(e.flags, [0x01, 0x0D, 0x07, 0x00]);
        assert_eq!(e.field_30, 0x10);
        assert!(e.reserved_zero);
        assert_eq!(s.toc_len(), 0x560);

        let c = Rpf9Header::parse(&wide_hdr()).unwrap();
        let ce = c.ext.as_ref().unwrap();
        assert_eq!(ce.field_24, 507);
        assert_eq!(ce.flags[0], 2);
        assert_eq!(c.toc_len(), 0xB400);

        // shared_key_hdr and wide_hdr share key_hash; small_hdr does not.
        let a = Rpf9Header::parse(&shared_key_hdr()).unwrap();
        assert_eq!(a.ext.as_ref().unwrap().key_hash, ce.key_hash);
        assert_ne!(e.key_hash, ce.key_hash);
        assert_ne!(a.ext.as_ref().unwrap().archive_id, ce.archive_id);
    }

    #[test]
    fn test_vectors_are_fully_synthetic() {
        // Guards the review rule: every test vector is built by
        // `synth_header` from invented values, and the fixed fields carry the
        // invented constants above. Only the magic and the zero tail are
        // format-defined.
        for h in [small_hdr(), wide_hdr(), shared_key_hdr()] {
            assert_eq!(&h[0x00..0x04], &RPF9_MAGIC.to_le_bytes());
            assert_eq!(&h[0x18..0x1C], &0x0031_9C40u32.to_le_bytes());
            assert_eq!(&h[0x1C..0x20], &0x0000_01C0u32.to_le_bytes());
            assert_eq!((h[0x2D], h[0x2E], h[0x2F]), (0x0D, 0x07, 0x00));
            assert!(h[0x34..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn entry_count_and_nested_archives() {
        assert_eq!(Rpf9Header::parse(&small_hdr()).unwrap().entry_count(), Some(5));
        assert_eq!(Rpf9Header::parse(&wide_hdr()).unwrap().entry_count(), Some(507));
        assert_eq!(Rpf9Header::parse(&first16(&small_hdr())).unwrap().entry_count(), None);

        // Parent with two nested archives at 4 KiB boundaries.
        let (child, _, _) = synthetic_rpf9();
        let mut parent = small_hdr().to_vec();
        parent.extend(noise(0x5A0 - 0x40, 0x4242));
        pad_to(&mut parent, 0x1000);
        parent.extend(&child);
        pad_to(&mut parent, 0x1000);
        let second = parent.len();
        let mut child2 = wide_hdr().to_vec();
        child2.extend(noise(0xB440 - 0x40, 0x77));
        parent.extend(&child2);
        // A "9FPR" that is not on a 4 KiB boundary is ignored.
        parent.extend(b"9FPR");
        parent.extend(noise(0x100, 1));

        let found = find_nested_headers(&parent);
        let offsets: Vec<usize> = found.iter().map(|(o, _)| *o).collect();
        assert_eq!(offsets, vec![0x1000, second]);
        assert_eq!(found[0].1.entry_count(), Some(5));
        assert_eq!(found[1].1.entry_count(), Some(507));
        assert!(find_nested_headers(&child2).is_empty());
    }

    /// A grandchild header inside the child's header+TOC range must not be
    /// listed as a sibling of the child: after a match at `off`, the scan
    /// skips `[off, off + toc_end)`. Going one level deeper (scanning the
    /// child's own bytes) is how the grandchild is reached.
    #[test]
    fn nested_headers_lists_direct_children_only() {
        // Child: TOC extends to 0x4000, so the parent's skip range covers the
        // grandchild embedded at child-relative 0x3000. (A real nested
        // archive's TOC is high-entropy noise; a `9FPR` header embedded in
        // that noise is what the skip must not double-report.)
        let mut child = synth_header(0x4000, 0x3E00, 0x00C0, 0x7777_8888_9999_AAAA, 3, 0x2468_ACE0, 1, 4, 1).to_vec();
        child.extend(noise(0x4000 - 0x40, 0x1F1F));

        // Grandchild: a small archive header at child-relative 0x3000,
        // 4 KiB-aligned in both the child's and the parent's coordinates.
        let gc_rel = 0x3000;
        let grandchild = shared_key_hdr(); // toc_end 0x820 fits in the remaining 0x1000 bytes
        child[gc_rel..gc_rel + grandchild.len()].copy_from_slice(&grandchild);

        let mut parent = small_hdr().to_vec();
        parent.extend(noise(0x5A0 - 0x40, 0x4242));
        pad_to(&mut parent, 0x1000);
        parent.extend(&child);

        // One direct child only, even though the grandchild is also
        // 4 KiB-aligned in the parent's coordinates (at 0x4000).
        let found = find_nested_headers(&parent);
        assert_eq!(found.len(), 1, "offsets: {:?}", found.iter().map(|(o, _)| o).collect::<Vec<_>>());
        assert_eq!(found[0].0, 0x1000);
        assert_eq!(found[0].1.entry_count(), Some(3));

        // Going one level deeper finds the grandchild inside the child.
        let inner = find_nested_headers(&parent[0x1000..]);
        assert_eq!(inner.iter().map(|(o, _)| *o).collect::<Vec<_>>(), vec![gc_rel]);
        assert_eq!(inner[0].1.entry_count(), Some(3));
    }

    #[test]
    fn header_validate() {
        assert!(Rpf9Header::parse(&small_hdr()).unwrap().validate(0x10000).is_empty());
        assert!(Rpf9Header::parse(&wide_hdr()).unwrap().validate(0x11000).is_empty());
        assert!(Rpf9Header::parse(&shared_key_hdr()).unwrap().validate(0x2000).is_empty());
        // A file shorter than the TOC fails validation.
        assert!(!Rpf9Header::parse(&wide_hdr()).unwrap().validate(0x1000).is_empty());
    }

    #[test]
    fn header_rejects_bad_input() {
        let small16 = first16(&small_hdr());
        assert!(Rpf9Header::parse(&small16[..12]).is_err());
        let mut rpf8 = small16;
        rpf8[0] = b'8';
        assert!(Rpf9Header::parse(&rpf8).is_err());
    }

    #[test]
    fn rpf9_magic_constant() {
        assert_eq!(RPF9_MAGIC.to_le_bytes(), *b"9FPR");
        assert_eq!(crate::RPF9_MAGIC, RPF9_MAGIC);
    }

    // ── Zlib scanner ──

    #[test]
    fn scanner_finds_all_header_variants() {
        let payload = b"the quick brown fox jumps over the lazy dog, repeatedly. ".repeat(20);
        let mut buf = noise(37, 1);
        let mut offs = Vec::new();
        for (lvl, flg) in [(1u32, 0x01u8), (2, 0x5E), (6, 0x9C), (9, 0xDA)] {
            offs.push(buf.len());
            let z = zlib(&payload, lvl);
            assert_eq!(z[..2], [0x78, flg], "level {lvl}");
            buf.extend(z);
            buf.extend(noise(13, lvl + 7));
        }
        let got = scan_zlib_streams(&buf, &ScanOptions::default());
        assert_eq!(got.iter().map(|s| s.offset).collect::<Vec<_>>(), offs);
        for s in &got {
            assert_eq!(s.data, payload);
            assert_eq!(s.blocks, 1);
            assert_eq!(s.kind(), "txt");
        }
    }

    #[test]
    fn scanner_ignores_false_headers_and_corrupt_streams() {
        let payload = b"<a><b/></a>".repeat(50);
        let mut good = zlib(&payload, 9);
        // Bare zlib magics with nothing valid behind them.
        let mut buf = vec![0x78, 0xDA, 0x00, 0x78, 0x9C, 0xFF, 0xFF, 0x78, 0x01];
        // Same stream with a broken Adler-32 trailer.
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        buf.extend(&bad);
        // Truncated stream.
        buf.extend(&good[..good.len() / 2]);
        let good_off = buf.len();
        buf.append(&mut good);
        buf.extend([0x78, 0x5E]); // dangling at EOF

        let got = scan_zlib_streams(&buf, &ScanOptions::default());
        assert_eq!(got.len(), 1, "{:?}", got.iter().map(|s| s.offset).collect::<Vec<_>>());
        assert_eq!(got[0].offset, good_off);
        assert_eq!(got[0].data, payload);
        assert_eq!(got[0].kind(), "xml");
    }

    #[test]
    fn scanner_joins_64k_chains() {
        let (file, xml, big) = synthetic_rpf9();
        let got = scan_zlib_streams(&file, &ScanOptions::default());
        assert_eq!(got.len(), 2, "{:?}", got.iter().map(|s| (s.offset, s.blocks)).collect::<Vec<_>>());

        assert_eq!(got[0].offset, 0x1000);
        assert_eq!(got[0].data, xml);
        assert_eq!(got[0].kind(), "xml");

        assert_eq!(got[1].offset, 0x2000);
        assert_eq!(got[1].blocks, 3);
        assert_eq!(got[1].data.len(), big.len());
        assert!(got[1].data == big);
    }

    #[test]
    fn scanner_without_chaining_returns_blocks() {
        let (file, _, big) = synthetic_rpf9();
        let opts = ScanOptions { join_chains: false, ..Default::default() };
        let got = scan_zlib_streams(&file, &opts);
        let sizes: Vec<usize> = got.iter().map(|s| s.data.len()).collect();
        assert_eq!(sizes[1..], [RPF9_CHUNK_SIZE, RPF9_CHUNK_SIZE, big.len() - 2 * RPF9_CHUNK_SIZE]);
    }

    #[test]
    fn scanner_does_not_join_misaligned_or_short_blocks() {
        let a: Vec<u8> = (0..RPF9_CHUNK_SIZE).map(|i| (i * 7) as u8).collect();
        let b = b"tail".repeat(100);
        // Full block, then a 32-byte gap: the next stream is not at the next
        // 16-byte boundary, so it is a separate file.
        let mut buf = zlib(&a, 9);
        pad_to(&mut buf, 16);
        buf.extend([0u8; 32]);
        let second = buf.len();
        buf.extend(zlib(&b, 9));
        pad_to(&mut buf, 16);
        // A short block followed straight away by another stream: the short
        // block ended its file.
        let third = buf.len();
        buf.extend(zlib(&b, 9));

        let got = scan_zlib_streams(&buf, &ScanOptions::default());
        assert_eq!(got.iter().map(|s| (s.offset, s.blocks)).collect::<Vec<_>>(),
                   vec![(0, 1), (second, 1), (third, 1)]);
    }

    #[test]
    fn scanner_respects_limits() {
        let payload = vec![0u8; 200_000];
        let z = zlib(&payload, 9);
        assert!(inflate_zlib_stream(&z, 100_000).is_none());
        assert_eq!(inflate_zlib_stream(&z, 200_000).unwrap().0.len(), 200_000);

        let opts = ScanOptions { min_size: 1000, ..Default::default() };
        let mut buf = zlib(b"tiny", 9);
        buf.extend(zlib(&payload[..5000], 9));
        let got = scan_zlib_streams(&buf, &opts);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data.len(), 5000);
    }

    #[test]
    fn sniff_kinds() {
        assert_eq!(sniff_kind(b"PSIN\x01\x00"), "psin");
        assert_eq!(sniff_kind(b"RSC\x07...."), "rsc");
        assert_eq!(sniff_kind(b"9FPR...."), "rpf");
        assert_eq!(sniff_kind(b"\xEF\xBB\xBF<?xml version"), "xml");
        assert_eq!(sniff_kind(b"plain words\n"), "txt");
        assert_eq!(sniff_kind(&[0x00, 0xFF, 0x10, 0x80]), "bin");
        assert_eq!(sniff_kind(b""), "bin");
    }
}
