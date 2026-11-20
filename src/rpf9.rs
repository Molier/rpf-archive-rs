//! RPF9 (`9FPR` on disk): header parsing and a zlib stream scanner.
//!
//! RPF9 is the next archive version after RDR2's RPF8. Its table of contents
//! is encrypted with a scheme this crate does not know, so [`RpfArchive`]
//! parses the plaintext header and reports no entries. The file bodies are
//! mostly plain zlib streams, and [`scan_zlib_streams`] pulls those out
//! without the TOC.
//!
//! # Header layout
//!
//! The plaintext header is 0x40 bytes, all little-endian. What each field
//! means is inferred from five sample archives, so the names are the
//! hypotheses, and the docs on [`Rpf9Header`] give the evidence for each:
//!
//! ```text
//! 0x00  u32  magic           0x52504639 ("9FPR" on disk)
//! 0x04  u32  toc_end         end of the encrypted TOC; zero padding or file data follows
//! 0x08  u32  field_08        unknown, a little below toc_end (TOC sub-size?)
//! 0x0C  u32  field_0c        unknown (names length?)
//! 0x10  u64  archive_id      different in every archive (per-archive hash, IV or key seed?)
//! 0x18  u32  field_18        0x00047A00 in every sample
//! 0x1C  u32  field_1c        0x00000150 in every sample
//! 0x20  u16  field_20        3, 5 or 6
//! 0x22  u16  field_22        1 in every sample
//! 0x24  u32  field_24        2 .. 418; not the file count (script.rpf: 2, ~1000 streams)
//! 0x28  u32  key_hash        shared between some archives (key or platform selector?)
//! 0x2C  u8   field_2c        1 or 2
//! 0x2D  u8   field_2d        0x0F in every sample
//! 0x2E  u8   field_2e        0x09 in every sample
//! 0x2F  u8   field_2f        0x00 in every sample
//! 0x30  u32  field_30        0x10 in every sample (data alignment?)
//! 0x34  ...  zero up to 0x40
//! 0x40  ...  encrypted TOC up to toc_end (byte entropy 7.7 to 8.0 bits)
//! ```
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
//! - Some payloads (most of `script.rpf`) are not zlib. They are probably
//!   encrypted, and the scanner skips them.
//!
//! [`RpfArchive`]: crate::RpfArchive

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
/// meaning, checked against the sample archives only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rpf9Header {
    /// 0x04. End offset of the header plus encrypted TOC. In 3 of 5 samples
    /// zero padding starts exactly here and runs to the next 4 KiB boundary.
    /// In the other two, data follows right away.
    pub toc_end : u32,
    /// 0x08. Unknown. Equals `toc_end - 0x20` in small archives
    /// (0x260/0x240, 0x360/0x340), `toc_end - 0x30` / `- 0x40` in others, and
    /// is 0x1060 below it in common.rpf. Might be the size of a TOC sub-table.
    pub field_08: u32,
    /// 0x0C. Unknown. 0x40 .. 0x3A10 in the samples, growing with the
    /// archive. Maybe the names table length (RPF7 keeps that at 0x08).
    pub field_0c: u32,
    /// The rest of the 0x40-byte header, if the input was that long.
    pub ext     : Option<Rpf9HeaderExt>,
}

/// Header fields 0x10 to 0x40, parsed when the full header is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rpf9HeaderExt {
    /// 0x10. Different in every sample, so likely a per-archive hash, IV or
    /// key seed.
    pub archive_id: u64,
    /// 0x18. 0x00047A00 in every sample.
    pub field_18  : u32,
    /// 0x1C. 0x150 in every sample.
    pub field_1c  : u32,
    /// 0x20. 3, 5 or 6.
    pub field_20  : u16,
    /// 0x22. 1 in every sample.
    pub field_22  : u16,
    /// 0x24. 2 to 418. It is not the file count: script.rpf has 2 here and
    /// about 1000 zlib streams.
    pub field_24  : u32,
    /// 0x28. Some archives share this value (appdata0.rpf and common.rpf;
    /// both pack archives), so it may select a key or platform.
    pub key_hash  : u32,
    /// 0x2C..0x30. `[1|2, 0x0F, 0x09, 0x00]` in the samples.
    pub flags     : [u8; 4],
    /// 0x30. 0x10 in every sample; possibly the data alignment.
    pub field_30  : u32,
    /// True when 0x34..0x40 are all zero, as in every sample.
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
    use crate::archive::{RpfArchive, RpfEncryption, RpfVersion};
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    // First 16 bytes of three RPF9 archives, as hex-dumped.
    const SCRIPT_16: [u8; 16] = [
        0x39, 0x46, 0x50, 0x52, 0x60, 0x02, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ];
    const COMMON_16: [u8; 16] = [
        0x39, 0x46, 0x50, 0x52, 0x80, 0x95, 0x00, 0x00, 0x20, 0x85, 0x00, 0x00, 0x10, 0x3A, 0x00, 0x00,
    ];
    const APPDATA0_16: [u8; 16] = [
        0x39, 0x46, 0x50, 0x52, 0x60, 0x03, 0x00, 0x00, 0x40, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    ];

    // Full 0x40-byte headers of the same archives.
    const SCRIPT_HDR: [u8; 0x40] = [
        0x39, 0x46, 0x50, 0x52, 0x60, 0x02, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x70, 0x15, 0xBB, 0x52, 0xAE, 0x8E, 0xF8, 0x86, 0x00, 0x7A, 0x04, 0x00, 0x50, 0x01, 0x00, 0x00,
        0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x54, 0x27, 0xA9, 0xC0, 0x01, 0x0F, 0x09, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const COMMON_HDR: [u8; 0x40] = [
        0x39, 0x46, 0x50, 0x52, 0x80, 0x95, 0x00, 0x00, 0x20, 0x85, 0x00, 0x00, 0x10, 0x3A, 0x00, 0x00,
        0x5C, 0x94, 0x68, 0x0D, 0xCD, 0xEB, 0x13, 0x49, 0x00, 0x7A, 0x04, 0x00, 0x50, 0x01, 0x00, 0x00,
        0x06, 0x00, 0x01, 0x00, 0xA2, 0x01, 0x00, 0x00, 0x3E, 0x57, 0x72, 0xDA, 0x02, 0x0F, 0x09, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const APPDATA0_HDR: [u8; 0x40] = [
        0x39, 0x46, 0x50, 0x52, 0x60, 0x03, 0x00, 0x00, 0x40, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x99, 0x37, 0xE6, 0x24, 0x72, 0xDF, 0x66, 0xB7, 0x00, 0x7A, 0x04, 0x00, 0x50, 0x01, 0x00, 0x00,
        0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3E, 0x57, 0x72, 0xDA, 0x01, 0x0F, 0x09, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

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

    /// A made-up RPF9 archive: the real script.rpf header, a noise TOC,
    /// then the RPF9 body layout: a small XML file at 0x1000, a 3-block
    /// chained file at 0x2000, and a non-zlib (encrypted) blob.
    fn synthetic_rpf9() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CDataFileMgr__ContentsOfDataFileXml>\n  <dataFiles/>\n</CDataFileMgr__ContentsOfDataFileXml>\n".to_vec();
        // 2.5 chunks: two full 64 KiB blocks and a shorter last one.
        let big: Vec<u8> = (0..RPF9_CHUNK_SIZE * 5 / 2).map(|i| (i % 251) as u8 ^ (i >> 9) as u8).collect();

        let mut f = SCRIPT_HDR.to_vec();
        f.extend(noise(0x260 - 0x40, 0x1234));
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
            (&SCRIPT_16,   0x0260, 0x0240, 0x0080),
            (&COMMON_16,   0x9580, 0x8520, 0x3A10),
            (&APPDATA0_16, 0x0360, 0x0340, 0x0040),
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
        let s = Rpf9Header::parse(&SCRIPT_HDR).unwrap();
        let e = s.ext.as_ref().unwrap();
        assert_eq!(e.archive_id, 0x86F8_8EAE_52BB_1570);
        assert_eq!(e.field_18, 0x0004_7A00);
        assert_eq!(e.field_1c, 0x150);
        assert_eq!((e.field_20, e.field_22), (3, 1));
        assert_eq!(e.field_24, 2);
        assert_eq!(e.key_hash, 0xC0A9_2754);
        assert_eq!(e.flags, [0x01, 0x0F, 0x09, 0x00]);
        assert_eq!(e.field_30, 0x10);
        assert!(e.reserved_zero);
        assert_eq!(s.toc_len(), 0x220);

        let c = Rpf9Header::parse(&COMMON_HDR).unwrap();
        let ce = c.ext.as_ref().unwrap();
        assert_eq!(ce.field_24, 418);
        assert_eq!(ce.flags[0], 2);
        assert_eq!(c.toc_len(), 0x9540);

        // appdata0 and common share key_hash; script does not.
        let a = Rpf9Header::parse(&APPDATA0_HDR).unwrap();
        assert_eq!(a.ext.as_ref().unwrap().key_hash, ce.key_hash);
        assert_ne!(e.key_hash, ce.key_hash);
        assert_ne!(a.ext.as_ref().unwrap().archive_id, ce.archive_id);
    }

    #[test]
    fn header_validate() {
        assert!(Rpf9Header::parse(&SCRIPT_HDR).unwrap().validate(4_358_960).is_empty());
        assert!(Rpf9Header::parse(&COMMON_HDR).unwrap().validate(6_642_192).is_empty());
        assert!(Rpf9Header::parse(&APPDATA0_HDR).unwrap().validate(8_880).is_empty());
        // A file shorter than the TOC fails validation.
        assert!(!Rpf9Header::parse(&COMMON_HDR).unwrap().validate(0x1000).is_empty());
    }

    #[test]
    fn header_rejects_bad_input() {
        assert!(Rpf9Header::parse(&SCRIPT_16[..12]).is_err());
        let mut rpf8 = SCRIPT_16;
        rpf8[0] = b'8';
        assert!(Rpf9Header::parse(&rpf8).is_err());
    }

    // ── Archive dispatch ──

    #[test]
    fn archive_parse_dispatches_to_v9() {
        let (file, _, _) = synthetic_rpf9();
        let a = RpfArchive::parse(&file, "script.rpf", None).unwrap();
        assert_eq!(a.version, RpfVersion::V9);
        assert_eq!(a.encryption, RpfEncryption::Unknown);
        assert!(a.encryption.is_encrypted());
        assert!(a.entries.is_empty());
    }

    #[test]
    fn archive_parse_rejects_truncated_toc() {
        // 16 bytes only: toc_end 0x260 is past the end of the data.
        assert!(RpfArchive::parse(&SCRIPT_16, "script.rpf", None).is_err());
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

    /// Runs against the sample archives when they are on disk; does nothing
    /// otherwise. Set RPF9_SAMPLE_DIR to point it somewhere else.
    #[test]
    fn real_samples_if_present() {
        let dir = std::env::var("RPF9_SAMPLE_DIR")
            .unwrap_or_else(|_| "/opt/gta6-analysis/extracted/torrent_files".into());
        for name in ["appdata0.rpf", "script.rpf", "common.rpf"] {
            let p = std::path::Path::new(&dir).join(name);
            let Ok(data) = std::fs::read(&p) else { continue };
            let h = Rpf9Header::parse(&data).unwrap();
            assert!(h.validate(data.len()).is_empty(), "{name}: {:?}", h.validate(data.len()));
            let a = RpfArchive::parse(&data, name, None).unwrap();
            assert_eq!(a.version, RpfVersion::V9);
            let found = scan_zlib_streams(&data, &ScanOptions::default());
            eprintln!("{name}: {} zlib payloads", found.len());
            // No stream can start inside the header or the encrypted TOC.
            assert!(found.iter().all(|s| s.offset >= h.toc_end as usize), "{name}");
        }
    }
}
