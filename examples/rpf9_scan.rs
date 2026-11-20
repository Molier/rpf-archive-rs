//! Print an RPF9 archive's header, then list (or dump) its zlib payloads.
//!
//! usage: cargo run --release --example rpf9_scan -- FILE [OUT_DIR]
//!
//! Each payload is printed as `offset  blocks  compressed  size  kind`. If
//! OUT_DIR is given, each one is also written to `OUT_DIR/<offset-hex>.<kind>`.

use rpf_archive::{scan_zlib_streams, Rpf9Header, ScanOptions};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.first() else {
        eprintln!("usage: rpf9_scan FILE [OUT_DIR]");
        std::process::exit(2);
    };
    let data = std::fs::read(path)?;

    match Rpf9Header::parse(&data) {
        Ok(h) => {
            println!("# toc_end={:#x} field_08={:#x} field_0c={:#x} toc_len={:#x}",
                     h.toc_end, h.field_08, h.field_0c, h.toc_len());
            if let Some(e) = &h.ext {
                println!("# archive_id={:#018x} field_18={:#x} field_1c={:#x} field_20={} field_22={} \
                          field_24={} key_hash={:#010x} flags={:02x?} field_30={:#x}",
                         e.archive_id, e.field_18, e.field_1c, e.field_20, e.field_22,
                         e.field_24, e.key_hash, e.flags, e.field_30);
            }
            for p in h.validate(data.len()) { println!("# warning: {p}"); }
        }
        Err(e) => println!("# not RPF9 ({e}); scanning anyway"),
    }

    let out_dir = args.get(1).map(std::path::PathBuf::from);
    if let Some(d) = &out_dir { std::fs::create_dir_all(d)?; }

    let found = scan_zlib_streams(&data, &ScanOptions::default());
    let mut total = 0usize;
    for s in &found {
        total += s.data.len();
        println!("{:#010x}  {:3}  {:9}  {:9}  {}", s.offset, s.blocks, s.compressed_size, s.data.len(), s.kind());
        if let Some(d) = &out_dir {
            std::fs::write(d.join(format!("{:010x}.{}", s.offset, s.kind())), &s.data)?;
        }
    }
    println!("# {} payloads, {} bytes inflated", found.len(), total);
    Ok(())
}
