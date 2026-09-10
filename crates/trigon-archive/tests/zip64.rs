//! Zip64, on both sides.
//!
//! Written blind and untested until now, which is the wrong order. Two boundaries matter and neither
//! needs a four-gigabyte fixture: an entry that carries zip64 extra fields, and an archive with more
//! members than the 16-bit count in the end-of-central-directory record can hold.

use std::io::{Cursor, Write};
use std::sync::Arc;

use trigon_archive::{Limits, SourceMap, zip};
use trigon_core::Note;

fn read(bytes: Vec<u8>) -> trigon_archive::Archive {
    let mut notes: Vec<Note> = Vec::new();
    zip::read(
        Arc::new(SourceMap::owned(bytes)),
        &Limits::default(),
        &mut notes,
    )
    .unwrap()
}

fn write(a: &trigon_archive::Archive) -> Vec<u8> {
    let mut out = Vec::new();
    zip::write(a, &mut out, true).unwrap();
    out
}

#[test]
fn reads_zip64_extra_fields() {
    // `large_file` forces the zip64 extra field regardless of the actual size, which is exactly the
    // parse path we need to cover without writing four gigabytes.
    use zip_crate::write::SimpleFileOptions;
    let opts = SimpleFileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored)
        .large_file(true);
    let mut w = zip_crate::ZipWriter::new(Cursor::new(Vec::new()));
    w.start_file("big.bin", opts).unwrap();
    w.write_all(b"not actually big").unwrap();
    let bytes = w.finish().unwrap().into_inner();

    let a = read(bytes);
    assert_eq!(a.entries.len(), 1);
    assert_eq!(
        a.entries[0].body_bytes().unwrap().as_ref(),
        b"not actually big"
    );
    assert_eq!(a.entries[0].meta.size, 16);
}

#[test]
fn round_trips_a_zip64_entry() {
    use zip_crate::write::SimpleFileOptions;
    let opts = SimpleFileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored)
        .large_file(true);
    let mut w = zip_crate::ZipWriter::new(Cursor::new(Vec::new()));
    for name in ["a.bin", "b.bin"] {
        w.start_file(name, opts).unwrap();
        w.write_all(name.as_bytes()).unwrap();
    }
    let a = read(w.finish().unwrap().into_inner());
    let once = write(&a);
    let b = read(once.clone());
    assert_eq!(
        write(&b),
        once,
        "re-serializing a zip64 archive changed the bytes"
    );
    assert_eq!(b.entries.len(), 2);
}

#[test]
fn more_members_than_a_16_bit_count_can_hold() {
    // 0xFFFF is the largest count the classic end-of-central-directory record can express, so past
    // it the writer has to emit a zip64 record and a locator, and the reader has to follow them.
    const N: usize = 70_000;
    use zip_crate::write::SimpleFileOptions;
    let opts =
        SimpleFileOptions::default().compression_method(zip_crate::CompressionMethod::Stored);
    let mut w = zip_crate::ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..N {
        w.start_file(format!("f{i:06}.txt"), opts).unwrap();
        w.write_all(b"x").unwrap();
    }
    let source = w.finish().unwrap().into_inner();

    let a = read(source);
    assert_eq!(a.entries.len(), N);

    let ours = write(&a);
    // Our own writer's zip64 path, read back by our own reader.
    let b = read(ours.clone());
    assert_eq!(b.entries.len(), N);
    assert_eq!(write(&b), ours, "the zip64 write path is not idempotent");

    // And by an external implementation.
    let mut z = zip_crate::ZipArchive::new(Cursor::new(ours)).expect("external reader rejected it");
    assert_eq!(z.len(), N);
    assert_eq!(z.by_index(0).unwrap().name(), "f000000.txt");

    // The classic record must be marked as overflowed rather than carrying a wrapped count.
    let bytes = write(&a);
    let eocd = bytes
        .windows(4)
        .rposition(|x| x == [0x50, 0x4b, 0x05, 0x06])
        .unwrap();
    let count = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]);
    assert_eq!(
        count, 0xFFFF,
        "the 16-bit count must signal overflow, not wrap"
    );
    assert!(
        bytes.windows(4).any(|x| x == [0x50, 0x4b, 0x06, 0x06]),
        "a zip64 end-of-central-directory record must be present"
    );
}
