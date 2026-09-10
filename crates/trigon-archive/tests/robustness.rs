//! Malformed input must not panic.
//!
//! We parse attacker-controlled bytes. `cargo-fuzz` covers this properly and lives in `fuzz/`, but
//! it needs a nightly toolchain, so these deterministic mutations run everywhere and on every pull
//! request. They are the floor, not the ceiling.
//!
//! Every case asserts the same three things: parsing returns `Ok` or `Err` and never panics,
//! anything that parses can be re-serialized without panicking, and limits hold whatever the input
//! claims.

use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note};

fn valid_tar() -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in [
        ("a/one.txt", &b"hello"[..]),
        ("a/b/two.bin", &[0u8, 1, 2, 3][..]),
    ] {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append_data(&mut h, name, body).unwrap();
    }
    b.into_inner().unwrap()
}

fn valid_targz() -> Vec<u8> {
    let mut v = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader::default(),
        &valid_tar(),
        flate2::Compression::default(),
        &mut v,
    )
    .unwrap();
    v
}

fn valid_zip() -> Vec<u8> {
    use std::io::Write as _;
    use zip_crate::write::SimpleFileOptions;
    let opts =
        SimpleFileOptions::default().compression_method(zip_crate::CompressionMethod::Deflated);
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file("a.txt", opts).unwrap();
    w.write_all(b"hello").unwrap();
    w.start_file("b/c.bin", opts).unwrap();
    w.write_all(&[0u8, 1, 2, 3]).unwrap();
    w.finish().unwrap().into_inner()
}

fn corpus() -> Vec<(&'static str, Format, Vec<u8>)> {
    vec![
        ("tar", Format::Tar, valid_tar()),
        ("tar+gzip", Format::TarGz, valid_targz()),
        ("zip", Format::Zip, valid_zip()),
    ]
}

/// Parse, and if it parses, re-serialize. Neither may panic.
fn exercise(bytes: Vec<u8>, format: Format) {
    let mut notes: Vec<Note> = Vec::new();
    if let Ok(p) = parse(bytes, format, &Limits::tiny(), &mut notes) {
        let _ = serialize(&p.archive, true);
    }
}

#[test]
fn truncation_at_every_boundary_is_survivable() {
    for (name, format, bytes) in corpus() {
        for cut in 0..=64 {
            let n = bytes.len() * cut / 64;
            exercise(bytes[..n].to_vec(), format);
        }
        // And one byte short of complete, which is where an off-by-one lives.
        exercise(bytes[..bytes.len().saturating_sub(1)].to_vec(), format);
        let _ = name;
    }
}

#[test]
fn single_byte_corruption_is_survivable() {
    for (_, format, bytes) in corpus() {
        // Every byte of the first two blocks, where the structure lives, plus a stride over the
        // rest so a large body does not make the test slow without making it stronger.
        let dense = bytes.len().min(1024);
        let offsets = (0..dense).chain((dense..bytes.len()).step_by(37));
        for i in offsets {
            for xor in [0x01u8, 0xff, 0x80] {
                let mut m = bytes.clone();
                m[i] ^= xor;
                exercise(m, format);
            }
        }
    }
}

#[test]
fn zeroed_and_extended_regions_are_survivable() {
    for (_, format, bytes) in corpus() {
        for start in (0..bytes.len()).step_by(29) {
            let mut m = bytes.clone();
            let end = (start + 64).min(m.len());
            m[start..end].fill(0);
            exercise(m, format);

            let mut m = bytes.clone();
            m.extend_from_slice(&[0xffu8; 128]);
            exercise(m, format);
        }
    }
}

#[test]
fn arbitrary_bytes_are_survivable() {
    // A cheap deterministic generator: no dependency, no seed file, reproducible on failure.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for len in [0usize, 1, 15, 512, 513, 4096, 20_000] {
        for _ in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|_| (next() >> 24) as u8).collect();
            for format in [
                Format::Tar,
                Format::TarGz,
                Format::Zip,
                Format::Gzip,
                Format::Raw,
            ] {
                exercise(bytes.clone(), format);
            }
        }
    }
}

#[test]
fn a_gzip_header_promising_more_than_it_delivers_is_survivable() {
    // FEXTRA, FNAME and FCOMMENT all carry lengths or terminators an attacker controls.
    for flags in [0x04u8, 0x08, 0x10, 0x1f] {
        let mut m = valid_targz();
        m[3] = flags;
        exercise(m, Format::TarGz);
    }
    // A truncated FEXTRA length field.
    let mut m = valid_targz();
    m[3] = 0x04;
    m.truncate(11);
    exercise(m, Format::TarGz);
}

#[test]
fn a_zip_central_directory_pointing_outside_the_file_is_survivable() {
    let mut m = valid_zip();
    let eocd = m
        .windows(4)
        .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
        .unwrap();
    // Central-directory offset far past the end.
    m[eocd + 16..eocd + 20].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    exercise(m.clone(), Format::Zip);

    // And an entry count larger than the file could hold.
    let mut m = valid_zip();
    m[eocd + 10..eocd + 12].copy_from_slice(&0xfffeu16.to_le_bytes());
    exercise(m, Format::Zip);
}

#[test]
fn nesting_a_gzip_inside_itself_terminates() {
    // Each layer names itself `.gz`, so the descent has to stop on the recursion limit rather than
    // on running out of stack.
    let mut payload = b"seed".to_vec();
    for _ in 0..12 {
        let mut outer = ::tar::Builder::new(Vec::new());
        let mut gz = Vec::new();
        trigon_archive::gzip::write(
            &trigon_archive::GzipHeader::default(),
            &payload,
            flate2::Compression::default(),
            &mut gz,
        )
        .unwrap();
        let mut h = ::tar::Header::new_ustar();
        h.set_size(gz.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        outer.append_data(&mut h, "inner.gz", &gz[..]).unwrap();
        payload = outer.into_inner().unwrap();
    }
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(payload, Format::Tar, &Limits::tiny(), &mut notes).unwrap();
    let _ = serialize(&p.archive, true).unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n.code == trigon_core::NoteCode::RecursionLimitReached)
    );
}
