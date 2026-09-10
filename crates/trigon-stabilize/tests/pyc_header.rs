//! `pyc-header` touches the source mtime and nothing else.
//!
//! A PEP 552 header is 16 bytes: a 4-byte magic, a 4-byte flags word, and 8 bytes whose meaning
//! bit 0 of the flags selects. An earlier version of this pass zeroed twelve of the sixteen, which
//! cleared the flags word that says how to read the rest and the source size that is derived from
//! the source. The differential caught it against a real wheel. Both are pinned here.

use std::io::Write as _;

use trigon_archive::{Limits, parse};
use trigon_core::{Format, Note};
use trigon_stabilize::{apply, profile};

/// A `.pyc` with the given flags word and the eight bytes that follow it.
fn pyc(flags: u32, tail: [u8; 8]) -> Vec<u8> {
    let mut v = vec![0x55, 0x0d, 0x0d, 0x0a];
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&tail);
    v.extend_from_slice(b"\xe3the-marshalled-code-object");
    v
}

/// A minimal wheel holding one member.
fn wheel(name: &str, body: &[u8]) -> Vec<u8> {
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> =
        zip_crate::write::FileOptions::default().compression_method(zip_crate::CompressionMethod::Stored);
    w.start_file(name, opts).unwrap();
    w.write_all(body).unwrap();
    w.finish().unwrap().into_inner()
}

/// Run the real `wheel` profile and return the member's bytes.
fn stabilized(name: &str, body: &[u8]) -> Vec<u8> {
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(wheel(name, body), Format::Zip, &Limits::default(), &mut notes).unwrap();
    apply(&profile("wheel").unwrap(), &mut p.archive);
    let e = p
        .archive
        .entries
        .iter()
        .find(|e| e.path.to_lossy() == name)
        .expect("member survives");
    e.body_bytes().unwrap().into_owned()
}

const PYC: &str = "pkg/__pycache__/m.cpython-38.pyc";

#[test]
fn a_timestamp_pyc_loses_its_mtime_and_keeps_its_source_size() {
    // Flags bit 0 clear: bytes 8..12 are the source mtime, 12..16 the source size.
    let out = stabilized(PYC, &pyc(0, [0xf5, 0x9a, 0xc3, 0x5f, 0x79, 0x06, 0x00, 0x00]));
    assert_eq!(&out[0..4], &[0x55, 0x0d, 0x0d, 0x0a], "magic is content");
    assert_eq!(&out[8..12], &[0, 0, 0, 0], "the source mtime is host state");
    assert_eq!(
        &out[12..16],
        &[0x79, 0x06, 0x00, 0x00],
        "the source size cannot differ while the source matches, so it survives"
    );
}

#[test]
fn a_hash_based_pyc_is_left_alone() {
    // Flags bit 0 set: bytes 8..16 are a hash of the source. Nothing to normalize.
    let input = pyc(0b11, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(stabilized(PYC, &input), input);
}

#[test]
fn the_flags_word_survives() {
    // Zeroing it would reinterpret a source hash as a timestamp plus a size.
    let out = stabilized(PYC, &pyc(0b11, [1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(u32::from_le_bytes([out[4], out[5], out[6], out[7]]), 0b11);
}

#[test]
fn a_header_too_short_to_read_is_not_touched() {
    let short = vec![0x55, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 1, 2, 3];
    assert_eq!(stabilized(PYC, &short), short);
}

#[test]
fn a_member_that_is_not_a_pyc_is_not_touched() {
    let body = pyc(0, [9, 9, 9, 9, 1, 0, 0, 0]);
    assert_eq!(stabilized("pkg/notes.txt", &body), body);
}

#[test]
fn the_pass_is_idempotent() {
    let once = stabilized(PYC, &pyc(0, [0xf5, 0x9a, 0xc3, 0x5f, 0x79, 0x06, 0x00, 0x00]));
    assert_eq!(stabilized(PYC, &once), once);
}

/// A wheel with several members, one of which is a gzip file the package ships.
fn wheel_with(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored);
    for (n, b) in members {
        w.start_file(*n, opts).unwrap();
        w.write_all(b).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn record_lists_a_gzip_member_the_package_ships() {
    // A `.gz` inside a wheel parses as a nested archive, so it has no body bytes of its own.
    // `wheel-record` used to skip the members it could not read, which quietly dropped this one
    // from the manifest: a membership change presented as a normalization. Caught by the
    // differential against a real wheel with two `.yml.gz` data files.
    let mut gz = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader::default(),
        b"a: 1\nb: 2\n",
        flate2::Compression::default(),
        &mut gz,
    )
    .unwrap();

    let bytes = wheel_with(&[
        ("pkg/data/values.yml.gz", &gz),
        ("pkg/__init__.py", b"x = 1\n"),
        ("pkg-1.0.dist-info/RECORD", b"stale\n"),
    ]);

    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(bytes, Format::Zip, &Limits::default(), &mut notes).unwrap();
    apply(&profile("wheel").unwrap(), &mut p.archive);

    let record = p
        .archive
        .entries
        .iter()
        .find(|e| e.path.to_lossy().ends_with("RECORD"))
        .unwrap();
    let text = String::from_utf8(record.body_bytes().unwrap().into_owned()).unwrap();

    assert!(
        text.contains("pkg/data/values.yml.gz,sha256="),
        "the gzip member must appear in RECORD:\n{text}"
    );
    assert!(text.contains("pkg/__init__.py,sha256="), "{text}");
    assert!(text.ends_with("pkg-1.0.dist-info/RECORD,,\n"), "{text}");

    // And the digest it records is over the bytes the writer will emit for that member.
    let line = text
        .lines()
        .find(|l| l.starts_with("pkg/data/values.yml.gz,"))
        .unwrap();
    let size: usize = line.rsplit(',').next().unwrap().parse().unwrap();
    assert_eq!(
        size,
        gz.len(),
        "an untouched nested archive contributes the bytes it arrived as"
    );
}
