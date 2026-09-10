//! Nested-archive behaviour: the `.gem` shape, and the failure mode the prior art gets wrong.

use trigon_archive::{Body, Limits, parse, serialize};
use trigon_core::{Format, Note, NoteCode};

/// A `.gem`: an outer tar whose members are gzipped, one of them a gzipped tar.
fn gem_fixture(corrupt_inner: bool) -> Vec<u8> {
    let mut inner = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(11);
    h.set_mode(0o644);
    h.set_cksum();
    inner
        .append_data(&mut h, "lib/rails.rb", &b"module Rail"[..])
        .unwrap();
    let inner_tar = inner.into_inner().unwrap();

    let gz = |payload: &[u8]| {
        let mut v = Vec::new();
        trigon_archive::gzip::write(
            &trigon_archive::GzipHeader::default(),
            payload,
            flate2::Compression::default(),
            &mut v,
        )
        .unwrap();
        v
    };

    let mut data_gz = gz(&inner_tar);
    if corrupt_inner {
        let n = data_gz.len();
        data_gz[n / 2] ^= 0xff;
    }
    let meta_gz = gz(b"--- !ruby/object:Gem::Specification\nname: rails\n");

    let mut outer = ::tar::Builder::new(Vec::new());
    for (name, body) in [("data.tar.gz", &data_gz), ("metadata.gz", &meta_gz)] {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        outer.append_data(&mut h, name, &body[..]).unwrap();
    }
    outer.into_inner().unwrap()
}

#[test]
fn descends_two_layers() {
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(
        gem_fixture(false),
        Format::Tar,
        &Limits::default(),
        &mut notes,
    )
    .unwrap();

    let data = p
        .archive
        .entries
        .iter()
        .find(|e| e.path.to_lossy() == "data.tar.gz")
        .unwrap();
    let Body::Nested(inner) = &data.body else {
        panic!("data.tar.gz should be nested")
    };
    assert_eq!(inner.format, Format::TarGz);
    assert_eq!(inner.entries.len(), 1);
    assert_eq!(inner.entries[0].path.to_lossy(), "lib/rails.rb");

    // metadata.gz wraps YAML, not a tar, so it becomes a single-member archive rather than a guess.
    let meta = p
        .archive
        .entries
        .iter()
        .find(|e| e.path.to_lossy() == "metadata.gz")
        .unwrap();
    let Body::Nested(m) = &meta.body else {
        panic!("metadata.gz should be nested")
    };
    assert_eq!(m.format, Format::Gzip);
    assert!(m.entries[0].body_bytes().unwrap().starts_with(b"--- !ruby"));
}

#[test]
fn a_malformed_inner_archive_notes_rather_than_guessing() {
    // The bug this design exists to avoid: the prior art swallows this error and silently
    // produces a different digest.
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(
        gem_fixture(true),
        Format::Tar,
        &Limits::default(),
        &mut notes,
    )
    .unwrap();

    assert!(
        notes.iter().any(|n| n.code == NoteCode::NestedParseFailed),
        "a malformed nested archive must produce a note, got {notes:?}"
    );
    let data = p
        .archive
        .entries
        .iter()
        .find(|e| e.path.to_lossy() == "data.tar.gz")
        .unwrap();
    assert!(
        !matches!(data.body, Body::Nested(_)),
        "a body we could not parse must not be presented as parsed"
    );
    // The bytes we could not read still reach the digest, unchanged.
    assert!(data.body_bytes().unwrap().starts_with(&[0x1f, 0x8b]));
}

#[test]
fn nested_round_trip_is_idempotent() {
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(
        gem_fixture(false),
        Format::Tar,
        &Limits::default(),
        &mut notes,
    )
    .unwrap();
    let once = serialize(&p.archive, true).unwrap();

    let mut notes2: Vec<Note> = Vec::new();
    let q = parse(once.clone(), Format::Tar, &Limits::default(), &mut notes2).unwrap();
    assert_eq!(serialize(&q.archive, true).unwrap(), once);
}

#[test]
fn recursion_limit_is_reported() {
    let mut notes: Vec<Note> = Vec::new();
    let limits = Limits {
        recursion: 1,
        ..Limits::default()
    };
    let p = parse(gem_fixture(false), Format::Tar, &limits, &mut notes).unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n.code == NoteCode::RecursionLimitReached)
    );
    let data = p
        .archive
        .entries
        .iter()
        .find(|e| e.path.to_lossy() == "data.tar.gz")
        .unwrap();
    assert!(matches!(data.body, Body::Inline(_) | Body::Original { .. }));
}

#[test]
fn container_bytes_are_exposed_for_compressed_formats() {
    let raw_tar = gem_fixture(false);
    let mut gzipped = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader::default(),
        &raw_tar,
        flate2::Compression::default(),
        &mut gzipped,
    )
    .unwrap();

    let mut notes: Vec<Note> = Vec::new();
    let p = parse(gzipped, Format::TarGz, &Limits::default(), &mut notes).unwrap();
    assert_eq!(
        p.container.as_deref(),
        Some(&raw_tar[..]),
        "container digest source must be the tar"
    );

    let mut notes2: Vec<Note> = Vec::new();
    let q = parse(raw_tar, Format::Tar, &Limits::default(), &mut notes2).unwrap();
    assert!(
        q.container.is_none(),
        "an uncompressed container has no outer codec"
    );
}
