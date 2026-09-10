use std::io::{Cursor, Write};
use std::sync::Arc;

use trigon_archive::{Archive, EntryKind, Limits, SourceMap, zip};
use trigon_core::Note;

fn fixture(method: zip_crate::CompressionMethod) -> Vec<u8> {
    use zip_crate::write::SimpleFileOptions;
    let mut w = zip_crate::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default()
        .compression_method(method)
        .unix_permissions(0o644);
    w.start_file("b/two.txt", opts).unwrap();
    w.write_all(b"hello").unwrap();
    w.start_file("a/one.txt", opts).unwrap();
    w.write_all(&b"padding".repeat(200)).unwrap();
    w.add_directory("dir/", opts).unwrap();
    w.start_file("empty.txt", opts).unwrap();
    w.set_comment("archive comment");
    w.finish().unwrap().into_inner()
}

fn read(bytes: Vec<u8>) -> (Archive, Vec<Note>) {
    let mut notes = Vec::new();
    let a = zip::read(
        Arc::new(SourceMap::owned(bytes)),
        &Limits::default(),
        &mut notes,
    )
    .unwrap();
    (a, notes)
}

fn write(a: &Archive) -> Vec<u8> {
    let mut out = Vec::new();
    zip::write(a, &mut out, true).unwrap();
    out
}

#[test]
fn reads_deflate_and_store() {
    for m in [
        zip_crate::CompressionMethod::Stored,
        zip_crate::CompressionMethod::Deflated,
    ] {
        let (a, _) = read(fixture(m));
        assert_eq!(a.entries.len(), 4, "method {m:?}");
        let two = a
            .entries
            .iter()
            .find(|e| e.path.to_lossy() == "b/two.txt")
            .unwrap();
        assert_eq!(two.body_bytes().unwrap().as_ref(), b"hello");
        let dir = a
            .entries
            .iter()
            .find(|e| e.path.to_lossy() == "dir/")
            .unwrap();
        assert_eq!(dir.kind, EntryKind::Directory);
    }
}

#[test]
fn round_trip_preserves_content_and_comment() {
    let (a, _) = read(fixture(zip_crate::CompressionMethod::Deflated));
    let before: Vec<_> = a
        .entries
        .iter()
        .map(|e| (e.path.clone(), e.body_bytes().unwrap().into_owned()))
        .collect();
    let (b, _) = read(write(&a));
    let after: Vec<_> = b
        .entries
        .iter()
        .map(|e| (e.path.clone(), e.body_bytes().unwrap().into_owned()))
        .collect();
    assert_eq!(before, after);
    match (&a.trailer, &b.trailer) {
        (
            trigon_archive::Trailer::Zip { comment: x },
            trigon_archive::Trailer::Zip { comment: y },
        ) => {
            assert_eq!(x, y);
            assert_eq!(x, b"archive comment");
        }
        _ => panic!("expected zip trailers"),
    }
}

#[test]
fn serialization_is_idempotent_and_stable() {
    let (a, _) = read(fixture(zip_crate::CompressionMethod::Deflated));
    let once = write(&a);
    let (b, _) = read(once.clone());
    assert_eq!(write(&b), once, "re-serializing changed the bytes");
    for _ in 0..10 {
        let (x, _) = read(fixture(zip_crate::CompressionMethod::Deflated));
        assert_eq!(write(&x), once);
    }
}

#[test]
fn an_external_implementation_reads_our_output() {
    // The `zip` crate here is standing in for any other implementation.
    let (a, _) = read(fixture(zip_crate::CompressionMethod::Deflated));
    let ours = write(&a);
    let mut z = zip_crate::ZipArchive::new(Cursor::new(ours)).expect("external reader rejected it");
    assert_eq!(z.len(), 4);
    let mut names: Vec<_> = (0..z.len())
        .map(|i| z.by_index(i).unwrap().name().to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["a/one.txt", "b/two.txt", "dir/", "empty.txt"]);
    use std::io::Read as _;
    let mut s = String::new();
    z.by_name("b/two.txt")
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
    assert_eq!(s, "hello");
}

#[test]
fn stored_output_carries_no_compression() {
    let (a, _) = read(fixture(zip_crate::CompressionMethod::Deflated));
    let ours = write(&a);
    let mut z = zip_crate::ZipArchive::new(Cursor::new(ours)).unwrap();
    for i in 0..z.len() {
        assert_eq!(
            z.by_index(i).unwrap().compression(),
            zip_crate::CompressionMethod::Stored
        );
    }
}
