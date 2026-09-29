//! The mutable model's own contract: renames, bodies, where bytes come from, and what counts as
//! changed.
//!
//! These are the promises a stabilizer relies on. A rename has to remember the name the bytes are
//! under (`Entry::renamed_from`); a nested archive has no bytes of its own until it is written, and
//! saying so is what stops it being dropped from a digest; and "did anything change" has to see
//! through nesting, because it decides whether an inner archive is re-serialized or written back.

use std::io::{Seek as _, SeekFrom, Write as _};
use std::sync::Arc;

use trigon_archive::{
    Archive, ArchiveError, Body, EntryKind, GzipHeader, Limits, SourceMap, gzip, parse, serialize,
    tar,
};
use trigon_core::{EntryPath, Format};

fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *body).unwrap();
    }
    b.into_inner().unwrap()
}

fn read(bytes: Vec<u8>, format: Format) -> Archive {
    parse(bytes, format, &Limits::default(), &mut Vec::new())
        .unwrap()
        .archive
}

/// A `.gem`-shaped outer tar whose `data.tar.gz` is deflated, so that writing it back and
/// re-serializing it store-only give different bytes.
fn gem() -> (Archive, Vec<u8>) {
    let mut data = Vec::new();
    gzip::write(
        &GzipHeader::default(),
        &tar_of(&[("lib/x.rb", &b"module X; end\n".repeat(40))]),
        flate2::Compression::best(),
        &mut data,
    )
    .unwrap();
    (read(tar_of(&[("data.tar.gz", &data)]), Format::Tar), data)
}

// --- renames --------------------------------------------------------------------------------------

#[test]
fn a_rename_remembers_the_name_in_the_artifact_and_the_first_one_wins() {
    let mut a = read(tar_of(&[("lib/net45/A.dll", b"x")]), Format::Tar);
    let e = &mut a.entries[0];
    assert!(!e.was_renamed());
    assert_eq!(e.raw_path(), &e.path, "unrenamed, the two names are one");

    e.rename_to(EntryPath::from("lib/portable/A.dll"));
    e.rename_to(EntryPath::from("lib/canonical/A.dll"));
    assert_eq!(e.path, EntryPath::from("lib/canonical/A.dll"));
    assert_eq!(
        e.raw_path(),
        &EntryPath::from("lib/net45/A.dll"),
        "the spelling in the bytes, never a step along the way"
    );
    assert!(e.was_renamed());
    assert!(e.is_dirty());
}

#[test]
fn renaming_an_entry_to_the_name_it_has_changes_nothing() {
    let mut a = read(tar_of(&[("same.txt", b"x")]), Format::Tar);
    let e = &mut a.entries[0];
    e.rename_to(EntryPath::from("same.txt"));
    assert!(!e.was_renamed());
    assert!(
        !e.is_dirty(),
        "a no-op must not force a nested archive to be re-serialized"
    );
    assert!(!a.is_dirty());
}

// --- bodies ---------------------------------------------------------------------------------------

#[test]
fn a_nested_archive_has_no_bytes_of_its_own_and_is_never_empty() {
    let (a, _) = gem();
    let body = &a.entries[0].body;
    assert!(matches!(body, Body::Nested { .. }));
    assert_eq!(body.len(), 0, "its length is only known once it is written");
    assert!(
        !body.is_empty(),
        "an inner archive read as empty would drop out of a manifest"
    );
    assert!(matches!(body.bytes(), Err(ArchiveError::Unsupported(_))));
    assert!(matches!(
        a.entries[0].body_bytes(),
        Err(ArchiveError::Unsupported(_))
    ));
    assert!(Body::empty().is_empty());
}

#[test]
fn a_body_range_outside_its_source_is_malformed_rather_than_short() {
    let src = Arc::new(SourceMap::owned(b"0123456789".to_vec()));
    let inside = Body::Original {
        src: src.clone(),
        off: 2,
        len: 3,
    };
    assert_eq!(inside.bytes().unwrap().as_ref(), b"234");
    assert_eq!(inside.len(), 3);

    for (off, len) in [(8u64, 3u64), (11, 0), (u64::MAX, 1), (1, u64::MAX)] {
        let outside = Body::Original {
            src: src.clone(),
            off,
            len,
        };
        match outside.bytes() {
            Err(ArchiveError::Malformed { detail, .. }) => {
                assert!(detail.contains("out of bounds"), "{detail}")
            }
            other => panic!("{off}+{len}: expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn the_bytes_a_nested_member_contributes_are_what_arrived_until_something_inside_changes() {
    let (mut a, data) = gem();
    assert_eq!(a.entries[0].stabilized_bytes().unwrap().as_ref(), &data[..]);

    let Body::Nested { inner, .. } = &mut a.entries[0].body else {
        panic!("nested")
    };
    inner.entries[0].mark_dirty();
    assert!(a.is_dirty(), "a change at any depth is a change");
    assert_eq!(
        a.touched_entries(),
        0,
        "no member of the outer archive was itself touched"
    );

    let rewritten = a.entries[0].stabilized_bytes().unwrap().into_owned();
    assert_ne!(
        rewritten, data,
        "a changed inner archive is re-serialized, not written back"
    );
    // Store-only, like every stabilized stream, and still the same archive inside.
    let (h, payload) = gzip::read(&rewritten, u64::MAX).unwrap();
    assert_eq!(h.xfl, gzip::xfl_for(0));
    let back = read(payload, Format::Tar);
    assert_eq!(
        back.entries[0].body_bytes().unwrap().as_ref(),
        &b"module X; end\n".repeat(40)[..]
    );
}

#[test]
fn a_plain_member_contributes_its_body() {
    let a = read(tar_of(&[("a", b"plain")]), Format::Tar);
    assert_eq!(a.entries[0].stabilized_bytes().unwrap().as_ref(), b"plain");
}

#[test]
fn mutating_a_body_copies_it_out_of_the_source_and_marks_the_entry() {
    let mut a = read(tar_of(&[("a", b"before"), ("b", b"other")]), Format::Tar);
    assert!(matches!(a.entries[0].body, Body::Original { .. }));
    assert_eq!(a.touched_entries(), 0);

    a.entries[0]
        .body_mut()
        .unwrap()
        .extend_from_slice(b"+after");
    assert!(matches!(a.entries[0].body, Body::Inline(_)));
    assert_eq!(a.entries[0].body_bytes().unwrap().as_ref(), b"before+after");
    assert!(a.entries[0].is_dirty() && !a.entries[1].is_dirty());
    assert_eq!(a.touched_entries(), 1);
    // Already inline: mutating again works on the same buffer.
    a.entries[0].body_mut().unwrap().truncate(6);
    assert_eq!(a.entries[0].body_bytes().unwrap().as_ref(), b"before");
}

#[test]
fn a_trailer_change_is_a_change_to_the_archive() {
    let mut a = read(tar_of(&[("a", b"x")]), Format::Tar);
    assert!(!a.is_dirty());
    a.mark_trailer_dirty();
    assert!(a.is_dirty());
    assert_eq!(a.touched_entries(), 0);
}

#[test]
fn only_a_symlink_or_hardlink_has_a_link_target() {
    let t = b"target".to_vec();
    assert_eq!(
        EntryKind::Symlink { target: t.clone() }.link_target(),
        Some(&t[..])
    );
    assert_eq!(
        EntryKind::Hardlink { target: t.clone() }.link_target(),
        Some(&t[..])
    );
    for k in [
        EntryKind::Regular,
        EntryKind::Directory,
        EntryKind::Fifo,
        EntryKind::CharDevice { major: 1, minor: 3 },
        EntryKind::Other(b'Z'),
    ] {
        assert_eq!(k.link_target(), None, "{k:?}");
    }
}

// --- sources --------------------------------------------------------------------------------------

#[test]
fn a_tar_read_from_a_mapped_file_serves_its_bodies_from_the_mapping() {
    let bytes = tar_of(&[("pkg/a.txt", b"mapped body")]);
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(&bytes).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();

    let src = Arc::new(SourceMap::map(&f).unwrap());
    assert_eq!(src.as_slice(), &bytes[..]);
    assert_eq!(src.slice(0, 3), Some(&bytes[..3]));
    assert_eq!(src.slice(bytes.len() as u64, 1), None);
    assert_eq!(
        src.slice(1, u64::MAX),
        None,
        "an overflowing range is absent, not wrapped"
    );

    let a = tar::read(src, &Limits::default(), &mut Vec::new()).unwrap();
    assert!(matches!(a.entries[0].body, Body::Original { .. }));
    assert_eq!(a.entries[0].body_bytes().unwrap().as_ref(), b"mapped body");
}

#[test]
fn a_raw_artifact_serializes_back_to_exactly_its_bytes() {
    let bytes = b"\x00\x01not an archive at all\xff".to_vec();
    let a = read(bytes.clone(), Format::Raw);
    assert_eq!(a.entries.len(), 1);
    assert_eq!(serialize(&a, true).unwrap(), bytes);
    assert_eq!(serialize(&a, false).unwrap(), bytes);

    let empty = Archive::new(Format::Raw, trigon_archive::Trailer::None);
    assert_eq!(serialize(&empty, true).unwrap(), b"");
}
