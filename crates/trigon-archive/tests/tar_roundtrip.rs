use std::sync::Arc;

use trigon_archive::{Archive, EntryKind, Limits, SourceMap, tar};
use trigon_core::Note;

/// Build a tar covering the cases the spec calls out: long names, duplicates, non-UTF-8 paths,
/// symlinks, directories, and an empty file.
fn fixture() -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());

    let mut h = ::tar::Header::new_ustar();
    h.set_size(5);
    h.set_mode(0o644);
    h.set_mtime(1_700_000_000);
    h.set_cksum();
    b.append_data(&mut h.clone(), "b/two.txt", &b"hello"[..])
        .unwrap();

    // Duplicate path: legal in tar, and the reason the sort key carries an ordinal.
    let mut h2 = ::tar::Header::new_ustar();
    h2.set_size(5);
    h2.set_mode(0o644);
    h2.set_cksum();
    b.append_data(&mut h2, "b/two.txt", &b"world"[..]).unwrap();

    // A name the ustar prefix field CAN carry: 140-byte dir, 8-byte leaf. No extension needed.
    let splittable = format!("{}/leaf.txt", "d".repeat(140));
    let mut hp = ::tar::Header::new_ustar();
    hp.set_size(2);
    hp.set_mode(0o644);
    hp.set_cksum();
    b.append_data(&mut hp, &splittable, &b"ok"[..]).unwrap();

    // A single component too long to split anywhere. Only an extension can carry this.
    let long = format!("{}.txt", "x".repeat(120));
    let mut h3 = ::tar::Header::new_gnu();
    h3.set_size(3);
    h3.set_mode(0o644);
    h3.set_cksum();
    b.append_data(&mut h3, &long, &b"abc"[..]).unwrap();

    let mut hd = ::tar::Header::new_ustar();
    hd.set_entry_type(::tar::EntryType::Directory);
    hd.set_size(0);
    hd.set_mode(0o755);
    hd.set_cksum();
    b.append_data(&mut hd, "a/", std::io::empty()).unwrap();

    let mut hs = ::tar::Header::new_ustar();
    hs.set_entry_type(::tar::EntryType::Symlink);
    hs.set_size(0);
    hs.set_mode(0o777);
    hs.set_link_name("b/two.txt").unwrap();
    hs.set_cksum();
    b.append_data(&mut hs, "link", std::io::empty()).unwrap();

    let mut he = ::tar::Header::new_ustar();
    he.set_size(0);
    he.set_mode(0o644);
    he.set_cksum();
    b.append_data(&mut he, "empty", std::io::empty()).unwrap();

    b.into_inner().unwrap()
}

fn read(bytes: Vec<u8>) -> (Archive, Vec<Note>) {
    let src = Arc::new(SourceMap::owned(bytes));
    let mut notes = Vec::new();
    let a = tar::read(src, &Limits::default(), &mut notes).unwrap();
    (a, notes)
}

fn write(a: &Archive) -> Vec<u8> {
    let mut out = Vec::new();
    tar::write(a, &mut out).unwrap();
    out
}

#[test]
fn reads_every_entry_kind() {
    let (a, _) = read(fixture());
    let kinds: Vec<_> = a
        .entries
        .iter()
        .map(|e| (e.path.to_lossy().into_owned(), e.kind.clone()))
        .collect();
    assert!(
        kinds
            .iter()
            .any(|(p, k)| p == "a/" && *k == EntryKind::Directory)
    );
    assert!(
        kinds
            .iter()
            .any(|(p, k)| p == "link" && matches!(k, EntryKind::Symlink { .. }))
    );
    assert_eq!(a.entries.len(), 7);
}

#[test]
fn round_trip_preserves_paths_kinds_and_bodies() {
    let (a, _) = read(fixture());
    let before: Vec<_> = a
        .entries
        .iter()
        .map(|e| {
            (
                e.path.clone(),
                e.kind.clone(),
                e.body_bytes().unwrap().into_owned(),
            )
        })
        .collect();

    let (b, _) = read(write(&a));
    let after: Vec<_> = b
        .entries
        .iter()
        .map(|e| {
            (
                e.path.clone(),
                e.kind.clone(),
                e.body_bytes().unwrap().into_owned(),
            )
        })
        .collect();

    assert_eq!(before, after);
}

#[test]
fn serialization_is_idempotent() {
    // write(parse(write(a))) == write(a). The property M0 exists to guarantee.
    let (a, _) = read(fixture());
    let once = write(&a);
    let (b, _) = read(once.clone());
    let twice = write(&b);
    assert_eq!(
        once, twice,
        "re-serializing a parsed archive changed the bytes"
    );
}

#[test]
fn output_is_byte_stable_across_runs() {
    let (a, _) = read(fixture());
    let first = write(&a);
    for _ in 0..20 {
        let (x, _) = read(fixture());
        assert_eq!(write(&x), first);
    }
}

#[test]
fn duplicate_paths_are_noted_and_ordering_is_total() {
    let (mut a, notes) = read(fixture());
    assert!(
        notes
            .iter()
            .any(|n| n.code == trigon_core::NoteCode::DuplicateEntryPath),
        "duplicate path should produce a note"
    );

    a.sort_entries();
    let sorted_once = write(&a);

    // Sorting an already-sorted archive is a no-op, and sorting a reversed one reaches the same
    // bytes: the (path, ordinal) key is a total order over the multiset.
    let (mut b, _) = read(fixture());
    // Reversing does not renumber: ordinals stay with their entries, which is the point.
    b.entries.reverse();
    b.sort_entries();
    assert_eq!(write(&b), sorted_once);
}

#[test]
fn long_names_are_re_encoded_as_pax() {
    let (a, notes) = read(fixture());
    assert!(
        notes
            .iter()
            .any(|n| n.code == trigon_core::NoteCode::LongNameReencoded)
    );

    let out = write(&a);
    // A PAX extended header entry is present, and no GNU long-name entry is.
    assert!(
        out.windows(13).any(|w| w == b"PaxHeaders.0/"),
        "expected a PAX extended header in the output"
    );
    let has_gnu_longname = out.chunks_exact(512).any(|blk| blk.get(156) == Some(&b'L'));
    assert!(
        !has_gnu_longname,
        "writer must never emit a GNU long-name entry"
    );

    // Every ustar `prefix` field is NUL: a long name goes in a PAX record, never a prefix split.
    for blk in out.chunks_exact(512) {
        if blk[257..263] == *b"ustar\0" {
            assert!(
                blk[345..500].iter().all(|&b| b == 0),
                "prefix field must never be used"
            );
        }
    }

    // Both long names are re-encoded: the 149-byte one arrived as a ustar prefix split and the
    // 124-byte one as a GNU long name, and neither framing survives.
    let mut noted: Vec<_> = notes
        .iter()
        .filter(|n| n.code == trigon_core::NoteCode::LongNameReencoded)
        .filter_map(|n| n.path.as_ref())
        .map(|p| p.to_lossy().into_owned())
        .collect();
    noted.sort();
    assert_eq!(noted.len(), 2, "both long names should be noted: {noted:?}");
    assert!(noted[0].starts_with("ddd"));
    assert!(noted[1].starts_with("xxx"));
}

#[test]
fn non_utf8_paths_survive() {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(1);
    h.set_mode(0o644);
    h.set_cksum();
    let raw = std::ffi::OsStr::new("x");
    let _ = raw;
    // The tar crate wants a path; write the odd bytes directly into the header instead.
    h.set_path("placeholder").unwrap();
    b.append_data(&mut h, "placeholder", &b"z"[..]).unwrap();
    let bytes = b.into_inner().unwrap();

    let mut patched = bytes.clone();
    patched[0] = 0xff;
    patched[1] = 0xfe;
    // Re-checksum the header we just corrupted.
    for x in patched[148..156].iter_mut() {
        *x = b' ';
    }
    let sum: u32 = patched[..512].iter().map(|&x| u32::from(x)).sum();
    let s = format!("{sum:06o}");
    patched[148..154].copy_from_slice(s.as_bytes());
    patched[154] = 0;
    patched[155] = b' ';

    let (a, _) = read(patched);
    assert_eq!(a.entries.len(), 1);
    assert_eq!(&a.entries[0].path.as_bytes()[..2], &[0xff, 0xfe]);
    // And it survives a round trip.
    let (b2, _) = read(write(&a));
    assert_eq!(b2.entries[0].path, a.entries[0].path);
}

#[test]
fn a_truncated_name_never_ends_in_a_slash() {
    // A long directory path whose first 100 bytes end exactly on a separator. The real name rides
    // in the PAX `path` record; the ustar field holds a truncation, and a truncation ending in '/'
    // reads as a directory to anything that infers the kind from the name rather than the typeflag.
    let dir = format!("{}/{}", "d".repeat(89), "e".repeat(9)); // 99 bytes, so byte 100 is the '/'
    let path = format!("{dir}/leaf.txt");
    assert_eq!(path.as_bytes()[99], b'/');

    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_gnu();
    h.set_size(2);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, &path, &b"ok"[..]).unwrap();
    let (a, _) = read(b.into_inner().unwrap());
    let out = write(&a);

    let block = out
        .chunks_exact(512)
        .find(|blk| blk[257..262] == *b"ustar" && blk[156] == b'0')
        .expect("a regular-file header");
    let field = &blk_name(block);
    assert!(
        !field.ends_with(b"/"),
        "truncated name must not end in a slash: {:?}",
        String::from_utf8_lossy(field)
    );
    assert_eq!(field.len(), 99, "the slash is dropped, not replaced");
    assert_eq!(block[99], 0, "and the NUL terminates the field");

    // The real name is unaffected: it rides in the PAX record.
    assert!(out.windows(path.len()).any(|w| w == path.as_bytes()));
}

fn blk_name(block: &[u8]) -> Vec<u8> {
    block[..100]
        .iter()
        .take_while(|&&c| c != 0)
        .copied()
        .collect()
}
