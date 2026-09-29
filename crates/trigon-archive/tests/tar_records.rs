//! Tar fields beyond name, mode and body: PAX records, the entry kinds, and values too wide for
//! their ustar field.
//!
//! The writer is ours because stabilization depends on forcing PAX (`src/tar.rs`), so every field
//! the ustar header cannot hold has to leave as a PAX record and come back as the same value. And
//! the reader faces whatever the publisher's tool wrote: an unrecognized typeflag is passed through
//! and noted, a kind that must be bodiless but is not is noted, and neither is guessed at
//! (`docs/05-archive-and-normalization.md` §2.2 (7)).

use std::collections::BTreeMap;
use std::sync::Arc;

use trigon_archive::{Archive, ArchiveError, EntryKind, Limits, RawMeta, SourceMap, TarRaw, tar};
use trigon_core::{Note, NoteCode};

fn read(bytes: Vec<u8>) -> (Archive, Vec<Note>) {
    let mut notes = Vec::new();
    let a = tar::read(
        Arc::new(SourceMap::owned(bytes)),
        &Limits::default(),
        &mut notes,
    )
    .unwrap();
    (a, notes)
}

fn write(a: &Archive) -> Vec<u8> {
    let mut out = Vec::new();
    tar::write(a, &mut out).unwrap();
    out
}

fn raw(a: &mut Archive, i: usize) -> &mut TarRaw {
    match &mut a.entries[i].raw {
        RawMeta::Tar(t) => t,
        RawMeta::Zip(_) => panic!("a tar entry"),
    }
}

/// The ustar header block written for `name`, found by scanning the output block by block.
///
/// Read from the bytes rather than from an independent reader's `header()`, which is not the block
/// on the wire: the `tar` crate patches PAX `uid` and `gid` into the header it hands back.
fn header<'a>(out: &'a [u8], name: &[u8]) -> &'a [u8] {
    out.chunks_exact(512)
        .find(|b| {
            b.starts_with(name) && b[name.len()] == 0 && &b[257..262] == b"ustar" && b[156] != b'x'
        })
        .unwrap_or_else(|| panic!("no header for {}", String::from_utf8_lossy(name)))
}

/// What an independent reader makes of one entry, PAX records in order.
struct Seen {
    path: Vec<u8>,
    typeflag: u8,
    pax: Vec<(String, String)>,
    link: Option<Vec<u8>>,
    size: u64,
    body: Vec<u8>,
}

fn external(bytes: &[u8]) -> Vec<Seen> {
    use std::io::Read as _;
    let mut ar = ::tar::Archive::new(bytes);
    let mut out = Vec::new();
    for e in ar.entries().unwrap() {
        let mut e = e.unwrap();
        let pax = match e.pax_extensions().unwrap() {
            Some(exts) => exts
                .map(|x| {
                    let x = x.unwrap();
                    (x.key().unwrap().to_string(), x.value().unwrap().to_string())
                })
                .collect(),
            None => Vec::new(),
        };
        let path = e.path_bytes().into_owned();
        let typeflag = e.header().entry_type().as_byte();
        let link = e.link_name_bytes().map(|c| c.into_owned());
        let size = e.size();
        let mut body = Vec::new();
        e.read_to_end(&mut body).unwrap();
        out.push(Seen {
            path,
            typeflag,
            pax,
            link,
            size,
            body,
        });
    }
    out
}

fn ustar(size: u64) -> ::tar::Header {
    let mut h = ::tar::Header::new_ustar();
    h.set_size(size);
    h.set_mode(0o644);
    h.set_mtime(1);
    h
}

// --- PAX records ----------------------------------------------------------------------------------

#[test]
fn pax_times_are_lifted_and_every_other_record_survives_in_keyword_order() {
    let mut b = ::tar::Builder::new(Vec::new());
    b.append_pax_extensions([
        ("mtime", &b"1650000000.25"[..]),
        ("comment", b"hello"),
        ("atime", b"1700000000.5"),
        ("SCHILY.xattr.user.k", b"v"),
        ("ctime", b"1600000000"),
    ])
    .unwrap();
    let mut h = ustar(2);
    h.set_cksum();
    b.append_data(&mut h, "a.txt", &b"hi"[..]).unwrap();
    let (a, _) = read(b.into_inner().unwrap());

    // The three times become typed fields, whole seconds, and the PAX mtime wins over the header's.
    let e = &a.entries[0];
    assert_eq!(e.meta.mtime, Some(1_650_000_000));
    let RawMeta::Tar(t) = &e.raw else {
        panic!("a tar entry")
    };
    assert_eq!(
        (t.atime, t.ctime),
        (Some(1_700_000_000), Some(1_600_000_000))
    );
    // The rest are kept verbatim for the writer to re-emit.
    let kept: BTreeMap<String, String> = [("SCHILY.xattr.user.k", "v"), ("comment", "hello")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(t.pax, kept);

    let out = write(&a);
    let seen = external(&out);
    assert_eq!(seen.len(), 1, "the PAX header is not an entry of its own");
    assert_eq!(
        seen[0].pax,
        vec![
            ("SCHILY.xattr.user.k".to_string(), "v".to_string()),
            ("atime".into(), "1700000000".into()),
            ("comment".into(), "hello".into()),
            ("ctime".into(), "1600000000".into()),
        ],
        "keyword order, times regenerated from the integer, and no mtime record for a time the \
         header can hold"
    );
    assert_eq!(
        &header(&out, b"a.txt")[136..148],
        b"14226200200\0",
        "1650000000 in octal"
    );

    // And it reads back as the model it was written from.
    let (again, _) = read(out.clone());
    assert_eq!(again.entries[0].raw, a.entries[0].raw);
    assert_eq!(write(&again), out);
}

#[test]
fn a_timestamp_the_header_cannot_hold_travels_as_a_pax_record() {
    // Before 1970, and past what eleven octal digits can say.
    for mtime in [-1i64, 0o77_777_777_777 + 1] {
        let mut b = ::tar::Builder::new(Vec::new());
        let mut h = ustar(1);
        h.set_cksum();
        b.append_data(&mut h, "t", &b"x"[..]).unwrap();
        let (mut a, _) = read(b.into_inner().unwrap());
        a.entries[0].meta.mtime = Some(mtime);

        let out = write(&a);
        let seen = external(&out);
        assert_eq!(seen[0].pax, vec![("mtime".to_string(), mtime.to_string())]);
        let field: &[u8] = if mtime < 0 {
            b"00000000000\0"
        } else {
            b"77777777777\0"
        };
        assert_eq!(
            &header(&out, b"t")[136..148],
            field,
            "the header clamps, the record carries it"
        );
        assert_eq!(read(out).0.entries[0].meta.mtime, Some(mtime));
    }
}

#[test]
fn an_owner_id_too_wide_for_its_field_is_clamped_in_the_header_and_carried_in_pax() {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ustar(1);
    h.set_cksum();
    b.append_data(&mut h, "o", &b"x"[..]).unwrap();
    let (mut a, _) = read(b.into_inner().unwrap());
    raw(&mut a, 0).uid = 3_000_000;
    raw(&mut a, 0).gid = 4_000_000;

    let out = write(&a);
    let seen = external(&out);
    assert_eq!(
        seen[0].pax,
        vec![
            ("gid".to_string(), "4000000".to_string()),
            ("uid".into(), "3000000".into()),
        ]
    );
    assert_eq!(&header(&out, b"o")[108..124], b"7777777\x007777777\x00");
    // A reader that applies PAX recovers the whole value, ours included.
    let (mut back, _) = read(out);
    assert_eq!(
        (raw(&mut back, 0).uid, raw(&mut back, 0).gid),
        (3_000_000, 4_000_000)
    );
}

#[test]
fn a_link_target_longer_than_the_header_field_is_carried_whole() {
    let target = format!("{}/target.txt", "d".repeat(140));
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_gnu();
    h.set_entry_type(::tar::EntryType::Symlink);
    h.set_size(0);
    h.set_mode(0o777);
    b.append_link(&mut h, "link", &target).unwrap();
    let (a, _) = read(b.into_inner().unwrap());
    assert_eq!(
        a.entries[0].kind,
        EntryKind::Symlink {
            target: target.clone().into_bytes()
        }
    );

    let out = write(&a);
    let seen = external(&out);
    assert_eq!(seen[0].pax, vec![("linkpath".to_string(), target.clone())]);
    assert_eq!(seen[0].link.as_deref(), Some(target.as_bytes()));
    assert_eq!(&header(&out, b"link")[157..257], &target.as_bytes()[..100]);
}

// --- entry kinds ----------------------------------------------------------------------------------

#[test]
fn every_special_kind_is_read_as_what_it_is_and_written_back_as_the_same() {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ustar(4);
    h.set_cksum();
    b.append_data(&mut h, "pkg/a.txt", &b"body"[..]).unwrap();

    let mut special = |name: &str, ty: ::tar::EntryType, dev: Option<(u32, u32)>| {
        let mut h = ustar(0);
        h.set_entry_type(ty);
        if let Some((major, minor)) = dev {
            h.set_device_major(major).unwrap();
            h.set_device_minor(minor).unwrap();
        }
        if ty == ::tar::EntryType::Link {
            h.set_link_name("pkg/a.txt").unwrap();
        }
        h.set_cksum();
        b.append_data(&mut h, name, std::io::empty()).unwrap();
    };
    special("pkg/hard", ::tar::EntryType::Link, None);
    special("dev/null", ::tar::EntryType::Char, Some((1, 3)));
    special("dev/sda", ::tar::EntryType::Block, Some((8, 0)));
    special("run/pipe", ::tar::EntryType::Fifo, None);
    let bytes = b.into_inner().unwrap();

    let (a, notes) = read(bytes);
    let kinds: Vec<_> = a.entries.iter().map(|e| e.kind.clone()).collect();
    assert_eq!(
        kinds,
        vec![
            EntryKind::Regular,
            EntryKind::Hardlink {
                target: b"pkg/a.txt".to_vec()
            },
            EntryKind::CharDevice { major: 1, minor: 3 },
            EntryKind::BlockDevice { major: 8, minor: 0 },
            EntryKind::Fifo,
        ]
    );
    assert!(
        !notes.iter().any(|n| matches!(
            n.code,
            NoteCode::MalformedEntry | NoteCode::UnknownEntryKind
        )),
        "well-formed special entries are neither malformed nor unknown: {notes:?}"
    );
    // docs/05 §2.2 (7) says a device node "is worth a note of its own", so the two devices are left
    // out of this: only the kinds the table gives no note are held to having none.
    let quiet: [&[u8]; 3] = [b"pkg/a.txt", b"pkg/hard", b"run/pipe"];
    assert!(
        !notes.iter().any(|n| n
            .path
            .as_ref()
            .is_some_and(|p| quiet.contains(&p.as_bytes()))),
        "a regular file, a hardlink and a FIFO are not remarkable: {notes:?}"
    );
    assert_eq!(a.entries[1].kind.link_target(), Some(&b"pkg/a.txt"[..]));
    assert_eq!(a.entries[2].kind.link_target(), None);
    assert!(a.entries[1..].iter().all(|e| e.kind.requires_empty_body()));
    assert!(a.entries.iter().all(|e| e.kind.is_normalizable()));

    let out = write(&a);
    let seen = external(&out);
    let flags: Vec<u8> = seen.iter().map(|s| s.typeflag).collect();
    assert_eq!(flags, b"01346".to_vec());
    assert_eq!(seen[1].link.as_deref(), Some(&b"pkg/a.txt"[..]));
    assert_eq!(
        &header(&out, b"dev/null")[329..345],
        b"0000001\x000000003\x00"
    );
    assert_eq!(
        &header(&out, b"dev/sda")[329..345],
        b"0000010\x000000000\x00"
    );
}

#[test]
fn an_unrecognized_typeflag_is_passed_through_with_its_body_and_noted() {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ustar(5);
    h.set_entry_type(::tar::EntryType::new(b'Z'));
    h.set_cksum();
    b.append_data(&mut h, "odd", &b"bytes"[..]).unwrap();
    let (a, notes) = read(b.into_inner().unwrap());

    assert_eq!(a.entries[0].kind, EntryKind::Other(b'Z'));
    assert!(!a.entries[0].kind.is_normalizable());
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0].code, NoteCode::UnknownEntryKind);
    assert_eq!(notes[0].path.as_ref().unwrap().as_bytes(), b"odd");
    assert!(notes[0].detail.contains("'Z'"), "{}", notes[0].detail);
    assert!(NoteCode::UnknownEntryKind.is_noteworthy());

    let seen = external(&write(&a));
    assert_eq!(seen[0].typeflag, b'Z');
    assert_eq!(seen[0].body, b"bytes", "guessing is worse than declining");
}

#[test]
fn a_directory_carrying_a_body_is_noted_and_the_bytes_kept_but_never_written() {
    // docs/05 §2.2 (7): the parser notes it and preserves the bytes; the writer puts `size = 0` on
    // the wire for a kind that must be empty, whatever the parser found.
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ustar(3);
    h.set_entry_type(::tar::EntryType::Directory);
    h.set_cksum();
    b.append_data(&mut h, "dir/", &b"abc"[..]).unwrap();
    let mut after = ustar(1);
    after.set_cksum();
    b.append_data(&mut after, "dir/next", &b"n"[..]).unwrap();
    let (a, notes) = read(b.into_inner().unwrap());

    assert_eq!(a.entries[0].kind, EntryKind::Directory);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0].code, NoteCode::MalformedEntry);
    assert_eq!(notes[0].path.as_ref().unwrap().as_bytes(), b"dir/");
    assert!(
        notes[0].detail.contains("3-byte body"),
        "{}",
        notes[0].detail
    );
    assert_eq!(
        a.entries[0].body_bytes().unwrap().as_ref(),
        b"abc",
        "preserved"
    );

    let seen = external(&write(&a));
    assert_eq!((seen[0].size, seen[0].body.as_slice()), (0, &b""[..]));
    assert_eq!(
        (seen[1].path.as_slice(), seen[1].body.as_slice()),
        (&b"dir/next"[..], &b"n"[..]),
        "the next member starts where an empty body ends"
    );
}

// --- refusals -------------------------------------------------------------------------------------

#[test]
fn a_zip_member_cannot_be_written_into_a_tar() {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ustar(1);
    h.set_cksum();
    b.append_data(&mut h, "z", &b"x"[..]).unwrap();
    let (mut a, _) = read(b.into_inner().unwrap());
    a.entries[0].raw = RawMeta::Zip(Default::default());

    let mut out = Vec::new();
    match tar::write(&a, &mut out) {
        Err(ArchiveError::Unsupported(what)) => assert!(what.contains("zip entry"), "{what}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A sink that refuses one write, at byte `at`, and takes everything before and after it.
///
/// The write that reaches `at` is short and the next one is the error. A sink that stayed full
/// would hide a writer that dropped that error, because the writer's next write would fail in its
/// place; this one would let such a writer carry on and return `Ok` for an archive with a hole in
/// it, which is exactly the short archive the caller must never be handed.
struct FailsAt {
    at: usize,
    failed: bool,
    taken: Vec<u8>,
}

impl FailsAt {
    fn new(at: usize) -> Self {
        FailsAt {
            at,
            failed: false,
            taken: Vec::new(),
        }
    }
}

impl std::io::Write for FailsAt {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = if self.failed {
            buf.len()
        } else {
            buf.len().min(self.at - self.taken.len())
        };
        if n == 0 && !buf.is_empty() {
            self.failed = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "no space",
            ));
        }
        self.taken.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_sink_that_fails_is_an_io_error_and_not_a_short_archive() {
    // A PAX header and its padded records, a ustar header, a one-byte body and its padding, then
    // the end-of-archive blocks. The sink fails at every offset in turn, so the error has to come
    // out of each of those writes and not only out of the first.
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ustar(1);
    h.set_cksum();
    b.append_data(&mut h, "a", &b"x"[..]).unwrap();
    let (mut a, _) = read(b.into_inner().unwrap());
    raw(&mut a, 0)
        .pax
        .insert("comment".into(), "forces a PAX header".into());
    // An archive with no members still has its end-of-archive blocks to write.
    let empty = Archive::new(trigon_core::Format::Tar, trigon_archive::Trailer::Tar);

    for archive in [&a, &empty] {
        let whole = write(archive);
        for at in 0..whole.len() {
            match tar::write(archive, &mut FailsAt::new(at)) {
                Err(ArchiveError::Io(_)) => {}
                other => panic!("failing at byte {at} of {}: {other:?}", whole.len()),
            }
        }
        let mut sink = FailsAt::new(whole.len());
        tar::write(archive, &mut sink).unwrap();
        assert_eq!(sink.taken, whole, "a failure past the end is no failure");
    }
}
