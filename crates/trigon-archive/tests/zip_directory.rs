//! The zip central directory as a publisher's tool may write it, and the writer's other paths.
//!
//! Both directions are ours (`src/zip.rs`): the reader walks the central directory itself, so every
//! zip64 shape — which of the three fields overflowed, what sits beside the zip64 extra field, a
//! marker with no field behind it — is a shape this code has to decide about. These are assembled
//! by hand, because no honest writer produces most of them.

use std::io::{Cursor, Write as _};
use std::sync::Arc;

use trigon_archive::{Archive, ArchiveError, Limits, RawMeta, SourceMap, TarRaw, Trailer, zip};
use trigon_core::{Format, Note, NoteCode};

const MARK32: u32 = 0xFFFF_FFFF;

fn read_with(bytes: Vec<u8>, limits: &Limits) -> Result<(Archive, Vec<Note>), ArchiveError> {
    let mut notes = Vec::new();
    let a = zip::read(Arc::new(SourceMap::owned(bytes)), limits, &mut notes)?;
    Ok((a, notes))
}

fn read(bytes: Vec<u8>) -> Result<Archive, ArchiveError> {
    read_with(bytes, &Limits::default()).map(|(a, _)| a)
}

fn malformed(err: ArchiveError) -> String {
    match err {
        ArchiveError::Malformed { format, detail } => {
            assert_eq!(format, "zip");
            detail
        }
        other => panic!("expected a malformed zip, got {other:?}"),
    }
}

/// The central-directory fields the zip64 cases rewrite.
struct Directory {
    comp: u32,
    uncomp: u32,
    offset: u32,
    extra: Vec<u8>,
}

/// One member at offset 0, its local header honest, then one central-directory record carrying
/// whatever `edit` makes of its sizes, offset and extra field, then the end record.
fn hand_zip(method: u16, stored: &[u8], uncomp: u32, edit: impl FnOnce(&mut Directory)) -> Vec<u8> {
    let name = b"member.bin";
    // A stored member's checksum is honest. The deflate and bzip2 cases are refused before any
    // checksum could be checked: one at the expansion ceiling, the other at its method.
    let crc = if method == 0 {
        crc32fast::hash(stored)
    } else {
        0
    };
    let mut out = Vec::new();
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&method.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // time, date
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(stored.len() as u32).to_le_bytes());
    out.extend_from_slice(&uncomp.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra length
    out.extend_from_slice(name);
    out.extend_from_slice(stored);

    let mut d = Directory {
        comp: stored.len() as u32,
        uncomp,
        offset: 0,
        extra: Vec::new(),
    };
    edit(&mut d);

    let cd_offset = out.len() as u32;
    let mut cd = Vec::new();
    cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
    cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
    cd.extend_from_slice(&0u16.to_le_bytes()); // flags
    cd.extend_from_slice(&method.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes()); // time, date
    cd.extend_from_slice(&crc.to_le_bytes());
    cd.extend_from_slice(&d.comp.to_le_bytes());
    cd.extend_from_slice(&d.uncomp.to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&(d.extra.len() as u16).to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes()); // comment
    cd.extend_from_slice(&0u16.to_le_bytes()); // disk
    cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    cd.extend_from_slice(&d.offset.to_le_bytes());
    cd.extend_from_slice(name);
    cd.extend_from_slice(&d.extra);
    out.extend_from_slice(&cd);

    out.extend_from_slice(&end_record(1, cd.len() as u32, cd_offset));
    out
}

fn end_record(count: u16, cd_size: u32, cd_offset: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // this disk, cd disk
    v.extend_from_slice(&count.to_le_bytes());
    v.extend_from_slice(&count.to_le_bytes());
    v.extend_from_slice(&cd_size.to_le_bytes());
    v.extend_from_slice(&cd_offset.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // comment length
    v
}

/// An extra field: id, length, body.
fn field(id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&(body.len() as u16).to_le_bytes());
    v.extend_from_slice(body);
    v
}

fn zip64(values: &[u64]) -> Vec<u8> {
    let body: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
    field(0x0001, &body)
}

// --- zip64 in the central directory ---------------------------------------------------------------

#[test]
fn a_zip64_field_holds_only_the_values_that_overflowed_in_the_order_the_spec_fixes() {
    // Uncompressed size and offset overflowed; the compressed size did not. The field then holds
    // two values, and the offset is the *second* — not the third slot of a fixed layout.
    let body = b"zip64 body";
    let bytes = hand_zip(0, body, body.len() as u32, |d| {
        d.uncomp = MARK32;
        d.offset = MARK32;
        d.extra = zip64(&[body.len() as u64, 0]);
    });
    let a = read(bytes).unwrap();
    assert_eq!(a.entries[0].body_bytes().unwrap().as_ref(), body);
    assert_eq!(a.entries[0].meta.size, body.len() as u64);

    // Only the offset.
    let bytes = hand_zip(0, body, body.len() as u32, |d| {
        d.offset = MARK32;
        d.extra = zip64(&[0]);
    });
    assert_eq!(
        read(bytes).unwrap().entries[0]
            .body_bytes()
            .unwrap()
            .as_ref(),
        body
    );

    // Only the compressed size.
    let bytes = hand_zip(0, body, body.len() as u32, |d| {
        d.comp = MARK32;
        d.extra = zip64(&[body.len() as u64]);
    });
    assert_eq!(
        read(bytes).unwrap().entries[0]
            .body_bytes()
            .unwrap()
            .as_ref(),
        body
    );
}

#[test]
fn a_zip64_field_is_found_behind_other_extra_fields_and_they_are_kept() {
    let body = b"behind a timestamp";
    let timestamp = field(0x5455, &[1, 0, 0, 0, 0]);
    let bytes = hand_zip(0, body, body.len() as u32, |d| {
        d.offset = MARK32;
        d.extra = [timestamp.clone(), zip64(&[0])].concat();
    });
    let a = read(bytes).unwrap();
    assert_eq!(a.entries[0].body_bytes().unwrap().as_ref(), body);
    let RawMeta::Zip(z) = &a.entries[0].raw else {
        panic!("a zip entry")
    };
    assert_eq!(
        z.extra,
        [timestamp, zip64(&[0])].concat(),
        "preserved verbatim"
    );
}

#[test]
fn a_zip64_marker_with_no_zip64_field_behind_it_is_malformed() {
    let bytes = hand_zip(0, b"x", 1, |d| {
        d.offset = MARK32;
        d.extra = field(0x5455, &[1, 0, 0, 0, 0]);
    });
    assert_eq!(
        malformed(read(bytes).unwrap_err()),
        "zip64 marker without a zip64 extra field"
    );
}

#[test]
fn a_zip64_field_shorter_than_it_claims_or_than_it_must_be_is_malformed() {
    // Declares sixteen bytes and carries eight.
    let bytes = hand_zip(0, b"x", 1, |d| {
        d.offset = MARK32;
        let mut f = zip64(&[0]);
        f[2] = 16;
        d.extra = f;
    });
    assert_eq!(malformed(read(bytes).unwrap_err()), "truncated extra field");

    // Honest about its length, but two fields overflowed and it holds one value.
    let bytes = hand_zip(0, b"x", 1, |d| {
        d.uncomp = MARK32;
        d.offset = MARK32;
        d.extra = zip64(&[1]);
    });
    assert_eq!(malformed(read(bytes).unwrap_err()), "short read");
}

// --- zip64 end records ----------------------------------------------------------------------------

#[test]
fn an_overflowed_count_without_a_zip64_locator_before_it_is_malformed() {
    let mut bytes = vec![0u8; 20];
    bytes.extend_from_slice(&end_record(0xFFFF, 0, 0));
    assert_eq!(
        malformed(read(bytes).unwrap_err()),
        "zip64 locator signature"
    );
}

#[test]
fn a_zip64_locator_pointing_at_something_else_is_malformed() {
    let mut bytes = vec![0u8; 56]; // where the zip64 end record should be, and is not
    bytes.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // disk
    bytes.extend_from_slice(&0u64.to_le_bytes()); // the zip64 end record's offset
    bytes.extend_from_slice(&1u32.to_le_bytes()); // disks
    bytes.extend_from_slice(&end_record(0xFFFF, MARK32, MARK32));
    assert_eq!(
        malformed(read(bytes).unwrap_err()),
        "zip64 end-of-central-directory signature"
    );
}

// --- members --------------------------------------------------------------------------------------

#[test]
fn a_deflated_member_that_inflates_past_the_remaining_budget_is_refused_at_the_budget() {
    // Declares a small size, so the cheap check on the declaration passes; what it inflates to is
    // what the ceiling is charged, and inflation stops one byte past it.
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(&vec![0u8; 64 * 1024]).unwrap();
    let deflated = e.finish().unwrap();
    let bytes = hand_zip(8, &deflated, 100, |_| {});

    let limits = Limits {
        total_expanded_bytes: 1000,
        ..Limits::default()
    };
    match read_with(bytes, &limits) {
        Err(ArchiveError::LimitExceeded {
            limit,
            actual,
            allowed,
        }) => assert_eq!(
            (limit, actual, allowed),
            ("total_expanded_bytes", 1001, 1000)
        ),
        other => panic!("expected the ceiling, got {other:?}"),
    }
}

#[test]
fn a_member_in_a_method_the_reader_cannot_inflate_is_policy_and_not_worth_retrying() {
    use trigon_core::{Classify as _, Fault};
    let err = read(hand_zip(12, b"BZh9", 4, |_| {})).unwrap_err();
    match &err {
        ArchiveError::Unsupported(what) => assert_eq!(what, "zip compression method 12"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(err.fault(), Fault::Policy);
    assert!(
        !err.is_retryable(),
        "the same bytes are the same method next time"
    );
}

#[test]
fn a_duplicate_member_path_is_noted_with_its_count() {
    let mut w = ::zip_crate::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = ::zip_crate::write::SimpleFileOptions::default()
        .compression_method(::zip_crate::CompressionMethod::Stored);
    for name in ["a.txt", "b.txt", "c.txt"] {
        w.start_file(name, opts).unwrap();
        w.write_all(name.as_bytes()).unwrap();
    }
    let mut a = read(w.finish().unwrap().into_inner()).unwrap();
    // The external writer refuses a duplicate name, so the duplicate is made in the model and
    // written by ours.
    a.entries[1].path = "a.txt".into();
    a.entries[2].path = "a.txt".into();
    let mut bytes = Vec::new();
    zip::write(&a, &mut bytes, true).unwrap();

    let (back, notes) = read_with(bytes, &Limits::default()).unwrap();
    assert_eq!(back.entries.len(), 3, "every copy is kept");
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0].code, NoteCode::DuplicateEntryPath);
    assert_eq!(notes[0].path.as_ref().unwrap().as_bytes(), b"a.txt");
    assert!(
        notes[0].detail.starts_with("appears 3 times"),
        "{}",
        notes[0].detail
    );
}

// --- the writer -----------------------------------------------------------------------------------

fn deflated_zip(body: &[u8]) -> Vec<u8> {
    let mut w = ::zip_crate::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = ::zip_crate::write::SimpleFileOptions::default()
        .compression_method(::zip_crate::CompressionMethod::Deflated);
    w.start_file("text.txt", opts).unwrap();
    w.write_all(body).unwrap();
    w.finish().unwrap().into_inner()
}

#[test]
fn without_store_only_each_member_keeps_its_method_and_is_really_compressed() {
    let body = b"the same line again\n".repeat(200);
    let a = read(deflated_zip(&body)).unwrap();

    let mut out = Vec::new();
    zip::write(&a, &mut out, false).unwrap();
    assert!(out.len() < body.len() / 4, "deflated: {} bytes", out.len());

    let back = read(out.clone()).unwrap();
    let RawMeta::Zip(z) = &back.entries[0].raw else {
        panic!("a zip entry")
    };
    assert_eq!(z.method, 8);
    assert_eq!(back.entries[0].body_bytes().unwrap().as_ref(), &body[..]);

    let mut ext = ::zip_crate::ZipArchive::new(Cursor::new(out)).unwrap();
    let mut got = Vec::new();
    std::io::Read::read_to_end(&mut ext.by_index(0).unwrap(), &mut got).unwrap();
    assert_eq!(got, body);
}

#[test]
fn a_method_the_writer_cannot_encode_is_refused_unless_the_output_is_stored() {
    let mut a = read(deflated_zip(b"bz2 in name only")).unwrap();
    let RawMeta::Zip(z) = &mut a.entries[0].raw else {
        panic!("a zip entry")
    };
    z.method = 12; // bzip2

    let mut out = Vec::new();
    match zip::write(&a, &mut out, false) {
        Err(ArchiveError::Unsupported(what)) => assert_eq!(what, "zip method 12"),
        other => panic!("expected a refusal rather than a mislabelled member, got {other:?}"),
    }

    // Stored output needs no encoder, so any method it arrived with is written as method 0.
    let mut out = Vec::new();
    zip::write(&a, &mut out, true).unwrap();
    let back = read(out).unwrap();
    let RawMeta::Zip(z) = &back.entries[0].raw else {
        panic!("a zip entry")
    };
    assert_eq!(z.method, 0);
    assert_eq!(
        back.entries[0].body_bytes().unwrap().as_ref(),
        b"bz2 in name only"
    );
}

#[test]
fn a_tar_member_cannot_be_written_into_a_zip() {
    let mut a = read(deflated_zip(b"x")).unwrap();
    a.entries[0].raw = RawMeta::Tar(TarRaw::default());
    match zip::write(&a, &mut Vec::new(), true) {
        Err(ArchiveError::Unsupported(what)) => assert!(what.contains("tar entry"), "{what}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_archive_with_no_zip_trailer_writes_as_a_valid_zip_with_no_comment() {
    let a = Archive::new(Format::Zip, Trailer::None);
    let mut out = Vec::new();
    zip::write(&a, &mut out, true).unwrap();
    assert_eq!(out, end_record(0, 0, 0), "an empty zip is its end record");
    let back = read(out.clone()).unwrap();
    assert!(back.entries.is_empty());
    assert_eq!(
        back.trailer,
        Trailer::Zip {
            comment: Vec::new()
        }
    );
    assert_eq!(
        ::zip_crate::ZipArchive::new(Cursor::new(out))
            .unwrap()
            .len(),
        0
    );
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
    // A local header, its name and payload; a central-directory record with its extra field and
    // comment; the end record and the archive comment. The sink fails at every offset in turn, so
    // the error has to come out of each of those writes and not only out of the first.
    let mut a = read(deflated_zip(b"x")).unwrap();
    let RawMeta::Zip(z) = &mut a.entries[0].raw else {
        panic!("a zip entry")
    };
    z.extra = field(0x5455, &[1, 0, 0, 0, 0]);
    z.comment = b"member comment".to_vec();
    a.trailer = Trailer::Zip {
        comment: b"archive comment".to_vec(),
    };
    // An empty zip is still its end record.
    let empty = Archive::new(Format::Zip, Trailer::None);

    for archive in [&a, &empty] {
        for store_only in [true, false] {
            let mut whole = Vec::new();
            zip::write(archive, &mut whole, store_only).unwrap();
            for at in 0..whole.len() {
                match zip::write(archive, &mut FailsAt::new(at), store_only) {
                    Err(ArchiveError::Io(_)) => {}
                    other => panic!("failing at byte {at} of {}: {other:?}", whole.len()),
                }
            }
            let mut sink = FailsAt::new(whole.len());
            zip::write(archive, &mut sink, store_only).unwrap();
            assert_eq!(sink.taken, whole, "a failure past the end is no failure");
        }
    }
}
