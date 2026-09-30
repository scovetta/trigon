//! The gzip header, field by field, on both sides.
//!
//! The container is framed by hand (`src/gzip.rs`) because stabilization has to control the
//! header's MTIME, OS and XFL bytes. That makes every optional field — FEXTRA, FNAME, FCOMMENT,
//! FHCRC — ours to read and to write, and a header is bytes the publisher chose.
//!
//! So is the file around it. RFC 1952 makes a gzip file a series of members, and what the publisher
//! put after the first one — another member, or bytes that are none — is read and checked rather
//! than skipped. A later member that holds data is refused, because the readers packages are
//! installed with disagree about it; one that holds nothing is read like the first, and bytes that
//! are no member are kept.

use trigon_archive::gzip::{self, OS_UNKNOWN, xfl_for};
use trigon_archive::{ArchiveError, Body, GzipHeader, Limits, Trailer, parse, serialize};
use trigon_core::{Format, NoteCode};

const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;

fn framed(h: &GzipHeader, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    gzip::write(h, payload, flate2::Compression::none(), &mut v).unwrap();
    v
}

/// [`gzip::read`] with nothing to limit it, for the tests about something other than limits.
fn gunzip(bytes: &[u8]) -> Result<(GzipHeader, Vec<u8>), ArchiveError> {
    let mut members = u32::MAX;
    gzip::read(bytes, u64::MAX, &mut members)
}

fn malformed(err: ArchiveError) -> String {
    match err {
        ArchiveError::Malformed { format, detail } => {
            assert_eq!(format, "gzip");
            detail
        }
        other => panic!("expected a malformed gzip, got {other:?}"),
    }
}

#[test]
fn every_optional_header_field_round_trips_in_the_order_the_format_fixes() {
    let h = GzipHeader {
        mtime: Some(1_700_000_000),
        name: Some(b"pkg-1.0.tar".to_vec()),
        comment: Some(b"built by hand".to_vec()),
        extra: Some(vec![b'A', b'P', 2, 0, 0xde, 0xad]),
        os: 3,
        xfl: 2,
        trailing: Vec::new(),
    };
    let bytes = framed(&h, b"payload");

    // FLG carries exactly the three present fields, and never FTEXT or FHCRC.
    assert_eq!(bytes[3], FEXTRA | FNAME | FCOMMENT);
    // RFC 1952 §2.3: XLEN and the extra field, then the name, then the comment, each NUL-ended.
    let mut expected = vec![6, 0, b'A', b'P', 2, 0, 0xde, 0xad];
    expected.extend_from_slice(b"pkg-1.0.tar\0built by hand\0");
    assert_eq!(&bytes[10..10 + expected.len()], &expected[..]);

    let (back, payload) = gunzip(&bytes).unwrap();
    assert_eq!(back, h);
    assert_eq!(payload, b"payload");
}

#[test]
fn a_header_crc_is_stepped_over_to_reach_the_payload() {
    // FHCRC puts two bytes between the header and the deflate stream. The writer never emits it;
    // a publisher's tool may.
    let plain = framed(&GzipHeader::default(), b"after the crc16");
    let mut with_crc = plain[..10].to_vec();
    with_crc[3] |= FHCRC;
    // RFC 1952 §2.3.1: the low sixteen bits of the CRC-32 of every header byte before it.
    let crc16 = (crc32fast::hash(&with_crc) & 0xffff) as u16;
    with_crc.extend_from_slice(&crc16.to_le_bytes());
    with_crc.extend_from_slice(&plain[10..]);

    let (h, payload) = gunzip(&with_crc).unwrap();
    assert_eq!(payload, b"after the crc16");
    assert_eq!(h, GzipHeader::default());

    // The fixture is honest: a reader that does check the header CRC accepts it.
    let mut checked = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(&with_crc[..]),
        &mut checked,
    )
    .unwrap();
    assert_eq!(checked, b"after the crc16");
}

#[test]
fn a_name_with_no_terminator_is_malformed_rather_than_read_to_the_end() {
    let mut bytes = vec![0x1f, 0x8b, 8, FNAME, 0, 0, 0, 0, 0, OS_UNKNOWN];
    bytes.extend_from_slice(b"no-nul-anywhere-in-here");
    let detail = malformed(gunzip(&bytes).unwrap_err());
    assert_eq!(detail, "unterminated string");

    // The comment is read by the same rule.
    let mut bytes = vec![0x1f, 0x8b, 8, FCOMMENT, 0, 0, 0, 0, 0, OS_UNKNOWN];
    bytes.extend_from_slice(b"a comment that never ends");
    let detail = malformed(gunzip(&bytes).unwrap_err());
    assert_eq!(detail, "unterminated string");
}

#[test]
fn an_extra_field_longer_than_the_member_is_malformed() {
    let mut bytes = vec![0x1f, 0x8b, 8, FEXTRA, 0, 0, 0, 0, 0, OS_UNKNOWN];
    bytes.extend_from_slice(&0xffffu16.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 16]);
    let detail = malformed(gunzip(&bytes).unwrap_err());
    assert_eq!(detail, "truncated FEXTRA body");
}

#[test]
fn fields_that_run_into_the_trailer_leave_no_payload_and_say_so() {
    // A name that ends inside the eight trailer bytes: nothing is left to inflate.
    let mut bytes = vec![0x1f, 0x8b, 8, FNAME, 0, 0, 0, 0, 0, OS_UNKNOWN];
    bytes.extend_from_slice(b"abcdefghi\0");
    let detail = malformed(gunzip(&bytes).unwrap_err());
    assert_eq!(detail, "truncated payload");
}

#[test]
fn the_xfl_byte_follows_the_level_as_deflate_writers_set_it() {
    assert_eq!(xfl_for(9), 2, "best compression");
    assert_eq!(xfl_for(1), 4, "fastest");
    for level in [0, 2, 6, 8] {
        assert_eq!(xfl_for(level), 0, "level {level}");
    }
}

#[test]
fn a_stabilized_reserialization_reports_the_xfl_of_stored_output() {
    // A published member compressed at level 9 says XFL=2. The stabilized stream is stored, and
    // an XFL claiming maximum compression over stored blocks would be a lie in a signed digest.
    let inner = {
        let mut b = ::tar::Builder::new(Vec::new());
        let mut h = ::tar::Header::new_ustar();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "a", &b"x"[..]).unwrap();
        b.into_inner().unwrap()
    };
    let mut published = Vec::new();
    gzip::write(
        &GzipHeader {
            xfl: xfl_for(9),
            ..GzipHeader::default()
        },
        &inner,
        flate2::Compression::best(),
        &mut published,
    )
    .unwrap();

    let parsed = parse(
        published,
        Format::TarGz,
        &Limits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert!(matches!(&parsed.archive.trailer, Trailer::Gzip(h) if h.xfl == 2));

    let stabilized = serialize(&parsed.archive, true).unwrap();
    assert_eq!(gunzip(&stabilized).unwrap().0.xfl, 0);

    // Not stabilizing: the header is written back as it was found.
    let kept = serialize(&parsed.archive, false).unwrap();
    let (h, payload) = gunzip(&kept).unwrap();
    assert_eq!(h.xfl, 2);
    let back = parse(payload, Format::Tar, &Limits::default(), &mut Vec::new()).unwrap();
    let e = &back.archive.entries[0];
    assert_eq!(
        (e.path.as_bytes(), e.body_bytes().unwrap().as_ref()),
        (&b"a"[..], &b"x"[..])
    );
}

#[test]
fn a_bare_gzip_member_reserializes_to_the_same_payload_and_name_either_way() {
    let h = GzipHeader {
        name: Some(b"notes.txt".to_vec()),
        os: OS_UNKNOWN,
        ..GzipHeader::default()
    };
    let text = b"not a tar, just text\n".repeat(20);
    let parsed = parse(
        framed(&h, &text),
        Format::Gzip,
        &Limits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(parsed.archive.entries[0].path.as_bytes(), b"notes.txt");

    for store_only in [true, false] {
        let out = serialize(&parsed.archive, store_only).unwrap();
        let (back, payload) = gunzip(&out).unwrap();
        assert_eq!(payload, text, "store_only {store_only}");
        assert_eq!(back.name, h.name, "store_only {store_only}");
    }
}

#[test]
fn a_tar_reserialized_as_tar_gz_without_a_gzip_header_leaks_no_name_or_time() {
    // The header comes from the trailer; an archive that never had a gzip one gets the empty
    // header rather than anything borrowed from the host.
    let mut b = ::tar::Builder::new(Vec::new());
    let mut th = ::tar::Header::new_ustar();
    th.set_size(1);
    th.set_mode(0o644);
    th.set_cksum();
    b.append_data(&mut th, "a", &b"x"[..]).unwrap();
    let mut a = parse(
        b.into_inner().unwrap(),
        Format::Tar,
        &Limits::default(),
        &mut Vec::new(),
    )
    .unwrap()
    .archive;
    assert_eq!(a.trailer, Trailer::Tar);
    a.format = Format::TarGz;

    let (h, _) = gunzip(&serialize(&a, true).unwrap()).unwrap();
    assert_eq!(h.mtime, None);
    assert_eq!(h.name, None);
    assert_eq!(h.comment, None);
    assert_eq!(h.extra, None);
}

// --- members, and what comes after them -----------------------------------------------------------

/// `member` with the CRC-32 its trailer stores replaced by `crc`.
fn with_crc(mut member: Vec<u8>, crc: u32) -> Vec<u8> {
    let n = member.len();
    member[n - 8..n - 4].copy_from_slice(&crc.to_le_bytes());
    member
}

/// What the two kinds of reader make of `bytes`: every member, as gunzip, Node's zlib and Python's
/// gzip read one, and the first alone, as RubyGems' `Zlib::GzipReader` and Cargo's `GzDecoder` do.
fn read_by_both(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use std::io::Read as _;
    let (mut every, mut first) = (Vec::new(), Vec::new());
    flate2::read::MultiGzDecoder::new(bytes)
        .read_to_end(&mut every)
        .unwrap();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut first)
        .unwrap();
    (every, first)
}

#[test]
fn a_member_after_the_first_that_holds_data_is_refused_because_readers_disagree_about_it() {
    // RFC 1952 §2.2: a gzip file is a series of members. gunzip, Node and Python decompress every
    // one; RubyGems and Cargo stop after the first. Read as every member's content, a gem whose
    // `data.tar.gz` carried its last entries in a second member matched an honest build of all of
    // them, and RubyGems installs it without them. There is no one content to compare.
    let first = GzipHeader {
        name: Some(b"first".to_vec()),
        ..GzipHeader::default()
    };
    let second = GzipHeader {
        name: Some(b"second".to_vec()),
        os: 3,
        ..GzipHeader::default()
    };
    let head = framed(&first, b"hello P");
    let bytes = [head.clone(), framed(&second, b"hidden Q")].concat();
    assert_eq!(
        read_by_both(&bytes),
        (b"hello Phidden Q".to_vec(), b"hello P".to_vec()),
        "the fixture is one the two kinds of reader read differently"
    );
    let detail = malformed(gunzip(&bytes).unwrap_err());
    let at = head.len();
    assert!(
        detail.starts_with(&format!(
            "the member at offset {at} holds data after a first member of 7 bytes"
        )),
        "{detail}"
    );
}

#[test]
fn members_after_the_first_that_hold_nothing_read_as_the_first_alone() {
    // An empty member says the same to every reader, so it is read, checked and set aside.
    let first = GzipHeader {
        name: Some(b"first".to_vec()),
        ..GzipHeader::default()
    };
    let bytes = [
        framed(&first, b"hello P"),
        framed(&GzipHeader::default(), b""),
        framed(&GzipHeader::default(), b""),
    ]
    .concat();
    let (h, payload) = gunzip(&bytes).unwrap();
    assert_eq!(payload, b"hello P");
    assert_eq!(
        h, first,
        "the header is the first member's, which every reader reports"
    );
    assert_eq!(
        read_by_both(&bytes),
        (payload.clone(), payload),
        "and both kinds of reader agree"
    );
}

#[test]
fn a_second_member_whose_crc_was_forged_to_the_firsts_is_refused_rather_than_skipped() {
    // The trailer was taken to be the file's last eight bytes, so a second member whose stored CRC
    // was set to the first member's content made the whole file read as its first member alone.
    // An npm tarball or sdist framed that way installs both, and stabilized to the same digest as
    // an honest rebuild of the first: a false match. A second member that holds data is refused
    // now whatever its trailer says, and one that holds nothing is held to its own trailer.
    let p = framed(&GzipHeader::default(), b"hello P");
    let q = with_crc(
        framed(&GzipHeader::default(), b"hidden Q"),
        crc32fast::hash(b"hello P"),
    );
    let detail = malformed(gunzip(&[p.clone(), q].concat()).unwrap_err());
    assert!(
        detail.contains("holds data after a first member"),
        "{detail}"
    );

    let empty = with_crc(
        framed(&GzipHeader::default(), b""),
        crc32fast::hash(b"hello P"),
    );
    let detail = malformed(gunzip(&[p, empty].concat()).unwrap_err());
    assert_eq!(detail, "crc32 mismatch: stored ed5a68a9, computed 00000000");
}

#[test]
fn bytes_between_the_deflate_stream_and_its_trailer_are_not_stepped_over() {
    // A member's trailer is the eight bytes after its deflate stream ends, wherever that is.
    let member = framed(&GzipHeader::default(), b"hello P");
    let n = member.len();
    let spliced = [&member[..n - 8], b"8 junk!!", &member[n - 8..]].concat();
    let detail = malformed(gunzip(&spliced).unwrap_err());
    assert!(
        detail.starts_with("crc32 mismatch: stored 756a2038"),
        "{detail}"
    );
}

#[test]
fn an_isize_that_disagrees_with_what_inflated_is_refused() {
    // ISIZE is the member's length modulo 2^32, and a member is its content only if both halves of
    // its trailer say so.
    let mut member = framed(&GzipHeader::default(), b"hello P");
    let n = member.len();
    member[n - 1] ^= 0x80;
    let detail = malformed(gunzip(&member).unwrap_err());
    assert_eq!(detail, "isize mismatch: stored 2147483655, inflated 7");
}

#[test]
fn a_later_member_is_refused_at_its_first_byte_whatever_the_budget_left() {
    // The first member draws on the budget, and a later one may add nothing to it, so it is
    // inflated one byte and no further: sixteen megabytes of zeros after a first member are
    // refused as data, under a budget with room for them and under one without.
    use std::io::Write as _;
    let first = framed(&GzipHeader::default(), &[0u8; 600]);
    let mut big = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    big.write_all(&vec![0u8; 16 << 20]).unwrap();
    let bytes = [first.clone(), big.finish().unwrap()].concat();
    for budget in [600, u64::MAX] {
        let detail = malformed(gzip::read(&bytes, budget, &mut 2).unwrap_err());
        assert!(
            detail.contains("holds data after a first member of 600 bytes"),
            "budget {budget}: {detail}"
        );
    }
    match gzip::read(&first, 599, &mut 1) {
        Err(ArchiveError::LimitExceeded {
            limit,
            actual,
            allowed,
        }) => assert_eq!((limit, actual, allowed), ("total_expanded_bytes", 600, 599)),
        other => panic!("expected the ceiling, got {other:?}"),
    }
}

#[test]
fn members_are_counted_and_the_one_past_the_count_is_refused() {
    // An empty member adds nothing to the output and still costs an inflate, so the byte budget
    // never runs out and five million of them in a nested `.gz` took 12.9 s to parse. The count is
    // what bounds them: taken down one per member read, and the member past it refused.
    let empty = framed(&GzipHeader::default(), b"");
    let bytes = empty.repeat(4);

    let mut left = 4;
    assert_eq!(
        gzip::read(&bytes, u64::MAX, &mut left).unwrap().1,
        b"",
        "four members, four allowed"
    );
    assert_eq!(left, 0, "every one of them taken from the count");

    let mut left = 3;
    match gzip::read(&bytes, u64::MAX, &mut left) {
        Err(ArchiveError::LimitExceeded {
            limit,
            actual,
            allowed,
        }) => assert_eq!((limit, actual, allowed), ("gzip_members", 4, 3)),
        other => panic!("expected the member count, got {other:?}"),
    }
}

#[test]
fn one_artifact_shares_one_member_count_across_every_gz_it_holds() {
    // A count per read would let the same members be spread over many `.gz` files, each under it.
    // Two nested files of three members each read under six; under five, the second is the one
    // that runs out, and it stays in the archive as the bytes it arrived as, with a note. The
    // members after the first hold nothing, as a member after the first has to.
    let three = [&b"x"[..], b"", b""]
        .map(|c| framed(&GzipHeader::default(), c))
        .concat();
    let mut b = ::tar::Builder::new(Vec::new());
    for name in ["a.gz", "b.gz"] {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(three.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, &three[..]).unwrap();
    }
    let outer = b.into_inner().unwrap();

    for (max_entries, nested, refused) in [
        (6, [true, true], None),
        (5, [true, false], Some("gzip_members limit (3 > 2)")),
    ] {
        let limits = Limits {
            max_entries,
            ..Limits::default()
        };
        let mut notes = Vec::new();
        let a = parse(outer.clone(), Format::Tar, &limits, &mut notes)
            .unwrap()
            .archive;
        let got = a
            .entries
            .iter()
            .map(|e| matches!(e.body, Body::Nested { .. }))
            .collect::<Vec<_>>();
        assert_eq!(got, nested, "max_entries {max_entries}");
        let failed = notes
            .iter()
            .filter(|n| n.code == NoteCode::NestedParseFailed)
            .map(|n| n.detail.as_str())
            .collect::<Vec<_>>();
        match refused {
            None => assert!(failed.is_empty(), "{failed:?}"),
            Some(why) => assert!(matches!(failed[..], [d] if d.contains(why)), "{failed:?}"),
        }
    }
}

#[test]
fn bytes_after_the_last_member_that_begin_no_other_are_kept_and_written_back() {
    // gunzip warns about trailing garbage and carries on; a reader that dropped it would make two
    // files that differ only there one digest. So it is kept: the writer puts it back where it was,
    // and the comparison names it as `container:gzip.trailing`.
    let h = GzipHeader {
        name: Some(b"a".to_vec()),
        ..GzipHeader::default()
    };
    for tail in [&b"trailing garbage"[..], &[0u8; 512][..], &[0x1f][..]] {
        let bytes = [framed(&h, b"payload"), tail.to_vec()].concat();
        let (back, payload) = gunzip(&bytes).unwrap();
        assert_eq!(payload, b"payload");
        assert_eq!(back.trailing, tail, "kept, not part of the content");
        assert_eq!(back.name, h.name, "and the header is the member's");
        assert_eq!(framed(&back, &payload), bytes, "parse(write(a)) == a");
    }
}

#[test]
fn trailing_bytes_that_would_read_back_as_a_member_are_refused_by_the_writer() {
    // The reader never produces them, but a model can hold them; written out, they would come back
    // as a member or as a malformed file, and never as what they were.
    let h = GzipHeader {
        trailing: vec![0x1f, 0x8b, 8, 0],
        ..GzipHeader::default()
    };
    let mut out = Vec::new();
    match gzip::write(&h, b"x", flate2::Compression::none(), &mut out) {
        Err(ArchiveError::Unsupported(what)) => assert!(what.contains("magic"), "{what}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(out.is_empty(), "nothing written before the refusal");
}

#[test]
fn a_remainder_that_begins_with_the_magic_is_a_member_and_has_to_be_a_whole_one() {
    // gunzip's rule, and the one that decides what counts as trailing: after a member, the magic
    // starts another and anything else is not a member. A cut-off second member is a malformed
    // file, not a first member with some bytes after it. The second holds nothing, as a member
    // after the first has to, in four empty stored blocks, so a cut can fall inside its stream.
    let one = framed(&GzipHeader::default(), b"hello P");
    let mut two = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, OS_UNKNOWN];
    two.extend([0u8, 0, 0, 0xff, 0xff].repeat(3));
    two.extend([1u8, 0, 0, 0xff, 0xff]);
    two.extend([0u8; 8]);
    assert_eq!(
        gunzip(&[&one[..], &two[..]].concat()).unwrap().1,
        b"hello P"
    );
    for (cut, why) in [
        (2, "not a gzip member"),
        (20, "inflate: incomplete deflate stream"),
        (two.len() - 1, "truncated trailer"),
    ] {
        let bytes = [&one[..], &two[..cut]].concat();
        let detail = malformed(gunzip(&bytes).unwrap_err());
        assert_eq!(detail, why, "cut at {cut}");
    }
}
