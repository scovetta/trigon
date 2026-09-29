//! The gzip header, field by field, on both sides.
//!
//! The container is framed by hand (`src/gzip.rs`) because stabilization has to control the
//! header's MTIME, OS and XFL bytes. That makes every optional field — FEXTRA, FNAME, FCOMMENT,
//! FHCRC — ours to read and to write, and a header is bytes the publisher chose.

use trigon_archive::gzip::{self, OS_UNKNOWN, xfl_for};
use trigon_archive::{ArchiveError, GzipHeader, Limits, Trailer, parse, serialize};
use trigon_core::Format;

const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;

fn framed(h: &GzipHeader, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    gzip::write(h, payload, flate2::Compression::none(), &mut v).unwrap();
    v
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
    };
    let bytes = framed(&h, b"payload");

    // FLG carries exactly the three present fields, and never FTEXT or FHCRC.
    assert_eq!(bytes[3], FEXTRA | FNAME | FCOMMENT);
    // RFC 1952 §2.3: XLEN and the extra field, then the name, then the comment, each NUL-ended.
    let mut expected = vec![6, 0, b'A', b'P', 2, 0, 0xde, 0xad];
    expected.extend_from_slice(b"pkg-1.0.tar\0built by hand\0");
    assert_eq!(&bytes[10..10 + expected.len()], &expected[..]);

    let (back, payload) = gzip::read(&bytes, u64::MAX).unwrap();
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

    let (h, payload) = gzip::read(&with_crc, u64::MAX).unwrap();
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
    let detail = malformed(gzip::read(&bytes, u64::MAX).unwrap_err());
    assert_eq!(detail, "unterminated string");

    // The comment is read by the same rule.
    let mut bytes = vec![0x1f, 0x8b, 8, FCOMMENT, 0, 0, 0, 0, 0, OS_UNKNOWN];
    bytes.extend_from_slice(b"a comment that never ends");
    let detail = malformed(gzip::read(&bytes, u64::MAX).unwrap_err());
    assert_eq!(detail, "unterminated string");
}

#[test]
fn an_extra_field_longer_than_the_member_is_malformed() {
    let mut bytes = vec![0x1f, 0x8b, 8, FEXTRA, 0, 0, 0, 0, 0, OS_UNKNOWN];
    bytes.extend_from_slice(&0xffffu16.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 16]);
    let detail = malformed(gzip::read(&bytes, u64::MAX).unwrap_err());
    assert_eq!(detail, "truncated FEXTRA body");
}

#[test]
fn fields_that_run_into_the_trailer_leave_no_payload_and_say_so() {
    // A name that ends inside the eight trailer bytes: nothing is left to inflate.
    let mut bytes = vec![0x1f, 0x8b, 8, FNAME, 0, 0, 0, 0, 0, OS_UNKNOWN];
    bytes.extend_from_slice(b"abcdefghi\0");
    let detail = malformed(gzip::read(&bytes, u64::MAX).unwrap_err());
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
    assert_eq!(gzip::read(&stabilized, u64::MAX).unwrap().0.xfl, 0);

    // Not stabilizing: the header is written back as it was found.
    let kept = serialize(&parsed.archive, false).unwrap();
    let (h, payload) = gzip::read(&kept, u64::MAX).unwrap();
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
        let (back, payload) = gzip::read(&out, u64::MAX).unwrap();
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

    let (h, _) = gzip::read(&serialize(&a, true).unwrap(), u64::MAX).unwrap();
    assert_eq!(h.mtime, None);
    assert_eq!(h.name, None);
    assert_eq!(h.comment, None);
    assert_eq!(h.extra, None);
}
