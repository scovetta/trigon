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

/// A zip64 locator pointing its end-of-central-directory at `u64::MAX`.
///
/// Forty-two bytes, and it used to panic: the cursor did `self.p + n` on an offset the file
/// controls, which wraps. Under this workspace's release profile, which enables overflow checks,
/// that is an abort; without them it is a read of whatever the wrapped range lands on.
fn zip64_locator_at_max() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x0706_4b50u32.to_le_bytes()); // zip64 EOCD locator signature
    b.extend_from_slice(&0u32.to_le_bytes()); // disk holding the zip64 EOCD
    b.extend_from_slice(&u64::MAX.to_le_bytes()); // its offset: the whole point
    b.extend_from_slice(&1u32.to_le_bytes()); // total disks
    b.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // EOCD signature
    b.extend_from_slice(&0u16.to_le_bytes()); // this disk
    b.extend_from_slice(&0u16.to_le_bytes()); // disk with the central directory
    b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // entries here: the zip64 marker
    b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // entries total
    b.extend_from_slice(&0u32.to_le_bytes()); // central directory size
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // its offset: the zip64 marker
    b.extend_from_slice(&0u16.to_le_bytes()); // comment length
    b
}

#[test]
fn an_offset_that_wraps_is_a_short_read_and_not_a_panic() {
    // A panic parsing an artifact is a denial of service on a sweep worker, and worse: an outcome
    // that reads as our infrastructure failing rather than as a hostile input.
    let bytes = zip64_locator_at_max();
    assert_eq!(bytes.len(), 42);
    let err = parse(bytes, Format::Zip, &Limits::default(), &mut Vec::new())
        .expect_err("a locator pointing past the end cannot resolve");
    assert!(
        err.to_string().contains("short read"),
        "named as what it is: {err}"
    );
}

/// A gzip member of `n` zero bytes, which compresses to almost nothing.
fn gzip_bomb(n: usize) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(&vec![0u8; n]).unwrap();
    e.finish().unwrap()
}

#[test]
fn a_gzip_bomb_is_refused_at_the_limit_rather_than_inflated() {
    // `total_expanded_bytes` used to be checked against the sizes a zip's central directory
    // *declares*, and gzip took no limits at all — so this inflated in full whatever the caller
    // asked for. `.tar.gz` is every npm package, so this is the hot path, not an exotic one.
    let bomb = gzip_bomb(64 * 1024 * 1024);
    assert!(
        bomb.len() < 100_000,
        "the point is that it is small: {}",
        bomb.len()
    );

    let limits = Limits {
        total_expanded_bytes: 1024 * 1024,
        ..Limits::default()
    };
    let err = parse(bomb.clone(), Format::Gzip, &limits, &mut Vec::new())
        .expect_err("64 MiB through a 1 MiB ceiling");
    assert!(
        err.to_string().contains("total_expanded_bytes"),
        "the limit that stopped it is named: {err}"
    );

    // And the same bytes parse when the ceiling allows them: the limit is a limit, not a refusal
    // to inflate.
    assert!(parse(bomb, Format::Gzip, &Limits::default(), &mut Vec::new()).is_ok());
}

/// A one-member deflate zip, with the central directory declaring `declared` uncompressed bytes.
///
/// Hand-assembled, because this crate deliberately owns its zip writer and that writer only ever
/// emits stored members — the deflate path is what a *published* artifact uses, and what this is
/// testing.
fn deflate_zip(body: &[u8], declared: u32) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(body).unwrap();
    let deflated = e.finish().unwrap();
    let crc = crc32fast::hash(body);
    let name = b"big";

    let mut lfh = Vec::new();
    lfh.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    lfh.extend_from_slice(&20u16.to_le_bytes()); // version needed
    lfh.extend_from_slice(&0u16.to_le_bytes()); // flags
    lfh.extend_from_slice(&8u16.to_le_bytes()); // deflate
    lfh.extend_from_slice(&0u16.to_le_bytes()); // time
    lfh.extend_from_slice(&0u16.to_le_bytes()); // date
    lfh.extend_from_slice(&crc.to_le_bytes());
    lfh.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
    lfh.extend_from_slice(&declared.to_le_bytes());
    lfh.extend_from_slice(&(name.len() as u16).to_le_bytes());
    lfh.extend_from_slice(&0u16.to_le_bytes()); // extra length
    lfh.extend_from_slice(name);

    let mut out = lfh;
    out.extend_from_slice(&deflated);
    let cd_offset = out.len() as u32;

    let mut cdh = Vec::new();
    cdh.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    cdh.extend_from_slice(&20u16.to_le_bytes()); // version made by
    cdh.extend_from_slice(&20u16.to_le_bytes()); // version needed
    cdh.extend_from_slice(&0u16.to_le_bytes()); // flags
    cdh.extend_from_slice(&8u16.to_le_bytes()); // deflate
    cdh.extend_from_slice(&0u16.to_le_bytes()); // time
    cdh.extend_from_slice(&0u16.to_le_bytes()); // date
    cdh.extend_from_slice(&crc.to_le_bytes());
    cdh.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
    cdh.extend_from_slice(&declared.to_le_bytes());
    cdh.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cdh.extend_from_slice(&0u16.to_le_bytes()); // extra
    cdh.extend_from_slice(&0u16.to_le_bytes()); // comment
    cdh.extend_from_slice(&0u16.to_le_bytes()); // disk
    cdh.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    cdh.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    cdh.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    cdh.extend_from_slice(name);
    let cd_size = cdh.len() as u32;
    out.extend_from_slice(&cdh);

    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    out.extend_from_slice(&1u16.to_le_bytes()); // entries here
    out.extend_from_slice(&1u16.to_le_bytes()); // entries total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

#[test]
fn a_zip_member_that_lies_about_its_size_is_refused() {
    // The declared size is what the walker adds to its running total, so a member declaring 64
    // bytes and inflating to 32 MiB made every limit downstream a limit on fiction: the artifact
    // passed the `total_expanded_bytes` check and then expanded past it inside this process.
    let bytes = deflate_zip(&vec![0u8; 32 * 1024 * 1024], 64);
    assert!(bytes.len() < 100_000, "small on the wire: {}", bytes.len());

    let err = parse(bytes, Format::Zip, &Limits::default(), &mut Vec::new())
        .expect_err("a member that inflates past what it declared");
    let text = err.to_string();
    assert!(
        text.contains("declares 64") || text.contains("total_expanded_bytes"),
        "refused for the right reason: {text}"
    );

    // An honest member of the same shape still parses, so the check is about the lie and not about
    // deflate.
    let honest = deflate_zip(b"hello", 5);
    assert!(parse(honest, Format::Zip, &Limits::default(), &mut Vec::new()).is_ok());
}
