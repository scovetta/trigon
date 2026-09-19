//! A decompressed artifact is held once, not twice.
//!
//! `Parsed::container` exists so a caller can digest the container — `trigon-compare` is the only
//! one that does, and it hashes the bytes and drops them. It used to be a `Vec<u8>` cloned out of
//! the very buffer the tar reader had just been handed, so every `.tar.gz` and every `.gz` sat in
//! memory twice for as long as the `Parsed` lived.
//!
//! Measured before the fix, calling `trigon_api::member::read` on a tarball of zeros: 4.9 MB
//! compressed expanding to 1024 MiB peaked at 2064 MB of RSS, and 19.5 MB expanding to 4095 MiB
//! peaked at **8213 MB** — 2.006x the decompressed size, for one member read. `MAX_ARTIFACT`
//! bounds the *compressed* blob at 256 MiB and the expansion ceiling is `total_expanded_bytes`, 4
//! GiB, so nothing in between said no.
//!
//! Asserted as pointer identity rather than as a memory measurement, because "these are the same
//! allocation" is the actual claim and an RSS threshold is a flaky restatement of it.

use std::sync::Arc;

use trigon_archive::{Body, Limits, parse};
use trigon_core::{Format, Note};

fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in entries {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append_data(&mut h, name, *body).unwrap();
    }
    let tar = b.into_inner().unwrap();
    let mut gz = Vec::new();
    let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
    e.write_all(&tar).unwrap();
    e.finish().unwrap();
    gz
}

#[test]
fn a_tar_gz_container_shares_the_readers_buffer() {
    let bytes = tar_gz(&[("a.txt", b"one"), ("b.txt", b"two")]);
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(bytes, Format::TarGz, &Limits::default(), &mut notes).unwrap();

    let container = p.container.as_ref().expect("a .tar.gz has a container");
    let body = &p
        .archive
        .entries
        .first()
        .expect("the fixture has entries")
        .body;
    let Body::Original { src, off, len } = body else {
        panic!("a tar entry's body should be a window onto the source, got {body:?}");
    };

    assert!(
        Arc::ptr_eq(container, src),
        "the container and the entry bodies are two allocations of the same decompressed tar; \
         that doubles the memory cost of every request that parses one"
    );
    // And it is the right buffer, not merely a shared one: read the member back through the
    // window the entry itself carries.
    let (start, end) = (*off as usize, (*off + *len) as usize);
    assert_eq!(
        &container.as_slice()[start..end],
        b"one",
        "the entry's own offsets must address its body inside the shared container"
    );
}

#[test]
fn a_bare_gzip_member_shares_it_too() {
    // The `.gz`-of-not-a-tar path built its single entry with `Body::Inline(inner.clone())`, which
    // is the same defect by a different spelling.
    use std::io::Write as _;
    let mut gz = Vec::new();
    let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
    e.write_all(b"not a tar, just a body").unwrap();
    e.finish().unwrap();

    let mut notes: Vec<Note> = Vec::new();
    let p = parse(gz, Format::Gzip, &Limits::default(), &mut notes).unwrap();

    let container = p.container.as_ref().expect("a .gz has a container");
    let body = &p.archive.entries.first().expect("one member").body;
    let Body::Original { src, off, len } = body else {
        panic!("the single gzip member should window onto the source, got {body:?}");
    };
    assert!(
        Arc::ptr_eq(container, src),
        "the gzip member and the container are two copies of one payload"
    );
    assert_eq!((*off, *len), (0, 22), "the window must cover the payload");
    assert_eq!(container.as_slice(), b"not a tar, just a body");
}

#[test]
fn the_container_is_still_the_bytes_that_get_digested() {
    // The point of keeping it at all. If sharing had changed *which* bytes these are, every
    // container digest in every attestation would move, and nothing else here would have noticed.
    let raw = {
        let mut b = ::tar::Builder::new(Vec::new());
        let mut h = ::tar::Header::new_ustar();
        h.set_size(3);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append_data(&mut h, "a.txt", &b"one"[..]).unwrap();
        b.into_inner().unwrap()
    };
    let gz = {
        use std::io::Write as _;
        let mut out = Vec::new();
        let mut e = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
        e.write_all(&raw).unwrap();
        e.finish().unwrap();
        out
    };

    let mut notes: Vec<Note> = Vec::new();
    let p = parse(gz, Format::TarGz, &Limits::default(), &mut notes).unwrap();
    assert_eq!(
        p.container_bytes(),
        Some(&raw[..]),
        "the container must still be the uncompressed tar, byte for byte"
    );
}
