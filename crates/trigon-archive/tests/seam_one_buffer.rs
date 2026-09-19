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

/// Every nested member is charged against one budget, not handed its own copy of it.
///
/// **`total_expanded_bytes` is documented as "a hard ceiling on everything one artifact expands
/// to".** It was a ceiling per nested member: `descend` passed the whole `Limits` to each `.gz` it
/// found, and every inflated body was retained at once in `Body::Nested`. Measured before the fix —
/// a 70 KB tar of eight `.gz` members, each inflating to 8 MiB, under a **16 MiB** ceiling — parsed
/// `Ok`, held **64 MiB**, and emitted no note at all.
///
/// A `.gem` is an outer tar of `.gz` members, so nothing about this shape is exotic.
///
/// `zip::read` already threaded a running total. This is the same idea in the other reader.
#[test]
fn nested_members_share_one_expansion_budget() {
    use std::io::Write as _;

    fn gz_of_zeros(n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = flate2::write::GzEncoder::new(&mut out, flate2::Compression::best());
        e.write_all(&vec![0u8; n]).unwrap();
        e.finish().unwrap();
        out
    }

    const MEMBER: usize = 8 << 20;
    const MEMBERS: usize = 8;
    let one = gz_of_zeros(MEMBER);
    let entries: Vec<(String, Vec<u8>)> = (0..MEMBERS)
        .map(|i| (format!("m{i}.gz"), one.clone()))
        .collect();

    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in &entries {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_cksum();
        b.append_data(&mut h, name, &body[..]).unwrap();
    }
    let outer = b.into_inner().unwrap();
    assert!(
        outer.len() < (1 << 20),
        "the fixture is meant to be small on disk: {} bytes",
        outer.len()
    );

    // A ceiling of two members' worth. Eight members must not all open.
    let limits = Limits {
        total_expanded_bytes: (2 * MEMBER) as u64,
        ..Limits::default()
    };
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(outer, Format::Tar, &limits, &mut notes).expect("the outer tar still parses");

    let opened = p
        .archive
        .entries
        .iter()
        .filter(|e| matches!(e.body, Body::Nested { .. }))
        .count();
    assert!(
        opened <= 2,
        "{opened} of {MEMBERS} members were opened under a ceiling that allows 2; the budget is \
         being handed out per member rather than shared"
    );

    // And the ones it could not open are *said*, not silently left closed. A member reported as
    // opaque bytes with no reason is indistinguishable from one that really is opaque.
    assert!(
        !notes.is_empty(),
        "members were left unopened and nothing said why"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.detail.contains("total_expanded_bytes")),
        "the note should name the limit that stopped it: {:?}",
        notes.iter().map(|n| &n.detail).collect::<Vec<_>>()
    );
}
