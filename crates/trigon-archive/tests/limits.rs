//! Limits, and what happens at them.
//!
//! We decompress attacker-controlled bytes and the prior art has no limits at all. Breaching one has
//! to produce a note or an error, never a silent truncation and never an allocation the size of the
//! attacker's imagination.

use trigon_archive::{ArchiveError, Limits, parse};
use trigon_core::{Classify, Fault, Format, Note, NoteCode};

fn tar_with_entries(n: usize) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for i in 0..n {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, format!("f{i}.txt"), &b"x"[..])
            .unwrap();
    }
    b.into_inner().unwrap()
}

/// A tar header claiming a body far larger than the file. The classic decompression-bomb shape:
/// cheap to send, expensive to believe.
fn tar_claiming_size(size: u64) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(4);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, "small.txt", &b"tiny"[..]).unwrap();
    let mut bytes = b.into_inner().unwrap();
    // Rewrite the size field of the first header, then re-checksum it. A ustar size field holds
    // 11 octal digits, so the claim has to fit there to be believed at all.
    let octal = format!("{size:011o}");
    assert_eq!(
        octal.len(),
        11,
        "a larger claim needs a PAX size record, not a ustar field"
    );
    bytes[124..135].copy_from_slice(octal.as_bytes());
    bytes[135] = 0;
    for x in bytes[148..156].iter_mut() {
        *x = b' ';
    }
    let sum: u32 = bytes[..512].iter().map(|&x| u32::from(x)).sum();
    bytes[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
    bytes[154] = 0;
    bytes[155] = b' ';
    bytes
}

#[test]
fn the_entry_limit_stops_and_says_so() {
    let limits = Limits {
        max_entries: 10,
        ..Limits::default()
    };
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(tar_with_entries(50), Format::Tar, &limits, &mut notes).unwrap();
    assert_eq!(p.archive.entries.len(), 10, "stopped at the limit");
    assert!(
        notes.iter().any(|n| n.code == NoteCode::EntryLimitReached),
        "a truncated archive must say it was truncated"
    );
}

#[test]
fn a_declared_size_bomb_is_refused_rather_than_allocated() {
    let limits = Limits {
        total_expanded_bytes: 1024 * 1024,
        ..Limits::default()
    };
    let mut notes: Vec<Note> = Vec::new();
    let err = parse(tar_claiming_size(4 << 30), Format::Tar, &limits, &mut notes)
        .expect_err("a four-gigabyte claim against a one-megabyte budget must be refused");
    match &err {
        ArchiveError::LimitExceeded { limit, allowed, .. } => {
            assert_eq!(*limit, "total_expanded_bytes");
            assert_eq!(*allowed, 1024 * 1024);
        }
        other => panic!("expected LimitExceeded, got {other:?}"),
    }
    // An oversized artifact is a fact about the artifact, so it must not count against us.
    assert_eq!(err.fault(), Fault::Upstream);
}

#[test]
fn the_recursion_limit_stops_descending_and_says_so() {
    // A gem-shaped archive: an outer tar holding a gzipped tar.
    let mut inner = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(2);
    h.set_mode(0o644);
    h.set_cksum();
    inner.append_data(&mut h, "deep.txt", &b"hi"[..]).unwrap();
    let mut gz = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader::default(),
        &inner.into_inner().unwrap(),
        flate2::Compression::default(),
        &mut gz,
    )
    .unwrap();

    let mut outer = ::tar::Builder::new(Vec::new());
    let mut oh = ::tar::Header::new_ustar();
    oh.set_size(gz.len() as u64);
    oh.set_mode(0o644);
    oh.set_cksum();
    outer.append_data(&mut oh, "data.tar.gz", &gz[..]).unwrap();
    let bytes = outer.into_inner().unwrap();

    let mut notes: Vec<Note> = Vec::new();
    parse(
        bytes,
        Format::Tar,
        &Limits {
            recursion: 1,
            ..Limits::default()
        },
        &mut notes,
    )
    .unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n.code == NoteCode::RecursionLimitReached)
    );
}

#[test]
fn tiny_limits_are_usable_for_tests_and_fuzzing() {
    let t = Limits::tiny();
    assert!(t.max_entries < Limits::default().max_entries);
    assert!(t.total_expanded_bytes < Limits::default().total_expanded_bytes);
    // And they actually bite.
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(tar_with_entries(2000), Format::Tar, &t, &mut notes).unwrap();
    assert_eq!(p.archive.entries.len(), t.max_entries as usize);
}

#[test]
fn faults_are_classified_so_benchmarks_stay_honest() {
    // The distinction that keeps infrastructure faults out of a reproduction rate.
    let malformed = ArchiveError::Malformed {
        format: "tar",
        detail: "x".into(),
    };
    assert_eq!(malformed.fault(), Fault::Upstream);
    assert!(!malformed.fault().is_about_the_package());

    let io = ArchiveError::Io(std::io::Error::other("disk"));
    assert_eq!(io.fault(), Fault::Infra);
    assert!(io.fault().is_retryable());

    let unsupported = ArchiveError::Unsupported("zip method 99".into());
    assert_eq!(unsupported.fault(), Fault::Policy);
}
