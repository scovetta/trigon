//! The pass-by-pass explanation, where it is counted and where it is not computed at all.
//!
//! `progression` is explanation, never verdict: nothing reads it to decide an outcome. What it
//! promises instead is a reader's count — "how far did the set get?" — which means not counting
//! the fields a writer recomputes (B47), and saying why when there are no steps rather than
//! leaving the field absent or failing the comparison.

use std::collections::BTreeSet;
use std::io::Write as _;

use trigon_archive::Limits;
use trigon_compare::progression::{self, Progression};
use trigon_compare::{Comparison, compare_bytes};
use trigon_core::{Format, Match};
use trigon_stabilize::profile;

/// A stored zip holding one member, with these unix permissions.
fn zip_of(name: &str, body: &[u8], mode: u32) -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(mode);
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file(name, opts).unwrap();
    w.write_all(body).unwrap();
    w.finish().unwrap().into_inner()
}

fn progression_of(c: &Comparison) -> &Progression {
    c.diff
        .as_ref()
        .and_then(|d| d.progression.as_ref())
        .expect("compare_bytes records a progression")
}

#[test]
fn a_member_the_set_made_byte_identical_is_not_counted_by_the_mode_shadow_it_leaves() {
    // B47: a zip's `meta.mode` is a parse-time shadow of `external_attrs`, which is what the writer
    // emits. `zip-versions` zeroes `external_attrs` and leaves the shadow, so the in-memory
    // signature still says `entry:mode` for two members the set made identical. The progression
    // counts that code only while `external_attrs` still differs beside it.
    let c = compare_bytes(
        zip_of("bin/tool", b"#!/bin/sh\n", 0o644),
        zip_of("bin/tool", b"#!/bin/sh\n", 0o755),
        Format::Zip,
        &profile("zip").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Normalized);
    let p = progression_of(&c);
    assert!(p.consistent, "{p:#?}");

    let first = &p.steps[0];
    assert_eq!(
        (first.differences, first.members, first.bodies),
        (2, 1, 0),
        "as published, the mode and the attributes it comes from both differ: {first:#?}"
    );

    let last = p.steps.last().unwrap();
    assert_eq!(
        (last.differences, last.members, last.bodies),
        (0, 0, 0),
        "the set made the member byte-identical, so nothing is left to count: {last:#?}"
    );
    let closer: Vec<_> = p
        .steps
        .iter()
        .filter(|s| s.closed.iter().any(|m| m == "bin/tool"))
        .map(|s| s.pass.clone())
        .collect();
    assert_eq!(closer, vec![Some("zip-versions".to_string())], "{p:#?}");
}

#[test]
fn a_body_difference_is_counted_once_and_not_again_for_the_size_and_crc_derived_from_it() {
    // `entry:size` and `entry:zip.crc32` are functions of the body, which `body@` already names.
    // The signature carries them today and B47 drops them once its format is versioned; either
    // way, the count is the same.
    let c = compare_bytes(
        zip_of("lib/x.py", b"print(1)\n", 0o644),
        zip_of("lib/x.py", b"print(22)\n", 0o644),
        Format::Zip,
        &profile("zip").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let codes = &c.diff.as_ref().unwrap().codes;
    assert!(
        codes.contains("body@lib/x.py"),
        "the premise: the body is named as differing: {codes:?}"
    );

    let p = progression_of(&c);
    assert!(p.consistent, "{p:#?}");
    for s in &p.steps {
        assert_eq!(
            (s.differences, s.members, s.bodies),
            (1, 1, 1),
            "one member, one body, one difference at every step: {s:#?}"
        );
    }
}

#[test]
fn an_archive_level_difference_is_counted_without_being_a_member() {
    // Same tar, two gzip framings. `container:gzip.os` has no member to belong to.
    let inner = {
        let mut b = ::tar::Builder::new(Vec::new());
        let mut h = ::tar::Header::new_ustar();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "a", &b"x"[..]).unwrap();
        b.into_inner().unwrap()
    };
    let framed = |os: u8| {
        let mut v = Vec::new();
        trigon_archive::gzip::write(
            &trigon_archive::GzipHeader {
                os,
                ..Default::default()
            },
            &inner,
            flate2::Compression::none(),
            &mut v,
        )
        .unwrap();
        v
    };
    let c = compare_bytes(
        framed(3),
        framed(0),
        Format::TarGz,
        &profile("tar-gzip").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Normalized);
    let p = progression_of(&c);
    assert_eq!(
        (p.steps[0].differences, p.steps[0].members),
        (1, 0),
        "{:#?}",
        p.steps[0]
    );
    let last = p.steps.last().unwrap();
    assert_eq!((last.differences, last.members), (0, 0), "{last:#?}");
    assert!(
        p.steps
            .iter()
            .all(|s| s.closed.is_empty() && s.opened.is_empty())
    );
}

#[test]
fn bytes_that_will_not_parse_give_an_omitted_progression_that_says_why() {
    // A failure here never fails the comparison it rides along with.
    let p = progression::compute(
        b"not a zip".to_vec(),
        b"not a zip either".to_vec(),
        Format::Zip,
        &profile("zip").unwrap(),
        &Limits::default(),
        &BTreeSet::new(),
    );
    assert!(p.steps.is_empty(), "{p:#?}");
    assert!(
        !p.consistent,
        "an explanation that was never computed is not a trustworthy one"
    );
    let why = p.omitted.expect("the reason is recorded");
    assert!(
        why.starts_with("the set could not be re-applied pass by pass: "),
        "{why}"
    );
}

#[test]
fn artifacts_over_the_bound_are_compared_but_not_re_applied_pass_by_pass() {
    // One byte over `MAX_BYTES` between the two. The verdict is still taken; only the explanation
    // is skipped, and the skip names the bound rather than leaving a reader to wonder.
    let half = progression::MAX_BYTES / 2;
    let upstream = vec![0u8; half];
    let rebuild = vec![0u8; half + 1];
    let c = compare_bytes(
        upstream,
        rebuild,
        Format::Raw,
        &profile("raw").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let p = progression_of(&c);
    assert!(p.steps.is_empty(), "{p:#?}");
    assert!(!p.consistent);
    let why = p.omitted.as_deref().expect("the reason is recorded");
    assert!(
        why.contains(&format!("{} MiB bound", progression::MAX_BYTES >> 20)),
        "{why}"
    );
}

#[test]
fn the_bound_is_on_what_the_two_artifacts_total_so_two_small_ones_are_explained() {
    // 12,000 bytes a side: 24 KB between them, a sliver of the bound. Any other combination of the
    // two sizes — their product is 144 MB — would put this pair over it and leave it unexplained.
    let c = compare_bytes(
        vec![1u8; 12_000],
        vec![2u8; 12_000],
        Format::Raw,
        &profile("raw").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let p = progression_of(&c);
    assert!(p.omitted.is_none(), "{:?}", p.omitted);
    assert!(!p.steps.is_empty(), "{p:#?}");
    assert!(p.consistent, "{p:#?}");
}
