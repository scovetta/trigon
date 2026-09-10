//! What `compare` decides, and why.
//!
//! The provenance cap is the invariant the whole design rests on, so it gets tested from both
//! sides: a builtin-only run reaches `Normalized`, and the same run with one model-authored pass
//! reaches `NormalizedWithCaveats` and no further.

use std::sync::Arc;

use trigon_archive::{Entry, Limits};
use trigon_compare::{CompareError, FileStatus, compare_bytes, summarize};
use trigon_core::{Format, Match, Provenance, RiskTier, StabilizerId};
use trigon_stabilize::{Cx, Stabilizer, StabilizerSet, Touched, profile};

/// A tar whose members are fixed but whose build-environment metadata varies.
fn tar(mtime: u64, uid: u64, body: &[u8]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, content) in [("pkg/a.txt", body), ("pkg/b.txt", b"constant")] {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(mtime);
        h.set_uid(uid);
        h.set_cksum();
        b.append_data(&mut h, name, content).unwrap();
    }
    b.into_inner().unwrap()
}

fn gz(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader::default(),
        payload,
        flate2::Compression::default(),
        &mut v,
    )
    .unwrap();
    v
}

#[test]
fn identical_bytes_are_exact() {
    let a = tar(1, 1, b"same");
    let c = compare_bytes(
        a.clone(),
        a,
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Exact);
    assert_eq!(c.upstream.raw.sha256, c.rebuild.raw.sha256);
    // Exact means no transform was needed, so nothing should have fired on either side.
    assert!(c.applied().is_empty() || c.upstream.stabilized == c.rebuild.stabilized);
}

#[test]
fn metadata_only_differences_are_normalized() {
    let c = compare_bytes(
        tar(1_700_000_000, 1000, b"same"),
        tar(1_500_000_000, 501, b"same"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Normalized);
    assert_ne!(c.upstream.raw.sha256, c.rebuild.raw.sha256);
    assert_eq!(c.upstream.stabilized.sha256, c.rebuild.stabilized.sha256);
    assert!(
        c.cap_reason().is_none(),
        "a builtin-only run should not be capped"
    );
}

#[test]
fn content_differences_are_divergent() {
    let c = compare_bytes(
        tar(1, 1, b"upstream"),
        tar(1, 1, b"rebuilt!"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let d = c.diff.as_ref().unwrap();
    assert_eq!(d.differs, 1);
    assert_eq!(d.identical, 1);
    let f = d
        .files
        .iter()
        .find(|f| f.status == FileStatus::Differs)
        .unwrap();
    assert_eq!(f.path.to_lossy(), "pkg/a.txt");
    assert_ne!(f.upstream_digest, f.rebuild_digest);
}

// --- the provenance cap ---------------------------------------------------------------------------

/// A pass that does exactly what `tar-owners` does, but claims a model wrote it.
///
/// Its only purpose is to prove the cap fires on provenance rather than on behaviour.
#[derive(Debug)]
struct ModelAuthored;

impl Stabilizer for ModelAuthored {
    fn id(&self) -> StabilizerId {
        StabilizerId::new("test-model-authored")
    }
    fn risk(&self) -> RiskTier {
        RiskTier::Metadata
    }
    fn provenance(&self) -> Provenance {
        Provenance::Model {
            model_id: "claude-opus-5".into(),
            run_id: "01J".into(),
        }
    }
    fn applies(&self, _cx: &Cx) -> bool {
        true
    }
    fn on_entry(&self, e: &mut Entry, _cx: &Cx) -> Touched {
        if let trigon_archive::RawMeta::Tar(raw) = &mut e.raw {
            if raw.uid != 0 {
                raw.uid = 0;
                e.mark_dirty();
                return Touched::entry();
            }
        }
        Touched::NONE
    }
}

/// A pass that rewrites bytes inside a distributed file. Builtin, and above `Metadata` risk.
#[derive(Debug)]
struct ContentRewrite;

impl Stabilizer for ContentRewrite {
    fn id(&self) -> StabilizerId {
        StabilizerId::new("test-content-rewrite")
    }
    fn risk(&self) -> RiskTier {
        RiskTier::Content
    }
    fn applies(&self, _cx: &Cx) -> bool {
        true
    }
    fn on_entry(&self, e: &mut Entry, _cx: &Cx) -> Touched {
        if e.path.ends_with(b"a.txt") {
            if let Ok(b) = e.body_mut() {
                b.iter_mut().for_each(|x| *x = b'X');
                return Touched::entry_bytes(b.len() as u64);
            }
        }
        Touched::NONE
    }
}

fn set_with(extra: Arc<dyn Stabilizer>) -> StabilizerSet {
    let mut members = profile("tar").unwrap().members;
    members.push(extra);
    StabilizerSet::new("tar+test", members)
}

/// A set where a model-authored pass stands in for a builtin one rather than duplicating it.
///
/// Duplicating is the realistic mistake and it hides the cap: `tar-owners` sorts first, does the
/// work, and the model pass then finds nothing to do and correctly does not cap anything.
fn set_replacing_owners(extra: Arc<dyn Stabilizer>) -> StabilizerSet {
    let base = profile("tar")
        .unwrap()
        .filtered(&["all".into()], &["tar-owners".into()]);
    let mut members = base.members;
    members.push(extra);
    StabilizerSet::new("tar-minus-owners+test", members)
}

#[test]
fn a_model_authored_pass_caps_the_outcome() {
    let set = set_replacing_owners(Arc::new(ModelAuthored));
    assert!(
        !set.members.iter().any(|m| m.id().as_str() == "tar-owners"),
        "filtered() should have removed the builtin this pass stands in for"
    );
    let c = compare_bytes(
        tar(1_700_000_000, 1000, b"same"),
        tar(1_500_000_000, 501, b"same"),
        Format::Tar,
        &set,
        &Limits::default(),
    )
    .unwrap();

    // The digests still agree. The cap is about who wrote the transform, not whether it worked.
    assert_eq!(c.upstream.stabilized.sha256, c.rebuild.stabilized.sha256);
    assert_eq!(c.outcome, Match::NormalizedWithCaveats);
    assert!(c.cap_reason().unwrap().contains("test-model-authored"));
    assert!(!c.outcome.is_at_least(Match::Normalized));
}

#[test]
fn a_content_risk_pass_caps_the_outcome_too() {
    // Provenance is not the only cap: risk above Metadata does it as well, and for the same reason.
    let set = set_with(Arc::new(ContentRewrite));
    let c = compare_bytes(
        tar(1_700_000_000, 1000, b"aaaaaaaa"),
        tar(1_500_000_000, 501, b"bbbbbbbb"),
        Format::Tar,
        &set,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.upstream.stabilized.sha256, c.rebuild.stabilized.sha256);
    assert_eq!(c.outcome, Match::NormalizedWithCaveats);
    assert!(c.cap_reason().unwrap().contains("Content"));
}

#[test]
fn a_capped_pass_that_does_nothing_does_not_cap() {
    // `applied` reports only passes that changed something, so a model-authored pass that found
    // nothing to do leaves the clean tier reachable. A pass that was merely configured has no
    // business in the predicate.
    let set = set_with(Arc::new(ModelAuthored));
    let already_zero_uid = tar(1_700_000_000, 0, b"same");
    let other = tar(1_500_000_000, 0, b"same");
    let c = compare_bytes(
        already_zero_uid,
        other,
        Format::Tar,
        &set,
        &Limits::default(),
    )
    .unwrap();
    assert!(
        !c.applied()
            .iter()
            .any(|a| a.id.as_str() == "test-model-authored"),
        "a pass that changed nothing must not appear in applied"
    );
    assert_eq!(c.outcome, Match::Normalized);
}

// --- containers, sets, and reports ---------------------------------------------------------------

#[test]
fn container_digest_separates_framing_from_content() {
    let inner = tar(1, 1, b"same");
    // Same tar, two different gzip framings.
    let a = gz(&inner);
    let mut b = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader {
            os: 3,
            mtime: Some(99),
            ..Default::default()
        },
        &inner,
        flate2::Compression::none(),
        &mut b,
    )
    .unwrap();

    let c = compare_bytes(
        a,
        b,
        Format::TarGz,
        &profile("tar-gzip").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_ne!(
        c.upstream.raw.sha256, c.rebuild.raw.sha256,
        "the framings differ"
    );
    assert_eq!(
        c.container_bit_identical(),
        Some(true),
        "the tars are identical"
    );
    assert_eq!(c.outcome, Match::Normalized);
}

#[test]
fn an_uncompressed_container_reports_no_container_digest() {
    let c = compare_bytes(
        tar(1, 1, b"x"),
        tar(1, 1, b"x"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert!(c.upstream.container.is_none());
    assert_eq!(c.container_bit_identical(), None);
}

#[test]
fn comparing_across_stabilizer_sets_is_refused() {
    // The two sides must have been stabilized the same way, or the comparison means nothing.
    let (a, _) = summarize(
        tar(1, 1, b"x"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let (b, _) = summarize(
        tar(1, 1, b"x"),
        Format::Tar,
        &set_with(Arc::new(ModelAuthored)),
        &Limits::default(),
    )
    .unwrap();

    match trigon_compare::compare(a, b, None, None) {
        Err(CompareError::SetMismatch(x, y)) => {
            assert_ne!(x, y);
        }
        other => panic!("expected a set mismatch, got {other:?}"),
    }
}

#[test]
fn raw_sha512_rides_along_but_derived_digests_do_not() {
    // SHA-512 is for cross-checking against a registry, which publishes it for the artifact and for
    // nothing else. Doubling the derived digests would double the hashing cost for no reader.
    let (s, _) = summarize(
        gz(&tar(1, 1, b"x")),
        Format::TarGz,
        &profile("tar-gzip").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert!(s.raw.sha512.is_some());
    assert!(s.stabilized.sha512.is_none());
    assert!(s.container.unwrap().sha512.is_none());
}

#[test]
fn the_diff_report_names_members_only_on_one_side() {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(4);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, "pkg/a.txt", &b"same"[..]).unwrap();
    let only_one = b.into_inner().unwrap();

    let c = compare_bytes(
        tar(1, 1, b"same"),
        only_one,
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let d = c.diff.as_ref().unwrap();
    assert_eq!(d.only_upstream, 1);
    assert_eq!(d.only_rebuild, 0);
    let f = d
        .files
        .iter()
        .find(|f| f.status == FileStatus::OnlyUpstream)
        .unwrap();
    assert_eq!(f.path.to_lossy(), "pkg/b.txt");
    assert!(f.rebuild_digest.is_none());
}

#[test]
fn executable_differences_are_counted_apart() {
    let build = |body: &[u8]| {
        let mut b = ::tar::Builder::new(Vec::new());
        for (name, content) in [("pkg/lib.so", body), ("pkg/README.md", b"docs" as &[u8])] {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(content.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append_data(&mut h, name, content).unwrap();
        }
        b.into_inner().unwrap()
    };
    let c = compare_bytes(
        build(b"\x7fELF-one"),
        build(b"\x7fELF-two"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let d = c.diff.as_ref().unwrap();
    assert_eq!(d.differs, 1);
    assert_eq!(
        d.executable_differs, 1,
        "a difference in an executable is never benign"
    );
}

#[test]
fn nested_members_are_named_through_the_container() {
    // A difference inside a gem should name the file, not the container.
    let build = |inner_body: &[u8]| {
        let mut inner = ::tar::Builder::new(Vec::new());
        let mut h = ::tar::Header::new_ustar();
        h.set_size(inner_body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        inner
            .append_data(&mut h, "lib/rails.rb", inner_body)
            .unwrap();
        let data_gz = gz(&inner.into_inner().unwrap());

        let mut outer = ::tar::Builder::new(Vec::new());
        let mut oh = ::tar::Header::new_ustar();
        oh.set_size(data_gz.len() as u64);
        oh.set_mode(0o644);
        oh.set_cksum();
        outer
            .append_data(&mut oh, "data.tar.gz", &data_gz[..])
            .unwrap();
        outer.into_inner().unwrap()
    };

    let c = compare_bytes(
        build(b"module Rails1"),
        build(b"module Rails2"),
        Format::Tar,
        &profile("gem").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let d = c.diff.as_ref().unwrap();
    let named: Vec<String> = d
        .files
        .iter()
        .map(|f| f.path.to_lossy().into_owned())
        .collect();
    assert!(
        named.iter().any(|n| n == "data.tar.gz!lib/rails.rb"),
        "expected the inner file to be named, got {named:?}"
    );
}

#[test]
fn duplicate_paths_compare_positionally() {
    // Keying on path alone would make a duplicate unmatchable. Upstream's second a.txt compares
    // against the rebuild's second a.txt.
    let build = |first: &[u8], second: &[u8]| {
        let mut b = ::tar::Builder::new(Vec::new());
        for content in [first, second] {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "dup.txt", content).unwrap();
        }
        b.into_inner().unwrap()
    };
    let same = compare_bytes(
        build(b"one", b"two"),
        build(b"one", b"two"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(same.diff.as_ref().unwrap().differs, 0);

    let swapped = compare_bytes(
        build(b"one", b"two"),
        build(b"two", b"one"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        swapped.diff.as_ref().unwrap().differs,
        2,
        "both occurrences moved"
    );
}
