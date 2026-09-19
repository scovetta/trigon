//! The rendered comparison reads a real one.
//!
//! `trigon-api` does not depend on `trigon-compare` at runtime — a crate that cannot reach the
//! comparator cannot produce a `Match`, whatever the handlers do — so it deserializes a stored
//! comparison into its own structs. That is two descriptions of one shape, which is the defect this
//! tree keeps finding. This is the assertion that makes them agree.
//!
//! The dependency is a **dev**-dependency, which is why `the_comparator_is_not_even_a_dependency`
//! scopes itself to `[dependencies]`: a crate linked into tests cannot be reached by a handler.

use trigon_archive::Limits;
use trigon_compare::compare_bytes;
use trigon_core::Format;

/// Two zip archives that differ in one member and agree on another, plus one member present on a
/// single side — enough that every census field has a non-zero value to lose.
fn pair() -> (Vec<u8>, Vec<u8>) {
    fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, body) in entries {
                use std::io::Write as _;
                w.start_file(*name, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        out
    }
    (
        zip(&[
            ("same.txt", b"identical"),
            ("differs.txt", b"upstream side"),
            ("only-upstream.txt", b"here"),
        ]),
        zip(&[
            ("same.txt", b"identical"),
            ("differs.txt", b"rebuild side!"),
        ]),
    )
}

fn rendered() -> trigon_api::comparison::View {
    let (up, rb) = pair();
    let set = trigon_stabilize::default_for(Format::Zip);
    let c = compare_bytes(up, rb, Format::Zip, &set, &Limits::default()).expect("compare");
    let bytes = serde_json::to_vec(&c).expect("serialize");
    trigon_api::comparison::render(&bytes, None)
        .expect("the projection could not read a real comparison")
}

/// Every field the projection claims to read comes back populated.
///
/// The point is not the values but the *absence of silence*: a field renamed in `trigon-compare`
/// would deserialize as its default and the page would render a blank where a number belongs, with
/// nothing anywhere reporting that it had happened.
#[test]
fn the_projection_reads_a_real_comparison() {
    let v = rendered();

    assert_eq!(v.outcome, "divergent");
    assert_eq!(v.format, "zip");
    assert!(!v.set.id.is_empty(), "the profile id did not survive");
    assert_eq!(v.set.digest.len(), 64, "the set digest did not survive");

    // Three rungs, exactly one of which answered.
    assert_eq!(v.ladder.len(), 3);
    assert_eq!(
        v.ladder.iter().filter(|r| r.answered).count(),
        1,
        "a verdict is a walk that stops at one question"
    );
    assert!(v.ladder[0].upstream.as_ref().is_some_and(|d| d.len() == 64));
    assert!(v.ladder[1].rebuild.as_ref().is_some_and(|d| d.len() == 64));

    // The census, from the real diff.
    assert_eq!(v.census.total, 3, "the member count did not survive");
    assert_eq!(v.census.differs, 1);
    assert_eq!(v.census.identical, 1);
    assert_eq!(v.census.only_upstream, 1);
    assert_eq!(v.census.only_rebuild, 0);

    // The members, with their paths decoded and the finding sorted first.
    assert_eq!(v.members.len(), 3);
    assert_eq!(v.members[0].path, "differs.txt");
    assert_eq!(v.members[0].status, "differs");
    assert!(v.members[0].digests_differ);
    assert!(v.members.iter().any(|m| m.path == "same.txt"));
    assert_eq!(v.members_omitted, 0);

    // What the artifact holds, by kind.
    assert!(!v.kinds.is_empty(), "the kind breakdown did not survive");
    assert_eq!(v.kinds.values().sum::<usize>(), v.census.total);

    assert!(v.upstream_bytes > 0 && v.rebuild_bytes > 0);
}

/// The ledger carries risk and provenance, and the ceiling agrees with the comparator's.
///
/// Two independent computations of one rule — `trigon-compare::ceiling` over `Applied` values, and
/// the projection's over deserialized ones — reaching the same answer. They share an implementation
/// in `trigon-core` and this asserts that neither path has drifted around it.
#[test]
fn the_ceiling_here_is_the_ceiling_the_comparator_computes() {
    let (up, rb) = pair();
    let set = trigon_stabilize::default_for(Format::Zip);
    let c = compare_bytes(up, rb, Format::Zip, &set, &Limits::default()).expect("compare");
    let theirs = trigon_compare::ceiling(c.applied());

    let bytes = serde_json::to_vec(&c).expect("serialize");
    let v = trigon_api::comparison::render(&bytes, None).expect("render");

    assert_eq!(
        v.ceiling,
        theirs.to_string(),
        "the page and the comparator disagree about what this run could have reached"
    );
    for p in &v.applied {
        assert!(!p.risk.is_empty(), "{} lost its risk tier", p.id);
        assert!(!p.who.is_empty(), "{} lost its provenance", p.id);
    }
    // Every capping row is named in `caps`, and nothing else is.
    let marked: Vec<&str> = v
        .applied
        .iter()
        .filter(|p| p.caps)
        .map(|p| p.id.as_str())
        .collect();
    let named: Vec<&str> = v.caps.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(marked, named);
    for c in &v.caps {
        assert!(
            c.why.contains("metadata") || c.why.contains("reviewed") || c.why.contains("proposed"),
            "`{}` caps and does not say which half fired: {}",
            c.id,
            c.why
        );
    }
}

/// Silence is reported as unknown, not as none.
///
/// The set's membership is not in the record, so nothing downstream can tell a pass that found
/// nothing from one that was never configured. An empty list would claim we had looked.
#[test]
fn a_pass_that_stayed_silent_is_unknown_rather_than_absent() {
    assert!(
        rendered().silent.is_none(),
        "the view claimed to know which passes stayed silent; the record does not carry the set's \
         membership, so nothing here can know that"
    );
}

/// Bytes that are not a comparison are refused rather than rendered as an empty one.
#[test]
fn a_blob_that_is_not_a_comparison_renders_nothing() {
    assert!(trigon_api::comparison::render(b"{}", None).is_none());
    assert!(trigon_api::comparison::render(b"not json at all", None).is_none());
    // And a *partial* one: a blob missing the diff is not a comparison with an empty diff.
    assert!(
        trigon_api::comparison::render(br#"{"outcome":"exact"}"#, None).is_none(),
        "a truncated comparison rendered as a clean result"
    );
}

/// An exact match does not describe differences it never had.
///
/// The ladder's second rung used to read "every way in which they differ was removed by a pass" on
/// a run where the bytes were identical before any pass ran — a caveat on a result that has none.
/// Found by rendering a clean run beside a divergent one, which is the only way this kind of
/// wording bug ever surfaces.
#[test]
fn a_clean_match_is_not_described_as_a_normalized_one() {
    let same = {
        let (up, _) = pair();
        up
    };
    let set = trigon_stabilize::default_for(Format::Zip);
    let c =
        compare_bytes(same.clone(), same, Format::Zip, &set, &Limits::default()).expect("compare");
    assert_eq!(c.outcome.to_string(), "exact");

    let bytes = serde_json::to_vec(&c).expect("serialize");
    let v = trigon_api::comparison::render(&bytes, None).expect("render");

    assert!(
        v.ladder[0].answered,
        "an exact match answers at the first rung"
    );
    assert!(
        !v.ladder[1].detail.contains("differ"),
        "rung 2 describes differences an exact match never had: {}",
        v.ladder[1].detail
    );
    assert!(
        v.ladder[2].detail.starts_with("None."),
        "rung 3 counts differences an exact match never had: {}",
        v.ladder[2].detail
    );
    assert_eq!(v.census.differs, 0);
}
