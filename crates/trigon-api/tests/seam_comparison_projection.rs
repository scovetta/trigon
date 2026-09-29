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

    // The pass-by-pass progression, recorded by `compare_bytes` and read back here. One step for
    // the artifacts as published and one per pass in the set, each pass named.
    let p = v
        .progression
        .as_ref()
        .expect("the progression did not survive");
    assert!(p.omitted.is_none(), "{:?}", p.omitted);
    assert!(
        p.consistent,
        "the last step must reproduce the verdict's signature"
    );
    let set = trigon_stabilize::default_for(Format::Zip);
    assert_eq!(p.steps.len(), set.members.len() + 1);
    assert!(p.steps[0].pass.is_none());
    assert!(p.steps[1..].iter().all(|s| s.pass.is_some()));
    assert!(p.steps[0].members >= p.steps.last().unwrap().members);
    // A step's `fired` is joined from the ledger: every pass the ledger shows is marked as fired.
    for s in &p.steps[1..] {
        let in_ledger = v.applied.iter().any(|a| Some(&a.id) == s.pass.as_ref());
        assert_eq!(s.fired, in_ledger, "{:?}", s.pass);
    }
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

/// A member a stabilizer renamed is still reachable in the artifact it came from.
///
/// The comparison names members from the **stabilized** archives — it has to, because that is what
/// makes `lib/portable-net45%2Bwin8%2Bwp8%2Bwpa81/x.dll` on the published side and
/// `lib/portable45-net45+win8+wp8+wpa81/x.dll` on the rebuilt side the same file. `member::read`
/// walks the **raw** artifact, where neither of those names exists any more.
///
/// Observed on a real NuGet divergence before this was fixed — Newtonsoft.Json 11.0.1, published
/// against a `dotnet pack` of its own source. The diff listed 23 members and 5 of them answered:
///
/// ```text
/// {"detail":"neither artifact holds a member by that name.","error":"no_such_member"}
/// ```
///
/// Four from `nupkg-portable-folder-name` and one from `nupkg-packaging-names`, the only two passes
/// in the tree that rename. The refusal blamed the artifacts for a name this project had invented.
///
/// The comparison now records, per side, the name that side's artifact carries, and the API asks
/// for it on a miss. This test drives the real comparator rather than a hand-built report, because
/// the property is that the two halves agree and a fixture proves only that the fixture does.
#[test]
fn a_renamed_member_resolves_in_the_artifact_it_came_from() {
    fn nupkg(portable: &str) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, body) in [
                (format!("lib/{portable}/x.dll"), &b"MZ\x90\x00payload"[..]),
                ("x.nuspec".into(), b"<package/>"),
            ] {
                use std::io::Write as _;
                w.start_file(name, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        out
    }

    // The two spellings a real pair carries, straight from `nupkg_portable_tests`.
    let up = nupkg("portable-net45%2Bwin8%2Bwp8%2Bwpa81");
    let rb = nupkg("portable45-net45+win8+wp8+wpa81");

    let set = trigon_stabilize::profile("nupkg").expect("the nupkg profile");
    let c = compare_bytes(
        up.clone(),
        rb.clone(),
        Format::Zip,
        &set,
        &Limits::default(),
    )
    .expect("compare");

    let diff = c.diff.as_ref().expect("a diff report");
    let member = diff
        .files
        .iter()
        .find(|f| f.path.to_lossy().contains("x.dll"))
        .expect("the renamed member is in the report");

    let canonical = member.path.to_lossy().into_owned();
    assert_eq!(
        canonical, "lib/portable-net45+win8+wp8+wpa81/x.dll",
        "the comparison must name it canonically; that is what makes the two sides one file"
    );

    // Neither artifact has a member under that name. This is the whole defect in one assertion.
    assert!(
        trigon_api::member::read(up.clone(), "x.nupkg", &canonical).is_err(),
        "if the published artifact did hold this name, there was never anything to fix"
    );

    // So the comparison has to have recorded what each side does call it.
    let u_raw = member
        .upstream_raw_path
        .as_ref()
        .expect("upstream's own name for a renamed member")
        .to_lossy()
        .into_owned();
    let r_raw = member
        .rebuild_raw_path
        .as_ref()
        .expect("the rebuild's own name")
        .to_lossy()
        .into_owned();
    assert_eq!(u_raw, "lib/portable-net45%2Bwin8%2Bwp8%2Bwpa81/x.dll");
    assert_eq!(r_raw, "lib/portable45-net45+win8+wp8+wpa81/x.dll");

    // And each side's bytes are reachable under that side's name.
    assert_eq!(
        trigon_api::member::read(up, "x.nupkg", &u_raw).expect("upstream member"),
        b"MZ\x90\x00payload"
    );
    assert_eq!(
        trigon_api::member::read(rb, "x.nupkg", &r_raw).expect("rebuild member"),
        b"MZ\x90\x00payload"
    );

    // The other half of the seam: the API reads the comparison back out of a stored blob with its
    // own mirror of the format, so recording the name is only useful if that mirror carries it.
    let blob = serde_json::to_vec(&c).expect("serialize");
    assert_eq!(
        trigon_api::comparison::raw_name(&blob, &canonical, "upstream").as_deref(),
        Some(u_raw.as_str()),
        "the API's projection dropped the field the comparator wrote"
    );
    assert_eq!(
        trigon_api::comparison::raw_name(&blob, &canonical, "rebuild").as_deref(),
        Some(r_raw.as_str())
    );

    // A comparison written before the field existed must read back as "no second name" rather than
    // as a parse failure, or every stored blob in the corpus becomes unrenderable.
    let mut v: serde_json::Value = serde_json::from_slice(&blob).expect("json");
    for f in v["diff"]["files"].as_array_mut().expect("files") {
        f.as_object_mut().unwrap().remove("upstream_raw_path");
        f.as_object_mut().unwrap().remove("rebuild_raw_path");
    }
    let old = serde_json::to_vec(&v).expect("serialize");
    assert!(
        trigon_api::comparison::raw_name(&old, &canonical, "upstream").is_none(),
        "an old comparison has no second name and must say so quietly"
    );
    assert!(
        trigon_api::comparison::render(&old, None).is_some(),
        "and must still render"
    );
}

/// A member nothing renamed records no raw name, so an old comparison reads back unchanged.
#[test]
fn an_unrenamed_member_carries_no_second_name() {
    let (up, rb) = pair();
    let set = trigon_stabilize::profile("zip").expect("profile");
    let c = compare_bytes(up, rb, Format::Zip, &set, &Limits::default()).expect("compare");
    for f in &c.diff.as_ref().expect("diff").files {
        assert!(
            f.upstream_raw_path.is_none() && f.rebuild_raw_path.is_none(),
            "`{}` recorded a raw name although no pass renames in the `zip` profile; that is \
             bytes in every stored comparison for nothing",
            f.path.to_lossy()
        );
    }
}
