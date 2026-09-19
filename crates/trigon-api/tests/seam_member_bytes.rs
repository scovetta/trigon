//! Reaching one member of a stored artifact, by the name the comparison gave it.
//!
//! The load-bearing assertion here is `a_nested_member_resolves_by_the_name_the_comparison_gave_it`.
//! `trigon-api` does not link the comparator, so it walks archives itself to find a member — and
//! the comparison's member *names* come from the comparator's walk. Two traversals of one tree,
//! written in two crates, that have to produce the same names or a page's links resolve to nothing.
//! That is the defect this tree keeps finding, so it is asserted against a real nested archive
//! rather than against a reading of the other function.

use trigon_archive::Limits;
use trigon_compare::compare_bytes;
use trigon_core::Format;

fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut b = tar::Builder::new(&mut out);
        for (name, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, *body).unwrap();
        }
        b.finish().unwrap();
    }
    out
}

fn gz(b: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut out = Vec::new();
    let mut e = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap();
    out
}

/// A `.gem`: a bare tar whose members are themselves gzipped tars.
///
/// **A `.tgz` is not this.** Gzip is that format's *container*, so its members are named plainly and
/// the `!` form never appears — which the first version of this fixture got wrong and which the
/// vacuity check below caught. Real nesting needs an archive inside an archive, and a gem is the
/// shape the ecosystems actually ship.
fn nested(inner_body: &[u8]) -> Vec<u8> {
    let inner = gz(&tar_of(&[("package/index.js", inner_body)]));
    tar_of(&[("data.tar.gz", &inner), ("metadata.gz", &gz(b"name: x\n"))])
}

/// A member named by the comparison is a member this crate can fetch.
#[test]
fn a_nested_member_resolves_by_the_name_the_comparison_gave_it() {
    let up = nested(b"module.exports = 1;\n");
    let rb = nested(b"module.exports = 2;\n");

    let set = trigon_stabilize::default_for(Format::Tar);
    let c = compare_bytes(
        up.clone(),
        rb.clone(),
        Format::Tar,
        &set,
        &Limits::default(),
    )
    .expect("compare");

    // Every path the comparison produced, in its own words.
    let named: Vec<String> = c
        .diff
        .as_ref()
        .expect("a comparison produces a diff report")
        .files
        .iter()
        .map(|f| String::from_utf8_lossy(f.path.as_bytes()).into_owned())
        .collect();
    assert!(
        !named.is_empty(),
        "the fixture produced no members to check"
    );

    for path in &named {
        let got = trigon_api::member::read(up.clone(), "pkg.gem", path);
        assert!(
            got.is_ok(),
            "the comparison named `{path}` and this crate cannot find it: {}\nall names: {named:?}",
            got.unwrap_err()
        );
    }

    // And specifically the nested form, so a fixture that stopped nesting would fail rather than
    // pass vacuously.
    assert!(
        named.iter().any(|p| p.contains('!')),
        "the fixture is not nested any more, so this test asserts nothing: {named:?}"
    );

    let body = trigon_api::member::read(up, "pkg.gem", &named[0]).unwrap();
    assert_eq!(body, b"module.exports = 1;\n");
}

/// The member list this crate builds carries the same names.
#[test]
fn every_member_this_crate_lists_can_be_fetched_by_the_name_it_listed() {
    let art = nested(b"x\n");
    let names = trigon_api::member::names(art.clone(), "pkg.gem").expect("names");
    assert!(!names.is_empty());
    for (path, size) in &names {
        let body = trigon_api::member::read(art.clone(), "pkg.gem", path)
            .unwrap_or_else(|e| panic!("listed `{path}` and could not read it: {e}"));
        assert_eq!(
            body.len() as u64,
            *size,
            "`{path}` listed a size it does not have"
        );
    }
}

/// A name that is in neither artifact is a refusal that says so, not an empty diff.
#[test]
fn a_member_that_is_not_there_says_so() {
    let art = nested(b"x\n");
    let e = trigon_api::member::read(art, "pkg.gem", "package/nope.js").unwrap_err();
    assert!(e.contains("holds no member"), "{e}");
}

/// An artifact whose name says nothing about its format is refused rather than guessed at.
#[test]
fn an_unparseable_artifact_is_refused_by_name() {
    let e = trigon_api::member::read(vec![1, 2, 3], "mystery", "a").unwrap_err();
    assert!(e.contains("names no format"), "{e}");
}

/// The name the comparison gives the member inside the inner tar.
const NESTED: &str = "data.tar.gz!package/index.js";

/// The two copies of a real member produce a diff that names the change.
#[test]
fn the_diff_of_a_text_member_names_what_changed() {
    let up = trigon_api::member::read(nested(b"a\nb\nc\n"), "pkg.gem", NESTED);
    let rb = trigon_api::member::read(nested(b"a\nB\nc\n"), "pkg.gem", NESTED);
    let (up, rb) = (up.expect("upstream"), rb.expect("rebuild"));

    let v = trigon_api::member::view("package/index.js", Some(up), Some(rb), None);
    assert!(!v.binary);
    let t = v.text.expect("a text member has a line diff");
    assert_eq!(t.hunks.len(), 1);
    let lines: Vec<(&str, &str)> = t.hunks[0]
        .lines
        .iter()
        .map(|l| (l.kind, l.text.as_str()))
        .collect();
    assert!(lines.contains(&("removed", "b")), "{lines:?}");
    assert!(lines.contains(&("added", "B")), "{lines:?}");
    // Unchanged lines are context, not noise: a diff with no context is a diff nobody can place.
    assert!(lines.contains(&("same", "a")), "{lines:?}");
}
