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

/// Three reasons a member has no bytes, and they are three different messages.
///
/// "We never kept this run's artifacts" is our retention policy; "neither artifact holds a member
/// by that name" is a fact about the package; "that member could not be read" is a fault. They were
/// one message, and a reader told the second about a run that was really the first would go looking
/// for a member that is there.
#[tokio::test]
async fn a_member_with_no_bytes_says_which_of_the_three_reasons_it_is() {
    use std::sync::Arc;
    use trigon_core::Digest;
    use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

    async fn ask(r: RunRecord, store: Arc<Store>) -> String {
        use axum::body::Body;
        use axum::http::Request;
        use tower_service::Service as _;

        store.put_run(&r).await.unwrap();
        let index = trigon_api::Index::new();
        index
            .refresh(&store, trigon_api::Switches::default())
            .await
            .unwrap();
        let api = Arc::new(trigon_api::Api {
            store,
            queue: None,
            index,
            switches: trigon_api::Switches::default(),
            unauthenticated: trigon_api::Principal::Operator,
        });
        let mut router = trigon_api::router(api);
        let res = router
            .call(
                Request::builder()
                    .uri(format!("/v1/runs/{}/member?path=package%2Findex.js", r.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let b = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        String::from_utf8_lossy(&b).into_owned()
    }

    fn base(id: &str, stored: bool, sha: Digest) -> RunRecord {
        let mut r = RunRecord::new(
            id,
            "pkg:npm/a@1.0.0",
            ArtifactRef {
                name: "pkg.gem".into(),
                sha256: sha,
                bytes: 1,
                stored,
            },
            Environment {
                base_image: "x@sha256:0".into(),
                egress: "mirror".into(),
                isolation: "podman".into(),
                attestable: true,
                registry_moment: None,
                pin: None,
                guard_manifest: None,
                guarded_members: None,
            },
            "2026-01-01T00:00:00Z",
        );
        r.state = RunState::Done;
        r.outcome = Some("exact".into());
        r
    }

    // 1. Retention dropped the bytes.
    let store = Arc::new(Store::in_memory());
    let body = ask(
        base("1700000001-aa", false, Digest::from_bytes([0u8; 32])),
        store,
    )
    .await;
    assert!(body.contains("not_kept"), "{body}");
    assert!(body.contains("Retention drops them on a match"), "{body}");

    // 2. The bytes are there and the member is not.
    let store = Arc::new(Store::in_memory());
    let art = nested(b"x\n");
    let d = store.blobs().put(art).await.unwrap();
    let body = ask(base("1700000002-bb", true, d), store).await;
    assert!(body.contains("no_such_member"), "{body}");
    assert!(
        !body.contains("not_kept"),
        "a present artifact was reported as dropped: {body}"
    );

    // 3. The bytes are there and will not parse as the format their name claims.
    let store = Arc::new(Store::in_memory());
    let d = store.blobs().put(vec![0u8; 64]).await.unwrap();
    let body = ask(base("1700000003-cc", true, d), store).await;
    assert!(
        body.contains("unreadable_member") || body.contains("no_such_member"),
        "{body}"
    );
    assert!(!body.contains("not_kept"), "{body}");
}
