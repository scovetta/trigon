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
            decompiler: None,
            member_reads: trigon_api::default_member_permits(),
            repository_switch: None,
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
                derived_image: None,
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

/// An artifact too large to parse is refused from the record, before a byte is read.
///
/// Measured before this existed: a request for a member of a 300 MiB-per-side artifact reached
/// **608 MiB of resident memory** and then answered 404 saying the artifact was too large to read.
/// The cap lived inside `member::read`, which runs after the whole thing has been fetched and
/// copied. The record already knows the size.
///
/// The check inside `read` is still the guarantee — a record can carry a wrong `bytes`, and this
/// test's sibling below relies on that. This one turns the common case from half a gigabyte into
/// nothing.
#[tokio::test]
async fn an_artifact_too_large_is_refused_without_reading_it() {
    use std::sync::Arc;
    use trigon_core::Digest;
    use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

    // An empty store: the blob this record names does not exist. If the handler tried to fetch it
    // the refusal would name the *store*, so the message below is proof nothing was read.
    let store = Arc::new(Store::in_memory());
    let mut r = RunRecord::new(
        "1700000001-aa",
        "pkg:npm/a@1.0.0",
        ArtifactRef {
            name: "pkg.zip".into(),
            sha256: Digest::from_bytes([1u8; 32]),
            // Larger than MAX_ARTIFACT.
            bytes: 300 * 1024 * 1024,
            stored: true,
        },
        Environment {
            base_image: "x@sha256:0".into(),
            derived_image: None,
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
    r.outcome = Some("divergent".into());
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
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    });

    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;
    let mut router = trigon_api::router(api);
    let res = router
        .call(
            Request::builder()
                .uri("/v1/runs/1700000001-aa/member/raw?path=a&side=upstream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);

    assert!(body.contains("too_large"), "{body}");
    assert!(
        !body.contains("no_such_blob"),
        "the handler went to the store before checking the size it already knew: {body}"
    );
}

/// Only so many member reads run at once.
///
/// One costs twice the artifact — 409 MiB measured for a 200 MiB-per-side artifact, against a cap
/// that allows 256 MiB a side. Unbounded concurrency is therefore unbounded memory, and the way
/// that ends is the process being killed, which a reader reports as the server crashing.
#[tokio::test]
async fn member_reads_are_bounded() {
    let permits = trigon_api::default_member_permits();
    let total = permits.available_permits();
    assert!(
        (1..=8).contains(&total),
        "the bound is {total}, which is either no bound at all or too tight to serve anybody"
    );

    // Taking them all leaves the next caller waiting rather than proceeding.
    let held: Vec<_> = (0..total)
        .map(|_| permits.clone().try_acquire_owned().expect("a permit"))
        .collect();
    assert!(
        permits.clone().try_acquire_owned().is_err(),
        "a {total}-permit semaphore handed out {}",
        total + 1
    );
    drop(held);
    assert_eq!(
        permits.available_permits(),
        total,
        "permits were not returned"
    );
}

/// A cap on what is read in is not a cap on what is sent out.
///
/// `MAX_TEXT` bounds a member at 2 MiB. Two MiB of bare newlines against two MiB of `x\n` is
/// 3,145,728 changed lines — and before this bound existed, all of them were rendered: an 86 MB
/// JSON body that took three and a half seconds to serialize, four of which at once peaked at a
/// gigabyte. A browser handed 86 MB of JSON is a browser that looks like it lost the network.
///
/// Asserted on the shape rather than the exact number, so it survives a change to the limit: the
/// diff must be small, and it must say how much it left out.
#[test]
fn a_diff_too_large_to_render_says_how_much_it_left_out() {
    let up = vec![b'\n'; 2 << 20];
    let rb: Vec<u8> = std::iter::repeat_n(*b"x\n", (2 << 20) / 2)
        .flatten()
        .collect();
    let (up_lines, rb_lines) = (up.len(), rb.len() / 2);

    let v = trigon_api::member::view("wide.txt", Some(up), Some(rb), None);
    let t = v.text.as_ref().expect("newlines are text");

    let rendered: usize = t.hunks.iter().map(|h| h.lines.len()).sum();
    assert_eq!(rendered, t.lines_shown, "lines_shown must count the hunks");
    assert!(
        rendered < 10_000,
        "the diff rendered {rendered} lines; the point of the bound is that it does not"
    );

    // The bound is only honest if the number it withheld is stated, and stated as a count of what
    // the reader is missing rather than of what some loop skipped.
    assert_eq!(
        t.lines_shown + t.lines_omitted,
        up_lines + rb_lines,
        "shown plus omitted must account for every changed line: {} + {} against {up_lines} \
         removed and {rb_lines} added",
        t.lines_shown,
        t.lines_omitted
    );
    assert!(t.unaligned, "a middle this wide is past MAX_ALIGN");

    let body = serde_json::to_vec(&v).expect("serialize");
    assert!(
        body.len() < (4 << 20),
        "the body was {} MB; it is meant to be a page, not a download",
        body.len() >> 20
    );
}

/// The same bound on the one-sided case, where there is no alignment at all and every line of the
/// surviving copy is an addition. This path builds its hunk directly rather than through `hunks`,
/// so it needs its own assertion or it keeps the old unbounded behaviour.
#[test]
fn a_new_file_too_large_to_render_is_bounded_the_same_way() {
    let rb: Vec<u8> = std::iter::repeat_n(*b"x\n", (2 << 20) / 2)
        .flatten()
        .collect();
    let total = rb.len() / 2;

    let v = trigon_api::member::view("added.txt", None, Some(rb), None);
    let t = v.text.as_ref().expect("text");

    assert!(
        t.lines_shown < 10_000,
        "a one-sided view rendered {} lines",
        t.lines_shown
    );
    assert_eq!(
        t.lines_shown + t.lines_omitted,
        total,
        "shown plus omitted must account for the whole file"
    );
}

/// A small artifact that opens into a huge one is refused, and told the truth about why.
///
/// `MAX_ARTIFACT` bounds the *stored* blob at 256 MiB. Nothing bounded what it opened into except
/// `Limits::default().total_expanded_bytes`, 4 GiB — a budget sized for a rebuild, not for an HTTP
/// handler serving four of them at once. Measured against the real reader: a 19.5 MB tarball of
/// zeros expanding to 4095 MiB held 8213 MB resident and returned `Ok`. Sharing the container
/// buffer (see `trigon-archive/tests/seam_one_buffer.rs`) halved that; this is the other half.
#[test]
fn an_artifact_that_expands_past_the_serving_budget_is_refused() {
    use std::io::Read;

    // 1200 MiB of zeros, which compresses to about a megabyte. Nothing here is large on disk.
    struct Zeros {
        left: u64,
    }
    impl Read for Zeros {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let n = b.len().min(self.left as usize);
            b[..n].fill(0);
            self.left -= n as u64;
            Ok(n)
        }
    }

    let expand: u64 = 1200 << 20;
    let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut b = tar::Builder::new(enc);
    let mut h = tar::Header::new_ustar();
    h.set_path("big").unwrap();
    h.set_size(expand);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_cksum();
    b.append(&h, Zeros { left: expand }).unwrap();
    let mut h2 = tar::Header::new_ustar();
    h2.set_path("small").unwrap();
    h2.set_size(6);
    h2.set_mode(0o644);
    h2.set_mtime(0);
    h2.set_cksum();
    b.append(&h2, &b"hello\n"[..]).unwrap();
    let tgz = b.into_inner().unwrap().finish().unwrap();

    assert!(
        tgz.len() < (16 << 20),
        "the fixture is meant to be small on disk and large when opened; it is {} bytes",
        tgz.len()
    );

    let e = trigon_api::member::read(tgz, "pkg-1.0.0.tgz", "small")
        .expect_err("1200 MiB expanded is past the serving budget");

    assert!(
        e.contains("expands to"),
        "the refusal must name expansion as the reason: {e}"
    );
    assert!(
        !e.contains("would not parse"),
        "a limit is not a parse failure, and saying so sends the reader to look at a package that \
         is perfectly fine: {e}"
    );
    assert!(
        e.contains("still downloadable"),
        "refusing to open it does not stop us handing over the bytes: {e}"
    );
}

/// The same budget applies to listing, which had no cap on the stored blob at all.
#[test]
fn listing_an_oversized_artifact_is_refused_too() {
    let e = trigon_api::member::names(vec![0u8; (256 << 20) + 1], "pkg.tgz")
        .expect_err("over MAX_ARTIFACT");
    assert!(e.contains("will not parse anything over"), "{e}");
}

/// A managed assembly's member view is the decompiled C#, where a decompiler was supplied.
///
/// The decompiler is injected — ILSpy runs in a container, which is the binary's world, so the
/// serving crate is handed a hook and never mentions it. This drives the seam with a *stub* hook
/// (no podman): the route must call it for a `.dll`, put the C# diff in the text view, and mark it
/// `decompiled`; and with no hook the same member stays a binary/hex view, so the C# is an
/// addition and never a silent replacement of the bytes.
#[tokio::test]
async fn a_dll_member_is_served_as_decompiled_csharp_from_the_hook_or_the_precomputed_cache() {
    use std::sync::Arc;
    use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

    fn tar_with_dll(byte: u8) -> Vec<u8> {
        tar_of(&[("lib/net6.0/A.dll", &[0u8, 1, 2, byte][..])])
    }

    async fn view(
        store: Arc<Store>,
        id: &str,
        decompiler: Option<trigon_api::Decompiler>,
    ) -> serde_json::Value {
        use axum::body::Body;
        use axum::http::Request;
        use tower_service::Service as _;
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
            decompiler,
            member_reads: trigon_api::default_member_permits(),
            repository_switch: None,
        });
        let mut router = trigon_api::router(api);
        let res = router
            .call(
                Request::builder()
                    .uri(format!("/v1/runs/{id}/member?path=lib%2Fnet6.0%2FA.dll"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let b = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    let store = Arc::new(Store::in_memory());
    let up = tar_with_dll(10);
    let rb = tar_with_dll(20);
    let up_d = store.blobs().put(up).await.unwrap();
    let rb_d = store.blobs().put(rb).await.unwrap();
    let env = Environment {
        base_image: "x@sha256:0".into(),
        derived_image: None,
        egress: "mirror".into(),
        isolation: "podman".into(),
        attestable: true,
        registry_moment: None,
        pin: None,
        guard_manifest: None,
        guarded_members: None,
    };
    let mut r = RunRecord::new(
        "1700000009-dd",
        "pkg:nuget/a@1.0.0",
        ArtifactRef {
            name: "a.tar".into(),
            sha256: up_d,
            bytes: 4,
            stored: true,
        },
        env,
        "2026-01-01T00:00:00Z",
    );
    r.rebuild = Some(ArtifactRef {
        name: "a.tar".into(),
        sha256: rb_d,
        bytes: 4,
        stored: true,
    });
    r.state = RunState::Done;
    r.outcome = Some("divergent".into());
    store.put_run(&r).await.unwrap();

    // A stub decompiler: distinct C# per side, keyed on the first differing byte, so the diff is
    // real. Only for `.dll`, so the predicate lives with the (stub) decompiler exactly as it does
    // with the real one.
    let dec: trigon_api::Decompiler = Arc::new(|name: &str, a: &[u8], b: &[u8]| {
        name.ends_with(".dll").then(|| {
            (
                format!("class A {{ int v = {}; }}\n", a[3]),
                format!("class A {{ int v = {}; }}\n", b[3]),
            )
        })
    });

    // With the hook: the text view is the C# diff, and it is marked decompiled.
    let with = view(store.clone(), "1700000009-dd", Some(dec)).await;
    assert_eq!(with["decompiled"], serde_json::json!(true), "{with}");
    assert_eq!(
        with["binary"],
        serde_json::json!(true),
        "the bytes are still binary: {with}"
    );
    let text = with["text"].to_string();
    assert!(
        text.contains("int v = 10") && text.contains("int v = 20"),
        "the C# diff: {text}"
    );

    // The pre-computed path: with the C# already in the store keyed by each side's assembly
    // digest, the view is decompiled **without any hook at all** — the read-replica case, no
    // podman. The member bytes inside the tar are `[0, 1, 2, byte]`.
    let store2 = Arc::new(Store::in_memory());
    let up2 = tar_with_dll(10);
    let rb2 = tar_with_dll(20);
    let up2_d = store2.blobs().put(up2).await.unwrap();
    let rb2_d = store2.blobs().put(rb2).await.unwrap();
    store2
        .put_decompiled(
            &trigon_store::digest_of(&[0, 1, 2, 10]),
            "class A { int v = 10; }\n",
        )
        .await
        .unwrap();
    store2
        .put_decompiled(
            &trigon_store::digest_of(&[0, 1, 2, 20]),
            "class A { int v = 20; }\n",
        )
        .await
        .unwrap();
    let mut r2 = RunRecord::new(
        "1700000010-ee",
        "pkg:nuget/a@1.0.0",
        ArtifactRef {
            name: "a.tar".into(),
            sha256: up2_d,
            bytes: 4,
            stored: true,
        },
        Environment {
            base_image: "x@sha256:0".into(),
            derived_image: None,
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
    r2.rebuild = Some(ArtifactRef {
        name: "a.tar".into(),
        sha256: rb2_d,
        bytes: 4,
        stored: true,
    });
    r2.state = RunState::Done;
    r2.outcome = Some("divergent".into());
    store2.put_run(&r2).await.unwrap();
    let precomputed = view(store2, "1700000010-ee", None).await;
    assert_eq!(
        precomputed["decompiled"],
        serde_json::json!(true),
        "{precomputed}"
    );
    let text = precomputed["text"].to_string();
    assert!(
        text.contains("int v = 10") && text.contains("int v = 20"),
        "cached C#: {text}"
    );

    // Without the hook and without a cache: the same member is a binary/hex view, no phantom text.
    let without = view(store, "1700000009-dd", None).await;
    assert_eq!(without["decompiled"], serde_json::json!(false), "{without}");
    assert_eq!(
        without["text"],
        serde_json::Value::Null,
        "no text view without a decompiler: {without}"
    );
}

/// Bytes a run's record says are kept and the store no longer has — deleted from outside, or
/// pruned for another run that shared the blob before pruning counted who else named it — are
/// reported as missing on every route that reads by the record's word, never as there and never
/// as dropped by retention.
#[tokio::test]
async fn bytes_the_record_says_are_kept_and_the_store_lost_are_reported_missing() {
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower_service::Service as _;
    use trigon_core::Digest;
    use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

    let store = Arc::new(Store::in_memory());
    // Never stored under these digests: the record's `stored: true` is all there is.
    let gone = Digest::from_bytes([7u8; 32]);
    let mut r = RunRecord::new(
        "1700000009-ee",
        "pkg:npm/a@1.0.0",
        ArtifactRef {
            name: "a-1.0.0.tgz".into(),
            sha256: gone,
            bytes: 10,
            stored: true,
        },
        Environment {
            base_image: "x@sha256:0".into(),
            derived_image: None,
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
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    });
    let mut router = trigon_api::router(api);
    let mut get = async |uri: String| {
        let res = router
            .call(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let b = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        String::from_utf8_lossy(&b).into_owned()
    };

    let raw = get(format!(
        "/v1/runs/{}/member/raw?path=package%2Findex.js",
        r.id
    ))
    .await;
    assert!(raw.contains("\"missing\""), "{raw}");
    assert!(raw.contains("the bytes are missing"), "{raw}");
    assert!(
        !raw.contains("not_kept"),
        "reported as dropped by retention: {raw}"
    );

    let member = get(format!("/v1/runs/{}/member?path=package%2Findex.js", r.id)).await;
    assert!(
        member.contains("the record says this artifact was kept and the store would not return it"),
        "{member}"
    );

    // And the run's row does not say it has its artifacts.
    let run: serde_json::Value =
        serde_json::from_str(&get(format!("/v1/runs/{}", r.id)).await).unwrap();
    assert_eq!(run["entry"]["has"]["artifacts"], false, "{run}");
}
