//! Controls that cannot run must not report success.
//!
//! `docs/16-findings.md` §3.12 found three of these at once and named the shape: *a control that
//! fails open, and reports success while doing it*. The worst of them was this crate's: the artifact
//! guard wrote its trip through `tracing`, which goes to stderr, while the process that read the
//! verdict read the mirror container's stdout. The single most important control in the design
//! returned an empty list on the only tier that enforces it — and **an unreadable log returned the
//! same empty list as a quiet one**.
//!
//! Every test here checks one of the mirror's controls for that shape. A control has to answer two
//! different questions with two different values:
//!
//! * *ran, and found nothing* — the ordinary case, and the only one allowed to look like success;
//! * *could not run* — no filter, no allowlist decision, no decomposition, nothing read.
//!
//! Two things about how these are written, both deliberate.
//!
//! **They do not touch the network.** Every end-to-end guard test in `tests/server.rs` is behind
//! `TRIGON_LIVE=1`, and CI runs a bare `cargo test --workspace`, so the wiring between the served
//! routes and the guard is exercised by nobody. That is the *first* finding of the five this sweep
//! was called for — the detector that existed, worked, and was not in CI. The refusals below all
//! resolve before a packet leaves: the host allowlist is checked before the upstream URL is built,
//! and the guard's URL refusal is checked before `send()`. So these run everywhere, always.
//!
//! **They assert across two components rather than inside one.** A unit test of
//! `artifact_host_allowed` passes whether or not the route calls it; §3.13 is the record of exactly
//! that — a correct predicate on one route and no call at all on the other, measured as
//! `GET /-artifact/npm/<moment>/example.com/` returning 200 with example.com's home page.

use std::collections::BTreeSet;

use sha2::{Digest as _, Sha256};
use trigon_core::{Digest, Format};
use trigon_mirror::{
    ARTIFACT_HOSTS, Guard, GuardManifest, GuardMatch, Mirror, MirrorHandle, TOOLCHAIN_HOSTS,
    artifact_host_allowed, toolchain_host_allowed,
};

// ---------------------------------------------------------------------------------------------
// The three routes that proxy bytes, and the one control that has to run on all of them.
// ---------------------------------------------------------------------------------------------

/// The URL refusal runs on every route that can hand bytes to a build.
///
/// `guard.rs` calls this "the cheapest control there is": at `mirror-only` egress the mirror is the
/// build's only route out, so a build asking for its own published artifact gets nothing. That is
/// only true if the check sits on *every* route that proxies, and the mirror has three of them —
/// `/-artifact/`, `/-toolchain/`, and the npm passthrough under `/-/`. The first two are handled
/// before the credential check and the third after it, so they are three separate opportunities to
/// forget, and `server.rs` closes all three by putting the check inside `proxy` rather than at each
/// call site. This asserts that is still where it is.
///
/// The toolchain route is the one worth naming: its own doc comment claims "the guard still
/// applies, because *the artifact arrived dressed as a toolchain* is exactly the route it exists to
/// close." §3.12's stale-disclaimer finding is what happens when a claim like that is checked by
/// reading it.
#[tokio::test]
async fn every_route_that_proxies_bytes_runs_the_artifact_refusal_before_the_fetch() {
    let m = Mirror::new()
        .unwrap()
        .with_guard(refusing(
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        ))
        .serve(0)
        .await
        .unwrap();

    // Each of these would proxy to a real host if the refusal did not fire first, which is also why
    // a passing run here proves the check precedes the request rather than merely following it.
    let routes = [
        (
            "the artifact route, which is reached before the credential check",
            "/-artifact/npm/2018-04-09T01:10:46/registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            None,
        ),
        (
            "the toolchain route, where the artifact arrives dressed as a toolchain",
            "/-toolchain/nodejs.org/dist/v18.0.0/left-pad-1.3.0.tgz",
            None,
        ),
        (
            "the npm passthrough, which is reached only after the filter is parsed",
            "/left-pad/-/left-pad-1.3.0.tgz",
            Some(basic("npm:2018-04-09T01:10:46")),
        ),
    ];

    for (n, (what, path, auth)) in routes.iter().enumerate() {
        let (status, body) = get(&m, path, auth.as_deref()).await;
        assert_eq!(status, 403, "{what}: {body}");
        assert!(
            body.contains("proves nothing"),
            "{what}: refused, but not by the guard — {body}"
        );
        // And the refusal is *recorded*, not merely served. A 403 the run cannot see is a control
        // whose result never reaches the verdict: `trips()` non-empty is what makes the run `Void`.
        assert_eq!(
            m.trips().len(),
            n + 1,
            "{what}: refused without recording a trip, so the run would not be void"
        );
        assert_eq!(m.trips()[n].matched, GuardMatch::RefusedUrl, "{what}");
    }

    m.shutdown().await;
}

/// A refusal is counted, so "asked and turned away" is a different number from "never asked".
///
/// This is the counter half of the same rule. `Observed::contacted` exists to separate *the pin did
/// not reach the client* from *the build never came here*, and `main.rs` prints one of two
/// different diagnoses from it. If a refused request incremented nothing, a build that dropped its
/// credentials on every request would be indistinguishable from a build with no dependencies —
/// which is the §1 pip finding all over again, where the only trace of a control that had stopped
/// applying was a counter sitting at zero.
#[tokio::test]
async fn a_refusal_is_counted_as_contact_so_a_broken_client_and_a_quiet_one_are_different_numbers()
{
    let m = Mirror::new().unwrap().serve(0).await.unwrap();

    let quiet = m.observed();
    assert!(!quiet.contacted(), "nobody has asked yet");
    assert!(!quiet.pin_bound());
    assert_eq!(quiet.rejected, 0);

    // A client that dropped the credentials carrying the moment. It gets nothing, and the fact that
    // it asked survives.
    let (status, _) = get(&m, "/left-pad", None).await;
    assert_eq!(status, 400);

    let after = m.observed();
    assert_eq!(
        after.rejected, 1,
        "a refusal that nothing counts is silence"
    );
    assert!(
        after.contacted(),
        "a build that was refused must not read as a build that never came"
    );
    assert!(
        !after.pin_bound(),
        "and being refused is not evidence that the pin bound anything"
    );
    assert_eq!(after.index_requests, 0);

    m.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// The host allowlists.
// ---------------------------------------------------------------------------------------------

/// Neither proxy route answers a host that is not on its own allowlist.
///
/// §3.13: `/-artifact/` had no allowlist at all while `/-toolchain/` had one, and the measurement
/// was `GET /-artifact/npm/<moment>/example.com/` returning **200 with example.com's home page**.
/// At `mirror-only` that made the build's only route out a general HTTP proxy to the internet
/// wearing the name of a boundary.
///
/// Two separate things are asserted here, and the §3.13 bug is precisely the gap between them: that
/// the *predicate* refuses the host, and that the *route* does. A unit test of the predicate alone
/// passes on a route that never calls it.
///
/// The lists are also asserted to be per-route. They are different lists for a reason — one holds
/// hosts this mirror rewrites index URLs into, the other holds toolchain distributions — so a host
/// allowed on one must not be allowed on the other by accident, which a single shared check or a
/// widened list would silently do.
#[tokio::test]
async fn neither_proxy_route_answers_a_host_that_is_not_on_its_own_allowlist() {
    let m = Mirror::new().unwrap().serve(0).await.unwrap();

    let refused = [
        // The host the finding was measured on.
        ("example.com", "the host §3.13 got a 200 from"),
        // Exact match, not a suffix: the obvious `ends_with` rule accepts both of these.
        ("registry.npmjs.org.evil.example", "a suffix-rule bypass"),
        ("evil-nodejs.org", "a suffix-rule bypass the other way"),
        ("nodejs.org.evil.example", "a suffix-rule bypass"),
        // Userinfo smuggled into the first path segment: the check must read the whole segment.
        ("registry.npmjs.org@evil.example", "userinfo smuggling"),
        ("", "no host at all"),
    ];

    for (host, why) in refused {
        for (route, path, allowed) in [
            (
                "artifact",
                format!("/-artifact/npm/2024-01-01T00:00:00/{host}/x.tgz"),
                artifact_host_allowed(host),
            ),
            (
                "toolchain",
                format!("/-toolchain/{host}/x.tgz"),
                toolchain_host_allowed(host),
            ),
        ] {
            assert!(!allowed, "the {route} predicate allows {host} ({why})");
            let (status, body) = get(&m, &path, None).await;
            assert_eq!(
                status, 403,
                "the {route} route answered {status} for {host} ({why}); the predicate says no and \
                 the route has to agree — {body}"
            );
            assert!(
                body.contains("refusing to proxy"),
                "the {route} route refused {host} for some other reason than the allowlist: {body}"
            );
        }
    }

    // Each route's list is its own. Crossing them would widen both without either list changing.
    for host in ARTIFACT_HOSTS {
        assert!(artifact_host_allowed(host), "{host}");
        assert!(
            !toolchain_host_allowed(host),
            "{host} is on the artifact list and the toolchain route takes it too"
        );
        let (status, _) = get(&m, &format!("/-toolchain/{host}/x.tgz"), None).await;
        assert_eq!(status, 403, "the toolchain route proxied to {host}");
    }
    for host in TOOLCHAIN_HOSTS {
        assert!(toolchain_host_allowed(host), "{host}");
        assert!(
            !artifact_host_allowed(host),
            "{host} is on the toolchain list and the artifact route takes it too"
        );
        let (status, _) = get(
            &m,
            &format!("/-artifact/npm/2024-01-01T00:00:00/{host}/x.tgz"),
            None,
        )
        .await;
        assert_eq!(status, 403, "the artifact route proxied to {host}");
    }

    m.shutdown().await;
}

/// The allowlist refuses by host, and does not merely refuse everything.
///
/// A route that answered 403 unconditionally — a typo in the prefix, a list that failed to load,
/// an allowlist consulted with the wrong string — would satisfy every assertion above while being
/// just as broken, in the other direction. So: an allowlisted host has to get *past* the allowlist
/// and be stopped by the next control instead, and the two refusals have to stay distinguishable.
/// Both are 403, so the status alone cannot tell them apart and the body has to.
///
/// This is the same rule as everywhere else in this file, applied to a response rather than a
/// counter: *refused because the host is not ours* and *allowed through, then refused because it is
/// this run's own artifact* are different facts, and one value for both is how a control stops
/// being readable.
#[tokio::test]
async fn the_allowlists_refuse_by_host_rather_than_refusing_everything() {
    let m = Mirror::new()
        .unwrap()
        .with_guard(refusing(
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        ))
        .serve(0)
        .await
        .unwrap();

    let (allowed_status, allowed_body) = get(
        &m,
        "/-artifact/npm/2024-01-01T00:00:00/registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        None,
    )
    .await;
    let (blocked_status, blocked_body) = get(
        &m,
        "/-artifact/npm/2024-01-01T00:00:00/example.com/left-pad/-/left-pad-1.3.0.tgz",
        None,
    )
    .await;

    assert_eq!(allowed_status, 403);
    assert_eq!(blocked_status, 403);
    assert!(
        allowed_body.contains("proves nothing"),
        "a listed host was stopped at the allowlist, so the allowlist refuses everything: \
         {allowed_body}"
    );
    assert!(
        blocked_body.contains("refusing to proxy"),
        "an unlisted host got past the allowlist: {blocked_body}"
    );
    assert_ne!(
        allowed_body, blocked_body,
        "two different refusals must not read the same"
    );
    // And only the one that reached the guard is recorded as a trip: a host refusal is a policy
    // answer about where the build may fetch from, not evidence that the build asked for its own
    // artifact, and conflating them would void honest runs.
    assert_eq!(m.trips().len(), 1);

    m.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// The time filter.
// ---------------------------------------------------------------------------------------------

/// No index document is served when the time filter is absent or unreadable.
///
/// The whole crate exists because a rebuild that resolves *today's* index is silently a rebuild of
/// a different dependency graph. So the failure to fail closed here is not a leak, it is the
/// product quietly doing the opposite of its purpose — and it would be invisible, because a build
/// served the live index succeeds.
///
/// Every shape below is a different way for the filter to be missing rather than wrong: no header,
/// the wrong scheme, undecodable base64, no colon, an empty moment, a moment that will not parse, a
/// platform this mirror does not serve. Each has to be refused with a 4xx and counted, and the
/// counting is the second half: `main.rs` reads `rejected` to tell an operator *somebody asked and
/// was turned away*, which is a different thing to investigate from silence.
#[tokio::test]
async fn no_index_document_is_served_when_the_time_filter_is_absent_or_unreadable() {
    let m = Mirror::new().unwrap().serve(0).await.unwrap();

    let cases: &[(&str, Option<String>, &str)] = &[
        ("/left-pad", None, "an npm packument with no credentials"),
        (
            "/simple/sniffio/",
            None,
            "a PyPI simple index with no credentials",
        ),
        (
            "/left-pad/-/left-pad-1.3.0.tgz",
            None,
            "even a tarball, which needs no filtering, is refused rather than proxied unfiltered",
        ),
        (
            "/left-pad",
            Some("Bearer something".into()),
            "a scheme that carries no moment",
        ),
        (
            "/left-pad",
            Some("Basic !!!!not-base64".into()),
            "credentials that will not decode",
        ),
        (
            "/left-pad",
            Some(basic("no-colon-at-all")),
            "credentials with no separator",
        ),
        ("/left-pad", Some(basic("npm:")), "an empty moment"),
        (
            "/left-pad",
            Some(basic("npm:yesterday")),
            "a moment that is not an instant",
        ),
        (
            "/left-pad",
            Some(basic("npm:1708902001")),
            "a unix timestamp, which is an instant but not one that compares lexically",
        ),
        (
            "/left-pad",
            Some(basic("npm:2024-02")),
            "a truncated instant, which would compare as a prefix and silently widen the window",
        ),
        (
            "/left-pad",
            Some(basic("maven:2024-01-01T00:00:00")),
            "a platform with no time filter implemented",
        ),
        (
            "/simple/sniffio/",
            Some(basic("pypi:whenever")),
            "the same on the PyPI side",
        ),
    ];

    for (path, auth, what) in cases {
        let (status, body) = get(&m, path, auth.as_deref()).await;
        assert!(
            (400..500).contains(&status),
            "{what}: got {status}, and anything that is not a refusal here is the live index — \
             {body}"
        );
    }

    assert_eq!(
        m.observed().rejected,
        cases.len() as u64,
        "a refusal nothing counts reads as a build that needed nothing"
    );
    assert_eq!(
        m.observed().index_requests,
        0,
        "nothing was served through the filter, so nothing may claim it was"
    );
    assert!(m.observed().contacted());
    assert!(!m.observed().pin_bound());

    m.shutdown().await;
}

/// A fetch on the artifact route is never counted as evidence that the pin bound.
///
/// The artifact route takes a moment in its path and applies no filter to it — stated outright in
/// §3.13, because "an artifact's bytes are immutable, so there is nothing to filter". The corollary
/// is that two of the three hosts on its allowlist, `registry.npmjs.org` and `pypi.org`, serve
/// their *index* on the same host: a build that addresses the index through the artifact route gets
/// today's index, unfiltered, from a route with no credential check.
///
/// That is survivable for exactly one reason, and this test is that reason. The route increments
/// `passthrough_requests` and never `index_requests`, so `pin_bound()` stays false, `main.rs` warns
/// "it was contacted but served no index document", and the signed predicate records
/// `registryPinBound: false`. The control cannot be bypassed *and report success*.
///
/// What would break it is someone deciding the artifact route's traffic is index traffic and
/// counting it as such. Then an unfiltered fetch would go green on the pin check and be signed as
/// pinned. Pinned here so that change cannot be made quietly.
///
/// No network: the request is stopped by the guard's URL refusal, which sits inside `proxy` and
/// therefore *after* the counter — so the counters below are exactly the ones a real fetch writes.
#[tokio::test]
async fn an_artifact_route_fetch_never_counts_as_evidence_that_the_pin_bound() {
    let m = Mirror::new()
        .unwrap()
        // Matched on the last path segment, so this refuses the packument path below before a
        // packet leaves.
        .with_guard(refusing("https://registry.npmjs.org/left-pad"))
        .serve(0)
        .await
        .unwrap();

    // An npm packument, addressed through the artifact route, with a moment nothing will parse.
    let (status, _) = get(
        &m,
        "/-artifact/npm/not-an-instant-at-all/registry.npmjs.org/left-pad",
        None,
    )
    .await;
    assert_eq!(status, 403, "the guard refusal is what stopped this");

    let o = m.observed();
    assert_eq!(
        o.index_requests, 0,
        "the artifact route served something the index route would have filtered, and counted it \
         as an index request: the pin check would go green on an unfiltered fetch and the signed \
         statement would carry registryPinBound: true"
    );
    assert!(
        !o.pin_bound(),
        "nothing about this fetch is evidence that the moment bound anything"
    );
    assert!(
        o.contacted(),
        "and it is still contact, so the run says `contacted but served no index document` rather \
         than `never contacted`"
    );
    assert_eq!(o.artifact_requests, 1, "it is counted, as what it was");

    m.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// The guard's member filters, and the states its manifest cannot express.
// ---------------------------------------------------------------------------------------------

/// No member filter ever drops an executable.
///
/// Three filters narrow the guarded member set, and every one is a chance to fail open: minimum
/// size, stock content, and byte-identical-to-something-in-the-source-tree. `guardable`'s own
/// comment states the rule they are narrowed around — *"Executables first, and unconditionally.
/// They are what an attacker wants to smuggle, so neither a size threshold nor a content rule gets
/// to exempt one."* — and the crate's unit tests assert it for two of the three.
///
/// The third is the one nothing asserted. `build` applies `in_source` *after* `guardable` and
/// without consulting it, so a `.so` the artifact ships that is also byte-identical to a file in
/// the checked-out tree is dropped from the member set. That is the smuggling case the module doc
/// opens with, disarmed by adding one file to a repository the attacker already controls: the
/// injected `BUILD.md` says to fetch the prebuilt binary from `cdn.evil.example`, the same bytes
/// sit in the repo, the guard has nothing to match, and the run reports a reproduction rather than
/// `Void`.
#[test]
fn no_member_filter_ever_drops_an_executable() {
    let payload = {
        let mut v = APACHE.as_bytes().to_vec();
        v.extend(vec![0u8; 9000]);
        v
    };
    let dir = scratch("member-filters");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("prebuilt.so"), &payload).unwrap();

    let cases: Vec<(&str, GuardManifest)> = vec![
        (
            // Already held by `an_executable_is_guarded_whatever_its_size`; here so the invariant
            // is stated once over all three filters rather than twice over two of them.
            "the minimum-size filter",
            GuardManifest::for_artifact(&tgz(&[("pkg/tiny.so", b"\x7fELF")]), Format::TarGz, None),
        ),
        (
            "the stock-content filter",
            GuardManifest::for_artifact(&tgz(&[("pkg/LICENSE.so", &payload)]), Format::TarGz, None),
        ),
        (
            "the also-in-source filter",
            GuardManifest::for_artifact_with_source(
                &tgz(&[("pkg/native.so", &payload)]),
                Format::TarGz,
                None,
                &dir,
            ),
        ),
    ];

    // The control for the third case: the same artifact with no source tree keeps the `.so`. Without
    // this the failure below could be read as the executable being unguardable for some other
    // reason, and the point is that it is guardable right up until a filter that knows nothing
    // about executables removes it.
    let without_source =
        GuardManifest::for_artifact(&tgz(&[("pkg/native.so", &payload)]), Format::TarGz, None);
    assert_eq!(
        without_source.members.len(),
        1,
        "the executable is guarded when no source tree narrows the set"
    );

    let dropped: Vec<&str> = cases
        .iter()
        .filter(|(_, m)| m.members.is_empty())
        .map(|(name, _)| *name)
        .collect();

    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        dropped.is_empty(),
        "{dropped:?} dropped an executable from the guarded member set. Every filter exists to \
         stop the guard voiding honest runs, and an executable is the one member no amount of \
         honest-run noise is worth exempting: this is the case `guard.rs`'s module doc is written \
         around."
    );
}

/// A body too large to decompose is reported as unchecked rather than as clean.
///
/// `observe` is handed `None` for the body in two situations that mean opposite things. Either the
/// manifest had no members to look for, in which case there was nothing to do; or the response grew
/// past `MAX_DECOMPOSE_BYTES` mid-stream and `guarded_stream` threw the bytes away, in which case
/// the member half of the guard — the half `guard.rs` calls "the interesting case", the target's
/// compiled `.so` smuggled inside some unrelated tarball — did not run at all.
///
/// The guard reports the same thing for both: an empty trip list. That is §3.12's shape exactly,
/// one layer down from where it was found — *an unreadable log returned the same empty list as a
/// quiet one*.
///
/// It matters because the limit is free to cross. `guard.rs` argues an attacker "gains nothing by
/// hiding a member inside a gigabyte tarball", and that argument holds only for the whole-body
/// hash, which does keep running at any size. It does not hold for the member check the limit
/// actually switches off: padding the carrier past 64 MiB costs the attacker one file and buys
/// silence. The same doc says "the size is recorded so the limit is visible rather than silent",
/// and nothing records it — not a counter, not a log line, not a field on the manifest.
#[test]
fn a_body_too_large_to_decompose_is_reported_as_unchecked_rather_than_clean() {
    let secret = vec![b'S'; 9000];
    let manifest =
        GuardManifest::for_artifact(&tgz(&[("pkg/native.so", &secret)]), Format::TarGz, None);
    assert!(
        !manifest.members.is_empty(),
        "there is a member to look for"
    );

    // An unrelated download that was small enough to open. The member check ran and found nothing.
    let carrier = tgz(&[("vendor/other.so", &vec![b'X'; 9000])]);
    let checked = Guard::new(manifest.clone());
    checked.observe(
        "http://cdn.example/small.tgz",
        digest(&carrier),
        Some(&carrier),
    );

    // The same download, except it crossed `MAX_DECOMPOSE_BYTES` and the bytes were dropped. This
    // is the call `guarded_stream` makes in that case, and it is a different call from
    // `observe(.., None)` on purpose: a `None` alone cannot say whether the body was never wanted
    // or was wanted and lost, and those mean opposite things. The member check did not run, so
    // whether those bytes carried `pkg/native.so` is unknown rather than answered.
    let skipped = Guard::new(manifest);
    skipped.observe_oversized("http://cdn.example/big.tgz", digest(&carrier));

    // Neither is a trip, and neither should be: voiding a run for downloading a large file would
    // fire on honest builds, and a control that fires on honest runs is one people turn off.
    assert!(checked.trips().is_empty() && skipped.trips().is_empty());

    // What must differ is whether the guard says it looked. The member check is what catches the
    // target's files arriving inside something else, and the size that suppresses it is chosen by
    // the thing under test.
    assert!(
        checked.undecomposed().is_empty(),
        "a body small enough to open was reported as unopened"
    );
    assert_eq!(
        skipped.undecomposed(),
        vec!["http://cdn.example/big.tgz".to_string()],
        "the guard's entire public surface reports a body it opened and cleared identically to one \
         it never opened. A run whose every download was too large to decompose is indistinguishable\
         , to the verdict and to the operator, from a run that was checked and clean — and the \
         build picks the size."
    );
}

/// A manifest the parser could not open still arms the whole-artifact half.
///
/// The other direction of the same question, and this one is right: `build` sets `artifact` before
/// it tries to decompose, so a `parse` that fails — a format guessed wrong from the filename, a
/// truncated fetch, an archive over `Limits::default()` — leaves a manifest that is not empty and a
/// guard that is armed. The expensive half degrades; the cheap half does not silently vanish with
/// it.
///
/// Worth pinning because the natural refactor is to build the member set first and fill the digest
/// in afterwards, and the failure would be invisible: `is_armed()` false means `guarded_stream`
/// stops hashing entirely, so the artifact could arrive under any name and nothing would look.
#[test]
fn a_manifest_the_parser_could_not_open_still_arms_the_whole_artifact_half() {
    let not_an_archive = b"this is not a gzip member, and the parser will refuse it".repeat(200);
    let m = GuardManifest::for_artifact(&not_an_archive, Format::TarGz, None);

    assert!(
        m.members.is_empty(),
        "nothing was decomposed, which is the premise of this test"
    );
    assert!(
        m.artifact.is_some(),
        "the whole-artifact digest is still set"
    );
    assert!(!m.is_empty());
    assert!(
        Guard::new(m.clone()).is_armed(),
        "a guard that could not decompose the artifact must still watch for the artifact"
    );

    let g = Guard::new(m);
    g.observe(
        "http://cdn.evil.example/prebuilt.bin",
        digest(&not_an_archive),
        Some(&not_an_archive),
    );
    assert_eq!(
        g.trips().len(),
        1,
        "the whole-artifact hash is what is left, and it has to keep working"
    );
    assert_eq!(g.trips()[0].matched, GuardMatch::WholeArtifact);
}

/// Whatever arms the guard also reads as a non-empty manifest.
///
/// Two predicates over one value: `GuardManifest::is_empty`, which callers outside this crate use,
/// and `Guard::is_armed`, which the streaming path uses. `trigon mirror serve --guard` computes
/// `let armed = !manifest.is_empty()` and prints "guard armed" from it, while the guard itself arms
/// on `!is_empty() || refuse_url.is_some()`.
///
/// A manifest carrying only a `refuse_url` — the shape `tests/server.rs` builds to test the URL
/// refusal, and the shape a run with an unreadable artifact would leave — is armed and announces
/// nothing. The direction is the safe one, but the mirror is where an operator finds out whether
/// the control is on, and a control whose reported state and actual state are computed by two
/// different expressions will eventually disagree in the other direction.
#[test]
fn whatever_arms_the_guard_also_reads_as_a_non_empty_manifest() {
    let artifact_only = GuardManifest {
        artifact: Some(digest(b"some artifact bytes")),
        ..Default::default()
    };
    let members_only = GuardManifest {
        members: BTreeSet::from([digest(b"some member bytes")]),
        ..Default::default()
    };

    for (what, m) in [
        ("no guard configured at all", GuardManifest::default()),
        ("the whole artifact only", artifact_only),
        ("member digests only", members_only),
        (
            "a URL refusal only",
            refusing("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"),
        ),
    ] {
        let armed = Guard::new(m.clone()).is_armed();
        assert_eq!(
            !m.is_empty(),
            armed,
            "with {what}, the guard is armed={armed} while the predicate every caller outside this \
             crate reaches for says non-empty={}. One of the two is what an operator is told.",
            !m.is_empty()
        );
    }
}

/// A source tree that cannot be read narrows nothing.
///
/// The in-source filter is the only one that depends on something outside the artifact, so it is
/// the only one that can fail to run. `digest_tree` swallows a `read_dir` error and returns
/// whatever it managed to collect, which for an unreadable root is nothing — and an empty in-source
/// set narrows nothing, so the guard keeps every member. That is the correct direction, and it is
/// the direction `a_missing_source_tree_guards_everything` already covers for a path that does not
/// exist.
///
/// The case here is a path that exists and is not a directory, which is what a caller passing a
/// tarball where a checkout was meant looks like. Same requirement: a filter that could not run has
/// to narrow nothing rather than silently drop the whole member set.
#[test]
fn a_source_tree_that_cannot_be_read_narrows_nothing() {
    let dir = scratch("unreadable-source");
    std::fs::create_dir_all(&dir).unwrap();
    let not_a_directory = dir.join("checkout.tgz");
    std::fs::write(&not_a_directory, b"a tarball where a checkout was meant").unwrap();

    let artifact = tgz(&[("pkg/index.js", &vec![b'x'; 8192])]);
    let m =
        GuardManifest::for_artifact_with_source(&artifact, Format::TarGz, None, &not_a_directory);

    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        m.members.len(),
        1,
        "an unreadable source tree narrowed the member set, so a filter that could not run \
         disarmed the guard"
    );
    assert_eq!(m.filtered_out, 0);
}

// ---------------------------------------------------------------------------------------------

const APACHE: &str = "\n                                 Apache License\n                           Version 2.0, January 2004\n";

fn digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(Sha256::digest(bytes).into())
}

fn refusing(url: &str) -> GuardManifest {
    GuardManifest {
        refuse_url: Some(url.to_string()),
        ..Default::default()
    }
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "trigon-seam-failopen-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

async fn get(m: &MirrorHandle, path: &str, auth: Option<&str>) -> (u16, String) {
    let mut req = reqwest::Client::new().get(format!("http://{}{path}", m.host()));
    if let Some(a) = auth {
        req = req.header(reqwest::header::AUTHORIZATION, a);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

/// `Authorization: Basic <base64>`, built here because the crate decodes base64 and never encodes
/// it.
fn basic(credentials: &str) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b = credentials.as_bytes();
    let mut out = String::from("Basic ");
    for chunk in b.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn tgz(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut h = tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, *name, *body).unwrap();
    }
    let tar = b.into_inner().unwrap();
    let mut out = Vec::new();
    {
        use std::io::Write as _;
        let mut e = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap();
    }
    out
}
