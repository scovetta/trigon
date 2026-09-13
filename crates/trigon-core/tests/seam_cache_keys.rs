//! Keys: a key must be a function of everything it identifies, and of nothing else.
//!
//! `docs/16-findings.md` §1 names "a cache key that is not a function of everything it depends on"
//! as one of this project's recurring bug classes, and `docs/01-architecture.md` §1.1 spells the
//! run key out as `H(target, upstream_artifact_digest, strategy_digest, base_image_digest,
//! stabilizer_set_digest, comparator_digest)`. Each of those is checked where it lives:
//! `strategy_digest` in `crates/trigon-strategy/tests/digest.rs`, the stabilizer set digest in
//! `crates/trigon-stabilize/tests/passes.rs`, the PURL that is the `target` half in
//! `seam_roundtrips.rs`.
//!
//! This file is about the *other* key in the system, the one that lives in this crate and that
//! nothing has ever asserted anything about: [`FailureSignature::key`]. It is a cache key in the
//! same sense and with more money attached to it. `docs/07-ai.md` §4.1 puts the number on it — key
//! the repair cache on the target and every sibling package misses, key it on the signature and
//! the first repair pays for all of them, and that is "the difference between a $4,000 sweep and a
//! $168,000 one". `trigon-ai`'s `Ledger::next` then reaches a persistent `Prior` through the same
//! string (`prior.is_novel(&key)`, `prior.ever_repaired(&key)`) and stops the loop on
//! `StopReason::KnownUnfixable` before any model is called.
//!
//! So the key has two obligations that pull in opposite directions, and both are testable:
//!
//! - **It must cover everything the cached decision depends on.** Two build logs that key alike
//!   are, to the repair loop, the same failure: the same prior, the same admission verdict, the
//!   same cluster in the operator's failure view. If two rules could produce one key while
//!   disagreeing about `repairable`, a repair filed under that key would be served to a failure
//!   that must never enter the loop at all.
//! - **It must cover nothing else.** Anything per-run that leaks into the key gives that failure a
//!   cluster of one, and a cluster of one is a cache that never hits. The module doc in
//!   `failure.rs` says this outright: "A signature carrying the package name, the version, a temp
//!   path or a hash is a signature that matches one run, and all three uses above collapse."
//!
//! Two of the tests below fail. Both are the second obligation: the key moves when something that
//! is not the failure moves.

use std::collections::BTreeMap;

use trigon_core::{FailureSignature, Fault, classify, compress};

/// What the admission control in `trigon-ai::Ledger::next` reads off a signature.
///
/// Grouped into a tuple because the claim is about all three at once: `repairable` decides whether
/// the loop is entered, `retryable` decides whether the scheduler re-enqueues, and `fault` decides
/// whether the failure is charged to the package or to us. None of the three is in `key()`.
type Decision = (Fault, bool, bool);

fn decision(s: &FailureSignature) -> Decision {
    (s.fault, s.retryable, s.repairable)
}

/// One log line per rule in the table, with the label naming the rule it is there to reach.
///
/// Written out rather than derived because `RULES` is private, which is the right call — the table
/// is an implementation detail and the classification is the contract. The cost is that a rule
/// added tomorrow is not covered here until somebody adds a line, so the tests below also assert
/// that this corpus still reaches more than one rule per shared code; that is what stops this from
/// decaying into a list that agrees with itself.
const ONE_LINE_PER_RULE: &[(&str, &str)] = &[
    // Two spellings of a missing tool: bash says `command not found`, and `/bin/sh` on any Debian
    // image is dash, which says `not found`. Different rules, one code.
    (
        "missing-tool/bash",
        "/build/run.sh: line 3: pnpm: command not found",
    ),
    ("missing-tool/dash", "sh: 1: pnpm: not found"),
    ("node-too-old", "Error: Cannot find module 'node:path'"),
    (
        "missing-shared-library",
        "/opt/node/bin/node: error while loading shared libraries: libatomic.so.1: cannot open shared object file",
    ),
    ("toolchain-crashed", "Aborted (core dumped)"),
    ("missing-venv", "ensurepip is not available"),
    (
        "no-ca-certificates",
        "fatal: unable to access 'https://github.com/x/y': server certificate verification failed",
    ),
    // Two rules, one code, and the code that matters most for this: `repairable: false` is the
    // admission-control short circuit, and it has to mean the same thing on both.
    ("out-of-memory/killed", "Killed"),
    (
        "out-of-memory/heap",
        "FATAL ERROR: JavaScript heap out of memory",
    ),
    ("no-space", "tar: write error: No space left on device"),
    (
        "cannot-chown",
        "tar: node_modules: Cannot change ownership to uid 1000",
    ),
    // Three rules, one code: three ways a denied egress tier looks from inside the sandbox.
    ("unreachable/dns", "Temporary failure in name resolution"),
    (
        "unreachable/host",
        "fatal: Could not resolve host: github.com",
    ),
    ("unreachable/route", "connect: Network is unreachable"),
    ("http-error", "2026-01-01 00:00:00 ERROR 403: Forbidden."),
    ("registry-5xx", "npm ERR! 503 Service Unavailable"),
    ("rate-limited", "npm ERR! 429 Too Many Requests"),
    ("peer-conflict", "npm ERR! code ERESOLVE"),
    (
        "version-gone",
        "npm ERR! notarget No matching version found for left-pad@9.9.9",
    ),
    (
        "lifecycle-script",
        "npm ERR! Failed at the demo@1.0.0 build script",
    ),
    ("node-gyp", "gyp ERR! build error"),
    ("engine-mismatch", "npm WARN EBADENGINE Unsupported engine"),
    (
        "no-matching-distribution",
        "ERROR: No matching distribution found for cython",
    ),
    (
        "unmet-build-dependency",
        "E: Unmet dependencies: libssl-dev",
    ),
    (
        "metadata-generation-failed",
        "error: metadata-generation-failed",
    ),
    (
        "missing-build-backend",
        "ERROR: Cannot import 'setuptools.build_meta'",
    ),
    (
        "missing-module",
        "ModuleNotFoundError: No module named 'cython'",
    ),
    ("syntax-error", "SyntaxError: invalid syntax"),
    (
        "missing-header",
        "foo.c:1:10: fatal error: Python.h: No such file or directory",
    ),
    (
        "missing-compiler",
        "error: unable to execute 'cc': No such file or directory",
    ),
    (
        "undefined-symbol",
        "main.o: undefined reference to `SSL_new'",
    ),
    // Two rules, one code: a ref that does not exist, in git's two vocabularies.
    (
        "no-such-ref/pathspec",
        "error: pathspec 'deadbeef' did not match any file(s) known to git",
    ),
    (
        "no-such-ref/branch",
        "fatal: Remote branch v1 not found in upstream origin",
    ),
    (
        "commit-not-in-repo",
        "fatal: reference is not a tree: deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ),
    ("repository-gone", "ERROR: Repository not found."),
    // Two rules, one code, and this one is ours: the symptom reads as a broken package and the
    // code exists so that it is counted against us instead.
    ("mirror-corrupted/zdata", "gzip: stdin: Z_DATA_ERROR"),
    (
        "mirror-corrupted/zlib",
        "tar: zlib: invalid stored block lengths",
    ),
    (
        "no-output",
        "trigon: no file matched the output path dist/*.whl",
    ),
];

// ---------------------------------------------------------------------------------------------
// 1. The key must cover everything the cached decision depends on.

#[test]
fn every_line_that_keys_the_same_repair_cache_entry_agrees_on_whether_to_attempt_a_repair() {
    // `Ledger::next` reaches the persistent prior through `failure.key()` and reads `repairable`
    // off the signature in front of it. Those are two different objects, joined only by the
    // assumption that the key determines the answer. Five codes in the table are produced by more
    // than one rule, so that assumption is load-bearing rather than vacuous: `env/out-of-memory`
    // is `repairable: false`, the short circuit that keeps an OOM kill from costing model spend,
    // and a second `env/out-of-memory` rule written with `repairable: true` would file a repair
    // under a key the loop is then told never to enter — or, worse, would enter the loop for the
    // half of OOM kills whose log happens to say "heap" rather than "Killed".
    //
    // The same argument holds for `fault`: `docs/16-findings.md` §1 is explicit that without
    // `Fault::Bug` and `Fault::Infra` "a reproduction rate silently becomes a measure of our own
    // reliability wearing the costume of a claim about packages". One key charged to the package
    // on Monday and to us on Tuesday is that measure quietly going wrong.
    let mut by_key: BTreeMap<String, Vec<(&str, Decision, String)>> = BTreeMap::new();
    for (label, line) in ONE_LINE_PER_RULE {
        let sig = classify(line);
        assert!(
            !sig.is_unknown(),
            "`{label}` no longer reaches a rule; the corpus line has drifted from the table \
             and this test is now asserting less than it claims: {line}"
        );
        by_key
            .entry(sig.key())
            .or_default()
            .push((label, decision(&sig), sig.evidence.clone()));
    }

    for (key, rows) in &by_key {
        let (first_label, first, _) = &rows[0];
        for (label, d, _) in rows {
            assert_eq!(
                d, first,
                "`{key}` is one repair-cache entry but two different verdicts: `{first_label}` \
                 says {first:?} and `{label}` says {d:?}. The prior, the admission control and \
                 the cluster are all reached through that one string."
            );
        }
    }

    // The guard that keeps the loop above from passing because every key had exactly one row.
    let shared: Vec<&String> = by_key
        .iter()
        .filter(|(_, rows)| rows.len() > 1)
        .map(|(k, _)| k)
        .collect();
    assert!(
        shared.len() >= 5,
        "only {} key(s) were reached by more than one rule ({shared:?}); the agreement check \
         above is close to vacuous",
        shared.len()
    );
}

#[test]
fn a_signature_is_finer_than_the_key_it_produces_so_the_struct_is_never_the_cache_key() {
    // `evidence` is documented as "not part of the key", and it must not be: it is the verbatim
    // line, which carries the package's own file names. But `FailureSignature` derives
    // `PartialEq`, so the struct *does* distinguish two runs that the key deliberately does not.
    //
    // That gap is the trap. A `HashMap<FailureSignature, Repair>` — or any `==` used as a
    // this-is-the-same-failure check — would miss on every second occurrence while the cache it
    // was standing in for would have hit, and the symptom is a repair bill that scales with
    // targets instead of with causes. Pinning it here says out loud that `key()` is the only
    // identity this type has.
    let a = classify(
        "/tmp/pip-install-8x1k/lxml_9a/src/etree.c:96:10: fatal error: Python.h: No such file or directory",
    );
    let b = classify(
        "/tmp/pip-install-qq3z/numpy_71/src/multiarray.c:4:10: fatal error: Python.h: No such file or directory",
    );

    assert_eq!(a.key(), b.key(), "one cause, one repair, one cache entry");
    assert_eq!(a.key(), "cc/missing-header:python.h");
    assert_ne!(
        a, b,
        "if the structs ever compare equal this test stops proving anything, but it also means \
         `evidence` has stopped being verbatim"
    );
    assert_ne!(a.evidence, b.evidence, "evidence is the per-run half");
}

// ---------------------------------------------------------------------------------------------
// 2. The key must cover nothing else. Both of these fail.

#[test]
fn the_repair_cache_key_survives_the_colour_the_compiler_chose() {
    // FAILS. `classify` matches and captures against the raw line, and nothing strips terminal
    // escapes before it does. `clip()` strips them out of `evidence` — the code already knows this
    // text can repaint a terminal and is about to be put in front of a model, `docs/12-security.md`
    // §4 — but `normalize_subject`, which produces the half of the key that varies, does not.
    //
    // So one failure has three names depending on whether the tool colourized, and gcc's real
    // `-fdiagnostics-color=always` form puts raw ESC bytes *inside* the cache key. That key is
    // also the failure-cluster id (`docs/11-interfaces.md` §4) and the ticket title, and
    // `trigon watch` renders it into HTML.
    //
    // Colour is not hypothetical in a container: tools that honour `FORCE_COLOR` or `CLICOLOR_FORCE`
    // emit it with no tty, and the whole point of the key is that the same cause reaches the same
    // entry however the build happened to be configured.
    let same_failure = [
        (
            "plain",
            "foo.c:1:10: fatal error: Python.h: No such file or directory".to_string(),
        ),
        (
            "bold-red marker",
            "\u{1b}[1;31mfatal error:\u{1b}[0m Python.h: No such file or directory".to_string(),
        ),
        (
            "gcc -fdiagnostics-color=always",
            "\u{1b}[01m\u{1b}[Kfoo.c:1:10:\u{1b}[m\u{1b}[K \u{1b}[01;31m\u{1b}[Kfatal error: \
             \u{1b}[m\u{1b}[KPython.h: No such file or directory"
                .to_string(),
        ),
    ];

    let keys: Vec<(&str, String)> = same_failure
        .iter()
        .map(|(label, line)| (*label, classify(line).key()))
        .collect();

    for (label, key) in &keys {
        assert_eq!(
            key, &keys[0].1,
            "the `{label}` spelling of one missing header is a different repair-cache entry from \
             the plain one; every package that hits it under a colourizing toolchain pays for its \
             own repair"
        );
    }
    for (label, key) in &keys {
        assert!(
            !key.chars().any(char::is_control),
            "the `{label}` spelling puts control characters in the cache key: {key:?} — this \
             string is a cluster id, a ticket title and HTML in `trigon watch`"
        );
    }
}

#[test]
fn naming_a_failure_before_and_after_the_log_is_compressed_reaches_the_same_cache_entry() {
    // FAILS, and this one decides which key a real run gets. `trigon-sandbox`'s `podman.rs` keeps
    // `BuildOutcome::log_tail` and compresses it — `if log.len() > LOG_TAIL_BYTES * 2 { *log =
    // compress(log, LOG_TAIL_BYTES).text }` — so a log over 128 KiB is compressed and a log under
    // it is not. `trigon`'s `main.rs` then runs `classify(&outcome.log_tail)` to get the signature
    // that goes in the run record, and `watch.rs` re-classifies the stored log to build the
    // failure clusters. The key therefore depends on how chatty the build was.
    //
    // It diverges because the two halves disagree about which end of a log matters. `classify`
    // reads from the *end* — "the last error is almost always the one that stopped the build" —
    // while `compress` marks lines to keep and then emits them in file order, so when the budget
    // runs out it is the tail that is dropped and the head that survives. A build that prints tens
    // of thousands of distinct lines matching an error marker (`FAILED`, `not found`, `ERROR` —
    // a pytest run with a few thousand failures does exactly this) fills the budget before the
    // emitter ever reaches the line that says why the build stopped.
    //
    // The consequence is not a worse log. It is that the real cause is filed under `unknown`, the
    // one bucket the design deliberately keeps undifferentiated — so it lands in the pile that is
    // supposed to mean "a gap in the rule table" while the rule that would have named it sits
    // right there, and the repair learned on the quiet build never hits on the loud one.
    let budget = 64 * 1024; // LOG_TAIL_BYTES in trigon-sandbox

    let mut noisy = String::new();
    for i in 0..4000 {
        noisy.push_str(&format!(
            "FAILED tests/test_module_{i}.py::test_case_{i} - AssertionError: 1 != 2\n"
        ));
    }
    noisy.push_str("foo.c:1:10: fatal error: Python.h: No such file or directory\n");

    let mut quiet = String::from("running build\n");
    quiet.push_str("foo.c:1:10: fatal error: Python.h: No such file or directory\n");

    // A third shape that already works, so a failure here is read as "this case", not "compression
    // is hopeless": npm's progress lines are noise, they are dropped rather than kept, and the
    // error at the end survives.
    let mut npmish = String::from("npm info it worked if it ends with ok\n");
    for i in 0..4000 {
        npmish.push_str(&format!(
            "npm http fetch GET 200 https://registry/pkg-{i} 12ms\n"
        ));
    }
    npmish.push_str("Module build failed: Error: Cannot find module 'node:path'\n");

    for (label, log) in [
        ("quiet", &quiet),
        ("npm progress", &npmish),
        ("noisy", &noisy),
    ] {
        let raw = classify(log);
        let c = compress(log, budget);
        let compressed = classify(&c.text);
        assert_eq!(
            compressed.key(),
            raw.key(),
            "`{label}` ({} bytes) keys as `{}` whole and `{}` after compression to {} bytes; \
             whether a run gets the right cache entry then depends on how much the build printed",
            log.len(),
            raw.key(),
            compressed.key(),
            c.text.len(),
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 3. What the key deliberately does not distinguish.
//
// Recorded rather than assumed away. Every one of these is a place where two causes share an
// entry; the design says that is the right trade, and the trade is only defensible if somebody
// can see its edges.

#[test]
fn a_header_name_loses_its_directory_so_two_libraries_share_one_repair_key() {
    // `normalize_subject` keeps only the last path component, because the capture would otherwise
    // pull in `/tmp/pip-install-8x1k/…` and give every target a cluster of one. The price is
    // exact and worth stating: `openssl/ssl.h` and `gnutls/ssl.h` are one key and two different
    // repairs (`libssl-dev` against `libgnutls28-dev`). A repair cached for one is offered for the
    // other, and the loop discovers that by failing.
    //
    // This is the same shape as `StabilizerSet::digest` hashing member metadata rather than member
    // behaviour: the key is a function of a projection, and the projection is not injective.
    let openssl =
        classify("build/ssl.c:1:10: fatal error: openssl/ssl.h: No such file or directory");
    let gnutls = classify("build/tls.c:1:10: fatal error: gnutls/ssl.h: No such file or directory");
    assert_eq!(openssl.key(), "cc/missing-header:ssl.h");
    assert_eq!(
        openssl.key(),
        gnutls.key(),
        "two libraries' headers collapse to one key — if this ever stops being true the \
         path-stripping has changed and the temp-path cluster-of-one is back"
    );

    // The collapse is only over the directory. Two different header *names* stay apart, which is
    // what makes the subject worth carrying at all.
    let python = classify("foo.c:1:10: fatal error: Python.h: No such file or directory");
    assert_ne!(python.key(), openssl.key());

    // And the case a temp path would have ruined, which is why the stripping is there.
    let a = classify(
        "/tmp/pip-install-8x1k/lxml_9a/src/lxml/etree.c: fatal error: /usr/include/openssl/ssl.h: No such file or directory",
    );
    assert_eq!(
        a.key(),
        openssl.key(),
        "an absolute include path is still one key"
    );
}

#[test]
fn two_failures_the_table_cannot_name_share_the_unknown_bucket_and_the_evidence_stays_out_of_it() {
    // `FailureSignature::unknown` is "deliberately one bucket rather than a per-message hash": an
    // unrecognised failure is a gap in the rule table and should surface as one large cluster
    // somebody fixes, not five hundred singletons that look like five hundred problems.
    //
    // So `unknown` is the one key in the system that is knowingly *not* a function of what it
    // identifies, and the two tests above it care about that: whatever else compression or colour
    // do, they must not be the reason a failure lands here. Pinning the bucket means a later
    // change that hashed the evidence into the key — which reads like an improvement — shows up
    // as a broken test rather than as a failure view that stops clustering.
    let a = classify("./configure: the frobnicator is misaligned (code 7)");
    let b = classify("make[2]: *** wibble target refused, giving up");
    assert!(
        a.is_unknown() && b.is_unknown(),
        "{} / {}",
        a.key(),
        b.key()
    );
    assert_eq!(a.key(), "unknown");
    assert_eq!(a.key(), b.key(), "one bucket, not two singletons");
    assert_ne!(
        a.evidence, b.evidence,
        "the evidence still tells them apart for a human"
    );
    assert!(
        a.repairable,
        "an unnamed failure is admitted to the loop; it is the named-and-hopeless ones that are \
         short-circuited"
    );

    // And the bucket has to be internally consistent for the same reason every other key does: it
    // is one entry in the prior, so it cannot mean two things about whether to spend money on it.
    // Deliberately not asserting *which* fault `unknown` carries — that is a taxonomy question
    // (`docs/16-findings.md` §1 argues an unnamed failure should be able to be charged to us)
    // rather than a key question, and pinning the value here would be this file having an opinion
    // about something it is not testing.
    assert_eq!(decision(&a), decision(&b), "one bucket, one verdict");
}
