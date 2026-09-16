//! A Signed Entry Timestamp that Rekor really produced, verified offline.
//!
//! The fixtures are a real entry from `rekor.sigstage.dev` — index 56040866, a DSSE envelope over an
//! `equivalence/v1` statement signed with an ed25519 key under a self-issued certificate — and the
//! log's own public key. They are checked in because the claim
//! [ADR-0011](../../../docs/adr/0011-keyed-signing-under-a-trusted-root.md) rests on is that we can
//! verify a log's timestamp *without* the log, and a test that fetched them would be asking the log
//! to vouch for itself over a socket the verifier is not allowed to open.
//!
//! What this pins that a hand-built fixture cannot: the exact canonicalization Rekor signs. Four
//! fields, RFC 8785, and nothing else from the entry — a fifth field or a different order produces
//! a different message and a failure that reads like a bad key.

use trigon_attest::{LogEntry, within_validity};

const ENTRY: &str = include_str!("fixtures/rekor-staging-entry.json");
/// The entry `trigon attest --rekor` produced on its own, rather than one assembled by hand to
/// probe the log. Two different claims: the one above pins the canonicalization, this one pins that
/// *our pipeline's* output is something the log accepts and later vouches for.
const OUR_RUN: &str = include_str!("fixtures/rekor-staging-our-run.json");
const LOG_KEY: &str = include_str!("fixtures/rekor-staging-key.pem");

fn entry() -> LogEntry {
    serde_json::from_str(ENTRY).expect("the fixture parses")
}

fn our_run() -> LogEntry {
    serde_json::from_str(OUR_RUN).expect("the fixture parses")
}

#[test]
fn a_real_signed_entry_timestamp_verifies() {
    let e = entry();
    let at = e.verify_set(LOG_KEY).expect("the staging log signed this");
    assert_eq!(at, e.integrated_at());
    assert_eq!(e.log_index, 56_040_866);
}

#[test]
fn the_time_it_attests_to_is_the_one_a_certificate_window_is_checked_against() {
    // The step ADR-0011 hinges on. The log says when the entry existed; the certificate says when
    // it was allowed to sign. A key stolen tomorrow cannot produce an entry dated today, because
    // the log is append-only and this is the number that proves it.
    let at = entry().verify_set(LOG_KEY).unwrap();
    assert!(within_validity(at, at - 600, at + 600), "inside its window");
    // Issued after the signature, or expired before it: both are the compromise this catches.
    assert!(!within_validity(at, at + 1, at + 600));
    assert!(!within_validity(at, at - 600, at - 1));
}

#[test]
fn another_logs_key_does_not_verify_this_logs_timestamp() {
    // Production's key against a staging entry. Both are real Rekor keys, so this fails for the
    // reason that matters — the signature is over a different log's view — rather than for a parse.
    const PRODUCTION: &str = "-----BEGIN PUBLIC KEY-----\n\
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n\
        kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n\
        -----END PUBLIC KEY-----";
    let err = entry()
        .verify_set(PRODUCTION)
        .expect_err("a staging entry is not signed by production");
    assert!(
        format!("{err}").contains("when this entry existed"),
        "the message has to say what is lost: {err}"
    );
}

#[test]
fn the_entry_our_own_attestor_published_verifies() {
    // End to end: `trigon attest --store … --key … --rekor https://rekor.sigstage.dev` signed an
    // `equivalence/v1` statement, posted it, and stored what came back. This is that record, and
    // the point is that nothing in the path between the POST and the stored fields mangles the
    // bytes the SET covers — `body` especially, which has to survive verbatim.
    let e = our_run();
    let at = e
        .verify_set(LOG_KEY)
        .expect("the staging log signed our own entry");
    assert_eq!(at, e.integrated_at());
    assert_eq!(e.log_index, 56_041_854);
    assert_eq!(e.log_id, entry().log_id, "the same log signed both");
}

#[test]
fn re_encoding_the_body_breaks_the_timestamp() {
    // Why `body` is stored verbatim rather than rebuilt. Rekor signs its own serialization, and a
    // round trip that produces equivalent JSON produces a SET that verifies against nothing — with
    // a failure that reads exactly like a wrong key, which is the trap worth pinning.
    //
    // Note what this entry does *not* show: Rekor already emits sorted keys and no whitespace, so
    // a compact serde round trip happens to be byte-identical here. That near-miss is the argument
    // for the rule rather than against it — "equivalent JSON" is not a property anything upstream
    // promises, and the one transformation that is obviously harmless (pretty-printing what you
    // decoded) already destroys the signature.
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    let decoded: serde_json::Value =
        serde_json::from_slice(&b64.decode(&our_run().body).expect("the body is base64")).unwrap();

    let mut e = our_run();
    e.body = b64.encode(serde_json::to_vec_pretty(&decoded).expect("re-encodes"));
    assert_ne!(e.body, our_run().body);
    e.verify_set(LOG_KEY)
        .expect_err("a re-indented body is not the body the log signed");

    // And the compact form, which for this entry *is* the original bytes, still verifies — so the
    // failure above is the re-encoding and not the decode-and-rebuild itself.
    let mut same = our_run();
    same.body = b64.encode(serde_json::to_vec(&decoded).expect("re-encodes"));
    assert_eq!(
        same.body,
        our_run().body,
        "compact serde matches Rekor here"
    );
    same.verify_set(LOG_KEY)
        .expect("unchanged bytes still verify");
}
