//! The third-party verification walkthrough, run as a test.
//!
//! This is the claim the product actually makes: someone who does not trust us, holding the two
//! artifacts and our stabilizer implementation, can check the equivalence statement themselves. If
//! these tests pass, that sentence is true; if they are deleted, nothing else in the system enforces
//! it.

use trigon_archive::Limits;
use trigon_attest::{
    Envelope, LocalKey, Signer, Statement, Subject, Unsigned, rederive, sign_statement,
    subject_sha256, verify_signature,
};
use trigon_compare::compare_bytes;
use trigon_core::{Format, Match};
use trigon_stabilize::profile;

/// Two tars whose members are identical and whose build-environment metadata is not.
fn tar(mtime: u64, uid: u64) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, content) in [("pkg/a.txt", &b"hello"[..]), ("pkg/b.txt", &b"world"[..])] {
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

fn comparison(upstream: &[u8], rebuild: &[u8]) -> trigon_compare::Comparison {
    compare_bytes(
        upstream.to_vec(),
        rebuild.to_vec(),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap()
}

#[test]
fn a_statement_is_rederivable_from_the_two_artifacts_alone() {
    let (u, r) = (tar(1, 0), tar(999, 501));
    let c = comparison(&u, &r);
    assert_eq!(c.outcome, Match::Normalized);

    let st = Statement::equivalence("pkg-1.0.0.tar", &c);

    // The verifier's whole input: the statement, and two files. No registry, no network, no us.
    let out = rederive(&st, u, r).unwrap();
    assert!(out.holds(), "{out:?}");
    assert_eq!(out.claimed, "normalized");
    assert_eq!(out.actual, Match::Normalized);
}

#[test]
fn the_subject_is_the_upstream_artifact_so_a_consumer_can_find_it() {
    // Keyed on the rebuild, the statement would be unfindable by anyone who does not already have
    // our rebuild — which is everyone we are trying to convince.
    let (u, r) = (tar(1, 0), tar(2, 0));
    let c = comparison(&u, &r);
    let st = Statement::equivalence("pkg-1.0.0.tar", &c);
    assert_eq!(subject_sha256(&st).unwrap(), c.upstream.raw.sha256);
}

#[test]
fn a_tampered_digest_is_refuted_not_merely_unverified() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let c = comparison(&u, &r);
    let mut st = Statement::equivalence("pkg-1.0.0.tar", &c);
    st.predicate["stabilized"]["rebuild"]["sha256"] = serde_json::Value::String("00".repeat(32));

    let e = rederive(&st, u, r).unwrap_err();
    assert!(
        matches!(
            e,
            trigon_attest::AttestError::ClaimRefuted {
                side: "rebuild",
                ..
            }
        ),
        "{e}"
    );
}

#[test]
fn a_statement_made_under_a_different_stabilizer_set_is_refused_not_reinterpreted() {
    // The binding consequence of `verify-attestation`: re-deriving under today's set would answer a
    // different question than the statement asked, so a match would mean nothing.
    let (u, r) = (tar(1, 0), tar(2, 0));
    let c = comparison(&u, &r);
    let mut st = Statement::equivalence("pkg-1.0.0.tar", &c);
    st.predicate["stabilizerSet"]["digest"]["sha256"] = serde_json::Value::String("ab".repeat(32));

    let e = rederive(&st, u, r).unwrap_err();
    assert!(
        matches!(e, trigon_attest::AttestError::SetMismatch { .. }),
        "{e}"
    );
    assert!(e.to_string().contains("Refusing to compare"), "{e}");
}

#[test]
fn a_substituted_artifact_is_rejected_even_when_it_stabilizes_identically() {
    // The hole the stabilized-digest check alone leaves open. `tar(1, 7)` differs from `tar(1, 0)`
    // only in a uid, which the tar profile normalizes away — so every stabilized digest in the
    // statement still matches, and a verifier checking only those would report that the claim holds
    // while holding a file the statement was never about.
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));

    let swapped = tar(1, 7);
    assert_ne!(swapped, u, "the substitution has to be a different file");
    assert_eq!(
        comparison(&swapped, &r).upstream.stabilized.sha256,
        comparison(&u, &r).upstream.stabilized.sha256,
        "and has to stabilize to the same form, or it proves nothing"
    );

    let e = rederive(&st, swapped, r).unwrap_err();
    assert!(
        matches!(
            e,
            trigon_attest::AttestError::WrongArtifact {
                side: "upstream",
                ..
            }
        ),
        "{e}"
    );
    // Reported as the wrong file, not as a signed lie. The two are different findings and a
    // verifier that conflates them accuses us of fraud over a fat-fingered download.
    assert!(
        e.to_string()
            .contains("is not the one this statement is about"),
        "{e}"
    );
}

#[test]
fn the_rebuild_side_is_checked_too() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    let e = rederive(&st, u, tar(3, 0)).unwrap_err();
    assert!(
        matches!(
            e,
            trigon_attest::AttestError::WrongArtifact {
                side: "rebuild",
                ..
            }
        ),
        "{e}"
    );
}

#[test]
fn a_divergence_is_a_first_class_signed_claim() {
    let mut r = tar(1, 0);
    // Change a member body, not metadata: no stabilizer can normalize this away.
    let at = r.windows(5).position(|w| w == b"world").unwrap();
    r[at..at + 5].copy_from_slice(b"WORLD");

    let u = tar(1, 0);
    let c = comparison(&u, &r);
    assert_eq!(c.outcome, Match::Divergent);

    let st = Statement::equivalence("pkg-1.0.0.tar", &c);
    assert_eq!(st.predicate_type, trigon_attest::DIVERGENCE);
    assert_eq!(st.predicate["members"]["differs"], 1);

    // The deterministic difference signature, which is what separates a finding from an
    // accusation. A maintainer can go and look at the member this names; "your package does not
    // rebuild" gives them nothing to do.
    let codes = st.predicate["differences"]
        .as_array()
        .unwrap_or_else(|| panic!("a divergence must name its differences: {}", st.predicate));
    assert!(
        codes
            .iter()
            .any(|c| c.as_str().is_some_and(|s| s.starts_with("body@"))),
        "{codes:?}"
    );
    assert!(
        codes
            .iter()
            .any(|c| c.as_str().is_some_and(|s| s.contains("pkg/b.txt"))),
        "the differing member should be named: {codes:?}"
    );

    // And it re-derives like any other. A divergence a maintainer cannot reproduce is an accusation,
    // not a finding.
    let out = rederive(&st, u, r).unwrap();
    assert!(out.holds(), "{out:?}");
    assert_eq!(out.actual, Match::Divergent);
}

#[test]
fn a_match_names_no_differences() {
    // The field is absent rather than present-and-empty. A consumer checking `differences` as a
    // truthy value should not have to also check its length.
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    assert!(
        st.predicate.get("differences").is_none(),
        "{}",
        st.predicate
    );
}

#[test]
fn signing_covers_the_canonical_bytes_and_survives_a_round_trip() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));

    let key = LocalKey::generate();
    let env = sign_statement(&st, &key).unwrap();
    assert!(env.is_signed());

    let wire = serde_json::to_string(&env).unwrap();
    let back: Envelope = serde_json::from_str(&wire).unwrap();
    verify_signature(&back.pae().unwrap(), &back.signatures[0], &key.public_hex()).unwrap();

    // And the payload inside is the statement, byte for byte.
    assert_eq!(back.decoded_payload().unwrap(), st.canonical().unwrap());
    let parsed: Statement = serde_json::from_slice(&back.decoded_payload().unwrap()).unwrap();
    assert_eq!(parsed, st);
}

#[test]
fn editing_the_payload_breaks_the_signature() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    let key = LocalKey::generate();
    let mut env = sign_statement(&st, &key).unwrap();

    let mut doc: Statement = serde_json::from_slice(&env.decoded_payload().unwrap()).unwrap();
    doc.predicate["outcome"] = serde_json::Value::String("exact".into());
    env = Envelope::new(&doc.canonical().unwrap(), env.signatures);

    let e =
        verify_signature(&env.pae().unwrap(), &env.signatures[0], &key.public_hex()).unwrap_err();
    assert!(matches!(e, trigon_attest::AttestError::BadSignature), "{e}");
}

#[test]
fn a_signature_from_another_key_does_not_verify() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    let env = sign_statement(&st, &LocalKey::generate()).unwrap();
    let other = LocalKey::generate();
    assert!(
        verify_signature(&env.pae().unwrap(), &env.signatures[0], &other.public_hex()).is_err()
    );
}

#[test]
fn an_unsigned_bundle_is_a_complete_claim_that_names_nobody() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    let env = sign_statement(&st, &Unsigned).unwrap();

    // Unsigned and "signed by someone you do not trust" must not collapse into one answer.
    assert!(!env.is_signed());
    // But the claim is intact and still falsifiable, which is the part that carries the value.
    let out = rederive(
        &serde_json::from_slice(&env.decoded_payload().unwrap()).unwrap(),
        u,
        r,
    )
    .unwrap();
    assert!(out.holds());
}

#[test]
fn a_key_id_is_derived_from_the_key_not_chosen() {
    // A name can be reused for a different key. A digest of the public key cannot.
    let k = LocalKey::generate();
    let same = LocalKey::from_bytes(&k.seed()).unwrap();
    assert_eq!(k.key_id(), same.key_id());
    assert_ne!(k.key_id(), LocalKey::generate().key_id());
    assert_eq!(k.key_id().len(), 16);
}

#[test]
fn the_provenance_cap_is_stated_in_the_predicate_not_left_to_be_rederived() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    assert_eq!(st.predicate["provenanceCap"]["allBuiltin"], true);
    // A consumer re-deriving our rule could re-derive it differently.
    assert!(st.predicate["provenanceCap"]["maxRiskApplied"].is_string());
}

#[test]
fn canonical_bytes_do_not_depend_on_how_the_statement_was_built() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    // Round-tripping through JSON reorders nothing that matters: canonicalization is what a
    // signature covers, so two spellings of one statement must hash identically.
    let reparsed: Statement = serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap();
    assert_eq!(st.canonical().unwrap(), reparsed.canonical().unwrap());
}

// --- Subjects carry every digest a consumer might hold (docs/19 §5) ------------------------------

#[test]
fn a_subject_carries_sha512_beside_sha256_and_both_are_of_the_upstream_bytes() {
    // An npm lockfile names a package by its sha512 `integrity`, and a statement keyed on sha256
    // alone is unfindable from it. Both digests are computed over the bytes, never copied from a
    // registry's declaration.
    use sha2::Digest as _;
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    let d = &st.subject[0].digest;
    assert_eq!(
        d.keys().map(String::as_str).collect::<Vec<_>>(),
        ["sha256", "sha512"],
        "no sha1: this caller named no ecosystem that publishes one"
    );
    assert_eq!(d["sha256"], hex(&sha2::Sha256::digest(&u)));
    assert_eq!(d["sha512"], hex(&sha2::Sha512::digest(&u)));
    assert!(rederive(&st, u, r).unwrap().holds());
}

#[test]
fn a_subject_for_an_ecosystem_that_publishes_sha1_carries_it_and_it_is_checked() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let subject = Subject::of_bytes("pkg-1.0.0.tgz", &u, true);
    let st = Statement::equivalence_for(subject, &comparison(&u, &r)).unwrap();
    let d = &st.subject[0].digest;
    assert_eq!(
        d.keys().map(String::as_str).collect::<Vec<_>>(),
        ["sha1", "sha256", "sha512"]
    );
    assert_eq!(d["sha1"], trigon_attest::sha1_of(&u).to_hex());
    assert!(rederive(&st, u.clone(), r.clone()).unwrap().holds());

    // A sha1 that is not of these bytes is a statement whose digests were not all computed over
    // one file, and it is refused by name rather than trusted because sha256 agreed: refuted,
    // since sha256 says the file is the artifact, and not the wrong file handed in.
    let mut wrong = st.clone();
    wrong.subject[0]
        .digest
        .insert("sha1".into(), "00".repeat(20));
    let e = rederive(&wrong, u, r).unwrap_err();
    assert!(
        matches!(
            &e,
            trigon_attest::AttestError::SubjectRefuted { algorithm, .. } if algorithm == "sha1"
        ),
        "{e}"
    );
    assert!(e.to_string().contains("sha1"), "{e}");
    assert!(e.fails_verification(), "{e}");
}

#[test]
fn a_tampered_sha512_in_the_subject_is_refused_even_though_sha256_agrees() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let mut st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    st.subject[0]
        .digest
        .insert("sha512".into(), "ab".repeat(64));
    let e = rederive(&st, u, r).unwrap_err();
    assert!(
        matches!(
            &e,
            trigon_attest::AttestError::SubjectRefuted { algorithm, .. } if algorithm == "sha512"
        ),
        "{e}"
    );
    assert!(e.fails_verification(), "{e}");
}

#[test]
fn a_statement_signed_with_a_sha256_only_subject_still_verifies() {
    // Every statement signed before subjects carried more than sha256. A verifier checks the
    // digests a subject names and no others, so the old shape verifies exactly as it did.
    let (u, r) = (tar(1, 0), tar(2, 0));
    let mut st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    st.subject = vec![Subject::new("pkg-1.0.0.tar", &subject_sha256(&st).unwrap())];
    let key = LocalKey::generate();
    let env = sign_statement(&st, &key).unwrap();
    verify_signature(&env.pae().unwrap(), &env.signatures[0], &key.public_hex()).unwrap();
    let back: Statement = serde_json::from_slice(&env.decoded_payload().unwrap()).unwrap();
    assert_eq!(back.subject[0].digest.len(), 1);
    assert!(rederive(&back, u, r).unwrap().holds());
}

#[test]
fn a_subject_about_other_bytes_is_refused_before_it_can_be_signed() {
    // `equivalence_for` takes the subject from the caller. One computed over some other file would
    // make a statement whose subject and whose `artifacts.upstream` disagree.
    let (u, r) = (tar(1, 0), tar(2, 0));
    let other = Subject::of_bytes("pkg-1.0.0.tgz", &tar(5, 0), true);
    let e = Statement::equivalence_for(other, &comparison(&u, &r)).unwrap_err();
    assert!(
        matches!(
            e,
            trigon_attest::AttestError::WrongArtifact {
                side: "upstream",
                ..
            }
        ),
        "{e}"
    );
}

#[test]
fn a_subject_whose_sha512_is_of_other_bytes_is_refused_though_its_sha256_agrees() {
    // `rebuild --attest` and `verify --attest` sign what `equivalence_for` returns without
    // re-deriving, so this comparison is the only check there. A subject carrying the right sha256
    // beside another file's sha512 would be found by a consumer holding that other file's npm
    // `integrity`, and tell them about bytes they do not have.
    let (u, r) = (tar(1, 0), tar(2, 0));
    let c = comparison(&u, &r);
    let other = trigon_attest::sha512_of(&tar(5, 0));
    let subject = Subject::with_digests("pkg-1.0.0.tar", &c.upstream.raw.sha256, &other, None);
    let e = Statement::equivalence_for(subject, &c).unwrap_err();
    assert!(
        matches!(
            &e,
            trigon_attest::AttestError::WrongArtifact { side: "upstream", algorithm, .. }
                if algorithm == "sha512"
        ),
        "{e}"
    );

    // And the subject computed over the right bytes is accepted, so the refusal above is about
    // the sha512 and nothing else.
    let right = Subject::of_bytes("pkg-1.0.0.tar", &u, true);
    assert!(Statement::equivalence_for(right, &c).is_ok());
}

#[test]
fn a_subject_digest_the_verifier_cannot_compute_is_not_passed_over() {
    // Absent a way to check it, a digest is reported as unchecked, never taken as agreeing.
    let (u, r) = (tar(1, 0), tar(2, 0));
    let mut st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    st.subject[0]
        .digest
        .insert("blake2b_256".into(), "00".repeat(32));
    let e = rederive(&st, u, r).unwrap_err();
    assert!(matches!(e, trigon_attest::AttestError::Malformed(_)), "{e}");
    assert!(e.to_string().contains("blake2b_256"), "{e}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A key or a signature that is not one is refused as what it is, and never verifies: a key of an
/// odd number of hex digits, or not hex, or not 32 bytes; a signature not base64, or not 64 bytes.
#[test]
fn a_key_or_a_signature_that_is_not_one_never_verifies() {
    let key = LocalKey::from_bytes(&[7u8; 32]).unwrap();
    let (u, r) = (tar(1, 0), tar(2, 0));
    let st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    let env = sign_statement(&st, &key).unwrap();
    let pae = env.pae().unwrap();
    let hex = key.public_hex();
    for bad in [&hex[1..], &format!("zz{}", &hex[2..]), &hex[..62]] {
        let e = verify_signature(&pae, &env.signatures[0], bad).unwrap_err();
        assert!(
            matches!(e, trigon_attest::AttestError::Key(_)),
            "{bad}: {e}"
        );
    }
    let mut sig = env.signatures[0].clone();
    sig.sig = "not base64!".into();
    let e = verify_signature(&pae, &sig, &hex).unwrap_err();
    assert!(matches!(e, trigon_attest::AttestError::Evidence(_)), "{e}");
    sig.sig = "AAAA".into();
    let e = verify_signature(&pae, &sig, &hex).unwrap_err();
    assert!(e.to_string().contains("64 bytes"), "{e}");
    verify_signature(&pae, &env.signatures[0], &hex).unwrap();
}

/// An equivalence subject names the upstream sha256 the comparison is keyed on, or it is refused;
/// one naming sha256 alone, as every subject signed before sha512 did, is accepted.
#[test]
fn an_equivalence_subject_without_the_upstream_sha256_is_refused() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let c = comparison(&u, &r);
    let mut no_sha256 = Subject::of_bytes("pkg-1.0.0.tar", &u, true);
    no_sha256.digest.remove("sha256");
    let e = Statement::equivalence_for(no_sha256, &c).unwrap_err();
    assert!(matches!(e, trigon_attest::AttestError::Malformed(_)), "{e}");
    assert!(e.to_string().contains("sha256"), "{e}");
    let st = Statement::equivalence_for(Subject::new("pkg-1.0.0.tar", &c.upstream.raw.sha256), &c)
        .unwrap();
    assert_eq!(st.subject[0].digest.len(), 1);
}

/// A member whose name is not UTF-8 is held to a published report by its bytes, which no text
/// equals: the report of the same comparison agrees, member by member.
#[cfg(unix)]
#[test]
fn a_member_whose_name_is_not_utf8_is_held_to_the_report_by_its_bytes() {
    use std::os::unix::ffi::OsStrExt as _;
    let archive = |mtime: u64, body: &[u8]| {
        let mut b = ::tar::Builder::new(Vec::new());
        let mut h = ::tar::Header::new_ustar();
        h.set_path(std::ffi::OsStr::from_bytes(b"pkg/\xff.txt"))
            .unwrap();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(mtime);
        h.set_cksum();
        b.append(&h, body).unwrap();
        b.into_inner().unwrap()
    };
    let (u, r) = (archive(1, b"hello"), archive(2, b"world"));
    let c = comparison(&u, &r);
    let member = &c.diff.as_ref().unwrap().files[0].path;
    assert!(
        std::str::from_utf8(member.as_bytes()).is_err(),
        "{member:?}"
    );
    let st = Statement::equivalence("pkg-1.0.0.tar", &c);
    let d = rederive(&st, u, r).unwrap();
    assert!(d.holds(), "{d:?}");
    let checked = d
        .check_report(&serde_json::to_vec(&c).unwrap())
        .unwrap()
        .unwrap();
    assert!(checked.agrees(), "{:?}", checked.disagreements);
}

/// An archive format this build does not know is refused as damaged evidence, never guessed at.
#[test]
fn an_archive_format_this_build_does_not_know_is_refused() {
    let (u, r) = (tar(1, 0), tar(2, 0));
    let mut st = Statement::equivalence("pkg-1.0.0.tar", &comparison(&u, &r));
    st.predicate["archiveFormat"] = "rar".into();
    let e = rederive(&st, u, r).unwrap_err();
    assert!(matches!(e, trigon_attest::AttestError::Evidence(_)), "{e}");
}
