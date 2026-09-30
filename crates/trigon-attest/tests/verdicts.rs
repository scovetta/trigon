//! What a published record's statement signs: the v2 verdicts, `void/v1` and `withdrawal/v1`, and
//! that everything signed before them still verifies.
//!
//! `docs/19` §4.2's list, one field at a time, at the library. `crates/trigon/tests/` holds the
//! same list through `trigon attest`, which is where the facts come from a stored run.

use trigon_archive::{Archive, Entry, Limits};
use trigon_attest::{
    ArchivedStabilizer, AttestError, AuthoredPass, DIVERGENCE_V2, EQUIVALENCE_V2, Envelope,
    EvidenceDigests, FalsifyingCommand, LocalKey, REBUILD, Record, RunFacts, RunIdentity,
    Signer as _, Statement, Subject, SupersedeReason, Supersession, VOID, VerdictFacts, VoidFacts,
    WITHDRAWAL, rederive, rederive_with, sign_statement, verify_signature,
};
use trigon_compare::compare_bytes;
use trigon_core::purl::canonicalize;
use trigon_core::{Digest, Format, StabilizerId};
use trigon_stabilize::{Cx, Stabilizer, StabilizerSet, profile};

fn tar(mtime: u64, body: &[u8]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(mtime);
    h.set_cksum();
    b.append_data(&mut h, "package/index.js", body).unwrap();
    b.into_inner().unwrap()
}

fn comparison(u: &[u8], r: &[u8]) -> trigon_compare::Comparison {
    compare_bytes(
        u.to_vec(),
        r.to_vec(),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap()
}

const PURL: &str = "pkg:npm/demo@1.0.0";
const ORIGIN: &str = "github.com/owner/trigon-evidence";
const DISPUTES: &str = "https://github.com/owner/trigon-evidence/issues";

fn identity(purl: &trigon_core::purl::CanonicalPurl) -> RunIdentity<'_> {
    RunIdentity {
        purl,
        run_id: "1789000000-aaaaaaaa",
        started: "2026-09-27T00:00:00Z",
        finished: Some("2026-09-27T00:02:00Z"),
        builder_version: Some("0.0.0+git.1111111111111111111111111111111111111111"),
        attestor_version: "0.0.0+git.2222222222222222222222222222222222222222",
        egress: "mirror-only",
        attestable: true,
    }
}

fn evidence() -> EvidenceDigests<'static> {
    EvidenceDigests {
        stabilizer_set_manifest: Some("51d0"),
        comparison: Some("3d88"),
        strategy: Some("b02f"),
        guard_manifest: Some("e5c9"),
        rebuilt_artifact: Some("a91c"),
    }
}

fn facts(purl: &trigon_core::purl::CanonicalPurl) -> VerdictFacts<'_> {
    VerdictFacts {
        run: identity(purl),
        derivation: Some("heuristic"),
        evidence: evidence(),
        namespace: Some((ORIGIN, DISPUTES)),
        supersedes: None,
    }
}

fn subject(bytes: &[u8]) -> Subject {
    Subject::of_bytes("demo-1.0.0.tar", bytes, true)
}

#[test]
fn a_v2_verdict_carries_every_field_docs_19_asks_for() {
    let (u, r) = (tar(1, b"x"), tar(2, b"x"));
    let c = comparison(&u, &r);
    let purl = canonicalize(PURL).unwrap();
    let st = Statement::verdict(subject(&u), &c, &facts(&purl)).unwrap();
    let p = &st.predicate;
    assert_eq!(st.predicate_type, EQUIVALENCE_V2);

    // 1. The outcome, as a string.
    assert_eq!(p["outcome"], "normalized");
    // 2. The stabilizer set, id and digest.
    assert_eq!(p["stabilizerSet"]["id"], "tar");
    assert_eq!(
        p["stabilizerSet"]["digest"]["sha256"],
        profile("tar").unwrap().digest().to_hex()
    );
    // 3. When, and which Trigon: the one that built and the one that signs.
    assert_eq!(p["run"]["id"], "1789000000-aaaaaaaa");
    assert_eq!(p["run"]["startedOn"], "2026-09-27T00:00:00Z");
    assert_eq!(p["run"]["finishedOn"], "2026-09-27T00:02:00Z");
    assert_eq!(
        p["trigonVersion"]["builder"],
        "0.0.0+git.1111111111111111111111111111111111111111"
    );
    assert_eq!(
        p["trigonVersion"]["attestor"],
        "0.0.0+git.2222222222222222222222222222222222222222"
    );
    // 4. The egress tier and `attestable`, in the verdict itself.
    assert_eq!(p["egressTier"], "mirror-only");
    assert_eq!(p["attestable"], true);
    // 5. The derivation method.
    assert_eq!(p["derivation"]["method"], "heuristic");
    // 6. The falsifying command and the dispute pointer.
    assert_eq!(
        FalsifyingCommand {
            argv: serde_json::from_value(p["falsifyingCommand"]["argv"].clone()).unwrap()
        }
        .render(),
        format!(
            "trigon verify-attestation --lookup sha256:{} --predicate {EQUIVALENCE_V2} --origin \
             {ORIGIN} --rerun-comparison --upstream <file>",
            c.upstream.raw.sha256.to_hex()
        )
    );
    assert_eq!(
        p["disputePointer"],
        serde_json::json!({ "kind": "url", "url": DISPUTES })
    );
    // 7. The evidence digests, the set manifest's file among them.
    for (key, digest) in [
        ("stabilizerSetManifest", "51d0"),
        ("comparison", "3d88"),
        ("strategy", "b02f"),
        ("guardManifest", "e5c9"),
        ("rebuiltArtifact", "a91c"),
    ] {
        assert_eq!(p["evidence"][key]["sha256"], digest, "{key}");
    }
    // 8. The canonical purl and its canonicalisation version.
    assert_eq!(p["purl"], PURL);
    assert_eq!(p["purlCanon"], 1);
    // 9. Not superseding anything, so no supersession.
    assert!(p.get("supersedes").is_none() && p.get("reason").is_none());

    // It is signable, and it re-derives: v2 is v1 with fields added.
    assert!(st.canonical().is_ok());
    let out = rederive(&st, u, r).unwrap();
    assert!(out.holds(), "{out:?}");
}

#[test]
fn a_v2_verdict_keeps_every_v1_field_where_it_was() {
    // So one verifier reads both versions, and nothing a v1 reader looked for has moved.
    let (u, r) = (tar(1, b"x"), tar(2, b"y"));
    let c = comparison(&u, &r);
    let purl = canonicalize(PURL).unwrap();
    let v1 = Statement::equivalence_for(subject(&u), &c).unwrap();
    let v2 = Statement::verdict(subject(&u), &c, &facts(&purl)).unwrap();
    assert_eq!(v1.subject, v2.subject);
    for (key, value) in v1.predicate.as_object().unwrap() {
        assert_eq!(&v2.predicate[key], value, "`{key}` moved or changed in v2");
    }
    // And a divergence is a `divergence/v2`, with its difference signature still in it.
    assert_eq!(v2.predicate_type, DIVERGENCE_V2);
    assert_eq!(v2.predicate["outcome"], "divergent");
    assert!(v2.predicate["differences"].is_array());
    assert!(rederive(&v2, u, r).unwrap().holds());
}

#[test]
fn without_an_origin_and_a_dispute_channel_neither_is_signed() {
    // Absent rather than empty: a statement made for local use names no repository.
    let (u, r) = (tar(1, b"x"), tar(2, b"x"));
    let c = comparison(&u, &r);
    let purl = canonicalize(PURL).unwrap();
    let st = Statement::verdict(
        subject(&u),
        &c,
        &VerdictFacts {
            namespace: None,
            ..facts(&purl)
        },
    )
    .unwrap();
    assert!(st.predicate.get("falsifyingCommand").is_none());
    assert!(st.predicate.get("disputePointer").is_none());
    assert!(!st.canonical().unwrap().windows(6).any(|w| w == b"origin"));
}

#[test]
fn what_a_run_did_not_record_is_absent_from_its_verdict() {
    let (u, r) = (tar(1, b"x"), tar(2, b"x"));
    let c = comparison(&u, &r);
    let purl = canonicalize(PURL).unwrap();
    let st = Statement::verdict(
        subject(&u),
        &c,
        &VerdictFacts {
            run: RunIdentity {
                finished: None,
                builder_version: None,
                ..identity(&purl)
            },
            derivation: None,
            evidence: EvidenceDigests {
                strategy: None,
                guard_manifest: None,
                ..evidence()
            },
            ..facts(&purl)
        },
    )
    .unwrap();
    let p = &st.predicate;
    // A run with no derivation was signed as `heuristic`, which is absence rendered as a value.
    assert!(p.get("derivation").is_none(), "{p}");
    assert!(p["trigonVersion"].get("builder").is_none());
    assert!(p["trigonVersion"]["attestor"].is_string());
    assert!(p["run"].get("finishedOn").is_none());
    assert!(p["evidence"].get("strategy").is_none());
    assert!(p["evidence"].get("guardManifest").is_none());
    assert_eq!(p["evidence"]["comparison"]["sha256"], "3d88");
}

#[test]
fn a_superseding_verdict_signs_what_it_supersedes_and_why() {
    let (u, r) = (tar(1, b"x"), tar(2, b"x"));
    let c = comparison(&u, &r);
    let purl = canonicalize(PURL).unwrap();
    let record = Digest::from_bytes([0x7f; 32]);
    let st = Statement::verdict(
        subject(&u),
        &c,
        &VerdictFacts {
            supersedes: Some(Supersession {
                record,
                reason: SupersedeReason::SetChanged,
            }),
            ..facts(&purl)
        },
    )
    .unwrap();
    assert_eq!(
        st.predicate["supersedes"],
        format!("sha256:{}", record.to_hex())
    );
    assert_eq!(st.predicate["reason"], "set_changed");
}

#[test]
fn the_reasons_are_a_closed_list() {
    for (s, r) in [
        ("withdrawn", SupersedeReason::Withdrawn),
        ("set_changed", SupersedeReason::SetChanged),
        (
            "attempts_disagree_later",
            SupersedeReason::AttemptsDisagreeLater,
        ),
        ("pipeline_bug", SupersedeReason::PipelineBug),
    ] {
        assert_eq!(s.parse::<SupersedeReason>().unwrap(), r);
        assert_eq!(r.to_string(), s);
    }
    let e = "wrong".parse::<SupersedeReason>().unwrap_err().to_string();
    assert!(
        e.contains("withdrawn, set_changed, attempts_disagree_later, pipeline_bug"),
        "{e}"
    );
}

fn void_facts<'a>(
    purl: &'a trigon_core::purl::CanonicalPurl,
    trips: &'a [String],
    authored: &'a [AuthoredPass],
) -> VoidFacts<'a> {
    VoidFacts {
        run: RunIdentity {
            egress: "mirror-only",
            ..identity(purl)
        },
        because: "guard_tripped",
        guard_trips: trips,
        guard_manifest: Some("e5c9"),
        guarded_members: Some(3),
        authored,
        stabilizer_set: Some(("tar", "2b7c")),
        guard_manifest_evidence: Some("e5c9"),
        supersedes: None,
    }
}

#[test]
fn a_void_carries_why_and_the_facts_and_nothing_about_which_way_the_run_went() {
    let purl = canonicalize(PURL).unwrap();
    let trips = vec!["package/index.js arrived from registry.npmjs.org".to_string()];
    let authored = vec![AuthoredPass {
        id: "demo-banner".into(),
        risk: "content".into(),
        provenance: "human".into(),
    }];
    let st = Statement::void(subject(b"x"), &void_facts(&purl, &trips, &authored));
    let p = &st.predicate;
    assert_eq!(st.predicate_type, VOID);
    assert_eq!(p["outcome"], "void");
    assert_eq!(p["because"], "guard_tripped");
    assert_eq!(p["facts"]["artifactHashCheck"]["performed"], true);
    assert_eq!(p["facts"]["artifactHashCheck"]["trips"][0], trips[0]);
    assert_eq!(
        p["facts"]["artifactHashCheck"]["guardManifest"]["sha256"],
        "e5c9"
    );
    assert_eq!(p["facts"]["artifactHashCheck"]["guardedMembers"], 3);
    assert_eq!(p["facts"]["authoredStabilizers"][0]["id"], "demo-banner");
    assert_eq!(p["egressTier"], "mirror-only");
    assert_eq!(p["purl"], PURL);
    assert_eq!(p["purlCanon"], 1);
    assert_eq!(p["stabilizerSet"]["id"], "tar");
    assert_eq!(
        p["evidence"],
        serde_json::json!({ "guardManifest": { "sha256": "e5c9" } })
    );

    // No comparison outcome and no difference data: nothing a reader could tell `exact` from
    // `divergent` by.
    for absent in [
        "artifacts",
        "stabilized",
        "applied",
        "members",
        "differences",
        "container",
        "containerBitIdentical",
        "provenanceCap",
        "falsifyingCommand",
        "disputePointer",
    ] {
        assert!(p.get(absent).is_none(), "a void carries `{absent}`: {p}");
    }
    for absent in ["comparison", "rebuiltArtifact", "strategy"] {
        assert!(p["evidence"].get(absent).is_none(), "{absent}: {p}");
    }

    // And nothing re-derives it, said as such rather than as a missing field.
    let e = rederive(&st, b"x".to_vec(), b"x".to_vec())
        .unwrap_err()
        .to_string();
    assert!(e.contains("makes no comparison claim"), "{e}");
    assert!(st.canonical().is_ok());
}

#[test]
fn a_void_the_guard_stopped_before_any_comparison_names_no_set() {
    let purl = canonicalize(PURL).unwrap();
    let st = Statement::void(
        subject(b"x"),
        &VoidFacts {
            stabilizer_set: None,
            guard_manifest: None,
            guarded_members: None,
            guard_manifest_evidence: None,
            ..void_facts(&purl, &[], &[])
        },
    );
    assert!(st.predicate.get("stabilizerSet").is_none());
    assert_eq!(
        st.predicate["facts"]["artifactHashCheck"]["performed"],
        false
    );
    assert!(st.predicate["facts"].get("authoredStabilizers").is_none());
    assert_eq!(st.predicate["evidence"], serde_json::json!({}));
}

#[test]
fn a_withdrawal_names_what_it_withdraws_and_why_and_no_verdict() {
    let record = Digest::from_bytes([0x7f; 32]);
    let s = subject(b"x");
    let st = Statement::withdrawal(
        s.clone(),
        PURL,
        1,
        Supersession {
            record,
            reason: SupersedeReason::Withdrawn,
        },
        "0.0.0+git.2222222222222222222222222222222222222222",
    );
    assert_eq!(st.predicate_type, WITHDRAWAL);
    assert_eq!(st.subject, [s]);
    let p = &st.predicate;
    assert_eq!(p["supersedes"], format!("sha256:{}", record.to_hex()));
    assert_eq!(p["reason"], "withdrawn");
    assert_eq!(p["purl"], PURL);
    assert_eq!(p["purlCanon"], 1);
    assert!(
        p.get("outcome").is_none(),
        "a withdrawal has no verdict: {p}"
    );
    assert!(p["trigonVersion"].get("builder").is_none(), "and no run");
    assert!(rederive(&st, vec![], vec![]).is_err());
}

#[test]
fn a_rebuild_statement_with_the_set_still_reads_in_the_types_a_verifier_already_has() {
    // `rebuild` gains `stabilizerSet` and stays v1, which works only because nothing that reads a
    // statement refuses a field it does not know. Asserted here, through the types
    // `verify-attestation` reads with, so adding `deny_unknown_fields` to either breaks this.
    let d = Digest::from_bytes([1; 32]);
    let st = Statement::rebuild(
        Subject::new("demo-1.0.0.tgz", &d),
        &RunFacts {
            run_id: "r",
            started: "t",
            stabilizer_set: Some(("tar", "2b7c")),
            ..RunFacts::default()
        },
    );
    assert_eq!(st.predicate_type, REBUILD);
    assert_eq!(st.predicate["stabilizerSet"]["id"], "tar");
    let key = LocalKey::from_bytes(&[3; 32]).unwrap();
    let env = sign_statement(&st, &key).unwrap();
    let wire = serde_json::to_vec(&env).unwrap();

    let read: Envelope = serde_json::from_slice(&wire).unwrap();
    let back: Statement = serde_json::from_slice(&read.decoded_payload().unwrap()).unwrap();
    assert_eq!(back, st);
    assert!(verify_signature(&read.pae().unwrap(), &read.signatures[0], &key.public_hex()).is_ok());
    assert_eq!(read.signatures[0].keyid, key.key_id());

    // And a field no version of Trigon writes, at every level a reader parses.
    let mut v: serde_json::Value = serde_json::from_slice(&back.canonical().unwrap()).unwrap();
    v["aFieldFromTheFuture"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Statement>(v).is_ok());
    let mut e: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    e["aFieldFromTheFuture"] = serde_json::json!(1);
    e["signatures"][0]["alsoFromTheFuture"] = serde_json::json!(1);
    assert!(serde_json::from_value::<Envelope>(e).is_ok());
}

/// The v1 bundles `trigon verify --attest` signed at `255d2f5`, before any of this existed.
const V1: &str = "../trigon/tests/fixtures/v1-statements";

/// A pass under the id it had when the v1 bundles were signed. On their artifacts, a flat `.tgz`
/// with nothing nested in it, each writes what it wrote then, and the digests below prove it.
#[derive(Debug)]
struct AsSigned(&'static str, std::sync::Arc<dyn Stabilizer>);

impl Stabilizer for AsSigned {
    fn id(&self) -> StabilizerId {
        StabilizerId::new(self.0)
    }
    fn stage(&self) -> trigon_stabilize::Stage {
        self.1.stage()
    }
    fn risk(&self) -> trigon_core::RiskTier {
        self.1.risk()
    }
    fn provenance(&self) -> trigon_core::Provenance {
        self.1.provenance()
    }
    fn applies(&self, cx: &Cx) -> bool {
        self.1.applies(cx)
    }
    fn on_archive(&self, a: &mut Archive, cx: &Cx) -> trigon_stabilize::Touched {
        self.1.on_archive(a, cx)
    }
    fn on_entry(&self, e: &mut Entry, cx: &Cx) -> trigon_stabilize::Touched {
        self.1.on_entry(e, cx)
    }
}

/// The `tar-gzip` set the v1 bundles name: today's, with the two passes renamed since
/// (`docs/16-findings.md` §3.106) under the ids they had.
fn tar_gzip_as_signed() -> StabilizerSet {
    let members = profile("tar-gzip")
        .unwrap()
        .members
        .into_iter()
        .map(|m| match m.id().as_str() {
            "gzip-meta-v2" => std::sync::Arc::new(AsSigned("gzip-meta", m)) as _,
            "tar-entry-order-v2" => std::sync::Arc::new(AsSigned("tar-entry-order", m)) as _,
            _ => m,
        })
        .collect();
    StabilizerSet::new("tar-gzip", members)
}

/// The module a verifier would load for that set: stabilized bytes, and no report.
struct Archived;

impl ArchivedStabilizer for Archived {
    fn digest(&mut self, profile_id: &str) -> Result<Digest, String> {
        match profile_id {
            "tar-gzip" => Ok(tar_gzip_as_signed().digest()),
            other => Err(format!("this module carries `tar-gzip`, not `{other}`")),
        }
    }

    fn stabilize(&mut self, _: &str, format: Format, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let set = tar_gzip_as_signed();
        let (_, archive) =
            trigon_compare::summarize(bytes.to_vec(), format, &set, &Limits::default())
                .map_err(|e| e.to_string())?;
        trigon_archive::serialize(&archive, true).map_err(|e| e.to_string())
    }
}

#[test]
fn a_v1_bundle_signed_before_v2_existed_still_verifies_and_rederives() {
    // Its signature verifies as it always did. Its set is the `tar-gzip` of `255d2f5`, which
    // today's is not since two of its passes took new ids, so today's refuses to re-derive it as
    // a set mismatch, which refutes nothing, and the set it was signed under re-derives it.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(V1);
    let public = std::fs::read_to_string(dir.join("public.hex")).unwrap();
    let upstream = std::fs::read(dir.join("demo-1.0.0.tgz")).unwrap();
    for (bundle, rebuilt, outcome, through_a_module) in [
        (
            "equivalence-v1.intoto.json",
            "rebuilt-demo-1.0.0.tgz",
            "normalized",
            // A module returns bytes and no tiers, so a match it re-derives is caveated at best.
            "normalized_with_caveats",
        ),
        (
            "divergence-v1.intoto.json",
            "diverged-demo-1.0.0.tgz",
            "divergent",
            "divergent",
        ),
    ] {
        let env: Envelope =
            serde_json::from_slice(&std::fs::read(dir.join(bundle)).unwrap()).unwrap();
        assert!(
            verify_signature(&env.pae().unwrap(), &env.signatures[0], public.trim()).is_ok(),
            "{bundle}"
        );
        let st: Statement = serde_json::from_slice(&env.decoded_payload().unwrap()).unwrap();
        assert!(st.predicate_type.ends_with("/v1"), "{bundle}");
        let rebuilt = std::fs::read(dir.join(rebuilt)).unwrap();

        let e = rederive(&st, upstream.clone(), rebuilt.clone()).unwrap_err();
        let AttestError::SetMismatch { claimed, .. } = &e else {
            panic!("{bundle}: expected a set mismatch, got {e}");
        };
        assert_eq!(
            claimed,
            &format!("tar-gzip@{}", &tar_gzip_as_signed().digest().to_hex()[..12])
        );
        assert!(!e.fails_verification(), "{bundle}: {e}");

        let out = rederive_with(&st, upstream.clone(), rebuilt, Some(&mut Archived)).unwrap();
        assert!(out.digests_match, "{bundle}: {out:?}");
        assert_eq!(out.claimed, outcome);
        assert_eq!(out.actual.to_string(), through_a_module, "{bundle}");
    }
}

#[test]
fn a_record_file_is_read_and_its_result_found() {
    let (u, r) = (tar(1, b"x"), tar(2, b"x"));
    let c = comparison(&u, &r);
    let purl = canonicalize(PURL).unwrap();
    let key = LocalKey::from_bytes(&[3; 32]).unwrap();
    let verdict = Statement::verdict(subject(&u), &c, &facts(&purl)).unwrap();
    let rebuild = Statement::rebuild(
        Subject::new("x", &Digest::from_bytes([1; 32])),
        &RunFacts::default(),
    );
    // The verdict second, so finding it is by type and not by position.
    let text = serde_json::json!({
        "schema": "trigon.record/v1",
        "subject": { "purl": PURL, "digests": verdict.subject[0].digest },
        "statements": [
            sign_statement(&rebuild, &key).unwrap(),
            sign_statement(&verdict, &key).unwrap(),
        ],
        "evidence": { "comparison": "sha256:3d88" },
        "aFieldFromTheFuture": 1,
    })
    .to_string();
    let record = Record::from_slice(text.as_bytes()).unwrap();
    assert_eq!(record.subject.purl, PURL);
    assert_eq!(record.evidence["comparison"], "sha256:3d88");
    assert_eq!(record.statement().unwrap(), verdict);
    // Named by the sha256 of its own bytes.
    use sha2::Digest as _;
    assert_eq!(
        Record::digest_of(text.as_bytes()).as_bytes()[..],
        sha2::Sha256::digest(text.as_bytes())[..]
    );

    let other = text.replace("trigon.record/v1", "trigon.record/v9");
    let e = Record::from_slice(other.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(e.contains("trigon.record/v9"), "{e}");
    assert!(Record::from_slice(b"{}").is_err());

    // A record of nothing but a rebuild statement has no result to supersede.
    let bare = serde_json::json!({
        "schema": "trigon.record/v1",
        "subject": { "purl": PURL, "digests": {} },
        "statements": [sign_statement(&rebuild, &key).unwrap()],
    })
    .to_string();
    let e = Record::from_slice(bare.as_bytes())
        .unwrap()
        .statement()
        .unwrap_err()
        .to_string();
    assert!(e.contains("no verdict, void or withdrawal"), "{e}");
}

#[test]
fn the_set_manifest_file_is_canonical_json_and_not_the_set_digest() {
    let set = profile("tar").unwrap();
    let m = set.manifest();
    let bytes = trigon_attest::set_manifest_file(&m).unwrap();
    let back: trigon_stabilize::SetManifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back, m);
    // Canonical: parsed and written again it is the same bytes.
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        trigon_core::jcs::canonicalize(&v).unwrap().into_bytes(),
        bytes
    );
    // And its digest is a different number from the set digest, which is over rows, not a file.
    let file = Subject::of_bytes("m", &bytes, false).digest["sha256"].clone();
    assert_ne!(file, set.digest().to_hex());
}

/// A void may supersede an earlier record — a later run looked again and could not tell — and signs
/// what it supersedes and why inside its statement, as a verdict does.
#[test]
fn a_void_that_supersedes_signs_what_and_why() {
    let purl = canonicalize(PURL).unwrap();
    let trips = vec!["package/index.js arrived from registry.npmjs.org".to_string()];
    let record = Digest::from_bytes([0x5e; 32]);
    let st = Statement::void(
        subject(b"x"),
        &VoidFacts {
            supersedes: Some(Supersession {
                record,
                reason: SupersedeReason::AttemptsDisagreeLater,
            }),
            ..void_facts(&purl, &trips, &[])
        },
    );
    assert_eq!(st.predicate_type, VOID);
    assert_eq!(
        st.predicate["supersedes"],
        format!("sha256:{}", record.to_hex())
    );
    assert_eq!(st.predicate["reason"], "attempts_disagree_later");
    let plain = Statement::void(subject(b"x"), &void_facts(&purl, &trips, &[]));
    assert!(plain.predicate.get("supersedes").is_none());
    assert!(plain.predicate.get("reason").is_none());
}

/// A stabilizer a person or a model wrote is named with who wrote it, once whichever sides it fired
/// on; a builtin one is never named as authored. What the verdict signs of each applied pass, on
/// each side, says the same.
#[test]
fn an_authored_stabilizer_is_named_with_who_wrote_it_and_a_builtin_is_not() {
    let (u, r) = (tar(1, b"x"), tar(2, b"x"));
    let c = comparison(&u, &r);
    assert!(!c.applied().is_empty(), "the tar profile edits a time");
    assert!(
        AuthoredPass::of(&c).is_empty(),
        "every pass here is builtin"
    );

    let builtin = serde_json::to_value(&c).unwrap();
    // Each pass that applied, the side it fired on, and its risk, as the comparison records them.
    let mut fired: Vec<(&str, String)> = Vec::new();
    let mut risk = std::collections::BTreeMap::<String, String>::new();
    for side in ["upstream", "rebuild"] {
        for a in builtin[side]["applied"].as_array().unwrap() {
            let id = a["id"].as_str().unwrap().to_string();
            risk.insert(id.clone(), a["risk"].as_str().unwrap().to_string());
            fired.push((side, id));
        }
    }
    assert!(
        ["upstream", "rebuild"]
            .iter()
            .all(|side| fired.iter().any(|(s, _)| s == side)),
        "each side's time is edited: {fired:?}"
    );

    let model = serde_json::json!({ "kind": "model", "model_id": "m-1", "run_id": "r-1" });
    let human = serde_json::json!({ "kind": "human", "reviewer": "a reviewer" });
    for (kind, who) in [("model", &model), ("human", &human)] {
        let mut v = builtin.clone();
        for side in ["upstream", "rebuild"] {
            for a in v[side]["applied"].as_array_mut().unwrap() {
                a["provenance"] = who.clone();
            }
        }
        let authored: trigon_compare::Comparison = serde_json::from_value(v).unwrap();
        let passes = AuthoredPass::of(&authored);
        assert_eq!(passes.len(), risk.len(), "{kind}: each once: {passes:?}");
        for (id, tier) in &risk {
            let pass = AuthoredPass {
                id: id.clone(),
                risk: tier.clone(),
                provenance: kind.into(),
            };
            assert!(passes.contains(&pass), "{kind}: {pass:?} in {passes:?}");
        }

        let st = Statement::equivalence("demo-1.0.0.tar", &authored);
        let said: Vec<(&str, &str, &str)> = st.predicate["applied"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["side"].as_str().unwrap(),
                    a["id"].as_str().unwrap(),
                    a["provenance"].as_str().unwrap(),
                )
            })
            .collect();
        let meant: Vec<(&str, &str, &str)> = fired
            .iter()
            .map(|(side, id)| (*side, id.as_str(), kind))
            .collect();
        assert_eq!(said, meant, "{kind}");
        assert_eq!(st.predicate["provenanceCap"]["allBuiltin"], false, "{kind}");
    }
}
