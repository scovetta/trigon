//! Re-deriving a published verdict from its record (`docs/19` §10 phase 4): the outcome and the
//! stabilized digests, and now what the verdict signs the comparison found — its `differences`,
//! `applied` and `members` — and the published comparison report held to all of it.

use trigon_archive::Limits;
use trigon_attest::evidence::EvidenceState;
use trigon_attest::{ArchivedStabilizer, rederive, rederive_with};
use trigon_core::{Digest, Format};
use trigon_stabilize::profile;

use crate::build::{digest, open_golden, pairs};

/// A golden verdict's statement, and its published comparison report.
fn published(name: &str) -> (trigon_attest::Statement, Vec<u8>) {
    let r = open_golden();
    let bytes = r.read_record(&digest(name)).unwrap().unwrap();
    let v = r.verify_record(&bytes).unwrap();
    let report = v.evidence.iter().find(|e| e.name == "comparison").unwrap();
    assert_eq!(report.state, EvidenceState::Matches);
    let report = r.read_evidence(&report.digest).unwrap().unwrap();
    (v.statement, report)
}

#[test]
fn a_published_verdict_re_derives_whole_and_its_report_agrees() {
    for (name, pair) in [("a2", "a"), ("b", "b"), ("e", "e")] {
        let (st, report) = published(name);
        let p = &pairs()[pair];
        let d = rederive(&st, p.upstream.clone(), p.rebuilt.clone()).unwrap();
        assert!(d.holds(), "{name}: {d:?}");
        assert!(
            d.disagreements.is_empty() && d.unchecked.is_empty(),
            "{name}"
        );
        let checked = d.check_report(&report).unwrap().unwrap();
        assert!(checked.agrees(), "{name}: {:?}", checked.disagreements);
        // What it is not held to is said, and never counted as agreeing.
        assert_eq!(
            checked.unchecked,
            ["diff.progression", "notes", "the members' raw paths"],
            "{name}"
        );
    }
    // The divergence names what differs, and re-deriving names the same.
    let (st, _) = published("b");
    assert_eq!(st.predicate["differences"][0], "body@package/index.js");
}

#[test]
fn a_statement_that_misreports_what_the_comparison_found_does_not_hold() {
    let (st, _) = published("b");
    let p = &pairs()["b"];
    for (field, lie) in [
        ("differences", serde_json::json!(["mode@package/index.js"])),
        (
            "members",
            serde_json::json!({"identical": 1, "differs": 0, "onlyUpstream": 0,
                                        "onlyRebuild": 0, "executableDiffers": 0}),
        ),
        ("applied", serde_json::json!([])),
    ] {
        let mut edited = st.clone();
        edited.predicate[field] = lie;
        let d = rederive(&edited, p.upstream.clone(), p.rebuilt.clone()).unwrap();
        assert!(!d.holds(), "{field}");
        // The outcome and the digests are right; only what it says it found is not.
        assert_eq!(d.claimed, d.actual.to_string());
        assert!(d.digests_match);
        assert_eq!(d.disagreements.len(), 1, "{field}: {:?}", d.disagreements);
        assert_eq!(d.disagreements[0].field, field);
        assert!(d.disagreements[0].to_string().contains(field));
    }
    // A match that leaves out a difference re-deriving finds disagrees too.
    let (st, _) = published("a2");
    let mut edited = st.clone();
    edited.predicate["differences"] = serde_json::json!(["body@package/index.js"]);
    let a = &pairs()["a"];
    let d = rederive(&edited, a.upstream.clone(), a.rebuilt.clone()).unwrap();
    assert_eq!(d.disagreements[0].field, "differences");
    assert_eq!(d.disagreements[0].rederived, serde_json::Value::Null);
}

#[test]
fn a_published_report_that_is_not_what_re_deriving_gives_is_named_field_by_field() {
    let (st, report) = published("b");
    let p = &pairs()["b"];
    let d = rederive(&st, p.upstream.clone(), p.rebuilt.clone()).unwrap();
    let mut edited: serde_json::Value = serde_json::from_slice(&report).unwrap();
    edited["outcome"] = "normalized".into();
    edited["diff"]["differs"] = 0.into();
    let got = d
        .check_report(&serde_json::to_vec(&edited).unwrap())
        .unwrap()
        .unwrap();
    let fields: Vec<&str> = got.disagreements.iter().map(|x| x.field).collect();
    assert_eq!(fields, ["outcome", "members"]);
    // One that is not a comparison at all is refused as damaged evidence.
    let e = d.check_report(b"{}").unwrap_err();
    assert!(matches!(e, trigon_attest::AttestError::Evidence(_)), "{e}");
}

/// Beyond what a verdict signs: every member the report names, with its status, kind, digests and
/// sizes, and the passes it says changed each field. A report whose counts and codes are right
/// and whose members are not does not agree.
#[test]
fn a_published_report_is_held_member_by_member_and_by_its_field_edits() {
    let check = |name: &str, pair: &str, edit: &dyn Fn(&mut serde_json::Value)| {
        let (st, report) = published(name);
        let p = &pairs()[pair];
        let d = rederive(&st, p.upstream.clone(), p.rebuilt.clone()).unwrap();
        let mut edited: serde_json::Value = serde_json::from_slice(&report).unwrap();
        edit(&mut edited);
        d.check_report(&serde_json::to_vec(&edited).unwrap())
            .unwrap()
            .unwrap()
    };
    let one = |got: trigon_attest::ReportCheck, field: &str| {
        let fields: Vec<&str> = got.disagreements.iter().map(|x| x.field).collect();
        assert_eq!(fields, [field], "{:?}", got.disagreements);
        got
    };

    // A member's rebuilt digest, and its size, that re-deriving does not give.
    let got = one(
        check("b", "b", &|r| {
            r["diff"]["files"][0]["rebuild_digest"] = "0".repeat(64).into()
        }),
        "diff.files",
    );
    assert!(
        got.disagreements[0]
            .to_string()
            .contains("package/index.js")
    );
    one(
        check("b", "b", &|r| {
            r["diff"]["files"][0]["rebuild_bytes"] = 99.into()
        }),
        "diff.files",
    );
    // A member it leaves out, and one it adds.
    one(
        check("b", "b", &|r| r["diff"]["files"] = serde_json::json!([])),
        "diff.files",
    );
    one(
        check("a2", "a", &|r| {
            let extra = r["diff"]["files"][0].clone();
            r["diff"]["files"].as_array_mut().unwrap().push(extra);
        }),
        "diff.files",
    );

    // The passes it says changed a field.
    let (_, report) = published("a2");
    let report: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert!(
        !report["diff"]["field_edits"].as_array().unwrap().is_empty(),
        "the tar profile edits a normalized pair's times: {report}"
    );
    one(
        check("a2", "a", &|r| {
            r["diff"]["field_edits"][0]["passes"] = serde_json::json!(["another-pass"])
        }),
        "diff.field_edits",
    );
    // None at all, as a report written before they were kept has none: unchecked, and not
    // counted as agreeing.
    let got = check("a2", "a", &|r| {
        r["diff"].as_object_mut().unwrap().remove("field_edits");
    });
    assert!(got.agrees(), "{:?}", got.disagreements);
    assert!(got.unchecked.contains(&"diff.field_edits"), "{got:?}");

    // What is explanation is not held to it: a report whose progression and notes a later build
    // words differently still agrees, and says it was not checked there.
    let got = check("a2", "a", &|r| {
        r["diff"]["progression"] = serde_json::Value::Null;
        r["diff"]["files"][0]["upstream_raw_path"] = serde_json::json!(b"package/renamed.js");
    });
    assert!(got.agrees(), "{:?}", got.disagreements);
    assert!(got.unchecked.contains(&"diff.progression"), "{got:?}");
}

/// A subject whose sha256 is the artifact's and whose sha512 is not is a signed claim refuted —
/// failed verification — and never "the wrong file", which is a mistake of whoever handed it in.
#[test]
fn a_subject_whose_other_digest_is_not_the_artifacts_is_refuted_not_the_wrong_file() {
    let (mut st, _) = published("b");
    let p = &pairs()["b"];
    st.subject[0]
        .digest
        .insert("sha512".into(), "ab".repeat(64));
    let e = rederive(&st, p.upstream.clone(), p.rebuilt.clone()).unwrap_err();
    assert!(
        matches!(&e, trigon_attest::AttestError::SubjectRefuted { algorithm, .. }
            if algorithm == "sha512"),
        "{e}"
    );
    assert!(e.fails_verification(), "{e}");
    // Another file altogether is still the wrong file.
    let e = rederive(&st, p.rebuilt.clone(), p.rebuilt.clone()).unwrap_err();
    assert!(
        matches!(&e, trigon_attest::AttestError::WrongArtifact { algorithm, .. }
            if algorithm == "sha256"),
        "{e}"
    );
    assert!(!e.fails_verification(), "{e}");
}

/// The tar profile run natively, as a module would run it: stabilized bytes and no report.
struct Native;

impl ArchivedStabilizer for Native {
    fn digest(&mut self, profile_id: &str) -> Result<Digest, String> {
        Ok(profile(profile_id).ok_or("no such profile")?.digest())
    }

    fn stabilize(
        &mut self,
        profile_id: &str,
        format: Format,
        bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let set = profile(profile_id).ok_or("no such profile")?;
        let (_, archive) =
            trigon_compare::summarize(bytes.to_vec(), format, &set, &Limits::default())
                .map_err(|e| e.to_string())?;
        trigon_archive::serialize(&archive, true).map_err(|e| e.to_string())
    }
}

#[test]
fn an_archived_set_leaves_what_it_cannot_re_derive_unchecked_and_never_passed() {
    let (st, report) = published("e");
    let p = &pairs()["e"];
    let mut native = Native;
    let d = rederive_with(
        &st,
        p.upstream.clone(),
        p.rebuilt.clone(),
        Some(&mut native),
    )
    .unwrap();
    assert_eq!(d.unchecked, ["differences", "applied", "members"]);
    assert!(d.disagreements.is_empty());
    assert_eq!(d.check_report(&report).unwrap(), None);
}

/// A comparison report read again to be judged is held to its signed digest again: a file that
/// changed after its record was verified is not what the verdict signs, and fails.
#[test]
fn evidence_read_again_to_be_judged_is_held_to_its_digest_again() {
    let tmp = tempfile::tempdir().unwrap();
    crate::build::copy(&crate::build::repo(), tmp.path());
    let r = crate::build::open(tmp.path());
    let bytes = r.read_record(&digest("a2")).unwrap().unwrap();
    let v = r.verify_record(&bytes).unwrap();
    let report = v.evidence.iter().find(|e| e.name == "comparison").unwrap();
    let (state, read) = r.read_evidence_checked(v.pos, report).unwrap();
    assert_eq!(state, EvidenceState::Matches);
    assert_eq!(
        trigon_attest::Record::digest_of(&read.unwrap()),
        report.digest
    );

    let path = tmp
        .path()
        .join(trigon_attest::evidence::evidence_path(&report.digest));
    std::fs::write(&path, b"a report that agrees with anything").unwrap();
    let e = r.read_evidence_checked(v.pos, report).unwrap_err();
    assert!(
        matches!(e, trigon_attest::evidence::RecordFailure::Evidence(_)),
        "{e}"
    );
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        r.read_evidence_checked(v.pos, report).unwrap(),
        (EvidenceState::Absent, None)
    );
}

/// Another set's module, handed in as the one a statement names: it stabilizes as the tar profile
/// does, and says its digest is the one `profile_id`'s own digest is not.
struct Impostor;

impl ArchivedStabilizer for Impostor {
    fn digest(&mut self, _profile_id: &str) -> Result<Digest, String> {
        Ok(profile("zip").ok_or("no such profile")?.digest())
    }

    fn stabilize(
        &mut self,
        profile_id: &str,
        format: Format,
        bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        Native.stabilize(profile_id, format, bytes)
    }
}

/// A module that cannot say what it is, or cannot stabilize.
struct Broken {
    digest: bool,
}

impl ArchivedStabilizer for Broken {
    fn digest(&mut self, profile_id: &str) -> Result<Digest, String> {
        match self.digest {
            true => Native.digest(profile_id),
            false => Err("the module trapped".into()),
        }
    }

    fn stabilize(&mut self, _: &str, _: Format, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("the module trapped".into())
    }
}

/// The one failure an archived set exists to prevent: a module implementing some other set gives a
/// plausible digest, not an error, so its digest is held to the set the statement names before
/// anything is stabilized, and one that is not it is refused as a set mismatch, never compared.
#[test]
fn an_archived_set_that_is_not_the_set_the_statement_names_is_refused_before_comparing() {
    let (st, _) = published("b");
    let p = &pairs()["b"];
    let e = rederive_with(
        &st,
        p.upstream.clone(),
        p.rebuilt.clone(),
        Some(&mut Impostor),
    )
    .unwrap_err();
    let trigon_attest::AttestError::SetMismatch { claimed, current } = &e else {
        panic!("expected a set mismatch, got {e}");
    };
    let named = st.predicate["stabilizerSet"]["digest"]["sha256"]
        .as_str()
        .unwrap();
    assert_eq!(claimed, &format!("tar@{}", &named[..12]));
    let other = profile("zip").unwrap().digest().to_hex();
    assert_eq!(
        current,
        &format!("tar@{} (the module supplied)", &other[..12])
    );
    assert!(!e.fails_verification(), "{e}");

    // A module that fails is a module that failed: never a verdict either way.
    for digest in [false, true] {
        let e = rederive_with(
            &st,
            p.upstream.clone(),
            p.rebuilt.clone(),
            Some(&mut Broken { digest }),
        )
        .unwrap_err();
        assert!(
            matches!(&e, trigon_attest::AttestError::Malformed(m)
                if m.contains("the archived set failed") && m.contains("trapped")),
            "{e}"
        );
    }
}

/// Through an archived set, which returns stabilized bytes and no report, equal stabilized forms of
/// different bytes re-derive as `normalized-with-caveats` and never `normalized`: the provenance
/// cap needs every applied pass's risk and provenance, which a module cannot give, and the stronger
/// outcome is never claimed on less evidence. Different stabilized forms are a divergence, which
/// holds where the statement claims one.
#[test]
fn an_archived_set_re_derives_a_match_as_caveated_at_best_and_a_divergence_as_one() {
    let (st, _) = published("a2");
    assert_eq!(st.predicate["outcome"], "normalized");
    let a = &pairs()["a"];
    let d = rederive_with(
        &st,
        a.upstream.clone(),
        a.rebuilt.clone(),
        Some(&mut Native),
    )
    .unwrap();
    assert_eq!(d.actual, trigon_core::Match::NormalizedWithCaveats);
    assert!(d.digests_match);
    assert_eq!(d.unchecked, ["differences", "applied", "members"]);

    let (st, report) = published("b");
    let b = &pairs()["b"];
    let d = rederive_with(
        &st,
        b.upstream.clone(),
        b.rebuilt.clone(),
        Some(&mut Native),
    )
    .unwrap();
    assert_eq!(d.actual, trigon_core::Match::Divergent);
    assert_eq!(d.claimed, "divergent");
    assert!(d.holds(), "{d:?}");
    assert_eq!(d.check_report(&report).unwrap(), None);

    // The stabilized digests are still held to the statement's, through the module as without it.
    let mut lie = st.clone();
    lie.predicate["stabilized"]["upstream"]["sha256"] = "0".repeat(64).into();
    let e = rederive_with(
        &lie,
        b.upstream.clone(),
        b.rebuilt.clone(),
        Some(&mut Native),
    )
    .unwrap_err();
    assert!(
        matches!(
            e,
            trigon_attest::AttestError::ClaimRefuted {
                side: "upstream",
                ..
            }
        ),
        "{e}"
    );
}

/// A set this build does not carry, with no module for it, is said as such, with the sets it does
/// carry: re-deriving under whatever set happens to be at hand would answer another question.
#[test]
fn a_set_this_build_does_not_carry_is_refused_naming_the_sets_it_does() {
    let (mut st, _) = published("b");
    st.predicate["stabilizerSet"]["id"] = "no-such-set".into();
    let p = &pairs()["b"];
    let e = rederive(&st, p.upstream.clone(), p.rebuilt.clone()).unwrap_err();
    let trigon_attest::AttestError::SetMismatch { claimed, current } = &e else {
        panic!("expected a set mismatch, got {e}");
    };
    assert_eq!(claimed, "no-such-set (unknown to this build)");
    assert!(current.split(", ").any(|s| s == "tar"), "{current}");
}

/// A verdict that leaves out a field re-deriving needs is refused as damaged evidence, never read
/// as agreeing: its archive format, the rebuilt artifact's raw digest, and either stabilized
/// digest.
#[test]
fn a_verdict_missing_what_re_deriving_needs_is_refused_as_damaged_evidence() {
    let (st, _) = published("b");
    let p = &pairs()["b"];
    for (pointer, says) in [
        ("/archiveFormat", "names no archive format"),
        (
            "/artifacts/rebuild/sha256",
            "no raw digest for the rebuild artifact",
        ),
        (
            "/stabilized/upstream/sha256",
            "no stabilized digest for the upstream artifact",
        ),
        (
            "/stabilized/rebuild/sha256",
            "no stabilized digest for the rebuild artifact",
        ),
    ] {
        let mut edited = st.clone();
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        let parent = match parent {
            "" => &mut edited.predicate,
            p => edited.predicate.pointer_mut(p).unwrap(),
        };
        parent.as_object_mut().unwrap().remove(field).unwrap();
        let e = rederive(&edited, p.upstream.clone(), p.rebuilt.clone()).unwrap_err();
        assert!(
            matches!(&e, trigon_attest::AttestError::Evidence(m) if m.contains(says)),
            "{pointer}: {e}"
        );
        assert!(!e.fails_verification(), "{pointer}: {e}");
    }
}

/// A published report that leaves out its member report altogether disagrees with a re-derivation
/// that has members: what it omits is not counted as agreeing.
#[test]
fn a_published_report_without_its_members_does_not_agree() {
    let (st, report) = published("b");
    let p = &pairs()["b"];
    let d = rederive(&st, p.upstream.clone(), p.rebuilt.clone()).unwrap();
    let mut edited: serde_json::Value = serde_json::from_slice(&report).unwrap();
    edited.as_object_mut().unwrap().remove("diff").unwrap();
    let got = d
        .check_report(&serde_json::to_vec(&edited).unwrap())
        .unwrap()
        .unwrap();
    assert!(!got.agrees());
    let fields: Vec<&str> = got.disagreements.iter().map(|x| x.field).collect();
    assert!(fields.contains(&"diff.files"), "{fields:?}");
}
