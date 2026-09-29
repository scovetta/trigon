//! The predicates that describe a *build* rather than a comparison.
//!
//! `equivalence/v1` says two artifacts agree. These say how the second one came to exist, and they
//! exist because the first claim is not much use without them: "this rebuild matches what was
//! published" is only interesting alongside "and here is the recipe, the image and the egress tier
//! it was produced under, so you can run it yourself".
//!
//! Everything here comes out of the run record (`docs/09-attestations.md` §2.1, §2.4), which is why
//! these could not be written before `trigon-store` existed. A predicate assembled from log lines is
//! a predicate nobody can regenerate.

use serde_json::{Value, json};

use crate::statement::{STATEMENT_TYPE, Statement, Subject};

pub const REBUILD: &str = "https://trigon.dev/rebuild/v1";
pub const BUILD_OBSERVATION: &str = "https://trigon.dev/buildobservation/v1";

/// What a run record has to expose for these predicates. A borrowed view, so `trigon-attest` stays
/// free of a dependency on the store — the judgement half must not need to know where bytes live.
#[derive(Clone, Debug, Default)]
pub struct RunFacts<'a> {
    pub run_id: &'a str,
    pub started: &'a str,
    pub finished: Option<&'a str>,
    pub base_image: &'a str,
    pub egress: &'a str,
    pub isolation: &'a str,
    /// Whether this run can account for everything that crossed into the build — true exactly
    /// when `network_transcript` is present. Stated in the statement rather than left out of it: a
    /// consumer who cannot tell an accounted-for run from an unaccounted one will read every run
    /// as accounted for.
    pub attestable: bool,
    /// The network transcript: every response that crossed into the build, one JSON object per
    /// line, named by hash rather than embedded.
    ///
    /// What it buys is that the tier claimed below stops being an assertion — a reader who wants to
    /// know what the build downloaded fetches these bytes, checks them against this hash, and reads
    /// them, rather than taking our word that we looked.
    pub network_transcript: Option<TranscriptRef<'a>>,
    pub registry_moment: Option<&'a str>,
    /// Evidence the pin above bound anything: `(index_requests, versions_withheld)`.
    ///
    /// `registry_moment` alone describes how a build was *configured*, not how it *resolved*, and
    /// the two came apart silently for weeks. A statement that carries the moment and no evidence
    /// invites a reader to assume the stronger thing, which is the mistake this whole field exists
    /// to prevent.
    pub pin_observed: Option<(u64, u64)>,
    /// `strategyDigest`: a domain-separated hash over the canonical strategy **and the tools it
    /// reaches**. What a cache key is built from. Not the digest of any file.
    pub strategy_digest: Option<&'a str>,
    /// The digest of the strategy's canonical JSON as the run stored it, which is a file: the blob
    /// `RunRecord.strategy` names.
    ///
    /// Kept apart from `strategy_digest` because the two answer different questions and were
    /// conflated: the `strategy.json` byproduct named `strategyDigest`, so a reader who fetched
    /// the file the byproduct describes found bytes that hash to something else (`docs/19` §4.2
    /// item 7). `None` on a run recorded before the strategy was stored.
    pub strategy_blob: Option<&'a str>,
    /// The source the artifact was rebuilt from: repository, commit, subdirectory, and which rung
    /// found the commit.
    ///
    /// **A statement that does not say what it built from is not checkable.** `docs/09` §3 rule 1
    /// requires every noun in "recipe R, executed in environment E, produced artifact A" to be
    /// deterministic and readable, and the recipe was named only by digest — a hash of a blob the
    /// statement does not offer. For npm that is the whole product: `docs/03` says the npm question
    /// is whether the published tarball corresponds to the *claimed source*, and a reader holding
    /// this statement could not tell which source was claimed.
    pub source: Option<SourceFacts<'a>>,
    /// `definition`, `heuristic`, `ci_derived`, `model_assisted`. `None` leaves the method out
    /// of the statement rather than naming one nobody recorded.
    pub derivation: Option<&'a str>,
    /// Hex SHA-256 of the model exchange the strategy came out of (`RunRecord.transcript`), where
    /// the run kept one.
    ///
    /// Signed as `derivation.transcript`, which was `null` on every statement whatever the run
    /// held: 24 of 75 attested runs in one store had kept a transcript, and not one statement
    /// named it. The bytes are not published (`docs/19` §4.1, they are unredacted); the digest
    /// binds the derivation to the exchange a holder of it can check. `None` only where the run
    /// recorded none, which is most runs, since most ask no model.
    pub transcript: Option<&'a str>,
    /// Digest of the rendered instructions, which is what actually ran.
    pub instructions: Option<&'a str>,
    pub build_log: Option<&'a str>,
    /// The Trigon signing the statement, which is what `builder.version.trigon` has always named.
    /// The one that ran the build is signed in the verdict (`trigonVersion.builder`).
    pub trigon_version: &'a str,
    /// The set the rebuilt artifact was judged under: `(id, digest)`.
    pub stabilizer_set: Option<(&'a str, &'a str)>,
    /// What the artifact guard refused or caught.
    pub guard_trips: &'a [String],
    /// Times the build asked for its own artifact and was refused. Distinct from a trip: nothing
    /// arrived, so this is the control working rather than the run being void. In the statement
    /// because a consumer who cannot see it would read a build failure as unexplained.
    pub refused_artifact: &'a [String],
    pub guard_manifest: Option<&'a str>,
    pub guarded_members: Option<u64>,
}

/// Where a rebuild's source came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceFacts<'a> {
    pub repo: &'a str,
    /// A resolved commit, never a ref name.
    pub commit: &'a str,
    pub subdir: Option<&'a str>,
    /// The tag or branch the commit came from, where one did.
    pub ref_name: Option<&'a str>,
    /// What the registry declared, where trimming changed it. Kept because the trim is lossy and
    /// the trimmed value is what everything else sees: a reader cannot otherwise check that the
    /// repository we built from is the one the package pointed at.
    pub declared: Option<&'a str>,
    /// Which rung found the commit, as its serialized name — `registry_commit`, `exact_tag`,
    /// `fuzzy_tag`, `tree_hash_match`, and so on.
    ///
    /// **Not decoration.** A commit the registry recorded and a commit found by stripping a prefix
    /// off a tag name support very different verdicts, and a consumer who cannot tell them apart
    /// will read every verdict as the stronger one.
    pub how: &'a str,
}

/// A network transcript, summarised beside its hash.
///
/// The three travel together so they cannot come apart, and every one of them is **derived from the
/// transcript bytes by the attestor**, never copied out of the run record. The attestor exists
/// precisely because the record was written by the process that ran the build: a count it was told
/// and a count it can check are different kinds of claim, and only the second belongs in something
/// signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptRef<'a> {
    /// Hex SHA-256 of the transcript blob.
    pub digest: &'a str,
    pub requests: u64,
    pub bytes: u64,
}

impl Statement {
    /// How the rebuilt artifact came to exist.
    ///
    /// The subject is the **rebuild**, not the published artifact — the opposite of `equivalence/v1`
    /// and deliberately so. This statement is about a thing we made; the equivalence statement is
    /// about a thing somebody else published, and is keyed on the digest a consumer already has.
    ///
    /// The caller builds the subject from the rebuilt bytes: sha256 and sha512 where it holds
    /// them, sha256 alone where it does not.
    pub fn rebuild(subject: Subject, f: &RunFacts) -> Self {
        let mut byproducts = Vec::new();
        if let Some(d) = f.build_log {
            byproducts.push(json!({ "name": "build.log", "digest": { "sha256": d } }));
        }
        if let Some(d) = f.instructions {
            byproducts.push(json!({ "name": "instructions", "digest": { "sha256": d } }));
        }
        // The strategy itself, not only its digest in `internalParameters`. A hash of a blob the
        // statement does not offer is not something a reader can check.
        //
        // **Named by the file's own digest.** This entry named `strategyDigest`, which hashes the
        // strategy together with the tools it reaches and is the digest of no file, so the one
        // reader this entry exists for — somebody holding `strategy.json` — could never match it.
        // A run that stored no strategy lists none, rather than a digest nothing hashes to;
        // `strategyDigest` stays in `internalParameters`, where it is described for what it is.
        if let Some(d) = f.strategy_blob {
            byproducts.push(json!({ "name": "strategy.json", "digest": { "sha256": d } }));
        }
        if let Some(t) = f.network_transcript {
            byproducts.push(json!({ "name": "network.jsonl", "digest": { "sha256": t.digest } }));
        }

        // SLSA shape: a URI naming the thing, a digest identifying the revision, and our own
        // annotations for what SLSA has no field for. `gitCommit` is the standard digest key, so a
        // generic SLSA consumer reads the commit without knowing anything about Trigon.
        let source = match &f.source {
            Some(s) => {
                let mut annotations = json!({ "discovery": s.how });
                for (key, value) in [
                    ("subdirectory", s.subdir),
                    ("ref", s.ref_name),
                    ("declaredUri", s.declared),
                ] {
                    if let Some(v) = value {
                        annotations[key] = json!(v);
                    }
                }
                json!([{
                    "uri": s.repo,
                    "digest": { "gitCommit": s.commit },
                    "annotations": annotations,
                }])
            }
            None => json!([]),
        };

        let mut predicate = json!({
            "buildDefinition": {
                "buildType": "https://trigon.dev/rebuild/v1",
                "externalParameters": {
                    // Pinned by digest. A tag names something that can change underneath the claim.
                    "baseImage": f.base_image,
                    "egressTier": f.egress,
                    "isolation": f.isolation,
                },
                "internalParameters": {
                    "strategyDigest": f.strategy_digest,
                    "registryMoment": f.registry_moment,
                    // Beside the moment, never instead of it. `false` here does not make the run
                    // wrong; it makes the pin unproven, and those are different claims.
                    "registryPinBound": f.pin_observed.map(|(i, _)| i > 0),
                },
                // SLSA's own home for "what went in", and it was empty. The source is the other
                // half of every verdict this project produces.
                "resolvedDependencies": source,
            },
            "runDetails": {
                "builder": {
                    "id": "https://trigon.dev/builder/v1",
                    "version": { "trigon": f.trigon_version },
                },
                "metadata": {
                    "invocationId": f.run_id,
                    "startedOn": f.started,
                    "finishedOn": f.finished,
                },
                "byproducts": byproducts,
            },
            // Provenance, beside the claim rather than inside it. A consumer who wants to filter on
            // "no model touched this" can; offering that costs one field (`docs/09` §4).
            "derivation": {
                "transcript": f.transcript.map_or(Value::Null, |d| json!({ "sha256": d })),
                "reviewedBy": Value::Null,
            },
            // Not a footnote. A pass at open egress is a weaker claim than a pass under an enforced
            // mirror, and a statement that does not say which invites the reader to assume the
            // stronger one.
            "attestable": f.attestable,
        });
        // The method only where the run recorded one. This was `unwrap_or("heuristic")`, so a run
        // with no recorded derivation was signed as heuristic: absence rendered as a value, and a
        // consumer filtering on the method could not tell the two apart (`docs/19` §4.2 item 5).
        if let Some(m) = f.derivation {
            predicate["derivation"]["method"] = json!(m);
        }
        // The set the rebuilt artifact was judged under, in the shape the verdict names it. The
        // field existed and the attestor passed no set, so no `rebuild` statement carried one
        // (`docs/19` §4.2 item 2). Additive: `rebuild` stays v1, and a verifier that does not know
        // the field reads past it.
        if let Some((id, digest)) = f.stabilizer_set {
            predicate["runDetails"]["builder"]["version"]["stabilizers"] =
                json!(format!("sha256:{digest}"));
            predicate["stabilizerSet"] = json!({ "id": id, "digest": { "sha256": digest } });
        }

        Statement {
            type_: STATEMENT_TYPE.into(),
            subject: vec![subject],
            predicate_type: REBUILD.into(),
            predicate,
        }
    }

    /// What the build was observed to do, and what the artifact guard saw.
    ///
    /// The `artifactHashCheck` block is the one that matters. A run where the artifact under test —
    /// or any of its member files — entered the sandbox over the network is `Void`: not a pass and
    /// not a failure, because a build that downloads its own published output reproduces it
    /// perfectly and proves nothing (`docs/12-security.md` §2). Recording that the check *ran* is as
    /// important as its result: a statement with no such block is one where nobody looked.
    ///
    /// Its subject is the upstream artifact, so the caller builds it the way an equivalence
    /// statement's is built: every digest a consumer might hold ([`Subject::with_digests`]).
    pub fn build_observation(subject: Subject, f: &RunFacts) -> Self {
        let tripped = !f.guard_trips.is_empty();
        let predicate = json!({
            // Tier 1 is the network transcript, which is what the mirror gives us and about eighty
            // per cent of the forensic value. Higher tiers are not claimed because they are not run.
            //
            // Derived from the transcript rather than from `attestable`, so the number and the
            // thing it describes cannot come apart: claiming tier 1 beside a null transcript is
            // exactly the shape of statement this project exists to refuse.
            "tier": if f.network_transcript.is_some() { 1 } else { 0 },
            "networkTranscript": f.network_transcript.map(|t| json!({
                "sha256": t.digest,
                "requests": t.requests,
                "bytes": t.bytes,
            })),
            "egressTier": f.egress,
            "isolation": f.isolation,
            "artifactHashCheck": {
                // A guard that could not run is not a guard that found nothing, and collapsing the
                // two is how an unchecked run comes to be read as a clean one.
                "performed": f.guard_manifest.is_some(),
                "matched": tripped,
                "guardManifest": f.guard_manifest.map(|d| json!({ "sha256": d })),
                "guardedMembers": f.guarded_members,
                "trips": f.guard_trips,
            },
            "violations": f.guard_trips,
            // Separate from `violations`, and the separation is the claim: the mirror turned the
            // request away, so the artifact did not enter the sandbox.
            "refusedOwnArtifact": f.refused_artifact,
            // The numbers, not just the verdict, so a reader can tell "the build asked for nothing"
            // from "the build asked somewhere else" without re-running anything.
            "registryPin": f.pin_observed.map(|(index_requests, withheld)| json!({
                "moment": f.registry_moment,
                "bound": index_requests > 0,
                "indexRequests": index_requests,
                "versionsWithheld": withheld,
            })),
        });

        Statement {
            type_: STATEMENT_TYPE.into(),
            subject: vec![subject],
            predicate_type: BUILD_OBSERVATION.into(),
            predicate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trigon_core::Digest;

    fn facts() -> RunFacts<'static> {
        RunFacts {
            run_id: "01J-A",
            started: "2026-09-11T19:00:00Z",
            finished: Some("2026-09-11T19:02:00Z"),
            base_image: "docker.io/library/debian@sha256:88200866",
            egress: "mirror-only",
            isolation: "UserNs",
            attestable: true,
            network_transcript: Some(TranscriptRef {
                digest: "cc".repeat(32).leak(),
                requests: 214,
                bytes: 18_244_912,
            }),
            registry_moment: Some("2018-04-09T01:10:45Z"),
            pin_observed: Some((153, 903)),
            strategy_digest: Some("be7ffd47303e29ca"),
            strategy_blob: Some("0bdc9f36d3b4e3b1"),
            source: Some(SourceFacts {
                repo: "https://github.com/stevemao/left-pad",
                commit: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                subdir: None,
                ref_name: Some("v1.3.0"),
                declared: None,
                how: "registry_commit",
            }),
            derivation: Some("heuristic"),
            transcript: None,
            instructions: None,
            build_log: Some("aa".repeat(32).leak()),
            trigon_version: "0.0.0",
            stabilizer_set: Some(("npm-tarball", "2b7c4f")),
            guard_trips: &[],
            refused_artifact: &[],
            guard_manifest: Some("bb00"),
            guarded_members: Some(34),
        }
    }

    #[test]
    fn a_rebuild_statement_is_about_the_artifact_we_made() {
        // The opposite subject to `equivalence/v1`, on purpose: that one is keyed on the digest a
        // consumer already has, this one on the thing we produced.
        let d = Digest::from_bytes([7; 32]);
        let s = Statement::rebuild(Subject::new("left-pad-1.3.0.tgz", &d), &facts());
        assert_eq!(s.predicate_type, REBUILD);
        assert_eq!(s.subject[0].digest["sha256"], d.to_hex());
        assert_eq!(
            s.predicate["buildDefinition"]["externalParameters"]["baseImage"],
            "docker.io/library/debian@sha256:88200866"
        );
        assert_eq!(s.predicate["derivation"]["method"], "heuristic");
        assert!(s.canonical().is_ok(), "it has to be signable");
    }

    #[test]
    fn a_run_with_no_recorded_derivation_is_not_signed_as_heuristic() {
        // Absence rendered as a value was the bug: `unwrap_or("heuristic")` signed a method nobody
        // recorded, and a consumer filtering out model-assisted runs could not tell "we do not
        // know" from "no model".
        let d = Digest::from_bytes([6; 32]);
        let s = Statement::rebuild(
            Subject::new("a.tgz", &d),
            &RunFacts {
                derivation: None,
                ..facts()
            },
        );
        assert!(
            s.predicate["derivation"].get("method").is_none(),
            "{}",
            s.predicate["derivation"]
        );
        // The rest of the block is still there, so a reader sees the method is what is missing.
        assert!(s.predicate["derivation"]["transcript"].is_null());
    }

    /// The model exchange a run kept is named, by digest, and one it did not keep is not.
    ///
    /// `derivation.transcript` was `Value::Null` whatever the run held, so 24 of 75 attested runs
    /// in one store had a transcript digest no statement signed: a `model_assisted` derivation with
    /// nothing binding it to the exchange it came out of is an assertion, not a record.
    #[test]
    fn the_transcript_the_run_kept_is_signed_and_one_it_did_not_is_absent() {
        let d = Digest::from_bytes([6; 32]);
        let kept = "3f".repeat(32);
        let with = Statement::rebuild(
            Subject::new("a.tgz", &d),
            &RunFacts {
                derivation: Some("model_assisted"),
                transcript: Some(&kept),
                ..facts()
            },
        );
        assert_eq!(
            with.predicate["derivation"]["transcript"],
            serde_json::json!({ "sha256": kept })
        );

        let without = Statement::rebuild(Subject::new("a.tgz", &d), &facts());
        assert!(
            without.predicate["derivation"]["transcript"].is_null(),
            "a run that kept no transcript is signed as having none, not as having an empty one: \
             {}",
            without.predicate["derivation"]
        );
    }

    #[test]
    fn a_rebuild_statement_names_the_set_it_was_judged_under() {
        // `docs/19` §4.2 item 2: the attestor passed no set, so no `rebuild` statement had one.
        let d = Digest::from_bytes([5; 32]);
        let s = Statement::rebuild(Subject::new("a.tgz", &d), &facts());
        assert_eq!(s.predicate["stabilizerSet"]["id"], "npm-tarball");
        assert_eq!(s.predicate["stabilizerSet"]["digest"]["sha256"], "2b7c4f");
        assert_eq!(
            s.predicate["runDetails"]["builder"]["version"]["stabilizers"],
            "sha256:2b7c4f"
        );
        let none = Statement::rebuild(
            Subject::new("a.tgz", &d),
            &RunFacts {
                stabilizer_set: None,
                ..facts()
            },
        );
        assert!(none.predicate.get("stabilizerSet").is_none());
    }

    #[test]
    fn the_egress_tier_and_attestability_are_in_the_statement_not_beside_it() {
        // A pass at open egress is a weaker claim than one under an enforced mirror, and a
        // statement that omits which invites the reader to assume the stronger one.
        let d = Digest::from_bytes([1; 32]);
        let weak = RunFacts {
            egress: "open",
            attestable: false,
            ..facts()
        };
        let s = Statement::rebuild(Subject::new("a.tgz", &d), &weak);
        assert_eq!(
            s.predicate["buildDefinition"]["externalParameters"]["egressTier"],
            "open"
        );
        assert_eq!(s.predicate["attestable"], false);
    }

    #[test]
    fn a_pinned_moment_carries_the_evidence_that_it_bound_something() {
        // The whole point. A statement naming a moment with nothing beside it invites the reader to
        // assume it applied, and for weeks it did not: pip ignores an untrusted plain-HTTP index
        // after one warning and resolves against the live one.
        let d = Digest::from_bytes([9; 32]);
        let s = Statement::rebuild(Subject::new("a.tgz", &d), &facts());
        assert_eq!(
            s.predicate["buildDefinition"]["internalParameters"]["registryPinBound"],
            true
        );

        let unproven = RunFacts {
            pin_observed: Some((0, 0)),
            ..facts()
        };
        let s = Statement::build_observation(Subject::new("a.tgz", &d), &unproven);
        assert_eq!(s.predicate["registryPin"]["bound"], false);
        assert_eq!(s.predicate["registryPin"]["indexRequests"], 0);
        // The moment is still recorded. An unproven pin is not an absent one.
        assert_eq!(s.predicate["registryPin"]["moment"], "2018-04-09T01:10:45Z");
    }

    #[test]
    fn a_run_with_no_mirror_claims_no_pin_either_way() {
        // A third state, and not a failure: nothing was configured, so there is nothing to prove.
        let d = Digest::from_bytes([8; 32]);
        let s = Statement::build_observation(
            Subject::new("a.tgz", &d),
            &RunFacts {
                registry_moment: None,
                pin_observed: None,
                ..facts()
            },
        );
        assert!(s.predicate["registryPin"].is_null());
    }

    #[test]
    fn a_guard_that_did_not_run_is_not_a_guard_that_found_nothing() {
        let d = Digest::from_bytes([2; 32]);
        let unguarded = RunFacts {
            guard_manifest: None,
            guarded_members: None,
            ..facts()
        };
        let s = Statement::build_observation(Subject::new("a.tgz", &d), &unguarded);
        assert_eq!(s.predicate["artifactHashCheck"]["performed"], false);
        assert_eq!(s.predicate["artifactHashCheck"]["matched"], false);

        let s = Statement::build_observation(Subject::new("a.tgz", &d), &facts());
        assert_eq!(s.predicate["artifactHashCheck"]["performed"], true);
        assert_eq!(s.predicate["artifactHashCheck"]["guardedMembers"], 34);
    }

    #[test]
    fn a_tripped_guard_is_recorded_as_a_match_and_a_violation() {
        let d = Digest::from_bytes([3; 32]);
        let trips = vec!["the artifact arrived from registry.npmjs.org".to_string()];
        let tripped = RunFacts {
            guard_trips: &trips,
            ..facts()
        };
        let s = Statement::build_observation(Subject::new("a.tgz", &d), &tripped);
        assert_eq!(s.predicate["artifactHashCheck"]["matched"], true);
        assert_eq!(s.predicate["violations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn an_unenforced_run_claims_no_observability_tier() {
        let d = Digest::from_bytes([4; 32]);
        let s = Statement::build_observation(
            Subject::new("a.tgz", &d),
            &RunFacts {
                attestable: false,
                network_transcript: None,
                ..facts()
            },
        );
        assert_eq!(
            s.predicate["tier"], 0,
            "a tier we did not achieve is not claimed"
        );
        assert!(s.predicate["networkTranscript"].is_null());
    }

    #[test]
    fn the_bytes_a_statement_is_about_are_named_in_it() {
        // Three byproduct digests were passed as `None` by the only caller that builds these,
        // because `RunFacts` borrows and `to_hex` allocates and nothing owned the strings. The
        // effect was a signed statement that named neither the build log, nor the scripts that
        // actually ran, nor what the build fetched — all three of which were sitting in the record.
        // A statement that omits the bytes it is about is one nobody can check.
        let d = Digest::from_bytes([2; 32]);
        let s = Statement::rebuild(Subject::new("a.tgz", &d), &facts());
        let names: Vec<&str> = s.predicate["runDetails"]["byproducts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"build.log"), "{names:?}");
        assert!(names.contains(&"network.jsonl"), "{names:?}");
    }

    /// The scripts that ran are named by their digest where the run kept them, and not at all
    /// where it did not.
    #[test]
    fn the_instructions_a_run_kept_are_named_and_none_are_invented() {
        let d = Digest::from_bytes([2; 32]);
        let kept = "1c".repeat(32);
        let s = Statement::rebuild(
            Subject::new("a.tgz", &d),
            &RunFacts {
                instructions: Some(&kept),
                ..facts()
            },
        );
        let byproducts = s.predicate["runDetails"]["byproducts"].as_array().unwrap();
        let instructions = byproducts
            .iter()
            .find(|b| b["name"] == "instructions")
            .expect("the instructions are named");
        assert_eq!(instructions["digest"]["sha256"], kept);
        let s = Statement::rebuild(Subject::new("a.tgz", &d), &facts());
        let byproducts = s.predicate["runDetails"]["byproducts"].as_array().unwrap();
        assert!(byproducts.iter().all(|b| b["name"] != "instructions"));
    }

    #[test]
    fn the_tier_and_the_transcript_cannot_come_apart() {
        // The tier used to be read off `attestable`, which is a second field that had to agree with
        // this one and nothing asserted that it did. A statement claiming tier 1 beside a null
        // transcript is the exact shape of claim this project exists to refuse, so the number is
        // derived from the thing it describes.
        let d = Digest::from_bytes([5; 32]);
        let lying = RunFacts {
            attestable: true,
            network_transcript: None,
            ..facts()
        };
        let s = Statement::build_observation(Subject::new("a.tgz", &d), &lying);
        assert_eq!(
            s.predicate["tier"], 0,
            "tier 1 was claimed with nothing to back it"
        );

        // And the other way: a transcript is named, by hash, so a reader fetches those bytes and
        // reads them rather than taking our word that we looked.
        let s = Statement::build_observation(Subject::new("a.tgz", &d), &facts());
        assert_eq!(s.predicate["tier"], 1);
        assert_eq!(
            s.predicate["networkTranscript"]["sha256"],
            "cc".repeat(32).as_str()
        );
        // The count and the byte total beside the hash, both derived from the bytes the hash is
        // over — so a reader gets the shape of the answer without a fetch, and can check it with
        // one.
        assert_eq!(s.predicate["networkTranscript"]["requests"], 214);
        assert_eq!(s.predicate["networkTranscript"]["bytes"], 18_244_912);
    }
}

#[cfg(test)]
mod source_facts_tests {
    use super::*;
    use crate::statement::Statement;
    use trigon_core::Digest;

    fn subject() -> Subject {
        Subject::new("x.whl", &Digest::from_bytes([1; 32]))
    }

    fn facts_with_source() -> RunFacts<'static> {
        RunFacts {
            run_id: "r1",
            started: "2026-01-01T00:00:00Z",
            base_image: "sha256:abc",
            egress: "mirror-only",
            isolation: "podman",
            attestable: true,
            strategy_digest: Some("deadbeef"),
            strategy_blob: Some("5a17"),
            source: Some(SourceFacts {
                repo: "https://github.com/tlsfuzzer/python-ecdsa",
                commit: "bd66899550d7185939bf27b75713a2ac9325a9d3",
                subdir: None,
                ref_name: Some("python-ecdsa-0.19.2"),
                declared: Some("https://github.com/tlsfuzzer/python-ecdsa/issues"),
                how: "fuzzy_tag",
            }),
            ..RunFacts::default()
        }
    }

    #[test]
    fn a_statement_says_what_it_built_from() {
        // `docs/09` §3 rule 1: every noun in "recipe R, executed in environment E, produced
        // artifact A" has to be deterministic and readable by someone who has never heard of us.
        // The recipe was named only by a digest of a blob the statement did not offer, and the
        // source — the other half of every verdict this project makes — was not in it at all.
        let s = Statement::rebuild(subject(), &facts_with_source());
        let dep = &s.predicate["buildDefinition"]["resolvedDependencies"][0];
        assert_eq!(dep["uri"], "https://github.com/tlsfuzzer/python-ecdsa");
        // `gitCommit` is SLSA's own key, so a consumer that knows nothing about Trigon still reads
        // the commit.
        assert_eq!(
            dep["digest"]["gitCommit"],
            "bd66899550d7185939bf27b75713a2ac9325a9d3"
        );
    }

    #[test]
    fn how_the_commit_was_found_is_part_of_the_claim() {
        // A commit the registry recorded and a commit found by stripping a prefix off a tag name
        // support very different verdicts. A consumer who cannot tell them apart reads every
        // verdict as the stronger one.
        let s = Statement::rebuild(subject(), &facts_with_source());
        let a = &s.predicate["buildDefinition"]["resolvedDependencies"][0]["annotations"];
        assert_eq!(a["discovery"], "fuzzy_tag");
        assert_eq!(a["ref"], "python-ecdsa-0.19.2");
        // And what the package actually declared, since trimming it is lossy and the trimmed form
        // is what every other field shows.
        assert_eq!(
            a["declaredUri"],
            "https://github.com/tlsfuzzer/python-ecdsa/issues"
        );
    }

    #[test]
    fn the_strategy_is_offered_and_not_merely_hashed() {
        // A digest of a blob the statement does not list is not something a reader can check.
        let s = Statement::rebuild(subject(), &facts_with_source());
        let names: Vec<&str> = s.predicate["runDetails"]["byproducts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"strategy.json"), "{names:?}");
    }

    #[test]
    fn the_strategy_file_is_named_by_its_own_digest_and_the_cache_digest_stays_apart() {
        // `docs/19` §4.2 item 7. `strategyDigest` hashes the strategy with the tools it reaches, so
        // it is the digest of no file, and the `strategy.json` byproduct used to carry it: the one
        // reader that entry is for, somebody holding the file, could never match it. The file is
        // named by the digest of the blob the run stored, and `strategyDigest` keeps its own place.
        let s = Statement::rebuild(subject(), &facts_with_source());
        let byproduct = s.predicate["runDetails"]["byproducts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["name"] == "strategy.json")
            .expect("the strategy is offered");
        assert_eq!(byproduct["digest"]["sha256"], "5a17");
        assert_eq!(
            s.predicate["buildDefinition"]["internalParameters"]["strategyDigest"],
            "deadbeef"
        );

        // A run recorded before the strategy was stored lists no file, rather than a digest
        // nothing hashes to.
        let old = RunFacts {
            strategy_blob: None,
            ..facts_with_source()
        };
        let s = Statement::rebuild(subject(), &old);
        let names: Vec<&str> = s.predicate["runDetails"]["byproducts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect();
        assert!(!names.contains(&"strategy.json"), "{names:?}");
        assert_eq!(
            s.predicate["buildDefinition"]["internalParameters"]["strategyDigest"], "deadbeef",
            "the cache digest is still stated, for what it is"
        );
    }

    #[test]
    fn a_run_with_no_source_says_so_rather_than_inventing_one() {
        let bare = RunFacts {
            source: None,
            ..facts_with_source()
        };
        let s = Statement::rebuild(subject(), &bare);
        assert_eq!(
            s.predicate["buildDefinition"]["resolvedDependencies"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
    }
}
