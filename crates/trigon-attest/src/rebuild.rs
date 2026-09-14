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
    pub strategy_digest: Option<&'a str>,
    /// `definition`, `heuristic`, `ci_derived`, `model_assisted`.
    pub derivation: Option<&'a str>,
    /// Digest of the rendered instructions, which is what actually ran.
    pub instructions: Option<&'a str>,
    pub build_log: Option<&'a str>,
    pub trigon_version: &'a str,
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
    pub fn rebuild(
        artifact_name: &str,
        rebuild_sha256: &trigon_core::Digest,
        f: &RunFacts,
    ) -> Self {
        let mut byproducts = Vec::new();
        if let Some(d) = f.build_log {
            byproducts.push(json!({ "name": "build.log", "digest": { "sha256": d } }));
        }
        if let Some(d) = f.instructions {
            byproducts.push(json!({ "name": "instructions", "digest": { "sha256": d } }));
        }
        if let Some(t) = f.network_transcript {
            byproducts.push(json!({ "name": "network.jsonl", "digest": { "sha256": t.digest } }));
        }

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
                "method": f.derivation.unwrap_or("heuristic"),
                "transcript": Value::Null,
                "reviewedBy": Value::Null,
            },
            // Not a footnote. A pass at open egress is a weaker claim than a pass under an enforced
            // mirror, and a statement that does not say which invites the reader to assume the
            // stronger one.
            "attestable": f.attestable,
        });
        if let Some((id, digest)) = f.stabilizer_set {
            predicate["runDetails"]["builder"]["version"]["stabilizers"] =
                json!(format!("sha256:{digest}"));
            predicate["buildDefinition"]["internalParameters"]["stabilizerSet"] = json!(id);
        }

        Statement {
            type_: STATEMENT_TYPE.into(),
            subject: vec![Subject::new(artifact_name, rebuild_sha256)],
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
    pub fn build_observation(
        artifact_name: &str,
        subject_sha256: &trigon_core::Digest,
        f: &RunFacts,
    ) -> Self {
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
            subject: vec![Subject::new(artifact_name, subject_sha256)],
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
            derivation: Some("heuristic"),
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
        let s = Statement::rebuild("left-pad-1.3.0.tgz", &d, &facts());
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
    fn the_egress_tier_and_attestability_are_in_the_statement_not_beside_it() {
        // A pass at open egress is a weaker claim than one under an enforced mirror, and a
        // statement that omits which invites the reader to assume the stronger one.
        let d = Digest::from_bytes([1; 32]);
        let weak = RunFacts {
            egress: "open",
            attestable: false,
            ..facts()
        };
        let s = Statement::rebuild("a.tgz", &d, &weak);
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
        let s = Statement::rebuild("a.tgz", &d, &facts());
        assert_eq!(
            s.predicate["buildDefinition"]["internalParameters"]["registryPinBound"],
            true
        );

        let unproven = RunFacts {
            pin_observed: Some((0, 0)),
            ..facts()
        };
        let s = Statement::build_observation("a.tgz", &d, &unproven);
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
            "a.tgz",
            &d,
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
        let s = Statement::build_observation("a.tgz", &d, &unguarded);
        assert_eq!(s.predicate["artifactHashCheck"]["performed"], false);
        assert_eq!(s.predicate["artifactHashCheck"]["matched"], false);

        let s = Statement::build_observation("a.tgz", &d, &facts());
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
        let s = Statement::build_observation("a.tgz", &d, &tripped);
        assert_eq!(s.predicate["artifactHashCheck"]["matched"], true);
        assert_eq!(s.predicate["violations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn an_unenforced_run_claims_no_observability_tier() {
        let d = Digest::from_bytes([4; 32]);
        let s = Statement::build_observation(
            "a.tgz",
            &d,
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
        let s = Statement::rebuild("a.tgz", &d, &facts());
        let names: Vec<&str> = s.predicate["runDetails"]["byproducts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"build.log"), "{names:?}");
        assert!(names.contains(&"network.jsonl"), "{names:?}");
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
        let s = Statement::build_observation("a.tgz", &d, &lying);
        assert_eq!(
            s.predicate["tier"], 0,
            "tier 1 was claimed with nothing to back it"
        );

        // And the other way: a transcript is named, by hash, so a reader fetches those bytes and
        // reads them rather than taking our word that we looked.
        let s = Statement::build_observation("a.tgz", &d, &facts());
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
