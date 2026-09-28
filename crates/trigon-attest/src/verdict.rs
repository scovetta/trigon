//! What a published record's statement signs: the v2 verdicts, `void/v1` and `withdrawal/v1`.
//!
//! `docs/19` §4.2 lists what every published record must carry, and the v1 verdicts carried the
//! outcome and the stabilizer set and little else a reader of a published record needs: not the
//! package's purl, not which Trigon built it, not the digests of the evidence a third party fetches
//! to re-derive it, not the command that would falsify it or where to dispute it. Those change what
//! the verdict signs, so its predicate types move to `equivalence/v2` and `divergence/v2`.
//!
//! **A v2 verdict is a v1 verdict with fields added**, never one with fields moved: `outcome`,
//! `stabilizerSet`, `archiveFormat`, `artifacts` and `stabilized` are where they were, so
//! [`crate::rederive`] reads both versions with one code path, and a v1 statement signed before
//! this existed verifies exactly as it did.
//!
//! Beside them, two predicates that are not verdicts. `void/v1` is "we looked, and could not tell,
//! for this reason": the run the publication gate calls void, with the facts that establish it and
//! no comparison outcome or difference data at all. `withdrawal/v1` is "we were wrong": it names
//! the record it supersedes, why, and nothing else.
//!
//! Every field is written down in `docs/09-attestations.md` §2.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trigon_compare::Comparison;
use trigon_core::Digest;
use trigon_core::purl::{CanonicalPurl, PURL_CANON};

use crate::AttestError;
use crate::statement::{DIVERGENCE, EQUIVALENCE, STATEMENT_TYPE, Statement, Subject};

pub const EQUIVALENCE_V2: &str = "https://trigon.dev/equivalence/v2";
pub const DIVERGENCE_V2: &str = "https://trigon.dev/divergence/v2";
pub const VOID: &str = "https://trigon.dev/void/v1";
pub const WITHDRAWAL: &str = "https://trigon.dev/withdrawal/v1";

/// Whether a predicate type is a verdict — a comparison claim `rederive` can check — in either
/// version.
pub fn is_verdict(predicate_type: &str) -> bool {
    matches!(
        predicate_type,
        EQUIVALENCE | DIVERGENCE | EQUIVALENCE_V2 | DIVERGENCE_V2
    )
}

/// Whether a predicate type is a record's result: a verdict, a void or a withdrawal, as against
/// the `rebuild` and `buildobservation` statements that accompany a verdict.
pub fn is_primary(predicate_type: &str) -> bool {
    is_verdict(predicate_type) || matches!(predicate_type, VOID | WITHDRAWAL)
}

/// The names evidence goes by: in a verdict's signed `evidence`, and in a record's unsigned map.
///
/// One set of names for both, so the check that a record's map agrees with its signed verdict
/// (`docs/19` §4.1) compares like with like.
pub mod evidence_key {
    /// The stabilizer set's manifest file, as canonical JSON. Not the set digest, which is a hash
    /// over the manifest's rows and the digest of no file.
    pub const STABILIZER_SET_MANIFEST: &str = "stabilizerSetManifest";
    /// The comparison report the run stored: per-member differences, codes and field edits.
    pub const COMPARISON: &str = "comparison";
    /// The strategy that ran, as the canonical JSON the run stored (`RunRecord.strategy`).
    pub const STRATEGY: &str = "strategy";
    /// The manifest the artifact guard was armed with.
    pub const GUARD_MANIFEST: &str = "guardManifest";
    /// The rebuilt artifact.
    pub const REBUILT_ARTIFACT: &str = "rebuiltArtifact";
}

/// Why a published record is superseded: the closed list of `docs/19` §3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupersedeReason {
    /// We were wrong, and say so.
    Withdrawn,
    /// The stabilizer set changed, and the claim is made again under the new one.
    SetChanged,
    /// A later attempt disagreed with the ones the record was published on.
    AttemptsDisagreeLater,
    /// Something in our pipeline made the record wrong.
    PipelineBug,
}

impl SupersedeReason {
    pub const ALL: [SupersedeReason; 4] = [
        SupersedeReason::Withdrawn,
        SupersedeReason::SetChanged,
        SupersedeReason::AttemptsDisagreeLater,
        SupersedeReason::PipelineBug,
    ];

    /// The wire name, which is also what `--reason` takes.
    pub fn as_str(self) -> &'static str {
        match self {
            SupersedeReason::Withdrawn => "withdrawn",
            SupersedeReason::SetChanged => "set_changed",
            SupersedeReason::AttemptsDisagreeLater => "attempts_disagree_later",
            SupersedeReason::PipelineBug => "pipeline_bug",
        }
    }
}

impl FromStr for SupersedeReason {
    type Err = AttestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SupersedeReason::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| {
                AttestError::Malformed(format!(
                    "`{s}` is not a reason a record is superseded for. The reasons are {}",
                    SupersedeReason::ALL.map(SupersedeReason::as_str).join(", ")
                ))
            })
    }
}

impl std::fmt::Display for SupersedeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A record this statement supersedes, and why. Signed into the statement, never beside it
/// (`docs/19` §4.1), and equal to the leaf's (§4.2 item 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Supersession {
    /// The sha256 of the superseded record file.
    pub record: Digest,
    pub reason: SupersedeReason,
}

impl Supersession {
    fn sign_into(&self, p: &mut Value) {
        p["supersedes"] = json!(format!("sha256:{}", self.record.to_hex()));
        p["reason"] = json!(self.reason.as_str());
    }
}

/// The command that would falsify a verdict, as argv.
///
/// Structured rather than a string, so a client runs it without parsing a shell line out of a
/// signed document, and renders it for a person with [`Self::render`]. It names the subject, the
/// predicate type and the log's origin, and not the record's own digest, which is the digest of
/// the file that contains it (`docs/19` §4.2 item 6). The client resolves the current record
/// through the log. `<file>` is the upstream artifact the reader holds; where the repository that
/// holds the record does not publish its rebuilt artifact (docs/19 D4), or the verdict is exact and
/// its rebuilt artifact is that upstream artifact, the client also asks for `--rebuild <file>`, so
/// the same signed command works either way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalsifyingCommand {
    pub argv: Vec<String>,
}

impl FalsifyingCommand {
    /// The placeholder for the upstream artifact, which the reader supplies.
    pub const UPSTREAM: &str = "<file>";

    pub fn new(subject_sha256: &str, predicate_type: &str, origin: &str) -> Self {
        let argv = [
            "trigon",
            "verify-attestation",
            "--lookup",
            &format!("sha256:{subject_sha256}"),
            "--predicate",
            predicate_type,
            "--origin",
            origin,
            "--rerun-comparison",
            "--upstream",
            Self::UPSTREAM,
        ];
        FalsifyingCommand {
            argv: argv.map(str::to_string).to_vec(),
        }
    }

    /// The command as a person reads it: `trigon verify-attestation --lookup sha256:<subject>
    /// --predicate <type> --origin <origin> --rerun-comparison --upstream <file>`.
    pub fn render(&self) -> String {
        self.argv.join(" ")
    }
}

/// Where a verdict is disputed. Typed, so a later kind — an email address, a form — is a new
/// variant a client can refuse by name rather than a string it has to guess at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum DisputePointer {
    Url { url: String },
}

/// Where a verdict's digests point: the evidence a record names, each a sha256 in hex. `None` is
/// absent, and is written as absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EvidenceDigests<'a> {
    pub stabilizer_set_manifest: Option<&'a str>,
    pub comparison: Option<&'a str>,
    pub strategy: Option<&'a str>,
    pub guard_manifest: Option<&'a str>,
    pub rebuilt_artifact: Option<&'a str>,
}

impl EvidenceDigests<'_> {
    fn to_value(self) -> Value {
        let mut o = serde_json::Map::new();
        for (key, digest) in [
            (
                evidence_key::STABILIZER_SET_MANIFEST,
                self.stabilizer_set_manifest,
            ),
            (evidence_key::COMPARISON, self.comparison),
            (evidence_key::STRATEGY, self.strategy),
            (evidence_key::GUARD_MANIFEST, self.guard_manifest),
            (evidence_key::REBUILT_ARTIFACT, self.rebuilt_artifact),
        ] {
            if let Some(d) = digest {
                o.insert(key.into(), json!({ "sha256": d }));
            }
        }
        Value::Object(o)
    }
}

/// What a run is, for the statements that describe its result. Borrowed from the run record, as
/// [`crate::RunFacts`] is, so this crate never learns where a run is stored.
#[derive(Clone, Copy, Debug)]
pub struct RunIdentity<'a> {
    pub purl: &'a CanonicalPurl,
    pub run_id: &'a str,
    pub started: &'a str,
    pub finished: Option<&'a str>,
    /// The Trigon that ran the build, as the run recorded it. `None` on a run recorded before it
    /// was, and then absent from the statement rather than guessed.
    pub builder_version: Option<&'a str>,
    /// The Trigon signing this statement.
    pub attestor_version: &'a str,
    pub egress: &'a str,
    pub attestable: bool,
}

impl RunIdentity<'_> {
    fn sign_into(&self, p: &mut Value) {
        p["purl"] = json!(self.purl.as_str());
        p["purlCanon"] = json!(PURL_CANON);
        let mut run = json!({ "id": self.run_id, "startedOn": self.started });
        if let Some(f) = self.finished {
            run["finishedOn"] = json!(f);
        }
        p["run"] = run;
        // Both, because they answer different questions and were conflated: the only version
        // signed anywhere was the attestor's, in `rebuild`, so a run attested by a later binary
        // claimed that binary had built it (`docs/19` §4.2 item 3).
        let mut versions = json!({ "attestor": self.attestor_version });
        if let Some(b) = self.builder_version {
            versions["builder"] = json!(b);
        }
        p["trigonVersion"] = versions;
        // In the verdict itself, so one statement answers: the tier was signed only in
        // `buildobservation` and `attestable` only in `rebuild` (§4.2 item 4).
        p["egressTier"] = json!(self.egress);
        p["attestable"] = json!(self.attestable);
    }
}

/// What a v2 verdict signs beyond the comparison.
#[derive(Clone, Copy, Debug)]
pub struct VerdictFacts<'a> {
    pub run: RunIdentity<'a>,
    /// `definition`, `heuristic`, `ci_derived`, `model_assisted`, as the run recorded it. `None`
    /// is absent from the statement: a run with none was signed as `heuristic`, which is absence
    /// rendered as a value (§4.2 item 5).
    pub derivation: Option<&'a str>,
    pub evidence: EvidenceDigests<'a>,
    /// The log's origin and the dispute channel, from `[publish]`, when both are set. Absent, both
    /// the falsifying command and the dispute pointer are left out, never written empty, so a
    /// statement made for local use names no repository (`docs/19` §2.4).
    pub namespace: Option<(&'a str, &'a str)>,
    pub supersedes: Option<Supersession>,
}

impl Statement {
    /// A v2 verdict: `equivalence/v2`, or `divergence/v2` for a divergence.
    ///
    /// Refused, as [`Self::equivalence_for`] refuses, when the subject is not the comparison's
    /// upstream artifact.
    pub fn verdict(
        subject: Subject,
        c: &Comparison,
        f: &VerdictFacts,
    ) -> Result<Self, AttestError> {
        let mut st = Self::equivalence_for(subject, c)?;
        st.predicate_type = if st.predicate_type == DIVERGENCE {
            DIVERGENCE_V2.into()
        } else {
            EQUIVALENCE_V2.into()
        };
        let p = &mut st.predicate;
        f.run.sign_into(p);
        if let Some(m) = f.derivation {
            p["derivation"] = json!({ "method": m });
        }
        p["evidence"] = f.evidence.to_value();
        if let Some((origin, disputes)) = f.namespace {
            let sha256 = st.subject[0].digest["sha256"].clone();
            p["falsifyingCommand"] =
                serde_json::to_value(FalsifyingCommand::new(&sha256, &st.predicate_type, origin))?;
            p["disputePointer"] = serde_json::to_value(DisputePointer::Url {
                url: disputes.to_string(),
            })?;
        }
        if let Some(s) = &f.supersedes {
            s.sign_into(p);
        }
        Ok(st)
    }
}

/// An applied stabilizer that was not built in: one of the facts a void can rest on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoredPass {
    pub id: String,
    pub risk: String,
    /// `human` or `model`.
    pub provenance: String,
}

impl AuthoredPass {
    /// The applied stabilizers of a comparison that a person or a model wrote, each once.
    pub fn of(c: &Comparison) -> Vec<AuthoredPass> {
        let mut out: Vec<AuthoredPass> = Vec::new();
        for a in c.applied() {
            let provenance = match &a.provenance {
                trigon_core::Provenance::Builtin => continue,
                trigon_core::Provenance::Human { .. } => "human",
                trigon_core::Provenance::Model { .. } => "model",
            };
            if out.iter().any(|p| p.id == a.id.as_str()) {
                continue;
            }
            out.push(AuthoredPass {
                id: a.id.as_str().to_string(),
                risk: format!("{:?}", a.risk).to_lowercase(),
                provenance: provenance.into(),
            });
        }
        out
    }
}

/// What a `void/v1` statement signs.
#[derive(Clone, Copy, Debug)]
pub struct VoidFacts<'a> {
    pub run: RunIdentity<'a>,
    /// Why the run is void, in the publication gate's words: `guard_tripped`, `open_egress` or
    /// `non_builtin_stabilizer`.
    pub because: &'a str,
    /// What the artifact guard caught, as the run recorded it.
    pub guard_trips: &'a [String],
    /// The digest of the manifest the guard was armed with, where it was.
    pub guard_manifest: Option<&'a str>,
    pub guarded_members: Option<u64>,
    /// The stabilizers a person or a model wrote that applied, where the run compared.
    pub authored: &'a [AuthoredPass],
    /// The set the run compared under, `(id, digest)`, where it compared at all. A build the guard
    /// stopped reached no comparison, and names no set.
    pub stabilizer_set: Option<(&'a str, &'a str)>,
    /// The guard manifest, as evidence the record carries, where the store holds it.
    pub guard_manifest_evidence: Option<&'a str>,
    pub supersedes: Option<Supersession>,
}

impl Statement {
    /// `void/v1`: the run is evidence of nothing about the package, and this says why.
    ///
    /// **No comparison outcome and no difference data**, deliberately: not the outcome, not the
    /// rebuilt artifact's digest (beside the upstream's it says whether the rebuild was `exact`),
    /// not the comparison report, not which members differed. A void is published so that "we
    /// looked, and could not tell" is on the record; anything that says which way the run went is
    /// an outcome published without the safeguards an outcome needs, and for a divergence it is
    /// the accusation the gate exists to stop.
    pub fn void(subject: Subject, f: &VoidFacts) -> Self {
        let mut check = json!({
            // A guard that was not armed is not one that found nothing.
            "performed": f.guard_manifest.is_some(),
            "trips": f.guard_trips,
        });
        if let Some(d) = f.guard_manifest {
            check["guardManifest"] = json!({ "sha256": d });
        }
        if let Some(n) = f.guarded_members {
            check["guardedMembers"] = json!(n);
        }
        // The egress tier is the third fact a void can rest on; it is signed at the top level,
        // where every statement about a run has it, by `sign_into` below.
        let mut facts = json!({ "artifactHashCheck": check });
        if !f.authored.is_empty() {
            facts["authoredStabilizers"] = f
                .authored
                .iter()
                .map(|a| json!({ "id": a.id, "risk": a.risk, "provenance": a.provenance }))
                .collect();
        }
        let mut p = json!({
            // `void` is not a rung of `Match`, and is never read as one; it is the fifth state.
            "outcome": "void",
            "because": f.because,
            "facts": facts,
        });
        f.run.sign_into(&mut p);
        // The set, which is also on the void's leaf, and its digest alone: which set a run was
        // judged under says nothing about what the judgement was.
        if let Some((id, digest)) = f.stabilizer_set {
            p["stabilizerSet"] = json!({ "id": id, "digest": { "sha256": digest } });
        }
        p["evidence"] = EvidenceDigests {
            guard_manifest: f.guard_manifest_evidence,
            ..Default::default()
        }
        .to_value();
        if let Some(s) = &f.supersedes {
            s.sign_into(&mut p);
        }
        Statement {
            type_: STATEMENT_TYPE.into(),
            subject: vec![subject],
            predicate_type: VOID.into(),
            predicate: p,
        }
    }

    /// `withdrawal/v1`: "we were wrong" about a published record, and no verdict in its place.
    ///
    /// The subject and purl are the superseded record's own, as its signed statement names them,
    /// so a client that finds the withdrawal under a key finds it under every key the record had.
    /// There is no run behind it, so no builder version and no environment.
    pub fn withdrawal(
        subject: Subject,
        purl: &str,
        purl_canon: u64,
        supersedes: Supersession,
        attestor_version: &str,
    ) -> Self {
        let mut p = json!({
            "purl": purl,
            "purlCanon": purl_canon,
            "trigonVersion": { "attestor": attestor_version },
        });
        supersedes.sign_into(&mut p);
        Statement {
            type_: STATEMENT_TYPE.into(),
            subject: vec![subject],
            predicate_type: WITHDRAWAL.into(),
            predicate: p,
        }
    }
}

/// A stabilizer set's manifest as a file: its canonical JSON, the bytes whose sha256 a verdict
/// signs as `evidence.stabilizerSetManifest`.
///
/// Canonical, so the digest is a property of the manifest rather than of how one writer
/// pretty-printed it; a record's evidence file is these bytes.
pub fn set_manifest_file(m: &trigon_stabilize::SetManifest) -> Result<Vec<u8>, AttestError> {
    let v = serde_json::to_value(m)?;
    Ok(trigon_core::jcs::canonicalize(&v)
        .map_err(|e| AttestError::Canonicalize(e.to_string()))?
        .into_bytes())
}
