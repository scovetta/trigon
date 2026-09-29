//! Re-deriving a claim from the artifacts it is about.
//!
//! The flagship. An attestation from a rebuilder is worth something only to someone who distrusts
//! the rebuilder, so the equivalence claim has to be **falsifiable by a third party holding two
//! artifacts and our stabilizer implementation**. That is what this does, and it is why several
//! other decisions are what they are: the stabilizer set is named by id *and* digest, the archive
//! format is named explicitly, and a set digest that does not match today's is refused rather than
//! papered over.

use sha2::{Digest as _, Sha256, Sha512};
use trigon_archive::Limits;
use trigon_compare::compare_bytes;
use trigon_core::{Digest, Format, Match};

use crate::AttestError;
use crate::dsse::Envelope;
use crate::statement::Statement;

/// Sign a statement into an envelope.
pub fn sign_statement(
    statement: &Statement,
    signer: &dyn crate::Signer,
) -> Result<Envelope, AttestError> {
    let payload = statement.canonical()?;
    let sig = signer.sign(&crate::dsse::pae(crate::PAYLOAD_TYPE, &payload))?;
    Ok(Envelope::new(&payload, vec![sig]))
}

/// What re-deriving a claim found.
#[derive(Debug, Clone, PartialEq)]
pub struct Rederived {
    /// The outcome the statement claims.
    pub claimed: String,
    /// The outcome recomputed here from the bytes.
    pub actual: Match,
    /// Whether the stabilized digests the statement claims are the ones the artifacts produce.
    pub digests_match: bool,
    pub stabilizer_set: String,
    /// What the statement signs about the comparison — its `differences`, `applied` and
    /// `members` — that re-deriving does not give, each with what it does give.
    pub disagreements: Vec<Disagreement>,
    /// What was not re-derived, and so is neither held nor refuted: with an archived set, which
    /// returns stabilized bytes and no report, `differences`, `applied` and `members`.
    pub unchecked: Vec<&'static str>,
    /// Every field a verdict signs about the comparison, as re-deriving gives it: what a published
    /// comparison report is checked against ([`Self::check_report`]). `None` where nothing was
    /// re-derived to check against, with an archived set.
    pub rederived: Option<serde_json::Value>,
    /// What re-deriving gives of the comparison report beyond what a verdict signs: every member,
    /// with its status, kind, digests and sizes, in order, and which passes changed which field
    /// (`diff.files`, `diff.field_edits`). The rest of a published report is held to these by
    /// [`Self::check_report`]. `None` where nothing was re-derived, as for
    /// [`Self::rederived`].
    pub located: Option<serde_json::Value>,
}

/// What holding a published comparison report to a re-derivation found
/// ([`Rederived::check_report`]).
#[derive(Debug, Clone, PartialEq)]
pub struct ReportCheck {
    /// Each part of the report that is not what re-deriving gives.
    pub disagreements: Vec<Disagreement>,
    /// The parts of the report it was not held to, which neither agree nor disagree: never
    /// counted as checked.
    pub unchecked: Vec<&'static str>,
}

impl ReportCheck {
    /// Whether every part it was held to agrees. Says nothing about [`Self::unchecked`].
    pub fn agrees(&self) -> bool {
        self.disagreements.is_empty()
    }
}

/// One field a statement, or a comparison report, says one thing about and re-deriving another.
#[derive(Debug, Clone, PartialEq)]
pub struct Disagreement {
    pub field: &'static str,
    /// What the statement signs, or the report says; `null` where it says nothing.
    pub said: serde_json::Value,
    pub rederived: serde_json::Value,
}

impl std::fmt::Display for Disagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Compact, and escaped: member paths and difference codes come from the artifacts.
        write!(
            f,
            "`{}` says {} and re-deriving gives {}",
            self.field,
            crate::location::printable(&self.said.to_string()),
            crate::location::printable(&self.rederived.to_string())
        )
    }
}

/// The fields of a verdict that describe what the comparison found, beyond its outcome and its
/// stabilized digests, which [`rederive_with`] checks on their own.
const FOUND: [&str; 3] = ["differences", "applied", "members"];

/// The fields a published comparison report is held to: everything a verdict signs about the
/// comparison that the report determines, read off the report as the verdict would sign it.
const REPORTED: [&str; 8] = [
    "outcome",
    "archiveFormat",
    "stabilizerSet",
    "artifacts",
    "stabilized",
    "differences",
    "applied",
    "members",
];

/// What a published comparison report is never held to, because the same bytes under the same set
/// need not give it back: explanation — the pass-by-pass progression, and the notes, whose words
/// a later build may change — and each member's name in either artifact, which a report written
/// before those were kept does not carry. Listed as unchecked, never passed.
const EXPLANATION: [&str; 3] = ["diff.progression", "notes", "the members' raw paths"];

/// A report's field edits, which a report written before they were kept does not carry.
const FIELD_EDITS: &str = "diff.field_edits";

impl Rederived {
    /// Whether the statement's claim survived being checked: the outcome, both stabilized digests,
    /// and what it says the comparison found.
    pub fn holds(&self) -> bool {
        self.digests_match
            && self.claimed == self.actual.to_string()
            && self.disagreements.is_empty()
    }

    /// Check a published comparison report — the comparison the run stored, which a record names
    /// by digest (`docs/19` §4.1) — against this re-derivation: its outcome, set, digests and
    /// what it found must be what re-deriving gives, field by field as a verdict signs them; and so
    /// must every member it reports, with its status, kind, digests and sizes, and its field
    /// edits, where it carries them. What it is not held to is listed in the result, and never
    /// counted as agreeing.
    ///
    /// `None` when there is nothing to check it against: an archived set re-derives digests and no
    /// report, and the report is then unchecked, never passed.
    pub fn check_report(&self, report: &[u8]) -> Result<Option<ReportCheck>, AttestError> {
        let (Some(rederived), Some(located)) = (&self.rederived, &self.located) else {
            return Ok(None);
        };
        let c: trigon_compare::Comparison = serde_json::from_slice(report).map_err(|e| {
            AttestError::Evidence(format!(
                "the comparison report is not a comparison this build reads: {}",
                crate::location::printable(&e.to_string())
            ))
        })?;
        let said = crate::statement::equivalence_predicate(&c);
        let mut found = disagreements(&REPORTED, &said, rederived);
        let mut unchecked = EXPLANATION.to_vec();
        let reported = located_in(&c)?;
        let files = "diff.files";
        found.extend(first_difference(files, &reported[files], &located[files]));
        // None, where re-deriving finds some, is a report written before field edits were kept:
        // unchecked. Any, and they must be the ones re-deriving finds.
        let (said, edits) = (&reported[FIELD_EDITS], &located[FIELD_EDITS]);
        let none = |v: &serde_json::Value| v.as_array().is_none_or(Vec::is_empty);
        if none(said) && !none(edits) {
            unchecked.push(FIELD_EDITS);
        } else {
            found.extend(first_difference(FIELD_EDITS, said, edits));
        }
        Ok(Some(ReportCheck {
            disagreements: found,
            unchecked,
        }))
    }
}

/// What a comparison says of each member, as [`Rederived::located`] holds it: `diff.files`
/// without the raw paths (see [`EXPLANATION`]), and `diff.field_edits`, each empty where the
/// comparison has no member report.
fn located_in(c: &trigon_compare::Comparison) -> Result<serde_json::Value, AttestError> {
    let empty = Vec::new();
    let (files, edits) = match &c.diff {
        Some(d) => (&d.files, serde_json::to_value(&d.field_edits)?),
        None => (&empty, serde_json::json!([])),
    };
    let mut members = Vec::with_capacity(files.len());
    for f in files {
        let mut v = serde_json::to_value(f)?;
        if let Some(o) = v.as_object_mut() {
            o.remove("upstream_raw_path");
            o.remove("rebuild_raw_path");
            // A path serializes as its bytes. As text where it is UTF-8, so that a disagreement
            // names the member readably; bytes where it is not, which no text equals, so two
            // members are one here only where they are one path.
            if let Ok(p) = std::str::from_utf8(f.path.as_bytes()) {
                o.insert("path".into(), p.into());
            }
        }
        members.push(v);
    }
    let files = serde_json::Value::Array(members);
    let mut out = serde_json::Map::new();
    out.insert("diff.files".into(), files);
    out.insert(FIELD_EDITS.into(), edits);
    Ok(serde_json::Value::Object(out))
}

/// The first entry at which two lists differ, as a disagreement over `field`: one entry is enough
/// to refute the list, and naming every entry after a missing one would bury it.
fn first_difference(
    field: &'static str,
    said: &serde_json::Value,
    rederived: &serde_json::Value,
) -> Option<Disagreement> {
    let empty = Vec::new();
    let (s, r) = (
        said.as_array().unwrap_or(&empty),
        rederived.as_array().unwrap_or(&empty),
    );
    let null = serde_json::Value::Null;
    (0..s.len().max(r.len())).find_map(|i| {
        let (a, b) = (s.get(i).unwrap_or(&null), r.get(i).unwrap_or(&null));
        (a != b).then(|| Disagreement {
            field,
            said: a.clone(),
            rederived: b.clone(),
        })
    })
}

/// Each of `fields` on which `said` and `rederived` differ. A field absent from either is `null`
/// there, so a statement that leaves out what re-deriving finds disagrees with it, and one that
/// names what re-deriving does not find disagrees too.
fn disagreements(
    fields: &[&'static str],
    said: &serde_json::Value,
    rederived: &serde_json::Value,
) -> Vec<Disagreement> {
    let null = serde_json::Value::Null;
    fields
        .iter()
        .filter_map(|&field| {
            let (s, r) = (
                said.get(field).unwrap_or(&null),
                rederived.get(field).unwrap_or(&null),
            );
            (s != r).then(|| Disagreement {
                field,
                said: s.clone(),
                rederived: r.clone(),
            })
        })
        .collect()
}

/// Recompute an equivalence claim from the two artifacts it is about.
///
/// Refuses to run under a different stabilizer set than the statement names. It could quietly
/// re-derive under today's set and report a match, but that would answer a different question than
/// the one the statement asked: a match would mean nothing and a mismatch would not be evidence
/// either. Loading the named set, or reporting a new claim, are the two honest options, and this
/// takes the first and names the second.
pub fn rederive(
    statement: &Statement,
    upstream: Vec<u8>,
    rebuild: Vec<u8>,
) -> Result<Rederived, AttestError> {
    rederive_with(statement, upstream, rebuild, None)
}

/// How to stabilize, when it is not the set compiled into this binary.
///
/// A trait so `trigon-attest` stays free of a WebAssembly runtime: the judgement half must not link
/// one, and the verifier build's dependency tree is the claim a sceptic checks. The implementation
/// lives in `trigon-stabilize-wasm` behind its `host` feature, below the line.
pub trait ArchivedStabilizer {
    /// The set digest this implementation provides for `profile`.
    fn digest(&mut self, profile: &str) -> Result<Digest, String>;
    fn stabilize(&mut self, profile: &str, format: Format, bytes: &[u8])
    -> Result<Vec<u8>, String>;
}

/// Re-derive a claim, optionally through a stabilizer set this binary does not carry.
///
/// The whole reason an archived set is worth publishing. Without one, a verifier holding a
/// statement made under an older set gets `SetMismatch` and stops: correct, and useless to them.
/// With one, the claim is checkable against the set it was actually made under — which is what
/// "every stabilizer version archived forever" was always for.
///
/// The archived path checks digests rather than producing a diff report. A diff describes *how* two
/// artifacts differ and is a triage aid; the claim under test is only that their stabilized forms
/// are equal, and that is a digest comparison. Running somebody else's module to produce prose
/// nobody reads would be paying for the wrong thing.
pub fn rederive_with(
    statement: &Statement,
    upstream: Vec<u8>,
    rebuild: Vec<u8>,
    archived: Option<&mut dyn ArchivedStabilizer>,
) -> Result<Rederived, AttestError> {
    // A void or a withdrawal makes no comparison claim, and one read as though it did would fail
    // on some missing field with a message about the field. Refused by what it is, and a verdict
    // type this build does not know is refused the same way rather than read as a v1.
    if !crate::verdict::is_verdict(&statement.predicate_type) {
        return Err(AttestError::Malformed(format!(
            "`{}` makes no comparison claim, so there is nothing to re-derive. \
             `--rerun-comparison` checks an equivalence or a divergence statement, v1 or v2",
            statement.predicate_type
        )));
    }
    let p = &statement.predicate;
    let claimed = p["outcome"]
        .as_str()
        .ok_or_else(|| AttestError::Evidence("predicate has no `outcome`".into()))?
        .to_string();

    let set_id = p["stabilizerSet"]["id"]
        .as_str()
        .ok_or_else(|| AttestError::Evidence("predicate names no stabilizer set".into()))?;
    let set_digest = p["stabilizerSet"]["digest"]["sha256"]
        .as_str()
        .ok_or_else(|| AttestError::Evidence("the stabilizer set has no digest".into()))?;

    // An archived set is consulted first and has to *be* the set the statement names — checked
    // here, because a module implementing some other set produces a plausible digest rather than an
    // error, and that is the one failure this whole mechanism exists to prevent.
    let archived = match archived {
        Some(a) => {
            let got = a
                .digest(set_id)
                .map_err(|e| AttestError::Malformed(format!("the archived set failed: {e}")))?
                .to_hex();
            if got != set_digest {
                return Err(AttestError::SetMismatch {
                    claimed: format!("{set_id}@{}", &set_digest[..12.min(set_digest.len())]),
                    current: format!(
                        "{set_id}@{} (the module supplied)",
                        &got[..12.min(got.len())]
                    ),
                });
            }
            Some(a)
        }
        None => None,
    };

    let native = trigon_stabilize::profile(set_id);
    if archived.is_none() {
        let set = native.as_ref().ok_or_else(|| AttestError::SetMismatch {
            claimed: format!("{set_id} (unknown to this build)"),
            current: trigon_stabilize::all_profiles().join(", "),
        })?;
        let current = set.digest().to_hex();
        if current != set_digest {
            return Err(AttestError::SetMismatch {
                claimed: format!("{set_id}@{}", &set_digest[..12.min(set_digest.len())]),
                current: format!("{set_id}@{}", &current[..12.min(current.len())]),
            });
        }
    }

    // The format is taken from the statement rather than sniffed. A verifier holding an attestation
    // and two files has no ecosystem to ask, and one that guesses reads a `.gem` as a plain tar and
    // computes a different digest for a correct artifact.
    let format = parse_format(
        p["archiveFormat"]
            .as_str()
            .ok_or_else(|| AttestError::Evidence("predicate names no archive format".into()))?,
    )?;

    // Are these even the artifacts the statement is about? Checked *before* the claim, and reported
    // as a different kind of error, because "you handed me the wrong file" and "this statement is a
    // lie" are not the same finding. It also closes a real hole: two artifacts can differ in raw
    // bytes and stabilize to the same form — that is the normal case, and it means the stabilized
    // check alone would accept a substituted artifact as proof of the claim.
    //
    // **Every digest the subject names, not only sha256.** A subject carries sha512, and sha1 for
    // npm, because those are what a consumer looks the artifact up by (`docs/19` §5). Checking one
    // and trusting the rest would let a statement be found under a digest of some other file and
    // then verify against this one. A statement signed before subjects carried more than sha256
    // names sha256 alone, and verifies exactly as it did.
    let subject = statement
        .subject
        .first()
        .filter(|s| s.digest.contains_key("sha256"))
        .ok_or_else(|| AttestError::Evidence("the statement names no subject digest".into()))?;
    // sha256 first, so a different file is reported by the digest every statement has. Once it
    // agrees, the file in hand is the artifact the statement is about, and another digest that
    // does not is the statement's error and not the caller's: refuted, not the wrong file.
    let mut named: Vec<(&String, &String)> = subject.digest.iter().collect();
    named.sort_by_key(|(algorithm, _)| algorithm.as_str() != "sha256");
    for (algorithm, expected) in named {
        let got = digest_hex(algorithm, &upstream).ok_or_else(|| {
            AttestError::Malformed(format!(
                "the subject names a {algorithm} digest, which this verifier cannot compute, so \
                 it cannot say the file in hand is the one the statement is about. Trigon writes \
                 sha256, sha512 and sha1 only."
            ))
        })?;
        if *expected == got {
            continue;
        }
        if algorithm == "sha256" {
            return Err(AttestError::WrongArtifact {
                side: "upstream",
                algorithm: algorithm.clone(),
                expected: expected.clone(),
                got,
            });
        }
        return Err(AttestError::SubjectRefuted {
            algorithm: algorithm.clone(),
            claimed: expected.clone(),
            actual: got,
        });
    }
    let Some(expected) = p["artifacts"]["rebuild"]["sha256"].as_str() else {
        return Err(AttestError::Evidence(
            "predicate has no raw digest for the rebuild artifact".into(),
        ));
    };
    let got = hex(&Sha256::digest(&rebuild));
    if expected != got {
        return Err(AttestError::WrongArtifact {
            side: "rebuild",
            algorithm: "sha256".into(),
            expected: expected.to_string(),
            got,
        });
    }

    let (outcome, up_stab, rb_stab, rederived, located) = match archived {
        Some(a) => {
            let u = a
                .stabilize(set_id, format, &upstream)
                .map_err(|e| AttestError::Malformed(format!("the archived set failed: {e}")))?;
            let r = a
                .stabilize(set_id, format, &rebuild)
                .map_err(|e| AttestError::Malformed(format!("the archived set failed: {e}")))?;
            let (ud, rd) = (hex(&Sha256::digest(&u)), hex(&Sha256::digest(&r)));
            // `Exact` when the raw bytes were identical, which the caller already established
            // above; otherwise equality of the stabilized forms is `NormalizedWithCaveats`. Not
            // `Normalized`: the provenance cap needs each applied stabilizer's risk and provenance,
            // and a module that only returns bytes cannot supply them. Claiming the stronger
            // outcome on less evidence is the one direction this must not err in.
            let outcome = if upstream == rebuild {
                Match::Exact
            } else if ud == rd {
                Match::NormalizedWithCaveats
            } else {
                Match::Divergent
            };
            (outcome, ud, rd, None, None)
        }
        None => {
            let set = native.expect("checked above when no archived set was supplied");
            let c = compare_bytes(upstream, rebuild, format, &set, &Limits::default())
                .map_err(|e| AttestError::Malformed(e.to_string()))?;
            (
                c.outcome,
                c.upstream.stabilized.sha256.to_hex(),
                c.rebuild.stabilized.sha256.to_hex(),
                // The comparison's claims as a verdict would sign them, by the one function that
                // builds a verdict: a second spelling here could agree with a wrong statement.
                Some(crate::statement::equivalence_predicate(&c)),
                Some(located_in(&c)?),
            )
        }
    };

    // Both sides, because a statement that got one right and one wrong is still refuted.
    for (side, claimed_digest, actual) in [
        (
            "upstream",
            p["stabilized"]["upstream"]["sha256"].as_str(),
            &up_stab,
        ),
        (
            "rebuild",
            p["stabilized"]["rebuild"]["sha256"].as_str(),
            &rb_stab,
        ),
    ] {
        let Some(claimed_digest) = claimed_digest else {
            return Err(AttestError::Evidence(format!(
                "predicate has no stabilized digest for the {side} artifact"
            )));
        };
        if claimed_digest != *actual {
            return Err(AttestError::ClaimRefuted {
                side,
                claimed: claimed_digest.to_string(),
                actual: actual.clone(),
            });
        }
    }

    // What the statement says the comparison found: which members differ and how, and which
    // passes fired on which side. Signed, so a statement that got the outcome and the digests
    // right and misreported either — a divergence naming members that do not differ, a match
    // hiding a pass that capped it — is refuted like one that got the outcome wrong.
    let (disagreements, unchecked) = match &rederived {
        Some(r) => (disagreements(&FOUND, p, r), Vec::new()),
        None => (Vec::new(), FOUND.to_vec()),
    };

    Ok(Rederived {
        claimed,
        actual: outcome,
        digests_match: true,
        stabilizer_set: format!("{set_id}@{}", &set_digest[..12.min(set_digest.len())]),
        disagreements,
        unchecked,
        rederived,
        located,
    })
}

/// The subject digest a statement is about, for checking it against the artifact in hand.
pub fn subject_sha256(statement: &Statement) -> Option<Digest> {
    statement
        .subject
        .first()
        .and_then(|s| s.digest.get("sha256"))
        .and_then(|h| Digest::from_hex(h).ok())
}

/// A digest of `bytes` under an algorithm a subject may name, or `None` for one this does not know.
fn digest_hex(algorithm: &str, bytes: &[u8]) -> Option<String> {
    Some(match algorithm {
        "sha256" => hex(&Sha256::digest(bytes)),
        "sha512" => hex(&Sha512::digest(bytes)),
        "sha1" => hex(&sha1::Sha1::digest(bytes)),
        _ => return None,
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_format(s: &str) -> Result<Format, AttestError> {
    // One parser, in `trigon-core`. This was a second table that accepted `tar-gz` where the
    // binary's accepted `tar.gz` and `tgz`, so the same string was a format in one process and an
    // error in the other.
    s.parse::<Format>()
        .map_err(|e| AttestError::Evidence(e.to_string()))
}
