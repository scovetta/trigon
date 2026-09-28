//! in-toto Statement v1, and the predicates we are willing to put inside one.
//!
//! Hand-written serde structs rather than a dependency. The Rust `in-toto` crate is not usable and
//! this is the one place in the design that can least afford a supply-chain dependency: the
//! statement is what we sign, so anything that shapes its bytes is as trusted as our own code.
//!
//! The rule the whole layer is built around: **a verifier who has never heard of a language model
//! has to be able to check the claim.**
//!
//! > Recipe R, executed in fully described environment E, produced artifact A whose stabilized form
//! > under versioned stabilizer set S equals the stabilized form of published artifact P.
//!
//! Every noun there is deterministic. Whether a model helped derive R appears beside the claim as a
//! provenance fact and stays out of it. See `docs/09-attestations.md` §1.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use trigon_compare::Comparison;
use trigon_core::{Digest, Sha1, Sha512};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const EQUIVALENCE: &str = "https://trigon.dev/equivalence/v1";
pub const DIVERGENCE: &str = "https://trigon.dev/divergence/v1";

/// One artifact a statement is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    /// Keyed by algorithm, as in-toto requires. `BTreeMap` because this is canonicalized and
    /// signed: an order that depended on insertion would make the same statement hash two ways.
    pub digest: BTreeMap<String, String>,
}

impl Subject {
    /// A subject named by sha256 alone.
    ///
    /// What every statement carried before subjects carried each digest a consumer might hold, and
    /// still the honest subject where sha256 is all that is known: a run recorded before its other
    /// digests were, whose bytes are no longer in the store. Such statements still verify, because
    /// a verifier checks the digests a subject names and no others.
    pub fn new(name: impl Into<String>, sha256: &Digest) -> Self {
        Subject {
            name: name.into(),
            digest: BTreeMap::from([("sha256".to_string(), sha256.to_hex())]),
        }
    }

    /// A subject carrying sha256 and sha512, and sha1 where the ecosystem publishes one.
    ///
    /// **Every digest a consumer might look the artifact up by, because a lookup key that is not
    /// in the subject finds nothing** (`docs/19` §5). An npm lockfile names a package by its sha512
    /// `integrity`, and an old one by its sha1 `shasum`; neither is sha256, so a statement keyed on
    /// sha256 alone is unfindable from the one thing an npm consumer holds.
    ///
    /// The digests are the caller's to compute **over the bytes**, never to copy from what a
    /// registry declared: a declaration is a claim the fetch checked, and a subject is what the
    /// signature is about. [`Self::of_bytes`] computes them; this is for a caller that already
    /// has them, such as a comparison that hashed the same bytes.
    pub fn with_digests(
        name: impl Into<String>,
        sha256: &Digest,
        sha512: &Sha512,
        sha1: Option<&Sha1>,
    ) -> Self {
        let mut digest = BTreeMap::from([
            ("sha256".to_string(), sha256.to_hex()),
            ("sha512".to_string(), sha512.to_hex()),
        ]);
        if let Some(d) = sha1 {
            digest.insert("sha1".to_string(), d.to_hex());
        }
        Subject {
            name: name.into(),
            digest,
        }
    }

    /// A subject whose every digest is computed here, over these bytes.
    ///
    /// `with_sha1` is whether the artifact's ecosystem publishes one
    /// ([`trigon_core::Ecosystem::publishes_sha1`]).
    pub fn of_bytes(name: impl Into<String>, bytes: &[u8], with_sha1: bool) -> Self {
        let sha256 = Digest::from_bytes(sha2::Sha256::digest(bytes).into());
        let sha1 = with_sha1.then(|| sha1_of(bytes));
        Subject::with_digests(name, &sha256, &sha512_of(bytes), sha1.as_ref())
    }
}

/// The sha512 of some bytes, as a subject carries it.
///
/// Public so a caller recording an artifact's digests computes them the way a subject does, rather
/// than with a second implementation that could disagree about one.
pub fn sha512_of(bytes: &[u8]) -> Sha512 {
    Sha512(sha2::Sha512::digest(bytes).into())
}

/// The sha1 of some bytes, as a subject carries it. See [`Sha1`] for why it exists at all.
pub fn sha1_of(bytes: &[u8]) -> Sha1 {
    Sha1(sha1::Sha1::digest(bytes).into())
}

/// A subject for the upstream side of a comparison, from the digests the comparison computed.
///
/// `summarize` hashes the raw bytes with sha512 beside sha256, so a comparison made by this code
/// always has both. One deserialized from a blob written before it did has sha256 alone, and the
/// subject says exactly that much.
fn upstream_subject(name: &str, c: &Comparison) -> Subject {
    match &c.upstream.raw.sha512 {
        Some(sha512) => Subject::with_digests(name, &c.upstream.raw.sha256, sha512, None),
        None => Subject::new(name, &c.upstream.raw.sha256),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

impl Statement {
    /// The equivalence statement: the load-bearing one.
    ///
    /// Its subject is the **upstream** artifact, not the rebuild. The claim is about what was
    /// published: a consumer holding a package from a registry looks it up by the digest they
    /// already have, and a statement keyed on our rebuild would be unfindable by anyone who did not
    /// already have our rebuild.
    ///
    /// The subject carries the sha256 and sha512 the comparison computed over the upstream bytes.
    /// A caller that knows the ecosystem, and so whether a sha1 belongs in it too, uses
    /// [`Self::equivalence_for`].
    pub fn equivalence(upstream_name: &str, c: &Comparison) -> Self {
        Self::equivalence_with(upstream_subject(upstream_name, c), c)
    }

    /// The equivalence statement about a subject the caller computed over the upstream bytes.
    ///
    /// Refused when the subject is not the comparison's upstream artifact: a statement whose
    /// subject and whose `artifacts.upstream` name different bytes is about nothing in particular,
    /// and signing one would be signing whichever half a reader happened to look at.
    pub fn equivalence_for(subject: Subject, c: &Comparison) -> Result<Self, crate::AttestError> {
        if !subject.digest.contains_key("sha256") {
            return Err(crate::AttestError::Malformed(
                "an equivalence subject must name the upstream artifact's sha256, which is what \
                 the comparison is keyed on"
                    .into(),
            ));
        }
        // Every algorithm both sides know. sha1 is not among them: the comparison never computes
        // one, and `rederive` checks it against the bytes before anything is signed.
        let compared = [
            ("sha256", Some(c.upstream.raw.sha256.to_hex())),
            ("sha512", c.upstream.raw.sha512.map(|d| d.to_hex())),
        ];
        for (algorithm, compared) in compared {
            let (Some(named), Some(compared)) = (subject.digest.get(algorithm), compared) else {
                continue;
            };
            if *named != compared {
                return Err(crate::AttestError::WrongArtifact {
                    side: "upstream",
                    algorithm: algorithm.to_string(),
                    expected: named.clone(),
                    got: compared,
                });
            }
        }
        Ok(Self::equivalence_with(subject, c))
    }

    fn equivalence_with(subject: Subject, c: &Comparison) -> Self {
        let predicate = equivalence_predicate(c);
        Statement {
            type_: STATEMENT_TYPE.into(),
            subject: vec![subject],
            predicate_type: if c.outcome == trigon_core::Match::Divergent {
                DIVERGENCE.into()
            } else {
                EQUIVALENCE.into()
            },
            predicate,
        }
    }

    /// The canonical bytes. What a signature actually covers.
    pub fn canonical(&self) -> Result<Vec<u8>, crate::AttestError> {
        let v = serde_json::to_value(self)?;
        Ok(trigon_core::jcs::canonicalize(&v)
            .map_err(|e| crate::AttestError::Canonicalize(e.to_string()))?
            .into_bytes())
    }
}

fn digests(m: &trigon_core::MultiDigest, bytes: Option<u64>) -> serde_json::Value {
    let mut o = serde_json::Map::new();
    o.insert("sha256".into(), m.sha256.to_hex().into());
    if let Some(s) = &m.sha512 {
        o.insert("sha512".into(), s.to_hex().into());
    }
    if let Some(b) = bytes {
        o.insert("bytes".into(), b.into());
    }
    serde_json::Value::Object(o)
}

fn equivalence_predicate(c: &Comparison) -> serde_json::Value {
    // **Both sides.** `apply` returns only the stabilizers that actually changed something, so the
    // two sides routinely differ: a wheel whose `RECORD` needed regenerating on the rebuild and not
    // upstream produces a `wheel-record` entry on one side only, and that pass is `Content` risk.
    // Reading `c.upstream.applied` here — as this did — left such a pass out of the signed document
    // while `compare()` correctly counted it in the cap, so the statement could read
    // `allBuiltin: true` and `maxRiskApplied: metadata` beside an outcome of
    // `normalized_with_caveats`, with nothing in `applied` to explain the caveat. A consumer doing
    // what `docs/threat-model.md` §1.13 tells them to do — read `applied` and reject a
    // normalization they do not accept — could not see the one that caused it.
    let side_of = |side: &'static str, xs: &[trigon_stabilize::Applied]| {
        xs.iter()
            .map(|a| {
                serde_json::json!({
                    "id": a.id.as_str(),
                    // Which artifact it fired on. A stabilizer that fired on one side and not the
                    // other is a fact worth having rather than a duplicate to deduplicate away.
                    "side": side,
                    "risk": format!("{:?}", a.risk).to_lowercase(),
                    "provenance": provenance_name(&a.provenance),
                    "entriesTouched": a.entries_touched,
                    "bytesChanged": a.bytes_changed,
                })
            })
            .collect::<Vec<_>>()
    };
    let applied: Vec<serde_json::Value> = side_of("upstream", &c.upstream.applied)
        .into_iter()
        .chain(side_of("rebuild", &c.rebuild.applied))
        .collect();

    // The provenance cap, stated outright rather than left for a consumer to re-derive from
    // `applied`. It is the invariant the whole design rests on, and a consumer that re-derived it
    // would be reimplementing our rule and could reimplement it differently.
    //
    // `c.applied()` is the same merged view `compare()` caps on, so these three fields and the
    // outcome cannot disagree.
    let all_builtin = c
        .applied()
        .iter()
        .all(|a| matches!(a.provenance, trigon_core::Provenance::Builtin));
    let max_risk = c
        .applied()
        .iter()
        .map(|a| a.risk)
        .max()
        .map(|r| format!("{r:?}").to_lowercase());

    let mut p = serde_json::json!({
        // A string, never an ordinal. A consumer writing `outcome <= 2` can never have an outcome
        // inserted between two existing ones.
        "outcome": c.outcome.to_string(),
        // A verifier holding an attestation and two artifacts has no ecosystem to ask, and one that
        // guesses reads a .gem as a plain tar and computes a different digest for a correct
        // artifact. Naming it costs one string.
        "archiveFormat": c.upstream.format.to_string(),
        "containerBitIdentical": c.container_bit_identical(),
        "artifacts": {
            "upstream": digests(&c.upstream.raw, Some(c.upstream.bytes)),
            "rebuild": digests(&c.rebuild.raw, Some(c.rebuild.bytes)),
        },
        "stabilized": {
            "upstream": digests(&c.upstream.stabilized, None),
            "rebuild": digests(&c.rebuild.stabilized, None),
        },
        "stabilizerSet": {
            "id": c.upstream.set.0.as_str(),
            "digest": { "sha256": c.upstream.set.1.to_hex() },
        },
        "applied": applied,
        "provenanceCap": {
            "allBuiltin": all_builtin,
            "maxRiskApplied": max_risk,
        },
    });

    // Present for a compressed container and absent otherwise. They are what
    // `containerBitIdentical` derives from, and they let a verifier tell "the tar matched, the gzip
    // framing did not" without re-running anything.
    if let (Some(u), Some(r)) = (&c.upstream.container, &c.rebuild.container) {
        p["container"] = serde_json::json!({
            "upstream": digests(u, None),
            "rebuild": digests(r, None),
        });
    }
    if let Some(d) = &c.diff {
        p["members"] = serde_json::json!({
            "identical": d.identical,
            "differs": d.differs,
            "onlyUpstream": d.only_upstream,
            "onlyRebuild": d.only_rebuild,
            // Named, because a divergence nobody can locate is not a finding. Executable
            // differences are never benign and are counted separately for that reason.
            "executableDiffers": d.executable_differs,
        });
        // The deterministic difference signature. What makes a published divergence something a
        // maintainer can reproduce rather than argue with: not "your package does not rebuild" but
        // "these four members differ in `zip.method`, under this stabilizer set". Deterministic and
        // model-free, which is why it is inside the signed document while the Explainer's prose
        // stays outside it.
        if !d.codes.is_empty() {
            p["differences"] = serde_json::json!(d.codes);
        }
    }
    p
}

fn provenance_name(p: &trigon_core::Provenance) -> &'static str {
    match p {
        trigon_core::Provenance::Builtin => "builtin",
        trigon_core::Provenance::Human { .. } => "human",
        trigon_core::Provenance::Model { .. } => "model",
    }
}

#[cfg(test)]
mod subject_tests {
    use super::*;

    #[test]
    fn a_subject_computed_over_bytes_carries_the_published_vectors() {
        // FIPS 180 test vectors for "abc", so a digest that is merely self-consistent — computed
        // the same wrong way on both sides of a check — cannot pass.
        let s = Subject::of_bytes("abc.tgz", b"abc", true);
        assert_eq!(
            s.digest["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            s.digest["sha512"],
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(s.digest["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d");

        // Where the ecosystem publishes no sha1, the subject carries none: it is a lookup key for
        // npm and nothing else.
        let s = Subject::of_bytes("abc.whl", b"abc", false);
        assert!(!s.digest.contains_key("sha1"), "{:?}", s.digest);
        assert_eq!(s.digest.len(), 2);
    }
}
