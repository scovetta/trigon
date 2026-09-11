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
use trigon_compare::Comparison;
use trigon_core::Digest;

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
    pub fn new(name: impl Into<String>, sha256: &Digest) -> Self {
        Subject {
            name: name.into(),
            digest: BTreeMap::from([("sha256".to_string(), sha256.to_hex())]),
        }
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
    pub fn equivalence(upstream_name: &str, c: &Comparison) -> Self {
        let predicate = equivalence_predicate(c);
        Statement {
            type_: STATEMENT_TYPE.into(),
            subject: vec![Subject::new(upstream_name, &c.upstream.raw.sha256)],
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
    let applied: Vec<serde_json::Value> = c
        .upstream
        .applied
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id.as_str(),
                "risk": format!("{:?}", a.risk).to_lowercase(),
                "provenance": provenance_name(&a.provenance),
                "entriesTouched": a.entries_touched,
                "bytesChanged": a.bytes_changed,
            })
        })
        .collect();

    // The provenance cap, stated outright rather than left for a consumer to re-derive from
    // `applied`. It is the invariant the whole design rests on, and a consumer that re-derived it
    // would be reimplementing our rule and could reimplement it differently.
    let all_builtin = c
        .upstream
        .applied
        .iter()
        .all(|a| matches!(a.provenance, trigon_core::Provenance::Builtin));
    let max_risk = c
        .upstream
        .applied
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
