//! Re-deriving a claim from the artifacts it is about.
//!
//! The flagship. An attestation from a rebuilder is worth something only to someone who distrusts
//! the rebuilder, so the equivalence claim has to be **falsifiable by a third party holding two
//! artifacts and our stabilizer implementation**. That is what this does, and it is why several
//! other decisions are what they are: the stabilizer set is named by id *and* digest, the archive
//! format is named explicitly, and a set digest that does not match today's is refused rather than
//! papered over.

use sha2::{Digest as _, Sha256};
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
}

impl Rederived {
    /// Whether the statement's claim survived being checked.
    pub fn holds(&self) -> bool {
        self.digests_match && self.claimed == self.actual.to_string()
    }
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
    let p = &statement.predicate;
    let claimed = p["outcome"]
        .as_str()
        .ok_or_else(|| AttestError::Malformed("predicate has no `outcome`".into()))?
        .to_string();

    let set_id = p["stabilizerSet"]["id"]
        .as_str()
        .ok_or_else(|| AttestError::Malformed("predicate names no stabilizer set".into()))?;
    let set_digest = p["stabilizerSet"]["digest"]["sha256"]
        .as_str()
        .ok_or_else(|| AttestError::Malformed("the stabilizer set has no digest".into()))?;

    let set = trigon_stabilize::profile(set_id).ok_or_else(|| AttestError::SetMismatch {
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

    // The format is taken from the statement rather than sniffed. A verifier holding an attestation
    // and two files has no ecosystem to ask, and one that guesses reads a `.gem` as a plain tar and
    // computes a different digest for a correct artifact.
    let format = parse_format(
        p["archiveFormat"]
            .as_str()
            .ok_or_else(|| AttestError::Malformed("predicate names no archive format".into()))?,
    )?;

    // Are these even the artifacts the statement is about? Checked *before* the claim, and reported
    // as a different kind of error, because "you handed me the wrong file" and "this statement is a
    // lie" are not the same finding. It also closes a real hole: two artifacts can differ in raw
    // bytes and stabilize to the same form — that is the normal case, and it means the stabilized
    // check alone would accept a substituted artifact as proof of the claim.
    let subject = statement
        .subject
        .first()
        .and_then(|s| s.digest.get("sha256"))
        .ok_or_else(|| AttestError::Malformed("the statement names no subject digest".into()))?;
    for (side, expected, bytes) in [
        ("upstream", Some(subject.as_str()), &upstream),
        (
            "rebuild",
            p["artifacts"]["rebuild"]["sha256"].as_str(),
            &rebuild,
        ),
    ] {
        let Some(expected) = expected else {
            return Err(AttestError::Malformed(format!(
                "predicate has no raw digest for the {side} artifact"
            )));
        };
        let got = hex(&Sha256::digest(bytes));
        if expected != got {
            return Err(AttestError::WrongArtifact {
                side,
                expected: expected.to_string(),
                got,
            });
        }
    }

    let c = compare_bytes(upstream, rebuild, format, &set, &Limits::default())
        .map_err(|e| AttestError::Malformed(e.to_string()))?;

    // Both sides, because a statement that got one right and one wrong is still refuted.
    for (side, claimed_digest, actual) in [
        (
            "upstream",
            p["stabilized"]["upstream"]["sha256"].as_str(),
            &c.upstream.stabilized.sha256,
        ),
        (
            "rebuild",
            p["stabilized"]["rebuild"]["sha256"].as_str(),
            &c.rebuild.stabilized.sha256,
        ),
    ] {
        let Some(claimed_digest) = claimed_digest else {
            return Err(AttestError::Malformed(format!(
                "predicate has no stabilized digest for the {side} artifact"
            )));
        };
        if claimed_digest != actual.to_hex() {
            return Err(AttestError::ClaimRefuted {
                side,
                claimed: claimed_digest.to_string(),
                actual: actual.to_hex(),
            });
        }
    }

    Ok(Rederived {
        claimed,
        actual: c.outcome,
        digests_match: true,
        stabilizer_set: format!("{set_id}@{}", &current[..12]),
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_format(s: &str) -> Result<Format, AttestError> {
    Ok(match s {
        "tar+gzip" | "tar-gz" => Format::TarGz,
        "tar" => Format::Tar,
        "zip" => Format::Zip,
        "gzip" => Format::Gzip,
        "raw" => Format::Raw,
        other => {
            return Err(AttestError::Malformed(format!(
                "unknown archive format `{other}`"
            )));
        }
    })
}
