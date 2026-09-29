//! One record file checked against its leaf (`docs/19` §4.1, §4.2, §8).
//!
//! A record is anyone's bytes until this says otherwise: the repository is written by whoever can
//! push, and a record file names its own subject and evidence in an unsigned map for convenience.
//! So everything a client shows is taken from what is signed and logged, and the rest is held to
//! it:
//!
//! 1. the file is the one its leaf names — its sha256 is the leaf's `record` — and a file no leaf
//!    names is unlogged;
//! 2. the leaf's key id names the source's attestation key at that leaf, from [`KeyHistory`], so a
//!    record signed by a key retired before its leaf, or by a key the source never had, is
//!    refused, and every envelope carries a signature by that key that verifies;
//! 3. the signed statement agrees with its leaf on subject digests, purl, predicate type, outcome,
//!    set digest, and supersession;
//! 4. what accompanies a verdict is about the same run — its `rebuild` names the run and the set,
//!    and is about the rebuilt artifact the verdict names; its `buildobservation` is about the
//!    verdict's subject, under the same egress tier and guard manifest, with no guard tripped —
//!    and a void or a withdrawal is one statement alone;
//! 5. a verdict carries the command that would falsify it, naming its own subject and predicate
//!    type and the origin of the log it is logged in, and a divergence the pointer to where it is
//!    disputed: a client never renders an outcome it cannot show with them (`docs/19` §4.2 item 6,
//!    §8);
//! 6. the unsigned `subject` and `evidence` map agree with the signed statement;
//! 7. the signed subject is the key the record was found under, and a purl key is the signed purl
//!    canonicalised;
//! 8. every evidence file present is the bytes the signed statement names, and one absent is
//!    reported unchecked, never passed.
//!
//! Each failure is a [`RecordFailure`] with the reason, and each is reported as failed
//! verification, never as nothing found.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use trigon_core::{Digest, Match, RiskTier};

use super::lookup::Key;
use super::paths::evidence_path;
use super::repository::EVIDENCE_LIMIT;
use crate::location::printable;
use crate::log::{KeyHistory, Leaf, LeafOutcome, LeafPos, LogFiles, RecordLeaf};
use crate::record::{Record, signed_evidence};
use crate::statement::Statement;
use crate::verdict::is_primary;
use crate::{
    AttestError, AttestationKey, BUILD_OBSERVATION, DIVERGENCE_V2, DisputePointer, EQUIVALENCE_V2,
    Envelope, FalsifyingCommand, PAYLOAD_TYPE, REBUILD, SupersedeReason, VOID, WITHDRAWAL,
    evidence_key,
};

/// Why a record failed verification. Every kind is reported loudly, as failed verification and
/// never as never checked, because each may be an attack (`docs/19` §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordFailure {
    /// No leaf of the log names the record: an unlogged record (`docs/19` §8).
    Unlogged { record: Digest },
    /// The file at a leaf's record path is not the record the leaf names.
    NotItsLeaf { leaf: Digest, file: Digest },
    /// Not a record file, or one whose statements cannot be read.
    Unreadable(String),
    /// The leaf names a key that was not the source's attestation key at that leaf, or an
    /// envelope carries no signature by it that verifies.
    Signature(String),
    /// The signed statement disagrees with its leaf.
    Leaf(String),
    /// The record's statements are not what a record of its kind carries.
    Statements(String),
    /// A verdict without the command that would falsify it, or whose command resolves elsewhere —
    /// another log's origin, another subject or predicate type — or a divergence without the
    /// pointer to where it is disputed. `docs/19` §8: a client never renders an outcome it cannot
    /// show with them, so the record fails rather than being shown without them.
    Recourse(String),
    /// The unsigned `subject` or `evidence` map disagrees with the signed statement.
    Map(String),
    /// An evidence file present is not the bytes the signed statement names.
    Evidence(String),
    /// The signed subject is not the key the record was found under.
    WrongKey(String),
    /// The log holds the record at more than one leaf. A record is logged once, when it is
    /// published, and one logged again after the record that supersedes or withdraws it would read
    /// as current again (`docs/19` §3), in the one history every client holds; so no leaf of it is
    /// taken as its place, and it is shown as neither current nor superseded.
    LoggedTwice {
        record: Digest,
        leaves: Vec<LeafPos>,
    },
}

impl RecordFailure {
    /// A short name for the kind, for a report or a machine to sort by.
    pub fn kind(&self) -> &'static str {
        match self {
            RecordFailure::Unlogged { .. } => "unlogged",
            RecordFailure::LoggedTwice { .. } => "logged-twice",
            RecordFailure::NotItsLeaf { .. } => "not-its-leaf",
            RecordFailure::Unreadable(_) => "unreadable",
            RecordFailure::Signature(_) => "signature",
            RecordFailure::Leaf(_) => "disagrees-with-leaf",
            RecordFailure::Statements(_) => "statements",
            RecordFailure::Recourse(_) => "no-recourse",
            RecordFailure::Map(_) => "unsigned-map",
            RecordFailure::Evidence(_) => "evidence",
            RecordFailure::WrongKey(_) => "wrong-key",
        }
    }
}

impl std::fmt::Display for RecordFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordFailure::Unlogged { record } => write!(
                f,
                "no leaf of the log names the record sha256:{}: it is unlogged, and a record the \
                 log does not hold is never shown as a verdict (docs/19 §8)",
                record.to_hex()
            ),
            RecordFailure::LoggedTwice { record, leaves } => write!(
                f,
                "the log holds the record sha256:{} at {} leaves — {} — and a record is logged \
                 once, when it is published: one logged again after what supersedes or withdraws \
                 it would read as current again, so none of its leaves is taken as its place",
                record.to_hex(),
                leaves.len(),
                leaves
                    .iter()
                    .map(LeafPos::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            RecordFailure::NotItsLeaf { leaf, file } => write!(
                f,
                "the record file's sha256 is {}, and its leaf names sha256:{}: it is not the \
                 record the log holds",
                file.to_hex(),
                leaf.to_hex()
            ),
            RecordFailure::Unreadable(why)
            | RecordFailure::Signature(why)
            | RecordFailure::Leaf(why)
            | RecordFailure::Statements(why)
            | RecordFailure::Recourse(why)
            | RecordFailure::Map(why)
            | RecordFailure::Evidence(why)
            | RecordFailure::WrongKey(why) => f.write_str(why),
        }
    }
}

/// What a verified record says: a verdict with its outcome, a void, or a withdrawal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Verdict(Match),
    Void,
    Withdrawal,
}

/// A piece of evidence a record's signed statement names, and what was found of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceFile {
    /// Its name in the statement: `comparison`, `stabilizerSetManifest`, and so on.
    pub name: String,
    pub digest: Digest,
    pub state: EvidenceState,
}

/// What was found of one piece of evidence. Only [`EvidenceState::Matches`] is checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceState {
    /// In the directory, and its sha256 is the digest the signed statement names.
    Matches,
    /// Not in the directory: unchecked, never passed. A default clone leaves `evidence/` out
    /// (`docs/19` §6), so this is the ordinary state of a record read from one.
    Absent,
    /// A release asset, never a file of the repository (`docs/19` §2.3): unchecked here.
    ReleaseAsset,
    /// There, and could not be read: unchecked, with why.
    Unreadable(String),
}

impl EvidenceState {
    /// Whether the file was checked against its digest.
    pub fn checked(&self) -> bool {
        matches!(self, EvidenceState::Matches)
    }
}

/// A record that verified: every check of the module's documentation held.
#[derive(Clone, Debug)]
pub struct VerifiedRecord {
    /// The sha256 of the record file.
    pub digest: Digest,
    /// Where its leaf is.
    pub pos: LeafPos,
    pub leaf: RecordLeaf,
    pub record: Record,
    /// Its result: the verdict, the void or the withdrawal, as signed.
    pub statement: Statement,
    /// The key every envelope verified under: the source's attestation key at its leaf.
    pub key: AttestationKey,
    /// Every piece of evidence its statement names, and what was found of each.
    pub evidence: Vec<EvidenceFile>,
}

impl VerifiedRecord {
    pub fn kind(&self) -> RecordKind {
        // The leaf's, which is the statement's: they were checked to agree.
        match self.leaf.outcome {
            None => RecordKind::Withdrawal,
            Some(LeafOutcome::Void) => RecordKind::Void,
            Some(LeafOutcome::Exact) => RecordKind::Verdict(Match::Exact),
            Some(LeafOutcome::Normalized) => RecordKind::Verdict(Match::Normalized),
            Some(LeafOutcome::NormalizedWithCaveats) => {
                RecordKind::Verdict(Match::NormalizedWithCaveats)
            }
            Some(LeafOutcome::Divergent) => RecordKind::Verdict(Match::Divergent),
        }
    }

    /// The record this one supersedes, and why, as signed and logged.
    pub fn supersedes(&self) -> Option<(Digest, SupersedeReason)> {
        Some((self.leaf.supersedes?, self.leaf.reason?))
    }

    /// Evidence the statement names that was not checked against its digest.
    pub fn unchecked(&self) -> impl Iterator<Item = &EvidenceFile> {
        self.evidence.iter().filter(|e| !e.state.checked())
    }

    /// The riskiest stabilizer tier the verdict signs as applied, from its `provenanceCap`:
    /// `Some(None)` where it signs that none applied, as an exact verdict does, and `None` where
    /// it signs no tier this build reads — which a `--max-risk` then cannot be held to, and is
    /// never read as nothing applied.
    pub fn max_risk_applied(&self) -> Option<Option<RiskTier>> {
        match self.statement.predicate.pointer("/provenanceCap/maxRiskApplied")? {
            Value::Null => Some(None),
            v => serde_json::from_value::<RiskTier>(v.clone()).ok().map(Some),
        }
    }
}

/// Check one record file (`bytes`) against the leaf that names it, the source's key history, and
/// the evidence files beside it — every check of the module's documentation, in that order.
///
/// `leaf` is the leaf found for the record's digest, `None` where the log has none, and `origin`
/// the origin of the log that leaf is in, which a verdict's falsifying command must name.
/// `evidence` reads the repository's files by their paths in it (`evidence/sha256/…`).
/// `found_under` is the key a lookup found the record by, which its signed subject must be; `None`
/// for a record handed in directly.
pub fn check_record(
    bytes: &[u8],
    leaf: Option<(LeafPos, &RecordLeaf)>,
    origin: &str,
    keys: &KeyHistory,
    evidence: &dyn LogFiles,
    found_under: Option<&Key>,
) -> Result<VerifiedRecord, RecordFailure> {
    let digest = Record::digest_of(bytes);
    let Some((pos, leaf)) = leaf else {
        return Err(RecordFailure::Unlogged { record: digest });
    };
    if leaf.record != digest {
        return Err(RecordFailure::NotItsLeaf {
            leaf: leaf.record,
            file: digest,
        });
    }
    let record = Record::from_slice(bytes).map_err(|e| RecordFailure::Unreadable(e.to_string()))?;

    // The key the leaf names must be the source's attestation key at that leaf: the pinned key,
    // or one a key change the log holds moved to, and not one retired before it.
    let key = keys
        .key_for(&leaf.key_id, pos)
        .map_err(|e| RecordFailure::Signature(e.to_string()))?
        .clone();
    let mut statements = Vec::with_capacity(record.statements.len());
    for envelope in &record.statements {
        statements.push(open(envelope, &key)?);
    }
    let statement = record
        .statement()
        .map_err(|e| RecordFailure::Unreadable(e.to_string()))?;

    agrees_with_leaf(&statement, leaf)?;
    accompanies(&statement, &statements)?;
    recourse(&statement, origin)?;
    unsigned_agrees(&record, &statement)?;
    if let Some(k) = found_under {
        k.check_signed(&statement)
            .map_err(RecordFailure::WrongKey)?;
    }
    let evidence = check_evidence(&statement, evidence)?;

    Ok(VerifiedRecord {
        digest,
        pos,
        leaf: leaf.clone(),
        record,
        statement,
        key,
        evidence,
    })
}

/// The leaf a record file is logged under (`docs/19` §2.3), taken from its signed statement: the
/// leaf [`check_record`] holds the record to, and held here to the same comparison before it is
/// returned, so that a leaf this gives is one every client accepts the record against. `key_id`
/// is the attestation key the record is signed with, and `time` when it is logged.
///
/// For `publish` and `trigon log sign` (`docs/19` §10 phase 5), which write and check a leaf for
/// each record; refused where the statement signs anything a leaf cannot carry, or carries in
/// another spelling, since a leaf once logged is there for good.
pub fn record_leaf(bytes: &[u8], key_id: &str, time: u64) -> Result<RecordLeaf, AttestError> {
    let record = Record::from_slice(bytes)?;
    let st = record.statement()?;
    let bad = |why: String| AttestError::Evidence(format!("this record cannot be logged: {why}"));
    let [subject] = st.subject.as_slice() else {
        return Err(bad(format!(
            "its statement names {} subjects",
            st.subject.len()
        )));
    };
    let p = &st.predicate;
    let text = |field: &str| p.get(field).and_then(Value::as_str);
    let purl = text("purl").ok_or_else(|| bad("its statement signs no purl".into()))?;
    let purl_canon = p
        .get("purlCanon")
        .and_then(Value::as_u64)
        .and_then(|r| u32::try_from(r).ok())
        .ok_or_else(|| bad("its statement signs no `purlCanon`".into()))?;
    let outcome = match text("outcome") {
        Some(o) => Some(
            serde_json::from_value::<LeafOutcome>(Value::String(o.to_string()))
                .map_err(|_| bad(format!("its outcome `{}` is not one", printable(o))))?,
        ),
        None => None,
    };
    let digest = |s: &str| {
        Digest::from_hex(s).map_err(|_| bad(format!("`{}` is not a sha256", printable(s))))
    };
    let stabilizer_set = match p
        .pointer("/stabilizerSet/digest/sha256")
        .and_then(Value::as_str)
    {
        Some(h) => Some(digest(h)?),
        None => None,
    };
    let supersedes = match text("supersedes") {
        Some(s) => Some(digest(s.strip_prefix("sha256:").unwrap_or(s))?),
        None => None,
    };
    let reason = match text("reason") {
        Some(r) => Some(r.parse::<SupersedeReason>()?),
        None => None,
    };
    let leaf = RecordLeaf {
        time,
        subject: subject.digest.clone(),
        purl: purl.to_string(),
        purl_canon,
        predicate_type: st.predicate_type.clone(),
        outcome,
        stabilizer_set,
        key_id: key_id.to_string(),
        record: Record::digest_of(bytes),
        supersedes,
        reason,
    };
    Leaf::Record(leaf.clone()).validate()?;
    // Held to what `check_record` compares, as it compares it, rather than trusted to agree: the
    // leaf is built from values parsed leniently — a `supersedes` with no `sha256:`, hex in either
    // case — and written as the log writes them, and a statement that signed another spelling
    // would fail verification at every client, for ever.
    let differ = leaf_differences(&st, &leaf).map_err(|e| bad(e.to_string()))?;
    if !differ.is_empty() {
        return Err(bad(format!(
            "its signed statement would disagree with the leaf it is logged under, and every \
             client would refuse it: {}. Sign it again with each field as a leaf writes it: \
             `supersedes` as `sha256:` and 64 lowercase hex digits, the set digest as 64 \
             lowercase hex digits",
            differ.join("; ")
        )));
    }
    Ok(leaf)
}

/// An envelope's statement, where it carries a signature by `key` that verifies.
fn open(e: &Envelope, key: &AttestationKey) -> Result<Statement, RecordFailure> {
    if e.payload_type != crate::PAYLOAD_TYPE {
        return Err(RecordFailure::Unreadable(format!(
            "an envelope's payload type is `{}`, and a record holds in-toto statements, \
             `{PAYLOAD_TYPE}`",
            printable(&e.payload_type)
        )));
    }
    let payload = e
        .decoded_payload()
        .map_err(|x| RecordFailure::Unreadable(x.to_string()))?;
    let st: Statement = serde_json::from_slice(&payload).map_err(|x| {
        RecordFailure::Unreadable(format!(
            "a statement in this record is not an in-toto statement: {}",
            printable(&x.to_string())
        ))
    })?;
    let pae = crate::pae(&e.payload_type, &payload);
    let signed = e
        .signatures
        .iter()
        .filter(|s| !s.sig.is_empty())
        .any(|s| crate::verify_signature(&pae, s, &key.to_hex()).is_ok());
    if !signed {
        return Err(RecordFailure::Signature(format!(
            "its `{}` statement carries no signature by {}, the source's attestation key at its \
             leaf, that verifies",
            printable(&st.predicate_type),
            key.key_id()
        )));
    }
    Ok(st)
}

/// `docs/19` §8: a record whose signed statement disagrees with its leaf on digests, purl,
/// outcome, set digest or supersession fails verification. The predicate type too, since the
/// leaf's outcome means what its type says.
fn agrees_with_leaf(st: &Statement, leaf: &RecordLeaf) -> Result<(), RecordFailure> {
    let differ = leaf_differences(st, leaf)?;
    match differ.is_empty() {
        true => Ok(()),
        false => Err(RecordFailure::Leaf(format!(
            "its signed statement disagrees with its leaf, which the log vouches for: {}",
            differ.join("; ")
        ))),
    }
}

/// Each field [`agrees_with_leaf`] holds the statement to on which it and `leaf` differ, said.
/// The writer's [`record_leaf`] asks the same, so the two agree by what is compared and not by
/// care.
fn leaf_differences(st: &Statement, leaf: &RecordLeaf) -> Result<Vec<String>, RecordFailure> {
    let [subject] = st.subject.as_slice() else {
        return Err(RecordFailure::Leaf(format!(
            "its statement names {} subjects, and a record is about one artifact",
            st.subject.len()
        )));
    };
    let p = &st.predicate;
    // A field that is there and is not a string is written as its JSON, so that it never passes
    // for one that is absent.
    let text =
        |v: Option<&Value>| v.map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string));
    let mut differ = Vec::new();
    if subject.digest != leaf.subject {
        differ.push(format!(
            "the subject: the statement signs {} and the leaf logs {}",
            digests(&subject.digest),
            digests(&leaf.subject)
        ));
    }
    // Compared as they are, and escaped only to be shown: a statement is anyone's bytes until its
    // signature is checked, and the leaf's fields were held to their rules when it was read.
    let mut compare = |what: &str, signed: Option<String>, logged: Option<String>| {
        if signed != logged {
            let shown = |v: Option<String>| {
                v.map_or_else(|| "none".to_string(), |s| format!("`{}`", printable(&s)))
            };
            differ.push(format!(
                "{what}: the statement signs {} and the leaf logs {}",
                shown(signed),
                shown(logged)
            ));
        }
    };
    compare(
        "the predicate type",
        Some(st.predicate_type.clone()),
        Some(leaf.predicate_type.clone()),
    );
    compare("the purl", text(p.get("purl")), Some(leaf.purl.clone()));
    compare(
        "the purl's canonicalisation rule",
        p.get("purlCanon").map(Value::to_string),
        Some(leaf.purl_canon.to_string()),
    );
    compare(
        "the outcome",
        text(p.get("outcome")),
        leaf.outcome.map(|o| o.as_str().to_string()),
    );
    compare(
        "the stabilizer-set digest",
        text(p.pointer("/stabilizerSet/digest/sha256")),
        leaf.stabilizer_set.map(|d| d.to_hex()),
    );
    compare(
        "the record it supersedes",
        text(p.get("supersedes")),
        leaf.supersedes.map(|d| format!("sha256:{}", d.to_hex())),
    );
    compare(
        "the reason",
        text(p.get("reason")),
        leaf.reason.map(|r| r.as_str().to_string()),
    );
    Ok(differ)
}

/// A void or a withdrawal is one statement alone (`docs/19` §4.1). A verdict's `rebuild` and
/// `buildobservation` are about its run, each at most once:
///
/// - the rebuild about the rebuilt artifact the verdict names, with the verdict's run as its
///   invocation, and the verdict's set where it names one (one signed before `rebuild` carried
///   the set names none);
/// - the observation about the verdict's subject, under the verdict's egress tier, with the guard
///   manifest the verdict names as evidence where it names one, and with no guard tripped, since a
///   run whose guard tripped is void and never signed as a verdict (threat model P6).
///
/// `buildobservation` names no run, so an observation of another attempt at the same artifact,
/// under the same tier and guard, is not told apart from this run's: the rebuild is what ties a
/// verdict to its run. A statement of a kind this build does not read has had its signature
/// checked, and is read past.
fn accompanies(primary: &Statement, all: &[Statement]) -> Result<(), RecordFailure> {
    let kind = primary.predicate_type.as_str();
    if kind == VOID || kind == WITHDRAWAL {
        if all.len() != 1 {
            return Err(RecordFailure::Statements(format!(
                "a `{kind}` record holds one statement, and this one holds {}",
                all.len()
            )));
        }
        return Ok(());
    }
    let refuse = |why: String| Err(RecordFailure::Statements(why));
    // A value as a message shows it: a string as itself, anything else as its JSON, and absence
    // as absence; escaped, since a statement is anyone's bytes until its signature is checked.
    let shown = |v: Option<&Value>| match v {
        None => "none".to_string(),
        Some(Value::String(s)) => format!("`{}`", printable(s)),
        Some(v) => format!("`{}`", printable(&v.to_string())),
    };
    let subject = &primary.subject[0].digest;
    let p = &primary.predicate;
    let rebuilt = p
        .pointer("/artifacts/rebuild/sha256")
        .and_then(Value::as_str);
    let run = p.pointer("/run/id");
    let set = p.get("stabilizerSet");
    let egress = p.get("egressTier");
    let guard = p.pointer("/evidence/guardManifest/sha256");
    let mut seen = BTreeSet::new();
    for st in all.iter().filter(|st| !is_primary(&st.predicate_type)) {
        if !seen.insert(st.predicate_type.as_str()) {
            return refuse(format!(
                "it holds two `{}` statements, and a verdict's run has one",
                printable(&st.predicate_type)
            ));
        }
        let about = st.subject.first().map(|s| &s.digest);
        let q = &st.predicate;
        match st.predicate_type.as_str() {
            BUILD_OBSERVATION => {
                if about != Some(subject) {
                    return refuse(format!(
                        "its build observation is about {}, and its verdict about {}",
                        about.map_or_else(|| "nothing".into(), digests),
                        digests(subject)
                    ));
                }
                if egress.is_some() && q.get("egressTier") != egress {
                    return refuse(format!(
                        "its build observation was under the egress tier {}, and its verdict's run \
                         under {}",
                        shown(q.get("egressTier")),
                        shown(egress)
                    ));
                }
                let armed = q.pointer("/artifactHashCheck/guardManifest/sha256");
                if guard.is_some() && armed != guard {
                    return refuse(format!(
                        "its build observation's guard was armed with the manifest {}, and its \
                         verdict names {} as the guard manifest",
                        shown(armed),
                        shown(guard)
                    ));
                }
                if q.pointer("/artifactHashCheck/matched") == Some(&Value::Bool(true)) {
                    return refuse(
                        "its build observation says the artifact guard tripped, and a run whose \
                         guard tripped is void: it is never signed as a verdict"
                            .into(),
                    );
                }
            }
            REBUILD => {
                let sha256 = about.and_then(|d| d.get("sha256")).map(String::as_str);
                if rebuilt.is_some() && sha256 != rebuilt {
                    return refuse(format!(
                        "its rebuild statement is about the artifact sha256:{}, and its verdict \
                         names the rebuilt artifact sha256:{}",
                        printable(sha256.unwrap_or("none")),
                        printable(rebuilt.unwrap_or("none"))
                    ));
                }
                let invocation = q.pointer("/runDetails/metadata/invocationId");
                if run.is_some() && invocation != run {
                    return refuse(format!(
                        "its rebuild statement is of the run {}, and its verdict of the run {}",
                        shown(invocation),
                        shown(run)
                    ));
                }
                if let Some(s) = q.get("stabilizerSet")
                    && set != Some(s)
                {
                    return refuse(format!(
                        "its rebuild statement names the stabilizer set {}, and its verdict {}",
                        shown(Some(s)),
                        shown(set)
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// `docs/19` §4.2 item 6 and §8: what a reader needs to answer a verdict. A verdict carries the
/// command that would falsify it, and the command resolves to this record: `trigon
/// verify-attestation` looking up the statement's own subject and predicate type in the log it is
/// logged in, by that log's origin, since one naming another origin sends a reader to another
/// source, or to none. A divergence also carries the pointer to where it is disputed, an
/// `https://` URL, and a verdict that carries one without having to is held to the same. A void and
/// a withdrawal are no claim about the package, and carry neither.
///
/// Read as a later writer may extend it: flags beyond these three are read past.
fn recourse(st: &Statement, origin: &str) -> Result<(), RecordFailure> {
    let kind = st.predicate_type.as_str();
    if kind != EQUIVALENCE_V2 && kind != DIVERGENCE_V2 {
        return Ok(());
    }
    let refuse = |why: String| {
        Err(RecordFailure::Recourse(format!(
            "its `{kind}` verdict {why}; a client never renders an outcome it cannot show with the \
             command that would falsify it and, for a divergence, where to dispute it (docs/19 \
             §4.2 item 6, §8)"
        )))
    };
    let p = &st.predicate;
    let Some(signed) = p.get("falsifyingCommand") else {
        return refuse("signs no falsifying command".into());
    };
    let shown = |v: &Value| printable(&v.to_string());
    let Ok(command) = serde_json::from_value::<FalsifyingCommand>(signed.clone()) else {
        return refuse(format!(
            "signs a falsifying command that is not an argv: `{}`",
            shown(signed)
        ));
    };
    let argv = &command.argv;
    if argv.len() < 2 || argv[0] != "trigon" || argv[1] != "verify-attestation" {
        return refuse(format!(
            "signs a falsifying command that is not `trigon verify-attestation`: `{}`",
            printable(&command.render())
        ));
    }
    let lookup = st
        .subject
        .first()
        .and_then(|s| s.digest.get("sha256"))
        .map(|h| format!("sha256:{h}"))
        .unwrap_or_default();
    for (flag, want) in [
        ("--lookup", lookup.as_str()),
        ("--predicate", kind),
        ("--origin", origin),
    ] {
        let given: Vec<&str> = argv
            .windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].as_str())
            .collect();
        match given.as_slice() {
            [v] if *v == want => {}
            [] => return refuse(format!("signs a falsifying command without `{flag}`")),
            [v] if flag == "--origin" => {
                return refuse(format!(
                    "signs a falsifying command naming the log `{}`, and it is logged in `{}`: \
                     the command would look for it in another source, or in none",
                    printable(v),
                    printable(origin)
                ));
            }
            [v] => {
                return refuse(format!(
                    "signs a falsifying command whose `{flag}` is `{}`, and its own is `{}`: the \
                     command would resolve another record",
                    printable(v),
                    printable(want)
                ));
            }
            _ => {
                return refuse(format!(
                    "signs a falsifying command that gives `{flag}` {} times",
                    given.len()
                ));
            }
        }
    }
    match p.get("disputePointer") {
        None if kind == DIVERGENCE_V2 => refuse("signs no dispute pointer".into()),
        None => Ok(()),
        Some(v) => match serde_json::from_value::<DisputePointer>(v.clone()) {
            Ok(DisputePointer::Url { url })
                if url.len() > "https://".len() && url.starts_with("https://") =>
            {
                Ok(())
            }
            _ => refuse(format!(
                "signs a dispute pointer that is not an `https://` URL a reader can open: `{}`",
                shown(v)
            )),
        },
    }
}

/// `docs/19` §4.1: the top-level `subject` and `evidence` map are unsigned conveniences, and a
/// record whose map disagrees with its signed statement fails verification.
fn unsigned_agrees(record: &Record, st: &Statement) -> Result<(), RecordFailure> {
    let signed_purl = st
        .predicate
        .get("purl")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if record.subject.purl != signed_purl {
        return Err(RecordFailure::Map(format!(
            "its unsigned subject names the purl `{}`, and its signed statement `{}`",
            printable(&record.subject.purl),
            printable(signed_purl)
        )));
    }
    if record.subject.digests != st.subject[0].digest {
        return Err(RecordFailure::Map(format!(
            "its unsigned subject names {}, and its signed statement {}",
            digests(&record.subject.digests),
            digests(&st.subject[0].digest)
        )));
    }
    let signed = signed_evidence(st).map_err(|e| RecordFailure::Unreadable(e.to_string()))?;
    if record.evidence != signed {
        return Err(RecordFailure::Map(format!(
            "its unsigned evidence map names {}, and its signed statement {}",
            named(&record.evidence),
            named(&signed)
        )));
    }
    Ok(())
}

/// Every piece of evidence the signed statement names — never the unsigned map, which was held to
/// it above — checked against the file in the repository where there is one.
fn check_evidence(
    st: &Statement,
    files: &dyn LogFiles,
) -> Result<Vec<EvidenceFile>, RecordFailure> {
    let signed = signed_evidence(st).map_err(|e| RecordFailure::Unreadable(e.to_string()))?;
    let mut out = Vec::with_capacity(signed.len());
    for (name, value) in signed {
        let digest = value
            .strip_prefix("sha256:")
            .and_then(|h| Digest::from_hex(h).ok())
            .expect("signed_evidence writes `sha256:` and 64 lowercase hex");
        let (state, _) = read_evidence(files, &name, &digest)?;
        out.push(EvidenceFile {
            name,
            digest,
            state,
        });
    }
    Ok(out)
}

/// One piece of evidence a verified record names, read from `files` and held to its signed digest
/// again: [`read_evidence`], for a reader whose evidence is not the repository's own directory — a
/// partial clone, whose `evidence/` is read from git's objects on demand.
pub fn read_evidence_from(
    files: &dyn LogFiles,
    e: &EvidenceFile,
) -> Result<(EvidenceState, Option<Vec<u8>>), RecordFailure> {
    read_evidence(files, &e.name, &e.digest)
}

/// One piece of evidence, by the name and digest its statement signs, read from the repository
/// and held to that digest: what was found of it, and its bytes where they are the bytes signed.
/// A file that is there and is other bytes fails; one absent, unreadable or a release asset is
/// unchecked, and has no bytes to judge.
pub(crate) fn read_evidence(
    files: &dyn LogFiles,
    name: &str,
    digest: &Digest,
) -> Result<(EvidenceState, Option<Vec<u8>>), RecordFailure> {
    if name == evidence_key::REBUILT_ARTIFACT {
        return Ok((EvidenceState::ReleaseAsset, None));
    }
    let path = evidence_path(digest);
    match files.read(&path, EVIDENCE_LIMIT) {
        Ok(None) => Ok((EvidenceState::Absent, None)),
        Ok(Some(bytes)) => {
            let got = Digest::from_bytes(Sha256::digest(&bytes).into());
            if got != *digest {
                return Err(RecordFailure::Evidence(format!(
                    "its `{}` evidence, `{path}`, is not the bytes its statement signs: their \
                     sha256 is {}, and it signs {}",
                    printable(name),
                    got.to_hex(),
                    digest.to_hex()
                )));
            }
            Ok((EvidenceState::Matches, Some(bytes)))
        }
        Err(e) => Ok((EvidenceState::Unreadable(e.to_string()), None)),
    }
}

/// A digest map as a message shows it: `sha1 …, sha256 …`, escaped.
fn digests(d: &BTreeMap<String, String>) -> String {
    let parts: Vec<String> = d
        .iter()
        .map(|(a, h)| format!("{} {}", printable(a), printable(h)))
        .collect();
    match parts.is_empty() {
        true => "no digest".into(),
        false => parts.join(", "),
    }
}

/// An evidence map as a message shows it.
fn named(m: &BTreeMap<String, String>) -> String {
    let parts: Vec<String> = m
        .iter()
        .map(|(n, d)| format!("{} {}", printable(n), printable(d)))
        .collect();
    match parts.is_empty() {
        true => "nothing".into(),
        false => parts.join(", "),
    }
}
