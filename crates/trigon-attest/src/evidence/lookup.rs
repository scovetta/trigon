//! Finding what a source holds for a key (`docs/19` §3, §5, §6 `lookup`).
//!
//! Every record leaf carries its subject's digests and its canonical purl, so a key is resolved
//! from the verified leaves and never from `index/`: an index file missing, altered or planted
//! changes nothing answered here. Each leaf the key names leads to a record file, which is
//! [`super::check_record`]ed, or is missing and so `deleted`.
//!
//! **Supersession is applied exactly as `docs/19` §3 says.** A record is superseded only by a
//! verified, logged record, signed by a key trusted for it — the source's attestation key at its
//! own leaf — that names it in `supersedes`, has a later leaf, and has the same subject digests
//! and canonical purl. A superseded record is returned marked, with the reason and both leaves,
//! and never hidden; two current records for one subject are both returned, and the more severe
//! answers.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use base64::Engine as _;
use sha2::{Digest as _, Sha256, Sha512};
use trigon_core::purl::{self, PURL_CANON};
use trigon_core::{Digest, Match};

use super::check::{RecordFailure, RecordKind, VerifiedRecord};
use super::paths::{IndexKey, digest_len};
use crate::location::printable;
use crate::log::{LeafPos, RecordLeaf};
use crate::statement::Statement;
use crate::{AttestError, SupersedeReason};

/// What a lookup is asked for (`docs/19` §6): a digest, a purl with or without its version, or a
/// file whose digests are computed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// A digest a subject carries — `sha256`, `sha512` or `sha1` — in lowercase hex.
    Digest {
        algorithm: &'static str,
        hex: String,
    },
    /// A purl with a version, as given. It is canonicalised under each leaf's own rule when it is
    /// matched, since a leaf is never rewritten and the rule may have moved on since.
    Purl(String),
    /// A purl without a version: every version of the package, as given.
    Package(String),
    /// A file's sha256, sha512 and sha1, computed over its bytes.
    File(BTreeMap<String, String>),
}

impl Key {
    /// Read a key as a person writes one: `sha256:<hex>`, `sha512:<hex>`, `sha1:<hex>`; an SRI
    /// string, such as npm's `integrity`, `sha512-<base64>`; or a purl, `pkg:npm/left-pad@1.3.0`,
    /// or `pkg:npm/left-pad` for every version. A file is [`Key::of_file`].
    pub fn parse(s: &str) -> Result<Key, AttestError> {
        let shown = printable(s);
        if s.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("pkg:")) {
            let c = purl::canonicalize(s).map_err(|e| AttestError::Malformed(e.to_string()))?;
            return Ok(match c.has_version() {
                true => Key::Purl(s.to_string()),
                false => Key::Package(s.to_string()),
            });
        }
        for algorithm in ["sha256", "sha512", "sha1"] {
            let len = digest_len(algorithm).expect("a subject's algorithm");
            if let Some(hex) = s.strip_prefix(algorithm).and_then(|r| r.strip_prefix(':')) {
                let hex = hex.to_ascii_lowercase();
                if hex.len() != len || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(AttestError::Malformed(format!(
                        "`{shown}` is not a {algorithm} key: `{algorithm}:` and {len} hex digits"
                    )));
                }
                return Ok(Key::Digest { algorithm, hex });
            }
            if let Some(b64) = s.strip_prefix(algorithm).and_then(|r| r.strip_prefix('-')) {
                // Subresource Integrity, as npm writes `integrity`: one hash, standard base64.
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .ok()
                    .filter(|r| r.len() * 2 == len)
                    .ok_or_else(|| {
                        AttestError::Malformed(format!(
                            "`{shown}` is not a {algorithm} integrity string: `{algorithm}-` and \
                             the base64 of {} bytes, one hash and nothing after it",
                            len / 2
                        ))
                    })?;
                return Ok(Key::Digest {
                    algorithm,
                    hex: raw.iter().map(|b| format!("{b:02x}")).collect(),
                });
            }
        }
        Err(AttestError::Malformed(format!(
            "`{shown}` is not a key a record is found by: `sha256:<hex>`, `sha512:<hex>`, \
             `sha1:<hex>`, an integrity string such as `sha512-<base64>`, or a purl such as \
             `pkg:npm/left-pad@1.3.0`; a file is looked up by its path"
        )))
    }

    /// The key of an artifact in hand: every digest a subject may carry, computed over its bytes.
    pub fn of_bytes(bytes: &[u8]) -> Key {
        let mut h = Hashes::default();
        h.update(bytes);
        h.key()
    }

    /// The key of the file at `path`, hashed as it is read rather than read whole, since an
    /// artifact may be large.
    pub fn of_file(path: &Path) -> Result<Key, AttestError> {
        let mut file = std::fs::File::open(path)?;
        let mut h = Hashes::default();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(h.key())
    }

    /// Whether a record leaf is filed under this key.
    pub fn matches(&self, leaf: &RecordLeaf) -> bool {
        match self {
            Key::Digest { algorithm, hex } => leaf.subject.get(*algorithm) == Some(hex),
            Key::Purl(given) => purl::canonicalize_under(leaf.purl_canon, given)
                .is_ok_and(|c| c.as_str() == leaf.purl),
            Key::Package(given) => same_package(leaf.purl_canon, given, &leaf.purl),
            // Every subject names its sha256; the others are held to the file's when the record's
            // signed subject is checked.
            Key::File(d) => leaf.subject.get("sha256") == d.get("sha256"),
        }
    }

    /// Whether the signed statement is about this key (`docs/19` §4.1, §4.2 item 8): its subject
    /// names the digest, or every digest of the file; or its signed purl, canonicalised, is the
    /// purl or the package. The error is why not.
    pub(crate) fn check_signed(&self, st: &Statement) -> Result<(), String> {
        let subject = st.subject.first().map(|s| &s.digest);
        let signed_purl = st.predicate.get("purl").and_then(|v| v.as_str());
        let rule = st
            .predicate
            .get("purlCanon")
            .and_then(|v| v.as_u64())
            .and_then(|r| u32::try_from(r).ok());
        match self {
            Key::Digest { algorithm, hex } => {
                let signed = subject.and_then(|d| d.get(*algorithm));
                match signed == Some(hex) {
                    true => Ok(()),
                    false => Err(format!(
                        "it was found under {self}, and its signed subject names {}",
                        signed.map_or_else(
                            || format!("no {algorithm}"),
                            |h| format!("{algorithm} {}", printable(h))
                        )
                    )),
                }
            }
            Key::File(computed) => {
                let Some(signed) = subject else {
                    return Err("its signed statement names no subject".into());
                };
                for (algorithm, hex) in signed {
                    if computed.get(algorithm) != Some(hex) {
                        return Err(format!(
                            "its signed subject names {} {}, and the file is {}",
                            printable(algorithm),
                            printable(hex),
                            computed
                                .get(algorithm)
                                .map_or("not hashed that way", String::as_str)
                        ));
                    }
                }
                Ok(())
            }
            Key::Purl(given) => {
                let (Some(signed), Some(rule)) = (signed_purl, rule) else {
                    return Err("its signed statement names no purl and rule".into());
                };
                // Accepted only if its signed purl canonicalises to the key (`docs/19` §4.2
                // item 8), under the rule it was signed under.
                match purl::canonicalize_under(rule, given) {
                    Ok(c) if c.as_str() == signed => Ok(()),
                    Ok(c) => Err(format!(
                        "it was found under `{c}`, and its signed purl is `{}`",
                        printable(signed)
                    )),
                    Err(e) => Err(format!(
                        "it was found under a purl that is not one under rule {rule}: {e}"
                    )),
                }
            }
            Key::Package(given) => {
                let (Some(signed), Some(rule)) = (signed_purl, rule) else {
                    return Err("its signed statement names no purl and rule".into());
                };
                match same_package(rule, given, signed) {
                    true => Ok(()),
                    false => Err(format!(
                        "it was found under the package `{}`, and its signed purl `{}` is not a \
                         version of it",
                        printable(given),
                        printable(signed)
                    )),
                }
            }
        }
    }

    /// The index files a reader without the log would read for this key (`docs/19` §5): one per
    /// digest, and for a purl or a package one per canonicalisation rule this build has, since a
    /// record is filed under the rule its leaf names.
    pub fn index_keys(&self) -> Vec<IndexKey> {
        let rules = 1..=PURL_CANON;
        match self {
            Key::Digest { algorithm, hex } => {
                IndexKey::digest(algorithm, hex).into_iter().collect()
            }
            Key::File(d) => d
                .iter()
                .filter_map(|(a, h)| IndexKey::digest(a, h).ok())
                .collect(),
            Key::Purl(given) => rules
                .filter_map(|r| {
                    let c = purl::canonicalize_under(r, given).ok()?;
                    IndexKey::purl(r, c.as_str()).ok()
                })
                .collect(),
            Key::Package(given) => rules
                .filter_map(|r| {
                    let c = purl::canonicalize_under(r, given).ok()?;
                    IndexKey::package(r, c.package()).ok()
                })
                .collect(),
        }
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Digest { algorithm, hex } => write!(f, "{algorithm}:{hex}"),
            Key::Purl(p) | Key::Package(p) => f.write_str(&printable(p)),
            Key::File(d) => write!(
                f,
                "the file with sha256:{}",
                d.get("sha256").map_or("?", String::as_str)
            ),
        }
    }
}

/// Whether `purl`, canonical under `rule`, is a version of the package `given` names.
fn same_package(rule: u32, given: &str, purl: &str) -> bool {
    match (
        purl::canonicalize_under(rule, given),
        purl::canonicalize_under(rule, purl),
    ) {
        (Ok(g), Ok(p)) => g.package() == p.package(),
        _ => false,
    }
}

#[derive(Default)]
struct Hashes {
    sha256: Sha256,
    sha512: Sha512,
    sha1: sha1::Sha1,
}

impl Hashes {
    fn update(&mut self, bytes: &[u8]) {
        self.sha256.update(bytes);
        self.sha512.update(bytes);
        self.sha1.update(bytes);
    }

    fn key(self) -> Key {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        Key::File(BTreeMap::from([
            ("sha256".to_string(), hex(&self.sha256.finalize())),
            ("sha512".to_string(), hex(&self.sha512.finalize())),
            ("sha1".to_string(), hex(&self.sha1.finalize())),
        ]))
    }
}

/// A record a later one supersedes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupersededBy {
    /// The superseding record's digest.
    pub record: Digest,
    /// The superseding record's leaf.
    pub pos: LeafPos,
    pub reason: SupersedeReason,
}

/// What was found of one record the key leads to.
#[derive(Clone, Debug)]
pub enum RecordState {
    /// Its file is there and verified.
    Verified(Box<VerifiedRecord>),
    /// The log has its leaf, and the repository has no file for it: evidence of a deletion,
    /// whatever the leaf's outcome (`docs/19` §3, §8).
    Deleted,
    /// Its file is there and failed verification, with why.
    Failed(RecordFailure),
}

/// One record leaf a key leads to, and what was found of it.
#[derive(Clone, Debug)]
pub struct Found {
    pub pos: LeafPos,
    pub leaf: RecordLeaf,
    pub state: RecordState,
    /// The verified records that supersede it, in the order the log holds them. Empty for a
    /// current record.
    pub superseded_by: Vec<SupersededBy>,
}

impl Found {
    /// Verified, and superseded by nothing.
    pub fn is_current(&self) -> bool {
        matches!(self.state, RecordState::Verified(_)) && self.superseded_by.is_empty()
    }

    pub fn verified(&self) -> Option<&VerifiedRecord> {
        match &self.state {
            RecordState::Verified(r) => Some(r),
            _ => None,
        }
    }
}

/// What a source says about a subject (`docs/19` §4.2), each state as loud as the others.
///
/// `unknown` — a stale or frozen source, or a `--remote` lookup that failed — is not here: it is a
/// fact about the source's freshness, which a caller holding the clocks decides (`docs/19` §6
/// phase 6), and never about what a verified log holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The log holds no record for the key.
    NeverChecked,
    /// The only current record is a withdrawal.
    Withdrawn,
    /// The log has a leaf, and the repository has no file for its record.
    Deleted,
    /// A record failed verification, with why.
    Failed(RecordFailure),
    /// A current verdict's outcome.
    Outcome(Match),
    /// A current void: "we looked, and could not tell".
    Void,
}

impl Answer {
    /// `docs/19` §6's exit code for this answer, with `min` the outcome floor
    /// (`normalized_with_caveats` by default): 4 for deleted or failed verification, 1 for a
    /// divergence, 3 for a void or an outcome below `min`, 2 for never checked or withdrawn, and 0
    /// otherwise.
    pub fn exit_code(&self, min: Match) -> u8 {
        match self {
            Answer::Failed(_) | Answer::Deleted => 4,
            Answer::Outcome(Match::Divergent) => 1,
            Answer::Void => 3,
            Answer::Outcome(m) if !m.is_at_least(min) => 3,
            Answer::NeverChecked | Answer::Withdrawn => 2,
            Answer::Outcome(_) => 0,
        }
    }

    /// The most severe of `answers`: by the precedence of their exit codes, 4, 1, 3, 2, then 0
    /// (`docs/19` §6), and within one code, the answer that says less for the package. Never
    /// checked, where there are none.
    pub fn most_severe(answers: impl IntoIterator<Item = Answer>, min: Match) -> Answer {
        answers
            .into_iter()
            .max_by_key(|a| (precedence(a.exit_code(min)), a.within()))
            .unwrap_or(Answer::NeverChecked)
    }

    /// Order within one exit code: failed before deleted, void before a low outcome, a lower
    /// outcome before a higher one, withdrawn before never checked.
    fn within(&self) -> u8 {
        match self {
            Answer::Failed(_) => 2,
            Answer::Deleted => 1,
            Answer::Void => 5,
            Answer::Outcome(Match::Divergent) => 4,
            Answer::Outcome(Match::NormalizedWithCaveats) => 3,
            Answer::Outcome(Match::Normalized) => 2,
            Answer::Outcome(Match::Exact) => 1,
            Answer::Withdrawn => 1,
            Answer::NeverChecked => 0,
        }
    }
}

impl std::fmt::Display for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Answer::NeverChecked => f.write_str("never checked"),
            Answer::Withdrawn => f.write_str("withdrawn"),
            Answer::Deleted => f.write_str("deleted"),
            Answer::Failed(why) => write!(f, "record failed verification: {why}"),
            Answer::Outcome(m) => write!(f, "{m}"),
            Answer::Void => f.write_str("void"),
        }
    }
}

/// `docs/19` §6: when several codes apply, the first in the order 5, 4, 1, 3, 2 wins.
fn precedence(code: u8) -> u8 {
    match code {
        5 => 5,
        4 => 4,
        1 => 3,
        3 => 2,
        2 => 1,
        _ => 0,
    }
}

/// Everything a key led to in one source.
#[derive(Clone, Debug)]
pub struct Lookup {
    pub key: Key,
    /// Every record leaf the key names, in the order the log holds them, each with what was found
    /// of it and what supersedes it.
    pub found: Vec<Found>,
}

impl Lookup {
    /// Mark every supersession the found records make, as `docs/19` §3 says.
    pub(crate) fn resolve(key: Key, mut found: Vec<Found>) -> Lookup {
        let superseding: Vec<(usize, Digest, SupersedeReason)> = found
            .iter()
            .enumerate()
            .filter_map(|(i, f)| {
                let (record, reason) = f.verified()?.supersedes()?;
                Some((i, record, reason))
            })
            .collect();
        for (by, record, reason) in superseding {
            let (pos, new) = (found[by].pos, found[by].leaf.clone());
            for old in found.iter_mut() {
                let same_purl = purl::canonicalize_under(new.purl_canon, &old.leaf.purl)
                    .is_ok_and(|c| c.as_str() == new.purl);
                if old.leaf.record == record
                    && old.pos < pos
                    && old.leaf.subject == new.subject
                    && same_purl
                {
                    old.superseded_by.push(SupersededBy {
                        record: new.record,
                        pos,
                        reason,
                    });
                }
            }
        }
        Lookup { key, found }
    }

    /// The records that are current: verified, and superseded by nothing.
    pub fn current(&self) -> impl Iterator<Item = &Found> {
        self.found.iter().filter(|f| f.is_current())
    }

    /// Each subject the key found, by its sha256, with what the source says about it, in the
    /// order the log first logged each.
    pub fn subjects(&self) -> Vec<(String, Answer)> {
        let mut order: Vec<String> = Vec::new();
        let mut by: BTreeMap<String, Vec<&Found>> = BTreeMap::new();
        for f in &self.found {
            let sha256 = f.leaf.subject.get("sha256").cloned().unwrap_or_default();
            if !by.contains_key(&sha256) {
                order.push(sha256.clone());
            }
            by.entry(sha256).or_default().push(f);
        }
        order
            .into_iter()
            .map(|s| {
                let answer = subject_answer(&by[&s]);
                (s, answer)
            })
            .collect()
    }

    /// What the source says about the key: the most severe of its subjects' answers under `min`,
    /// and never checked where the log holds nothing for it.
    pub fn answer(&self, min: Match) -> Answer {
        Answer::most_severe(self.subjects().into_iter().map(|(_, a)| a), min)
    }
}

/// What a source says about one subject: failed verification or deleted where any of its records
/// is, since either may be an attack; otherwise its current verdicts and voids, the most severe;
/// otherwise withdrawn, where its current records are withdrawals only.
fn subject_answer(found: &[&Found]) -> Answer {
    if let Some(why) = found.iter().find_map(|f| match &f.state {
        RecordState::Failed(why) => Some(why.clone()),
        _ => None,
    }) {
        return Answer::Failed(why);
    }
    if found
        .iter()
        .any(|f| matches!(f.state, RecordState::Deleted))
    {
        return Answer::Deleted;
    }
    let current: Vec<RecordKind> = found
        .iter()
        .filter(|f| f.is_current())
        .filter_map(|f| f.verified().map(VerifiedRecord::kind))
        .collect();
    let claims = current.iter().filter_map(|k| match k {
        RecordKind::Verdict(m) => Some(Answer::Outcome(*m)),
        RecordKind::Void => Some(Answer::Void),
        RecordKind::Withdrawal => None,
    });
    // The floor does not matter here: among claims, a divergence, then a void, then the lowest
    // outcome is the most severe under any floor, which is `most_severe`'s order under the
    // highest one.
    let claim = claims.max_by_key(|a| (precedence(a.exit_code(Match::Exact)), a.within()));
    match claim {
        Some(a) => a,
        None if current.contains(&RecordKind::Withdrawal) => Answer::Withdrawn,
        None => Answer::NeverChecked,
    }
}
