//! `trigon lookup <key>`: what every evidence source says of one artifact or package (`docs/19`
//! §4.2, §6, §6.1), and the asking that `trigon check` shares.
//!
//! **From the verified leaves, never from `index/`.** Each source is opened from its clones as
//! [`super::ready`] opens it — a stale one synced first and said to be, none touched under
//! `--offline` — and the key is resolved over the log it holds whole
//! (`trigon_attest::evidence::Repository::lookup`), every record checked against its leaf and every
//! supersession the log records applied. `--remote` is the labelled exception
//! ([`super::remote`]).
//!
//! **Per source, never merged** (§6.1). Each source's answer is printed beside its name, the file
//! that added it and the keys it rests on, with the checkpoint it came from; every record the key
//! led to is shown with the fields §4.2 has every client render — the outcome as a string, the set,
//! when and which Trigon, the egress tier and `attestable`, the derivation, the falsifying command
//! and the dispute pointer — and a superseded one struck through with its reason and both leaves.
//! Two sources that answer differently are said to disagree, and neither is taken over the other.
//! A record found by sha1 alone says that sha1 is collision-broken.
//!
//! **Exit codes are §6's**, from every source's answer weighed as `trigon_attest::evidence::
//! exit_code` weighs them.

use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use trigon_attest::config::{AddedBy, Env, EvidenceConfig, Source};
use trigon_attest::evidence::{
    Answer, Found, Key, Lookup, RecordFailure, RecordKind, RecordState, Said, Standing, exit_code,
    first_that_wins,
};
use trigon_attest::location::printable;
use trigon_attest::log::LeafPos;
use trigon_core::{Match, RiskTier};

use super::remote::{self, Http, Remote};
use super::{Mode, Ready, ready};
use crate::OutputFormat;

/// The outcome floor where none is asked for (`docs/19` §6).
pub(crate) const FLOOR: Match = Match::NormalizedWithCaveats;

/// What `trigon lookup` is given.
pub(crate) struct Args {
    pub key: String,
    pub sources: Vec<String>,
    pub offline: bool,
    pub remote: bool,
    pub output: OutputFormat,
    pub verbose: bool,
}

/// How the sources are asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Via {
    /// From the clones, a stale source synced first.
    Sync,
    /// From the clones as they are, touching no network (`--offline`).
    Offline,
    /// Over HTTPS, one file at a time (`--remote`).
    Remote,
}

/// One source, ready to be asked: how it stands, and what it answers from where it can.
pub(crate) struct Asker<'h> {
    pub name: String,
    /// What every answer from it carries: its name, the file that added it, the keys it rests on,
    /// and the checkpoint its answers come from.
    pub label: String,
    /// Whether its being unknown fails a check: `required = true`, `--require`, or
    /// `TRIGON_EVIDENCE_REPO`.
    pub required: bool,
    pub project_file: bool,
    pub first_use: bool,
    /// `fresh`, `usable`, `frozen`, `unknown`, `refused`, or `remote`.
    pub standing: &'static str,
    /// Why it cannot answer, where it cannot.
    pub why: Option<String>,
    /// What was done and found: synced first, a sync that failed, a mirror lagging.
    pub notes: Vec<String>,
    how: How<'h>,
}

enum How<'h> {
    Clone(Box<Ready>),
    Remote(Box<Remote<'h>>),
    /// It cannot answer: refused, where it failed verification, or unknown.
    Cannot {
        refused: bool,
    },
}

/// What one source said of one question.
pub(crate) struct Asked {
    /// Every record the question led to, where the source answered.
    pub lookup: Option<Lookup>,
    /// Records `--remote` could not prove a leaf for: failed verification.
    pub unproven: Vec<String>,
    pub said: Said,
    /// The keys that found the records: `sha512`, `sha256`, `sha1`, or the purl.
    pub by: Vec<String>,
    /// What else is said of this answer: sha1's weakness, a purl found for another artifact.
    pub notes: Vec<String>,
}

impl Asker<'_> {
    /// Whether it answers.
    pub(crate) fn answers(&self) -> bool {
        !matches!(self.how, How::Cannot { .. })
    }

    /// What it says it cannot, as a `Said`.
    fn cannot(&self) -> Said {
        match self.how {
            How::Cannot { refused: true } => Said::Refused,
            _ => Said::Unknown {
                required: self.required,
            },
        }
    }

    /// The origin of each log of its chain, by position, for naming a leaf.
    pub(crate) fn origins(&self) -> Vec<String> {
        match &self.how {
            How::Clone(r) => r.opened.as_ref().map_or_else(Vec::new, |o| {
                o.repo
                    .logs()
                    .iter()
                    .map(|l| l.origin().to_string())
                    .collect()
            }),
            How::Remote(r) => r.origins(),
            How::Cannot { .. } => Vec::new(),
        }
    }

    /// Every record `key` leads to in this source, with whatever `--remote` could not prove. An
    /// error is a source that could not be read for it: `--remote` failing midway.
    fn find(&self, key: &Key) -> std::result::Result<(Lookup, Vec<String>), String> {
        match &self.how {
            How::Clone(r) => match &r.opened {
                Some(o) => Ok((o.repo.lookup(key), Vec::new())),
                None => Err("it has no clone to answer from".into()),
            },
            How::Remote(r) => r.lookup(key),
            How::Cannot { .. } => Err("it cannot answer".into()),
        }
    }

    /// Ask it one key: every record it holds for the key, and its answer.
    pub(crate) fn ask(&self, key: &Key, min: Match, max_risk: Option<RiskTier>) -> Asked {
        self.ask_package(std::slice::from_ref(key), false, None, min, max_risk)
    }

    /// Ask it about one package (`docs/19` §6 `check`): by `digests` first — every digest the
    /// lockfile declares that a record may be filed under — and by `purl` second, where no digest
    /// found a record about the artifact the lockfile pins. `alternatives` says the digests are of
    /// artifacts any one of which may be installed, as a requirement's `--hash`es are, rather
    /// than of one artifact.
    ///
    /// A record is an answer about the package only where its leaf is about the artifact the
    /// lockfile pins ([`pinned_by`]): one found by a digest that another the lockfile declares
    /// contradicts — sha1, which is collision-broken, matching while the sha512 does not — and one
    /// found by purl whose digests are another artifact's are said, and never answer. Where
    /// nothing is left, the package is never checked.
    pub(crate) fn ask_package(
        &self,
        digests: &[Key],
        alternatives: bool,
        purl: Option<&Key>,
        min: Match,
        max_risk: Option<RiskTier>,
    ) -> Asked {
        if !self.answers() {
            return Asked {
                lookup: None,
                unproven: Vec::new(),
                said: self.cannot(),
                by: Vec::new(),
                notes: Vec::new(),
            };
        }
        let unknown = |why: String| Asked {
            lookup: None,
            unproven: Vec::new(),
            said: Said::Unknown {
                required: self.required,
            },
            by: Vec::new(),
            notes: vec![format!("--remote could not answer: {why}")],
        };
        let declared: Vec<(&str, &str)> = digests
            .iter()
            .filter_map(|k| match k {
                Key::Digest { algorithm, hex } => Some((*algorithm, hex.as_str())),
                _ => None,
            })
            .collect();
        let mut found: Vec<Found> = Vec::new();
        let mut unproven = Vec::new();
        let mut by = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        // Records set aside as another artifact's, by their leaf, so each is said once.
        let mut other: Vec<LeafPos> = Vec::new();
        let mut first: Option<&Key> = None;
        for k in digests {
            let (l, u) = match self.find(k) {
                Ok(x) => x,
                Err(why) => return unknown(why),
            };
            let mut kept = false;
            for f in l.found {
                match pinned_by(&f.leaf.subject, &declared, alternatives) {
                    Pinned::Other(why) => {
                        if !other.contains(&f.pos) {
                            other.push(f.pos);
                            notes.push(another(&f, &key_kind(k), &why));
                        }
                        continue;
                    }
                    Pinned::Mixed(why) => {
                        if !notes.contains(&why) {
                            notes.push(why);
                        }
                    }
                    Pinned::Yes | Pinned::Inconclusive => {}
                }
                kept = true;
                if !found.iter().any(|g| g.pos == f.pos) {
                    found.push(f);
                }
            }
            if kept {
                by.push(key_kind(k));
            }
            if kept || !u.is_empty() {
                first = first.or(Some(k));
            }
            unproven.extend(u);
        }
        let lookup = match (first, purl) {
            (Some(k), _) => {
                // The same records, found under several digests of one artifact: marked again
                // once, over all of them.
                for f in &mut found {
                    f.superseded_by.clear();
                }
                found.sort_by_key(|f| f.pos);
                Lookup::resolve(k.clone(), found)
            }
            (None, Some(p)) => {
                let (l, u) = match self.find(p) {
                    Ok(x) => x,
                    Err(why) => return unknown(why),
                };
                unproven.extend(u);
                let (mut kept, mut elsewhere, mut uncompared) = (Vec::new(), Vec::new(), false);
                for f in l.found {
                    match pinned_by(&f.leaf.subject, &declared, alternatives) {
                        Pinned::Other(_) => elsewhere.push(f),
                        Pinned::Inconclusive => {
                            uncompared |= !declared.is_empty();
                            kept.push(f);
                        }
                        Pinned::Yes | Pinned::Mixed(_) => kept.push(f),
                    }
                }
                if !elsewhere.is_empty() {
                    notes.push(format!(
                        "{} found by {} {} about another artifact than the one the lockfile pins, \
                         {}: {}{}",
                        elsewhere.len(),
                        printable(&p.to_string()),
                        match elsewhere.len() {
                            1 => "is",
                            _ => "are",
                        },
                        said_declared(&declared),
                        elsewhere
                            .iter()
                            .filter_map(|f| f.leaf.subject.get("sha256"))
                            .map(|h| format!("sha256:{h}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                        match kept.is_empty() {
                            true => ", so it is never checked for the artifact it pins",
                            false => "",
                        }
                    ));
                }
                if uncompared {
                    notes.push(format!(
                        "found by {}: the lockfile declares {}, and {} not carry any of those \
                         algorithms, so whether {} about the artifact it pins could not be \
                         compared. {} answered as the package's",
                        printable(&p.to_string()),
                        said_declared(&declared),
                        match kept.len() {
                            1 => "its subject does",
                            _ => "their subjects do",
                        },
                        match kept.len() {
                            1 => "it is",
                            _ => "they are",
                        },
                        match kept.len() {
                            1 => "It is",
                            _ => "They are",
                        }
                    ));
                }
                if !kept.is_empty() {
                    by.push("purl".into());
                }
                for f in &mut kept {
                    f.superseded_by.clear();
                }
                Lookup::resolve(p.clone(), kept)
            }
            (None, None) => Lookup {
                key: digests
                    .first()
                    .cloned()
                    .unwrap_or_else(|| Key::Purl(String::new())),
                found: Vec::new(),
            },
        };
        if by == ["sha1"] {
            notes.push(SHA1.into());
        }
        let answer = answer_of(&lookup, &unproven, min, max_risk);
        Asked {
            lookup: Some(lookup),
            unproven,
            said: Said::Answered(answer),
            by,
            notes,
        }
    }
}

/// Whether a record's leaf is about the artifact a lockfile pins, by the digests it declares.
#[derive(Debug, PartialEq, Eq)]
enum Pinned {
    /// It is.
    Yes,
    /// It is, by the strongest digest the lockfile declares, and a weaker one the lockfile
    /// declares is another artifact's: the lockfile's digests are not of one artifact. Said.
    Mixed(String),
    /// The leaf carries none of the algorithms the lockfile declares, so they cannot be compared.
    Inconclusive,
    /// It is not: a digest the lockfile declares, of an algorithm the leaf carries, is another's.
    Other(String),
}

/// How strong a subject's algorithm is, for deciding which of a lockfile's digests names the
/// artifact where they disagree: npm installs by the strongest in `integrity` and checks no other.
fn strength(algorithm: &str) -> u8 {
    match algorithm {
        "sha512" => 3,
        "sha256" => 2,
        "sha1" => 1,
        _ => 0,
    }
}

/// Whether a leaf whose subject is `subject` is about the artifact `declared` pins.
///
/// Of alternatives, it is about one of them where it matches any declared digest, and about none
/// where every one it could be compared with differs. Of one artifact's digests, the strongest
/// algorithm the leaf carries decides, as npm decides what it installs: a record matched by sha1
/// whose sha512 is not the one declared is another artifact, whatever its sha1 says, and one
/// matched by the sha512 is the artifact, with a weaker digest that disagrees said. An algorithm
/// the leaf does not carry — sha1, beyond npm — says nothing either way.
fn pinned_by(
    subject: &std::collections::BTreeMap<String, String>,
    declared: &[(&str, &str)],
    alternatives: bool,
) -> Pinned {
    let carried: Vec<(&str, &str)> = declared
        .iter()
        .copied()
        .filter(|(a, _)| subject.contains_key(*a))
        .collect();
    let Some(strongest) = carried.iter().map(|(a, _)| strength(a)).max() else {
        return Pinned::Inconclusive;
    };
    let matches = |(a, h): &(&str, &str)| subject.get(*a).map(String::as_str) == Some(*h);
    let differs = |(a, h): &(&str, &str)| {
        format!(
            "its {a} is {}, and the lockfile declares {a}:{h}",
            subject.get(*a).map_or("", String::as_str)
        )
    };
    if alternatives {
        return match carried.iter().any(matches) {
            true => Pinned::Yes,
            false => Pinned::Other(carried.iter().map(differs).collect::<Vec<_>>().join("; ")),
        };
    }
    let deciding: Vec<(&str, &str)> = carried
        .iter()
        .copied()
        .filter(|(a, _)| strength(a) == strongest)
        .collect();
    if !deciding.iter().any(matches) {
        return Pinned::Other(differs(&deciding[0]));
    }
    // A weaker algorithm none of whose declared digests is this artifact's.
    let mut weaker: Vec<&str> = carried
        .iter()
        .map(|(a, _)| *a)
        .filter(|a| strength(a) < strongest)
        .collect();
    weaker.sort_unstable();
    weaker.dedup();
    let disagree: Vec<String> = weaker
        .into_iter()
        .filter(|a| !carried.iter().any(|d| d.0 == *a && matches(d)))
        .flat_map(|a| carried.iter().filter(move |d| d.0 == a).map(differs))
        .collect();
    match disagree.is_empty() {
        true => Pinned::Yes,
        false => Pinned::Mixed(format!(
            "the lockfile's digests are not of one artifact: {}. Its {} decides which artifact it \
             pins, as npm installs by the strongest digest it declares, and that is the one \
             answered for",
            disagree.join("; "),
            deciding[0].0
        )),
    }
}

/// A note for a record set aside as another artifact's than the one a lockfile pins.
fn another(f: &Found, by: &str, why: &str) -> String {
    format!(
        "sha256:{} at {}, found by {by}, is about another artifact than the one the lockfile pins, \
         and does not answer for it: {why}{}",
        f.leaf.record.to_hex(),
        f.pos,
        match by {
            "sha1" =>
                ". sha1 is collision-broken, and the stronger digest the lockfile declares \
                       names the artifact",
            _ => "",
        }
    )
}

/// The digests a lockfile declares, as a note names them.
fn said_declared(declared: &[(&str, &str)]) -> String {
    declared
        .iter()
        .map(|(a, h)| format!("{a}:{h}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a record found by sha1 alone says of it (`docs/19` §5).
const SHA1: &str = "found by sha1 alone, which is collision-broken: an artifact made to collide \
                    with this one would be found by it too. Look it up by its sha512 or sha256 \
                    where you have one";

/// The kind of key a key is, as an answer names what found it.
fn key_kind(k: &Key) -> String {
    match k {
        Key::Digest { algorithm, .. } => (*algorithm).to_string(),
        Key::Purl(_) => "purl".into(),
        Key::Package(_) => "package".into(),
        Key::File(_) => "file".into(),
    }
}

/// What a source says of a question: the most severe of its subjects' answers, held to `min` and
/// `max_risk`, and a record whose leaf `--remote` could not prove failing verification.
pub(crate) fn answer_of(
    lookup: &Lookup,
    unproven: &[String],
    min: Match,
    max_risk: Option<RiskTier>,
) -> Answer {
    let mut all: Vec<Answer> = lookup
        .subjects_under(max_risk)
        .into_iter()
        .map(|(_, a)| a)
        .collect();
    all.extend(
        unproven
            .iter()
            .map(|w| Answer::Failed(RecordFailure::Unreadable(w.clone()))),
    );
    Answer::most_severe(all, min)
}

/// What several sources' answers about one package come to, as `exit_code` weighs them: the most
/// severe answer any source gave that is not unknown, and never checked only where no source that
/// answered holds a record for it; `None` where no source answered at all.
pub(crate) fn weighed(said: &[Said], min: Match) -> Option<Answer> {
    let answered: Vec<Answer> = said
        .iter()
        .filter_map(|s| match s {
            Said::Answered(a) => Some(a.clone()),
            _ => None,
        })
        .collect();
    if answered.is_empty() {
        return None;
    }
    let held: Vec<Answer> = answered
        .into_iter()
        .filter(|a| *a != Answer::NeverChecked)
        .collect();
    Some(Answer::most_severe(held, min))
}

/// Now, in Unix seconds.
fn now() -> u64 {
    super::now()
}

/// Every source a command asks — `names`, or all — ready to be asked `via` its clones or over
/// HTTPS, each marked required where `require` names it. None configured is exit 5.
pub(crate) fn askers<'h>(
    config: &EvidenceConfig,
    names: &[String],
    require: &[String],
    via: Via,
    http: Option<&'h Http>,
    verbose: bool,
) -> Result<Vec<Asker<'h>>> {
    for n in require {
        if !config
            .sources()
            .iter()
            .any(|s| s.name.eq_ignore_ascii_case(n))
        {
            return Err(trigon_attest::config::ConfigError::NoSuchSource {
                name: printable(n),
                known: config.sources().iter().map(|s| s.name.clone()).collect(),
            }
            .into());
        }
        // A required source the command does not ask could never fail it: refused as the bad
        // argument it is (exit 5), rather than a check that passes on the other sources alone.
        if !names.is_empty() && !names.iter().any(|s| s.eq_ignore_ascii_case(n)) {
            return Err(anyhow!(
                "--require {} names a source --source leaves out, so it would never be asked and \
                 could never fail the check; name it with --source too, or drop --require",
                printable(n)
            ));
        }
    }
    let required =
        |s: &Source| s.required || require.iter().any(|n| n.eq_ignore_ascii_case(&s.name));
    let now = now();
    match via {
        Via::Sync | Via::Offline => {
            let mode = match via {
                Via::Offline => Mode::Offline,
                _ => Mode::Sync,
            };
            Ok(ready(config, names, mode, now, verbose)?
                .into_iter()
                .map(|mut r| {
                    r.source.required = required(&r.source);
                    let answers = r.standing.answers() && r.opened.is_some();
                    let refused = matches!(r.standing, Standing::Refused { .. });
                    let (name, label, notes) = (r.source.name.clone(), r.label(), r.notes.clone());
                    Asker {
                        name,
                        label,
                        required: r.source.required,
                        project_file: matches!(r.source.added_by, AddedBy::ProjectFile(_)),
                        first_use: r.first_use.is_some(),
                        standing: r.standing.key(),
                        why: (!answers).then(|| standing_why(&r.standing)),
                        notes,
                        how: match answers {
                            true => How::Clone(Box::new(r)),
                            false => How::Cannot { refused },
                        },
                    }
                })
                .collect())
        }
        Via::Remote => {
            let http = http.ok_or_else(|| anyhow!("--remote was asked for with no HTTP client"))?;
            let chosen = super::chosen(config, names)?;
            // A source that cannot be asked this way at all is the tool failing before it could
            // answer (§6: exit 5), and said before anything is fetched.
            if let Some(s) = chosen
                .iter()
                .find(|s| remote::github_repository(s).is_none())
            {
                return Err(remote::unreadable_source(s));
            }
            let mut out = Vec::new();
            for s in chosen {
                let mut a = Asker {
                    name: s.name.clone(),
                    label: format!("`{}`, {}", s.name, super::added_by(&s.added_by)),
                    required: required(&s),
                    project_file: matches!(s.added_by, AddedBy::ProjectFile(_)),
                    first_use: false,
                    standing: "remote",
                    why: None,
                    notes: Vec::new(),
                    how: How::Cannot { refused: false },
                };
                if let Ok(p) = config.pins(&s.name)
                    && let Some(f) = p.first_use
                {
                    a.first_use = true;
                    a.label.push_str(&format!(
                        "; resting on keys trusted on first use, read from {} at {}",
                        f.read_from,
                        crate::rfc3339_from_unix(f.at)
                    ));
                }
                match Remote::open(http, config, &s) {
                    Ok(r) if r.frozen(config.freshness(), now) => {
                        a.label.push_str(&format!("; {}", r.label()));
                        a.standing = "frozen";
                        a.why = Some(match r.newest {
                            Some(t) => format!(
                                "frozen: its newest leaf was logged {}, longer ago than \
                                 `frozen_after`",
                                crate::rfc3339_from_unix(t)
                            ),
                            None => "frozen: its log has no leaf, which says nothing about how \
                                     recent it is"
                                .into(),
                        });
                    }
                    Ok(r) => {
                        a.label.push_str(&format!("; {}", r.label()));
                        a.notes.extend(r.notes.iter().cloned());
                        a.how = How::Remote(Box::new(r));
                    }
                    Err(u) => {
                        a.standing = match u.refused {
                            true => "refused",
                            false => "unknown",
                        };
                        a.why = Some(printable(&u.why));
                        a.how = How::Cannot { refused: u.refused };
                    }
                }
                out.push(a);
            }
            Ok(out)
        }
    }
}

/// Why a source that does not answer does not, in words.
pub(crate) fn standing_why(s: &Standing) -> String {
    super::standing_said(s)
}

/// `trigon lookup`: the report, and §6's exit code; anything that stops it before it can answer
/// is the tool failing, exit 5.
pub(crate) fn run(args: Args) -> Result<()> {
    finish(answer(args))
}

/// Exit with `code`, or, where the command stopped before it could answer, say why and exit 5: the
/// end of `lookup` and `check` alike.
pub(crate) fn finish(code: Result<u8>) -> Result<()> {
    let code = match code {
        Ok(c) => i32::from(c),
        Err(e) => {
            crate::report_fault(&e);
            eprintln!("Error: {e:?}");
            crate::verify_record::CANNOT
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn answer(args: Args) -> Result<u8> {
    let key = match Key::parse(&args.key) {
        Ok(k) => k,
        // Not a key a record is filed under: a file whose digests are computed, or nothing.
        Err(e) => {
            let path = std::path::Path::new(&args.key);
            if path.is_file() {
                Key::of_file(path).map_err(|x| anyhow!("reading {}: {x}", path.display()))?
            } else {
                crate::verify_record::usage(&format!(
                    "{e}, and there is no file at {}",
                    printable(&args.key)
                ));
            }
        }
    };
    let env = Env::from_process()?;
    let config = EvidenceConfig::load(&env)?;
    let via = match (args.offline, args.remote) {
        (_, true) => Via::Remote,
        (true, false) => Via::Offline,
        (false, false) => Via::Sync,
    };
    let http = match via {
        Via::Remote => Some(Http::new()?),
        _ => None,
    };
    let askers = askers(
        &config,
        &args.sources,
        &[],
        via,
        http.as_ref(),
        args.verbose,
    )?;
    let asked: Vec<Asked> = askers.iter().map(|a| a.ask(&key, FLOOR, None)).collect();
    let said: Vec<Said> = asked.iter().map(|a| a.said.clone()).collect();
    let code = exit_code(&said, FLOOR, true);
    let disagree = disagreement(&askers, &asked);
    match args.output {
        OutputFormat::Json => {
            let doc = json!({
                "key": key.to_string(),
                "keyKind": key_kind(&key),
                "digests": match &key {
                    Key::File(d) => json!(d),
                    _ => Value::Null,
                },
                "sources": askers.iter().zip(&asked).map(|(a, x)| source_json(a, x)).collect::<Vec<_>>(),
                "disagreement": disagree.as_ref().map(|d| json!(d)),
                "caveats": match via {
                    Via::Remote => json!(remote::CAVEATS),
                    _ => json!([]),
                },
                "requested": http.as_ref().map(|h| json!(h.asked())),
                "exit": code,
            });
            println!("{}", crate::verify_record::pretty(&doc));
        }
        OutputFormat::Text => {
            println!("key       {}", key_said(&key));
            for (a, x) in askers.iter().zip(&asked) {
                println!();
                print_source(a, x);
            }
            if let Some(d) = &disagree {
                println!();
                println!(
                    "{}",
                    crate::style::bad("disagree  the sources disagree about it:")
                );
                for line in d {
                    println!("          {line}");
                }
                println!(
                    "          each is its own claim, shown as its source makes it, and neither \
                     is taken over the other (docs/19 §6.1)"
                );
            }
            if via == Via::Remote {
                println!();
                for c in remote::CAVEATS {
                    println!("caveat    {}", crate::style::wrap(c, 10));
                }
                if args.verbose
                    && let Some(h) = &http
                {
                    for u in h.asked() {
                        println!("fetched   {u}");
                    }
                }
            }
            println!();
            println!("exit      {code}: {}", code_said(code));
        }
    }
    Ok(code)
}

/// A key as the report names it.
fn key_said(key: &Key) -> String {
    match key {
        Key::File(d) => format!(
            "the file with {}",
            ["sha256", "sha512", "sha1"]
                .iter()
                .filter_map(|a| d.get(*a).map(|h| format!("{a}:{h}")))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Key::Package(p) => format!("{}, every version", printable(p)),
        k => k.to_string(),
    }
}

/// What an exit code means, as §6 lists them.
pub(crate) fn code_said(code: u8) -> &'static str {
    match code {
        0 => "every answer at or above the threshold",
        1 => "a divergence",
        2 => "never checked, or withdrawn",
        3 => "a void, or a result below the threshold",
        4 => {
            "a deleted record, a record or source that failed verification, a required source \
              that is unknown, or no source able to answer"
        }
        _ => "the tool could not check",
    }
}

/// Where the answering sources disagree: each one's answer, where more than one claim is made and
/// they are not one claim. Never checked is no claim, and unknown is no answer.
pub(crate) fn disagreement(askers: &[Asker<'_>], asked: &[Asked]) -> Option<Vec<String>> {
    let claims: Vec<(String, String)> = askers
        .iter()
        .zip(asked)
        .filter_map(|(a, x)| match &x.said {
            Said::Answered(Answer::NeverChecked) => None,
            Said::Answered(ans) => Some((a.name.clone(), answer_word(ans))),
            _ => None,
        })
        .collect();
    let distinct = {
        let mut words: Vec<&str> = claims.iter().map(|(_, w)| w.as_str()).collect();
        words.sort_unstable();
        words.dedup();
        words.len()
    };
    (distinct > 1).then(|| {
        claims
            .into_iter()
            .map(|(n, w)| format!("`{n}` says {w}"))
            .collect()
    })
}

/// An answer as one word or phrase, for comparing sources and for a table.
pub(crate) fn answer_word(a: &Answer) -> String {
    match a {
        Answer::NeverChecked => "never checked".into(),
        Answer::Withdrawn => "withdrawn".into(),
        Answer::Deleted => "deleted".into(),
        Answer::Failed(_) => "failed verification".into(),
        Answer::Outcome(m) => m.to_string(),
        Answer::AboveMaxRisk { outcome, .. } => format!("{outcome}, above --max-risk"),
        Answer::Void => "void".into(),
    }
}

/// What one source said, as a word: its answer, or why it gave none.
pub(crate) fn said_word(s: &Said) -> String {
    match s {
        Said::Answered(a) => answer_word(a),
        Said::Unknown { required: true } => "unknown, and it is required".into(),
        Said::Unknown { required: false } => "unknown".into(),
        Said::Refused => "refused: it failed verification".into(),
    }
}

fn print_source(a: &Asker<'_>, x: &Asked) {
    println!("source    {}", crate::style::wrap(&a.label, 10));
    for n in &a.notes {
        println!("note      {}", crate::style::wrap(&printable(n), 10));
    }
    match &x.said {
        Said::Answered(ans) => {
            let n = x.lookup.as_ref().map_or(0, |l| l.found.len());
            let from = match n {
                0 => "its log holds no record for it".to_string(),
                n => format!("from {n} record(s) its log holds for it"),
            };
            println!(
                "answer    {} — {from}",
                paint(ans, &crate::style::wrap(&ans.to_string(), 10))
            );
        }
        Said::Unknown { required } => println!(
            "answer    unknown — {}{}",
            crate::style::wrap(a.why.as_deref().unwrap_or("it could not answer"), 10),
            match required {
                true => "; it is required, so this fails a check",
                false => "",
            }
        ),
        Said::Refused => println!(
            "answer    {} — {}",
            crate::style::bad("REFUSED"),
            crate::style::wrap(
                a.why
                    .as_deref()
                    .unwrap_or("its last sync failed verification"),
                10
            )
        ),
    }
    for n in &x.notes {
        println!("note      {}", crate::style::wrap(n, 10));
    }
    for w in &x.unproven {
        println!(
            "record    {} — {}",
            crate::style::bad("FAILED VERIFICATION"),
            crate::style::wrap(&printable(w), 10)
        );
    }
    let Some(l) = &x.lookup else { return };
    let origins = a.origins();
    let subjects = l.subjects();
    for (sha256, answer) in &subjects {
        if subjects.len() > 1 {
            println!("artifact  sha256:{sha256}: {answer}");
        }
        for f in l
            .found
            .iter()
            .filter(|f| f.leaf.subject.get("sha256") == Some(sha256))
        {
            print_record(f, &origins);
        }
    }
}

/// Paint an answer by what it is: green at or above the floor, yellow below it, red for a
/// divergence or a failure.
fn paint(a: &Answer, text: &str) -> String {
    match a.exit_code(FLOOR) {
        0 => crate::style::good(text),
        1 | 4 => crate::style::bad(text),
        _ => crate::style::warn(text),
    }
}

/// A leaf, as a person reads where it is.
pub(crate) fn leaf_said(origins: &[String], pos: LeafPos) -> String {
    match origins.get(pos.log) {
        Some(o) => format!("leaf {} of `{o}`", pos.index),
        None => pos.to_string(),
    }
}

fn print_record(f: &Found, origins: &[String]) {
    let at = leaf_said(origins, f.pos);
    let digest = format!("sha256:{}", f.leaf.record.to_hex());
    match &f.state {
        // Whatever its leaf says is not shown: a client never renders an outcome it cannot show
        // with the record that carries its dispute pointer and falsifying command (§8).
        RecordState::Deleted => println!(
            "record    {digest} at {at}: {} — the log has its leaf, and the repository has no \
             file for it. That is evidence of a deletion, and what its leaf says is not shown \
             without the record that carries its recourse",
            crate::style::bad("DELETED")
        ),
        RecordState::Failed(why) => println!(
            "record    {digest} at {at}: {} ({}) — {}",
            crate::style::bad("FAILED VERIFICATION"),
            why.kind(),
            crate::style::wrap(&printable(&why.to_string()), 10)
        ),
        RecordState::Verified(v) if !f.superseded_by.is_empty() => {
            let by: Vec<String> = f
                .superseded_by
                .iter()
                .map(|s| {
                    format!(
                        "sha256:{} at {} ({})",
                        s.record.to_hex(),
                        leaf_said(origins, s.pos),
                        s.reason
                    )
                })
                .collect();
            println!(
                "record    {} SUPERSEDED by {}",
                strike(&format!(
                    "{digest} at {at}: {}",
                    crate::verify_record::kind_said(v.kind())
                )),
                by.join(", and by ")
            );
            // Its §4.2 fields too, struck through as it is: an outcome is never shown without its
            // dispute pointer and falsifying command (§8), a superseded one included.
            for (label, value) in crate::verify_record::signed_fields(v) {
                println!("{label:<10}{}", strike(&crate::style::wrap(&value, 10)));
            }
        }
        RecordState::Verified(v) => {
            println!("record    {digest} at {at}, current");
            for s in &v.statement.subject {
                println!(
                    "subject   {} ({})",
                    printable(&s.name),
                    s.digest.get("sha256").map(String::as_str).unwrap_or("?")
                );
            }
            println!("purl      {}", v.leaf.purl);
            println!("predicate {}", v.statement.predicate_type);
            let said = |k: &str| printable(v.statement.predicate[k].as_str().unwrap_or("?"));
            match v.kind() {
                RecordKind::Withdrawal => {
                    println!("withdraws {} ({})", said("supersedes"), said("reason"))
                }
                RecordKind::Void => println!("claims    void, because {}", said("because")),
                RecordKind::Verdict(m) => println!("claims    {m}"),
            }
            for (label, value) in crate::verify_record::signed_fields(v) {
                println!("{label:<10}{}", crate::style::wrap(&value, 10));
            }
            if v.kind() != RecordKind::Withdrawal
                && let Some((record, reason)) = v.supersedes()
            {
                println!("supersedes sha256:{} ({reason})", record.to_hex());
            }
            let unchecked: Vec<&str> = v.unchecked().map(|e| e.name.as_str()).collect();
            if !unchecked.is_empty() {
                println!(
                    "evidence  {}",
                    crate::style::wrap(
                        &format!(
                            "not checked here: {}. A clone keeps `evidence/` out, and \
                             `verify-attestation --lookup` fetches what it re-derives the claim \
                             from",
                            unchecked.join(", ")
                        ),
                        10
                    )
                );
            }
        }
    }
}

/// Text struck through: with colour, the terminal's strike-through; plain, between `~~`, since
/// the words beside it say "superseded" either way.
fn strike(text: &str) -> String {
    match crate::style::enabled() {
        true => format!("\x1b[9m{text}\x1b[0m"),
        false => format!("~~{text}~~"),
    }
}

/// One source's answer, as `--output json` carries it.
pub(crate) fn source_json(a: &Asker<'_>, x: &Asked) -> Value {
    let origins = a.origins();
    json!({
        "name": a.name,
        "label": a.label,
        "required": a.required,
        "projectFile": a.project_file,
        "trustOnFirstUse": a.first_use,
        "standing": a.standing,
        "why": a.why,
        "notes": a.notes,
        "said": said_word(&x.said),
        "answer": match &x.said {
            Said::Answered(ans) => json!(ans.to_string()),
            _ => Value::Null,
        },
        "foundBy": x.by,
        "answerNotes": x.notes,
        "unproven": x.unproven,
        "records": x.lookup.as_ref().map_or_else(Vec::new, |l| {
            l.found.iter().map(|f| record_json(f, &origins)).collect::<Vec<_>>()
        }),
    })
}

/// One record a key led to, as `--output json` carries it: where its leaf is, what was found of
/// it, and for a verified one the fields `docs/19` §4.2 has every client render, as signed.
pub(crate) fn record_json(f: &Found, origins: &[String]) -> Value {
    let mut doc = json!({
        "record": format!("sha256:{}", f.leaf.record.to_hex()),
        "leaf": {
            "origin": origins.get(f.pos.log),
            "log": f.pos.log,
            "index": f.pos.index,
        },
        "current": f.is_current(),
        "supersededBy": f.superseded_by.iter().map(|s| json!({
            "record": format!("sha256:{}", s.record.to_hex()),
            "leaf": { "origin": origins.get(s.pos.log), "log": s.pos.log, "index": s.pos.index },
            "reason": s.reason.as_str(),
        })).collect::<Vec<_>>(),
    });
    match &f.state {
        RecordState::Deleted => {
            doc["state"] = json!("deleted");
        }
        RecordState::Failed(why) => {
            doc["state"] = json!("failed-verification");
            doc["failure"] = json!({ "kind": why.kind(), "reason": why.to_string() });
        }
        RecordState::Verified(v) => {
            doc["state"] = json!("verified");
            let p = &v.statement.predicate;
            doc["subject"] = json!(v.statement.subject);
            doc["purl"] = json!(v.leaf.purl);
            doc["predicateType"] = json!(v.statement.predicate_type);
            doc["claims"] = json!(crate::verify_record::kind_said(v.kind()));
            for (key, value) in [
                ("because", p.get("because")),
                ("stabilizerSet", p.get("stabilizerSet")),
                ("run", p.get("run")),
                ("trigonVersion", p.get("trigonVersion")),
                ("egressTier", p.get("egressTier")),
                ("attestable", p.get("attestable")),
                ("derivation", p.pointer("/derivation/method")),
                ("falsifyingCommand", p.get("falsifyingCommand")),
                ("disputePointer", p.get("disputePointer")),
                ("maxRiskApplied", p.pointer("/provenanceCap/maxRiskApplied")),
            ] {
                doc[key] = value.cloned().unwrap_or(Value::Null);
            }
            doc["key"] = json!(v.key.key_id());
            doc["supersedes"] = match v.supersedes() {
                Some((record, reason)) => json!({
                    "record": format!("sha256:{}", record.to_hex()),
                    "reason": reason.as_str(),
                }),
                None => Value::Null,
            };
            doc["evidence"] = json!(
                v.evidence
                    .iter()
                    .map(|e| json!({
                        "name": e.name,
                        "digest": format!("sha256:{}", e.digest.to_hex()),
                        "state": crate::verify_record::state_name(&e.state),
                    }))
                    .collect::<Vec<_>>()
            );
        }
    }
    doc
}

/// The exit code of several packages' codes, as §6 has the first of 5, 4, 1, 3, 2 win.
pub(crate) fn worst(codes: impl IntoIterator<Item = u8>) -> u8 {
    first_that_wins(codes)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn subject(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(a, h)| ((*a).to_string(), (*h).to_string()))
            .collect()
    }

    /// Of one artifact's digests the strongest the leaf carries decides, as npm decides what it
    /// installs; of alternatives, any one matching is enough; and an algorithm the leaf does not
    /// carry says nothing either way, so a record it cannot be compared with is never called
    /// another artifact's.
    #[test]
    fn a_leaf_is_about_the_pinned_artifact_by_the_strongest_digest_it_can_be_compared_with() {
        let npm = subject(&[("sha256", "a2"), ("sha512", "a5"), ("sha1", "a1")]);
        let pypi = subject(&[("sha256", "a2"), ("sha512", "a5")]);
        // Found by sha1, and its sha512 is not the one declared: another artifact.
        assert!(matches!(
            pinned_by(&npm, &[("sha512", "b5"), ("sha1", "a1")], false),
            Pinned::Other(why) if why.contains("its sha512 is a5, and the lockfile declares sha512:b5")
        ));
        // Found by sha512, and the sha1 declared beside it is another's: the sha512 decides.
        assert!(matches!(
            pinned_by(&npm, &[("sha512", "a5"), ("sha1", "b1")], false),
            Pinned::Mixed(why) if why.contains("not of one artifact")
        ));
        assert_eq!(
            pinned_by(&npm, &[("sha512", "a5"), ("sha1", "a1")], false),
            Pinned::Yes
        );
        // A sha1 the leaf does not carry cannot be compared.
        assert_eq!(
            pinned_by(&pypi, &[("sha1", "b1")], false),
            Pinned::Inconclusive
        );
        assert_eq!(pinned_by(&pypi, &[], false), Pinned::Inconclusive);
        // A requirement's hashes are alternatives: one matching is enough, none is another's.
        assert_eq!(
            pinned_by(&pypi, &[("sha256", "b2"), ("sha256", "a2")], true),
            Pinned::Yes
        );
        assert_eq!(
            pinned_by(&pypi, &[("sha256", "b2"), ("sha512", "c5")], true),
            Pinned::Other(
                "its sha256 is a2, and the lockfile declares sha256:b2; its sha512 is a5, and \
                 the lockfile declares sha512:c5"
                    .into()
            )
        );
    }
}
