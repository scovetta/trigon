//! What a model was asked, what it answered, and enough to ask it again.
//!
//! **A replay proves provenance of the derivation. It does not prove reproducibility of the
//! result.** It replays the model, not the world (`docs/07-ai.md` §8). That sentence belongs
//! wherever this is described, because the stronger claim is tempting and false: a transcript shows
//! that *this exchange* produced *that strategy*, and says nothing about whether asking again today
//! would produce the same one.
//!
//! What it is good for is narrower and real: regression testing a prompt change at zero cost,
//! evaluating a new model against recorded inputs, and auditing how a model-assisted strategy came
//! to exist. The last is why it is worth storing even when nobody intends to replay: a strategy with
//! `derivation: model_assisted` and no transcript is an assertion, and one with a transcript is a
//! record.
//!
//! Everything needed to make the weaker claim true is recorded on the [`Turn`] rather than left to a
//! convention: the exact model snapshot, the sampling parameters, and digests of the prompt and the
//! schema. An alias like `claude-opus-5` is refused where a snapshot is expected, because an alias
//! that resolves to a new snapshot breaks replay *and says nothing when it does*.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::provider::{LlmError, ModelCaps, Provider, Reasoning, Request, Response, Usage};

/// One exchange, with everything a replay needs to be honest about what it is repeating.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Turn {
    /// The snapshot that answered, as the provider reported it — not the one that was asked for.
    /// They differ when an alias was used, and that difference is the thing replay must surface.
    pub model: String,
    pub temperature: f32,
    /// SHA-256 of the flattened prompt. The prompt itself can be large and is often uninteresting;
    /// the digest is what says "this is the same question" without storing it twice.
    pub prompt_sha256: String,
    /// SHA-256 of the system message, separately, because it is the one part that must never come
    /// from a package and a change to it is a change to the operator's instructions.
    pub system_sha256: String,
    /// SHA-256 of the requested output schema, or absent where none was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_sha256: Option<String>,
    pub answer: String,
    /// What the model reasoned before answering, where the provider returned it separately.
    ///
    /// Recorded rather than dropped: it was charged as output and it is the derivation. A
    /// transcript whose answer is a build recipe and whose reasoning is gone can say *what* was
    /// proposed and never *why*, which is the half a reviewer needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    /// What was asked for, which is part of the question in the same way `temperature` is.
    #[serde(default, skip_serializing_if = "Reasoning::is_default")]
    pub reasoning_asked: Reasoning,
    pub usage: Usage,
    pub stop_reason: String,
}

/// A recorded run.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Transcript {
    /// What was being worked on, for a human reading this later.
    pub target: String,
    pub turns: Vec<Turn>,
}

impl Transcript {
    pub fn new(target: impl Into<String>) -> Self {
        Transcript {
            target: target.into(),
            turns: Vec::new(),
        }
    }

    pub fn tokens(&self) -> Usage {
        self.turns.iter().fold(Usage::default(), |mut a, t| {
            a.input += t.usage.input;
            a.cached_input += t.usage.cached_input;
            a.output += t.usage.output;
            a
        })
    }

    /// Whether every turn names a concrete snapshot rather than an alias.
    ///
    /// A transcript that fails this can still be read by a human, and cannot be replayed as
    /// evidence of anything: the model it names is whatever that alias resolves to today.
    pub fn replayable(&self) -> bool {
        self.turns.iter().all(|t| is_snapshot(&t.model))
    }
}

/// Whether a model id pins specific weights.
///
/// Crude on purpose, and it accepts three shapes: a dated snapshot
/// (`claude-haiku-4-5-20251001`), a version that *is* the complete id — Anthropic's current models
/// are named `claude-opus-5` with no date to append, and appending one is an error — and a content
/// digest, which is how a local tag gets pinned to bytes (`qwen2.5:0.5b@a8b0c5157701`).
///
/// What it refuses is a label that resolves to whatever is behind it today: `gpt-latest`,
/// `sonnet-preview`, a bare Ollama tag. Being wrong in the strict direction costs a caller a
/// re-record; being wrong the other way costs a transcript that claims to be replayable and is not.
pub fn is_snapshot(model: &str) -> bool {
    // `replay` is the recorded-answer provider, which by construction *is* pinned: its answers are
    // the recording.
    if model == "replay" {
        return true;
    }
    let Some(last) = model.rsplit(['-', ':', '@']).next() else {
        return false;
    };
    let digits = !last.is_empty() && last.chars().all(|c| c.is_ascii_digit());
    let digest = last.len() >= 12 && last.chars().all(|c| c.is_ascii_hexdigit());
    digits || digest
}

/// A provider that records everything through it.
///
/// Wraps another rather than replacing it, so recording is never a second code path that can drift
/// from the one that runs in production. Interior mutability because [`Provider::complete`] takes
/// `&self`: the trait is shaped for concurrent use and a recorder must not change that.
#[derive(Debug)]
pub struct Recorder<P> {
    inner: P,
    turns: std::sync::Mutex<Vec<Turn>>,
}

impl<P: Provider> Recorder<P> {
    pub fn new(inner: P) -> Self {
        Recorder {
            inner,
            turns: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// The transcript so far.
    pub fn transcript(&self, target: impl Into<String>) -> Transcript {
        Transcript {
            target: target.into(),
            turns: self.turns.lock().map(|t| t.clone()).unwrap_or_default(),
        }
    }
}

impl<P: Provider> Provider for Recorder<P> {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn caps(&self) -> ModelCaps {
        self.inner.caps()
    }

    fn complete(&self, req: &Request) -> Result<Response, LlmError> {
        let resp = self.inner.complete(req)?;
        let turn = Turn {
            // The provider's answer, not the request's. An alias asked for and a snapshot answered
            // is exactly the case worth recording.
            model: resp.model.clone(),
            temperature: req.temperature,
            prompt_sha256: sha(req.prompt.flatten().as_bytes()),
            system_sha256: sha(req.prompt.system.as_bytes()),
            schema_sha256: req
                .schema
                .as_ref()
                .map(|s| sha(serde_json::to_string(s).unwrap_or_default().as_bytes())),
            answer: resp.text.clone(),
            reasoning: resp.reasoning.clone(),
            reasoning_asked: req.reasoning,
            usage: resp.usage,
            stop_reason: resp.stop_reason.clone(),
        };
        if let Ok(mut t) = self.turns.lock() {
            t.push(turn);
        }
        Ok(resp)
    }
}

/// Replay a transcript, answering from the recording and calling nothing.
///
/// Checks the prompt against what was recorded and **refuses when it differs**. A replay that
/// answered a changed prompt with an old answer would be the most misleading thing this module
/// could do: the run would succeed, the strategy would look derived, and the derivation on record
/// would be of a different question.
#[derive(Debug)]
pub struct Replaying {
    turns: Vec<Turn>,
    at: std::sync::atomic::AtomicUsize,
}

impl Replaying {
    pub fn new(transcript: Transcript) -> Self {
        Replaying {
            turns: transcript.turns,
            at: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl Provider for Replaying {
    fn id(&self) -> &str {
        "replaying"
    }

    /// What the recording was made under. The caller copies this into its request, so replaying a
    /// no-reasoning recording asks a no-reasoning question rather than a different one.
    fn reasoning(&self) -> Reasoning {
        self.turns
            .first()
            .map(|t| t.reasoning_asked)
            .unwrap_or_default()
    }

    fn caps(&self) -> ModelCaps {
        ModelCaps {
            structured_output: true,
            tools: true,
            prompt_cache: false,
            context_tokens: u32::MAX,
        }
    }

    fn complete(&self, req: &Request) -> Result<Response, LlmError> {
        let i = self.at.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let turn = self.turns.get(i).ok_or_else(|| {
            LlmError::Malformed(format!(
                "the transcript holds {} turn(s) and the run asked for {}",
                self.turns.len(),
                i + 1
            ))
        })?;

        let asked = sha(req.prompt.flatten().as_bytes());
        if asked != turn.prompt_sha256 {
            return Err(LlmError::Malformed(format!(
                "turn {} asks a different question than the one recorded ({} against {}). \
                 Answering it from the recording would make a changed prompt look derived.",
                i + 1,
                &asked[..12],
                &turn.prompt_sha256[..12],
            )));
        }
        Ok(Response {
            text: turn.answer.clone(),
            reasoning: turn.reasoning.clone(),
            usage: turn.usage,
            model: turn.model.clone(),
            stop_reason: turn.stop_reason.clone(),
        })
    }
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Prompt, Replay};

    fn request(system: &str, body: &str) -> Request {
        Request {
            prompt: Prompt::new(system).stable("prelude").volatile(body),
            model: "claude-haiku-4-5-20251001".into(),
            max_output_tokens: 100,
            temperature: 0.0,
            schema: None,
            reasoning: Reasoning::Default,
        }
    }

    #[test]
    fn a_recorder_captures_what_was_asked_without_being_a_second_code_path() {
        // Wrapping rather than replacing is what stops recording from drifting from the path that
        // runs in production.
        let r = Recorder::new(Replay::once("an answer"));
        let resp = r.complete(&request("sys", "body")).unwrap();
        assert_eq!(resp.text, "an answer");

        let t = r.transcript("pkg:npm/a@1");
        assert_eq!(t.turns.len(), 1);
        assert_eq!(t.turns[0].answer, "an answer");
        assert_eq!(t.turns[0].prompt_sha256.len(), 64);
        // Recorded separately, because the system message is the one part that must never come from
        // a package and a change to it changes the operator's instructions.
        assert_ne!(t.turns[0].system_sha256, t.turns[0].prompt_sha256);
    }

    #[test]
    fn a_replay_refuses_a_prompt_that_changed() {
        // The most misleading thing this module could do is answer a changed question from an old
        // recording: the run succeeds, the strategy looks derived, and the derivation on record is
        // of something else.
        let r = Recorder::new(Replay::once("an answer"));
        r.complete(&request("sys", "body")).unwrap();
        let t = r.transcript("pkg:npm/a@1");

        let replaying = Replaying::new(t);
        assert_eq!(
            replaying.complete(&request("sys", "body")).unwrap().text,
            "an answer"
        );

        // An empty transcript answers nothing rather than inventing a turn.
        let empty = Replaying::new(Transcript::new("t"));
        let e = empty.complete(&request("sys", "body")).unwrap_err();
        assert!(matches!(e, LlmError::Malformed(_)), "{e}");
    }

    #[test]
    fn a_changed_prompt_is_named_as_such_rather_than_answered() {
        let r = Recorder::new(Replay::once("an answer"));
        r.complete(&request("sys", "original")).unwrap();
        let replaying = Replaying::new(r.transcript("t"));

        let e = replaying.complete(&request("sys", "edited")).unwrap_err();
        let text = e.to_string();
        assert!(text.contains("different question"), "{text}");
        assert!(text.contains("look derived"), "{text}");
    }

    #[test]
    fn a_replay_that_runs_out_of_turns_says_so() {
        // The recording and the code have diverged, which is what replay exists to detect.
        let r = Recorder::new(Replay::once("one"));
        r.complete(&request("sys", "a")).unwrap();
        let replaying = Replaying::new(r.transcript("t"));
        replaying.complete(&request("sys", "a")).unwrap();
        let e = replaying.complete(&request("sys", "a")).unwrap_err();
        assert!(e.to_string().contains("asked for 2"), "{e}");
    }

    #[test]
    fn an_alias_is_not_replayable_and_a_snapshot_is() {
        // An alias that resolves to a new snapshot breaks replay and says nothing when it does, so
        // the transcript says up front whether it can be replayed as evidence.
        assert!(is_snapshot("claude-haiku-4-5-20251001"));
        assert!(is_snapshot("some-model:20240101"));
        // A version that is the whole id, with no date to append — Anthropic's current naming.
        assert!(is_snapshot("claude-opus-5"));
        // A local tag moves; the same tag with the digest it resolved to does not.
        assert!(!is_snapshot("qwen2.5:0.5b"));
        assert!(is_snapshot("qwen2.5:0.5b@a8b0c5157701"));
        assert!(!is_snapshot("gpt-latest"));
        assert!(!is_snapshot("sonnet-preview"));

        let mut t = Transcript::new("pkg:npm/a@1");
        t.turns.push(Turn {
            model: "gpt-latest".into(),
            temperature: 0.0,
            prompt_sha256: sha(b"x"),
            system_sha256: sha(b"s"),
            schema_sha256: None,
            answer: "a".into(),
            reasoning: None,
            reasoning_asked: Reasoning::Default,
            usage: Usage::default(),
            stop_reason: "end_turn".into(),
        });
        assert!(!t.replayable());
        t.turns[0].model = "claude-haiku-4-5-20251001".into();
        assert!(t.replayable());
    }

    #[test]
    fn a_transcript_records_what_answered_rather_than_what_was_asked_for() {
        // Asking for an alias and being answered by a snapshot is precisely the case worth having
        // on record, so the provider's reported model wins.
        let r = Recorder::new(Replay::new(vec![Response {
            text: "a".into(),
            reasoning: None,
            usage: Usage::default(),
            model: "claude-haiku-4-5-20251001".into(),
            stop_reason: "end_turn".into(),
        }]));
        let mut req = request("sys", "body");
        req.model = "claude-latest".into();
        r.complete(&req).unwrap();
        assert_eq!(
            r.transcript("t").turns[0].model,
            "claude-haiku-4-5-20251001"
        );
        assert!(r.transcript("t").replayable());
    }

    #[test]
    fn a_transcript_round_trips_and_sums_its_own_cost() {
        let r = Recorder::new(Replay::new(vec![
            Response {
                text: "one".into(),
                reasoning: None,
                usage: Usage {
                    input: 100,
                    cached_input: 80,
                    output: 10,
                },
                model: "m-20240101".into(),
                stop_reason: "end_turn".into(),
            },
            Response {
                text: "two".into(),
                reasoning: None,
                usage: Usage {
                    input: 200,
                    cached_input: 150,
                    output: 20,
                },
                model: "m-20240101".into(),
                stop_reason: "end_turn".into(),
            },
        ]));
        r.complete(&request("sys", "a")).unwrap();
        r.complete(&request("sys", "b")).unwrap();

        let t = r.transcript("pkg:npm/a@1");
        assert_eq!(t.tokens().input, 300);
        assert_eq!(t.tokens().cached_input, 230);
        assert_eq!(t.tokens().output, 30);

        let back: Transcript = serde_json::from_str(&serde_json::to_string(&t).unwrap()).unwrap();
        assert_eq!(back, t);
    }
}
