//! The seam every model call goes through.
//!
//! Hand-written over `reqwest` rather than a framework, per `docs/17`. The Rust LLM-framework
//! ecosystem moves faster than it stabilizes, and what we need from a provider is small: one
//! request shape, one response shape, and a description of what the model can do so the caller can
//! decline gracefully rather than discover it at runtime.
//!
//! Two decisions here are load-bearing rather than stylistic.
//!
//! **The prompt is a list of parts, not a string.** Provider prompt caching is charged per token
//! and keyed on an exact prefix, so the difference between a 70% cache-read rate and a 0% one is
//! whether the stable material is byte-identical across calls and whether the volatile material
//! comes strictly after it. A `String` makes that a convention nobody can enforce; a list with an
//! explicit `cache_breakpoint` makes it checkable, and [`Prompt::is_cacheable`] checks it.
//!
//! **Structured output is a capability, not an assumption.** Providers disagree about it and local
//! models are unreliable at all of them (`docs/07-ai.md` §7). [`ModelCaps::structured_output`] gates
//! a text-first fallback, and the one place we ask for a schema is the final `Strategy`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How much a model should spend thinking before it answers.
///
/// A thinking model emits a reasoning trace and then an answer, and the trace is charged as output.
/// It is worth being able to decline: on a local 27B model, asking for `{"ok":true}` costs 52 output
/// tokens with reasoning and 6 without, and the wall clock on a CPU-only host moves with it.
///
/// The trace itself is not thrown away when it does arrive — see [`Response::reasoning`]. Paying for
/// derivation and then dropping it is the failure `docs/07-ai.md` §8 is about, so the choice here is
/// between not buying it and keeping it, never between buying it and losing it.
///
/// This is a request the provider may ignore. `Off` is honoured by Ollama through
/// `reasoning_effort` and ignored by endpoints that do not know the field, which is a difference in
/// speed rather than in what comes back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reasoning {
    /// Whatever the model does when nothing is said.
    #[default]
    Default,
    /// Answer without a reasoning trace.
    Off,
}

/// How deep to think, where the provider has a dial for it.
///
/// **This exists because lowering it is the only lever that works, and it was not reachable.**
/// Adaptive thinking spends what it is given, so raising `max_output_tokens` raises the reasoning
/// with it; the depth is a separate setting. It was a constant in the Anthropic client, which meant
/// the one thing that fixes a truncated answer could not be asked for — not by a caller, and not by
/// a retry.
///
/// `None` on a [`Request`] means the provider's own default, which is what every call made before
/// this existed asked for. Skipped when serializing for the same reason `Reasoning::Default` is: a
/// transcript recorded before this field must still compare equal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    Low,
    #[default]
    Medium,
    High,
}

impl Effort {
    /// The next notch down, or `None` at the bottom.
    ///
    /// What a retry walks after a truncated answer. Below `Low` the only remaining move is to turn
    /// reasoning off entirely, which is [`Reasoning::Off`] and not a depth.
    pub fn lower(self) -> Option<Effort> {
        match self {
            Effort::High => Some(Effort::Medium),
            Effort::Medium => Some(Effort::Low),
            Effort::Low => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
        }
    }
}

impl Reasoning {
    /// For `skip_serializing_if`, so a transcript from a run that said nothing does not grow a
    /// field and stop comparing equal to the one recorded before this existed.
    pub fn is_default(&self) -> bool {
        matches!(self, Reasoning::Default)
    }
}

/// What a model can do, asked before it is asked to do it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCaps {
    /// Whether the provider will honour a JSON schema. When false the caller asks for free-form
    /// YAML and repairs it through `serde_path_to_error` instead.
    pub structured_output: bool,
    pub tools: bool,
    /// Whether a cache breakpoint means anything to this provider. When false the breakpoint is
    /// still recorded — it costs nothing and keeps transcripts comparable across providers.
    pub prompt_cache: bool,
    pub context_tokens: u32,
}

/// One piece of a prompt, and whether it is expected to be identical next time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    pub text: String,
    /// `true` for the ecosystem prelude and the tool schemas, `false` for this target's context.
    ///
    /// Not a hint. Everything stable has to precede everything volatile for a prefix cache to hit,
    /// and this is the field that says which is which.
    pub stable: bool,
}

/// A prompt, ordered so that a prefix cache can work.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    /// Operator instructions. A separate field because they must never be spliced into text that
    /// came from a package: `docs/12-security.md` §4 turns on that separation surviving all the way
    /// to the wire.
    pub system: String,
    pub parts: Vec<Part>,
}

impl Prompt {
    pub fn new(system: impl Into<String>) -> Self {
        Prompt {
            system: system.into(),
            parts: Vec::new(),
        }
    }

    pub fn stable(mut self, text: impl Into<String>) -> Self {
        self.parts.push(Part {
            text: text.into(),
            stable: true,
        });
        self
    }

    pub fn volatile(mut self, text: impl Into<String>) -> Self {
        self.parts.push(Part {
            text: text.into(),
            stable: false,
        });
        self
    }

    /// Where the cached prefix ends, as an index into `parts`.
    pub fn cache_breakpoint(&self) -> usize {
        self.parts.iter().take_while(|p| p.stable).count()
    }

    /// Whether this prompt can actually hit a prefix cache.
    ///
    /// False as soon as one stable part follows a volatile one, because everything after the first
    /// volatile byte is uncacheable however stable it claims to be. Worth asserting rather than
    /// hoping: cache-read rate is a first-class SLO (`docs/07-ai.md` §4.2), and the failure is
    /// invisible — the calls succeed and the bill is four times larger.
    pub fn is_cacheable(&self) -> bool {
        !self.parts[self.cache_breakpoint()..]
            .iter()
            .any(|p| p.stable)
    }

    /// The whole prompt as one string, for providers with no part structure.
    pub fn flatten(&self) -> String {
        self.parts
            .iter()
            .map(|p| p.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

/// What a model was asked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub prompt: Prompt,
    /// The exact snapshot, never an alias. An alias that resolves to a new snapshot breaks replay
    /// and says nothing when it does (`docs/07-ai.md` §8).
    pub model: String,
    pub max_output_tokens: u32,
    /// Zero unless something needs otherwise. Replay cannot reproduce sampling, and the point of
    /// this subsystem is search rather than prose.
    pub temperature: f32,
    /// A JSON schema the answer must satisfy. Ignored, with a fallback, when the provider cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
    /// Recorded for the same reason `temperature` is: it changes the answer, so two calls that
    /// differ only here are not the same question and a replay must be able to say so.
    #[serde(default, skip_serializing_if = "Reasoning::is_default")]
    pub reasoning: Reasoning,
    /// How deep to think. `None` is the provider's default. See [`Effort`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<Effort>,
}

/// What came back, and what it cost.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub text: String,
    /// The reasoning trace, where the provider returned one separately from the answer.
    ///
    /// Kept rather than dropped because it was paid for as output and it is the derivation — the
    /// part of a transcript that says *why* this recipe and not another. Absent when the model did
    /// not think, when [`Reasoning::Off`] was asked for, or when the provider folds its reasoning
    /// into the answer instead of alongside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    pub usage: Usage,
    /// The snapshot the provider says answered, which is not always the one asked for.
    pub model: String,
    pub stop_reason: String,
}

/// Token accounting, in the prior art's shape so published cost figures stay comparable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input: u64,
    /// **A subset of `input`, not an addition.** Adding them double-counts every cached token and
    /// makes a well-cached run look more expensive than a cold one.
    pub cached_input: u64,
    pub output: u64,
}

impl Usage {
    pub fn cache_read_rate(&self) -> Option<f64> {
        (self.input > 0).then(|| self.cached_input as f64 / self.input as f64)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("no model is configured for the `{0}` role")]
    NoModel(String),
    /// The answer did not fit. Distinct from `Malformed`, which says the provider is broken: this
    /// says the budget was too small, which is ours to fix and says exactly how.
    #[error(
        "the answer did not fit in {limit} output tokens ({thinking} of them spent on reasoning), \
         at every depth down to reasoning off. Adaptive thinking scales to the room it is given, so \
         raising `max_output_tokens` raises the reasoning with it rather than reaching the answer — \
         which is why `propose` walks the effort down instead. Reaching here means even a \
         no-reasoning call could not write the answer in {limit} tokens, so the prompt is asking \
         for something too large rather than the model thinking too hard."
    )]
    Truncated { limit: u32, thinking: u64 },
    #[error("the provider refused: {0}")]
    Refused(String),
    #[error("the provider returned {status}: {body}")]
    Http { status: u16, body: String },
    #[error("could not read the provider's answer: {0}")]
    Malformed(String),
    /// The provider ended the turn without producing an answer at all.
    ///
    /// Distinct from `Malformed`, which says an answer arrived and could not be read, and from
    /// `Truncated`, which says the answer hit a budget *we* set. This is the provider stopping
    /// mid-turn with nothing to show and no error: the Copilot CLI does it on a hard prompt, ending
    /// the stream inside the model's reasoning with no `assistant.message` and no `error` event.
    /// Nothing was returned, so there is nothing to parse and nothing that says why.
    #[error("the provider ended the turn without an answer: {0}")]
    EmptyTurn(String),
    /// The prompt is larger than the channel that hands it to the provider, so nothing was sent.
    ///
    /// The Copilot CLI takes its prompt as one command-line argument, and the kernel bounds one.
    /// Distinct from `Transport`, which is asked again: the same prompt is the same size next time.
    /// `limit` says which bound it met, and how large that is where it is known.
    #[error("the prompt is {bytes} bytes and {limit}, so nothing was sent")]
    PromptTooLarge { bytes: usize, limit: String },
    #[error("transport: {0}")]
    Transport(String),
}

impl trigon_core::Classify for LlmError {
    fn fault(&self) -> trigon_core::Fault {
        match self {
            // A missing model is a misconfiguration of ours, and a refusal is a policy outcome.
            LlmError::NoModel(_) => trigon_core::Fault::Bug,
            LlmError::Refused(_) => trigon_core::Fault::Policy,
            LlmError::Http { .. } | LlmError::Transport(_) => trigon_core::Fault::Infra,
            LlmError::Malformed(_) => trigon_core::Fault::Upstream,
            // The provider's, like a 5xx: it accepted the request and returned nothing.
            LlmError::EmptyTurn(_) => trigon_core::Fault::Infra,
            // **Ours, not the provider's.** The model answered exactly as asked; the budget we
            // gave it was too small for the answer we wanted. Charging this upstream would put a
            // configuration mistake of ours in a column about somebody else's reliability.
            LlmError::Truncated { .. } => trigon_core::Fault::Bug,
            // Ours as well: the prompt is ours, and so is the choice of a channel too narrow for
            // it. Nothing reached the provider, so it has no part in this.
            LlmError::PromptTooLarge { .. } => trigon_core::Fault::Bug,
        }
    }

    /// Every variant named, never a catch-all.
    ///
    /// This ended in `_ => false`, so three of five variants took their answer from a wildcard
    /// nobody chose and a new variant would silently join them. This one gates the repair loop's
    /// live retries, so the cost runs both ways: a transient fault marked final throws away a run
    /// that would have succeeded, and a refusal marked retryable spends the budget re-asking a
    /// question already answered.
    fn is_retryable(&self) -> bool {
        match self {
            // Rate limited, or the provider's own fault. The only two worth asking again.
            LlmError::Http { status, .. } => *status == 429 || *status >= 500,
            LlmError::Transport(_) => true,
            // A misconfiguration. The next call is addressed to the same absent model.
            LlmError::NoModel(_) => false,
            // The provider decided. Asking again is asking the same question.
            LlmError::Refused(_) => false,
            // An answer we could not read. Retrying is defensible — sampling could produce a
            // parseable one next time — but the repair loop already owns that decision and has a
            // budget for it, and treating it as transport-level would retry inside the retry.
            LlmError::Malformed(_) => false,
            // **Retryable, and this is the one that earns it.** A turn that produced nothing is not
            // a different answer to the same question — it is no answer, and the next attempt is
            // the first one that gets to be an answer. Observed three times in four real repairs
            // against the Copilot CLI, with the same prompt succeeding on a manual replay, so the
            // failure is in the turn and not in what was asked.
            LlmError::EmptyTurn(_) => true,
            // The same budget produces the same truncation. Retrying spends tokens to reach the
            // identical wall, which is the shape `docs/07-ai.md` §5's "if the failure signature
            // repeats twice, abort" exists to stop.
            LlmError::Truncated { .. } => false,
            // The same prompt is the same size on the next attempt, and meets the same bound.
            LlmError::PromptTooLarge { .. } => false,
        }
    }
}

/// A model, behind one call.
///
/// Synchronous, which departs from `docs/07-ai.md` §7 for the same reason [`crate::Signer`]'s
/// sibling in `trigon-attest` does: an async trait obliges every caller to hold a runtime, and the
/// implementations that matter here either block in their own client or are a recorded transcript
/// with no I/O at all. The engine that drives a sweep already has a runtime and can spawn this on a
/// blocking thread; a replay harness and a test should not have to.
pub trait Provider: Send + Sync {
    fn id(&self) -> &str;
    fn caps(&self) -> ModelCaps;
    fn complete(&self, req: &Request) -> Result<Response, LlmError>;

    /// What this provider was configured to ask for. Not a capability — a choice the operator made
    /// when they named the endpoint, which the caller copies into the request so it is recorded.
    fn reasoning(&self) -> Reasoning {
        Reasoning::Default
    }

    /// How deep this provider is asked to think by default.
    ///
    /// A method rather than a constant so a retry can ask for less — which is the only thing that
    /// fixes a truncated answer, and was reachable from nowhere when it lived in the client.
    fn default_effort(&self) -> Effort {
        Effort::default()
    }
}

/// Delegating impls, so a provider can be wrapped and still be one.
///
/// Without these a `Recorder` cannot sit inside a `Counting` — `Recorder<P>` needs `P: Provider`
/// and the thing being wrapped is a `Box<dyn Provider>`, which was not one. That is the whole
/// reason production never recorded a transcript: the wrapper existed, the store had a field for
/// its digest, and there was no way to compose the two.
///
/// **Every method, including the ones with a default.** A defaulted method left out of a wrapper
/// still compiles, and answers with the trait's value in place of the wrapped provider's.
/// `default_effort` was missing here, so a provider that set its own depth would have been asked
/// for `medium` through a `Box` — latent only because none sets one yet.
impl<P: Provider + ?Sized> Provider for Box<P> {
    fn id(&self) -> &str {
        (**self).id()
    }
    fn caps(&self) -> ModelCaps {
        (**self).caps()
    }
    fn complete(&self, req: &Request) -> Result<Response, LlmError> {
        (**self).complete(req)
    }
    fn reasoning(&self) -> Reasoning {
        (**self).reasoning()
    }
    fn default_effort(&self) -> Effort {
        (**self).default_effort()
    }
}

impl<P: Provider + ?Sized> Provider for std::sync::Arc<P> {
    fn id(&self) -> &str {
        (**self).id()
    }
    fn caps(&self) -> ModelCaps {
        (**self).caps()
    }
    fn complete(&self, req: &Request) -> Result<Response, LlmError> {
        (**self).complete(req)
    }
    fn reasoning(&self) -> Reasoning {
        (**self).reasoning()
    }
    fn default_effort(&self) -> Effort {
        (**self).default_effort()
    }
}

impl fmt::Debug for dyn Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Provider({})", self.id())
    }
}

/// A provider that answers from a recording and never opens a socket.
///
/// The replay half of `docs/07-ai.md` §8, and the reason the trait is synchronous. It proves
/// *provenance of the derivation* — that this transcript produced that strategy — and not
/// reproducibility of the result: it replays the model, not the world. Saying so in those words
/// matters, because the stronger claim is tempting and false.
#[derive(Debug, Default)]
pub struct Replay {
    answers: Vec<Response>,
    at: std::sync::atomic::AtomicUsize,
    /// Every request this provider was handed, in order. What a test reads to assert what
    /// actually reached the wire — the properties worth asserting here (control-stripping, part
    /// ordering, the model named) are invisible in the answer.
    asked: std::sync::Mutex<Vec<Request>>,
}

impl Replay {
    pub fn new(answers: Vec<Response>) -> Self {
        Replay {
            answers,
            at: std::sync::atomic::AtomicUsize::new(0),
            asked: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// What this provider has been asked so far, cloned.
    pub fn asked(&self) -> Vec<Request> {
        self.asked.lock().expect("no panics hold this").clone()
    }

    /// A canned answer, for tests that care about the loop rather than the model.
    pub fn once(text: impl Into<String>) -> Self {
        Self::new(vec![Response {
            text: text.into(),
            reasoning: None,
            usage: Usage::default(),
            model: "replay".into(),
            stop_reason: "end_turn".into(),
        }])
    }
}

impl Provider for Replay {
    fn id(&self) -> &str {
        "replay"
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
        self.asked
            .lock()
            .expect("no panics hold this")
            .push(req.clone());
        let i = self.at.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.answers.get(i).cloned().ok_or_else(|| {
            // Running off the end means the recording and the code have diverged, which is the one
            // thing a replay exists to detect. Silently repeating the last answer would hide it.
            LlmError::Malformed(format!(
                "the recording holds {} answers and the run asked for {}",
                self.answers.len(),
                i + 1
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prompt_is_cacheable_only_while_the_stable_parts_come_first() {
        // The failure this catches is invisible: the calls succeed and the bill is several times
        // larger, because everything after the first volatile byte is uncacheable however stable it
        // claims to be.
        let good = Prompt::new("sys")
            .stable("ecosystem prelude")
            .stable("tool schemas")
            .volatile("this target");
        assert!(good.is_cacheable());
        assert_eq!(good.cache_breakpoint(), 2);

        let bad = Prompt::new("sys")
            .stable("ecosystem prelude")
            .volatile("this target")
            .stable("tool schemas");
        assert!(!bad.is_cacheable());
        assert_eq!(bad.cache_breakpoint(), 1);
    }

    #[test]
    fn cached_input_is_a_subset_of_input() {
        // Adding them double-counts every cached token and makes a well-cached run look more
        // expensive than a cold one — the opposite of the signal the SLO exists to give.
        let u = Usage {
            input: 1000,
            cached_input: 800,
            output: 50,
        };
        assert_eq!(u.cache_read_rate(), Some(0.8));
        assert!(u.cached_input <= u.input);
        assert_eq!(Usage::default().cache_read_rate(), None);
    }

    #[test]
    fn a_replay_that_runs_out_of_answers_says_so() {
        // The recording and the code have diverged, which is exactly what a replay is for.
        // Repeating the last answer would turn that into a silent pass.
        let p = Replay::once("first");
        let req = Request {
            prompt: Prompt::new("s"),
            model: "replay".into(),
            max_output_tokens: 10,
            temperature: 0.0,
            schema: None,
            reasoning: Reasoning::Default,
            effort: None,
        };
        assert_eq!(p.complete(&req).unwrap().text, "first");
        let e = p.complete(&req).unwrap_err();
        assert!(matches!(e, LlmError::Malformed(_)), "{e}");
        assert!(e.to_string().contains("asked for 2"), "{e}");
    }

    #[test]
    fn transient_provider_failures_are_told_apart_from_permanent_ones() {
        use trigon_core::Classify as _;
        assert!(
            LlmError::Http {
                status: 429,
                body: String::new()
            }
            .is_retryable()
        );
        assert!(
            LlmError::Http {
                status: 503,
                body: String::new()
            }
            .is_retryable()
        );
        assert!(
            !LlmError::Http {
                status: 400,
                body: String::new()
            }
            .is_retryable()
        );
        // A refusal is a policy outcome, not an infrastructure one: retrying it burns budget to
        // reach the same answer.
        assert_eq!(
            LlmError::Refused("no".into()).fault(),
            trigon_core::Fault::Policy
        );
        assert!(!LlmError::Refused("no".into()).is_retryable());
    }

    #[test]
    fn every_failure_is_charged_to_whoever_owns_it_and_retried_only_where_it_could_differ() {
        // Every variant, because this gates the repair loop's live retries both ways: a transient
        // fault marked final throws away a run that would have succeeded, and a final one marked
        // retryable spends the budget re-asking a question already answered. And the fault column
        // is what says whose reliability a failure counts against.
        use trigon_core::{Classify as _, Fault};
        let http = |status| LlmError::Http {
            status,
            body: String::new(),
        };
        let cases = [
            // A misconfiguration of ours; the next call goes to the same absent model.
            (LlmError::NoModel("builder".into()), Fault::Bug, false),
            // The budget we set was too small, and the same budget truncates the same way.
            (
                LlmError::Truncated {
                    limit: 16_384,
                    thinking: 16_382,
                },
                Fault::Bug,
                false,
            ),
            (LlmError::Refused("no".into()), Fault::Policy, false),
            (http(429), Fault::Infra, true),
            (http(500), Fault::Infra, true),
            (http(529), Fault::Infra, true),
            (http(400), Fault::Infra, false),
            (http(404), Fault::Infra, false),
            (LlmError::Transport("reset".into()), Fault::Infra, true),
            // The repair loop owns re-asking for a readable answer, with its own budget.
            (LlmError::Malformed("?".into()), Fault::Upstream, false),
            // No answer is not a different answer: the next attempt is the first one.
            (LlmError::EmptyTurn("nothing".into()), Fault::Infra, true),
            // Our prompt, too large for our channel, and the same size on the next attempt.
            (
                LlmError::PromptTooLarge {
                    bytes: 200_000,
                    limit: "one argument".into(),
                },
                Fault::Bug,
                false,
            ),
        ];
        for (e, fault, retryable) in cases {
            assert_eq!(e.fault(), fault, "{e:?}");
            assert_eq!(e.is_retryable(), retryable, "{e:?}");
        }
    }

    #[test]
    fn the_depth_walks_down_one_notch_at_a_time_and_stops_at_the_bottom() {
        // What a retry walks after a truncated answer. Below `Low` the only move left is
        // `Reasoning::Off`, which is not a depth, so the walk says there is none.
        assert_eq!(Effort::High.lower(), Some(Effort::Medium));
        assert_eq!(Effort::Medium.lower(), Some(Effort::Low));
        assert_eq!(Effort::Low.lower(), None);
        assert_eq!(Effort::default(), Effort::Medium);
        // The word sent is the word recorded.
        for e in [Effort::Low, Effort::Medium, Effort::High] {
            assert_eq!(serde_json::to_value(e).unwrap(), e.as_str());
        }
    }

    /// A provider configured away from each default the trait supplies, so a wrapper that answers
    /// with the trait's own in place of the provider's is caught: no reasoning, and when it is
    /// asked to think, deeply.
    struct Quiet;

    impl Provider for Quiet {
        fn id(&self) -> &str {
            "quiet"
        }
        fn caps(&self) -> ModelCaps {
            ModelCaps {
                structured_output: false,
                tools: false,
                prompt_cache: true,
                context_tokens: 4_096,
            }
        }
        fn complete(&self, _: &Request) -> Result<Response, LlmError> {
            Err(LlmError::NoModel("quiet".into()))
        }
        fn reasoning(&self) -> Reasoning {
            Reasoning::Off
        }
        fn default_effort(&self) -> Effort {
            Effort::High
        }
    }

    #[test]
    fn a_boxed_or_shared_provider_is_still_the_provider_it_wraps() {
        // What a wrapper reports has to be what it wraps, or composing them changes the answer.
        let boxed: Box<dyn Provider> = Box::new(Quiet);
        let shared = std::sync::Arc::new(Quiet);
        for p in [&boxed as &dyn Provider, &shared as &dyn Provider] {
            assert_eq!(p.id(), "quiet");
            assert_eq!(p.caps(), Quiet.caps());
            assert_eq!(p.reasoning(), Reasoning::Off);
            // The depth `propose` starts its walk from. Answering the trait's default here would
            // ask every wrapped provider for `medium`, whatever it had said.
            assert_eq!(p.default_effort(), Effort::High);
            assert!(matches!(
                p.complete(&Request {
                    prompt: Prompt::new("s"),
                    model: "m".into(),
                    max_output_tokens: 1,
                    temperature: 0.0,
                    schema: None,
                    reasoning: Reasoning::Default,
                    effort: None,
                }),
                Err(LlmError::NoModel(_))
            ));
        }
        // And a provider in a log line is named by what it is, not dumped.
        assert_eq!(format!("{:?}", &*boxed), "Provider(quiet)");
    }

    #[test]
    fn the_recorded_answer_provider_names_itself_and_claims_no_cache() {
        let p = Replay::once("a");
        assert_eq!(p.id(), "replay");
        // Nothing is sent anywhere, so nothing is cached, and a cache-read rate measured through
        // it would be a fiction.
        assert!(!p.caps().prompt_cache);
        assert!(p.caps().structured_output);
    }
}
