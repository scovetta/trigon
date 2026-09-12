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
}

/// What came back, and what it cost.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub text: String,
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
    #[error("the provider refused: {0}")]
    Refused(String),
    #[error("the provider returned {status}: {body}")]
    Http { status: u16, body: String },
    #[error("could not read the provider's answer: {0}")]
    Malformed(String),
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
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            LlmError::Http { status, .. } => *status == 429 || *status >= 500,
            LlmError::Transport(_) => true,
            _ => false,
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
}

impl Replay {
    pub fn new(answers: Vec<Response>) -> Self {
        Replay {
            answers,
            at: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// A canned answer, for tests that care about the loop rather than the model.
    pub fn once(text: impl Into<String>) -> Self {
        Self::new(vec![Response {
            text: text.into(),
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

    fn complete(&self, _req: &Request) -> Result<Response, LlmError> {
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
}
