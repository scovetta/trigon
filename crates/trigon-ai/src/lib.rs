//! The search half.
//!
//! Everything here is nondeterministic, budgeted, cached and replayable, and none of it may reach a
//! verdict. A model proposes a *candidate strategy*; the judgement half decides whether what came
//! out matches, and nothing in this crate can influence that decision. See `docs/07-ai.md`.
//!
//! The crate begins with the parts that are deterministic — what to spend, when to stop — because
//! they decide whether the subsystem costs thousands of dollars or hundreds of thousands for the
//! same work, and because they are testable before a single provider exists.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod builder;
mod opinion;
mod copilot;
mod eval;
mod http;
mod provider;
mod repair;
mod transcript;

pub use builder::{Candidate, Task, candidate_schema, parse_candidate, prompt, propose};
pub use copilot::Copilot;
pub use eval::{Capability, Change, Flips, Labelled, Observation, Rate, Scorecard, flips, score};
pub use http::{Anthropic, Flavor, OpenAiCompatible};
pub use opinion::on_diff as opinion_on_diff;
pub use provider::{
    LlmError, ModelCaps, Part, Prompt, Provider, Reasoning, Replay, Request, Response, Usage,
};
pub use repair::{Attempt, Budget, Decision, NoPrior, Prior, RepairLoop, StopReason, Trigger};
pub use transcript::{Recorder, Replaying, Transcript, Turn, is_snapshot};
