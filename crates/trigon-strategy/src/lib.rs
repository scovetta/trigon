//! Strategies: what to do to reproduce an artifact, as reviewable data.
//!
//! The load-bearing idea, taken from the prior art and kept: a strategy is *data*, rendering is
//! pure, and executors are dumb consumers. The argument for it is that project's `definitions/`
//! directory, where one file carries a six-line comment explaining that a published wheel was built
//! from a working tree still containing a file deleted two commits earlier. That directory is the
//! institutional memory of the project, and it exists only because strategies have a reviewable
//! text form.
//!
//! This crate is pure: no network, no clock, no filesystem beyond what a caller hands it.

mod error;
mod model;
mod parse;

pub use error::StrategyError;
pub use model::{
    CURRENT_SCHEMA, FlowStrategy, Location, LocationHint, ManualStrategy, PrebuiltStrategy, Step,
    StepBody, StepRaw, Strategy,
};
pub use parse::{from_yaml, to_yaml};
