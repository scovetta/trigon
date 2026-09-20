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

mod yarn;
mod compat;
mod context;
mod digest;
mod error;
mod instructions;
mod model;
mod parse;
mod render;
mod tool;

pub use yarn::{scripts_from_checkout, without_yarn};
pub use compat::{CustomStabilizer, Imported, import};
pub use context::{Context, EnvCtx, IntrinsicsCtx, LocationCtx, TargetCtx};
pub use digest::{canonical, strategy_digest};
pub use error::StrategyError;
pub use instructions::{Instructions, Requirements, Script, SourceProvenance};
pub use model::{
    CURRENT_SCHEMA, FlowStrategy, Location, LocationHint, ManualStrategy, PrebuiltStrategy, Step,
    StepBody, StepRaw, Strategy,
};
pub use parse::{from_yaml, from_yaml_longest_prefix, to_yaml};
pub use render::render;
pub use tool::{Tool, ToolParam, ToolRegistry, VENV};
