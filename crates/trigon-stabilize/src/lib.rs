//! Stabilizers: pure, total transforms that remove one known class of benign nondeterminism.
//!
//! Three rules keep this honest, and they are properties of the types rather than conventions:
//!
//! 1. A stabilizer takes no parameter that could tell it which side of a comparison it is on, so it
//!    cannot be conditioned on the comparison.
//! 2. Every stabilizer carries its own [`RiskTier`] and [`Provenance`], so the attestation predicate
//!    is derived mechanically rather than from a side table someone forgets to update.
//! 3. Stabilizers are **total**. They return no error. A parse failure inside one falls back to the
//!    original bytes and emits a note, which leaves no half-stabilized state to reason about.
//!
//! See `docs/05-archive-and-normalization.md` §3.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod cx;
mod ilcanon;
mod passes;
mod profiles;
mod set;

pub use cx::{Cx, Level};
pub use passes::all_builtin;
pub use profiles::{all_profiles, default_for, profile};
pub use set::{Applied, FieldEdit, SetManifest, SetMember, StabilizerSet, Touched, apply, apply_traced};

use std::fmt::Debug;

use trigon_archive::{Archive, Entry};
use trigon_core::{Provenance, RiskTier, StabilizerId};

/// When a pass runs.
///
/// `Finalize` exists for invariants that depend on every prior pass. Wheel `RECORD` regeneration is
/// the canonical case: earlier passes change archive membership, and `RECORD` is a manifest *of*
/// membership.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Stage {
    Default = 0,
    /// Where custom stabilizers from the definitions repository run.
    Patch = 10,
    Finalize = 100,
}

pub trait Stabilizer: Debug + Send + Sync + 'static {
    fn id(&self) -> StabilizerId;
    fn stage(&self) -> Stage {
        Stage::Default
    }
    fn risk(&self) -> RiskTier;
    fn provenance(&self) -> Provenance {
        Provenance::Builtin
    }
    fn applies(&self, cx: &Cx) -> bool;

    /// Act on the archive as a whole: reorder entries, rewrite the trailer.
    fn on_archive(&self, _a: &mut Archive, _cx: &Cx) -> Touched {
        Touched::NONE
    }

    /// Act on one member. Both hooks carry defaults, so one stabilizer can do both. The Go prior art
    /// dispatches on function kind and so structurally cannot.
    fn on_entry(&self, _e: &mut Entry, _cx: &Cx) -> Touched {
        Touched::NONE
    }
}
