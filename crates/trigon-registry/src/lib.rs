//! Reading the internet about a package.
//!
//! Resolution, artifact bytes, and the first rungs of source discovery, behind one trait. The
//! ecosystems differ in their APIs and agree on almost nothing else, so the shape of this crate is
//! the shape of the extension seam: adding one is a `Registry` implementation and some YAML tools,
//! with no change anywhere else.
//!
//! Two rules hold across every implementation.
//!
//! **Fetched bytes are checked against what the registry declared.** A run against bytes the
//! registry does not vouch for proves nothing about what it published, and a silent mismatch is
//! indistinguishable from a successful reproduction of the wrong thing.
//!
//! **Source discovery starts with what the registry already told us.** npm records the commit it
//! published from; PyPI records a project URL. That is one request we were making anyway, and it
//! is a better answer than any amount of tag matching.

mod client;
mod definitions;
mod error;
mod heuristic;
mod infer;
mod model;
mod npm;
mod pypi;
mod registry;
mod tags;
pub mod wheel;

pub use client::{Client, ClientConfig};
pub use definitions::DefinitionsInferrer;
pub use error::RegistryError;
pub use heuristic::{NpmInferrer, PyPiInferrer};
pub use infer::{Candidate, Derivation, StrategyInferrer, infer};
pub use model::{ArtifactMeta, BlobSink, ResolvedTarget};
pub use npm::NpmRegistry;
pub use pypi::PyPiRegistry;
pub use registry::{Registry, for_ecosystem};
pub use tags::resolve_version_tag;
