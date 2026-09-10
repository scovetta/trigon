//! The closed context a template may read, and nothing else.
//!
//! Closed on purpose. A template that can reach a clock, an environment variable or the filesystem
//! makes rendering impure, and rendering has to be a pure function of `(strategy, target, env)` for
//! `strategy_digest` to mean anything. There are also no floats: their formatting varies by
//! platform and locale, and a digest is not the place to discover that.
//!
//! Every map is a `BTreeMap`. `minijinja` preserves insertion order when a template ranges a map,
//! so a `HashMap` here would make the rendered script, and therefore the digest, depend on hash
//! seeding. The dependency policy enforces this at the crate level. See
//! `docs/04-strategies.md` §3.2.

use std::collections::BTreeMap;

use serde::Serialize;

/// Everything a template can see.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Context {
    pub location: LocationCtx,
    pub target: TargetCtx,
    pub env: EnvCtx,
    pub intrinsics: IntrinsicsCtx,
    /// Tool parameters. Populated per step, empty at the top level.
    pub with: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct LocationCtx {
    pub repo: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub subdir: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TargetCtx {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub artifact: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct EnvCtx {
    /// The moment the registry is filtered to, as RFC 3339. A string rather than a time value,
    /// because a template that can do date arithmetic can produce a different answer tomorrow.
    pub registry_moment: Option<String>,
    pub source_date_epoch: Option<i64>,
    pub arch: String,
    pub platform: String,
    /// Whether the working tree is already present, which decides whether `git-checkout` clones.
    pub has_repo: bool,
    /// Base URL of the time-filtering registry mirror, when one is in play.
    pub timewarp_base: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct IntrinsicsCtx {
    pub publish_time: Option<String>,
    /// Toolchain versions the evidence narrowed to, keyed by toolchain name.
    pub toolchains: BTreeMap<String, String>,
    pub backend: Option<String>,
}
