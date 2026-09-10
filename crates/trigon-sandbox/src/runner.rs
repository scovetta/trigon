//! The runner seam.
//!
//! `#[async_trait]` rather than AFIT: these are dyn-dispatched, every call does at least a
//! container start's worth of IO, and AFIT is neither dyn-compatible nor `Send`-bounded. One box
//! allocation is noise next to a process spawn.

use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::error::SandboxError;
use crate::model::{BuildEvent, BuildOutcome, BuildPlan, RunOpts, RunnerCaps};

#[async_trait]
pub trait BuildRunner: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn caps(&self) -> RunnerCaps;

    /// Whether this runner can run this plan **as specified**.
    ///
    /// The load-bearing word is "as specified". A runner that accepts a plan it will silently
    /// downgrade produces a build whose recorded egress tier is a fiction.
    fn accepts(&self, p: &BuildPlan) -> bool {
        let c = self.caps();
        c.egress_modes.contains(&p.egress()) && (!p.privileged() || c.privileged)
    }

    async fn start(&self, p: &BuildPlan, o: &RunOpts)
    -> Result<Box<dyn BuildHandle>, SandboxError>;

    /// Whether the underlying runtime is usable right now.
    async fn health(&self) -> Result<(), SandboxError>;
}

#[async_trait]
pub trait BuildHandle: Send + Sync {
    /// Everything the build does, as it happens.
    fn events(&self) -> BoxStream<'static, BuildEvent>;

    /// Wait for the build to finish.
    ///
    /// Consumes the handle, so waiting twice does not compile. The alternative, an `&self` method
    /// returning a second outcome, is a bug that only shows up under a retry.
    async fn wait(self: Box<Self>) -> Result<BuildOutcome, SandboxError>;
}

/// Pick the first runner that accepts the plan.
pub fn route<'a>(
    runners: &'a [Box<dyn BuildRunner>],
    plan: &BuildPlan,
) -> Result<&'a dyn BuildRunner, SandboxError> {
    runners
        .iter()
        .find(|r| r.accepts(plan))
        .map(|r| r.as_ref())
        .ok_or_else(|| {
            SandboxError::Unroutable(format!(
                "plan wants {} egress{}; runners offer: {}",
                plan.egress(),
                if plan.privileged() {
                    " and privileged execution"
                } else {
                    ""
                },
                runners
                    .iter()
                    .map(|r| {
                        format!(
                            "{} [{}]",
                            r.name(),
                            r.caps()
                                .egress_modes
                                .iter()
                                .map(|e| e.to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        })
}
