use async_trait::async_trait;
use trigon_core::{Ecosystem, TargetRef};

use crate::client::Client;
use crate::error::RegistryError;
use crate::model::{ArtifactMeta, BlobSink, ResolvedTarget};

#[async_trait]
pub trait Registry: Send + Sync + 'static {
    fn ecosystem(&self) -> Ecosystem;

    /// Everything the registry knows about one version.
    async fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, RegistryError>;

    /// Fetch one artifact's bytes, verifying them against the declared digest.
    ///
    /// Returns the digest the bytes actually hashed to, which is what the run key and the
    /// attestation record. That is the digest we computed rather than the one we were told, so a
    /// registry that later serves different bytes under the same name is visible rather than
    /// invisible.
    async fn fetch(
        &self,
        meta: &ArtifactMeta,
        sink: &mut (dyn BlobSink + Send),
    ) -> Result<trigon_core::Digest, RegistryError>;
}

/// The registry for an ecosystem, or a refusal naming it.
pub fn for_ecosystem(
    ecosystem: Ecosystem,
    client: Client,
) -> Result<Box<dyn Registry>, RegistryError> {
    match ecosystem {
        Ecosystem::Npm => Ok(Box::new(crate::npm::NpmRegistry::new(client))),
        Ecosystem::PyPI => Ok(Box::new(crate::pypi::PyPiRegistry::new(client))),
        // Named rather than silently unsupported. M1 is npm and PyPI to a high standard; the
        // others have tools and profiles but no client yet, and pretending otherwise would fail
        // somewhere less obvious.
        other => Err(RegistryError::Unsupported {
            ecosystem: other.to_string(),
            supported: "npm, pypi".into(),
        }),
    }
}
