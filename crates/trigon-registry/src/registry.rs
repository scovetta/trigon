use async_trait::async_trait;
use trigon_core::{Ecosystem, TargetRef};

use crate::client::Client;
use crate::error::RegistryError;
use crate::model::{ArtifactMeta, BlobSink, Fetched, ResolvedTarget};

#[async_trait]
pub trait Registry: Send + Sync + 'static {
    fn ecosystem(&self) -> Ecosystem;

    /// Everything the registry knows about one version.
    async fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, RegistryError>;

    /// Fetch one artifact's bytes, verifying them against every digest the registry declared.
    ///
    /// Returns the digests the bytes actually hashed to, which are what the run key and the
    /// attestation record, beside what was declared and what came of checking it. Those are the
    /// digests we computed rather than the ones we were told, so a registry that later serves
    /// different bytes under the same name is visible rather than invisible. A declared digest the
    /// bytes do not match refuses the fetch, naming the algorithm and both values.
    async fn fetch(
        &self,
        meta: &ArtifactMeta,
        sink: &mut (dyn BlobSink + Send),
    ) -> Result<Fetched, RegistryError>;
}

/// The registry for an ecosystem, or a refusal naming it.
pub fn for_ecosystem(
    ecosystem: Ecosystem,
    client: Client,
) -> Result<Box<dyn Registry>, RegistryError> {
    match ecosystem {
        Ecosystem::Npm => Ok(Box::new(crate::npm::NpmRegistry::new(client))),
        Ecosystem::PyPI => Ok(Box::new(crate::pypi::PyPiRegistry::new(client))),
        Ecosystem::CratesIo => Ok(Box::new(crate::cargo::CratesIoRegistry::new(client))),
        Ecosystem::NuGet => Ok(Box::new(crate::nuget::NuGetRegistry::new(client))),
        // Named rather than silently unsupported. These have profiles and, for some, tools, but no
        // client — and pretending otherwise would fail somewhere less obvious.
        other => Err(RegistryError::Unsupported {
            ecosystem: other.to_string(),
            supported: "npm, pypi, cargo, nuget".into(),
        }),
    }
}
