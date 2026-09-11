//! What a registry tells us about a package.

use serde::{Deserialize, Serialize};
use trigon_core::{ArtifactId, Digest, Intrinsics, SourceProvenance, TargetRef};

/// One downloadable file of one version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMeta {
    pub id: ArtifactId,
    pub url: String,
    /// What the registry says the bytes hash to.
    ///
    /// `Option` because not every registry publishes one: npm has served sha1 for most of its
    /// history and only newer entries carry a sha512 integrity string. Where it is absent we say
    /// so rather than inventing a check that always passes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_sha256: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// A package coordinate, resolved against the registry that holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedTarget {
    pub reference: TargetRef,
    /// Every artifact this version publishes. A version is not one file: a PyPI release commonly
    /// has an sdist and a dozen wheels, and they do not reproduce alike.
    pub artifacts: Vec<ArtifactMeta>,
    pub intrinsics: Intrinsics,
    /// Where the source is, when the registry knew. This is the resolver's cheapest rung and it
    /// costs one request we were making anyway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceProvenance>,
}

impl ResolvedTarget {
    /// The artifact with this exact filename.
    pub fn artifact(&self, id: &str) -> Option<&ArtifactMeta> {
        self.artifacts.iter().find(|a| a.id.as_str() == id)
    }

    /// The artifact a run should be about when the caller named no file.
    ///
    /// Only when there is exactly one candidate. A PyPI release with an sdist and eleven platform
    /// wheels has no single obvious answer, and picking one would attach a verdict to whichever
    /// the registry happened to list first.
    pub fn sole_artifact(&self) -> Option<&ArtifactMeta> {
        match self.artifacts.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }

    /// The artifact the caller named, or the only one, or an error listing what exists.
    ///
    /// The listing is the point. "no such artifact" against a release with twelve wheels sends
    /// someone to a browser; the same error with the twelve filenames in it does not.
    pub fn pick(&self, wanted: Option<&str>) -> Result<&ArtifactMeta, crate::RegistryError> {
        let found = match wanted {
            Some(id) => self.artifact(id),
            None => self.sole_artifact(),
        };
        found.ok_or_else(|| crate::RegistryError::NoSuchArtifact {
            name: self.reference.registry_name(),
            version: self.reference.version.clone(),
            wanted: wanted.unwrap_or("(unspecified)").to_string(),
            available: self.artifacts.iter().map(|a| a.id.to_string()).collect(),
        })
    }
}

/// Where fetched bytes go.
///
/// A trait rather than a `Vec<u8>` return, because an artifact can be gigabytes and the judgement
/// half is built to stream: a fleet worker that buffers a 2 GB wheel to hash it has a memory
/// profile that looks like a build failure.
pub trait BlobSink {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<()>;
}

impl BlobSink for Vec<u8> {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        self.extend_from_slice(chunk);
        Ok(())
    }
}

impl BlobSink for std::fs::File {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        std::io::Write::write_all(self, chunk)
    }
}
