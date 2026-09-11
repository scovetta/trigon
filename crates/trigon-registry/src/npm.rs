//! npm.
//!
//! The useful thing npm gives us for free is `gitHead`: the commit the publisher's working tree
//! was at. That is the resolver's top rung and it arrives in the same request as the tarball URL,
//! which makes source discovery for most of npm a lookup rather than a search.
//!
//! It is also not proof. `gitHead` is whatever the publishing client reported, so a rebuild from it
//! that matches is evidence the artifact corresponds to that commit, and a rebuild that does not
//! match is not evidence the publisher lied. The framing matters for npm in particular: tarballs
//! are close to universally reproducible at the byte level and carry no source linkage, so the
//! question worth answering is not "does it rebuild" but "does the published tarball correspond to
//! the claimed source".

use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use trigon_core::{
    ArtifactId, Claim, Confidence, Digest, Ecosystem, Evidence, Intrinsics, RegistryMoment,
    SourceDiscovery, SourceProvenance, TargetRef,
};

use crate::client::Client;
use crate::error::RegistryError;
use crate::model::{ArtifactMeta, BlobSink, ResolvedTarget};
use crate::registry::Registry;

const ECO: &str = "npm";

pub struct NpmRegistry {
    client: Client,
    base: String,
}

impl NpmRegistry {
    pub fn new(client: Client) -> Self {
        NpmRegistry {
            client,
            base: "https://registry.npmjs.org".into(),
        }
    }

    /// Point at a different registry, which is how the time-filtering mirror gets used.
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into().trim_end_matches('/').to_string();
        self
    }
}

#[async_trait]
impl Registry for NpmRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    async fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, RegistryError> {
        let name = target.registry_name();
        // The version document rather than the full packument. A popular package's packument is
        // megabytes of every version ever published, and we want one.
        let url = format!("{}/{}/{}", self.base, encode(&name), target.version);
        let doc: Value = match self.client.get(&url, ECO).await {
            Ok(r) => r.json().await?,
            Err(RegistryError::Http { status: 404, .. }) => {
                return Err(self.not_found(target).await);
            }
            Err(e) => return Err(e),
        };

        let dist = doc.get("dist").ok_or_else(|| RegistryError::Malformed {
            ecosystem: ECO.into(),
            what: format!("{name}@{}", target.version),
            detail: "no `dist` block".into(),
        })?;
        let url = dist
            .get("tarball")
            .and_then(Value::as_str)
            .ok_or_else(|| RegistryError::Malformed {
                ecosystem: ECO.into(),
                what: format!("{name}@{}", target.version),
                detail: "no `dist.tarball`".into(),
            })?
            .to_string();

        let file = url.rsplit('/').next().unwrap_or("artifact.tgz").to_string();
        let artifact = ArtifactMeta {
            id: ArtifactId::new(file),
            url,
            // npm publishes sha1 in `dist.shasum` and, for newer entries, a subresource-integrity
            // string that is usually sha512. Neither is sha256, so there is nothing to compare the
            // computed digest against, and saying so beats a check that always passes.
            declared_sha256: integrity_sha256(dist),
            size: dist.get("unpackedSize").and_then(Value::as_u64),
        };

        let publish_time = self.publish_time(&name, &target.version).await;
        let mut evidence = Vec::new();
        let mut source = None;

        if let Some(repo) = repo_url(&doc) {
            evidence.push(Evidence::new(
                Claim::RepoIs { url: repo.clone() },
                Confidence::Strong,
                "npm:package.json:repository",
            ));
            if let Some(commit) = doc.get("gitHead").and_then(Value::as_str) {
                source = Some(SourceProvenance {
                    repo_url: repo,
                    commit: commit.to_string(),
                    ref_name: None,
                    subdir: None,
                    how: SourceDiscovery::RegistryCommit,
                });
            }
        }
        if let Some(t) = &publish_time {
            evidence.push(Evidence::new(
                Claim::RegistryMomentIs {
                    moment: RegistryMoment::Timestamp { rfc3339: t.clone() },
                },
                Confidence::Certain,
                "npm:time",
            ));
        }

        Ok(ResolvedTarget {
            reference: target.clone(),
            artifacts: vec![artifact],
            intrinsics: Intrinsics {
                publish_time: publish_time.clone(),
                declared_repo: repo_url(&doc),
                registry_moment: publish_time.map(|rfc3339| RegistryMoment::Timestamp { rfc3339 }),
                evidence,
            },
            source,
        })
    }

    async fn fetch(
        &self,
        meta: &ArtifactMeta,
        sink: &mut (dyn BlobSink + Send),
    ) -> Result<Digest, RegistryError> {
        fetch_verified(&self.client, ECO, meta, sink).await
    }
}

impl NpmRegistry {
    /// Turn a 404 into a message that says whether the package or the version is missing.
    async fn not_found(&self, target: &TargetRef) -> RegistryError {
        let name = target.registry_name();
        let url = format!("{}/{}", self.base, encode(&name));
        let Ok(resp) = self.client.get(&url, ECO).await else {
            return RegistryError::NoSuchPackage {
                ecosystem: ECO.into(),
                name,
            };
        };
        let Ok(doc) = resp.json::<Value>().await else {
            return RegistryError::NoSuchPackage {
                ecosystem: ECO.into(),
                name,
            };
        };
        let mut available: Vec<String> = doc
            .get("versions")
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        available.sort();
        RegistryError::NoSuchVersion {
            ecosystem: ECO.into(),
            name,
            version: target.version.clone(),
            available,
        }
    }

    /// The publish timestamp, from the packument's `time` map.
    ///
    /// Best effort: this is a second request and a package whose metadata omits it is unusual but
    /// not broken. Absent means we cannot pin the registry moment, which is a caveat on the
    /// verdict rather than a reason to refuse.
    async fn publish_time(&self, name: &str, version: &str) -> Option<String> {
        let url = format!("{}/{}", self.base, encode(name));
        let doc: Value = self.client.get(&url, ECO).await.ok()?.json().await.ok()?;
        doc.get("time")?.get(version)?.as_str().map(str::to_owned)
    }
}

fn repo_url(doc: &Value) -> Option<String> {
    let repo = doc.get("repository")?;
    let raw = repo
        .as_str()
        .or_else(|| repo.get("url").and_then(Value::as_str))?;
    Some(canonicalize_repo(raw))
}

/// Normalize the many spellings of a GitHub URL into one clonable HTTPS form.
///
/// package.json carries `git+ssh://git@github.com/a/b.git`, `git://github.com/a/b`, `github:a/b`
/// and plain `a/b`. Left alone, the first would have us clone over SSH with credentials we do not
/// have, and the cache would hold four entries for one repository.
pub(crate) fn canonicalize_repo(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_prefix("git+").unwrap_or(s);
    let s = s.strip_suffix(".git").unwrap_or(s);
    if let Some(rest) = s.strip_prefix("github:") {
        return format!("https://github.com/{rest}");
    }
    if let Some(rest) = s.strip_prefix("git@github.com:") {
        return format!("https://github.com/{rest}");
    }
    if let Some(rest) = s.strip_prefix("ssh://git@github.com/") {
        return format!("https://github.com/{rest}");
    }
    if let Some(rest) = s.strip_prefix("git://github.com/") {
        return format!("https://github.com/{rest}");
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return s.replace("http://", "https://");
    }
    // A bare `owner/repo`, which npm accepts and means GitHub by convention.
    if s.split('/').count() == 2 && !s.contains(' ') && !s.contains(':') {
        return format!("https://github.com/{s}");
    }
    s.to_string()
}

/// A sha256 out of npm's subresource-integrity string, when it happens to be one.
fn integrity_sha256(dist: &Value) -> Option<Digest> {
    let integrity = dist.get("integrity").and_then(Value::as_str)?;
    let b64 = integrity.strip_prefix("sha256-")?;
    let bytes = base64_decode(b64)?;
    Some(Digest::from_bytes(
        <[u8; 32]>::try_from(bytes.as_slice()).ok()?,
    ))
}

/// Enough base64 to read an integrity string. Standard alphabet, padding optional.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = ALPHABET.iter().position(|a| *a == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Percent-encode the one character that matters: the `/` in a scoped name.
fn encode(name: &str) -> String {
    name.replace('/', "%2f")
}

/// Stream an artifact, hashing as it goes, and check the result against what was declared.
pub(crate) async fn fetch_verified(
    client: &Client,
    ecosystem: &str,
    meta: &ArtifactMeta,
    sink: &mut (dyn BlobSink + Send),
) -> Result<Digest, RegistryError> {
    let mut response = client.get(&meta.url, ecosystem).await?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;

    // Streamed rather than buffered: an artifact can be gigabytes, and a worker that holds one in
    // memory to hash it has a memory profile indistinguishable from a build failure.
    while let Some(chunk) = response.chunk().await? {
        hasher.update(&chunk);
        sink.write(&chunk)?;
        bytes += chunk.len() as u64;
    }
    let actual = Digest::from_bytes(hasher.finalize().into());

    if let Some(expected) = &meta.declared_sha256
        && *expected != actual
    {
        return Err(RegistryError::DigestMismatch {
            name: meta.id.to_string(),
            artifact: meta.id.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    tracing::debug!(
        artifact = %meta.id,
        bytes,
        sha256 = %actual,
        verified = meta.declared_sha256.is_some(),
        "fetched"
    );
    Ok(actual)
}
