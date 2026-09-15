//! PyPI.
//!
//! Where npm records the commit it published from, PyPI records a project URL and nothing more, so
//! source discovery here starts one rung lower: we learn the repository and still have to find the
//! commit. That is the honest state of the ecosystem rather than a gap in this client.
//!
//! The other structural difference is that a PyPI release is genuinely several artifacts. One
//! version commonly publishes an sdist and a dozen platform wheels, built on a dozen machines, and
//! they do not reproduce alike. A verdict has to name the file.

use async_trait::async_trait;
use serde_json::Value;
use trigon_core::{
    ArtifactId, Claim, Confidence, Digest, Ecosystem, Evidence, Intrinsics, RegistryMoment,
    SourceDiscovery, SourceProvenance, TargetRef,
};

use crate::client::Client;
use crate::error::RegistryError;
use crate::model::{ArtifactMeta, BlobSink, ResolvedTarget};
use crate::npm::fetch_verified;
use crate::registry::Registry;

const ECO: &str = "pypi";

pub struct PyPiRegistry {
    client: Client,
    base: String,
}

impl PyPiRegistry {
    pub fn new(client: Client) -> Self {
        PyPiRegistry {
            client,
            base: "https://pypi.org".into(),
        }
    }

    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into().trim_end_matches('/').to_string();
        self
    }
}

#[async_trait]
impl Registry for PyPiRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    async fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, RegistryError> {
        let name = target.registry_name();
        let url = format!("{}/pypi/{}/{}/json", self.base, name, target.version);
        let doc: Value = match self.client.get(&url, ECO).await {
            Ok(r) => r.json().await?,
            Err(RegistryError::Http { status: 404, .. }) => {
                return Err(self.not_found(target).await);
            }
            Err(e) => return Err(e),
        };

        let files =
            doc.get("urls")
                .and_then(Value::as_array)
                .ok_or_else(|| RegistryError::Malformed {
                    ecosystem: ECO.into(),
                    what: format!("{name} {}", target.version),
                    detail: "no `urls` array".into(),
                })?;

        let mut artifacts = Vec::new();
        let mut publish_time = None;
        for f in files {
            let Some(filename) = f.get("filename").and_then(Value::as_str) else {
                continue;
            };
            let Some(url) = f.get("url").and_then(Value::as_str) else {
                continue;
            };
            // PyPI publishes sha256 for every file, so unlike npm there is always something to
            // check the bytes against.
            let declared_sha256 = f
                .get("digests")
                .and_then(|d| d.get("sha256"))
                .and_then(Value::as_str)
                .and_then(|h| Digest::from_hex(h).ok());
            artifacts.push(ArtifactMeta {
                id: ArtifactId::new(filename),
                url: url.to_string(),
                declared_sha256,
                size: f.get("size").and_then(Value::as_u64),
            });
            // The earliest upload of this release. A release's files can be uploaded minutes or
            // months apart, and the moment a dependency graph should resolve against is when the
            // release happened, not when someone backfilled a wheel for a new Python.
            if let Some(t) = f
                .get("upload_time_iso_8601")
                .and_then(Value::as_str)
                .or_else(|| f.get("upload_time").and_then(Value::as_str))
            {
                let t = t.to_string();
                publish_time = Some(match publish_time {
                    Some(prev) if prev <= t => prev,
                    _ => t,
                });
            }
        }

        if artifacts.is_empty() {
            return Err(RegistryError::NoSuchVersion {
                ecosystem: ECO.into(),
                name,
                version: target.version.clone(),
                available: Vec::new(),
            });
        }

        let (repo, subdir) = source_and_subdir(&doc);
        let mut evidence = Vec::new();
        if let Some(r) = &repo {
            evidence.push(Evidence::new(
                Claim::RepoIs { url: r.clone() },
                // Weaker than npm's, deliberately. This is a link a human typed into project
                // metadata, not something the publishing tool recorded, and it is routinely a
                // documentation site or an organization page.
                Confidence::Weak,
                "pypi:project_urls",
            ));
        }
        if let Some(t) = &publish_time {
            evidence.push(Evidence::new(
                Claim::RegistryMomentIs {
                    moment: RegistryMoment::Timestamp { rfc3339: t.clone() },
                },
                Confidence::Certain,
                "pypi:upload_time",
            ));
        }

        Ok(ResolvedTarget {
            reference: target.clone(),
            artifacts,
            intrinsics: Intrinsics {
                publish_time: publish_time.clone(),
                declared_repo: repo.clone(),
                registry_moment: publish_time.map(|rfc3339| RegistryMoment::Timestamp { rfc3339 }),
                evidence,
            },
            // A repository with no commit. The rung is named so the verdict can be read for what
            // it is: something still has to find which commit this release was built from.
            source: repo.map(|repo_url| SourceProvenance {
                repo_url,
                commit: String::new(),
                ref_name: None,
                // From the same URL the repository came from: PyPI has no field for this, and a
                // `tree/<ref>/<path>` link says it in passing.
                subdir,
                how: SourceDiscovery::RegistryMetadata,
            }),
            about: None,
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

impl PyPiRegistry {
    async fn not_found(&self, target: &TargetRef) -> RegistryError {
        let name = target.registry_name();
        let url = format!("{}/pypi/{}/json", self.base, name);
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
            .get("releases")
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
}

/// The repository a project declares, and the subdirectory its URL points into.
///
/// Returned together because they come from the same string: PyPI has no `repository.directory`,
/// and a monorepo member's `project_urls` often says where it lives in passing —
/// `…/google-cloud-python/tree/main/packages/google-auth`. Reading the repository and discarding
/// the path was how `google-auth` came to check out a monorepo and build at its root.
fn source_and_subdir(doc: &Value) -> (Option<String>, Option<String>) {
    let raw = raw_source_url(doc);
    let subdir = raw.as_deref().and_then(crate::npm::subdir_from_view);
    (raw.map(|u| crate::npm::canonicalize_repo(&u)), subdir)
}

/// The declared URL, out of the several places a project might have declared one, before it is
/// trimmed to a repository.
///
/// Ordered by how likely each is to be a repository rather than a documentation site. `Source` and
/// `Repository` are the conventional keys; `home_page` is checked last and only when it looks like
/// a forge, because for most projects it is a docs URL and following it would send the resolver
/// somewhere with no source in it at all.
fn raw_source_url(doc: &Value) -> Option<String> {
    let info = doc.get("info")?;
    if let Some(urls) = info.get("project_urls").and_then(Value::as_object) {
        for key in [
            "Source",
            "source",
            "Source Code",
            "Repository",
            "repository",
            "Code",
            "GitHub",
        ] {
            if let Some(u) = urls.get(key).and_then(Value::as_str)
                && looks_like_a_forge(u)
            {
                return Some(u.to_string());
            }
        }
        // Any project URL that is a forge, before falling back to home_page.
        for u in urls.values().filter_map(Value::as_str) {
            if looks_like_a_forge(u) {
                return Some(u.to_string());
            }
        }
    }
    info.get("home_page")
        .and_then(Value::as_str)
        .filter(|u| looks_like_a_forge(u))
        .map(str::to_string)
}

fn looks_like_a_forge(url: &str) -> bool {
    const FORGES: &[&str] = &[
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "git.sr.ht",
    ];
    let u = url.to_ascii_lowercase();
    FORGES.iter().any(|f| u.contains(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(json: &str) -> Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_source_key_wins_over_documentation() {
        let d = doc(r#"{"info":{"project_urls":{
                "Documentation":"https://docs.example.com",
                "Source":"https://github.com/a/b"}}}"#);
        assert_eq!(
            source_and_subdir(&d).0.as_deref(),
            Some("https://github.com/a/b")
        );
    }

    #[test]
    fn a_documentation_only_project_yields_nothing() {
        // Better than pointing the resolver at a site with no source in it.
        let d = doc(
            r#"{"info":{"project_urls":{"Documentation":"https://docs.example.com"},
                        "home_page":"https://example.com"}}"#,
        );
        assert_eq!(source_and_subdir(&d).0, None);
    }

    #[test]
    fn a_forge_url_under_an_unconventional_key_is_still_found() {
        let d = doc(r#"{"info":{"project_urls":{"Tracker":"https://github.com/a/b/issues"}}}"#);
        assert!(source_and_subdir(&d).0.unwrap().contains("github.com/a/b"));
    }

    #[test]
    fn home_page_is_used_only_when_it_is_a_forge() {
        let d = doc(r#"{"info":{"home_page":"https://github.com/a/b"}}"#);
        assert_eq!(
            source_and_subdir(&d).0.as_deref(),
            Some("https://github.com/a/b")
        );
    }
}
