//! nuget.org, through the v3 API.
//!
//! Two endpoints, because NuGet splits them. The **flat container** holds the bytes and the version
//! list at a predictable URL; the **registration** index holds the metadata, and its
//! `catalogEntry` is where the publish instant and the project URL live. Both key on a
//! lowercased id, which is the one thing about this API that will bite somebody: `Newtonsoft.Json`
//! is `newtonsoft.json` in every path and `Newtonsoft.Json` in every document.
//!
//! **Source discovery here should be the best of any ecosystem and this rung does not do it yet.**
//! `docs/03-ecosystems.md` §5 is right that a `.nuspec` carries
//! `<repository type="git" url="…" commit="…"/>` — repo *and commit*, directly, which no other
//! registry gives — and that SourceLink data in the PDB maps every source file to a commit. Both
//! live inside the `.nupkg`, so reading them needs the artifact, and `Registry::resolve` runs
//! before the fetch. `projectUrl` is what is reachable without the bytes, and it is the weak
//! substitute PyPI's `home_page` is: often a docs site, occasionally a forge. Recorded at
//! `Confidence::Weak` and only when it looks like one.
//!
//! No `declared_sha256`. The flat container serves the package and the API publishes no digest for
//! it beside the URL — the catalog carries `packageHash` in some entries and not others, and a
//! check that is present for some packages and silently absent for the rest is worse than one that
//! says it is absent. See [`ArtifactMeta::declared_sha256`].

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

const ECO: &str = "nuget";

pub struct NuGetRegistry {
    client: Client,
    flat: String,
    registration: String,
}

impl NuGetRegistry {
    pub fn new(client: Client) -> Self {
        NuGetRegistry {
            client,
            flat: "https://api.nuget.org/v3-flatcontainer".into(),
            registration: "https://api.nuget.org/v3/registration5-gz-semver2".into(),
        }
    }

    /// Point both endpoints at one base, for a test server.
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        self.flat = format!("{base}/v3-flatcontainer");
        self.registration = format!("{base}/v3/registration5-gz-semver2");
        self
    }

    /// Every version of this package, newest last, as the flat container lists them.
    async fn versions(&self, id: &str) -> Vec<String> {
        let url = format!("{}/{id}/index.json", self.flat);
        let Ok(resp) = self.client.get(&url, ECO).await else {
            return Vec::new();
        };
        let Ok(doc) = resp.json::<Value>().await else {
            return Vec::new();
        };
        doc.get("versions")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The `catalogEntry` for one version, out of the registration index.
    ///
    /// The index is paged, and a package with enough releases has `items` that are *references* to
    /// pages rather than the pages themselves — `Newtonsoft.Json` is one. Following one page is
    /// enough because the pages are ordered and each declares the range it covers.
    async fn catalog_entry(&self, id: &str, version: &str) -> Option<Value> {
        let url = format!("{}/{id}/index.json", self.registration);
        let doc: Value = self.client.get(&url, ECO).await.ok()?.json().await.ok()?;
        for page in doc.get("items")?.as_array()? {
            // An inline page carries its items; a reference has to be followed.
            let items = match page.get("items") {
                Some(i) => i.clone(),
                None => {
                    let href = page.get("@id").and_then(Value::as_str)?;
                    let fetched: Value =
                        self.client.get(href, ECO).await.ok()?.json().await.ok()?;
                    fetched.get("items")?.clone()
                }
            };
            for item in items.as_array()? {
                let entry = item.get("catalogEntry")?;
                if entry.get("version").and_then(Value::as_str) == Some(version) {
                    return Some(entry.clone());
                }
            }
        }
        None
    }
}

#[async_trait]
impl Registry for NuGetRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }

    async fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, RegistryError> {
        let name = target.registry_name();
        // Every path in this API is lowercased; every document says the id the way the author
        // wrote it. Mixing the two up gives a 404 that reads like a missing package.
        let id = name.to_ascii_lowercase();
        let version = target.version.to_ascii_lowercase();

        let known = self.versions(&id).await;
        if known.is_empty() {
            return Err(RegistryError::NoSuchPackage {
                ecosystem: ECO.into(),
                name,
            });
        }
        if !known
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&target.version))
        {
            return Err(RegistryError::NoSuchVersion {
                ecosystem: ECO.into(),
                name,
                version: target.version.clone(),
                available: known,
            });
        }

        // The one download, at the flat container's predictable path.
        let file = format!("{id}.{version}.nupkg");
        let url = format!("{}/{id}/{version}/{file}", self.flat);

        let entry = self.catalog_entry(&id, &target.version).await;
        let published = entry
            .as_ref()
            .and_then(|e| e.get("published"))
            .and_then(Value::as_str)
            // **`1900-01-01` means unlisted, not published in 1900.** NuGet stamps a delisted
            // package with that sentinel, and carrying it into `registry_moment` would pin every
            // dependency resolution to the beginning of the twentieth century and fail every build
            // for a reason nobody would trace back to here.
            .filter(|t| !t.starts_with("1900-01-01"))
            .map(str::to_owned);

        let mut evidence = Vec::new();
        let declared = entry
            .as_ref()
            .and_then(|e| e.get("projectUrl"))
            .and_then(Value::as_str)
            .filter(|u| looks_like_a_forge(u))
            .map(str::to_owned);
        let repo = declared.as_deref().map(crate::npm::canonicalize_repo);
        if let Some(r) = &repo {
            evidence.push(Evidence::new(
                Claim::RepoIs { url: r.clone() },
                // The weakest of the four, and for PyPI's reason: `projectUrl` is a link an author
                // typed, and for most packages it is documentation. The `.nuspec` inside the
                // package has the real answer and needs the bytes to read.
                Confidence::Weak,
                "nuget:projectUrl",
            ));
        }
        if let Some(t) = &published {
            evidence.push(Evidence::new(
                Claim::RegistryMomentIs {
                    moment: RegistryMoment::Timestamp { rfc3339: t.clone() },
                },
                Confidence::Certain,
                "nuget:published",
            ));
        }

        Ok(ResolvedTarget {
            reference: target.clone(),
            artifacts: vec![ArtifactMeta {
                id: ArtifactId::new(file),
                url,
                // See the module docs: the API publishes no digest beside this URL for every
                // package, and a check that silently covers some is worse than a stated absence.
                declared_sha256: None,
                size: None,
            }],
            intrinsics: Intrinsics {
                publish_time: published.clone(),
                declared_repo: repo.clone(),
                registry_moment: published.map(|rfc3339| RegistryMoment::Timestamp { rfc3339 }),
                evidence,
            },
            source: repo.map(|repo_url| SourceProvenance {
                declared_url: declared.filter(|d| *d != repo_url),
                repo_url,
                commit: String::new(),
                ref_name: None,
                subdir: None,
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

fn looks_like_a_forge(url: &str) -> bool {
    const FORGES: &[&str] = &[
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "dev.azure.com",
    ];
    let u = url.to_ascii_lowercase();
    FORGES.iter().any(|f| u.contains(f))
}

#[cfg(test)]
mod tests {
    use super::looks_like_a_forge;

    #[test]
    fn a_project_url_counts_only_when_it_is_a_forge() {
        // `Newtonsoft.Json` declares `https://www.newtonsoft.com/json`, which is a docs site. Most
        // of this ecosystem is the same, which is why the real answer is in the `.nuspec`.
        assert!(!looks_like_a_forge("https://www.newtonsoft.com/json"));
        assert!(looks_like_a_forge(
            "https://github.com/JamesNK/Newtonsoft.Json"
        ));
        // Azure DevOps is where a lot of this ecosystem actually lives.
        assert!(looks_like_a_forge(
            "https://dev.azure.com/org/proj/_git/repo"
        ));
    }
}
