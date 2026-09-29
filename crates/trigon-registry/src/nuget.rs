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
//! **The digest is in the catalog, one request further.** The flat container publishes no digest
//! beside the package, and the registration's `catalogEntry` is a summary that carries none either.
//! The catalog leaf it names by `@id` carries `packageHash`, a base64 sha512 of the `.nupkg` with
//! `packageHashAlgorithm` beside it — for most entries, and not all. So the download is verified
//! against it where the catalog carries it, and where it does not, the absence is recorded with its
//! reason rather than passed over: a check present for some packages and silently absent for the
//! rest would be worse than one that says which it is. Measured on Newtonsoft.Json 13.0.3 and
//! 3.5.8 (2011): both leaves carry one, and it is the sha512 of the bytes the flat container
//! serves.
//!
//! **Absent is something read, never something assumed.** A registration or a leaf that could not
//! be read — a 503, a 429 past the retries, a dropped connection, a body that is not the document —
//! refuses the resolve ([`RegistryError::CatalogUnreadable`], retried where the failure was
//! transient). It used to come back as "no catalog entry for this version", so a moment of catalog
//! trouble turned a verified download into one checked against nothing, and the run recorded that
//! the registry had declared nothing.

use async_trait::async_trait;
use serde_json::Value;
use trigon_core::{
    ArtifactId, Claim, Confidence, DeclaredDigest, Ecosystem, Evidence, Intrinsics, RegistryMoment,
    SourceDiscovery, SourceProvenance, TargetRef,
};

use crate::client::Client;
use crate::declared::fetch_verified;
use crate::error::RegistryError;
use crate::model::{ArtifactMeta, BlobSink, Fetched, ResolvedTarget};
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

    /// A catalog document, or the reason it could not be read.
    ///
    /// Every failure is kept as [`RegistryError::CatalogUnreadable`], naming the document, so that
    /// nothing downstream can mistake "could not read" for "read, and it declares nothing".
    async fn document(&self, url: &str, what: &str) -> Result<Value, RegistryError> {
        let read = match self.client.get(url, ECO).await {
            Ok(r) => r.json::<Value>().await.map_err(RegistryError::from),
            Err(e) => Err(e),
        };
        read.map_err(|cause| RegistryError::CatalogUnreadable {
            what: what.to_string(),
            cause: Box::new(cause),
        })
    }

    /// The `catalogEntry` for one version, out of the registration index, or `None` where the index
    /// was read and does not list it.
    ///
    /// The index is paged, and a package with enough releases has `items` that are *references* to
    /// pages rather than the pages themselves — `Newtonsoft.Json` is one. Following one page is
    /// enough because the pages are ordered and each declares the range it covers.
    ///
    /// **An error where the index or a page could not be read, or is not the document it should
    /// be**, never `None`. `None` is recorded as "the registration has no catalog entry for this
    /// version", and that sentence has to be a fact about the registry.
    async fn catalog_entry(&self, id: &str, version: &str) -> Result<Option<Value>, RegistryError> {
        let url = format!("{}/{id}/index.json", self.registration);
        let what = format!("the NuGet registration index for `{id}`");
        let malformed = |detail: &str| RegistryError::Malformed {
            ecosystem: ECO.into(),
            what: what.clone(),
            detail: detail.to_string(),
        };
        let doc = self.document(&url, &what).await?;
        let pages = doc
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("no `items` list"))?;
        for page in pages {
            // An inline page carries its items; a reference has to be followed.
            let fetched;
            let page = match page.get("items") {
                Some(_) => page,
                None => {
                    let href = page
                        .get("@id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| malformed("a page with neither `items` nor an `@id`"))?;
                    fetched = self
                        .document(
                            href,
                            &format!("a page of the NuGet registration for `{id}`"),
                        )
                        .await?;
                    &fetched
                }
            };
            let items = page
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| malformed("a page whose `items` is not a list"))?;
            for item in items {
                let entry = item
                    .get("catalogEntry")
                    .ok_or_else(|| malformed("an item with no `catalogEntry`"))?;
                // NuGet versions compare without case, as `resolve`'s check of the flat container's
                // list does.
                let listed = entry.get("version").and_then(Value::as_str);
                if listed.is_some_and(|v| v.eq_ignore_ascii_case(version)) {
                    return Ok(Some(entry.clone()));
                }
            }
        }
        Ok(None)
    }

    /// The `packageHash` the catalog declares for one version, where it declares one.
    ///
    /// Read from the registration's own `catalogEntry` if it ever carries one, and otherwise from
    /// the catalog leaf that entry names by `@id`, which is where nuget.org puts it. **Never
    /// silent**: no entry, no leaf named, or a leaf with no hash each come back as an empty list
    /// with the reason, which the run records. A leaf that could not be read refuses the resolve
    /// instead, as a hash that is present and is not a digest does: dropping either would make a
    /// declaration nobody saw read as no declaration.
    async fn package_hash(
        &self,
        entry: Option<&Value>,
        what: &str,
    ) -> Result<(Vec<DeclaredDigest>, Option<String>), RegistryError> {
        let absent = |why: String| Ok((Vec::new(), Some(why)));
        let Some(entry) = entry else {
            return absent(
                "the NuGet registration has no catalog entry for this version, so there was no \
                 `packageHash` to check the package against"
                    .into(),
            );
        };
        let leaf = if entry.get("packageHash").is_some() {
            entry.clone()
        } else {
            let Some(href) = entry.get("@id").and_then(Value::as_str) else {
                return absent(
                    "the NuGet catalog entry for this version names no catalog leaf, so there was \
                     no `packageHash` to check the package against"
                        .into(),
                );
            };
            self.document(href, &format!("the NuGet catalog leaf for {what}"))
                .await?
        };
        let Some(hash) = leaf.get("packageHash").and_then(Value::as_str) else {
            return absent(
                "the NuGet catalog entry for this version carries no `packageHash`, and the flat \
                 container publishes no digest, so the package was checked against nothing"
                    .into(),
            );
        };
        // Always `SHA512` on nuget.org, and named beside every hash it writes. Absent, the
        // catalog's own default is assumed rather than the hash being thrown away.
        let algorithm = leaf
            .get("packageHashAlgorithm")
            .and_then(Value::as_str)
            .unwrap_or("SHA512");
        let d = crate::declared::from_base64(algorithm, hash, "nuget:catalog.packageHash")
            .map_err(|detail| RegistryError::Malformed {
                ecosystem: ECO.into(),
                what: what.to_string(),
                detail,
            })?;
        Ok((vec![d], None))
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

        let entry = self.catalog_entry(&id, &target.version).await?;
        let (package_hash, hash_note) = self
            .package_hash(entry.as_ref(), &format!("{name} {}", target.version))
            .await?;
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
                // See the module docs: from the catalog leaf where it carries one, and a stated
                // absence where it does not.
                declared: package_hash,
                declared_note: hash_note,
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
    ) -> Result<Fetched, RegistryError> {
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
