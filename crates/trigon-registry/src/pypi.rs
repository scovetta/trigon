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

        // Ask the package what it says now only when the release itself said nothing: one extra
        // request, never on the common path. See [`believe`] for why it is worth making.
        let mut believed = believe(&doc, None);
        if believed.repo.is_none() {
            let latest = self.latest_doc(&name).await;
            believed = believe(&doc, latest.as_ref());
        }
        let Believed {
            repo,
            declared,
            subdir,
            source,
        } = believed;

        let mut evidence = Vec::new();
        if let Some(r) = &repo {
            evidence.push(Evidence::new(
                Claim::RepoIs { url: r.clone() },
                // Weaker than npm's, deliberately. This is a link a human typed into project
                // metadata, not something the publishing tool recorded, and it is routinely a
                // documentation site or an organization page.
                Confidence::Weak,
                source,
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
                declared_url: declared,
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
    /// What the package says about itself now, for a release that said nothing.
    ///
    /// Best-effort by construction: this runs only when the version's own record named no
    /// repository, so a failure here leaves the resolver exactly where it already was. Returning
    /// `None` rather than an error keeps a rate limit or a transient 503 from turning a resolvable
    /// target into a failed one.
    async fn latest_doc(&self, name: &str) -> Option<Value> {
        let url = format!("{}/pypi/{}/json", self.base, name);
        match self.client.get(&url, ECO).await {
            Ok(r) => r.json().await.ok(),
            Err(e) => {
                tracing::debug!(%name, error = %e, "no package-level metadata to fall back on");
                None
            }
        }
    }

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

/// What a resolve believes about where the source is, and on whose word.
struct Believed {
    repo: Option<String>,
    /// The URL exactly as the record gave it, when trimming changed it. See
    /// [`SourceProvenance::declared_url`].
    declared: Option<String>,
    subdir: Option<String>,
    /// The evidence source string, which differs by which record was believed.
    source: &'static str,
}

/// Which record to believe about the repository: the release's own, or the package's as it stands.
///
/// The repository is a per-package fact, and the metadata around it improves over time, so the
/// version under test is routinely the one that says least. `pytz` 2026.1 declares a `Download`
/// link and a docs `Homepage` and nothing else; `pytz` today declares
/// `Source: https://github.com/stub42/pytz.git`, and the repository has not moved in between.
///
/// The release's own record always wins where it names anything, because it is contemporary with
/// the artifact. The fallback is a guess about continuity — a package that changed hands would
/// send us to the wrong repository — so it is recorded under its own evidence source and the
/// caller is not told the two are the same kind of claim.
///
/// The subdirectory comes from whichever record won. Reading the repository out of one document
/// and the subdirectory out of another is how a monorepo member comes to build at the wrong root.
fn believe(version: &Value, latest: Option<&Value>) -> Believed {
    let believed = |doc: &Value, source| {
        let raw = raw_source_url(doc);
        let repo = raw.as_deref().map(crate::npm::canonicalize_repo);
        Believed {
            declared: match (&raw, &repo) {
                // Only where trimming changed it, so the common case costs nothing.
                (Some(r), Some(c)) if r != c => Some(r.clone()),
                _ => None,
            },
            subdir: raw.as_deref().and_then(crate::npm::subdir_from_view),
            repo,
            source,
        }
    };
    let own = believed(version, "pypi:project_urls");
    if own.repo.is_some() {
        return own;
    }
    match latest {
        Some(doc) => {
            let fallback = believed(doc, "pypi:project_urls@latest");
            match fallback.repo.is_some() {
                true => fallback,
                false => own,
            }
        }
        None => own,
    }
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
            believe(&d, None).repo.as_deref(),
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
        assert_eq!(believe(&d, None).repo, None);
    }

    #[test]
    fn a_forge_url_under_an_unconventional_key_is_still_found() {
        let d = doc(r#"{"info":{"project_urls":{"Tracker":"https://github.com/a/b/issues"}}}"#);
        assert!(believe(&d, None).repo.unwrap().contains("github.com/a/b"));
    }

    /// The two records `pytz` 2026.1 actually has: the release names no forge, the package does.
    const PYTZ_RELEASE: &str = r#"{"info":{"project_urls":{
            "Download":"https://pypi.org/project/pytz/",
            "Homepage":"http://pythonhosted.org/pytz"}}}"#;
    const PYTZ_PACKAGE: &str = r#"{"info":{"project_urls":{
            "Homepage":"http://pythonhosted.org/pytz",
            "Issues":"https://github.com/stub42/pytz/issues",
            "Source":"https://github.com/stub42/pytz.git"}}}"#;

    #[test]
    fn a_release_that_names_no_forge_falls_back_to_what_the_package_says_now() {
        let b = believe(&doc(PYTZ_RELEASE), Some(&doc(PYTZ_PACKAGE)));
        assert_eq!(b.repo.as_deref(), Some("https://github.com/stub42/pytz"));
        // Not the same claim as a contemporary one, and it does not get to say it is.
        assert_eq!(b.source, "pypi:project_urls@latest");
    }

    #[test]
    fn the_release_is_believed_over_the_package_wherever_it_says_anything() {
        // Contemporary with the artifact, so it wins even though the package names another repo.
        let release = doc(r#"{"info":{"project_urls":{"Source":"https://github.com/a/old"}}}"#);
        let package = doc(r#"{"info":{"project_urls":{"Source":"https://github.com/a/new"}}}"#);
        let b = believe(&release, Some(&package));
        assert_eq!(b.repo.as_deref(), Some("https://github.com/a/old"));
        assert_eq!(b.source, "pypi:project_urls");
    }

    #[test]
    fn the_subdirectory_comes_from_whichever_record_was_believed() {
        // Taking the repository from one document and the subdirectory from another is how a
        // monorepo member comes to build at the wrong root.
        let release = doc(r#"{"info":{"project_urls":{"Homepage":"https://example.com"}}}"#);
        let package = doc(r#"{"info":{"project_urls":{
                "Source":"https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-blob"}}}"#);
        let b = believe(&release, Some(&package));
        assert_eq!(
            b.repo.as_deref(),
            Some("https://github.com/Azure/azure-sdk-for-python")
        );
        assert_eq!(b.subdir.as_deref(), Some("sdk/storage/azure-storage-blob"));
    }

    #[test]
    fn neither_record_naming_a_forge_is_not_an_answer() {
        let b = believe(&doc(PYTZ_RELEASE), Some(&doc(PYTZ_RELEASE)));
        assert_eq!(b.repo, None);
        assert_eq!(b.subdir, None);
        // And a resolve with no package-level record to fall back on is the same answer, not a
        // different one: the fetch is best-effort and its failure changes nothing.
        assert_eq!(believe(&doc(PYTZ_RELEASE), None).repo, None);
    }

    #[test]
    fn home_page_is_used_only_when_it_is_a_forge() {
        let d = doc(r#"{"info":{"home_page":"https://github.com/a/b"}}"#);
        assert_eq!(
            believe(&d, None).repo.as_deref(),
            Some("https://github.com/a/b")
        );
    }
}
