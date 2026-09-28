//! crates.io.
//!
//! The easiest of the four to resolve and the hardest to reproduce, and both for the same reason:
//! Cargo owns the whole pipeline. It publishes a `.crate` — a gzipped tar of the package directory
//! — built by `cargo package`, and it records more about that build than any other registry here.
//! The API gives a **sha256** (npm gives sha1 or sha512, PyPI gives sha256, so this is the good
//! case), the exact publish instant, the repository, and the crate's declared `edition`.
//!
//! What it does not give is a commit, so like PyPI the tag ladder has to find one.
//!
//! The reproduction difficulty is elsewhere: `cargo package` **rewrites `Cargo.toml`** on the way
//! in — normalizing tables, dropping `dev-dependencies`' `path` keys, inserting a header comment —
//! and the rules changed across Cargo releases. `docs/03-ecosystems.md` treats that as an asset
//! rather than an obstacle: the rewrite is a fingerprint that pins the toolchain window far tighter
//! than a publish date does. None of that is inference this rung performs; it is recorded here so
//! the next person does not re-derive why `edition` is worth carrying.

use async_trait::async_trait;
use serde_json::Value;
use trigon_core::{
    ArtifactId, Claim, Confidence, Ecosystem, Evidence, Intrinsics, RegistryMoment,
    SourceDiscovery, SourceProvenance, TargetRef,
};

use crate::client::Client;
use crate::declared::fetch_verified;
use crate::error::RegistryError;
use crate::model::{ArtifactMeta, BlobSink, Fetched, ResolvedTarget};
use crate::registry::Registry;

const ECO: &str = "cargo";

pub struct CratesIoRegistry {
    client: Client,
    base: String,
}

impl CratesIoRegistry {
    pub fn new(client: Client) -> Self {
        CratesIoRegistry {
            client,
            base: "https://crates.io".into(),
        }
    }

    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into().trim_end_matches('/').to_string();
        self
    }

    /// The versions this crate has, for an error that names them.
    ///
    /// Best effort: a listing we could not read gives an error with an empty list rather than a
    /// different error about the listing, because the caller asked about a version and that is
    /// still the answer.
    async fn available(&self, name: &str) -> Vec<String> {
        let url = format!("{}/api/v1/crates/{name}", self.base);
        let Ok(resp) = self.client.get(&url, ECO).await else {
            return Vec::new();
        };
        let Ok(doc) = resp.json::<Value>().await else {
            return Vec::new();
        };
        doc.get("versions")
            .and_then(Value::as_array)
            .map(|vs| {
                vs.iter()
                    .filter_map(|v| v.get("num").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[async_trait]
impl Registry for CratesIoRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::CratesIo
    }

    async fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, RegistryError> {
        let name = target.registry_name();
        let url = format!("{}/api/v1/crates/{name}/{}", self.base, target.version);
        let doc: Value = match self.client.get(&url, ECO).await {
            Ok(r) => r.json().await?,
            Err(RegistryError::Http { status: 404, .. }) => {
                return Err(RegistryError::NoSuchVersion {
                    ecosystem: ECO.into(),
                    name: name.clone(),
                    version: target.version.clone(),
                    available: self.available(&name).await,
                });
            }
            Err(e) => return Err(e),
        };
        let version = doc.get("version").ok_or_else(|| RegistryError::Malformed {
            ecosystem: ECO.into(),
            what: format!("{name} {}", target.version),
            detail: "no `version` object".into(),
        })?;

        // **A yanked version is still a published artifact**, and reproducing one is a reasonable
        // thing to ask: a yank is a request not to depend on it, not a statement that it never
        // existed. So it resolves like any other. It is not recorded, because there is no honest
        // place to put it — `Claim` has no variant for it and inventing one out of `RepoIs` with an
        // empty URL would be a lie in the evidence list, which is the one list that must not
        // contain any. `ResolvedTarget` needs a `notes` channel before this is sayable.
        // The one download, named as Cargo names it.
        let file = format!("{name}-{}.crate", target.version);
        let dl = version
            .get("dl_path")
            .and_then(Value::as_str)
            .map(|p| format!("{}{p}", self.base))
            .unwrap_or_else(|| {
                format!(
                    "{}/api/v1/crates/{name}/{}/download",
                    self.base, target.version
                )
            });

        // crates.io publishes sha256 for every version, so there is always something to check the
        // bytes against. A checksum that is not a sha256 is refused rather than dropped: dropping
        // it, as this did, made a malformed declaration read as no declaration.
        let checksum = match version.get("checksum").and_then(Value::as_str) {
            Some(h) => vec![
                crate::declared::from_hex("sha256", h, "cargo:checksum").map_err(|detail| {
                    RegistryError::Malformed {
                        ecosystem: ECO.into(),
                        what: format!("{name} {}", target.version),
                        detail,
                    }
                })?,
            ],
            None => Vec::new(),
        };

        let publish_time = version
            .get("created_at")
            .and_then(Value::as_str)
            .map(str::to_owned);

        let mut evidence = Vec::new();
        // The repository, which crates.io carries on the *version* rather than on the crate — the
        // crate-level field is frequently null while every version has one.
        let declared = version
            .get("repository")
            .and_then(Value::as_str)
            .or_else(|| {
                doc.get("crate")
                    .and_then(|c| c.get("repository"))
                    .and_then(Value::as_str)
            })
            .map(str::to_owned);
        let repo = declared.as_deref().map(crate::npm::canonicalize_repo);
        if let Some(r) = &repo {
            evidence.push(Evidence::new(
                Claim::RepoIs { url: r.clone() },
                // Stronger than PyPI's and weaker than npm's: `Cargo.toml`'s `repository` is read
                // by the publishing tool out of the manifest rather than typed into a web form,
                // but it is still what the author wrote rather than what the tool observed.
                Confidence::Strong,
                "cargo:version.repository",
            ));
        }
        if let Some(t) = &publish_time {
            evidence.push(Evidence::new(
                Claim::RegistryMomentIs {
                    moment: RegistryMoment::Timestamp { rfc3339: t.clone() },
                },
                Confidence::Certain,
                "cargo:created_at",
            ));
        }
        // **The edition is a toolchain floor and nothing more.** `edition = "2021"` cannot have
        // been packaged by a Cargo older than 1.56, and says nothing about the upper end. A range
        // with no `hi` is exactly what `Claim::ToolchainRange` is for, and `resolve_toolchain`
        // intersects it with whatever else turns up rather than this rung guessing a version.
        if let Some(edition) = version.get("edition").and_then(Value::as_str)
            && let Some(lo) = cargo_floor(edition)
        {
            evidence.push(Evidence::new(
                Claim::ToolchainRange {
                    tool: "cargo".into(),
                    lo: Some(lo.into()),
                    hi: None,
                },
                Confidence::Certain,
                "cargo:edition",
            ));
        }

        Ok(ResolvedTarget {
            reference: target.clone(),
            artifacts: vec![ArtifactMeta {
                id: ArtifactId::new(file),
                url: dl,
                declared: checksum,
                declared_note: None,
                size: version.get("crate_size").and_then(Value::as_u64),
            }],
            intrinsics: Intrinsics {
                publish_time: publish_time.clone(),
                declared_repo: repo.clone(),
                registry_moment: publish_time.map(|rfc3339| RegistryMoment::Timestamp { rfc3339 }),
                evidence,
            },
            source: repo.map(|repo_url| SourceProvenance {
                declared_url: declared.filter(|d| *d != repo_url),
                repo_url,
                // crates.io records no commit. `.cargo_vcs_info.json` inside the `.crate` does, and
                // reading it needs the bytes — a rung above this one, not a field this one can fill.
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

/// The oldest Cargo that can package a crate declaring this edition.
///
/// A floor, never a ceiling: every later Cargo packages an older edition happily. Returning `None`
/// for an edition we do not know is the honest answer — a future `2027` must not silently become a
/// claim about 1.56.
fn cargo_floor(edition: &str) -> Option<&'static str> {
    match edition {
        "2015" => Some("1.0.0"),
        "2018" => Some("1.31.0"),
        "2021" => Some("1.56.0"),
        "2024" => Some("1.85.0"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::cargo_floor;

    #[test]
    fn an_edition_is_a_floor_and_an_unknown_one_is_not_a_guess() {
        assert_eq!(cargo_floor("2021"), Some("1.56.0"));
        assert_eq!(cargo_floor("2024"), Some("1.85.0"));
        // The point of returning `None`: a future edition must not silently claim 1.56, which is
        // what a `_ => Some("1.0.0")` arm would do.
        assert_eq!(cargo_floor("2027"), None);
        assert_eq!(cargo_floor(""), None);
    }
}
