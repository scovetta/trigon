//! Resolving a version to a commit, for registries that do not record one.
//!
//! npm publishes `gitHead` and needs none of this. PyPI, crates.io and RubyGems do not, so for them
//! a version has to be matched against the repository's tags. This is the cheap end of the ladder
//! in `docs/07-ai.md` §2: an exact tag, then the conventional `v` prefix, and then nothing. The
//! expensive rungs, scoring date-windowed candidates by tree hash against the published sdist,
//! come later and are worth more than any prompt.
//!
//! Only GitHub for now, because that is where the M1 corpus lives, and because each forge needs its
//! own API. A repository somewhere else yields no commit rather than a guess.

use serde_json::Value;
use trigon_core::SourceDiscovery;

use crate::client::Client;
use crate::error::RegistryError;

const ECO: &str = "github";

/// Owner and repository from a canonicalized GitHub URL.
pub fn github_slug(repo_url: &str) -> Option<(String, String)> {
    let rest = repo_url
        .strip_prefix("https://github.com/")?
        .trim_end_matches('/')
        .trim_end_matches(".git");
    let mut parts = rest.split('/');
    let owner = parts.next()?.to_string();
    let name = parts.next()?.to_string();
    (!owner.is_empty() && !name.is_empty()).then_some((owner, name))
}

/// The commit a version's tag points at, and which spelling matched.
///
/// Unauthenticated GitHub allows 60 requests an hour, which is nothing at fleet scale. `GITHUB_TOKEN`
/// raises it to 5,000, and a sweep without one will spend most of its time rate-limited rather than
/// building. Said here because the failure looks like flakiness rather than like a missing token.
pub async fn resolve_version_tag(
    client: &Client,
    repo_url: &str,
    version: &str,
) -> Option<(String, String, SourceDiscovery)> {
    let (owner, repo) = github_slug(repo_url)?;

    for (tag, how) in [
        (version.to_string(), SourceDiscovery::ExactTag),
        (format!("v{version}"), SourceDiscovery::PrefixedTag),
    ] {
        match peel(client, &owner, &repo, &tag).await {
            Ok(Some(sha)) => return Some((sha, tag, how)),
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(repo = repo_url, tag, "resolving the tag failed: {e}");
                return None;
            }
        }
    }
    tracing::debug!(repo = repo_url, version, "no tag matches this version");
    None
}

/// The commit a tag ultimately points at.
///
/// Annotated tags point at a tag object, not a commit, and using that object's SHA as a commit
/// gives a checkout that fails with an unhelpful error. So a tag object is dereferenced once.
async fn peel(
    client: &Client,
    owner: &str,
    repo: &str,
    tag: &str,
) -> Result<Option<String>, RegistryError> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{tag}");
    let doc: Value = match client.get(&url, ECO).await {
        Ok(r) => r.json().await?,
        Err(RegistryError::Http { status: 404, .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    let object = doc.get("object");
    let sha = object
        .and_then(|o| o.get("sha"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let kind = object.and_then(|o| o.get("type")).and_then(Value::as_str);

    match (sha, kind) {
        (Some(sha), Some("commit")) => Ok(Some(sha)),
        (Some(sha), Some("tag")) => {
            let url = format!("https://api.github.com/repos/{owner}/{repo}/git/tags/{sha}");
            let doc: Value = client.get(&url, ECO).await?.json().await?;
            Ok(doc
                .get("object")
                .and_then(|o| o.get("sha"))
                .and_then(Value::as_str)
                .map(str::to_owned))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::github_slug;

    #[test]
    fn a_github_url_yields_its_slug() {
        assert_eq!(
            github_slug("https://github.com/stevemao/left-pad"),
            Some(("stevemao".into(), "left-pad".into()))
        );
        assert_eq!(
            github_slug("https://github.com/python-trio/sniffio/"),
            Some(("python-trio".into(), "sniffio".into()))
        );
    }

    #[test]
    fn another_forge_yields_nothing_rather_than_a_guess() {
        assert_eq!(github_slug("https://gitlab.com/a/b"), None);
        assert_eq!(github_slug("https://github.com/onlyowner"), None);
    }
}
