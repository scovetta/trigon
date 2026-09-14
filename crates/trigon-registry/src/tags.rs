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

    let mut tried: Vec<(String, SourceDiscovery)> = vec![
        (version.to_string(), SourceDiscovery::ExactTag),
        (format!("v{version}"), SourceDiscovery::PrefixedTag),
    ];
    // Calendar versioning, zero-padded. PEP 440 normalizes a leading zero out of every numeric
    // component, so `certifi`'s tag `2026.07.22` reaches us as the version `2026.7.22` and neither
    // spelling above matches. The project is not doing anything unusual — it is what CalVer looks
    // like once a package manager has normalized it — and the run ends `no-strategy`, which reads
    // as "we could not infer a recipe" rather than "we could not find the tag".
    //
    // Only where padding changes the string, so an ordinary `1.2.3` adds no request.
    if let Some(padded) = zero_padded(version) {
        tried.push((padded.clone(), SourceDiscovery::ExactTag));
        tried.push((format!("v{padded}"), SourceDiscovery::PrefixedTag));
    }

    for (tag, how) in tried {
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

/// A calendar version with its month and day padded back to two digits.
///
/// `2026.7.22` becomes `2026.07.22`. `None` when nothing changes, so an ordinary version costs no
/// extra request.
///
/// **Only where the first component is a four-digit year.** The first version of this padded every
/// short numeric component and turned `1.2.3` into `01.02.03` — a tag no project has, requested on
/// every semver package in the corpus. Its own test caught it. CalVer is the only scheme where the
/// padding is real, because it is the only one where the components are dates and a date has a
/// canonical width.
///
/// Anything that is not purely digits passes through untouched, so a pre-release or `.postN` suffix
/// cannot be mangled into something nobody tagged.
fn zero_padded(version: &str) -> Option<String> {
    let mut parts = version.split('.');
    let year = parts.next()?;
    if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut out = vec![year.to_string()];
    for part in parts {
        if part.len() == 1 && part.chars().all(|c| c.is_ascii_digit()) {
            out.push(format!("0{part}"));
        } else {
            out.push(part.to_string());
        }
    }
    let joined = out.join(".");
    (joined != version).then_some(joined)
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
    #[test]
    fn a_calendar_version_matches_its_zero_padded_tag() {
        // PEP 440 normalizes a leading zero out of every numeric component, so `certifi`'s tag
        // `2026.07.22` reaches us as the version `2026.7.22` and neither the exact nor the
        // `v`-prefixed spelling matches. The run ended `no-strategy`, which reads as "no recipe
        // could be inferred" rather than "the tag is spelled differently".
        assert_eq!(
            super::zero_padded("2026.7.22").as_deref(),
            Some("2026.07.22")
        );
        assert_eq!(
            super::zero_padded("2026.4.22").as_deref(),
            Some("2026.04.22")
        );

        // `None` where nothing changes, so an ordinary version costs no extra request.
        assert_eq!(super::zero_padded("1.2.3"), None);
        assert_eq!(super::zero_padded("2026.10.22"), None);
        // The year is already wider than the padding and is left alone.
        assert_eq!(super::zero_padded("2026.07.22"), None);

        // Anything not purely digits passes through, so a pre-release cannot be mangled into a tag
        // nobody has.
        assert_eq!(super::zero_padded("1.2.3rc1"), None);
        assert_eq!(
            super::zero_padded("2026.7.22.post1").as_deref(),
            Some("2026.07.22.post1")
        );
    }

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
