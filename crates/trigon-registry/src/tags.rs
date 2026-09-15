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

use trigon_core::SourceDiscovery;

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
    repo_url: &str,
    version: &str,
) -> Option<(String, String, SourceDiscovery)> {
    // **Still GitHub only, and no longer because it has to be.** `ls-remote` works against any
    // https git URL, so this gate is now a deliberate restriction on what we claim rather than a
    // limit of the mechanism — widening it changes which targets resolve, which is a change to
    // measure on purpose rather than to slip in beside a corpus run.
    let _ = github_slug(repo_url)?;

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

    // **One `ls-remote`, not one API request per spelling.** The ladder below is unchanged — the
    // same spellings in the same order, so what resolves is what resolved before — but the question
    // is asked over git protocol, which is not subject to the API's 60-an-hour unauthenticated
    // limit. Measured at two API requests per PyPI target, a 200-target corpus needed about 400 and
    // would have exhausted its budget in minutes, reporting the remainder as `no-strategy`.
    //
    // The listing is fetched on a blocking thread because it is a subprocess; the API client's
    // pacing does not apply to it, and `ls-remote` against one repository is one connection.
    let url = repo_url.to_string();
    let tags =
        match tokio::task::spawn_blocking(move || crate::source::remote_tags(&url, false)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                tracing::warn!(repo = repo_url, "listing the repository's tags failed: {e}");
                return None;
            }
            Err(e) => {
                tracing::warn!(
                    repo = repo_url,
                    "listing the repository's tags panicked: {e}"
                );
                return None;
            }
        };

    for (tag, how) in tried {
        if let Some(sha) = tags.get(&tag) {
            return Some((sha.clone(), tag, how));
        }
    }
    tracing::debug!(
        repo = repo_url,
        version,
        known = tags.len(),
        "no tag matches this version"
    );
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
