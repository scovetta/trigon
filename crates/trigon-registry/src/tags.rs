//! Resolving a version to a commit, for registries that do not record one.
//!
//! npm publishes `gitHead` and needs none of this. PyPI, crates.io and RubyGems do not, so for them
//! a version has to be matched against the repository's tags. This is the cheap end of the ladder
//! in `docs/07-ai.md` §2: an exact tag, then the conventional `v` prefix, then a prefixed tag whose
//! remainder is the version exactly. The expensive rung, scoring date-windowed candidates by tree
//! hash against the published sdist, comes later and is worth more than any prompt.
//!
//! All three are answered from one `ls-remote`, so the third costs nothing. It used to be the
//! expensive one — a request per spelling against the GitHub API — and the note saying so outlived
//! the change that made the whole tag list arrive at once.
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
    package: &str,
) -> Option<(String, String, SourceDiscovery)> {
    // **Still GitHub only, and no longer because it has to be.** `ls-remote` works against any
    // https git URL, so this gate is now a deliberate restriction on what we claim rather than a
    // limit of the mechanism — widening it changes which targets resolve, which is a change to
    // measure on purpose rather than to slip in beside a corpus run.
    let _ = github_slug(repo_url)?;

    let spellings = spellings(version);
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

    let names: Vec<&str> = tags.keys().map(String::as_str).collect();
    let (tag, how) = pick_tag(&names, &spellings, package).or_else(|| {
        tracing::debug!(
            repo = repo_url,
            version,
            known = tags.len(),
            "no tag matches this version"
        );
        None
    })?;
    let sha = tags.get(&tag)?.clone();
    Some((sha, tag, how))
}

/// The spellings of a version that a tag might use, in the order they are believed.
///
/// The exact string first, then the conventional `v` prefix, then the same two for a zero-padded
/// calendar version. PEP 440 normalizes a leading zero out of every numeric component, so
/// `certifi`'s tag `2026.07.22` reaches us as the version `2026.7.22` and neither of the first two
/// matches. The project is not doing anything unusual — it is what CalVer looks like once a
/// package manager has normalized it.
fn spellings(version: &str) -> Vec<(String, SourceDiscovery)> {
    let mut out = vec![
        (version.to_string(), SourceDiscovery::ExactTag),
        (format!("v{version}"), SourceDiscovery::PrefixedTag),
    ];
    if let Some(padded) = zero_padded(version) {
        out.push((padded.clone(), SourceDiscovery::ExactTag));
        out.push((format!("v{padded}"), SourceDiscovery::PrefixedTag));
    }
    out
}

/// The tag this version was released under, out of everything the repository has.
///
/// Three rungs, and the third is new. The first two are the spellings above, matched exactly.
/// The third is what the corpus said was missing: of fifteen PyPI targets that resolved a
/// repository and still found no commit, three had a tag for exactly that version under a name
/// this function could not see —
///
/// | package | version | tag |
/// |---|---|---|
/// | `ecdsa` | 0.19.2 | `python-ecdsa-0.19.2` |
/// | `xlsxwriter` | 3.2.9 | `RELEASE_3.2.9` |
/// | `azure-storage-blob` | 12.28.0 | `azure-storage-blob_12.28.0` |
///
/// So: a tag matches if removing a prefix leaves the version exactly. **Prefix only.** Stripping a
/// suffix too would make `1.2.3-rc1` match `1.2.3`, which is a different release, and the whole
/// value of this rung is that it does not guess.
///
/// The prefix has to end at a separator (`-`, `_`, `/`, `.`) so `1.2.30` cannot match `1.2.3` by
/// treating `1.2.3` as a prefix of itself — the exact-equality check on the remainder already
/// prevents that, and the separator rule prevents the subtler `beta-1.2.3`-style near-misses from
/// matching a *numeric* prefix.
///
/// Where several tags match — the monorepo case, where `azure-storage-blob_12.28.0` sits beside a
/// hundred other `azure-*_12.28.0` — the package name breaks the tie, and only the package name.
/// If it does not, this returns `None`: `docs/07-ai.md` §2 is that a wrong commit is worse than no
/// commit, and choosing between two tags on anything else would be choosing on tag ordering.
fn pick_tag(
    tags: &[&str],
    spellings: &[(String, SourceDiscovery)],
    package: &str,
) -> Option<(String, SourceDiscovery)> {
    for (spelling, how) in spellings {
        if tags.contains(&spelling.as_str()) {
            return Some((spelling.clone(), *how));
        }
    }

    let mut matched: Vec<&str> = Vec::new();
    for tag in tags {
        for (spelling, _) in spellings {
            let Some(prefix) = tag.strip_suffix(spelling.as_str()) else {
                continue;
            };
            if prefix.is_empty() {
                continue; // Handled exactly above.
            }
            if prefix.ends_with(['-', '_', '/', '.']) {
                matched.push(tag);
                break;
            }
        }
    }
    match matched.as_slice() {
        [] => None,
        [one] => Some(((*one).to_string(), SourceDiscovery::FuzzyTag)),
        several => {
            let wanted = squash(package);
            let named: Vec<&&str> = several
                .iter()
                .filter(|t| squash(t).contains(&wanted))
                .collect();
            match named.as_slice() {
                [one] => Some(((**one).to_string(), SourceDiscovery::FuzzyTag)),
                _ => {
                    tracing::debug!(
                        package,
                        candidates = ?several,
                        "several tags match this version and the package name does not choose \
                         between them"
                    );
                    None
                }
            }
        }
    }
}

/// A name with its separators removed and its case flattened, so `python-ecdsa` contains `ecdsa`
/// and `azure_storage_blob` contains `azure-storage-blob`.
fn squash(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
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

    use super::{SourceDiscovery, pick_tag, spellings};

    fn pick(tags: &[&str], version: &str, package: &str) -> Option<(String, SourceDiscovery)> {
        pick_tag(tags, &spellings(version), package)
    }

    #[test]
    fn a_project_that_puts_its_own_name_in_front_of_the_version_is_still_tagged() {
        // Three real repositories, and between them three of the fifteen PyPI targets that
        // resolved a repository and still ended `no-strategy`. Each has a tag for exactly the
        // version under test; none of them spells it the two ways this resolver could see.
        for (tags, version, package, want) in [
            (
                &["python-ecdsa-0.19.1", "python-ecdsa-0.19.2"][..],
                "0.19.2",
                "ecdsa",
                "python-ecdsa-0.19.2",
            ),
            (
                &["RELEASE_3.2.8", "RELEASE_3.2.9"][..],
                "3.2.9",
                "xlsxwriter",
                "RELEASE_3.2.9",
            ),
            (&["release/2.1.0"][..], "2.1.0", "anything", "release/2.1.0"),
        ] {
            assert_eq!(
                pick(tags, version, package),
                Some((want.to_string(), SourceDiscovery::FuzzyTag)),
                "{package} {version}"
            );
        }
    }

    #[test]
    fn an_exact_tag_still_wins_and_is_still_called_exact() {
        // The new rung is the *last* one. A repository that tags plainly must not start reporting
        // its commits as fuzzily matched, because the discovery kind reaches the attestation.
        let tags = &["1.2.3", "v1.2.3", "mypkg-1.2.3"];
        assert_eq!(
            pick(tags, "1.2.3", "mypkg"),
            Some(("1.2.3".into(), SourceDiscovery::ExactTag))
        );
        assert_eq!(
            pick(&["v1.2.3", "mypkg-1.2.3"], "1.2.3", "mypkg"),
            Some(("v1.2.3".into(), SourceDiscovery::PrefixedTag))
        );
    }

    #[test]
    fn the_package_name_is_the_only_thing_that_breaks_a_tie() {
        // The Azure SDK monorepo tags every package at every release, so a hundred tags end in the
        // same version string. Exactly one of them is about this package.
        let tags = &[
            "azure-storage-blob_12.28.0",
            "azure-storage-file-share_12.28.0",
            "azure-identity_12.28.0",
        ];
        assert_eq!(
            pick(tags, "12.28.0", "azure-storage-blob"),
            Some((
                "azure-storage-blob_12.28.0".to_string(),
                SourceDiscovery::FuzzyTag
            ))
        );
        // And where it does not choose, nothing does. A wrong commit is worse than no commit, and
        // picking the first would be picking on tag ordering.
        assert_eq!(pick(tags, "12.28.0", "unrelated"), None);
    }

    #[test]
    fn a_neighbouring_version_is_not_this_version() {
        // The failure this rung must not have. Each of these shares a prefix or a suffix with
        // `1.2.3` and is a different release.
        for tag in [
            "1.2.30",
            "v1.2.30",
            "pkg-1.2.30",
            "1.2.3-rc1",
            "pkg-1.2.3-rc1",
            "1.2.3.post1",
            "11.2.3",
        ] {
            assert_eq!(pick(&[tag], "1.2.3", "pkg"), None, "{tag}");
        }
        // A prefix that is not separated is not a prefix: `x1.2.3` is a tag about something else.
        assert_eq!(pick(&["x1.2.3"], "1.2.3", "pkg"), None);
    }

    #[test]
    fn a_calendar_version_is_matched_under_a_prefix_too() {
        // The two corrections compose: the tag is both padded and prefixed.
        assert_eq!(
            pick(&["certifi-2026.07.22"], "2026.7.22", "certifi"),
            Some(("certifi-2026.07.22".into(), SourceDiscovery::FuzzyTag))
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
