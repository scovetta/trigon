//! Which .NET SDK to build a NuGet package with.
//!
//! **NuGet publishes no compiler version.** The rung records that as an assumption on every target
//! it infers, and ADR-0012's correction of 2026-09-19 is the consequence: nothing pins the SDK, so
//! an image has to supply one and the only question is which. A constant was the first answer and
//! it is wrong twice over — too new for an old package, too old for a new one.
//!
//! Two pieces of evidence narrow it, and neither is a guess:
//!
//! 1. **What the project declares.** A `.csproj` naming `<TargetFramework>net8.0</TargetFramework>`
//!    cannot be built by an SDK older than 8. The SDK says so itself, precisely — `NETSDK1045`,
//!    which this repository classifies as `env/dotnet-sdk-too-old` and captures the wanted version
//!    from. That is a floor.
//! 2. **When the package was published.** An SDK released in November 2025 cannot have built a
//!    package published in 2022. The publish instant is already in the strategy as
//!    `registry_time`, put there for the dependency timewarp; this is the same evidence applied to
//!    the toolchain instead of to the index. That is a ceiling.
//!
//! Neither is certain and the run says so: whatever is chosen lands in the report's assumptions
//! with the reason, because a divergence in a compiled assembly is as likely to be the toolchain as
//! the source — which is what the NuGet rung's own assumption has always said.

/// .NET major versions and the month they shipped.
///
/// **Months, not days, and deliberately.** The question this answers is "could this SDK have built
/// a package published on that date", and a month is enough for it. Day precision I have not
/// verified would be a number that looks more exact than the thing it is made of.
///
/// Sources: `learn.microsoft.com/dotnet/core/releases-and-support`, which states .NET 8 released
/// November 2023 and .NET 9 November 2024, and the annual November cadence from .NET 5 onward.
/// .NET Core's own majors are the earlier entries. `4` is absent because there is no .NET 4: the
/// number was skipped to avoid confusion with .NET Framework 4.x.
const RELEASES: &[(u32, &str)] = &[
    (2, "2017-08"),
    (3, "2019-09"),
    (5, "2020-11"),
    (6, "2021-11"),
    (7, "2022-11"),
    (8, "2023-11"),
    (9, "2024-11"),
    (10, "2025-11"),
];

/// The SDK major the project's declared target frameworks require, if any.
///
/// Only `netN.0` moniker forms carry a floor. `netstandard2.0` is a standard many SDKs implement,
/// `net48` and `portable-net45+…` are .NET Framework targets that modern SDKs still build, and none
/// of the three says an SDK is too old. The highest wins: a project multi-targeting `net6.0;net8.0`
/// needs an SDK that can do both, which is 8.
pub fn floor_from_project(text: &str) -> Option<u32> {
    let mut best = None;
    for tag in ["<TargetFramework>", "<TargetFrameworks>"] {
        let mut rest = text;
        while let Some(at) = rest.find(tag) {
            let after = &rest[at + tag.len()..];
            let Some(end) = after.find('<') else { break };
            for moniker in after[..end].split(';') {
                let m = moniker.trim();
                // `net8.0`, `net10.0`, and `net8.0-windows` — the platform suffix does not change
                // which SDK is needed.
                let Some(digits) = m.strip_prefix("net") else {
                    continue;
                };
                let Some((major, tail)) = digits.split_once('.') else {
                    continue;
                };
                // `net4.8` is .NET Framework and is not an SDK major. The tail of a real moniker is
                // `0` or `0-something`; Framework's is a second digit.
                if !tail.starts_with('0') {
                    continue;
                }
                if let Ok(n) = major.parse::<u32>()
                    && n >= 5
                    && best.is_none_or(|b| n > b)
                {
                    best = Some(n);
                }
            }
            rest = &after[end..];
        }
    }
    best
}

/// The newest SDK major that existed when `published` happened.
///
/// `published` is an RFC 3339 instant — the strategy's `registry_time`. Compared as a string
/// because both sides start `YYYY-MM`, which orders correctly without a date library; the
/// repository already carries five copies of the civil-calendar arithmetic and this needs none.
pub fn ceiling_at(published: &str) -> Option<u32> {
    RELEASES
        .iter()
        .filter(|(_, when)| published >= *when)
        .map(|(major, _)| *major)
        .next_back()
}

/// The image tag to build with, and the sentence explaining it.
///
/// The sentence goes into the run's assumptions. A reader of a divergence has to be able to see
/// which SDK produced it and why that one, because "the toolchain" is the first thing to suspect in
/// a compiled ecosystem and the second thing they cannot check without this.
pub fn choose(project: Option<&str>, published: Option<&str>) -> (u32, String) {
    let floor = project.and_then(floor_from_project);
    let ceiling = published.and_then(ceiling_at);
    let newest = RELEASES.last().map(|(m, _)| *m).unwrap_or(9);

    match (floor, ceiling) {
        // The project names what it needs. Trust it: an SDK older than this cannot build the
        // project at all, and one much newer changes more than it has to.
        (Some(f), Some(c)) if f <= c => (
            f,
            format!(
                "the project declares a .NET {f} target framework and the package was published \
                 when .NET {c} was the newest SDK available, so this builds with the SDK matching \
                 the declared target rather than the newest one"
            ),
        ),
        // The project targets something newer than anything that existed when it was published.
        // Possible — a preview SDK — and worth saying out loud rather than silently overriding.
        (Some(f), Some(c)) => (
            f,
            format!(
                "the project declares a .NET {f} target framework, which is newer than .NET {c}, \
                 the newest SDK released when this package was published. Building with {f} \
                 anyway, because nothing older can build the project; the publisher used a preview \
                 SDK or the recorded publish instant is not when the bytes were made"
            ),
        ),
        (Some(f), None) => (
            f,
            format!(
                "the project declares a .NET {f} target framework, and this run records no publish \
                 instant to bound the choice from above"
            ),
        ),
        // No declared framework — a `netstandard` or .NET Framework project, or no checkout to read
        // one from. The publish date is then the only evidence there is.
        (None, Some(c)) => (
            c,
            format!(
                "no .NET target framework was readable for this project, so this builds with .NET \
                 {c}, the newest SDK that existed when the package was published"
            ),
        ),
        (None, None) => (
            newest,
            format!(
                "neither a declared target framework nor a publish instant was available, so this \
                 builds with .NET {newest} — the newest this tool knows of, and a guess"
            ),
        ),
    }
}

/// The SDK image for a major version.
///
/// **Not every major has a `.0` tag, and the two that do not are the old ones.** .NET Core 2.0 and
/// 3.0 were superseded within months by 2.1 and 3.1, and Microsoft's registry keeps only the
/// survivors: `mcr.microsoft.com/dotnet/sdk:3.0` is `manifest unknown`, while `3.1` and `2.1` are
/// both there. Every major from 5 onward tags `.0`.
///
/// Found by a package published in 2019 choosing .NET 3 correctly and then failing to pull it,
/// which is the right failure in the wrong place: the version was right and the reference was not.
pub fn image_for(major: u32) -> String {
    let minor = match major {
        2 | 3 => 1,
        _ => 0,
    };
    format!("mcr.microsoft.com/dotnet/sdk:{major}.{minor}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declared_target_framework_is_a_floor() {
        assert_eq!(
            floor_from_project("<TargetFramework>net8.0</TargetFramework>"),
            Some(8)
        );
        // Multi-targeting needs the SDK that can do all of them.
        assert_eq!(
            floor_from_project("<TargetFrameworks>net6.0;net8.0;netstandard2.0</TargetFrameworks>"),
            Some(8)
        );
        // A platform suffix does not change which SDK is needed.
        assert_eq!(
            floor_from_project("<TargetFramework>net10.0-windows</TargetFramework>"),
            Some(10)
        );
    }

    #[test]
    fn what_is_not_a_floor_is_not_mistaken_for_one() {
        // `netstandard` is a standard many SDKs implement, and .NET Framework monikers are built by
        // modern SDKs. Reading either as "needs SDK 2" or "needs SDK 4" would pick an SDK that
        // cannot build anything.
        assert_eq!(
            floor_from_project("<TargetFramework>netstandard2.0</TargetFramework>"),
            None
        );
        assert_eq!(
            floor_from_project("<TargetFramework>net48</TargetFramework>"),
            None
        );
        assert_eq!(
            floor_from_project("<TargetFramework>net4.8</TargetFramework>"),
            None,
            "net4.8 is .NET Framework, not an SDK major"
        );
        assert_eq!(
            floor_from_project("<TargetFrameworks>portable-net45+win8+wpa81</TargetFrameworks>"),
            None
        );
        assert_eq!(floor_from_project("no project here"), None);
    }

    #[test]
    fn an_sdk_released_after_a_package_could_not_have_built_it() {
        // The whole of the second mechanism: a package published in 2022 was built with something
        // that existed in 2022.
        assert_eq!(ceiling_at("2022-06-01T00:00:00Z"), Some(6));
        assert_eq!(ceiling_at("2023-01-15T12:00:00Z"), Some(7));
        assert_eq!(ceiling_at("2026-09-19T00:00:00Z"), Some(10));
        // Before .NET Core existed at all.
        assert_eq!(ceiling_at("2016-01-01T00:00:00Z"), None);
        // The boundary is the release month itself, not the month after.
        assert_eq!(ceiling_at("2023-11-01T00:00:00Z"), Some(8));
        assert_eq!(ceiling_at("2023-10-31T23:59:59Z"), Some(7));
    }

    #[test]
    fn the_releases_are_ordered_and_skip_the_version_that_does_not_exist() {
        // `ceiling_at` takes the last match, which is only the newest if the table is ordered.
        for w in RELEASES.windows(2) {
            assert!(w[0].0 < w[1].0, "{:?} then {:?}", w[0], w[1]);
            assert!(w[0].1 < w[1].1, "{:?} then {:?}", w[0], w[1]);
        }
        // There is no .NET 4: the number was skipped to avoid confusion with .NET Framework 4.x.
        assert!(!RELEASES.iter().any(|(m, _)| *m == 4));
        // The two the Microsoft lifecycle page states outright.
        assert!(RELEASES.contains(&(8, "2023-11")));
        assert!(RELEASES.contains(&(9, "2024-11")));
    }

    #[test]
    fn the_declared_target_wins_where_it_is_available() {
        let (major, why) = choose(
            Some("<TargetFramework>net6.0</TargetFramework>"),
            Some("2026-01-01T00:00:00Z"),
        );
        assert_eq!(major, 6, "a net6.0 project builds with the SDK it names");
        assert!(why.contains("declares a .NET 6"), "{why}");
        assert!(why.contains("rather than the newest"), "{why}");
    }

    #[test]
    fn a_target_newer_than_the_publish_date_is_said_out_loud() {
        // QuestPDF's shape: .NET 10 declared. If the publish instant predates .NET 10 the two
        // pieces of evidence disagree, and silently preferring one would hide that.
        let (major, why) = choose(
            Some("<TargetFramework>net10.0</TargetFramework>"),
            Some("2024-01-01T00:00:00Z"),
        );
        assert_eq!(major, 10, "nothing older can build the project");
        // January 2024: .NET 8 is the newest that had shipped, because 9 is that November.
        assert!(why.contains("newer than .NET 8"), "{why}");
        assert!(why.contains("preview"), "{why}");
    }

    #[test]
    fn with_no_declared_framework_the_publish_date_decides() {
        let (major, why) = choose(
            Some("<TargetFramework>netstandard2.0</TargetFramework>"),
            Some("2019-06-01T00:00:00Z"),
        );
        assert_eq!(
            major, 2,
            ".NET Core 3.0 shipped that September, so 2 is the newest here"
        );
        assert!(
            why.contains("no .NET target framework was readable"),
            "{why}"
        );
    }

    #[test]
    fn knowing_nothing_is_a_guess_and_says_so() {
        let (_, why) = choose(None, None);
        assert!(why.contains("a guess"), "{why}");
    }

    #[test]
    fn the_image_reference_is_the_one_microsoft_publishes() {
        assert_eq!(image_for(9), "mcr.microsoft.com/dotnet/sdk:9.0");
        assert_eq!(image_for(10), "mcr.microsoft.com/dotnet/sdk:10.0");
        // The two majors whose `.0` tag does not exist. `sdk:3.0` answers `manifest unknown`;
        // .NET Core 3.0 and 2.0 were each superseded within months and the registry keeps the
        // survivor. Verified against the registry, not assumed.
        assert_eq!(image_for(3), "mcr.microsoft.com/dotnet/sdk:3.1");
        assert_eq!(image_for(2), "mcr.microsoft.com/dotnet/sdk:2.1");
    }
}
