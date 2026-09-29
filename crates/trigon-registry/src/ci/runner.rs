//! `runs-on` and `container:` to something we can build in, or to a stated reason we cannot.
//!
//! The rule from `docs/06` §2 and ADR-0009: the mapping is an **approximation**, recorded as one,
//! never an equality claim. A GitHub runner image carries several gigabytes of preinstalled
//! toolchains that `docker.io/library/ubuntu:24.04` does not, and the set changes weekly. What we
//! reproduce is the distribution release, and the rest is stated rather than implied.
//!
//! `ubuntu-latest` is the interesting case and the reason this file holds a dated table. Resolving
//! it means asking what the label pointed at when the artifact was published, which is a heuristic
//! and is recorded at `Confidence::Weak`. The rollout **windows** are the load-bearing part:
//! GitHub moves `-latest` to a percentage of runners over weeks, so a publish time inside a window
//! yields no mapping at all rather than a coin flip. During the window the label genuinely was
//! both, and a rebuild that picks one is describing a machine that may never have existed.

use trigon_core::Confidence;

use super::recipe::{BaseImageApprox, OutOfScope, RunnerSpec};

/// When `ubuntu-latest` pointed at which release.
///
/// `(release, settled_from, moves_away_from)` in RFC 3339 date order: the label resolved to
/// `release` for a publish time at or after `settled_from` and strictly before `moves_away_from`,
/// which is the start of the *next* release's rollout. A time falling between a
/// `moves_away_from` and the following `settled_from` is inside a rollout and resolves to nothing.
///
/// Dated static data that goes stale. It costs an assumption rather than a wrong verdict, because
/// it only ever produces `Confidence::Weak` and a gap produces no mapping at all.
/// Sourced from GitHub's `actions/runner-images` announcements. Last reviewed 2026-09-13.
const UBUNTU_LATEST_HISTORY: &[(&str, &str, &str)] = &[
    // 18.04 was `ubuntu-latest` from before anything we verify; the 20.04 rollout opened 2021-10-19.
    ("18.04", "2018-01-01", "2021-10-19"),
    ("20.04", "2021-12-01", "2022-11-08"),
    ("22.04", "2022-12-08", "2024-12-05"),
    // No upper bound yet. A publish time after the 24.04 rollout completed resolves to 24.04 until
    // someone adds the next row, which is the failure mode this table is allowed to have: it goes
    // stale in the direction of naming an older release, not in the direction of inventing one.
    ("24.04", "2025-01-17", "9999-01-01"),
];

/// Map one `runs-on` label onto a runner spec.
///
/// `publish_time` is the artifact's, as RFC 3339. Absent, `ubuntu-latest` resolves to nothing:
/// there is no moment to resolve the label against, and picking today's answer to explain a 2022
/// publish is the exact mistake the table exists to avoid.
pub fn map_label(label: &str, publish_time: Option<&str>) -> RunnerSpec {
    let l = label.trim().to_ascii_lowercase();

    if l.is_empty() {
        return RunnerSpec::OutOfScope(OutOfScope::UnknownLabel(label.to_string()));
    }
    if l == "self-hosted" || l.starts_with("self-hosted") {
        return RunnerSpec::OutOfScope(OutOfScope::SelfHosted);
    }
    if l.starts_with("macos") || l.starts_with("mac-") {
        return RunnerSpec::OutOfScope(OutOfScope::MacOs(label.to_string()));
    }
    if l.starts_with("windows") {
        return RunnerSpec::OutOfScope(OutOfScope::Windows(label.to_string()));
    }
    if !l.starts_with("ubuntu") {
        return RunnerSpec::OutOfScope(OutOfScope::UnknownLabel(label.to_string()));
    }
    // `ubuntu-24.04-arm`, `ubuntu-24.04-ppc64le`, `ubuntu-latest-arm64`. `pyca/cryptography` builds
    // on the first two. Mapping either onto an amd64 image would be a rebuild of a different
    // architecture reported as a rebuild of this one.
    for suffix in [
        "-arm", "-arm64", "-aarch64", "-ppc64le", "-s390x", "-riscv64",
    ] {
        if l.ends_with(suffix) {
            return RunnerSpec::OutOfScope(OutOfScope::NonX86(label.to_string()));
        }
    }

    // An explicit release. `ubuntu-slim` is a real label (vitejs/vite uses it) and names no
    // release, so it goes through the `-latest` path.
    if let Some(rest) = l.strip_prefix("ubuntu-")
        && rest
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && rest.contains('.')
    {
        return RunnerSpec::LinuxLabel {
            label: label.to_string(),
            approx: Some(BaseImageApprox {
                image: format!("docker.io/library/ubuntu:{rest}"),
                from_label: label.to_string(),
                confidence: Confidence::Strong,
                why: format!(
                    "`runs-on: {label}` names an Ubuntu release, mapped to the distribution image \
                     of the same release. The runner image's several gigabytes of preinstalled \
                     toolchains are not reproduced, and this is an approximation of the build \
                     environment rather than a claim of equality."
                ),
            }),
        };
    }

    if l == "ubuntu-latest" || l == "ubuntu-slim" || l.starts_with("ubuntu-latest") {
        let approx = publish_time
            .and_then(resolve_latest)
            .map(|release| BaseImageApprox {
                image: format!("docker.io/library/ubuntu:{release}"),
                from_label: label.to_string(),
                confidence: Confidence::Weak,
                // Weak, and the sentence says why: two guesses stacked, one about which release the
                // label pointed at and one about how close the distribution image is to the runner.
                why: format!(
                    "`runs-on: {label}` was resolved to Ubuntu {release} by checking the publish \
                     time against GitHub's label history, which is a heuristic, and then mapped to \
                     the distribution image of that release, which is an approximation."
                ),
            });
        return RunnerSpec::LinuxLabel {
            label: label.to_string(),
            approx,
        };
    }

    RunnerSpec::OutOfScope(OutOfScope::UnknownLabel(label.to_string()))
}

/// Which Ubuntu release `ubuntu-latest` pointed at at this instant, or nothing.
///
/// Date-prefix comparison on RFC 3339 strings. That is a real comparison rather than a shortcut:
/// RFC 3339 is lexicographically ordered within a timezone, and every publish timestamp we hold is
/// UTC (`Intrinsics::publish_time` is carried verbatim from a registry that emits `Z`). A
/// non-UTC offset would shift the answer by less than a day, and every boundary here is weeks wide.
fn resolve_latest(publish_time: &str) -> Option<&'static str> {
    let day = publish_time.get(..10)?;
    if day.len() != 10 || day.as_bytes()[4] != b'-' {
        return None;
    }
    for (release, from, until) in UBUNTU_LATEST_HISTORY {
        if day >= *from && day < *until {
            return Some(release);
        }
    }
    // Inside a rollout window, or before the table starts. Both mean "we do not know", and saying
    // so is worth more than a coin flip that looks like an answer.
    None
}

/// `container:` — the case where the workflow already did the pinning for us.
///
/// An image carrying `@sha256:` is not an approximation at all, and saying so is the point: a
/// digest-pinned container is the strongest runner statement a workflow can make, and `docs/06` §6
/// notes GitLab usually gets this right where GitHub does not.
pub fn map_container(image: &str) -> RunnerSpec {
    let image = image.trim().to_string();
    let digest = image
        .split_once("@sha256:")
        .map(|(_, d)| format!("sha256:{d}"));
    RunnerSpec::Container { image, digest }
}

impl RunnerSpec {
    /// The approximation to report, if there is one to report.
    pub fn approximation(&self) -> Option<&BaseImageApprox> {
        match self {
            RunnerSpec::LinuxLabel { approx, .. } => approx.as_ref(),
            _ => None,
        }
    }

    /// The platform this runner is, in the vocabulary `Claim::PlatformIs` uses.
    ///
    /// A Linux label carries `linux/amd64` and **not** the distribution release: the release is the
    /// approximation and it lives in `BaseImageApprox`, where it is labelled as one. Folding it
    /// into a `Claim` would launder a guess into a fact on its way to an attestation.
    pub fn platform(&self) -> Option<&'static str> {
        match self {
            RunnerSpec::LinuxLabel { .. } | RunnerSpec::Container { .. } => Some("linux/amd64"),
            RunnerSpec::OutOfScope(OutOfScope::MacOs(_)) => Some("macos"),
            RunnerSpec::OutOfScope(OutOfScope::Windows(_)) => Some("windows"),
            RunnerSpec::OutOfScope(_) => None,
        }
    }

    pub fn out_of_scope(&self) -> Option<&OutOfScope> {
        match self {
            RunnerSpec::OutOfScope(o) => Some(o),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(spec: &RunnerSpec) -> Option<(&str, Confidence)> {
        spec.approximation()
            .map(|a| (a.image.as_str(), a.confidence))
    }

    #[test]
    fn a_named_ubuntu_release_maps_to_that_distribution_at_strong() {
        let spec = map_label("ubuntu-22.04", None);
        assert_eq!(
            image(&spec),
            Some(("docker.io/library/ubuntu:22.04", Confidence::Strong))
        );
        assert_eq!(spec.platform(), Some("linux/amd64"));
        assert_eq!(spec.out_of_scope(), None);
        // Labelled as the approximation it is, not an equality.
        assert!(spec.approximation().unwrap().why.contains("approximation"));
        // Case and surrounding space are the author's, not a different label.
        assert_eq!(
            image(&map_label(" Ubuntu-24.04 ", None)),
            Some(("docker.io/library/ubuntu:24.04", Confidence::Strong))
        );
    }

    #[test]
    fn ubuntu_latest_is_what_it_pointed_at_on_the_day_and_nothing_inside_a_rollout() {
        for (when, want) in [
            ("2020-06-01T00:00:00Z", Some("18.04")),
            ("2022-01-10T00:00:00Z", Some("20.04")),
            ("2024-03-01T00:00:00Z", Some("22.04")),
            ("2026-01-01T00:00:00Z", Some("24.04")),
            // Inside the 20.04 -> 22.04 and 22.04 -> 24.04 rollouts: the label was both.
            ("2022-11-20T00:00:00Z", None),
            ("2024-12-20T00:00:00Z", None),
            // Before the table, or not a date: no moment to resolve against.
            ("2017-01-01T00:00:00Z", None),
            ("yesterday", None),
            ("2024/03/01", None),
        ] {
            let spec = map_label("ubuntu-latest", Some(when));
            let got = spec.approximation().map(|a| a.image.clone());
            assert_eq!(
                got,
                want.map(|r| format!("docker.io/library/ubuntu:{r}")),
                "{when}"
            );
            if let Some(a) = spec.approximation() {
                // Two guesses stacked, and the confidence says so.
                assert_eq!(a.confidence, Confidence::Weak);
                assert_eq!(a.from_label, "ubuntu-latest");
            }
            // Recognised as Linux either way: not knowing the release is not out of scope.
            assert_eq!(spec.platform(), Some("linux/amd64"), "{when}");
        }
        // No publish time at all resolves to nothing, rather than to today's answer.
        assert_eq!(map_label("ubuntu-latest", None).approximation(), None);
        // `ubuntu-slim` names no release and goes the same way.
        assert_eq!(
            image(&map_label("ubuntu-slim", Some("2026-01-01T00:00:00Z"))),
            Some(("docker.io/library/ubuntu:24.04", Confidence::Weak))
        );
    }

    #[test]
    fn a_runner_we_do_not_build_on_is_out_of_scope_with_its_reason() {
        for (label, want) in [
            ("macos-14", OutOfScope::MacOs("macos-14".into())),
            ("mac-studio", OutOfScope::MacOs("mac-studio".into())),
            ("windows-2022", OutOfScope::Windows("windows-2022".into())),
            ("self-hosted", OutOfScope::SelfHosted),
            ("self-hosted-gpu", OutOfScope::SelfHosted),
            (
                "ubuntu-24.04-arm",
                OutOfScope::NonX86("ubuntu-24.04-arm".into()),
            ),
            (
                "ubuntu-latest-arm64",
                OutOfScope::NonX86("ubuntu-latest-arm64".into()),
            ),
            (
                "ubuntu-24.04-ppc64le",
                OutOfScope::NonX86("ubuntu-24.04-ppc64le".into()),
            ),
            ("", OutOfScope::UnknownLabel(String::new())),
            (
                "buildjet-4vcpu",
                OutOfScope::UnknownLabel("buildjet-4vcpu".into()),
            ),
            (
                "ubuntu-jammy",
                OutOfScope::UnknownLabel("ubuntu-jammy".into()),
            ),
            ("ubuntu-22", OutOfScope::UnknownLabel("ubuntu-22".into())),
        ] {
            let spec = map_label(label, Some("2024-03-01T00:00:00Z"));
            assert_eq!(spec.out_of_scope(), Some(&want), "{label:?}");
            assert_eq!(spec.approximation(), None, "{label:?}");
        }
        // A macOS or Windows runner is still a platform worth claiming; the rest are not.
        assert_eq!(map_label("macos-14", None).platform(), Some("macos"));
        assert_eq!(
            map_label("windows-latest", None).platform(),
            Some("windows")
        );
        assert_eq!(map_label("ubuntu-24.04-arm", None).platform(), None);
        assert_eq!(map_label("self-hosted", None).platform(), None);
    }

    #[test]
    fn a_container_pinned_by_digest_says_so_and_a_tag_does_not() {
        assert_eq!(
            map_container(" python:3.12@sha256:0123abcd "),
            RunnerSpec::Container {
                image: "python:3.12@sha256:0123abcd".into(),
                digest: Some("sha256:0123abcd".into()),
            }
        );
        let tagged = map_container("node:20");
        assert_eq!(
            tagged,
            RunnerSpec::Container {
                image: "node:20".into(),
                digest: None,
            }
        );
        // A container is not an approximation of a runner: it is the environment itself.
        assert_eq!(tagged.approximation(), None);
        assert_eq!(tagged.platform(), Some("linux/amd64"));
        assert_eq!(tagged.out_of_scope(), None);
    }
}
