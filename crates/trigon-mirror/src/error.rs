use thiserror::Error;
use trigon_core::{Classify, Fault};

#[derive(Debug, Error)]
pub enum MirrorError {
    #[error(
        "no time filter on this request. The mirror is addressed as \
         http://<platform>:<RFC3339>@<host>/, and a request without one would be served the index \
         as it is today, which is the opposite of what this exists for."
    )]
    NoFilter,

    #[error("unknown platform `{found}`; this mirror serves npm and pypi")]
    UnknownPlatform { found: String },

    #[error("`{found}` is not an RFC 3339 instant this mirror can compare")]
    BadMoment { found: String },

    #[error("upstream {platform} answered {status}")]
    Upstream { platform: String, status: u16 },

    #[error(
        "the cache directory could not be opened: {0}. A cache is an optimisation and never a \
         reason to serve a build wrong, so this refuses at startup rather than quietly running \
         without one — a sweep that thinks it is caching and is not looks like a slow machine."
    )]
    Cache(#[source] std::io::Error),

    #[error("upstream {platform} returned {content_type}, which cannot be filtered by date")]
    Unfilterable {
        platform: String,
        content_type: String,
    },

    #[error(
        "refusing {url}: it is the artifact this run is trying to reproduce. A build that can \
         download its own published output reproduces it perfectly and proves nothing."
    )]
    Refused { url: String },

    #[error(
        "`{path}` is not a shape this mirror serves. It answers a NuGet service index at \
         `/-nuget/<moment>/index.json`, a registration at `/-nuget/<moment>/reg/<id>/index.json`, \
         and the flat container under `/-nuget/<moment>/flat/`."
    )]
    NotFound { path: String },

    #[error(
        "refusing to proxy `{host}` on the `{route}` route. Every route this mirror serves is an \
         allowlist of hosts chosen here rather than by the package under test, and widening one is \
         an edit to `trigon-mirror` rather than a runtime decision: at mirror-only egress this \
         proxy is the build's only route out, so any host reachable through it is a host the build \
         can be told to fetch from."
    )]
    HostNotAllowed { host: String, route: &'static str },

    #[error(
        "upstream redirected to `{found}`, which this mirror did not follow: it is not a URL the \
         mirror can resolve and check, or it comes after the last hop the mirror takes. A \
         destination we cannot name is a destination we cannot put on an allowlist, so it is \
         refused rather than followed, and never handed on: a build behind an enforced egress \
         boundary cannot follow a redirect itself."
    )]
    BadRedirect { found: String },

    #[error("could not listen on port {port}: {detail}")]
    Bind { port: u16, detail: String },

    #[error(transparent)]
    Transport(#[from] reqwest::Error),
}

impl MirrorError {
    /// The status a client should see.
    pub fn status(&self) -> u16 {
        match self {
            MirrorError::NoFilter
            | MirrorError::UnknownPlatform { .. }
            | MirrorError::BadMoment { .. } => 400,
            MirrorError::HostNotAllowed { .. } => 403,
            MirrorError::Upstream { status, .. } => *status,
            MirrorError::Unfilterable { .. } | MirrorError::BadRedirect { .. } => 502,
            MirrorError::Bind { .. } | MirrorError::Cache(_) => 500,
            MirrorError::Refused { .. } => 403,
            MirrorError::NotFound { .. } => 404,
            MirrorError::Transport(_) => 502,
        }
    }
}

impl Classify for MirrorError {
    fn fault(&self) -> Fault {
        match self {
            // A build configured the mirror wrongly, or asked for something it does not serve.
            MirrorError::NoFilter
            | MirrorError::UnknownPlatform { .. }
            | MirrorError::BadMoment { .. }
            | MirrorError::HostNotAllowed { .. } => Fault::Policy,
            MirrorError::Upstream { .. }
            | MirrorError::Unfilterable { .. }
            | MirrorError::BadRedirect { .. }
            | MirrorError::Transport(_) => Fault::Upstream,
            // Ours: a directory this machine could not open. Never the package's, and never the
            // registry's.
            MirrorError::Bind { .. } | MirrorError::Cache(_) => Fault::Infra,
            // A policy this run is enforcing, not a broken package and not broken infrastructure.
            MirrorError::Refused { .. } => Fault::Policy,
            // **Ours.** A path shape this mirror does not serve means we told a client to ask for
            // something we do not answer — a strategy pointing at the wrong route, not a package
            // doing anything wrong.
            MirrorError::NotFound { .. } => Fault::Bug,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whose fault each refusal is, and the status a client sees for it.
    ///
    /// The fault decides whose record a failure lands on. A registry's bad afternoon charged to
    /// the package reads as a package that does not build, and a path shape this mirror told a
    /// client to use and then does not serve is ours — never the package's, never the registry's.
    #[test]
    fn every_refusal_says_whose_fault_it_is_and_what_the_client_sees() {
        let cases = [
            (MirrorError::NoFilter, 400, Fault::Policy),
            (
                MirrorError::UnknownPlatform {
                    found: "maven".into(),
                },
                400,
                Fault::Policy,
            ),
            (
                MirrorError::BadMoment {
                    found: "yesterday".into(),
                },
                400,
                Fault::Policy,
            ),
            (
                MirrorError::HostNotAllowed {
                    host: "cdn.evil.example".into(),
                    route: "artifact",
                },
                403,
                Fault::Policy,
            ),
            (
                MirrorError::Refused {
                    url: "https://registry.npmjs.org/a/-/a-1.0.0.tgz".into(),
                },
                403,
                Fault::Policy,
            ),
            // Upstream's own status goes back to the client, so a 503 reads as a 503.
            (
                MirrorError::Upstream {
                    platform: "npm".into(),
                    status: 503,
                },
                503,
                Fault::Upstream,
            ),
            (
                MirrorError::Unfilterable {
                    platform: "pypi".into(),
                    content_type: "text/html".into(),
                },
                502,
                Fault::Upstream,
            ),
            (
                MirrorError::BadRedirect {
                    found: "http://[".into(),
                },
                502,
                Fault::Upstream,
            ),
            (
                MirrorError::Bind {
                    port: 8129,
                    detail: "address in use".into(),
                },
                500,
                Fault::Infra,
            ),
            (
                MirrorError::Cache(std::io::Error::other("read-only file system")),
                500,
                Fault::Infra,
            ),
            (
                MirrorError::NotFound {
                    path: "/-nuget/2020-01-01T00:00:00Z/nonsense".into(),
                },
                404,
                Fault::Bug,
            ),
        ];
        for (e, status, fault) in cases {
            assert_eq!((e.status(), e.fault()), (status, fault), "{e}");
        }
    }

    #[test]
    fn an_unfilterable_answer_names_what_upstream_sent() {
        let e = MirrorError::Unfilterable {
            platform: "pypi".into(),
            content_type: "text/html".into(),
        };
        assert_eq!(
            e.to_string(),
            "upstream pypi returned text/html, which cannot be filtered by date"
        );
    }
}
