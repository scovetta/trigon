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
        "upstream redirected to `{found}`, which is not a URL this mirror can resolve or check. A \
         destination we cannot name is a destination we cannot put on an allowlist, so it is \
         refused rather than followed."
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
            MirrorError::Bind { .. } => 500,
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
            MirrorError::Bind { .. } => Fault::Infra,
            // A policy this run is enforcing, not a broken package and not broken infrastructure.
            MirrorError::Refused { .. } => Fault::Policy,
            // **Ours.** A path shape this mirror does not serve means we told a client to ask for
            // something we do not answer — a strategy pointing at the wrong route, not a package
            // doing anything wrong.
            MirrorError::NotFound { .. } => Fault::Bug,
        }
    }
}
