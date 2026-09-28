use thiserror::Error;
use trigon_core::{Classify, Fault};

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("{ecosystem} has no package `{name}`")]
    NoSuchPackage { ecosystem: String, name: String },

    #[error(
        "{ecosystem} has no version `{version}` of `{name}`{}",
        suggestion(available)
    )]
    NoSuchVersion {
        ecosystem: String,
        name: String,
        version: String,
        available: Vec<String>,
    },

    #[error(
        "version {version} of {name} has no artifact named `{wanted}`. It has: {}",
        available.join(", ")
    )]
    NoSuchArtifact {
        name: String,
        version: String,
        wanted: String,
        available: Vec<String>,
    },

    #[error("could not read the source at {repo}: {detail}")]
    Source { repo: String, detail: String },

    /// A repository reference this will not act on, as opposed to one that failed.
    ///
    /// Separate because the two want different handling and the difference is not visible in the
    /// message: a fetch that broke may work on the next attempt, and a URL we declined to hand to
    /// `git` will be declined every time.
    #[error("refusing to read the source at `{repo}`: {detail}")]
    SourceRefused { repo: String, detail: String },

    /// Bytes that do not match a digest the registry declared for them.
    ///
    /// Boxed because it carries six strings, and inline they would make every
    /// `Result<_, RegistryError>` in the crate that wide, on the path that succeeds as much as on
    /// this one, which is rare.
    #[error("{0}")]
    DigestMismatch(Box<DigestMismatch>),

    /// A catalog document that could not be read, where it is the only place the artifact's digest
    /// is declared: NuGet's registration index, one of its pages, or a catalog leaf.
    ///
    /// Its own variant rather than the failure inside it, because the message has to say what was
    /// at stake. Whether the package declares a digest is then unknown, and recording that as "the
    /// catalog declared none" is the absence-read-as-a-fact error `docs/19` §4.2 warns about.
    /// Classified as the failure inside it, so a busy catalog is retried and a 404 is not.
    #[error(
        "could not read {what}: {cause}. Whether the catalog declares a `packageHash` for this \
         package is therefore unknown, and it is not fetched unchecked, which would record a \
         catalog nobody read as one that declared nothing. Try again once the catalog answers."
    )]
    CatalogUnreadable {
        what: String,
        cause: Box<RegistryError>,
    },

    #[error("{ecosystem} answered {status} for {url}")]
    Http {
        ecosystem: String,
        url: String,
        status: u16,
    },

    #[error("{ecosystem} is rate-limiting us{}", retry_hint(retry_after_s))]
    RateLimited {
        ecosystem: String,
        retry_after_s: Option<u64>,
    },

    #[error("{ecosystem} returned something unexpected for {what}: {detail}")]
    Malformed {
        ecosystem: String,
        what: String,
        detail: String,
    },

    #[error("trigon does not speak {ecosystem}; this build knows {supported}")]
    Unsupported {
        ecosystem: String,
        supported: String,
    },

    #[error(transparent)]
    Transport(#[from] reqwest::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// What [`RegistryError::DigestMismatch`] says: bytes that do not match a digest the registry
/// declared for them.
///
/// Names the algorithm and both values, because "the digest did not match" with neither is a
/// sentence nobody can act on: whoever reads it has to tell a registry serving other bytes from
/// metadata declaring the wrong digest, and the two values are how.
#[derive(Debug, Error)]
#[error(
    "{ecosystem} declares {algorithm} {declared} for {artifact} (`{field}`), and the bytes we \
     fetched hash to {computed}. Refusing: a run against bytes the registry does not vouch for \
     proves nothing about what it published. Retrying will not change this unless whatever \
     served the bytes, or the metadata, changes; compare them with a download from another \
     network to tell which is wrong."
)]
pub struct DigestMismatch {
    pub ecosystem: String,
    pub artifact: String,
    pub algorithm: String,
    /// The field the declaration came from, as `<ecosystem>:<field>`. Not `source`, which
    /// `thiserror` reads as the error this one wraps.
    pub field: String,
    pub declared: String,
    pub computed: String,
}

fn suggestion(available: &[String]) -> String {
    if available.is_empty() {
        return String::new();
    }
    // The nearest few, not all of them. A package with 800 versions produces an error nobody reads.
    let shown: Vec<&str> = available.iter().rev().take(5).map(String::as_str).collect();
    format!(". Recent: {}", shown.join(", "))
}

fn retry_hint(after: &Option<u64>) -> String {
    match after {
        Some(s) => format!("; it asked for {s}s"),
        None => String::new(),
    }
}

impl Classify for RegistryError {
    fn fault(&self) -> Fault {
        match self {
            // The registry, or what it holds. Not us, and not the package's build.
            RegistryError::NoSuchPackage { .. }
            | RegistryError::NoSuchVersion { .. }
            | RegistryError::NoSuchArtifact { .. }
            | RegistryError::DigestMismatch(_)
            | RegistryError::Malformed { .. }
            | RegistryError::Http { .. }
            | RegistryError::RateLimited { .. }
            | RegistryError::Transport(_) => Fault::Upstream,
            RegistryError::Unsupported { .. } => Fault::Policy,
            RegistryError::CatalogUnreadable { cause, .. } => cause.fault(),
            // A repository that will not fetch is upstream's, the same as a registry that will
            // not answer.
            RegistryError::Source { .. } => Fault::Upstream,
            // A reference we declined is ours, and a policy rather than a bug.
            RegistryError::SourceRefused { .. } => Fault::Policy,
            RegistryError::Io(_) => Fault::Infra,
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            // Transient: the registry was busy or the connection broke.
            RegistryError::RateLimited { .. } | RegistryError::Transport(_) => true,
            RegistryError::Http { status, .. } => *status >= 500,
            // As whatever stopped the read: a catalog that was busy may answer, and one that said
            // 404 will say it again.
            RegistryError::CatalogUnreadable { cause, .. } => cause.is_retryable(),
            // Facts. A package that does not exist will not exist on the next attempt, and a
            // digest mismatch means the bytes and the metadata disagree, which retrying cannot fix.
            RegistryError::NoSuchPackage { .. }
            | RegistryError::NoSuchVersion { .. }
            | RegistryError::NoSuchArtifact { .. }
            | RegistryError::DigestMismatch(_)
            | RegistryError::Malformed { .. }
            | RegistryError::Unsupported { .. } => false,
            // A fetch can fail for a moment and succeed after it. A reference we declined cannot.
            RegistryError::Source { .. } => true,
            RegistryError::SourceRefused { .. } => false,
            RegistryError::Io(_) => true,
        }
    }
}
