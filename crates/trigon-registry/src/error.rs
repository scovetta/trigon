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

    #[error(
        "{name} declares sha256 {expected} for {artifact}, and the bytes we fetched hash to \
         {actual}. Refusing: a run against bytes the registry does not vouch for proves nothing \
         about what it published."
    )]
    DigestMismatch {
        name: String,
        artifact: String,
        expected: String,
        actual: String,
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
            | RegistryError::DigestMismatch { .. }
            | RegistryError::Malformed { .. }
            | RegistryError::Http { .. }
            | RegistryError::RateLimited { .. }
            | RegistryError::Transport(_) => Fault::Upstream,
            RegistryError::Unsupported { .. } => Fault::Policy,
            RegistryError::Io(_) => Fault::Infra,
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            // Transient: the registry was busy or the connection broke.
            RegistryError::RateLimited { .. } | RegistryError::Transport(_) => true,
            RegistryError::Http { status, .. } => *status >= 500,
            // Facts. A package that does not exist will not exist on the next attempt, and a
            // digest mismatch means the bytes and the metadata disagree, which retrying cannot fix.
            RegistryError::NoSuchPackage { .. }
            | RegistryError::NoSuchVersion { .. }
            | RegistryError::NoSuchArtifact { .. }
            | RegistryError::DigestMismatch { .. }
            | RegistryError::Malformed { .. }
            | RegistryError::Unsupported { .. } => false,
            RegistryError::Io(_) => true,
        }
    }
}
