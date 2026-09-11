use trigon_core::{Classify, Fault};

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed {format}: {detail}")]
    Malformed {
        format: &'static str,
        detail: String,
    },
    #[error("archive exceeds the {limit} limit ({actual} > {allowed})")]
    LimitExceeded {
        limit: &'static str,
        actual: u64,
        allowed: u64,
    },
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl Classify for ArchiveError {
    fn fault(&self) -> Fault {
        match self {
            // A malformed or oversized artifact is a fact about the artifact, not about us.
            ArchiveError::Malformed { .. } | ArchiveError::LimitExceeded { .. } => Fault::Upstream,
            ArchiveError::Unsupported(_) => Fault::Policy,
            ArchiveError::Io(_) => Fault::Infra,
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            // These are facts about the bytes. Fetching them again produces the same bytes.
            ArchiveError::Malformed { .. } | ArchiveError::LimitExceeded { .. } => false,
            ArchiveError::Unsupported(_) => false,
            ArchiveError::Io(_) => true,
        }
    }
}

pub type Result<T> = std::result::Result<T, ArchiveError>;
