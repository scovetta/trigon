//! Evidence, not decisions.
//!
//! The most consequential modelling choice in the domain. The prior art derives a Cargo toolchain
//! version by clamping in sequence: start from the release current a week before publication, raise
//! to the declared MSRV, apply an edition floor, apply a lockfile-version floor, then narrow using
//! structural fingerprints of the packaged manifest. Those steps are a set of independent interval
//! constraints wearing an imperative costume, and written that way they cannot be tested
//! individually, cannot explain themselves, and cannot say when they disagree.
//!
//! Written as constraints they can do all three. Intersecting them is a pure function, so the
//! interesting outcomes are types rather than heuristics: an **empty** intersection means the
//! evidence contradicts itself and an **unconstrained** one means there is no evidence at all.
//! Those two are the signal to escalate to a model, and without the type that decision stays
//! something somebody tunes by hand.

use serde::{Deserialize, Serialize};

use crate::digest::Digest;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The registry stated it, or the bytes say so directly.
    Certain,
    /// A fingerprint that has held across a corpus.
    Strong,
    /// A guess with a reason.
    Weak,
}

/// What the dependency graph resolved against.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegistryMoment {
    /// A committed lockfile: the build resolves nothing, which is the strongest form of this.
    Lockfile { digest: Digest },
    /// Filter the index to this instant.
    Timestamp { rfc3339: String },
    /// An index commit satisfying the lockfile, for a git-indexed registry.
    GitCommit { oid: String },
}

/// One thing we believe about how an artifact was built, and why.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub claim: Claim,
    pub confidence: Confidence,
    /// Where it came from, as a stable identifier. Appears in the attestation, so a reader can see
    /// why we chose what we chose.
    pub source: String,
}

impl Evidence {
    pub fn new(claim: Claim, confidence: Confidence, source: impl Into<String>) -> Self {
        Evidence {
            claim,
            confidence,
            source: source.into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "claim", rename_all = "snake_case")]
pub enum Claim {
    /// A half-open interval. `lo` is inclusive, `hi` exclusive, and either may be absent.
    ToolchainRange {
        tool: String,
        lo: Option<String>,
        hi: Option<String>,
    },
    ToolchainExact {
        tool: String,
        version: String,
    },
    BuildBackend {
        backend: String,
    },
    RegistryMomentIs {
        moment: RegistryMoment,
    },
    RepoIs {
        url: String,
    },
    SubdirIs {
        path: String,
    },
    PlatformIs {
        platform: String,
    },
    RequiresNetwork {
        required: bool,
    },
    /// The package declares a build step that its packaging tool does not run.
    ///
    /// The signal behind `needs-build-inference`: a recipe of "pack the repository" cannot produce
    /// files that only exist after something builds them, and the packaging tool is not going to
    /// build them by itself. npm runs `prepare` and `prepack` during `npm pack` and never runs
    /// `build`, so a package whose build hangs off `build` — or off `pretest`, as `escalade` does —
    /// publishes output no rebuild will contain.
    ///
    /// A transcription rather than an inference: the script is in the registry's own version
    /// document, and which hooks the packaging tool runs was measured per version rather than read
    /// off documentation that turned out to be wrong.
    UnrunScript {
        name: String,
        command: String,
    },
}

/// What a registry and an artifact's own bytes say about how it was built.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Intrinsics {
    /// RFC 3339. A string rather than a time type: this is carried into templates and attestations
    /// verbatim, and reformatting it on the way through would change a digest for no reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_moment: Option<RegistryMoment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// What intersecting the evidence for one tool produced.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
pub enum ToolchainResolution {
    /// One version, either stated exactly or the only one left.
    Pinned { version: String },
    /// A range. `width` is how many published releases fall inside it, when we know.
    Window {
        lo: Option<String>,
        hi: Option<String>,
    },
    /// The constraints cannot all hold. One of them is wrong, and guessing which produces a build
    /// that fails for a reason nobody can trace.
    Contradiction { conflicting: Vec<Evidence> },
    /// Nothing said anything.
    Unconstrained,
}

impl ToolchainResolution {
    /// Whether this is a case where a deterministic answer was not reached.
    ///
    /// The escalation signal, as a method rather than a comparison someone writes at each call
    /// site and gets subtly different each time.
    pub fn needs_help(&self) -> bool {
        matches!(
            self,
            ToolchainResolution::Contradiction { .. } | ToolchainResolution::Unconstrained
        )
    }
}

/// Intersect every claim about one tool.
///
/// Versions are compared as dotted numeric sequences, which is what every toolchain here uses.
/// A version this cannot parse is treated as evidence we do not understand and skipped with a
/// note, rather than ordered lexically: "1.10" sorts before "1.9" as text, and a toolchain window
/// silently off by a release is worse than one we declined to compute.
pub fn resolve_toolchain(tool: &str, evidence: &[Evidence]) -> ToolchainResolution {
    let mut lo: Option<(Vec<u64>, &Evidence)> = None;
    let mut hi: Option<(Vec<u64>, &Evidence)> = None;
    let mut exact: Option<(Vec<u64>, &Evidence)> = None;
    let mut relevant = Vec::new();

    for ev in evidence {
        match &ev.claim {
            Claim::ToolchainExact { tool: t, version } if t == tool => {
                let Some(v) = parse_version(version) else {
                    continue;
                };
                relevant.push(ev);
                if let Some((prev, prev_ev)) = &exact
                    && *prev != v
                {
                    return ToolchainResolution::Contradiction {
                        conflicting: vec![(*prev_ev).clone(), ev.clone()],
                    };
                }
                exact = Some((v, ev));
            }
            Claim::ToolchainRange {
                tool: t,
                lo: l,
                hi: h,
            } if t == tool => {
                relevant.push(ev);
                if let Some(v) = l.as_deref().and_then(parse_version)
                    && lo.as_ref().is_none_or(|(cur, _)| v > *cur)
                {
                    lo = Some((v, ev));
                }
                if let Some(v) = h.as_deref().and_then(parse_version)
                    && hi.as_ref().is_none_or(|(cur, _)| v < *cur)
                {
                    hi = Some((v, ev));
                }
            }
            _ => {}
        }
    }

    // An exact version has to sit inside every range, or the evidence disagrees.
    if let Some((v, ev)) = &exact {
        for (bound, bound_ev, ok) in [
            (&lo, "lo", lo.as_ref().is_none_or(|(b, _)| v >= b)),
            (&hi, "hi", hi.as_ref().is_none_or(|(b, _)| v < b)),
        ] {
            let _ = bound_ev;
            if !ok {
                return ToolchainResolution::Contradiction {
                    conflicting: vec![(*ev).clone(), bound.as_ref().unwrap().1.clone()],
                };
            }
        }
        return ToolchainResolution::Pinned {
            version: version_string(v),
        };
    }

    match (&lo, &hi) {
        (Some((l, le)), Some((h, he))) if l >= h => ToolchainResolution::Contradiction {
            conflicting: vec![(*le).clone(), (*he).clone()],
        },
        (None, None) => ToolchainResolution::Unconstrained,
        _ => ToolchainResolution::Window {
            lo: lo.map(|(v, _)| version_string(&v)),
            hi: hi.map(|(v, _)| version_string(&v)),
        },
    }
}

fn parse_version(s: &str) -> Option<Vec<u64>> {
    let core = s.split(['-', '+']).next()?;
    let parts: Vec<u64> = core
        .split('.')
        .map(|p| p.parse::<u64>().ok())
        .collect::<Option<_>>()?;
    (!parts.is_empty()).then_some(parts)
}

fn version_string(v: &[u64]) -> String {
    v.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// Where the source came from, and which rung of the ladder found it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SourceProvenance {
    pub repo_url: String,
    /// Always a resolved commit, never a ref name. A tag moves.
    pub commit: String,
    /// The tag or branch it came from, for humans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdir: Option<String>,
    pub how: SourceDiscovery,
}

/// Which rung found the source.
///
/// Recorded because it predicts a false result better than anything else available. A tree-hash
/// match against the published sdist is strong evidence; a fuzzy tag match on a repository with
/// four thousand tags is a coin flip, and the verdict that follows deserves to be read differently.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceDiscovery {
    /// The registry recorded the commit itself. npm's `gitHead` is this.
    RegistryCommit,
    /// A trusted-publishing attestation.
    PublishedProvenance,
    /// The registry's declared repository, with no commit.
    RegistryMetadata,
    ExactTag,
    PrefixedTag,
    FuzzyTag,
    ManifestHistory,
    TreeHashMatch,
    /// A human said so.
    Definition,
    ModelAssisted,
}

impl SourceDiscovery {
    /// Whether this rung identifies a commit on its own, rather than needing one resolved.
    pub const fn is_exact(self) -> bool {
        matches!(
            self,
            SourceDiscovery::RegistryCommit
                | SourceDiscovery::PublishedProvenance
                | SourceDiscovery::Definition
        )
    }
}
