//! What a build is asked to do, and what comes back.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// How much the sandbox can reach.
///
/// The strategy **declares** a tier, the runner **enforces** it, and the attestation **records** it
/// as a required signed field. A pass at `Open` gets a different verdict name rather than a
/// footnote: give it a footnote and everything drifts to `Open` inside six months.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressTier {
    /// Nothing. Vendored builds, and the strongest claim available.
    DenyAll,
    /// Our registry mirror and image registry. The intended default.
    MirrorOnly,
    /// The above plus allowlisted git hosts.
    GitAndMirror,
    /// Anything, fully logged. Last resort, and it downgrades the trust tier.
    Open,
}

impl std::fmt::Display for EgressTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            EgressTier::DenyAll => "deny-all",
            EgressTier::MirrorOnly => "mirror-only",
            EgressTier::GitAndMirror => "git-and-mirror",
            EgressTier::Open => "open",
        })
    }
}

/// What kind of boundary the build runs behind.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationClass {
    /// No boundary at all. Development only, and it refuses to sign.
    Process,
    Container,
    UserNs,
    Gvisor,
    Kata,
    Vm,
}

/// How much of what the build did we can see afterwards.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityTier {
    /// Exit status and logs.
    None,
    /// Plus a network transcript from the proxy. Works everywhere, and answers the question people
    /// actually ask, which is what this build downloaded.
    Network,
    Runtime,
    Syscall,
}

/// What a runner can actually do.
///
/// Advertised rather than assumed. A plan asking for more than this is rejected by `accepts`, which
/// is the difference between a control and a hope: a runner that silently downgrades an egress
/// request produces a verdict labelled with a tier it never enforced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerCaps {
    pub isolation: IsolationClass,
    pub privileged: bool,
    /// Whether a live container can be entered. Exploration environments only.
    pub exec: bool,
    pub egress_modes: Vec<EgressTier>,
    pub observability: ObservabilityTier,
    pub max_concurrency: usize,
    /// Whether an attestation from this runner may claim full trust.
    pub attestable: bool,
}

/// Resource ceilings and the wall-clock kill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub cpus: Option<String>,
    pub memory: Option<String>,
    pub pids: Option<u32>,
    /// A build that has not finished by here is killed. Not optional: a hung build otherwise holds
    /// a worker slot until someone notices.
    pub wall_clock: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            cpus: Some("2".into()),
            memory: Some("4g".into()),
            pids: Some(2048),
            wall_clock: Duration::from_secs(30 * 60),
        }
    }
}

/// A build to run as an OCI image.
///
/// Holds the inputs, not the Dockerfile. Rendering it is a pure function so it can be tested
/// without a container runtime, and so the bytes that describe the build are inspectable before
/// anything executes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciPlan {
    /// Pinned by digest. A tag here would make the run unreproducible, and the digest goes into
    /// both the run key and the attestation.
    pub base_image: String,
    /// System packages installed before anything else runs.
    pub system_deps: BTreeSet<String>,
    /// Fetch and prepare the working tree.
    pub source: String,
    /// Toolchain and dependencies.
    pub deps: String,
    /// The build itself. Written to a script at image-build time and run afterwards.
    pub build: String,
    /// What to collect, relative to the working tree. May be a glob.
    pub output_path: String,
    pub egress: EgressTier,
    pub privileged: bool,
}

/// A build to run, in whatever shape the runner understands.
///
/// A concrete enum rather than an opaque handle: the engine holds a heterogeneous list of runners
/// and dispatches on `accepts`, and a plan it cannot inspect is a plan it cannot route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildPlan {
    Oci(OciPlan),
}

impl BuildPlan {
    pub fn egress(&self) -> EgressTier {
        match self {
            BuildPlan::Oci(p) => p.egress,
        }
    }
    pub fn privileged(&self) -> bool {
        match self {
            BuildPlan::Oci(p) => p.privileged,
        }
    }
}

/// Per-run knobs that are not part of what is being built.
#[derive(Clone, Debug, Default)]
pub struct RunOpts {
    pub limits: Limits,
    /// Identifies the run in image tags and container names, so a triage session can find them.
    pub run_id: String,
    /// Keep the image and container after the run, for an agent to `exec` into or a human to pull.
    pub retain: bool,
}

/// Which part of the build something happened in.
///
/// Also the unit the timings are reported in. Each phase is an image layer, so the durations fall
/// out of layer metadata without instrumenting anything.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Setup,
    Source,
    Deps,
    Build,
    Collect,
}

/// Something the build did, as it happens.
///
/// A stream rather than a reader. Three consumers want the same bytes with structure: the phase
/// timings, the bounded log tail an agent reads, and the tee into the blob store. Splitting one
/// `AsyncRead` three ways to serve them is worse than emitting events once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildEvent {
    PhaseStart(Phase),
    Stdout(String),
    Stderr(String),
    PhaseEnd {
        phase: Phase,
        /// `None` means no data, never zero. A timing we failed to read is not a fast phase.
        duration: Option<Duration>,
    },
    Exit(i32),
}

/// How a build ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildOutcome {
    pub exit_code: i32,
    /// Where the collected artifact landed on the host, when there was one. A failed build can
    /// still produce one, and a failed build that produced nothing is still worth its logs.
    pub artifact: Option<std::path::PathBuf>,
    /// Per-phase durations, `None` where we could not read one.
    pub timings: Vec<(Phase, Option<Duration>)>,
    /// The phase the failure happened in, when it failed.
    pub failed_in: Option<Phase>,
    /// The tier actually enforced, which the attestation records.
    pub egress: EgressTier,
    pub isolation: IsolationClass,
    /// Whether this run may be attested at full trust.
    pub attestable: bool,
    /// Bounded tail of the combined log, for an agent and for triage.
    pub log_tail: String,
}

impl BuildOutcome {
    pub fn succeeded(&self) -> bool {
        self.exit_code == 0
    }
}
