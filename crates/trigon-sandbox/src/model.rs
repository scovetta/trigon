//! What a build is asked to do, and what comes back.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
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
}

// There is deliberately no `attestable` here. It used to sit alongside these, and its only two
// readers built a *fresh, mirror-less* runner to ask — so a run that had been done by a
// mirror-equipped runner was recorded with the mirror-less one's answer. Whether a run may be
// attested is a fact about that run, not a property advertised in advance, and it lives on
// [`BuildOutcome`] where it is computed from what actually happened.

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
    /// Extra name-to-address mappings for the build's resolver.
    ///
    /// How the time-filtering mirror becomes reachable: the strategy names a stable host, and the
    /// runner maps it to wherever the mirror is actually listening. Without this the strategy
    /// would have to carry a port number, which would put the operator's machine into the
    /// strategy digest and make two runs of the same recipe hash differently.
    pub extra_hosts: BTreeMap<String, String>,
    /// A checkout of the source at the commit the strategy names, fetched on the host and copied
    /// into the image.
    ///
    /// `Some` at every enforced tier and `None` at `Open`. The source phase is an image-build
    /// layer and rootless `podman build` cannot join the island, so the only way a phase that needs
    /// the repository can run inside the boundary is for the repository to already be there. That
    /// is what lets the image build run with no network at all.
    pub source_tree: Option<PathBuf>,
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

/// Somewhere to send build events as they happen.
///
/// [`BuildHandle::events`] returns a *snapshot*: everything pushed so far, which is the whole
/// history once the build is over and nothing at all while it is the thing you want to watch. A
/// caller that needs to know which phase is running now needs to be told, so this is the telling.
///
/// A plain callback rather than a channel, because the one caller wants to write a file and a
/// channel would oblige every other caller to drain it.
pub type EventSink = std::sync::Arc<dyn Fn(&BuildEvent) + Send + Sync>;

/// Per-run knobs that are not part of what is being built.
#[derive(Clone)]
pub struct RunOpts {
    pub limits: Limits,
    /// Identifies the run in image tags and container names, so a triage session can find them.
    pub run_id: String,
    /// Keep the image and container after the run, for an agent to `exec` into or a human to pull.
    pub retain: bool,
    /// Port the mirror listens on inside the build's network island.
    pub mirror_port: u16,
    /// A guard manifest to mount into that mirror.
    ///
    /// Without it the island still enforces egress, but nothing notices if the build downloads the
    /// artifact it is meant to be reproducing from somewhere the mirror proxies.
    pub guard: Option<std::path::PathBuf>,
    /// Called as each event is recorded. `None` is the ordinary case: nothing is watching.
    pub on_event: Option<EventSink>,
}

impl std::fmt::Debug for RunOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunOpts")
            .field("limits", &self.limits)
            .field("run_id", &self.run_id)
            .field("retain", &self.retain)
            .field("mirror_port", &self.mirror_port)
            .field("guard", &self.guard)
            .field("on_event", &self.on_event.is_some())
            .finish()
    }
}

impl Default for RunOpts {
    fn default() -> Self {
        RunOpts {
            limits: Limits::default(),
            run_id: String::new(),
            retain: false,
            mirror_port: 8129,
            guard: None,
            on_event: None,
        }
    }
}

/// Which part of the build something happened in, and the unit the timings are reported in.
///
/// Defined in `trigon-core`: the repair loop and the verdict both need it and neither may depend on
/// a container runtime. Each phase is an image layer here, so the durations fall out of layer
/// metadata without instrumenting anything.
pub use trigon_core::Phase;

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
    /// Whether this run can account for everything that crossed into the build.
    ///
    /// Exactly [`BuildOutcome::transcript`]`.is_some()`, and nothing more: it says the egress
    /// boundary was enforced *and* we can say what came through it. It is not a statement that the
    /// sandbox class, the base image or the strategy are good enough to sign — those are separate
    /// claims made elsewhere, and reading this as "full trust" is how a control starts reporting
    /// success it has not earned.
    pub attestable: bool,
    /// Bounded tail of the combined log, for an agent and for triage.
    pub log_tail: String,
    /// The failure named while the log was still whole, where a rule claimed a line.
    ///
    /// `log_tail` is compressed on overflow, so a caller that classifies it afterwards can miss the
    /// line that named the failure and get `unknown` instead — on exactly the chatty builds that
    /// fail. That signature is the repair cache key, the admission-control prior and the cluster id,
    /// so the same failure keying two ways means the flywheel never recognises what it has already
    /// solved. Prefer this over re-deriving from `log_tail`.
    pub signature: Option<trigon_core::FailureSignature>,
    /// What the artifact guard caught. Non-empty means the run is `Void`: the artifact under test
    /// reached the build over the network, so whatever it produced says nothing about the source.
    pub guard_trips: Vec<String>,
    /// Everything that crossed the network into this build — Tier 1 observability of
    /// `docs/08-execution.md` §7, and what makes `attestable` a computed value rather than the
    /// constant `false` it used to be.
    ///
    /// **The complete account, or none at all.** `Some` means every byte that crossed into the
    /// build is listed here; `Some(vec![])` means nothing crossed, which under `DenyAll` is what
    /// having no interface means and under `MirrorOnly` is a mirror that served nothing. `None`
    /// means no complete account exists — an `Open` run, or a read that failed. Nothing downstream
    /// may turn a `None` into an empty list: "we could not look" and "nothing came through" are
    /// the two answers this type exists to keep apart.
    pub transcript: Option<Vec<trigon_mirror::Exchange>>,
    /// What the mirror served and refused, as the registry-pin counters.
    ///
    /// `None` where no mirror ran — at `deny-all` there is nothing to resolve against and at `open`
    /// the build can bypass the mirror entirely, so neither can produce this. `Some` with
    /// `index_requests == 0` is the interesting value and the one this exists for: it says the
    /// mirror was up, the build talked to it, and it never asked for an index — which is either a
    /// build that needed no dependencies or a pin that did not reach the client.
    ///
    /// Derived from the transcript rather than carried out as a number, so a reader holding the
    /// transcript can redo the arithmetic instead of trusting it.
    pub pin: Option<trigon_mirror::Observed>,
}

impl BuildOutcome {
    pub fn succeeded(&self) -> bool {
        self.exit_code == 0
    }
}
