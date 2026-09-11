//! The Podman runner: rootless containers on a laptop, and the local default.
//!
//! Rootless is why Podman rather than Docker for the local case. The build runs in a user
//! namespace, so root inside the container is an unprivileged user outside it, and a container
//! escape lands somewhere that cannot do much.
//!
//! What this runner will and will not claim is the important part. It advertises the egress tiers
//! it can actually enforce and rejects a plan asking for any other, rather than downgrading. There
//! is no allowlisting proxy yet, so `MirrorOnly` and `GitAndMirror` are not on offer: a plan asking
//! for either fails loudly. `Open` runs, and is marked as not attestable at full trust, because a
//! build that could reach anything could have reached the published artifact.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::dockerfile;
use crate::error::SandboxError;
use crate::model::{
    BuildEvent, BuildOutcome, BuildPlan, EgressTier, IsolationClass, ObservabilityTier, OciPlan,
    Phase, RunOpts, RunnerCaps,
};
use crate::runner::{BuildHandle, BuildRunner};

/// How much of the combined log is kept for triage and for an agent's prompt.
///
/// Bounded because a build that prints a megabyte a second would otherwise fill a worker's memory,
/// and because nothing downstream reads more than the tail anyway.
const LOG_TAIL_BYTES: usize = 64 * 1024;

pub struct PodmanRunner {
    binary: String,
    /// Where collected artifacts land on the host.
    workdir: PathBuf,
    max_concurrency: usize,
    /// An image holding `trigon mirror`, which is what makes `MirrorOnly` enforceable.
    mirror_image: Option<String>,
}

impl PodmanRunner {
    pub fn new(workdir: impl Into<PathBuf>) -> Self {
        PodmanRunner {
            binary: std::env::var("TRIGON_PODMAN").unwrap_or_else(|_| "podman".into()),
            workdir: workdir.into(),
            max_concurrency: 4,
            mirror_image: None,
        }
    }

    /// Offer `MirrorOnly`, using this image to run the mirror inside the build's network island.
    ///
    /// Without it the tier is not advertised and a plan asking for it is refused. A runner that
    /// accepted the plan and ran the build with ordinary networking would record a tier nothing
    /// enforced, which is worse than refusing.
    pub fn with_mirror_image(mut self, image: Option<String>) -> Self {
        self.mirror_image = image;
        self
    }

    pub fn with_binary(mut self, bin: impl Into<String>) -> Self {
        self.binary = bin.into();
        self
    }
}

#[async_trait]
impl BuildRunner for PodmanRunner {
    fn name(&self) -> &'static str {
        "podman"
    }

    fn caps(&self) -> RunnerCaps {
        RunnerCaps {
            isolation: IsolationClass::UserNs,
            privileged: false,
            // No live-container entry yet. An exploration environment needs it; a verification
            // environment must not have it, and this runner is currently only the latter.
            exec: false,
            // Only what can be enforced. MirrorOnly appears once there is an image to run the
            // mirror from, because the enforcement is an internal network whose only route out is
            // that container. GitAndMirror still needs the allowlisting proxy.
            egress_modes: match &self.mirror_image {
                Some(_) => vec![
                    EgressTier::DenyAll,
                    EgressTier::MirrorOnly,
                    EgressTier::Open,
                ],
                None => vec![EgressTier::DenyAll, EgressTier::Open],
            },
            observability: ObservabilityTier::None,
            max_concurrency: self.max_concurrency,
            // Local, unproxied, with no network transcript. Good enough to build and compare, not
            // good enough to sign at full trust.
            attestable: false,
        }
    }

    #[tracing::instrument(skip(self), fields(runner = "podman"))]
    async fn health(&self) -> Result<(), SandboxError> {
        let out = Command::new(&self.binary)
            .arg("--version")
            .output()
            .await
            .map_err(|e| SandboxError::ToolMissing {
                tool: self.binary.clone(),
                detail: e.to_string(),
            })?;
        if !out.status.success() {
            return Err(SandboxError::ToolMissing {
                tool: self.binary.clone(),
                detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(())
    }

    async fn start(
        &self,
        plan: &BuildPlan,
        opts: &RunOpts,
    ) -> Result<Box<dyn BuildHandle>, SandboxError> {
        let BuildPlan::Oci(p) = plan;

        if !self.caps().egress_modes.contains(&p.egress) {
            return Err(SandboxError::EgressUnenforceable {
                requested: p.egress,
                available: self
                    .caps()
                    .egress_modes
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        if p.privileged {
            return Err(SandboxError::PrivilegedUnavailable);
        }
        // A tag resolves to different bytes on different days, which makes the run unreproducible
        // and the attestation a claim about nothing in particular.
        if !p.base_image.contains('@') {
            return Err(SandboxError::ImageNotPinned(p.base_image.clone()));
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let handle = PodmanBuild {
            binary: self.binary.clone(),
            plan: p.clone(),
            opts: opts.clone(),
            workdir: self.workdir.clone(),
            mirror_image: self.mirror_image.clone(),
            events,
        };
        Ok(Box::new(handle))
    }
}

struct PodmanBuild {
    binary: String,
    plan: OciPlan,
    opts: RunOpts,
    workdir: PathBuf,
    mirror_image: Option<String>,
    events: Arc<Mutex<Vec<BuildEvent>>>,
}

impl PodmanBuild {
    /// Resolve `host-gateway` to the address a container actually sees.
    ///
    /// `podman run --add-host name:host-gateway` understands the keyword; `podman build` does not,
    /// and rejects it outright on podman 4.x. The deps phase runs at image-build time, which is
    /// exactly where a package manager talks to the mirror, so the keyword has to become a real
    /// address before the build starts. The address is whatever this machine's rootless networking
    /// hands out, so it is asked for rather than assumed: 10.0.2.2 is right for slirp4netns and
    /// wrong for pasta.
    async fn resolve_host_gateway(&self, image: &str) -> Option<String> {
        let out = Command::new(&self.binary)
            .args([
                "run",
                "--rm",
                "--add-host",
                "trigon-probe:host-gateway",
                image,
                "getent",
                "hosts",
                "trigon-probe",
            ])
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let addr = text.split_whitespace().next()?.to_string();
        tracing::debug!(addr, "resolved host-gateway");
        Some(addr)
    }

    fn tag(&self) -> String {
        format!("trigon-build:{}", self.opts.run_id)
    }

    /// Run one podman invocation, streaming its output into the event log.
    async fn run(
        &self,
        args: &[String],
        phase: Phase,
        log: &mut String,
    ) -> Result<i32, SandboxError> {
        tracing::debug!(
            target: "trigon::build",
            phase = ?phase,
            command = %format!("{} {}", self.binary, args.join(" ")),
            "running"
        );
        let mut child = Command::new(&self.binary)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdout = child.stdout.take().expect("piped");
        let stderr = child.stderr.take().expect("piped");
        let mut out = BufReader::new(stdout).lines();
        let mut err = BufReader::new(stderr).lines();

        let deadline = tokio::time::Instant::now() + self.opts.limits.wall_clock;
        loop {
            tokio::select! {
                line = out.next_line() => match line? {
                    Some(l) => {
                        // At `debug`, because a build prints thousands of these and an operator
                        // watching a fleet wants the phase boundaries, not the compiler output.
                        // At `-vv` it is the live progress that a silent 90-second build lacks.
                        tracing::debug!(target: "trigon::build", phase = ?phase, "{l}");
                        push(&self.events, BuildEvent::Stdout(l.clone()));
                        append(log, &l);
                    }
                    None => break,
                },
                line = err.next_line() => match line? {
                    Some(l) => {
                        tracing::debug!(target: "trigon::build", phase = ?phase, stream = "stderr", "{l}");
                        push(&self.events, BuildEvent::Stderr(l.clone()));
                        append(log, &l);
                    }
                    None => break,
                },
                _ = tokio::time::sleep_until(deadline) => {
                    tracing::warn!(
                        phase = ?phase,
                        timeout_s = self.opts.limits.wall_clock.as_secs(),
                        "wall-clock limit reached, killing the build"
                    );
                    // Kill rather than wait. A hung build otherwise holds a worker slot until a
                    // human notices, and at fleet scale nobody notices.
                    let _ = child.start_kill();
                    return Err(SandboxError::Timeout(self.opts.limits.wall_clock));
                }
            }
        }
        // Drain whatever the other pipe still holds after the first one closed.
        while let Some(l) = err.next_line().await? {
            push(&self.events, BuildEvent::Stderr(l.clone()));
            append(log, &l);
        }
        while let Some(l) = out.next_line().await? {
            push(&self.events, BuildEvent::Stdout(l.clone()));
            append(log, &l);
        }

        let status = child.wait().await?;
        Ok(status.code().unwrap_or(-1))
    }
}

fn push(events: &Arc<Mutex<Vec<BuildEvent>>>, e: BuildEvent) {
    if let Ok(mut v) = events.lock() {
        v.push(e);
    }
}

/// Append a line to the bounded log, compressing rather than truncating once it is full.
///
/// This used to drop from the front, which is the mistake `trigon_core::compress` exists to avoid:
/// **the first error is usually the real one**, and everything after it is consequence. A build
/// that emits a megabyte of dependency-resolution chatter after the line that broke it would push
/// that line out of a front-dropping buffer, leaving a tail full of downstream noise and no cause —
/// for a human reading it, and for the classifier and the repair loop that read it next.
///
/// Compression runs only on overflow, so the per-line cost stays amortized constant.
fn append(log: &mut String, line: &str) {
    log.push_str(line);
    log.push('\n');
    if log.len() > LOG_TAIL_BYTES * 2 {
        *log = trigon_core::compress(log, LOG_TAIL_BYTES).text;
        log.push('\n');
    }
}

#[async_trait]
impl BuildHandle for PodmanBuild {
    fn events(&self) -> BoxStream<'static, BuildEvent> {
        let snapshot = self.events.lock().map(|v| v.clone()).unwrap_or_default();
        stream::iter(snapshot).boxed()
    }

    async fn wait(self: Box<Self>) -> Result<BuildOutcome, SandboxError> {
        let mut log = String::new();
        let mut timings: Vec<(Phase, Option<Duration>)> = Vec::new();

        // The island has to exist before the image build, because the deps phase runs there and
        // that is where a package manager talks to the mirror.
        let island = match (self.plan.egress, &self.mirror_image) {
            (EgressTier::MirrorOnly, Some(image)) => Some(
                crate::network::Island::create(
                    &self.binary,
                    &self.opts.run_id,
                    image,
                    self.opts.mirror_port,
                    self.opts.guard.as_deref(),
                )
                .await?,
            ),
            _ => None,
        };
        let network = island.as_ref().map(|i| i.network().to_string());
        // Whatever the strategy called the mirror is mapped to where it actually is. The strategy
        // names a stable host so the address, which is whatever this run's network handed out,
        // stays out of the strategy digest.
        let mirror_ip = match &island {
            Some(i) => i.mirror_ip().await,
            None => None,
        };

        prune_stale_leftovers(&self.binary);

        let ctx = tempdir(&self.opts.run_id)?;
        let _leftovers = Leftovers {
            binary: self.binary.clone(),
            ctx: ctx.clone(),
            image: (!self.opts.retain).then(|| self.tag()),
        };
        // Rootless `podman build` cannot join a named network, so under mirror-only the deps phase
        // has to run in the container instead of as an image layer.
        let defer_deps = network.is_some();
        dockerfile::render(&self.plan, defer_deps).write(&ctx)?;

        // Image build: setup, source and deps are layers here.
        push(&self.events, BuildEvent::PhaseStart(Phase::Deps));
        tracing::info!(
            run_id = %self.opts.run_id,
            image = %self.plan.base_image,
            egress = %self.plan.egress,
            "building the image: setup, source and deps run here"
        );
        let started = Instant::now();
        let mut build_args = vec![
            "build".to_string(),
            "--tag".to_string(),
            self.tag(),
            "--file".to_string(),
            ctx.join("Dockerfile").display().to_string(),
            ctx.display().to_string(),
        ];
        // The deps phase runs at image-build time, which is where a package manager actually talks
        // to the mirror, so the mapping has to exist here too and not only at run time.
        let gateway = if self.plan.extra_hosts.values().any(|v| v == "host-gateway") {
            self.resolve_host_gateway(&self.plan.base_image).await
        } else {
            None
        };
        for (name, addr) in &self.plan.extra_hosts {
            let addr = match (addr.as_str(), &gateway, &mirror_ip) {
                // The mirror lives on the island, and `podman build` does not join podman's DNS
                // the way `podman run` does, so the name has to become an address here.
                ("mirror", _, Some(ip)) => ip.as_str(),
                ("mirror", _, None) => {
                    return Err(SandboxError::Failed {
                        phase: "setup".into(),
                        detail: "the mirror container has no address on the build's network".into(),
                    });
                }
                ("host-gateway", Some(ip), _) => ip.as_str(),
                ("host-gateway", None, _) => {
                    return Err(SandboxError::Failed {
                        phase: "setup".into(),
                        detail: format!(
                            "could not work out how `{name}` should reach the host from inside a \
                             container. `podman build` does not accept the host-gateway keyword, \
                             so it has to be resolved first, and the probe failed."
                        ),
                    });
                }
                (other, _, _) => other,
            };
            build_args.push("--add-host".into());
            build_args.push(format!("{name}:{addr}"));
        }
        let code = self.run(&build_args, Phase::Deps, &mut log).await?;
        timings.push((Phase::Deps, Some(started.elapsed())));
        push(
            &self.events,
            BuildEvent::PhaseEnd {
                phase: Phase::Deps,
                duration: Some(started.elapsed()),
            },
        );
        if code != 0 {
            if let Some(i) = island {
                i.destroy().await;
            }
            // Which script died, not just "the image build failed". Setup, source and deps are all
            // image-build-time layers, and calling every one of them a dependency failure is the
            // difference between "this package does not build" and "our base image has no CA
            // bundle".
            let phase = failing_phase(&log).unwrap_or(Phase::Deps);
            push(&self.events, BuildEvent::Exit(code));
            tracing::error!(
                run_id = %self.opts.run_id,
                phase = ?phase,
                exit = code,
                "image build failed"
            );
            return Ok(self.outcome(code, None, timings, Some(phase), log));
        }
        tracing::info!(
            run_id = %self.opts.run_id,
            elapsed_s = started.elapsed().as_secs_f64(),
            "image built"
        );

        // The build itself.
        let out_dir = self.workdir.join(&self.opts.run_id);
        std::fs::create_dir_all(&out_dir)?;

        push(&self.events, BuildEvent::PhaseStart(Phase::Build));
        tracing::info!(run_id = %self.opts.run_id, "running the build");
        let started = Instant::now();
        let mut run_args = vec!["run".to_string(), "--rm".to_string()];
        run_args.extend(self.isolation_args(network.as_deref(), mirror_ip.as_deref()));
        run_args.push("--volume".into());
        // `:Z` relabels for SELinux. Without it, a build on a Fedora-family host cannot write here
        // and the failure looks like the build's fault.
        run_args.push(format!("{}:/out:Z", out_dir.display()));
        run_args.push(self.tag());

        let code = self.run(&run_args, Phase::Build, &mut log).await?;
        timings.push((Phase::Build, Some(started.elapsed())));
        push(
            &self.events,
            BuildEvent::PhaseEnd {
                phase: Phase::Build,
                duration: Some(started.elapsed()),
            },
        );
        push(&self.events, BuildEvent::Exit(code));

        // A failed build can still have produced an artifact, and its logs are worth keeping either
        // way. Collect before deciding anything.
        let artifact = collect(&out_dir);
        // With deps deferred, a failure in the run could be either phase. The log says which, and
        // guessing "build" would attribute a dependency-resolution failure to the package.
        let failed_in = (code != 0).then_some(if defer_deps && log.contains("/trigon/deps.sh") {
            Phase::Deps
        } else {
            Phase::Build
        });
        match (&artifact, code) {
            (Some(p), 0) => tracing::info!(
                run_id = %self.opts.run_id,
                elapsed_s = started.elapsed().as_secs_f64(),
                artifact = %p.display(),
                "build succeeded"
            ),
            (None, 0) => tracing::warn!(
                run_id = %self.opts.run_id,
                output_path = %self.plan.output_path,
                "build succeeded but collected no single artifact; check output_path"
            ),
            (_, exit) => tracing::error!(
                run_id = %self.opts.run_id,
                exit,
                phase = "build",
                "build failed"
            ),
        }

        let mut guard_trips = Vec::new();
        if let Some(i) = island {
            guard_trips = i.guard_trips().await;
            i.destroy().await;
        }

        let mut outcome = self.outcome(code, artifact, timings, failed_in, log);
        outcome.guard_trips = guard_trips;
        Ok(outcome)
    }
}

impl PodmanBuild {
    /// Isolation flags, in the order they matter.
    fn isolation_args(&self, network: Option<&str>, mirror_ip: Option<&str>) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();
        for (name, addr) in &self.plan.extra_hosts {
            let addr = match (addr.as_str(), mirror_ip) {
                ("mirror", Some(ip)) => ip.to_string(),
                other => other.0.to_string(),
            };
            a.extend(["--add-host".into(), format!("{name}:{addr}")]);
        }

        // Egress. `none` is a real boundary: no interfaces at all, so nothing to reach.
        match self.plan.egress {
            EgressTier::DenyAll => a.extend(["--network".into(), "none".into()]),
            // The island, and only the island. The build has no other interface, so the mirror is
            // the only thing it can reach and there is nothing to opt out of.
            EgressTier::MirrorOnly => match network {
                Some(n) => a.extend(["--network".into(), n.to_string()]),
                None => unreachable!("an island is created before the build under MirrorOnly"),
            },
            EgressTier::Open => {}
            // `start` rejects this before we get here; the arm exists so that adding a tier without
            // teaching the runner to enforce it fails to compile rather than at run time.
            EgressTier::GitAndMirror => unreachable!("rejected in start()"),
        }

        a.extend([
            // The build gets no capabilities it did not have. It is running someone else's build
            // scripts, and none of them need to change the system clock.
            "--cap-drop".into(),
            "all".into(),
            // No path to gaining privileges it was not started with.
            "--security-opt".into(),
            "no-new-privileges".into(),
        ]);

        if let Some(c) = &self.opts.limits.cpus {
            a.extend(["--cpus".into(), c.clone()]);
        }
        if let Some(m) = &self.opts.limits.memory {
            a.extend(["--memory".into(), m.clone()]);
        }
        if let Some(p) = self.opts.limits.pids {
            a.extend(["--pids-limit".into(), p.to_string()]);
        }
        a
    }

    fn outcome(
        &self,
        exit_code: i32,
        artifact: Option<PathBuf>,
        timings: Vec<(Phase, Option<Duration>)>,
        failed_in: Option<Phase>,
        log_tail: String,
    ) -> BuildOutcome {
        BuildOutcome {
            exit_code,
            artifact,
            timings,
            failed_in,
            egress: self.plan.egress,
            isolation: IsolationClass::UserNs,
            // Still not full trust even under MirrorOnly: the egress boundary holds, but there is
            // no network transcript, so we cannot say what the build fetched from the mirror.
            attestable: false,
            log_tail,
            guard_trips: Vec::new(),
        }
    }
}

/// Which phase script the image build died in.
///
/// Read from the last `RUN /bin/sh /trigon/<phase>.sh` the builder announced, because that is the
/// one it was executing when it stopped.
pub fn failing_phase(log: &str) -> Option<Phase> {
    let mut last = None;
    for line in log.lines() {
        let Some(rest) = line.split("/trigon/").nth(1) else {
            continue;
        };
        last = match rest.split(".sh").next() {
            Some("setup") => Some(Phase::Setup),
            Some("source") => Some(Phase::Source),
            Some("deps") => Some(Phase::Deps),
            _ => last,
        };
    }
    last
}

/// The single file the build left in `/out`, if there is exactly one.
///
/// Exactly one on purpose. A glob that matched three files means the strategy's `output_path` does
/// not identify an artifact, and picking one of them would attach a verdict to whichever the
/// filesystem happened to list first.
fn collect(dir: &std::path::Path) -> Option<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    match files.len() {
        1 => files.pop(),
        _ => None,
    }
}

/// Whatever a run leaves behind, removed however the run ends.
///
/// A guard rather than a line at the end of the happy path, which is what this was: a build that
/// failed kept its context directory and its image forever. On this machine that had accumulated
/// nineteen contexts and a 602 MB image, and a failing build is the common case for exactly the
/// packages a sweep spends most of its time on.
struct Leftovers {
    binary: String,
    ctx: PathBuf,
    /// `None` when the caller asked to keep the image, to exec into or pull.
    image: Option<String>,
}

impl Drop for Leftovers {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.ctx);
        if let Some(tag) = &self.image {
            // Synchronous on purpose: `Drop` cannot await, and leaving this to an async path is
            // how it came to run only on success.
            let _ = std::process::Command::new(&self.binary)
                .args(["rmi", "--force", tag])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Remove contexts and images whose run is gone.
///
/// `Leftovers` covers every path a process can return by; it cannot cover a process that does not
/// return. A wall-clock timeout, a Ctrl-C or a fatal signal skips `Drop` entirely, and those are
/// not rare: three contexts and three 600 MB images were sitting here from runs killed by a SIGPIPE
/// bug earlier in this session.
///
/// Keyed on the process id embedded in the run id, so a concurrent run is never disturbed. Age is
/// required as well, because process ids are reused and deleting a live run's context because some
/// unrelated process inherited its number would be worse than the leak.
fn prune_stale_leftovers(binary: &str) {
    const MIN_AGE: std::time::Duration = std::time::Duration::from_secs(600);

    let dead = |run_id: &str| -> bool {
        let Some(pid) = run_id
            .rsplit('-')
            .next()
            .and_then(|p| p.parse::<u32>().ok())
        else {
            return false;
        };
        !std::path::Path::new(&format!("/proc/{pid}")).exists()
    };
    let old_enough = |t: std::time::SystemTime| t.elapsed().map(|e| e >= MIN_AGE).unwrap_or(false);

    for e in std::fs::read_dir(std::env::temp_dir())
        .into_iter()
        .flatten()
        .flatten()
    {
        let p = e.path();
        let Some(run_id) = p
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("trigon-ctx-"))
        else {
            continue;
        };
        let stale = e
            .metadata()
            .and_then(|m| m.modified())
            .map(old_enough)
            .unwrap_or(false);
        if stale && dead(run_id) {
            let _ = std::fs::remove_dir_all(&p);
        }
    }

    let Ok(out) = std::process::Command::new(binary)
        .args(["images", "--format", "{{.Repository}}:{{.Tag}}"])
        .stderr(Stdio::null())
        .output()
    else {
        return;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(tag) = line.strip_prefix("localhost/trigon-build:") else {
            continue;
        };
        if dead(tag) {
            let _ = std::process::Command::new(binary)
                .args(["rmi", "--force", line])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn tempdir(run_id: &str) -> Result<PathBuf, SandboxError> {
    let d = std::env::temp_dir().join(format!("trigon-ctx-{run_id}"));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}
