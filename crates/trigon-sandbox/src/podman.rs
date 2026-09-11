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
}

impl PodmanRunner {
    pub fn new(workdir: impl Into<PathBuf>) -> Self {
        PodmanRunner {
            binary: std::env::var("TRIGON_PODMAN").unwrap_or_else(|_| "podman".into()),
            workdir: workdir.into(),
            max_concurrency: 4,
        }
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
            // Only what can be enforced. MirrorOnly and GitAndMirror need the allowlisting proxy,
            // and advertising them before it exists would let a plan record a tier nothing applied.
            egress_modes: vec![EgressTier::DenyAll, EgressTier::Open],
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
    events: Arc<Mutex<Vec<BuildEvent>>>,
}

impl PodmanBuild {
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

/// Append a line to the bounded tail, dropping from the front once it is full.
fn append(log: &mut String, line: &str) {
    log.push_str(line);
    log.push('\n');
    if log.len() > LOG_TAIL_BYTES * 2 {
        let cut = log.len() - LOG_TAIL_BYTES;
        // Cut on a character boundary, and prefer a line boundary just after it.
        let mut at = cut;
        while at < log.len() && !log.is_char_boundary(at) {
            at += 1;
        }
        if let Some(nl) = log[at..].find('\n') {
            at += nl + 1;
        }
        *log = log[at..].to_string();
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

        let ctx = tempdir(&self.opts.run_id)?;
        dockerfile::render(&self.plan).write(&ctx)?;

        // Image build: setup, source and deps are layers here.
        push(&self.events, BuildEvent::PhaseStart(Phase::Deps));
        tracing::info!(
            run_id = %self.opts.run_id,
            image = %self.plan.base_image,
            egress = %self.plan.egress,
            "building the image: setup, source and deps run here"
        );
        let started = Instant::now();
        let build_args = vec![
            "build".to_string(),
            "--tag".to_string(),
            self.tag(),
            "--file".to_string(),
            ctx.join("Dockerfile").display().to_string(),
            ctx.display().to_string(),
        ];
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
            push(&self.events, BuildEvent::Exit(code));
            tracing::error!(
                run_id = %self.opts.run_id,
                phase = "deps",
                exit = code,
                "image build failed"
            );
            return Ok(self.outcome(code, None, timings, Some(Phase::Deps), log));
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
        run_args.extend(self.isolation_args());
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
        let failed_in = (code != 0).then_some(Phase::Build);
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

        if !self.opts.retain {
            let _ = Command::new(&self.binary)
                .args(["rmi", "--force", &self.tag()])
                .output()
                .await;
        }
        let _ = std::fs::remove_dir_all(&ctx);

        Ok(self.outcome(code, artifact, timings, failed_in, log))
    }
}

impl PodmanBuild {
    /// Isolation flags, in the order they matter.
    fn isolation_args(&self) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();

        // Egress. `none` is a real boundary: no interfaces at all, so nothing to reach.
        match self.plan.egress {
            EgressTier::DenyAll => a.extend(["--network".into(), "none".into()]),
            EgressTier::Open => {}
            // `start` rejects these before we get here; this arm exists so that adding a tier
            // without teaching the runner to enforce it fails to compile rather than at runtime.
            EgressTier::MirrorOnly | EgressTier::GitAndMirror => {
                unreachable!("rejected in start()")
            }
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
            attestable: false,
            log_tail,
        }
    }
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

fn tempdir(run_id: &str) -> Result<PathBuf, SandboxError> {
    let d = std::env::temp_dir().join(format!("trigon-ctx-{run_id}"));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}
