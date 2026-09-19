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
    /// Whether the local image store holds this reference.
    ///
    /// Best effort in one direction only: a probe that cannot run answers `true`, so a podman that is
    /// broken in some other way fails later with its own message rather than being reported here as a
    /// missing image.
    async fn image_exists(&self, image: &str) -> bool {
        Command::new(&self.binary)
            .args(["image", "exists", image])
            .status()
            .await
            .map_or(true, |s| s.success())
    }

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
            // The mirror is what makes a transcript possible: it is the build's only route out
            // under `MirrorOnly`, and it writes down every body it serves. Without an image to run
            // it from there is no proxy and nothing to transcribe — `DenyAll` still accounts for
            // egress completely, but by having no interface rather than by observing one, which is
            // not what this tier names.
            observability: match &self.mirror_image {
                Some(_) => ObservabilityTier::Network,
                None => ObservabilityTier::None,
            },
            max_concurrency: self.max_concurrency,
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
        if !is_pinned(&p.base_image) {
            return Err(SandboxError::ImageNotPinned(p.base_image.clone()));
        }
        // **And a pinned reference that names nothing is not a pinned image.** `is_pinned` checks
        // the *shape* of the string, so `localhost/base@sha256:<anything>` passed it and the run
        // went on to spend six seconds discovering that podman cannot reach a registry called
        // `localhost`. Only the references that can *only* be local are checked here — a bare
        // `sha256:` id, and anything under `localhost/`, which no registry will ever serve — so a
        // legitimate remote image that has not been pulled yet is still pulled rather than refused.
        let local_only = p.base_image.starts_with("localhost/")
            || p.base_image.starts_with("sha256:")
            || !p.base_image.contains('/');
        if local_only && !self.image_exists(&p.base_image).await {
            return Err(SandboxError::ImageNotInStore(p.base_image.clone()));
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let handle = PodmanBuild {
            named: Arc::new(Mutex::new(None)),
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
    /// The failure this build named while its log was still whole.
    ///
    /// `log_tail` is compressed on overflow, so classifying it afterwards can miss the line that
    /// named the failure and fall back to `unknown` — on the chatty builds, which are the ones that
    /// fail. Kept here so the signature survives the compression that happens beside it.
    named: Arc<Mutex<Option<trigon_core::FailureSignature>>>,
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
                        push_to(self.opts.on_event.as_ref(), &self.events, BuildEvent::Stdout(l.clone()));
                        append(log, &l, &self.named);
                    }
                    None => break,
                },
                line = err.next_line() => match line? {
                    Some(l) => {
                        tracing::debug!(target: "trigon::build", phase = ?phase, stream = "stderr", "{l}");
                        push_to(self.opts.on_event.as_ref(), &self.events, BuildEvent::Stderr(l.clone()));
                        append(log, &l, &self.named);
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
            push_to(
                self.opts.on_event.as_ref(),
                &self.events,
                BuildEvent::Stderr(l.clone()),
            );
            append(log, &l, &self.named);
        }
        while let Some(l) = out.next_line().await? {
            push_to(
                self.opts.on_event.as_ref(),
                &self.events,
                BuildEvent::Stdout(l.clone()),
            );
            append(log, &l, &self.named);
        }

        let status = child.wait().await?;
        Ok(status.code().unwrap_or(-1))
    }
}

/// Record an event, and tell anything that asked to be told.
///
/// The sink is called before the lock is taken, so a slow watcher cannot block the build behind a
/// mutex the build needs — and a panicking one takes only itself.
fn push_to(
    sink: Option<&crate::model::EventSink>,
    events: &Arc<Mutex<Vec<BuildEvent>>>,
    e: BuildEvent,
) {
    if let Some(f) = sink {
        f(&e);
    }
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
fn append(log: &mut String, line: &str, named: &Mutex<Option<trigon_core::FailureSignature>>) {
    // Named as it passes, not at the end. `log_tail` is compressed here on overflow, and the
    // consumer then classified *that* — so on a build chatty enough to trip the threshold the line
    // that named the failure could already be gone and the signature came out `unknown`. The same
    // failure therefore keyed two different cache entries depending on how much the build printed,
    // and `unknown` is the bucket the repair loop treats as novel: a repair learned on a quiet
    // build never matched the noisy one.
    //
    // Last match wins, which is what `classify` does over a whole log — the deepest cause is
    // usually the last thing said about it.
    if let Some(sig) = trigon_core::classify_line(line)
        && let Ok(mut n) = named.lock()
    {
        *n = Some(sig);
    }
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

        // The checkout the host fetched, into the build context so the image can `COPY` it. `cp
        // -a` rather than a hand-rolled walk: it preserves mtimes, which is what keeps the layer's
        // cache key stable across attempts, and it copies `.git`, which the source phase's
        // `git checkout --force <sha>` needs in order to be a check rather than a no-op.
        if let Some(tree) = &self.plan.source_tree {
            let dest = ctx.join("src");
            std::fs::create_dir_all(&dest)?;
            let status = std::process::Command::new("cp")
                .arg("-a")
                .arg(format!("{}/.", tree.display()))
                .arg(&dest)
                .status();
            match status {
                Ok(s) if s.success() => {}
                _ => {
                    return Err(SandboxError::Failed {
                        phase: "source".into(),
                        detail: format!(
                            "could not copy the checkout at {} into the build context",
                            tree.display()
                        ),
                    });
                }
            }
        }

        // Image build: setup, source and deps are layers here.
        push_to(
            self.opts.on_event.as_ref(),
            &self.events,
            BuildEvent::PhaseStart(Phase::Deps),
        );
        tracing::info!(
            run_id = %self.opts.run_id,
            image = %self.plan.base_image,
            egress = %self.plan.egress,
            "building the image: setup, source and deps run here"
        );
        let started = Instant::now();
        let mut build_args = vec!["build".to_string()];
        if self.opts.no_cache {
            build_args.push("--no-cache".into());
        }
        build_args.extend([
            "--tag".to_string(),
            self.tag(),
            "--file".to_string(),
            ctx.join("Dockerfile").display().to_string(),
            ctx.display().to_string(),
        ]);
        // The image build had no network flag at all, so every phase rendered as a layer — setup,
        // source, and deps unless deferred — ran with ordinary rootless networking whatever tier
        // was asked for. At `deny-all` that meant a tier whose entire content is "reaches nothing"
        // reached everything, and the run was still recorded as enforced. `docs/12-security.md`
        // §1.1 needs no more than that: a `src:` step fetching the published artifact, a `build:`
        // step copying it to the output, and a signed `Exact`.
        //
        // Only `DenyAll` can be closed here. `MirrorOnly` cannot: rootless `podman build` refuses
        // to join a named network, and the source phase has to clone from a forge the island has
        // no route to. That gap is real, is not closed by this, and is written down in
        // `docs/16-findings.md` §3.12 and `docs/17-backlog.md` B7.
        // Every enforced tier, not only `DenyAll`. At `MirrorOnly` this used to be the hole: the
        // setup and source phases are image layers, rootless `podman build` cannot join the island,
        // and with no flag at all they had ordinary networking — so the tier the README recommends
        // enforced nothing for three of its four phases. It can be closed here rather than by
        // teaching the island to reach a forge, because the source arrives as a copied checkout.
        //
        // What it costs is stated where it is refused: with no network there is no `apt-get`, so an
        // enforced run needs a base image that already carries the strategy's system packages.
        if self.plan.egress != EgressTier::Open {
            build_args.push("--network".into());
            build_args.push("none".into());
        }
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
        // **Held across the image build and the container run.** Podman's cache lookup walks the
        // layer store before the first instruction, and a removal running beside it fails *this*
        // process with `getting top layer info: layer not known` — not the one doing the removing.
        // Shared, so lanes do not exclude each other; removals wait, and a removal that will not
        // wait skips itself.
        //
        // `None` is not fatal. A machine where the lock file cannot be made is one where the old
        // behaviour applies, and refusing to build because a lock could not be taken trades a rare
        // race for a certain failure.
        let store = crate::store_lock::StoreLock::shared();
        if store.is_none() {
            tracing::debug!("no image-store lock; a concurrent removal could fail this build");
        }

        let code = self.run(&build_args, Phase::Deps, &mut log).await?;
        // Which script the span belongs to, not just "the image build". Setup, source and deps are
        // all image-build-time layers, and calling every one of them a dependency phase is the
        // difference between "this package does not build" and "our base image has no CA bundle".
        //
        // Read once and used for both the timing and `failed_in`. It used to be read only for
        // `failed_in`, after the timing row had already been pushed as `Deps`, so a build that died
        // in setup reported `phase=Setup` on one line and `Deps 1.9s` two lines below it.
        //
        // **`None` is an answer, and it used to be `unwrap_or(Phase::Deps)`.** `failing_phase`
        // returns nothing when the log holds no `/trigon/<script>.sh` line, which is exactly the
        // case where podman died before executing any instruction: `STEP 1/11: FROM <image>`, an
        // image that is not in the local store, a registry it cannot reach. Defaulting that to
        // `Deps` invented a phase, a timing row for it, and a `build-failed:deps` verdict — and at
        // `mirror-only` the invention names the one phase that provably cannot have run, because
        // `defer_deps` keeps the deps script out of the image entirely.
        //
        // `Phase` is ordered and the repair loop measures progress against it, so a run that
        // executed nothing recorded as having reached *further* than one that genuinely failed in
        // setup.
        let reached = failing_phase(&log);
        if let Some(phase) = reached {
            timings.push((phase, Some(started.elapsed())));
            push_to(
                self.opts.on_event.as_ref(),
                &self.events,
                BuildEvent::PhaseEnd {
                    phase,
                    duration: Some(started.elapsed()),
                },
            );
        }
        if code != 0 && reached.is_none() {
            // Nothing of ours ran, so there is nothing here about the package. An error rather
            // than an outcome: `docs/03` reserves `Error` for our faults and says a verdict must
            // never carry one, and `main.rs`'s own comment records a regression where our mirror
            // failing "read, in the sweep summary, as five packages that do not build".
            if let Some(i) = island {
                i.destroy().await;
            }
            return Err(SandboxError::RuntimeRefused {
                code,
                detail: runtime_complaint(&log),
            });
        }
        if code != 0 {
            // Read before the island goes, even here. The image build has no network at any
            // enforced tier, so the honest answer is an *empty* account rather than no account —
            // and reporting "what crossed is unknown" about a phase that provably had no interface
            // is the pessimistic mirror of the mistake this codebase keeps finding.
            let mut seen = None;
            if let Some(i) = island {
                let read = i.observations().await;
                i.destroy().await;
                seen = Some(read?);
            }
            let phase = reached.expect("checked above");
            push_to(
                self.opts.on_event.as_ref(),
                &self.events,
                BuildEvent::Exit(code),
            );
            tracing::error!(
                run_id = %self.opts.run_id,
                phase = ?phase,
                exit = code,
                "image build failed"
            );
            return Ok(self.outcome(code, None, timings, Some(phase), log, seen));
        }
        tracing::info!(
            run_id = %self.opts.run_id,
            elapsed_s = started.elapsed().as_secs_f64(),
            "image built"
        );

        // The build itself.
        let out_dir = self.workdir.join(&self.opts.run_id);
        std::fs::create_dir_all(&out_dir)?;

        push_to(
            self.opts.on_event.as_ref(),
            &self.events,
            BuildEvent::PhaseStart(Phase::Build),
        );
        tracing::info!(run_id = %self.opts.run_id, "running the build");
        let started = Instant::now();
        let mut run_args = vec!["run".to_string(), "--rm".to_string()];
        run_args.extend(self.isolation_args(network.as_deref(), mirror_ip.as_deref()));
        run_args.push("--volume".into());
        // `:Z` relabels for SELinux. Without it, a build on a Fedora-family host cannot write here
        // and the failure looks like the build's fault.
        run_args.push(format!("{}:/out:Z", crate::mount_source(&out_dir)));
        run_args.push(self.tag());

        let code = self.run(&run_args, Phase::Build, &mut log).await?;
        // The container has run; nothing else reads the image store for this target. Released here
        // rather than at the end of the function so a finishing lane stops holding removals off
        // while it collects its artifact and reads the mirror's log.
        drop(store);
        timings.push((Phase::Build, Some(started.elapsed())));
        push_to(
            self.opts.on_event.as_ref(),
            &self.events,
            BuildEvent::PhaseEnd {
                phase: Phase::Build,
                duration: Some(started.elapsed()),
            },
        );
        push_to(
            self.opts.on_event.as_ref(),
            &self.events,
            BuildEvent::Exit(code),
        );

        // A failed build can still have produced an artifact, and its logs are worth keeping either
        // way. Collect before deciding anything.
        let artifact = collect(&out_dir);
        // With deps deferred, a failure in the run could be either phase, and the log says which.
        //
        // It used to ask whether the deps script had been *invoked*, which is true of every run
        // that reached the container at all — so at an enforced tier every failure was reported as
        // a deps failure. `stub42/pytz` installed its build frontend and then failed in
        // `python -m build`; the record said `build-failed:deps`, which sends a reader to the
        // wrong half of the log. The comment above described the intent and the code tested
        // something weaker.
        //
        // `DEPS_DONE` is printed between the two under `set -e`, so its absence after a deps
        // invocation is the deps script having exited non-zero.
        let deps_ran = defer_deps && log.contains("/trigon/deps.sh");
        let failed_in =
            (code != 0).then_some(match deps_ran && !log.contains(dockerfile::DEPS_DONE) {
                true => Phase::Deps,
                false => Phase::Build,
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

        let mut seen = None;
        if let Some(i) = island {
            // The island is destroyed either way, and the read happens first: a failure to read the
            // guard must not leave a network behind, and must not be swallowed.
            let read = i.observations().await;
            i.destroy().await;
            seen = Some(read?);
        }

        Ok(self.outcome(code, artifact, timings, failed_in, log, seen))
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

    /// The complete account of what crossed into this build, or `None` when there is none.
    ///
    /// One function, so the rule exists once. Written per-call-site it would be two rules that had
    /// to agree with nothing asserting they did, which is the bug this codebase keeps finding.
    ///
    /// `DenyAll` needs no mirror to be complete: `--network none` on both the image build and the
    /// run means the build has no interface, so "nothing crossed" is enforced by the kernel rather
    /// than observed by a proxy. `MirrorOnly` is complete exactly when the mirror's log was read —
    /// a read that fails is an error out of `wait`, not an empty list here. `Open` is never
    /// complete, which is the entire content of the tier.
    fn transcript(
        &self,
        from_mirror: Option<Vec<trigon_mirror::Exchange>>,
    ) -> Option<Vec<trigon_mirror::Exchange>> {
        complete_account(self.plan.egress, from_mirror)
    }

    /// Everything one read of the mirror's log produced, as an outcome.
    ///
    /// The whole `MirrorLog` rather than its three fields separately, because they *are* one read:
    /// a transcript from one `podman logs` beside a trip list from another is two accounts of one
    /// run, and the pin evidence is derived from the transcript in the same breath.
    fn outcome(
        &self,
        exit_code: i32,
        artifact: Option<PathBuf>,
        timings: Vec<(Phase, Option<Duration>)>,
        failed_in: Option<Phase>,
        log_tail: String,
        seen: Option<crate::network::MirrorLog>,
    ) -> BuildOutcome {
        let pin = seen.as_ref().map(|s| s.observed());
        let (arrived, refused_artifact, throttled, from_mirror) = match seen {
            Some(s) => (s.trips, s.refused_artifact, s.throttled, Some(s.transcript)),
            None => (Vec::new(), Vec::new(), Vec::new(), None),
        };
        // **Reported, not decided.** Whether a trip voids the run depends on whether the bytes came
        // back out in the rebuilt artifact, and the caller resolves that artifact — the runner's
        // `collect` finds the single file at the output path, the caller also walks for builds
        // whose output lands in a subdirectory. Deciding here as well would be a second answer to
        // one question, with nothing asserting the two agreed.
        let transcript = self.transcript(from_mirror);
        BuildOutcome {
            guard_arrived: arrived,
            signature: self.named.lock().ok().and_then(|n| n.clone()),
            exit_code,
            artifact,
            timings,
            failed_in,
            egress: self.plan.egress,
            isolation: IsolationClass::UserNs,
            // Derived, never asserted. The claim is exactly "we can say what crossed into this
            // build", which is true when a complete account exists and false otherwise.
            attestable: transcript.is_some(),
            log_tail,
            refused_artifact,
            transcript,
            pin,
            throttled,
        }
    }
}

/// Whether an image reference names exact bytes.
///
/// A repository digest (`name@sha256:…`) or a bare image id. The id is here because a base image
/// built on this machine has no repository digest until it is pushed, and an enforced tier is
/// unusable without one: with no network in the image build, the packages a strategy needs have to
/// come from a base image somebody built. An id identifies exactly one set of bytes in the local
/// store, which is the property the check exists for.
/// Whether podman can actually resolve this reference, and what to say when it cannot.
///
/// **`localhost/name@sha256:…` is the trap.** It has the shape of a pinned image and podman reads
/// `localhost` as a *registry hostname*, so it tries to pull over HTTPS from a registry nobody is
/// running and fails with `pinging container registry localhost: connection refused` — a message
/// about networking, for a reference that names an image already on disk. A locally built image is
/// reachable only by its bare id.
///
/// Returns `Err` with the sentence to print. `Ok(())` means podman has some chance of resolving it:
/// either it is in the local store, or it names a registry that might serve it.
pub fn resolvable(image: &str, exists_locally: bool) -> Result<(), String> {
    if exists_locally {
        return Ok(());
    }
    let bare_id = |s: &str| {
        let id = s.strip_prefix("sha256:").unwrap_or(s);
        id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
    };
    if let Some(rest) = image.strip_prefix("localhost/") {
        let id = rest.rsplit('@').next().unwrap_or_default();
        let hint = match bare_id(id) {
            true => format!("Use the id on its own:\n\n    {id}\n"),
            false => "`podman images --no-trunc` prints the id to use.".into(),
        };
        return Err(format!(
            "`{image}` is not in the local image store, and podman cannot fetch it: it reads \
             `localhost` as a registry hostname and tries to pull over HTTPS from a registry \
             nobody is running. A locally built image is reachable only by its bare id.\n\n{hint}"
        ));
    }
    if bare_id(image) {
        return Err(format!(
            "no image with id `{image}` is in the local store. `podman images --no-trunc` lists \
             what is there."
        ));
    }
    // A real registry reference. podman may or may not be able to pull it, and finding out is its
    // job rather than ours.
    Ok(())
}

/// Whether this reference names exact bytes rather than a moving tag.
///
/// Two forms count. A digest reference (`name@sha256:…`) names the bytes wherever it is served
/// from; a bare image id (`sha256:<64 hex>`, or the hex alone) names them in the local store, which
/// is *more* pinned rather than less.
///
/// **Public because two copies of this rule disagreed.** `base-image` had its own, requiring `@`,
/// so it refused a bare id — and `env/base-image-incomplete` builds its suggested fix command out of
/// whatever `--image` the run used, which for a locally built base is exactly that form. Trigon
/// printed a command Trigon then rejected. One definition, so they cannot drift again.
pub fn is_pinned(image: &str) -> bool {
    if image.contains('@') {
        return true;
    }
    let id = image.strip_prefix("sha256:").unwrap_or(image);
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Which phase script the image build died in.
///
/// Read from the last `RUN /bin/sh /trigon/<phase>.sh` the builder announced, because that is the
/// one it was executing when it stopped.
/// What the runtime said, out of a log that is mostly its own progress chatter.
///
/// podman's diagnosis is one or two lines among the `STEP n/m` announcements, and the whole of it
/// used to be discarded into `failure unknown` — so an operator was told nothing about a message
/// that named the cause exactly ("pinging container registry localhost: connection refused").
///
/// The tail, minus the step announcements and the retry warnings that repeat it.
fn runtime_complaint(log: &str) -> String {
    let lines: Vec<&str> = log
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with("STEP ")
                && !l.contains("level=warning msg=\"Failed, retrying")
        })
        .collect();
    let tail = lines.len().saturating_sub(4);
    match lines[tail..].join("\n") {
        s if s.is_empty() => "the runtime printed nothing".into(),
        s => s,
    }
}

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
/// The single file at the output path, if there is exactly one.
///
/// Regular files only, and the type is read without following the link: the build chose what is in
/// this directory, and a symlink there points at a path on *our* filesystem. See `newest_file` in
/// the binary, which had the same hole.
fn collect(dir: &std::path::Path) -> Option<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
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
            //
            // No `--force`. A concurrent build on the same machine reuses this image's layers as
            // its cache, and forcing the removal takes them out from under it: podman fails that
            // build with `getting top layer info: layer not known`, which reads as our sandbox
            // being broken rather than as one run deleting another's cache. Without it podman
            // declines while anything still depends on the image, and the stale-leftover sweep
            // collects it on a later run.
            //
            // **And no removal at all while a build is reading the store.** Declining to force was
            // not enough: podman's own cache lookup walks the layer store, and a removal running
            // beside it fails the *build* rather than the removal. The lock is what makes that a
            // mechanism rather than an argument about timing. Taken with `try`, so a run that
            // finishes mid-build leaves its image for the sweep instead of waiting minutes to exit.
            let Some(_store) = crate::store_lock::StoreLock::try_exclusive() else {
                // **Deferred, not dropped.** Skipping was the whole point — a removal must never
                // block a build — but skipping and *forgetting* grows the store without limit: a
                // sweep holds the lock almost continuously, and `prune_images` runs once per
                // process and only for pids that are gone, so nothing is collected until the sweep
                // ends. Measured at four lanes: seventeen build images at ~240 MB each left behind,
                // and 400 targets would be near a hundred gigabytes. The image is remembered, and
                // `reap_deferred` takes it when the store is next quiet.
                tracing::debug!(image = %tag, "a build holds the image store; deferring the image");
                defer(tag.clone());
                return;
            };
            // A run that *did* get the lock clears whatever earlier runs could not — inline,
            // because `reap_deferred` would take the lock again and `flock` treats two opens in one
            // process as two holders. Calling it here was dead code: the inner `try_exclusive`
            // always lost to the guard above it and returned, so the backlog only ever drained at
            // the end of a sweep. The measurement that "proved" this worked was measuring that.
            for tag in std::mem::take(&mut *DEFERRED.lock().unwrap_or_else(|e| e.into_inner())) {
                let _ = std::process::Command::new(&self.binary)
                    .args(["rmi", &tag])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = std::process::Command::new(&self.binary)
                .args(["rmi", tag])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Images this process could not remove when it wanted to, because a build held the store.
///
/// Per process and in memory: a tag here belongs to a run that has already finished, so losing the
/// list to a crash costs a stale image that `prune_stale_leftovers` collects on a later run. It is
/// not a durable queue and must not become one.
static DEFERRED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn defer(tag: String) {
    if let Ok(mut d) = DEFERRED.lock() {
        d.push(tag);
    }
}

/// Remove what earlier runs deferred, if the store is quiet.
///
/// Called where a removal was already going to happen — a finishing run that *did* get the lock
/// clears the backlog at the same time — and once more when a sweep ends and no build is left to
/// hold anything. Never blocks: a backlog that cannot be drained now is drained by whichever of
/// those comes next, and failing that by the stale-leftover sweep in a later process.
pub fn reap_deferred(binary: &str) {
    let Some(_store) = crate::store_lock::StoreLock::try_exclusive() else {
        return;
    };
    let tags: Vec<String> = match DEFERRED.lock() {
        Ok(mut d) => std::mem::take(&mut *d),
        Err(_) => return,
    };
    if tags.is_empty() {
        return;
    }
    tracing::debug!(
        count = tags.len(),
        "removing images deferred while builds held the store"
    );
    for tag in tags {
        // Still no `--force`, for the reason the per-run removal gives: podman declines while
        // anything depends on the image, and the stale sweep collects it later.
        let _ = std::process::Command::new(binary)
            .args(["rmi", &tag])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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
/// Remove what previous runs left behind.
///
/// Only what a **dead** process left, and only once it has been idle for ten minutes — process ids
/// get reused, and a prune that disturbed a live run would be worse than the leak it cleans up.
///
/// The two halves are guarded differently on purpose. Removing a directory touches nothing else, so
/// it happens before every build. Removing an *image* reaches into a store that concurrent builds
/// share: they reuse cached layers belonging to images from earlier runs, so removing one pulls the
/// store out from under a build that is using it — podman fails with `getting top layer info: layer
/// not known`, which reads as our sandbox being broken. That half runs once per process and does
/// not force.
///
/// Best effort throughout. Every failure here is ignored: a stale image costs disk, and refusing to
/// build because the cleanup failed costs the run.
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

    static IMAGES: std::sync::Once = std::sync::Once::new();
    IMAGES.call_once(|| prune_images(binary, MIN_AGE));
}

/// The half that reaches into the shared image store. See [`prune_stale_leftovers`].
fn prune_images(binary: &str, min_age: std::time::Duration) {
    // Nothing is removed while any build on this machine is reading the store. Best effort, like
    // everything else here: a sweep that cannot have the lock runs on the next process.
    let Some(_store) = crate::store_lock::StoreLock::try_exclusive() else {
        tracing::debug!("a build holds the image store; skipping the stale-image sweep");
        return;
    };
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
    // `until` is not cosmetic, and neither is the missing `--force`. The dead-pid check alone is
    // not enough: the image being removed need not be the one a live build is using — they share
    // layers, and removing one disturbs the store underneath the other.
    let Ok(out) = std::process::Command::new(binary)
        .args([
            "images",
            "--filter",
            &format!("until={}m", min_age.as_secs() / 60),
            "--format",
            "{{.Repository}}:{{.Tag}}",
        ])
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
                // No `--force`: an image another build still depends on must survive.
                .args(["rmi", line])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// See [`PodmanBuild::transcript`]. A free function so the one rule that decides whether a run is
/// attestable can be tested without a container runtime — it is the last thing that should only be
/// covered by a test that skips when podman is missing.
fn complete_account(
    egress: EgressTier,
    from_mirror: Option<Vec<trigon_mirror::Exchange>>,
) -> Option<Vec<trigon_mirror::Exchange>> {
    match egress {
        EgressTier::DenyAll => Some(from_mirror.unwrap_or_default()),
        EgressTier::MirrorOnly => from_mirror,
        EgressTier::Open | EgressTier::GitAndMirror => None,
    }
}

fn tempdir(run_id: &str) -> Result<PathBuf, SandboxError> {
    let d = std::env::temp_dir().join(format!("trigon-ctx-{run_id}"));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

#[cfg(test)]
mod account_tests {
    use super::*;

    fn one() -> Vec<trigon_mirror::Exchange> {
        vec![trigon_mirror::Exchange {
            route: "artifact".into(),
            url: "https://registry.npmjs.org/a/-/a-1.0.0.tgz".into(),
            sha256: "aa".repeat(32),
            bytes: 10,
            checked: trigon_mirror::Checked::Opened,
            withheld: None,
        }]
    }

    #[test]
    fn deny_all_accounts_for_egress_without_a_proxy() {
        // `--network none` on both the image build and the run: the build has no interface, so
        // "nothing crossed" is enforced by the kernel rather than observed. An account, and an
        // empty one — which is a claim, not an absence.
        let account = complete_account(EgressTier::DenyAll, None);
        assert_eq!(account.as_deref(), Some(&[][..]));
    }

    #[test]
    fn mirror_only_is_accounted_for_only_when_the_mirror_was_read() {
        assert_eq!(
            complete_account(EgressTier::MirrorOnly, Some(one())),
            Some(one())
        );
        // Not `Some(vec![])`. A mirror we failed to read and a mirror that served nothing are
        // different answers, and turning the first into the second is how "we never looked"
        // becomes "we looked and it was clean".
        assert_eq!(complete_account(EgressTier::MirrorOnly, None), None);
    }

    #[test]
    fn open_egress_is_never_accounted_for() {
        // The tier's entire content is that there is no boundary, so there is nothing to account
        // for and nothing that could produce a complete account of it. Even handed a transcript.
        assert_eq!(complete_account(EgressTier::Open, None), None);
        assert_eq!(complete_account(EgressTier::Open, Some(one())), None);
    }
}
