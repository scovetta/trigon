//! Egress enforcement.
//!
//! The control this exists for is not sandbox escape. It is that **a build which can reach the
//! network can fetch the artifact it is supposed to be reproducing**, and will then reproduce it
//! perfectly, every time, deterministically, past every clean re-run. The clean re-run is not a
//! defence against that; it is the mechanism. See `docs/12-security.md` §2.
//!
//! What enforcement means here is a kernel-level boundary rather than a configured one. Setting
//! `HTTP_PROXY` and hoping is not enforcement: the build runs the package's own scripts, and those
//! scripts are free to ignore it.
//!
//! Rootless podman gives us exactly one primitive that does this: an **internal network**, which
//! netavark firewalls off from the internet *and* from the host. A container on one can reach only
//! other containers on the same network. That is the whole mechanism:
//!
//! ```text
//!   [ build container ]---- internal network ----[ mirror container ]---- default network ----> registries
//!    no other interface                                                    (the only uplink)
//! ```
//!
//! Measured rather than assumed, because the details decide whether this works at all:
//!
//! | Container is on | Reaches internet | Reaches host |
//! |---|---|---|
//! | default network | yes | yes, via host-gateway |
//! | internal only | no | no |
//! | internal **and** default | yes | **no** |
//!
//! The last row is why the mirror runs as a container rather than on the host: once a container
//! touches an internal network, netavark blocks host access on all of its interfaces, so a relay
//! forwarding to a mirror on the host cannot work. It also means the mirror container needs the
//! second network, or it could not reach the registries it proxies.

use std::process::Stdio;

use tokio::process::Command;

use crate::error::SandboxError;

/// A per-run network island.
pub struct Island {
    binary: String,
    pub name: String,
    /// The mirror container, which is the island's only route out.
    mirror: Option<String>,
    pub mirror_host: Option<String>,
}

/// What one run's mirror recorded.
#[derive(Clone, Debug, Default)]
pub struct MirrorLog {
    /// What the artifact guard caught: the artifact under test, or a guarded member of it,
    /// **arrived**.
    ///
    /// Not yet a void. A member arriving is only harmful if it comes back out in the rebuilt
    /// artifact, and that is decided against the build's output — `trigon_mirror::voiding`.
    pub trips: Vec<trigon_mirror::Trip>,
    /// Times the build asked the mirror for its own published artifact and was refused.
    ///
    /// **Not a void.** Nothing arrived, so the thing a void exists to describe did not happen. Some
    /// packages are part of the machinery that builds packages — `python -m build` needs
    /// `packaging` and `pyproject-hooks` — so rebuilding one makes the build ask for it, and
    /// voiding there means those packages can never be verified at an enforced tier. Worth
    /// recording loudly, because it usually explains a build failure further down.
    pub refused_artifact: Vec<String>,
    /// Every response body the mirror served into the build, in the order it finished serving
    /// them. Empty means the build downloaded nothing — a read that failed is an error, not this.
    pub transcript: Vec<trigon_mirror::Exchange>,
    /// Every request the mirror turned away. Separate from the transcript because a refusal serves
    /// no body and has no digest — and because "somebody asked and was refused" is a different
    /// thing to investigate than silence.
    pub refusals: Vec<trigon_mirror::Refusal>,
}

impl MirrorLog {
    /// The registry-pin evidence, derived from what crossed rather than read off a counter.
    ///
    /// This is why refusals are carried out beside the transcript. The counters live on the
    /// `Mirror` object; under an enforced tier that object is inside the build's network island and
    /// the host has no route to it — so the control that caught the `PIP_TRUSTED_HOST` finding read
    /// `null` on exactly the tier where it is the claim, and read fine at `open`, where it matters
    /// least. See `docs/17-backlog.md` B7b.
    pub fn observed(&self) -> trigon_mirror::Observed {
        trigon_mirror::Observed::from_transcript(&self.transcript, self.refusals.len() as u64)
    }
}

impl Island {
    /// Create the network and start the mirror on it.
    pub async fn create(
        binary: &str,
        run_id: &str,
        mirror_image: &str,
        mirror_port: u16,
        guard: Option<&std::path::Path>,
    ) -> Result<Self, SandboxError> {
        let name = format!("trigon-{run_id}");
        let mut island = Island {
            binary: binary.to_string(),
            name: name.clone(),
            mirror: None,
            mirror_host: None,
        };

        // Sweep up after runs that did not get to tear down. A process killed by a wall-clock
        // timeout, a Ctrl-C or an OOM leaves its network and its mirror container behind, and at
        // fleet scale that is an unbounded leak on every worker: after one night of this machine's
        // testing there were two orphaned networks and a container up for eleven hours.
        prune_orphans(binary).await;

        run_ok(binary, &["network", "create", "--internal", &name]).await?;
        tracing::debug!(network = %name, "created an internal network");

        // Two networks: the internal one so the build can reach it, and the default one so it can
        // reach the registries it proxies. A container with only the internal network has no
        // uplink at all, which is the point of the internal network.
        let container = format!("{name}-mirror");
        let port = mirror_port.to_string();
        let mut args: Vec<String> = [
            "run",
            "--detach",
            "--name",
            &container,
            "--network",
            &name,
            "--network",
            "podman",
            // Deliberately no `--rm`. A mirror that crashes on startup takes its logs with it, and
            // then a crash and a slow start are the same observation: the readiness probe polls a
            // container that no longer exists and reports a timeout, which sent an afternoon
            // looking at the wrong thing. `destroy` and `prune_orphans` already remove these.
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Read-only, and `:Z` for SELinux hosts. The mirror needs the manifest and has no business
        // writing to it.
        if let Some(g) = guard {
            args.push("--volume".into());
            args.push(format!("{}:/guard.json:ro,Z", crate::mount_source(g)));
        }
        args.extend([
            mirror_image.to_string(),
            "mirror".into(),
            "--port".into(),
            port,
        ]);
        if guard.is_some() {
            args.extend(["--guard".to_string(), "/guard.json".into()]);
        }
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        run_ok(binary, &argv)
        .await
        .map_err(|e| SandboxError::Failed {
            phase: "setup".into(),
            detail: format!(
                "could not start the mirror container from `{mirror_image}`: {e}. Build one with \
                 `trigon mirror-image`, or name a different one."
            ),
        })?;
        island.mirror = Some(container.clone());

        // Wait for it to bind. `podman run --detach` returns when the container starts, not when
        // the process inside is listening, and the image build begins immediately afterwards: the
        // race shows up as `ECONNREFUSED` from a package manager, which reads like a broken mirror
        // rather than a mirror that was not up yet.
        island.wait_ready(container_start_timeout()).await?;

        // The address the build will use. A name rather than an IP so the strategy stays free of
        // this machine, and podman resolves container names on a shared network.
        island.mirror_host = Some(format!("{container}:{mirror_port}"));
        tracing::info!(
            network = %name,
            mirror = %container,
            "egress island: the build can reach the mirror and nothing else"
        );
        Ok(island)
    }

    /// Block until the mirror reports that it is listening, or give up.
    async fn wait_ready(&self, timeout: std::time::Duration) -> Result<(), SandboxError> {
        let Some(container) = &self.mirror else {
            return Ok(());
        };
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if combined(&self.binary, &["logs", container])
                .await
                .contains("listening")
            {
                return Ok(());
            }
            // A container that has already exited will never start listening, so say what it said
            // rather than waiting out the timeout. An inspect that *fails* means the container is
            // gone entirely, which is equally terminal: polling on is how a crash at startup came
            // to be reported as a 30-second timeout.
            match run_ok(
                &self.binary,
                &["inspect", "--format", "{{.State.Status}}", container],
            )
            .await
            {
                Ok(state) if state != "running" && state != "created" => {
                    let logs = combined(&self.binary, &["logs", container]).await;
                    return Err(SandboxError::Failed {
                        phase: "setup".into(),
                        detail: format!("the mirror container is {state}: {}", tail(&logs)),
                    });
                }
                Err(_) => {
                    return Err(SandboxError::Failed {
                        phase: "setup".into(),
                        detail: format!(
                            "the mirror container {container} disappeared before it started                              listening. If `{}` is older than this build it will not understand                              the flags we pass it; rebuild it with `trigon mirror-image`.",
                            self.mirror_image_hint()
                        ),
                    });
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(SandboxError::Failed {
                    phase: "setup".into(),
                    detail: format!(
                        "the mirror container did not start listening within {timeout:?}"
                    ),
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    /// For the message above, which is the only place it is needed.
    fn mirror_image_hint(&self) -> &str {
        "localhost/trigon-mirror:latest"
    }

    /// The name to attach a build container to.
    pub fn network(&self) -> &str {
        &self.name
    }

    /// What the mirror saw, read out of its container log.
    ///
    /// The log rather than an endpoint, because the mirror sits inside the island and the host has
    /// no route to it: that is the point of the island. Both markers are fixed prefixes so this
    /// does not depend on parsing prose, and only the mirror writes to this log, so nothing the
    /// build prints can forge a line into it.
    ///
    /// **Both streams, and an error when they cannot be read.** This used to take stdout only, and
    /// the mirror writes its trip through `tracing`, which writes to *stderr* — so the single most
    /// important control in the system reported nothing on the only tier that enforces it. A
    /// failure to read is an error rather than an empty list for the same reason: "we could not
    /// look" and "nothing tripped" are different answers, and only one of them means the run is
    /// evidence of anything. The transcript is read the same way and for the same reason: an empty
    /// transcript must mean the build downloaded nothing, never that we failed to ask.
    ///
    /// One read, both answers. Two `podman logs` calls against a container being torn down can
    /// disagree, and a trip list from one read beside a transcript from another is two accounts of
    /// one run.
    pub async fn observations(&self) -> Result<MirrorLog, SandboxError> {
        let Some(container) = &self.mirror else {
            return Ok(MirrorLog::default());
        };
        let logs = run_both(&self.binary, &["logs", container]).await?;
        Ok(MirrorLog {
            trips: trigon_mirror::Trip::parse_log(&logs).map_err(|detail| {
                SandboxError::Failed {
                    phase: "build".into(),
                    detail: format!(
                        "the mirror wrote a guard line this build cannot read, so whether the \
                         artifact under test reached the build is unknown rather than no: {detail}"
                    ),
                }
            })?,
            transcript: trigon_mirror::Exchange::parse_log(&logs).map_err(|detail| {
                SandboxError::Failed {
                    phase: "build".into(),
                    detail: format!(
                        "the mirror wrote a transcript line this build cannot read, so what the                          build downloaded is unknown rather than empty: {detail}"
                    ),
                }
            })?,
            refused_artifact: logs
                .lines()
                .filter(|l| l.contains(trigon_mirror::REFUSED_ARTIFACT_MARKER))
                .map(str::to_owned)
                .collect(),
            refusals: trigon_mirror::Refusal::parse_log(&logs).map_err(|detail| {
                SandboxError::Failed {
                    phase: "build".into(),
                    detail: format!(
                        "the mirror wrote a refusal line this build cannot read, so whether the \
                         build was turned away is unknown rather than no: {detail}"
                    ),
                }
            })?,
        })
    }

    /// The mirror's address on the island.
    ///
    /// An IP rather than the container name, because `podman build` does not join podman's DNS the
    /// way `podman run` does, and the deps phase runs at image-build time. The strategy still names
    /// a stable host; this is what that host is mapped to, so nothing about this machine reaches
    /// the strategy digest.
    pub async fn mirror_ip(&self) -> Option<String> {
        let container = self.mirror.as_ref()?;
        let out = run_ok(
            &self.binary,
            &[
                "inspect",
                "--format",
                // `index`, not dot access: the network name contains dashes, which a Go template
                // reads as subtraction. Dot access here is a template parse error, and the empty
                // output it produces looks exactly like a container with no address.
                &format!(
                    "{{{{(index .NetworkSettings.Networks \"{}\").IPAddress}}}}",
                    self.name
                ),
                container,
            ],
        )
        .await
        .ok()?;
        (!out.is_empty()).then_some(out)
    }

    /// Stop the mirror and remove the network.
    pub async fn destroy(self) {
        if let Some(c) = &self.mirror {
            let _ = run_ok(&self.binary, &["stop", "--time", "2", c]).await;
            // Explicit, now that the container does not remove itself.
            let _ = run_ok(&self.binary, &["rm", "--force", c]).await;
        }
        let _ = run_ok(&self.binary, &["network", "rm", "--force", &self.name]).await;
        tracing::debug!(network = %self.name, "tore down the egress island");
    }
}

/// A container's output, both streams.
///
/// `podman logs` splits them, and a program that dies on a bad argument says so on stderr — which
/// is exactly the case this is here to report. Reading stdout alone produced an empty diagnosis for
/// the one failure that most needed one.
/// Both streams, or the reason neither could be read.
///
/// Distinct from [`combined`], which answers the empty string on failure. Anything deciding whether
/// a run is evidence needs to tell a quiet log from an unreadable one.
async fn run_both(binary: &str, args: &[&str]) -> Result<String, SandboxError> {
    let out = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await?;
    if !out.status.success() {
        return Err(SandboxError::Failed {
            phase: "collect".into(),
            detail: format!(
                "reading the mirror's log: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(s)
}

async fn combined(binary: &str, args: &[&str]) -> String {
    let Ok(out) = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
    else {
        return String::new();
    };
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

/// The last few lines of a container's output, for an error message a person reads.
fn tail(logs: &str) -> String {
    let lines: Vec<&str> = logs.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(4)..].join(" / ")
}

async fn run_ok(binary: &str, args: &[&str]) -> Result<String, SandboxError> {
    let out = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await?;
    if !out.status.success() {
        return Err(SandboxError::Failed {
            phase: "setup".into(),
            detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn container_start_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

/// Remove islands whose mirror is gone.
///
/// Keyed on whether the mirror container is still running rather than on age, so a concurrent run
/// is never disturbed: a live island always has one. A network that outlives its mirror can never
/// be used again, because the mirror was its only route out.
/// Whether the process that created this island is gone.
///
/// The network is named `trigon-{run_id}` and a run id ends in the pid that built it, so the
/// question has an answer without inspecting anything. Errs toward *alive*: a name with no
/// parseable pid, or a pid that still exists, is left alone. That direction is the safe one — the
/// failure it prevents is one Trigon deleting the network out from under another's running build,
/// and the failure it permits is a leak surviving one more sweep.
///
/// Pid reuse can only produce the harmless answer. A live run always has its `/proc` entry, so a
/// reused pid makes this say "alive" about a dead owner and the orphan waits; it can never say
/// "gone" about a live one.
pub fn owner_is_gone(network: &str) -> bool {
    let Some(pid) = network
        .rsplit('-')
        .next()
        .and_then(|p| p.parse::<u32>().ok())
    else {
        return false;
    };
    !std::path::Path::new(&format!("/proc/{pid}")).exists()
}

async fn prune_orphans(binary: &str) {
    let Ok(list) = run_ok(binary, &["network", "ls", "--format", "{{.Name}}"]).await else {
        return;
    };
    for name in list.lines().filter(|n| n.starts_with("trigon-")) {
        let container = format!("{name}-mirror");
        // **Running is not the same as owned.** This used to skip every running container, which
        // is the one state a killed-parent orphan is ever in: a process felled by a wall-clock
        // timeout, a Ctrl-C or an OOM leaves its mirror *running*, not exited. So the sweep could
        // only ever collect islands that had already tidied themselves, and the leak it was written
        // for — this function's own doc comment describes "a container up for eleven hours" —
        // survived every subsequent run. One was found at seven hours with this code in place.
        //
        // The sibling sweeper for build contexts and images had the missing half all along: a run
        // id ends in the pid of the process that made it, so ownership is a question with an
        // answer. Two sweepers for one class of leak, and only one of them asked.
        let running = run_ok(
            binary,
            &["inspect", "--format", "{{.State.Status}}", &container],
        )
        .await
        .map(|s| s == "running")
        .unwrap_or(false);
        if running && !owner_is_gone(name) {
            continue;
        }
        let _ = run_ok(binary, &["rm", "--force", &container]).await;
        if run_ok(binary, &["network", "rm", "--force", name])
            .await
            .is_ok()
        {
            tracing::debug!(network = name, "removed an orphaned egress island");
        }
    }
}
