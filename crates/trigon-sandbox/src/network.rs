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

impl Island {
    /// Create the network and start the mirror on it.
    pub async fn create(
        binary: &str,
        run_id: &str,
        mirror_image: &str,
        mirror_port: u16,
    ) -> Result<Self, SandboxError> {
        let name = format!("trigon-{run_id}");
        let mut island = Island {
            binary: binary.to_string(),
            name: name.clone(),
            mirror: None,
            mirror_host: None,
        };

        run_ok(binary, &["network", "create", "--internal", &name]).await?;
        tracing::debug!(network = %name, "created an internal network");

        // Two networks: the internal one so the build can reach it, and the default one so it can
        // reach the registries it proxies. A container with only the internal network has no
        // uplink at all, which is the point of the internal network.
        let container = format!("{name}-mirror");
        run_ok(
            binary,
            &[
                "run",
                "--detach",
                "--name",
                &container,
                "--network",
                &name,
                "--network",
                "podman",
                "--rm",
                mirror_image,
                "mirror",
                "--port",
                &mirror_port.to_string(),
            ],
        )
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
            if let Ok(logs) = run_ok(&self.binary, &["logs", container]).await
                && logs.contains("listening")
            {
                return Ok(());
            }
            // A container that has already exited will never start listening, so say what it said
            // rather than waiting out the timeout.
            if let Ok(state) = run_ok(
                &self.binary,
                &["inspect", "--format", "{{.State.Status}}", container],
            )
            .await
                && state != "running"
                && state != "created"
            {
                let logs = run_ok(&self.binary, &["logs", container])
                    .await
                    .unwrap_or_default();
                return Err(SandboxError::Failed {
                    phase: "setup".into(),
                    detail: format!("the mirror container is {state}: {logs}"),
                });
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

    /// The name to attach a build container to.
    pub fn network(&self) -> &str {
        &self.name
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
        }
        let _ = run_ok(&self.binary, &["network", "rm", "--force", &self.name]).await;
        tracing::debug!(network = %self.name, "tore down the egress island");
    }
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
