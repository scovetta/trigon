//! `trigon`, the single binary.
//!
//! Two builds from one source. The default one can build packages; `--no-default-features` drops
//! the async runtime and everything that needs one, leaving a binary that reproduces a verdict from
//! two artifacts and nothing else. That second build is the claim a sceptic can check with
//! `cargo tree` rather than take on trust, and the `verifier` CI job checks it on every commit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use trigon_archive::Limits;
use trigon_compare::{Comparison, compare_bytes};
use trigon_core::{Format, Match};
use trigon_stabilize::{default_for, profile};

#[derive(Parser, Debug)]
#[command(
    name = "trigon",
    version,
    about = "Semantic rebuild verification for open-source packages."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Say more. Once for what the tool is doing, twice for the build's own output.
    ///
    /// A container build is minutes of silence otherwise, which is indistinguishable from a hang.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Structured logs, one JSON object per line, for anything that aggregates them.
    #[arg(long, global = true)]
    log_json: bool,
}

/// Install the subscriber.
///
/// `RUST_LOG` wins when it is set, because someone debugging one crate should not have to discover
/// our flags. Logs go to stderr so that stdout stays the machine-readable result: `--output json`
/// piped to `jq` must not have log lines in it.
fn init_logging(verbose: u8, json: bool) {
    use tracing_subscriber::{EnvFilter, fmt};

    let default = match verbose {
        0 => "warn",
        1 => "info,trigon::build=info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    // ANSI follows the terminal, always. Escape sequences written into a pipe corrupt whatever
    // reads them, and a log line that greps differently depending on whether a human was watching
    // is worse than one with no colour at all.
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let builder = fmt()
        .with_writer(std::io::stderr)
        .with_target(verbose >= 2)
        .with_ansi(ansi)
        .with_env_filter(filter);
    if json {
        builder.json().flatten_event(true).init();
    } else {
        // Timestamps only when they can mean something. For a one-shot command they are noise;
        // for a multi-minute build they are how you tell a slow phase from a stuck one.
        if verbose >= 1 {
            builder.init();
        } else {
            // Timestamps only when they can mean something. For a one-shot command they are noise;
            // for a multi-minute build they are how you tell a slow phase from a stuck one.
            builder.without_time().init();
        }
    }
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Compare two artifacts and report how far they agree.
    Verify {
        /// The published artifact.
        upstream: PathBuf,
        /// The rebuilt artifact.
        rebuild: PathBuf,
        /// Container format. Inferred from the upstream file name when omitted.
        #[arg(long)]
        format: Option<String>,
        /// Stabilizer profile. Defaults to the one implied by the format.
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
        /// List every differing member rather than the first few.
        #[arg(long)]
        explain: bool,
        /// Write a DSSE-wrapped in-toto statement of the result here.
        ///
        /// Emitted for a divergence as readily as for a match: a negative result somebody else can
        /// check is the more useful of the two, and one that only we can reproduce is an accusation.
        #[arg(long)]
        attest: Option<PathBuf>,
        /// Sign the statement with an ed25519 key held in this file (32 raw bytes).
        ///
        /// Without one the bundle is unsigned. That is a complete, re-derivable claim that names
        /// nobody, which is the honest default for a laptop.
        #[arg(long, requires = "attest")]
        key: Option<PathBuf>,
        /// The name to record as the statement's subject. Defaults to the upstream file name.
        #[arg(long, requires = "attest")]
        subject: Option<String>,
    },
    /// Check an attestation against the artifacts it is about.
    ///
    /// The point of the whole design: this needs the bundle and two files, no network, and no trust
    /// in us. Under `--rerun-comparison` it recomputes the claim from the bytes rather than reading
    /// what the statement asserts.
    VerifyAttestation {
        /// A DSSE bundle, as written by `trigon verify --attest`.
        bundle: PathBuf,
        /// Recompute the equivalence claim from the artifacts instead of believing it.
        #[arg(long)]
        rerun_comparison: bool,
        /// The published artifact. Required by `--rerun-comparison`.
        #[arg(long, requires = "rerun_comparison")]
        upstream: Option<PathBuf>,
        /// The rebuilt artifact. Required by `--rerun-comparison`.
        #[arg(long, requires = "rerun_comparison")]
        rebuild: Option<PathBuf>,
        /// Check the signature against this ed25519 public key, given as hex.
        ///
        /// Omitted, the signature is reported but not checked — and a bundle nobody pinned a key
        /// for is worth exactly its re-derivation.
        #[arg(long)]
        public_key: Option<String>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
    },
    /// Stabilize one artifact and write the result.
    ///
    /// Flags mirror the reference implementation's, so a differential run can enable one pass at a
    /// time on both sides and localize a digest mismatch to the pass that caused it.
    Stabilize {
        #[arg(long)]
        infile: PathBuf,
        #[arg(long)]
        outfile: PathBuf,
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        /// Comma-separated pass ids, or `all`, or `none`.
        #[arg(long, value_delimiter = ',', default_value = "all")]
        enable_passes: Vec<String>,
        /// Comma-separated pass ids, or `all`, or `none`.
        #[arg(long, value_delimiter = ',', default_value = "none")]
        disable_passes: Vec<String>,
        /// Print a JSON summary of the result to stdout.
        #[arg(long)]
        report: bool,
    },
    /// List the stabilizers in a profile, with risk tiers and the set digest.
    Stabilizers {
        #[arg(long, default_value = "tar-gzip")]
        profile: String,
    },
    /// Work with strategy documents.
    #[command(subcommand)]
    Strategy(StrategyCmd),
    /// Rebuild a published package from source and compare the result.
    ///
    /// Resolve, infer a strategy, fetch what the registry published, build it in a container, and
    /// report how far the two agree. Every step is printed, because a verdict whose derivation is
    /// invisible is a verdict nobody can argue with.
    #[cfg(feature = "build")]
    Rebuild {
        /// A package URL, such as `pkg:npm/left-pad@1.3.0`.
        purl: String,
        /// Which file, when the version publishes more than one.
        #[arg(long)]
        artifact: Option<String>,
        /// Base image, pinned by digest.
        #[arg(long)]
        image: String,
        /// Working directory for the fetched and rebuilt artifacts.
        #[arg(long, default_value = "./trigon-work")]
        work: PathBuf,
        /// What the build may reach.
        #[arg(long, default_value = "open")]
        egress: String,
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
        /// A checked-in definitions directory, consulted before any heuristic.
        #[arg(long)]
        definitions: Option<PathBuf>,
        /// Image holding `trigon mirror`, which is what makes `--egress mirror-only` enforceable.
        #[arg(long, default_value = "localhost/trigon-mirror:latest")]
        mirror_image: String,
        /// Resolve dependencies against the index as it stood when the package was published.
        ///
        /// `auto` starts a mirror for the run. Without one the rebuild resolves against today's
        /// registry, which makes any package with a floating range irreproducible by construction,
        /// and that is reported as an assumption rather than pinned to a mirror that is not there.
        #[arg(long)]
        timewarp: Option<String>,
        /// A checkout of the package's source.
        ///
        /// Narrows the artifact guard: a member the repository also contains is not evidence of
        /// anything, because the build is entitled to fetch it and something else vendoring the
        /// same file is ordinary. Without one the guard is wider than designed, which errs toward
        /// voiding an honest run rather than missing a forged one.
        #[arg(long)]
        source: Option<PathBuf>,
        /// Write a DSSE-wrapped statement of the result here.
        #[arg(long)]
        attest: Option<PathBuf>,
        /// Sign it with an ed25519 key held in this file (32 raw bytes, or hex).
        #[arg(long, requires = "attest")]
        key: Option<PathBuf>,
    },
    /// Build the container image that runs the mirror inside a build's network island.
    ///
    /// Compiled inside a container, so nothing is needed on this machine beyond podman. The image
    /// is what makes `--egress mirror-only` enforceable: the build's network has no route out
    /// except this container.
    #[cfg(feature = "build")]
    MirrorImage {
        #[arg(long, default_value = "localhost/trigon-mirror:latest")]
        tag: String,
    },
    /// Serve a registry index as it stood at a named instant.
    ///
    /// Point a package manager at `http://<platform>:<RFC3339>@<host>/`. The credentials carry the
    /// filter, which is the one configuration channel every client forwards on every request.
    #[cfg(feature = "build")]
    Mirror {
        #[arg(long, default_value_t = 8129)]
        port: u16,
        /// A guard manifest: the artifact this run must not be allowed to download, and the
        /// members of it worth watching for inside anything else.
        #[arg(long)]
        guard: Option<PathBuf>,
    },
    /// Rebuild many packages and report the rate.
    ///
    /// One data point is an anecdote. This is what turns a working pipeline into a number, and the
    /// number is only meaningful because outcomes are separated: a package that does not reproduce
    /// and a build our own infrastructure could not run are different findings.
    #[cfg(feature = "build")]
    Sweep {
        /// A file of package URLs, one per line. `#` comments and blank lines are skipped.
        targets: PathBuf,
        #[arg(long)]
        image: String,
        #[arg(long, default_value = "./trigon-sweep")]
        work: PathBuf,
        #[arg(long, default_value = "open")]
        egress: String,
        #[arg(long, default_value_t = 600)]
        timeout: u64,
        #[arg(long)]
        definitions: Option<PathBuf>,
        #[arg(long, default_value = "localhost/trigon-mirror:latest")]
        mirror_image: String,
        #[arg(long)]
        timewarp: Option<String>,
    },
    /// Ask a registry what it knows about a package.
    #[cfg(feature = "build")]
    Resolve {
        /// A package URL, such as `pkg:npm/left-pad@1.3.0`.
        purl: String,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
    },
    /// Download a published artifact, verifying it against what the registry declared.
    #[cfg(feature = "build")]
    Fetch {
        /// A package URL.
        purl: String,
        /// Which file, when the version publishes more than one.
        #[arg(long)]
        artifact: Option<String>,
        /// Where to write it. Defaults to the artifact's own filename in the current directory.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Build a package from a strategy, in a container.
    #[cfg(feature = "build")]
    Build {
        /// A strategy document, or an oss-rebuild `build.yaml` with `--import`.
        file: PathBuf,
        #[arg(long)]
        import: bool,
        /// Base image, pinned by digest. A tag is refused: it resolves to different bytes on
        /// different days, which makes the run unreproducible.
        #[arg(long)]
        image: String,
        /// Where the built artifact lands.
        #[arg(long, default_value = "./out")]
        out: PathBuf,
        /// What the build may reach. `deny-all` is the strongest claim available.
        #[arg(long, default_value = "deny-all")]
        egress: String,
        /// Seconds before the build is killed.
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
        /// Keep the image afterwards, to exec into or pull.
        #[arg(long)]
        retain: bool,
        /// Image holding `trigon mirror`, which is what makes `--egress mirror-only` enforceable.
        #[arg(long, default_value = "localhost/trigon-mirror:latest")]
        mirror_image: String,
        /// Host the strategy calls the mirror, mapped by the runner to wherever it is.
        #[arg(long, default_value = "timewarp:8129")]
        timewarp: String,
        /// A checkout of the package's source.
        ///
        /// Narrows the artifact guard: a member the repository also contains is not evidence of
        /// anything, because the build is entitled to fetch it and something else vendoring the
        /// same file is ordinary. Without one the guard is wider than designed, which errs toward
        /// voiding an honest run rather than missing a forged one.
        #[arg(long)]
        source: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum StrategyCmd {
    /// Render a strategy to the scripts an executor would run.
    ///
    /// Rendering is a pure function of the strategy, the target and the environment, so this is
    /// exactly what a build would receive: no part of it is decided later.
    Render {
        /// A strategy document, or an oss-rebuild `build.yaml` with `--import`.
        file: PathBuf,
        /// Read the prior art's format and lower it into ours.
        #[arg(long)]
        import: bool,
        /// Base host of the time-filtering registry mirror.
        #[arg(long, default_value = "timewarp")]
        timewarp: String,
        /// Treat the working tree as already checked out, as a cached image layer would.
        #[arg(long)]
        has_repo: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
    },
    /// List the registered tools.
    Tools,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

/// Exit quietly when the reader goes away, rather than panicking.
///
/// `trigon verify x y | head -3` would otherwise exit 101 with a backtrace: Rust masks SIGPIPE at
/// startup, so the write returns EPIPE and `println!` panics on it. That matters more here than in
/// most tools because the exit code carries the verdict, and a panic mid-pipeline is
/// indistinguishable from a real failure.
///
/// A panic hook rather than restoring SIGPIPE to its default, which is what this was and which was
/// worse than the problem. The signal disposition is process-wide and applies to **every** write,
/// including sockets: the mirror proxies to a build container, the container finishes and closes
/// its connection, the mirror writes one more chunk, and the whole run dies with status 141 having
/// printed nothing. It killed a twenty-target sweep twice at the same target before anyone looked
/// at the exit code.
fn exit_quietly_on_broken_pipe() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("");
        if msg.contains("Broken pipe") || msg.contains("os error 32") {
            // 128 + SIGPIPE, which is what a shell reports for `yes | head`.
            std::process::exit(141);
        }
        default(info);
    }));
}

fn main() -> Result<()> {
    exit_quietly_on_broken_pipe();
    let cli = Cli::parse();
    init_logging(cli.verbose, cli.log_json);
    let result = dispatch(cli.cmd);
    if let Err(e) = &result {
        report_fault(e);
    }
    result
}

/// Say whose fault a failure was, when the error knows.
///
/// `Fault` exists so that a sweep's numbers mean something: a hundred failures is a different
/// situation depending on whether they are our infrastructure, the packages' own builds, or a
/// policy we are enforcing. The classification was implemented and never used, which made it
/// documentation rather than a control.
fn report_fault(e: &anyhow::Error) {
    use trigon_core::{Classify, Fault};
    let fault = e
        .downcast_ref::<trigon_compare::CompareError>()
        .map(|e| e.fault())
        .or_else(|| {
            e.downcast_ref::<trigon_archive::ArchiveError>()
                .map(|e| e.fault())
        })
        .or_else(|| {
            e.downcast_ref::<trigon_strategy::StrategyError>()
                .map(|e| e.fault())
        });
    #[cfg(feature = "build")]
    let fault = fault
        .or_else(|| {
            e.downcast_ref::<trigon_sandbox::SandboxError>()
                .map(|e| e.fault())
        })
        .or_else(|| {
            e.downcast_ref::<trigon_registry::RegistryError>()
                .map(|e| e.fault())
        });
    let Some(fault) = fault else { return };
    let retryable = retryable_of(e).unwrap_or_else(|| fault.is_retryable());
    let whose = match fault {
        Fault::Infra => "ours: infrastructure, and retryable",
        Fault::Upstream => "the published artifact's",
        Fault::Build => "the package's own build",
        Fault::Policy => "a policy this run is enforcing",
        Fault::Bug => "a bug in trigon; please report it",
    };
    tracing::error!(fault = ?fault, retryable, "{whose}");
}

/// Retryability as the error itself reports it.
///
/// The fault class is a default and cannot always answer: a registry that was briefly down and an
/// artifact that will never parse are both `Upstream`. Asking the error means a fleet does not
/// spend a worker slot per sweep re-reaching the same conclusion.
fn retryable_of(e: &anyhow::Error) -> Option<bool> {
    use trigon_core::Classify;
    let r = e
        .downcast_ref::<trigon_compare::CompareError>()
        .map(Classify::is_retryable)
        .or_else(|| {
            e.downcast_ref::<trigon_archive::ArchiveError>()
                .map(Classify::is_retryable)
        })
        .or_else(|| {
            e.downcast_ref::<trigon_strategy::StrategyError>()
                .map(Classify::is_retryable)
        });
    #[cfg(feature = "build")]
    let r = r
        .or_else(|| {
            e.downcast_ref::<trigon_sandbox::SandboxError>()
                .map(Classify::is_retryable)
        })
        .or_else(|| {
            e.downcast_ref::<trigon_registry::RegistryError>()
                .map(Classify::is_retryable)
        });
    r
}

fn dispatch(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Verify {
            upstream,
            rebuild,
            format,
            profile: prof,
            output,
            explain,
            attest,
            key,
            subject,
        } => verify(
            &upstream,
            &rebuild,
            format.as_deref(),
            prof.as_deref(),
            output,
            explain,
            Attest {
                to: attest.as_deref(),
                key: key.as_deref(),
                subject: subject.as_deref(),
            },
        ),
        Cmd::VerifyAttestation {
            bundle,
            rerun_comparison,
            upstream,
            rebuild,
            public_key,
            output,
        } => verify_attestation(
            &bundle,
            rerun_comparison,
            upstream.as_deref(),
            rebuild.as_deref(),
            public_key.as_deref(),
            output,
        ),
        Cmd::Stabilize {
            infile,
            outfile,
            format,
            profile: prof,
            enable_passes,
            disable_passes,
            report,
        } => stabilize_one(
            &infile,
            &outfile,
            format.as_deref(),
            prof.as_deref(),
            &enable_passes,
            &disable_passes,
            report,
        ),
        Cmd::Stabilizers { profile: prof } => stabilizers(&prof),
        Cmd::Strategy(StrategyCmd::Render {
            file,
            import,
            timewarp,
            has_repo,
            output,
        }) => strategy_render(&file, import, &timewarp, has_repo, output),
        Cmd::Strategy(StrategyCmd::Tools) => strategy_tools(),
        #[cfg(feature = "build")]
        Cmd::Rebuild {
            purl,
            artifact,
            image,
            work,
            egress,
            timeout,
            definitions,
            mirror_image,
            timewarp,
            source,
            attest,
            key,
        } => rebuild::run(rebuild::Args {
            purl,
            artifact,
            image,
            work,
            egress,
            timeout,
            definitions,
            mirror_image,
            timewarp,
            source,
            attest,
            key,
        }),
        #[cfg(feature = "build")]
        Cmd::Sweep {
            targets,
            image,
            work,
            egress,
            timeout,
            definitions,
            mirror_image,
            timewarp,
        } => sweep::run(sweep::Args {
            targets,
            image,
            work,
            egress,
            timeout,
            definitions,
            mirror_image,
            timewarp,
        }),
        #[cfg(feature = "build")]
        Cmd::MirrorImage { tag } => mirror::build_image(&tag),
        #[cfg(feature = "build")]
        Cmd::Mirror { port, guard } => mirror::serve(port, guard.as_deref()),
        #[cfg(feature = "build")]
        Cmd::Resolve { purl, output } => registry::resolve(&purl, output),
        #[cfg(feature = "build")]
        Cmd::Fetch {
            purl,
            artifact,
            out,
        } => registry::fetch(&purl, artifact.as_deref(), out.as_deref()),
        #[cfg(feature = "build")]
        Cmd::Build {
            file,
            import,
            image,
            out,
            egress,
            timeout,
            retain,
            mirror_image,
            timewarp,
            source,
        } => build::run_with(
            &file,
            import,
            &image,
            &out,
            &egress,
            timeout,
            retain,
            &timewarp,
            None,
            Some(&mirror_image),
            true,
            None,
            source.as_deref(),
        ),
    }
}

#[cfg(feature = "build")]
mod registry {
    use std::str::FromStr;

    use super::*;
    use trigon_core::TargetRef;
    use trigon_registry::{Client, ClientConfig, for_ecosystem};

    fn runtime() -> Result<tokio::runtime::Runtime> {
        Ok(tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?)
    }

    pub fn resolve(purl: &str, output: OutputFormat) -> Result<()> {
        let target = TargetRef::from_str(purl)?;
        let registry = for_ecosystem(target.ecosystem, Client::new(ClientConfig::default())?)?;

        let resolved = runtime()?.block_on(registry.resolve(&target))?;

        match output {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&resolved)?);
            }
            OutputFormat::Text => {
                println!("{}", resolved.reference);
                if let Some(t) = &resolved.intrinsics.publish_time {
                    println!("  published  {t}");
                }
                match &resolved.source {
                    // The rung is printed, not just the answer. A registry-recorded commit and a
                    // fuzzy tag match are both "a commit", and they should not be read alike.
                    Some(s) if !s.commit.is_empty() => {
                        println!("  source     {} @ {}", s.repo_url, s.commit);
                        println!("  found by   {:?}", s.how);
                    }
                    Some(s) => {
                        println!("  source     {} (no commit)", s.repo_url);
                        println!(
                            "  found by   {:?}: something still has to find the commit",
                            s.how
                        );
                    }
                    None => println!("  source     not declared"),
                }
                println!("\n  artifacts");
                let w = resolved
                    .artifacts
                    .iter()
                    .map(|a| a.id.as_str().len())
                    .max()
                    .unwrap_or(0);
                for a in &resolved.artifacts {
                    let digest = match &a.declared_sha256 {
                        Some(d) => format!("sha256:{}", &d.to_hex()[..16]),
                        // Said plainly. npm publishes sha1 and sometimes sha512, so for most of it
                        // there is nothing to check the bytes against.
                        None => "no sha256 declared".into(),
                    };
                    println!("    {:<w$}  {digest}", a.id.as_str());
                }
            }
        }
        Ok(())
    }

    pub fn fetch(purl: &str, artifact: Option<&str>, out: Option<&Path>) -> Result<()> {
        let target = TargetRef::from_str(purl)?;
        let registry = for_ecosystem(target.ecosystem, Client::new(ClientConfig::default())?)?;
        let rt = runtime()?;

        let resolved = rt.block_on(registry.resolve(&target))?;
        let meta = resolved.pick(artifact)?;
        let path = out
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(meta.id.as_str()));

        let mut file =
            std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        let digest = rt.block_on(registry.fetch(meta, &mut file))?;

        println!("{}", path.display());
        println!("  sha256  {digest}");
        println!(
            "  {}",
            match &meta.declared_sha256 {
                Some(_) => "matches the digest the registry declared",
                None => "the registry declared no sha256, so nothing was checked against it",
            }
        );
        Ok(())
    }
}

#[cfg(feature = "build")]
mod build {
    use super::*;
    use trigon_sandbox::{
        BuildPlan, BuildRunner, EgressTier, Limits, OciPlan, PodmanRunner, RunOpts,
    };

    fn egress_tier(s: &str) -> Result<EgressTier> {
        Ok(match s {
            "deny-all" => EgressTier::DenyAll,
            "mirror-only" => EgressTier::MirrorOnly,
            "git-and-mirror" => EgressTier::GitAndMirror,
            "open" => EgressTier::Open,
            other => bail!(
                "unknown egress tier `{other}`; one of: deny-all, mirror-only, git-and-mirror, open"
            ),
        })
    }

    /// Render a strategy and run it, saying where the mirror is and what the strategy calls it.
    #[allow(clippy::too_many_arguments)]
    pub fn run_with(
        file: &Path,
        import: bool,
        image: &str,
        out: &Path,
        egress: &str,
        timeout: u64,
        retain: bool,
        timewarp_host: &str,
        mirror_addr: Option<&str>,
        mirror_image: Option<&str>,
        verbose: bool,
        guard: Option<&Path>,
        _source: Option<&Path>,
    ) -> Result<()> {
        let (instructions, digest, _custom) =
            crate::render_strategy(file, import, timewarp_host, false)?;
        let egress = egress_tier(egress)?;

        // `host-gateway` is podman's name for the host as seen from the container. The strategy
        // names a stable host so that the port, which is whatever was free on this machine, stays
        // out of the strategy digest.
        // Where the mirror is depends on the tier. Under `mirror-only` it runs inside the build's
        // network island, because a container on an internal network cannot reach the host at all;
        // otherwise it runs on the host and the container reaches it through the gateway. Either
        // way the strategy names a stable host and the runner maps it.
        let mut extra_hosts = std::collections::BTreeMap::new();
        let name = timewarp_host
            .split(':')
            .next()
            .unwrap_or(timewarp_host)
            .to_string();
        match egress {
            trigon_sandbox::EgressTier::MirrorOnly => {
                extra_hosts.insert(name, "mirror".to_string());
            }
            _ if mirror_addr.is_some() => {
                extra_hosts.insert(name, "host-gateway".to_string());
            }
            _ => {}
        }

        let plan = BuildPlan::Oci(OciPlan {
            base_image: image.to_string(),
            system_deps: instructions.requires.system_deps.clone(),
            source: instructions.source.clone(),
            deps: instructions.deps.clone(),
            build: instructions.build.clone(),
            output_path: instructions.output_path.clone(),
            egress,
            privileged: instructions.requires.privileged,
            extra_hosts,
        });

        let run_id = format!("{}-{}", &digest[..12], std::process::id());
        let runner = PodmanRunner::new(out).with_mirror_image(mirror_image.map(str::to_string));

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            runner.health().await.context("podman is not usable")?;

            let opts = RunOpts {
                run_id: run_id.clone(),
                limits: Limits {
                    wall_clock: std::time::Duration::from_secs(timeout),
                    ..Default::default()
                },
                retain,
                mirror_port: 8129,
                guard: guard.map(Path::to_path_buf),
            };
            let handle = runner.start(&plan, &opts).await?;
            let outcome = handle.wait().await?;

            if verbose {
                println!("strategy {}", &digest[..16]);
                println!("  egress    {}", outcome.egress);
                println!("  isolation {:?}", outcome.isolation);
                for (phase, d) in &outcome.timings {
                    match d {
                        // `None` means no data, never zero. A timing we failed to read is not a
                        // fast phase, and reporting it as one poisons every average downstream.
                        Some(d) => println!("  {phase:?}{:>10.1}s", d.as_secs_f64()),
                        None => println!("  {phase:?}      no data"),
                    }
                }
                if !outcome.attestable {
                    println!(
                        "\n  not attestable: this runner enforces no mirror and records no \
                         network transcript, so it cannot claim the build fetched nothing it \
                         should not have"
                    );
                }
                match (&outcome.artifact, outcome.succeeded()) {
                    (Some(p), _) => println!("\n  artifact  {}", p.display()),
                    (None, true) => println!(
                        "\n  the build succeeded but produced no single artifact. Check \
                         output_path: a glob matching several files does not identify one."
                    ),
                    (None, false) => {}
                }
            }
            if let Some(t) = outcome.guard_trips.first() {
                // Before the exit status is even considered: a tripped guard means the run cannot
                // be used, whether the build succeeded or failed.
                bail!("void: {t}");
            }
            // The log, always, whether the build worked or not. A successful build's log is what
            // tells you *how* it succeeded, and until `trigon-store` exists this file is the whole
            // run record. Next to the strategy and the artifact, which is where somebody looks.
            let log_path = out.join("build.log");
            if let Err(e) = std::fs::write(&log_path, &outcome.log_tail) {
                tracing::warn!("could not write {}: {e}", log_path.display());
            }

            if !outcome.succeeded() {
                // Named here, where the log is in hand. Re-deriving it later from an error string
                // would mean classifying our own prose instead of the build's output.
                let signature = trigon_core::classify(&outcome.log_tail);
                if verbose {
                    // The compressed form, not the raw tail. A hundred kilobytes of dependency
                    // chatter in a terminal buries the four lines that say what happened, and the
                    // full text is on disk either way.
                    let short = trigon_core::compress(&outcome.log_tail, 4096);
                    eprintln!("\n{}", short.text);
                    println!("\n  failure   {signature}");
                    if !signature.repairable {
                        println!("            no strategy change fixes this one");
                    }
                    println!("  log       {}", log_path.display());
                }
                return Err(BuildFailure {
                    phase: outcome
                        .failed_in
                        .map(|p| format!("{p:?}").to_lowercase())
                        .unwrap_or_else(|| "build".into()),
                    exit_code: outcome.exit_code,
                    signature,
                }
                .into());
            }
            Ok(())
        })
    }
}

/// A build that ran and did not finish, with the failure already named.
///
/// A typed error rather than a formatted string, because the signature keys a cache and gates
/// spend: reconstructing it by pattern-matching our own error prose would put a second, worse
/// classifier in the path of every decision the first one exists to make.
#[derive(Debug)]
pub struct BuildFailure {
    pub phase: String,
    pub exit_code: i32,
    pub signature: trigon_core::FailureSignature,
}

impl std::fmt::Display for BuildFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the build failed in {} with exit {} ({})",
            self.phase, self.exit_code, self.signature
        )
    }
}

impl std::error::Error for BuildFailure {}

fn verify(
    upstream: &Path,
    rebuild: &Path,
    format: Option<&str>,
    prof: Option<&str>,
    output: OutputFormat,
    explain: bool,
    attest: Attest<'_>,
) -> Result<()> {
    let fmt = resolve_format(upstream, format)?;
    let set = resolve_profile(upstream, prof, fmt)?;

    let a = std::fs::read(upstream).with_context(|| format!("reading {}", upstream.display()))?;
    let b = std::fs::read(rebuild).with_context(|| format!("reading {}", rebuild.display()))?;

    let c = compare_bytes(a, b, fmt, &set, &Limits::default())?;
    if let Some(path) = attest.to {
        let name = attest
            .subject
            .map(str::to_string)
            .unwrap_or_else(|| file_name(upstream));
        write_bundle(path, attest.key, &name, &c)?;
    }
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&c)?),
        OutputFormat::Text => print_text(&c, explain),
    }
    // Exit non-zero on divergence so this drops into a pipeline without a wrapper.
    if c.outcome == Match::Divergent {
        std::process::exit(1);
    }
    Ok(())
}

fn stabilize_one(
    infile: &Path,
    outfile: &Path,
    format: Option<&str>,
    prof: Option<&str>,
    enable: &[String],
    disable: &[String],
    report: bool,
) -> Result<()> {
    let fmt = resolve_format(infile, format)?;
    let base = match prof {
        Some(p) => profile(p).with_context(|| format!("unknown profile `{p}`"))?,
        None => default_for(fmt),
    };
    let set = base.filtered(enable, disable);

    let bytes = std::fs::read(infile).with_context(|| format!("reading {}", infile.display()))?;
    let mut notes = Vec::new();
    let mut parsed = trigon_archive::parse(bytes, fmt, &Limits::default(), &mut notes)?;
    let applied = trigon_stabilize::apply(&set, &mut parsed.archive);
    let out = trigon_archive::serialize(&parsed.archive, true)?;
    std::fs::write(outfile, &out).with_context(|| format!("writing {}", outfile.display()))?;

    if report {
        // Machine-readable, so `xtask golden` can group a digest move by the pass that moved it
        // instead of by guesswork.
        let summary = serde_json::json!({
            "stabilized": trigon_core::Digest::from_bytes(
                <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&out))
            ).to_hex(),
            "bytes": out.len(),
            "set": { "id": set.id.as_str(), "digest": set.digest().to_hex() },
            "applied": applied.iter().map(|a| serde_json::json!({
                "id": a.id.as_str(),
                "risk": format!("{:?}", a.risk).to_lowercase(),
                "entries_touched": a.entries_touched,
                "bytes_changed": a.bytes_changed,
            })).collect::<Vec<_>>(),
            "notes": notes.iter().map(|n| format!("{:?}", n.code)).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&summary)?);
    } else {
        for a in &applied {
            eprintln!("applied {} ({} entries)", a.id, a.entries_touched);
        }
    }
    Ok(())
}

fn resolve_format(path: &Path, explicit: Option<&str>) -> Result<Format> {
    if let Some(s) = explicit {
        return match s {
            "tar+gzip" | "tar.gz" | "tgz" => Ok(Format::TarGz),
            "tar" => Ok(Format::Tar),
            "zip" => Ok(Format::Zip),
            "gzip" | "gz" => Ok(Format::Gzip),
            "raw" => Ok(Format::Raw),
            other => bail!("unknown format `{other}`"),
        };
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    Format::from_file_name(&name).with_context(|| {
        format!(
            "cannot infer a format from `{name}`; pass --format. A .gem is a tar, and only the \
                 ecosystem knows that from the name alone."
        )
    })
}

/// Which stabilizer set to use.
///
/// The container format is not enough. A wheel and an arbitrary zip are both `Format::Zip`, and
/// the wheel needs `wheel-record` and `pyc-header` on top of the zip set: without them a rebuilt
/// wheel's RECORD is compared against the published one line for line rather than regenerated from
/// the members that are actually there, so one differing member reports as two. The artifact kind
/// is what selects the profile, and for these extensions the filename carries it unambiguously.
///
/// `.tgz` deliberately stays generic. An npm tarball is a `.tgz` and so is a great deal else, and
/// nothing in the name says which. The registry knows, and will say so once it exists; guessing
/// here would apply npm-specific passes to whatever happened to share the extension.
fn resolve_profile(
    artifact: &Path,
    requested: Option<&str>,
    fmt: Format,
) -> Result<trigon_stabilize::StabilizerSet> {
    if let Some(p) = requested {
        return profile(p).with_context(|| {
            format!(
                "unknown profile `{p}`; known: {}",
                trigon_stabilize::all_profiles().join(", ")
            )
        });
    }
    let name = artifact
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    let by_kind = if name.ends_with(".whl") {
        Some("wheel")
    } else if name.ends_with(".crate") {
        Some("crate")
    } else if name.ends_with(".gem") {
        Some("gem")
    } else if name.ends_with(".nupkg") {
        Some("nupkg")
    } else {
        None
    };
    match by_kind.and_then(profile) {
        Some(set) => Ok(set),
        None => Ok(default_for(fmt)),
    }
}

fn print_text(c: &Comparison, explain: bool) {
    let mark = match c.outcome {
        Match::Exact | Match::Normalized => "✔",
        Match::NormalizedWithCaveats => "◐",
        Match::Divergent => "✖",
    };
    println!("{mark} {}", c.outcome);
    println!();
    println!("  format         {}", c.upstream.format);
    println!(
        "  stabilizer set {} ({})",
        c.upstream.set.0,
        short(&c.upstream.set.1.to_hex())
    );
    println!();
    println!("  {:<12} {:<18} {:<18}", "", "upstream", "rebuild");
    row(
        "raw",
        &c.upstream.raw.sha256.to_hex(),
        &c.rebuild.raw.sha256.to_hex(),
    );
    if let (Some(u), Some(r)) = (&c.upstream.container, &c.rebuild.container) {
        row("container", &u.sha256.to_hex(), &r.sha256.to_hex());
    }
    row(
        "stabilized",
        &c.upstream.stabilized.sha256.to_hex(),
        &c.rebuild.stabilized.sha256.to_hex(),
    );

    if let Some(false) = c.container_bit_identical() {
        println!();
        println!("  containers differ as well as the framing");
    } else if c.container_bit_identical() == Some(true) && c.outcome != Match::Exact {
        println!();
        println!("  same container, different outer framing");
    }

    let applied = c.applied();
    if !applied.is_empty() {
        println!();
        println!("  applied");
        let mut seen: Vec<String> = Vec::new();
        for a in applied {
            let key = a.id.to_string();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            println!(
                "    {:<24} {:<10} {:>6} entries",
                a.id.as_str(),
                format!("{:?}", a.risk).to_lowercase(),
                a.entries_touched
            );
        }
    }

    if let Some(reason) = c.cap_reason() {
        println!();
        println!("  capped below `normalized`: {reason}");
    }

    let notes: Vec<_> = c
        .upstream
        .notes
        .iter()
        .chain(&c.rebuild.notes)
        .filter(|n| n.code.is_noteworthy())
        .collect();
    if !notes.is_empty() {
        println!();
        println!("  notes");
        for n in notes {
            let at = n.path.as_ref().map(|p| format!(" {p}")).unwrap_or_default();
            println!("    {:?}{at}: {}", n.code, n.detail);
        }
    }

    if let Some(d) = &c.diff {
        println!();
        println!(
            "  members  {} identical, {} differ, {} upstream-only, {} rebuild-only",
            d.identical, d.differs, d.only_upstream, d.only_rebuild
        );
        if d.executable_differs > 0 {
            println!(
                "  {} executable member(s) differ, which is never benign",
                d.executable_differs
            );
        }
        let interesting: Vec<_> = d
            .files
            .iter()
            .filter(|f| f.status != trigon_compare::FileStatus::Identical)
            .collect();
        let limit = if explain {
            interesting.len()
        } else {
            10.min(interesting.len())
        };
        for f in &interesting[..limit] {
            println!(
                "    {:<16} {}",
                format!("{:?}", f.status).to_lowercase(),
                f.path
            );
        }
        if interesting.len() > limit {
            println!("    … {} more, pass --explain", interesting.len() - limit);
        }
    }
}

fn row(label: &str, a: &str, b: &str) {
    let same = a == b;
    println!(
        "  {:<12} {:<18} {:<18} {}",
        label,
        short(a),
        short(b),
        if same { "=" } else { "≠" }
    );
}

fn short(hex: &str) -> String {
    format!("{}…", &hex[..hex.len().min(12)])
}

fn stabilizers(prof: &str) -> Result<()> {
    let set = profile(prof).with_context(|| {
        format!(
            "unknown profile `{prof}`; known: {}",
            trigon_stabilize::all_profiles().join(", ")
        )
    })?;
    println!("{} ({})", set.id, set.digest());
    println!();
    // Sized to the longest id present rather than to a guess: `gem-metadata-rubygems-version` is
    // 29 characters and a fixed width silently breaks the alignment of every row after it.
    let w = set
        .members
        .iter()
        .map(|m| m.id().as_str().len())
        .max()
        .unwrap_or(0);
    for m in &set.members {
        println!(
            "  {:<w$} {:<11} {:<9} {:?}",
            m.id().as_str(),
            format!("{:?}", m.risk()).to_lowercase(),
            format!("{:?}", m.stage()).to_lowercase(),
            m.provenance()
        );
    }
    Ok(())
}

/// Read a strategy document, lower it if it is the prior art's format, and render it.
///
/// Shared by `strategy render` and `build`, so the script a build runs is byte-for-byte the one
/// `strategy render` prints. Two code paths here would let them drift, and the difference would
/// only show up as an unexplained divergence.
fn render_strategy(
    file: &Path,
    import: bool,
    timewarp: &str,
    has_repo: bool,
) -> Result<(
    trigon_strategy::Instructions,
    String,
    Vec<trigon_strategy::CustomStabilizer>,
)> {
    let src =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;

    let (strategy, custom) = if import {
        let i = trigon_strategy::import(&src)
            .with_context(|| format!("importing {}", file.display()))?;
        (i.strategy, i.custom_stabilizers)
    } else {
        (
            trigon_strategy::from_yaml(&src)
                .with_context(|| format!("parsing {}", file.display()))?,
            Vec::new(),
        )
    };

    let tools = trigon_strategy::ToolRegistry::builtin()?;
    let loc = strategy.location().cloned().unwrap_or_default();
    let cx = trigon_strategy::Context {
        location: trigon_strategy::LocationCtx {
            repo: loc.repo,
            git_ref: loc.git_ref,
            subdir: loc.subdir.unwrap_or_default(),
        },
        env: trigon_strategy::EnvCtx {
            arch: "x86_64".into(),
            platform: "linux".into(),
            has_repo,
            timewarp_base: Some(timewarp.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let instructions = trigon_strategy::render(&strategy, &cx, &tools)?;
    let digest = trigon_strategy::strategy_digest(&strategy, &tools)?;
    Ok((instructions, digest, custom))
}

fn strategy_render(
    file: &Path,
    import: bool,
    timewarp: &str,
    has_repo: bool,
    output: OutputFormat,
) -> Result<()> {
    let (instructions, digest, custom) = render_strategy(file, import, timewarp, has_repo)?;

    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "strategy_digest": digest,
                "instructions": instructions,
                "custom_stabilizers": custom,
            }))?
        ),
        OutputFormat::Text => {
            println!("strategy {}", &digest[..16]);
            println!("  repo    {}", instructions.location.repo);
            println!("  commit  {}", instructions.location.commit);
            println!("  output  {}", instructions.output_path);
            if !instructions.requires.system_deps.is_empty() {
                println!(
                    "  needs   {}",
                    instructions
                        .requires
                        .system_deps
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            for (name, script) in [
                ("source", &instructions.source),
                ("deps", &instructions.deps),
                ("build", &instructions.build),
            ] {
                if script.trim().is_empty() {
                    continue;
                }
                println!("\n# {name}");
                println!("{script}");
            }
            for cs in &custom {
                // Printed, never silently dropped: the definition says the comparison needs it, so
                // a run without it reports a divergence its author already explained.
                println!("\n# custom stabilizer: {} (not yet executed)", cs.kind);
                for line in cs.reason.lines() {
                    println!("#   {line}");
                }
            }
        }
    }
    Ok(())
}

fn strategy_tools() -> Result<()> {
    let tools = trigon_strategy::ToolRegistry::builtin()?;
    let ids: Vec<&str> = tools.ids().collect();
    let w = ids.iter().map(|i| i.len()).max().unwrap_or(0);
    for id in &ids {
        let t = tools.get(id).expect("just listed");
        let params: Vec<String> = t
            .params
            .iter()
            .map(|(n, p)| {
                if p.required {
                    format!("{n}*")
                } else {
                    n.clone()
                }
            })
            .collect();
        println!("  {id:<w$}  {}", params.join(", "));
    }
    println!("\n  {} tools, * marks a required parameter", ids.len());
    Ok(())
}

#[cfg(feature = "build")]
mod rebuild {
    use std::str::FromStr;

    use super::*;
    use trigon_core::TargetRef;
    use trigon_registry::{
        Client, ClientConfig, DefinitionsInferrer, NpmInferrer, PyPiInferrer, StrategyInferrer,
        for_ecosystem,
    };

    /// How far a rebuild got, and what it concluded.
    ///
    /// A sweep needs this rather than prose plus an error: "47 failed" is not a finding, and the
    /// difference between no strategy, a build that would not run, and a real divergence is the
    /// whole reason for a reproduction rate to mean anything.
    #[derive(Clone, Debug)]
    pub enum Outcome {
        Compared(trigon_core::Match),
        /// No rung had anything to say. A scope statement, not a failure.
        NoStrategy,
        /// The build ran and did not finish.
        BuildFailed {
            phase: String,
            /// What stopped it, named so that every run sharing the cause shares the name.
            /// `None` only where the failure happened outside a build we have a log for.
            signature: Option<trigon_core::FailureSignature>,
        },
        /// Ours, the registry's, or a policy. Never the package's.
        Failed {
            fault: trigon_core::Fault,
            detail: String,
        },
        /// Neither a pass nor a failure.
        ///
        /// The artifact under test reached the build over the network, so whatever the build
        /// produced is not evidence about the source. It may be perfectly honest and we cannot
        /// tell, which is exactly what this says. See `docs/12-security.md` §2.4.
        Void {
            reason: String,
        },
        /// Read back from a previous run of the same sweep.
        Recorded(String, Option<String>),
    }

    impl Outcome {
        pub fn label(&self) -> String {
            match self {
                Outcome::Compared(m) => m.to_string(),
                Outcome::NoStrategy => "no-strategy".into(),
                Outcome::BuildFailed { phase, .. } => format!("build-failed:{phase}"),
                Outcome::Failed { fault, .. } => format!("error:{fault:?}").to_lowercase(),
                Outcome::Void { .. } => "void".into(),
                Outcome::Recorded(label, _) => label.clone(),
            }
        }

        /// The failure cluster this row belongs to, where it has one.
        ///
        /// What turns a column of red rows into a handful of tickets. Kept off `label` on purpose:
        /// the label is the sweep's outcome taxonomy and stays small enough to read as a table,
        /// while clusters are open-ended and belong beside it.
        pub fn cluster(&self) -> Option<String> {
            match self {
                Outcome::BuildFailed { signature, .. } => signature.as_ref().map(|s| s.key()),
                // A resumed row carries its cluster forward. Without this, resuming a sweep — which
                // is how a long one always finishes — silently empties the cluster summary, and the
                // summary is the reason to run it.
                Outcome::Recorded(_, cluster) => cluster.clone(),
                _ => None,
            }
        }

        /// Whether this says anything about the package reproducing.
        ///
        /// An infrastructure fault is not an unreproducible package, and counting it as one is how
        /// a reproduction rate becomes a number about our own reliability.
        pub fn is_evidence(&self) -> bool {
            self.as_match().is_some()
        }

        /// The comparison this outcome carries, however it was produced.
        ///
        /// Parsed rather than string-matched, so a resumed row and a fresh one cannot disagree
        /// about what a verdict is called.
        pub fn as_match(&self) -> Option<trigon_core::Match> {
            match self {
                Outcome::Compared(m) => Some(*m),
                Outcome::Recorded(label, _) => label.parse().ok(),
                _ => None,
            }
        }
    }

    pub struct Args {
        pub purl: String,
        pub artifact: Option<String>,
        pub image: String,
        pub work: PathBuf,
        pub egress: String,
        pub timeout: u64,
        pub definitions: Option<PathBuf>,
        pub mirror_image: String,
        pub timewarp: Option<String>,
        /// A checkout of the package's source, when one is available locally.
        pub source: Option<PathBuf>,
        /// Write a DSSE-wrapped statement of the comparison here.
        pub attest: Option<PathBuf>,
        /// Sign it with an ed25519 key held in this file.
        pub key: Option<PathBuf>,
    }

    /// The ladder, in the order `docs/04-strategies.md` §6 sets out.
    ///
    /// A definition first, because one exists exactly where inference already failed. Then the
    /// ecosystem heuristic. No rung here costs money or calls a model, and the engine contains no
    /// branch asking which kind of rung produced a candidate: the ordering is the policy.
    fn ladder(
        target: &trigon_core::Ecosystem,
        client: Client,
        definitions: Option<PathBuf>,
        mirror: Option<String>,
    ) -> Vec<Box<dyn StrategyInferrer>> {
        let mut rungs: Vec<Box<dyn StrategyInferrer>> = Vec::new();
        if let Some(d) = definitions
            .map(DefinitionsInferrer::new)
            .or_else(DefinitionsInferrer::from_env)
        {
            rungs.push(Box::new(d));
        }
        match target {
            trigon_core::Ecosystem::Npm => {
                rungs.push(Box::new(NpmInferrer::new(client).with_mirror(mirror)))
            }
            trigon_core::Ecosystem::PyPI => {
                rungs.push(Box::new(PyPiInferrer::new(client).with_mirror(mirror)))
            }
            _ => {}
        }
        rungs
    }

    pub fn run(args: Args) -> Result<()> {
        let outcome = run_one(args, true)?;
        match outcome {
            // `Recorded` only comes from a sweep's results file, never from a single run.
            Outcome::Compared(_) | Outcome::NoStrategy | Outcome::Recorded(..) => Ok(()),
            // Not an error, and not a pass. The exit code says something went wrong because
            // something did: the run cannot be used.
            Outcome::Void { reason } => bail!("void: {reason}"),
            Outcome::BuildFailed { phase, signature } => match signature {
                Some(s) => bail!("the build failed in {phase}: {s}"),
                None => bail!("the build failed in {phase}"),
            },
            Outcome::Failed { detail, .. } => bail!("{detail}"),
        }
    }

    /// One rebuild, reported rather than raised.
    ///
    /// Returns `Err` only for something that would stop a sweep entirely, such as an unusable
    /// registry. Everything about one target, including its failures, comes back as an `Outcome`.
    pub fn run_one(args: Args, verbose: bool) -> Result<Outcome> {
        let target = TargetRef::from_str(&args.purl)?;
        let client = Client::new(ClientConfig::default())?;
        let registry = for_ecosystem(target.ecosystem, client.clone())?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        std::fs::create_dir_all(&args.work)?;

        // 1. What the registry knows.
        let resolved = match rt.block_on(registry.resolve(&target)) {
            Ok(r) => r,
            Err(e) => return Ok(classify(&e)),
        };
        let meta = match resolved.pick(args.artifact.as_deref()) {
            Ok(m) => m.clone(),
            Err(e) => return Ok(classify(&e)),
        };
        if verbose {
            println!("{}", resolved.reference);
            println!("  artifact   {}", meta.id);
        }

        // 2. The published bytes, before anything else.
        //
        // The guard manifest is built from them, and the mirror has to be armed with it before a
        // build can ask the mirror for anything.
        let upstream_path = args.work.join(meta.id.as_str());
        let mut file = std::fs::File::create(&upstream_path)?;
        let upstream_digest = match rt.block_on(registry.fetch(&meta, &mut file)) {
            Ok(d) => d,
            Err(e) => return Ok(classify(&e)),
        };
        drop(file);
        if verbose {
            println!("  published  sha256 {}", &upstream_digest.to_hex()[..16]);
        }

        // The guard manifest, from the bytes we just fetched. This is the control that defeats the
        // attack the whole design is shaped around: a strategy that downloads the published
        // artifact reproduces it byte for byte, passes every clean re-run, and is worth nothing.
        let guard = match std::fs::read(&upstream_path) {
            Ok(bytes) => {
                let format = crate::resolve_format(&upstream_path, None)?;
                let url = Some(meta.url.clone());
                match args.source.as_deref() {
                    Some(dir) => trigon_mirror::GuardManifest::for_artifact_with_source(
                        &bytes, format, url, dir,
                    ),
                    None => trigon_mirror::GuardManifest::for_artifact(&bytes, format, url),
                }
            }
            Err(_) => trigon_mirror::GuardManifest::default(),
        };
        if verbose {
            println!(
                "  guarding   the artifact and {} of its members ({} too small or too common)",
                guard.members.len(),
                guard.filtered_out
            );
        }

        // 3. A strategy, from the first rung that has one.
        // Under `mirror-only` the mirror runs inside the build's network island rather than here:
        // a container on an internal network cannot reach the host, which is the whole point of
        // the tier. The port is fixed because it is inside that island and collides with nothing.
        let enforced = args.egress == "mirror-only";
        let mirror = match args.timewarp.as_deref() {
            Some("auto") if enforced => {
                println!(
                    "  mirror     inside the build's network island, which is its only route out"
                );
                None
            }
            Some("auto") => {
                let g = guard.clone();
                let handle = rt.block_on(async {
                    trigon_mirror::Mirror::new()?.with_guard(g).serve(0).await
                })?;
                if verbose {
                    println!("  mirror     serving the index as of the publish date");
                }
                Some(handle)
            }
            _ => None,
        };
        // The name the strategy uses, and the port the container has to reach. The name is stable
        // so the port stays out of the strategy digest.
        let timewarp_host = if enforced && args.timewarp.is_some() {
            Some("timewarp:8129".to_string())
        } else {
            mirror
                .as_ref()
                .map(|m| format!("timewarp:{}", m.addr.port()))
                .or_else(|| args.timewarp.clone().filter(|t| t != "auto"))
        };

        let rungs = ladder(
            &target.ecosystem,
            client,
            args.definitions,
            timewarp_host.clone(),
        );
        let Some(candidate) = rt.block_on(trigon_registry::infer(&rungs, &resolved))? else {
            return Ok(Outcome::NoStrategy);
        };
        let loc = candidate.strategy.location().cloned().unwrap_or_default();
        if verbose {
            println!("  source     {} @ {}", loc.repo, loc.git_ref);
            println!(
                "  strategy   {:?}, commit found by {:?}, confidence {:?}",
                candidate.derivation, candidate.discovery, candidate.confidence
            );
            for a in &candidate.assumptions {
                // Printed, not buried. A divergence has to be readable against the guesses that
                // produced it rather than taken as a fact about the package.
                println!("  assuming   {a}");
            }
        }

        // 4. Build it.
        let strategy_file = args.work.join("strategy.yaml");
        std::fs::write(
            &strategy_file,
            trigon_strategy::to_yaml(&candidate.strategy)?,
        )?;
        let out = args.work.join("rebuild");
        // Written next to the run, and mounted read-only into the island's mirror when there is
        // one. The mirror runs in a container with no route to this process, so a file is how the
        // manifest gets there.
        let guard_file = args.work.join("guard.json");
        std::fs::write(&guard_file, serde_json::to_vec_pretty(&guard)?)?;

        let mirror_addr = mirror.as_ref().map(|m| m.host());
        let built = crate::build::run_with(
            &strategy_file,
            false,
            &args.image,
            &out,
            &args.egress,
            args.timeout,
            false,
            timewarp_host.as_deref().unwrap_or("timewarp"),
            mirror_addr.as_deref(),
            Some(args.mirror_image.as_str()),
            verbose,
            enforced.then_some(guard_file.as_path()),
            args.source.as_deref(),
        );

        if let Some(m) = mirror {
            use std::sync::atomic::Ordering;
            let s = m.stats();
            // Printed because a claim of a pinned dependency graph should be able to show the pin
            // did something. Zero filtered requests means the build never asked the mirror.
            if verbose {
                println!(
                    "\n  mirror     {} index request(s), {} version(s) withheld",
                    s.index_requests.load(Ordering::Relaxed),
                    s.versions_withheld.load(Ordering::Relaxed),
                );
            }
            let trips = m.trips();
            rt.block_on(m.shutdown());
            if let Some(t) = trips.first() {
                // Checked before the build's exit status is even considered. A tripped guard means
                // the run cannot be used, whether the build succeeded or failed.
                return Ok(Outcome::Void {
                    reason: format!("{:?} arrived from {}", t.matched, t.url),
                });
            }
        }
        if let Err(e) = built {
            let text = e.to_string();
            if let Some(reason) = text.strip_prefix("void: ") {
                return Ok(Outcome::Void {
                    reason: reason.to_string(),
                });
            }
            return Ok(build_outcome(&e));
        }

        // 5. Compare, with the same code path `verify` uses.
        let Some(rebuilt) = newest_file(&out) else {
            return Ok(Outcome::BuildFailed {
                phase: "collect".into(),
                signature: Some(trigon_core::FailureSignature {
                    code: "trigon/no-output",
                    subject: None,
                    fault: trigon_core::Fault::Bug,
                    retryable: false,
                    repairable: true,
                    evidence: "the build succeeded and left no artifact at the output path".into(),
                }),
            });
        };
        let set = crate::resolve_profile(
            &upstream_path,
            None,
            crate::resolve_format(&upstream_path, None)?,
        )?;
        let a = std::fs::read(&upstream_path)?;
        let b = std::fs::read(&rebuilt)?;
        let comparison = match compare_bytes(
            a,
            b,
            crate::resolve_format(&upstream_path, None)?,
            &set,
            &Limits::default(),
        ) {
            Ok(c) => c,
            Err(e) => return Ok(classify(&e)),
        };
        if verbose {
            println!();
            print_text(&comparison, false);
        }
        // Reached only by a run that got this far, which is the point: every path that voids a run —
        // a tripped artifact guard above all — returns before here, so no statement can be written
        // about a run that is evidence of nothing. That is a property of the control flow rather
        // than a check somebody has to remember to write.
        if let Some(path) = &args.attest {
            crate::write_bundle(
                path,
                args.key.as_deref(),
                &crate::file_name(&upstream_path),
                &comparison,
            )?;
        }
        Ok(Outcome::Compared(comparison.outcome))
    }

    /// An error that stopped one target, as an outcome.
    fn classify<E: trigon_core::Classify + std::fmt::Display>(e: &E) -> Outcome {
        Outcome::Failed {
            fault: e.fault(),
            detail: e.to_string(),
        }
    }

    /// A build failure, keeping the phase it died in.
    ///
    /// The phase is the difference between "our infrastructure" and "this package does not build",
    /// and collapsing them makes a sweep's numbers uninterpretable.
    /// A build that ran and failed, or a failure of ours that never got that far.
    ///
    /// Only a [`crate::BuildFailure`] — which exists only where a build actually produced a log —
    /// becomes `BuildFailed`. Everything else is `Failed`, and the distinction is load-bearing:
    /// `BuildFailed` says the package did not build, `Failed` says we could not test it. This used
    /// to search our own error text for a phase name, so "the mirror container did not start
    /// listening" became `build-failed:setup` and a broken mirror on our side read, in the sweep
    /// summary, as five packages that do not build.
    fn build_outcome(e: &anyhow::Error) -> Outcome {
        if let Some(f) = e.downcast_ref::<crate::BuildFailure>() {
            return Outcome::BuildFailed {
                phase: f.phase.clone(),
                signature: Some(f.signature.clone()),
            };
        }
        if let Some(s) = e.downcast_ref::<trigon_sandbox::SandboxError>() {
            return classify(s);
        }
        Outcome::Failed {
            fault: trigon_core::Fault::Infra,
            detail: e.to_string(),
        }
    }

    /// The artifact the build left behind.
    fn newest_file(dir: &Path) -> Option<PathBuf> {
        let mut found: Vec<PathBuf> = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).ok()?.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    found.push(p);
                }
            }
        }
        found.sort();
        found.pop()
    }
}

#[cfg(feature = "build")]
mod mirror {
    use super::*;

    /// Build the mirror image from this workspace.
    ///
    /// A multi-stage podman build: the first stage compiles against musl inside an image that has
    /// the toolchain, the second is a scratch-thin runtime. Compiling in a container rather than on
    /// the host is what makes this work anywhere: a host binary is linked against the host's glibc
    /// and will not run in a base image with an older one, which is not a hypothetical.
    pub fn build_image(tag: &str) -> Result<()> {
        let root = workspace_root()?;
        let dockerfile = root.join("target").join("mirror.Dockerfile");
        std::fs::write(
            &dockerfile,
            "FROM docker.io/library/rust:1-alpine AS build\n\
             RUN apk add --no-cache musl-dev\n\
             WORKDIR /src\n\
             COPY . .\n\
             RUN cargo build --release -p trigon --bin trigon\n\
             \n\
             FROM docker.io/library/alpine:3.20\n\
             COPY --from=build /src/target/release/trigon /usr/local/bin/trigon\n\
             ENTRYPOINT [\"/usr/local/bin/trigon\"]\n",
        )?;

        // Without this the build context is the whole workspace including `target`, which is
        // gigabytes and is being written to by any concurrent cargo run: the copy then fails on a
        // file that vanished underneath it.
        let ignore = root.join("target").join("mirror.containerignore");
        std::fs::write(&ignore, "target/\n.git/\nfuzz/target/\ncorpora/cache/\n")?;

        println!("building {tag} (this compiles trigon in a container; it takes a few minutes)");
        let status = std::process::Command::new("podman")
            .arg("build")
            .args(["--tag", tag, "--file"])
            .arg(&dockerfile)
            .arg("--ignorefile")
            .arg(&ignore)
            .arg(&root)
            .status()
            .context("running podman build")?;
        if !status.success() {
            bail!("podman build failed");
        }
        println!("\n{tag} is ready. `--egress mirror-only` can now be enforced.");
        Ok(())
    }

    fn workspace_root() -> Result<PathBuf> {
        let mut d = std::env::current_dir()?;
        loop {
            if d.join("Cargo.toml").is_file() && d.join("crates").is_dir() {
                return Ok(d);
            }
            if !d.pop() {
                bail!(
                    "run this from inside the trigon workspace: the image is built from its source"
                );
            }
        }
    }

    pub fn serve(port: u16, guard: Option<&Path>) -> Result<()> {
        let manifest = match guard {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?;
                serde_json::from_str::<trigon_mirror::GuardManifest>(&text)
                    .with_context(|| format!("parsing {}", p.display()))?
            }
            None => trigon_mirror::GuardManifest::default(),
        };
        let armed = !manifest.is_empty();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let handle = trigon_mirror::Mirror::new()?
                .with_guard(manifest)
                .serve(port)
                .await?;
            if armed {
                println!("  guard armed");
            }
            println!("mirror listening on {}", handle.host());
            println!(
                "  npm    npm config set registry http://npm:<RFC3339>@{}",
                handle.host()
            );
            println!(
                "  pypi   PIP_INDEX_URL=http://pypi:<RFC3339>@{}/simple",
                handle.host()
            );
            println!("\nCtrl-C to stop.");
            tokio::signal::ctrl_c().await.ok();
            handle.shutdown().await;
            Ok(())
        })
    }
}

#[cfg(feature = "build")]
mod sweep {
    use std::collections::BTreeMap;
    use std::time::Instant;

    use super::*;
    use crate::rebuild::Outcome;

    pub struct Args {
        pub targets: PathBuf,
        pub image: String,
        pub work: PathBuf,
        pub egress: String,
        pub timeout: u64,
        pub definitions: Option<PathBuf>,
        pub mirror_image: String,
        pub timewarp: Option<String>,
    }

    pub fn run(args: Args) -> Result<()> {
        let text = std::fs::read_to_string(&args.targets)
            .with_context(|| format!("reading {}", args.targets.display()))?;
        let purls: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        if purls.is_empty() {
            bail!("{} has no targets", args.targets.display());
        }
        std::fs::create_dir_all(&args.work)?;

        // Each row is written as it completes, not held until the end. A sweep is hours long and
        // the first one lost two of twenty results when the process died near the finish: a run
        // that summarizes only at the end throws away everything it already knew. The file is also
        // what makes a sweep resumable, and what a second process can read while it runs.
        let results = args.work.join("results.tsv");
        let already = completed(&results);
        if !already.is_empty() {
            println!(
                "resuming: {} of {} already done",
                already.len(),
                purls.len()
            );
        }
        let mut sink = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&results)
            .with_context(|| format!("opening {}", results.display()))?;

        println!(
            "sweeping {} targets -> {}\n",
            purls.len(),
            results.display()
        );

        let mut rows: Vec<(String, Outcome, f64)> = Vec::new();
        for (i, purl) in purls.iter().enumerate() {
            if let Some((label, secs, cluster)) = already.get(*purl) {
                println!(
                    "  {:<28} {:<20} {:>6.0}s   [{}/{}] (done)",
                    short(purl),
                    label,
                    secs,
                    i + 1,
                    purls.len()
                );
                rows.push((
                    purl.to_string(),
                    Outcome::Recorded(label.clone(), cluster.clone()),
                    *secs,
                ));
                continue;
            }
            let started = Instant::now();
            // A per-target directory, or one run's artifacts are collected as another's.
            let work = args.work.join(format!("{i:03}"));
            let _ = std::fs::remove_dir_all(&work);

            let outcome = crate::rebuild::run_one(
                crate::rebuild::Args {
                    purl: purl.to_string(),
                    artifact: None,
                    image: args.image.clone(),
                    work,
                    egress: args.egress.clone(),
                    timeout: args.timeout,
                    definitions: args.definitions.clone(),
                    mirror_image: args.mirror_image.clone(),
                    timewarp: args.timewarp.clone(),
                    // A sweep has no checkout per target: the source cache that would supply one
                    // is fleet work. The guard is wider than designed without it, which errs
                    // toward voiding an honest run rather than missing a forged one.
                    source: None,
                    // A sweep writes no statements. Its product is a rate, and 20 bundles nobody
                    // asked for is 20 files to explain.
                    attest: None,
                    key: None,
                },
                false,
            )
            // A target that cannot even be parsed is that target's problem, not the sweep's.
            .unwrap_or_else(|e| Outcome::Failed {
                fault: trigon_core::Fault::Policy,
                detail: e.to_string(),
            });

            let secs = started.elapsed().as_secs_f64();
            println!(
                "  {:<28} {:<20} {:>6.0}s   [{}/{}]",
                short(purl),
                outcome.label(),
                secs,
                i + 1,
                purls.len()
            );
            // Flushed per row. Buffered output is lost with the process, which is the failure this
            // exists to prevent.
            use std::io::Write as _;
            writeln!(
                sink,
                "{purl}\t{}\t{secs:.1}\t{}",
                outcome.label(),
                outcome.cluster().unwrap_or_default()
            )?;
            sink.flush()?;
            rows.push((purl.to_string(), outcome, secs));
        }

        summarize(&rows);
        Ok(())
    }

    /// Targets already recorded in a previous run of this sweep.
    fn completed(path: &Path) -> BTreeMap<String, (String, f64, Option<String>)> {
        let mut out = BTreeMap::new();
        let Ok(text) = std::fs::read_to_string(path) else {
            return out;
        };
        for line in text.lines() {
            let mut f = line.split('\t');
            if let (Some(purl), Some(label), Some(secs)) = (f.next(), f.next(), f.next()) {
                // The cluster column arrived after the first results files did, so its absence is
                // read as "not recorded" rather than as a malformed row.
                let cluster = f.next().filter(|c| !c.is_empty()).map(str::to_string);
                out.insert(
                    purl.to_string(),
                    (label.to_string(), secs.parse().unwrap_or(0.0), cluster),
                );
            }
        }
        out
    }

    /// One line of what the build said, for a human scanning clusters.
    fn short_evidence(s: &str) -> String {
        let s = s.trim();
        if s.chars().count() > 96 {
            format!("{}…", s.chars().take(95).collect::<String>())
        } else {
            s.to_string()
        }
    }

    fn short(purl: &str) -> String {
        purl.strip_prefix("pkg:").unwrap_or(purl).to_string()
    }

    fn summarize(rows: &[(String, Outcome, f64)]) {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for (_, o, _) in rows {
            *counts.entry(o.label()).or_default() += 1;
        }

        println!("\n  {} targets", rows.len());
        for (label, n) in &counts {
            println!("    {label:<22} {n}");
        }

        // The clusters, which is what a failed sweep is actually for. Twenty red rows are twenty
        // tickets until they are grouped; grouped, they are usually three. The count is what says
        // which one to fix first, and a cluster nothing can fix is marked so nobody tries.
        let mut clusters: BTreeMap<String, (usize, bool, String)> = BTreeMap::new();
        for (_, o, _) in rows {
            let Some(key) = o.cluster() else { continue };
            let (repairable, evidence) = match o {
                Outcome::BuildFailed {
                    signature: Some(s), ..
                } => (s.repairable, s.evidence.clone()),
                // A resumed row kept its cluster but not the log line behind it, which is on disk
                // in that target's work directory rather than in the results file.
                _ => (true, String::new()),
            };
            let e = clusters.entry(key).or_insert((0, repairable, evidence));
            e.0 += 1;
        }
        if !clusters.is_empty() {
            let mut ranked: Vec<_> = clusters.into_iter().collect();
            ranked.sort_by_key(|(k, (n, ..))| (std::cmp::Reverse(*n), k.clone()));
            println!("\n  failure clusters");
            for (key, (n, repairable, evidence)) in &ranked {
                println!(
                    "    {n:>3}  {key:<34}{}",
                    if *repairable {
                        ""
                    } else {
                        "  (nothing to repair)"
                    }
                );
                if !evidence.is_empty() {
                    println!("         {}", short_evidence(evidence));
                }
            }
        }

        // The denominator is the load-bearing part. A package that did not reproduce and a build
        // our own infrastructure could not run are different findings, and averaging them produces
        // a number about our reliability wearing the costume of a reproduction rate.
        let evidence: Vec<&Outcome> = rows
            .iter()
            .map(|(_, o, _)| o)
            .filter(|o| o.is_evidence())
            .collect();
        let reproduced = evidence
            .iter()
            .filter(|o| {
                o.as_match()
                    .is_some_and(|m| m != trigon_core::Match::Divergent)
            })
            .count();

        println!();
        if evidence.is_empty() {
            println!("  no target reached a comparison, so there is no rate to report");
        } else {
            println!(
                "  {reproduced} of {} compared targets reproduced ({:.0}%)",
                evidence.len(),
                100.0 * reproduced as f64 / evidence.len() as f64
            );
            println!(
                "  {} of {} targets reached a comparison at all",
                evidence.len(),
                rows.len()
            );
        }
        let total: f64 = rows.iter().map(|(_, _, s)| s).sum();
        println!(
            "  {:.0}s total, {:.0}s mean",
            total,
            total / rows.len() as f64
        );
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn write(dir: &Path, rows: &str) -> PathBuf {
            let p = dir.join("results.tsv");
            std::fs::write(&p, rows).unwrap();
            p
        }

        fn tmpdir(tag: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!("trigon-sweep-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        #[test]
        fn a_resumed_row_keeps_its_failure_cluster() {
            // A long sweep always finishes by resuming. Losing the cluster on the way back in would
            // empty the summary that is the reason to run it, and it would do so silently — which
            // is exactly how the caveated-match rate went missing once already.
            let d = tmpdir("cluster");
            let p = write(
                &d,
                "pkg:npm/a@1\tbuild-failed:deps\t12.0\tcc/missing-header:python.h\n",
            );
            let got = completed(&p);
            let (label, secs, cluster) = got.get("pkg:npm/a@1").unwrap();
            assert_eq!(label, "build-failed:deps");
            assert_eq!(*secs, 12.0);
            assert_eq!(cluster.as_deref(), Some("cc/missing-header:python.h"));

            let o = Outcome::Recorded(label.clone(), cluster.clone());
            assert_eq!(o.cluster().as_deref(), Some("cc/missing-header:python.h"));
        }

        #[test]
        fn a_results_file_written_before_clusters_existed_still_resumes() {
            // Three columns, not four. Read as "no cluster recorded" rather than as a broken row:
            // refusing to resume an older file would throw away hours of completed builds.
            let d = tmpdir("legacy");
            let p = write(&d, "pkg:npm/a@1\tnormalized\t12.0\n");
            let got = completed(&p);
            let (label, _, cluster) = got.get("pkg:npm/a@1").unwrap();
            assert_eq!(label, "normalized");
            assert!(cluster.is_none());
        }

        #[test]
        fn a_resumed_match_still_counts_toward_the_rate() {
            // The outcome label round-trips through the file as a string, and `as_match` parses it
            // back. A spelling that does not parse drops the row out of the numerator without
            // dropping it out of the denominator, which understates the rate and looks like data.
            for label in [
                "exact",
                "normalized",
                "normalized_with_caveats",
                "divergent",
            ] {
                let o = Outcome::Recorded(label.to_string(), None);
                assert!(
                    o.as_match().is_some(),
                    "`{label}` did not parse back into an outcome"
                );
                assert_eq!(o.label(), label);
            }
        }

        #[test]
        fn an_infrastructure_failure_is_not_counted_as_a_package_that_does_not_build() {
            let ours = Outcome::Failed {
                fault: trigon_core::Fault::Infra,
                detail: "the mirror container did not start".into(),
            };
            assert!(
                !ours.is_evidence(),
                "our own fault is not evidence about the package"
            );
            let theirs = Outcome::BuildFailed {
                phase: "build".into(),
                signature: None,
            };
            assert!(!theirs.is_evidence());
            assert!(Outcome::Compared(trigon_core::Match::Divergent).is_evidence());
        }
    }
}

// ---------------------------------------------------------------------------
// Attestations
//
// The bundle is a DSSE envelope and nothing else: no wrapper object, no metadata sidecar. A
// verifier's whole job is to decode one payload and check one signature, and every field we add
// beside the envelope is a field that is not covered by that signature.

/// Where a statement goes and who signs it. Grouped because they are one decision — whether this
/// run leaves behind something a third party can check — and travel together everywhere.
#[derive(Clone, Copy, Default)]
struct Attest<'a> {
    to: Option<&'a Path>,
    key: Option<&'a Path>,
    subject: Option<&'a str>,
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn load_key(path: &Path) -> Result<trigon_attest::LocalKey> {
    let raw = std::fs::read(path).with_context(|| format!("reading key {}", path.display()))?;
    // Accept hex as well as raw bytes: a key pasted out of a terminal is hex more often than not.
    let bytes = match std::str::from_utf8(&raw).map(str::trim) {
        Ok(s) if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) => (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .context("key file looked like hex but did not parse")?,
        _ => raw,
    };
    Ok(trigon_attest::LocalKey::from_bytes(&bytes)?)
}

fn write_bundle(
    path: &Path,
    key: Option<&Path>,
    subject: &str,
    c: &trigon_compare::Comparison,
) -> Result<()> {
    use trigon_attest::Signer as _;

    let st = trigon_attest::Statement::equivalence(subject, c);
    let env = match key {
        Some(k) => {
            let key = load_key(k)?;
            let env = trigon_attest::sign_statement(&st, &key)?;
            eprintln!("signed with key {}", key.key_id());
            eprintln!("public key: {}", key.public_hex());
            env
        }
        None => trigon_attest::sign_statement(&st, &trigon_attest::Unsigned)?,
    };
    let mut json = serde_json::to_string_pretty(&env)?;
    json.push('\n');
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;

    eprintln!("attestation: {}", path.display());
    if key.is_none() {
        // Said once, plainly, at the moment it is produced. "Unsigned" and "signed by someone you
        // do not trust" are different answers and only one of them is this bundle.
        eprintln!(
            "  unsigned — the claim is complete and checkable, but nothing here says who made it"
        );
    }
    Ok(())
}

fn verify_attestation(
    bundle: &Path,
    rerun: bool,
    upstream: Option<&Path>,
    rebuild: Option<&Path>,
    public_key: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let raw = std::fs::read(bundle).with_context(|| format!("reading {}", bundle.display()))?;
    let env: trigon_attest::Envelope =
        serde_json::from_slice(&raw).context("this file is not a DSSE envelope")?;
    let payload = env.decoded_payload()?;
    let st: trigon_attest::Statement = serde_json::from_slice(&payload)
        .context("the envelope's payload is not an in-toto statement")?;

    let signature = match (env.is_signed(), public_key) {
        (false, _) => "unsigned".to_string(),
        (true, None) => format!(
            "present ({}), not checked — pass --public-key to check it",
            env.signatures
                .iter()
                .map(|s| s.keyid.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        (true, Some(pk)) => {
            let pae = env.pae()?;
            // Any one signature verifying is enough; a bundle may carry several.
            let ok = env
                .signatures
                .iter()
                .filter(|s| !s.sig.is_empty())
                .any(|s| trigon_attest::verify_signature(&pae, s, pk).is_ok());
            if !ok {
                bail!("no signature on this bundle verifies against that key");
            }
            "verified".to_string()
        }
    };

    let rederived = if rerun {
        let (u, r) = match (upstream, rebuild) {
            (Some(u), Some(r)) => (u, r),
            _ => bail!("--rerun-comparison needs both --upstream and --rebuild"),
        };
        let ub = std::fs::read(u).with_context(|| format!("reading {}", u.display()))?;
        let rb = std::fs::read(r).with_context(|| format!("reading {}", r.display()))?;
        Some(trigon_attest::rederive(&st, ub, rb)?)
    } else {
        None
    };

    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "subject": st.subject,
                "predicateType": st.predicate_type,
                "outcome": st.predicate["outcome"],
                "signature": signature,
                "rederived": rederived.as_ref().map(|d| serde_json::json!({
                    "claimed": d.claimed,
                    "actual": d.actual.to_string(),
                    "stabilizerSet": d.stabilizer_set,
                    "holds": d.holds(),
                })),
            }))?
        ),
        OutputFormat::Text => {
            for s in &st.subject {
                println!(
                    "subject   {} ({})",
                    s.name,
                    s.digest.get("sha256").map(String::as_str).unwrap_or("?")
                );
            }
            println!("predicate {}", st.predicate_type);
            println!(
                "claims    {}",
                st.predicate["outcome"].as_str().unwrap_or("?")
            );
            println!("signature {signature}");
            match &rederived {
                Some(d) if d.holds() => println!(
                    "rederived {} under {} — the claim holds",
                    d.actual, d.stabilizer_set
                ),
                Some(d) => println!(
                    "rederived {} under {}, but the statement claims {} — the claim does NOT hold",
                    d.actual, d.stabilizer_set, d.claimed
                ),
                // Worth saying outright. Reading a statement is not checking it, and the difference
                // is the entire reason this subcommand exists.
                None => {
                    println!("rederived not attempted — pass --rerun-comparison to check the claim")
                }
            }
        }
    }

    if rederived.as_ref().is_some_and(|d| !d.holds()) {
        std::process::exit(1);
    }
    Ok(())
}
