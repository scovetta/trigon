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

/// Die quietly when the reader goes away, rather than panicking.
///
/// Rust masks SIGPIPE at startup, so a write to a closed pipe returns EPIPE, `println!` panics on
/// it, and `trigon verify x y | head -3` exits 101 with a backtrace instead of 0. That matters more
/// here than in most tools, because the exit code carries the verdict: 0 for a match and 1 for a
/// divergence. A panic in the middle of a pipeline is indistinguishable from a real failure.
fn die_quietly_on_sigpipe() {
    // SAFETY: restoring a signal to its default disposition, before any thread is spawned.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() -> Result<()> {
    die_quietly_on_sigpipe();
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
        } => verify(
            &upstream,
            &rebuild,
            format.as_deref(),
            prof.as_deref(),
            output,
            explain,
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
        } => build::run(&file, import, &image, &out, &egress, timeout, retain),
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

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        file: &Path,
        import: bool,
        image: &str,
        out: &Path,
        egress: &str,
        timeout: u64,
        retain: bool,
    ) -> Result<()> {
        let (instructions, digest, _custom) =
            crate::render_strategy(file, import, "timewarp", false)?;
        let egress = egress_tier(egress)?;

        let plan = BuildPlan::Oci(OciPlan {
            base_image: image.to_string(),
            system_deps: instructions.requires.system_deps.clone(),
            source: instructions.source.clone(),
            deps: instructions.deps.clone(),
            build: instructions.build.clone(),
            output_path: instructions.output_path.clone(),
            egress,
            privileged: instructions.requires.privileged,
        });

        let run_id = format!("{}-{}", &digest[..12], std::process::id());
        let runner = PodmanRunner::new(out);

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
            };
            let handle = runner.start(&plan, &opts).await?;
            let outcome = handle.wait().await?;

            println!("strategy {}", &digest[..16]);
            println!("  egress    {}", outcome.egress);
            println!("  isolation {:?}", outcome.isolation);
            for (phase, d) in &outcome.timings {
                match d {
                    // `None` means no data, never zero. A timing we failed to read is not a fast
                    // phase, and reporting it as one poisons every average downstream.
                    Some(d) => println!("  {phase:?}{:>10.1}s", d.as_secs_f64()),
                    None => println!("  {phase:?}      no data"),
                }
            }
            if !outcome.attestable {
                println!(
                    "\n  not attestable: this runner enforces no mirror and records no network \
                     transcript, so it cannot claim the build fetched nothing it should not have"
                );
            }
            match (&outcome.artifact, outcome.succeeded()) {
                (Some(p), _) => println!("\n  artifact  {}", p.display()),
                (None, true) => println!(
                    "\n  the build succeeded but produced no single artifact. Check output_path: \
                     a glob matching several files does not identify one."
                ),
                (None, false) => {}
            }
            if !outcome.succeeded() {
                eprintln!("\n{}", outcome.log_tail);
                bail!(
                    "build failed in {:?} with exit {}",
                    outcome.failed_in,
                    outcome.exit_code
                );
            }
            Ok(())
        })
    }
}

fn verify(
    upstream: &Path,
    rebuild: &Path,
    format: Option<&str>,
    prof: Option<&str>,
    output: OutputFormat,
    explain: bool,
) -> Result<()> {
    let fmt = resolve_format(upstream, format)?;
    let set = resolve_profile(upstream, prof, fmt)?;

    let a = std::fs::read(upstream).with_context(|| format!("reading {}", upstream.display()))?;
    let b = std::fs::read(rebuild).with_context(|| format!("reading {}", rebuild.display()))?;

    let c = compare_bytes(a, b, fmt, &set, &Limits::default())?;
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
