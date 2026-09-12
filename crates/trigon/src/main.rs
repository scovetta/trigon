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
        /// The stabilizer set the attestation was made under: a published `.json` manifest, or a
        /// `.wasm` module.
        ///
        /// A manifest says what the set *was*, which turns "these digests disagree" from a dead end
        /// into something a person can act on. A module lets the claim be **checked** under the set
        /// it was actually made under, which is what archiving stabilizer sets was always for. The
        /// module path needs this binary built with `--features wasm`.
        #[arg(long)]
        stabilizers: Option<PathBuf>,
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
        /// Ask a model for a strategy when nothing deterministic produced one.
        ///
        /// `replay:<transcript.json>` answers from a recording and opens no socket. Off by
        /// default: a run that silently calls a model is a run whose cost and derivation are a
        /// surprise.
        #[arg(long)]
        model: Option<String>,
        /// Where to keep the source checkouts a model rung reads.
        #[arg(long)]
        source_cache: Option<PathBuf>,
        /// Record the run — its artifacts, log, comparison and environment — in a store, so that a
        /// separate `trigon attest` can re-derive the claim and sign it without ever running a
        /// build. This is what makes the signing process separable from the one that executes
        /// attacker-supplied scripts.
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Sign what a stored run says, after re-deriving it from the bytes.
    ///
    /// A separate process from the one that ran the build, and that is the point: it reads blobs by
    /// hash, checks each against the hash it asked for, recomputes the claim, and only then signs.
    /// The process that ran the build could record any outcome it liked; an attestor that signed
    /// what it was told would launder that into a signature.
    #[cfg(feature = "build")]
    Attest {
        /// The store the run was written to.
        #[arg(long, default_value = "./trigon-store")]
        store: PathBuf,
        /// Which run. Defaults to the most recent.
        run: Option<String>,
        /// Sign with an ed25519 key held in this file. Without one the statements are unsigned.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Drop the rebuilt artifact's bytes afterwards, keeping its digests.
        #[arg(long)]
        prune: bool,
    },
    /// Score a sweep against a labelled corpus.
    ///
    /// A pass rate on its own cannot show the regression that matters: a change that raises the
    /// aggregate while making the model fire on targets that were supposed to need nothing. This
    /// splits the rate by the capability each target was labelled with, and fails on a model
    /// invocation where the label forbids one, whatever the rate did.
    #[cfg(feature = "build")]
    Score {
        /// A sweep's `results.tsv`.
        results: PathBuf,
        /// The labels for that corpus, as JSON.
        #[arg(long)]
        labels: PathBuf,
        /// An earlier sweep of the same corpus, to report what changed.
        ///
        /// This is what makes a proposed rule answerable: not "does the rate look better" but
        /// "which targets flipped, in which direction". A rule that fixes one package and breaks
        /// two is a net loss, and an aggregate rate hides that by construction.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Exit non-zero if any target that reproduced in the baseline no longer does.
        ///
        /// For CI and for the promotion gate. Off by default so a human reading a comparison is
        /// not told their shell command failed.
        #[arg(long, requires = "baseline")]
        fail_on_regression: bool,
    },
    /// List the runs a store holds.
    #[cfg(feature = "build")]
    Runs {
        #[arg(long, default_value = "./trigon-store")]
        store: PathBuf,
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
        /// Record every run in a store, so the sweep leaves something an attestor can sign.
        #[arg(long)]
        store: Option<PathBuf>,
        /// Ask a model where nothing deterministic answers, for every target or none.
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        source_cache: Option<PathBuf>,
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

#[cfg(feature = "build")]
mod inferrer;

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
            stabilizers,
            public_key,
            output,
        } => verify_attestation(
            &bundle,
            rerun_comparison,
            upstream.as_deref(),
            rebuild.as_deref(),
            stabilizers.as_deref(),
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
            store,
            model,
            source_cache,
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
            store,
            model,
            source_cache,
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
            store,
            model,
            source_cache,
        } => sweep::run(sweep::Args {
            targets,
            image,
            work,
            egress,
            timeout,
            store,
            definitions,
            mirror_image,
            timewarp,
            model,
            source_cache,
        }),
        #[cfg(feature = "build")]
        Cmd::Attest {
            store,
            run,
            key,
            prune,
        } => attestor::run(attestor::Args {
            store,
            run,
            key,
            prune,
        }),
        #[cfg(feature = "build")]
        Cmd::Score {
            results,
            labels,
            baseline,
            fail_on_regression,
        } => score_run(&results, &labels, baseline.as_deref(), fail_on_regression),
        #[cfg(feature = "build")]
        Cmd::Runs { store } => attestor::list(&store),
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
        if let Some(tag) = mirror_image
            && egress != EgressTier::Open
        {
            mirror::warn_if_stale(tag);
        }
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
                    // Three different reasons, and naming the wrong one sends the reader to the
                    // wrong fix.
                    //
                    // The middle one used to say "the egress boundary held", and that was not
                    // true: rootless `podman build` cannot join the island, so at `mirror-only`
                    // the setup and source phases run as image layers with ordinary networking.
                    // Only `deny-all` closes the image build, and it does so by having no network
                    // there at all. Saying the boundary held when one phase ran outside it is the
                    // kind of claim this whole system exists to refuse.
                    let why = match outcome.egress {
                        trigon_sandbox::EgressTier::Open => {
                            "this run enforced no mirror and recorded no network transcript"
                        }
                        trigon_sandbox::EgressTier::DenyAll => {
                            "the build reached nothing, but this runner records no network \
                             transcript to show it"
                        }
                        _ => {
                            "the build phase was inside the boundary, the image build was not \
                             (setup and source run as layers, which rootless podman cannot put on \
                             the island), and this runner records no network transcript"
                        }
                    };
                    println!(
                        "\n  not attestable: {why}, so it cannot claim the build fetched nothing \
                         it should not have"
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
            //
            // `create_dir_all` first: a build that failed during the *image* build never reached
            // the point where the output directory is made, and those are exactly the runs whose
            // log nobody can otherwise see — which is how one target in the corpus came back
            // `unknown` with nothing to read.
            let log_path = out.join("build.log");
            if let Err(e) = std::fs::create_dir_all(out)
                .and_then(|()| std::fs::write(&log_path, &outcome.log_tail))
            {
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
        /// Read back from a previous run of the same sweep: label, cluster, model calls.
        Recorded(String, Option<String>, u32),
    }

    impl Outcome {
        pub fn label(&self) -> String {
            match self {
                Outcome::Compared(m) => m.to_string(),
                Outcome::NoStrategy => "no-strategy".into(),
                Outcome::BuildFailed { phase, .. } => format!("build-failed:{phase}"),
                Outcome::Failed { fault, .. } => format!("error:{fault:?}").to_lowercase(),
                Outcome::Void { .. } => "void".into(),
                Outcome::Recorded(label, ..) => label.clone(),
            }
        }

        /// How many times a model was called for this target.
        ///
        /// Zero from every live arm, and that is a measurement rather than a placeholder: no
        /// inference rung installed today calls one. It is written to the results file all the same,
        /// because the column is what lets `trigon score` tell "no model fired" apart from "nobody
        /// counted" — and the second reads exactly like the first once a model is wired in.
        pub fn model_calls(&self) -> u32 {
            match self {
                Outcome::Recorded(_, _, calls) => *calls,
                _ => 0,
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
                // Errors cluster too, and for the same reason. Twenty-six targets once came back
                // `error:upstream` with no diagnosis attached anywhere, and the cause was a single
                // bug of ours: one cluster, invisible because this arm returned `None`. A bucket
                // with no grouping is a bucket nobody reads.
                Outcome::Failed { detail, .. } => Some(format!("error:{}", generalize(detail))),
                // A resumed row carries its cluster forward. Without this, resuming a sweep — which
                // is how a long one always finishes — silently empties the cluster summary, and the
                // summary is the reason to run it.
                Outcome::Recorded(_, cluster, _) => cluster.clone(),
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
                Outcome::Recorded(label, ..) => label.parse().ok(),
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
        /// Record the run in a store for a separate attestor to sign.
        pub store: Option<PathBuf>,
        /// Ask a model for a strategy when nothing above it on the ladder produced one.
        ///
        /// Off unless the operator names a provider. A run that would silently call a model is a
        /// run whose cost and derivation are a surprise, and `docs/07-ai.md` §6 measures the
        /// invocation rate precisely because it is supposed to be something you choose.
        pub model: Option<String>,
        /// Where the model rung keeps its source checkouts.
        pub source_cache: Option<PathBuf>,
    }

    /// The ladder, in the order `docs/04-strategies.md` §6 sets out.
    ///
    /// A definition first, because one exists exactly where inference already failed. Then the
    /// ecosystem heuristic. Then, only if the operator asked for one, the model. The engine
    /// contains no branch asking which kind of rung produced a candidate: the ordering is the
    /// policy, and the model is last because everything above it is free and deterministic.
    fn ladder(
        target: &trigon_core::Ecosystem,
        client: Client,
        definitions: Option<PathBuf>,
        mirror: Option<String>,
        model: Option<&crate::inferrer::Configured>,
        sources: Option<PathBuf>,
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
                // The cache is shared with the model rung: a target whose repository both want is
                // fetched once.
                let sources = std::sync::Arc::new(trigon_registry::SourceCache::new(
                    sources.unwrap_or_else(trigon_registry::SourceCache::default_root),
                ));
                rungs.push(Box::new(
                    NpmInferrer::new(client)
                        .with_mirror(mirror)
                        .with_sources(Some(sources)),
                ))
            }
            trigon_core::Ecosystem::PyPI => {
                rungs.push(Box::new(PyPiInferrer::new(client).with_mirror(mirror)))
            }
            _ => {}
        }
        if let Some(m) = model
            && crate::inferrer::supported(*target)
        {
            rungs.push(Box::new(m.rung()));
        }
        rungs
    }

    pub fn run(args: Args) -> Result<()> {
        let outcome = run_one(args, true)?.outcome;
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
    /// One run's outcome, and what it cost in model calls.
    ///
    /// A pair rather than a field on `Outcome`, because the count is a property of the *run* and
    /// not of the verdict: a target that reproduced after two calls and one that reproduced after
    /// none are the same verdict and very different data points, and the eval harness needs the
    /// second number to say whether the invocation rate is trending down.
    pub struct Ran {
        pub outcome: Outcome,
        pub model_calls: u32,
    }

    impl From<Outcome> for Ran {
        fn from(outcome: Outcome) -> Self {
            Ran {
                outcome,
                model_calls: 0,
            }
        }
    }

    pub fn run_one(args: Args, verbose: bool) -> Result<Ran> {
        let target = TargetRef::from_str(&args.purl)?;
        // Before anything touches the network. A typo in `--model` should cost nothing and be
        // reported as a typo, not as a run that resolved a package and then died.
        //
        // Parsed once rather than per rung: a transcript is read once, and a live provider would
        // otherwise open a connection pool per target.
        let model = match &args.model {
            Some(spec) => Some(
                crate::inferrer::Configured::parse(spec)?
                    .with_cache_root(args.source_cache.clone()),
            ),
            None => None,
        };
        let client = Client::new(ClientConfig::default())?;
        let registry = for_ecosystem(target.ecosystem, client.clone())?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        std::fs::create_dir_all(&args.work)?;

        // 1. What the registry knows.
        let mut resolved = match rt.block_on(registry.resolve(&target)) {
            Ok(r) => r,
            Err(e) => return Ok(classify(&e).into()),
        };
        let meta = match resolved.pick(args.artifact.as_deref()) {
            Ok(m) => m.clone(),
            Err(e) => return Ok(classify(&e).into()),
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
            Err(e) => return Ok(classify(&e).into()),
        };
        drop(file);
        if verbose {
            println!("  published  sha256 {}", &upstream_digest.to_hex()[..16]);
        }

        // What the published artifact says about the toolchain that made it, added to the
        // intrinsics before inference so a rung can pin it. A read from the artifact under test,
        // which is the one source that cannot be out of date about its own build.
        if let Ok(bytes) = std::fs::read(&upstream_path) {
            let found = trigon_registry::wheel::generator_evidence(&bytes);
            if verbose && let Some(e) = found.first() {
                println!("  generator  {:?}", e.claim);
            }
            resolved.intrinsics.evidence.extend(found);
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

        // Taken before the ladder consumes `args`, so the record can be written at the end without
        // keeping the whole argument struct alive.
        let inputs = RecordInputs {
            purl: args.purl.clone(),
            work: args.work.clone(),
            image: args.image.clone(),
            egress: args.egress.clone(),
            // The instant the index was actually pinned to, not the flag that asked for one.
            // `auto` is a description of our command line; a signed statement has to describe the
            // environment, and a consumer reading `auto` learns nothing they could check.
            timewarp: resolved
                .intrinsics
                .publish_time
                .clone()
                .filter(|_| args.timewarp.is_some()),
            strategy_digest: None,
            derivation: None,
            pin: None,
            // Overwritten below from what the runner reported. `false` until then, because
            // claiming a run is attestable when we do not yet know is the one direction this must
            // not err in.
            attestable: false,
        };

        if let (Some(m), true) = (&model, verbose) {
            println!(
                "  model      {}, asked only where nothing deterministic answers",
                m.describe()
            );
        }
        let rungs = ladder(
            &target.ecosystem,
            client,
            args.definitions,
            timewarp_host.clone(),
            model.as_ref(),
            args.source_cache.clone(),
        );
        let Some(candidate) = rt.block_on(trigon_registry::infer(&rungs, &resolved))? else {
            return Ok(Ran {
                outcome: Outcome::NoStrategy,
                model_calls: calls(&model),
            });
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

        // 4. Build it, and repair it where a model is configured to try.
        let strategy_file = args.work.join("strategy.yaml");
        let out = args.work.join("rebuild");
        // Written next to the run, and mounted read-only into the island's mirror when there is
        // one. The mirror runs in a container with no route to this process, so a file is how the
        // manifest gets there.
        let guard_file = args.work.join("guard.json");
        std::fs::write(&guard_file, serde_json::to_vec_pretty(&guard)?)?;

        // Evidence the registry pin bound something, filled in once the mirror is torn down.
        let mut pin: Option<trigon_mirror::Observed> = None;
        let mirror_addr = mirror.as_ref().map(|m| m.host());

        // One mirror for the whole run rather than one per attempt: what it observed is a fact
        // about this run's dependency resolution, and restarting it between repairs would reset
        // the counters that say whether the pin bound anything.
        let mut strategy = candidate.strategy.clone();
        let mut repairs = trigon_ai::RepairLoop::new(
            trigon_ai::Budget::default(),
            // A person is waiting on a single `rebuild`, so admission control is off: they asked,
            // and the cost is one target's. A sweep passes prevalence and every gate applies.
            trigon_ai::Trigger::Interactive,
        );
        let repair_started = std::time::Instant::now();
        // Read on the first repair and not before. A run whose build works never touches the
        // repository, and a `--model` that is only there as a fallback should cost nothing.
        let mut repo_inputs: Option<crate::inferrer::Inputs> = None;
        // What the comparison said, when there was one to make. Carried out of the loop rather
        // than returned from inside it, because the mirror is torn down after the loop and an
        // early return would leave it running.
        let mut judged: Option<(PathBuf, trigon_compare::Comparison)> = None;
        let mut compare_error: Option<Outcome> = None;
        let (built, strategy_digest) = loop {
            // A fresh directory every attempt, including the first. Without clearing it before
            // the first, a `--work` directory reused across targets hands the *previous run's*
            // artifact to the comparison: `newest_file` takes the last path in sort order, which
            // has nothing to do with which run produced it. A second target built into the same
            // work directory would be judged against the first one's tarball.
            let _ = std::fs::remove_dir_all(&out);
            let strategy_yaml = trigon_strategy::to_yaml(&strategy)?;
            std::fs::write(&strategy_file, &strategy_yaml)?;
            // Over the canonical value, not the YAML bytes, so editing a comment does not change
            // what the attestation names or bust a cache entry across a hundred thousand targets.
            let strategy_digest = trigon_strategy::ToolRegistry::builtin()
                .and_then(|tools| trigon_strategy::strategy_digest(&strategy, &tools))
                .ok();
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

            // A tripped guard ends the loop whatever else happened, and before another attempt can
            // spend anything: the artifact under test reached the build, so nothing this run
            // produces is evidence about the source. The block below turns it into a `Void`.
            if mirror.as_ref().is_some_and(|m| !m.trips().is_empty()) {
                break (built, strategy_digest);
            }

            let Err(e) = &built else {
                // A build that ran is not yet an answer. The comparison happens here, inside the
                // loop, because a divergence is the repair case that matters most: the recipe
                // works and builds something that is not what was published.
                let Some(rebuilt) = newest_file(&out) else {
                    break (built, strategy_digest);
                };
                let comparison = match judge(&upstream_path, &rebuilt) {
                    Ok(c) => c,
                    Err(outcome) => {
                        compare_error = Some(outcome);
                        break (built, strategy_digest);
                    }
                };
                if comparison.outcome != trigon_core::Match::Divergent {
                    judged = Some((rebuilt, comparison));
                    break (built, strategy_digest);
                }

                let Some(cfg) = &model else {
                    judged = Some((rebuilt, comparison));
                    break (built, strategy_digest);
                };
                // The same admission control as a build failure, over a signature built from the
                // difference codes. Two divergences that differ the same way are the model
                // restating, exactly as two builds that fail the same way are.
                let failure = divergence_signature(&comparison);
                match repairs.next(&failure, &trigon_ai::NoPrior, repair_started.elapsed().as_secs())
                {
                    trigon_ai::Decision::Stop(reason) => {
                        if verbose {
                            println!("  repair     stopped: {}", stop_reason(&reason));
                        }
                        tracing::info!(?reason, "the repair loop stopped after a divergence");
                        judged = Some((rebuilt, comparison));
                        break (built, strategy_digest);
                    }
                    trigon_ai::Decision::Attempt { .. } => {
                        if repo_inputs.is_none() {
                            match cfg.inputs(&resolved) {
                                Ok(i) => repo_inputs = Some(i),
                                Err(e) => {
                                    tracing::warn!("no repair: {e:#}");
                                    judged = Some((rebuilt, comparison));
                                    break (built, strategy_digest);
                                }
                            }
                        }
                        let read = repo_inputs.as_ref().expect("just filled");
                        let brief = divergence_brief(&comparison);
                        if verbose {
                            println!(
                                "  repair     attempt {} on {}",
                                repairs.attempts().len() + 1,
                                failure.key()
                            );
                        }
                        let before = cfg.spent();
                        let proposed = cfg.repair_divergence(read, &strategy_yaml, &brief);
                        let after = cfg.spent();
                        repairs.record(trigon_ai::Attempt {
                            signature: failure.key(),
                            // The build reached the end; what differs is what it produced.
                            reached: trigon_core::Phase::Collect,
                            tokens_in: after.input.saturating_sub(before.input),
                            tokens_out: after.output.saturating_sub(before.output),
                            cached_in: after.cached_input.saturating_sub(before.cached_input),
                        });
                        match proposed {
                            Ok(next) => {
                                strategy = next;
                                continue;
                            }
                            Err(e) => {
                                tracing::warn!("the proposal produced nothing: {e:#}");
                                judged = Some((rebuilt, comparison));
                                break (built, strategy_digest);
                            }
                        }
                    }
                }
            };
            // Only a failure the build itself reported carries a signature. Our own errors and a
            // void run are not something a different recipe fixes.
            let Some(failure) = e
                .downcast_ref::<crate::BuildFailure>()
                .map(|f| f.signature.clone())
            else {
                break (built, strategy_digest);
            };
            let Some(cfg) = &model else {
                break (built, strategy_digest);
            };

            match repairs.next(&failure, &trigon_ai::NoPrior, repair_started.elapsed().as_secs()) {
                trigon_ai::Decision::Stop(reason) => {
                    // Said out loud. Which stop rule fired is the difference between "the budget
                    // is too small", "we have no rule for this" and "working as intended", and a
                    // run that just stops tells the operator none of them.
                    if verbose {
                        println!("  repair     stopped: {}", stop_reason(&reason));
                    }
                    tracing::info!(?reason, "the repair loop stopped");
                    break (built, strategy_digest);
                }
                trigon_ai::Decision::Attempt { escalate } => {
                    if repo_inputs.is_none() {
                        match cfg.inputs(&resolved) {
                            Ok(i) => repo_inputs = Some(i),
                            // No repository to read is not a failure of the run: the build failed
                            // for its own reasons and that is what gets reported.
                            Err(e) => {
                                tracing::warn!("no repair: {e:#}");
                                break (built, strategy_digest);
                            }
                        }
                    }
                    let read = repo_inputs.as_ref().expect("just filled");
                    // Compressed here rather than inside the provider, so the caller who chose the
                    // budget can see what it is spending. Raw build output is the most expensive
                    // mistake available: `docs/07-ai.md` §4.5 measures the difference at ~7x.
                    let log = std::fs::read_to_string(out.join("build.log")).unwrap_or_default();
                    // 8k, which is what `docs/07-ai.md` §4.5 costs its figures at. A larger
                    // budget buys dependency noise; a smaller one clips the error.
                    let compressed = trigon_core::compress(&log, 8 * 1024);
                    if verbose {
                        println!(
                            "  repair     attempt {} on {}{}",
                            repairs.attempts().len() + 1,
                            failure.key(),
                            if escalate { ", escalated" } else { "" },
                        );
                    }
                    let before = cfg.spent();
                    let proposed = cfg.repair(read, &strategy_yaml, &failure, &compressed.text);
                    // Recorded whether or not the answer was usable. An attempt that produced
                    // nothing still cost tokens and still counts against the budget; not recording
                    // it is how a loop spends its cap on calls it threw away.
                    let after = cfg.spent();
                    repairs.record(trigon_ai::Attempt {
                        signature: failure.key(),
                        reached: e
                            .downcast_ref::<crate::BuildFailure>()
                            .and_then(|f| f.phase.parse().ok())
                            .unwrap_or(trigon_core::Phase::Build),
                        tokens_in: after.input.saturating_sub(before.input),
                        tokens_out: after.output.saturating_sub(before.output),
                        cached_in: after.cached_input.saturating_sub(before.cached_input),
                    });
                    match proposed {
                        Ok(next) => {
                            strategy = next;
                            continue;
                        }
                        Err(e) => {
                            // A model that will not answer, or an answer that will not parse. The
                            // run ends on the build failure it already had rather than on ours.
                            tracing::warn!("the repair produced nothing: {e:#}");
                            break (built, strategy_digest);
                        }
                    }
                }
            }
        };
        let derivation = if repairs.attempts().is_empty() {
            format!("{:?}", candidate.derivation).to_lowercase()
        } else {
            // Whatever produced the first candidate, what ran is what a model last proposed.
            "model_assisted".to_string()
        };

        if let Some(m) = mirror {
            // A claim of a pinned dependency graph has to be able to show the pin did something,
            // and until this check existed it could not. `PIP_INDEX_URL` without `PIP_TRUSTED_HOST`
            // makes pip warn once and then resolve against the live index, so every PyPI run
            // recorded a moment it did not have — for weeks, with this counter sitting at zero the
            // whole time and reading exactly like a build that needed nothing.
            let observed = m.observed();
            pin = Some(observed);
            if verbose {
                // The denominator is stated inline because the count is a total across every
                // packument the build fetched, not the target's own. left-pad publishes fifteen
                // versions and withholds none of them; the thousand-odd are its devDependency
                // tree, where `mocha` alone accounts for a hundred. "1044 versions withheld" on
                // its own reads as a claim about left-pad and is not one.
                println!(
                    "\n  mirror     {} index request(s), {} version(s) withheld across them",
                    observed.index_requests, observed.versions_withheld,
                );
                if observed.toolchain_requests > 0 {
                    // Named separately because it is a different claim: the build fetched the
                    // thing that would run, not a dependency, and it did so from a host on the
                    // mirror's allowlist rather than one the strategy chose.
                    println!(
                        "             {} toolchain download(s) through the allowlist",
                        observed.toolchain_requests
                    );
                }
            }
            // Zero is ambiguous — a package with no dependencies asks for nothing — so this warns
            // rather than fails unless the caller says otherwise. Silence was the whole problem;
            // guessing which silence is which would be a different one.
            if !observed.pin_bound() {
                let how = if observed.contacted() {
                    "it was contacted but served no index document"
                } else {
                    "it was never contacted"
                };
                tracing::warn!(
                    rejected = observed.rejected,
                    "this run claims to resolve against the index as it stood at the publish \
                     moment, and the mirror cannot confirm it: {how}. Either the build needed no \
                     dependencies, or the pin did not reach the client and it resolved against \
                     today's index."
                );
            }
            let trips = m.trips();
            rt.block_on(m.shutdown());
            if let Some(t) = trips.first() {
                // Checked before the build's exit status is even considered. A tripped guard means
                // the run cannot be used, whether the build succeeded or failed.
                return Ok(Ran {
                    outcome: Outcome::Void {
                        reason: format!("{:?} arrived from {}", t.matched, t.url),
                    },
                    model_calls: calls(&model),
                });
            }
        }
        if let Err(e) = built {
            let text = e.to_string();
            if let Some(reason) = text.strip_prefix("void: ") {
                return Ok(Ran {
                    outcome: Outcome::Void {
                        reason: reason.to_string(),
                    },
                    model_calls: calls(&model),
                });
            }
            return Ok(Ran {
                outcome: build_outcome(&e),
                model_calls: calls(&model),
            });
        }

        // 5. The comparison the loop already made, with the same code path `verify` uses.
        if let Some(outcome) = compare_error {
            return Ok(Ran {
                outcome,
                model_calls: calls(&model),
            });
        }
        let Some((rebuilt, comparison)) = judged else {
            return Ok(Ran {
                model_calls: calls(&model),
                outcome: Outcome::BuildFailed {
                    phase: "collect".into(),
                    signature: Some(trigon_core::FailureSignature {
                        code: std::borrow::Cow::Borrowed("trigon/no-output"),
                        subject: None,
                        fault: trigon_core::Fault::Bug,
                        retryable: false,
                        repairable: true,
                        evidence: "the build succeeded and left no artifact at the output path"
                            .into(),
                    }),
                },
            });
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
        if let Some(dir) = &args.store {
            // A failure here does not fail the run. The comparison already happened and its verdict
            // is what the caller asked for; losing the record is a thing to report, not a reason to
            // throw the verdict away.
            let inputs = RecordInputs {
                strategy_digest: strategy_digest.clone(),
                derivation: Some(derivation.clone()),
                pin,
                // Asked of the runner that ran it, rather than derived from the flag that asked
                // for a tier. The local runner reports `false` at every tier — it records no
                // network transcript — and deriving this from `--egress` stamped `attestable:
                // true` on runs whose image-build phases were outside the boundary entirely.
                attestable: trigon_sandbox::BuildRunner::caps(&trigon_sandbox::PodmanRunner::new(
                    &args.work,
                ))
                .attestable,
                ..inputs.clone()
            };
            if let Err(e) = record_run(dir, &inputs, &upstream_path, &rebuilt, &comparison, verbose)
            {
                tracing::warn!("could not record this run: {e:#}");
            }
        }
        Ok(Ran {
            outcome: Outcome::Compared(comparison.outcome),
            model_calls: calls(&model),
        })
    }

    /// What a run has spent so far, with no provider configured reading as zero rather than as
    /// missing: nothing was asked because nothing could be.
    fn calls(model: &Option<crate::inferrer::Configured>) -> u32 {
        model.as_ref().map_or(0, |m| m.calls())
    }

    /// Reduce one of our own error messages to the part that is the same across targets.
    ///
    /// Paths, digests, versions and package names are what make two reports of one bug look like
    /// two bugs. Dropping them is crude — it cannot know which number mattered — but the alternative
    /// in practice is no grouping at all, and a cluster of twenty-six is what makes somebody look.
    fn generalize(detail: &str) -> String {
        let first = detail.lines().next().unwrap_or(detail);
        let mut out = String::with_capacity(first.len());
        let mut last_was_elision = false;
        for word in first.split_whitespace() {
            let noisy =
                word.len() > 24 || word.contains('/') || word.chars().any(|c| c.is_ascii_digit());
            if noisy {
                if !last_was_elision {
                    out.push_str(" _");
                    last_was_elision = true;
                }
            } else {
                out.push(' ');
                out.push_str(word);
                last_was_elision = false;
            }
        }
        out.trim().chars().take(80).collect()
    }

    /// Write everything a separate attestor needs to sign this run without re-running it.
    ///
    /// Artifacts, the build log and the comparison go in as blobs addressed by their own hashes; the
    /// record holds digests and small scalars. That split is what lets the attestor check every byte
    /// it reads against the hash it asked for rather than trusting whoever wrote it.
    /// The fields a record needs, captured before `args` is consumed by the inference ladder.
    #[derive(Clone)]
    struct RecordInputs {
        purl: String,
        work: PathBuf,
        image: String,
        egress: String,
        timewarp: Option<String>,
        strategy_digest: Option<String>,
        derivation: Option<String>,
        pin: Option<trigon_mirror::Observed>,
        /// What the runner reported about its own enforcement, never what the flag asked for.
        attestable: bool,
    }

    fn record_run(
        dir: &Path,
        args: &RecordInputs,
        upstream_path: &Path,
        rebuilt: &Path,
        c: &trigon_compare::Comparison,
        verbose: bool,
    ) -> Result<()> {
        use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let store = Store::local(dir)?;
            let up_bytes = std::fs::read(upstream_path)?;
            let rb_bytes = std::fs::read(rebuilt)?;
            let up = store.blobs().put(up_bytes.clone()).await?;
            let rb = store.blobs().put(rb_bytes.clone()).await?;
            let comparison = store.blobs().put(serde_json::to_vec(c)?).await?;
            let build_log = match std::fs::read(args.work.join("rebuild").join("build.log"))
                .or_else(|_| std::fs::read(args.work.join("build.log")))
            {
                Ok(b) => Some(store.blobs().put(b).await?),
                Err(_) => None,
            };

            // Time-ordered, so listing a store gives the most recent run first without reading
            // every record to sort them.
            let id = format!(
                "{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                &c.upstream.raw.sha256.to_hex()[..8]
            );

            let mut record = RunRecord::new(
                id.clone(),
                &args.purl,
                ArtifactRef {
                    name: crate::file_name(upstream_path),
                    sha256: up,
                    bytes: up_bytes.len() as u64,
                    stored: true,
                },
                Environment {
                    base_image: args.image.clone(),
                    egress: args.egress.clone(),
                    isolation: String::new(),
                    // What the runner reported, not what the flag asked for. Deriving this from
                    // `--egress` stamped `attestable: true` on a local podman run — which is never
                    // attestable at full trust, because it records no network transcript, and
                    // whose image-build phases are outside the boundary at every tier but
                    // `deny-all`. A claim about enforcement has to come from the thing that
                    // enforced it.
                    attestable: args.attestable,
                    registry_moment: args.timewarp.clone(),
                    pin: args.pin.map(|o| trigon_store::PinEvidence {
                        index_requests: o.index_requests,
                        versions_withheld: o.versions_withheld,
                        artifact_requests: o.artifact_requests,
                        toolchain_requests: o.toolchain_requests,
                        rejected: o.rejected,
                    }),
                },
                now_rfc3339(),
            );
            record.state = RunState::Done;
            record.strategy_digest = args.strategy_digest.clone();
            record.derivation = args.derivation.clone();
            record.outcome = Some(c.outcome.to_string());
            record.rebuild = Some(ArtifactRef {
                name: crate::file_name(rebuilt),
                sha256: rb,
                bytes: rb_bytes.len() as u64,
                stored: true,
            });
            record.comparison = Some(comparison);
            record.build_log = build_log;
            record.finished = Some(now_rfc3339());
            store.put_run(&record).await?;
            if verbose {
                println!("\n  recorded   run {id} in {}", dir.display());
            }
            anyhow::Ok(())
        })
    }

    /// The current instant, as RFC 3339 UTC.
    ///
    /// Hand-rolled rather than pulling in a date library for one format. UTC only, and seconds
    /// precision, which is all a run record needs.
    fn now_rfc3339() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let days = secs.div_euclid(86_400);
        let tod = secs.rem_euclid(86_400);
        // Civil-from-days, Howard Hinnant's algorithm: exact, branch-free and about ten lines,
        // against a dependency whose only other use here would be formatting.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            tod / 3600,
            (tod % 3600) / 60,
            tod % 60
        )
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
    /// Compare the two artifacts, the way `verify` does.
    fn judge(upstream: &Path, rebuilt: &Path) -> Result<trigon_compare::Comparison, Outcome> {
        let read = || -> Result<trigon_compare::Comparison> {
            let format = crate::resolve_format(upstream, None)?;
            let set = crate::resolve_profile(upstream, None, format)?;
            let a = std::fs::read(upstream)?;
            let b = std::fs::read(rebuilt)?;
            // Classified as itself rather than as an anyhow string: a comparison that could not
            // run is our fault or the archive's, and which one it is has to survive to the caller.
            compare_bytes(a, b, format, &set, &Limits::default())
                .map_err(|e| anyhow::Error::new(ComparisonFailed(classify(&e))))
        };
        read().map_err(|e| match e.downcast::<ComparisonFailed>() {
            Ok(ComparisonFailed(o)) => o,
            Err(e) => Outcome::Failed {
                fault: trigon_core::Fault::Infra,
                detail: e.to_string(),
            },
        })
    }

    /// A comparison that could not run, carrying the classification it already had.
    #[derive(Debug)]
    struct ComparisonFailed(Outcome);

    impl std::fmt::Display for ComparisonFailed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "the comparison could not run")
        }
    }

    impl std::error::Error for ComparisonFailed {}

    /// A divergence, in the shape the repair loop's admission control reads.
    ///
    /// The subject is the difference *codes*, not the file names: `docs/07-ai.md` §4.2 keys repair
    /// caching on a normalized signature, and a key carrying `dist/index.js` is a key that matches
    /// one package. `entry:content` is a class of problem that recurs across thousands.
    ///
    /// Repairable, because a divergence is the case a different recipe can fix — which is the whole
    /// reason this exists. Not retryable: the same recipe produces the same bytes.
    fn divergence_signature(c: &trigon_compare::Comparison) -> trigon_core::FailureSignature {
        let codes = c.diff.as_ref().map(|d| &d.codes);
        // The codes carry `@path` suffixes; the class is what comes before, and a handful of
        // classes is what makes this a cluster rather than a list of packages.
        let mut classes: std::collections::BTreeSet<&str> = Default::default();
        for code in codes.into_iter().flatten() {
            classes.insert(code.split('@').next().unwrap_or(code));
        }
        let subject = (!classes.is_empty()).then(|| classes.into_iter().collect::<Vec<_>>().join(","));
        trigon_core::FailureSignature {
            code: std::borrow::Cow::Borrowed("divergence"),
            subject,
            // The package built and the result differs. Not our infrastructure, and not a broken
            // package either until somebody has looked.
            fault: trigon_core::Fault::Build,
            retryable: false,
            repairable: true,
            evidence: c
                .diff
                .as_ref()
                .map(|d| {
                    format!(
                        "{} identical, {} differ, {} only upstream, {} only in the rebuild",
                        d.identical, d.differs, d.only_upstream, d.only_rebuild
                    )
                })
                .unwrap_or_else(|| "the stabilized digests differ".into()),
        }
    }

    /// What differs, for a model to read.
    ///
    /// Named files here, unlike the signature: the signature is a cluster key and this is the
    /// evidence. A model that is told "four members differ" can do nothing; one told
    /// `dist/index.js` is only in the published artifact can infer a build step.
    fn divergence_brief(c: &trigon_compare::Comparison) -> String {
        let mut out = String::new();
        let Some(d) = &c.diff else {
            return "the stabilized digests differ, with no member-level detail available".into();
        };
        out.push_str(&format!(
            "{} members identical, {} differ, {} only in the published artifact, {} only in the \
             rebuild.\n",
            d.identical, d.differs, d.only_upstream, d.only_rebuild
        ));
        if !d.codes.is_empty() {
            out.push_str("\nDifference codes:\n");
            // Capped: a wholesale mismatch produces one code per member, and a thousand of them
            // buys nothing the first twenty do not say.
            for code in d.codes.iter().take(40) {
                out.push_str(&format!("  {code}\n"));
            }
            if d.codes.len() > 40 {
                out.push_str(&format!("  … and {} more\n", d.codes.len() - 40));
            }
        }
        let mut named = 0;
        for f in &d.files {
            if f.status == trigon_compare::FileStatus::Identical || named >= 40 {
                continue;
            }
            named += 1;
            out.push_str(&format!(
                "  {:?} {} ({:?})\n",
                f.status,
                String::from_utf8_lossy(f.path.as_bytes()),
                f.kind
            ));
        }
        out
    }

    /// Why the repair loop stopped, in a sentence.
    ///
    /// Each of these is a different thing to do about it — a knob, a gap in our rule table, or the
    /// budget working as intended — and a run that just stops tells the operator none of them.
    fn stop_reason(r: &trigon_ai::StopReason) -> String {
        use trigon_ai::StopReason as S;
        match r {
            S::NotRepairable => "the failure is not one a different recipe fixes".into(),
            S::KnownUnfixable => "this failure has been attempted before and never repaired".into(),
            S::NoProgress { signature } => format!(
                "two attempts failed the same way ({signature}), so the model is restating rather \
                 than searching"
            ),
            S::BelowPrevalenceThreshold { score, threshold } => format!(
                "prevalence {score:.3} is below the sweep's threshold of {threshold:.3}"
            ),
            S::IterationCap { cap } => format!("the iteration cap of {cap} was reached"),
            S::BudgetExhausted { what } => format!("the {what} budget was exhausted"),
            S::Repaired => "the build succeeded".into(),
        }
    }

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
    ///
    /// **Regular files only, and the type is taken without following the link.** The build writes
    /// into a directory this process then reads, so a symlink there is the build choosing a path on
    /// *our* filesystem — and the published artifact is sitting two levels up, under a name the
    /// package knows. `ln -s ../../evil-1.2.3.tgz /out/zzz.tgz` would otherwise make the published
    /// bytes the "rebuild", compare them against themselves, and sign `Exact`. That is
    /// `docs/12-security.md` §1.1 with no network needed at all.
    fn newest_file(dir: &Path) -> Option<PathBuf> {
        let mut found: Vec<PathBuf> = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).ok()?.flatten() {
                let p = e.path();
                // `file_type` on the entry is `lstat`: a symlink reports as a symlink rather than
                // as whatever it points at. `Path::is_dir`/`is_file` follow it, which is the bug.
                let Ok(kind) = e.file_type() else { continue };
                if kind.is_dir() {
                    stack.push(p);
                } else if !kind.is_file() {
                    tracing::warn!(
                        path = %p.display(),
                        "ignoring a collected entry that is not a regular file"
                    );
                // Belt and braces beside writing the log elsewhere. Anything that is obviously ours
                // rather than the build's has no business being mistaken for the artifact, and the
                // failure when it is — a log parsed as a zip — names the wrong culprit.
                } else if p.file_name() != Some(std::ffi::OsStr::new("build.log")) {
                    found.push(p);
                }
            }
        }
        found.sort();
        found.pop()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn tmpdir(tag: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!("trigon-collect-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        #[test]
        fn a_symlink_the_build_wrote_is_never_taken_for_the_artifact() {
            // The build writes into a directory this process reads, so a symlink there is the
            // build choosing a path on *our* filesystem — and the published artifact sits two
            // levels up under a name the package knows. Following it would compare the published
            // bytes against themselves and sign `Exact`: `docs/12-security.md` §1.1, with no
            // network needed.
            let d = tmpdir("symlink");
            let published = d.join("evil-1.2.3.tgz");
            std::fs::write(&published, b"the published bytes").unwrap();
            let out = d.join("rebuild");
            std::fs::create_dir_all(&out).unwrap();

            // Sorts last, so it would win on any collector that took it.
            std::os::unix::fs::symlink(&published, out.join("zzz.tgz")).unwrap();
            assert_eq!(newest_file(&out), None, "a symlink is not an artifact");

            // A real file beside it is still found, and the symlink still is not.
            let real = out.join("aaa.tgz");
            std::fs::write(&real, b"built here").unwrap();
            assert_eq!(newest_file(&out), Some(real));
        }

        #[test]
        fn a_symlinked_directory_is_not_walked_into() {
            // The same escape one level up: a link to a directory elsewhere would put every file
            // under it in the running for "the artifact".
            let d = tmpdir("symlink-dir");
            let elsewhere = d.join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();
            std::fs::write(elsewhere.join("zzz.tgz"), b"not ours to collect").unwrap();
            let out = d.join("rebuild");
            std::fs::create_dir_all(&out).unwrap();
            std::os::unix::fs::symlink(&elsewhere, out.join("sub")).unwrap();

            assert_eq!(newest_file(&out), None);
        }
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
            // The cache mounts turn a rebuild from a forty-minute full recompile into an
            // incremental one. `COPY . .` invalidates on any source change, so without them every
            // rebuild compiles all ~180 dependency crates against musl again to pick up a one-line
            // change in ours — which is most of why this image goes stale and stays stale.
            //
            // A cache mount is not part of the resulting layer, so the binary has to be copied out
            // of the target directory before the mount goes away.
            "FROM docker.io/library/rust:1-alpine AS build\n\
             RUN apk add --no-cache musl-dev\n\
             WORKDIR /src\n\
             COPY . .\n\
             RUN --mount=type=cache,target=/usr/local/cargo/registry \\\n\
             \x20   --mount=type=cache,target=/src/target \\\n\
             \x20   cargo build --release -p trigon --bin trigon \\\n\
             \x20   && cp target/release/trigon /trigon\n\
             \n\
             FROM docker.io/library/alpine:3.20\n\
             COPY --from=build /trigon /usr/local/bin/trigon\n\
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
            .args(["--label", &format!("{SOURCE_LABEL}={}", source_digest(&root)?)])
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

    /// The label carrying the source the image was compiled from.
    const SOURCE_LABEL: &str = "dev.trigon.mirror-source";

    /// A digest of the source that decides how the mirror behaves.
    ///
    /// Scoped to `trigon-mirror` alone, not the workspace and not its dependencies. A digest over
    /// everything would be correct and useless: it changes when a stabilizer or a failure rule
    /// changes, and a warning that fires on every commit is one people learn to ignore. The routes,
    /// the time filter and the guard all live in this one crate, so this is where staleness that
    /// changes what a build sees comes from.
    fn source_digest(root: &Path) -> Result<String> {
        use sha2::Digest as _;
        let mut files = Vec::new();
        for crate_name in ["trigon-mirror"] {
            let dir = root.join("crates").join(crate_name);
            files.push(dir.join("Cargo.toml"));
            let mut stack = vec![dir.join("src")];
            while let Some(d) = stack.pop() {
                for entry in std::fs::read_dir(&d)
                    .with_context(|| format!("reading {}", d.display()))?
                    .flatten()
                {
                    let p = entry.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else {
                        files.push(p);
                    }
                }
            }
        }
        // Sorted, because a directory listing is in whatever order the filesystem feels like and a
        // digest that depends on that is a digest that changes for no reason.
        files.sort();
        let mut h = sha2::Sha256::new();
        for f in &files {
            h.update(f.strip_prefix(root).unwrap_or(f).to_string_lossy().as_bytes());
            h.update([0]);
            h.update(std::fs::read(f).with_context(|| format!("reading {}", f.display()))?);
            h.update([0]);
        }
        Ok(format!("{:x}", h.finalize())[..16].to_string())
    }

    /// Say so when the mirror image predates the source it is being used with.
    ///
    /// The failure this exists for is silent and expensive: an image built before a mirror change
    /// serves the old routes, so a build fails on something the current source handles. What the
    /// operator sees is a 400 from inside the island and a strategy that looks wrong. Found by
    /// hitting it — the toolchain route returned `400 Bad Request` from an image built twenty
    /// minutes earlier.
    ///
    /// A warning and never an error. The image may be deliberately older, the workspace may not be
    /// present at all, and refusing to run would turn a diagnostic into an obstacle.
    pub fn warn_if_stale(tag: &str) {
        let Ok(root) = workspace_root() else { return };
        let Ok(want) = source_digest(&root) else {
            return;
        };
        let out = std::process::Command::new("podman")
            .args(["image", "inspect", tag, "--format"])
            .arg(format!("{{{{index .Labels \"{SOURCE_LABEL}\"}}}}"))
            .output();
        let Ok(out) = out else { return };
        if !out.status.success() {
            return;
        }
        let have = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if have == want {
            return;
        }
        let detail = if have.is_empty() || have == "<no value>" {
            "it carries no source label, so it was built before this check existed".to_string()
        } else {
            format!("it was built from {have}, and this binary is {want}")
        };
        tracing::warn!(
            "{tag} may be stale: {detail}. Rebuild it with `trigon mirror-image`. A stale mirror \
             serves the routes it was built with, and the build inside the island fails on \
             something this source handles."
        );
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
            // Both lines, because `index-url` on its own does not work and does not say so: pip
            // warns once about an untrusted plain-HTTP index and then resolves as though none were
            // configured. Printing only the first half is an instruction to reproduce the bug.
            println!("  pypi   /etc/pip.conf:");
            println!("           [global]");
            println!(
                "           index-url = http://pypi:<RFC3339>@{}/simple",
                handle.host()
            );
            println!("           trusted-host = {}", handle.host());
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
        /// Record every run in a store, so a sweep leaves something an attestor can sign.
        pub store: Option<PathBuf>,
        /// Passed to every target. A sweep that asks a model does so for all of them or none: a
        /// rate measured over a mixture of the two is not a rate of anything.
        pub model: Option<String>,
        pub source_cache: Option<PathBuf>,
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
            if let Some((label, secs, cluster, calls)) = already.get(*purl) {
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
                    Outcome::Recorded(label.clone(), cluster.clone(), *calls),
                    *secs,
                ));
                continue;
            }
            let started = Instant::now();
            // A per-target directory, or one run's artifacts are collected as another's.
            let work = args.work.join(format!("{i:03}"));
            let _ = std::fs::remove_dir_all(&work);

            let ran = crate::rebuild::run_one(
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
                    store: args.store.clone(),
                    model: args.model.clone(),
                    source_cache: args.source_cache.clone(),
                },
                false,
            )
            // A target that cannot even be parsed is that target's problem, not the sweep's.
            .unwrap_or_else(|e| {
                Outcome::Failed {
                    fault: trigon_core::Fault::Policy,
                    detail: e.to_string(),
                }
                .into()
            });
            let (outcome, model_calls) = (ran.outcome, ran.model_calls);

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
                "{purl}\t{}\t{secs:.1}\t{}\t{}",
                outcome.label(),
                outcome.cluster().unwrap_or_default(),
                // What this run actually spent, not what the outcome remembers: a fresh row knows
                // its own count and only a resumed one has to read it back out of the file.
                model_calls.max(outcome.model_calls()),
            )?;
            sink.flush()?;
            rows.push((purl.to_string(), outcome, secs));
        }

        summarize(&rows);
        Ok(())
    }

    /// Targets already recorded in a previous run of this sweep.
    fn completed(path: &Path) -> BTreeMap<String, (String, f64, Option<String>, u32)> {
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
                // The model-call column arrived after the cluster column did, and is read the same
                // way: absent means the sweep that wrote this row did not count, which resumes as
                // zero rather than refusing the row.
                let calls = f.next().and_then(|c| c.parse().ok()).unwrap_or(0);
                out.insert(
                    purl.to_string(),
                    (label.to_string(), secs.parse().unwrap_or(0.0), cluster, calls),
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
            let (label, secs, cluster, _) = got.get("pkg:npm/a@1").unwrap();
            assert_eq!(label, "build-failed:deps");
            assert_eq!(*secs, 12.0);
            assert_eq!(cluster.as_deref(), Some("cc/missing-header:python.h"));

            let o = Outcome::Recorded(label.clone(), cluster.clone(), 0);
            assert_eq!(o.cluster().as_deref(), Some("cc/missing-header:python.h"));
        }

        #[test]
        fn a_resumed_row_carries_its_model_call_count_forward() {
            // Same reason the cluster is carried: resuming a sweep is how a long one finishes, and
            // a count that resets on resume reports fewer model calls the longer the sweep took.
            let d = tmpdir("calls");
            let p = write(&d, "pkg:npm/a@1\tnormalized\t12.0\t\t3\n");
            let got = completed(&p);
            let (_, _, _, calls) = got.get("pkg:npm/a@1").unwrap();
            assert_eq!(*calls, 3);
            assert_eq!(Outcome::Recorded("normalized".into(), None, *calls).model_calls(), 3);
        }

        #[test]
        fn a_results_file_written_before_clusters_existed_still_resumes() {
            // Three columns, not four. Read as "no cluster recorded" rather than as a broken row:
            // refusing to resume an older file would throw away hours of completed builds.
            let d = tmpdir("legacy");
            let p = write(&d, "pkg:npm/a@1\tnormalized\t12.0\n");
            let got = completed(&p);
            let (label, _, cluster, _) = got.get("pkg:npm/a@1").unwrap();
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
                let o = Outcome::Recorded(label.to_string(), None, 0);
                assert!(
                    o.as_match().is_some(),
                    "`{label}` did not parse back into an outcome"
                );
                assert_eq!(o.label(), label);
            }
        }

        #[test]
        fn our_own_errors_cluster_so_one_bug_does_not_read_as_many() {
            // The case this comes from: a bug of ours made every successful build compare a log
            // file against the published artifact. Twenty-six targets, one cause, and the summary
            // showed twenty-six undiagnosed rows because errors had no cluster at all.
            let a = Outcome::Failed {
                fault: trigon_core::Fault::Upstream,
                detail: "malformed zip: no end-of-central-directory record".into(),
            };
            let b = Outcome::Failed {
                fault: trigon_core::Fault::Upstream,
                detail: "malformed zip: no end-of-central-directory record".into(),
            };
            assert_eq!(a.cluster(), b.cluster());
            assert!(a.cluster().is_some());

            // And what varies per target does not split the cluster.
            let x = Outcome::Failed {
                fault: trigon_core::Fault::Infra,
                detail: "reading /work/041/left-pad-1.3.0.tgz: No such file".into(),
            };
            let y = Outcome::Failed {
                fault: trigon_core::Fault::Infra,
                detail: "reading /work/002/is-odd-3.0.1.tgz: No such file".into(),
            };
            assert_eq!(
                x.cluster(),
                y.cluster(),
                "{:?} vs {:?}",
                x.cluster(),
                y.cluster()
            );

            // But genuinely different errors stay apart.
            assert_ne!(a.cluster(), x.cluster());
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

/// Read a sweep's `results.tsv`.
///
/// Returns the observations and whether the file recorded model calls at all. Rows written before
/// the column existed carry no count, and reading their absence as zero would report "0 model
/// calls" for a sweep that never looked — the same sentence a clean run prints. Absent is not zero.
#[cfg(feature = "build")]
fn read_results(path: &Path) -> Result<(Vec<trigon_ai::Observation>, bool)> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut recorded = false;
    let observed = text
        .lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let purl = f.next()?.to_string();
            let label = f.next()?;
            let calls = f
                .nth(2)
                .filter(|c| !c.is_empty())
                .and_then(|c| c.parse::<u32>().ok());
            recorded |= calls.is_some();
            Some(trigon_ai::Observation {
                purl,
                outcome: label
                    .parse::<trigon_core::Match>()
                    .ok()
                    .map(|m| m.to_string()),
                model_calls: calls.unwrap_or(0),
                is_evidence: label.parse::<trigon_core::Match>().is_ok(),
            })
        })
        .collect();
    Ok((observed, recorded))
}

/// Score a sweep's results against its labelled corpus, and against an earlier sweep of it.
#[cfg(feature = "build")]
fn score_run(
    results: &Path,
    labels: &Path,
    baseline: Option<&Path>,
    fail_on_regression: bool,
) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct Corpus {
        labels: Vec<trigon_ai::Labelled>,
    }
    let corpus: Corpus = serde_json::from_slice(
        &std::fs::read(labels).with_context(|| format!("reading {}", labels.display()))?,
    )
    .with_context(|| format!("parsing {}", labels.display()))?;

    let (observed, recorded) = read_results(results)?;

    let card = trigon_ai::score(&corpus.labels, &observed);
    if recorded {
        println!(
            "{} targets, {} model call(s)\n",
            corpus.labels.len(),
            card.model_calls
        );
    } else {
        println!(
            "{} targets, model calls not recorded by this sweep\n",
            corpus.labels.len()
        );
    }
    for (capability, rate) in &card.by_capability {
        match rate.fraction() {
            Some(f) => println!(
                "  {capability:<24} {:>2}/{:<2} reproduced ({:.0}%)   of {} labelled",
                rate.reproduced,
                rate.evidence,
                f * 100.0,
                rate.total
            ),
            // Not 0%. "Nothing reproduces" and "nothing was tested" are different findings.
            None => println!(
                "  {capability:<24}  no evidence            of {} labelled",
                rate.total
            ),
        }
    }
    if !card.forbidden_model_calls.is_empty() {
        println!("\n  REGRESSION: a model fired on targets labelled trivial-deterministic:");
        for p in &card.forbidden_model_calls {
            println!("    {p}");
        }
    }
    for (heading, list) in [
        ("labelled but not reported on", &card.missing),
        ("reported but not labelled", &card.unlabelled),
    ] {
        if !list.is_empty() {
            println!("\n  {heading}:");
            for p in list {
                println!("    {p}");
            }
        }
    }
    let mut regressed = false;
    if let Some(path) = baseline {
        let (before, _) = read_results(path)?;
        let f = trigon_ai::flips(&before, &observed);
        regressed = !f.broken.is_empty();
        println!("\nagainst {}:", path.display());

        // Named, never counted. "Two regressions" is a number to argue with; a list of package
        // URLs is a list of things to go and look at.
        let sections: [(&str, &[String]); 5] = [
            ("now reproduces", &f.fixed),
            ("NO LONGER REPRODUCES", &f.broken),
            ("stopped producing evidence (ours, not the rule's)", &f.lost_evidence),
            ("now produces evidence", &f.gained_evidence),
            ("in this run and not the baseline", &f.added),
        ];
        let mut said = false;
        for (heading, list) in sections {
            if list.is_empty() {
                continue;
            }
            said = true;
            println!("  {} {heading}:", list.len());
            for p in list {
                println!("    {p}");
            }
        }
        if !f.changed.is_empty() {
            said = true;
            println!("  {} reproduce differently:", f.changed.len());
            for c in &f.changed {
                println!("    {} {} -> {}", c.purl, c.from, c.to);
            }
        }
        if !f.dropped.is_empty() {
            said = true;
            // A corpus that quietly shrank is how a rate improves without anything improving.
            println!("  {} in the baseline and not this run:", f.dropped.len());
            for p in &f.dropped {
                println!("    {p}");
            }
        }
        if !said {
            println!("  nothing changed");
        }
        println!(
            "\n  {}",
            if f.is_net_gain() {
                "a net gain: something was fixed and nothing regressed"
            } else if regressed {
                "NOT a net gain: something that reproduced no longer does"
            } else {
                "not a gain: nothing was fixed"
            }
        );
    }

    if !card.acceptable() || (fail_on_regression && regressed) {
        std::process::exit(1);
    }
    Ok(())
}

/// Say what stabilizer set a statement was made under, from a published manifest.
///
/// Printed on a set mismatch, which is otherwise a dead end: the verifier is told two digests
/// disagree and has no way to learn what the first one was. Not gated behind `build` — the
/// minimal verifier is exactly who hits this, and it needs no runtime to read a JSON file.
fn describe_set(st: &trigon_attest::Statement, from: Option<&Path>) {
    let want = st.predicate["stabilizerSet"]["digest"]["sha256"]
        .as_str()
        .unwrap_or_default();
    let Some(path) = from else {
        eprintln!(
            "\nThe set this claim was made under is `{}@{}`. Pass --stabilizers with its published \
             manifest (stabilizers/sha256/{want}.json) to see what it contained.",
            st.predicate["stabilizerSet"]["id"].as_str().unwrap_or("?"),
            &want[..12.min(want.len())],
        );
        return;
    };
    let text = match std::fs::read(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("\ncould not read {}: {e}", path.display());
            return;
        }
    };
    let m: trigon_stabilize::SetManifest = match serde_json::from_slice(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("\n{} is not a stabilizer set manifest: {e}", path.display());
            return;
        }
    };
    // Both checks, for the same reason the store does them: a self-consistent manifest for some
    // other set is a correct document and the wrong answer.
    if !m.self_consistent() {
        eprintln!("\nthat manifest does not recompute the digest it claims; ignoring it");
        return;
    }
    if m.digest != want {
        eprintln!(
            "\nthat manifest describes set {} and the claim was made under {want}",
            m.digest
        );
        return;
    }
    eprintln!("\nthe claim was made under `{}`, which contained:", m.id);
    for member in &m.members {
        eprintln!(
            "  {:<26} {:<11} {}",
            member.id, member.risk, member.provenance
        );
    }
}

fn verify_attestation(
    bundle: &Path,
    rerun: bool,
    upstream: Option<&Path>,
    rebuild: Option<&Path>,
    stabilizers: Option<&Path>,
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
        // A `.wasm` module is run; anything else is read as a manifest and described. Chosen by
        // extension rather than by sniffing, because the two failure modes differ: a module we
        // cannot run should say so, and a manifest we cannot parse should say that instead.
        #[cfg(feature = "wasm")]
        let mut archived = match stabilizers {
            Some(p) if p.extension().is_some_and(|e| e == "wasm") => Some(
                trigon_stabilize_wasm::ArchivedSet::load(p)
                    .with_context(|| format!("loading {}", p.display()))?,
            ),
            _ => None,
        };
        #[cfg(feature = "wasm")]
        let outcome = match archived.as_mut() {
            Some(a) => trigon_attest::rederive_with(&st, ub, rb, Some(a)),
            None => trigon_attest::rederive(&st, ub, rb),
        };
        #[cfg(not(feature = "wasm"))]
        let outcome = {
            if stabilizers.is_some_and(|p| p.extension().is_some_and(|e| e == "wasm")) {
                bail!(
                    "this build cannot run a stabilizer module. Rebuild with `--features wasm`, or \
                     pass the set's `.json` manifest to see what it contained."
                );
            }
            trigon_attest::rederive(&st, ub, rb)
        };
        match outcome {
            Ok(d) => Some(d),
            // The one error worth turning into a description rather than a refusal. A verifier who
            // cannot reach the statement's set is not looking at a broken attestation; they are
            // looking at one made under a set their binary does not carry, and saying which
            // stabilizers those were is most of what they need.
            Err(e @ trigon_attest::AttestError::SetMismatch { .. }) => {
                describe_set(&st, stabilizers);
                return Err(e.into());
            }
            Err(e) => return Err(e.into()),
        }
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

// ---------------------------------------------------------------------------
// The attestor.
//
// A separate process on purpose, and the separation is the security control rather than a tidiness
// preference (`docs/09-attestations.md` §6). The sandbox executes attacker-supplied build scripts
// and writes blobs; this reads those blobs **by hash**, checks each against the hash it asked for,
// re-derives the equivalence claim from the bytes, and only then signs. It runs no build, opens no
// socket, and holds the only thing worth stealing — the key.
//
// Which is why it re-derives rather than believing the run record. The record was written by the
// process that ran the build. If that process were compromised it could record any outcome it
// liked, and an attestor that signed what it was told would launder that into a signature.

#[cfg(feature = "build")]
mod attestor {
    use anyhow::{Context, Result, bail};
    use std::path::Path;
    use trigon_attest::{RunFacts, Statement};
    use trigon_store::{RunRecord, Store};

    pub struct Args {
        pub store: std::path::PathBuf,
        pub run: Option<String>,
        pub key: Option<std::path::PathBuf>,
        pub prune: bool,
    }

    pub fn run(args: Args) -> Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let store = Store::local(&args.store)?;
            let id = match args.run {
                Some(id) => id,
                None => store
                    .list_runs()
                    .await?
                    .into_iter()
                    .next()
                    .context("this store holds no runs")?,
            };
            let mut record = store.get_run(&id).await?;
            println!("run       {id}");
            println!("target    {}", record.target);

            // Before anything else. A run whose artifact reached the build over the network is
            // evidence of nothing, and the one thing we must never do is sign a statement saying
            // otherwise — that is the forged-attestation attack, arriving exactly as designed.
            if !record.guard_trips.is_empty() {
                println!("\nvoid: {}", record.guard_trips.join("; "));
                bail!(
                    "refusing to attest a void run: the artifact under test reached the build over \
                     the network, so a match proves only that the build downloaded it"
                );
            }

            let signer: Box<dyn trigon_attest::Signer> = match &args.key {
                Some(p) => Box::new(crate::load_key(p)?),
                None => Box::new(trigon_attest::Unsigned),
            };

            let mut written = Vec::new();
            let mut published_set: Option<String> = None;

            // 1. The equivalence (or divergence) claim, re-derived from the bytes.
            if let Some(comparison_digest) = record.comparison {
                let bytes = store.blobs().get(&comparison_digest).await?;
                let comparison: trigon_compare::Comparison = serde_json::from_slice(&bytes)?;

                let rebuilt = record
                    .rebuild
                    .as_ref()
                    .context("a run with a comparison must name a rebuilt artifact")?;
                if !record.upstream.stored || !rebuilt.stored {
                    bail!(
                        "the artifacts for this run are no longer in the store, so the claim \
                         cannot be re-derived. It was pruned after being attested; the existing \
                         statement is still checkable by anyone holding the two files."
                    );
                }

                // Fetched by hash and checked against it. The attestor trusts the digest, never the
                // process that wrote the bytes.
                let upstream = store.blobs().get(&record.upstream.sha256).await?;
                let rebuild = store.blobs().get(&rebuilt.sha256).await?;

                // The record and the evidence it points at must agree. Re-derivation already
                // catches a forged *comparison*, because it recomputes from the artifact bytes —
                // but the record is a separate document, and a worker that wrote an honest
                // comparison beside a record claiming something better would otherwise have that
                // claim survive into `trigon runs` and anything reading it.
                if record.outcome.as_deref() != Some(comparison.outcome.to_string().as_str()) {
                    bail!(
                        "the run record says `{}` and the comparison it points at says `{}`. \
                         Refusing to attest a run that disagrees with its own evidence.",
                        record.outcome.as_deref().unwrap_or("nothing"),
                        comparison.outcome
                    );
                }

                // Publish the set this claim was made under, addressed by its own digest. A
                // verifier whose binary carries a different set gets `SetMismatch` and, without
                // this, nothing else — a digest that matches nothing they have. It does not let
                // them run the old set, but it says exactly what the claim was made under.
                let set_id = comparison.upstream.set.0.as_str();
                if let Some(set) = trigon_stabilize::profile(set_id) {
                    match store.put_stabilizer_set(&set.manifest()).await {
                        Ok(p) => published_set = Some(p),
                        Err(e) => tracing::warn!("could not publish the stabilizer set: {e}"),
                    }
                }

                let statement = Statement::equivalence(&record.upstream.name, &comparison);
                let checked = trigon_attest::rederive(&statement, upstream.into(), rebuild.into())
                    .context("re-deriving the claim before signing it")?;
                if !checked.holds() {
                    bail!(
                        "refusing to sign: the run recorded `{}` and the bytes give `{}`",
                        checked.claimed,
                        checked.actual
                    );
                }
                println!(
                    "rederived {} under {} — signing",
                    checked.actual, checked.stabilizer_set
                );

                let env = trigon_attest::sign_statement(&statement, signer.as_ref())?;
                let target = record.target.parse::<trigon_core::TargetRef>()?;
                let target = trigon_core::Target::new(
                    target,
                    trigon_core::ArtifactId::new(record.upstream.name.clone()),
                );
                written.push(
                    store
                        .put_attestation(
                            &target,
                            &record.upstream.name,
                            &statement.predicate_type,
                            &env,
                        )
                        .await?,
                );
            }

            // 2. How the rebuild came to exist, and what the build was observed to do.
            let facts = facts(&record);
            if let Some(rebuilt) = &record.rebuild {
                let st = Statement::rebuild(&rebuilt.name, &rebuilt.sha256, &facts);
                written.push(put(&store, &record, &st, signer.as_ref()).await?);
            }
            let obs = Statement::build_observation(
                &record.upstream.name,
                &record.upstream.sha256,
                &facts,
            );
            written.push(put(&store, &record, &obs, signer.as_ref()).await?);

            record.attestations = written.clone();
            store.put_run(&record).await?;

            println!();
            for p in &written {
                println!("  {p}");
            }
            if let Some(p) = &published_set {
                println!("  {p}");
            }
            if !signer.key_id().is_empty() {
                println!("\nsigned with key {}", signer.key_id());
            } else {
                println!(
                    "\nunsigned — the claims are complete and checkable, but nothing here says who \
                     made them"
                );
            }

            if args.prune {
                match store.prune_rebuild(&id).await {
                    Ok(true) => println!("pruned the rebuilt artifact; its digests remain"),
                    Ok(false) => {
                        println!("kept the rebuilt artifact: a divergence needs its bytes")
                    }
                    Err(e) => println!("did not prune: {e}"),
                }
            }
            Ok(())
        })
    }

    async fn put(
        store: &Store,
        record: &RunRecord,
        st: &Statement,
        signer: &dyn trigon_attest::Signer,
    ) -> Result<String> {
        let env = trigon_attest::sign_statement(st, signer)?;
        let reference = record.target.parse::<trigon_core::TargetRef>()?;
        let target = trigon_core::Target::new(
            reference,
            trigon_core::ArtifactId::new(record.upstream.name.clone()),
        );
        Ok(store
            .put_attestation(&target, &record.upstream.name, &st.predicate_type, &env)
            .await?)
    }

    fn facts(r: &RunRecord) -> RunFacts<'_> {
        RunFacts {
            run_id: &r.id,
            started: &r.started,
            finished: r.finished.as_deref(),
            base_image: &r.environment.base_image,
            egress: &r.environment.egress,
            isolation: &r.environment.isolation,
            attestable: r.environment.attestable,
            registry_moment: r.environment.registry_moment.as_deref(),
            pin_observed: r
                .environment
                .pin
                .map(|p| (p.index_requests, p.versions_withheld)),
            strategy_digest: r.strategy_digest.as_deref(),
            derivation: r.derivation.as_deref(),
            instructions: None,
            build_log: None,
            trigon_version: env!("CARGO_PKG_VERSION"),
            stabilizer_set: None,
            guard_trips: &r.guard_trips,
            guard_manifest: None,
            guarded_members: None,
        }
    }

    /// List what a store holds.
    pub fn list(store: &Path) -> Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let store = Store::local(store)?;
            let ids = store.list_runs().await?;
            if ids.is_empty() {
                println!("no runs");
                return Ok(());
            }
            for id in ids {
                let r = store.get_run(&id).await?;
                println!(
                    "{id}  {:<34} {:<24} {}",
                    r.target,
                    r.outcome.as_deref().unwrap_or(match r.guard_trips.len() {
                        0 => "-",
                        _ => "void",
                    }),
                    if r.attestations.is_empty() {
                        "unattested"
                    } else {
                        "attested"
                    }
                );
            }
            Ok(())
        })
    }
}
