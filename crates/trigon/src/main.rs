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
    /// Build a base image carrying the system packages an enforced tier cannot install.
    ///
    /// At `mirror-only` and `deny-all` the image build has no network, so nothing can `apt-get`.
    /// That is what makes those tiers mean what they say, and it means the packages have to be in
    /// the image already. This builds one.
    #[cfg(feature = "build")]
    BaseImage {
        /// The image to build on, pinned by digest.
        #[arg(long)]
        from: String,
        /// Packages to install. Defaults to the union every builtin tool asks for, which is what
        /// the npm and PyPI corpora between them need.
        #[arg(long)]
        packages: Vec<String>,
        #[arg(long, default_value = "localhost/trigon-base:latest")]
        tag: String,
        /// Print the Containerfile instead of building it.
        #[arg(long)]
        print: bool,
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
        /// Targets to build at once. Defaults to 1, which is what a sweep did before this existed.
        ///
        /// Bounded by memory, not by cores: every target in flight holds a build container and a
        /// mirror container, and running out means the OOM killer takes a build — which reads as a
        /// broken package rather than as a machine that was too small.
        #[arg(long, default_value_t = 1)]
        concurrency: usize,
        #[arg(long)]
        source_cache: Option<PathBuf>,
    },
    /// Watch a sweep's work directory, from a browser, while it runs.
    ///
    /// Read-only, and it never talks to the sweep: it reads the files the sweep already writes, so
    /// it survives the sweep's death. That is the point — every completed result stays on the page,
    /// the silence is labelled with its age, and the target that was in flight is reported as
    /// unknown rather than converted into a failure.
    ///
    /// Not `serve`, which `docs/11-interfaces.md` reserves for an API, a UI and workers together.
    #[cfg(feature = "build")]
    Watch {
        /// A sweep's `--work` directory.
        work: PathBuf,
        /// The targets file that sweep was given.
        ///
        /// Without it the page has no denominator — it can say how many targets were attempted and
        /// not how many there are — and it says so rather than guessing. It is also what names the
        /// per-target directories, so without it a resumed sweep's rows may link to the wrong one.
        #[arg(long)]
        targets: Option<PathBuf>,
        /// Loopback by default. A work directory holds artifacts fetched from registries and build
        /// logs that may carry credentials from a build environment.
        #[arg(long, default_value = "127.0.0.1:8099")]
        bind: String,
        /// A store the sweep was given, to enrich a compared run with its digest chain.
        ///
        /// Only an enrichment: the store records a run only past a comparison, so a page rooted in
        /// it would report a perfect rate on a sweep where nothing built.
        #[arg(long)]
        store: Option<PathBuf>,
        /// An earlier sweep of the same corpus, to say what changed.
        #[arg(long)]
        baseline: Option<PathBuf>,
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

// Shared with `build.rs` through `include!`, so the digest the mirror image is labelled with and
// the digest the staleness check compares come from one function rather than two.
#[cfg(feature = "build")]
include!("mirror_source.rs");

#[cfg(feature = "build")]
mod inferrer;

/// Where a strategy should be told the mirror is, as `host:port`.
///
/// The name is stable so the port stays out of the strategy digest; the port is whatever this run's
/// mirror is actually listening on.
///
/// **`enforced` alone, not `enforced && --timewarp`.** At an enforced tier the island mirror exists
/// whether or not a registry moment was asked for — it is the build's only route out, so every URL
/// a strategy renders has to reach it. This used to require `--timewarp` as well, and without it
/// the host fell through to `run_with`'s bare `timewarp` default: every toolchain download at
/// `mirror-only` died on `Connection refused`, because the mirror was there, listening on 8129, and
/// the rendered URL said port 80. Two ways to know where the mirror is, disagreeing, with nothing
/// asserting they agreed.
#[cfg(feature = "build")]
fn timewarp_host_for(
    enforced: bool,
    mirror_port: Option<u16>,
    requested: Option<&str>,
) -> Option<String> {
    if enforced {
        // Fixed, because it is inside the island and collides with nothing there. Matches
        // `RunOpts::mirror_port`.
        return Some("timewarp:8129".to_string());
    }
    mirror_port
        .map(|p| format!("timewarp:{p}"))
        .or_else(|| requested.filter(|t| *t != "auto").map(str::to_string))
}

#[cfg(all(test, feature = "build"))]
mod timewarp_host_tests {
    #[test]
    fn an_enforced_tier_always_names_the_islands_port() {
        // The bug: this used to require `--timewarp` as well, so a plain `--egress mirror-only`
        // rendered `http://timewarp/-toolchain/...` — port 80, against a mirror on 8129 — and
        // every build that downloads a toolchain died on `Connection refused` after the image was
        // already built.
        for requested in [None, Some("auto"), Some("elsewhere:9000")] {
            assert_eq!(
                super::timewarp_host_for(true, None, requested).as_deref(),
                Some("timewarp:8129"),
                "requested={requested:?}"
            );
        }
    }

    #[test]
    fn an_unenforced_tier_names_the_host_mirrors_actual_port() {
        // Whatever was free on this machine, so it cannot be a constant — and the name stays
        // stable so the port never reaches the strategy digest.
        assert_eq!(
            super::timewarp_host_for(false, Some(41234), Some("auto")).as_deref(),
            Some("timewarp:41234")
        );
    }

    #[test]
    fn with_no_mirror_at_all_only_an_explicit_host_is_used() {
        assert_eq!(super::timewarp_host_for(false, None, None), None);
        assert_eq!(super::timewarp_host_for(false, None, Some("auto")), None);
        assert_eq!(
            super::timewarp_host_for(false, None, Some("elsewhere:9000")).as_deref(),
            Some("elsewhere:9000")
        );
    }
}

/// The guard trips that void this run, given what the build produced.
///
/// The host-mirror counterpart of the same decision the island makes in `trigon-sandbox`, and it
/// calls the same two functions to make it: a member that arrived and is not in the rebuilt
/// artifact came in without coming out, which is not the harm the guard exists to catch.
#[cfg(feature = "build")]
fn voiding_trips(
    mirror: &trigon_mirror::MirrorHandle,
    produced: Option<&Path>,
) -> Vec<trigon_mirror::Trip> {
    let rebuilt = produced.and_then(trigon_mirror::member_digests_at);
    trigon_mirror::voiding(&mirror.arrived(), rebuilt.as_ref())
}

/// The current instant, as RFC 3339 UTC.
///
/// Hand-rolled rather than pulling in a date library for one format. UTC only, and seconds
/// precision, which is all a run record needs.
///
/// Gated because every caller is: a run record is written by `rebuild` and by `sweep`, and the
/// verifier build has neither. Without the gate the verifier compiles it and CI fails on
/// `-D warnings` — which it was doing, silently, because the dependency-policy check builds the
/// verifier without `RUSTFLAGS` and so agreed the build was fine.
#[cfg(feature = "build")]
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

#[cfg(feature = "build")]
mod progress;
#[cfg(feature = "build")]
mod watch;

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
        })
        // `AttestError` classifies every variant deliberately and this never asked, so a signing or
        // re-derivation failure exited with its message alone while the error itself knew whose
        // fault it was. A fault nobody reads is a comment.
        .or_else(|| {
            e.downcast_ref::<trigon_attest::AttestError>()
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
        })
        .or_else(|| {
            e.downcast_ref::<trigon_store::StoreError>()
                .map(|e| e.fault())
        })
        .or_else(|| {
            e.downcast_ref::<trigon_mirror::MirrorError>()
                .map(|e| e.fault())
        })
        .or_else(|| e.downcast_ref::<trigon_ai::LlmError>().map(|e| e.fault()));
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
        })
        .or_else(|| {
            e.downcast_ref::<trigon_attest::AttestError>()
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
        })
        .or_else(|| {
            e.downcast_ref::<trigon_store::StoreError>()
                .map(Classify::is_retryable)
        })
        .or_else(|| {
            e.downcast_ref::<trigon_mirror::MirrorError>()
                .map(Classify::is_retryable)
        })
        .or_else(|| {
            e.downcast_ref::<trigon_ai::LlmError>()
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
            // One target on a terminal: the phases are already in front of whoever asked.
            phases: None,
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
            concurrency,
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
            concurrency,
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
        Cmd::Watch {
            work,
            targets,
            bind,
            store,
            baseline,
        } => watch::serve(work, targets, bind, store, baseline),
        #[cfg(feature = "build")]
        Cmd::Runs { store } => attestor::list(&store),
        #[cfg(feature = "build")]
        Cmd::BaseImage {
            from,
            packages,
            tag,
            print,
        } => mirror::base_image(&from, &packages, &tag, print),
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
            None,
            None,
        )
        .map(|_| ()),
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
        let client = Client::new(ClientConfig::default())?;
        let registry = for_ecosystem(target.ecosystem, client.clone())?;
        let rt = runtime()?;

        let resolved = rt.block_on(registry.resolve(&target))?;

        // The registry did not record a commit, which is every PyPI project. A tag named for the
        // version usually exists and is what a rebuild will use, so `resolve` asks the same
        // question rather than reporting a dead end the next command silently answers.
        let tag = match &resolved.source {
            Some(s) if s.commit.is_empty() => rt.block_on(trigon_registry::resolve_version_tag(
                &s.repo_url,
                &target.version,
                &target.name,
            )),
            _ => None,
        };

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
                        match &tag {
                            Some((sha, name, how)) => {
                                println!("  tag        {name} -> {sha}");
                                println!(
                                    "  found by   {:?}, which is what a rebuild would use",
                                    how
                                );
                                // The caveat is the point. A tag is a mutable reference: it can be
                                // moved or deleted after a release, and `pad-left 2.1.0` in the
                                // corpus is a package whose recorded commit was force-pushed away.
                                // What a tag gives is a good approximation, and a divergence
                                // against one has to be read against that.
                                println!(
                                    "             a tag is mutable — it can be moved after the \
                                     release, so this identifies the commit the tag points at \
                                     today rather than the one that was published"
                                );
                            }
                            None => println!(
                                "  found by   {:?}: no tag matches this version, so something \
                                 stronger has to find the commit",
                                s.how
                            ),
                        }
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

    /// What a build left behind that only the runner could know.
    ///
    /// Returned rather than printed. The two observability facts about a run — whether its egress
    /// is completely accounted for, and what crossed — were computed inside the sandbox and dropped
    /// on the floor, so the record was filled in from a *freshly constructed, mirror-less* runner's
    /// advertised capabilities. That is a different object than the one that ran, and it answered a
    /// different question.
    pub struct Built {
        /// Exactly `transcript.is_some()`; see [`trigon_sandbox::BuildOutcome::attestable`].
        pub attestable: bool,
        /// The complete account of what crossed into the build, or `None` when none exists. An
        /// empty `Some` means nothing crossed and must never be flattened into `None`.
        pub transcript: Option<Vec<trigon_mirror::Exchange>>,
        /// What the mirror inside the island served and refused, as the registry-pin counters.
        ///
        /// `None` where no mirror ran. This is the whole of `docs/17-backlog.md` B7b: the counters
        /// live on the `Mirror` object, which under an enforced tier sits inside the build's
        /// network island where the host cannot reach it — so the check that caught the
        /// `PIP_TRUSTED_HOST` finding was blank on exactly the tier that recommends itself, and
        /// present at `open`, where a build can ignore the mirror entirely.
        pub pin: Option<trigon_mirror::Observed>,
        /// Times the build asked for its own published artifact and was refused. Not a void —
        /// nothing arrived — but usually the explanation for whatever failed next, and a sweep
        /// without `--store` has only `run.json` to find it in.
        pub refused_artifact: Vec<String>,
        /// Guarded members that arrived over the network and are **not** in the rebuilt artifact.
        ///
        /// The bytes came in and did not come out, which is not the harm the guard exists to catch
        /// — so the run stands. Carried anyway, and for the same reason as `refused_artifact`: a
        /// control whose near-misses are invisible cannot be told from one that never fires.
        pub guard_notes: Vec<String>,
        /// Where the runner collected the rebuilt artifact, when it collected exactly one.
        ///
        /// The runner knows this — it mounted the directory the build wrote into — and the caller
        /// was rediscovering it by walking the *parent* for the newest file. That guess had to
        /// keep agreeing with every file this process writes beside the artifact, and it stopped:
        /// adding `network.jsonl` there was enough to make a run judge its own network transcript
        /// as the thing it had just built.
        pub artifact: Option<std::path::PathBuf>,
    }

    /// Files this process writes into a run's output directory.
    ///
    /// One list, declared where they are written, because [`crate::rebuild::newest_file`] walks
    /// that directory looking for the rebuilt artifact and has no other way to tell our bytes from
    /// the build's. It is a backstop and not the mechanism — `Built::artifact` is — but a backstop
    /// spread across two files is the shape of bug this whole project keeps finding.
    pub const OURS: &[&str] = &["build.log", "network.jsonl"];

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
        source: Option<&Path>,
        // Told as each phase starts, for anything watching this run from outside the process.
        on_event: Option<trigon_sandbox::EventSink>,
        source_cache: Option<&Path>,
    ) -> Result<Built> {
        let egress = egress_tier(egress)?;

        // At an enforced tier the image build has no network, so the source cannot be cloned
        // there. It is fetched here instead, on the host, and copied into the image — which is what
        // lets the boundary hold for every phase rather than only for the build.
        //
        // At `open`, nothing: no host clone, no copy, and the in-container `git clone` runs exactly
        // as it always has. That matters because `open` is what `rebuild` and `sweep` default to,
        // so every published rate keeps coming from a code path this does not touch.
        // Why the host checkout failed, kept so the *build's* failure can be attributed to it.
        // Only read when the build dies in the source phase, which is the only phase it explains.
        let mut checkout_failure: Option<trigon_core::FailureSignature> = None;
        let source_tree = match (egress, source) {
            (trigon_sandbox::EgressTier::Open, _) => None,
            // An operator-named checkout is used as it stands. It is now a build input rather than
            // only a hint that narrows the guard, which is a change in what `--source` means.
            (_, Some(p)) => Some(p.to_path_buf()),
            // **Still best effort, and the reason is kept.** A strategy whose source phase
            // generates its own tree — or clones nothing at all — has nothing to fetch, and
            // failing here would refuse it for a repository it never intended to use. The e2e
            // strategy in `tests/cli.rs` is exactly that shape and caught a version of this that
            // did fail.
            //
            // What was wrong was not the fallback, it was the silence. When the source phase
            // *does* need the clone, the fallback is the in-container `git clone`, which at an
            // enforced tier has no route to a forge — so the run dies a minute later on a DNS
            // error about a host it was never going to reach, and files under `net/unreachable`
            // beside genuine hidden-network-dependency findings. `pad-left`'s real cause is that
            // npm's recorded `gitHead` names a commit GitHub refuses to serve, and that sentence
            // existed only at `debug`. So the reason is carried to the failure instead.
            (_, None) => match crate::strategy_location(file, import) {
                Err(e) => {
                    tracing::debug!("the strategy names no source location: {e:#}");
                    None
                }
                Ok((_, loc)) => match (|| {
                    let cache = trigon_registry::SourceCache::new(
                        source_cache
                            .map(Path::to_path_buf)
                            .unwrap_or_else(trigon_registry::SourceCache::default_root),
                    );
                    let checkout = cache.checkout(&loc.repo, &loc.git_ref)?;
                    // Said out loud, because the alternative is a divergence about how we cloned.
                    // `hatch-vcs`, `setuptools-scm` and their siblings take the package version from
                    // `git describe`, so a commit no tag names builds as `0.1.dev1+g<sha>` — a wheel
                    // whose every `dist-info` member is named wrong while its code is byte-identical.
                    // Most commits are not releases, so this is a note rather than a refusal; what it
                    // must not be is silent.
                    if checkout.tags.is_empty() {
                        tracing::warn!(
                            commit = %loc.git_ref,
                            "no tag names this commit, so a build that derives its version from \
                             `git describe` will produce a development version rather than the \
                             release. Every difference that follows is about the checkout rather than \
                             about the package."
                        );
                    }
                    Ok::<_, trigon_registry::RegistryError>(checkout.path)
                })() {
                    Ok(p) => Some(p),
                    Err(e) => {
                        let detail = format!("{e:#}");
                        tracing::warn!(
                            repo = %loc.repo,
                            commit = %loc.git_ref,
                            "no host checkout. If the source phase clones, it will fail at this \
                             egress tier with a network error about a host it was never going to \
                             reach — this is the reason underneath it: {detail}"
                        );
                        checkout_failure = Some(trigon_core::classify(&detail));
                        None
                    }
                },
            },
        };

        // With the tree in hand the checkout step has nothing to fetch, so the strategy renders
        // with `has_repo` set and `git-checkout` collapses to the `git checkout --force <sha>` that
        // verifies the copy landed on the commit the strategy names. The strategy digest is
        // unchanged by this: `has_repo` drops a line from the rendered script and is not part of
        // what is hashed.
        let (instructions, digest, _custom) =
            crate::render_strategy(file, import, timewarp_host, source_tree.is_some())?;

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

        // Before anything is built. A plan whose build phase renders empty produces nothing and
        // ends as "the build succeeded and left no artifact", which blames the run rather than the
        // recipe.
        instructions.executable()?;

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
            source_tree,
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
                on_event,
                // Read from the environment rather than given a flag, because the caller that needs
                // it is not a person: it is the clean-re-run path of `docs/09-attestations.md` §5,
                // which does not exist yet, and the test that proves two builds normalize. A flag
                // nobody is meant to type is a flag that gets typed.
                no_cache: std::env::var_os("TRIGON_NO_BUILD_CACHE").is_some(),
            };
            let handle = runner.start(&plan, &opts).await?;
            let outcome = handle.wait().await?;

            // Written before anything is reported, so a run that goes on to fail still leaves the
            // account of what it fetched. `create_dir_all` first for the same reason the log does
            // it: a build that died during the *image* build never reached the point where the
            // output directory was made, and those are the runs whose evidence nobody can
            // otherwise see.
            //
            // One JSON object per line, the same shape `RunRecord::network_transcript` stores, so
            // what a person reads here and what a verifier reads out of the store are the same
            // bytes rather than two renderings that have to agree.
            let transcript_path = outcome.transcript.as_ref().and_then(|t| {
                let path = out.join("network.jsonl");
                let mut buf = Vec::new();
                for e in t {
                    match serde_json::to_vec(e) {
                        Ok(line) => {
                            buf.extend_from_slice(&line);
                            buf.push(b'\n');
                        }
                        Err(e) => tracing::warn!("could not write a transcript line: {e}"),
                    }
                }
                match std::fs::create_dir_all(out).and_then(|()| std::fs::write(&path, &buf)) {
                    Ok(()) => Some(path),
                    Err(e) => {
                        tracing::warn!("could not write {}: {e}", path.display());
                        None
                    }
                }
            });

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
                match &outcome.transcript {
                    // The count, and what it was made of. A bare "network  12 responses" hides the
                    // one number worth seeing: whether the guard opened them or only weighed them,
                    // which is the difference between the member check having run and not.
                    Some(t) => {
                        let opened = t
                            .iter()
                            .filter(|e| e.checked == trigon_mirror::Checked::Opened)
                            .count();
                        println!(
                            "  network   {} response{} crossed into the build, {opened} opened \
                             and checked",
                            t.len(),
                            if t.len() == 1 { "" } else { "s" },
                        );
                        // Said out loud, because it is the one row a reader should not have to go
                        // looking for: a body the build hung up on is bytes that crossed and could
                        // not be checked, and a build that does it repeatedly is doing something
                        // worth asking about.
                        let partial = t
                            .iter()
                            .filter(|e| e.checked == trigon_mirror::Checked::Partial)
                            .count();
                        if partial > 0 {
                            println!(
                                "            {partial} of them were abandoned part-way, so their \
                                 bytes crossed unchecked"
                            );
                        }
                        if let Some(p) = &transcript_path {
                            println!("            {}", p.display());
                        }
                    }
                    // Two reasons, and naming the wrong one sends the reader to the wrong fix.
                    // The first draft of this had one reason and told a `mirror-only` run that it
                    // "enforced no egress boundary" — which is what `docs/16-findings.md` §3.6
                    // records happening the last time this message was written from one variable
                    // instead of two.
                    None => {
                        let why = match outcome.egress {
                            trigon_sandbox::EgressTier::Open => {
                                "this run enforced no egress boundary, so there was nothing to \
                                 account for. Use `--egress mirror-only` or `deny-all`."
                            }
                            _ => {
                                "the tier was enforced, but the build ended before the mirror's \
                                 record of it could be read — so what crossed is unknown rather \
                                 than nothing."
                            }
                        };
                        println!("\n  not attestable: {why}");
                    }
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
            // Said whatever else happened, because it usually explains the failure below it.
            // **Not a void**: the mirror turned the request away, so the artifact never arrived and
            // the thing a void describes did not happen. Some packages are part of the machinery
            // that builds packages — `python -m build` needs `packaging` and `pyproject-hooks` —
            // so rebuilding one makes the build ask for it.
            for r in &outcome.refused_artifact {
                let url = r.rsplit(' ').next().unwrap_or(r);
                tracing::warn!(
                    url = %url,
                    "the build asked for its own published artifact and was refused. Nothing \
                     arrived, so this run is not void — but a build that needed it and could not \
                     have it will have failed for that reason."
                );
            }
            // Asked again here, against the artifact *this* function can find. The runner decided
            // with the single file at the output path; where it found none, the walk below reaches
            // builds whose output lands in a subdirectory — and a member trip left unjudged on
            // exactly those runs is a control declining to answer on the runs it was armed for.
            //
            // Cheap, because a match on the runner's own artifact costs one parse and the two
            // agree on every ordinary build.
            let produced = outcome
                .artifact
                .clone()
                .or_else(|| crate::rebuild::newest_file(out));
            let rebuilt = produced
                .as_deref()
                .and_then(trigon_mirror::member_digests_at);
            let voiding = trigon_mirror::voiding(&outcome.guard_arrived, rebuilt.as_ref());
            // The guard fired and the run still stands, because the bytes did not come back out in
            // what the build produced. Said out loud: a control whose near-misses are invisible
            // cannot be told from one that never fires.
            let guard_notes: Vec<String> = outcome
                .guard_arrived
                .iter()
                .filter(|t| !voiding.contains(t))
                .map(|t| {
                    format!(
                        "{} — it is not in the rebuilt artifact, so the bytes came in and did not \
                         come out, and the run stands",
                        t.describe()
                    )
                })
                .collect();
            for n in &guard_notes {
                tracing::warn!("{n}");
            }
            if let Some(t) = voiding.first() {
                // Before the exit status is even considered: the artifact *arrived* and came back
                // out, so the run cannot be used whether the build succeeded or failed.
                bail!("void: {}", t.describe());
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
                // The runner's own naming, taken while its log was whole. `log_tail` is
                // compressed on overflow, so classifying it here — which is what this did — missed
                // the line that named the failure on exactly the builds chatty enough to trip the
                // threshold, and called them `unknown`. Falling back to the tail only where no rule
                // claimed a line as it streamed.
                let signature = outcome
                    .signature
                    .clone()
                    .unwrap_or_else(|| trigon_core::classify(&outcome.log_tail));
                let phase = outcome
                    .failed_in
                    .map(|p| format!("{p:?}").to_lowercase())
                    .unwrap_or_else(|| "build".into());
                // A source phase that died having been denied its checkout is explained by the
                // checkout, not by the DNS the tier refuses it. Only in `source`, and only when
                // there is actually a reason: everywhere else the build's own account is the better
                // one, and replacing it would hide a real failure behind a stale note.
                //
                // **Before the verbose block, not after.** It was after, so the terminal printed
                // `failure net/unreachable` and then returned `src/commit-not-on-the-forge` two
                // lines later — two answers to one question, the wrong one first.
                let signature = match (phase.as_str(), checkout_failure) {
                    ("source", Some(why)) => why,
                    _ => signature,
                };
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
                    phase,
                    exit_code: outcome.exit_code,
                    signature,
                }
                .into());
            }
            Ok(Built {
                attestable: outcome.attestable,
                transcript: outcome.transcript,
                pin: outcome.pin,
                refused_artifact: outcome.refused_artifact,
                guard_notes,
                artifact: outcome.artifact,
            })
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
    // `resolve_profile`, not `default_for`. The container format is not enough — a wheel and an
    // arbitrary zip are both `Format::Zip` — and this used `default_for(fmt)`, so `trigon stabilize`
    // on a `.whl` silently ran the plain zip set and skipped `pyc-header`, `wheel-metadata-eol` and
    // `wheel-record`. `trigon verify` already called `resolve_profile`, so the two commands in one
    // binary computed different stabilized digests for the same file, which is the one thing the
    // judgement half must never do.
    let base = resolve_profile(infile, prof, fmt)?;
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
        // `Format::from_str`, not a table here. There were three of these over the same strings
        // with different vocabularies, and an alias added to one was missing from the others.
        return s.parse::<Format>().map_err(|e| anyhow::anyhow!("{e}"));
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
    } else {
        // No `.nupkg` arm. It named a `nupkg` profile that `trigon-stabilize` does not have, and
        // `by_kind.and_then(profile)` swallowed the miss and fell through to the plain zip set — so
        // the table claimed a NuGet-specific normalization the system could not perform, and said
        // nothing when it did not. A `.nupkg` still gets the zip set; the difference is that it is
        // now the documented fallback rather than a silently failed lookup. `docs/17-backlog.md`
        // B8 adds the profile, and the assertion below is what will notice when it does.
        None
    };
    match by_kind {
        // Compiled-in on both sides, so a name here that the registry does not know is a
        // programming error rather than anything a user did, and it must not read as a fallback.
        Some(id) => Ok(profile(id).unwrap_or_else(|| {
            panic!(
                "the artifact-kind table names profile `{id}`, which trigon-stabilize does not \
                    have; add it to profiles.rs or remove the arm"
            )
        })),
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

    // Both parses and the comparison. The comparison's notes were missing, so
    // `ExecutableContentDiffers` — which the enum calls never benign and `is_noteworthy()` promises
    // reaches a human even on a clean match — had no way to get here.
    let notes: Vec<_> = c
        .upstream
        .notes
        .iter()
        .chain(&c.rebuild.notes)
        .chain(&c.notes)
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

/// The location a strategy names, without rendering it.
///
/// Read separately because the source has to be fetched *before* the render: the render needs to
/// know whether a checkout is in hand, and that is only knowable once it has been fetched.
#[cfg(feature = "build")]
fn strategy_location(file: &Path, import: bool) -> Result<(String, trigon_strategy::Location)> {
    let src =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let strategy = if import {
        trigon_strategy::import(&src)
            .with_context(|| format!("importing {}", file.display()))?
            .strategy
    } else {
        trigon_strategy::from_yaml(&src).with_context(|| format!("parsing {}", file.display()))?
    };
    let loc = strategy.location().cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "{} names no source location, so there is nothing to fetch for an enforced tier",
            file.display()
        )
    })?;
    Ok((src, loc))
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
            timewarp_base: timewarp.to_string(),
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
        /// Where to report which phase this target is in, when something is watching.
        ///
        /// `None` for a single `trigon rebuild`: nobody is watching one target, and the phases are
        /// on the terminal already.
        pub phases: Option<std::sync::Arc<crate::progress::Progress>>,
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
                rungs.push(Box::new(PyPiInferrer::new().with_mirror(mirror)))
            }
            // **Named, not silent.** This was `_ => {}`, and it is the seam leak
            // `docs/17-backlog.md` B8 exists to find: adding an ecosystem needs an arm here, and
            // until one is written a target of that ecosystem gets a ladder with no heuristic rung
            // and no model rung, resolves and fetches perfectly, and reports `NoStrategy` — which
            // is what a package we genuinely could not infer a recipe for also reports. "We have
            // no rung for this ecosystem" and "we tried every rung and none fitted" are different
            // answers, and only one of them is about the package.
            //
            // `for_ecosystem` in `trigon-registry` gets this right for the same situation: it
            // refuses by name and lists what is served. It also runs first, so today this arm is
            // unreachable for any ecosystem with no registry client — which is exactly why it must
            // say something rather than nothing when that stops being true.
            other => tracing::warn!(
                ecosystem = %other.purl_type(),
                "no heuristic rung is implemented for this ecosystem, so this run has only the \
                 definitions rung and whatever a model can propose. A `no-strategy` verdict here \
                 is a statement about Trigon, not about the package."
            ),
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
    /// Per-phase durations as they arrive, shared with the event sink that collects them.
    type Timings = std::sync::Arc<std::sync::Mutex<Vec<(String, Option<f64>)>>>;

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

    /// One rebuild, with a record of it written whatever happened.
    ///
    /// A thin wrapper so that "on every terminal outcome" is a property of the control flow rather
    /// than a line somebody has to remember at each of the eight places this returns. The store
    /// deliberately records only runs that reached a comparison — no statement may be written about
    /// a run that is evidence of nothing — and that is exactly why something else has to record the
    /// rest: a monitor rooted in successes reports a perfect rate on a sweep where nothing built.
    pub fn run_one(args: Args, verbose: bool) -> Result<Ran> {
        let work = args.work.clone();
        let purl = args.purl.clone();
        let mut report = crate::progress::RunReport::new(&purl);
        let out = run_inner(args, verbose, &mut report);
        match &out {
            Ok(ran) => report.outcome = Some(ran.outcome.label()),
            // Our own error, not the package's. Recorded as such rather than left absent, because
            // an absent outcome and a failure of ours read alike to anybody counting.
            Err(e) => report.error = Some(e.to_string()),
        }
        report.write(&work);
        out
    }

    fn run_inner(
        args: Args,
        verbose: bool,
        report: &mut crate::progress::RunReport,
    ) -> Result<Ran> {
        // The phases before the sandbox. The build reports its own; these are ours, and without
        // them a page watching a target sits on "not recorded" for the minute it takes to resolve
        // a package and fetch an artifact — which is indistinguishable from a hang.
        let mark = |phase: &str| {
            if let Some(p) = &args.phases {
                p.phase(phase);
            }
        };
        mark("resolve");
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
        // Told to the ladder, so a recipe builds the same *kind* of thing it will be compared
        // against. Without this the PyPI rung always built a wheel, and for a native package —
        // where `preferred()` correctly picks the sdist, because platform wheels do not reproduce
        // across machines — the run compared a wheel against an sdist and reported the upstream
        // file as malformed.
        resolved.about = Some(meta.id.clone());
        if verbose {
            println!("{}", resolved.reference);
            println!("  artifact   {}", meta.id);
        }

        mark("fetch");
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

        mark("strategy");
        // 3. A strategy, from the first rung that has one.
        //
        // **The mirror's address is claimed here and the mirror is started further down**, because
        // the guard manifest is narrowed by the source tree, the source tree is a function of the
        // strategy's location, and a strategy has to be told where the mirror will be before it can
        // be chosen. Arming a mirror before the manifest is final would have it serving under a
        // wider guard than the run settled on. The inferrers only need to *know* a mirror will
        // exist — they read it to decide whether to pin a registry moment, and make no request
        // through it — so the reservation is enough to run the ladder.
        //
        // Under `mirror-only` there is nothing to claim: the mirror runs inside the build's network
        // island, on a port that is fixed because it collides with nothing in there.
        let enforced = args.egress == "mirror-only";
        let reserved = match args.timewarp.as_deref() {
            Some("auto") if enforced => {
                println!(
                    "  mirror     inside the build's network island, which is its only route out"
                );
                None
            }
            Some("auto") => Some(rt.block_on(trigon_mirror::reserve(0))?),
            _ => None,
        };
        let timewarp_host = crate::timewarp_host_for(
            enforced,
            reserved
                .as_ref()
                .and_then(|l| l.local_addr().ok())
                .map(|a| a.port()),
            args.timewarp.as_deref(),
        );

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
            // Filled where the run reaches a comparison, from the recorder wrapped around the
            // provider. `None` here means nothing has been asked yet, not that nothing was.
            transcript: None,
            // Both overwritten below from what the runner reported. `false` and `None` until
            // then, because claiming a run is attestable — or that its egress was accounted for —
            // when we do not yet know is the one direction these must not err in.
            attestable: false,
            network_transcript: None,
            // Likewise filled at the end, from the counters the run itself kept. `None` is no
            // data, never zero: a run that asked no model and one whose counts we lost are
            // different facts, and the second read as zero understates every figure built on it.
            inference_seconds: None,
            tokens: Vec::new(),
            timings: Vec::new(),
        };

        report.model = model.as_ref().map(|m| m.describe());
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
        report.derivation = Some(candidate.derivation.to_string());
        report.confidence = Some(format!("{:?}", candidate.confidence).to_lowercase());
        report.assumptions = candidate.assumptions.clone();
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

        // The checkout the build will use, taken here so the guard manifest can be narrowed by it.
        //
        // The checkout the build will use, and the guard manifest narrowed by it.
        //
        // **One function, because the ordering is the invariant.** A file the artifact ships and
        // the repository also contains is not evidence of anything — the build is entitled to
        // produce it — and the manifest has always known how to drop those. It could not, because
        // it was built from the published bytes *before* a strategy existed and the tree is a
        // function of the strategy's location. So `packaging` and `pyproject-hooks` voided on their
        // own source files arriving inside the adjacent release, and the filter that would have
        // stopped it was tested while the ordering that reaches it was asserted by nothing.
        //
        // Returning both together is what stops that coming back: there is no longer a point in
        // this function where a manifest exists and the checkout does not.
        let (checkout, guard) = checkout_and_guard(
            &upstream_path,
            &meta.url,
            &loc,
            args.source.as_deref(),
            args.source_cache.as_deref(),
            &target,
        )?;
        if verbose {
            println!(
                "  guarding   the artifact and {} of its members ({} too small, too common, or \
                 also in the source)",
                guard.members.len(),
                guard.filtered_out
            );
        }

        // Armed now, on the address claimed before the ladder ran. Nothing has been served from it
        // yet: the reservation held the port and the manifest it serves under is the final one.
        let mirror = match reserved {
            Some(listener) => {
                let g = guard.clone();
                let handle = rt.block_on(async {
                    trigon_mirror::Mirror::new()?
                        .with_guard(g)
                        .serve_on(listener)
                        .await
                })?;
                if verbose {
                    println!("  mirror     serving the index as of the publish date");
                }
                Some(handle)
            }
            None => None,
        };

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
        // Timings come back through the same event sink the phase marks use: `PhaseEnd` already
        // carries the duration, and `None` there means no data rather than a phase of zero length,
        // which is the convention the record has to preserve.
        let timings: Timings = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // What the comparison said, when there was one to make. Carried out of the loop rather
        // than returned from inside it, because the mirror is torn down after the loop and an
        // early return would leave it running.
        let mut judged: Option<(PathBuf, trigon_compare::Comparison)> = None;
        let mut compare_error: Option<Outcome> = None;
        // What the last attempt built, carried out of the loop because the guard is read again
        // after it and asks a question only this file can answer. Uninitialized on purpose: every
        // path out of the loop runs the assignment below first, and saying so here means a future
        // early `break` fails to compile rather than silently voiding against a stale `None`.
        let mut produced: Option<PathBuf>;
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
            report.strategy_digest = strategy_digest.clone();
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
                // The checkout the guard was narrowed by, not a second one resolved inside the
                // build. Two fetches of one commit would agree today and be two things that have
                // to keep agreeing; and the tree the guard exempted files from has to be the tree
                // the build compiled, or the exemption is about a different set of bytes.
                checkout.as_deref(),
                // Phase marks from inside the sandbox, forwarded to whatever is watching, and the
                // timings on the way past. The build already recorded both and threw them away;
                // only the sink was missing.
                {
                    let (phases, timings) = (args.phases.clone(), timings.clone());
                    Some(
                        std::sync::Arc::new(move |e: &trigon_sandbox::BuildEvent| match e {
                            trigon_sandbox::BuildEvent::PhaseStart(phase) => {
                                if let Some(p) = &phases {
                                    p.phase(&phase.to_string());
                                }
                            }
                            trigon_sandbox::BuildEvent::PhaseEnd { phase, duration } => {
                                if let Ok(mut t) = timings.lock() {
                                    t.push((phase.to_string(), duration.map(|d| d.as_secs_f64())));
                                }
                            }
                            _ => {}
                        }) as trigon_sandbox::EventSink,
                    )
                },
                args.source_cache.as_deref(),
            );

            // What the build produced, taken before the guard is consulted rather than after.
            // Whether a guarded member arriving voids the run depends on whether it came back out
            // in this file, and that question cannot be asked without it.
            //
            // What the runner collected, and only then a walk of the directory. The walk is for
            // builds whose output lands in a subdirectory, which `collect` deliberately does not
            // reach; it is not a second opinion about the common case.
            produced = built
                .as_ref()
                .ok()
                .and_then(|b| b.artifact.clone())
                .or_else(|| newest_file(&out));

            // A tripped guard ends the loop whatever else happened, and before another attempt can
            // spend anything: the artifact under test reached the build, so nothing this run
            // produces is evidence about the source. The block below turns it into a `Void`.
            // `voiding`, not every trip: a refusal is the mirror turning the build away, and a
            // member that arrived and is not in the output came in without coming out.
            if mirror
                .as_ref()
                .is_some_and(|m| !voiding_trips(m, produced.as_deref()).is_empty())
            {
                break (built, strategy_digest);
            }

            let Err(e) = &built else {
                // A build that ran is not yet an answer. The comparison happens here, inside the
                // loop, because a divergence is the repair case that matters most: the recipe
                // works and builds something that is not what was published.
                let Some(rebuilt) = produced.clone() else {
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
                match repairs.next(
                    &failure,
                    &trigon_ai::NoPrior,
                    repair_started.elapsed().as_secs(),
                ) {
                    trigon_ai::Decision::Stop(reason) => {
                        if verbose {
                            println!("  repair     stopped: {}", stop_reason(&reason));
                        }
                        report.repair_stopped = Some(stop_reason(&reason));
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
                        report.repairs.push(format!(
                            "attempt {} on {}",
                            repairs.attempts().len() + 1,
                            failure.key()
                        ));
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
            report.failure = e
                .downcast_ref::<crate::BuildFailure>()
                .map(|f| f.signature.clone());
            let Some(failure) = report.failure.clone() else {
                break (built, strategy_digest);
            };
            let Some(cfg) = &model else {
                break (built, strategy_digest);
            };

            match repairs.next(
                &failure,
                &trigon_ai::NoPrior,
                repair_started.elapsed().as_secs(),
            ) {
                trigon_ai::Decision::Stop(reason) => {
                    // Said out loud. Which stop rule fired is the difference between "the budget
                    // is too small", "we have no rule for this" and "working as intended", and a
                    // run that just stops tells the operator none of them.
                    if verbose {
                        println!("  repair     stopped: {}", stop_reason(&reason));
                    }
                    report.repair_stopped = Some(stop_reason(&reason));
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
                    report.repairs.push(format!(
                        "attempt {} on {}",
                        repairs.attempts().len() + 1,
                        failure.key()
                    ));
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
        if let Ok(t) = timings.lock() {
            report.timings = t.clone();
        }
        report.egress = Some(args.egress.clone());
        report.guard_notes = built
            .as_ref()
            .map(|b| b.guard_notes.clone())
            .unwrap_or_default();
        report.refused_artifact = built
            .as_ref()
            .map(|b| b.refused_artifact.clone())
            .unwrap_or_default();
        // From the run, not from a runner constructed afterwards to be asked. `None` where the
        // build never finished, which is a third answer: an unknown is not a `false`, and a report
        // that says "not attestable" about a build that never ran sends the reader after the wrong
        // thing entirely.
        report.attestable = built.as_ref().ok().map(|b| b.attestable);
        report.network_exchanges = built
            .as_ref()
            .ok()
            .and_then(|b| b.transcript.as_ref())
            .map(Vec::len);
        report.network_bytes = built
            .as_ref()
            .ok()
            .and_then(|b| b.transcript.as_ref())
            .map(|t| t.iter().map(|e| e.bytes).sum());
        report.inference_seconds = model.as_ref().and_then(|m| m.inference_seconds());
        if calls(&model) > 0 {
            let u = model.as_ref().map(|m| m.spent()).unwrap_or_default();
            report.tokens_in = Some(u.input);
            report.tokens_out = Some(u.output);
            report.tokens_cached = Some(u.cached_input);
        }
        let derivation = if repairs.attempts().is_empty() {
            candidate.derivation.to_string()
        } else {
            // Whatever produced the first candidate, what ran is what a model last proposed. Via
            // the enum rather than a literal: the two branches spelled it differently for as long
            // as both existed.
            trigon_registry::Derivation::ModelAssisted.to_string()
        };

        // A claim of a pinned dependency graph has to be able to show the pin did something, and
        // until this check existed it could not. `PIP_INDEX_URL` without `PIP_TRUSTED_HOST` makes
        // pip warn once and then resolve against the live index, so every PyPI run recorded a
        // moment it did not have — for weeks, with this counter sitting at zero the whole time and
        // reading exactly like a build that needed nothing.
        //
        // **Two places the answer can come from, and for a while only one of them could answer.**
        // A mirror on this host is asked directly. A mirror inside the build's network island
        // cannot be: that is what the island is for, and the counters live on an object the host
        // has no route to — so the control was blank at `mirror-only`, the tier that recommends
        // itself, and present at `open`, where a build can ignore the mirror entirely. The island's
        // answer is now derived from the transcript, which does get out. See `docs/17-backlog.md`
        // B7b.
        let observed = match &mirror {
            Some(m) => Some(m.observed()),
            None => built.as_ref().ok().and_then(|b| b.pin),
        };
        if let Some(observed) = observed {
            pin = Some(observed);
            report.pin = Some(observed);
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
        }

        if let Some(m) = mirror {
            for t in m.refused() {
                tracing::warn!(
                    url = %t.url,
                    "the build asked for its own published artifact and was refused; nothing \
                     arrived, so this is not a void"
                );
            }
            let trips = voiding_trips(&m, produced.as_deref());
            for t in m.arrived().iter().filter(|t| !trips.contains(t)) {
                tracing::warn!(
                    "{} — it is not in the rebuilt artifact, so the bytes came in and did not \
                     come out, and the run stands",
                    t.describe()
                );
            }
            rt.block_on(m.shutdown());
            if let Some(t) = trips.first() {
                // Checked before the build's exit status is even considered. A tripped guard means
                // the run cannot be used, whether the build succeeded or failed.
                let reason = t.describe();
                report.void_reason = Some(reason.clone());
                return Ok(Ran {
                    outcome: Outcome::Void { reason },
                    model_calls: calls(&model),
                });
            }
        }
        if let Err(e) = built {
            let text = e.to_string();
            if let Some(reason) = text.strip_prefix("void: ") {
                report.void_reason = Some(reason.to_string());
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

        mark("judge");
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
                // From the run itself. This used to build a *fresh* `PodmanRunner` — with no
                // mirror image, so not the runner that ran anything — and read its advertised
                // capability, which answered "could some run on this runner be attested" and was
                // recorded as though it answered "was this one". Deriving it from `--egress`
                // instead was worse still: that stamped `attestable: true` on runs whose
                // image-build phases were outside the boundary entirely.
                attestable: built.as_ref().is_ok_and(|b| b.attestable),
                network_transcript: built.as_ref().ok().and_then(|b| b.transcript.clone()),
                // What the run's own counters say, not what a budget allowed. `docs/03` §3 puts
                // costs beside the timings for one reason: the number that decides where money
                // goes is dollars per *verdict gained*, and a denominator nobody records is a
                // denominator nobody can divide by.
                inference_seconds: model.as_ref().and_then(|m| m.inference_seconds()),
                tokens: match &model {
                    // One entry, because one model is configured per run. A vector rather than an
                    // option because adding counts across models with different prices produces a
                    // number that means nothing, and the shape should refuse that before a second
                    // model exists rather than after.
                    Some(m) if calls(&model) > 0 => {
                        let u = m.spent();
                        vec![trigon_store::Tokens {
                            input: u.input,
                            cached_input: u.cached_input,
                            output: u.output,
                            model: m.model_id().to_string(),
                            calls: calls(&model),
                        }]
                    }
                    _ => Vec::new(),
                },
                timings: report.timings.clone(),
                // What the model was asked, where one was configured. Empty for the healthy
                // majority of a corpus, which is the point of measuring the invocation rate.
                transcript: model.as_ref().map(|m| m.transcript(&args.purl)),
                ..inputs.clone()
            };
            if let Err(e) = record_run(dir, &inputs, &upstream_path, &rebuilt, &comparison, verbose)
            {
                tracing::warn!("could not record this run: {e:#}");
            }
        }
        report.model_calls = calls(&model);
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
        /// Everything that crossed the network into the build, or `None` where no complete account
        /// exists. An empty `Some` is stored as an empty blob and means nothing crossed; flattening
        /// it to `None` would turn "we looked and it was clean" into "we never looked".
        network_transcript: Option<Vec<trigon_mirror::Exchange>>,
        /// Wall-clock seconds spent waiting on a model, and what the calls cost in tokens. `None`
        /// and empty where nothing was asked, which is the healthy majority of a corpus.
        inference_seconds: Option<f64>,
        tokens: Vec<trigon_store::Tokens>,
        /// Per-phase durations as the run reported them. Summed into `build_seconds` at write
        /// time, dropping the phases with no reading rather than counting them as zero — so the
        /// figure is a floor and never an overstatement.
        timings: Vec<(String, Option<f64>)>,
        /// What the model was asked and what it said, when one was asked anything.
        ///
        /// `None` when no provider was configured — the common case, and not the same as a model
        /// that was asked and said nothing. `RunRecord::transcript` says why it is kept: a
        /// `derivation: model_assisted` with no transcript is an assertion, and one with a
        /// transcript is evidence.
        transcript: Option<trigon_ai::Transcript>,
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
            // Everything this run adds to the store, counted as each blob goes in rather than
            // estimated afterwards. `docs/10-scale.md` §1 budgets ~3 MB a run and ~270 GB a sweep,
            // and a budget with nothing measuring it is a wish.
            let mut blob_bytes = (up_bytes.len() + rb_bytes.len()) as u64;
            let mut log_bytes = 0u64;

            let comparison_bytes = serde_json::to_vec(c)?;
            blob_bytes += comparison_bytes.len() as u64;
            let comparison = store.blobs().put(comparison_bytes).await?;
            let build_log = match std::fs::read(args.work.join("rebuild").join("build.log"))
                .or_else(|_| std::fs::read(args.work.join("build.log")))
            {
                Ok(b) => {
                    log_bytes = b.len() as u64;
                    blob_bytes += log_bytes;
                    Some(store.blobs().put(b).await?)
                }
                Err(_) => None,
            };
            // Only where a model was actually asked something. An empty transcript and an absent
            // one mean different things and the store keeps the difference: no provider configured
            // is `None`, and a provider that answered nothing is a recorded transcript with no
            // turns.
            let transcript = match &args.transcript {
                Some(t) if !t.turns.is_empty() => {
                    let bytes = serde_json::to_vec(t)?;
                    blob_bytes += bytes.len() as u64;
                    Some(store.blobs().put(bytes).await?)
                }
                _ => None,
            };

            // One line per exchange rather than one JSON array, so a transcript from a build that
            // fetched ten thousand files can be grepped, tailed and appended to without a parser
            // holding all of it. `None` and `Some(vec![])` are kept apart by storing a blob in the
            // second case and none in the first: an empty blob is a complete account of a build
            // that fetched nothing, which is a claim, and no blob is the absence of one.
            let network_transcript = match &args.network_transcript {
                Some(t) => {
                    let mut buf = Vec::new();
                    for e in t {
                        buf.extend_from_slice(&serde_json::to_vec(e)?);
                        buf.push(b'\n');
                    }
                    blob_bytes += buf.len() as u64;
                    Some(store.blobs().put(buf).await?)
                }
                None => None,
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
                    // `--egress` stamped `attestable: true` on runs whose image-build phases were
                    // outside the boundary entirely. A claim about enforcement has to come from
                    // the thing that enforced it.
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
                crate::now_rfc3339(),
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
            record.transcript = transcript;
            record.network_transcript = network_transcript;
            record.costs = Some(trigon_store::Costs {
                inference_seconds: args.inference_seconds,
                tokens: args.tokens.clone(),
                // Summed over the phases we have a reading for, and `None` when that is none of
                // them. A phase whose duration we failed to read is dropped rather than counted as
                // zero, which makes this a floor on the true figure instead of an understatement
                // dressed up as a measurement.
                build_seconds: {
                    let read: Vec<f64> = args.timings.iter().filter_map(|(_, d)| *d).collect();
                    (!read.is_empty()).then(|| read.iter().sum())
                },
                // Straight off the network transcript, which is the thing that made this
                // measurable at all: before it, "how many bytes did this build pull" could only be
                // guessed at. `None` where there is no transcript and `Some(0)` where there is one
                // and nothing crossed — the same distinction, carried one level further out.
                egress_bytes: args
                    .network_transcript
                    .as_ref()
                    .map(|t| t.iter().map(|e| e.bytes).sum()),
                blob_bytes: Some(blob_bytes),
                artifact_bytes: Some((up_bytes.len() + rb_bytes.len()) as u64),
                log_bytes: Some(log_bytes),
            });
            record.finished = Some(crate::now_rfc3339());
            store.put_run(&record).await?;
            if verbose {
                println!("\n  recorded   run {id} in {}", dir.display());
                if let Some(c) = &record.costs {
                    // Said out loud, because a cost nobody sees is a cost discovered on an invoice.
                    // Every figure carries its unit and omits what it does not know, rather than
                    // printing a zero that reads as a measurement.
                    let mut parts = Vec::new();
                    if let Some(s) = c.build_seconds {
                        parts.push(format!("{s:.1}s building"));
                    }
                    if let Some(s) = c.inference_seconds {
                        parts.push(format!("{s:.1}s inference"));
                    }
                    for t in &c.tokens {
                        parts.push(format!(
                            "{} in / {} out over {} call{} to {}",
                            t.input,
                            t.output,
                            t.calls,
                            if t.calls == 1 { "" } else { "s" },
                            t.model
                        ));
                    }
                    match c.egress_bytes {
                        Some(b) => parts.push(format!("{} fetched", human_bytes(b))),
                        None => parts.push("egress not measured".into()),
                    }
                    if let Some(b) = c.blob_bytes {
                        parts.push(format!("{} stored", human_bytes(b)));
                    }
                    println!("  cost       {}", parts.join(", "));
                }
            }
            anyhow::Ok(())
        })
    }

    /// Bytes, at the precision a person reading a cost line needs.
    fn human_bytes(b: u64) -> String {
        match b {
            0..=1023 => format!("{b} B"),
            1024..=1_048_575 => format!("{:.1} KB", b as f64 / 1024.0),
            1_048_576..=1_073_741_823 => format!("{:.1} MB", b as f64 / 1_048_576.0),
            _ => format!("{:.2} GB", b as f64 / 1_073_741_824.0),
        }
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
            // **Both files, before either is parsed.** The format comes from the upstream name and
            // is then applied to both, so a rebuild of a different kind is fed to the wrong parser
            // and reports the *upstream* artifact as malformed — `not a gzip member` against a
            // perfectly good sdist, because the thing beside it was a wheel. Three PyPI targets
            // came back that way the first time a C toolchain let them build at all.
            //
            // Named here rather than left to the parser: "we built the wrong kind of file" is a
            // statement about our recipe and has a fix, where "the archive is malformed" sends
            // somebody to look at the registry.
            let rebuilt_format = crate::resolve_format(rebuilt, None).ok();
            if let Some(rf) = rebuilt_format
                && rf != format
            {
                anyhow::bail!(
                    "the build produced a {rf:?} and the artifact under test is a {format:?}, so \
                     there is nothing to compare. The recipe built the wrong kind of \
                     distribution — a release publishes an sdist and platform wheels, and a run \
                     is about one of them."
                );
            }
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
        let subject =
            (!classes.is_empty()).then(|| classes.into_iter().collect::<Vec<_>>().join(","));
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
            S::BelowPrevalenceThreshold { score, threshold } => {
                format!("prevalence {score:.3} is below the sweep's threshold of {threshold:.3}")
            }
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

    /// The checkout the build will use, and the guard manifest narrowed by it.
    ///
    /// **Both or neither, deliberately.** The manifest exempts members byte-identical to a file in
    /// the source tree — "a file the artifact ships and the repository also contains is not
    /// evidence of anything: the build is entitled to fetch it" — and for a long time nothing
    /// reached that filter on an ordinary run, because the manifest was built before a strategy
    /// named a location. Handing them back as a pair means a later edit cannot separate them
    /// without changing this signature.
    ///
    /// The checkout is also the build's input, not just the guard's: the tree the guard exempted
    /// files from has to be the tree the build compiled, or the exemption is about a different set
    /// of bytes.
    ///
    /// Best effort, in the direction it has always been. A strategy whose source phase generates
    /// its own tree has nothing to fetch, and failing here would refuse it for a repository it
    /// never intended to use. Without a tree the manifest stays wide, which errs toward voiding an
    /// honest run rather than missing a forged one.
    fn checkout_and_guard(
        upstream: &Path,
        url: &str,
        loc: &trigon_strategy::Location,
        named: Option<&Path>,
        cache_root: Option<&Path>,
        target: &trigon_core::TargetRef,
    ) -> Result<(Option<PathBuf>, trigon_mirror::GuardManifest)> {
        let checkout = match named {
            Some(p) => Some(p.to_path_buf()),
            None if loc.repo.is_empty() => None,
            None => {
                let cache = trigon_registry::SourceCache::new(
                    cache_root
                        .map(Path::to_path_buf)
                        .unwrap_or_else(trigon_registry::SourceCache::default_root),
                );
                match cache.checkout(&loc.repo, &loc.git_ref) {
                    Ok(c) => Some(c.path),
                    Err(e) => {
                        // Said out loud rather than at `debug`: the guard is about to watch files
                        // the build is entitled to produce, and a run that voids for that reason
                        // should be readable as this rather than as a catch.
                        tracing::warn!(
                            repo = %loc.repo,
                            "no host checkout, so the guard is wider than designed: a member the \
                             repository also contains cannot be exempted. {e:#}"
                        );
                        None
                    }
                }
            }
        };

        // This is the control that defeats the attack the whole design is shaped around: a strategy
        // that downloads the published artifact reproduces it byte for byte, passes every clean
        // re-run, and is worth nothing.
        let guard = match std::fs::read(upstream) {
            Ok(bytes) => {
                let format = crate::resolve_format(upstream, None)?;
                let u = Some(url.to_string());
                let m = match checkout.as_deref() {
                    Some(dir) => trigon_mirror::GuardManifest::for_artifact_with_source(
                        &bytes, format, u, dir,
                    ),
                    None => trigon_mirror::GuardManifest::for_artifact(&bytes, format, u),
                };
                // And withhold this version from the index the build resolves against. The refusal
                // is the control; this is what makes it survivable. A resolver that is offered a
                // version and then denied the file fails outright, which is how every package that
                // is part of the machinery that builds packages died at an enforced tier —
                // `python -m build` needs `packaging`, npm's installer needs `object-assign`. A
                // version that was never listed is routed around instead.
                //
                // `registry_name`, not `name`: an npm scope is part of what the registry calls the
                // package, and `core` is a different package from `@babel/core`.
                m.withholding(&target.registry_name(), &target.version)
            }
            Err(_) => trigon_mirror::GuardManifest::default(),
        };
        Ok((checkout, guard))
    }

    #[cfg(test)]
    mod guard_ordering_tests {
        use super::*;

        fn tgz(members: &[(&str, &[u8])]) -> Vec<u8> {
            let mut b = ::tar::Builder::new(Vec::new());
            for (name, body) in members {
                let mut h = ::tar::Header::new_ustar();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, *name, *body).unwrap();
            }
            let tar = b.into_inner().unwrap();
            let mut out = Vec::new();
            {
                use std::io::Write as _;
                let mut e = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
                e.write_all(&tar).unwrap();
                e.finish().unwrap();
            }
            out
        }

        fn target() -> trigon_core::TargetRef {
            trigon_core::TargetRef::new(trigon_core::Ecosystem::Npm, "demo", "1.0.0")
        }

        /// The one this project had to learn twice: the *filter* was tested and the ordering that
        /// reaches it was asserted by nothing, so an ordinary run never got there and two packages
        /// voided on their own source files for weeks.
        #[test]
        fn a_run_with_a_checkout_guards_nothing_the_repository_also_holds() {
            let shared = vec![b'S'; 9000];
            let only_in_the_artifact = vec![b'A'; 9000];
            let dir = std::env::temp_dir().join(format!("trigon-b14-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("shared.js"), &shared).unwrap();
            let art = dir.join("demo-1.0.0.tgz");
            std::fs::write(
                &art,
                tgz(&[
                    ("package/shared.js", &shared),
                    ("package/built.js", &only_in_the_artifact),
                ]),
            )
            .unwrap();

            let loc = trigon_strategy::Location::default();
            let (checkout, guard) = checkout_and_guard(
                &art,
                "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                &loc,
                Some(dir.as_path()),
                None,
                &target(),
            )
            .unwrap();

            assert_eq!(
                guard.members.len(),
                1,
                "the file the repository also holds is exempt; the one only the artifact has is not"
            );
            assert_eq!(guard.filtered_out, 1);
            // **The tree the build gets is the tree the guard exempted from.** Handing back a
            // different one would make the exemption a statement about other bytes, and nothing
            // downstream could tell.
            assert_eq!(checkout.as_deref(), Some(dir.as_path()));

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// And with no tree the guard stays wide, which is the safe direction: it errs toward
        /// voiding an honest run rather than missing a forged one.
        #[test]
        fn a_run_with_no_checkout_guards_everything() {
            let shared = vec![b'S'; 9000];
            let dir = std::env::temp_dir().join(format!("trigon-b14-none-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let art = dir.join("demo-1.0.0.tgz");
            std::fs::write(&art, tgz(&[("package/shared.js", &shared)])).unwrap();

            let (checkout, guard) = checkout_and_guard(
                &art,
                "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                // No location, so there is nothing to check out and nothing to narrow with.
                &trigon_strategy::Location::default(),
                None,
                None,
                &target(),
            )
            .unwrap();
            assert!(checkout.is_none());
            assert_eq!(guard.members.len(), 1);
            assert_eq!(guard.filtered_out, 0);

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// The withholding rides on the same manifest, so it cannot be lost by a reordering of the
        /// two halves either.
        #[test]
        fn the_manifest_carries_the_version_to_withhold() {
            let dir = std::env::temp_dir().join(format!("trigon-b14-w-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let art = dir.join("demo-1.0.0.tgz");
            std::fs::write(&art, tgz(&[("package/x.js", &vec![b'x'; 9000])])).unwrap();

            let (_, guard) = checkout_and_guard(
                &art,
                "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                &trigon_strategy::Location::default(),
                None,
                None,
                &target(),
            )
            .unwrap();
            let w = guard.withhold.expect("the version under test is withheld");
            assert_eq!(w.project, "demo");
            assert_eq!(w.version, "1.0.0");

            let _ = std::fs::remove_dir_all(&dir);
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
    pub(crate) fn newest_file(dir: &Path) -> Option<PathBuf> {
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
                // Anything that is obviously ours rather than the build's has no business being
                // mistaken for the artifact, and the failure when it is — a log parsed as a zip,
                // a JSON-Lines transcript parsed as a gzip — names the wrong culprit entirely.
                //
                // The list lives beside the code that writes those files rather than here, because
                // this used to name `build.log` and nothing else: adding a second file next to the
                // artifact was enough to make a `mirror-only` run report `malformed gzip: not a
                // gzip member` about a tarball it had built perfectly well.
                } else if !p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| crate::build::OURS.contains(&n))
                {
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
            let d =
                std::env::temp_dir().join(format!("trigon-collect-{tag}-{}", std::process::id()));
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
        fn nothing_this_process_writes_is_ever_taken_for_the_artifact() {
            // Driven off the same list the writers use, so the two cannot drift. They did: this
            // check named `build.log` and nothing else, and writing the network transcript beside
            // the artifact was enough to make a `mirror-only` run judge its own transcript as the
            // tarball it had just built — reported as `malformed gzip: not a gzip member`, which
            // reads as a broken build rather than as us handing the comparator the wrong file.
            let d = tmpdir("ours");
            let out = d.join("rebuild");
            std::fs::create_dir_all(&out).unwrap();
            for name in crate::build::OURS {
                std::fs::write(out.join(name), b"ours, not the build's").unwrap();
            }
            assert_eq!(
                newest_file(&out),
                None,
                "a file this process wrote was offered as the rebuilt artifact"
            );

            // And the artifact is still found with all of them sitting beside it, including the
            // ones that sort after it.
            let real = out.join("aaa-1.0.0.tgz");
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

    /// Every system package a builtin tool asks for.
    ///
    /// The union rather than a per-ecosystem split, because a wrong split is a build that fails at
    /// the boundary for a reason that reads as the package's fault. `npm` is deliberately absent:
    /// Debian's `npm` pulls its own Node and a system-wide `NODE_PATH` that puts modules for it
    /// ahead of the pinned toolchain, which is `env/toolchain-crashed` on the M1 corpus and not a
    /// vintage problem. A strategy that truly needs the distribution's npm has to say so in its own
    /// image.
    ///
    /// **What is still absent, and why**, so the next person does not have to re-derive it from a
    /// corpus run: a Rust toolchain (one target) and `meson` with `ninja` (one target). Both are
    /// real gaps and neither is a package name — Debian's `rustc` trails the ecosystem far enough
    /// that a crate needing a newer one fails differently rather than building, so pinning a Rust
    /// toolchain is the same decision the Node one already is, and belongs with it rather than in
    /// this list. `yarn` and `just` are absent for the same reason as `npm`: a package whose build
    /// requires another package manager is a finding about that package, and installing every one
    /// of them makes the image the union of every ecosystem's opinions.
    const DEFAULT_PACKAGES: &[&str] = &[
        "ca-certificates",
        "git",
        "libatomic",
        "python3",
        "wget",
        // **The toolchains the M1 corpus showed missing**, which nothing could install at an
        // enforced tier because the image build has no network — so a target that needs one fails
        // at the boundary and reads as the package's fault.
        //
        // A C compiler and the Python headers: five of the corpus's ten unnamed PyPI failures were
        // `command 'x86_64-linux-gnu-gcc' failed: No such file or directory` and one was `g++`.
        // Every native extension needs these, and the native stratum exists to measure them.
        "cc",
        "python3-dev",
        // Asked for by most extension builds to locate system libraries; absent, the build guesses
        // and fails further in, where the error is about a header rather than about pkg-config.
        "pkg-config",
        // `git+ssh://` dependencies, which npm resolves by running ssh. Eight npm targets on the
        // full corpus failed `ssh: not found`, all of them in the strata with real dependency
        // trees.
        "ssh",
    ];

    /// Build a base image that carries what an enforced tier cannot install.
    pub fn base_image(from: &str, packages: &[String], tag: &str, print: bool) -> Result<()> {
        if !from.contains('@') {
            bail!(
                "pin `--from` by digest. A tag resolves to different bytes on different days, \
                 which is exactly what a base image for a reproducibility tool must not do."
            );
        }
        let packages: Vec<String> = if packages.is_empty() {
            DEFAULT_PACKAGES.iter().map(|s| s.to_string()).collect()
        } else {
            packages.to_vec()
        };
        // The same expansion the sandbox would have used, so the image carries exactly what the
        // setup phase would have installed rather than an operator's guess at the package names.
        let containerfile = format!(
            "FROM {from}\nRUN {}\n",
            trigon_sandbox::install_command(from, &packages)
        );
        if print {
            print!("{containerfile}");
            return Ok(());
        }

        let dir = std::env::temp_dir().join(format!("trigon-base-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let file = dir.join("Containerfile");
        std::fs::write(&file, &containerfile)?;
        println!("building {tag} from {from} with: {}", packages.join(", "));
        let status = std::process::Command::new("podman")
            .args(["build", "--tag", tag, "--file"])
            .arg(&file)
            .arg(&dir)
            .status()
            .context("running podman build")?;
        let _ = std::fs::remove_dir_all(&dir);
        if !status.success() {
            bail!("podman build failed");
        }
        // The digest, because `--image` refuses a tag and this is the number the operator needs.
        let out = std::process::Command::new("podman")
            .args([
                "image",
                "inspect",
                tag,
                "--format",
                "{{index .RepoDigests 0}}",
            ])
            .output();
        match out {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => {
                println!(
                    "\n{tag} is ready: {}",
                    String::from_utf8_lossy(&o.stdout).trim()
                );
            }
            // A locally built image has no repository digest until it is pushed, so the id is what
            // the operator passes. It names exactly one set of bytes in the local store, which is
            // the property `--image` is checking for.
            _ => {
                let id = std::process::Command::new("podman")
                    .args(["image", "inspect", tag, "--format", "{{.Id}}"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                println!(
                    "\n{tag} is ready. It has no repository digest until it is pushed, so \
                          pass its id:\n\n    --image {id}"
                );
            }
        }
        Ok(())
    }

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
            .args([
                "--label",
                &format!("{SOURCE_LABEL}={}", source_digest(&root)?),
            ])
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
    /// The label `mirror-image` stamps on the image it builds.
    ///
    /// Reads the workspace, and correctly so: that command builds the image *out of* the workspace,
    /// so the label has to describe what was copied in. The staleness check on the other side reads
    /// a digest baked in at compile time, because it is asking about the binary. Both call the one
    /// function in `src/mirror_source.rs`, which `build.rs` includes too — two copies of a hashing
    /// rule would either never match, and warn on every run, or match by luck and never warn.
    fn source_digest(root: &Path) -> Result<String> {
        Ok(crate::mirror_source_digest(root)?)
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
        // Baked in by `build.rs`, not read off the disk. This walked up from the current directory
        // to find the workspace and returned silently when it could not — so the check worked from
        // inside the checkout and did nothing at all from anywhere else, which is everywhere an
        // installed Trigon is actually run. A control that fails open and says nothing while it
        // does. It is also the honest question: "is this image older than the mirror code *this
        // binary* speaks" is a fact about the binary, not about whatever source is on the disk.
        let want = env!("TRIGON_MIRROR_SOURCE");
        if want == "unknown" {
            tracing::warn!(
                "cannot tell whether {tag} is current: this binary was built without the mirror's \
                 source to hash, so nothing checked it"
            );
            return;
        }
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
        /// Targets built at once.
        ///
        /// **Defaults to 1, which is what a sweep did before this existed.** Raising it is the
        /// difference between a 400-target corpus being an overnight job and something you can
        /// re-run after a fix, and the M1 corpus is not a measurement anyone iterates on at eight
        /// hours a pass.
        ///
        /// Bounded by memory rather than by cores: every target in flight holds a build container
        /// and a mirror container, and the failure mode when that runs out is the OOM killer taking
        /// a build, which reads as a broken package. Podman's own image store is shared across
        /// processes and [`docs/17-backlog.md`] B6's cross-process window is still open, so this
        /// parallelises *within* one sweep and says nothing about two sweeps at once.
        pub concurrency: usize,
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

        // What this sweep is, and where it is. Two files a second reader can watch from another
        // terminal — the sweep never talks to that reader, it only writes, which is what makes the
        // page survive this process dying. `docs/18-management-ui.md`.
        let progress = std::sync::Arc::new(crate::progress::Progress::start(
            &args.work,
            crate::progress::Sweep {
                started: crate::now_rfc3339(),
                pid: std::process::id(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                targets_path: Some(args.targets.display().to_string()),
                // The corpus by content as well as by path: the digest is what says two sweeps are
                // of the same corpus, and a path says only where somebody's file was.
                targets_sha256: crate::progress::digest_of(&args.targets),
                targets_count: purls.len(),
                resumed_from: already.len(),
                image: args.image.clone(),
                egress: args.egress.clone(),
                timewarp: args.timewarp.clone(),
                model: args.model.clone(),
                store: args.store.as_ref().map(|p| p.display().to_string()),
                definitions: args.definitions.as_ref().map(|p| p.display().to_string()),
                timeout_seconds: args.timeout,
                finished: None,
            },
        ));

        // Resumed rows first, in target order and without touching a container. Separated from the
        // work below because a resumed row is not a run: it spends nothing, it cannot fail, and
        // mixing it into the pool would have the pool's bound describe a queue that is mostly
        // already answered.
        let mut rows: Vec<(String, Outcome, f64)> = Vec::new();
        let mut todo: Vec<(usize, &str)> = Vec::new();
        for (i, purl) in purls.iter().enumerate() {
            match already.get(*purl) {
                Some((label, secs, cluster, calls)) => {
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
                }
                None => todo.push((i, purl)),
            }
        }

        // **Bounded, and the bound is memory.** Every target in flight holds a build container and
        // a mirror container; the failure when that runs out is the OOM killer taking a build,
        // which arrives looking like a broken package. One at a time is the default and is exactly
        // what this loop did before.
        //
        // Threads rather than tasks: `run_one` is synchronous and builds its own tokio runtime, and
        // wrapping that in an async pool would nest runtimes for no gain. The channel carries
        // finished rows back; the terminal line is printed by the worker as it finishes, so the
        // order on screen is completion order and the `[i/n]` on each line says which target it is.
        // **Bounded, and the bound is memory.** Every target in flight holds a build container
        // and a mirror container; the failure when that runs out is the OOM killer taking a build,
        // which arrives looking like a broken package. One at a time is the default.
        //
        // This refused above one lane until B6 closed, and the refusal was right: the first run at
        // three lanes lost two of seventeen targets to podman's shared image store — a finishing
        // lane removing an image another was reading, and an orphan sweep force-removing a mirror
        // container that had been created but had not finished starting. Both arrived labelled as
        // the package's failure, which is the one thing a reproduction rate must never contain.
        // What makes it safe now is a mechanism rather than an argument about timing: builds hold
        // the image store shared, removals take it exclusively or skip themselves, and the orphan
        // sweep asks who owns a container instead of whether it is running yet.
        let lanes = args.concurrency.max(1).min(todo.len().max(1));
        if lanes > 1 {
            println!("  {lanes} targets at a time\n");
        }
        // **Before anything builds.** A build image is ~240 MB and a sweep keeps one per target
        // until the store is quiet enough to reap them, so a large corpus needs real headroom —
        // and a machine that fills up mid-sweep fails the remaining targets with errors that read
        // like the packages' fault, which is the one thing a rate must not contain. Checked, said,
        // and not enforced: the estimate is a rule of thumb, and refusing to start on a guess would
        // be worse than a warning somebody can act on.
        if let Some(free) = free_bytes(&args.work) {
            const PER_TARGET: u64 = 300 * 1024 * 1024;
            let need = PER_TARGET * todo.len() as u64;
            let gb = |b: u64| b as f64 / 1e9;
            println!(
                "  disk       {:.1} GB free, about {:.1} GB wanted for {} target(s)",
                gb(free),
                gb(need),
                todo.len()
            );
            if free < need {
                tracing::warn!(
                    "this sweep may want more disk than is free. A build image is around 240 MB \
                     and one is kept per target until the image store is quiet enough to reap it; \
                     a machine that fills mid-sweep fails the rest with errors that read as the \
                     packages' fault."
                );
            }
        }

        // How many identical consecutive failures mean a wall rather than a set of findings, how
        // often to check the disk, and how little free space is too little to keep going.
        const WALL: u32 = 10;
        const REAP_EVERY: usize = 20;
        const FLOOR: u64 = 20 * 1_000_000_000;
        // Each lane holds a build container and a mirror container. Below this there is not room
        // for the one in flight, let alone the next.
        const MEMORY_FLOOR: u64 = 3 * 1_000_000_000;
        let mut consecutive: u32 = 0;
        let mut repeated: Option<String> = None;

        // **Set when the collector gives up, and read by every lane.** Without it `break` stopped
        // the *reporting* and not the *building*: a worker ignores a failed send and takes the next
        // target, so a breaker meant to save seven hours saved none of them.
        let stop = std::sync::atomic::AtomicBool::new(false);
        let next = std::sync::atomic::AtomicUsize::new(0);
        let (tx, rx) = std::sync::mpsc::channel::<(usize, String, Outcome, f64, u32)>();
        let total = purls.len();
        let done = std::sync::Mutex::new(rows.len());

        std::thread::scope(|scope| -> Result<()> {
            for _ in 0..lanes {
                let (tx, next, todo, args, progress, done, stop) =
                    (tx.clone(), &next, &todo, &args, &progress, &done, &stop);
                scope.spawn(move || {
                    loop {
                        if stop.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(&(i, purl)) = todo.get(at) else {
                            break;
                        };
                        let (outcome, secs, calls) = one(i, purl, args, progress, total, done);
                        // A send that fails means the collector is gone, which means the sweep is
                        // already unwinding. Nothing useful to do with the row.
                        let _ = tx.send((i, purl.to_string(), outcome, secs, calls));
                    }
                });
            }
            // The senders the workers hold are clones; this one has to go or the receive below
            // never ends.
            drop(tx);

            use std::io::Write as _;
            for (_, purl, outcome, secs, calls) in rx {
                // **Flushed per row, in completion order, and that is deliberate — see below.**
                // Buffered output is lost with the process, which is the failure this exists to
                // prevent, and a row cannot wait for its neighbours without giving that up.
                writeln!(
                    sink,
                    "{purl}\t{}\t{secs:.1}\t{}\t{}",
                    outcome.label(),
                    outcome.cluster().unwrap_or_default(),
                    calls,
                )?;
                sink.flush()?;

                // **A breaker, because this runs unattended for hours.** When throttling or a full
                // disk starts, every remaining target fails the same way: an eight-hour sweep
                // spends seven of them proving one fact, and reports a denominator built from our
                // own infrastructure. The signature is repetition — genuine package failures are
                // diverse, a wall is not — so the rule is the same cluster, over and over, with
                // nothing succeeding in between.
                //
                // Deliberately blunt. It stops rather than pausing, because every row is already
                // flushed and `completed()` resumes them: stopping costs nothing but the targets
                // that would have failed anyway, and the operator gets the cluster that explains it.
                // **Keyed on the cluster where there is one, and the label where there is not.**
                // Keying on the cluster alone made the breaker blind to exactly the wall it was
                // built for: `Outcome::NoStrategy` has no cluster, so every one of them took the
                // reset arm — and the M1 PyPI run produced 37 in a row. The largest single failure
                // mode in that run was the one shape this could not see.
                let key = match outcome.cluster() {
                    Some(c) => c,
                    None => outcome.label(),
                };
                if outcome.is_evidence() {
                    repeated = None;
                    consecutive = 0;
                } else if Some(&key) == repeated.as_ref() {
                    consecutive += 1;
                } else {
                    repeated = Some(key);
                    consecutive = 1;
                }
                rows.push((purl, outcome, secs));

                if consecutive >= WALL {
                    let key = repeated.clone().unwrap_or_default();
                    tracing::error!(
                        cluster = %key,
                        "{WALL} targets in a row failed the same way and none succeeded between \
                         them. That is a wall rather than {WALL} findings — throttling, a full \
                         disk, a stopped daemon — so the sweep is stopping instead of spending the \
                         night proving it. Every row so far is written; re-run the same command to \
                         resume once the cause is fixed."
                    );
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }

                // Disk, periodically rather than only at the start: a sweep that fills the
                // filesystem fails the rest with errors that read as the packages' fault, and the
                // deferred images are what fills it. Reaping here bounds the backlog that
                // `store_lock` deliberately lets grow.
                if rows.len() % REAP_EVERY == 0 {
                    trigon_sandbox::reap_deferred("podman");
                    // **Memory, which is what actually stopped the first attempt.** Disk and rate
                    // limits were instrumented and neither was the constraint: four lanes each hold
                    // a build container and a mirror container, and the machine ran out of RAM 29
                    // targets in. The OOM killer takes whichever process is largest, which is a
                    // build, and that arrives looking like the package's failure — the same shape
                    // as every other infrastructure fault this sweep now refuses to report as one.
                    if let Some(free) = available_bytes()
                        && free < MEMORY_FLOOR
                    {
                        tracing::error!(
                            available_gb = free as f64 / 1e9,
                            lanes,
                            "less than {:.0} GB of memory available after {} targets; stopping \
                             rather than letting the OOM killer take a build and report it as the \
                             package's failure. Re-run with fewer lanes to resume.",
                            MEMORY_FLOOR as f64 / 1e9,
                            rows.len()
                        );
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    if let Some(free) = free_bytes(&args.work)
                        && free < FLOOR
                    {
                        tracing::error!(
                            free_gb = free as f64 / 1e9,
                            "less than {:.0} GB free after {} targets; stopping rather than \
                             failing the rest on a full disk. Every row so far is written.",
                            FLOOR as f64 / 1e9,
                            rows.len()
                        );
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                }
            }
            Ok(())
        })?;

        // Back into target order — in memory *and* on disk. The pool finishes them in whatever
        // order it likes, and a results file whose order depends on how many lanes were free is not
        // comparable with another: a reader lining it up against the corpus reads the wrong target.
        //
        // That happened. Diagnosing a cluster meant reading row N's work directory, which is
        // indexed by *corpus* position, and the two had silently diverged — so the investigation
        // was of a different package than the one that failed. Only the in-memory rows were being
        // sorted, which is the half nobody reads afterwards.
        //
        // Rewritten at the end rather than buffered during, because a row must reach disk the
        // moment it exists: a sweep that is killed keeps every row it finished, and resume depends
        // on it. This is the one moment both properties can hold at once.
        let position: BTreeMap<&str, usize> =
            purls.iter().enumerate().map(|(i, p)| (*p, i)).collect();
        rows.sort_by_key(|(purl, _, _)| position.get(purl.as_str()).copied().unwrap_or(usize::MAX));
        if let Err(e) = rewrite_in_order(&results, &rows, &already) {
            tracing::warn!(
                "the results file is in completion order rather than target order: {e}. It resumes \
                 correctly either way — `completed()` reads it by package URL — but lining it up \
                 against the corpus by position would read the wrong target."
            );
        }

        // Every lane is done, so nothing holds the image store: this is the one moment in a sweep
        // when the images that finishing runs could not remove can actually go. Without it a long
        // sweep grows the store by one build image per target — ~240 MB each, measured — because a
        // removal always loses the lock to some other lane still building.
        trigon_sandbox::reap_deferred("podman");

        // Before the summary, so a reader watching the page sees `finished` at the same moment the
        // terminal does.
        progress.finish(rows.len());
        summarize(&rows);
        Ok(())
    }

    /// Run one target and report it, returning what it produced and how long it took.
    fn one(
        i: usize,
        purl: &str,
        args: &Args,
        progress: &std::sync::Arc<crate::progress::Progress>,
        total: usize,
        done: &std::sync::Mutex<usize>,
    ) -> (Outcome, f64, u32) {
        {
            let n = done.lock().map(|g| *g).unwrap_or(0);
            progress.target(i, purl, n);
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
                // No *operator-named* checkout. The run fetches its own from the source cache
                // once a strategy names a location, and narrows the guard with it — which is
                // what B14 closed. This used to say a sweep had no checkout at all, and the
                // guard was wider than designed on every target because of it.
                source: None,
                // A sweep writes no statements. Its product is a rate, and 20 bundles nobody
                // asked for is 20 files to explain.
                attest: None,
                key: None,
                store: args.store.clone(),
                model: args.model.clone(),
                source_cache: args.source_cache.clone(),
                phases: Some(progress.clone()),
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
        // What this run actually spent, not what the outcome remembers: a fresh row knows its own
        // count and only a resumed one has to read it back out of the file.
        let calls = ran.model_calls.max(ran.outcome.model_calls());
        let outcome = ran.outcome;

        let secs = started.elapsed().as_secs_f64();
        if let Ok(mut n) = done.lock() {
            *n += 1;
        }
        println!(
            "  {:<28} {:<20} {:>6.0}s   [{}/{}]",
            short(purl),
            outcome.label(),
            secs,
            i + 1,
            total
        );
        (outcome, secs, calls)
    }

    /// Memory available to start another build, from `MemAvailable`.
    ///
    /// `MemAvailable` rather than `MemFree`: the kernel's own estimate of what can be had without
    /// swapping, which counts reclaimable page cache. `MemFree` on a machine that has been building
    /// containers reads near zero and would stop every sweep.
    fn available_bytes() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("MemAvailable:") {
                let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }

    /// Free bytes on the filesystem holding a path, or `None` where it cannot be asked.
    ///
    /// `statvfs` through `libc` rather than parsing `df`: the output of `df` is a human format that
    /// has changed, and a wrong number here is worse than no number — it would either refuse a
    /// sweep that would have fitted or reassure one that will not.
    fn free_bytes(path: &Path) -> Option<u64> {
        // The directory may not exist yet; ask about the nearest ancestor that does.
        let mut at = path.to_path_buf();
        while !at.exists() {
            if !at.pop() {
                return None;
            }
        }
        let c = std::ffi::CString::new(at.as_os_str().as_encoded_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `c` is a valid NUL-terminated path and `st` is owned here.
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            return None;
        }
        Some(st.f_bavail as u64 * st.f_frsize as u64)
    }

    /// Rewrite the results file with the rows in target order.
    ///
    /// The per-row flush during the sweep is what survives a kill; this is what makes the finished
    /// file comparable with another run of the same corpus. Both matter, and they want opposite
    /// things during the run, so the ordering is imposed once at the end.
    fn rewrite_in_order(
        path: &Path,
        rows: &[(String, Outcome, f64)],
        already: &BTreeMap<String, (String, f64, Option<String>, u32)>,
    ) -> Result<()> {
        use std::io::Write as _;
        let mut out = String::new();
        for (purl, outcome, secs) in rows {
            // A resumed row's model-call count lives in the file it was read from, not on the
            // outcome; taking it from there keeps a resumed sweep's totals equal to a fresh one's.
            let calls = already
                .get(purl)
                .map(|(_, _, _, c)| *c)
                .unwrap_or_else(|| outcome.model_calls());
            out.push_str(&format!(
                "{purl}\t{}\t{secs:.1}\t{}\t{}\n",
                outcome.label(),
                outcome.cluster().unwrap_or_default(),
                calls,
            ));
        }
        let mut f = std::fs::File::create(path)?;
        f.write_all(out.as_bytes())?;
        f.sync_all()?;
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
                    (
                        label.to_string(),
                        secs.parse().unwrap_or(0.0),
                        cluster,
                        calls,
                    ),
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

        // **What we asked of the registries, beside what we concluded from them.** Upstream
        // reputation is what breaks first at scale (`docs/10-scale.md` §3), and until this existed
        // nothing counted a request: a sweep that exhausted GitHub's 60-an-hour allowance kept
        // going, every later target came back `no-strategy`, and the run reported that Trigon
        // cannot infer strategies for most of PyPI. That is a statement about our request budget
        // wearing the costume of a finding about packages.
        let traffic = trigon_registry::traffic();
        let throttled: u64 = traffic.values().map(|t| t.throttled).sum();
        if !traffic.is_empty() {
            println!("\n  upstream");
            for (host, t) in &traffic {
                let note = match (t.throttled, t.failed) {
                    (0, 0) => String::new(),
                    (0, f) => format!("   {f} failed"),
                    (r, 0) => format!("   {r} throttled"),
                    (r, f) => format!("   {r} throttled, {f} failed"),
                };
                println!("    {host:<28} {:>5} request(s){note}", t.requests);
            }
            if throttled > 0 && trigon_registry::github_token_present() {
                println!(
                    "\n  a host throttled us {throttled} time(s). The rate below is about our \
                     request budget as much as about the packages."
                );
            } else if throttled > 0 {
                println!(
                    "\n  a host throttled us {throttled} time(s), and no GITHUB_TOKEN is set — \
                     unauthenticated GitHub allows 60 requests an hour. Set one and re-run before \
                     believing the rate below."
                );
            }
        }

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
            assert_eq!(
                Outcome::Recorded("normalized".into(), None, *calls).model_calls(),
                3
            );
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
            // The seconds column, required. `watch::parse_results` and `sweep::completed` both
            // require it and this did not, so a half-written final row — purl and label flushed,
            // seconds not yet — was a target to `trigon score` and not a target to `trigon watch`,
            // and the two reported different rates for one file.
            f.next().filter(|s| !s.is_empty())?;
            let calls = f
                .nth(1)
                .filter(|c| !c.is_empty())
                .and_then(|c| c.parse::<u32>().ok());
            recorded |= calls.is_some();
            Some(trigon_ai::Observation {
                purl,
                outcome: label
                    .parse::<trigon_core::Match>()
                    .ok()
                    .map(|m| m.to_string()),
                // Per row. This was `calls.unwrap_or(0)` beside a `recorded` flag for the whole
                // file, so one counted row suppressed the caveat for every uncounted one and the
                // uncounted rows were summed in as zeroes — in the function whose own comment says
                // absent is not zero.
                model_calls: calls,
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
        // The total counts only the rows that carry a count. Where some rows do and some do not —
        // a sweep resumed across this column's introduction — saying so is the whole point: a
        // total presented as if it covered every target is a claim the file does not support.
        let unknown = observed.iter().filter(|o| o.model_calls.is_none()).count();
        if unknown == 0 {
            println!(
                "{} targets, {} model call(s)\n",
                corpus.labels.len(),
                card.model_calls
            );
        } else {
            println!(
                "{} targets, {} model call(s) across {} that recorded one; {unknown} did not\n",
                corpus.labels.len(),
                card.model_calls,
                observed.len() - unknown,
            );
        }
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
    // Not a regression and not a pass. The gate this command exists to hold is "no model fired on a
    // target labelled trivial-deterministic", and on a target whose count was never recorded that
    // check cannot be made. Reporting it as passed is how a gate stops being one.
    if !card.unknown_model_calls.is_empty() {
        println!(
            "\n  NOT CHECKED: these forbid a model and recorded no count, so the gate did not run:"
        );
        for p in &card.unknown_model_calls {
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
            (
                "stopped producing evidence (ours, not the rule's)",
                &f.lost_evidence,
            ),
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
            let hex = Hex::of(&store, &record).await?;
            let facts = facts(&record, &hex);
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

    /// The hex forms [`RunFacts`] borrows.
    ///
    /// `RunFacts` holds `&str` so that `trigon-attest` never has to own anything, and `to_hex`
    /// allocates — so the strings have to live somewhere outside the call. Somewhere was nowhere,
    /// which is why three byproduct digests were passed as `None`: the build log, the rendered
    /// instructions and now the network transcript were all in the record and none of them reached
    /// the statement. A statement that omits the bytes it is about is one nobody can check.
    #[derive(Default)]
    struct Hex {
        network_transcript: Option<(String, u64, u64)>,
        build_log: Option<String>,
        instructions: Option<String>,
    }

    impl Hex {
        /// The transcript's count and byte total are **counted from the blob**, never copied out of
        /// the record's `costs`. This process exists because the record was written by the one that
        /// ran the build: a number it was handed and a number it can check are different kinds of
        /// claim, and only the second belongs in something signed.
        async fn of(store: &Store, r: &RunRecord) -> Result<Self> {
            let network_transcript = match r.network_transcript {
                Some(d) => {
                    let bytes = store.blobs().get(&d).await.with_context(|| {
                        format!("reading the network transcript {} names", r.id)
                    })?;
                    let text = String::from_utf8_lossy(&bytes);
                    // Strict: a transcript blob we cannot read stops the attestation rather than
                    // being summarised as empty. An empty transcript is the claim that the build
                    // fetched nothing, and signing that off a parse failure is the one mistake
                    // this whole path exists to avoid.
                    let lines = trigon_mirror::Exchange::parse_jsonl(&text).map_err(|e| {
                        anyhow::anyhow!("the network transcript {} names cannot be read: {e}", r.id)
                    })?;
                    Some((
                        d.to_hex(),
                        lines.len() as u64,
                        lines.iter().map(|e| e.bytes).sum(),
                    ))
                }
                None => None,
            };
            Ok(Hex {
                network_transcript,
                build_log: r.build_log.map(|d| d.to_hex()),
                instructions: r.instructions.map(|d| d.to_hex()),
            })
        }
    }

    fn facts<'a>(r: &'a RunRecord, hex: &'a Hex) -> RunFacts<'a> {
        RunFacts {
            run_id: &r.id,
            started: &r.started,
            finished: r.finished.as_deref(),
            base_image: &r.environment.base_image,
            egress: &r.environment.egress,
            isolation: &r.environment.isolation,
            attestable: r.environment.attestable,
            network_transcript: hex
                .network_transcript
                .as_ref()
                .map(|(digest, requests, bytes)| trigon_attest::TranscriptRef {
                    digest,
                    requests: *requests,
                    bytes: *bytes,
                }),
            registry_moment: r.environment.registry_moment.as_deref(),
            pin_observed: r
                .environment
                .pin
                .map(|p| (p.index_requests, p.versions_withheld)),
            strategy_digest: r.strategy_digest.as_deref(),
            derivation: r.derivation.as_deref(),
            instructions: hex.instructions.as_deref(),
            build_log: hex.build_log.as_deref(),
            trigon_version: env!("CARGO_PKG_VERSION"),
            stabilizer_set: None,
            guard_trips: &r.guard_trips,
            refused_artifact: &r.refused_artifact,
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
