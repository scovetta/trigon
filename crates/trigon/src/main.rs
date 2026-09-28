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

/// Which Trigon this is: the crate version and the git revision it was built from, as `build.rs`
/// found it (`src/build_version.rs`). What `--version` prints, what a run records as the Trigon that
/// built it, and what a statement signs as the one that attested it.
const TRIGON_VERSION: &str = env!("TRIGON_BUILD_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "trigon",
    version = TRIGON_VERSION,
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

    /// The palette and flourishes for the human-readable output.
    ///
    /// `auto` (the default) colours when stdout is a terminal; `textnocolor` is always plain and
    /// `textcolor` always the base palette; `neon` brightens it; `bbs` adds the flourishes.
    /// `NO_COLOR` still overrides everything. This is a display choice, orthogonal to `--output
    /// text|json` — `json` is never themed.
    #[arg(long, value_enum, default_value_t = ThemeArg::Auto, global = true)]
    theme: ThemeArg,
}

/// The `--theme` values, named as the reader types them. Kept apart from [`style::Theme`] so `clap`
/// owns the surface and the style module owns the behaviour.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ThemeArg {
    Auto,
    Textcolor,
    Textnocolor,
    Neon,
    Bbs,
}

impl From<ThemeArg> for style::Theme {
    fn from(a: ThemeArg) -> Self {
        match a {
            ThemeArg::Auto => style::Theme::Auto,
            ThemeArg::Textcolor => style::Theme::Colour,
            ThemeArg::Textnocolor => style::Theme::Mono,
            ThemeArg::Neon => style::Theme::Neon,
            ThemeArg::Bbs => style::Theme::Bbs,
        }
    }
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
        /// `json` prints `subject`, `predicateType`, `outcome`, `signature` and `rederived`.
        ///
        /// Those five only. The key that carried an external log's entry for the bundle was
        /// removed with the log (ADR-0014), so a script that read it gets nothing there now.
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
        /// List every profile instead: how many passes each has, its digest, and what selects it.
        #[arg(long, conflicts_with = "profile")]
        list_profiles: bool,
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
        /// Base image: a digest, `auto`, or `derive`.
        ///
        /// `auto` uses a local image that already carries what the strategy needs, and builds one
        /// where none does — but not at an enforced egress tier, because building one means `apt-get`
        /// and that is network the run's transcript would never see. `derive` builds it anyway and
        /// records that it did: the parent, what was installed, and whether these bytes were built by
        /// this run. The build itself still runs at the tier you asked for.
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
        #[arg(long, default_value = MIRROR_IMAGE)]
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
        /// Write a DSSE-wrapped statement of the result here: `equivalence/v1` or `divergence/v1`,
        /// signed by the process that ran the build.
        ///
        /// It asks no publication gate, so a run at `--egress open` or one a stabilizer somebody
        /// wrote applied to is signed as a verdict here, where `trigon attest` would sign it as
        /// `void/v1`. For a claim that matters, record the run with `--store` and sign it with
        /// `trigon attest`.
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
        /// Let the mirror serve upstream bytes it already has, from this directory.
        ///
        /// Off by default: every run before this fetched everything, every time. Measured over one
        /// 186-run npm sweep that is 39 GB and 143,362 requests, of which **86.7% were repeats** —
        /// one packument alone was fetched 309 times for 6.89 GB. Artifacts and toolchains are
        /// immutable and shared permanently; index documents are scoped to this invocation,
        /// because a packument decides which versions exist and that is not a decision to inherit
        /// from last Tuesday. See `docs/adr/0013-a-cache-supplies-bytes-never-decisions.md`.
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Record the run — its artifacts, log, comparison and environment — in a store, so that a
        /// separate `trigon attest` can re-derive the claim and sign it without ever running a
        /// build. This is what makes the signing process separable from the one that executes
        /// attacker-supplied scripts.
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Create an ed25519 signing key.
    ///
    /// Deliberately available in the `--no-default-features` verifier too, which links no runtime
    /// and no network client. Generating a signing key on a machine that has never had a socket
    /// open is a reasonable thing to want, and nothing about making one needs the build half.
    ///
    /// This produces a **bare** key, which signs unchained statements: they verify against a
    /// pinned public key and against nothing else. That is the development and air-gapped case,
    /// and, until a root exists, it is also the key records are published under (ADR-0014
    /// Decision 8). ADR-0011's key under a certificate chaining to a published root would replace
    /// it; whether one is built is docs/19 D6.
    Keygen {
        /// Where to write the private key. Created `0600`, and refused if it already exists.
        #[arg(long, default_value = "./signing.key")]
        out: PathBuf,
        /// Also write the public key here, as SPKI PEM — the form `openssl` reads, and the one an
        /// evidence repository publishes its key in. The hex form is printed either way.
        #[arg(long, value_name = "PATH")]
        public_out: Option<PathBuf>,
    },
    /// Print the public half of a signing key.
    ///
    /// `keygen` prints it once, at the moment the key is made. This is how you get it back — and
    /// you need it every time anyone checks a signature, so a key whose public half can only be
    /// recovered by signing something and reading the key id off the output is a key nobody can
    /// pin. Reads the private key and computes; nothing is written.
    PublicKey {
        /// The private key file, as written by `keygen`.
        key: PathBuf,
        /// Print SPKI PEM instead of hex — the form `openssl` reads, and the one an evidence
        /// repository publishes its key in.
        #[arg(long)]
        pem: bool,
    },
    /// Sign what a stored run says, after re-deriving it from the bytes.
    ///
    /// A separate process from the one that ran the build, and that is the point: it reads blobs by
    /// hash, checks each against the hash it asked for, recomputes the claim, and only then signs.
    /// The process that ran the build could record any outcome it liked; an attestor that signed
    /// what it was told would launder that into a signature.
    ///
    /// Signs into the store and publishes nothing, so it opens no socket. Publishing is its own
    /// step, behind the publication gate (`docs/19-distribution-and-lookup.md` §3).
    ///
    /// A run the gate calls void — its guard tripped, it ran at open egress, or a stabilizer
    /// somebody wrote applied — is signed as `void/v1` and nothing else, never as a verdict. Any
    /// other run gets `equivalence/v2` or `divergence/v2`, with `rebuild/v1` and
    /// `buildobservation/v1` beside it. `[publish] origin` and `disputes` in `evidence.toml`, when
    /// both are set, are signed into the verdict's falsifying command and dispute pointer.
    #[cfg(feature = "build")]
    Attest {
        /// The store the run was written to, and where a withdrawal is filed.
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
        /// A published record file this run's statement supersedes. It is signed into the
        /// statement with `--reason`, and refused unless the record is about this run's artifact
        /// and purl.
        #[arg(
            long,
            value_name = "RECORD",
            requires = "reason",
            conflicts_with = "withdraw"
        )]
        supersedes: Option<PathBuf>,
        /// Withdraw a published record: sign a `withdrawal/v1` naming it and `--reason`, with no
        /// verdict and no run. Filed in the store under the record's digest.
        #[arg(
            long,
            value_name = "RECORD",
            requires = "reason",
            conflicts_with_all = ["run", "prune"]
        )]
        withdraw: Option<PathBuf>,
        /// Why the record is superseded.
        #[arg(
            long,
            value_parser = clap::builder::PossibleValuesParser::new(
                trigon_attest::SupersedeReason::ALL.map(trigon_attest::SupersedeReason::as_str)
            )
        )]
        reason: Option<String>,
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
    /// Check a lockfile or SBOM against what a store holds, with an explicit *never checked* row.
    ///
    /// The one view that starts from something you already have. Everything else assumes you care
    /// about a package we happen to have scanned.
    ///
    /// Reads `package-lock.json`, `npm-shrinkwrap.json`, `requirements.txt` and SPDX JSON, chosen
    /// by file name rather than sniffed, so a file pointed at by mistake is refused instead of
    /// reported as zero packages.
    ///
    /// **Five rows, never four.** `unsupported` counts runs that reached no verdict and
    /// `never checked` counts packages with no run; neither is a statement about the package, and
    /// neither is summed with the three verdicts above them. No overall percentage is printed,
    /// because a single rate needs one denominator and there are three here.
    #[cfg(feature = "build")]
    Check {
        /// The lockfile or SBOM.
        file: PathBuf,
        /// `text` for a terminal, `json` for a script, `sarif` for a code-scanning UI.
        #[arg(long, default_value = "text", value_parser = ["text", "json", "sarif"])]
        format: String,
        #[arg(long, default_value = "./trigon-store")]
        store: PathBuf,
    },
    /// List the runs a store holds.
    #[cfg(feature = "build")]
    Runs {
        #[arg(long, default_value = "./trigon-store")]
        store: PathBuf,
    },
    /// Fill in how a stored run was normalized: per-field attribution and the pass-by-pass
    /// progression, for runs judged before either was recorded.
    ///
    /// Re-derives each comparison from the two artifacts in the store under the stabilizer set the
    /// run was judged with, and writes it **beside** the original under `derived/` only when it
    /// agrees with the original on the verdict, the digests and the difference signature. The run
    /// record and its comparison are never changed. A run judged under a set this binary no longer
    /// has is skipped, because a different set would explain a different verdict.
    #[cfg(feature = "build")]
    Rederive {
        #[arg(long, default_value = "./trigon-store")]
        store: PathBuf,
        /// Runs to re-derive. Every run in the store when omitted.
        runs: Vec<String>,
        /// Re-derive even where a derivation, or a judge-time progression, already exists.
        #[arg(long)]
        force: bool,
        /// Say what would be written, and write nothing.
        #[arg(long)]
        dry_run: bool,
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
        ///
        /// Takes a list: `--packages python3 python3-venv`, comma-separated, or the flag repeated.
        /// All three, because that is the form a failing build prints for you to paste — and a
        /// suggestion the suggesting program rejects is worse than no suggestion.
        #[arg(long, num_args = 1.., value_delimiter = ',')]
        packages: Vec<String>,
        /// Also vendor the PCL reference assemblies that .NETPortable targets need.
        ///
        /// About a megabyte, extracted and not installed. NuGet ships no package for these — every
        /// plausible id returns nothing — and the only public source is Mono's
        /// `referenceassemblies-pcl`. Without them a `.NETPortable` target fails `MSB3644` with
        /// advice to install a Windows Developer Pack, which reads as a dead end and is not one:
        /// the .NET Framework targets need nothing at all, and only PCL needs this.
        ///
        /// Off by default because it is a network fetch from outside the distribution's archive,
        /// and most images will never build a PCL target.
        #[arg(long)]
        pcl_reference_assemblies: bool,
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
        #[arg(long, default_value = MIRROR_IMAGE)]
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
        /// Serve upstream bytes from this directory where they are already in it.
        ///
        /// Behind the mirror, never in front of it: the guard still runs first, every body still
        /// goes through the same hashing stream, and the transcript is byte for byte what it would
        /// have been. See ADR-0013.
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Which invocation index entries belong to.
        ///
        /// An artifact is immutable and shared by every run on the machine. An index document
        /// decides which versions exist, so it is scoped to one invocation rather than given a
        /// lifetime — staleness bounded by construction instead of by a number somebody picked.
        #[arg(long, requires = "cache")]
        cache_scope: Option<String>,
        /// Prune the cache to this many bytes at startup, oldest first.
        #[arg(long, requires = "cache")]
        cache_max_bytes: Option<u64>,
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
        /// Base image: a digest, `auto`, or `derive`.
        ///
        /// One image for every target in the sweep. `derive` may build one, with network, before
        /// a build — recorded on each run that derived, not once in the sweep's header.
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
        #[arg(long, default_value = MIRROR_IMAGE)]
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
        /// Let the mirror serve upstream bytes it already has, from this directory.
        ///
        /// Off by default: every run before this fetched everything, every time. Measured over one
        /// 186-run npm sweep that is 39 GB and 143,362 requests, of which **86.7% were repeats** —
        /// one packument alone was fetched 309 times for 6.89 GB. Artifacts and toolchains are
        /// immutable and shared permanently; index documents are scoped to this invocation,
        /// because a packument decides which versions exist and that is not a decision to inherit
        /// from last Tuesday. See `docs/adr/0013-a-cache-supplies-bytes-never-decisions.md`.
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Stop after this many targets fail the same way with none succeeding between them.
        ///
        /// **A wall is a claim about the corpus, not only about the run.** Ten identical failures
        /// in a row on a corpus chosen because every target has a `gitHead` means something broke —
        /// throttling, a full disk, a stopped daemon — and spending the night proving it is waste.
        /// On a corpus sampled at random from a registry, ten `no-strategy` in a row is the
        /// finding: most of what is published declares no repository. The first sweep of
        /// `corpora/random-125.txt` stopped after ten targets for exactly that reason.
        ///
        /// `0` turns it off, for a corpus whose answer is expected to be homogeneous.
        #[arg(long, default_value_t = 10)]
        wall: u32,
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
    /// Serve the corpus: browse, search and read every run in a store, from a browser.
    ///
    /// Not `watch`, and the difference is the point. `watch` reads a **work directory** — one
    /// sweep, live, on this disk, loopback only, correct even after the sweep it watches has
    /// died. `serve` reads a **store**: the corpus, historical, over an object store that may be
    /// a bucket, and it is the surface a decoupled front-end talks to. See
    /// `docs/22-management-layer.md`.
    #[cfg(feature = "build")]
    Serve {
        /// The store to read. A local directory, or anything `trigon-store` can open.
        store: PathBuf,
        /// Loopback by default, for the reason `watch` is: a store holds build logs that have not
        /// been redacted, and `--public` is what makes it safe to bind anywhere else.
        #[arg(long, default_value = "127.0.0.1:8100")]
        bind: String,
        /// Treat unauthenticated callers as the public rather than as an operator.
        ///
        /// Turns on both halves of `docs/22` §7: the ADR-0010 publication gate, so only results
        /// with two agreeing attempts and a restricted egress tier are shown; and the evidence
        /// class table, so no build log, network transcript or comparison leaves the process. Set
        /// this before binding to anything but loopback. Leaving it off on a routable address
        /// publishes unredacted build logs.
        #[arg(long)]
        public: bool,
        /// Stop publishing divergences. ADR-0010's fifth safeguard, which exists so that crossing
        /// a false-mismatch threshold is something a human can act on in one command.
        ///
        /// Matches are unaffected: a false match is an error and a false divergence is an
        /// accusation, and the two do not deserve the same switch.
        #[arg(long)]
        stop_divergences: bool,
        /// How often to look for runs written since startup. Zero serves a fixed snapshot.
        #[arg(long, default_value_t = 30)]
        refresh_seconds: u64,
        /// The queue this site may put requested rebuilds on.
        ///
        /// Without it the site is read-only: it serves the corpus and answers every write route
        /// with "this instance has no queue" rather than accepting a request it cannot honour.
        #[arg(long)]
        queue: Option<String>,
    },
    /// Give somebody a credential for `trigon serve`.
    ///
    /// Prints the token **once**; only its digest is stored, so a stolen database yields no
    /// credentials. Re-running with the same id rotates the quota and scopes and adds a token
    /// rather than replacing one, because revoking is a separate decision from issuing.
    #[cfg(feature = "build")]
    Grant {
        /// The queue holding the identity tables.
        queue: String,
        /// A stable id for the principal. Appears in every audit row.
        id: String,
        /// What to call them on a page.
        #[arg(long)]
        name: Option<String>,
        /// `request`, `review`, `operate`. Read access needs none of these — reading is anonymous.
        #[arg(long, default_value = "request")]
        scopes: String,
        /// How many rebuilds a day. Enforced where work is admitted, not reported afterwards.
        #[arg(long, default_value_t = 20)]
        daily_quota: i64,
    },
    /// Take work off a queue and rebuild what it names.
    ///
    /// One worker. Run several against the same queue on as many machines as you like: a job goes
    /// to exactly one of them, a worker that dies releases its job without anybody noticing, and
    /// the run and the acknowledgement land in one transaction so nothing is built twice.
    #[cfg(feature = "build")]
    Worker {
        /// `sqlite:///var/lib/trigon/queue.db` or `postgres://…`.
        queue: String,
        /// Base image: a digest, `auto`, or `derive`.
        ///
        /// `auto` uses a local image that already carries what the strategy needs, and builds one
        /// where none does — but not at an enforced egress tier, because building one means `apt-get`
        /// and that is network the run's transcript would never see. `derive` builds it anyway and
        /// records that it did: the parent, what was installed, and whether these bytes were built by
        /// this run. The build itself still runs at the tier you asked for.
        #[arg(long)]
        image: String,
        /// Where builds happen. One directory per job and attempt underneath.
        #[arg(long)]
        work: PathBuf,
        /// Where records and blobs go. Every worker points at the same one.
        #[arg(long)]
        store: PathBuf,
        /// The egress tier every job runs at.
        ///
        /// A property of the **worker**, never of the job: the shipped default elsewhere is `open`,
        /// which adds no network isolation, and a job payload that could name a tier would let
        /// whoever enqueued it ask for an unsandboxed build. See `docs/22-management-layer.md` §2.4.
        #[arg(long, default_value = "mirror-only", value_parser = ["deny-all", "mirror-only", "git-and-mirror", "open"])]
        egress: String,
        /// What this worker may do: `infer`, `build` or `judge`.
        ///
        /// A capability, not a hint. `docs/12-security.md` §2.6: the judge reads the upstream
        /// artifact and the build worker has to be unable to, or a build can reproduce the artifact
        /// by copying it out of our own storage. A worker asked for jobs outside its class is
        /// refused rather than quietly given the subset it may have.
        ///
        /// `build` is the only class with a worker today, because the `rebuild` job still runs
        /// inference, the build and the comparison in one process. See `docs/17-backlog.md` B32.
        #[arg(long, default_value = "build", value_parser = ["infer", "build", "judge"])]
        class: String,
        /// Names this worker in every lease and every event. Defaults to host and pid, which is
        /// what answers "which process held this" months later, from a row.
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
        #[arg(long)]
        definitions: Option<PathBuf>,
        #[arg(long, default_value = MIRROR_IMAGE)]
        mirror_image: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        source_cache: Option<PathBuf>,
        /// Create the queue's tables if they are not there.
        #[arg(long)]
        migrate: bool,
        /// Take one batch and stop. For a cron, and for checking a deployment.
        #[arg(long)]
        once: bool,
        /// Do not enqueue a confirming second attempt after a verdict.
        ///
        /// ADR-0010 safeguard 1 needs two agreeing attempts before anything publishes, so a fleet
        /// run this way produces results no public reader will ever be shown. For a private corpus
        /// where that is the intent, and it says so rather than being discovered later.
        #[arg(long)]
        no_confirm: bool,
    },
    /// Put targets on a queue for workers to pick up.
    #[cfg(feature = "build")]
    Enqueue {
        /// `sqlite://…` or `postgres://…`.
        queue: String,
        /// Package URLs, or `-` to read them one per line from stdin.
        #[arg(required = true)]
        targets: Vec<String>,
        /// `interactive`, `regression`, or `bulk`.
        ///
        /// A sweep is `bulk` and should stay there: the tier exists so that somebody waiting on a
        /// single answer is not queued behind five thousand of them.
        #[arg(long, default_value = "bulk")]
        tier: String,
        /// Create the queue's tables if they are not there.
        #[arg(long)]
        migrate: bool,
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
        /// Base image: a digest, `auto`, or `derive`.
        ///
        /// `auto` uses a local image that already carries what the strategy needs, and builds one
        /// where none does — but not at an enforced egress tier, because building one means `apt-get`
        /// and that is network the run's transcript would never see. `derive` builds it anyway and
        /// records that it did: the parent, what was installed, and whether these bytes were built by
        /// this run. The build itself still runs at the tier you asked for.
        ///
        /// A tag is refused: it resolves to different bytes on different days, which makes the
        /// run unreproducible.
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
        #[arg(long, default_value = MIRROR_IMAGE)]
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
    // The package under test, so a member arriving inside one of its *own* other releases can be
    // told from one arriving inside somebody else's package.
    trigon_mirror::voiding(&mirror.arrived(), rebuilt.as_ref(), mirror.withheld())
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
    rfc3339_from_unix(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// A unix second as RFC 3339 UTC.
///
/// Split from [`now_rfc3339`] when the fetch cache needed to render an instant it was handed rather
/// than the current one. The mirror stores seconds because it has no formatter and this repository
/// already carries five copies of the one it would need; this is the caller that has one.
#[cfg(feature = "build")]
fn rfc3339_from_unix(secs: u64) -> String {
    let secs = secs as i64;
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

/// Colour and alignment for the human-readable output. Not gated: the verifier's `verify` prints a
/// verdict too, and it should read as well as a build's does.
mod style;

#[cfg(feature = "build")]
mod decompile;
#[cfg(feature = "build")]
mod dotnet;
#[cfg(feature = "build")]
mod progress;
#[cfg(feature = "build")]
mod provenance;
#[cfg(feature = "build")]
mod watch;
#[cfg(feature = "build")]
mod worker;

#[cfg(feature = "build")]
mod check;
#[cfg(feature = "build")]
mod rederive;

fn main() -> Result<()> {
    exit_quietly_on_broken_pipe();
    let cli = Cli::parse();
    // Before any output: the palette functions read this, and the first write must already know it.
    style::set_theme(cli.theme.into());
    init_logging(cli.verbose, cli.log_json);
    let result = dispatch(cli.cmd, cli.verbose > 0);
    if let Err(e) = &result {
        report_fault(e);
        // `docs/19` §6 gives the tool failing before it could answer exit 5, and a configuration
        // that cannot be read is that: an `evidence.toml` with an unknown key, a pin that does not
        // parse, a command that needs a source and has none. Printed as `main` would print it.
        if let Some(c) = e.downcast_ref::<trigon_attest::config::ConfigError>() {
            eprintln!("Error: {e:?}");
            std::process::exit(c.exit_code());
        }
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

///  reaches only the worker, which is the one command that hands it on to a build it did
/// not itself start. Everything else reads it through the tracing subscriber.
fn dispatch(cmd: Cmd, verbose: bool) -> Result<()> {
    let _ = verbose;
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
            Rerun {
                upstream: upstream.as_deref(),
                rebuild: rebuild.as_deref(),
                stabilizers: stabilizers.as_deref(),
            },
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
        Cmd::Stabilizers {
            profile: prof,
            list_profiles,
        } => {
            if list_profiles {
                list_profiles_cmd()
            } else {
                stabilizers(&prof)
            }
        }
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
            cache,
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
            // One target, so its own scope: an index document is a decision and there is nobody
            // here to share one with. The artifact tier is shared with every run on the machine,
            // which is the half that is immutable.
            fetch_cache: cache.map(|c| (c, format!("run-{}", std::process::id()))),
            // One target on a terminal: the phases are already in front of whoever asked.
            phases: None,
            // **No key, deliberately.** A `trigon rebuild` is one person asking one question, and
            // inventing a key here would make two unrelated local runs look to the publication
            // gate like a confirmed pair. Confirmation is something a queue arranges, between two
            // attempts it knows are attempts at the same work.
            cache_key: None,
            attempt: 1,
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
            cache,
            wall,
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
            // **One scope for the whole sweep**, which is where the prize is. Only 8% of index
            // fetches repeat within a single target; the 309 fetches of `registry.npmjs.org/npm`
            // that were 18% of one sweep's egress were spread across its targets. A resumed sweep
            // is a new invocation and gets a new scope, which is the conservative answer.
            fetch_cache: cache.map(|c| (c, format!("sweep-{}", std::process::id()))),
            wall,
        }),
        Cmd::Keygen { out, public_out } => keygen(&out, public_out.as_deref()),
        Cmd::PublicKey { key, pem } => {
            let k = load_key(&key)?;
            print!(
                "{}",
                if pem {
                    k.public_pem()
                } else {
                    k.public_hex() + "\n"
                }
            );
            Ok(())
        }
        #[cfg(feature = "build")]
        Cmd::Attest {
            store,
            run,
            key,
            prune,
            supersedes,
            withdraw,
            reason,
        } => attestor::run(attestor::Args {
            store,
            run,
            key,
            prune,
            supersedes,
            withdraw,
            // The parser admits only the closed list, so this parses.
            reason: reason.map(|r| r.parse()).transpose()?,
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
        Cmd::Serve {
            store,
            bind,
            public,
            stop_divergences,
            refresh_seconds,
            queue,
        } => serve_corpus(
            &store,
            bind,
            public,
            stop_divergences,
            refresh_seconds,
            queue,
        ),
        #[cfg(feature = "build")]
        Cmd::Grant {
            queue,
            id,
            name,
            scopes,
            daily_quota,
        } => grant(&queue, &id, name.as_deref(), &scopes, daily_quota),
        #[cfg(feature = "build")]
        Cmd::Worker {
            queue,
            image,
            work,
            store,
            egress,
            class,
            name,
            timeout,
            definitions,
            mirror_image,
            model,
            source_cache,
            migrate,
            once,
            no_confirm,
        } => worker::serve(
            &queue,
            worker::Builder {
                image,
                egress,
                work,
                store,
                timeout,
                definitions,
                mirror_image,
                model,
                source_cache,
                verbose,
            },
            trigon_engine::Config {
                worker: name.unwrap_or_else(|| {
                    format!(
                        "{}-{}",
                        std::env::var("HOSTNAME").unwrap_or_else(|_| "host".into()),
                        std::process::id()
                    )
                }),
                class: match class.as_str() {
                    "infer" => trigon_engine::Class::Infer,
                    "judge" => trigon_engine::Class::Judge,
                    // `value_parser` above admits only the three, so this is the third and not a
                    // default standing in for an unrecognised one.
                    _ => trigon_engine::Class::Build,
                },
                confirm: !no_confirm,
                ..Default::default()
            },
            migrate,
            once,
        ),
        #[cfg(feature = "build")]
        Cmd::Enqueue {
            queue,
            targets,
            tier,
            migrate,
        } => enqueue_targets(&queue, &targets, &tier, migrate),
        #[cfg(feature = "build")]
        Cmd::Check {
            file,
            format,
            store,
        } => check::run(&file, &store, &format),
        #[cfg(feature = "build")]
        Cmd::Runs { store } => attestor::list(&store),
        #[cfg(feature = "build")]
        Cmd::Rederive {
            store,
            runs,
            force,
            dry_run,
        } => rederive::run(rederive::Args {
            store,
            runs,
            force,
            dry_run,
        }),
        #[cfg(feature = "build")]
        Cmd::BaseImage {
            from,
            packages,
            pcl_reference_assemblies,
            tag,
            print,
        } => mirror::base_image(&from, &packages, &tag, print, pcl_reference_assemblies),
        #[cfg(feature = "build")]
        Cmd::MirrorImage { tag } => mirror::build_image(&tag),
        #[cfg(feature = "build")]
        Cmd::Mirror {
            port,
            guard,
            cache,
            cache_scope,
            cache_max_bytes,
        } => mirror::serve(
            port,
            guard.as_deref(),
            cache.as_deref(),
            cache_scope.as_deref(),
            cache_max_bytes,
        ),
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
            // One strategy, run by hand. There is nothing for it to share with anybody.
            None,
            // No purl here, so no ecosystem to take a toolchain from. `--image auto` on this path
            // derives from a distribution parent and nothing more.
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
                println!("{}", style::heading(&resolved.reference.to_string()));
                if let Some(t) = &resolved.intrinsics.publish_time {
                    println!("  {} {t}", style::label_col("published"));
                }
                match &resolved.source {
                    // The rung is printed, not just the answer. A registry-recorded commit and a
                    // fuzzy tag match are both "a commit", and they should not be read alike.
                    Some(s) if !s.commit.is_empty() => {
                        field(
                            "source",
                            format!("{} @ {}", s.repo_url, style::ident(&short_ref(&s.commit))),
                        );
                        field("found by", format!("{:?}", s.how));
                    }
                    Some(s) => {
                        field(
                            "source",
                            format!("{} {}", s.repo_url, style::muted("(no commit)")),
                        );
                        match &tag {
                            Some((sha, name, how)) => {
                                field(
                                    "tag",
                                    format!("{name} -> {}", style::ident(&short_ref(sha))),
                                );
                                field(
                                    "found by",
                                    format!("{how:?}, which is what a rebuild would use"),
                                );
                                // The caveat is the point. A tag is a mutable reference: it can be
                                // moved or deleted after a release, and `pad-left 2.1.0` in the
                                // corpus is a package whose recorded commit was force-pushed away.
                                // What a tag gives is a good approximation, and a divergence
                                // against one has to be read against that.
                                field_wrapped(
                                    "",
                                    "a tag is mutable — it can be moved after the release, so this \
                                     identifies the commit the tag points at today rather than the \
                                     one that was published",
                                    style::muted,
                                );
                            }
                            None => {
                                field("found by", format!("{:?}", s.how));
                                field_wrapped(
                                    "",
                                    "no tag matches this version, so something stronger has to \
                                     find the commit",
                                    style::muted,
                                );
                            }
                        }
                    }
                    None => field("source", style::muted("not declared")),
                }
                println!("\n  {}", style::heading("artifacts"));
                let w = resolved
                    .artifacts
                    .iter()
                    .map(|a| a.id.as_str().len())
                    .max()
                    .unwrap_or(0);
                for a in &resolved.artifacts {
                    // Every algorithm the registry declared, not only sha256: npm declares sha512
                    // and sha1 and never sha256, and printing "no sha256 declared" for it read as
                    // though npm vouched for nothing.
                    let digest = if a.declared.is_empty() {
                        style::muted(a.declared_note.as_deref().unwrap_or("no digest declared"))
                    } else {
                        let named: Vec<String> = a
                            .declared
                            .iter()
                            .map(|d| {
                                let shown = &d.value[..16.min(d.value.len())];
                                format!("{}:{shown}", d.algorithm)
                            })
                            .collect();
                        style::ident(&named.join("  "))
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

        let fetched = keep_if_fetched(&path, |file| rt.block_on(registry.fetch(meta, file)))?;

        println!("{}", style::heading(&path.display().to_string()));
        field("sha256", style::ident(&short(&fetched.sha256.to_hex())));
        // One line per declaration: which algorithm, from which field, and what came of it. A
        // single "checked" line could not say that npm declares two digests and PyPI three.
        for c in &fetched.checks {
            let what = format!("{} ({})", c.declared.algorithm, c.declared.source);
            match c.result {
                trigon_core::CheckResult::Matched => {
                    field("checked", style::good(&format!("{what} matches")))
                }
                trigon_core::CheckResult::Unchecked => field(
                    "declared",
                    style::muted(&format!("{what}, which this build cannot compute")),
                ),
            }
        }
        // The note whenever nothing was checked, and not only when nothing was declared: a file
        // whose every declaration is of an algorithm this build cannot compute was checked against
        // nothing too, and the lines above alone do not say so.
        let matched = fetched
            .checks
            .iter()
            .any(|c| c.result == trigon_core::CheckResult::Matched);
        if !matched && let Some(note) = &fetched.note {
            field("checked", style::muted(note));
        }
        Ok(())
    }

    /// Stream a download to `path` through `fetch`, and keep it only if `fetch` succeeds.
    ///
    /// **Refused means not kept.** Bytes the registry does not vouch for, or half a download, left
    /// under the artifact's own name are one `ls` away from being mistaken for it. So a download to
    /// a regular file, or to a name nothing holds yet, is written beside it under a name of its own
    /// and renamed onto it once the checks hold. A failed one removes only that staging file, which
    /// this command created, and leaves whatever was at `path` as it was rather than truncated.
    ///
    /// Anything else at `path` — `/dev/stdout`, a FIFO, a symlink — is written in place and never
    /// removed. The first version unlinked `path` on any error, and `--out /dev/null` run as root
    /// with the registry unreachable deleted `/dev/null`; renaming onto one would replace it too.
    pub(crate) fn keep_if_fetched<T>(
        path: &Path,
        fetch: impl FnOnce(&mut std::fs::File) -> Result<T, trigon_registry::RegistryError>,
    ) -> Result<T> {
        let regular = match std::fs::symlink_metadata(path) {
            Ok(m) => m.file_type().is_file(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        if !regular {
            let mut file = std::fs::File::create(path)
                .with_context(|| format!("opening {}", path.display()))?;
            return fetch(&mut file).with_context(|| {
                format!(
                    "{} is not a regular file, so the download was written to it in place and it \
                     is left as it is: whatever it received is not bytes the registry vouched for",
                    path.display()
                )
            });
        }

        let name = path
            .file_name()
            .with_context(|| format!("{} names no file to write", path.display()))?;
        let staging = path.with_file_name(format!(
            ".{}.{}.partial",
            name.to_string_lossy(),
            std::process::id()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .with_context(|| format!("creating {}", staging.display()))?;
        let fetched = fetch(&mut file);
        drop(file);
        let kept = fetched.map_err(anyhow::Error::from).and_then(|f| {
            std::fs::rename(&staging, path)
                .with_context(|| format!("moving the download onto {}", path.display()))?;
            Ok(f)
        });
        if kept.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
        kept
    }

    #[cfg(test)]
    mod keep_if_fetched_tests {
        use super::keep_if_fetched;
        use trigon_registry::{BlobSink as _, RegistryError};

        fn dir(what: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!(
                "trigon-keep-if-fetched-{}-{what}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        fn refused() -> RegistryError {
            RegistryError::Http {
                ecosystem: "npm".into(),
                url: "http://127.0.0.1:0/x".into(),
                status: 503,
            }
        }

        fn names(d: &std::path::Path) -> Vec<String> {
            let mut n: Vec<String> = std::fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            n.sort();
            n
        }

        #[test]
        fn a_download_that_holds_lands_under_its_name_and_nothing_else_is_left() {
            let d = dir("kept");
            let path = d.join("left-pad-1.3.0.tgz");
            keep_if_fetched(&path, |f| {
                f.write(b"the bytes").map_err(RegistryError::from)
            })
            .unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"the bytes");
            assert_eq!(names(&d), ["left-pad-1.3.0.tgz"]);
        }

        #[test]
        fn a_refused_download_leaves_nothing_new_and_what_was_there_untouched() {
            let d = dir("refused");
            let fresh = d.join("fresh.tgz");
            let e = keep_if_fetched(&fresh, |f| {
                f.write(b"half a download")?;
                Err::<(), _>(refused())
            })
            .unwrap_err();
            assert!(e.to_string().contains("503"), "{e}");
            assert!(names(&d).is_empty(), "{:?}", names(&d));

            // An earlier download under the same name is not truncated by a later one that fails.
            let earlier = d.join("earlier.tgz");
            std::fs::write(&earlier, b"an earlier, good download").unwrap();
            keep_if_fetched(&earlier, |f| {
                f.write(b"bytes nobody vouched for")?;
                Err::<(), _>(refused())
            })
            .unwrap_err();
            assert_eq!(
                std::fs::read(&earlier).unwrap(),
                b"an earlier, good download"
            );
            assert_eq!(names(&d), ["earlier.tgz"]);
        }

        #[cfg(unix)]
        #[test]
        fn what_is_not_a_regular_file_is_written_in_place_and_never_removed() {
            // Standing in for `/dev/null` or `/dev/stdout`, which a test cannot safely risk: a
            // path this command did not create as a file. The error path must not unlink it.
            let d = dir("in-place");
            let target = d.join("target");
            std::fs::write(&target, b"").unwrap();
            let link = d.join("link.tgz");
            std::os::unix::fs::symlink(&target, &link).unwrap();

            let e = keep_if_fetched(&link, |f| {
                f.write(b"partial")?;
                Err::<(), _>(refused())
            })
            .unwrap_err();
            assert!(
                std::fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the error path removed a path it did not create"
            );
            assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
            assert_eq!(names(&d), ["link.tgz", "target"]);

            keep_if_fetched(&link, |f| f.write(b"whole").map_err(RegistryError::from)).unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"whole");
            assert!(
                std::fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
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
    #[derive(Clone)]
    pub struct Built {
        /// Exactly `transcript.is_some()`; see [`trigon_sandbox::BuildOutcome::attestable`].
        pub attestable: bool,
        /// The boundary the runner actually achieved, in its serde spelling.
        ///
        /// Carried because the signed predicate has a field for it and was writing `""`: the value
        /// reached a `println!` and stopped there, so nineteen statements described an unbounded
        /// build. What the runner reports, never what the flag asked for — the same rule
        /// `attestable` above is under.
        pub isolation: String,
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
        /// Every time an upstream host told the mirror to slow down during this build.
        pub throttled: Vec<trigon_mirror::Throttled>,
        /// Why this SDK, where the run had to choose one.
        ///
        /// **Carried out to the report's assumptions.** A compiled ecosystem's divergence is as
        /// likely to be the toolchain as the source — the NuGet rung's own assumption says exactly
        /// that — and a reader who cannot see which SDK was chosen, or why, cannot tell the two
        /// apart. `Environment.base_image` names the bytes; this names the reasoning.
        pub sdk_choice: Option<String>,
        /// Where each body the mirror served came from: the network, or its own disk.
        pub asked: Vec<trigon_mirror::Asked>,
        /// Guarded members that arrived over the network and are **not** in the rebuilt artifact.
        ///
        /// The bytes came in and did not come out, which is not the harm the guard exists to catch
        /// — so the run stands. Carried anyway, and for the same reason as `refused_artifact`: a
        /// control whose near-misses are invisible cannot be told from one that never fires.
        pub guard_notes: Vec<String>,
        /// What this run built its base image from, where it built one. See
        /// [`trigon_store::DerivedImage`]; `None` means this run derived nothing.
        pub derived_image: Option<trigon_store::DerivedImage>,
        /// The image the build actually ran on, resolved.
        ///
        /// **Carried because `Environment.base_image` was recording the flag.** `--image auto`
        /// resolves at render time, inside this function, into a binding that never escaped it —
        /// so every `auto` run wrote the literal word `auto` where the record says "pinned by
        /// digest. A tag would make the record unreproducible by anyone else." Measured on this
        /// machine's store: **205 records name no image at all.**
        ///
        /// `sdk_choice` above already says "`Environment.base_image` names the bytes; this names
        /// the reasoning" — the intent was written down and the value never travelled. Same shape
        /// as `isolation` two fields up, which reached a `println!` and stopped there while
        /// nineteen signed statements described an unbounded build.
        pub base_image: String,
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
        // Where the mirror may keep upstream bytes, and which invocation its index entries
        // belong to. `None` fetches everything every time.
        fetch_cache: Option<&(PathBuf, String)>,
        // A runtime the image has to carry because nothing in the evidence pins one — `dotnet`
        // today, and nothing else. Passed by the caller, which knows the ecosystem; the better
        // shape is a `toolchain:` line the tool itself declares, beside its `needs:`, which is not
        // built because it would change the plan hash for every target.
        toolchain: Option<&str>,
        // When the registry says this version was published.
        //
        // **From the resolution, not from the strategy's `registry_time`.** The first version read
        // that timewarp parameter, which only exists when a run is timewarping — so at
        // `--egress open` there was no instant at all, and the SDK choice fell through to "the
        // newest this tool knows of, and a guess". The publish time is a fact about the package
        // that the resolver already holds either way.
        published: Option<&str>,
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

        // **Which SDK, from the evidence rather than from a constant.** A package is built with
        // whatever SDK the publisher's CI had installed — the newest that existed when it was
        // published — so the publish instant leads. `registry_time` is already in the strategy, put
        // there for the dependency timewarp; this is the same evidence applied to the toolchain.
        // Two things override that lead: a `global.json` pins the SDK outright, and the project's
        // declared `TargetFramework` is a floor — an SDK older than it cannot build the project,
        // and says so as `NETSDK1045` — that pulls the choice up when the target is newer than
        // anything that had shipped.
        //
        // All best effort. A checkout that is not on disk yields no floor and no pin, a strategy
        // with no moment yields no publish date, and `choose` says which of them it had.
        let sdk_major = (toolchain == Some("dotnet")).then(|| {
            // The host-side checkout where there is one, and the source cache otherwise. At
            // `--egress open` nothing is fetched host-side — the clone happens in the container —
            // but a rung that read the repository to find a commit will have left one here, and a
            // project file is a project file wherever it is read from.
            let subdir = instructions.location.subdir.as_deref();
            let cache_dir = || {
                let dir = crate::provenance::checkout_dir(
                    &trigon_registry::SourceCache::default_root(),
                    &instructions.location.repo,
                    &instructions.location.commit,
                );
                dir.is_dir().then_some(dir)
            };
            let project = source_tree
                .as_deref()
                .and_then(|root| crate::dotnet_project_text(root, subdir))
                .or_else(|| cache_dir().and_then(|d| crate::dotnet_project_text(&d, subdir)));
            // A global.json pins the SDK, and pins it over both the target framework and the
            // publish date — the same two roots, read the same two ways.
            let global_json = source_tree
                .as_deref()
                .and_then(|root| crate::dotnet_global_json(root, subdir))
                .or_else(|| cache_dir().and_then(|d| crate::dotnet_global_json(&d, subdir)));
            let (major, why) =
                crate::dotnet::choose(project.as_deref(), global_json.as_deref(), published);
            println!(
                "  {} {}",
                style::label_col("sdk"),
                style::muted(&style::wrap(
                    &format!(".NET {major}: {why}"),
                    style::VALUE_COL
                ))
            );
            (major, why)
        });
        let sdk_why = sdk_major.as_ref().map(|(_, w)| w.clone());
        let sdk_major = sdk_major.map(|(m, _)| m);

        // **`auto` and `derive`, resolved here and nowhere earlier.** The required set is
        // `instructions.requires.system_deps`, which only exists once the strategy has rendered —
        // and resolving before it exists would mean guessing, or deriving an image per target from
        // a set nobody computed. This is a pre-flight: no container has started, so a refusal
        // costs nothing and a derivation happens once for a set rather than once per failure.
        //
        // The two values differ in one thing only, and it is the thing below.
        let resolved = if image == "auto" || image == "derive" {
            let deps: Vec<String> = instructions.requires.system_deps.iter().cloned().collect();
            // **Derivation is `apt-get`, and `apt-get` is network.** At an enforced tier the run's
            // whole claim is that everything crossing into it was accounted for, and an image
            // built moments earlier by fetching from a distribution archive is bytes the egress
            // transcript never saw. B7 is the precedent: it was closed by moving the image build
            // *inside* the boundary rather than by letting it happen outside and not counting it.
            //
            // `--image derive` is the operator saying they want it anyway. That is a real choice
            // and not a loophole, because the alternative every operator already takes is worse:
            // `scripts/rebuild-and-attest.sh` derives an image by hand, at `mirror-only`, and
            // records nothing anywhere. Doing it inside the run is what makes it recordable —
            // `Environment.derived_image` carries the parent, the packages and whether these
            // bytes were built here, and the publication gate withholds on it.
            //
            // What it is *not* is a wider egress tier. The build still runs at `mirror-only`; only
            // the image that precedes it is built with a route out, and that fact is now on the
            // record rather than in somebody's shell history.
            crate::mirror::resolve_auto(
                &crate::mirror::auto_parent(sdk_major)?,
                &deps,
                verbose,
                crate::may_derive(image, egress),
            )?
        } else {
            // An image the operator named. Whatever is in it, they put it there, and this run
            // derived nothing.
            crate::mirror::Resolved {
                image: image.to_string(),
                derived: None,
            }
        };
        let image = &resolved.image;

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
                cache: fetch_cache.cloned(),
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
                println!(
                    "{} {}",
                    style::heading("strategy"),
                    style::ident(&digest[..16])
                );
                println!("  {} {}", style::label_col("egress"), outcome.egress);
                println!(
                    "  {} {:?}",
                    style::label_col("isolation"),
                    outcome.isolation
                );
                for (phase, d) in &outcome.timings {
                    let name = style::label_col(&format!("{phase:?}").to_lowercase());
                    match d {
                        // `None` means no data, never zero. A timing we failed to read is not a
                        // fast phase, and reporting it as one poisons every average downstream.
                        Some(d) => println!("  {name} {:>7.1}s", d.as_secs_f64()),
                        None => println!("  {name} {}", style::muted("no data")),
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
                            "  {} {} response{} crossed into the build, {opened} opened and \
                             checked",
                            style::label_col("network"),
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
                                "  {} {}",
                                style::label_col(""),
                                style::warn(&format!(
                                    "{partial} of them were abandoned part-way, so their bytes \
                                     crossed unchecked"
                                ))
                            );
                        }
                        if let Some(p) = &transcript_path {
                            println!(
                                "  {} {}",
                                style::label_col(""),
                                style::muted(&p.display().to_string())
                            );
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
                        println!();
                        field_wrapped("not attestable", why, style::warn);
                    }
                }
                match (&outcome.artifact, outcome.succeeded()) {
                    (Some(p), _) => {
                        println!("\n  {} {}", style::label_col("artifact"), p.display())
                    }
                    (None, true) => {
                        println!();
                        field_wrapped(
                            "artifact",
                            "the build succeeded but produced no single artifact. Check \
                             output_path: a glob matching several files does not identify one.",
                            style::warn,
                        );
                    }
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
            // The package under test, read back from the manifest the mirror was armed with —
            // there is no `MirrorHandle` on this path, because the mirror runs inside the
            // container. Without it, a member arriving inside one of the package's own other
            // releases cannot be told from one arriving inside somebody else's.
            let withheld = guard
                .and_then(|p| std::fs::read(p).ok())
                .and_then(|b| serde_json::from_slice::<trigon_mirror::GuardManifest>(&b).ok())
                .and_then(|m| m.withhold);
            let voiding =
                trigon_mirror::voiding(&outcome.guard_arrived, rebuilt.as_ref(), withheld.as_ref());
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
                    println!(
                        "\n  {} {}",
                        style::label_col("failure"),
                        style::bad(&signature.to_string())
                    );
                    // What the flag gates, not a claim about the world. It said `no strategy
                    // change fixes this one` until a run printed that line and then repaired the
                    // build two lines later: `yarn: not found` is `repairable: false` because no
                    // model call is worth making, and the deterministic rung below rewrites it
                    // anyway.
                    if !signature.repairable {
                        println!(
                            "  {} {}",
                            style::label_col(""),
                            style::muted("not one to ask the model about")
                        );
                    }
                    println!("  {} {}", style::label_col("log"), log_path.display());
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
                // The resolved one, which for `--image auto` is not the string the caller passed.
                base_image: image.to_string(),
                derived_image: resolved.derived.clone(),
                isolation: outcome.isolation.as_str().to_string(),
                transcript: outcome.transcript,
                pin: outcome.pin,
                refused_artifact: outcome.refused_artifact,
                throttled: outcome.throttled,
                asked: outcome.asked,
                sdk_choice: sdk_why.clone(),
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

    // Computed before the comparison takes the bytes. No sha1: two files name no ecosystem, and a
    // sha1 is carried only where one publishes it.
    let subject = attest.to.map(|_| {
        let name = attest
            .subject
            .map(str::to_string)
            .unwrap_or_else(|| file_name(upstream));
        trigon_attest::Subject::of_bytes(name, &a, false)
    });
    let c = compare_bytes(a, b, fmt, &set, &Limits::default())?;
    if let (Some(path), Some(subject)) = (attest.to, subject) {
        write_bundle(path, attest.key, subject, &c)?;
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
/// Which profile a filename selects, and the only table that decides it.
///
/// One table, used by [`resolve_profile`] and printed by [`show_profiles`]. It was a `match` arm
/// and nothing else, so a profile the selector could not reach was invisible from outside — and
/// `npm-tarball` is exactly that: it exists, `docs/03-ecosystems.md` says npm uses it, and every
/// npm rebuild in the store carries the set digest of plain `tar-gzip`.
/// The mirror image every command that builds defaults to.
///
/// **One constant, because five copies drifted.** `worker` was added with `:dev` while `rebuild`,
/// `sweep` and the rest kept `:latest`, so the first fleet run pulled an image that does not exist
/// and failed at `setup` with a connection refused to `localhost:443` — a message that says
/// nothing about the actual mistake. Two commands that must build identically cannot have two
/// defaults; a literal repeated five times is four opportunities for exactly this.
/// Every command naming it is behind `build`, and the verifier's `-D warnings` is what noticed:
/// a constant no reachable code uses is dead code in that build.
#[cfg(feature = "build")]
const MIRROR_IMAGE: &str = "localhost/trigon-mirror:latest";

const BY_EXTENSION: &[(&str, &str)] = &[
    (".whl", "wheel"),
    (".crate", "crate"),
    (".gem", "gem"),
    // The arm the comment that used to sit here was waiting for. It described a `nupkg` profile
    // that did not exist, whose lookup failed silently into the plain zip set — so the table
    // claimed a NuGet-specific normalization the system could not perform and said nothing.
    (".nupkg", "nupkg"),
];

/// Every format, so a listing over the fallbacks cannot silently miss one.
///
/// The `match` below is exhaustive on purpose: adding a variant to [`Format`] fails this file
/// rather than quietly dropping a row from `show-profiles`.
const ALL_FORMATS: [Format; 5] = [
    Format::Tar,
    Format::TarGz,
    Format::Zip,
    Format::Gzip,
    Format::Raw,
];

const _: () = {
    // Exhaustiveness, checked by the compiler rather than by remembering.
    const fn covered(f: Format) -> bool {
        match f {
            Format::Tar | Format::TarGz | Format::Zip | Format::Gzip | Format::Raw => true,
        }
    }
    assert!(covered(Format::Tar));
};

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
    let by_kind = BY_EXTENSION
        .iter()
        .find(|(ext, _)| name.ends_with(ext))
        .map(|(_, id)| *id);
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

/// `trigon grant`: issue a credential.
///
/// The token is 32 bytes of the system's randomness, hex-encoded, and printed once. Nothing stores
/// it — `add_principal` keeps its sha256 — so losing it means issuing another, which is the right
/// trade for a credential that can spend compute.
#[cfg(feature = "build")]
fn grant(url: &str, id: &str, name: Option<&str>, scopes: &str, daily_quota: i64) -> Result<()> {
    use trigon_store::queue::Queue;

    let scopes: Vec<&str> = scopes
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    for s in &scopes {
        anyhow::ensure!(
            matches!(*s, "request" | "review" | "operate"),
            "unknown scope `{s}`; known: request, review, operate"
        );
    }
    let token = {
        let mut bytes = [0u8; 32];
        getrandom(&mut bytes)?;
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let q = Queue::open(url).await.map_err(anyhow::Error::from)?;
        q.migrate_identity().await.map_err(anyhow::Error::from)?;
        q.add_principal(id, name.unwrap_or(id), &scopes, daily_quota, &token)
            .await
            .map_err(anyhow::Error::from)?;
        field(
            "principal",
            format!(
                "{} {}",
                style::ident(id),
                style::muted(&format!("({})", scopes.join(", ")))
            ),
        );
        field("quota", format!("{daily_quota} rebuild(s) a day"));
        field("token", style::ident(&token.to_string()));
        println!();
        println!(
            "{}",
            style::muted(&style::wrap(
                "Shown once; only its digest is stored. Use it as `Authorization: Bearer <token>`.",
                0,
            ))
        );
        anyhow::Ok(())
    })
}

/// Bytes from the operating system, with no dependency for it.
///
/// `/dev/urandom` on the platforms this runs on. A credential's randomness is worth reading
/// directly rather than through a crate whose defaults could change.
#[cfg(feature = "build")]
fn getrandom(buf: &mut [u8]) -> Result<()> {
    use std::io::Read as _;
    let mut f = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    f.read_exact(buf).context("reading /dev/urandom")?;
    Ok(())
}

/// `trigon enqueue`: put targets on a queue.
///
/// The cache key is the target plus the tier's *absence* — a key made of the target alone, so a
/// bulk sweep and an interactive request for the same package are one job rather than two. That is
/// the behaviour somebody clicking "rebuild this" on a package a sweep already covers should get:
/// their answer, not a second build of it.
#[cfg(feature = "build")]
fn enqueue_targets(url: &str, targets: &[String], tier: &str, migrate: bool) -> Result<()> {
    use trigon_store::queue::{NewJob, Queue, Tier};

    let tier = match tier {
        "interactive" => Tier::Interactive,
        "regression" => Tier::Regression,
        "bulk" => Tier::Bulk,
        other => anyhow::bail!("unknown tier `{other}`; known: interactive, regression, bulk"),
    };
    let list: Vec<String> = if targets == ["-"] {
        std::io::BufRead::lines(std::io::stdin().lock())
            .map_while(Result::ok)
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    } else {
        targets.to_vec()
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let q = Queue::open(url).await.map_err(anyhow::Error::from)?;
        if migrate {
            q.migrate().await.map_err(anyhow::Error::from)?;
        }
        let mut n = 0;
        for t in &list {
            q.enqueue(&NewJob::rebuild(t.clone(), t.clone(), tier))
                .await
                .map_err(anyhow::Error::from)?;
            n += 1;
        }
        // The count is of targets *offered*, not of jobs created: `enqueue` is idempotent, so
        // re-running this over the same list adds nothing and says so rather than claiming to have
        // queued five thousand builds it did not queue.
        println!(
            "{} {} target(s) to the {} queue",
            style::heading("offered"),
            style::good(&n.to_string()),
            style::ident(tier.as_str())
        );
        for (state, count) in q.depth().await.map_err(anyhow::Error::from)? {
            field(&state, style::ident(&count.to_string()));
        }
        anyhow::Ok(())
    })
}

/// `trigon serve`: the corpus, from a browser.
///
/// Builds its own runtime for the same reason `watch` does — the judgement half is sync, and a
/// command that needs a reactor makes one rather than the binary carrying one everywhere.
///
/// **`--public` is one flag and two controls**, which is deliberate: the publication gate and the
/// evidence class table protect different things and a reader who turned on only one of them would
/// have a site that either accuses without confirmation or leaks unredacted logs. There is no way
/// to ask for half.
#[cfg(feature = "build")]
fn serve_corpus(
    store: &std::path::Path,
    bind: String,
    public: bool,
    stop_divergences: bool,
    refresh_seconds: u64,
    queue: Option<String>,
) -> Result<()> {
    let store = trigon_store::Store::local(store)?;
    let cfg = trigon_api::Config {
        bind,
        unauthenticated: if public {
            trigon_api::Principal::Anonymous
        } else {
            trigon_api::Principal::Operator
        },
        switches: trigon_api::Switches { stop_divergences },
        refresh_seconds,
        queue,
        // The decompiler the member view uses for managed assemblies. The predicate for *which*
        // members are assemblies lives here with the decompiler, so the API asks about every
        // member and gets `None` for the ones ILSpy does not handle — a hex view, as before.
        decompiler: Some(std::sync::Arc::new(|name: &str, a: &[u8], b: &[u8]| {
            crate::decompile::looks_like_assembly(name)
                .then(|| crate::decompile::sources(a, b))
                .flatten()
        })),
    };
    // Loudly, not in a doc comment nobody reads at three in the morning. A store bound to a
    // routable address without `--public` serves build logs that were never redacted, and D14 says
    // in as many words that loopback was the only thing that ever mitigated that.
    if !public && !cfg.bind.starts_with("127.") && !cfg.bind.starts_with("localhost") {
        eprintln!(
            "{} {}",
            style::bad("warning:"),
            style::warn(&style::wrap(
                &format!(
                    "binding {} without --public. Build logs and network transcripts are stored \
                     unredacted and this serves them to anyone who can reach that address.",
                    cfg.bind
                ),
                9,
            ))
        );
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(trigon_api::run(store, cfg))
        .map_err(|e| anyhow::anyhow!(e))
}

/// One `label   value` line of narration, the tool-wide shape: a bold-blue label padded to
/// [`style::LABEL`], a space, then a value already painted by its role. Every command that narrates
/// uses this, so a value starts at the same column whichever command printed it.
fn field(label: &str, value: impl std::fmt::Display) {
    println!("  {} {value}", style::label_col(label));
}

/// A field whose value is long prose: folded to the terminal under its value column with a hanging
/// indent, *then* painted — the wrap has to see the plain text, because an escape sequence has bytes
/// but no width. Piped, [`style::wrap`] leaves it one line, so redirected output is unchanged.
///
/// Build-only: every caller narrates a build (resolve, the run, image derivation); the verifier
/// wraps its own long lines through [`style::wrap`] inline.
#[cfg(feature = "build")]
fn field_wrapped(label: &str, text: &str, paint: fn(&str) -> String) {
    println!(
        "  {} {}",
        style::label_col(label),
        paint(&style::wrap(text, style::VALUE_COL))
    );
}

/// A risk tier, painted by how much latitude the pass took. Structural and metadata edits are the
/// cheap, reversible ones and read cool — cyan and grey; content and lossy edits are the ones that
/// can hold a match only with a caveat, so they earn a warm colour that says to look twice.
fn risk_painted(risk: trigon_core::RiskTier, text: &str) -> String {
    use trigon_core::RiskTier::*;
    match risk {
        Structural => style::ident(text),
        Metadata => style::muted(text),
        Content => style::warn(text),
        Lossy => style::bad(text),
    }
}

fn print_text(c: &Comparison, explain: bool) {
    // The verdict, and the one line a reader looks for first: painted to the outcome, and still
    // legible with a symbol and a word when it is not painted at all.
    let (code, mark) = match c.outcome {
        Match::Exact | Match::Normalized => ("1;32", "✔"),
        Match::NormalizedWithCaveats => ("1;33", "◐"),
        Match::Divergent => ("1;31", "✖"),
    };
    println!("{}", style::verdict(code, mark, &c.outcome.to_string()));
    println!();

    // What was compared, and under which set — the frame for everything below it.
    println!("  {} {}", style::label_col("format"), c.upstream.format);
    println!(
        "  {} {} {}",
        style::label_col("stabilizers"),
        c.upstream.set.0,
        style::muted(&format!("({})", short(&c.upstream.set.1.to_hex()))),
    );
    println!();

    // The digests, upstream against rebuild, each row marked with whether the two sides agree.
    println!(
        "  {} {} {}",
        style::label_col(""),
        style::heading(&format!("{:<18}", "upstream")),
        style::heading("rebuild"),
    );
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
        println!(
            "  {}",
            style::muted("containers differ as well as the framing")
        );
    } else if c.container_bit_identical() == Some(true) && c.outcome != Match::Exact {
        println!();
        println!(
            "  {}",
            style::muted("same container, different outer framing")
        );
    }

    let applied = c.applied();
    if !applied.is_empty() {
        println!();
        println!("  {}", style::heading("applied"));
        let mut seen: Vec<String> = Vec::new();
        for a in applied {
            let key = a.id.to_string();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            println!(
                "    {:<24} {} {}",
                a.id.as_str(),
                risk_painted(
                    a.risk,
                    &format!("{:<10}", format!("{:?}", a.risk).to_lowercase())
                ),
                style::muted(&format!("{:>6} entries", a.entries_touched)),
            );
        }
    }

    if let Some(reason) = c.cap_reason() {
        println!();
        println!(
            "  {} {}",
            style::label_col("capped"),
            style::warn(&style::wrap(
                &format!("below `normalized` — {reason}"),
                style::VALUE_COL
            )),
        );
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
        println!("  {}", style::heading("notes"));
        for n in notes {
            let at = n.path.as_ref().map(|p| format!(" {p}")).unwrap_or_default();
            println!(
                "    {}{}: {}",
                style::warn(&format!("{:?}", n.code)),
                style::ident(&at),
                style::wrap(&n.detail, 6),
            );
        }
    }

    if let Some(d) = &c.diff {
        println!();
        // A count is coloured only when it is worth the eye: identical is the good number, and a
        // non-zero differ / only-side count is the one to notice; a zero stays plain.
        let hot = |n: u32, paint: fn(&str) -> String| {
            if n > 0 {
                paint(&n.to_string())
            } else {
                n.to_string()
            }
        };
        println!(
            "  {}  {} identical, {} differ, {} upstream-only, {} rebuild-only",
            style::heading("members"),
            style::good(&d.identical.to_string()),
            hot(d.differs, style::bad),
            hot(d.only_upstream, style::warn),
            hot(d.only_rebuild, style::warn),
        );
        if d.executable_differs > 0 {
            println!(
                "  {}",
                style::bad(&format!(
                    "{} executable member(s) differ, which is never benign",
                    d.executable_differs
                )),
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
            use trigon_compare::FileStatus::*;
            let status = format!("{:<16}", format!("{:?}", f.status).to_lowercase());
            let status = match f.status {
                Differs => style::warn(&status),
                OnlyUpstream | OnlyRebuild => style::ident(&status),
                Identical => status,
            };
            println!("    {} {}", status, f.path);
        }
        if interesting.len() > limit {
            println!(
                "    {}",
                style::muted(&format!(
                    "… {} more, pass --explain",
                    interesting.len() - limit
                )),
            );
        }
    }
}

fn row(label: &str, a: &str, b: &str) {
    let mark = if a == b {
        style::good("=")
    } else {
        style::bad("≠")
    };
    println!(
        "  {} {} {} {}",
        style::label_col(label),
        style::ident(&format!("{:<18}", short(a))),
        style::ident(&format!("{:<18}", short(b))),
        mark,
    );
}

fn short(hex: &str) -> String {
    format!("{}…", &hex[..hex.len().min(12)])
}

/// A git ref or image reference for display, with any long hex object name in it shortened to its
/// first twelve like a digest — because at full length it wraps the terminal and pushes the line
/// after it back to the margin. This is a bare 40-char commit or 64-char image id, and also one
/// *embedded* in a readable reference: `mcr.microsoft.com/dotnet/sdk@sha256:2dd7f3b0…eca9` is a name
/// the reader wants but for the 64 hex characters on the end, which are what overflow. A tag, a
/// branch, or a plain `registry/name:tag` carries no such run and is left exactly as it is.
///
/// Build-only: it shortens the run narration, which the verifier does not print.
#[cfg(feature = "build")]
fn short_ref(reference: &str) -> String {
    // Every maximal run of hex digits of 32 or more is a digest; leave shorter runs (a `:8.0`, a
    // year) alone. Rebuilt left to right so the byte offsets stay valid as the string shrinks.
    let bytes = reference.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let run = &reference[start..i];
        if run.len() >= 32 {
            out.push_str(&run[..12]);
            out.push('…');
        } else {
            out.push_str(run);
        }
        if i < bytes.len() {
            // The one non-hex byte that ended the run (ASCII in every reference we handle).
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// What selects a profile, in the words the reader would use to cause it.
///
/// Empty where nothing does, which is the answer worth having: a profile no selector reaches is a
/// normalization the tool claims and never performs.
fn selectors_for(id: &str) -> Vec<String> {
    let mut out: Vec<String> = BY_EXTENSION
        .iter()
        .filter(|(_, p)| *p == id)
        .map(|(ext, _)| (*ext).to_string())
        .collect();
    for fmt in ALL_FORMATS {
        if default_for(fmt).id.as_str() == id {
            out.push(format!("any {fmt}"));
        }
    }
    out
}

/// The passes in a profile that can hold a match at `normalized_with_caveats`.
///
/// The rule lives in `trigon_compare::compare` and is read off the passes that **fired**, so this
/// says *can*: a profile carrying a content-risk pass caps nothing on a run where that pass found
/// nothing to do. Naming them is the point — `urllib3` is caveated for exactly one reason, and
/// "which pass" is the first thing anybody asks.
fn capping_passes(set: &trigon_stabilize::StabilizerSet) -> Vec<String> {
    set.members
        .iter()
        .filter(|m| !m.provenance().is_builtin() || m.risk() > trigon_core::RiskTier::Metadata)
        .map(|m| {
            format!(
                "{} ({})",
                m.id().as_str(),
                format!("{:?}", m.risk()).to_lowercase()
            )
        })
        .collect()
}

/// Every profile, with what it costs a verdict and what reaches it.
///
/// `trigon stabilizers` answers "what is in this one" and needed you to already know the name.
/// There was no way to see the set, so the one fact that matters across them — that a profile can
/// exist and be selected by nothing — was not visible from any command.
fn list_profiles_cmd() -> Result<()> {
    let ids = trigon_stabilize::all_profiles();
    let sets: Vec<trigon_stabilize::StabilizerSet> = ids
        .iter()
        .map(|id| {
            profile(id).unwrap_or_else(|| {
                panic!("all_profiles() lists `{id}`, which profile() does not answer to")
            })
        })
        .collect();

    // Sized to what is present rather than to a guess, the way `stabilizers` does it.
    let w = ids.iter().map(|i| i.len()).max().unwrap_or(0).max(7);
    println!(
        "{} stabilizer profiles.",
        style::heading(&ids.len().to_string())
    );
    println!();
    println!(
        "  {}  {}  {}  {}",
        style::heading(&format!("{:<w$}", "profile")),
        style::heading(&format!("{:>6}", "passes")),
        style::heading(&format!("{:<16}", "set digest")),
        style::heading("selected by"),
    );
    for set in &sets {
        let sel = selectors_for(set.id.as_str());
        println!(
            "  {:<w$}  {:>6}  {}  {}",
            set.id.as_str(),
            set.members.len(),
            style::ident(&format!("{:<16}", &set.digest().to_hex()[..16])),
            if sel.is_empty() {
                style::muted("nothing")
            } else {
                sel.join(", ")
            },
        );
    }

    println!();
    println!(
        "{}",
        style::heading("Passes that can hold a match at `normalized_with_caveats`:")
    );
    let mut any = false;
    for set in &sets {
        let caps = capping_passes(set);
        if caps.is_empty() {
            continue;
        }
        any = true;
        println!(
            "  {:<w$}  {}",
            set.id.as_str(),
            style::warn(&caps.join(", "))
        );
    }
    if !any {
        println!(
            "  {}",
            style::muted(
                "none: every pass in every profile is built in, at metadata risk or below"
            )
        );
    }
    println!(
        "  {}",
        style::muted(&style::wrap(
            "The cap is read off the passes that fired, not off this list, so a profile carrying \
             one caps nothing on a run where it found nothing to do.",
            2,
        ))
    );

    let orphans: Vec<&str> = sets
        .iter()
        .filter(|s| selectors_for(s.id.as_str()).is_empty())
        .map(|s| s.id.as_str())
        .collect();
    if !orphans.is_empty() {
        println!();
        println!(
            "{}",
            style::warn(&style::wrap(
                &format!(
                    "Nothing selects {}: {}. An artifact of that shape gets the fallback for its \
                     format, so these passes never run and the normalization they describe does \
                     not happen. `--profile` reaches one by hand.",
                    if orphans.len() == 1 {
                        "one profile".to_string()
                    } else {
                        format!("{} profiles", orphans.len())
                    },
                    orphans.join(", ")
                ),
                0,
            ))
        );
    }
    println!();
    println!(
        "{}",
        style::muted(&style::wrap(
            "The digest is over the passes and their tiers, and it is what an attestation carries: \
             a statement stays readable against the set it named, and reordering a pass makes a \
             new one.",
            0,
        ))
    );
    println!(
        "{}",
        style::muted("`trigon stabilizers --profile <id>` lists the passes in one.")
    );
    Ok(())
}

#[cfg(all(test, feature = "build"))]
mod guard_arming {
    //! Whether a signed statement may say the artifact-hash check was performed.
    //!
    //! The manifest is built for every run, because building it is how we learn what we *would*
    //! watch. Arming it is a separate event, and only an armed guard is a fact about the run.

    #[test]
    fn only_an_armed_guard_is_a_fact_about_the_run() {
        // `mirror-only`: the manifest goes to the mirror inside the build's network island.
        assert!(super::guard_was_armed(true, false));
        // `--egress open --timewarp auto`: a host mirror is reserved and built `.with_guard(...)`.
        assert!(super::guard_was_armed(false, true));
        assert!(super::guard_was_armed(true, true));

        // **The default configuration.** `--egress open`, no `--timewarp`, so no mirror exists at
        // all and the guard file is never handed to anything. Carrying the manifest anyway signed
        // `artifactHashCheck: { performed: true, guardedMembers: 34, trips: [] }` about a run where
        // nothing had looked at anything — which is precisely what
        // `trigon-attest/src/rebuild.rs`'s own comment says must not happen: "A guard that could
        // not run is not a guard that found nothing, and collapsing the two is how an unchecked run
        // comes to be read as a clean one."
        assert!(
            !super::guard_was_armed(false, false),
            "a run with no mirror and no enforcement armed no guard, and must not sign that it did"
        );
    }
}

#[cfg(test)]
mod profile_listing {
    use super::*;

    #[test]
    fn the_listing_and_the_selector_read_one_table() {
        // They were a `match` arm and a hand-written list, which is the shape of defect this
        // project keeps finding: two things that had to agree, with nothing asserting they did.
        for (ext, id) in BY_EXTENSION {
            let picked = resolve_profile(Path::new(&format!("a-1.0{ext}")), None, Format::Zip)
                .expect("a built-in profile");
            assert_eq!(picked.id.as_str(), *id, "{ext}");
            assert!(
                selectors_for(id).iter().any(|s| s == ext),
                "{id} is selected by {ext} and does not say so"
            );
        }
        // And a name that matches nothing falls to the format's own profile, which is what makes
        // an unselected profile possible at all.
        let fallback = resolve_profile(Path::new("a-1.0.tgz"), None, Format::TarGz).unwrap();
        assert_eq!(fallback.id.as_str(), "tar-gzip");
    }

    #[test]
    fn a_profile_nothing_selects_is_named_rather_than_listed_like_the_rest() {
        // `npm-tarball` exists, `docs/03-ecosystems.md` §1 says npm's profile is "tar set + gzip
        // set + npm-tarball", and every npm run in the store carries the set digest of plain
        // `tar-gzip`: an artifact named `.tgz` matches no extension arm and falls to the format's
        // fallback. So `npm-install-fields` has never run on anything this tool has verified.
        //
        // Pinned as a list rather than asserted empty, because emptying it is a decision about
        // verdicts — the set digest changes and npm statements stop matching the ones before them.
        // This is here so the list shrinks on purpose and never grows by accident.
        let orphans: Vec<&str> = trigon_stabilize::all_profiles()
            .into_iter()
            .filter(|id| selectors_for(id).is_empty())
            .collect();
        assert_eq!(orphans, vec!["npm-tarball"]);
    }

    #[test]
    fn the_capping_list_is_the_comparators_rule_and_not_a_second_one() {
        // `compare` caps on `provenance != Builtin || risk > Metadata`, read off the passes that
        // fired. A listing that drew the line anywhere else would describe a tool that does not
        // exist — and this is a page-versus-behaviour claim, which is where this project's bugs
        // live.
        for id in trigon_stabilize::all_profiles() {
            let set = profile(id).unwrap();
            let named = capping_passes(&set);
            let expected: Vec<String> = set
                .members
                .iter()
                .filter(|m| {
                    !m.provenance().is_builtin() || m.risk() > trigon_core::RiskTier::Metadata
                })
                .map(|m| m.id().as_str().to_string())
                .collect();
            assert_eq!(named.len(), expected.len(), "{id}");
            for (row, want) in named.iter().zip(&expected) {
                assert!(row.starts_with(want), "{id}: {row} is not {want}");
            }
        }
        // The two real shapes: a wheel can be capped four ways, a gem by nothing at all.
        assert!(
            capping_passes(&profile("wheel").unwrap())
                .iter()
                .any(|c| c.starts_with("wheel-record (content)"))
        );
        assert!(capping_passes(&profile("gem").unwrap()).is_empty());
    }

    #[test]
    fn every_format_has_a_fallback_and_the_listing_names_it() {
        // `default_for` panics on a format with no profile, and it is called on a path where the
        // answer decides a verdict. A listing that walked a shorter list of formats than the
        // selector does would hide exactly that.
        for fmt in ALL_FORMATS {
            let set = default_for(fmt);
            assert!(
                selectors_for(set.id.as_str())
                    .iter()
                    .any(|s| s == &format!("any {fmt}")),
                "{fmt} falls to {} and the listing does not say so",
                set.id.as_str()
            );
        }
    }
}

fn stabilizers(prof: &str) -> Result<()> {
    let set = profile(prof).with_context(|| {
        format!(
            "unknown profile `{prof}`; known: {}",
            trigon_stabilize::all_profiles().join(", ")
        )
    })?;
    // The digest in full, unlike everywhere else a digest is shown: printing it is what this command
    // is for, and a statement signs all 64 hex characters, so twelve of them cannot be compared
    // against one. It is one line, and a terminal narrower than it wraps a heading, not a table.
    println!(
        "{} {}",
        style::heading(&set.id.to_string()),
        style::muted(&format!("({})", set.digest()))
    );
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
            "  {:<w$} {} {} {}",
            m.id().as_str(),
            risk_painted(
                m.risk(),
                &format!("{:<11}", format!("{:?}", m.risk()).to_lowercase())
            ),
            style::muted(&format!("{:<9}", format!("{:?}", m.stage()).to_lowercase())),
            style::muted(&format!("{:?}", m.provenance()))
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

/// Whether the artifact-hash guard was actually armed, and so whether the manifest is a fact about
/// this run rather than a description of what we would have watched.
///
/// Two things arm it, and a run needs only one of them: `mirror-only` hands the manifest to the
/// mirror inside the build's network island, and a reserved host mirror is built `.with_guard(...)`.
/// The default configuration does neither — `--egress open` with no `--timewarp` starts no mirror
/// at all — and carrying the manifest anyway signed `artifactHashCheck.performed: true` about runs
/// where nothing looked.
///
/// A named function with a test rather than an inline `||`, because the signed claim downstream is
/// derived from it and an inline boolean is where the last version of this rule went wrong.
#[cfg(feature = "build")]
const fn guard_was_armed(enforced: bool, host_mirror: bool) -> bool {
    enforced || host_mirror
}

/// Whether this run may *build* a base image, as opposed to only selecting one.
///
/// The whole of what separates `--image auto` from `--image derive`, in one place and testable
/// without a container. Two inputs and one answer: `auto` may build only where the tier already
/// admits unaccounted network, `derive` may build anywhere because the operator asked and the run
/// records that it did.
///
/// A pinned image reaches here as `IfNeeded` and never uses it — nothing is resolved for an image
/// the operator named — so the answer for that case is arbitrary rather than wrong. Taking `image`
/// rather than a pre-computed bool is what keeps the two values' difference visible at the one
/// site that cares.
#[cfg(feature = "build")]
fn may_derive(image: &str, egress: trigon_sandbox::EgressTier) -> crate::mirror::Derive {
    if image == "derive" || matches!(egress, trigon_sandbox::EgressTier::Open) {
        crate::mirror::Derive::IfNeeded
    } else {
        crate::mirror::Derive::NotAtThisTier
    }
}

#[cfg(all(test, feature = "build"))]
mod may_derive_tests {
    use crate::mirror::Derive;
    use trigon_sandbox::EgressTier;

    #[test]
    fn auto_never_builds_an_image_inside_an_enforced_boundary() {
        // Deriving is `apt-get`, which is network, and at `mirror-only` the run's whole claim is
        // that its transcript is a complete account of what crossed into it. This is the refusal
        // that cost 73 of 89 PyPI targets on the M1 sweep — correct, and expensive.
        for tier in [EgressTier::MirrorOnly, EgressTier::DenyAll] {
            assert_eq!(super::may_derive("auto", tier), Derive::NotAtThisTier);
        }
    }

    #[test]
    fn auto_builds_freely_where_the_tier_already_admits_the_network() {
        // At `open` there is no account to keep complete, so there is nothing for the refusal to
        // protect and refusing would only cost the run.
        assert_eq!(
            super::may_derive("auto", EgressTier::Open),
            Derive::IfNeeded
        );
    }

    #[test]
    fn derive_builds_at_every_tier_because_that_is_the_whole_of_the_difference() {
        // The one thing the flag changes. Everything else — selection, the admission table, the
        // content tag — is `auto`'s, unchanged. What `derive` does *not* change is the build's own
        // egress: the tier passed here is still the tier the build runs at.
        for tier in [
            EgressTier::Open,
            EgressTier::MirrorOnly,
            EgressTier::DenyAll,
        ] {
            assert_eq!(super::may_derive("derive", tier), Derive::IfNeeded);
        }
    }
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
        /// Where the mirror may keep upstream bytes, and which invocation shares index entries.
        ///
        /// `None` is what every run did before this existed: fetch everything, every time. Honest
        /// and, measured over one 186-run npm sweep, 39 GB and 143,362 requests — 86.7% of them
        /// for bytes already fetched (`docs/adr/0013-…`).
        pub fetch_cache: Option<(PathBuf, String)>,
        /// Where to report which phase this target is in, when something is watching.
        ///
        /// `None` for a single `trigon rebuild`: nobody is watching one target, and the phases are
        /// on the terminal already.
        pub phases: Option<std::sync::Arc<crate::progress::Progress>>,
        /// What makes two runs runs at the *same thing*, and which attempt this is.
        ///
        /// **Carried in rather than invented here.** The publication gate groups attempts by
        /// `cache_key` and releases nothing until two of them agree, so a record written without
        /// one corroborates nothing — including itself. A worker knows the key because the job
        /// carries it; a bare `trigon rebuild` has none, and `None` is the honest answer there
        /// rather than a key made up on the spot, which would make one run look like a
        /// confirmation of another.
        pub cache_key: Option<String>,
        pub attempt: u32,
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
            trigon_core::Ecosystem::CratesIo => rungs.push(Box::new(
                trigon_registry::CratesIoInferrer::new().with_mirror(mirror),
            )),
            trigon_core::Ecosystem::NuGet => {
                // The same shared cache: this rung asks the repository where the `.csproj` is,
                // because nothing in a `.nuspec` says.
                let sources = std::sync::Arc::new(trigon_registry::SourceCache::new(
                    sources.unwrap_or_else(trigon_registry::SourceCache::default_root),
                ));
                rungs.push(Box::new(
                    trigon_registry::NuGetInferrer::new()
                        .with_mirror(mirror)
                        .with_sources(Some(sources)),
                ))
            }
            trigon_core::Ecosystem::PyPI => {
                // The same cache the npm rung and the model rung use: a target whose repository
                // more than one of them wants is fetched once.
                let sources = std::sync::Arc::new(trigon_registry::SourceCache::new(
                    sources.unwrap_or_else(trigon_registry::SourceCache::default_root),
                ));
                rungs.push(Box::new(
                    PyPiInferrer::new()
                        .with_mirror(mirror)
                        .with_sources(Some(sources)),
                ))
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
        /// The id of the record this run wrote, where a store was configured.
        ///
        /// Handed back rather than rediscovered. A worker that has to find "the newest record for
        /// this target" is a worker that finds the wrong one whenever two attempts at the same
        /// package overlap — which, now that a verdict enqueues a confirmation, is the normal case
        /// rather than an unlucky one.
        pub record_id: Option<String>,
    }

    impl From<Outcome> for Ran {
        fn from(outcome: Outcome) -> Self {
            Ran {
                outcome,
                model_calls: 0,
                record_id: None,
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
        // Bracketed here rather than counted inside, because the traffic table is process-wide and
        // this is the only scope that knows where one run's share of it begins. Taken before
        // anything resolves: the first thing a run does is ask a registry.
        let before = trigon_politeness::traffic();
        let out = run_inner(args, verbose, &mut report);
        // Both halves: what this process asked while resolving and fetching, and what the mirror
        // inside the island asked on the build's behalf, which `run_inner` hands to the same table
        // before returning. A record holding one of those would be a complete-looking account of a
        // fraction of the traffic — which is what it was, reading 3 requests for a run that made
        // 399.
        report.hosts = trigon_politeness::since(&before);
        match &out {
            Ok(ran) => report.outcome = Some(ran.outcome.label()),
            // Our own error, not the package's. Recorded as such rather than left absent, because
            // an absent outcome and a failure of ours read alike to anybody counting.
            Err(e) => report.error = Some(e.to_string()),
        }
        report.write(&work);
        out
    }

    /// What a terminal record needs, gathered as the run learns it.
    ///
    /// **`record_run` had one call site, past the early return that unwraps the comparison.** So a
    /// `Void`, a build failure, a no-strategy and an infrastructure error all left the store
    /// untouched, and a corpus browser over it reported a perfect reproduction rate on a corpus
    /// where nothing had ever failed to build. Measured on this machine's store the day the browser
    /// was first pointed at it: 32 runs, 32 of them evidence, **zero** failures — on a project whose
    /// last random sweep reached comparison 7 times in 125.
    ///
    /// Filled in as the facts arrive rather than threaded through a thousand lines of orchestration,
    /// which is what keeps this an addition rather than the rewrite `docs/22` §2 warned about.
    #[derive(Default)]
    struct Recording {
        inputs: Option<RecordInputs>,
        /// The published artifact, once it is on disk. Everything terminal *after* the fetch has
        /// one, which is every outcome that is about a package: the fetch is the second phase.
        upstream: Option<(PathBuf, trigon_core::Digest, u64)>,
        /// Set by the compared path, so the wrapper below does not write a second record over the
        /// one that has the comparison in it.
        record_id: Option<String>,
    }

    fn run_inner(
        args: Args,
        verbose: bool,
        report: &mut crate::progress::RunReport,
    ) -> Result<Ran> {
        let store = args.store.clone();
        let mut rec = Recording::default();
        let mut out = run_body(args, verbose, report, &mut rec);
        if let Some(dir) = &store
            && rec.record_id.is_none()
        {
            match record_terminal(dir, &rec, report, &out) {
                Ok(id) => rec.record_id = id,
                // A failure to record does not fail the run, for the reason the compared path
                // gives: losing the record is a thing to report, not a reason to throw the result
                // away.
                Err(e) => tracing::warn!("could not record this run: {e:#}"),
            }
        }
        if let Ok(ran) = &mut out {
            ran.record_id = rec.record_id.clone();
        }
        out
    }

    /// Everything a run does, unchanged.
    ///
    /// Split from [`run_inner`] only so the recording above brackets it. `docs/18-management-ui.md`
    /// records the same shape for `RunReport`: "on every terminal outcome" is a property of a
    /// wrapper, not a rule six return statements are each expected to remember.
    fn run_body(
        args: Args,
        verbose: bool,
        report: &mut crate::progress::RunReport,
        rec: &mut Recording,
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
            println!("{}", style::heading(&resolved.reference.to_string()));
            // The invocation's frame — image, tier, where the work and the record land. This was
            // printed by `rebuild-and-attest.sh` in plain, narrower columns; it belongs in the
            // binary, which owns the styling and the `NO_COLOR` rule and shows it to anyone who
            // runs `trigon rebuild` directly rather than through the script.
            field("image", style::ident(&short_ref(&args.image)));
            field("egress", style::ident(&args.egress));
            field("work", args.work.display());
            if let Some(store) = &args.store {
                field("store", store.display());
            }
            field("artifact", &meta.id);
        }

        mark("fetch");
        // 2. The published bytes, before anything else.
        //
        // The guard manifest is built from them, and the mirror has to be armed with it before a
        // build can ask the mirror for anything.
        let upstream_path = args.work.join(meta.id.as_str());
        let mut file = std::fs::File::create(&upstream_path)?;
        let fetched = match rt.block_on(registry.fetch(&meta, &mut file)) {
            Ok(f) => f,
            Err(e) => {
                // Refused means not kept. Bytes the registry does not vouch for — or half a
                // download — left at the top of the work directory under the artifact's own name
                // are exactly what a later run reusing the directory would pick up.
                drop(file);
                let _ = std::fs::remove_file(&upstream_path);
                return Ok(classify(&e).into());
            }
        };
        drop(file);
        let upstream_digest = fetched.sha256;
        if verbose {
            // What the registry vouched for, said once, because "fetched" alone reads the same
            // whether the bytes were checked against two declarations or against none.
            let checked: Vec<String> = fetched
                .checks
                .iter()
                .map(|c| {
                    let algorithm = &c.declared.algorithm;
                    match c.result {
                        trigon_core::CheckResult::Matched => format!("{algorithm} matches"),
                        trigon_core::CheckResult::Unchecked => {
                            format!("{algorithm} declared, not computable here")
                        }
                    }
                })
                .collect();
            // The note wherever nothing matched: declarations of algorithms this build cannot
            // compute are a list that checked nothing, and the list alone does not say so.
            let matched = fetched
                .checks
                .iter()
                .any(|c| c.result == trigon_core::CheckResult::Matched);
            let said = match (matched, &fetched.note) {
                (true, _) => checked.join(", "),
                (false, Some(note)) => note.clone(),
                (false, None) => "nothing declared".into(),
            };
            field(
                "declared",
                style::muted(&style::wrap(&said, style::VALUE_COL)),
            );
        }
        // Kept for the record, whichever way it ends. The sha512 and sha1 are what a statement's
        // subject carries, and a run that reaches no verdict does not keep the bytes to recompute
        // them from; sha1 only where the ecosystem publishes one.
        let upstream_digests = trigon_store::UpstreamDigests {
            sha512: fetched.sha512,
            sha1: target.ecosystem.publishes_sha1().then_some(fetched.sha1),
            declared: fetched.checks.clone(),
            note: fetched.note.clone(),
        };
        // From here on every terminal outcome is about a package and can be recorded as one. A
        // failure before this point is a resolve or a fetch — ours or the registry's — and has no
        // artifact to be a record *about*, which is also what the run id is built from.
        rec.upstream = Some((
            upstream_path.clone(),
            upstream_digest,
            std::fs::metadata(&upstream_path)
                .map(|m| m.len())
                .unwrap_or(0),
        ));
        if verbose {
            field(
                "published",
                format!(
                    "{} {}",
                    style::muted("sha256"),
                    style::ident(&upstream_digest.to_hex()[..16])
                ),
            );
        }

        // What the published artifact says about the toolchain that made it, added to the
        // intrinsics before inference so a rung can pin it. A read from the artifact under test,
        // which is the one source that cannot be out of date about its own build.
        if let Ok(bytes) = std::fs::read(&upstream_path) {
            let found = trigon_registry::wheel::generator_evidence(&bytes);
            if verbose && let Some(e) = found.first() {
                field("generator", format!("{:?}", e.claim));
            }
            resolved.intrinsics.evidence.extend(found);

            // **And where the artifact says its own source is.** Two of the four ecosystems record
            // it inside the package and neither records it in their API: a `.nuspec` carries
            // `<repository url commit>`, and a `.crate` carries `.cargo_vcs_info.json`. Both are
            // written by the publishing tool during the build being reproduced, so neither is an
            // inference — and for NuGet it is close to the only rung there is, because three of
            // twelve popular packages declare a forge in `projectUrl` and the rest point at a
            // documentation site.
            //
            // Only ever *adds*. A source the API already gave is contemporary with the release and
            // is not overridden; what this fills is the commit the API never has.
            match target.ecosystem {
                trigon_core::Ecosystem::NuGet => {
                    if let Some(found) = trigon_registry::nupkg_source(&bytes) {
                        if verbose {
                            let commit = if found.commit.is_empty() {
                                style::muted("(no commit)")
                            } else {
                                style::ident(&short_ref(&found.commit))
                            };
                            field("nuspec", format!("{} @ {commit}", found.repo_url));
                        }
                        resolved.source = Some(found);
                    }
                }
                trigon_core::Ecosystem::CratesIo => {
                    if let Some(sha) = trigon_registry::crate_commit(&bytes)
                        && let Some(src) = resolved.source.as_mut()
                        && src.commit.is_empty()
                    {
                        if verbose {
                            field("vcs-info", style::ident(&short_ref(&sha)));
                        }
                        src.commit = sha;
                        src.how = trigon_core::SourceDiscovery::PublishedProvenance;
                    }
                }
                _ => {}
            }
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
                field(
                    "mirror",
                    style::muted("inside the build's network island, which is its only route out"),
                );
                None
            }
            Some("auto") => Some(rt.block_on(trigon_mirror::reserve(0))?),
            _ => None,
        };

        // **Whether anything will be armed with the guard**, captured here because `reserved` is
        // moved into the mirror handle a hundred lines down and the answer is needed after that.
        // See [`guard_was_armed`] for why this is a named function rather than an inline `||`.
        let armed = guard_was_armed(enforced, reserved.is_some());
        let timewarp_host = crate::timewarp_host_for(
            enforced,
            reserved
                .as_ref()
                .and_then(|l| l.local_addr().ok())
                .map(|a| a.port()),
            args.timewarp.as_deref(),
        );
        // **One value, used by the build and by the validation.** The repair guard renders a
        // proposal to decide whether to accept it, and rendering with a different mirror than the
        // build will use makes that guard answer a different question. Bound here so the two
        // cannot drift.
        let timewarp = timewarp_host.as_deref().unwrap_or("timewarp");

        // Taken before the ladder consumes `args`, so the record can be written at the end without
        // keeping the whole argument struct alive.
        //
        // The three run-derived fields below are empty here and filled at the second construction,
        // which is the one that writes: nothing has been built or armed at this point, so an empty
        // value is the true one rather than a placeholder.
        let inputs = RecordInputs {
            isolation: String::new(),
            guard_manifest: None,
            guarded_members: None,
            guard_bytes: None,
            // Filled per attempt in the build loop, beside `strategy_digest`.
            strategy: None,
            // Known now, and true of the run however it ends: the fetch is behind us.
            upstream_digests: Some(upstream_digests.clone()),
            purl: args.purl.clone(),
            work: args.work.clone(),
            image: args.image.clone(),
            // Filled in from the build below, which is the only thing that knows. See the
            // override in the compared path.
            derived_image: None,
            diff_opinion: None,
            egress: args.egress.clone(),
            cache_key: args.cache_key.clone(),
            attempt: args.attempt,
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
            source: None,
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
            // Filled at the second construction, from the report, once the ladder has spoken.
            declines: Vec::new(),
            assumptions: Vec::new(),
            confidence: None,
        };
        // Handed to the recorder now rather than at the end: every return between here and the
        // comparison is a terminal outcome somebody will want to read, and each one of them used to
        // leave nothing behind.
        rec.inputs = Some(inputs.clone());

        report.model = model.as_ref().map(|m| m.describe());
        if let (Some(m), true) = (&model, verbose) {
            field(
                "model",
                format!(
                    "{} {}",
                    style::ident(&m.describe()),
                    style::muted("— asked only where nothing deterministic answers")
                ),
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
        // `climb` rather than `infer`: the same ladder, and it keeps what the rungs that said
        // nothing said about why. Written to the report before the early return, because a
        // `no-strategy` is exactly the run whose reasons nobody could otherwise see.
        let climb = rt.block_on(trigon_registry::climb(&rungs, &resolved));
        report.declines = climb
            .declines
            .iter()
            .map(|(rung, why)| format!("{rung}: {why}"))
            .collect();
        let Some(candidate) = climb.candidate else {
            // **Printed, not logged.** These went to `tracing::info!`, which is off at the default
            // level, so a `no-strategy` run said everything it knew about the package and nothing
            // about why it stopped — the comment above says this is exactly the run whose reasons
            // nobody could otherwise see, and then the reasons went somewhere nobody sees. Every
            // other line this command emits is a `println!`; the one explaining a dead end was the
            // exception.
            //
            // A run with no reasons at all is worse still, and possible: a ladder whose every rung
            // declined silently. Saying so beats printing a blank space where an explanation goes.
            println!();
            if report.declines.is_empty() {
                println!(
                    "  {}  {}",
                    style::warn("no-strategy"),
                    style::muted(&style::wrap(
                        "no rung proposed a recipe, and none said why. That is a gap in Trigon \
                         rather than a fact about this package.",
                        style::VALUE_COL,
                    ))
                );
            }
            for d in &report.declines {
                field_wrapped("declined", d, style::warn);
            }
            return Ok(Ran {
                outcome: Outcome::NoStrategy,
                model_calls: calls(&model),
                record_id: None,
            });
        };
        report.derivation = Some(candidate.derivation.to_string());
        report.confidence = Some(format!("{:?}", candidate.confidence).to_lowercase());
        report.assumptions = candidate.assumptions.clone();
        let loc = candidate.strategy.location().cloned().unwrap_or_default();
        // The source half of the verdict, assembled from the two places that know different parts
        // of it: the strategy has the repository, commit and subdirectory the build will use, and
        // the candidate has the rung that found the commit. Neither reached a file before this.
        report.source = Some(trigon_core::SourceProvenance {
            repo_url: loc.repo.clone(),
            declared_url: resolved
                .source
                .as_ref()
                .and_then(|s| s.declared_url.clone()),
            commit: loc.git_ref.clone(),
            ref_name: resolved.source.as_ref().and_then(|s| s.ref_name.clone()),
            subdir: loc.subdir.clone(),
            how: candidate.discovery,
        });
        // **And back onto the target, because two later readers ask it rather than the strategy.**
        // `Configured::inputs` and the model rung both read `ResolvedTarget.source.commit`, which is
        // the commit the *registry* recorded — and that is empty for every PyPI target, every NuGet
        // package published without SourceLink, and every npm monorepo with no `gitHead`. The
        // commit the ladder resolved from a tag lives only in the candidate's location, so both of
        // them declined on targets whose repository this run had *already cloned*: a divergent
        // Newtonsoft.Json run printed `no repair: no source commit, so there is no repository to
        // read` three lines under the commit it had just resolved, and `--model` was a silent no-op
        // on the same targets the model rung exists to rescue.
        //
        // Assigned rather than merged: `report.source` is built from the location the build will
        // use plus the declared fields off `resolved`, so it is strictly better informed than what
        // it replaces.
        resolved.source = report.source.clone();
        if verbose {
            field(
                "source",
                format!("{} @ {}", loc.repo, style::ident(&short_ref(&loc.git_ref))),
            );
            field(
                "strategy",
                format!(
                    "{:?}, commit found by {:?}, confidence {:?}",
                    candidate.derivation, candidate.discovery, candidate.confidence
                ),
            );
            for a in &candidate.assumptions {
                // Printed, not buried. A divergence has to be readable against the guesses that
                // produced it rather than taken as a fact about the package. Folded under the
                // value column, because an assumption is a whole sentence and wrapping it to the
                // left margin loses which line it belongs to.
                field("assuming", style::muted(&style::wrap(a, style::VALUE_COL)));
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
            field(
                "guarding",
                style::muted(&style::wrap(
                    &format!(
                        "the artifact and {} of its members ({} too small, too common, or also \
                         in the source)",
                        guard.members.len(),
                        guard.filtered_out
                    ),
                    style::VALUE_COL,
                )),
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
                    field(
                        "mirror",
                        style::muted("serving the index as of the publish date"),
                    );
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
        let guard_bytes = serde_json::to_vec_pretty(&guard)?;
        std::fs::write(&guard_file, &guard_bytes)?;
        // **Taken here, where the guard is armed, because this is the only place that knows.** The
        // signed `artifactHashCheck` block derives `performed` from the presence of this digest, so
        // a run that does not carry it forward signs a statement saying nobody looked. Nineteen
        // statements said exactly that about runs where the guard was armed and reported its member
        // count to the terminal in the same breath.
        //
        // **And only where it was armed**, which is the other half of the same rule and was missing.
        // The manifest is built for every run, because building it is how we learn what we would
        // have watched; arming it is a different event. Carried unconditionally, the default
        // configuration — `--egress open`, no `--timewarp`, so no mirror at all — signed
        // `artifactHashCheck: { performed: true, guardedMembers: 34, trips: [] }` about a run where
        // nothing had looked at anything. That is the failure the comment three lines above
        // `"performed"` in `trigon-attest/src/rebuild.rs` names exactly: a guard that could not run
        // is not a guard that found nothing.
        //
        // Both fields move together. `guardedMembers: 34` beside `performed: false` is the same
        // false statement with the other half missing.
        let guard_manifest = armed.then(|| {
            trigon_core::Digest::from_bytes(<[u8; 32]>::from(
                <sha2::Sha256 as sha2::Digest>::digest(&guard_bytes),
            ))
            .to_hex()
        });
        let guarded_members = armed.then_some(guard.members.len() as u64);
        // And the manifest's bytes, under the same condition, for the store. A run that ends
        // without a verdict — a void above all, where the guard is the whole story — is recorded
        // from `rec`, so it learns them here rather than at the end.
        let guard_kept = armed.then(|| guard_bytes.clone());
        if let Some(i) = rec.inputs.as_mut() {
            i.guard_manifest = guard_manifest.clone();
            i.guarded_members = guarded_members;
            i.guard_bytes = guard_kept.clone();
        }

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
        // The build that produced `judged`, kept so a later failed repair does not describe the
        // run by the attempt that failed. See the fallback below the loop.
        let mut judged_built: Option<crate::build::Built> = None;
        // And the strategy it came from, as `(strategy_digest, canonical JSON)`, for the same
        // reason: the record names the recipe that produced the verdict, and a failed repair
        // after it is a different recipe. Stashed and cleared with `judged_built`.
        let mut judged_strategy: Option<(Option<String>, Option<String>)> = None;
        // The canonical JSON of the strategy the current attempt runs, beside `strategy_digest`.
        // Uninitialized for the reason `produced` is: every attempt assigns it before anything
        // reads it.
        let mut strategy_json: Option<String>;
        let mut compare_error: Option<Outcome> = None;
        // What the last attempt built, carried out of the loop because the guard is read again
        // after it and asks a question only this file can answer. Uninitialized on purpose: every
        // path out of the loop runs the assignment below first, and saying so here means a future
        // early `break` fails to compile rather than silently voiding against a stale `None`.
        let mut produced: Option<PathBuf>;
        let (mut built, mut strategy_digest) = loop {
            // **The verdict's bytes have to outlive the attempt that follows it.**
            //
            // `judged` is deliberately carried across an iteration so a failed repair still
            // reports the divergence the run had already established — and the wipe on the next
            // line deletes the file it names. A path and the bytes under it with different
            // lifetimes and nothing asserting it: `record_run` read a file the loop had just
            // removed, and the run was lost to `could not record this run: No such file or
            // directory` with no file name in the message to say which.
            //
            // Observed on `prop-types@15.8.1`, which is the third defect this one target has
            // found on this exact seam: the run built, compared, confirmed two missing UMD
            // bundles, kept the verdict correctly — and then recorded nothing.
            //
            // Here rather than at each of the eight `judged =` sites, because this is the line
            // that causes it, and a rule enforced next to its cause cannot be forgotten by a
            // site added later. It costs a copy only on an iteration that actually goes round
            // again, which is a repair; the common run never reaches it twice.
            if let Some((path, _)) = &mut judged {
                *path = keep_judged(&args.work, path);
            }
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
            // The strategy itself, from the same value in the same place, so the blob a record
            // names and the digest beside it describe one attempt. Canonical JSON, as the digest
            // hashes it, so the file a reader fetches is the strategy and not a YAML rendering.
            strategy_json = trigon_strategy::canonical(&strategy).ok();
            if let Some(i) = rec.inputs.as_mut() {
                i.strategy = strategy_json.clone();
            }
            let built = crate::build::run_with(
                &strategy_file,
                false,
                &args.image,
                &out,
                &args.egress,
                args.timeout,
                false,
                timewarp,
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
                args.fetch_cache.as_ref(),
                // NuGet builds with whatever SDK the image carries — its own recorded assumption
                // says so — because the registry publishes no compiler version. Nothing is pinned,
                // so there is no pin for an image to override, and an image that supplies one is
                // the only way this ecosystem builds at all.
                match target.ecosystem {
                    trigon_core::Ecosystem::NuGet => Some("dotnet"),
                    _ => None,
                },
                resolved.intrinsics.publish_time.as_deref(),
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
                let judgement = judge(&upstream_path, &rebuilt);
                // This attempt reached its own comparison, and whatever came of it is what the run
                // reports: every arm below keeps a verdict in `judged`, and a comparison that
                // failed is returned as the outcome. So a build and strategy stashed for an
                // earlier attempt's comparison describe nothing any more. Left in place, the
                // record described a repaired run that went on to reproduce by the build and
                // recipe of the divergence before it — and, when the repair's comparison failed,
                // blamed that failure on the recipe whose build had compared cleanly.
                judged_built = None;
                judged_strategy = None;
                let comparison = match judgement {
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

                // **The .NET version rung, before the model and without needing one.** A managed
                // assembly that diverges only in its version stamps is answered by building with the
                // published version, read back from the assembly itself — deterministic, so it runs
                // whether or not a provider is configured. It keeps this divergence before going
                // round, exactly as an accepted model repair does, so a re-run that fails still
                // reports what was found here.
                if let Some(next) = dotnet_version_repair(&comparison, &upstream_path, &strategy)
                    && usable(&next, timewarp).is_ok()
                    && changes_anything(&next, &strategy_digest)
                {
                    if verbose {
                        field_wrapped(
                            "repair",
                            "reconstructed the assembly version from the published package; no \
                             model needed",
                            style::good,
                        );
                    }
                    report
                        .repairs
                        .push("deterministic: .NET assembly version reconstruction".into());
                    judged = Some((rebuilt, comparison));
                    judged_built = built.as_ref().ok().cloned();
                    judged_strategy = Some((strategy_digest.clone(), strategy_json.clone()));
                    strategy = next;
                    continue;
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
                            field(
                                "repair",
                                style::warn(&format!("stopped: {}", stop_reason(&reason))),
                            );
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
                            field(
                                "repair",
                                format!(
                                    "attempt {} on {}",
                                    repairs.attempts().len() + 1,
                                    failure.key()
                                ),
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
                            // **Rendered before it is accepted**, exactly as on the build-failure
                            // path. This is the site that actually fires for a divergence, and it
                            // is the one where losing the run costs most: the build *succeeded*,
                            // the comparison is computed, and the verdict is sitting in `judged`
                            // waiting to be recorded. A proposal naming four parameters the tool
                            // does not declare threw all of it away.
                            //
                            // Both arms below keep `judged`, so the run reports the divergence it
                            // found rather than an error about the suggestion for improving it.
                            Ok(next) => match usable(&next, timewarp) {
                                Ok(()) if !changes_anything(&next, &strategy_digest) => {
                                    if verbose {
                                        field(
                                            "repair",
                                            style::warn("proposed the same recipe; nothing to try"),
                                        );
                                    }
                                    report.repair_stopped = Some(
                                        "the proposal renders to the recipe that just ran".into(),
                                    );
                                    judged = Some((rebuilt, comparison));
                                    break (built, strategy_digest);
                                }
                                Ok(()) => {
                                    // **Keep it here too.** The comment above says both arms keep
                                    // `judged`; there are three, and this one — the arm that
                                    // accepts a repair and goes round again — did not. So a
                                    // divergence found on the first pass was dropped the moment
                                    // the *repaired* recipe failed to build, and the run reported
                                    // `build-failed` about the suggestion instead of the
                                    // divergence it had already established.
                                    //
                                    // Observed on `prop-types@15.8.1`: two UMD bundles missing,
                                    // compared and confirmed, then a repaired recipe that called
                                    // `yarn` on an image without it — and the run recorded no
                                    // outcome at all.
                                    //
                                    // A later iteration that reaches a comparison overwrites this,
                                    // so the last real answer always wins.
                                    judged = Some((rebuilt, comparison));
                                    // And the build it came from. Three fields of the record are
                                    // read off `built` — `attestable`, `isolation` and the network
                                    // transcript — and the *failed* repair attempt would answer all
                                    // three about a build that never finished: no isolation, no
                                    // transcript, which reads as "no build ran" rather than "the
                                    // second one did not".
                                    judged_built = built.as_ref().ok().cloned();
                                    judged_strategy =
                                        Some((strategy_digest.clone(), strategy_json.clone()));
                                    strategy = next;
                                    continue;
                                }
                                Err(e) => {
                                    if verbose {
                                        field("repair", style::warn(&format!("discarded: {e}")));
                                    }
                                    report.repair_stopped =
                                        Some(format!("the proposed recipe does not render: {e}"));
                                    tracing::warn!(
                                        "the repair proposed a recipe that will not render: {e:#}"
                                    );
                                    judged = Some((rebuilt, comparison));
                                    break (built, strategy_digest);
                                }
                            },
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
            // **Set, never cleared.** A later iteration's error can be one of ours — a repaired
            // recipe that will not render or will not execute — and `downcast_ref` yields `None`
            // for it. Assigning that would erase the signature this run actually found and file
            // the whole thing as `error:infra` with no failure code, which is the second half of
            // the same defect `usable` closes: the repair must not be able to cost us the answer.
            let this_failure = e
                .downcast_ref::<crate::BuildFailure>()
                .map(|f| f.signature.clone());
            if let Some(sig) = &this_failure {
                report.failure = Some(sig.clone());
            }
            // The decision to attempt a repair is about *this* iteration's failure, so it reads
            // `this_failure` and not the sticky one — otherwise a render error would be answered
            // by repairing a build failure that has already been repaired once.
            let Some(failure) = this_failure else {
                break (built, strategy_digest);
            };

            // **The deterministic rung, before the model and without needing one.**
            //
            // `yarn <script>` where `<script>` is a key in the checkout's `package.json` is
            // `npm run <script>` by another name: same script, same binaries from the same pinned
            // dependency tree. The rule table is right that installing *some* yarn would produce a
            // verdict about a build the publisher never did — and wrong that "a different recipe
            // cannot conjure support for a package manager", because when yarn is a task runner a
            // different recipe does not need to.
            //
            // `prop-types@15.8.1` is the case: its strategy never mentions yarn, and `npm run
            // build` reaches `yarn umd && yarn umd-min` two levels down.
            //
            // Tried here rather than after the model because `docs/13-roadmap.md`'s M3 asks for
            // exactly this — a rule that answers a failure outright, before any provider is
            // configured and without spending a token. It refuses on `yarn install` and friends,
            // where yarn is resolving rather than running.
            if failure.code == "npm/unsupported-package-manager"
                && failure.subject.as_deref() == Some("yarn")
                && let Some(dir) = checkout.as_deref()
                && let Some(next) = trigon_strategy::without_yarn(
                    &strategy,
                    &trigon_strategy::scripts_from_checkout(dir),
                )
                && usable(&next, timewarp).is_ok()
                && changes_anything(&next, &strategy_digest)
            {
                if verbose {
                    field(
                        "repair",
                        style::good("rewrote yarn as npm run; no model needed"),
                    );
                }
                report
                    .repairs
                    .push("deterministic: yarn <script> -> npm run <script>".into());
                strategy = next;
                continue;
            }

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
                        field(
                            "repair",
                            style::warn(&format!("stopped: {}", stop_reason(&reason))),
                        );
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
                        field(
                            "repair",
                            format!(
                                "attempt {} on {}{}",
                                repairs.attempts().len() + 1,
                                failure.key(),
                                if escalate {
                                    style::warn(", escalated")
                                } else {
                                    String::new()
                                },
                            ),
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
                        // **Rendered before it is accepted.** Parsing is not enough: a proposal can
                        // be valid YAML naming a tool parameter that does not exist, and the
                        // rejection then happens inside the *next* build, where it is a fatal error
                        // rather than a rejected suggestion. A model asked to repair Newtonsoft.Json
                        // proposed `project:` for a tool whose parameter is `dir`, and that killed a
                        // run which had already produced a complete comparison — the divergence was
                        // computed, the artifact was on disk, and all of it was thrown away because
                        // the suggestion for improving it was malformed.
                        //
                        // A repair is an attempt to do better than an answer we already have. It
                        // must never be able to cost us that answer.
                        Ok(next) => match usable(&next, timewarp) {
                            Ok(()) if !changes_anything(&next, &strategy_digest) => {
                                if verbose {
                                    field(
                                        "repair",
                                        style::warn("proposed the same recipe; nothing to try"),
                                    );
                                }
                                report.repair_stopped =
                                    Some("the proposal renders to the recipe that just ran".into());
                                break (built, strategy_digest);
                            }
                            Ok(()) => {
                                strategy = next;
                                continue;
                            }
                            Err(e) => {
                                if verbose {
                                    field("repair", style::warn(&format!("discarded: {e}")));
                                }
                                report.repair_stopped =
                                    Some(format!("the proposed recipe does not render: {e}"));
                                tracing::warn!(
                                    "the repair proposed a recipe that will not render: {e:#}"
                                );
                                break (built, strategy_digest);
                            }
                        },
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
        // Beside the rung's own assumptions rather than in a field of its own. The rung already
        // records "NuGet publishes no compiler version, so this builds with whatever .NET SDK the
        // base image carries"; this is the sentence that says which one it carried and why, and the
        // two belong in one list because a reader weighing a divergence reads them together.
        if let Ok(b) = built.as_ref()
            && let Some(why) = &b.sdk_choice
        {
            report.assumptions.push(why.clone());
        }
        // **The mirror's share, derived from what crossed rather than read off a counter.** At an
        // enforced tier the mirror runs inside the build's network namespace in its own process,
        // so its counters die with the container — the same constraint that put `Withheld` in the
        // transcript instead of in `Observed`. The transcript names the upstream URL of every body
        // that crossed, which is the request count; the 429s that carried no body come out through
        // the log as `Throttled`.
        //
        // Handed to the process table rather than written straight into the report, so that one
        // table is the whole account: a sweep's summary then covers the traffic its builds made
        // without summing anything, and `run_one`'s bracket picks this run's share up with the
        // rest.
        if let Ok(b) = built.as_ref() {
            let mut remote: std::collections::BTreeMap<String, trigon_politeness::HostTraffic> =
                Default::default();
            // **Requests, not transcript rows.** A row says a body crossed into the build, which a
            // cache behind the mirror does not change; whether anybody asked a registry for it is
            // a different question the moment one exists. `Asked` is emitted from the two places a
            // body can come from and nowhere else.
            //
            // A run from a mirror too old to emit them falls back to the transcript, which is what
            // it meant before the cache: every body was a request, because there was nowhere else
            // for one to come from.
            if b.asked.is_empty() {
                for e in b.transcript.iter().flatten() {
                    remote
                        .entry(trigon_politeness::host_of(&e.url))
                        .or_default()
                        .requests += 1;
                }
            } else {
                for a in b.asked.iter().filter(|a| !a.cached) {
                    remote.entry(a.host.clone()).or_default().requests += 1;
                }
                // What the cache did, and the one thing ADR-0013 could not discharge by
                // construction: how old the oldest index document this run decided against was.
                report.fetch_cache = Some(crate::progress::FetchCache {
                    hits: b.asked.iter().filter(|a| a.cached).count() as u64,
                    fetched: b.asked.iter().filter(|a| !a.cached).count() as u64,
                    oldest_index_snapshot: b
                        .asked
                        .iter()
                        .filter_map(|a| a.index_fetched_at)
                        .min()
                        .map(rfc3339_from_unix),
                });
            }
            for t in &b.throttled {
                let h = remote.entry(t.host.clone()).or_default();
                h.throttled += 1;
                // A give-up is a request that failed, and it failed because of our request rate.
                if t.gave_up {
                    h.failed += 1;
                }
            }
            for (host, t) in &remote {
                trigon_politeness::note_remote(host, t);
            }
        }
        report.inference_seconds = model.as_ref().and_then(|m| m.inference_seconds());
        // **Beside the tokens, because they are two facts about one provider.** `model_calls` was
        // set only at the success return, past every early return a failing run takes — so a repair
        // that spent 8345 input and 9325 output tokens and then failed recorded `model_calls: 0`.
        // A counter that reads zero while tokens flow makes `docs/07-ai.md` §8's invocation rate,
        // which is supposed to trend down, a number about nothing.
        report.model_calls = calls(&model);
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
                println!();
                field(
                    "mirror",
                    format!(
                        "{} index request(s), {} version(s) withheld across them",
                        observed.index_requests, observed.versions_withheld,
                    ),
                );
                if observed.toolchain_requests > 0 {
                    // Named separately because it is a different claim: the build fetched the
                    // thing that would run, not a dependency, and it did so from a host on the
                    // mirror's allowlist rather than one the strategy chose.
                    field(
                        "",
                        style::muted(&format!(
                            "{} toolchain download(s) through the allowlist",
                            observed.toolchain_requests
                        )),
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
                    record_id: None,
                });
            }
        }
        // **A failed repair must not cost the answer.** `judged` holds a comparison only when an
        // earlier iteration produced one, so reaching here with it set means: the package was
        // built, compared, and found to diverge, and then an *attempt to improve the recipe*
        // failed. The divergence is the finding; the failed attempt is a note about our own
        // suggestion. Reporting the second and discarding the first is what the repair loop's own
        // comments say must never happen, and it happened.
        if let Err(e) = &built {
            let text = e.to_string();
            // A void outranks everything: the artifact under test reached the build, so nothing
            // this run produced is evidence, including any comparison made before the trip.
            if let Some(reason) = text.strip_prefix("void: ") {
                report.void_reason = Some(reason.to_string());
                return Ok(Ran {
                    outcome: Outcome::Void {
                        reason: reason.to_string(),
                    },
                    model_calls: calls(&model),
                    record_id: None,
                });
            }
            if judged.is_none() {
                return Ok(Ran {
                    outcome: build_outcome(e),
                    model_calls: calls(&model),
                    record_id: None,
                });
            }
            // Otherwise fall through to the comparison below. Reaching here with `judged` set
            // means the package was built, compared, and found to diverge — and then an *attempt
            // to improve the recipe* failed to build. The divergence is the finding; the failed
            // attempt is a note about our own suggestion, and reporting the second while
            // discarding the first is what the repair loop's own comments say must never happen.
            if verbose {
                println!("  repair     the repaired recipe did not build; keeping the divergence");
            }
            report
                .repair_stopped
                .get_or_insert(format!("the repaired recipe did not build: {text}"));
            tracing::warn!(
                "a repair attempt failed to build; reporting the divergence found before it: {text}"
            );
        }
        // Describe the run by the build the comparison came from, not by the attempt that failed
        // after it.
        if let Some(b) = judged_built {
            built = Ok(b);
        }
        if let Some((digest, json)) = judged_strategy {
            strategy_digest = digest;
            strategy_json = json;
            report.strategy_digest = strategy_digest.clone();
            if let Some(i) = rec.inputs.as_mut() {
                i.strategy = strategy_json.clone();
            }
        }

        mark("judge");
        // 5. The comparison the loop already made, with the same code path `verify` uses.
        if let Some(outcome) = compare_error {
            return Ok(Ran {
                outcome,
                model_calls: calls(&model),
                record_id: None,
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
                record_id: None,
            });
        };
        if verbose {
            println!();
            print_text(&comparison, false);
        }
        // **A reading of the diff, where a model is on hand to give one.** After the loop, once,
        // about the comparison the run is going to report — not per attempt, where it would be
        // paid for and superseded. The header's promise is "asked only where nothing
        // deterministic answers", and whether a twelve-byte difference in a generated bundle
        // *matters* is exactly such a question.
        //
        // The answer changes nothing. The outcome above is already final, the publication gate
        // does not read the field (`trigon-api` asserts that), and a failed ask is a `WARN` and
        // an absent field — a replayed transcript recorded before this question existed lands
        // there, by design.
        let diff_opinion = match &model {
            Some(cfg) if comparison.outcome == trigon_core::Match::Divergent => {
                diff_for_opinion(&upstream_path, &rebuilt, &comparison).and_then(
                    |(text, shown, of)| match cfg.opinion_on_diff(&text, shown, of) {
                        Ok(o) => Some(o),
                        Err(e) => {
                            tracing::warn!("no reading of the diff: {e:#}");
                            None
                        }
                    },
                )
            }
            _ => None,
        };
        if verbose && let Some(o) = &diff_opinion {
            println!("\n  opinion   likely {} — {}", o.verdict.as_str(), o.reason);
            println!(
                "            a model's reading of the diff, not part of the verdict ({}, {} of \
                 {} differing member(s) shown)",
                o.model, o.members_shown, o.members_differing
            );
        }
        report.diff_opinion = diff_opinion.clone();
        // **Re-read every counter the ask moved, not just the one.** The cost block above ran
        // before the opinion existed; `model_calls` alone was refreshed at the end of this
        // function, so `run.json` counted the opinion call while its token and inference-seconds
        // fields excluded it — and a divergent run whose only model call was the opinion recorded
        // `model_calls: 1` with no token fields at all, the calls-versus-tokens mismatch the cost
        // block's own comment recounts, pointed the other way.
        report.inference_seconds = model.as_ref().and_then(|m| m.inference_seconds());
        if calls(&model) > 0 {
            let u = model.as_ref().map(|m| m.spent()).unwrap_or_default();
            report.tokens_in = Some(u.input);
            report.tokens_out = Some(u.output);
            report.tokens_cached = Some(u.cached_input);
        }
        // Reached only by a run that got this far: a tripped artifact guard returns before here, so
        // no statement is written about a run that fetched its own answer, by the control flow
        // rather than by a check somebody has to remember to write.
        //
        // **Not every void returns, though.** A run at `--egress open`, this command's default, or
        // one a stabilizer somebody wrote applied to, gets here and is signed as a v1 verdict,
        // where `trigon attest` signs the same run as `void/v1` alone (P6 is that command's). This
        // path asks no publication gate. Whether it should refuse, sign the void, or go now that
        // `attest` exists is the owner's decision (`docs/16-findings.md` §3.96, threat model Q2);
        // `--store` then `trigon attest` is the path a claim that matters takes.
        if let Some(path) = &args.attest {
            // The digests the fetch computed over these bytes, sha1 included where the ecosystem
            // publishes one; `write_bundle` refuses them if they are not the comparison's.
            let subject = trigon_attest::Subject::with_digests(
                crate::file_name(&upstream_path),
                &upstream_digest,
                &upstream_digests.sha512,
                upstream_digests.sha1.as_ref(),
            );
            crate::write_bundle(path, args.key.as_deref(), subject, &comparison)?;
        }
        if let Some(dir) = &args.store {
            // A failure here does not fail the run. The comparison already happened and its verdict
            // is what the caller asked for; losing the record is a thing to report, not a reason to
            // throw the verdict away.
            let inputs = RecordInputs {
                strategy_digest: strategy_digest.clone(),
                derivation: Some(derivation.clone()),
                source: report.source.clone(),
                diff_opinion: report.diff_opinion.clone(),
                pin,
                // From the run itself. This used to build a *fresh* `PodmanRunner` — with no
                // mirror image, so not the runner that ran anything — and read its advertised
                // capability, which answered "could some run on this runner be attested" and was
                // recorded as though it answered "was this one". Deriving it from `--egress`
                // instead was worse still: that stamped `attestable: true` on runs whose
                // image-build phases were outside the boundary entirely.
                attestable: built.as_ref().is_ok_and(|b| b.attestable),
                // **The image the build ran on, not the word the caller typed.** `--image auto`
                // resolves inside `build::run_with`, and the resolved value used to stop there:
                // 205 records in this machine's store name `"auto"` as the base image of a run
                // whose record says the field is "pinned by digest". Where no build ran there is
                // no resolved image and the flag is the honest answer, which is what the
                // `unwrap_or_else` says.
                image: built
                    .as_ref()
                    .map(|b| b.base_image.clone())
                    .unwrap_or_else(|_| inputs.image.clone()),
                derived_image: built.as_ref().ok().and_then(|b| b.derived_image.clone()),
                // From the runner, and from the site that armed the guard. These three are why the
                // signed `artifactHashCheck` block said `performed: false` on every run where it
                // had been performed: the values existed, and nothing carried them this far.
                isolation: built
                    .as_ref()
                    .map(|b| b.isolation.clone())
                    .unwrap_or_default(),
                guard_manifest: guard_manifest.clone(),
                guarded_members,
                guard_bytes: guard_kept.clone(),
                // The recipe that produced this comparison, restored above where a failed repair
                // ran after it.
                strategy: strategy_json.clone(),
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
                declines: report.declines.clone(),
                assumptions: report.assumptions.clone(),
                confidence: report.confidence.clone(),
                // What the model was asked, where one was configured. Empty for the healthy
                // majority of a corpus, which is the point of measuring the invocation rate.
                transcript: model.as_ref().map(|m| m.transcript(&args.purl)),
                ..inputs.clone()
            };
            match record_run(dir, &inputs, &upstream_path, &rebuilt, &comparison, verbose) {
                // Claimed, so the wrapper in `run_inner` leaves it alone. Without this the richer
                // record — the one with the comparison, both artifacts and the applied stabilizers
                // in it — would be overwritten by the thinner terminal one a moment later.
                Ok(id) => rec.record_id = Some(id),
                Err(e) => tracing::warn!("could not record this run: {e:#}"),
            }
        }
        report.model_calls = calls(&model);
        Ok(Ran {
            outcome: Outcome::Compared(comparison.outcome),
            model_calls: calls(&model),
            record_id: None,
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
        /// What this run built its base image from, where it built one. `None` on a run that
        /// derived nothing, and on one that never got as far as resolving an image.
        derived_image: Option<trigon_store::DerivedImage>,
        egress: String,
        timewarp: Option<String>,
        strategy_digest: Option<String>,
        derivation: Option<String>,
        /// What was built, and which rung found it. See `RunReport::source`.
        source: Option<trigon_core::SourceProvenance>,
        /// What a model made of the final diff, where one was asked. See the field on `RunRecord`.
        diff_opinion: Option<trigon_core::DiffOpinion>,
        pin: Option<trigon_mirror::Observed>,
        /// What the runner reported about its own enforcement, never what the flag asked for.
        attestable: bool,
        /// The boundary the runner achieved, in its serde spelling. Empty only where no build ran.
        isolation: String,
        /// Digest of the guard manifest the mirror was armed with, and how many members it watched.
        ///
        /// `None` means the guard did not run, and the signed `artifactHashCheck` block says so by
        /// deriving `performed` from the first of these. They are carried rather than re-derived
        /// because only the arming site knows them, and it is eight hundred lines from here.
        guard_manifest: Option<String>,
        guarded_members: Option<u64>,
        /// The manifest itself, exactly the bytes `guard_manifest` is the digest of, and only where
        /// the guard was armed. Stored as a blob so the digest names something a reader can fetch;
        /// it lived in the work directory and was lost with it.
        guard_bytes: Option<Vec<u8>>,
        /// The strategy the recorded attempt ran, as the canonical JSON the store keeps: the blob
        /// `RunRecord.strategy` names. Computed beside `strategy_digest`, from the same value, so
        /// the two describe one attempt; and never mistaken for it, since that digest also covers
        /// the tools the strategy reaches.
        strategy: Option<String>,
        /// What the fetch computed over the published bytes beyond sha256, and what the registry
        /// declared and whether it held. See [`trigon_store::UpstreamDigests`].
        upstream_digests: Option<trigon_store::UpstreamDigests>,
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
        /// The identity of the work: see [`Args::cache_key`]. Without it the publication gate
        /// cannot tell two attempts at one package from two runs against two packages.
        cache_key: Option<String>,
        attempt: u32,
        /// Why each rung that could have answered did not, what the chosen strategy had to assume,
        /// and how far the derivation trusts itself. Lived in the work directory and nowhere the
        /// store could see, so a corpus could report a rate and not what to build next.
        declines: Vec<String>,
        assumptions: Vec<String>,
        confidence: Option<String>,
    }

    fn record_run(
        dir: &Path,
        args: &RecordInputs,
        upstream_path: &Path,
        rebuilt: &Path,
        c: &trigon_compare::Comparison,
        verbose: bool,
    ) -> Result<String> {
        use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let store = Store::local(dir)?;
            // **Named, because the bare `?` said only `No such file or directory`.** Two reads
            // in one function and neither said which file, so a run lost to a deleted rebuild
            // artifact and one lost to a fetch that left nothing behind produced the same eight
            // words. Naming the path is what turned the first of those into a fixable bug.
            let up_bytes = std::fs::read(upstream_path).with_context(|| {
                format!(
                    "reading the published artifact at {}",
                    upstream_path.display()
                )
            })?;
            let rb_bytes = std::fs::read(rebuilt).with_context(|| {
                format!("reading the rebuilt artifact at {}", rebuilt.display())
            })?;
            let up = store.blobs().put(up_bytes.clone()).await?;
            let rb = store.blobs().put(rb_bytes.clone()).await?;
            // The fetch hashed these bytes as they arrived. Confirmed against the bytes being
            // stored, because the record is about to say both describe one artifact, and a file
            // rewritten between the two would make that false with nothing to show it.
            if let Some(d) = &args.upstream_digests {
                let sha512 = trigon_attest::sha512_of(&up_bytes);
                let sha1 = d.sha1.map(|_| trigon_attest::sha1_of(&up_bytes));
                if sha512 != d.sha512 || sha1 != d.sha1 {
                    bail!(
                        "the published artifact at {} is not the bytes the fetch hashed: it \
                         changed on disk between the fetch and the record. Nothing was recorded; \
                         run it again in a work directory nothing else writes to.",
                        upstream_path.display()
                    );
                }
            }

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

            let (strategy, guard_bytes) = keep_strategy_and_guard(&store, args).await?;
            blob_bytes += guard_bytes;
            blob_bytes += args.strategy.as_ref().map_or(0, |j| j.len() as u64);

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
                    derived_image: args.derived_image.clone(),
                    egress: args.egress.clone(),
                    // From the runner, not from a flag, and no longer the empty string it was for
                    // nineteen signed statements.
                    isolation: args.isolation.clone(),
                    guard_manifest: args.guard_manifest.clone(),
                    guarded_members: args.guarded_members,
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
            record.strategy = strategy;
            record.strategy_digest = args.strategy_digest.clone();
            record.trigon_version = Some(building_version());
            record.upstream_digests = args.upstream_digests.clone();
            record.derivation = args.derivation.clone();
            record.source = args.source.clone();
            record.outcome = Some(c.outcome.to_string());
            record.rebuild = Some(ArtifactRef {
                name: crate::file_name(rebuilt),
                sha256: rb,
                bytes: rb_bytes.len() as u64,
                stored: true,
            });
            record.comparison = Some(comparison);
            // ADR-0010 safeguard 2's provenance clause, written down where the gate can reach it.
            // `applied()` is only the passes that actually changed something, which is the same
            // set the provenance cap and the attestation use — a pass that was configured and did
            // no work has no bearing on whether the normalization was somebody's judgement call.
            record.non_builtin_stabilizer =
                Some(c.applied().iter().any(|a| !a.provenance.is_builtin()));
            // The reading, where one was asked. Beside `non_builtin_stabilizer` because they are
            // the same shape of fact: written by the run path, absent meaning unevaluated.
            record.diff_opinion = args.diff_opinion.clone();
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
            // A verdict leaves `terminal` absent by construction: the two are exclusive, and a
            // record carrying both would be saying it did and did not reach a comparison.
            record.terminal = None;
            record.cache_key = args.cache_key.clone();
            record.attempt = args.attempt;
            record.declines = args.declines.clone();
            record.assumptions = args.assumptions.clone();
            record.confidence = args.confidence.clone();
            record.finished = Some(crate::now_rfc3339());
            store.put_run(&record).await?;

            // **Pre-compute the decompiled C# for the members a reader will want it for.** A
            // managed assembly's byte diff is unreadable, so the member view decompiles it — and
            // doing that at serve time needs podman on the serving machine and a container per
            // view. A read replica over a bucket has neither. So the run, which has both, does it
            // once: for each *differing* assembly member (the interesting few, only on a
            // divergence), decompile both sides and store the C# keyed by the assembly's digest.
            // `trigon serve` then reads it without a container. Best effort — a decompile that
            // cannot run leaves the reader the hex view, exactly as before — and content-addressed,
            // so a re-run of the same target rewrites nothing.
            //
            // **After the record is persisted, never before.** This is an aid, and the record is
            // the result; a decompile that stalled — a cold image build reaching the network — must
            // not be able to lose the divergence finding. The container calls it makes are
            // wall-clock bounded (see `decompile`), so this cannot hang the run either, only cost
            // the aid on a bad day. Not counted into `blob_bytes`: the cache is its own namespace
            // and the run's storage budget is about the run.
            if c.outcome == trigon_core::Match::Divergent
                && let Some(diff) = &c.diff
            {
                let up_name = crate::file_name(upstream_path);
                let rb_name = crate::file_name(rebuilt);
                for f in diff
                    .files
                    .iter()
                    .filter(|f| f.status == trigon_compare::FileStatus::Differs)
                {
                    let path = String::from_utf8_lossy(f.path.as_bytes()).into_owned();
                    if !crate::decompile::looks_like_assembly(&path) {
                        continue;
                    }
                    let up_raw = String::from_utf8_lossy(
                        f.upstream_raw_path.as_ref().unwrap_or(&f.path).as_bytes(),
                    )
                    .into_owned();
                    let rb_raw = String::from_utf8_lossy(
                        f.rebuild_raw_path.as_ref().unwrap_or(&f.path).as_bytes(),
                    )
                    .into_owned();
                    let (Ok(a), Ok(b)) = (
                        trigon_api::member::read(up_bytes.clone(), &up_name, &up_raw),
                        trigon_api::member::read(rb_bytes.clone(), &rb_name, &rb_raw),
                    ) else {
                        continue;
                    };
                    let (ad, bd) = (trigon_store::digest_of(&a), trigon_store::digest_of(&b));
                    // Both already cached — a re-run, or an earlier view — so nothing to do.
                    if matches!(store.get_decompiled(&ad).await, Ok(Some(_)))
                        && matches!(store.get_decompiled(&bd).await, Ok(Some(_)))
                    {
                        continue;
                    }
                    if let Some((a_cs, b_cs)) = crate::decompile::sources(&a, &b) {
                        let _ = store.put_decompiled(&ad, &a_cs).await;
                        let _ = store.put_decompiled(&bd, &b_cs).await;
                    }
                }
            }

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
            anyhow::Ok(id)
        })
    }

    /// The Trigon that ran this build, for its record: the crate version and the git revision it
    /// was built from (`docs/19` §4.2 item 3). Not the attestor's version, which a statement signs
    /// beside it and may be a later binary altogether.
    fn building_version() -> String {
        crate::TRIGON_VERSION.to_string()
    }

    /// Store the strategy that ran and the guard manifest the mirror was armed with, as blobs.
    ///
    /// Returns the strategy blob's digest, for `RunRecord.strategy`, and the guard manifest's size
    /// for the cost block. Both used to be thrown away with the work directory:
    /// `RunRecord.strategy` was declared and written by nothing (0 of 371 stored runs), and the
    /// guard manifest's digest was signed into `buildobservation` naming bytes nobody kept (none
    /// of the 167 stored runs that carry one has the manifest in the store).
    ///
    /// The guard's digest was computed where it was armed, from these same bytes, and the record
    /// carries that one; the store's own digest of them is checked against it, so a record can
    /// never name a manifest the store holds under another name.
    async fn keep_strategy_and_guard(
        store: &trigon_store::Store,
        args: &RecordInputs,
    ) -> Result<(Option<trigon_core::Digest>, u64)> {
        let strategy = match &args.strategy {
            Some(json) => Some(store.blobs().put(json.clone().into_bytes()).await?),
            None => None,
        };
        let mut guard_bytes = 0;
        if let Some(bytes) = &args.guard_bytes {
            let stored = store.blobs().put(bytes.clone()).await?.to_hex();
            if args.guard_manifest.as_deref() != Some(stored.as_str()) {
                bail!(
                    "the guard manifest stored as {stored} is not the one the run was armed with \
                     ({}). Refusing to record a run whose guard digest names other bytes; this is \
                     a bug in the run path.",
                    args.guard_manifest.as_deref().unwrap_or("none")
                );
            }
            guard_bytes = bytes.len() as u64;
        }
        Ok((strategy, guard_bytes))
    }

    /// A record for a run that never reached a comparison.
    ///
    /// The other three quarters of a corpus. A `no-strategy`, a build that failed, a guard that
    /// tripped and an infrastructure error are each a different finding, and none of them reached
    /// the store before this existed — so the store held only successes and a browse page over it
    /// reported a rate of one.
    ///
    /// **Thinner than the compared record on purpose.** There is no comparison, no rebuilt
    /// artifact and often no build log, and every one of those is recorded as absent rather than as
    /// empty. `is_evidence()` keys on `outcome.is_some()`, so a record written here is correctly
    /// *not* evidence about the package reproducing, whatever else it says.
    fn record_terminal(
        dir: &Path,
        rec: &Recording,
        report: &crate::progress::RunReport,
        out: &Result<Ran>,
    ) -> Result<Option<String>> {
        use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

        // No artifact means the run died resolving or fetching, before there was anything to be a
        // record about — and before there was a digest to build a run id from. Those stay in the
        // work directory, where `RunReport` already records them on every path.
        let (Some(inputs), Some((path, digest, bytes))) = (&rec.inputs, &rec.upstream) else {
            return Ok(None);
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let store = Store::local(dir)?;
            let id = format!(
                "{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                &digest.to_hex()[..8]
            );
            let mut record = RunRecord::new(
                &id,
                &inputs.purl,
                ArtifactRef {
                    name: crate::file_name(path),
                    sha256: *digest,
                    bytes: *bytes,
                    // Not put in the blob store. A run with no verdict has nothing a signature
                    // could be about, and keeping every artifact of every failed build is how a
                    // corpus becomes a mirror of the registries.
                    stored: false,
                },
                Environment {
                    base_image: inputs.image.clone(),
                    derived_image: inputs.derived_image.clone(),
                    egress: inputs.egress.clone(),
                    // What the runner reported, where one ran. Empty where no build happened,
                    // which is the true value and is how a reader tells the two apart.
                    isolation: report.isolation.clone().unwrap_or_default(),
                    attestable: report.attestable.unwrap_or(false),
                    registry_moment: inputs.timewarp.clone(),
                    pin: report.pin.as_ref().map(|o| trigon_store::PinEvidence {
                        index_requests: o.index_requests,
                        versions_withheld: o.versions_withheld,
                        artifact_requests: o.artifact_requests,
                        toolchain_requests: o.toolchain_requests,
                        rejected: o.rejected,
                    }),
                    // From the arming site, where the guard was armed. These were `None` on every
                    // record this path wrote, so a void run — the one run whose whole story is the
                    // guard — said the guard had not been armed.
                    guard_manifest: inputs.guard_manifest.clone(),
                    guarded_members: inputs.guarded_members,
                },
                &report.started,
            );
            let (strategy, guard_bytes) = keep_strategy_and_guard(&store, inputs).await?;
            record.strategy = strategy;
            record.trigon_version = Some(building_version());
            record.upstream_digests = inputs.upstream_digests.clone();
            record.state = RunState::Done;
            record.cache_key = inputs.cache_key.clone();
            record.attempt = inputs.attempt;
            // No outcome, ever, on this path. `outcome` is what a comparison produced and this ran
            // without one; the story is in `failure` and in `guard_trips`.
            record.outcome = None;
            // From the outcome in hand, not from `report.outcome`.
            //
            // The report's copy is written by `run_one`, which is the *caller* of the function this
            // recording is wrapped inside — so at this instant it is still `None` on every path, and
            // the first version of this recorded a blank for every run. The same shape this file
            // keeps finding: two things that had to agree, with nothing asserting they did.
            record.terminal = Some(match out {
                Ok(ran) => ran.outcome.label(),
                // Ours, and it never reached an outcome to label. `Fault::Infra` by construction:
                // a package cannot cause an error this layer returns as `Err`.
                Err(_) => "failed".to_string(),
            });
            record.failure = report.failure.clone();
            record.declines = report.declines.clone();
            record.assumptions = report.assumptions.clone();
            record.confidence = report.confidence.clone();
            // Paid for and in hand; this is the degraded path, not a reason to drop it. The
            // sibling fields above travel, and an opinion that survived only in `run.json` when
            // `record_run` failed would be the §3.69 shape at a smaller scale.
            record.diff_opinion = report.diff_opinion.clone();
            record.refused_artifact = report.refused_artifact.clone();
            if let Some(r) = &report.void_reason {
                // The artifact under test reached the build, so whatever it produced is evidence of
                // nothing. `is_evidence` keys on this list and must keep doing so.
                record.guard_trips.push(r.clone());
            }
            if let Ok(Ran {
                outcome: Outcome::Void { reason },
                ..
            }) = out
                && !record.guard_trips.iter().any(|g| g == reason)
            {
                record.guard_trips.push(reason.clone());
            }
            record.strategy_digest = report.strategy_digest.clone();
            record.derivation = report.derivation.clone();
            record.source = report.source.clone();
            record.timings = report.timings.clone();
            record.finished = Some(crate::now_rfc3339());
            record.costs = Some(trigon_store::Costs {
                inference_seconds: report.inference_seconds,
                tokens: match (&report.model, report.tokens_in, report.tokens_out) {
                    // One row per model, never summed across them. Absent where nothing was asked,
                    // which is not the same as a model that was asked and returned nothing.
                    (Some(m), Some(i), Some(o)) => vec![trigon_store::Tokens {
                        input: i,
                        cached_input: report.tokens_cached.unwrap_or(0),
                        output: o,
                        model: m.clone(),
                        calls: report.model_calls,
                    }],
                    _ => Vec::new(),
                },
                // Phases with no reading are left out rather than counted as zero, so this is a
                // floor on the true figure and never an overstatement.
                build_seconds: {
                    let read: Vec<f64> = report.timings.iter().filter_map(|(_, s)| *s).collect();
                    (!read.is_empty()).then(|| read.iter().sum())
                },
                egress_bytes: report.network_bytes,
                // The strategy and the guard manifest, and nothing else: no artifact and no log
                // went into the store, and those zeroes are measurements rather than gaps.
                blob_bytes: Some(
                    guard_bytes + inputs.strategy.as_ref().map_or(0, |j| j.len() as u64),
                ),
                artifact_bytes: Some(0),
                log_bytes: Some(0),
            });
            store.put_run(&record).await?;
            tracing::debug!(run = %id, "recorded a run that reached no verdict");
            anyhow::Ok(Some(id))
        })
    }

    #[cfg(test)]
    mod record_keeps_what_the_run_threw_away {
        //! `docs/19` §10 phase 2: the strategy, the guard manifest, the building version and the
        //! published artifact's other digests, which the run computed and then dropped with the
        //! work directory.
        use super::*;

        const STRATEGY: &str = r#"
schema: 1
kind: flow
location:
  repo: https://github.com/stevemao/left-pad
  ref: ff8e7ba8b4122829cf66125ca8445cac7f073bce
src:
- uses: git-checkout
build:
- runs: npm pack
output_path: '*.tgz'
"#;

        fn tmpdir(tag: &str) -> PathBuf {
            let d =
                std::env::temp_dir().join(format!("trigon-record-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        fn tgz() -> Vec<u8> {
            let mut b = ::tar::Builder::new(Vec::new());
            let body = b"module.exports = leftPad;\n";
            let mut h = ::tar::Header::new_ustar();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(1_700_000_000);
            h.set_cksum();
            b.append_data(&mut h, "package/index.js", &body[..])
                .unwrap();
            let tar = b.into_inner().unwrap();
            let mut gz = Vec::new();
            {
                use std::io::Write as _;
                let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
                e.write_all(&tar).unwrap();
                e.finish().unwrap();
            }
            gz
        }

        /// What a run that fetched `bytes` from npm, which declared nothing, knows about them.
        fn fetched(bytes: &[u8]) -> trigon_store::UpstreamDigests {
            trigon_store::UpstreamDigests {
                sha512: trigon_attest::sha512_of(bytes),
                sha1: Some(trigon_attest::sha1_of(bytes)),
                declared: Vec::new(),
                note: Some("npm declared neither `dist.integrity` nor `dist.shasum`".into()),
            }
        }

        /// The inputs a run that got as far as arming the guard carries, with everything else at
        /// the value a run starts with.
        fn inputs(work: &Path, strategy: &trigon_strategy::Strategy, guard: &[u8]) -> RecordInputs {
            let tools = trigon_strategy::ToolRegistry::builtin().unwrap();
            RecordInputs {
                purl: "pkg:npm/left-pad@1.3.0".into(),
                work: work.to_path_buf(),
                image: "localhost/trigon-base@sha256:7cdd".into(),
                derived_image: None,
                egress: "mirror-only".into(),
                timewarp: None,
                strategy_digest: Some(trigon_strategy::strategy_digest(strategy, &tools).unwrap()),
                derivation: Some("heuristic".into()),
                source: None,
                diff_opinion: None,
                pin: None,
                attestable: true,
                isolation: "user_ns".into(),
                guard_manifest: Some(trigon_store::digest_of(guard).to_hex()),
                guarded_members: Some(1),
                guard_bytes: Some(guard.to_vec()),
                strategy: Some(trigon_strategy::canonical(strategy).unwrap()),
                upstream_digests: None,
                network_transcript: Some(Vec::new()),
                inference_seconds: None,
                tokens: Vec::new(),
                timings: Vec::new(),
                transcript: None,
                cache_key: None,
                attempt: 1,
                declines: Vec::new(),
                assumptions: Vec::new(),
                confidence: None,
            }
        }

        fn store(dir: &Path) -> (tokio::runtime::Runtime, trigon_store::Store) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            (rt, trigon_store::Store::local(dir).unwrap())
        }

        #[test]
        fn a_compared_run_stores_its_strategy_and_guard_and_names_both_by_digest() {
            let work = tmpdir("compared");
            let bytes = tgz();
            let (up, rb) = (work.join("left-pad-1.3.0.tgz"), work.join("kept.tgz"));
            std::fs::write(&up, &bytes).unwrap();
            std::fs::write(&rb, &bytes).unwrap();
            let c = trigon_compare::compare_bytes(
                bytes.clone(),
                bytes.clone(),
                trigon_core::Format::TarGz,
                &trigon_stabilize::profile("tar-gzip").unwrap(),
                &trigon_archive::Limits::default(),
            )
            .unwrap();
            let strategy = trigon_strategy::from_yaml(STRATEGY).unwrap();
            let guard = br#"{"artifact":"870c0fe1","members":["ab"]}"#;
            let mut args = inputs(&work, &strategy, guard);
            args.upstream_digests = Some(fetched(&bytes));
            let dir = work.join("store");

            let id = record_run(&dir, &args, &up, &rb, &c, false).unwrap();
            let (rt, store) = store(&dir);
            let r = rt.block_on(store.get_run(&id)).unwrap();

            // The strategy: a blob of its canonical JSON, named by that blob's own digest, which
            // is a file digest and therefore not `strategy_digest`.
            let blob = r.strategy.expect("the strategy is kept");
            let json = trigon_strategy::canonical(&strategy).unwrap();
            assert_eq!(blob, trigon_store::digest_of(json.as_bytes()));
            assert_eq!(
                &rt.block_on(store.blobs().get(&blob)).unwrap()[..],
                json.as_bytes()
            );
            assert_ne!(
                Some(blob.to_hex()),
                r.strategy_digest,
                "the blob digest and the cache digest are different digests"
            );
            assert_eq!(r.strategy_digest, args.strategy_digest);

            // The guard manifest: the bytes the guard was armed with, under the digest the record
            // already carried, so `buildobservation`'s `guardManifest` names something fetchable.
            let named = r.environment.guard_manifest.clone().expect("armed");
            let d = trigon_core::Digest::from_hex(&named).unwrap();
            assert_eq!(&rt.block_on(store.blobs().get(&d)).unwrap()[..], &guard[..]);

            // The build that recorded it, revision and all: `0.0.0` alone identified nothing.
            assert_eq!(r.trigon_version.as_deref(), Some(crate::TRIGON_VERSION));
            assert!(
                crate::TRIGON_VERSION.starts_with(concat!(env!("CARGO_PKG_VERSION"), "+git.")),
                "{}",
                crate::TRIGON_VERSION
            );
            assert_eq!(r.upstream_digests, args.upstream_digests);
            // Counted, because a budget with nothing measuring it is a wish.
            let costs = r.costs.unwrap();
            assert_eq!(
                costs.blob_bytes,
                Some(
                    2 * bytes.len() as u64
                        + serde_json::to_vec(&c).unwrap().len() as u64
                        + guard.len() as u64
                        + json.len() as u64
                )
            );
        }

        #[test]
        fn a_record_whose_fetched_digests_are_not_of_the_stored_bytes_is_not_written() {
            // The sha512 is what a subject will carry. One that is not of the bytes the store keeps
            // would be signed about some other file.
            let work = tmpdir("drifted");
            let bytes = tgz();
            let up = work.join("left-pad-1.3.0.tgz");
            std::fs::write(&up, &bytes).unwrap();
            let c = trigon_compare::compare_bytes(
                bytes.clone(),
                bytes.clone(),
                trigon_core::Format::TarGz,
                &trigon_stabilize::profile("tar-gzip").unwrap(),
                &trigon_archive::Limits::default(),
            )
            .unwrap();
            let strategy = trigon_strategy::from_yaml(STRATEGY).unwrap();
            let mut args = inputs(&work, &strategy, b"{}");
            args.upstream_digests = Some(fetched(b"some other bytes"));
            let e = record_run(&work.join("store"), &args, &up, &up, &c, false).unwrap_err();
            assert!(e.to_string().contains("changed on disk"), "{e:#}");
        }

        #[test]
        fn a_void_run_records_the_guard_it_tripped_the_strategy_and_the_declared_absence() {
            // The run whose whole story is the guard. This path wrote `guard_manifest: None` for
            // every run it recorded, so a void said the guard had never been armed.
            let work = tmpdir("void");
            let bytes = tgz();
            let up = work.join("left-pad-1.3.0.tgz");
            std::fs::write(&up, &bytes).unwrap();
            let strategy = trigon_strategy::from_yaml(STRATEGY).unwrap();
            let guard = br#"{"artifact":"870c0fe1","members":["cd"]}"#;
            let mut args = inputs(&work, &strategy, guard);
            args.upstream_digests = Some(fetched(&bytes));
            let rec = Recording {
                inputs: Some(args.clone()),
                upstream: Some((
                    up.clone(),
                    trigon_store::digest_of(&bytes),
                    bytes.len() as u64,
                )),
                record_id: None,
            };
            let mut report = crate::progress::RunReport::new("pkg:npm/left-pad@1.3.0");
            report.strategy_digest = args.strategy_digest.clone();
            let reason = "the artifact under test arrived from registry.npmjs.org".to_string();
            let out = Ok(Ran::from(Outcome::Void {
                reason: reason.clone(),
            }));
            let dir = work.join("store");

            let id = record_terminal(&dir, &rec, &report, &out).unwrap().unwrap();
            let (rt, store) = store(&dir);
            let r = rt.block_on(store.get_run(&id)).unwrap();
            assert_eq!(r.guard_trips, [reason]);
            assert!(!r.is_evidence());

            let named = r.environment.guard_manifest.expect("the guard was armed");
            assert_eq!(r.environment.guarded_members, Some(1));
            let d = trigon_core::Digest::from_hex(&named).unwrap();
            assert_eq!(&rt.block_on(store.blobs().get(&d)).unwrap()[..], &guard[..]);

            let blob = r.strategy.expect("the strategy that ran is kept too");
            assert_eq!(
                &rt.block_on(store.blobs().get(&blob)).unwrap()[..],
                trigon_strategy::canonical(&strategy).unwrap().as_bytes()
            );
            // The build that recorded it, revision and all: `0.0.0` alone identified nothing.
            assert_eq!(r.trigon_version.as_deref(), Some(crate::TRIGON_VERSION));
            assert!(
                crate::TRIGON_VERSION.starts_with(concat!(env!("CARGO_PKG_VERSION"), "+git.")),
                "{}",
                crate::TRIGON_VERSION
            );

            // The bytes are not kept on this path, so the digests the fetch computed are what a
            // statement's subject will be built from. And npm declared nothing here, which reads
            // as an empty list and a reason, never as a check that passed.
            let digests = r.upstream_digests.expect("kept");
            assert_eq!(digests.sha512, trigon_attest::sha512_of(&bytes));
            assert!(digests.declared.is_empty());
            assert!(digests.note.unwrap().contains("declared neither"));
            assert!(!r.upstream.stored);
        }
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
    /// Render the differing members for a model to read, bounded in bytes.
    ///
    /// Returns the text and `(shown, differing)` — how many members made it in, of how many
    /// there are. The pair travels with the opinion because it is the condition the opinion was
    /// formed under, and `docs/16-findings.md` §3.62's lesson applies to the budget: it is
    /// measured on the rendered string, in bytes, because that is what a prompt is billed in —
    /// a line cap let one long line blow the window.
    ///
    /// The diff machinery is `trigon_api::member`'s — the same `read` and `view` the management
    /// UI serves, budget and binary-sniff included, because a second diff implementation is how
    /// the page and the prompt would come to disagree about what changed (B42 wants this same
    /// renderer for the repair brief).
    fn diff_for_opinion(
        upstream: &Path,
        rebuilt: &Path,
        c: &trigon_compare::Comparison,
    ) -> Option<(String, u32, u32)> {
        const MAX_BYTES: usize = 48 * 1024;
        const MAX_MEMBERS: usize = 8;

        let d = c.diff.as_ref()?;
        let differing: Vec<&trigon_compare::FileDiff> = d
            .files
            .iter()
            .filter(|f| f.status != trigon_compare::FileStatus::Identical)
            .collect();
        if differing.is_empty() {
            return None;
        }
        let up_bytes = std::fs::read(upstream).ok()?;
        let rb_bytes = std::fs::read(rebuilt).ok()?;
        let up_name = crate::file_name(upstream);
        let rb_name = crate::file_name(rebuilt);

        let mut out =
            String::from("`-` lines are the published artifact, `+` lines are the rebuild.\n");
        {
            // **The census and the bytes are taken at different moments, and the model is told.**
            // The comparison that called these members different ran *after* normalization; the
            // bytes below are the raw published and rebuilt members, *before* it. So the diff can
            // show noise — timestamps, ordering, modes — that the verdict already discounted, and
            // an opinion of "equivalent — just a timestamp" about a member the stabilized
            // comparison still flags would be answering the wrong question. Saying which passes
            // ran is the cheap honest half; diffing stabilized bytes is B43.
            let applied: Vec<String> = c.applied().iter().map(|a| a.id.to_string()).collect();
            if !applied.is_empty() {
                out.push_str(&format!(
                    "The comparison that found these differences ran after normalization \
                     ({}); the members are shown before it, so some visible noise may already \
                     be discounted.\n",
                    applied.join(", ")
                ));
            }
        }
        let mut shown = 0u32;
        for f in differing.iter().take(MAX_MEMBERS) {
            if out.len() >= MAX_BYTES {
                break;
            }
            let path = String::from_utf8_lossy(f.path.as_bytes()).into_owned();
            // Each side by the name it has in its own container: a stabilizer may have renamed
            // the member, and `member::read` walks the raw archive.
            let up_path = f.upstream_raw_path.as_ref().unwrap_or(&f.path);
            let rb_path = f.rebuild_raw_path.as_ref().unwrap_or(&f.path);
            use trigon_compare::FileStatus as St;
            let up = (f.status != St::OnlyRebuild)
                .then(|| {
                    trigon_api::member::read(
                        up_bytes.clone(),
                        &up_name,
                        &String::from_utf8_lossy(up_path.as_bytes()),
                    )
                    .ok()
                })
                .flatten();
            let rb = (f.status != St::OnlyUpstream)
                .then(|| {
                    trigon_api::member::read(
                        rb_bytes.clone(),
                        &rb_name,
                        &String::from_utf8_lossy(rb_path.as_bytes()),
                    )
                    .ok()
                })
                .flatten();
            if up.is_none() && rb.is_none() {
                // Neither side readable — a nested member the serving limits refused, say. Name
                // it rather than skip it: the census says it differs and silence would misstate
                // what the model was shown.
                out.push_str(&format!(
                    "\n=== {path} — differs; contents unavailable ===\n"
                ));
                shown += 1;
                continue;
            }
            if f.status == St::Differs && (up.is_none() || rb.is_none()) {
                // One side readable, and the census says both exist. Handing the pair to `view`
                // would render "only in the published artifact" — a false claim, and one the
                // rubric explicitly reads as substantive ("code present on one side only"). A
                // member over the serving limits on one side of a `Differs` pair is enough to
                // get here; the hedge is the truth.
                out.push_str(&format!(
                    "\n=== {path} — differs; only one side was readable, so no diff is shown \
                     ===\n"
                ));
                shown += 1;
                continue;
            }
            // **A managed assembly is decompiled, so the diff is C# and not bytes.** A `.dll`
            // reads as binary and would render as a hex window nobody can act on — and the model
            // reads "binary differences in all DLLs" as substantive because they look it. ILSpy
            // turns each side back into source, normalising the compiler codegen that a rebuild
            // under a different SDK changes throughout, so what is left in the diff is the
            // difference that is really there: on `castle.core` it is three version attributes on
            // otherwise identical code. Display only, best effort, both-sides-or-fall-through —
            // see `crate::decompile`.
            if f.status == St::Differs
                && crate::decompile::looks_like_assembly(&path)
                && let (Some(a), Some(b)) = (up.as_deref(), rb.as_deref())
                && let Some((up_cs, rb_cs)) = crate::decompile::sources(a, b)
            {
                // One header, from `render_member`, so the byte counts stay the *assembly's* and
                // not the decompiled string's — a reader comparing 385 KB to 385 KB should not be
                // told the members are a megabyte of C#. The path carries the caveat that the diff
                // below is a decompilation.
                let mut cs = trigon_api::member::view(
                    &format!(
                        "{path} — C# decompiled by ILSpy (a reading aid, not the bytes). The \
                         decompiler hides most compiler codegen, so an empty diff below means it \
                         found no source-level difference — the bytes still differ, and that is \
                         likely the toolchain, though the decompiler can also miss a difference it \
                         does not render or one past a `diff truncated` note. Weigh it with the \
                         byte census; it is not proof the sources match."
                    ),
                    Some(up_cs.into_bytes()),
                    Some(rb_cs.into_bytes()),
                    None,
                );
                cs.upstream_bytes = Some(a.len() as u64);
                cs.rebuild_bytes = Some(b.len() as u64);
                render_member(&mut out, &cs, MAX_BYTES);
                shown += 1;
                continue;
            }
            let view = trigon_api::member::view(&path, up, rb, None);
            if f.status == St::Differs
                && !view.binary
                && view
                    .text
                    .as_ref()
                    .is_some_and(|t| t.hunks.is_empty() && t.truncated.is_none())
            {
                // Both sides read, text, no truncation — and no difference visible. The archives
                // hold more than one member at this path and `member::read` returns the first,
                // while the census counts occurrences; showing an empty diff under a header that
                // says "differs" would invite "equivalent" about bytes the model never saw.
                out.push_str(&format!(
                    "\n=== {path} — differs; the archives hold more than one member at this \
                     path and the differing occurrence could not be shown ===\n"
                ));
                shown += 1;
                continue;
            }
            render_member(&mut out, &view, MAX_BYTES);
            shown += 1;
        }
        let differing = differing.len() as u32;
        if shown < differing {
            out.push_str(&format!(
                "\n… and {} more differing member(s) not shown.\n",
                differing - shown
            ));
        }
        Some((out, shown, differing))
    }

    /// The longest prefix of `s` that is at most `max` bytes and ends on a char boundary.
    fn prefix_at_char_boundary(s: &str, max: usize) -> &str {
        if s.len() <= max {
            return s;
        }
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }

    /// One member of the diff, appended up to `budget` bytes of the whole rendering.
    fn render_member(out: &mut String, v: &trigon_api::member::MemberView, budget: usize) {
        let sides = match (v.in_upstream, v.in_rebuild) {
            (true, true) => "in both".to_string(),
            (true, false) => "only in the published artifact".to_string(),
            (false, true) => "only in the rebuild".to_string(),
            (false, false) => "in neither".to_string(),
        };
        let size = |b: Option<u64>| b.map(|n| n.to_string()).unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "\n=== {} — {sides}; {} bytes published, {} rebuilt ===\n",
            v.path,
            size(v.upstream_bytes),
            size(v.rebuild_bytes)
        ));
        if let Some(why) = &v.binary_because {
            out.push_str(&format!("(binary: {why}; no text diff)\n"));
            return;
        }
        let Some(t) = &v.text else {
            out.push_str("(no text diff available)\n");
            return;
        };
        if let Some(note) = &t.truncated {
            out.push_str(&format!("(diff truncated: {note})\n"));
        }
        if t.unaligned {
            // The distinction the field exists for, handed to the model in words: "every line
            // changed" and "we did not align it" are different claims.
            out.push_str(
                "(the changed middle was too large to align line by line; it is rendered as \
                 wholly replaced)\n",
            );
        }
        'hunks: for h in &t.hunks {
            out.push_str(&format!(
                "@@ published:{} rebuild:{} @@\n",
                h.upstream_start, h.rebuild_start
            ));
            for l in &h.lines {
                let mark = match l.kind {
                    "removed" => '-',
                    "added" => '+',
                    _ => ' ',
                };
                // The budget is measured *including* the line about to land, not before it —
                // checked before the push, a minified bundle that is one two-megabyte line
                // sailed through at budget-minus-one and blew the window forty-fold, which is
                // §3.62's exact failure mode readmitted through the door that cites it.
                let room = budget.saturating_sub(out.len());
                if room < 2 {
                    out.push_str("(cut here: the byte budget for this prompt is spent)\n");
                    break 'hunks;
                }
                out.push(mark);
                if l.text.len() + 1 > room {
                    out.push_str(prefix_at_char_boundary(&l.text, room - 1));
                    out.push_str("\n(cut mid-line: the byte budget for this prompt is spent)\n");
                    break 'hunks;
                }
                out.push_str(&l.text);
                out.push('\n');
            }
        }
        if t.lines_omitted > 0 {
            out.push_str(&format!("({} diff line(s) omitted)\n", t.lines_omitted));
        }
    }

    #[cfg(test)]
    mod diff_opinion_render_tests {
        use trigon_api::member::{Hunk, Line, MemberView, TextDiff};

        fn text_view(lines: Vec<Line>) -> MemberView {
            MemberView {
                path: "package/index.js".into(),
                in_upstream: true,
                in_rebuild: true,
                upstream_bytes: Some(100),
                rebuild_bytes: Some(101),
                binary: false,
                binary_because: None,
                decompiled: false,
                text: Some(TextDiff {
                    lines_shown: lines.len(),
                    lines_omitted: 0,
                    hunks: vec![Hunk {
                        upstream_start: 5,
                        rebuild_start: 5,
                        lines,
                    }],
                    upstream_lines: 10,
                    rebuild_lines: 10,
                    truncated: None,
                    unaligned: false,
                }),
                hex: None,
                unavailable: None,
            }
        }

        fn line(kind: &'static str, text: &str) -> Line {
            Line {
                kind,
                text: text.into(),
            }
        }

        #[test]
        fn a_text_member_renders_as_marked_lines_with_both_names_for_the_sides() {
            let mut out = String::new();
            super::render_member(
                &mut out,
                &text_view(vec![
                    line("same", "a"),
                    line("removed", "old"),
                    line("added", "new"),
                ]),
                1 << 20,
            );
            assert!(
                out.contains(
                    "=== package/index.js — in both; 100 bytes published, 101 rebuilt ==="
                ),
                "{out}"
            );
            assert!(out.contains("@@ published:5 rebuild:5 @@"), "{out}");
            assert!(out.contains("\n-old\n+new\n"), "{out}");
        }

        #[test]
        fn the_byte_budget_cuts_the_rendering_and_says_so() {
            // §3.62's rule: the cap is measured on the rendered string, in bytes, because that is
            // what a prompt is billed in. A line cap over these ten would pass and a single long
            // line would blow the window.
            let lines: Vec<_> = (0..10).map(|_| line("added", &"y".repeat(200))).collect();
            let mut out = String::new();
            super::render_member(&mut out, &text_view(lines), 600);
            assert!(
                out.contains("the byte budget for this prompt is spent"),
                "{out}"
            );
            assert!(
                out.len() < 1_200,
                "the cut did not hold: {} bytes",
                out.len()
            );
        }

        #[test]
        fn one_line_bigger_than_the_whole_budget_cannot_blow_it() {
            // §3.62's exact failure mode, readmitted once already through the door that cites
            // it: the check ran before the push, so at budget-minus-one a single two-megabyte
            // minified-bundle line landed whole — a forty-fold overshoot. The budget is a
            // budget: the line is cut at a char boundary and the cut says so.
            let lines = vec![line("added", &"y".repeat(2 << 20))];
            let mut out = String::new();
            super::render_member(&mut out, &text_view(lines), 600);
            assert!(
                out.len() < 800,
                "one line blew the budget: {} bytes",
                out.len()
            );
            assert!(
                out.contains("cut mid-line"),
                "{}",
                &out[..out.len().min(200)]
            );
        }

        #[test]
        fn the_cut_lands_on_a_char_boundary() {
            let lines = vec![line("added", &"é".repeat(4_000))];
            let mut out = String::new();
            // An odd budget, so a naive byte slice would land mid-`é` and panic.
            super::render_member(&mut out, &text_view(lines), 601);
            assert!(out.len() < 800, "{}", out.len());
        }

        #[test]
        fn the_line_vocabulary_here_is_the_one_member_view_actually_speaks() {
            // `render_member` matches `Line.kind` by string and falls back to a context mark, so
            // a renamed kind in `trigon_api::member` would silently render every change as
            // unchanged text. Ask the real machinery for a real diff and assert the words.
            let v = trigon_api::member::view(
                "f.txt",
                Some(b"same\nold\n".to_vec()),
                Some(b"same\nnew\n".to_vec()),
                None,
            );
            let kinds: std::collections::BTreeSet<&str> = v
                .text
                .expect("two small text files diff")
                .hunks
                .iter()
                .flat_map(|h| &h.lines)
                .map(|l| l.kind)
                .collect();
            for k in &kinds {
                assert!(
                    ["same", "removed", "added"].contains(k),
                    "member::view now speaks `{k}`, which render_member would draw as context"
                );
            }
            assert!(
                kinds.contains("removed") && kinds.contains("added"),
                "{kinds:?}"
            );
        }

        #[test]
        fn a_binary_member_is_named_and_never_dumped() {
            let mut v = text_view(Vec::new());
            v.binary = true;
            v.binary_because = Some("a NUL in the first kilobyte".into());
            v.text = None;
            let mut out = String::new();
            super::render_member(&mut out, &v, 1 << 20);
            assert!(
                out.contains("(binary: a NUL in the first kilobyte; no text diff)"),
                "{out}"
            );
        }

        #[test]
        fn what_the_diff_machinery_hedged_travels_to_the_model_in_words() {
            // `truncated` and `unaligned` exist because "every line changed" and "we did not
            // look" are different claims. An opinion formed without being told which would be a
            // claim about a diff the model was not shown.
            let mut v = text_view(vec![line("added", "x")]);
            if let Some(t) = &mut v.text {
                t.truncated = Some("only the first 512 KiB of each side was read.".into());
                t.unaligned = true;
                t.lines_omitted = 7;
            }
            let mut out = String::new();
            super::render_member(&mut out, &v, 1 << 20);
            assert!(
                out.contains("(diff truncated: only the first 512 KiB"),
                "{out}"
            );
            assert!(out.contains("too large to align"), "{out}");
            assert!(out.contains("(7 diff line(s) omitted)"), "{out}");
        }
    }

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
    /// Copy a judged artifact out of the directory the next attempt clears.
    ///
    /// `<work>/rebuild` is wiped at the top of every iteration of the build loop, and a verdict
    /// kept across a repair names a file inside it. Returns where the bytes now are, which is
    /// what the record must read.
    ///
    /// **Copied, not moved.** `rebuild/<strategy>-<pid>/<name>` is where
    /// `scripts/rebuild-and-attest.sh` tells the operator to look for the rebuilt artifact, and
    /// it is still the right place for every run that does not repair. This adds a second copy
    /// that outlives the wipe; it does not relocate the first.
    ///
    /// The build log goes with it, to `<work>/build.log` — the path `record_run` already falls
    /// back to when `rebuild/build.log` is gone, so the fallback that existed for another layout
    /// turns out to be exactly the one this needs.
    ///
    /// **On failure the original path is returned rather than a silent substitute.** A copy that
    /// did not happen means the record is about to fail to read the artifact, and it should fail
    /// naming the file that is missing rather than one that was never written.
    pub(crate) fn keep_judged(work: &Path, artifact: &Path) -> PathBuf {
        // Its own name, under `kept/` rather than at the top of the work directory: npm
        // publishes `<name>-<version>.tgz` and the *upstream* copy already sits up there under
        // exactly that name, so writing beside it would overwrite the thing being compared
        // against with the thing being compared.
        let dir = work.join("kept");
        let to = dir.join(crate::file_name(artifact));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!(dir = %dir.display(), "could not keep the judged artifact: {e}");
            return artifact.to_path_buf();
        }
        if let Err(e) = std::fs::copy(artifact, &to) {
            tracing::warn!(from = %artifact.display(), "could not keep the judged artifact: {e}");
            return artifact.to_path_buf();
        }
        // Best effort, and separately: losing the log costs a field of the record, losing the
        // artifact costs the record.
        let log = work.join("rebuild").join("build.log");
        if log.exists() {
            let _ = std::fs::copy(&log, work.join("build.log"));
        }
        to
    }

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

    /// Resolve an image reference that may be a tag into one pinned by digest.
    ///
    /// Pulls if it is not here. `base_image` refuses anything unpinned, and rightly: a tag resolves
    /// to different bytes on different days, which is the one thing a base image for a
    /// reproducibility tool must not do. So the tag is turned into a digest *once*, here, and the
    /// digest is what everything downstream sees and records.
    fn pinned(reference: &str) -> Result<String> {
        if trigon_sandbox::is_pinned(reference) {
            return Ok(reference.to_string());
        }
        let here = std::process::Command::new("podman")
            .args(["image", "exists", reference])
            .status()
            .is_ok_and(|s| s.success());
        if !here {
            println!(
                "  {} {} {}",
                style::label_col("image"),
                style::muted("pulling"),
                style::ident(&short_ref(reference))
            );
            let ok = std::process::Command::new("podman")
                .args(["pull", reference])
                .status()
                .context("running podman pull")?;
            if !ok.success() {
                // Named rather than left as podman's `manifest unknown`. A derived SDK version
                // that has no published image is a gap in this tool's table, not something an
                // operator did, and the next thing they need is a reference that does exist.
                bail!(
                    "could not pull {reference}. If this is a .NET SDK, the version was chosen \
                     from the project's target framework and the package's publish date — see the \
                     `sdk` line above — and the tag it produced does not exist. Name one that \
                     does:\n\n    TRIGON_BASE_PARENT=<an image id> trigon rebuild …"
                );
            }
        }
        // A repository digest where there is one; the local id otherwise. Both are shapes
        // `is_pinned` accepts, and both name exactly one set of bytes.
        for fmt in ["{{index .RepoDigests 0}}", "{{.Id}}"] {
            if let Ok(out) = std::process::Command::new("podman")
                .args(["image", "inspect", reference, "--format", fmt])
                .output()
                && out.status.success()
            {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if trigon_sandbox::is_pinned(&s) {
                    return Ok(s);
                }
            }
        }
        bail!("podman could not give a digest or an id for {reference}")
    }

    /// What an image carries, in the neutral vocabulary `needs:` speaks.
    pub const LABEL_PACKAGES: &str = "org.trigon.packages";
    /// The image it was built from, pinned.
    pub const LABEL_PARENT: &str = "org.trigon.parent";
    /// Which package manager's names those are.
    pub const LABEL_FAMILY: &str = "org.trigon.family";

    /// What `--image auto` derives from, without baking a digest into this source.
    ///
    /// **A hardcoded parent digest is the bug we are here to fix, one level up.** The image the
    /// random sweep used had been pinned in a shell script and never rebuilt as the tool's needs
    /// grew, so it carried `git`, `wget` and `dpkg` against a default list of nine. A digest
    /// written into this file would go stale the same way and would be harder to notice.
    ///
    /// So the parent is taken from what is already on the machine, in order:
    ///
    /// 1. `TRIGON_BASE_PARENT`, for an operator who has decided.
    /// 2. The `org.trigon.parent` of a trigon base image already here — derive a **sibling** from
    ///    the same distribution rather than stacking on our own output.
    /// 3. A trigon base image itself, as a parent. Stacking is worse than a sibling because the
    ///    layers accumulate, but it is much better than refusing, and it is the case that arises
    ///    when the images predate the labels.
    /// 4. Refuse, and say exactly what to run.
    pub fn auto_parent(dotnet_sdk_major: Option<u32>) -> Result<String> {
        // The operator's choice always wins. Naming a parent is how somebody says "build against
        // this SDK", and a default that overrode it would make that unsayable.
        if let Ok(p) = std::env::var("TRIGON_BASE_PARENT")
            && !p.trim().is_empty()
        {
            return pinned(p.trim());
        }

        // **A runtime the evidence does not pin, supplied by the image, because nothing else can.**
        //
        // ADR-0012's rule is that an image may supply bytes the evidence does not pin and never a
        // decision it does. For npm that forbids baking Node in: the registry records
        // `_nodeVersion` for every publish, so an image's Node would override a pin and the run
        // would measure a toolchain nobody chose.
        //
        // NuGet is the other case and the ADR's own list got it wrong. It groups the .NET SDK with
        // Node on the grounds that "a `.csproj` names its frameworks" — but naming a target
        // framework is not pinning an SDK, and the NuGet rung's recorded assumption says so in as
        // many words: *"NuGet publishes no compiler version, so this builds with whatever .NET SDK
        // the base image carries."* Nothing is pinned, so there is no pin to override; refusing to
        // choose does not protect a decision, it just means the ecosystem cannot be verified at
        // all. Twenty-one of twenty-five NuGet targets on the random sweep died on `dotnet: not
        // found`.
        //
        // So `auto` starts from the SDK image, records the digest it resolved, and the run's
        // assumptions already say the SDK was unrecorded upstream. That is the ADR's actual rule
        // applied, rather than its example list repeated.
        if let Some(major) = dotnet_sdk_major {
            return pinned(&crate::dotnet::image_for(major));
        }
        let out = std::process::Command::new("podman")
            .args([
                "images",
                "--filter",
                "reference=localhost/trigon-base",
                "--sort",
                "created",
                "--format",
                &format!("{{{{.Id}}}}\t{{{{index .Labels \"{LABEL_PARENT}\"}}}}"),
            ])
            .output()
            .context("asking podman which base images are here")?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Newest last, which is how `--sort created` orders them.
        let mut newest_id = None;
        for line in text.lines().rev() {
            let (id, parent) = line.split_once('\t').unwrap_or((line, ""));
            if id.trim().is_empty() {
                continue;
            }
            newest_id.get_or_insert_with(|| id.trim().to_string());
            let parent = parent.trim();
            if !parent.is_empty() && !parent.starts_with('<') {
                return Ok(parent.to_string());
            }
        }
        if let Some(id) = newest_id {
            return Ok(id);
        }
        bail!(
            "`--image auto` needs something to build on, and there is no trigon base image on \
             this machine to take a parent from. Either name one:\n\n    \
             TRIGON_BASE_PARENT=docker.io/library/debian@sha256:<digest> trigon rebuild …\n\n\
             or build a base image once and `auto` will derive from its parent afterwards:\n\n    \
             trigon base-image --from docker.io/library/debian@sha256:<digest>\n\n\
             `podman image inspect debian:bookworm-slim --format '{{{{index .RepoDigests 0}}}}'` \
             prints a digest for one you already have."
        )
    }

    /// What a local image says it carries, or `None` if it says nothing.
    ///
    /// `None` is not "carries nothing": it is an image built before the labels existed, or by hand.
    /// Every caller treats it as unknown and goes on to the probe rather than concluding.
    pub fn labelled_packages(image: &str) -> Option<Vec<String>> {
        let out = std::process::Command::new("podman")
            .args([
                "image",
                "inspect",
                image,
                "--format",
                &format!("{{{{index .Labels \"{LABEL_PACKAGES}\"}}}}"),
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // podman prints `<no value>` for a label that is not there.
        if text.is_empty() || text.starts_with('<') {
            return None;
        }
        Some(text.split_whitespace().map(str::to_string).collect())
    }

    /// The tag a derived image gets, from what is in it rather than from when it was made.
    ///
    /// Content-addressed so two runs wanting the same set find the same image instead of building a
    /// second one, and so a changed parent or a changed list is a different image rather than a
    /// silent overwrite.
    fn derived_tag(parent: &str, packages: &[String]) -> String {
        use sha2::Digest as _;
        let mut sorted: Vec<&str> = packages.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted.dedup();
        let mut h = sha2::Sha256::new();
        h.update(parent.as_bytes());
        h.update(b"\0");
        h.update(sorted.join(" ").as_bytes());
        format!("localhost/trigon-base:auto-{:.16x}", h.finalize())
    }

    /// Whether this run may *build* an image, and the reason where it may not.
    ///
    /// **A decision, computed once by the caller, not a tier re-read here.** It was `enforced:
    /// bool`, which meant this function held half the rule — "enforced implies no derivation" —
    /// while the caller held the other half. `--image derive` makes the tier no longer sufficient
    /// to decide, and two places deciding one thing is how they come to disagree.
    ///
    /// The variant travels so the refusal can name the way through it. A message that says only
    /// "not here" is a message that has to be rewritten every time the condition changes.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Derive {
        /// Build one when nothing local carries what the strategy needs.
        IfNeeded,
        /// Refuse instead: the tier is enforced and nobody asked for the derivation.
        NotAtThisTier,
    }

    /// What [`resolve_auto`] settled on, and how it got there.
    ///
    /// The image alone was not enough once `derive` existed: a reference says which bytes ran the
    /// build and says nothing about whether this run fetched them into being. That second fact is
    /// the one the record has to disclose, so it travels with the first rather than being
    /// reconstructed from the tier later.
    pub struct Resolved {
        /// A reference a runner can use. Never a `localhost/...@sha256:` one — see step 4.
        pub image: String,
        /// What this run derived, or `None` where an image already on the machine carried what
        /// the strategy needed. `None` is "nothing was built", not "no image".
        pub derived: Option<trigon_store::DerivedImage>,
    }

    /// Find or build an image carrying `required`, and return a reference a runner can use.
    ///
    /// **This is the whole of "on the fly", and it is a pre-flight rather than a retry.** The
    /// required set is known at render time from the strategy's `system_deps`, so there is no
    /// reason to spend a build discovering it — and a mechanism that only reacts to failure cannot
    /// help the tier where the failure is most expensive.
    ///
    /// Four steps, in this order, because the refusal has to come before the network:
    ///
    /// 1. **Classify.** Any `Decision` or `Unknown` in the set refuses now, with the table's own
    ///    reason. Nothing is derived and nothing is run. This is the gate `docs/21` says must land
    ///    before any apply path: `needs: [npm]` exists in the tree, and installing Debian's npm
    ///    drags Node 18 in behind it and reproduces `env/toolchain-crashed`.
    /// 2. **Select.** An image whose label is a superset of the required set is used as it is.
    /// 3. **Derive.** Otherwise build one, tagged by content.
    /// 4. **Return an id**, never a `localhost/...@sha256:` reference: podman reads the
    ///    `localhost/` prefix as a registry hostname and tries to pull over HTTPS from a registry
    ///    nobody is running, so the operator gets `connection refused` about an image on their own
    ///    disk. `plan.rs` notes that had already cost somebody three round trips.
    pub fn resolve_auto(
        parent: &str,
        required: &[String],
        verbose: bool,
        derive: Derive,
    ) -> Result<Resolved> {
        // The same call the repair gate makes, so a proposal cannot pass validation and be
        // refused here. See `trigon_sandbox::inadmissible`.
        if let Some(why) = trigon_sandbox::inadmissible(required.iter().map(String::as_str)) {
            bail!(why);
        }

        if let Some(have) = labelled_packages(parent)
            && required.iter().all(|r| have.iter().any(|h| h == r))
        {
            if verbose {
                println!(
                    "  {} {}",
                    style::label_col("image"),
                    style::ident(&short_ref(parent))
                );
                println!(
                    "  {} {}",
                    style::label_col(""),
                    style::muted("already carries what this strategy needs")
                );
            }
            return Ok(Resolved {
                image: parent.to_string(),
                derived: None,
            });
        }

        // **Ask the image, where the label cannot answer.** A label is an index and only our own
        // images carry one; `mcr.microsoft.com/dotnet/sdk` has none, so without this every NuGet
        // run derived a child of it — and derived the *wrong* child, adding the npm and PyPI floor
        // to an image that needs none of it. On the .NET 3.1 SDK that is fatal rather than merely
        // wasteful: its base is Debian buster, whose archive has moved, so `apt-get update` exits
        // 100 and a package published in 2019 cannot be built at all.
        //
        // The probe is `verify_command`'s, run in a throwaway container, so the question asked here
        // is the same one the build asks later and the two cannot disagree.
        let missing = missing_from(parent, required);
        if missing.is_empty() {
            if verbose {
                println!(
                    "  {} {}",
                    style::label_col("image"),
                    style::ident(&short_ref(parent))
                );
                println!(
                    "  {} {}",
                    style::label_col(""),
                    style::muted("already carries what this strategy needs")
                );
            }
            return Ok(Resolved {
                image: parent.to_string(),
                derived: None,
            });
        }

        if derive == Derive::NotAtThisTier {
            bail!(
                "`--image auto` would have to build an image to satisfy this strategy, and \
                 building one means `apt-get`, which means network — at an enforced egress tier \
                 that is bytes the run's transcript would never see.\n\n\
                 `--image derive` does it anyway and records that it did, which is the honest \
                 form of what most operators were already doing by hand:\n\n    \
                 trigon rebuild … --egress mirror-only --image derive\n\n\
                 Or keep the derivation outside the run entirely and pass the id:\n\n    \
                 trigon base-image --from {parent}"
            );
        }

        // **What is missing, and for a distribution parent the floor as well.**
        //
        // The floor exists so an image derived for one target serves the next: a set that is
        // exactly one strategy's needs would build a new image per target on a machine doing npm
        // and PyPI work. That reasoning holds for a distribution parent and not for a toolchain
        // image, which is already specialised — nothing else is going to reuse a .NET SDK image
        // with `build-essential` bolted on, and installing it there is how a 2019 package met an
        // archived Debian.
        let toolchain_parent = parent.contains("dotnet");
        let mut packages: Vec<String> = if toolchain_parent {
            missing.clone()
        } else {
            DEFAULT_PACKAGES.iter().map(|s| s.to_string()).collect()
        };
        for r in required {
            if !packages.contains(r) {
                packages.push(r.clone());
            }
        }
        let tag = derived_tag(parent, &packages);
        // Sorted, because this is what the record shows a reader and two runs that installed the
        // same set should not look different for having computed it in a different order.
        let mut recorded = packages.clone();
        recorded.sort();
        recorded.dedup();

        if std::process::Command::new("podman")
            .args(["image", "exists", &tag])
            .status()
            .is_ok_and(|s| s.success())
        {
            // **Derived, and not by this run.** A cache hit spends no network now; an earlier run
            // spent it, possibly without recording anything. Saying `built_here: false` rather
            // than `derived: None` is the difference between "this image was assembled" and "this
            // image came with the machine", and only the first needs a reader's attention.
            return Ok(Resolved {
                image: image_id(&tag)?,
                derived: Some(trigon_store::DerivedImage {
                    parent: parent.to_string(),
                    packages: recorded,
                    built_here: false,
                }),
            });
        }

        field("image", style::ident(&short_ref(parent)));
        field_wrapped(
            "",
            &format!("deriving from it, adding: {}", packages.join(", ")),
            style::warn,
        );
        base_image(parent, &packages, &tag, false, false)?;
        Ok(Resolved {
            image: image_id(&tag)?,
            derived: Some(trigon_store::DerivedImage {
                parent: parent.to_string(),
                packages: recorded,
                built_here: true,
            }),
        })
    }

    /// Which of `required` this image does not have, asked of the image itself.
    ///
    /// The same probe `verify_command` renders for the build, run now instead of later. A failure
    /// to run it answers "everything is missing" rather than "nothing is": deriving an image that
    /// turns out to be redundant costs a build, and skipping one that was needed costs the run.
    fn missing_from(image: &str, required: &[String]) -> Vec<String> {
        if required.is_empty() {
            return Vec::new();
        }
        let script = trigon_sandbox::verify_command(image, required);
        let out = std::process::Command::new("podman")
            .args([
                "run",
                "--rm",
                // **`--network none`, because the probe needs none and P11 says so.** This runs
                // `command -v` against an image; it fetches nothing. It had podman's default
                // networking, and it runs at every tier — before the enforced-tier refusal below
                // it, so `--egress mirror-only` started a container with a route out and the
                // egress accounting never saw it. Threat-model P11 is "at every tier but `open`
                // no phase reaches the network", and this was a phase that could.
                "--network",
                "none",
                "--entrypoint",
                "",
                image,
                "sh",
                "-c",
                &script,
            ])
            .output();
        match out {
            // The probe prints `this base image is missing: a b c` and exits non-zero.
            Ok(o) if !o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                text.lines()
                    .find_map(|l| l.split_once("this base image is missing:"))
                    .map(|(_, rest)| {
                        rest.split_whitespace()
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| required.to_vec())
            }
            Ok(_) => Vec::new(),
            Err(_) => required.to_vec(),
        }
    }

    /// The bare 64-hex id of a local image. See `resolve_auto` step 4 for why not a reference.
    fn image_id(tag: &str) -> Result<String> {
        let out = std::process::Command::new("podman")
            .args(["image", "inspect", tag, "--format", "{{.Id}}"])
            .output()
            .context("asking podman for the derived image's id")?;
        if !out.status.success() {
            bail!("podman could not inspect the image just built as {tag}");
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Build a base image that carries what an enforced tier cannot install.
    /// Mono's PCL reference assemblies, fetched and unpacked rather than installed.
    ///
    /// **Pinned to an exact file.** The archive is content-addressed by nothing, so a floating
    /// `apt-get install` from a third-party repository would put different bytes in the image on
    /// different days — the one thing a base image for a reproducibility tool must not do. This
    /// names one `.deb` and checks its digest, and `dpkg-deb -x` unpacks it without running a
    /// maintainer script or touching the package database.
    const PCL_DEB: &str = "https://download.mono-project.com/repo/ubuntu/pool/main/r/referenceassemblies-pcl/referenceassemblies-pcl_2014.04.14-1xamarin7+ubuntu2004b1_all.deb";

    /// Where the profiles land, and what the NuGet build tool looks for.
    pub const PCL_ROOT: &str = "/opt/pcl-reference-assemblies";

    pub fn base_image(
        from: &str,
        packages: &[String],
        tag: &str,
        print: bool,
        pcl: bool,
    ) -> Result<()> {
        // The sandbox's own rule, not a second copy of it. This used to require `@`, which refused
        // a bare `sha256:<id>` — the form a locally built base image has, and the form
        // `env/base-image-incomplete` puts into the fix command it prints. Trigon was telling an
        // operator to run a command Trigon rejected.
        if !trigon_sandbox::is_pinned(from) {
            bail!(
                "pin `--from` by digest or by image id. A tag resolves to different bytes on \
                 different days, which is exactly what a base image for a reproducibility tool \
                 must not do. `podman images --no-trunc` prints the id of a local image."
            );
        }
        let packages: Vec<String> = if packages.is_empty() {
            DEFAULT_PACKAGES.iter().map(|s| s.to_string()).collect()
        } else {
            packages.to_vec()
        };
        // The same expansion the sandbox would have used, so the image carries exactly what the
        // setup phase would have installed rather than an operator's guess at the package names.
        // **An index, not an authority.** `verify_command`'s probe stays and stays the thing that
        // decides; a selection mechanism that trusted a label would be a second control that fails
        // open, and anyone can build an image by hand carrying any label they like. The label
        // exists so `--image auto` can answer "does this image carry what this strategy needs"
        // without starting a container, and so `podman inspect` can answer "is this current",
        // which today nothing can. Neutral names, because that is the vocabulary `needs:` speaks
        // and the expansion is a function of the family — which is on the label too.
        let mut sorted = packages.clone();
        sorted.sort();
        sorted.dedup();
        let mut containerfile = format!(
            "FROM {from}\n\
             LABEL {LABEL_PACKAGES}=\"{}\"\n\
             LABEL {LABEL_PARENT}=\"{from}\"\n\
             LABEL {LABEL_FAMILY}=\"{}\"\n\
             RUN {}\n",
            sorted.join(" "),
            trigon_sandbox::family_of(from),
            trigon_sandbox::install_command(from, &packages)
        );
        if pcl {
            // `dpkg-deb -x`, not `dpkg -i`: unpack the tree and nothing else. Installing would run
            // maintainer scripts from a third-party repository and write to the package database,
            // neither of which this image wants — it needs the assemblies on disk, at a path the
            // build tool knows.
            containerfile.push_str(&format!(
                "RUN set -eu; \\\n\
                 \x20 wget -O /tmp/pcl.deb {PCL_DEB}; \\\n\
                 \x20 mkdir -p {PCL_ROOT}; \\\n\
                 \x20 dpkg-deb -x /tmp/pcl.deb {PCL_ROOT}; \\\n\
                 \x20 rm /tmp/pcl.deb; \\\n\
                 \x20 test -d {PCL_ROOT}/usr/lib/mono/xbuild-frameworks/.NETPortable\n"
            ));
        }
        // **Before the store check, deliberately.** `--print` renders a Containerfile out of two
        // strings; it pulls nothing, builds nothing and reads nothing from the local store, so
        // gating it on what that store happens to hold made the output a function of the machine
        // rather than of the arguments. It also meant the printed file could not be previewed for
        // an image not yet pulled, which is one of the times you most want to read it.
        if print {
            print!("{containerfile}");
            return Ok(());
        }

        // **Pinned is not the same as resolvable**, and the gap between them is one podman prints a
        // networking error for. Checked before the build rather than discovered eight seconds in —
        // and only on the path that builds, which is the only one the answer is about.
        let exists = std::process::Command::new("podman")
            .args(["image", "exists", from])
            .status()
            .map_or(true, |s| s.success());
        if let Err(why) = trigon_sandbox::resolvable(from, exists) {
            bail!("{why}");
        }

        let dir = std::env::temp_dir().join(format!("trigon-base-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let file = dir.join("Containerfile");
        std::fs::write(&file, &containerfile)?;
        println!(
            "{} {} from {} with: {}",
            style::heading("building"),
            style::ident(&short_ref(tag)),
            style::ident(&short_ref(from)),
            style::warn(&packages.join(", "))
        );
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
                    "\n{} {}: {}",
                    style::good(tag),
                    style::good("is ready"),
                    style::ident(&short_ref(String::from_utf8_lossy(&o.stdout).trim()))
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
                    "\n{} {}",
                    style::good(&format!("{tag} is ready.")),
                    style::muted(&format!(
                        "It has no repository digest until it is pushed, so pass its id:\n\n    \
                         --image {id}"
                    ))
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
            //
            // **The `touch` is not a superstition.** `COPY` writes the context's files with
            // normalized timestamps, and cargo's fingerprints live in the cached `target` — so a
            // crate of ours whose source changed could look unchanged and be served from a stale
            // rlib. That happened: a build failed on a function that was in the tree and not in the
            // compiled library, and it would have failed the other way round just as easily —
            // producing an image labelled with this source digest, carrying a binary compiled from
            // older code. The staleness warning compares labels, so it would have said the image
            // was current. Touching only `crates/` costs the recompile of our seven and keeps the
            // ~180 dependencies cached.
            "FROM docker.io/library/rust:1-alpine AS build\n\
             RUN apk add --no-cache musl-dev\n\
             WORKDIR /src\n\
             COPY . .\n\
             RUN --mount=type=cache,target=/usr/local/cargo/registry \\\n\
             \x20   --mount=type=cache,target=/src/target \\\n\
             \x20   find crates -name '*.rs' -exec touch {} + \\\n\
             \x20   && cargo build --release -p trigon --bin trigon \\\n\
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

        println!(
            "{} {} {}",
            style::heading("building"),
            style::ident(tag),
            style::muted("(this compiles trigon in a container; it takes a few minutes)")
        );
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
        println!(
            "\n{} {}",
            style::good(&format!("{tag} is ready.")),
            style::muted("`--egress mirror-only` can now be enforced.")
        );
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

    pub fn serve(
        port: u16,
        guard: Option<&Path>,
        cache: Option<&Path>,
        cache_scope: Option<&str>,
        cache_max_bytes: Option<u64>,
    ) -> Result<()> {
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
        // Owned before the runtime takes the closure.
        let cache = cache.map(Path::to_path_buf);
        // A scope nobody named is this process, which gives a standalone mirror its own and shares
        // nothing. The conservative default: the prize is across the targets of one sweep, and a
        // mirror serving one build has nothing to share with anybody.
        let scope = cache_scope
            .map(str::to_string)
            .unwrap_or_else(|| format!("pid-{}", std::process::id()));
        let rt = rt;
        rt.block_on(async move {
            let mut mirror = trigon_mirror::Mirror::new()?.with_guard(manifest);
            if let Some(root) = cache {
                mirror = mirror.with_cache(root.clone(), scope.clone(), cache_max_bytes)?;
                println!("  cache      {} (index scope {scope})", root.display());
            }
            let handle = mirror.serve(port).await?;
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
        /// Where the mirror may keep upstream bytes, shared by every target in this sweep.
        pub fetch_cache: Option<(PathBuf, String)>,
        /// Identical consecutive failures that mean a wall rather than a set of findings. `0` is off.
        pub wall: u32,
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

        // How often to check the disk, and how little free space is too little to keep going.
        //
        // The wall itself is `args.wall`, because how many identical failures mean "something
        // broke" is a property of the corpus rather than of the code: on a curated corpus it is
        // ten, and on one sampled at random from a registry ten `no-strategy` in a row is the
        // answer rather than a fault.
        let wall = args.wall;
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

                if wall > 0 && consecutive >= wall {
                    let key = repeated.clone().unwrap_or_default();
                    tracing::error!(
                        cluster = %key,
                        "{wall} targets in a row failed the same way and none succeeded between \
                         them. That is a wall rather than {wall} findings — throttling, a full \
                         disk, a stopped daemon — so the sweep is stopping instead of spending the \
                         night proving it. Every row so far is written; re-run the same command to \
                         resume once the cause is fixed, or pass `--wall 0` if this corpus is \
                         expected to answer the same way this often."
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
                // Every target in the sweep shares one, which is where the repeats are: only 8% of
                // index fetches repeat inside a single target, and the 309 fetches of the npm
                // packument that were 18% of one sweep's egress were spread across its targets.
                fetch_cache: args.fetch_cache.clone(),
                phases: Some(progress.clone()),
                // A sweep runs each target once. Its second attempt, where one is wanted, comes
                // from the queue — which is the component that knows what a confirmation is.
                cache_key: None,
                attempt: 1,
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
        // The whole account, including what the mirrors inside the islands asked on the builds'
        // behalf: `run_one` hands each run's transcript-derived counts to this same table. Before
        // that it covered resolution only, which on an npm sweep is three requests per target out
        // of about eight hundred — a number that looked like a budget and was 0.4% of one.
        let traffic = trigon_politeness::traffic();
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

/// Whether a strategy will render, without running anything.
///
/// Behind `build`, because its only caller is the repair loop and the verifier links no model. The
/// verifier build is `-D warnings`, so an ungated helper is a hard error there rather than a lint.
///
/// The same check the build does, done early so a proposal that cannot work is discarded as a
/// suggestion instead of aborting the run that asked for it. Deliberately the real `render` rather
/// than a cheaper approximation: the failure this exists to catch — a tool parameter that does not
/// exist — is found nowhere else.
/// Whether a proposal actually changes the recipe.
///
/// **Measured on a real run**: a repair proposed a strategy that rendered to the same digest as the
/// one that had just diverged, and the loop rebuilt it — a hundred seconds of container time and a
/// second round of tokens to reach a result that was identical by construction. Two attempts, two
/// `strategy ab54e552a23d45d0` blocks, one answer.
///
/// Compared on the digest rather than the YAML, for the same reason the attestation names it: a
/// reordered key or an edited comment is not a different recipe.
#[cfg(feature = "build")]
fn changes_anything(next: &trigon_strategy::Strategy, current: &Option<String>) -> bool {
    let Some(current) = current else {
        return true;
    };
    match trigon_strategy::ToolRegistry::builtin()
        .and_then(|tools| trigon_strategy::strategy_digest(next, &tools))
    {
        // A digest we cannot compute is not evidence of sameness. Proceed, and let the build say.
        Err(_) => true,
        Ok(d) => &d != current,
    }
}

/// The deterministic .NET version-reconstruction rung: read the published assembly's version stamps
/// and set them on the strategy's `nuget/build/pack` step, or `None` if there is nothing to do.
///
/// Fires on a divergence in which a managed assembly differs — the common case for a signed .NET
/// package whose code reproduces but whose `AssemblyVersion`/`FileVersion`/copyright were stamped by
/// CI from an environment a checkout does not carry. Reconstructs rather than normalizes, because
/// those stamps are consumer-meaningful; the values are the published assembly's own, read back by
/// decompiling one differing member. Guarded by `usable` and `changes_anything` so it neither
/// proposes an unrenderable recipe nor loops once the stamps are set.
#[cfg(feature = "build")]
fn dotnet_version_repair(
    c: &trigon_compare::Comparison,
    upstream_path: &Path,
    strategy: &trigon_strategy::Strategy,
) -> Option<trigon_strategy::Strategy> {
    let d = c.diff.as_ref()?;
    // A differing managed assembly is the signal to try. Its bytes carry the version we need.
    let f = d.files.iter().find(|f| {
        f.status == trigon_compare::FileStatus::Differs
            && trigon_core::is_managed_assembly(&String::from_utf8_lossy(f.path.as_bytes()))
    })?;
    let up_bytes = std::fs::read(upstream_path).ok()?;
    let up_name = crate::file_name(upstream_path);
    let raw = f.upstream_raw_path.as_ref().unwrap_or(&f.path);
    let dll =
        trigon_api::member::read(up_bytes, &up_name, &String::from_utf8_lossy(raw.as_bytes()))
            .ok()?;
    let info = crate::decompile::assembly_version_info(&dll)?;
    // The candidate only; the caller validates it with `usable` and guards against a no-op with
    // `changes_anything`, in view of both, the way the yarn rung does — the acceptance-site
    // tripwire reads that guard out of the source and a validation hidden in here is invisible to
    // it.
    trigon_strategy::with_assembly_version(strategy, &info)
}

#[cfg(feature = "build")]
fn usable(strategy: &trigon_strategy::Strategy, timewarp_base: &str) -> Result<(), String> {
    let tools = trigon_strategy::ToolRegistry::builtin().map_err(|e| e.to_string())?;
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
            has_repo: true,
            // **The run's, not a default.** This was `..Default::default()`, which leaves
            // `timewarp_base` empty — and a recipe that pins a registry moment renders
            // `timewarp_url(…)`, which refuses when no mirror is configured. So a repair that
            // correctly asked for the published moment was discarded as unrenderable, in a run
            // whose mirror was sitting inside the build's network island the whole time.
            //
            // That is the same defect the note below describes, pointed the other way: a guard
            // that validates in a context the build does not use will reject what the build would
            // have accepted, as surely as it accepts what the build will reject.
            timewarp_base: timewarp_base.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    // **Rendered *and* checked for executability, because the executor checks both.** `executable`
    // is deliberately not part of `render` — `trigon strategy render` exists to look at a
    // deps-only fragment and must not refuse one — so a guard that only renders accepts a proposal
    // the build will then reject. That is the gap this function exists to close, and it was open:
    // a repair for `xstate@4.38.3` proposed a recipe that rendered an empty build phase, passed
    // here, replaced the strategy, and died on the next iteration with an error that was not a
    // `BuildFailure`. The run was filed `error:infra` with no failure code — the repair having
    // cost us exactly the answer the comment at its call site says it must never cost.
    let rendered = trigon_strategy::render(strategy, &cx, &tools).map_err(|e| e.to_string())?;
    rendered.executable().map_err(|e| e.to_string())?;
    // **And admissible, because the build asks that too.** The two checks above are the ones the
    // executor makes; `resolve_auto` makes a third before any container starts, and this gate did
    // not. So a repair proposing `needs: [npm]` — which Debian answers with its own Node 18, the
    // `env/toolchain-crashed` the admission table exists to prevent — rendered, executed cleanly
    // on paper, replaced a working strategy, and was refused three steps later where the refusal
    // could no longer become another attempt.
    //
    // Observed on `prop-types@15.8.1`: a divergence found, compared and confirmed, then thrown
    // away by a proposal this function had already approved. The rule and its wording live in
    // `trigon_sandbox::inadmissible` so that the answer here and the answer there cannot differ.
    match trigon_sandbox::inadmissible(rendered.requires.system_deps.iter().map(String::as_str)) {
        Some(why) => Err(why),
        None => Ok(()),
    }
}

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

/// Write a new ed25519 signing key, and say what was written.
fn keygen(out: &Path, public_out: Option<&Path>) -> Result<()> {
    use std::io::Write as _;

    // Refused rather than overwritten, with no `--force`. A signing key is not a file you can
    // regenerate: every statement ever signed with the old one becomes unattributable the moment
    // it is gone, and nothing about `trigon keygen` should be able to do that by being run twice.
    if out.exists() {
        bail!(
            "{} already exists. Refusing to overwrite a signing key — everything ever signed with \
             it becomes unattributable and there is no way back. Move it aside if that is really \
             what you want.",
            out.display()
        );
    }
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let key = trigon_attest::LocalKey::generate();
    let hex: String = key.seed().iter().map(|b| format!("{b:02x}")).collect();

    // Created `0600` rather than chmod'd to it afterwards. A chmod leaves a window in which the
    // key is on disk and world-readable, and that window is the whole vulnerability.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(out)
        .with_context(|| format!("creating {}", out.display()))?;
    writeln!(f, "{hex}").with_context(|| format!("writing {}", out.display()))?;
    drop(f);

    // And then checked, because a mode that was asked for is not a mode that was applied — a
    // filesystem that ignores permissions accepts the request and grants everyone the key. Fail
    // closed: take the file back rather than report success over a key anyone can read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(out)
            .with_context(|| format!("checking the mode on {}", out.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            let _ = std::fs::remove_file(out);
            bail!(
                "{} came out mode {mode:04o} rather than 0600, so the key would be readable by \
                 others. Removed it rather than leave it there; this filesystem cannot hold a \
                 signing key safely.",
                out.display()
            );
        }
    }

    if let Some(pub_path) = public_out {
        std::fs::write(pub_path, key.public_pem())
            .with_context(|| format!("writing {}", pub_path.display()))?;
    }

    field(
        "wrote",
        format!(
            "{} {}",
            style::ident(&out.display().to_string()),
            style::muted("(0600)")
        ),
    );
    if let Some(pub_path) = public_out {
        field("wrote", style::ident(&pub_path.display().to_string()));
    }
    println!();
    // The full hex, never shortened: it is what a verifier pins, so it has to be copyable whole.
    field("public key", style::ident(&key.public_hex()));
    println!();
    field(
        "verify",
        style::ident(&format!(
            "trigon verify-attestation <bundle> --public-key {}",
            key.public_hex()
        )),
    );
    println!();
    println!(
        "{}",
        style::muted(&style::wrap(
            "Pin that hex in whoever checks these statements — it is the only thing that makes a \
             signature mean anything, and an unpinned signature is worth exactly the bundle's \
             re-derivation. This key signs unchained statements, and until a root exists a key \
             like it is what records are published under (ADR-0014 Decision 8); whether a root \
             is built is docs/19 D6.",
            0,
        ))
    );
    Ok(())
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

/// Sign an equivalence statement about `subject` and write it to `path`.
///
/// The subject is the caller's, computed over the upstream bytes, because only the caller knows
/// whether the ecosystem publishes a sha1 for it. It is refused if it is not the comparison's
/// upstream artifact.
///
/// **A v1 statement, deliberately.** `verify --attest` compares two files with no run behind them,
/// so nothing v2 adds — the purl, the strategy, the Trigon that built it, the evidence digests — is
/// known there. `rebuild --attest` does have a run behind it, in this process, and signs v1 as
/// well: it signs what the comparison says and asks no publication gate, so a run the gate calls
/// void at open egress or for a stabilizer somebody wrote is signed here as a verdict. `trigon
/// attest` signs v2 from the store, and signs such a run as `void/v1` (`docs/09` §2.5, §2.6).
fn write_bundle(
    path: &Path,
    key: Option<&Path>,
    subject: trigon_attest::Subject,
    c: &trigon_compare::Comparison,
) -> Result<()> {
    use trigon_attest::Signer as _;

    let st = trigon_attest::Statement::equivalence_for(subject, c)?;
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

/// What `--rerun-comparison` needs: the two artifacts, and the set the claim was made under.
///
/// Grouped for the same reason [`Attest`] is — they are one decision, and they are meaningless
/// apart.
#[derive(Clone, Copy, Default)]
struct Rerun<'a> {
    upstream: Option<&'a Path>,
    rebuild: Option<&'a Path>,
    stabilizers: Option<&'a Path>,
}

fn verify_attestation(
    bundle: &Path,
    rerun: bool,
    files: Rerun<'_>,
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
        let (u, r) = match (files.upstream, files.rebuild) {
            (Some(u), Some(r)) => (u, r),
            _ => bail!("--rerun-comparison needs both --upstream and --rebuild"),
        };
        let stabilizers = files.stabilizers;
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
            let said = |key: &str| st.predicate[key].as_str().unwrap_or("?").to_string();
            match st.predicate_type.as_str() {
                // No verdict, and it is not shown as one: a `?` where a withdrawal has no outcome
                // would read as a claim nobody could parse.
                trigon_attest::WITHDRAWAL => {
                    println!("withdraws {} ({})", said("supersedes"), said("reason"))
                }
                trigon_attest::VOID => println!("claims    void, because {}", said("because")),
                _ => println!("claims    {}", said("outcome")),
            }
            if st.predicate_type != trigon_attest::WITHDRAWAL
                && st.predicate.get("supersedes").is_some()
            {
                println!("supersedes {} ({})", said("supersedes"), said("reason"));
            }
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
    use trigon_attest::config::{Env, EvidenceConfig};
    use trigon_attest::{
        AuthoredPass, EvidenceDigests, Record, RunFacts, RunIdentity, Statement, Subject,
        SupersedeReason, Supersession, VerdictFacts, VoidFacts,
    };
    use trigon_core::purl::CanonicalPurl;
    use trigon_store::{RunRecord, Store};

    pub struct Args {
        pub store: std::path::PathBuf,
        pub run: Option<String>,
        pub key: Option<std::path::PathBuf>,
        pub prune: bool,
        /// A record file this run's statement supersedes.
        pub supersedes: Option<std::path::PathBuf>,
        /// A record file to withdraw, with no run.
        pub withdraw: Option<std::path::PathBuf>,
        pub reason: Option<SupersedeReason>,
    }

    pub fn run(args: Args) -> Result<()> {
        // Before anything is read or signed: a configuration file with an unknown key or a pin
        // that does not parse is refused here, and the main loop exits 5 on it.
        let config = EvidenceConfig::load(&Env::from_process()?)?;
        let signer: Box<dyn trigon_attest::Signer> = match &args.key {
            Some(p) => Box::new(crate::load_key(p)?),
            None => Box::new(trigon_attest::Unsigned),
        };
        // `--withdraw` and `--supersedes` each require `--reason`, which the parser enforces;
        // the other direction it cannot say, and a reason for nothing is a mistake to name.
        let reason = args.reason;
        if reason.is_some() && args.withdraw.is_none() && args.supersedes.is_none() {
            bail!(
                "--reason says why a record is superseded; name the record with --supersedes or \
                 --withdraw"
            );
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let store = Store::local(&args.store)?;
            if let (Some(path), Some(reason)) = (&args.withdraw, reason) {
                return withdraw(&store, path, reason, signer.as_ref()).await;
            }
            let superseded = match (&args.supersedes, reason) {
                (Some(path), Some(reason)) => Some(Superseded::read(path, reason)?),
                _ => None,
            };

            let id = match args.run {
                Some(id) => id,
                None => store
                    .list_runs()
                    .await?
                    .into_iter()
                    .next()
                    .context("this store holds no runs")?,
            };
            let record = store.get_run(&id).await?;
            println!("run       {id}");
            println!("target    {}", record.target);

            let purl = trigon_core::purl::canonicalize(&record.target).with_context(|| {
                format!(
                    "run `{id}` is about `{}`, which has no canonical purl, and every statement \
                     about a published artifact signs one",
                    record.target
                )
            })?;

            let mut written = Vec::new();
            let mut published_set: Option<String> = None;

            let reference = record.target.parse::<trigon_core::TargetRef>()?;
            let target = trigon_core::Target::new(
                reference.clone(),
                trigon_core::ArtifactId::new(record.upstream.name.clone()),
            );
            // The published bytes, where the store kept them, fetched by hash and checked against
            // it. Every statement about the published artifact takes its subject from them.
            let upstream_bytes = match record.upstream.stored {
                true => Some(store.blobs().get(&record.upstream.sha256).await?),
                false => None,
            };
            let upstream_subject = upstream_subject(
                &record,
                upstream_bytes.as_deref(),
                reference.ecosystem.publishes_sha1(),
            )?;
            let supersedes = match &superseded {
                Some(s) => Some(s.check(&upstream_subject, &purl)?),
                None => None,
            };

            // Before anything else. A void run is evidence of nothing about the package — its
            // artifact reached the build over the network, or the build had the whole network, or
            // a stabilizer somebody wrote did the matching — and the one thing we must never do is
            // sign a verdict about it: for a tripped guard that is the forged-attestation attack,
            // arriving exactly as designed. The gate's own answer, so this and `trigon serve` and
            // `publish` cannot disagree about which runs are void.
            if let Some(because) = trigon_api::publication::voided(&record) {
                // Folded on a terminal, one line when piped, as every other narrated line is.
                let said = format!("{}: {}", because.key(), because.sentence());
                println!("void      {}", crate::style::wrap(&said, 10));
                println!(
                    "\n{}",
                    crate::style::wrap(
                        "signing void/v1 and nothing else: a void run gets no verdict, and no \
                         statement that says which way its comparison went",
                        0
                    )
                );
                let st = void_statement(
                    &store,
                    &record,
                    because,
                    &purl,
                    upstream_subject,
                    supersedes,
                )
                .await?;
                written.push(put(&store, &target, &record, &st, signer.as_ref()).await?);
                return finish(
                    &store,
                    &id,
                    &record,
                    &written,
                    None,
                    signer.as_ref(),
                    args.prune,
                )
                .await;
            }

            // Only a verdict signs these, so it is said only where one may be signed.
            let namespace = namespace(&config);
            // The rebuilt artifact's subject, from its bytes when step 1 has them in hand.
            let mut rebuild_subject: Option<Subject> = None;
            // The set the comparison was made under, for `rebuild` to name as the verdict does.
            let mut judged_under: Option<(String, String)> = None;
            // The blobs whose content the statements below vouch for — the network transcript,
            // counted, and the strategy, recomputed — read before anything is signed, so that a
            // refusal over either leaves no statement behind it: step 1 files one.
            let hex = Hex::of(&store, &record).await?;
            let guard_manifest = kept_guard_manifest(&store, &record).await;

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
                let upstream = upstream_bytes
                    .clone()
                    .context("the published artifact is stored, as checked above")?;
                let rebuild = store.blobs().get(&rebuilt.sha256).await?;
                rebuild_subject = Some(Subject::of_bytes(&rebuilt.name, &rebuild, false));

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
                // And about who wrote the stabilizers, which is what makes a run void. The gate
                // reads the record's bit, here and in `serve` and `publish`, so a record saying no
                // hand-written pass applied, beside a comparison in which one did, would have its
                // void run signed here as a verdict and published by the gate as one. A record that
                // says nothing either way (written before the bit existed) is held to the same:
                // the comparison says the run is void, and the gate cannot see that it is.
                let authored = AuthoredPass::of(&comparison);
                let shows = !authored.is_empty();
                if record.non_builtin_stabilizer.map_or(shows, |says| says != shows) {
                    let says = match record.non_builtin_stabilizer {
                        Some(true) => "that a stabilizer a person or a model wrote applied",
                        Some(false) => "that every stabilizer that applied was built in",
                        None => "nothing about who wrote the stabilizers that applied",
                    };
                    let evidence = match shows {
                        true => {
                            let passes: Vec<String> = authored
                                .iter()
                                .map(|a| format!("`{}` ({})", a.id, a.provenance))
                                .collect();
                            format!("shows {} applied", passes.join(", "))
                        }
                        false => "shows every applied pass was built in".to_string(),
                    };
                    bail!(
                        "run `{id}` records {says}, and the comparison it points at {evidence}. \
                         A run a hand-written stabilizer applied to is void, and the publication \
                         gate reads the record to know it. Refusing to attest a run that disagrees \
                         with its own evidence."
                    );
                }

                // Publish the set this claim was made under, addressed by its own digest. A
                // verifier whose binary carries a different set gets `SetMismatch` and, without
                // this, nothing else — a digest that matches nothing they have. It does not let
                // them run the old set, but it says exactly what the claim was made under.
                //
                // And keep the manifest as a blob of its canonical JSON, which is the file a
                // published record carries and the digest the verdict signs as evidence: not the
                // set digest, which is a hash over the manifest's rows and names no file (`docs/19`
                // §4.2 item 7).
                let set_id = comparison.upstream.set.0.as_str();
                let set = trigon_stabilize::profile(set_id).with_context(|| {
                    format!(
                        "the comparison was made under stabilizer set `{set_id}`, which this build \
                         does not carry, so the claim cannot be re-derived to be signed"
                    )
                })?;
                let manifest = set.manifest();
                match store.put_stabilizer_set(&manifest).await {
                    Ok(p) => published_set = Some(p),
                    Err(e) => tracing::warn!("could not publish the stabilizer set: {e}"),
                }
                let manifest_blob = store
                    .blobs()
                    .put(trigon_attest::set_manifest_file(&manifest)?)
                    .await?
                    .to_hex();
                judged_under = Some((set_id.to_string(), comparison.upstream.set.1.to_hex()));

                // The subject computed over the bytes above, not the one the comparison blob
                // carries: that blob was written by the process that ran the build. The two are
                // checked against each other here and against the bytes again by `rederive`.
                let comparison_hex = comparison_digest.to_hex();
                let rebuilt_hex = rebuilt.sha256.to_hex();
                let run = run_identity(&record, &purl);
                let facts = VerdictFacts {
                    run,
                    derivation: record.derivation.as_deref(),
                    evidence: EvidenceDigests {
                        stabilizer_set_manifest: Some(&manifest_blob),
                        comparison: Some(&comparison_hex),
                        strategy: hex.strategy.as_deref(),
                        guard_manifest: guard_manifest.as_deref(),
                        rebuilt_artifact: Some(&rebuilt_hex),
                    },
                    namespace,
                    supersedes,
                };
                let statement =
                    Statement::verdict(upstream_subject.clone(), &comparison, &facts)
                        .context("the comparison is not about the run's published artifact")?;
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

                written.push(put(&store, &target, &record, &statement, signer.as_ref()).await?);
            } else if supersedes.is_some() {
                // A supersession rides on the run's result, and a run that compared nothing has
                // none: its build observation is not a record.
                bail!(
                    "run `{id}` reached no comparison, so there is no verdict to supersede the \
                     record with. A run that is void supersedes as `void/v1`; one that failed to \
                     build supersedes nothing"
                );
            }

            // 2. How the rebuild came to exist, and what the build was observed to do.
            let facts = RunFacts {
                stabilizer_set: judged_under
                    .as_ref()
                    .map(|(id, digest)| (id.as_str(), digest.as_str())),
                ..facts(&record, &hex)
            };
            if let Some(rebuilt) = &record.rebuild {
                // sha256 alone only where the rebuilt bytes were not in hand, which a run with a
                // comparison never reaches: step 1 refuses one whose bytes are gone.
                let subject = rebuild_subject
                    .take()
                    .unwrap_or_else(|| Subject::new(&rebuilt.name, &rebuilt.sha256));
                let st = Statement::rebuild(subject, &facts);
                written.push(put(&store, &target, &record, &st, signer.as_ref()).await?);
            }
            let obs = Statement::build_observation(upstream_subject, &facts);
            written.push(put(&store, &target, &record, &obs, signer.as_ref()).await?);

            finish(
                &store,
                &id,
                &record,
                &written,
                published_set.as_deref(),
                signer.as_ref(),
                args.prune,
            )
            .await
        })
    }

    /// Name what was signed on the run's record, say what was written, and prune if asked.
    async fn finish(
        store: &Store,
        id: &str,
        record: &RunRecord,
        written: &[String],
        published_set: Option<&str>,
        signer: &dyn trigon_attest::Signer,
        prune: bool,
    ) -> Result<()> {
        // **Appended, never replaced.** Statements are filed under this run and never
        // overwritten, and the record names every one of them: an earlier attest's statements
        // are the history of what was claimed about this run, and dropping their paths here
        // would lose them as surely as overwriting the files did. Merged into the record as it
        // is now rather than written back from the copy read above, so another attestor that
        // finished meanwhile keeps its paths; and per-target paths from before statements were
        // filed per run are set aside, since another run may have written over any of them.
        let named = store.record_attestations(id, written).await?;
        let set_aside = record
            .attestations
            .iter()
            .filter(|p| named.per_target_attestations.contains(p))
            .count();
        if set_aside > 0 {
            println!(
                "set aside {set_aside} statement path(s) filed per target, which any run of \
                 this target may have written over; the record now names only statements \
                 filed under this run"
            );
        }

        println!();
        for p in written {
            println!("  {p}");
        }
        if let Some(p) = published_set {
            println!("  {p}");
        }
        say_who_signed(signer);

        if prune {
            match store.prune_rebuild(id).await {
                Ok(true) => println!("pruned the rebuilt artifact; its digests remain"),
                Ok(false) => {
                    println!("kept the rebuilt artifact: a divergence needs its bytes")
                }
                Err(e) => println!("did not prune: {e}"),
            }
        }
        Ok(())
    }

    fn say_who_signed(signer: &dyn trigon_attest::Signer) {
        if !signer.key_id().is_empty() {
            println!("\nsigned with key {}", signer.key_id());
        } else {
            println!(
                "\nunsigned — the claims are complete and checkable, but nothing here says who \
                 made them"
            );
        }
    }

    /// The origin and the dispute channel to sign into a verdict, and a line saying what was
    /// decided, because a statement that names no repository is fine for local use and refused
    /// by `publish`, and the operator should not find that out there.
    fn namespace(config: &EvidenceConfig) -> Option<(&str, &str)> {
        let p = config.publish();
        match (&p.origin, &p.disputes) {
            (Some(origin), Some(_)) => {
                println!("origin    {origin} — signed into the falsifying command");
            }
            (Some(_), None) | (None, Some(_)) => println!(
                "origin    [publish] sets one of `origin` and `disputes` and not the other, so \
                 neither is signed: the falsifying command and the dispute pointer go in \
                 together or not at all"
            ),
            (None, None) => {}
        }
        p.namespace()
    }

    fn run_identity<'a>(r: &'a RunRecord, purl: &'a CanonicalPurl) -> RunIdentity<'a> {
        RunIdentity {
            purl,
            run_id: &r.id,
            started: &r.started,
            finished: r.finished.as_deref(),
            builder_version: r.trigon_version.as_deref(),
            attestor_version: crate::TRIGON_VERSION,
            egress: &r.environment.egress,
            attestable: r.environment.attestable,
        }
    }

    /// The guard manifest's digest, where the run names one **and the store holds it**.
    ///
    /// The verdict and a void name it as evidence a published record carries, and a record cannot
    /// carry bytes nobody kept. Runs recorded before the manifest was stored name a digest and
    /// hold nothing (`docs/19` §10 phase 2); their statements name no guard manifest evidence, and
    /// `buildobservation` still names its digest, as it always did, for what the guard was armed
    /// with. Fetched by hash, so a blob that does not hash to its name is not it.
    async fn kept_guard_manifest(store: &Store, r: &RunRecord) -> Option<String> {
        let named = r.environment.guard_manifest.as_deref()?;
        let digest = trigon_core::Digest::from_hex(named).ok()?;
        match store.blobs().get(&digest).await {
            Ok(_) => Some(digest.to_hex()),
            Err(_) => {
                println!(
                    "guard     the manifest {} names is not in the store (recorded before \
                     manifests were kept), so no statement names it as evidence",
                    crate::short(named)
                );
                None
            }
        }
    }

    /// The `void/v1` statement for a run the gate calls void, from the facts that make it one.
    ///
    /// Each fact is checked against what the store holds before it is signed, as a verdict's are:
    /// a void that says a hand-written stabilizer fired, over a comparison in which none did, is a
    /// signed statement that is not true, even if it is a harmless one.
    async fn void_statement(
        store: &Store,
        r: &RunRecord,
        because: trigon_api::Withheld,
        purl: &CanonicalPurl,
        subject: Subject,
        supersedes: Option<Supersession>,
    ) -> Result<Statement> {
        let guard_manifest = kept_guard_manifest(store, r).await;
        let mut set: Option<(String, String)> = None;
        let mut authored = Vec::new();
        if let Some(d) = r.comparison {
            let bytes = store.blobs().get(&d).await?;
            let comparison: trigon_compare::Comparison = serde_json::from_slice(&bytes)?;
            set = Some((
                comparison.upstream.set.0.as_str().to_string(),
                comparison.upstream.set.1.to_hex(),
            ));
            authored = AuthoredPass::of(&comparison);
        }
        if because == trigon_api::Withheld::NonBuiltinStabilizer && authored.is_empty() {
            bail!(
                "run `{}` records that a stabilizer somebody wrote applied, and {}. Refusing to \
                 sign a void that rests on a fact its own evidence does not show",
                r.id,
                match r.comparison {
                    Some(_) => "its comparison shows every applied pass was built in",
                    None => "it has no comparison to show which",
                }
            );
        }
        Ok(Statement::void(
            subject,
            &VoidFacts {
                run: run_identity(r, purl),
                because: because.key(),
                guard_trips: &r.guard_trips,
                guard_manifest: r.environment.guard_manifest.as_deref(),
                guarded_members: r.environment.guarded_members,
                authored: &authored,
                stabilizer_set: set.as_ref().map(|(id, d)| (id.as_str(), d.as_str())),
                guard_manifest_evidence: guard_manifest.as_deref(),
                supersedes,
            },
        ))
    }

    /// A record this attest supersedes, read from its file.
    ///
    /// A path to a record file for now; `docs/19` §10 phase 4 defines verifying one and phase 6
    /// resolves one by digest in a clone. Nothing here checks its signatures: what is taken from
    /// it is its name, the sha256 of its bytes, and what its own statement says it is about, which
    /// a supersession has to match to mean anything.
    struct Superseded {
        record: trigon_core::Digest,
        reason: SupersedeReason,
        statement: Statement,
    }

    impl Superseded {
        fn read(path: &Path, reason: SupersedeReason) -> Result<Self> {
            let bytes =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            let record = Record::from_slice(&bytes)
                .with_context(|| format!("reading the record {}", path.display()))?;
            let statement = record
                .statement()
                .with_context(|| format!("reading the record {}", path.display()))?;
            Ok(Superseded {
                record: Record::digest_of(&bytes),
                reason,
                statement,
            })
        }

        /// The subject and the purl the superseded record's statement signed.
        fn about(&self) -> Result<(&Subject, &str, u64)> {
            let subject = self
                .statement
                .subject
                .first()
                .context("the record's statement names no subject")?;
            let purl = self.statement.predicate["purl"].as_str().context(
                "the record's statement signs no purl, so it is not a record this can supersede",
            )?;
            let canon = self.statement.predicate["purlCanon"]
                .as_u64()
                .context("the record's statement signs a purl and no `purlCanon`")?;
            Ok((subject, purl, canon))
        }

        /// The supersession, where this run is about the record's artifact.
        ///
        /// A client drops a superseded record only for a superseding one with the same subject
        /// digests and canonical purl (`docs/19` §3), so one that differs would be signed, logged
        /// and ignored: refused here, where the mistake is made.
        fn check(&self, subject: &Subject, purl: &CanonicalPurl) -> Result<Supersession> {
            let (theirs, their_purl, _) = self.about()?;
            if theirs.digest != subject.digest {
                bail!(
                    "the record names {:?} and this run's published artifact is {:?}. A \
                     superseding statement is about the same artifact, digest for digest, or a \
                     client never applies it",
                    theirs.digest,
                    subject.digest
                );
            }
            if their_purl != purl.as_str() {
                bail!(
                    "the record is about `{their_purl}` and this run about `{purl}`. A \
                     superseding statement names the same package, or a client never applies it"
                );
            }
            println!(
                "supersedes sha256:{} ({})",
                self.record.to_hex(),
                self.reason
            );
            Ok(Supersession {
                record: self.record,
                reason: self.reason,
            })
        }
    }

    /// `trigon attest --withdraw <record> --reason <code>`: "we were wrong", with no run behind it.
    async fn withdraw(
        store: &Store,
        path: &Path,
        reason: SupersedeReason,
        signer: &dyn trigon_attest::Signer,
    ) -> Result<()> {
        let superseded = Superseded::read(path, reason)?;
        let (subject, purl, canon) = superseded.about()?;
        println!("withdraws {purl}");
        println!("record    sha256:{} ({reason})", superseded.record.to_hex());
        let st = Statement::withdrawal(
            subject.clone(),
            purl,
            canon,
            Supersession {
                record: superseded.record,
                reason,
            },
            crate::TRIGON_VERSION,
        );
        let env = trigon_attest::sign_statement(&st, signer)?;
        let written = store.put_withdrawal(&superseded.record, &env).await?;
        println!("\n  {written}");
        say_who_signed(signer);
        Ok(())
    }

    /// Sign a statement and file it under this run.
    async fn put(
        store: &Store,
        target: &trigon_core::Target,
        record: &RunRecord,
        st: &Statement,
        signer: &dyn trigon_attest::Signer,
    ) -> Result<String> {
        let env = trigon_attest::sign_statement(st, signer)?;
        Ok(store
            .put_attestation(
                target,
                &record.id,
                &record.upstream.name,
                &st.predicate_type,
                &env,
            )
            .await?)
    }

    /// The subject of every statement about the published artifact.
    ///
    /// **Computed over the bytes wherever the store kept them**, which is every run with a
    /// comparison: sha256 and sha512, and sha1 where the ecosystem publishes one, so a consumer
    /// holding an npm lockfile's `integrity` or an old one's `shasum` finds the statement
    /// (`docs/19` §5). The digests the run recorded at fetch must agree, or the record and its
    /// bytes describe different artifacts and nothing is signed.
    ///
    /// Where the bytes are gone — a run that reached no verdict keeps none — the recorded digests
    /// are what the fetch computed over them; and a run recorded before it kept any is named by
    /// sha256 alone, which is all anybody knows about it.
    fn upstream_subject(r: &RunRecord, bytes: Option<&[u8]>, with_sha1: bool) -> Result<Subject> {
        let name = r.upstream.name.as_str();
        let Some(bytes) = bytes else {
            return Ok(match &r.upstream_digests {
                Some(d) => {
                    Subject::with_digests(name, &r.upstream.sha256, &d.sha512, d.sha1.as_ref())
                }
                None => Subject::new(name, &r.upstream.sha256),
            });
        };
        let subject = Subject::of_bytes(name, bytes, with_sha1);
        if let Some(d) = &r.upstream_digests {
            let named = |algorithm: &str| subject.digest.get(algorithm).cloned();
            let agrees = named("sha512") == Some(d.sha512.to_hex())
                && d.sha1.is_none_or(|h| named("sha1") == Some(h.to_hex()));
            if !agrees {
                bail!(
                    "run `{}` recorded digests for its published artifact that the stored bytes do \
                     not hash to, so the record and the bytes describe different artifacts. \
                     Refusing to sign a subject for either.",
                    r.id
                );
            }
        }
        Ok(subject)
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
        /// The strategy blob's digest, which is what the `strategy.json` byproduct names.
        strategy: Option<String>,
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
            let strategy = match &r.strategy {
                Some(blob) => Some(checked_strategy(store, r, blob).await?),
                None => None,
            };
            Ok(Hex {
                network_transcript,
                build_log: r.build_log.map(|d| d.to_hex()),
                instructions: r.instructions.map(|d| d.to_hex()),
                strategy,
            })
        }
    }

    /// The strategy blob a run names, fetched and checked before its digest is signed.
    ///
    /// The `strategy.json` byproduct names this blob, and `strategyDigest` beside it names the
    /// strategy with the tools it reaches; `docs/19` §4.2 item 7 binds the record's strategy
    /// evidence by the blob. Copied out of the record, as it was, the pair could name a file the
    /// store does not hold, or one that is not the strategy the digest describes, and no reader
    /// could fetch the one or match the other. So the blob is fetched by hash, which refuses one
    /// that is missing or does not hash to its name; read as a strategy, and required to be that
    /// strategy's canonical JSON, the only form a run writes; and its `strategyDigest` recomputed
    /// under this binary's tools and held to the record's.
    ///
    /// **The last can refuse an honest record.** `strategyDigest` covers the definitions of the
    /// tools the strategy reaches, so a binary in which one of them has changed since the build
    /// recomputes another digest. Refused all the same: the attestor cannot tell that from an
    /// altered record, and a digest it could not reproduce is a digest it was told.
    async fn checked_strategy(
        store: &Store,
        r: &RunRecord,
        blob: &trigon_core::Digest,
    ) -> Result<String> {
        let bytes = store.blobs().get(blob).await.with_context(|| {
            format!(
                "reading the strategy blob run `{}` names. Refusing to sign a `strategy.json` \
                 byproduct nobody could fetch.",
                r.id
            )
        })?;
        let not_a_strategy = |why: String| {
            anyhow::anyhow!(
                "the strategy blob run `{}` names is not a strategy as a run writes one ({why}). \
                 Refusing to sign it as the strategy that ran.",
                r.id
            )
        };
        let text = std::str::from_utf8(&bytes).map_err(|e| not_a_strategy(e.to_string()))?;
        let strategy =
            trigon_strategy::from_yaml(text).map_err(|e| not_a_strategy(e.to_string()))?;
        if trigon_strategy::canonical(&strategy)? != text {
            return Err(not_a_strategy(
                "it is not the strategy's canonical JSON".into(),
            ));
        }
        if let Some(recorded) = &r.strategy_digest {
            let tools = trigon_strategy::ToolRegistry::builtin()?;
            let recomputed = trigon_strategy::strategy_digest(&strategy, &tools)?;
            if &recomputed != recorded {
                bail!(
                    "run `{}` records strategyDigest {recorded}, and the strategy blob it names \
                     recomputes to {recomputed} under this binary's tools. Either the record was \
                     altered, or a tool the strategy uses has changed since Trigon {} built it. \
                     Refusing to sign a digest that cannot be reproduced; attest with the Trigon \
                     that ran the build.",
                    r.id,
                    r.trigon_version
                        .as_deref()
                        .unwrap_or("(version not recorded)")
                );
            }
        }
        Ok(blob.to_hex())
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
            strategy_blob: hex.strategy.as_deref(),
            source: r.source.as_ref().map(|s| trigon_attest::SourceFacts {
                repo: &s.repo_url,
                commit: &s.commit,
                subdir: s.subdir.as_deref(),
                ref_name: s.ref_name.as_deref(),
                declared: s.declared_url.as_deref(),
                // The stable name, which a test holds equal to the serialized one: this string
                // goes into a signed document, and `Debug` would put `FuzzyTag` where the schema
                // says `fuzzy_tag`.
                how: s.how.as_str(),
            }),
            derivation: r.derivation.as_deref(),
            instructions: hex.instructions.as_deref(),
            build_log: hex.build_log.as_deref(),
            trigon_version: crate::TRIGON_VERSION,
            // The caller names the set where the run compared: it is the comparison's.
            stabilizer_set: None,
            guard_trips: &r.guard_trips,
            refused_artifact: &r.refused_artifact,
            // The two fields that made nineteen signed statements say nobody looked. They are read
            // from the record now rather than hardcoded, and a test below builds a record the way a
            // run does and asserts the predicate comes out `performed: true`.
            guard_manifest: r.environment.guard_manifest.as_deref(),
            guarded_members: r.environment.guarded_members,
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
                    },
                );
            }
            Ok(())
        })
    }

    #[cfg(test)]
    mod guard_facts_reach_the_statement {
        use super::*;
        use trigon_store::{ArtifactRef, Environment, RunRecord};

        fn record(guard: Option<&str>, members: Option<u64>, isolation: &str) -> RunRecord {
            let d = trigon_core::Digest::from_bytes([7u8; 32]);
            let mut r = RunRecord::new(
                "1789753859-cf51460b",
                "pkg:npm/once@1.4.0",
                ArtifactRef {
                    name: "once-1.4.0.tgz".into(),
                    sha256: d,
                    bytes: 1979,
                    stored: true,
                },
                Environment {
                    base_image: "localhost/trigon-base@sha256:7cdd".into(),
                    derived_image: None,
                    egress: "mirror-only".into(),
                    isolation: isolation.into(),
                    attestable: true,
                    registry_moment: None,
                    pin: None,
                    guard_manifest: guard.map(str::to_string),
                    guarded_members: members,
                },
                "2026-09-18T00:00:00Z",
            );
            r.outcome = Some("exact".into());
            r
        }

        /// The regression that signed nineteen false statements.
        ///
        /// `Statement::build_observation` renders `performed` from `guard_manifest.is_some()`, and
        /// its own tests prove both branches. What nothing proved was that a record built the way a
        /// run builds one supplies the field — and none did, so every statement said the artifact
        /// guard had not run on runs where it had, beside an `egressTier` that was correct.
        ///
        /// This asserts the join rather than either half.
        #[test]
        fn a_record_from_an_armed_run_says_the_guard_ran() {
            let r = record(Some(&"ab".repeat(32)), Some(1), "user_ns");
            let hex = Hex {
                network_transcript: None,
                build_log: None,
                instructions: None,
                strategy: None,
            };
            let f = facts(&r, &hex);
            let s = trigon_attest::Statement::build_observation(
                Subject::new(
                    "once-1.4.0.tgz",
                    &trigon_core::Digest::from_bytes([7u8; 32]),
                ),
                &f,
            );
            let check = &s.predicate["artifactHashCheck"];
            assert_eq!(check["performed"], true, "the guard was armed: {check}");
            assert_eq!(check["guardedMembers"], 1);
            assert_eq!(check["guardManifest"]["sha256"], "ab".repeat(32));
            assert_eq!(
                s.predicate["isolation"], "user_ns",
                "the runner's boundary, not an empty string: {}",
                s.predicate
            );
        }

        /// And the other direction still works, so the field keeps meaning something.
        #[test]
        fn a_record_from_an_unarmed_run_still_says_nobody_looked() {
            let r = record(None, None, "");
            let hex = Hex {
                network_transcript: None,
                build_log: None,
                instructions: None,
                strategy: None,
            };
            let s = trigon_attest::Statement::build_observation(
                Subject::new(
                    "once-1.4.0.tgz",
                    &trigon_core::Digest::from_bytes([7u8; 32]),
                ),
                &facts(&r, &hex),
            );
            assert_eq!(s.predicate["artifactHashCheck"]["performed"], false);
        }
    }

    #[cfg(test)]
    mod the_strategy_is_checked_before_it_is_signed {
        use super::*;
        use trigon_store::{ArtifactRef, Environment, RunRecord};

        const STRATEGY: &str = r#"
schema: 1
kind: flow
location:
  repo: https://github.com/stevemao/left-pad
  ref: ff8e7ba8b4122829cf66125ca8445cac7f073bce
src:
- uses: git-checkout
build:
- runs: npm pack
output_path: '*.tgz'
"#;

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        }

        /// A record naming the strategy blob `json` would be, with `strategy_digest` beside it,
        /// and the store holding the blob when `stored`.
        fn run(store: &Store, json: &str, digest: Option<String>, stored: bool) -> RunRecord {
            let blob = match stored {
                true => rt()
                    .block_on(store.blobs().put(json.as_bytes().to_vec()))
                    .unwrap(),
                false => trigon_store::digest_of(json.as_bytes()),
            };
            let mut r = RunRecord::new(
                "1789000000-5a175a17",
                "pkg:npm/left-pad@1.3.0",
                ArtifactRef {
                    name: "left-pad-1.3.0.tgz".into(),
                    sha256: trigon_core::Digest::from_bytes([7u8; 32]),
                    bytes: 3619,
                    stored: false,
                },
                Environment {
                    base_image: "localhost/trigon-base@sha256:7cdd".into(),
                    derived_image: None,
                    egress: "mirror-only".into(),
                    isolation: "user_ns".into(),
                    attestable: true,
                    registry_moment: None,
                    pin: None,
                    guard_manifest: None,
                    guarded_members: None,
                },
                "2026-09-27T00:00:00Z",
            );
            r.strategy = Some(blob);
            r.strategy_digest = digest;
            r.trigon_version = Some("0.0.0".into());
            r
        }

        fn canonical() -> (String, String) {
            let s = trigon_strategy::from_yaml(STRATEGY).unwrap();
            let tools = trigon_strategy::ToolRegistry::builtin().unwrap();
            (
                trigon_strategy::canonical(&s).unwrap(),
                trigon_strategy::strategy_digest(&s, &tools).unwrap(),
            )
        }

        #[test]
        fn a_stored_strategy_that_recomputes_to_its_digest_is_named_by_its_blob() {
            let store = Store::in_memory();
            let (json, digest) = canonical();
            let r = run(&store, &json, Some(digest), true);
            let hex = rt().block_on(Hex::of(&store, &r)).unwrap();
            assert_eq!(hex.strategy, r.strategy.map(|d| d.to_hex()));

            // A record from before `strategyDigest` was kept beside it has only the blob to check.
            let r = run(&store, &json, None, true);
            assert!(rt().block_on(Hex::of(&store, &r)).is_ok());
        }

        #[test]
        fn a_strategy_the_store_does_not_hold_is_not_signed() {
            // The byproduct would name a file nobody can fetch.
            let store = Store::in_memory();
            let (json, digest) = canonical();
            let r = run(&store, &json, Some(digest), false);
            let e = rt().block_on(Hex::of(&store, &r)).err().expect("it signed");
            assert!(format!("{e:#}").contains("strategy blob"), "{e:#}");
        }

        #[test]
        fn a_strategy_digest_the_blob_does_not_recompute_to_is_not_signed() {
            // The record and the file it names describe different recipes: signing both would be
            // signing whichever a reader happened to check.
            let store = Store::in_memory();
            let (json, _) = canonical();
            let r = run(&store, &json, Some("ab".repeat(32)), true);
            let e = rt().block_on(Hex::of(&store, &r)).err().expect("it signed");
            let msg = format!("{e:#}");
            assert!(msg.contains("recomputes to"), "{msg}");
            assert!(msg.contains(&"ab".repeat(32)), "{msg}");
        }

        #[test]
        fn a_blob_that_is_not_a_strategy_in_canonical_form_is_not_signed() {
            let store = Store::in_memory();
            let (json, digest) = canonical();
            let yaml = STRATEGY.to_string();
            for bad in ["not a strategy at all", "{}", yaml.as_str()] {
                let r = run(&store, bad, Some(digest.clone()), true);
                let e = rt().block_on(Hex::of(&store, &r)).err().expect("it signed");
                assert!(format!("{e:#}").contains("not a strategy"), "{bad}: {e:#}");
            }
            // The YAML above is the same strategy, and still refused: a run writes canonical JSON,
            // so a blob in any other form was not written by one.
            assert_ne!(yaml, json);
        }
    }
}

#[cfg(all(test, feature = "build"))]
mod usable_tests {
    /// The proposal that killed a completed run, verbatim in shape: valid YAML, a real tool, and a
    /// parameter that tool does not declare. `nuget/build/pack` takes `dir`, not `project`.
    const NAMES_A_PARAMETER_THAT_DOES_NOT_EXIST: &str = "\
schema: 1
kind: flow
location:
  repo: https://github.com/JamesNK/Newtonsoft.Json
  ref: d50b912e9948472e122cfaf24ffeebbf77032806
  subdir: Src/Newtonsoft.Json
src:
- uses: git-checkout
build:
- uses: nuget/build/pack
  with:
    project: Src/Newtonsoft.Json
output_dir: trigon-pack
";

    const USES_THE_PARAMETER_IT_DECLARES: &str = "\
schema: 1
kind: flow
location:
  repo: https://github.com/JamesNK/Newtonsoft.Json
  ref: d50b912e9948472e122cfaf24ffeebbf77032806
  subdir: Src/Newtonsoft.Json
src:
- uses: git-checkout
build:
- uses: nuget/build/pack
  with:
    dir: Src/Newtonsoft.Json
output_dir: trigon-pack
";

    #[test]
    fn a_proposal_that_will_not_render_is_refused_before_it_can_replace_a_working_recipe() {
        // A repair is an attempt to do better than an answer we already have. Accepting this one
        // cost a run that had already computed a complete comparison: the rejection happened inside
        // the *next* build, where it was a fatal error rather than a discarded suggestion.
        let bad = trigon_strategy::from_yaml(NAMES_A_PARAMETER_THAT_DOES_NOT_EXIST).unwrap();
        let why = super::usable(&bad, "timewarp:8129")
            .expect_err("`project` is not a parameter of this tool");
        assert!(why.contains("has no parameter"), "{why}");
        assert!(why.contains("project"), "{why}");
        // And it names what the tool does take, so the operator reading the line can tell whether
        // the model was close or lost.
        assert!(why.contains("dir"), "{why}");
    }

    #[test]
    fn every_place_a_proposal_is_accepted_validates_it_first() {
        // **The class, not the instance.** There are two repair paths — one for a build failure and
        // one for a divergence — and the first fix guarded only the build-failure one. The
        // divergence path is the one that actually fires for a package that builds and compares,
        // and it is where losing the run costs most: the verdict is already computed.
        //
        // Read out of the source rather than asserted about behaviour, because what must not
        // happen is a *third* acceptance site added without the check. A behavioural test on the
        // two that exist would pass on the day someone adds one.
        let src = include_str!("main.rs");
        // **The property, not one spelling of it.** This counted `match usable(&next, timewarp)`
        // against acceptances, which held while every site was a `match` — and then the
        // deterministic yarn rung arrived, guarding with `usable(&next, timewarp).is_ok()` in an
        // `&&` chain. Counting one form made a correctly-guarded site look unguarded.
        //
        // So: every acceptance must have a validation somewhere above it in the same block.
        let accept = concat!("strategy = ", "next;");
        let guard = concat!("usable(&next,", " timewarp)");
        let sites: Vec<usize> = src.match_indices(accept).map(|(i, _)| i).collect();
        assert!(
            sites.len() >= 2,
            "the acceptance sites moved; this test needs rewriting"
        );
        for at in sites {
            // **Anchored on where `next` is bound, not on a byte count.** A window was the first
            // attempt and had to keep growing: a comment added above one acceptance pushed its
            // guard 2,800 bytes away and the check started failing on correct code. The rule is
            // that the proposal is validated between being bound and being accepted, so those are
            // the two ends to measure between.
            let bound = ["Ok(next)", "Some(next)"]
                .iter()
                .filter_map(|b| src[..at].rfind(b))
                .max()
                .expect("an acceptance names a proposal that was bound somewhere above it");
            assert!(
                src[bound..at].contains(guard),
                "a repair proposal bound at byte {bound} is accepted at byte {at} without \
                 `{guard}` in between. An unvalidated one can abort a run that already has an \
                 answer."
            );
        }
        // And each guard must keep the run's result rather than propagate. Both paths break with
        // the state they had; neither may use `?` on the proposal.
        // Split so this test's own source does not contain the pattern it forbids — it reads
        // `main.rs`, and `main.rs` is where this assertion lives.
        // **Every arm keeps the answer, including the one that goes round again.**
        //
        // The comment at the divergence site says "both arms below keep `judged`" — and there are
        // three. The middle one accepts the repair and continues, and did not. So a divergence
        // that had been built, compared and confirmed was dropped the moment the *repaired* recipe
        // failed to build: `prop-types@15.8.1` reported no outcome at all, having established two
        // minutes earlier that two UMD bundles were missing.
        //
        // Pinned as a *pair*, not as a count. There are two accept arms and only one of them has
        // a comparison to keep: the build-failure path has no verdict yet, so requiring one there
        // would be wrong. The divergence arm is the one that stashes the build, so that assignment
        // is the anchor — and the keep must sit immediately before it.
        //
        // Split, so this test's own source does not satisfy the check it is making, which is the
        // same trap the assertion above documents.
        // Every arm that stashes the build must keep the comparison first. There are two now — the
        // model's divergence accept arm and the deterministic .NET version rung — so this pairs
        // each `stash` with a `keep` that precedes it and follows the previous `stash`, rather than
        // pinning a count or a single anchor. That spans the comment one arm puts between the two
        // lines, and cannot be satisfied by a neighbour: each keep is spent on exactly one stash.
        let stash = concat!("judged_built = built", ".as_ref().ok().cloned();");
        let keep = concat!("judged = Some((rebuilt,", " comparison));");
        let stashes: Vec<usize> = src.match_indices(stash).map(|(i, _)| i).collect();
        assert!(
            !stashes.is_empty(),
            "the divergence accept arm moved; this check needs rewriting"
        );
        let mut prev = 0;
        for at in stashes {
            assert!(
                src[prev..at].contains(keep),
                "an arm that accepts a repair after a divergence stashes the build at byte {at} \
                 without keeping the comparison first. A repaired recipe that then fails to build \
                 would lose a verdict the run had already established and report `build-failed`."
            );
            prev = at + stash.len();
        }

        let propagates = concat!("usable(&next, timewarp)", "?");
        assert!(
            !src.contains(propagates),
            "a validation failure must discard the proposal, not end the run"
        );
    }

    #[test]
    fn an_attempt_that_reaches_a_comparison_lets_go_of_the_one_before() {
        // The other half of the stash above. It keeps a divergence's build and strategy so a
        // repair that fails cannot lose them, and it was never let go of: a repair that went on
        // to reproduce was recorded with the divergent attempt's isolation, transcript and
        // attestability, restored after the loop over the attempt that actually answered. Every
        // arm after a comparison keeps that comparison, so reaching one is the moment the stash
        // stops describing anything.
        //
        // Read out of the source, like the check above, because the property is about the order
        // of lines in a loop that needs a container runtime to execute.
        //
        // Both ways a comparison can end, not only success. A comparison that fails is the run's
        // outcome, returned after the loop; with the stash cleared only on success, that failure
        // was recorded with the strategy and build of the earlier, divergent attempt, whose own
        // comparison had worked. So the clearing sits between the call and the failure arm.
        let src = include_str!("main.rs");
        let judged = concat!("let judgement = judge(&upstream_path,", " &rebuilt);");
        let at = src
            .find(judged)
            .expect("the comparison inside the loop moved");
        let after = &src[at..];
        let failed = after
            .find(concat!("compare_error = Some", "(outcome);"))
            .expect("the failure arm moved");
        let kept = after
            .find(concat!("if comparison.outcome", " != "))
            .unwrap();
        assert!(
            failed < kept,
            "the failure arm is handled before any verdict is kept"
        );
        for cleared in [
            concat!("judged_built", " = None;"),
            concat!("judged_strategy", " = None;"),
        ] {
            assert!(
                after[..failed].contains(cleared),
                "`{cleared}` must follow the comparison and precede both its failure arm and any \
                 arm that keeps its verdict"
            );
        }
        // And the strategy travels with the build wherever the build is stashed.
        let stash = concat!("judged_built = built", ".as_ref().ok().cloned();");
        let with = concat!("judged_strategy", " =");
        for (i, _) in src.match_indices(stash) {
            let next: String = src[i..].lines().take(3).collect();
            assert!(
                next.contains(with),
                "a build stashed at byte {i} without the strategy that made it"
            );
        }
    }

    #[test]
    fn a_proposal_asking_for_what_no_image_may_supply_is_refused_by_the_gate() {
        // The model's answer on `prop-types@15.8.1`, reduced to the line that mattered: a build
        // step declaring `needs: [npm]`. It renders. It is executable. Both checks this gate used
        // to make pass it — and `resolve_auto` refuses it three steps later, by which time the
        // repair has replaced a strategy that worked and the run has discarded a divergence it
        // spent two minutes establishing.
        //
        // Debian's npm is the table's own worked example: it brings its own Node, 18 on bookworm,
        // and a pinned Node 10 then loads modules written for 18 and aborts.
        let yaml = r#"
schema: 1
kind: flow
location:
  repo: https://example.invalid/r
  ref: abc
src:
- uses: git-checkout
build:
- runs: npm run build
  needs: [npm]
output_path: '*.tgz'
"#;
        let s = trigon_strategy::from_yaml(yaml).expect("the proposal itself is valid YAML");
        let e = super::usable(&s, "http://mirror.invalid")
            .expect_err("a recipe needing `npm` in the image must not pass the repair gate");
        assert!(
            e.contains("npm"),
            "the refusal should name the dependency: {e}"
        );
        assert!(e.contains("ADR-0012"), "and say which rule refuses it: {e}");
    }

    #[test]
    fn the_admission_rule_is_asked_in_one_place() {
        // ADR-0008. The gate and the image resolver both have to answer "may an image supply
        // this?", and they answered it separately: the resolver ran the filter, the gate did not
        // run it at all. Re-implementing the filter here is how they drift back apart — and the
        // *wording* counts too, because a refusal phrased differently in the two places is the
        // same defect one level down.
        //
        // Split so this test's own source does not contain the pattern it forbids.
        let src = include_str!("main.rs");
        let filter = concat!("admission(d)", ".refusal(d)");
        assert!(
            !src.contains(filter),
            "the admission filter is re-implemented here; call \
             `trigon_sandbox::inadmissible` so the two sites cannot disagree"
        );
    }

    #[test]
    fn the_verdicts_bytes_are_moved_out_of_reach_before_the_loop_clears_the_directory() {
        // The wipe at the top of the build loop deletes `<work>/rebuild`, and `judged` is
        // deliberately carried across it so a failed repair still reports the divergence the run
        // had already found. The path outlived the bytes, and nothing said so: the record read a
        // file the loop had just removed and the run was lost.
        //
        // Anchored on the wipe rather than on a byte window, because the comment between the two
        // is long and a window wide enough to hold it is wide enough to catch something else.
        // Split so this test's own source does not satisfy the check.
        let src = include_str!("main.rs");
        let wipe = concat!("let _ = std::fs::remove_dir_all(", "&out);");
        let at = src
            .find(wipe)
            .expect("the build loop still clears the output directory");
        let keep = concat!("*path = keep_judged(", "&args.work, path);");
        assert!(
            src[..at].contains(keep),
            "the build loop clears `<work>/rebuild` without first moving the judged artifact out \
             of it. A repair that goes round again would delete the bytes the kept verdict names, \
             and the run would end with no record at all."
        );
    }

    #[test]
    fn a_proposal_identical_to_the_recipe_that_just_ran_is_not_worth_a_rebuild() {
        let same = trigon_strategy::from_yaml(USES_THE_PARAMETER_IT_DECLARES).unwrap();
        let tools = trigon_strategy::ToolRegistry::builtin().unwrap();
        let digest = trigon_strategy::strategy_digest(&same, &tools).unwrap();
        assert!(
            !super::changes_anything(&same, &Some(digest)),
            "a proposal rendering to the digest that just ran changes nothing"
        );
        // A different recipe does change something.
        let other = trigon_strategy::from_yaml(
            &USES_THE_PARAMETER_IT_DECLARES.replace("Src/Newtonsoft.Json", "Src/Other"),
        )
        .unwrap();
        assert!(super::changes_anything(
            &other,
            &Some(trigon_strategy::strategy_digest(&same, &tools).unwrap())
        ));
        // And an unknown current digest is not evidence of sameness.
        assert!(super::changes_anything(&same, &None));
    }

    /// A recipe that renders and builds nothing must not get past the guard.
    ///
    /// `Instructions::executable` is deliberately not part of `render` — `trigon strategy render`
    /// has to be able to show a deps-only fragment — so the guard has to ask for both. It did not,
    /// and the consequence was measured: a repair for `xstate@4.38.3` proposed exactly this shape,
    /// passed, replaced the strategy, and the next iteration died with an error that carried no
    /// signature. The run was filed `error:infra` with no failure code, losing a real
    /// `npm/workspace-unbuilt-sibling` verdict to a suggestion for improving it.
    #[test]
    fn a_proposal_that_renders_but_builds_nothing_is_rejected() {
        let empty = trigon_strategy::from_yaml(
            "kind: flow\n\
             location:\n  repo: https://github.com/statelyai/xstate\n  ref: e87600ea\n\
             src:\n  - uses: git-checkout\n\
             deps:\n  - runs: npm ci\n\
             build: []\n\
             output_path: '*.tgz'\n",
        )
        .expect("this parses; that is the point");
        let why = super::usable(&empty, "timewarp:8129")
            .expect_err("a recipe that builds nothing is not usable");
        assert!(
            why.contains("empty build phase"),
            "the rejection has to say what is wrong with it: {why}"
        );
    }

    #[test]
    fn a_proposal_that_renders_is_accepted() {
        // The other half. A check that rejected everything would discard working repairs as
        // readily as broken ones, and would look identical from the outside.
        let good = trigon_strategy::from_yaml(USES_THE_PARAMETER_IT_DECLARES).unwrap();
        super::usable(&good, "timewarp:8129").expect("`dir` is what the tool declares");
    }

    /// A repair that pins the registry moment is not unrenderable.
    ///
    /// **The guard validated in a context the build does not use.** `usable` built its `Context`
    /// with `..Default::default()`, leaving `timewarp_base` empty — and a recipe that pins a
    /// publish moment renders `timewarp_url(…)`, which refuses when no mirror is configured. So a
    /// correct repair was discarded as unrenderable:
    ///
    /// ```text
    /// repair  discarded: deps.[0].npm/deps/custom.[1].npm/install.[0].npm/npx.[0]: template:
    ///         invalid operation: timewarp_url was called but no mirror is configured for this run
    /// ```
    ///
    /// — in a run whose mirror was inside the build's network island the whole time. The comment
    /// on `usable` already describes this defect pointed the other way: a guard that renders in a
    /// context the build does not use will reject what the build accepts as surely as it accepts
    /// what the build rejects.
    #[test]
    fn a_recipe_that_pins_the_registry_moment_renders_under_a_mirror() {
        let yaml = "schema: 1\n\
                    kind: flow\n\
                    location:\n  repo: https://example.invalid/x\n  ref: aa\n\
                    src:\n  - uses: git-checkout\n\
                    deps:\n  - uses: npm/deps/custom\n    with:\n\
                    \x20     node_version: 17.3.0\n\
                    \x20     npm_version: 8.3.0\n\
                    \x20     registry_time: 2022-01-05T00:08:33.458Z\n\
                    build:\n  - uses: npm/build/pack\n    with:\n\
                    \x20     npm_version: 8.3.0\n\
                    \x20     registry_time: 2022-01-05T00:08:33.458Z\n\
                    output_dir: .\n\
                    output_path: '*.tgz'\n";
        let s = trigon_strategy::from_yaml(yaml).expect("the fixture parses");

        // With the mirror the run actually has.
        super::usable(&s, "timewarp:8129")
            .expect("a recipe pinning the registry moment must validate under a mirror");

        // And without one it is genuinely unrenderable, which is the message the operator saw —
        // correct there, and asked in the wrong context here.
        let why = super::usable(&s, "").expect_err("no mirror, no timewarp_url");
        assert!(
            why.contains("no mirror is configured"),
            "the refusal should still name the cause: {why}"
        );
    }
}

/// The text of the project file a .NET build would compile, from a checkout on disk.
///
/// Best effort, and the caller treats absence as "no floor" rather than as an answer. Searched
/// under the strategy's `subdir` where it names one, because a monorepo's other projects target
/// whatever they like and the one being packed is the only one whose framework matters.
///
/// The first `.csproj` in sorted order rather than a search for the right one: the strategy already
/// chose which project to build, and re-deriving that here would be a second answer to a question
/// `nuget_project` settled. Where a directory holds several, their target frameworks are almost
/// always the same, and `choose` takes the highest anyway.
#[cfg(feature = "build")]
/// The `global.json` that applies to a project, if any.
///
/// .NET resolves `global.json` by walking up from the project directory to the filesystem root and
/// taking the first one it finds. This walks up from `subdir` to `root` — the checkout boundary,
/// which is as far as anything we build reaches, and the `starts_with` guard keeps the walk from
/// escaping it. Repositories almost always keep the file at the root, so the common case is one
/// `read` at the top of the walk.
///
/// Build-only: nothing in the verifier chooses an SDK, so under `--no-default-features` this and
/// its sibling below have no caller and `-D warnings` would reject them.
#[cfg(feature = "build")]
fn dotnet_global_json(root: &Path, subdir: Option<&str>) -> Option<String> {
    let start = match subdir {
        Some(d) => root.join(d),
        None => root.to_path_buf(),
    };
    let mut dir = start.as_path();
    loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("global.json")) {
            return Some(text);
        }
        if dir == root {
            break;
        }
        match dir.parent() {
            Some(p) if p.starts_with(root) => dir = p,
            _ => break,
        }
    }
    None
}

#[cfg(feature = "build")]
fn dotnet_project_text(root: &Path, subdir: Option<&str>) -> Option<String> {
    let start = match subdir {
        Some(d) => root.join(d),
        None => root.to_path_buf(),
    };
    let mut found: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![start];
    // Bounded: a deep tree should not turn a pre-flight into a walk of the whole repository.
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == ".git") {
                    continue;
                }
                stack.push(p);
                continue;
            }
            seen += 1;
            if seen > 20_000 {
                break;
            }
            if p.extension().is_some_and(|x| x == "csproj") {
                found.push(p);
            }
        }
    }
    found.sort();
    std::fs::read_to_string(found.first()?).ok()
}

#[cfg(all(test, feature = "build"))]
mod global_json_tests {
    use super::dotnet_global_json;

    #[test]
    fn it_is_found_at_the_root_and_from_a_subdir_walks_up_to_it() {
        let root = std::env::temp_dir().join(format!("trigon-gj-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let deep = root.join("src").join("Castle.Core");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(
            root.join("global.json"),
            r#"{ "sdk": { "version": "7.0.101" } }"#,
        )
        .unwrap();

        // A project two directories down still sees the repository-root pin.
        let from_subdir = dotnet_global_json(&root, Some("src/Castle.Core"));
        assert!(
            from_subdir
                .as_deref()
                .is_some_and(|t| t.contains("7.0.101")),
            "{from_subdir:?}"
        );
        // And so does a build rooted at the top.
        assert!(dotnet_global_json(&root, None).is_some());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_global_json_anywhere_is_none_and_the_walk_stays_inside_the_root() {
        // A global.json above the checkout boundary must not be read: it is not part of what was
        // published, and reading it would pin a build to a file the package never carried.
        let base = std::env::temp_dir().join(format!("trigon-gj-outside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("checkout");
        let sub = root.join("src");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            base.join("global.json"),
            r#"{ "sdk": { "version": "6.0.0" } }"#,
        )
        .unwrap();

        assert_eq!(
            dotnet_global_json(&root, Some("src")),
            None,
            "the walk stops at the root and never reaches the parent's global.json"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod build_version_tests {
    //! `src/build_version.rs`, which `build.rs` runs, run here against repositories made for it.

    include!("build_version.rs");

    fn dir(what: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "trigon-build-version-{}-{what}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn git(root: &std::path::Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.org"])
            .args(args)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .expect("git runs")
            .status
            .success();
        assert!(ok, "git {args:?}");
    }

    #[test]
    fn a_tree_that_is_not_a_checkout_says_the_revision_is_unknown() {
        // A source archive, which is what a build outside the repository compiles from. It must
        // still build, and say what it does not know rather than leave the revision empty.
        let d = dir("plain");
        let (v, watch) = build_version("1.2.3", &d);
        assert_eq!(v, "1.2.3+git.unknown");
        assert!(watch.is_empty());
    }

    #[test]
    fn a_checkout_is_named_by_its_commit_and_marked_when_it_has_changes() {
        let d = dir("repo");
        git(&d, &["init", "-q"]);
        std::fs::write(d.join("a"), "one").unwrap();
        git(&d, &["add", "a"]);
        git(&d, &["commit", "-q", "-m", "one"]);
        let (v, watch) = build_version("1.2.3", &d);
        let rev = v.strip_prefix("1.2.3+git.").expect(&v);
        assert_eq!(rev.len(), 40, "{v}");
        assert!(rev.bytes().all(|b| b.is_ascii_hexdigit()), "{v}");
        // What moves HEAD, for `cargo:rerun-if-changed`: the HEAD file and the branch it names.
        assert!(watch.iter().any(|p| p.ends_with("HEAD")), "{watch:?}");
        assert!(
            watch
                .iter()
                .any(|p| p.to_string_lossy().contains("refs/heads/")),
            "{watch:?}"
        );

        std::fs::write(d.join("a"), "two").unwrap();
        let (dirty, _) = build_version("1.2.3", &d);
        assert_eq!(dirty, format!("{v}.dirty"));
        // An untracked file is a change too: it may be a source file the build compiled.
        git(&d, &["checkout", "-q", "--", "a"]);
        std::fs::write(d.join("new.rs"), "fn f() {}").unwrap();
        assert_eq!(build_version("1.2.3", &d).0, format!("{v}.dirty"));
    }

    #[test]
    fn a_tree_inside_someone_elses_checkout_is_not_stamped_with_their_commit() {
        // An unpacked source archive inside another repository: `git rev-parse HEAD` from there
        // answers with the enclosing repository's commit, which built nothing here.
        let d = dir("nested");
        git(&d, &["init", "-q"]);
        std::fs::write(d.join("a"), "one").unwrap();
        git(&d, &["add", "a"]);
        git(&d, &["commit", "-q", "-m", "one"]);
        let inner = d.join("vendor/trigon");
        std::fs::create_dir_all(&inner).unwrap();
        assert_eq!(build_version("1.2.3", &inner).0, "1.2.3+git.unknown");
    }

    #[test]
    fn a_repository_with_no_commit_yet_says_unknown() {
        let d = dir("empty");
        git(&d, &["init", "-q"]);
        assert_eq!(build_version("1.2.3", &d).0, "1.2.3+git.unknown");
    }

    #[test]
    fn asking_whether_the_tree_is_dirty_writes_nothing() {
        // A file whose stat no longer matches the index, with the same content: `git status`
        // refreshes that entry and writes the index back under `index.lock`, which a `git commit`
        // at the same moment fails on. The build script runs on every build, so it must not.
        let d = dir("no-locks");
        git(&d, &["init", "-q"]);
        std::fs::write(d.join("a"), "one").unwrap();
        git(&d, &["add", "a"]);
        git(&d, &["commit", "-q", "-m", "one"]);
        let index = d.join(".git/index");
        let before = std::fs::read(&index).unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(120);
        std::fs::File::options()
            .write(true)
            .open(d.join("a"))
            .unwrap()
            .set_modified(later)
            .unwrap();
        let (v, _) = build_version("1.2.3", &d);
        assert!(!v.ends_with(".dirty"), "the content is the commit's: {v}");
        assert_eq!(
            std::fs::read(&index).unwrap(),
            before,
            "the index was rewritten"
        );
    }

    #[test]
    fn this_binary_names_the_revision_it_was_built_from() {
        // Never the bare crate version, in any build.
        assert!(
            crate::TRIGON_VERSION.starts_with(concat!(env!("CARGO_PKG_VERSION"), "+git.")),
            "{}",
            crate::TRIGON_VERSION
        );
        assert_ne!(crate::TRIGON_VERSION, env!("CARGO_PKG_VERSION"));

        // And, built from a checkout with git to ask, a revision: every assertion above passes for
        // `+git.unknown`, so a build script that always fell back — a wrong root, say — would pass
        // them too. A build from a source archive has no `.git`, and is not held to this.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let has_git = std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if !root.join(".git").exists() || !has_git {
            eprintln!("not built from a checkout with git to ask: the revision is not checked");
            return;
        }
        let rev = crate::TRIGON_VERSION
            .strip_prefix(concat!(env!("CARGO_PKG_VERSION"), "+git."))
            .unwrap();
        let rev = rev.strip_suffix(".dirty").unwrap_or(rev);
        assert_eq!(rev.len(), 40, "{}", crate::TRIGON_VERSION);
        assert!(
            rev.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}",
            crate::TRIGON_VERSION
        );
    }
}
