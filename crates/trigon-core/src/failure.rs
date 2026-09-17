//! Naming a build failure in a way that generalizes across the packages that share it.
//!
//! Three things in the design need this one value, which is why it is a type rather than a helper
//! buried in the agent:
//!
//! 1. **The repair cache key** (`docs/07-ai.md` §4.1). "setuptools omits the PKG-INFO trailing
//!    newline before version X" is *one* repair covering thousands of packages. Key the cache on
//!    the target and every sibling misses; key it on the signature and the first repair pays for
//!    all of them. This is the difference between a $4,000 sweep and a $168,000 one.
//! 2. **Admission control** (§4.3). We enter the repair loop only when the signature is *novel*. A
//!    signature already known unfixable short-circuits to a verdict at zero model spend, and a
//!    repeated signature within one run is the stop rule — cheaper and better than counting
//!    iterations.
//! 3. **The failure-cluster view** (`docs/11-interfaces.md` §4). What turns 500 red rows into 12
//!    tickets, which is the operator need that outranks everything else in the UI.
//!
//! So the whole value is in *generalizing*. A signature carrying the package name, the version, a
//! temp path or a hash is a signature that matches one run, and all three uses above collapse. The
//! rules below therefore capture only the part of a message that is a property of the **failure
//! class**, never of the target: the missing header, not the package that needed it.
//!
//! Deterministic, and it stays that way. A model reads the compressed log this module produces; it
//! does not get to decide what the failure was, because the answer keys a cache and gates spend.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Fault;

/// A build failure, named so that every run sharing the cause shares the name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureSignature {
    /// Stable, `ecosystem/what-happened`. Appears in cache keys, cluster ids and tickets, so it is
    /// treated as a wire value: renaming one splits its cluster in two and orphans its repairs.
    ///
    /// `Cow` rather than `&'static str`, which is what the rule table holds and what this wanted to
    /// be. Serde can only deserialize a `&'static str` from input that is itself `'static`, so the
    /// derive on any struct *containing* one fails to compile — and a signature that cannot be read
    /// back from a file is no use in a run record, which is where it has to end up. `Cow::Borrowed`
    /// keeps construction from the table allocation-free; only a value read back from JSON owns
    /// its bytes.
    pub code: Cow<'static, str>,
    /// The part of the message that generalizes, normalized. `Some("Python.h")` for a missing
    /// header — the repair is the same for every package that needs it. Never a package name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub fault: Fault,
    /// Whether running this again unchanged could reach a different answer.
    pub retryable: bool,
    /// Whether a repair attempt has any prospect at all.
    ///
    /// `false` is the admission-control short circuit: a build killed for running out of memory is
    /// not a strategy problem, and a model iterating on it spends money to reach the same place.
    pub repairable: bool,
    /// The line that produced the classification, verbatim and bounded. For a human reading a
    /// cluster, not part of the key.
    pub evidence: String,
}

impl FailureSignature {
    /// The cache and cluster key. Everything that varies per target is already out.
    pub fn key(&self) -> String {
        match &self.subject {
            Some(s) => format!("{}:{s}", self.code),
            None => self.code.to_string(),
        }
    }

    /// The failure we could not name.
    ///
    /// Deliberately one bucket rather than a per-message hash. An unrecognised failure is a gap in
    /// the rule table, and it should show up as one large cluster somebody fixes, not as five
    /// hundred singleton clusters that look like five hundred unrelated problems.
    ///
    /// **`Fault::Build`, and the tripwire in `seam_fault_classification.rs` is why it still is.**
    /// The reading it rests on — `classify` only runs on a build log, so a build ran and failed —
    /// was false while the container runtime's own output reached here: an image that was not in
    /// the store produced a registry error, matched no rule, and charged the package. That case now
    /// returns `SandboxError::RuntimeRefused` and never reaches this function, and the table has
    /// rules for the runtime failures that do produce a log. Whether the residue should still cost
    /// a package anything is a question about what the published rate means, and it is recorded in
    /// `docs/17-backlog.md` rather than answered here.
    pub fn unknown(evidence: impl Into<String>) -> Self {
        FailureSignature {
            code: Cow::Borrowed("unknown"),
            subject: None,
            fault: Fault::Build,
            retryable: false,
            repairable: true,
            evidence: clip(&evidence.into()),
        }
    }

    pub fn is_unknown(&self) -> bool {
        self.code == "unknown"
    }
}

impl fmt::Display for FailureSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key())
    }
}

/// How a rule pulls the generalizing part out of a matched line.
#[derive(Clone, Copy, Debug)]
enum Capture {
    /// Nothing varies within this class that is worth keying on.
    None,
    /// The text between the first `open` after the needle and the next `close`.
    Between(&'static str, &'static str),
    /// The word following `after`, with trailing punctuation trimmed.
    WordAfter(&'static str),
    /// The token immediately preceding `marker`.
    ///
    /// For messages that name the thing last: a shell says `run.sh: line 3: yarn: command not
    /// found`, where every candidate delimiter before the tool name is also a delimiter inside the
    /// shell's own preamble. Reading backwards from the marker is the only stable anchor.
    WordBefore(&'static str),
}

struct Rule {
    code: &'static str,
    /// Every needle must appear in the same line. Substrings, not patterns: a regex table is a
    /// dependency and a performance cliff on logs this size, and nothing here needs one.
    needles: &'static [&'static str],
    fault: Fault,
    retryable: bool,
    repairable: bool,
    capture: Capture,
}

/// The taxonomy.
///
/// Ordered, first match wins, so the specific rules come before the general ones. Several of these
/// are here because they actually happened while building this system, which is the only reason to
/// trust a taxonomy at all: `node:path` was a Node too old for the strategy, `python3-venv` was a
/// Debian package split, `wheel` was pip running without build isolation.
const RULES: &[Rule] = &[
    // ---- our own environment, not the package's fault -----------------------------------------
    // **A package manager the *package* reached for, which is not the same as a tool our image
    // lacks.** Both arrive as `: not found`, and collapsing them cost a real decision: a sweep
    // reported nine `env/missing-tool` failures from four unrelated causes, an operator read a
    // bucket named after the environment, and reasonably asked whether the environment should
    // carry more. Three were ours. Six were packages whose own lifecycle scripts shell out to yarn
    // or pnpm — `"prepack": "yarn build"`, `"prepare": "if [ ! -d 'dist' ]; then pnpm build; fi"` —
    // which npm ran faithfully because the publisher wrote them.
    //
    // **One rule per manager, because needles are AND-ed and cannot express "any of these".** A
    // single rule with the bare `: not found` needle would claim every missing tool in the table,
    // including the ones that really are ours — the precise inversion this exists to prevent. They
    // share a code, which the invariant test requires to agree on fault, retryable and repairable.
    //
    // **`Fault::Build`, and it earns it.** Trigon drives npm and never invokes these itself, so the
    // call can only have come from the package. It declares a build needing a package manager we do
    // not drive, at a version pinned in its own repository rather than ours to choose. Putting yarn
    // in a base image would run it with *some* yarn and produce a verdict about a build the
    // publisher never did.
    //
    // **Both spellings.** bash says `yarn: command not found`, dash says `yarn: not found`, and
    // every Debian image's `/bin/sh` is dash — so a rule catching only one would charge the same
    // failure to opposite parties depending on which shell ran the script.
    //
    // Before both general missing-tool rules, because those match any `: not found` and any
    // `command not found`, and the table is first-match-wins within a line.
    Rule {
        code: "npm/unsupported-package-manager",
        needles: &["yarn: not found"],
        fault: Fault::Build,
        retryable: false,
        // A different recipe cannot conjure support for a package manager. Builder work, not repair.
        repairable: false,
        capture: Capture::WordBefore(": not found"),
    },
    Rule {
        code: "npm/unsupported-package-manager",
        needles: &["pnpm: not found"],
        fault: Fault::Build,
        retryable: false,
        // A different recipe cannot conjure support for a package manager. Builder work, not repair.
        repairable: false,
        capture: Capture::WordBefore(": not found"),
    },
    Rule {
        code: "npm/unsupported-package-manager",
        needles: &["bun: not found"],
        fault: Fault::Build,
        retryable: false,
        // A different recipe cannot conjure support for a package manager. Builder work, not repair.
        repairable: false,
        capture: Capture::WordBefore(": not found"),
    },
    Rule {
        code: "npm/unsupported-package-manager",
        needles: &["yarn: not found"],
        fault: Fault::Build,
        retryable: false,
        repairable: false,
        capture: Capture::WordBefore(": not found"),
    },
    Rule {
        code: "npm/unsupported-package-manager",
        needles: &["yarn: command not found"],
        fault: Fault::Build,
        retryable: false,
        repairable: false,
        capture: Capture::WordBefore(": command not found"),
    },
    Rule {
        code: "npm/unsupported-package-manager",
        needles: &["pnpm: not found"],
        fault: Fault::Build,
        retryable: false,
        repairable: false,
        capture: Capture::WordBefore(": not found"),
    },
    Rule {
        code: "npm/unsupported-package-manager",
        needles: &["pnpm: command not found"],
        fault: Fault::Build,
        retryable: false,
        repairable: false,
        capture: Capture::WordBefore(": command not found"),
    },
    Rule {
        code: "npm/unsupported-package-manager",
        needles: &["bun: not found"],
        fault: Fault::Build,
        retryable: false,
        repairable: false,
        capture: Capture::WordBefore(": not found"),
    },
    Rule {
        code: "npm/unsupported-package-manager",
        needles: &["bun: command not found"],
        fault: Fault::Build,
        retryable: false,
        repairable: false,
        capture: Capture::WordBefore(": command not found"),
    },
    Rule {
        code: "env/missing-tool",
        needles: &["command not found"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::WordBefore(": command not found"),
    },
    Rule {
        // The same failure in dash's words rather than bash's. A `/bin/sh` that is dash — which is
        // every Debian image — says `npx: not found`, with no `command`. Found by a run whose
        // whole cluster came back `unknown` for a missing `npx`, which is exactly the failure this
        // rule exists to name.
        code: "env/missing-tool",
        needles: &[": not found"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::WordBefore(": not found"),
    },
    Rule {
        // setuptools saying a compiler is absent, in its own words. It names the toolchain by its
        // Debian triplet — `command 'x86_64-linux-gnu-gcc' failed: No such file or directory` — so
        // neither of the shell rules above sees it, and six of the M1 PyPI corpus's ten unnamed
        // failures were this one message.
        //
        // **Ours, not the package's.** Every C extension needs a compiler, the base image did not
        // carry one, and at an enforced tier nothing can install it at the moment it is wanted. The
        // package is doing the ordinary thing.
        code: "env/missing-tool",
        needles: &["failed: No such file or directory", "command '"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::Between("command '", "'"),
    },
    Rule {
        // A Rust extension with no Rust toolchain. Distinct from the C case because the answer is
        // different: Debian's `rustc` trails the ecosystem far enough that shipping it would turn
        // this into a version failure rather than fix it, so this names a gap that is still open
        // rather than one the base image closed.
        code: "env/missing-tool",
        needles: &["can't find Rust compiler"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        // `meson-python: error: Could not find the specified meson`. Same class, named separately
        // because the message shares no wording with the others.
        code: "env/missing-tool",
        needles: &["Could not find the specified meson"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "env/node-too-old",
        needles: &["Cannot find module 'node:"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        // Found in the npm corpus: a slim Debian image has no `libatomic1`, and the Node build that
        // needs it dies before printing anything of its own. The missing library *is* the repair
        // and it is shared by every package that hits it, which is what makes it worth capturing.
        code: "env/missing-shared-library",
        needles: &["error while loading shared libraries"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::Between("libraries: ", ":"),
    },
    Rule {
        // An old interpreter on a new kernel. Node 5 and Node 9 both abort on contemporary glibc,
        // which matters because the toolchain that published a package is part of what we are
        // reproducing: the fix is a base image of the right vintage, not a newer toolchain.
        code: "env/toolchain-crashed",
        needles: &["Aborted (core dumped)"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "env/missing-venv",
        needles: &["ensurepip is not available"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        // The build could not install a package because the mirror refused to serve it — and the
        // reason it refused is that the package is the one under test. That happens whenever a
        // package is part of the machinery that builds packages: `python -m build` needs
        // `packaging` and `pyproject-hooks`, so rebuilding either makes the build ask for itself.
        //
        // Ours, not the package's: the refusal is a control we chose to arm. Not repairable either,
        // because no strategy change gets a build its own artifact — what it needs is a way to
        // satisfy the toolchain from somewhere that is not the target, which is a design question
        // rather than a recipe.
        //
        // Named because it clustered as `unknown` across three of seventeen targets on the M1 PyPI
        // corpus, and it is the signature of a class of package rather than an accident.
        code: "env/needs-the-package-under-test",
        needles: &["Could not install requirement"],
        fault: Fault::Bug,
        retryable: false,
        repairable: false,
        capture: Capture::WordAfter("Could not install requirement"),
    },
    Rule {
        // **Our own message, and it keyed as `unknown`.** The setup phase at an enforced tier
        // checks the base image for the packages the strategy needs and prints this when they are
        // absent, along with the exact `trigon base-image` line that fixes it. Nothing claimed the
        // line, so a run that diagnosed itself perfectly reported `failure unknown` — which reads
        // as "we have no idea" directly underneath a paragraph saying precisely what was wrong.
        //
        // It is also the first failure a new reader hits: `mirror-only` against a stock image is
        // what the README suggests trying, and this is what that does. Unnamed, it could not
        // cluster, could not key the repair cache and could not be recognised by the flywheel the
        // next thousand times it happened (`docs/07-ai.md` §5).
        //
        // `Fault::Policy`, not `Bug`: the tier is doing what it was asked to. The operator builds
        // an image or picks a looser tier, and no strategy change helps, so it is not repairable.
        //
        // No capture, deliberately. `WordAfter` would key on the first of however many packages are
        // listed — `env/base-image-incomplete:ca-certificates` for a line naming four — which both
        // reads wrong and splits one cluster into a combination per image. The operator action is
        // the same whichever package is absent, so this is one cluster; which packages they were is
        // in the evidence line, where a fleet report can still count them.
        code: "env/base-image-incomplete",
        needles: &["this base image is missing:"],
        fault: Fault::Policy,
        retryable: false,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        // **Ours, and it read as the package's.** A Debian image's root directory is mode 0555, and
        // root writes there only through `CAP_DAC_OVERRIDE` — which the sandbox drops by name. So a
        // recipe naming a path under `/` fails at an enforced tier and nowhere else, because
        // `defer_deps` moves the phase out of the image build (full capabilities) and into the
        // container run (none). The PyPI heuristic named `/deps`, so every PyPI build succeeded at
        // `--egress open` and failed at `mirror-only` with `Errno 13`, keyed `unknown`, attributed
        // to the package.
        //
        // The path moved, which fixes the instance. This names the class, because the next recipe
        // to reach for a path under `/` — a hand-written definition, a model's proposal, an
        // imported `build.yaml` — will do it again, and it should arrive as a cluster rather than
        // as a thousand unknowns.
        //
        // `Fault::Bug`: the recipe chose the path and the sandbox chose the capabilities. Nothing
        // about the package is implicated, and a retry changes nothing — but a *different recipe*
        // fixes it, which is what `repairable` means.
        code: "env/cannot-write-path",
        needles: &["Permission denied"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        // The path is the whole diagnosis, and it is the thing that differs between instances, so
        // it keys the cluster: `env/cannot-write-path:/deps` and `…:/opt/x` are separate repairs.
        capture: Capture::Between("'", "'"),
    },
    Rule {
        code: "env/no-ca-certificates",
        needles: &["server certificate verification failed"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    // ---- The container runtime's own refusals. -----------------------------------------------
    //
    // **The table had no rule for any of them**, so every one fell through to `unknown`, which
    // charges the package (`Fault::Build`) and asks the repair loop to edit a strategy in response
    // to podman being unable to reach a registry. An operator pointing `--image` at a digest that
    // is not in the store was told "the build failed in deps: unknown".
    Rule {
        code: "env/image-unavailable",
        needles: &["pinging container registry"],
        fault: Fault::Infra,
        retryable: true,
        // Nothing a model can write into a strategy fixes an unreachable registry.
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/image-unavailable",
        needles: &["initializing source docker://"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/image-unavailable",
        needles: &["image not known"],
        fault: Fault::Infra,
        retryable: false,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/runtime-refused",
        needles: &["creating build container"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/runtime-refused",
        needles: &["error creating container storage"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/out-of-memory",
        // The runtime's own form. `Killed` below is the *shell* reporting a killed child, which a
        // container OOM never produces — so a build the kernel killed inside podman matched no
        // rule at all and was charged to the package. One needle, because every needle in a rule
        // has to match the *same line* and these two never share one.
        needles: &["signal: killed"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/out-of-memory",
        needles: &["cannot allocate memory"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/no-space",
        // Lowercase, which is what the runtime and Go tooling print. The capitalised form below is
        // the C library's, and matching only that missed every containerised instance.
        needles: &["no space left on device"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/cannot-write-path",
        // Lowercase, as Go tooling emits it. **Identical to the capitalised rule in every other
        // field**, because two spellings of one failure that key into two clusters is the defect
        // this table exists to avoid — the repair cache, the admission prior and the cluster id are
        // all the same string.
        needles: &["permission denied"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::Between("'", "'"),
    },
    Rule {
        code: "env/out-of-memory",
        needles: &["Killed"],
        fault: Fault::Infra,
        retryable: true,
        // Not a strategy problem. A model iterating here spends money to reach the same place.
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/out-of-memory",
        needles: &["JavaScript heap out of memory"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/no-space",
        needles: &["No space left on device"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        // Extracting an archive that records an owner the sandbox's user namespace does not map.
        // Ours, not the package's: the same tarball extracts fine as an image layer, where the
        // mapping is wide, and fails in a deferred phase inside the container, where it is narrow.
        // The repair is `--no-same-owner`, which is why this is repairable rather than merely a
        // fault to report.
        code: "env/cannot-chown",
        needles: &["Cannot change ownership"],
        fault: Fault::Infra,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    // ---- the network, and what a denied egress tier looks like from inside ---------------------
    Rule {
        // A *build backend* reaching the internet directly, rather than a package manager asking
        // the index. `zipp` builds through `coherent.licensed`, which calls `urlopen` from
        // `get_requires_for_build_wheel` to fetch its licence text — so it never sees
        // `/etc/pip.conf`, never goes through the mirror, and hits the boundary.
        //
        // This is the tier working, and naming it says so. It clustered with `net/unreachable`,
        // where the other member was our own malformed repository URL: one is a bug of ours and the
        // other is a hidden remote dependency in somebody's build, which is exactly what
        // `docs/08-execution.md` §7.1 says the transcript exists to surface. Same code, opposite
        // readings, so they are not the same code any more.
        //
        // Not repairable: no strategy change makes a build stop calling `urlopen`. The choices are
        // to widen the allowlist, which is what the allowlist exists to prevent, or to record that
        // this package cannot be built at an enforced tier.
        code: "net/build-fetches-directly",
        needles: &["urlopen error", "Network is unreachable"],
        fault: Fault::Policy,
        retryable: false,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        // The registry names a commit the forge will not serve. npm records `gitHead` at publish
        // time and nothing keeps it reachable afterwards: a force-push, a rebased or deleted
        // branch, a commit that only ever existed in a fork. GitHub answers `upload-pack: not our
        // ref` and there is no fetch that recovers it — the commit is not reachable from any ref
        // in that repository today.
        //
        // **Ours to name, not ours to repair.** It clustered as `net/unreachable` for every corpus
        // run, because the host checkout failed silently and the build then died on the DNS the
        // enforced tier denies it — the same code as a genuine hidden network dependency in
        // somebody's build, which is the opposite reading. `pad-left@2.1.0` is the corpus member.
        //
        // What would fix the target is source discovery, not a strategy: the version's tag names a
        // commit the forge does serve, and falling back to it is a different claim about what was
        // verified — `SourceDiscovery::ExactTag` rather than `RegistryCommit`. That is a decision
        // about what we assert, so it is a backlog item rather than a repair the loop can attempt.
        code: "src/commit-not-on-the-forge",
        needles: &["not our ref"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "net/unreachable",
        needles: &["Temporary failure in name resolution"],
        fault: Fault::Policy,
        retryable: false,
        // Under `--egress mirror-only` this is the enforcement working, not a fault to repair. The
        // strategy asked for something the tier does not grant, and the fix is the strategy.
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "net/unreachable",
        needles: &["Could not resolve host"],
        fault: Fault::Policy,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "net/unreachable",
        needles: &["Network is unreachable"],
        fault: Fault::Policy,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    // A fetch that reached a server and was turned away. Under an enforced tier the server is
    // almost always our own mirror, and the status says which refusal: 400 for a request that
    // arrived without the time filter, 403 for a host outside the toolchain allowlist or for the
    // run's own artifact. Classified separately from `net/unreachable` because the fix is
    // different — the route exists and the request was wrong — and because an unclassified failure
    // clusters as `unknown`, where twenty-six identical ones once hid a single bug of ours.
    Rule {
        code: "net/http-error",
        needles: &["ERROR 4"],
        fault: Fault::Policy,
        retryable: false,
        repairable: true,
        capture: Capture::WordAfter("ERROR"),
    },
    Rule {
        code: "net/registry-5xx",
        needles: &["503 Service Unavailable"],
        fault: Fault::Upstream,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "net/rate-limited",
        needles: &["429 Too Many Requests"],
        fault: Fault::Upstream,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    // ---- npm -----------------------------------------------------------------------------------
    Rule {
        code: "npm/peer-conflict",
        needles: &["ERESOLVE"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        // Deliberately uncaptured. Which two packages conflict is a property of the target, and
        // keying on it would give every target its own cluster of one.
        capture: Capture::None,
    },
    Rule {
        code: "npm/version-gone",
        needles: &["notarget No matching version found"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "npm/lifecycle-script",
        needles: &["Failed at the", "script"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "npm/node-gyp",
        needles: &["gyp ERR!"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "npm/engine-mismatch",
        needles: &["EBADENGINE"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    // ---- Python ---------------------------------------------------------------------------------
    Rule {
        code: "pip/no-matching-distribution",
        needles: &["No matching distribution found for"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "pip/unmet-build-dependency",
        needles: &["Unmet dependencies"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::WordAfter("Unmet dependencies:"),
    },
    Rule {
        code: "pip/metadata-generation-failed",
        needles: &["metadata-generation-failed"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "pip/missing-build-backend",
        needles: &["Cannot import 'setuptools.build_meta'"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "py/missing-module",
        needles: &["ModuleNotFoundError: No module named"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        // Which module *is* the repair, and it is shared: every package needing `cython` needs the
        // same fix.
        capture: Capture::Between("named '", "'"),
    },
    Rule {
        code: "py/syntax-error",
        needles: &["SyntaxError:"],
        fault: Fault::Build,
        retryable: false,
        // Nearly always an interpreter too new or too old for the source, which is a toolchain
        // window the evidence should have pinned.
        repairable: true,
        capture: Capture::None,
    },
    // ---- NuGet and MSBuild -------------------------------------------------------------------------
    Rule {
        // **An MSBuild target that is not there, and the framework it names is a bystander.**
        // Newtonsoft.Json 11.0.1 overrides `<LanguageTargets>` to `Microsoft.Portable.CSharp.targets`,
        // a file the .NET SDK does not ship on Linux. That import fails quietly, so the inner
        // project never imports `NuGet.targets`, so the outer restore's call into
        // `_GetRestoreSettingsPerFramework` lands on a project with no such target. MSBuild reports
        // it against a PCL target framework, which reads as "this old framework is unsupported" and
        // is wrong: neutralise the override and all nine of that package's frameworks restore.
        //
        // `nuget/restore` now passes `-p:LanguageTargets=<sdk>/Microsoft.CSharp.targets`, which is
        // the SDK's own default for C# and so a no-op for every project that does not override it.
        // This rule is what is left over: reaching it means the override was not the cause, and
        // someone should look rather than guess.
        //
        // **`Fault::Bug`, not `Build`.** Measured before it was named: unclaimed, this line keyed
        // `unknown`, which defaults to `Fault::Build` — charging a package for our image's missing
        // MSBuild target, and counting it against the reproduction rate.
        //
        // **`repairable: false`, which is the money decision.** `repairable` is the sole admission
        // gate on model spend — `trigon_ai::Ledger::next` returns `Stop(NotRepairable)` before any
        // budget check, and nothing gates the loop on `fault`. A model cannot conjure a missing
        // targets file, and the one recipe change that helps is already applied above, so every
        // call this would buy is spent.
        //
        // Captured on the target name so the cluster says which target was absent; that is a
        // property of the SDK and the project's imports, and it is the same for every package that
        // trips the same import.
        code: "env/msbuild-target-missing",
        needles: &["MSB4057"],
        fault: Fault::Bug,
        retryable: false,
        repairable: false,
        capture: Capture::Between("The target \"", "\""),
    },
    Rule {
        // **Reference assemblies the image does not carry**, for a framework that is perfectly
        // buildable on Linux once it does. MSBuild's advice — "install the Developer Pack" — names
        // a Windows installer, so the message reads as a dead end and is not one.
        //
        // The .NET Framework targets need nothing: the SDK adds
        // `Microsoft.NETFramework.ReferenceAssemblies` implicitly, and `net20` through `net48` build
        // out of the box. It is the **PCL** profiles (`.NETPortable`) that have no NuGet package at
        // all; their reference assemblies ship in Mono's `referenceassemblies-pcl`, about a
        // megabyte, which `trigon base-image --pcl-reference-assemblies` vendors into an image.
        //
        // `Fault::Policy` and not `Bug`, matching `env/base-image-incomplete`: the build is doing
        // what it was asked and the image is missing a thing the operator adds. No strategy change
        // reaches it, so it is not repairable — a model asked to fix this would rewrite the recipe
        // until the budget ran out.
        //
        // Captured on the profile, so `Profile259` and `Profile328` cluster separately: they are
        // different assemblies to vendor, even though today the same package supplies both.
        code: "env/missing-reference-assemblies",
        needles: &["MSB3644"],
        fault: Fault::Policy,
        retryable: false,
        repairable: false,
        capture: Capture::Between("reference assemblies for ", " were not found"),
    },
    // ---- native toolchains ------------------------------------------------------------------------
    Rule {
        code: "cc/missing-header",
        needles: &["fatal error:", "No such file or directory"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::Between("fatal error: ", ":"),
    },
    Rule {
        code: "cc/missing-compiler",
        needles: &["unable to execute 'cc'"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "ld/undefined-symbol",
        needles: &["undefined reference to"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    // ---- git ---------------------------------------------------------------------------------------
    Rule {
        code: "git/no-such-ref",
        needles: &["did not match any file(s) known to git"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "git/no-such-ref",
        needles: &["Remote branch", "not found in upstream"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        // npm records the publisher's `gitHead`, and a force-push or a rebase can leave it pointing
        // at nothing. Not repairable by a strategy change: the recorded commit is simply gone, and
        // the answer is source rediscovery or nothing.
        code: "git/commit-not-in-repo",
        needles: &["reference is not a tree"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "git/repository-gone",
        needles: &["Repository not found"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: false,
        capture: Capture::None,
    },
    // ---- ours ---------------------------------------------------------------------------------------
    Rule {
        // A package published from a monorepo, rebuilt outside the monorepo. Its `package.json`
        // names siblings with `workspace:^`, a protocol only the workspace's own package manager
        // resolves, and npm run against the member alone cannot.
        //
        // **A finding about our strategy, not about the package.** The tarball was produced by a
        // build that had the whole repository; ours checks out the repository and builds in the
        // subdirectory, which is not the same thing. Named so the monorepo stratum reports what it
        // is rather than sitting in `unknown` — four of the M1 npm corpus's twenty-three.
        //
        // Repairable in principle: install from the workspace root and pack the member. Nothing
        // does that yet, so it is repairable rather than done.
        code: "npm/workspace-protocol",
        needles: &["Unsupported URL Type \"workspace:\""],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        // The other half of the monorepo problem, and the one that had no rule at all. A workspace
        // member compiles against a sibling that the build has not produced yet: `xstate`'s
        // `packages/xstate-analytics` imports `xstate`, and `tsc` stops with
        // `TS2307: Cannot find module 'xstate'`.
        //
        // **Ours, like the sibling rule above.** The published tarball came from a build that had
        // the whole workspace linked; the recipe builds a member as though it stood alone.
        //
        // Named because nothing named it. `classify` scans backwards for the last line a rule
        // claims, and with no rule for this one the scan ran past it to `npm WARN ERESOLVE` —
        // which npm prints on installs that *succeed*, thousands of lines earlier. So a workspace
        // link error was reported as `npm/peer-conflict`, and the repair loop spent a model call
        // fixing a peer conflict that was never the failure.
        code: "npm/workspace-unbuilt-sibling",
        needles: &["error TS2307: Cannot find module"],
        fault: Fault::Bug,
        retryable: false,
        // A recipe that builds from the workspace root rather than the member would fix it.
        repairable: true,
        // The module it could not find, which is the sibling that needed building first. One
        // cluster per missing sibling is the right grain: it names what to build.
        capture: Capture::Between("'", "'"),
    },
    Rule {
        // A dependency that is not a registry package at all: a `github:` or tarball specifier that
        // sends the installer to a forge. At an enforced tier the mirror is the only route out and
        // the forge is not on the artifact allowlist, so it is refused.
        //
        // **The tier working, and a finding about the package**: a build that fetches code from a
        // forge at install time is a supply-chain fact worth reporting, which is what
        // `docs/08-execution.md` §7.1 says the transcript exists to surface. Not repairable by a
        // recipe — the dependency is in the package's own manifest.
        code: "net/dependency-from-a-forge",
        needles: &["npm error request to https://codeload.github.com"],
        fault: Fault::Policy,
        retryable: false,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        // A package whose install script refuses to run under npm — a `preinstall` guard that
        // insists on yarn or pnpm. Our recipes drive npm, so the build stops on purpose.
        //
        // Named rather than left unknown because it is a property of the package that no recipe
        // change alters while we drive npm, and because it reads as a mysterious script failure.
        code: "npm/refuses-npm",
        needles: &["disallow-npm"],
        fault: Fault::Policy,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        // A native dependency downloading a prebuilt binary at install time, blocked by the tier.
        // `sharp` is the common one and it names itself.
        //
        // Worth separating from a generic network refusal: a build that fetches a *binary* it did
        // not compile is the shape `docs/12-security.md` §1.1 is about, and the fact that the tier
        // stopped it is the control working rather than an inconvenience.
        code: "net/prebuilt-binary-download",
        needles: &["Installation error: connect ENETUNREACH"],
        fault: Fault::Policy,
        retryable: false,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        // The recipe built a different kind of distribution from the one under test. Ours, and
        // fixable: a release publishes an sdist and a dozen platform wheels, and the run is about
        // one of them.
        code: "trigon/wrong-artifact-kind",
        needles: &["so there is nothing to compare"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        // **Our own mirror, refusing our own request.** A 400 from the mirror means a request
        // arrived without the time filter, and for a tarball that is npm composing the URL itself
        // from the registry root and dropping the credentials on the way. The build reports
        // `E400`, the run reports the package failing, and the cluster reports `unknown`.
        //
        // Named because 34 of 197 targets on the M1 npm corpus were this, all of them inside the
        // 50-strong `unknown` cluster — the largest single cause of a lost target, and ours.
        //
        // Not repairable by a strategy: no recipe changes which URL npm builds. What fixes it is
        // the mirror serving that shape, which it now does.
        code: "trigon/mirror-refused-unfiltered",
        // One line, because every needle has to match the *same* line — a rule whose needles are
        // spread across two lines matches nothing, which is how this one failed its first test.
        // npm prints the method, the status and the URL together, and the host is ours.
        needles: &["400 Bad Request - GET http://timewarp"],
        fault: Fault::Bug,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        // The build could not read a tarball it downloaded. Named as ours, loudly, because the
        // symptom reads exactly like a broken package and would otherwise be counted against one.
        //
        // **It was named for the mirror, and the mirror was not doing it.** The first instance was
        // ours — the mirror was transparently gunzipping artifacts — and the name outlived the
        // cause. The six npm targets that carried this code on the M1 corpus were npm itself:
        // every release from 7.0 to 8.2 splices the tarballs it fetches concurrently, on any Node,
        // while the mirror's transcript recorded complete bodies matching upstream byte for byte
        // and a second, unrelated server reproduced it. `tools/npm/npx.yaml` holds the evidence and
        // the fix; this rule is the backstop for a client outside the range we serialize.
        code: "trigon/client-corrupted-download",
        needles: &["Z_DATA_ERROR"],
        fault: Fault::Bug,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "trigon/client-corrupted-download",
        needles: &["zlib: invalid stored block lengths"],
        fault: Fault::Bug,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "trigon/no-output",
        needles: &["no file matched the output path"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
];

/// Name the failure in a build log.
///
/// Scans from the end. The last error is almost always the one that stopped the build, and the
/// first is often a tolerated warning from a phase that went on to succeed — the opposite of how a
/// human skims, and right more often.
pub fn classify(log: &str) -> FailureSignature {
    let lines: Vec<&str> = log.lines().collect();
    for line in lines.iter().rev() {
        if let Some(sig) = classify_line(line) {
            return sig;
        }
    }
    FailureSignature::unknown(last_interesting(&lines))
}

/// Name one line, or `None` if no rule claims it.
///
/// Public because a log that is compressed as it streams cannot be classified at the end: by then
/// the line that named the failure may be gone. A caller holding the raw stream names each line as
/// it passes and keeps the last one that matched, which is what [`classify`] does over a whole log.
pub fn classify_line(line: &str) -> Option<FailureSignature> {
    // Matched and captured against the *plain* line.
    //
    // This ran the needles and the capture over the raw bytes, and `clip` stripped control
    // characters only on the way into `evidence`. A build that emits colour therefore produced a
    // different signature from the same build that did not: an escape landing inside a needle
    // breaks the match and the failure keys as `unknown`, and an escape inside a captured subject
    // becomes part of the cache key. One failure, three keys, depending on whether the compiler
    // felt like colouring — and this key is the repair cache, the admission-control prior and the
    // cluster id all at once (`docs/07-ai.md` §5), so the flywheel never recognises a failure it
    // has already solved.
    let plain = strip_controls(line);
    let rule = RULES
        .iter()
        .find(|r| r.needles.iter().all(|n| plain.contains(n)))?;
    Some(FailureSignature {
        code: Cow::Borrowed(rule.code),
        subject: capture(&plain, rule.capture).map(|s| normalize_subject(&s)),
        fault: rule.fault,
        retryable: rule.retryable,
        repairable: rule.repairable,
        evidence: clip(plain.trim()),
    })
}

/// A line with terminal control sequences removed, so matching sees what a human reads.
///
/// ANSI SGR is `ESC [ ... m`, and the parameters in between are ordinary printable characters, so
/// dropping control characters alone leaves `[1;31m` behind — which is still not what the build
/// printed. The whole sequence goes.
fn strip_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI: `ESC [` then parameter and intermediate bytes, ended by a byte in `@`..=`~`.
            if chars.peek() == Some(&'[') {
                chars.next();
                for t in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&t) {
                        break;
                    }
                }
            } else {
                // A two-character escape. Drop the pair.
                chars.next();
            }
            continue;
        }
        if !c.is_control() || c == '\t' {
            out.push(c);
        }
    }
    out
}

fn capture(line: &str, how: Capture) -> Option<String> {
    match how {
        Capture::None => None,
        Capture::Between(open, close) => {
            let rest = line.split_once(open)?.1;
            let end = rest.find(close)?;
            Some(rest[..end].to_string())
        }
        Capture::WordBefore(marker) => {
            let head = line.split(marker).next()?;
            head.rsplit([' ', ':'])
                .find(|t| !t.is_empty())
                .map(str::to_string)
        }
        Capture::WordAfter(marker) => {
            line.split_once(marker)?
                .1
                .split_whitespace()
                .next()
                .map(|w| {
                    w.trim_matches(|c: char| !c.is_alphanumeric() && c != '.')
                        .to_string()
                })
        }
    }
}

/// Strip what makes one occurrence different from the next.
///
/// A subject carrying a version, a build id or an absolute path defeats the whole point: the
/// cluster becomes a cluster of one. Paths keep only their last component, and a trailing version
/// goes, because `Python.h` and `libssl-dev` are repairs while `/tmp/pip-build-9k2/Python.h` is a
/// run.
fn normalize_subject(s: &str) -> String {
    let s = s.trim().trim_matches('\'').trim_matches('"');
    let s = s.rsplit('/').next().unwrap_or(s);
    let s = s.split_once("==").map(|(a, _)| a).unwrap_or(s);
    s.trim().to_lowercase()
}

/// The last line that looks like it says something, for a failure we could not name.
///
/// Bounded and stripped of control characters. A build script can print anything, including text
/// shaped like our own output, and this string reaches a model.
fn last_interesting(lines: &[&str]) -> String {
    // Stripped for the same reason `classify_line` strips: this becomes the evidence on an
    // `unknown` signature, and an evidence string that differs only by colour clusters as two
    // failures in the UI that a human would read as one.
    lines
        .iter()
        .rev()
        .map(|l| strip_controls(l).trim().to_string())
        .find(|l| !l.is_empty() && l.len() > 8)
        .unwrap_or_default()
}

fn clip(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .take(300)
        .collect();
    cleaned.trim().to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_missing_msbuild_target_is_ours_and_not_the_packages() {
        // Verbatim from a `pkg:nuget/Newtonsoft.Json@11.0.1` run. Unnamed, this keyed `unknown`,
        // which defaults to `Fault::Build` — charging the package for our image, and admitting it
        // to the repair loop, where `repairable` is the only gate on model spend.
        let s = super::classify(
            "/src/Src/Newtonsoft.Json/Newtonsoft.Json.csproj : error MSB4057: The target \
             \"_GetRestoreSettingsPerFramework\" does not exist in the project. \
             [TargetFramework=portable-net45+win8+wpa81+wp8]",
        );
        assert_eq!(s.code, "env/msbuild-target-missing");
        assert_eq!(s.fault, super::Fault::Bug);
        assert!(
            !s.repairable,
            "a missing targets file is not something a model can write"
        );
        assert!(!s.retryable);
        assert!(
            s.key().contains("getrestoresettingsperframework"),
            "the cluster should name the target that was absent: {}",
            s.key()
        );
    }

    #[test]
    fn missing_reference_assemblies_name_the_profile_and_are_not_repairable() {
        // The failure after the `LanguageTargets` one is fixed: the image has no PCL reference
        // assemblies. MSBuild's own advice names a Windows installer, so the message reads as a
        // dead end when the answer is `trigon base-image --pcl-reference-assemblies`.
        let s = super::classify(
            "/usr/share/dotnet/sdk/8.0.423/Microsoft.Common.CurrentVersion.targets(1259,5): \
             error MSB3644: The reference assemblies for \
             .NETPortable,Version=v4.5,Profile=Profile259 were not found. To resolve this, \
             install the Developer Pack",
        );
        assert_eq!(s.code, "env/missing-reference-assemblies");
        assert_eq!(s.fault, super::Fault::Policy);
        assert!(!s.repairable);
        assert!(s.key().contains("profile259"), "{}", s.key());
    }

    #[test]
    fn the_two_dotnet_failures_do_not_claim_each_others_lines() {
        // Both are MSBuild errors with similar shapes, and the table is first-match-wins per line.
        let a = super::classify("error MSB4057: The target \"X\" does not exist in the project.");
        let b = super::classify("error MSB3644: The reference assemblies for Y were not found.");
        assert_ne!(a.code, b.code);
    }

    #[test]
    fn a_missing_build_toolchain_is_named_however_the_backend_words_it() {
        // Every line here is copied from a build log in the M1 PyPI pilot, where eight of ten
        // unnamed failures were a missing compiler and the cluster read as "no idea". Three
        // backends, three vocabularies, one cause — and the shell rules catch none of them,
        // because none of these messages is a shell saying `not found`.
        let gcc = super::classify(
            "error: command 'x86_64-linux-gnu-gcc' failed: No such file or directory",
        );
        assert_eq!(gcc.code, "env/missing-tool");
        assert_eq!(
            gcc.subject.as_deref(),
            Some("x86_64-linux-gnu-gcc"),
            "the subject keys the cluster, so it has to name the tool"
        );
        assert_eq!(gcc.fault, crate::Fault::Bug, "ours: the image lacked it");

        assert_eq!(
            super::classify(
                "error: command 'x86_64-linux-gnu-g++' failed: No such file or directory"
            )
            .subject
            .as_deref(),
            Some("x86_64-linux-gnu-g++")
        );
        assert_eq!(
            super::classify("  = note: error: can't find Rust compiler").code,
            "env/missing-tool"
        );
        assert_eq!(
            super::classify("meson-python: error: Could not find the specified meson: \"x\"").code,
            "env/missing-tool"
        );
    }

    #[test]
    fn the_npm_corpus_unknowns_are_named_from_their_real_log_lines() {
        // Every string here is copied from a build log in the M1 npm corpus run, where all four
        // sat in one twenty-three-strong `unknown` cluster — which reads as "twenty-three packages
        // failed for reasons nobody looked into" and was four causes wearing one label.
        for (log, code) in [
            (
                "npm error Unsupported URL Type \"workspace:\": workspace:^",
                "npm/workspace-protocol",
            ),
            (
                "npm error request to https://codeload.github.com/uNetworking/uWebSockets.js/tar.gz/v20 failed",
                "net/dependency-from-a-forge",
            ),
            (
                "npm ERR! command sh -c node scripts/disallow-npm.js",
                "npm/refuses-npm",
            ),
            (
                "npm error sharp: Installation error: connect ENETUNREACH 140.82.114.3:443",
                "net/prebuilt-binary-download",
            ),
        ] {
            assert_eq!(super::classify(log).code, code, "{log}");
        }
    }

    #[test]
    fn the_mirror_refusing_our_own_request_is_named_as_ours() {
        // It was `unknown` — the bucket that means "a gap in this table" — for 34 of 197 targets on
        // the first M1 npm corpus run, which read as thirty-four packages failing for reasons
        // nobody had looked into. The answer was one defect of ours.
        let s = super::classify(
            "npm error code E400\nnpm error 400 Bad Request - GET \
             http://timewarp:8129/yocto-queue/-/yocto-queue-0.1.0.tgz",
        );
        assert_eq!(s.code, "trigon/mirror-refused-unfiltered");
        assert_eq!(s.fault, crate::Fault::Bug, "ours, not the package's");
        assert!(!s.repairable, "no recipe changes which URL npm builds");
    }

    #[test]
    fn a_commit_the_forge_will_not_serve_is_not_a_network_problem() {
        // These two used to be the same cluster, and they are opposite readings. `not our ref` is
        // the registry naming a commit that is not reachable from anything in the repository —
        // bad metadata, nothing to do with us or with the tier. `Could not resolve host` under an
        // enforced tier is the boundary working: a build reaching for the internet and being
        // stopped. Filing them together made `pad-left`'s metadata problem look like a finding
        // about somebody's build, and vice versa.
        let s = super::classify(
            "git fetch failed: fatal: remote error: upload-pack: not our ref 89347534a8",
        );
        assert_eq!(s.code, "src/commit-not-on-the-forge");
        assert_eq!(s.fault, crate::Fault::Upstream);
        // No recipe recovers a commit the forge does not have.
        assert!(!s.repairable);

        assert_eq!(
            super::classify("fatal: unable to access: Could not resolve host: github.com").code,
            "net/unreachable"
        );
    }

    #[test]
    fn a_build_that_needs_the_package_under_test_is_named_as_ours() {
        // Some packages are part of the machinery that builds packages, so rebuilding one makes
        // the build ask for itself — and the mirror refuses, correctly, because serving it would
        // let a build hand back its own published output. `packaging`, `toml` and
        // `pyproject-hooks` all hit it on the M1 PyPI corpus and all three keyed `unknown`.
        let s = super::classify(
            "ERROR: Could not install requirement packaging>=24.0 from http://timewarp:8129/x",
        );
        assert_eq!(s.code, "env/needs-the-package-under-test");
        // Ours: the refusal is a control we armed, not a fault in the package.
        assert_eq!(s.fault, crate::Fault::Bug);
        // And no recipe fixes it. What it needs is a way to satisfy the toolchain from somewhere
        // that is not the target, which is a design decision rather than a strategy change.
        assert!(!s.repairable);
    }

    #[test]
    fn a_path_the_sandbox_cannot_write_is_ours_and_is_named() {
        // A Debian image's root directory is mode 0555 and the sandbox drops `CAP_DAC_OVERRIDE`, so
        // a recipe naming a path under `/` fails at an enforced tier and nowhere else. Every PyPI
        // build did: `python3 -m venv /deps` succeeded at `--egress open`, where the phase is an
        // image layer with full capabilities, and failed at `mirror-only`, where `defer_deps` moves
        // it into the container run with none. It keyed `unknown` and was attributed to the package.
        for log in [
            "Error: [Errno 13] Permission denied: '/deps'",
            "mkdir: cannot create directory '/opt/build': Permission denied",
        ] {
            let s = super::classify(log);
            assert_eq!(s.code, "env/cannot-write-path", "{log}");
            // Ours: the recipe chose the path and the sandbox chose the capabilities. Nothing about
            // the package is implicated.
            assert_eq!(s.fault, crate::Fault::Bug, "{log}");
            // A retry changes nothing; a different recipe fixes it, which is what this means.
            assert!(s.repairable && !s.retryable, "{log}");
            assert_ne!(
                s.key(),
                "env/cannot-write-path",
                "the path keys the cluster: {log}"
            );
        }
    }

    #[test]
    fn the_setup_phases_own_diagnostic_is_named_rather_than_unknown() {
        // Trigon writes this line itself: the setup phase at an enforced tier checks the base image
        // for what the strategy needs, prints the exact `trigon base-image` command that fixes it,
        // and exits. Nothing claimed the line, so a run that diagnosed itself perfectly reported
        // `failure unknown` — "we have no idea", printed directly under a paragraph saying exactly
        // what was wrong.
        //
        // It is also the first failure a new reader hits, because `mirror-only` against a stock
        // image is what the README suggests trying.
        let log = "\
this base image is missing: ca-certificates git libatomic1 wget\n\
an enforced egress tier gives the image build no network, so the packages a\n\
strategy needs have to be in the image already. Build one with:\n\
    trigon base-image --from <this image> --packages ca-certificates git libatomic1 wget\n";
        let s = super::classify(log);
        assert_eq!(s.code, "env/base-image-incomplete");
        // Policy, not Bug: the tier is doing exactly what it was asked to. And no strategy change
        // helps, so a model iterating here would spend money to reach the same place.
        assert_eq!(
            s.fault,
            crate::Fault::Policy,
            "the tier is working as asked"
        );
        assert!(!s.repairable);
        // One cluster, not one per combination of missing packages: the operator action is the same
        // whichever is absent, and a key naming the first of four reads wrong.
        assert_eq!(s.key(), "env/base-image-incomplete");
    }

    use super::*;

    #[test]
    fn the_key_generalizes_across_packages_that_share_a_cause() {
        // The property the whole module exists for. Two different packages, one repair.
        let a = classify("gcc: fatal error: Python.h: No such file or directory\ncc failed");
        let b =
            classify("building 'lxml' extension\nfatal error: Python.h: No such file or directory");
        assert_eq!(a.key(), b.key());
        assert_eq!(a.key(), "cc/missing-header:python.h");
    }

    #[test]
    fn a_package_manager_the_package_asked_for_is_not_our_image_lacking_a_tool() {
        // Both arrive as `: not found` and they are opposite findings. Nine failures in one sweep
        // collapsed into a bucket named after the environment; an operator read it and asked
        // whether the environment should carry more, which for six of the nine would have meant
        // running a build with some arbitrary yarn.
        for (log, tool) in [
            (
                "npm ERR! command sh -c yarn build\nnpm ERR! sh: 1: yarn: not found",
                "yarn",
            ),
            (
                "> if [ ! -d 'dist' ]; then pnpm build; fi\nsh: 1: pnpm: not found",
                "pnpm",
            ),
        ] {
            let s = classify(log);
            assert_eq!(s.code, "npm/unsupported-package-manager", "{log}");
            assert_eq!(s.subject.as_deref(), Some(tool));
            assert_eq!(
                s.fault,
                Fault::Build,
                "trigon drives npm and never calls these, so the call came from the package"
            );
            assert!(!s.repairable, "no recipe change conjures a package manager");
        }
    }

    #[test]
    fn a_tool_our_own_recipe_invoked_is_still_charged_to_us() {
        // The other side of the split. `npx` is reached for by *our* tool, so it must stay
        // `Fault::Bug` — the specific rules above must not swallow the general one.
        let s = classify("/trigon/deps.sh: 13: /usr/local/bin/npx: not found");
        assert_eq!(s.code, "env/missing-tool");
        assert_eq!(s.fault, Fault::Bug);
    }

    #[test]
    fn a_shell_that_is_not_bash_names_a_missing_tool_the_same_way() {
        // `/bin/sh` on a Debian image is dash, which says `npx: not found` where bash says
        // `npx: command not found`. Before this, a missing tool under dash clustered as `unknown`.
        let s = classify("+ npx --yes pack\n/build: 2: npx: not found");
        assert_eq!(s.code, "env/missing-tool");
        assert_eq!(s.subject.as_deref(), Some("npx"));
        assert_eq!(
            s.fault,
            Fault::Bug,
            "our image lacks it, the package is fine"
        );
        assert!(s.repairable);
    }

    #[test]
    fn a_missing_tool_is_named_by_the_tool_not_by_the_shell_preamble() {
        // A shell prefixes the message with its own script and line number, and every delimiter
        // before the tool name appears in that preamble too. Reading forwards captured `line 3`,
        // which clusters by where the script happened to break rather than by what is missing.
        // `npx`, not `yarn`: this test is about the *capture* reading backwards from the marker,
        // and yarn now keys as `npm/unsupported-package-manager` because it can only have been
        // invoked by the package. The preamble question is the same either way, so it is asserted
        // on both codes rather than quietly moved off one of them.
        for line in [
            "/build/run.sh: line 3: npx: command not found",
            "sh: 1: npx: command not found",
            "bash: npx: command not found",
        ] {
            assert_eq!(classify(line).key(), "env/missing-tool:npx", "{line}");
        }
        for line in [
            "/build/run.sh: line 3: yarn: command not found",
            "sh: 1: yarn: command not found",
            "bash: yarn: command not found",
        ] {
            assert_eq!(
                classify(line).key(),
                "npm/unsupported-package-manager:yarn",
                "{line}"
            );
        }
    }

    #[test]
    fn a_subject_that_is_a_path_keeps_only_what_repairs_are_shared_by() {
        let s = classify(
            "fatal error: /usr/include/x86_64-linux-gnu/openssl/ssl.h: No such file or directory",
        );
        assert_eq!(s.subject.as_deref(), Some("ssl.h"));
    }

    #[test]
    fn a_class_whose_detail_is_per_target_captures_nothing() {
        // Which two packages conflict is a fact about the target. Keying on it would give every
        // target a cluster of one and make the repair cache useless.
        let a = classify("npm ERR! code ERESOLVE\nnpm ERR! while resolving: left-pad@1.3.0");
        let b = classify("npm ERR! code ERESOLVE\nnpm ERR! while resolving: request@2.88.0");
        assert_eq!(a.key(), b.key());
        assert_eq!(a.key(), "npm/peer-conflict");
    }

    #[test]
    fn the_last_error_wins_not_the_first() {
        // A warning early in a phase that went on to succeed is not why the build stopped.
        let log = "npm WARN EBADENGINE unsupported engine\nrunning build\nfatal error: ffi.h: No such file or directory";
        assert_eq!(classify(log).code, "cc/missing-header");
    }

    #[test]
    fn an_unrecognised_failure_is_one_cluster_not_five_hundred() {
        // A per-message hash would scatter a single missing rule across the whole corpus and make
        // it invisible. One bucket is a gap somebody fixes.
        let a = classify("error: the frobnicator declined, code 7");
        let b = classify("error: the frobnicator declined, code 9");
        assert!(a.is_unknown() && b.is_unknown());
        assert_eq!(a.key(), b.key());
        // The differing detail is still there for a human, just not in the key.
        assert_ne!(a.evidence, b.evidence);
    }

    #[test]
    fn a_failure_no_strategy_change_can_fix_is_marked_unrepairable() {
        // Admission control. A model iterating on an OOM spends money to reach the same place.
        let s = classify("/build/run.sh: line 4: 1213 Killed  npm run build");
        assert_eq!(s.code, "env/out-of-memory");
        assert!(!s.repairable);
        assert!(s.retryable, "a bigger worker could get further");
    }

    #[test]
    fn a_mirror_turning_a_request_away_is_not_an_unknown_failure() {
        // The real line, from a toolchain fetch against a mirror image built before the route
        // existed. It classified as `unknown`, which is where a whole cluster of our own bugs goes
        // to be invisible.
        let s = classify(
            "--2026-09-12 13:44:18--  http://timewarp:8129/-toolchain/nodejs.org/dist/v9.2.1/node-v9.2.1-linux-x64.tar.gz\n             Connecting to timewarp (timewarp)|10.89.0.2|:8129... connected.\n             HTTP request sent, awaiting response... 400 Bad Request\n             2026-09-12 13:44:18 ERROR 400: Bad Request.",
        );
        assert_eq!(s.code, "net/http-error");
        assert_eq!(
            s.subject.as_deref(),
            Some("400"),
            "the status is what clusters"
        );
        assert_eq!(
            s.fault,
            Fault::Policy,
            "the route was wrong, not the package"
        );
        assert!(s.repairable);
        assert!(!s.retryable, "the same request gets the same answer");
    }

    #[test]
    fn denied_egress_reads_as_policy_not_as_a_broken_package() {
        // Under mirror-only this is the enforcement working. Counting it against the package would
        // make the reproduction rate a measure of our own network policy.
        let s = classify(
            "npm ERR! request to https://registry.npmjs.org failed, reason: getaddrinfo EAI_AGAIN\nTemporary failure in name resolution",
        );
        assert_eq!(s.code, "net/unreachable");
        assert_eq!(s.fault, Fault::Policy);
    }

    #[test]
    fn the_failures_we_actually_hit_are_named() {
        // Every one of these stopped a real build while this system was being written. A taxonomy
        // built only from documentation would have missed all of them.
        for (log, code) in [
            ("Error: Cannot find module 'node:path'", "env/node-too-old"),
            (
                "The virtual environment was not created successfully because ensurepip is not available",
                "env/missing-venv",
            ),
            (
                "error: Unmet dependencies: wheel",
                "pip/unmet-build-dependency",
            ),
            (
                "fatal: unable to access 'https://github.com/x/y.git/': server certificate verification failed",
                "env/no-ca-certificates",
            ),
        ] {
            assert_eq!(classify(log).code, code, "log: {log}");
        }
    }

    #[test]
    fn the_failures_the_npm_corpus_actually_produced_are_named() {
        // Added from a real sweep, where all three arrived as `unknown` — which is what an unnamed
        // cluster is for: a pile of red rows nobody can act on until the rule exists.
        for (log, key) in [
            (
                "node: error while loading shared libraries: libatomic.so.1: cannot open shared object file: No such file or directory",
                "env/missing-shared-library:libatomic.so.1",
            ),
            (
                "add\tmocha\t3.5.3\tnode_modules/mocha\nAborted (core dumped)\nError: building at STEP \"RUN /bin/sh /trigon/deps.sh\": while running runtime: exit status 134",
                "env/toolchain-crashed",
            ),
        ] {
            assert_eq!(classify(log).key(), key, "log: {log}");
        }
    }

    #[test]
    fn a_fault_of_ours_that_looks_like_a_broken_package_is_named_as_ours() {
        // A corrupt tarball reads exactly like a package problem. When the corruption is our
        // harness's — our mirror, or a package manager we chose to pin — counting it against the
        // package makes the reproduction rate a measure of our own bugs, which is the failure this
        // whole taxonomy exists to prevent.
        let s = classify("npm ERR! code Z_DATA_ERROR\nnpm ERR! zlib: invalid stored block lengths");
        assert_eq!(s.code, "trigon/client-corrupted-download");
        assert_eq!(s.fault, Fault::Bug);
        assert!(
            !s.repairable,
            "no strategy change fixes a client that mangles its own download"
        );
        assert!(s.retryable);
    }

    #[test]
    fn a_commit_that_is_gone_is_upstream_and_beyond_repair() {
        let s =
            classify("fatal: reference is not a tree: 89347534a881a1fbf0d866bcb0cdc24e7a1ff642");
        assert_eq!(s.code, "git/commit-not-in-repo");
        assert_eq!(s.fault, Fault::Upstream);
        // The recorded commit is gone. A different strategy cannot conjure it back.
        assert!(!s.repairable);
    }

    #[test]
    fn evidence_is_bounded_and_carries_no_control_characters() {
        // This string reaches a model, and the build script that produced it chose every byte.
        let log = format!(
            "fatal error: x.h: No such file or directory {}",
            "A\u{1b}[2J".repeat(400)
        );
        let s = classify(&log);
        assert!(s.evidence.len() <= 300, "{}", s.evidence.len());
        assert!(!s.evidence.contains('\u{1b}'));
    }

    #[test]
    fn a_retryable_failure_is_told_apart_from_a_permanent_one() {
        assert!(classify("npm ERR! 503 Service Unavailable").retryable);
        assert!(
            !classify("npm ERR! notarget No matching version found for left-pad@9.9.9").retryable
        );
    }

    #[test]
    fn a_signature_survives_a_round_trip_through_a_file() {
        // It has to: a run record carries one, and a record nobody can read back is not a record.
        // `code` was `&'static str` until this test existed, which compiles on its own and makes
        // the derive fail on every struct that contains one — serde can only produce a `'static`
        // borrow from `'static` input.
        let before = classify("fatal error: Python.h: No such file or directory");
        let json = serde_json::to_string(&before).unwrap();
        let after: FailureSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(before, after);
        assert_eq!(after.key(), "cc/missing-header:python.h");
    }

    #[test]
    fn every_code_is_shaped_for_a_cluster_id() {
        for r in RULES {
            assert!(
                r.code == "unknown" || r.code.contains('/'),
                "`{}` should read `area/what-happened`",
                r.code
            );
            assert!(
                r.code
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "/-".contains(c)),
                "`{}` is not safe as a cluster id",
                r.code
            );
        }
    }
}
