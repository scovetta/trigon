//! The rung that asks a model.
//!
//! Last on the ladder, and structurally identical to the ones above it: [`StrategyInferrer`] is the
//! only thing the engine knows about, so there is no branch anywhere asking whether a candidate
//! came from a heuristic or a model (`docs/01-architecture.md` §5.1). What differs is the
//! `derivation` recorded beside the answer, which a consumer can filter on.
//!
//! It lives in the binary rather than in `trigon-registry` because the trait is defined there and
//! `trigon-registry` must not depend on `trigon-ai`. The binary already depends on both, so the
//! adapter belongs here and the dependency edge that would matter never exists.
//!
//! **Declining is the normal case.** No repository, no commit, no provider configured: the rung
//! returns nothing and the ladder moves on. A model that answers where it has nothing to read is
//! the failure mode `docs/07-ai.md` §6 labels the corpus to catch.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use trigon_ai::{Provider, Task};
use trigon_core::{Confidence, Ecosystem};
use trigon_registry::{Candidate, Derivation, RegistryError, ResolvedTarget, SourceCache};

/// Manifests worth quoting in full.
///
/// Named rather than discovered, and the same list for every ecosystem: a repository has a handful
/// of these, the reader skips what is absent, and a rule like "every `.toml` at the root" reads a
/// CI config and a linter's settings into a prompt that has a budget.
const MANIFESTS: &[&str] = &[
    "package.json",
    "npm-shrinkwrap.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Cargo.toml",
    "Gemfile",
    "Makefile",
];

/// How much of the repository the model is shown.
///
/// A file list is cheap per entry and long in the tail: a thousand paths is most of a repository's
/// shape, and the twenty thousand after it are `test/fixtures`. The manifest cap is what stops a
/// generated lockfile from becoming the prompt.
const FILE_LIMIT: usize = 1_000;
const MANIFEST_BYTES: usize = 32 * 1024;

pub struct ModelInferrer {
    provider: Arc<dyn Provider>,
    model: String,
    cache: Arc<SourceCache>,
}

impl ModelInferrer {
    pub fn new(provider: Arc<dyn Provider>, model: impl Into<String>, cache: SourceCache) -> Self {
        ModelInferrer {
            provider,
            model: model.into(),
            cache: Arc::new(cache),
        }
    }
}

#[async_trait::async_trait]
impl trigon_registry::StrategyInferrer for ModelInferrer {
    fn name(&self) -> &'static str {
        "model"
    }

    async fn infer(&self, target: &ResolvedTarget) -> Result<Vec<Candidate>, RegistryError> {
        let Some(source) = target.source.clone() else {
            // Source discovery is a different rung's job and a different capability label. Asking a
            // model to guess a repository from a package name is how a corpus grows targets that
            // pass for the wrong reason.
            tracing::debug!("no source recorded, so there is no repository to read");
            return Ok(Vec::new());
        };
        if source.commit.is_empty() {
            return Ok(Vec::new());
        }

        let cache = self.cache.clone();
        let (repo, commit) = (source.repo_url.clone(), source.commit.clone());
        let checkout = tokio::task::spawn_blocking(move || cache.checkout(&repo, &commit))
            .await
            .map_err(|e| RegistryError::Source {
                repo: source.repo_url.clone(),
                detail: format!("the checkout task did not finish: {e}"),
            })??;

        let inputs = Inputs::read(&checkout, target)?;
        let provider = self.provider.clone();
        let model = self.model.clone();

        // On a blocking thread because [`Provider`] is synchronous by design: the implementations
        // either block in their own client or are a recorded transcript. Blocking a worker thread
        // of the runtime that is also driving a sweep would stall every other target.
        let proposed = tokio::task::spawn_blocking(move || {
            trigon_ai::propose(provider.as_ref(), &model, &inputs.task(None, None, None))
        })
        .await
        .map_err(|e| RegistryError::Source {
            repo: source.repo_url.clone(),
            detail: format!("the inference task did not finish: {e}"),
        })?;

        let proposed = match proposed {
            Ok(c) => c,
            // A model that will not answer is not a failure of this run: the ladder has already
            // produced nothing, and the target ends as `no-strategy` rather than as an error of
            // ours. Logged at warn, because a provider that is refusing everything should be
            // visible without reading a results file.
            Err(e) => {
                tracing::warn!("the model rung produced nothing: {e}");
                return Ok(Vec::new());
            }
        };

        let strategy = match trigon_strategy::from_yaml(&proposed.strategy) {
            Ok(s) => s,
            // The parse error carries the path to the offending field, which is what a repair
            // iteration feeds back. Nothing here repairs yet, so it is logged and declined.
            Err(e) => {
                tracing::warn!("the model's strategy did not parse: {e}");
                return Ok(Vec::new());
            }
        };

        Ok(vec![Candidate {
            strategy,
            derivation: Derivation::ModelAssisted,
            // Always `Weak`, whatever the model said about itself. Its own confidence is recorded
            // beside the claim and never inside it: an outcome that moved because a model said
            // "certain" would be exactly the thing `docs/09-attestations.md` §4 forbids.
            confidence: Confidence::Weak,
            discovery: source.how,
            assumptions: assumptions(&proposed),
        }])
    }
}

/// What the model said it was doing, as the assumptions this candidate carries.
///
/// The diagnosis is a required field of the answer, which is how one call does the work the prior
/// art spent three on. It is printed beside a divergence so the result can be read against the
/// reasoning that produced it rather than as a fact about the package.
fn assumptions(c: &trigon_ai::Candidate) -> Vec<String> {
    let mut out = vec![format!(
        "a model proposed this recipe: {}",
        first_line(&c.diagnosis)
    )];
    if let Some(said) = &c.confidence {
        out.push(format!(
            "the model called its own confidence `{said}`, which nothing downstream acts on"
        ));
    }
    out
}

fn first_line(s: &str) -> String {
    let line = s.trim().lines().next().unwrap_or_default().trim();
    match line.char_indices().nth(300) {
        Some((i, _)) => format!("{}…", &line[..i]),
        None => line.to_string(),
    }
}

/// Everything about a target the Builder is shown, read once.
///
/// Owned rather than borrowed because the call happens on another thread, and shared between the
/// first proposal and every repair after it: the repository does not change between attempts, and
/// re-reading it would be both wasteful and a way for the two to disagree.
pub struct Inputs {
    purl: String,
    ecosystem: Ecosystem,
    files: Vec<String>,
    manifests: Vec<(String, String)>,
    evidence: Vec<String>,
}

impl Inputs {
    fn read(
        checkout: &trigon_registry::Checkout,
        target: &ResolvedTarget,
    ) -> Result<Self, RegistryError> {
        Ok(Inputs {
            purl: target.reference.to_string(),
            ecosystem: target.reference.ecosystem,
            files: checkout.files(FILE_LIMIT)?,
            manifests: checkout.read(MANIFESTS, MANIFEST_BYTES),
            evidence: target
                .intrinsics
                .evidence
                .iter()
                .map(|e| format!("{}: {:?} ({:?})", e.source, e.claim, e.confidence))
                .collect(),
        })
    }

    /// The task, with the repair fields filled in on an iteration after the first.
    pub(crate) fn task<'a>(
        &'a self,
        previous: Option<&'a str>,
        failure: Option<&'a trigon_core::FailureSignature>,
        log: Option<&'a str>,
    ) -> Task<'a> {
        Task {
            purl: &self.purl,
            ecosystem: self.ecosystem,
            repo_files: &self.files,
            manifests: &self.manifests,
            evidence: &self.evidence,
            previous,
            failure,
            log,
            divergence: None,
        }
    }
}

/// A provider the operator asked for, and the model id to address it with.
///
/// Held separately from the rung because a ladder is rebuilt per target and a provider is not:
/// re-reading a transcript once per target in a sweep would be silly, and a live client would
/// re-open a connection pool every time.
#[derive(Debug)]
pub struct Configured {
    provider: Arc<Counting>,
    /// The same provider, one layer in, so the run can ask what was said.
    ///
    /// `Recorder` and `RunRecord::transcript` both existed and were never connected: production
    /// wrapped the provider in `Counting` and nothing else, so no run has ever written a
    /// transcript and `docs/13-roadmap.md` M3's "replay reproduces a recorded run" was true only of
    /// the provider seam, with nothing to replay. `docs/07-ai.md` §8 is clear about what a
    /// transcript is worth and what it is not — it replays the model, not the world — but a
    /// `derivation: model_assisted` with no transcript beside it is an assertion rather than
    /// evidence, which is exactly what `RunRecord::transcript`'s own comment says.
    recorder: Arc<trigon_ai::Recorder<Box<dyn Provider>>>,
    model: String,
    cache_root: std::path::PathBuf,
}

/// A provider that counts what goes through it.
///
/// The number the eval harness is built around: `docs/07-ai.md` §6 wants the model-invocation rate
/// to trend *down*, and a rate needs a numerator that comes from the run rather than from an
/// assumption about which rungs called anything. Counting here rather than at each call site means
/// a future repair loop is counted without remembering to.
#[derive(Debug)]
pub struct Counting {
    inner: Box<dyn Provider>,
    calls: std::sync::atomic::AtomicU32,
    /// Tokens, so the repair loop's budgets are enforceable rather than decorative. Summed across
    /// every call this run made, which is what a per-target budget is about.
    spent: std::sync::Mutex<trigon_ai::Usage>,
    /// Nanoseconds spent inside `complete`, summed.
    ///
    /// Here rather than around the ladder, because this is the only place that sees exactly the
    /// time spent *waiting on a model* — a rung that reads a repository and then asks a question
    /// would otherwise bill the reading as inference. `docs/03` §3 wants this beside the build
    /// seconds, and the two are only comparable if they measure the same kind of thing.
    nanos: std::sync::atomic::AtomicU64,
}

impl Counting {
    fn new(inner: Box<dyn Provider>) -> Self {
        Counting {
            inner,
            calls: std::sync::atomic::AtomicU32::new(0),
            spent: std::sync::Mutex::new(trigon_ai::Usage::default()),
            nanos: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Wall-clock seconds spent waiting on a model, or `None` if it was never asked.
    ///
    /// `None` rather than `0.0`, and for the reason the phase timings give: a run that asked
    /// nothing and a run whose timing we lost are different facts, and averaging the second as zero
    /// understates every figure downstream.
    fn inference_seconds(&self) -> Option<f64> {
        match self.nanos.load(std::sync::atomic::Ordering::Relaxed) {
            0 => None,
            n => Some(n as f64 / 1e9),
        }
    }

    fn calls(&self) -> u32 {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn spent(&self) -> trigon_ai::Usage {
        self.spent.lock().map(|u| *u).unwrap_or_default()
    }
}

impl Provider for Counting {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn caps(&self) -> trigon_ai::ModelCaps {
        self.inner.caps()
    }

    fn reasoning(&self) -> trigon_ai::Reasoning {
        self.inner.reasoning()
    }

    fn complete(
        &self,
        req: &trigon_ai::Request,
    ) -> Result<trigon_ai::Response, trigon_ai::LlmError> {
        // Before the call, not after it: a call that failed still cost something and still happened,
        // and a counter that only counts successes understates exactly the runs worth looking at.
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let started = std::time::Instant::now();
        let resp = self.inner.complete(req);
        // Timed whether or not it worked, for the same reason the call is counted before it runs: a
        // provider that hangs for ninety seconds and then fails cost ninety seconds, and a figure
        // that counts only successes flatters exactly the runs worth investigating.
        self.nanos.fetch_add(
            started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        let resp = resp?;
        if let Ok(mut u) = self.spent.lock() {
            u.input += resp.usage.input;
            u.cached_input += resp.usage.cached_input;
            u.output += resp.usage.output;
        }
        Ok(resp)
    }
}

impl Configured {
    /// Read `--model`.
    ///
    /// `<provider>:<model>`, or `replay:<transcript.json>` to answer from a recording and open no
    /// socket. Replay is not a placeholder for the live providers — it is the form the eval tiers
    /// run on, where the exit criterion is *reproduces a recorded run with zero model calls*
    /// (`docs/07-ai.md` §8).
    ///
    /// Keys come from the environment and never from the command line, so a key does not end up in
    /// a shell history, a process list, or a `--help` example somebody copies.
    pub fn parse(spec: &str) -> Result<Self> {
        let (kind, rest) = spec.split_once(':').unwrap_or((spec, ""));
        match kind {
            // Local, and the reason this is the one that needs no key: the model is on this
            // machine. The tag is pinned to the digest it resolves to, so a recording names bytes
            // rather than a label that the next `ollama pull` moves.
            "ollama" => {
                let base = std::env::var("OLLAMA_HOST")
                    .unwrap_or_else(|_| "http://localhost:11434".into());
                let base = format!("{}/v1", base.trim_end_matches('/').trim_end_matches("/v1"));
                // `+no-reasoning` rather than a flag, so everything about which model answers stays
                // in one string. `+` is not a character an Ollama name can contain, so a tag can
                // never be read as carrying this by accident.
                let (tag, reasoning) = match rest.strip_suffix("+no-reasoning") {
                    Some(tag) => (tag, trigon_ai::Reasoning::Off),
                    None => (rest, trigon_ai::Reasoning::Default),
                };
                let p = trigon_ai::OpenAiCompatible::new(base, None, trigon_ai::Flavor::Ollama)?
                    .with_reasoning(reasoning);
                let model = p.pinned_model(&named(tag, "ollama")?);
                Ok(Self::live(Box::new(p), model))
            }
            "openai" => Ok(Self::live(
                Box::new(trigon_ai::OpenAiCompatible::new(
                    std::env::var("OPENAI_BASE_URL")
                        .unwrap_or_else(|_| "https://api.openai.com/v1".into()),
                    Some(key("OPENAI_API_KEY")?),
                    trigon_ai::Flavor::OpenAi,
                )?),
                named(rest, "openai")?,
            )),
            "openrouter" => Ok(Self::live(
                Box::new(trigon_ai::OpenAiCompatible::new(
                    "https://openrouter.ai/api/v1",
                    Some(key("OPENROUTER_API_KEY")?),
                    trigon_ai::Flavor::OpenRouter,
                )?),
                named(rest, "openrouter")?,
            )),
            // An agent with a shell on this machine, configured so the model sees no tools at all.
            // The reasoning is in `trigon_ai::Copilot`'s module docs and it is worth reading before
            // using this: the prompt carries text a package wrote, and every other provider here is
            // a function from a prompt to a string rather than something that can act.
            "copilot" => Ok(Self::live(
                Box::new(trigon_ai::Copilot::new(
                    std::env::temp_dir().join("trigon-copilot"),
                )?),
                // `auto` lets Copilot pick, and the transcript records what answered.
                if rest.is_empty() {
                    "auto".into()
                } else {
                    rest.to_string()
                },
            )),
            "anthropic" => Ok(Self::live(
                Box::new(trigon_ai::Anthropic::new(
                    key("ANTHROPIC_API_KEY")?,
                    std::env::var("ANTHROPIC_BASE_URL").ok(),
                )?),
                named(rest, "anthropic")?,
            )),
            // Anything else speaking the same protocol: vLLM, llama.cpp, a gateway. The URL is in
            // the spec because there is nothing else to guess it from.
            "compatible" => {
                let (base, model) = rest.split_once('#').ok_or_else(|| {
                    anyhow::anyhow!(
                        "`--model compatible:<base-url>#<model>` needs both, such as \
                         `compatible:http://localhost:8000/v1#my-model`"
                    )
                })?;
                Ok(Self::live(
                    Box::new(trigon_ai::OpenAiCompatible::new(
                        base,
                        std::env::var("TRIGON_LLM_API_KEY").ok(),
                        trigon_ai::Flavor::Other,
                    )?),
                    named(model, "compatible")?,
                ))
            }
            "replay" => {
                if rest.is_empty() {
                    anyhow::bail!("`--model replay:<transcript.json>` needs a recording to replay");
                }
                let text = std::fs::read(rest)
                    .with_context(|| format!("reading the transcript at {rest}"))?;
                let transcript: trigon_ai::Transcript = serde_json::from_slice(&text)
                    .with_context(|| format!("parsing the transcript at {rest}"))?;
                // Refused up front rather than at the first mismatch. A transcript whose turns name
                // an alias cannot be replayed as evidence of anything: the model it names is
                // whatever that alias resolves to today.
                if !transcript.replayable() {
                    anyhow::bail!(
                        "{rest} names a model alias rather than a snapshot, so replaying it would \
                         prove nothing about which model answered"
                    );
                }
                let model = transcript
                    .turns
                    .first()
                    .map(|t| t.model.clone())
                    .unwrap_or_else(|| "replay".into());
                Ok(Self::live(
                    Box::new(trigon_ai::Replaying::new(transcript)),
                    model,
                ))
            }
            other => anyhow::bail!(
                "`{other}` is not a provider this build knows. One of: \
                 `ollama:<model>[+no-reasoning]`, `anthropic:<model>`, `openai:<model>`, \
                 `openrouter:<model>`, \
                 `copilot:<model|auto>`, `compatible:<base-url>#<model>`, or \
                 `replay:<transcript.json>`."
            ),
        }
    }

    fn live(provider: Box<dyn Provider>, model: String) -> Self {
        // Recorder innermost, so it sees what the provider actually answered; Counting outside it,
        // so a call that failed still counts. Both hold the same inner provider through an `Arc`.
        let recorder = Arc::new(trigon_ai::Recorder::new(provider));
        Configured {
            provider: Arc::new(Counting::new(Box::new(recorder.clone()))),
            recorder,
            model,
            cache_root: trigon_registry::SourceCache::default_root(),
        }
    }

    /// What the model was asked and what it said, for the run to record.
    ///
    /// Empty when nothing was asked, which is the common and healthy case: `docs/07-ai.md` §6 wants
    /// the model-invocation rate to trend down, so most targets should produce no turns at all.
    pub fn transcript(&self, target: &str) -> trigon_ai::Transcript {
        self.recorder.transcript(target)
    }

    /// Where checkouts are kept.
    pub fn with_cache_root(mut self, root: Option<std::path::PathBuf>) -> Self {
        if let Some(r) = root {
            self.cache_root = r;
        }
        self
    }

    /// What this provider is, for the run record and the line the CLI prints.
    pub fn describe(&self) -> String {
        format!("{} ({})", self.model, self.provider.id())
    }

    /// How many times a model was asked, so far.
    pub fn calls(&self) -> u32 {
        self.provider.calls()
    }

    /// Wall-clock seconds spent waiting on a model, or `None` if it was never asked.
    pub fn inference_seconds(&self) -> Option<f64> {
        self.provider.inference_seconds()
    }

    /// The pinned model id these costs are against.
    ///
    /// A cost figure without one is not comparable to anything: the same token count is two orders
    /// of magnitude apart in price between a local 0.5B and a frontier model, so the id travels
    /// with the tokens rather than being looked up from a config that has since changed.
    pub fn model_id(&self) -> &str {
        &self.model
    }

    /// What those calls have cost, so far.
    ///
    /// A provider that reports nothing leaves this at zero, which is honest rather than estimated —
    /// and means a token budget cannot stop a run against a provider that does not count. The
    /// iteration cap and the repeated-signature rule still can.
    pub fn spent(&self) -> trigon_ai::Usage {
        self.provider.spent()
    }

    /// Read a target's repository once, for a run that is going to ask more than one question.
    ///
    /// Synchronous, unlike the rung: the repair loop runs after the build, where there is no async
    /// context to borrow and nothing to overlap with.
    pub fn inputs(&self, target: &ResolvedTarget) -> Result<Inputs> {
        let source = target
            .source
            .as_ref()
            .filter(|s| !s.commit.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("no source commit, so there is no repository to read")
            })?;
        let checkout = SourceCache::new(&self.cache_root)
            .checkout(&source.repo_url, &source.commit)
            .context("fetching the source for a repair")?;
        Ok(Inputs::read(&checkout, target)?)
    }

    /// Ask for a repair after a divergence: the recipe that ran, and how what it built differs.
    ///
    /// Separate from [`Self::repair`] because it is a different question. A build failure says the
    /// recipe does not run; a divergence says it runs and builds something else, which is the
    /// harder half and the one the corpus's `needs-build-inference` label is about.
    pub fn repair_divergence(
        &self,
        inputs: &Inputs,
        previous: &str,
        divergence: &str,
    ) -> Result<trigon_strategy::Strategy> {
        let mut task = inputs.task(Some(previous), None, None);
        task.divergence = Some(divergence);
        let proposed = trigon_ai::propose(self.provider.as_ref(), &self.model, &task)
            .context("asking about a divergence")?;
        trigon_strategy::from_yaml(&proposed.strategy).with_context(|| {
            format!(
                "the proposal did not parse as a strategy. The model said: {}",
                first_line(&proposed.diagnosis)
            )
        })
    }

    /// Ask for a repair: the recipe that was tried, how it failed, and the log.
    ///
    /// The log is **already compressed** by the caller. Sending raw build output is the single
    /// most expensive mistake available here — `docs/07-ai.md` §4.5 measures it at roughly 7× —
    /// and a function that quietly compressed it would hide the cost from the caller who chose the
    /// budget.
    pub fn repair(
        &self,
        inputs: &Inputs,
        previous: &str,
        failure: &trigon_core::FailureSignature,
        log: &str,
    ) -> Result<trigon_strategy::Strategy> {
        let task = inputs.task(Some(previous), Some(failure), Some(log));
        let proposed = trigon_ai::propose(self.provider.as_ref(), &self.model, &task)
            .context("asking for a repair")?;
        trigon_strategy::from_yaml(&proposed.strategy).with_context(|| {
            format!(
                "the repair did not parse as a strategy. The model said: {}",
                first_line(&proposed.diagnosis)
            )
        })
    }

    pub fn rung(&self) -> ModelInferrer {
        ModelInferrer::new(
            self.provider.clone(),
            self.model.clone(),
            SourceCache::new(&self.cache_root),
        )
    }
}

/// The model a spec named, or a message saying one is needed.
fn named(rest: &str, provider: &str) -> Result<String> {
    if rest.is_empty() {
        anyhow::bail!("`--model {provider}:<model>` needs a model, such as `{provider}:<name>`");
    }
    Ok(rest.to_string())
}

/// A key from the environment, never from the command line.
fn key(var: &str) -> Result<String> {
    std::env::var(var)
        .ok()
        .filter(|k| !k.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "${var} is not set. Keys are read from the environment rather than passed on the \
                 command line, so they stay out of shell history and process listings."
            )
        })
}

/// Which ecosystems this rung will speak about.
///
/// Not a capability of the model, a capability of the strategy vocabulary: a proposed recipe is
/// only useful where there are tools for it to name. So this must be widened in the same commit
/// that adds `tools/<ecosystem>/` and registers them in `BUILTIN_TOOLS`, and not before — a model
/// asked to propose a recipe from a vocabulary that does not exist produces a strategy that fails
/// tool validation, which costs tokens to learn nothing.
///
/// Exhaustive rather than a `matches!`, so adding an `Ecosystem` variant fails to compile here
/// instead of silently answering `false`. The silent answer is worse than it sounds: it turns off
/// the model rung with no line anywhere saying it did.
pub fn supported(e: Ecosystem) -> bool {
    match e {
        Ecosystem::Npm | Ecosystem::PyPI => true,
        Ecosystem::CratesIo
        | Ecosystem::RubyGems
        | Ecosystem::NuGet
        | Ecosystem::Maven
        | Ecosystem::GitHub => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use trigon_ai::{Recorder, Replay, Replaying, Transcript};
    use trigon_core::{
        ArtifactId, Claim, Confidence, Ecosystem, Evidence, Intrinsics, SourceDiscovery,
        SourceProvenance, TargetRef,
    };
    use trigon_registry::{ArtifactMeta, ResolvedTarget, StrategyInferrer};

    use super::*;

    /// What a model would answer for left-pad: the same recipe the heuristic builds.
    const ANSWER: &str = r#"{
      "diagnosis": "An npm package with no build step; `npm pack` at the published commit reproduces the tarball.",
      "strategy": "kind: flow\nlocation:\n  repo: https://github.com/stevemao/left-pad\n  ref: ff8e7ba8b4122829cf66125ca8445cac7f073bce\nsrc:\n  - uses: git-checkout\nbuild:\n  - runs: npm pack\noutput_path: '*.tgz'\n",
      "confidence": "likely"
    }"#;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("trigon-rung-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
    }

    /// A repository the rung can read, and the commit to pin it at.
    fn fixture(root: &Path) -> (PathBuf, String) {
        let repo = root.join("origin");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("package.json"), "{\"name\":\"left-pad\"}\n").unwrap();
        std::fs::write(repo.join("index.js"), "module.exports = 1;\n").unwrap();
        git(&repo, &["init", "--quiet", "-b", "main"]);
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "--quiet", "-m", "one"]);
        let out = Command::new("git")
            .current_dir(&repo)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        (
            repo,
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        )
    }

    fn target(repo: &Path, commit: &str) -> ResolvedTarget {
        ResolvedTarget {
            reference: TargetRef::new(Ecosystem::Npm, "left-pad", "1.3.0"),
            artifacts: vec![ArtifactMeta {
                id: ArtifactId::new("left-pad-1.3.0.tgz"),
                url: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into(),
                declared_sha256: None,
                size: None,
            }],
            intrinsics: Intrinsics {
                publish_time: Some("2018-04-09T01:10:45.796Z".into()),
                declared_repo: None,
                registry_moment: None,
                evidence: vec![Evidence::new(
                    Claim::ToolchainExact {
                        tool: "node".into(),
                        version: "9.2.1".into(),
                    },
                    Confidence::Certain,
                    "npm:_nodeVersion",
                )],
            },
            source: Some(SourceProvenance {
                repo_url: repo.to_string_lossy().into_owned(),
                declared_url: None,
                commit: commit.to_string(),
                ref_name: None,
                subdir: None,
                how: SourceDiscovery::RegistryCommit,
            }),
            about: None,
        }
    }

    fn rung(provider: Arc<dyn Provider>, cache_root: &Path) -> ModelInferrer {
        ModelInferrer::new(
            provider,
            "claude-haiku-4-5-20251001",
            SourceCache::new(cache_root).trusting_local_paths(),
        )
    }

    #[tokio::test]
    async fn the_rung_reads_the_repository_and_returns_a_model_assisted_candidate() {
        let d = tmpdir("candidate");
        let (repo, commit) = fixture(&d);
        let r = rung(Arc::new(Replay::once(ANSWER)), &d.join("cache"));

        let got = r.infer(&target(&repo, &commit)).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].derivation,
            trigon_registry::Derivation::ModelAssisted
        );
        // Never promoted on what the model said about itself, whatever it said.
        assert_eq!(got[0].confidence, Confidence::Weak);
        assert!(
            got[0].assumptions.iter().any(|a| a.contains("npm pack")),
            "the diagnosis is not carried as an assumption: {:?}",
            got[0].assumptions
        );
        assert!(
            got[0].assumptions.iter().any(|a| a.contains("likely")),
            "the model's own confidence is recorded rather than acted on"
        );
    }

    #[tokio::test]
    async fn the_provider_a_run_actually_uses_records_what_it_was_asked() {
        // The test below exercises `Recorder` at the provider seam, which is where M3's replay
        // criterion was met. Production does not build a rung that way: it builds a `Configured`,
        // and `Configured` wrapped the provider in `Counting` and nothing else — so `Recorder`
        // existed, `RunRecord::transcript` had a field for the digest, and no run ever wrote one.
        // This is the seam that was missing, so this is the test that has to exist.
        let d = tmpdir("configured-records");
        let (repo, commit) = fixture(&d);
        let cfg = Configured::live(Box::new(Replay::once(ANSWER)), "replay".into())
            .with_cache_root(Some(d.join("cache")));

        assert!(
            cfg.transcript("pkg:npm/left-pad@1.3.0").turns.is_empty(),
            "nothing has been asked yet, and an empty transcript is the honest state for that"
        );

        // The rung is built from `cfg`'s own provider — the thing that was not being recorded —
        // but with the test helper's source cache, because `Configured::rung` correctly refuses a
        // local repository path (P10: a repo URL comes from package metadata and is https-only
        // unless the *operator* named a path) and weakening that to make a test pass would trade a
        // security control for a convenience.
        rung(cfg.provider.clone(), &d.join("cache"))
            .infer(&target(&repo, &commit))
            .await
            .unwrap();

        let t = cfg.transcript("pkg:npm/left-pad@1.3.0");
        assert_eq!(
            t.turns.len(),
            1,
            "the provider a real run uses recorded nothing: {t:?}"
        );
        assert_eq!(t.target, "pkg:npm/left-pad@1.3.0");
        // And the count the eval harness reads still works through the extra layer.
        assert_eq!(
            cfg.calls(),
            1,
            "Counting stopped counting once Recorder sat inside it"
        );
    }

    #[tokio::test]
    async fn a_recorded_run_replays_with_no_provider_behind_it() {
        // M3's exit criterion, end to end through the rung rather than at the provider: record one
        // exchange, then run the same target against the recording and get the same candidate.
        let d = tmpdir("replay");
        let (repo, commit) = fixture(&d);
        let t = target(&repo, &commit);

        let recorder = Arc::new(Recorder::new(Replay::once(ANSWER)));
        let live = rung(recorder.clone(), &d.join("cache"))
            .infer(&t)
            .await
            .unwrap();

        let transcript = recorder.transcript("pkg:npm/left-pad@1.3.0");
        assert_eq!(transcript.turns.len(), 1, "one call, not three");

        let replayed = rung(Arc::new(Replaying::new(transcript)), &d.join("cache"))
            .infer(&t)
            .await
            .unwrap();
        assert_eq!(
            replayed, live,
            "the replay did not reproduce the derivation"
        );
    }

    #[tokio::test]
    async fn a_target_with_no_source_is_declined_rather_than_guessed_at() {
        // Source discovery is a different rung and a different capability label. A model asked to
        // guess a repository from a package name is how a corpus grows targets that pass for the
        // wrong reason.
        let d = tmpdir("nosource");
        let (repo, commit) = fixture(&d);
        let mut t = target(&repo, &commit);
        t.source = None;

        let r = rung(Arc::new(Replay::once(ANSWER)), &d.join("cache"));
        assert!(r.infer(&t).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_answer_that_does_not_parse_is_declined_rather_than_raised() {
        // The ladder moving on is the right outcome: the target ends as `no-strategy`, which is a
        // statement about this run, not an error of ours that pollutes a sweep's denominator.
        let d = tmpdir("unparseable");
        let (repo, commit) = fixture(&d);
        let bad = r#"{"diagnosis": "d", "strategy": "kind: flow\nlocation: {}\n"}"#;
        let r = rung(Arc::new(Replay::once(bad)), &d.join("cache"));
        assert!(r.infer(&target(&repo, &commit)).await.unwrap().is_empty());
    }

    #[test]
    fn a_transcript_naming_an_alias_is_refused_before_a_run_starts() {
        let d = tmpdir("alias");
        let mut t = Transcript::new("pkg:npm/a@1");
        t.turns.push(trigon_ai::Turn {
            // A label that resolves to whatever is behind it today. `claude-opus-5` is not one:
            // that version *is* the complete model id, with no date to append.
            model: "gpt-latest".into(),
            temperature: 0.0,
            prompt_sha256: "0".repeat(64),
            system_sha256: "1".repeat(64),
            schema_sha256: None,
            answer: ANSWER.into(),
            reasoning: None,
            reasoning_asked: Default::default(),
            usage: Default::default(),
            stop_reason: "end_turn".into(),
        });
        let p = d.join("t.json");
        std::fs::write(&p, serde_json::to_vec(&t).unwrap()).unwrap();

        let e = Configured::parse(&format!("replay:{}", p.display()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("alias"), "{e}");

        // And an unknown provider says what this build does know rather than failing later.
        let e = Configured::parse("gpt-4o").unwrap_err().to_string();
        assert!(e.contains("replay:"), "{e}");
    }
}
