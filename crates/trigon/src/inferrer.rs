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

        let files = checkout.files(FILE_LIMIT)?;
        let manifests = checkout.read(MANIFESTS, MANIFEST_BYTES);
        let evidence: Vec<String> = target
            .intrinsics
            .evidence
            .iter()
            .map(|e| format!("{}: {:?} ({:?})", e.source, e.claim, e.confidence))
            .collect();

        let purl = target.reference.to_string();
        let ecosystem = target.reference.ecosystem;
        let provider = self.provider.clone();
        let model = self.model.clone();

        // On a blocking thread because [`Provider`] is synchronous by design: the implementations
        // either block in their own client or are a recorded transcript. Blocking a worker thread
        // of the runtime that is also driving a sweep would stall every other target.
        let proposed = tokio::task::spawn_blocking(move || {
            let task = Task {
                purl: &purl,
                ecosystem,
                repo_files: &files,
                manifests: &manifests,
                evidence: &evidence,
                previous: None,
                failure: None,
                log: None,
            };
            trigon_ai::propose(provider.as_ref(), &model, &task)
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
    let mut out = vec![format!("a model proposed this recipe: {}", first_line(&c.diagnosis))];
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

/// A provider the operator asked for, and the model id to address it with.
///
/// Held separately from the rung because a ladder is rebuilt per target and a provider is not:
/// re-reading a transcript once per target in a sweep would be silly, and a live client would
/// re-open a connection pool every time.
#[derive(Debug)]
pub struct Configured {
    provider: Arc<Counting>,
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
}

impl Counting {
    fn new(inner: Box<dyn Provider>) -> Self {
        Counting {
            inner,
            calls: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn calls(&self) -> u32 {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Provider for Counting {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn caps(&self) -> trigon_ai::ModelCaps {
        self.inner.caps()
    }

    fn complete(&self, req: &trigon_ai::Request) -> Result<trigon_ai::Response, trigon_ai::LlmError> {
        // Before the call, not after it: a call that failed still cost something and still happened,
        // and a counter that only counts successes understates exactly the runs worth looking at.
        self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.complete(req)
    }
}

impl Configured {
    /// Read `--model`.
    ///
    /// One spec form today: `replay:<transcript.json>`, which answers from a recording and opens no
    /// socket. That is not a placeholder for a live provider — it is the form the eval tiers run
    /// on, where the exit criterion is *reproduces a recorded run with zero model calls*
    /// (`docs/07-ai.md` §8). A live provider is another arm here and changes nothing else.
    pub fn parse(spec: &str) -> Result<Self> {
        let (kind, rest) = spec.split_once(':').unwrap_or((spec, ""));
        match kind {
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
                Ok(Configured {
                    provider: Arc::new(Counting::new(Box::new(trigon_ai::Replaying::new(
                        transcript,
                    )))),
                    model,
                    cache_root: trigon_registry::SourceCache::default_root(),
                })
            }
            other => anyhow::bail!(
                "`{other}` is not a provider this build knows. Today: \
                 `--model replay:<transcript.json>`."
            ),
        }
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

    pub fn rung(&self) -> ModelInferrer {
        ModelInferrer::new(
            self.provider.clone(),
            self.model.clone(),
            SourceCache::new(&self.cache_root),
        )
    }
}

/// Which ecosystems this rung will speak about.
///
/// Not a capability of the model, a capability of the strategy vocabulary: a proposed recipe is
/// only useful where there are tools for it to name.
pub fn supported(e: Ecosystem) -> bool {
    matches!(e, Ecosystem::Npm | Ecosystem::PyPI)
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
                commit: commit.to_string(),
                ref_name: None,
                subdir: None,
                how: SourceDiscovery::RegistryCommit,
            }),
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
        assert_eq!(got[0].derivation, trigon_registry::Derivation::ModelAssisted);
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
        assert_eq!(replayed, live, "the replay did not reproduce the derivation");
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
            model: "claude-opus-5".into(),
            temperature: 0.0,
            prompt_sha256: "0".repeat(64),
            system_sha256: "1".repeat(64),
            schema_sha256: None,
            answer: ANSWER.into(),
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
