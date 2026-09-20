//! What a climb keeps, which file a run is about, and whether a failure is worth retrying.
//!
//! Three decisions this crate makes that nothing else can make for it, and that the live suite
//! cannot reach because they are about what happens when the network has already answered.
//!
//! All three leave the crate. A climb's declines are the only explanation a `no-strategy` verdict
//! ever carries; the artifact a run is about is named in a signed statement; and `is_retryable`
//! decides whether the queue tries again or writes the failure down as final. None of them had a
//! test.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use trigon_core::{
    ArtifactId, Classify, Confidence, Ecosystem, Fault, Intrinsics, SourceDiscovery, TargetRef,
};
use trigon_registry::{
    ArtifactMeta, Candidate, DefinitionsInferrer, Derivation, RegistryError, ResolvedTarget,
    StrategyInferrer, climb,
};
use trigon_strategy::{Strategy, from_yaml};

const FLOW: &str = r#"
schema: 1
kind: flow
location:
  repo: https://github.com/example/widget
  ref: ff8e7ba8b4122829cf66125ca8445cac7f073bce
build:
  - runs: make
"#;

fn a_strategy() -> Strategy {
    from_yaml(FLOW).expect("the fixture parses")
}

/// What a test rung was told to do when it is asked.
#[derive(Clone, Copy)]
enum Answer {
    /// Produces a candidate, which should end the climb.
    Candidate,
    /// Produces nothing, with or without a reason to offer afterwards.
    Silent(Option<&'static str>),
    /// Fails, which is not fatal: the next rung may still know.
    Broken,
}

/// A rung that does as it is told and counts what it was asked.
///
/// The counts are the point of several of these tests: the ladder's cost model says a rung that
/// answered pays nothing for `why_not`, and an assertion about the *record* cannot see whether the
/// call was made.
struct Rung {
    label: &'static str,
    answer: Answer,
    infers: Arc<AtomicUsize>,
    why_nots: Arc<AtomicUsize>,
}

impl Rung {
    fn new(label: &'static str, answer: Answer) -> Self {
        Rung {
            label,
            answer,
            infers: Arc::new(AtomicUsize::new(0)),
            why_nots: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl StrategyInferrer for Rung {
    fn name(&self) -> &'static str {
        self.label
    }

    async fn infer(&self, _t: &ResolvedTarget) -> Result<Vec<Candidate>, RegistryError> {
        self.infers.fetch_add(1, Ordering::SeqCst);
        match self.answer {
            Answer::Candidate => Ok(vec![Candidate {
                strategy: a_strategy(),
                derivation: Derivation::Heuristic,
                confidence: Confidence::Strong,
                discovery: SourceDiscovery::ExactTag,
                assumptions: Vec::new(),
            }]),
            Answer::Silent(_) => Ok(Vec::new()),
            Answer::Broken => Err(RegistryError::Malformed {
                ecosystem: "npm".into(),
                what: "the packument".into(),
                detail: "truncated".into(),
            }),
        }
    }

    async fn why_not(&self, _t: &ResolvedTarget) -> Option<String> {
        self.why_nots.fetch_add(1, Ordering::SeqCst);
        match self.answer {
            Answer::Silent(why) => why.map(str::to_string),
            _ => None,
        }
    }
}

/// The rungs, plus a handle on each one's counters, since `climb` takes the boxes by value.
fn ladder(rungs: Vec<Rung>) -> (Vec<Box<dyn StrategyInferrer>>, Vec<(Arc<AtomicUsize>, Arc<AtomicUsize>)>)
{
    let counts = rungs
        .iter()
        .map(|r| (Arc::clone(&r.infers), Arc::clone(&r.why_nots)))
        .collect();
    let boxed = rungs
        .into_iter()
        .map(|r| Box::new(r) as Box<dyn StrategyInferrer>)
        .collect();
    (boxed, counts)
}

fn target(artifacts: &[&str]) -> ResolvedTarget {
    ResolvedTarget {
        reference: TargetRef::new(Ecosystem::PyPI, "widget", "1.2.3"),
        artifacts: artifacts
            .iter()
            .map(|id| ArtifactMeta {
                id: ArtifactId::new(*id),
                url: format!("https://files.pythonhosted.org/{id}"),
                declared_sha256: None,
                size: None,
            })
            .collect(),
        intrinsics: Intrinsics::default(),
        source: None,
        about: None,
    }
}

// ---------------------------------------------------------------------------
// The climb
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_first_rung_with_an_answer_ends_the_climb() {
    // The ordering *is* the policy: nothing downstream asks which rung produced a candidate, so a
    // later rung running at all would mean a cheaper answer could be overridden by a dearer one.
    let (rungs, counts) = ladder(vec![
        Rung::new("first", Answer::Silent(None)),
        Rung::new("second", Answer::Candidate),
        Rung::new("third", Answer::Candidate),
    ]);
    let out = climb(&rungs, &target(&["widget-1.2.3.tar.gz"])).await;

    assert!(out.candidate.is_some(), "the second rung answered");
    assert_eq!(
        counts[2].0.load(Ordering::SeqCst),
        0,
        "the third rung was asked although the second had already answered"
    );
}

#[tokio::test]
async fn a_rung_that_answers_is_never_asked_why_not() {
    // `why_not` is asked only after `infer` came back empty. A rung that produced a candidate pays
    // nothing, which is what makes it affordable to compute a careful reason in the rungs that do.
    let (rungs, counts) = ladder(vec![Rung::new("only", Answer::Candidate)]);
    let out = climb(&rungs, &target(&["widget-1.2.3.tar.gz"])).await;

    assert!(out.candidate.is_some());
    assert_eq!(counts[0].1.load(Ordering::SeqCst), 0, "why_not was asked of a rung that answered");
    assert!(out.declines.is_empty(), "a climb that ended in an answer recorded declines");
}

#[tokio::test]
async fn every_rung_that_declined_for_a_reason_is_in_the_record_in_order() {
    // The whole point of `Climb::declines`. Before it existed each of these reasons ended at a
    // `tracing::debug!` that is off by default, so a `no-strategy` verdict recorded no reason at
    // all and someone had to re-derive it from the registry by hand, days later.
    let (rungs, _) = ladder(vec![
        Rung::new("definitions", Answer::Silent(Some("nobody has written one down"))),
        Rung::new("ci", Answer::Silent(Some("the release job runs on a self-hosted runner"))),
        Rung::new("heuristic", Answer::Silent(Some("no repository is declared"))),
    ]);
    let out = climb(&rungs, &target(&["widget-1.2.3.tar.gz"])).await;

    assert!(out.candidate.is_none());
    let names: Vec<&str> = out.declines.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        ["definitions", "ci", "heuristic"],
        "the declines are the order the rungs were asked in"
    );
    assert!(out.declines[1].1.contains("self-hosted"), "{:?}", out.declines[1]);
}

#[tokio::test]
async fn a_rung_with_nothing_to_add_leaves_no_line() {
    // `None` from `why_not` is the honest answer for a heuristic asked about an ecosystem it does
    // not handle, and a record padded with "the npm rung is not the pypi rung" hides the one line
    // that explains the verdict.
    let (rungs, _) = ladder(vec![
        Rung::new("npm", Answer::Silent(None)),
        Rung::new("pypi", Answer::Silent(Some("the sdist has no pyproject.toml"))),
    ]);
    let out = climb(&rungs, &target(&["widget-1.2.3.tar.gz"])).await;

    assert_eq!(out.declines.len(), 1, "{:?}", out.declines);
    assert_eq!(out.declines[0].0, "pypi");
}

#[tokio::test]
async fn a_rung_that_breaks_is_written_down_and_the_next_one_still_runs() {
    // A rung that fails is not fatal — the next may still know — but "this rung broke" is exactly
    // the thing a `no-strategy` must not hide, so it is recorded as a decline with its error.
    let (rungs, counts) = ladder(vec![
        Rung::new("ci", Answer::Broken),
        Rung::new("heuristic", Answer::Candidate),
    ]);
    let out = climb(&rungs, &target(&["widget-1.2.3.tar.gz"])).await;

    assert!(out.candidate.is_some(), "the rung after the broken one was not asked");
    assert_eq!(counts[1].0.load(Ordering::SeqCst), 1);
    assert_eq!(out.declines.len(), 1);
    assert_eq!(out.declines[0].0, "ci");
    assert!(
        out.declines[0].1.starts_with("failed: "),
        "a broken rung must be distinguishable from one that declined on purpose: {:?}",
        out.declines[0]
    );
    assert!(out.declines[0].1.contains("packument"), "{:?}", out.declines[0]);
}

// ---------------------------------------------------------------------------
// Which file the run is about
// ---------------------------------------------------------------------------

#[test]
fn a_release_with_one_file_needs_no_choosing() {
    let t = target(&["widget-1.2.3.tar.gz"]);
    assert_eq!(t.sole_artifact().unwrap().id.as_str(), "widget-1.2.3.tar.gz");
    assert_eq!(t.preferred().unwrap().id.as_str(), "widget-1.2.3.tar.gz");
    assert_eq!(t.pick(None).unwrap().id.as_str(), "widget-1.2.3.tar.gz");
}

#[test]
fn the_pure_wheel_is_what_a_release_is_about() {
    // The only artifact whose contents do not depend on the machine that built it, and the one
    // almost everything installs.
    let t = target(&[
        "widget-1.2.3.tar.gz",
        "widget-1.2.3-py3-none-any.whl",
        "widget-1.2.3-cp39-cp39-manylinux_2_17_x86_64.whl",
    ]);
    assert!(t.sole_artifact().is_none(), "three files is not a sole artifact");
    assert_eq!(t.preferred().unwrap().id.as_str(), "widget-1.2.3-py3-none-any.whl");
}

#[test]
fn a_lone_sdist_is_chosen_when_no_wheel_is_pure() {
    // A native package publishes platform wheels built on a dozen machines. They do not reproduce
    // alike, and the sdist is the only thing left that does.
    let t = target(&[
        "widget-1.2.3.tar.gz",
        "widget-1.2.3-cp39-cp39-manylinux_2_17_x86_64.whl",
        "widget-1.2.3-cp310-cp310-manylinux_2_17_x86_64.whl",
    ]);
    assert_eq!(t.preferred().unwrap().id.as_str(), "widget-1.2.3.tar.gz");
}

#[test]
fn a_genuinely_ambiguous_release_stays_an_error() {
    // Two pure wheels and no sdist. Picking one would attach a verdict to whichever the registry
    // happened to list first, which is worse than refusing.
    let t = target(&["widget-1.2.3-py2-none-any.whl", "widget-1.2.3-py3-none-any.whl"]);
    assert!(t.preferred().is_none());
    let e = t.pick(None).unwrap_err();
    assert!(matches!(e, RegistryError::NoSuchArtifact { .. }));
}

#[test]
fn the_error_for_an_unknown_file_lists_the_ones_that_exist() {
    // The listing is the point: "no such artifact" against a release with twelve wheels sends
    // someone to a browser, and the same error with the filenames in it does not.
    let t = target(&[
        "widget-1.2.3.tar.gz",
        "widget-1.2.3-py3-none-any.whl",
        "widget-1.2.3-cp39-cp39-manylinux_2_17_x86_64.whl",
    ]);
    let msg = t.pick(Some("widget-1.2.3-cp38-cp38-win_amd64.whl")).unwrap_err().to_string();
    assert!(msg.contains("widget-1.2.3-cp38-cp38-win_amd64.whl"), "{msg}");
    for present in [
        "widget-1.2.3.tar.gz",
        "widget-1.2.3-py3-none-any.whl",
        "widget-1.2.3-cp39-cp39-manylinux_2_17_x86_64.whl",
    ] {
        assert!(msg.contains(present), "the message omits `{present}`: {msg}");
    }
}

#[test]
fn a_named_file_is_taken_over_the_obvious_one() {
    // `preferred()` would pick the pure wheel. A caller that named the sdist gets the sdist.
    let t = target(&["widget-1.2.3.tar.gz", "widget-1.2.3-py3-none-any.whl"]);
    assert_eq!(t.preferred().unwrap().id.as_str(), "widget-1.2.3-py3-none-any.whl");
    assert_eq!(t.pick(Some("widget-1.2.3.tar.gz")).unwrap().id.as_str(), "widget-1.2.3.tar.gz");
    assert!(t.artifact("widget-9.9.9.tar.gz").is_none());
}

// ---------------------------------------------------------------------------
// Whose fault it was, and whether to try again
// ---------------------------------------------------------------------------

fn http(status: u16) -> RegistryError {
    RegistryError::Http {
        ecosystem: "pypi".into(),
        url: "https://pypi.org/simple/widget/".into(),
        status,
    }
}

#[test]
fn a_registry_failure_is_upstreams_and_a_refusal_is_ours() {
    // The two denominators depend on this: "a package that did not reproduce" and "a build we
    // could not run" are different numbers, and `Fault` is what sorts a failure into one of them.
    for (e, want) in [
        (
            RegistryError::NoSuchPackage {
                ecosystem: "npm".into(),
                name: "widget".into(),
            },
            Fault::Upstream,
        ),
        (http(404), Fault::Upstream),
        (
            RegistryError::DigestMismatch {
                name: "widget".into(),
                artifact: "widget-1.2.3.tar.gz".into(),
                expected: "aa".into(),
                actual: "bb".into(),
            },
            Fault::Upstream,
        ),
        (
            // A repository that will not fetch is upstream's, the same as a registry that will
            // not answer.
            RegistryError::Source {
                repo: "https://github.com/example/widget".into(),
                detail: "connection reset".into(),
            },
            Fault::Upstream,
        ),
        (
            // A reference we declined is ours, and a policy rather than a bug.
            RegistryError::SourceRefused {
                repo: "file:///etc".into(),
                detail: "not a remote".into(),
            },
            Fault::Policy,
        ),
        (
            RegistryError::Unsupported {
                ecosystem: "maven".into(),
                supported: "npm, pypi".into(),
            },
            Fault::Policy,
        ),
        (
            RegistryError::Io(std::io::Error::other("disk full")),
            Fault::Infra,
        ),
    ] {
        assert_eq!(e.fault(), want, "`{e}` was attributed to the wrong side");
    }
}

#[test]
fn only_a_failure_that_could_go_differently_is_retried() {
    // The queue reads this. Retrying a fact burns a worker slot until the attempt budget runs out
    // and then records the same failure, so the distinction has to hold for every variant.
    let retry = [
        RegistryError::RateLimited {
            ecosystem: "npm".into(),
            retry_after_s: Some(30),
        },
        http(503),
        RegistryError::Source {
            repo: "https://github.com/example/widget".into(),
            detail: "connection reset".into(),
        },
        RegistryError::Io(std::io::Error::other("disk full")),
    ];
    for e in retry {
        assert!(e.is_retryable(), "`{e}` is transient and was not retried");
    }

    let facts = [
        http(404),
        RegistryError::NoSuchPackage {
            ecosystem: "npm".into(),
            name: "widget".into(),
        },
        RegistryError::DigestMismatch {
            name: "widget".into(),
            artifact: "widget-1.2.3.tar.gz".into(),
            expected: "aa".into(),
            actual: "bb".into(),
        },
        RegistryError::Malformed {
            ecosystem: "npm".into(),
            what: "the packument".into(),
            detail: "truncated".into(),
        },
        RegistryError::SourceRefused {
            repo: "file:///etc".into(),
            detail: "not a remote".into(),
        },
        RegistryError::Unsupported {
            ecosystem: "maven".into(),
            supported: "npm, pypi".into(),
        },
    ];
    for e in facts {
        assert!(!e.is_retryable(), "`{e}` cannot go differently and was retried anyway");
    }
}

#[test]
fn the_5xx_4xx_line_is_where_retrying_stops() {
    // The one boundary in the whole classification that is arithmetic rather than a variant, so it
    // is the one that can drift without anything failing to compile.
    assert!(!http(499).is_retryable());
    assert!(http(500).is_retryable());
}

#[test]
fn a_missing_version_suggests_the_recent_ones_not_all_of_them() {
    // A package with 800 versions produces an error nobody reads.
    let available: Vec<String> = (1..=800).map(|n| format!("0.0.{n}")).collect();
    let msg = RegistryError::NoSuchVersion {
        ecosystem: "pypi".into(),
        name: "widget".into(),
        version: "9.9.9".into(),
        available,
    }
    .to_string();

    assert!(msg.contains("0.0.800"), "the newest is missing: {msg}");
    assert!(msg.contains("0.0.796"), "five were promised: {msg}");
    assert!(!msg.contains("0.0.795"), "more than five were printed: {msg}");
    assert!(!msg.contains("0.0.1,"), "the whole list was printed: {msg}");
}

#[test]
fn a_package_whose_versions_are_unknown_gets_no_empty_suggestion() {
    let msg = RegistryError::NoSuchVersion {
        ecosystem: "pypi".into(),
        name: "widget".into(),
        version: "9.9.9".into(),
        available: Vec::new(),
    }
    .to_string();
    assert!(!msg.contains("Recent"), "an empty list produced a dangling `Recent:`: {msg}");
}

// ---------------------------------------------------------------------------
// The definitions rung
// ---------------------------------------------------------------------------

/// Write a `build.yaml` where the definitions rung looks for one.
fn definition(root: &std::path::Path, artifact: &str, body: &str) {
    let dir = root.join("pypi").join("widget").join("1.2.3").join(artifact);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("build.yaml"), body).unwrap();
}

#[tokio::test]
async fn a_checked_in_definition_is_believed_completely() {
    // A definition exists precisely where inference failed, so it is `Certain` by construction and
    // the rung sits above every heuristic.
    let tmp = tempfile::tempdir().unwrap();
    definition(tmp.path(), "widget-1.2.3.tar.gz", FLOW);

    let rung = DefinitionsInferrer::new(tmp.path());
    let out = rung.infer(&target(&["widget-1.2.3.tar.gz"])).await.unwrap();

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].derivation, Derivation::Definition);
    assert_eq!(out[0].confidence, Confidence::Certain);
    assert_eq!(out[0].discovery, SourceDiscovery::Definition);
    assert!(out[0].assumptions.is_empty(), "{:?}", out[0].assumptions);
}

#[tokio::test]
async fn a_target_nobody_wrote_a_definition_for_is_silent() {
    let tmp = tempfile::tempdir().unwrap();
    let rung = DefinitionsInferrer::new(tmp.path());
    assert!(
        rung.infer(&target(&["widget-1.2.3.tar.gz"])).await.unwrap().is_empty(),
        "an absent definition is not an error: most targets have none"
    );
}

#[tokio::test]
async fn a_definition_that_does_not_parse_is_an_error_not_a_fallthrough() {
    // The load-bearing half of this rung. Falling through would run a heuristic against a target
    // somebody had already established needs something else, and report the resulting divergence
    // as a fact about the package.
    let tmp = tempfile::tempdir().unwrap();
    definition(tmp.path(), "widget-1.2.3.tar.gz", "kind: flow\nlocation: [not, a, mapping]\n");

    let rung = DefinitionsInferrer::new(tmp.path());
    let e = rung.infer(&target(&["widget-1.2.3.tar.gz"])).await.unwrap_err();

    assert!(matches!(e, RegistryError::Malformed { .. }), "{e:?}");
    let msg = e.to_string();
    assert!(msg.contains("build.yaml"), "the message must name the file: {msg}");
}

#[tokio::test]
async fn a_custom_stabilizer_the_run_cannot_execute_is_surfaced_not_dropped() {
    // The definition says the comparison needs this. A run without it reports a divergence its
    // author already explained, so the gap travels with the candidate as an assumption.
    let tmp = tempfile::tempdir().unwrap();
    definition(
        tmp.path(),
        "widget-1.2.3.tar.gz",
        "custom_stabilizers:\n  \
         - reason: the tarball records the build host's timezone\n    \
           exclude_path:\n      paths: [build/stamp]\n\
         rebuild_location_hint:\n  \
         location:\n    repo: https://github.com/example/widget\n    \
         ref: ff8e7ba8b4122829cf66125ca8445cac7f073bce\n",
    );

    let rung = DefinitionsInferrer::new(tmp.path());
    let out = rung.infer(&target(&["widget-1.2.3.tar.gz"])).await.unwrap();

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].assumptions.len(), 1, "{:?}", out[0].assumptions);
    let a = &out[0].assumptions[0];
    assert!(a.contains("exclude_path"), "the assumption must name the operation: {a}");
    assert!(a.contains("timezone"), "the assumption must carry the author's reason: {a}");
    assert!(a.contains("not executed yet"), "{a}");
}

#[tokio::test]
async fn a_release_gets_one_candidate_per_artifact_that_has_a_definition() {
    // Definitions are per-artifact: the sdist and the wheel of one version are built differently
    // and a definition for one says nothing about the other.
    let tmp = tempfile::tempdir().unwrap();
    definition(tmp.path(), "widget-1.2.3.tar.gz", FLOW);

    let rung = DefinitionsInferrer::new(tmp.path());
    let out = rung
        .infer(&target(&["widget-1.2.3.tar.gz", "widget-1.2.3-py3-none-any.whl"]))
        .await
        .unwrap();

    assert_eq!(out.len(), 1, "the wheel has no definition and must not borrow the sdist's");
}

#[test]
fn the_definitions_rung_says_its_name() {
    assert_eq!(DefinitionsInferrer::new(".").name(), "definitions");
}
