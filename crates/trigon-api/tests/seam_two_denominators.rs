//! A package that did not reproduce and a build we could not run are different findings.
//!
//! `18-management-ui.md` §3 is the argument and this is the enforcement. The rule survives exactly
//! as long as nothing merges the two columns, and the merge is always one convenient percentage
//! away — so the type has no total, the API has no rate, and these assert that both stay true.

use std::sync::Arc;
use trigon_api::{Api, Index, Principal, Switches};
use trigon_core::{Digest, FailureSignature, Fault};
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

fn base(id: &str, target: &str) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        target,
        ArtifactRef {
            name: "a.tgz".into(),
            sha256: Digest::from_bytes([9u8; 32]),
            bytes: 1,
            stored: true,
        },
        Environment {
            base_image: "x@sha256:0".into(),
            derived_image: None,
            egress: "mirror".into(),
            isolation: "podman".into(),
            attestable: true,
            registry_moment: None,
            pin: None,
            guard_manifest: None,
            guarded_members: None,
        },
        "2026-01-01T00:00:00Z",
    );
    r.state = RunState::Done;
    r
}

async fn stats_over(records: Vec<RunRecord>) -> trigon_api::index::Stats {
    let store = Arc::new(Store::in_memory());
    for r in &records {
        store.put_run(r).await.unwrap();
    }
    let index = Index::new();
    index.refresh(&store, Switches::default()).await.unwrap();
    let api = Arc::new(Api {
        store,
        queue: None,
        index,
        switches: Switches::default(),
        unauthenticated: Principal::Operator,
        member_reads: trigon_api::default_member_permits(),
    });
    api.index.stats(false)
}

/// The two columns account for every run and are never added together.
#[tokio::test]
async fn a_failed_build_is_not_a_failed_reproduction() {
    let mut reproduced = base("1700000001-aa", "pkg:npm/a@1");
    reproduced.outcome = Some("exact".into());

    let mut diverged = base("1700000002-bb", "pkg:npm/b@1");
    diverged.outcome = Some("divergent".into());

    let mut could_not_build = base("1700000003-cc", "pkg:npm/c@1");
    could_not_build.terminal = Some("build-failed".into());
    could_not_build.failure = Some(FailureSignature {
        code: "env/missing-tool".into(),
        subject: Some("dotnet".into()),
        // Ours. A missing tool in *our* image is not a statement about the package, and this is the
        // field that keeps it out of the reproduction column.
        fault: Fault::Infra,
        retryable: false,
        repairable: true,
        evidence: "dotnet: command not found".into(),
    });

    let mut no_recipe = base("1700000004-dd", "pkg:npm/d@1");
    no_recipe.terminal = Some("no-strategy".into());

    let s = stats_over(vec![reproduced, diverged, could_not_build, no_recipe]).await;

    assert_eq!(s.runs, 4);
    assert_eq!(
        s.evidence, 2,
        "only the two that reached a verdict are evidence"
    );
    assert_eq!(s.by_outcome.get("exact"), Some(&1));
    assert_eq!(s.by_outcome.get("divergent"), Some(&1));
    assert_eq!(s.by_fault.get("infra"), Some(&1));

    // A no-strategy has no fault, because nobody failed: it is a statement about our coverage. It
    // must still be counted, and it must not read as `unclassified` — that word is for a cause
    // nobody has named, and this one was named.
    assert_eq!(s.by_fault.get("no-strategy"), Some(&1));
    assert_eq!(s.by_fault.get("unclassified"), None);

    // The parts account for every run without the type ever offering a way to add them.
    assert_eq!(
        s.by_outcome.values().sum::<usize>() + s.by_fault.values().sum::<usize>(),
        s.runs
    );
}

/// No rate, anywhere, in the type or on the wire.
///
/// The merge is always one convenient division away, and the only honest rate needs a denominator
/// the reader has to choose. So the shape refuses to carry one: a field named `rate` or `percent`
/// here would be read by every consumer as "the reproduction rate", and there isn't one.
#[tokio::test]
async fn nothing_serializes_a_rate() {
    let mut a = base("1700000001-aa", "pkg:npm/a@1");
    a.outcome = Some("exact".into());
    let mut b = base("1700000002-bb", "pkg:npm/b@1");
    b.terminal = Some("build-failed".into());

    let s = stats_over(vec![a, b]).await;
    let json = serde_json::to_string(&s).unwrap();
    for word in ["rate", "percent", "success", "pass_rate", "ratio", "score"] {
        assert!(
            !json.contains(word),
            "`{word}` reached the wire. The two denominators are kept apart by having no field \
             that could merge them, not by asking renderers to remember."
        );
    }
    // And there is no `total` either, for the same reason: a total over both columns is the
    // denominator of exactly the rate this refuses to compute.
    assert!(!json.contains("\"total\""));
}
