//! What a strategy document is, and what happens when it is wrong.
//!
//! The error-message tests are not decoration. `docs/04` §2.2 argues that the quality of the
//! build-repair loop is bounded by the quality of these messages, so they are asserted rather
//! than left to whatever serde happens to say this release.

use trigon_strategy::{Location, StepBody, Strategy, from_yaml, to_yaml};

const FLOW: &str = r#"
schema: 1
kind: flow
location:
  repo: https://github.com/requests/toolbelt
  ref: b7d1a1fcdda9ebcd9afe5011690ab860fce780c2
src:
  - uses: git-checkout
  - runs: git checkout '{{ location.ref }}^' -- requests_toolbelt/adapters/appengine.py
deps:
  - uses: pypi/setup-venv
    with:
      python: "3.9"
      backend: setuptools==67.7.2
    needs: [ca-certificates]
build:
  - runs: python -m build --wheel -n
output_dir: dist
"#;

#[test]
fn a_flow_strategy_round_trips() {
    let s = from_yaml(FLOW).expect("parses");
    let Strategy::Flow(f) = &s else {
        panic!("expected a flow, got {s:?}")
    };
    assert_eq!(f.location.repo, "https://github.com/requests/toolbelt");
    assert_eq!(f.src.len(), 2);
    assert_eq!(f.output_dir.as_deref(), Some("dist"));
}

#[test]
fn steps_carry_their_shape() {
    let Strategy::Flow(f) = from_yaml(FLOW).unwrap() else {
        unreachable!()
    };
    match &f.src[0].body {
        StepBody::Uses { tool, with } => {
            assert_eq!(tool, "git-checkout");
            assert!(with.is_empty());
        }
        other => panic!("expected a tool step, got {other:?}"),
    }
    match &f.deps[0].body {
        StepBody::Uses { tool, with } => {
            assert_eq!(tool, "pypi/setup-venv");
            assert_eq!(with.get("python").map(String::as_str), Some("3.9"));
        }
        other => panic!("expected a tool step, got {other:?}"),
    }
    assert_eq!(f.deps[0].needs, vec!["ca-certificates".to_string()]);
}

#[test]
fn a_missing_kind_says_which_kinds_exist() {
    let e = from_yaml("location:\n  repo: x\n  ref: y\n").unwrap_err();
    let m = e.to_string();
    assert!(m.contains("missing `kind`"), "{m}");
    assert!(m.contains("flow"), "the message must list the kinds: {m}");
}

#[test]
fn an_ecosystem_variant_is_rejected_with_the_reason() {
    // The prior art's thirteen strategy types are flows here. Someone porting a definition needs
    // to be told that rather than left with "unknown variant".
    let e = from_yaml("kind: pypi_pure_wheel_build\n").unwrap_err();
    let m = e.to_string();
    assert!(m.contains("pypi_pure_wheel_build"), "{m}");
    assert!(m.contains("named tool"), "{m}");
}

#[test]
fn a_bad_field_reports_the_path_to_it() {
    let src = r#"
kind: flow
location: { repo: x, ref: y }
deps:
  - uses: pypi/setup-venv
    with:
      python: 3
"#;
    let e = from_yaml(src).unwrap_err();
    let m = e.to_string();
    // The path is what a repair loop acts on. Without it this reads "invalid type: integer".
    assert!(m.contains("deps"), "the path must name the phase: {m}");
    assert!(m.contains("python"), "and the field: {m}");
}

#[test]
fn a_step_with_neither_runs_nor_uses_says_so() {
    let src = "kind: flow\nlocation: { repo: x, ref: y }\nbuild:\n  - needs: [git]\n";
    let m = from_yaml(src).unwrap_err().to_string();
    assert!(m.contains("exactly one of `runs` or `uses`"), "{m}");
    assert!(m.contains("build"), "the path must locate the step: {m}");
}

#[test]
fn a_step_with_both_says_so() {
    let src = "kind: flow\nlocation: { repo: x, ref: y }\nbuild:\n  - runs: make\n    uses: git-checkout\n";
    let m = from_yaml(src).unwrap_err().to_string();
    assert!(m.contains("not both"), "{m}");
}

#[test]
fn with_on_a_runs_step_is_a_mistake_worth_naming() {
    let src =
        "kind: flow\nlocation: { repo: x, ref: y }\nbuild:\n  - runs: make\n    with: { x: y }\n";
    let m = from_yaml(src).unwrap_err().to_string();
    assert!(m.contains("`with` belongs to `uses`"), "{m}");
}

#[test]
fn an_unknown_field_is_refused_rather_than_ignored() {
    // A typo'd key that parses to nothing is how a strategy silently stops doing what it says.
    let src = "kind: flow\nlocation: { repo: x, ref: y }\noutput_dirs: dist\n";
    let m = from_yaml(src).unwrap_err().to_string();
    assert!(m.contains("output_dirs"), "{m}");
}

#[test]
fn a_future_schema_is_refused_rather_than_guessed_at() {
    let m = from_yaml("schema: 99\nkind: flow\nlocation: { repo: x, ref: y }\n")
        .unwrap_err()
        .to_string();
    assert!(m.contains("newer than this build"), "{m}");
    assert!(m.contains("Upgrade trigon"), "{m}");
}

#[test]
fn a_location_hint_cannot_be_executed() {
    let s = from_yaml("kind: location_hint\nlocation: { repo: r, ref: c }\n").unwrap();
    assert!(!s.is_executable());
    assert_eq!(
        s.location(),
        Some(&Location {
            repo: "r".into(),
            git_ref: "c".into(),
            subdir: None
        })
    );
}

#[test]
fn a_prebuilt_strategy_must_name_its_approver() {
    let m = from_yaml("kind: prebuilt\nurl: https://x/y\nsha256: ab\nreason: because\n")
        .unwrap_err()
        .to_string();
    assert!(m.contains("approved_by"), "{m}");
}

#[test]
fn serializing_puts_the_schema_first() {
    let s = from_yaml(FLOW).unwrap();
    let out = to_yaml(&s).unwrap();
    assert!(out.starts_with("schema: 1\n"), "{out}");
    assert_eq!(from_yaml(&out).unwrap(), s, "and it round-trips");
}

#[test]
fn the_messages_are_the_ones_a_repair_loop_gets() {
    // Printed, not just asserted on. If these ever degrade to "data did not match any variant",
    // the argument for two-pass parsing has quietly stopped being true.
    for (label, src) in [
        (
            "wrong type, nested",
            "kind: flow\nlocation: { repo: x, ref: y }\ndeps:\n  - uses: t\n    with:\n      python: 3\n",
        ),
        (
            "empty step",
            "kind: flow\nlocation: { repo: x, ref: y }\nbuild:\n  - needs: [git]\n",
        ),
        (
            "typo'd key",
            "kind: flow\nlocation: { repo: x, ref: y }\noutput_dirs: dist\n",
        ),
        (
            "missing required field",
            "kind: flow\nlocation: { repo: x }\n",
        ),
    ] {
        let m = from_yaml(src).unwrap_err().to_string();
        println!("{label:24} {m}");
        assert!(
            !m.contains("did not match any variant"),
            "{label}: the message a repair loop cannot act on: {m}"
        );
    }
}
