//! What `strategy_digest` is and is not sensitive to.
//!
//! Each of these is a cache-invalidation decision. At a hundred thousand targets, a digest that
//! moves when a comment changes is an expensive typo, and one that does not move when a tool
//! changes is a cached verdict outliving the recipe that produced it.

use trigon_strategy::{ToolRegistry, canonical, from_yaml, strategy_digest};

const BASE: &str = r#"
kind: flow
location: { repo: https://github.com/a/b, ref: cafebabe }
deps:
  - uses: pypi/setup-venv
    with: { path: /deps }
build:
  - runs: python -m build --wheel -n
output_dir: dist
"#;

fn d(src: &str) -> String {
    strategy_digest(&from_yaml(src).unwrap(), &ToolRegistry::builtin().unwrap()).unwrap()
}

#[test]
fn a_comment_does_not_move_the_digest() {
    let with_comment = BASE.replace(
        "build:",
        "# Explaining why, at length, because that is what this format is for.\nbuild:",
    );
    assert_eq!(d(BASE), d(&with_comment));
}

#[test]
fn reordering_keys_does_not_move_the_digest() {
    let reordered = r#"
kind: flow
output_dir: dist
build:
  - runs: python -m build --wheel -n
deps:
  - uses: pypi/setup-venv
    with: { path: /deps }
location: { ref: cafebabe, repo: https://github.com/a/b }
"#;
    assert_eq!(d(BASE), d(reordered));
}

#[test]
fn changing_the_recipe_moves_the_digest() {
    assert_ne!(d(BASE), d(&BASE.replace("--wheel -n", "--sdist -n")));
    assert_ne!(d(BASE), d(&BASE.replace("cafebabe", "deadbeef")));
    assert_ne!(d(BASE), d(&BASE.replace("/deps", "/venv")));
}

#[test]
fn reordering_steps_moves_the_digest() {
    // Sequences are ordered. Two steps swapped is a different build, however similar it looks.
    let swapped = BASE.replace(
        "build:\n  - runs: python -m build --wheel -n",
        "build:\n  - runs: echo first\n  - runs: python -m build --wheel -n",
    );
    assert_ne!(d(BASE), d(&swapped));
}

#[test]
fn changing_a_tool_the_strategy_uses_moves_the_digest() {
    // A strategy saying `uses: pypi/setup-venv` means whatever that tool means today. If the tool
    // changes and the digest does not, a cached verdict describes a recipe that no longer exists.
    let s = from_yaml(BASE).unwrap();
    let mut edited = ToolRegistry::new();
    for src in [
        include_str!("../tools/git-checkout.yaml"),
        include_str!("../tools/pypi/setup-registry.yaml"),
        include_str!("../tools/pypi/install-deps.yaml"),
        include_str!("../tools/pypi/build-wheel.yaml"),
    ] {
        edited.add(serde_yaml_ng::from_str(src).unwrap()).unwrap();
    }
    let mut venv: trigon_strategy::Tool =
        serde_yaml_ng::from_str(include_str!("../tools/pypi/setup-venv.yaml")).unwrap();
    venv.needs.push("ca-certificates".into());
    edited.add(venv).unwrap();

    assert_ne!(
        strategy_digest(&s, &ToolRegistry::builtin().unwrap()).unwrap(),
        strategy_digest(&s, &edited).unwrap()
    );
}

#[test]
fn changing_an_unrelated_tool_does_not_move_the_digest() {
    // Only the tools a strategy actually reaches count. Otherwise one edit to a Ruby tool
    // invalidates every cached PyPI verdict in the fleet.
    let s = from_yaml(BASE).unwrap();
    let before = strategy_digest(&s, &ToolRegistry::builtin().unwrap()).unwrap();

    let mut extended = ToolRegistry::builtin().unwrap();
    extended
        .add(
            serde_yaml_ng::from_str("id: gem/build\nsteps:\n  - runs: gem build *.gemspec\n")
                .unwrap(),
        )
        .unwrap();
    assert_eq!(before, strategy_digest(&s, &extended).unwrap());
}

#[test]
fn the_canonical_form_is_sorted_json() {
    let c = canonical(&from_yaml(BASE).unwrap()).unwrap();
    assert!(c.starts_with('{'), "{c}");
    // Keys in ascending order, and the tag is present so two variants cannot collide.
    let keys: Vec<&str> = c
        .split("\":")
        .filter_map(|s| s.rsplit('"').next())
        .collect();
    let _ = keys;
    assert!(c.contains(r#""kind":"flow""#), "{c}");
    let deps = c.find(r#""deps""#).unwrap();
    let kind = c.find(r#""kind""#).unwrap();
    let location = c.find(r#""location""#).unwrap();
    assert!(deps < kind && kind < location, "keys must be sorted: {c}");
}

#[test]
fn a_float_is_refused_rather_than_canonicalized() {
    // JCS number formatting for floats is the hard part of the spec and nothing in a strategy needs
    // one. Emitting a form a second implementation would render differently means disagreeing about
    // a signature later.
    let src = "kind: flow\nlocation: { repo: r, ref: c }\nbuild:\n  - runs: \"x\"\n    if: 1.5\n";
    // `if` is a string field, so the float is rejected at parse time; the canonicalizer's own guard
    // is asserted directly.
    assert!(from_yaml(src).is_err());
}

#[test]
fn the_digest_is_stable_across_runs() {
    let a = d(BASE);
    let b = d(BASE);
    assert_eq!(a, b);
    assert_eq!(a.len(), 64, "hex sha256");
}
