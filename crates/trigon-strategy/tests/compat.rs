//! Lowering one of `oss-rebuild`'s `build.yaml` documents, without their checkout.
//!
//! `tests/definitions.rs` runs the real corpus through this and is the better test — 53 documents
//! written for packages where inference failed. It also skips itself when the checkout is absent,
//! which is most machines and, unless someone has arranged otherwise, CI. So the rules below were
//! being asserted by a suite that mostly did not run.
//!
//! Every one of them is about the same hazard, which is why `import` refuses so much: a shape
//! lowered wrongly builds something other than what the definition asked for and still reports a
//! verdict under the definition's name.

use trigon_strategy::{Location, StepBody, Strategy, import};

/// The `with` map of the nth step of a section, or a panic naming what was there instead.
fn with_of(
    steps: &[trigon_strategy::Step],
    n: usize,
) -> &std::collections::BTreeMap<String, String> {
    match &steps[n].body {
        StepBody::Uses { with, .. } => with,
        other => panic!("expected a tool step, got {other:?}"),
    }
}

fn tool_of(steps: &[trigon_strategy::Step], n: usize) -> &str {
    match &steps[n].body {
        StepBody::Uses { tool, .. } => tool,
        other => panic!("expected a tool step, got {other:?}"),
    }
}

fn flow(src: &str) -> trigon_strategy::FlowStrategy {
    match import(src).expect("lowers").strategy {
        Strategy::Flow(f) => f,
        other => panic!("expected a flow, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Which key is the strategy
// ---------------------------------------------------------------------------

#[test]
fn a_document_with_two_strategy_keys_is_refused() {
    // Their format sets exactly one. Picking either would build one of the two things the document
    // describes and report it under a name that meant both.
    let e = import("npm_pack_build:\n  location:\n    repo: x\nflow:\n  build: []\n").unwrap_err();
    let m = e.to_string();
    assert!(m.contains("two strategy keys"), "{m}");
    assert!(
        m.contains("npm_pack_build") && m.contains("flow"),
        "both keys must be named: {m}"
    );
}

#[test]
fn a_document_with_no_strategy_key_says_what_it_expected() {
    let e = import("custom_stabilizers: []\n").unwrap_err();
    let m = e.to_string();
    assert!(m.contains("no strategy key"), "{m}");
    assert!(
        m.contains("flow"),
        "the message must list what it takes: {m}"
    );
}

#[test]
fn a_document_that_is_not_a_mapping_is_refused() {
    let e = import("- just\n- a list\n").unwrap_err();
    assert!(e.to_string().contains("mapping"), "{e}");
}

#[test]
fn a_shape_we_have_not_ported_names_the_tools_it_would_need() {
    // Refusing rather than guessing, and the message has a job: it tells the reader which
    // ecosystem's tools are missing, so the refusal is a piece of work rather than a dead end.
    for (kind, ecosystem) in [
        ("maven_maven_build", "maven"),
        ("cratesio_cargo_package", "crates.io"),
        ("gem_build", "rubygems"),
        ("rubygems_build", "rubygems"),
        ("something_else", "required"),
    ] {
        let e = import(&format!("{kind}:\n  location:\n    repo: x\n")).unwrap_err();
        let m = e.to_string();
        assert!(m.contains(kind), "{m}");
        assert!(
            m.contains(ecosystem),
            "`{kind}` should name `{ecosystem}`: {m}"
        );
    }
}

// ---------------------------------------------------------------------------
// The location, and the empty subdir that would render `cd `
// ---------------------------------------------------------------------------

#[test]
fn a_location_with_no_repo_is_refused() {
    let e = import("flow:\n  build: []\n").unwrap_err();
    assert!(e.to_string().contains("no repo"), "{e}");
}

#[test]
fn the_repository_root_is_no_subdir_rather_than_an_empty_one() {
    // They call it `dir`; we call it `subdir`. Both `.` and `""` mean the root, and carrying
    // either through as `Some` would render `cd ` or `cd .` into a build script.
    for dir in ["\"\"", "\".\""] {
        let f = flow(&format!(
            "flow:\n  location:\n    repo: https://github.com/a/b\n    ref: c\n    dir: {dir}\n  build: []\n"
        ));
        assert_eq!(
            f.location.subdir, None,
            "dir: {dir} became {:?}",
            f.location.subdir
        );
    }

    let f = flow(
        "flow:\n  location:\n    repo: https://github.com/a/b\n    ref: c\n    dir: packages/core\n  build: []\n",
    );
    assert_eq!(f.location.subdir.as_deref(), Some("packages/core"));
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

#[test]
fn a_step_that_is_both_a_command_and_a_tool_is_refused() {
    let e = import(
        "flow:\n  location:\n    repo: r\n  build:\n    - runs: make\n      uses: git-checkout\n",
    )
    .unwrap_err();
    assert!(e.to_string().contains("both"), "{e}");
}

#[test]
fn a_step_that_is_neither_is_refused() {
    let e = import("flow:\n  location:\n    repo: r\n  build:\n    - needs: [git]\n").unwrap_err();
    assert!(e.to_string().contains("neither"), "{e}");
}

#[test]
fn a_tool_parameter_arrives_in_our_spelling() {
    // Their parameters are camelCase and ours are snake_case. The conversion is mechanical rather
    // than a lookup table, so a parameter we have not seen before still arrives with the right
    // name instead of being silently dropped on the floor.
    let f = flow(
        "flow:\n  location:\n    repo: r\n  deps:\n    - uses: pypi/setup-venv\n      with:\n        \
         pythonVersion: \"3.9\"\n        someParameterNobodyHasSeen: yes-really\n        plain: v\n",
    );
    let with = with_of(&f.deps, 0);
    assert_eq!(
        with.get("python_version").map(String::as_str),
        Some("3.9"),
        "{with:?}"
    );
    assert_eq!(
        with.get("some_parameter_nobody_has_seen")
            .map(String::as_str),
        Some("yes-really"),
        "an unknown parameter must still arrive: {with:?}"
    );
    assert_eq!(with.get("plain").map(String::as_str), Some("v"), "{with:?}");
}

#[test]
fn a_steps_needs_list_survives_the_lowering() {
    let f = flow(
        "flow:\n  location:\n    repo: r\n  deps:\n    - uses: pypi/setup-venv\n      needs: [ca-certificates, git]\n",
    );
    assert_eq!(f.deps[0].needs, ["ca-certificates", "git"]);
}

// ---------------------------------------------------------------------------
// The pre-canned shapes
// ---------------------------------------------------------------------------

#[test]
fn a_pure_wheel_build_writes_its_dist_beside_the_project() {
    // `dist` is relative to the directory the build ran in, so a definition with a subdir has to
    // get `<subdir>/dist` or the comparison looks for the wheel where nothing wrote one.
    let root = flow("pypi_pure_wheel_build:\n  location:\n    repo: r\n");
    assert_eq!(root.output_dir.as_deref(), Some("dist"));

    let sub = flow("pypi_pure_wheel_build:\n  location:\n    repo: r\n    dir: src/lib/\n");
    assert_eq!(
        sub.output_dir.as_deref(),
        Some("src/lib/dist"),
        "a trailing slash must not double"
    );
}

#[test]
fn a_pure_wheel_builds_requirements_list_reaches_the_tool_as_json() {
    let f = flow(
        "pypi_pure_wheel_build:\n  location:\n    repo: r\n  requirements:\n    - setuptools==67.7.2\n    - wheel\n",
    );
    let with = with_of(&f.deps, 0);
    assert_eq!(
        with.get("requirements").map(String::as_str),
        Some(r#"["setuptools==67.7.2","wheel"]"#),
        "{with:?}"
    );

    // Absent is an empty list, not a missing key: the tool takes a list either way.
    let none = flow("pypi_pure_wheel_build:\n  location:\n    repo: r\n");
    assert_eq!(
        with_of(&none.deps, 0)
            .get("requirements")
            .map(String::as_str),
        Some("[]")
    );
}

#[test]
fn an_npm_build_names_the_tarball_not_the_working_tree() {
    // `npm pack` writes a tarball. Naming the directory would compare the whole working tree
    // against a published `.tgz`, which diverges on everything.
    let f = flow(
        "npm_pack_build:\n  location:\n    repo: r\n  node_version: \"18.17.0\"\n  npm_version: \"9.6.7\"\n",
    );
    assert_eq!(f.output_dir, None);
    assert_eq!(f.output_path.as_deref(), Some("*.tgz"));

    let sub = flow(
        "npm_pack_build:\n  location:\n    repo: r\n    dir: packages/core/\n  node_version: \"18.17.0\"\n  npm_version: \"9.6.7\"\n",
    );
    assert_eq!(sub.output_path.as_deref(), Some("packages/core/*.tgz"));
}

#[test]
fn a_toolchain_the_definition_did_not_state_is_refused_rather_than_defaulted() {
    // Guessing one would pin a toolchain the definition did not ask for, which is a different
    // build reported under this definition's name.
    for missing in ["node_version", "npm_version"] {
        let mut doc = String::from("npm_pack_build:\n  location:\n    repo: r\n");
        for k in ["node_version", "npm_version"] {
            if k != missing {
                doc.push_str(&format!("  {k}: \"1.2.3\"\n"));
            }
        }
        let e = import(&doc).unwrap_err();
        let m = e.to_string();
        assert!(m.contains(missing), "{m}");
        assert!(m.contains("pin a toolchain"), "{m}");
    }

    // Present but empty is the same as absent: an empty version pins nothing.
    let e = import(
        "npm_pack_build:\n  location:\n    repo: r\n  node_version: \"\"\n  npm_version: \"9.6.7\"\n",
    )
    .unwrap_err();
    assert!(e.to_string().contains("node_version"), "{e}");
}

#[test]
fn an_absent_boolean_is_not_carried_through_as_the_string_false() {
    // Their booleans are optional and default false, and absent and false are the same build. A
    // literal "false" in the map would change the rendered command and the strategy digest with
    // it, so two documents that describe one build would hash differently.
    let bare = flow(
        "npm_custom_build:\n  location:\n    repo: r\n  node_version: \"18.17.0\"\n  npm_version: \"9.6.7\"\n  command: build\n",
    );
    let with = with_of(&bare.build, 0);
    assert!(!with.contains_key("keep_root"), "{with:?}");
    assert!(!with.contains_key("remove_deps"), "{with:?}");

    let set = flow(
        "npm_custom_build:\n  location:\n    repo: r\n  node_version: \"18.17.0\"\n  npm_version: \"9.6.7\"\n  \
         keep_root: true\n  prepack_remove_deps: true\n",
    );
    let with = with_of(&set.build, 0);
    assert_eq!(
        with.get("keep_root").map(String::as_str),
        Some("true"),
        "{with:?}"
    );
    assert_eq!(
        with.get("remove_deps").map(String::as_str),
        Some("true"),
        "their `prepack_remove_deps` is our `remove_deps`: {with:?}"
    );

    // And an explicit `false` is still absent, because it is still the same build.
    let off = flow(
        "npm_custom_build:\n  location:\n    repo: r\n  node_version: \"18.17.0\"\n  npm_version: \"9.6.7\"\n  keep_root: false\n",
    );
    assert!(!with_of(&off.build, 0).contains_key("keep_root"));
}

#[test]
fn a_registry_moment_reaches_the_dependency_step() {
    // What the definition pinned the registry to. Dropping it would resolve today's dependencies
    // into a build the definition described against an older index.
    let f = flow(
        "npm_pack_build:\n  location:\n    repo: r\n  node_version: \"18.17.0\"\n  npm_version: \"9.6.7\"\n  \
         registry_time: \"2023-06-01T00:00:00Z\"\n",
    );
    assert_eq!(
        with_of(&f.deps, 0).get("registry_time").map(String::as_str),
        Some("2023-06-01T00:00:00Z")
    );
    assert_eq!(tool_of(&f.deps, 0), "npm/deps/custom");
    assert_eq!(tool_of(&f.src, 0), "git-checkout");
}

#[test]
fn a_location_hint_lowers_to_a_hint_and_says_where_it_came_from() {
    let imported = import(
        "rebuild_location_hint:\n  location:\n    repo: https://github.com/a/b\n    ref: deadbeef\n",
    )
    .expect("lowers");
    match imported.strategy {
        Strategy::LocationHint(h) => {
            assert_eq!(
                h.location,
                Location {
                    repo: "https://github.com/a/b".into(),
                    git_ref: "deadbeef".into(),
                    subdir: None
                }
            );
            assert!(
                h.note.unwrap_or_default().contains("oss-rebuild"),
                "the provenance is the point"
            );
        }
        other => panic!("expected a location hint, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Custom stabilizers
// ---------------------------------------------------------------------------

#[test]
fn a_custom_stabilizer_without_a_reason_is_refused() {
    // Both formats require one. A stabilizer is a deliberate blindness in the comparison, and one
    // with no stated reason is not reviewable by anybody.
    let e = import(
        "custom_stabilizers:\n  - exclude_path:\n      paths: [a]\nrebuild_location_hint:\n  location:\n    repo: r\n",
    )
    .unwrap_err();
    assert!(e.to_string().contains("reason"), "{e}");
    assert!(e.to_string().contains("reviewable"), "{e}");
}

#[test]
fn a_custom_stabilizer_carries_its_kind_reason_and_parameters() {
    let imported = import(
        "custom_stabilizers:\n  - reason: |\n      the tarball records the build host's timezone\n    \
         exclude_path:\n      paths: [build/stamp]\nrebuild_location_hint:\n  location:\n    repo: r\n",
    )
    .expect("lowers");
    assert_eq!(imported.custom_stabilizers.len(), 1);
    let cs = &imported.custom_stabilizers[0];
    assert_eq!(cs.kind, "exclude_path");
    assert!(cs.reason.contains("timezone"), "{}", cs.reason);
    assert!(cs.config.contains_key("paths"), "{:?}", cs.config);
}

#[test]
fn a_document_with_no_custom_stabilizers_carries_none() {
    let imported = import("rebuild_location_hint:\n  location:\n    repo: r\n").expect("lowers");
    assert!(imported.custom_stabilizers.is_empty());
}

#[test]
fn a_registry_moment_the_definition_states_reaches_the_deps_phase_in_every_shape() {
    // Dropping a stated moment lowers a pinned definition into one that resolves against today's
    // index: a different build, reported under the definition's name.
    const T: &str = "2023-05-01T04:11:28Z";
    let wheel = flow(&format!(
        "pypi_pure_wheel_build:\n  location:\n    repo: r\n  registry_time: \"{T}\"\n"
    ));
    let custom = flow(&format!(
        "npm_custom_build:\n  location:\n    repo: r\n  node_version: \"18.17.0\"\n  \
         npm_version: \"9.6.7\"\n  registry_time: \"{T}\"\n  command: build\n"
    ));
    let pack = flow(&format!(
        "npm_pack_build:\n  location:\n    repo: r\n  node_version: \"18.17.0\"\n  \
         npm_version: \"9.6.7\"\n  registry_time: \"{T}\"\n  version_override: 1.2.3-fixed\n"
    ));
    for (name, f) in [("wheel", &wheel), ("custom", &custom), ("pack", &pack)] {
        assert_eq!(
            with_of(&f.deps, 0).get("registry_time").map(String::as_str),
            Some(T),
            "{name}"
        );
    }
    // The version the definition overrides to is the one the pack step writes.
    assert_eq!(tool_of(&pack.build, 0), "npm/build/pack");
    assert_eq!(
        with_of(&pack.build, 0)
            .get("version_override")
            .map(String::as_str),
        Some("1.2.3-fixed")
    );
}
