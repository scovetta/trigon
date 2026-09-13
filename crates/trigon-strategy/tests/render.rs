//! Rendering a strategy to instructions, and the four settings that stop it going wrong quietly.

use std::collections::BTreeMap;

use trigon_strategy::{Context, EnvCtx, LocationCtx, TargetCtx, ToolRegistry, from_yaml, render};

fn cx() -> Context {
    Context {
        location: LocationCtx {
            repo: "https://github.com/requests/toolbelt".into(),
            git_ref: "b7d1a1fcdda9ebcd9afe5011690ab860fce780c2".into(),
            subdir: String::new(),
        },
        target: TargetCtx {
            ecosystem: "pypi".into(),
            name: "requests-toolbelt".into(),
            version: "1.0.0".into(),
            artifact: "requests_toolbelt-1.0.0-py2.py3-none-any.whl".into(),
        },
        env: EnvCtx {
            registry_moment: "2023-05-01T04:11:28Z".into(),
            arch: "x86_64".into(),
            platform: "linux".into(),
            has_repo: false,
            timewarp_base: "timewarp".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The requests-toolbelt override, in our schema. The comment is the reason the format exists.
const TOOLBELT: &str = r#"
kind: flow
location:
  repo: https://github.com/requests/toolbelt
  ref: b7d1a1fcdda9ebcd9afe5011690ab860fce780c2
src:
  - uses: git-checkout
  # The 1.0.0 tag does not contain requests_toolbelt/adapters/appengine.py: it was removed two
  # commits earlier. The wheel on PyPI has it, because it was built from a working tree that still
  # did. Restore it from the parent of the deletion commit.
  - runs: git checkout 'da0306dd4f84cdcad6b0e694d674b9d9c9479c61^' -- requests_toolbelt/adapters/appengine.py
deps:
  - uses: pypi/deps/basic
    with:
      venv: /deps
      registry_time: "2023-05-01T04:11:28Z"
      requirements: '["wheel==0.40.0", "setuptools==67.7.2"]'
build:
  - uses: pypi/build/wheel
    with:
      locator: /deps/bin/
output_dir: dist
"#;

#[test]
fn a_real_override_renders_to_a_runnable_script() {
    let s = from_yaml(TOOLBELT).unwrap();
    let tools = ToolRegistry::builtin().unwrap();
    let i = render(&s, &cx(), &tools).unwrap();

    println!(
        "--- source ---\n{}\n--- deps ---\n{}\n--- build ---\n{}",
        i.source, i.deps, i.build
    );

    assert!(
        i.source
            .contains("git clone https://github.com/requests/toolbelt .")
    );
    assert!(
        i.source
            .contains("git checkout --force 'b7d1a1fcdda9ebcd9afe5011690ab860fce780c2'")
    );
    assert!(i.source.contains("adapters/appengine.py"));

    // The composite tool expanded through three levels.
    assert!(i.deps.contains("python3 -m venv /deps"), "{}", i.deps);
    assert!(i.deps.contains("/deps/bin/pip install build"), "{}", i.deps);
    assert!(
        i.deps
            .contains("index-url = http://pypi:2023-05-01T04:11:28Z@timewarp/simple"),
        "the mirror has to carry the moment: {}",
        i.deps
    );
    // Without this pip warns once about an untrusted plain-HTTP index and then resolves as though
    // none were configured — so the moment above would be carried and ignored.
    assert!(
        i.deps.contains("trusted-host = timewarp"),
        "the index has to be trusted or the pin is silently dropped: {}",
        i.deps
    );
    assert!(
        i.deps.contains("/deps/bin/pip install 'wheel==0.40.0'"),
        "{}",
        i.deps
    );
    assert!(
        i.deps
            .contains("/deps/bin/pip install 'setuptools==67.7.2'"),
        "{}",
        i.deps
    );

    assert!(
        i.build.contains("/deps/bin/python3 -m build --wheel -n"),
        "{}",
        i.build
    );
    assert_eq!(i.output_path, "dist/*");

    // System dependencies are hoisted out of the steps that declared them.
    assert!(i.requires.system_deps.contains("git"));
    assert!(i.requires.system_deps.contains("python3"));
    // And only from the steps that actually run. No python_version here, so the venv comes from
    // the stdlib module and `uv` is never called.
    assert!(
        !i.requires.system_deps.contains("uv"),
        "a skipped step must not contribute its system deps: {:?}",
        i.requires.system_deps
    );
}

#[test]
fn a_system_dep_follows_the_branch_that_uses_it() {
    // Declaring both interpreters' dependencies unconditionally asks every image to carry `uv`
    // even when the build never calls it. On Alpine there is no such package, so the setup phase
    // fails with "uv (no such package)" for a tool that was never going to run. Found by building
    // sniffio from source.
    let tools = ToolRegistry::builtin().unwrap();
    let with_version = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\ndeps:\n  - uses: pypi/setup-venv\n    with: { path: /deps, python_version: \"3.11\" }\n",
    )
    .unwrap();
    let i = render(&with_version, &cx(), &tools).unwrap();
    assert!(
        i.deps.contains("uv venv /deps --seed --python 3.11"),
        "{}",
        i.deps
    );
    assert!(i.requires.system_deps.contains("uv"));
    assert!(!i.requires.system_deps.contains("python3"));

    let without = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\ndeps:\n  - uses: pypi/setup-venv\n    with: { path: /deps }\n",
    )
    .unwrap();
    let i = render(&without, &cx(), &tools).unwrap();
    assert!(i.deps.contains("python3 -m venv /deps"), "{}", i.deps);
    assert!(i.requires.system_deps.contains("python3"));
    assert!(!i.requires.system_deps.contains("uv"));
}

#[test]
fn rendering_is_a_pure_function_of_its_inputs() {
    let s = from_yaml(TOOLBELT).unwrap();
    let tools = ToolRegistry::builtin().unwrap();
    let a = render(&s, &cx(), &tools).unwrap();
    let b = render(&s, &cx(), &tools).unwrap();
    assert_eq!(a, b, "the same inputs must render the same script");
}

#[test]
fn a_typo_in_a_variable_is_an_error_rather_than_an_empty_string() {
    // The whole reason for UndefinedBehavior::Strict. By default this renders `pip install ==`
    // and fails somewhere else entirely.
    let s = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\nbuild:\n  - runs: pip install {{ targt.version }}\n",
    )
    .unwrap();
    let e = render(&s, &cx(), &ToolRegistry::builtin().unwrap()).unwrap_err();
    let m = e.to_string();
    assert!(m.contains("build"), "the phase: {m}");
    assert!(m.to_lowercase().contains("undefined"), "the cause: {m}");
}

#[test]
fn an_unregistered_tool_fails_rather_than_rendering_to_nothing() {
    // A `uses:` that silently produced an empty fragment would give a build that runs, does less
    // than it was asked to, and can still match. That is a false pass.
    let s =
        from_yaml("kind: flow\nlocation: { repo: r, ref: c }\ndeps:\n  - uses: pypi/setup-vnev\n")
            .unwrap();
    let m = render(&s, &cx(), &ToolRegistry::builtin().unwrap())
        .unwrap_err()
        .to_string();
    assert!(m.contains("pypi/setup-vnev"), "{m}");
    assert!(m.contains("not a registered tool"), "{m}");
    assert!(m.contains("pypi/setup-venv"), "the known list helps: {m}");
}

#[test]
fn a_misspelled_parameter_is_refused() {
    // Otherwise the tool reads its own parameter name, gets nothing, and renders a command with a
    // hole in it.
    let s = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\ndeps:\n  - uses: pypi/setup-venv\n    with: { paht: /deps }\n",
    )
    .unwrap();
    let m = render(&s, &cx(), &ToolRegistry::builtin().unwrap())
        .unwrap_err()
        .to_string();
    assert!(m.contains("paht"), "{m}");
    assert!(m.contains("path"), "the declared names help: {m}");
}

#[test]
fn a_missing_required_parameter_is_refused() {
    let s =
        from_yaml("kind: flow\nlocation: { repo: r, ref: c }\ndeps:\n  - uses: pypi/setup-venv\n")
            .unwrap();
    let m = render(&s, &cx(), &ToolRegistry::builtin().unwrap())
        .unwrap_err()
        .to_string();
    assert!(m.contains("requires path"), "{m}");
}

#[test]
fn a_conditional_step_is_dropped_rather_than_rendered_empty() {
    let s = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\nbuild:\n  - runs: always\n  - runs: never\n    if: \"{{ with.nothing_here }}\"\n",
    )
    .unwrap();
    let mut c = cx();
    c.with = BTreeMap::from([("nothing_here".to_string(), String::new())]);
    let i = render(&s, &c, &ToolRegistry::builtin().unwrap()).unwrap();
    assert_eq!(i.build, "always");
}

#[test]
fn a_location_hint_says_why_it_cannot_run() {
    let s = from_yaml("kind: location_hint\nlocation: { repo: r, ref: c }\n").unwrap();
    let m = render(&s, &cx(), &ToolRegistry::builtin().unwrap())
        .unwrap_err()
        .to_string();
    assert!(m.contains("cannot be executed"), "{m}");
}

#[test]
fn pinning_a_registry_moment_with_no_mirror_is_an_error() {
    // Rendering to an empty PIP_INDEX_URL would resolve against the live index and report a
    // reproduction that pinned nothing.
    let s = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\ndeps:\n  - uses: pypi/setup-registry\n    with: { registry_time: \"2023-05-01T04:11:28Z\" }\n",
    )
    .unwrap();
    let mut c = cx();
    c.env.timewarp_base = String::new();
    let m = render(&s, &c, &ToolRegistry::builtin().unwrap())
        .unwrap_err()
        .to_string();
    assert!(m.contains("no mirror is configured"), "{m}");
}

#[test]
fn the_builtin_tools_load_and_resolve() {
    let r = ToolRegistry::builtin().unwrap();
    assert!(r.get("git-checkout").is_some());
    assert!(r.get("pypi/deps/basic").is_some());
    r.validate()
        .expect("every uses: resolves and there are no cycles");
}

#[test]
fn the_node_libc_variant_is_a_parameter_not_a_hardcoded_url() {
    // Found by rebuilding left-pad 1.3.0: npm recorded `_nodeVersion: 9.2.1`, which is exactly
    // right, and the musl build of it does not exist. Hardcoding musl makes every package whose
    // publisher used an older Node unbuildable for a reason that looks like our bug.
    let tools = ToolRegistry::builtin().unwrap();
    let strategy = |libc: &str| {
        from_yaml(&format!(
            "kind: flow\nlocation: {{ repo: r, ref: c }}\ndeps:\n  - uses: npm/install-node\n    with: {{ node_version: \"9.2.1\"{libc} }}\n"
        ))
        .unwrap()
    };

    let glibc = render(&strategy(""), &cx(), &tools).unwrap();
    assert!(
        glibc
            .deps
            .contains("nodejs.org/dist/v9.2.1/node-v9.2.1-linux-x64.tar.gz"),
        "{}",
        glibc.deps
    );

    let musl = render(&strategy(", libc: musl"), &cx(), &tools).unwrap();
    assert!(musl.deps.contains("unofficial-builds"), "{}", musl.deps);
    assert!(musl.deps.contains("linux-x64-musl"), "{}", musl.deps);
}

#[test]
fn a_toolchain_download_goes_through_the_mirror_when_there_is_one() {
    // The deps phase runs inside the network island at `mirror-only` egress, where the mirror is
    // the only reachable host. A template that writes the upstream URL builds an image fine and
    // then dies at `Network is unreachable` in the phase after it, which reads as our sandbox being
    // broken rather than as the strategy naming a host it cannot reach.
    let tools = ToolRegistry::builtin().unwrap();
    let strategy = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\ndeps:\n  - uses: npm/install-node\n    with: { node_version: \"9.2.1\" }\n",
    )
    .unwrap();

    let mirrored = render(&strategy, &cx(), &tools).unwrap();
    assert!(
        mirrored
            .deps
            .contains("http://timewarp/-toolchain/nodejs.org/dist/v9.2.1/"),
        "{}",
        mirrored.deps
    );

    // And straight upstream when there is no mirror, because a pinned toolchain URL names its own
    // version: there is nothing for a time filter to do, so needing one would be a false dependency.
    let mut plain = cx();
    plain.env.timewarp_base = String::new();
    let plain = render(&strategy, &plain, &tools).unwrap();
    assert!(
        plain
            .deps
            .contains("https://nodejs.org/dist/v9.2.1/node-v9.2.1-linux-x64.tar.gz"),
        "{}",
        plain.deps
    );
}
