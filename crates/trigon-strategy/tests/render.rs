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

/// A project that is not at the root of its repository, which is what `stub42/pytz` is.
const IN_A_SUBDIRECTORY: &str = r#"
kind: flow
location:
  repo: https://github.com/stub42/pytz
  ref: 95fe75d8f15cfc3d5b70e1e71258ddebf0776436
  subdir: src
src:
  - uses: git-checkout
deps:
  - uses: pypi/deps/basic
    with:
      venv: /deps
build:
  - uses: pypi/build/wheel
    with:
      locator: /deps/bin/
output_dir: src/dist
"#;

#[test]
fn a_pypi_build_runs_where_the_project_is() {
    // `location.subdir` reached `git-checkout` and `output_dir` and not the build command, so the
    // frontend ran at the tree root and stopped with "Source /src does not appear to be a Python
    // project". The npm tools have read `location.subdir` the whole time; the PyPI one never did,
    // and nothing noticed until the first target whose project was not at the root.
    let s = from_yaml(IN_A_SUBDIRECTORY).unwrap();
    let tools = ToolRegistry::builtin().unwrap();
    let i = render(&s, &cx(), &tools).unwrap();
    assert!(
        i.build.contains("-m build --wheel") && i.build.trim_end().ends_with("src"),
        "the build has to run where the project is: {}",
        i.build
    );
}

#[test]
fn an_explicit_directory_still_wins_over_the_location() {
    // `dir` is what a definition writes when the project directory and the checkout subdirectory
    // are not the same thing. The default must not take that away.
    let s = from_yaml(&IN_A_SUBDIRECTORY.replace(
        "      locator: /deps/bin/",
        "      locator: /deps/bin/\n      dir: elsewhere",
    ))
    .unwrap();
    let tools = ToolRegistry::builtin().unwrap();
    let i = render(&s, &cx(), &tools).unwrap();
    assert!(
        i.build.trim_end().ends_with("elsewhere"),
        "an explicit dir was overridden: {}",
        i.build
    );
}

#[test]
fn the_ordinary_layout_adds_no_directory_argument() {
    let s = from_yaml(TOOLBELT).unwrap();
    let tools = ToolRegistry::builtin().unwrap();
    let i = render(&s, &cx(), &tools).unwrap();
    let line = i
        .build
        .lines()
        .find(|l| l.contains("-m build"))
        .expect("a build line");
    assert!(
        line.trim_end().ends_with("-n") || line.trim_end().ends_with("--wheel"),
        "a project at the root got a directory argument: {line}"
    );
}

#[test]
fn the_strategys_location_wins_over_the_contexts() {
    // Two copies of one fact, and nothing asserted they agreed. `{{ location.subdir }}` in a tool
    // reads the *context*; the checkout and the output path come from the *strategy*. They came
    // apart the first time a PyPI project was not at its repository root — the build ran at the
    // tree root while the output was collected from `src/dist` — and the caller that built the
    // context is the only thing that had been keeping them in step.
    let s = from_yaml(IN_A_SUBDIRECTORY).unwrap();
    let tools = ToolRegistry::builtin().unwrap();
    // A context that disagrees about every field of the location, as a caller that forgot to
    // derive it would produce.
    let stale = Context {
        location: LocationCtx {
            repo: "https://example.invalid/wrong".into(),
            git_ref: "0000000000000000000000000000000000000000".into(),
            subdir: String::new(),
        },
        ..cx()
    };
    let i = render(&s, &stale, &tools).unwrap();
    assert!(
        i.source.contains("https://github.com/stub42/pytz"),
        "the checkout followed the context rather than the strategy: {}",
        i.source
    );
    assert!(
        i.build.trim_end().ends_with("src"),
        "the build followed the context rather than the strategy: {}",
        i.build
    );
}

/// The npm versions that corrupt their own concurrent downloads are serialized, on both branches.
///
/// npm 7.0 through 8.2 splices the tarballs it fetches in parallel; `tools/npm/npx.yaml` carries
/// the evidence. The guard is a shell `case` rather than a template conditional because the
/// boundary is the part that is easy to get wrong — `8.1.*` must catch `8.1.2` and must *not*
/// catch `8.10.0`, which npm shipped and which is fine — and a glob on a dotted version gets that
/// right where a prefix comparison does not. So the test runs the real `case` under a real `sh`
/// instead of grepping for a string that is present either way.
#[test]
fn the_npm_versions_that_corrupt_concurrent_fetches_are_serialized() {
    let tools = ToolRegistry::builtin().unwrap();
    let script = |version: &str, locator: &str| -> String {
        let s = from_yaml(&format!(
            r#"
kind: flow
location:
  repo: https://github.com/x/y
  ref: 0000000000000000000000000000000000000000
src:
  - uses: git-checkout
deps:
  - uses: npm/npx
    with:
      command: npm ci
      npm_version: "{version}"
      locator: "{locator}"
build:
  - uses: npm/npx
    with:
      command: npm pack
      npm_version: "{version}"
      locator: "{locator}"
output_dir: .
"#
        ))
        .unwrap();
        let i = render(&s, &cx(), &tools).unwrap();
        format!("{}\n{}", i.deps, i.build)
    };

    // Both branches, because only one of them renders per invocation: a guard added to the branch
    // without a `locator` silently does nothing for every definition that sets one.
    for locator in ["", "/deps/bin/"] {
        for (version, want) in [
            ("7.0.0", "1"),
            ("7.24.1", "1"),
            ("8.0.0", "1"),
            ("8.1.2", "1"),
            ("8.2.0", "1"),
            // The first release that fetches concurrently without corrupting anything, and the
            // two-digit minors above it that a prefix test would have swept up by mistake.
            ("8.3.0", "unset"),
            ("8.10.0", "unset"),
            ("8.19.4", "unset"),
            ("6.14.18", "unset"),
            ("11.6.2", "unset"),
        ] {
            let rendered = script(version, locator);
            let guards: Vec<&str> = rendered
                .match_indices("case \"")
                .map(|(i, _)| {
                    let rest = &rendered[i..];
                    &rest[..rest.find("esac").expect("an unterminated case") + 4]
                })
                .collect();
            assert_eq!(
                guards.len(),
                2,
                "both the deps and the build script carry the guard: {rendered}"
            );
            for guard in guards {
                let out = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(format!(
                        "{guard}\necho \"${{npm_config_maxsockets:-unset}}\""
                    ))
                    .output()
                    .expect("sh");
                assert_eq!(
                    String::from_utf8_lossy(&out.stdout).trim(),
                    want,
                    "npm {version} (locator {locator:?}) got the wrong concurrency: {guard}"
                );
            }
        }
    }
}
