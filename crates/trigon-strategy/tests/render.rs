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

/// io.js versions resolve to io.js's own host, and nothing else moves.
///
/// For the year before the projects merged at 4.0.0, majors 1 to 3 were io.js releases served from
/// `iojs.org/dist` under an `iojs-` filename; nodejs.org has no v1, v2 or v3. `delayed-stream@1.0.0`
/// records `_nodeVersion: 1.6.4` and asked nodejs.org for a file that never existed there.
///
/// The selection is a shell `case`, so the test runs that `case` under a real `sh` rather than
/// grepping the rendered text — the boundary is the part that is easy to get wrong, and `1.*` must
/// catch `1.6.4` while leaving `10.9.2` alone.
#[test]
fn iojs_versions_come_from_iojs_and_the_boundary_holds_either_side() {
    let tools = ToolRegistry::builtin().unwrap();
    let deps_for = |version: &str| -> String {
        let s = from_yaml(&format!(
            r#"
kind: flow
location:
  repo: https://github.com/felixge/node-delayed-stream
  ref: 0000000000000000000000000000000000000000
src:
  - uses: git-checkout
deps:
  - uses: npm/install-node
    with:
      node_version: "{version}"
build:
  - runs: npm pack
output_path: '*.tgz'
"#
        ))
        .unwrap();
        render(&s, &cx(), &tools).unwrap().deps
    };

    // Every io.js major, plus the versions on each side of the two boundaries. Node 0.x predates
    // io.js and 4.0.0 is the merge, so both belong to nodejs.org.
    for (version, host, name) in [
        ("0.12.7", "nodejs.org", "node"),
        ("1.0.0", "iojs.org", "iojs"),
        ("1.6.4", "iojs.org", "iojs"),
        ("2.5.0", "iojs.org", "iojs"),
        ("3.3.1", "iojs.org", "iojs"),
        ("4.0.0", "nodejs.org", "node"),
        ("8.9.4", "nodejs.org", "node"),
        // The trap a prefix comparison walks into: two-digit majors must not read as io.js.
        ("10.9.2", "nodejs.org", "node"),
        ("22.14.0", "nodejs.org", "node"),
    ] {
        let deps = deps_for(version);
        let start = deps
            .find("TRIGON_NODE_URL=")
            .expect("the fetch is in there");
        let block = &deps[start..deps[start..].find("esac").map(|i| start + i + 4).unwrap()];
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{block}\necho \"$TRIGON_NODE_URL\""))
            .output()
            .expect("sh");
        let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(
            url.contains(host),
            "node {version} should come from {host}: {url}"
        );
        assert!(
            url.contains(&format!("/{name}-v{version}-linux-x64.tar.gz")),
            "node {version} should be named {name}-v{version}: {url}"
        );
    }
}
/// One top-level build step, rendered with these `with` values and this mirror.
fn build_step(
    script: &str,
    with: &[(&str, &str)],
    mirror: &str,
) -> Result<String, trigon_strategy::StrategyError> {
    let s = from_yaml(&format!(
        "kind: flow\nlocation: {{ repo: r, ref: c }}\nbuild:\n  - runs: {}\n",
        serde_json::to_string(script).unwrap()
    ))
    .unwrap();
    let mut c = cx();
    c.env.timewarp_base = mirror.to_string();
    c.with = with
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    render(&s, &c, &ToolRegistry::builtin().unwrap()).map(|i| i.build)
}

#[test]
fn a_list_parameter_that_is_not_json_is_an_error_naming_the_filter_and_the_line() {
    // `pypi/install-deps` loops over `with.requirements | from_json`. A requirements list that is
    // not JSON rendering as an empty loop would install nothing and build anyway; it is refused,
    // and the message quotes the line the author wrote, because that is the repair loop's input.
    let script = "{% for r in with.reqs | from_json %}pip install {{ r }}\n{% endfor %}";
    let e = build_step(script, &[("reqs", "[\"wheel==0.40.0\"")], "timewarp").unwrap_err();
    let m = e.to_string();
    assert!(m.contains("from_json"), "{m}");
    assert!(
        m.contains("with.reqs | from_json"),
        "the author's own line: {m}"
    );

    // An absent list is an empty one, which is what a tool with an optional list wants.
    assert_eq!(
        build_step(script, &[("reqs", "  ")], "timewarp").unwrap(),
        ""
    );
    assert_eq!(
        build_step(script, &[("reqs", "[\"a==1\", \"b==2\"]")], "timewarp").unwrap(),
        "pip install a==1\npip install b==2"
    );
}

#[test]
fn a_value_passed_through_to_json_is_quoted_as_json_quotes_it() {
    let got = build_step(
        "echo {{ with.v | to_json }}",
        &[("v", "it's \"quoted\"")],
        "timewarp",
    )
    .unwrap();
    assert_eq!(got, r#"echo "it's \"quoted\"""#);
}

#[test]
fn indent_pads_every_line_that_has_something_on_it() {
    // A blank line stays blank: trailing spaces in a heredoc are content, and a YAML block that
    // gained them would not be the block that was written.
    let got = build_step(
        "cat <<EOF\n{{ with.body | indent(4) }}\nEOF",
        &[("body", "a:\n\n  b: 1")],
        "timewarp",
    )
    .unwrap();
    assert_eq!(got, "cat <<EOF\n    a:\n\n      b: 1\nEOF");
}

#[test]
fn a_mirror_url_with_no_moment_to_pin_is_refused() {
    // Forwarding an absent publish time used to produce `http://pypi:none@timewarp/simple`, which
    // the mirror reads as a real filter. An empty moment is not a pin.
    let e = build_step(
        "{{ timewarp_url('pypi', with.t) }}",
        &[("t", "")],
        "timewarp",
    )
    .unwrap_err();
    assert!(e.to_string().contains("no moment to pin to"), "{e}");
    assert_eq!(
        build_step(
            "{{ timewarp_url('pypi', with.t) }}",
            &[("t", "2023-05-01T04:11:28Z")],
            "timewarp:8080"
        )
        .unwrap(),
        "http://pypi:2023-05-01T04:11:28Z@timewarp:8080"
    );
}

#[test]
fn the_mirror_host_is_only_there_when_a_mirror_is() {
    // pip ignores a plain-HTTP index that is not also a trusted host, and resolves against the live
    // index instead; the host is what makes it trusted, so asking for it with no mirror is an error
    // rather than an empty `trusted-host`.
    assert_eq!(
        build_step("{{ timewarp_host() }}", &[], "timewarp:8080").unwrap(),
        "timewarp:8080"
    );
    let e = build_step("{{ timewarp_host() }}", &[], "").unwrap_err();
    assert!(e.to_string().contains("no mirror is configured"), "{e}");
}
