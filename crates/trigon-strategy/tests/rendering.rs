
/// `uses: runs` is read as a `runs` step.
///
/// **Four of eight recorded answers for one package wrote it this way.** `runs` is a step kind and
/// can never be a registered tool, so the intent is unambiguous — and refusing it cost a correct
/// repair on every run that produced it, with an error listing nineteen tools the model was not
/// asking for.
#[test]
fn uses_runs_is_a_runs_step() {
    for key in ["script", "run", "cmd", "command"] {
        let src = format!(
            "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
             build:\n  - uses: runs\n    with:\n      {key}: make all\n"
        );
        let s = trigon_strategy::from_yaml(&src)
            .unwrap_or_else(|e| panic!("`with.{key}` should be read as a script: {e}"));
        let trigon_strategy::Strategy::Flow(f) = &s else {
            panic!("shape")
        };
        assert_eq!(
            f.build[0].body,
            trigon_strategy::StepBody::Runs("make all".into()),
            "`uses: runs` with `{key}` should become a runs step"
        );
    }
}

/// And it is refused when it carries no script, or more than one.
#[test]
fn uses_runs_without_exactly_one_script_is_refused() {
    let none = "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
                build:\n  - uses: runs\n";
    let e = trigon_strategy::from_yaml(none).expect_err("no script");
    assert!(format!("{e}").contains("carries no script"), "{e}");

    let two = "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
               build:\n  - uses: runs\n    with:\n      script: a\n      cmd: b\n";
    let e = trigon_strategy::from_yaml(two).expect_err("two scripts");
    assert!(format!("{e}").contains("runs one thing"), "{e}");
}

/// `npm/install-yarn` renders, and pins through the mirror rather than the image.
#[test]
fn install_yarn_resolves_through_the_registry() {
    let src = "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
               deps:\n  - uses: npm/install-yarn\n    with:\n      npm_version: 8.3.0\n\
               \x20     registry_time: 2022-01-05T00:08:33.458Z\n\
               build:\n  - runs: 'true'\n";
    let s = trigon_strategy::from_yaml(src).expect("parses");
    let tools = trigon_strategy::ToolRegistry::builtin().expect("registry");
    let cx = trigon_strategy::Context {
        location: trigon_strategy::LocationCtx {
            repo: "https://example.invalid/x".into(),
            git_ref: "aa".into(),
            subdir: String::new(),
        },
        env: trigon_strategy::EnvCtx {
            arch: "x86_64".into(),
            platform: "linux".into(),
            has_repo: true,
            timewarp_base: "timewarp:8129".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let rendered = trigon_strategy::render(&s, &cx, &tools).expect("renders");
    let text = format!("{rendered:?}");
    assert!(
        text.contains("npm install -g") && text.contains("yarn"),
        "it should install yarn from the registry: {text}"
    );
    // The point of the tool: the yarn it gets is the one the registry served at that moment, which
    // is what makes it the publisher's yarn rather than some yarn.
    assert!(
        text.contains("timewarp"),
        "the install must go through the timewarped mirror: {text}"
    );
}
