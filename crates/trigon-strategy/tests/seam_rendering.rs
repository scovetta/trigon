//! Rendering as a pure, total function with no silent empties.
//!
//! `docs/04-strategies.md` §1 makes rendering the load-bearing seam: a strategy is data, rendering
//! is a pure function of `(strategy, target, environment)`, and the executor is a dumb consumer
//! that never re-renders. Everything downstream — the digest, the attestation, the cached verdict —
//! is a statement about the bytes this function returned. So the failure that matters here is not
//! rendering *wrongly*; a wrong script fails loudly and somebody reads the log. It is rendering
//! *emptily*: a `uses:` that resolves to nothing, an interpolation that evaporates, a required
//! argument that is present as a key and absent as a value. Each of those produces a build that
//! runs, does less than it was asked to, exits zero, and can still match — which is a false pass
//! with an attestation on it.
//!
//! Threat-model P27 names that harm exactly: "an empty script fragment silently replacing a build
//! step". P15 names the other half: a strategy cannot widen its own boundary. The tests below are
//! organised as those two claims plus the totality rule they rest on, and they are split into the
//! ones that hold today and the ones that do not. The failing ones are left failing on purpose;
//! each is a live disagreement between two halves of this crate, and the disagreement is stated in
//! the test's own comment rather than in a document nobody runs.
//!
//! Sibling files: `render.rs` covers the happy path and the four minijinja settings; `parse.rs`
//! covers document shape; `digest.rs` covers what the digest is sensitive to. This file deliberately
//! does not restate them — it goes at the seams between them.

use std::collections::BTreeMap;

use trigon_strategy::{
    Context, EnvCtx, IntrinsicsCtx, LocationCtx, Strategy, TargetCtx, Tool, ToolRegistry,
    from_yaml, render, strategy_digest,
};

/// A context with everything a real run would have *except* the optional intrinsics, which is
/// exactly the shape `trigon strategy render` and `trigon build` construct today: `main.rs`
/// `render_strategy` sets `location` and four `env` fields and takes `..Default::default()` for the
/// rest, so `intrinsics` is empty in every shipped code path.
fn cx() -> Context {
    Context {
        location: LocationCtx {
            repo: "https://github.com/psf/requests-toolbelt".into(),
            git_ref: "da0306dcbb4e0e8dbe1ac6d1e0d8c4f6a1a3b2c1".into(),
            subdir: String::new(),
        },
        target: TargetCtx {
            ecosystem: "pypi".into(),
            name: "requests-toolbelt".into(),
            version: "1.0.0".into(),
            artifact: "requests_toolbelt-1.0.0-py2.py3-none-any.whl".into(),
        },
        env: EnvCtx {
            arch: "x86_64".into(),
            platform: "linux".into(),
            has_repo: false,
            timewarp_base: "timewarp".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A flow document with the boilerplate filled in, so a test body is the thing it is testing.
fn flow(body: &str) -> Strategy {
    let src = format!(
        "kind: flow\nlocation: {{ repo: https://github.com/psf/requests-toolbelt, \
         ref: da0306dcbb4e0e8dbe1ac6d1e0d8c4f6a1a3b2c1 }}\n{body}"
    );
    from_yaml(&src).unwrap_or_else(|e| panic!("fixture does not parse: {e}\n{src}"))
}

fn tool(src: &str) -> Tool {
    serde_yaml_ng::from_str(src).expect("tool fixture")
}

// ---------------------------------------------------------------------------------------------
// P27, first half: an absent value must be a hole that something notices, not a word.
// ---------------------------------------------------------------------------------------------

/// FAILS TODAY. An absent optional in the context renders as the literal text `None`.
///
/// `context.rs` already knows this is the bug. Its comment on `LocationCtx::subdir` says, in full:
/// "A template that prints an absent `Option` renders `none`, and `cd none` in a build script is a
/// failure three steps removed from its cause. Empty string still answers `{% if %}`." That is why
/// `subdir` is a `String` and not an `Option<String>`.
///
/// The reasoning was applied to one field and not to the other four. `EnvCtx::registry_moment`,
/// `EnvCtx::source_date_epoch`, `IntrinsicsCtx::publish_time` and `IntrinsicsCtx::backend` are all
/// still `Option`, so each of them puts the four characters `None` into a build script when the
/// caller has nothing to say. That is not a hole a `{% if %}` can see and not a hole
/// `UndefinedBehavior::Strict` can see: Strict catches an *undefined* name, and an `Option` that
/// serialises to null is defined. The one setting the crate leans on to make a missing value loud
/// is blind to the most common way a value goes missing.
///
/// `export SOURCE_DATE_EPOCH=None` is the compact version of the harm. A build that reads it either
/// fails somewhere unrelated or ignores it and bakes today's clock into the artifact, and the run
/// reports a divergence in timestamps with no sign of where it came from.
#[test]
fn an_absent_context_value_renders_a_hole_rather_than_the_word_none() {
    let tools = ToolRegistry::builtin().unwrap();
    let mut bad = Vec::new();

    for expr in [
        "{{ intrinsics.publish_time }}",
        "{{ intrinsics.backend }}",
        "{{ env.registry_moment }}",
        "{{ env.source_date_epoch }}",
    ] {
        let s = flow(&format!("build:\n  - runs: 'echo {expr}'\n"));
        // Either answer is defensible: the empty string, as `subdir` chose, so `{% if %}` can ask;
        // or an error, as Strict does for a name that was never defined. What is not defensible is
        // a word a shell will accept as an argument.
        if let Ok(i) = render(&s, &cx(), &tools)
            && i.build.to_ascii_lowercase().contains("none")
        {
            bad.push(format!("{expr} -> {:?}", i.build));
        }
    }

    assert!(
        bad.is_empty(),
        "an absent optional must not render as a word a shell will happily accept as an \
         argument:\n  {}",
        bad.join("\n  ")
    );
}

/// FAILS TODAY. The `{% if %}` guard that means "no moment was given" is defeated by `None`.
///
/// This is the first-order bug made concrete, and it is the reason it is rated above a cosmetic
/// one. `pypi/setup-registry` guards its whole body on `{%- if with.registry_time %}`, and the
/// comment above that guard is nine lines about how a silently-unpinned index is the failure the
/// tool exists to prevent. The documented worked example in `docs/04-strategies.md` §3 forwards the
/// moment as `with: { moment: "{{ intrinsics.publish_time }}" }`.
///
/// Put those together on a run with no publish time — which is every run the shipped binary makes,
/// since `main.rs` never populates `intrinsics` — and the guard sees the non-empty string `None`,
/// decides a moment *was* given, and writes:
///
/// ```text
/// index-url = http://pypi:None@timewarp/simple
/// ```
///
/// Reproduced against `./target/debug/trigon strategy render`, not inferred. The mirror then
/// refuses `None` as a moment (`trigon-mirror`'s `normalize` requires exactly 19 shaped bytes and
/// returns `BadMoment` otherwise), so the build dies inside the network island on every index
/// request — an authentication-looking failure from the mirror, for a strategy that asked for no
/// pinning at all. The condition and the value disagree about what "absent" looks like.
#[test]
fn a_tool_guard_on_an_absent_moment_sees_absence_rather_than_the_word_none() {
    let s = flow(
        "deps:\n  - uses: pypi/setup-registry\n    with: { registry_time: \"{{ intrinsics.publish_time }}\" }\n",
    );
    let deps = match render(&s, &cx(), &ToolRegistry::builtin().unwrap()) {
        // An error here would be a fine outcome too: it says "you forwarded something that is not
        // a moment" at render time rather than at index time.
        Err(_) => return,
        Ok(i) => i.deps,
    };
    assert!(
        !deps.contains("index-url"),
        "no publish time was available, so the mirror must not be pinned to anything. Instead the \
         guard fired on the word `None` and pinned the index to it:\n{deps}"
    );
}

/// FAILS TODAY. `required: true` is satisfied by a key with an empty value.
///
/// `check_params` asks whether the caller supplied the key. It does not ask whether the key carries
/// a value, so `with: { venv: "" }` passes, and `pypi/deps/basic` renders
///
/// ```text
/// /bin/pip install build
/// ```
///
/// `/bin/pip` is not a missing path that fails fast. On most images it is the *system* pip, so the
/// build frontend and every later `{{ with.venv }}/bin/...` install into the system interpreter
/// instead of the pinned environment the strategy asked for. The build succeeds; it is simply a
/// build of something else.
///
/// The crate already rejects the near-identical mistake one line up. `check_params`' own comment on
/// the unknown-parameter branch reads: "A misspelled parameter is otherwise invisible: the tool
/// reads its own name for the value, gets nothing, and renders a command with a hole in it." A
/// misspelled parameter and an empty required parameter produce the same hole in the same command;
/// only the first is caught.
///
/// The forwarded case is the one that bites in practice and needs no author error at all: a
/// composite tool passes its own optional parameter straight into an inner tool's required one, the
/// caller omits the optional, `expand` fills it with the empty string by design, and the inner
/// tool's requirement is met by nothing.
#[test]
fn a_required_tool_parameter_is_not_satisfied_by_the_empty_string() {
    let mut tools = ToolRegistry::builtin().unwrap();
    tools
        .add(tool(
            "id: local/forwards\nparams:\n  p: { required: false }\n\
             steps:\n  - uses: pypi/setup-venv\n    with: { path: \"{{ with.p }}\" }\n",
        ))
        .unwrap();
    tools.validate().unwrap();

    // Written directly, which is what a model emits when it has no value for a field it can see is
    // required.
    let direct = flow("deps:\n  - uses: pypi/deps/basic\n    with: { venv: \"\" }\n");
    let direct = render(&direct, &cx(), &tools);
    assert!(
        direct.is_err(),
        "a required parameter given the empty string has to be refused by name, or the tool \
         renders a command missing an argument: {:?}",
        direct.map(|i| i.deps)
    );

    // And forwarded, where nobody wrote an empty string anywhere: an optional parameter left out
    // becomes the empty string by design, and then satisfies a requirement.
    let forwarded = flow("deps:\n  - uses: local/forwards\n");
    let forwarded = render(&forwarded, &cx(), &tools);
    assert!(
        forwarded.is_err(),
        "an omitted optional must not be able to satisfy an inner tool's required parameter: {:?}",
        forwarded.map(|i| i.deps)
    );
}

/// FAILS TODAY. An executable strategy that renders no build at all is accepted.
///
/// `kind: flow` with a location and nothing else reports `is_executable() == true`, renders to
/// three empty scripts and an `output_path` of `*`, and gets a `strategy_digest` computed over it —
/// confirmed against the binary, which prints a digest and no script sections at all.
///
/// Nothing downstream catches it either. `crates/trigon-sandbox/src/dockerfile.rs` composes the
/// build script as `set -eux` + the (empty) build + `cp -r /src/<output_path> /out/`, so an empty
/// flow produces a container that copies the *unbuilt source tree* into the output directory and
/// exits zero. That is the P27 harm in its purest form: a run that built nothing, succeeded, and
/// produced artifact-shaped bytes for the comparator to judge.
///
/// This crate already believes the invariant. `tests/definitions.rs` asserts
/// `!i.build.trim().is_empty()` for every corpus definition it renders, which is this rule enforced
/// on 53 files from someone else's repository and on nothing we produce ourselves. `docs/04` §7
/// lists what a rendered strategy is rejected for and does not list this, which is the gap.
#[test]
fn an_executable_strategy_that_renders_no_build_is_refused_rather_than_run_as_a_no_op() {
    let tools = ToolRegistry::builtin().unwrap();

    // Nothing but a location.
    let bare = flow("");
    assert!(bare.is_executable(), "a flow claims it can be executed");
    // `render` stays pure — `trigon strategy render` exists to show a fragment, including a
    // deps-only one — so the refusal lives on the plan rather than on rendering it.
    let bare = render(&bare, &cx(), &tools).and_then(|i| i.executable());
    assert!(
        bare.is_err(),
        "a flow with no steps must not render to an empty script the executor will run as a \
         success: {:?}",
        render(&flow(""), &cx(), &tools).map(|i| (i.source, i.deps, i.build, i.output_path))
    );

    // The subtler shape, and the one that survives review: every build step is conditional, and on
    // this run every condition is false. The document looks like a build; the render is silence.
    let all_skipped = flow(
        "build:\n  - runs: python -m build --wheel -n\n    if: \"{% if env.has_repo %}yes{% endif %}\"\n",
    );
    let all_skipped = render(&all_skipped, &cx(), &tools).and_then(|i| i.executable());
    assert!(
        all_skipped.is_err(),
        "a build phase whose every step was skipped is an empty build, however it got that way: \
         {:?}",
        render(&flow("build:\n  - runs: python -m build --wheel -n\n    if: \"{% if env.has_repo %}yes{% endif %}\"\n"), &cx(), &tools).map(|i| i.build)
    );
}

/// FAILS TODAY. A `schema:` that is not an integer is read as schema 1 rather than refused.
///
/// `from_yaml` does `.and_then(|v| v.as_u64()).unwrap_or(CURRENT_SCHEMA)`, which conflates "no
/// schema declared" with "a schema declared in a shape we could not read". `schema: 99` is refused
/// with the good message; `schema: "99"` — the same document with the quoting a model happens to
/// emit — is silently read as schema 1 and rendered. So are `schema: 99.5` and `schema: -1`.
///
/// `docs/04` §4 opens with "Every strategy document begins `schema: 1`. The prior art carries no
/// version field, and we decline to inherit that problem." The field exists so that a future format
/// is refused rather than guessed at, and `tests/parse.rs` asserts that for the one spelling that
/// works. A version gate with a spelling-dependent hole is the problem the field was added to avoid,
/// arriving later and quieter.
#[test]
fn a_schema_that_is_not_a_number_is_refused_rather_than_read_as_schema_one() {
    for declared in ["\"99\"", "99.5", "-1", "one"] {
        let src = format!(
            "schema: {declared}\nkind: flow\nlocation: {{ repo: r, ref: c }}\nbuild:\n  - runs: make\n"
        );
        let got = from_yaml(&src);
        assert!(
            got.is_err(),
            "`schema: {declared}` is not a schema this build understands, and reading it as \
             schema {} is a guess: {got:?}",
            trigon_strategy::CURRENT_SCHEMA
        );
    }

    // Omitting it entirely is the one case that legitimately defaults, and it must keep working:
    // the definitions corpus predates the field.
    assert!(
        from_yaml("kind: flow\nlocation: { repo: r, ref: c }\nbuild:\n  - runs: make\n").is_ok()
    );
}

/// FAILS TODAY. The undefined-variable error does not name the variable.
///
/// `render.rs`'s own module doc, item 1, says of `UndefinedBehavior::Strict`: "A typo'd
/// `{{ targt.version }}` renders empty by default, which turns into `pip install ==` and a failure
/// nobody can trace back to the typo. **Here it is an error naming the variable.**" It is not. The
/// message is:
///
/// ```text
/// build.[0]: template: undefined value (in <string>:4)
/// ```
///
/// The path is good and does real work — it names the phase, the step index and the chain of tools
/// the step expanded through. The variable is missing, and the variable is the repair. `docs/04`
/// §2.2 stakes the whole two-pass parser on the claim that "the build-repair loop can only be as
/// good as this error", and hands the loop a line naming neither the identifier nor the template it
/// came from. `<string>:4` is line four of a fragment that exists only inside the renderer.
///
/// Cheap to fix and worth fixing: minijinja is built here with `default-features = false`, which
/// leaves its `debug` feature off, and that feature is what attaches the referenced name to an
/// undefined-value error. Failing that, the template can be scanned for the name before the error
/// is wrapped in `template_message`.
#[test]
fn an_undefined_variable_error_names_the_variable_the_author_typed() {
    let s = flow("build:\n  - runs: 'pip install requests=={{ targt.version }}'\n");
    let m = render(&s, &cx(), &ToolRegistry::builtin().unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        m.contains("targt"),
        "a repair loop is given this and has to find the typo from it: {m}"
    );
}

// ---------------------------------------------------------------------------------------------
// P27, second half: what already holds, and must keep holding.
// ---------------------------------------------------------------------------------------------

/// Every shape of typo is a hard error, and none of them renders to an empty string.
///
/// `render.rs`'s existing test covers the headline case, an undefined root name. These are the
/// other four ways a template reaches for something that is not there, and they are different code
/// paths inside minijinja rather than restatements: a missing *attribute* of a defined object, a
/// missing key of the `with` map, a name referenced from inside a tool two levels down, and a name
/// referenced from a step's `if:` condition.
///
/// The last one is the one worth having. A condition is the only place in the DSL where rendering
/// to empty has a *defined* meaning — `expand` drops the step — so a typo there would not be an
/// error and would not be an empty script either. It would be a step that silently does not run,
/// which is the same false pass arriving through the one door that is meant to be open.
#[test]
fn every_shape_of_missing_name_is_an_error_rather_than_an_empty_interpolation() {
    let mut tools = ToolRegistry::builtin().unwrap();
    tools
        .add(tool(
            "id: local/inner\nparams:\n  a: { required: true }\nsteps:\n  - runs: 'echo {{ with.b }}'\n",
        ))
        .unwrap();
    tools
        .add(tool(
            "id: local/outer\nparams:\n  a: { required: true }\n\
             steps:\n  - uses: local/inner\n    with: { a: \"{{ with.a }}\" }\n",
        ))
        .unwrap();
    tools.validate().unwrap();

    let cases = [
        // A misspelled attribute of an object that does exist.
        (
            "attribute",
            "build:\n  - runs: 'echo {{ target.verson }}'\n",
        ),
        // A `with` key at the top level, where `with` is empty by construction.
        ("with key", "build:\n  - runs: 'echo {{ with.python }}'\n"),
        // A misspelled name inside a tool, reached through another tool.
        (
            "inside a tool",
            "build:\n  - uses: local/outer\n    with: { a: x }\n",
        ),
        // And in a condition, where empty is a legal answer meaning "skip".
        (
            "condition",
            "build:\n  - runs: python -m build\n    if: \"{{ intrinsics.tolchains }}\"\n",
        ),
    ];

    for (label, body) in cases {
        let got = render(&flow(body), &cx(), &tools);
        let m = match got {
            Ok(i) => panic!("{label}: rendered {:?} instead of failing", i.build),
            Err(e) => e.to_string(),
        };
        assert!(
            m.to_lowercase().contains("undefined"),
            "{label}: must fail as undefined rather than some other way: {m}"
        );
        assert!(
            m.starts_with("build"),
            "{label}: and must locate the step for a repair loop: {m}"
        );
    }
}

/// An unregistered `uses:` is refused twice, at load and at render, and both name the tool.
///
/// P27 states this one directly. `tool.rs`'s module doc says why the render-time half matters more
/// than it sounds: "A `uses:` that silently produces an empty fragment gives a build that runs, does
/// less than it was asked to, and can still match, which is a false pass."
///
/// The load-time half is the one no other test covers, and it is a different failure: not a strategy
/// naming a tool that does not exist, but a *tool* naming one. That reaches nobody until some
/// unrelated strategy happens to use the tool that wraps it, so catching it when the registry is
/// assembled is the difference between a definitions-repo merge failing and a single package's
/// rebuild failing months later.
#[test]
fn an_unregistered_uses_is_refused_at_load_and_at_render_and_names_the_tool() {
    // Load time: a tool whose step names a tool nobody registered.
    let mut broken = ToolRegistry::builtin().unwrap();
    broken
        .add(tool(
            "id: local/wrapper\nsteps:\n  - uses: pypi/setup-vnev\n",
        ))
        .unwrap();
    let m = broken.validate().unwrap_err().to_string();
    assert!(m.contains("local/wrapper"), "the tool that is wrong: {m}");
    assert!(m.contains("step 0"), "and where in it: {m}");
    assert!(m.contains("pypi/setup-vnev"), "and what it asked for: {m}");
    assert!(
        m.contains("pypi/setup-venv"),
        "and the near-miss it probably meant, from the known list: {m}"
    );

    // Render time: the result is an error, never an `Ok` carrying a shorter script.
    let got = render(
        &flow("deps:\n  - uses: pypi/setup-vnev\n"),
        &cx(),
        &ToolRegistry::builtin().unwrap(),
    );
    assert!(
        got.is_err(),
        "an unresolvable step must not render to the empty fragment: {:?}",
        got.map(|i| i.deps)
    );
}

/// Tool composition is acyclic at load, and the refusal prints the cycle.
///
/// P27 claims it; `check_acyclic` implements it. What is asserted here is the message, because a
/// cycle in a composition graph is diagnosed by reading it: "tools form a cycle: a -> b -> a" tells
/// a definitions author which edge to cut, and "tools form a cycle" does not.
///
/// The direct self-reference is worth its own assertion. It is the shape a copy-pasted tool
/// definition takes, and it is the one a naive "have I seen this before" check on the *children*
/// rather than the path would miss.
#[test]
fn tool_composition_is_refused_at_load_when_it_cycles_and_the_message_names_the_cycle() {
    let mut two = ToolRegistry::new();
    two.add(tool("id: a\nsteps:\n  - uses: b\n")).unwrap();
    two.add(tool("id: b\nsteps:\n  - uses: a\n")).unwrap();
    let m = two.validate().unwrap_err().to_string();
    assert!(m.contains("cycle"), "{m}");
    assert!(
        m.contains("a -> b -> a"),
        "the message has to draw the cycle, not just report that there is one: {m}"
    );

    let mut itself = ToolRegistry::new();
    itself.add(tool("id: s\nsteps:\n  - uses: s\n")).unwrap();
    let m = itself.validate().unwrap_err().to_string();
    assert!(m.contains("s -> s"), "a tool that uses itself: {m}");

    // And the shipped registry is clean, which is the only reason `builtin()` can call `validate`
    // and `unwrap` it everywhere in this crate's tests.
    ToolRegistry::builtin().unwrap().validate().unwrap();
}

/// Render depth is bounded, so an unvalidated cycle terminates instead of hanging.
///
/// `MAX_TOOL_DEPTH`'s comment calls itself "a backstop, not the mechanism", and the distinction is
/// load-bearing because the mechanism is opt-in: `ToolRegistry::add` does not validate, and only
/// `builtin()` calls `validate()` for you. Anything assembling a registry from a definitions
/// checkout has to remember. When it forgets, this bound is the difference between a worker that
/// reports an error and a worker that spins.
///
/// Both halves are asserted: the legal-but-absurd chain, which is what the bound was written for,
/// and the cycle that got past a skipped `validate()`, which is what it actually saves you from.
#[test]
fn render_depth_is_bounded_so_an_unvalidated_cycle_terminates_rather_than_spinning() {
    // A legal chain, 30 distinct tools deep. `validate()` has nothing to say about it: there is no
    // cycle, it is just absurd.
    let mut chain = ToolRegistry::new();
    for n in 0..30usize {
        let step = if n == 29 {
            "  - runs: echo bottom\n".to_string()
        } else {
            format!("  - uses: chain/{}\n", n + 1)
        };
        chain
            .add(tool(&format!("id: chain/{n}\nsteps:\n{step}")))
            .unwrap();
    }
    chain
        .validate()
        .expect("a deep chain is acyclic; depth is not the load-time check's business");

    let m = render(&flow("build:\n  - uses: chain/0\n"), &cx(), &chain)
        .unwrap_err()
        .to_string();
    assert!(
        m.contains("deeper than 16 levels"),
        "the error has to name the bound, or the reader cannot tell a runaway from a legal \
         composition that is one level too deep: {m}"
    );

    // The case the backstop exists for: a cycle in a registry whose owner never called `validate`.
    // If this test hangs rather than fails, the bound is gone.
    let mut cyclic = ToolRegistry::new();
    cyclic.add(tool("id: a\nsteps:\n  - uses: b\n")).unwrap();
    cyclic.add(tool("id: b\nsteps:\n  - uses: a\n")).unwrap();
    let m = render(&flow("build:\n  - uses: a\n"), &cx(), &cyclic)
        .unwrap_err()
        .to_string();
    assert!(m.contains("deeper than 16 levels"), "{m}");
}

/// FAILS TODAY. A refused `add` has already applied itself.
///
/// `ToolRegistry::add` says the right thing and does the opposite:
///
/// ```ignore
/// if let Some(prev) = self.tools.insert(t.id.clone(), t) {
///     return Err(... "tool `{}` is registered twice. A definitions repo overriding a builtin has
///                     to say so explicitly rather than shadowing it by load order." ...)
/// }
/// ```
///
/// `BTreeMap::insert` replaces and *returns the displaced value*, so by the time the error is
/// constructed the shadowing has happened. The refusal describes a state the registry is not in.
/// Asserted below: after `add` returns `Err`, `get` hands back the intruder, and a strategy using
/// `pypi/deps/basic` renders `echo hijacked`.
///
/// Two things make this worse than a tidy-up. The error even names the wrong tool — it reports
/// `prev.id`, the definition that was *evicted*, which reads correctly only because the two ids are
/// equal by construction. And `add` is the only way to build a registry that is not `builtin()`, so
/// it is exactly the path a definitions-repo loader takes; a loader that collects load errors and
/// reports them at the end, rather than aborting on the first, ends up running builds against the
/// tools it just refused. Failure-atomicity is a contract dimension the threat model claims for
/// this component, and this is the one place in the crate that breaks it.
#[test]
fn a_refused_tool_registration_leaves_the_registry_as_it_was() {
    let mut tools = ToolRegistry::builtin().unwrap();
    let before = tools.get("pypi/deps/basic").cloned().expect("a builtin");

    let m = tools
        .add(tool(
            "id: pypi/deps/basic\nsteps:\n  - runs: echo hijacked\n",
        ))
        .unwrap_err()
        .to_string();
    assert!(m.contains("pypi/deps/basic"), "{m}");
    assert!(m.contains("registered twice"), "{m}");

    // Compared by shape rather than by value, so the failure message stays readable: the builtin
    // declares six parameters and five steps, and the intruder declares none and one.
    let now = tools
        .get("pypi/deps/basic")
        .expect("registered under something");
    assert_eq!(
        (now.params.len(), now.steps.len()),
        (before.params.len(), before.steps.len()),
        "the add was refused, so the builtin must still be the builtin. It is not: a caller that \
         logs the error and carries on is now running someone else's tool under a name every \
         strategy in the fleet already references."
    );

    let i = render(
        &flow("deps:\n  - uses: pypi/deps/basic\n    with: { venv: /deps }\n"),
        &cx(),
        &tools,
    )
    .unwrap();
    assert!(
        !i.deps.contains("hijacked"),
        "and the shadowed tool is what renders: {}",
        i.deps
    );
}

// ---------------------------------------------------------------------------------------------
// P15: a strategy cannot widen its own boundary.
// ---------------------------------------------------------------------------------------------

/// A strategy cannot ask for privilege, egress, a base image or a platform.
///
/// P15 is marked security-critical and `docs/04` §7 lists the four requests that get a rendered
/// strategy rejected. The implementation answers them in a way the documents do not quite say: there
/// is no field to refuse. `Requirements` is *computed* — `privileged` is a literal `false` in
/// `render_flow` and `Requirements::default()` in `render_manual` — and `deny_unknown_fields` on
/// every struct in the schema means the request cannot be written down in the first place.
///
/// That is a stronger guarantee than a check, and it is exactly the kind that erodes without a test,
/// because the erosion is additive: someone adds `platform` to `FlowStrategy` for a good reason and
/// the boundary widens as a side effect of a feature. This asserts the refusal at all three levels a
/// request could be smuggled in at — the document, the step, and the `Requirements` block the
/// executor actually reads — and that each refusal names the field, since a strategy author who
/// needs a platform deserves to be told no by name rather than have it ignored.
#[test]
fn a_strategy_cannot_widen_its_own_boundary_and_the_refusal_names_the_field() {
    let widenings = [
        ("privileged", "privileged: true\n"),
        ("egress", "egress: internet\n"),
        ("image", "image: python:3.9\n"),
        ("base_image", "base_image: python@sha256:abc\n"),
        ("platform", "platform: linux/arm64\n"),
        ("requires", "requires: { privileged: true }\n"),
    ];

    for (field, line) in widenings {
        // At the document level, for a flow...
        let m = from_yaml(&format!(
            "kind: flow\nlocation: {{ repo: r, ref: c }}\n{line}"
        ))
        .unwrap_err()
        .to_string();
        assert!(m.contains(field), "flow must refuse `{field}` by name: {m}");
        assert!(
            m.contains("unknown field"),
            "and as unknown rather than as some parse accident: {m}"
        );

        // ...and for a manual strategy, which is the lower-trust variant a model writes and
        // therefore the one an attacker would aim at.
        let m = from_yaml(&format!(
            "kind: manual\nlocation: {{ repo: r, ref: c }}\nbuild: make\n{line}"
        ))
        .unwrap_err()
        .to_string();
        assert!(
            m.contains(field),
            "manual must refuse `{field}` by name: {m}"
        );
    }

    // At the step level, where a reader's eye is least likely to be.
    let m = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\nbuild:\n  - runs: make\n    privileged: true\n",
    )
    .unwrap_err()
    .to_string();
    assert!(m.contains("privileged"), "{m}");
    assert!(
        m.contains("build[0]"),
        "and the path locates the step that asked: {m}"
    );

    // And what a legal strategy actually renders to: no privilege, whichever variant it is.
    let tools = ToolRegistry::builtin().unwrap();
    let f = render(&flow("build:\n  - runs: make\n"), &cx(), &tools).unwrap();
    assert!(!f.requires.privileged);
    let m = from_yaml("kind: manual\nlocation: { repo: r, ref: c }\nbuild: make\n").unwrap();
    let m = render(&m, &cx(), &tools).unwrap();
    assert!(!m.requires.privileged);
}

/// An unknown field is refused with the path that locates it, at every depth.
///
/// `docs/04` §2.2 calls `serde_path_to_error` the highest-return dependency in the design, on the
/// grounds that its output goes verbatim into a repair prompt. The dependency only earns that if the
/// path survives the two-pass parser at depths below the top level, and `parse.rs` is explicit that
/// the naive arrangement loses it: internal tagging buffers through serde's `Content` and every
/// error comes back anchored at the document root.
///
/// So these assert the path itself rather than the fact of an error. `tests/parse.rs` covers a
/// top-level typo; below are the three depths where the buffering defect would show up first — a
/// field of a nested struct, a field of a step inside an indexed sequence, and a key inside a step's
/// `with` map — plus the expected-field list, which is what turns a repair from a guess into an
/// edit.
#[test]
fn an_unknown_field_is_refused_with_the_path_that_locates_it() {
    // A nested struct.
    let m = from_yaml("kind: flow\nlocation: { repo: r, ref: c, subdirr: pkg }\n")
        .unwrap_err()
        .to_string();
    assert!(
        m.starts_with("flow.location.subdirr:"),
        "the path has to reach into the nested struct: {m}"
    );
    assert!(
        m.contains("`repo`") && m.contains("`subdir`"),
        "and list what was expected, which is where the repair comes from: {m}"
    );

    // A step in an indexed sequence: the index is the difference between "a step is wrong" and
    // "this step is wrong" in a nine-step deps phase.
    let m = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\n\
         deps:\n  - uses: pypi/setup-venv\n  - runs: make\n    ifx: \"{{ env.has_repo }}\"\n",
    )
    .unwrap_err()
    .to_string();
    assert!(
        m.starts_with("flow.deps[1].ifx:"),
        "the path has to carry the index: {m}"
    );

    // A bad value, rather than a bad key, one level deeper still.
    let m = from_yaml(
        "kind: flow\nlocation: { repo: r, ref: c }\n\
         deps:\n  - uses: pypi/setup-venv\n    with:\n      python_version: 3.11\n",
    )
    .unwrap_err()
    .to_string();
    assert!(
        m.starts_with("flow.deps[0].with.python_version:"),
        "the path has to reach a map key inside a step: {m}"
    );
}

// ---------------------------------------------------------------------------------------------
// Purity, and the one false friend that must stay false.
// ---------------------------------------------------------------------------------------------

/// A template ranging a context map sees sorted order, not insertion order.
///
/// This is `docs/04` §3.2 (2) and the reason the dependency policy bans `HashMap` in this crate:
/// "minijinja preserves insertion order when a template ranges a map, so a `HashMap` here would make
/// the rendered script, and therefore `strategy_digest`, vary between runs." Note what that means —
/// the failure does not reproduce in a single process, because two `HashMap`s in one thread share a
/// seed and iterate alike. It reproduces across runs, as a cache key that moves for no reason and a
/// signed attestation nobody can re-derive.
///
/// A test cannot observe two processes, so it observes the property that distinguishes the two map
/// types *within* one: a `BTreeMap` yields sorted order whatever order it was filled in, and a
/// `HashMap` yields neither. Fill in reverse and assert sorted, and a swap of either map type — the
/// context's `toolchains`, or `StepRaw`'s `with` — fails here rather than in a digest mismatch six
/// months later.
#[test]
fn a_template_ranging_a_context_map_sees_sorted_order_not_insertion_order() {
    let mut tools = ToolRegistry::builtin().unwrap();
    tools
        .add(tool(
            "id: local/ranges\nsteps:\n  - runs: '{% for k, v in with|items %}{{ k }}={{ v }} {% endfor %}'\n",
        ))
        .unwrap();
    tools.validate().unwrap();

    // The intrinsics map, filled in descending order.
    let mut c = cx();
    let mut toolchains = BTreeMap::new();
    for (k, v) in [
        ("python", "3.11"),
        ("node", "18.0.0"),
        ("go", "1.21"),
        ("cargo", "1.75"),
    ] {
        toolchains.insert(k.to_string(), v.to_string());
    }
    c.intrinsics = IntrinsicsCtx {
        toolchains,
        ..Default::default()
    };
    let i = render(
        &flow("build:\n  - runs: '{% for k, v in intrinsics.toolchains|items %}{{ k }}:{{ v }} {% endfor %}'\n"),
        &c,
        &tools,
    )
    .unwrap();
    assert_eq!(
        i.build, "cargo:1.75 go:1.21 node:18.0.0 python:3.11",
        "a ranged context map must render in key order, whatever order it was built in"
    );

    // And a step's `with`, filled in descending order by the document itself.
    let i = render(
        &flow("build:\n  - uses: local/ranges\n    with: { zulu: \"1\", mike: \"2\", alpha: \"3\" }\n"),
        &cx(),
        &tools,
    )
    .unwrap();
    assert_eq!(i.build, "alpha=3 mike=2 zulu=1");

    // The digest follows from the same property, and is the thing that actually costs money when it
    // moves. Two documents differing only in the order their keys were written must be one cache
    // entry, not two.
    let a = flow(
        "deps:\n  - uses: pypi/deps/basic\n    with: { venv: /deps, registry_time: \"2023-05-01T04:11:28Z\" }\nbuild:\n  - runs: make\noutput_dir: dist\n",
    );
    let b = flow(
        "output_dir: dist\nbuild:\n  - runs: make\ndeps:\n  - uses: pypi/deps/basic\n    with: { registry_time: \"2023-05-01T04:11:28Z\", venv: /deps }\n",
    );
    assert_eq!(
        render(&a, &cx(), &tools).unwrap(),
        render(&b, &cx(), &tools).unwrap()
    );
    assert_eq!(
        strategy_digest(&a, &tools).unwrap(),
        strategy_digest(&b, &tools).unwrap()
    );
}

/// Rendering does not shell-escape, and the escaping filter is opt-in. Pinned, not fixed.
///
/// Threat-model §1.12 lists this under false friends, and §7 of `docs/04` is blunt about why:
/// "validating a string that contains bash is validating a string." The template engine substitutes
/// text; the boundary is the sandbox. Anybody who reads `UndefinedBehavior::Strict` and the
/// parameter checking and concludes that a rendered script is therefore safe against its own inputs
/// is wrong, and this test is where they find out.
///
/// It is pinned rather than repaired deliberately. Escaping by default would be the wrong fix twice
/// over: it would break every template that composes a command out of fragments, and it would turn a
/// documented non-guarantee into an undocumented partial one, which is worse than either. The filter
/// `shell_single_quote` is the supported answer, and its exact output is asserted too — an escaper
/// that is subtly wrong is more dangerous than none, because it is the one people trust.
#[test]
fn rendering_does_not_shell_escape_and_the_escaping_filter_is_the_opt_in() {
    let tools = ToolRegistry::builtin().unwrap();
    let mut c = cx();
    // A version string that closes the quote the template opened. Registries have shipped stranger.
    c.target.version = "1.0.0'; touch /tmp/pwned #".into();

    let i = render(
        &flow("build:\n  - runs: pip install 'requests=={{ target.version }}'\n"),
        &c,
        &tools,
    )
    .unwrap();
    assert_eq!(
        i.build, "pip install 'requests==1.0.0'; touch /tmp/pwned #'",
        "rendering substitutes text and does not escape it. If this assertion fails because \
         escaping was added, threat-model §1.12 and docs/04 §7 have to change in the same commit, \
         and every template that composes a command out of fragments has to be re-checked."
    );

    // The opt-in, asserted byte for byte: `'` becomes `'\''`, which closes the literal, emits an
    // escaped quote, and reopens it.
    let i = render(
        &flow(
            "build:\n  - runs: pip install 'requests=={{ target.version | shell_single_quote }}'\n",
        ),
        &c,
        &tools,
    )
    .unwrap();
    assert_eq!(
        i.build,
        r"pip install 'requests==1.0.0'\''; touch /tmp/pwned #'"
    );
}

/// `render` is total over all four variants: two produce instructions, two refuse by name.
///
/// Totality is the half of "pure and total" that has no other test. The failure it rules out is not
/// a panic — it is the variant that falls through to `Ok(Instructions::default())` and hands the
/// executor three empty scripts. `Prebuilt` is the live risk: it is the only variant with no
/// `location`, `render` is the only thing standing between it and an executor, and its refusal is
/// asserted nowhere else in the suite.
///
/// The `Manual` assertion pins a deliberate asymmetry rather than an achievement, so it is worth
/// stating plainly. `render_manual` copies `deps` and `build` through untouched — its comment
/// explains that running a model's raw shell through a template engine would give `{{` inside a
/// here-doc a meaning its author did not intend — and it emits **no source script at all**. A flow's
/// `git-checkout` ends in `git checkout --force '<sha>'`, which the sandbox's `COPY`-based image
/// build turns into the check that the copied tree really is at the commit the attestation names. A
/// manual strategy skips that check while its provenance still carries the commit. Pinned here so
/// that the asymmetry is a decision on the record rather than a thing nobody noticed.
#[test]
fn render_is_total_over_all_four_variants_and_never_returns_silence() {
    let tools = ToolRegistry::builtin().unwrap();

    let hint = from_yaml("kind: location_hint\nlocation: { repo: r, ref: c }\n").unwrap();
    let m = render(&hint, &cx(), &tools).unwrap_err().to_string();
    assert!(m.contains("cannot be executed"), "{m}");
    assert!(
        m.contains("where the source is"),
        "the refusal says what a location_hint is for, because the caller has to pick another \
         inferrer rather than fix the document: {m}"
    );

    let prebuilt = from_yaml(
        "kind: prebuilt\nurl: https://example.invalid/x.whl\nsha256: ab\n\
         approved_by: someone\nreason: upstream builds it reproducibly\n",
    )
    .unwrap();
    let m = render(&prebuilt, &cx(), &tools).unwrap_err().to_string();
    assert!(
        m.contains("no build to run"),
        "a prebuilt strategy must be refused rather than rendered to three empty scripts: {m}"
    );

    let manual = from_yaml(
        "kind: manual\nlocation: { repo: r, ref: c }\n\
         deps: pip install build\nbuild: \"cat <<'EOF' > x\\n{{ not_a_template }}\\nEOF\"\n",
    )
    .unwrap();
    let i = render(&manual, &cx(), &tools).unwrap();
    assert!(
        i.build.contains("{{ not_a_template }}"),
        "a manual script is raw shell and is never run through the template engine: {}",
        i.build
    );
    assert_eq!(i.deps, "pip install build");
    assert!(
        i.source.is_empty(),
        "pinned, not endorsed: a manual strategy renders no source phase, so nothing inside the \
         build verifies the tree is at the commit its provenance names. A flow's git-checkout does. \
         If this starts failing because manual grew a source phase, that is an improvement — delete \
         the assertion and say so."
    );
    assert_eq!(
        i.location.commit, "c",
        "the provenance carries it regardless"
    );
}
