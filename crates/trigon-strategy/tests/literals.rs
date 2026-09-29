//! What a step carries from outside the strategy is data, never template source.
//!
//! A step's `runs`, `if` and `with` values are minijinja templates, which is what lets a strategy
//! author write `{{ intrinsics.publish_time }}`. A rung that copied the package's own text into one
//! of them — a copyright read out of the published assembly, a script body read from the checkout's
//! `package.json` — had that text evaluated: the package under test was writing part of its own
//! build recipe. `literal:` is where such a value goes instead, and these tests hold both halves of
//! that: the package's text arrives exactly, and the author's templates still render.

use std::collections::BTreeMap;

use trigon_strategy::{
    AssemblyVersionInfo, Context, EnvCtx, IntrinsicsCtx, LocationCtx, Step, StepBody, Strategy,
    Tool, ToolParam, ToolRegistry, from_yaml, render, to_yaml, with_assembly_version,
};

const PACK: &str = "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  \
                    ref: aa\n  subdir: src/Castle.Core\nbuild:\n  - uses: nuget/build/pack\n    \
                    with:\n      version: 5.1.1\noutput_dir: trigon-pack\n\
                    output_path: trigon-pack/*.nupkg\n";

fn cx() -> Context {
    Context {
        location: LocationCtx {
            repo: "https://example.invalid/x".into(),
            git_ref: "aa".into(),
            subdir: "src/Castle.Core".into(),
        },
        env: EnvCtx {
            arch: "x86_64".into(),
            platform: "linux".into(),
            has_repo: true,
            timewarp_base: "timewarp:8129".into(),
            ..Default::default()
        },
        intrinsics: IntrinsicsCtx {
            publish_time: "2022-04-01T10:11:12Z".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn build_of(s: &Strategy) -> String {
    render(s, &cx(), &ToolRegistry::builtin().expect("registry"))
        .expect("renders")
        .build
}

/// The one argument the build script's `-p:<prop>=` line hands `dotnet`, run through `sh` as the
/// build runs it.
fn argument(build: &str, prop: &str) -> String {
    let needle = format!("-p:{prop}=");
    let lines: Vec<&str> = build
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("set -- \"$@\" ") && l.contains(&needle))
        .collect();
    let [line] = lines.as_slice() else {
        panic!("expected one line setting {prop}, got {lines:?} in:\n{build}");
    };
    let script = format!("set --\n{line}\nprintf '%s\\0' \"$@\"\n");
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(&script)
        .env_clear()
        .env("HOME", "/nonexistent-home")
        .current_dir(std::env::temp_dir())
        .output()
        .expect("sh runs");
    assert!(
        out.status.success(),
        "{script}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let argv: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .split_terminator('\0')
        .map(str::to_string)
        .collect();
    let [arg] = argv.as_slice() else {
        panic!("{script} gave {argv:?}");
    };
    arg.strip_prefix(&needle)
        .unwrap_or_else(|| panic!("{arg}"))
        .to_string()
}

/// What MSBuild makes of a `-p:` value: each `%XX` is the byte it names. Refuses a value MSBuild
/// would split, since a property that was split was never set to the value at all.
fn as_msbuild_reads_it(value: &str) -> String {
    assert!(
        !value.contains([';', ',']),
        "MSBuild splits a -p: value on `;` and `,`: {value}"
    );
    let mut out = Vec::new();
    let b = value.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(hex) = value.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

/// **The finding, as a test.** A copyright read out of the published assembly — ILSpy writes it
/// with its braces as they are — holding each of the three things minijinja reads: an expression
/// that would render as `49`, a statement that fails the render, and a comment that is never
/// closed. With the MSBuild punctuation it splits or decodes on, a quote of each kind, and what a
/// shell or MSBuild would expand. It reaches `dotnet` as the one argument that sets the property
/// to exactly that text, and none of it is evaluated.
#[test]
fn a_copyright_reaches_the_dotnet_invocation_byte_for_byte_and_is_never_evaluated() {
    let copyright = "© 2004 {{ 7*7 }} {% if %} {# Castle; a,b 100%3B \"q\" it's @(I) $(P) \\";
    let info = AssemblyVersionInfo {
        version: Some("5.1.1".into()),
        informational_version: Some("5.1.1 {{ 7*7 }}".into()),
        copyright: Some(copyright.into()),
        ..Default::default()
    };
    let s = with_assembly_version(&from_yaml(PACK).unwrap(), &info).expect("the stamps are set");
    let build = build_of(&s);
    let properties: Vec<&str> = build.lines().filter(|l| l.contains("'-p:")).collect();
    assert!(
        !properties.iter().any(|l| l.contains("49")),
        "a stamp was evaluated: {properties:#?}"
    );

    let got = argument(&build, "Copyright");
    assert_eq!(
        got,
        "© 2004 {{ 7*7 }} {%25 if %25} {# Castle%3B a%2Cb 100%253B %22q%22 it's %40(I) $(P) \\"
    );
    assert_eq!(as_msbuild_reads_it(&got), copyright);
    assert_eq!(
        as_msbuild_reads_it(&argument(&build, "InformationalVersion")),
        "5.1.1 {{ 7*7 }}"
    );
}

/// Where a value sits decides whether it is evaluated, and nothing else does: the same text as a
/// literal is passed as it is, and as a `with` value — the author's template — is rendered, as it
/// always was.
#[test]
fn a_literal_is_passed_as_written_where_the_same_text_in_with_is_rendered() {
    let literal = PACK.replace(
        "    with:\n      version: 5.1.1\n",
        "    literal:\n      copyright: '{{ 7*7 }}'\n",
    );
    let with = PACK.replace("      version: 5.1.1\n", "      copyright: '{{ 7*7 }}'\n");
    assert_eq!(
        argument(&build_of(&from_yaml(&literal).unwrap()), "Copyright"),
        "{{ 7*7 }}"
    );
    assert_eq!(
        argument(&build_of(&from_yaml(&with).unwrap()), "Copyright"),
        "49"
    );
}

/// The templates an author writes still render: a `with` value forwarding the publish time, which
/// the definitions and the tools lean on throughout, beside literals on the same step; and a
/// `runs` step reading a literal by name, which prints it without evaluating it.
#[test]
fn an_authored_template_still_renders_beside_a_literal() {
    let s = from_yaml(
        "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
         deps:\n  - uses: npm/deps/custom\n    with:\n      \
         registry_time: '{{ intrinsics.publish_time }}'\n    literal:\n      \
         node_version: 18.17.1\n      npm_version: 9.6.7\n\
         build:\n  - runs: 'echo {{ literal.note }} for {{ location.repo }}'\n    literal:\n      \
         note: '{{ 7*7 }} {% if %}'\noutput_path: '*.tgz'\n",
    )
    .expect("parses");
    let i = render(&s, &cx(), &ToolRegistry::builtin().unwrap()).expect("renders");
    assert!(i.deps.contains("2022-04-01T10:11:12Z"), "{}", i.deps);
    assert!(
        i.deps.contains("18.17.1") && i.deps.contains("9.6.7"),
        "{}",
        i.deps
    );
    assert_eq!(
        i.build,
        "echo {{ 7*7 }} {% if %} for https://example.invalid/x"
    );
}

/// A parameter is a template or a literal. Given both ways, which value the tool received would
/// depend on the order two maps were merged in, so it is refused — when the document is parsed,
/// and when a step built in code is rendered.
#[test]
fn a_parameter_given_both_ways_is_refused_when_parsed_and_when_rendered() {
    let both = PACK.replace(
        "      version: 5.1.1\n",
        "      version: 5.1.1\n    literal:\n      version: 5.1.2\n",
    );
    let e = from_yaml(&both).expect_err("refused");
    assert!(e.to_string().contains("given both in `with`"), "{e}");

    let Strategy::Flow(mut f) = from_yaml(PACK).unwrap() else {
        panic!("flow")
    };
    f.build[0].literal.insert("version".into(), "5.1.2".into());
    let e =
        render(&Strategy::Flow(f), &cx(), &ToolRegistry::builtin().unwrap()).expect_err("refused");
    assert!(e.to_string().contains("given both in `with`"), "{e}");
}

/// A literal is a parameter like any other: one the tool does not declare is refused by name.
#[test]
fn a_literal_the_tool_does_not_declare_is_refused() {
    let s = PACK.replace(
        "      version: 5.1.1\n",
        "      version: 5.1.1\n    literal:\n      copyrite: x\n",
    );
    let e = render(
        &from_yaml(&s).unwrap(),
        &cx(),
        &ToolRegistry::builtin().unwrap(),
    )
    .expect_err("refused");
    assert!(e.to_string().contains("no parameter copyrite"), "{e}");
}

fn runs(template: &str) -> Step {
    Step {
        body: StepBody::Runs(template.into()),
        needs: Vec::new(),
        when: None,
        literal: BTreeMap::new(),
    }
}

/// A literal belongs to the step that carries it. The tool it calls receives it as a parameter,
/// through `with`; the tool's own steps never see their caller's `literal`, so a value is never
/// read somewhere its step did not put it.
#[test]
fn a_tool_receives_a_literal_as_a_parameter_and_never_sees_its_callers_literals() {
    let mut tools = ToolRegistry::new();
    for (id, template) in [
        ("t/param", "echo {{ with.x }}"),
        ("t/peek", "echo {{ literal.x }}"),
    ] {
        tools
            .add(Tool {
                id: id.into(),
                params: BTreeMap::from([("x".to_string(), ToolParam::default())]),
                needs: Vec::new(),
                steps: vec![runs(template)],
            })
            .unwrap();
    }
    let call = |tool: &str| {
        from_yaml(&format!(
            "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
             build:\n  - uses: {tool}\n    literal:\n      x: '{{{{ 7*7 }}}}'\n\
             output_path: '*.tgz'\n"
        ))
        .unwrap()
    };
    assert_eq!(
        render(&call("t/param"), &cx(), &tools).unwrap().build,
        "echo {{ 7*7 }}"
    );
    let e = render(&call("t/peek"), &cx(), &tools).expect_err("not the tool's to read");
    assert!(e.to_string().contains("undefined"), "{e}");
}

/// A strategy that carries no literal serializes as it did before the field existed, so its
/// canonical form and its digest did not move; one that carries them keeps them through the text a
/// reviewer reads.
#[test]
fn literals_round_trip_and_a_strategy_without_them_is_unchanged() {
    let plain = from_yaml(PACK).unwrap();
    let canonical = trigon_strategy::canonical(&plain).unwrap();
    assert!(!canonical.contains("literal"), "{canonical}");

    let info = AssemblyVersionInfo {
        copyright: Some("{{ a }}{% endraw %}{# b".into()),
        ..Default::default()
    };
    let s = with_assembly_version(&plain, &info).unwrap();
    let text = to_yaml(&s).unwrap();
    assert!(text.contains("literal:"), "{text}");
    assert_eq!(from_yaml(&text).unwrap(), s, "{text}");
}

/// **A document with literals declares the schema that added them.** A build that knows only
/// schema 1 refuses a document declaring 2 as newer than it understands, which tells its reader to
/// upgrade; given the same document declaring 1, it stumbled on `literal` as an unknown field. So
/// the YAML a reviewer reads and the canonical JSON a record names both say 2 — and a strategy
/// without literals still says 1, and still has the canonical form, and so the digest, it had.
#[test]
fn a_strategy_with_literals_declares_schema_two_and_one_without_still_declares_one() {
    let plain = from_yaml(PACK).unwrap();
    assert_eq!(plain.schema(), 1);
    assert!(to_yaml(&plain).unwrap().starts_with("schema: 1\n"));
    let canonical = trigon_strategy::canonical(&plain).unwrap();
    assert!(!canonical.contains("schema"), "{canonical}");

    let info = AssemblyVersionInfo {
        copyright: Some("{{ 7*7 }}".into()),
        ..Default::default()
    };
    let s = with_assembly_version(&plain, &info).unwrap();
    assert_eq!(s.schema(), 2);
    let text = to_yaml(&s).unwrap();
    assert!(text.starts_with("schema: 2\n"), "{text}");
    assert_eq!(from_yaml(&text).unwrap(), s, "{text}");

    // The stored form: it says 2, it reads back as the same strategy, and it is canonical as it
    // stands, which is what a record's `strategy.json` is checked for before it is signed.
    let json = trigon_strategy::canonical(&s).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["schema"], 2, "{json}");
    let back = from_yaml(&json).unwrap();
    assert_eq!(back, s);
    assert_eq!(trigon_strategy::canonical(&back).unwrap(), json);

    // This build reads both, including a literal under a declared 1, which is how a model shown
    // the shape as schema 1 writes one; and it refuses the schema after its own by name.
    let declared_one = text.replacen("schema: 2", "schema: 1", 1);
    assert_eq!(from_yaml(&declared_one).unwrap(), s);
    let e = from_yaml(&text.replacen("schema: 2", "schema: 3", 1)).unwrap_err();
    assert!(e.to_string().contains("highest known: 2"), "{e}");
}
