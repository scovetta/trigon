//! Rendering: a pure function of `(strategy, context, tools)`.
//!
//! Four settings depart from `minijinja`'s defaults, each blocking a class of silent wrongness.
//! See `docs/04-strategies.md` §3.2.
//!
//! 1. `UndefinedBehavior::Strict`. A typo'd `{{ targt.version }}` renders empty by default, which
//!    turns into `pip install ==` and a failure nobody can trace back to the typo. Here it is an
//!    error naming the variable.
//! 2. `BTreeMap` everywhere in the context, because `minijinja` preserves insertion order when a
//!    template ranges a map and the rendered script feeds `strategy_digest`.
//! 3. A closed context type: strings, integers, booleans, lists and maps. No floats, whose
//!    formatting varies, and no time values, since a template that reads a clock is not a pure
//!    function of its inputs.
//! 4. Render once, here, and store the result. The executor never re-renders.

use std::collections::{BTreeMap, BTreeSet};

use minijinja::{Environment, UndefinedBehavior, Value};

use crate::context::Context;
use crate::error::StrategyError;
use crate::instructions::{Instructions, Requirements, SourceProvenance};
use crate::model::{FlowStrategy, ManualStrategy, Step, StepBody, Strategy};
use crate::tool::ToolRegistry;

/// How deep tool composition may go before we call it a runaway.
///
/// The registry rejects cycles at load time, so this only catches a legal but absurd chain. It is
/// a backstop, not the mechanism.
const MAX_TOOL_DEPTH: usize = 16;

/// Render a strategy to instructions.
#[tracing::instrument(level = "debug", skip_all, fields(repo = s.location().map(|l| l.repo.as_str())))]
pub fn render(
    s: &Strategy,
    cx: &Context,
    tools: &ToolRegistry,
) -> Result<Instructions, StrategyError> {
    match s {
        Strategy::Flow(f) => render_flow(f, cx, tools),
        Strategy::Manual(m) => Ok(render_manual(m, cx)),
        Strategy::LocationHint(_) => Err(StrategyError::Invalid(
            "a location_hint seeds inference and cannot be executed: it says where the source is, \
             not how to build it"
                .into(),
        )),
        Strategy::Prebuilt(_) => Err(StrategyError::Invalid(
            "a prebuilt strategy is fetched rather than rendered; it has no build to run".into(),
        )),
    }
}

fn render_flow(
    f: &FlowStrategy,
    cx: &Context,
    tools: &ToolRegistry,
) -> Result<Instructions, StrategyError> {
    let env = environment(cx);
    let mut needs: BTreeSet<String> = BTreeSet::new();

    let phase = |name: &str, steps: &[Step], needs: &mut BTreeSet<String>| {
        expand(&env, steps, cx, tools, needs, 0).map_err(|e| prefix(name, e))
    };

    let source = phase("src", &f.src, &mut needs)?;
    let deps = phase("deps", &f.deps, &mut needs)?;
    let build = phase("build", &f.build, &mut needs)?;

    Ok(Instructions {
        location: SourceProvenance::from(&f.location),
        source,
        deps,
        build,
        output_path: output_path(f.output_dir.as_deref(), f.output_path.as_deref()),
        requires: Requirements {
            system_deps: needs,
            privileged: false,
        },
    })
}

fn render_manual(m: &ManualStrategy, _cx: &Context) -> Instructions {
    // Deliberately not rendered. A manual strategy is raw shell, which is what a model emits before
    // anything has been lifted into a tool, and running it through a template engine would give
    // `{{` in a here-doc a meaning the author did not intend.
    Instructions {
        location: SourceProvenance::from(&m.location),
        source: String::new(),
        deps: m.deps.clone(),
        build: m.build.clone(),
        output_path: output_path(m.output_dir.as_deref(), m.output_path.as_deref()),
        requires: Requirements::default(),
    }
}

fn output_path(dir: Option<&str>, path: Option<&str>) -> String {
    match (dir, path) {
        (_, Some(p)) => p.to_string(),
        (Some(d), None) => format!("{}/*", d.trim_end_matches('/')),
        (None, None) => "*".to_string(),
    }
}

/// Expand a phase's steps into one script, resolving tools as it goes.
fn expand(
    env: &Environment<'static>,
    steps: &[Step],
    cx: &Context,
    tools: &ToolRegistry,
    needs: &mut BTreeSet<String>,
    depth: usize,
) -> Result<String, StrategyError> {
    if depth > MAX_TOOL_DEPTH {
        return Err(StrategyError::Invalid(format!(
            "tool composition went deeper than {MAX_TOOL_DEPTH} levels"
        )));
    }
    let mut out: Vec<String> = Vec::new();

    for (i, step) in steps.iter().enumerate() {
        let at = |e: StrategyError| prefix(&format!("[{i}]"), e);

        if let Some(cond) = &step.when {
            let rendered = render_str(env, cond, cx).map_err(at)?;
            let t = rendered.trim();
            if t.is_empty() || t == "false" {
                continue;
            }
        }
        needs.extend(step.needs.iter().cloned());

        match &step.body {
            StepBody::Runs(template) => {
                // Trimmed at both ends. Template whitespace control leaves a leading newline
                // whenever a fragment opens with a conditional, and these bytes are hashed into
                // strategy_digest, so "harmless to a shell" is not the standard.
                let s = render_str(env, template, cx).map_err(at)?;
                if !s.trim().is_empty() {
                    out.push(s.trim().to_string());
                }
            }
            StepBody::Uses { tool, with } => {
                let t = tools.get(tool).ok_or_else(|| {
                    at(StrategyError::Invalid(format!(
                        "uses `{tool}`, which is not a registered tool. Known: {}",
                        tools.ids().collect::<Vec<_>>().join(", ")
                    )))
                })?;

                // Parameters are themselves templates, so a composite tool can forward its own
                // `with` down to the tool it wraps.
                let mut resolved: BTreeMap<String, String> = BTreeMap::new();
                for (k, v) in with {
                    resolved.insert(k.clone(), render_str(env, v, cx).map_err(&at)?);
                }
                for (name, p) in &t.params {
                    if let Some(d) = &p.default
                        && !resolved.contains_key(name)
                    {
                        resolved.insert(name.clone(), d.clone());
                    }
                }
                tools.check_params(t, &resolved).map_err(&at)?;

                // Every declared parameter is defined, empty when the caller omitted it. Strict
                // undefined-handling is what makes a typo an error, and it would otherwise make an
                // optional parameter unusable: `{% if with.crlf %}` is the idiom for "the caller
                // may not have said", and it has to be askable. A name the tool does not declare is
                // still undefined, and `check_params` above has already rejected it.
                for name in t.params.keys() {
                    resolved.entry(name.clone()).or_default();
                }

                needs.extend(t.needs.iter().cloned());
                let inner = Context {
                    with: resolved,
                    ..cx.clone()
                };
                let s = expand(env, &t.steps, &inner, tools, needs, depth + 1)
                    .map_err(|e| at(prefix(tool, e)))?;
                if !s.trim().is_empty() {
                    out.push(s.trim().to_string());
                }
            }
        }
    }
    Ok(out.join("\n"))
}

fn render_str(
    env: &Environment<'static>,
    template: &str,
    cx: &Context,
) -> Result<String, StrategyError> {
    env.render_str(template, cx)
        .map_err(|e| StrategyError::Template(template_message(&e)))
}

/// `minijinja` errors carry a cause chain, and the cause is usually the useful half.
fn template_message(e: &minijinja::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut cur: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(c) = cur {
        parts.push(c.to_string());
        cur = std::error::Error::source(c);
    }
    parts.join(": ")
}

fn prefix(what: &str, e: StrategyError) -> StrategyError {
    match e {
        StrategyError::Field { path, message } => StrategyError::Field {
            path: format!("{what}.{path}"),
            message,
        },
        other => StrategyError::Field {
            path: what.to_string(),
            message: other.to_string(),
        },
    }
}

fn environment(cx: &Context) -> Environment<'static> {
    let mut env = Environment::new();
    // The setting that turns a typo from a mystifying build failure into an error naming it.
    env.set_undefined_behavior(UndefinedBehavior::Strict);

    env.add_filter(
        "from_json",
        |s: String| -> Result<Value, minijinja::Error> {
            if s.trim().is_empty() {
                return Ok(Value::from(Vec::<Value>::new()));
            }
            serde_json::from_str::<serde_json::Value>(&s)
                .map(|v| Value::from_serialize(&v))
                .map_err(|e| {
                    minijinja::Error::new(
                        minijinja::ErrorKind::InvalidOperation,
                        format!("from_json: {e}"),
                    )
                })
        },
    );
    env.add_filter("to_json", |v: Value| -> Result<String, minijinja::Error> {
        serde_json::to_string(&v).map_err(|e| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                format!("to_json: {e}"),
            )
        })
    });
    // Named for what it does rather than `regex_replace` with a quoting pattern at every call site.
    // Shell quoting is the one thing these templates actually need a regex for, and getting it
    // wrong is a command injection rather than a typo.
    env.add_filter("shell_single_quote", |s: String| s.replace('\'', r"'\''"));
    env.add_filter("indent", |s: String, n: usize| {
        let pad = " ".repeat(n);
        s.lines()
            .map(|l| {
                if l.is_empty() {
                    String::new()
                } else {
                    format!("{pad}{l}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    });

    // A pure function of its arguments and the configured mirror. Not a network call, and not a
    // clock: the moment is passed in.
    let base = cx.env.timewarp_base.clone();
    env.add_function(
        "timewarp_url",
        move |ecosystem: String, moment: String| -> Result<String, minijinja::Error> {
            let Some(base) = &base else {
                return Err(minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    "timewarp_url was called but no mirror is configured for this run. A build \
                     that pins a registry moment needs one, or it resolves against the live index.",
                ));
            };
            Ok(format!("{}://{ecosystem}:{moment}@{}", "http", base))
        },
    );

    // A toolchain download, routed through the mirror when there is one.
    //
    // Unlike `timewarp_url` this has a correct answer when no mirror is configured — the upstream
    // URL — because a toolchain URL names an exact version and there is no moment to pin it to.
    // What it fixes is the tier where there *is* a mirror: the deps phase runs inside the network
    // island, the mirror is the only host in there, and a template that writes `https://nodejs.org`
    // produces a build that dies at `Network is unreachable` after the image is built. The mirror
    // refuses any host outside its own allowlist, so this is a rewrite and not a hole.
    let base = cx.env.timewarp_base.clone();
    env.add_function(
        "toolchain_url",
        move |host: String, path: String| -> String {
            let path = path.trim_start_matches('/');
            match &base {
                Some(base) => format!("http://{base}/-toolchain/{host}/{path}"),
                None => format!("https://{host}/{path}"),
            }
        },
    );

    // The mirror's `host:port`, with no scheme and no credentials.
    //
    // pip **silently ignores** a plain-HTTP index that is not also a trusted host: it prints a
    // warning and resolves as though no index were configured. Every PyPI rebuild that pinned a
    // registry moment was therefore resolving against the live index, and the only sign was the
    // mirror reporting zero requests. A client that needs this needs the bare authority, which the
    // URL form cannot supply without string surgery in a template.
    let base = cx.env.timewarp_base.clone();
    env.add_function(
        "timewarp_host",
        move || -> Result<String, minijinja::Error> {
            base.clone().ok_or_else(|| {
                minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    "timewarp_host was called but no mirror is configured for this run.",
                )
            })
        },
    );
    env
}
