//! `yarn <script>` is `npm run <script>` by another name.
//!
//! A deterministic repair rung, in the sense [`docs/13-roadmap.md`](../../../docs/13-roadmap.md)'s
//! M3 means: a rule that lowers the model-invocation rate by answering a failure outright, before
//! any provider is configured and without spending a token.
//!
//! **The distinction that matters is what `yarn` is being asked to do.** As a *resolver* —
//! `yarn install`, `yarn add`, anything reading a `yarn.lock` — it is genuinely unsupported, and
//! `trigon-core`'s rule table is right to say so: installing some yarn and running it produces a
//! verdict about a build the publisher never did. As a *task runner*, `yarn umd` is
//! `npm run umd` and nothing else. Same script, same binaries from the same pinned dependency
//! tree, same versions. Rewriting it changes who types the command, not what runs.
//!
//! From `prop-types@15.8.1`, whose published `package.json` is the case this was written for:
//!
//! ```text
//! umd        NODE_ENV=development browserify index.js -t loose-envify --standalone PropTypes …
//! umd-min    NODE_ENV=production  browserify index.js -t loose-envify -t uglifyify …
//! build      yarn umd && yarn umd-min
//! ```
//!
//! A strategy that runs `npm run build` reaches `yarn` two levels down and dies with
//! `sh: 1: yarn: not found`. The work is browserify, pinned in `devDependencies`; yarn is doing
//! nothing a rewrite cannot do exactly.

use std::collections::BTreeMap;
use std::path::Path;

use crate::{Step, StepBody, Strategy};

/// How far an expansion will follow one script into another.
///
/// `build: yarn umd` → `umd: yarn raw` is a chain worth following; a cycle is not, and a package
/// can contain one. Two is enough for every real case and terminates on all of them.
const MAX_DEPTH: u8 = 3;

/// The `scripts` block of a checkout's `package.json`.
///
/// The **checkout's**, not the published artifact's: the failing command came from the repository
/// the build ran in, and the two can differ. Empty where there is no manifest, no `scripts`, or
/// nothing readable — all of which mean the same thing here, that there is nothing to rewrite with.
pub fn scripts_from_checkout(checkout: &Path) -> BTreeMap<String, String> {
    let Ok(text) = std::fs::read_to_string(checkout.join("package.json")) else {
        return BTreeMap::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return BTreeMap::new();
    };
    v.get("scripts")
        .and_then(|s| s.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// The same strategy with every yarn task-runner call rewritten, or `None` when there is nothing
/// to do or a yarn call is not a task-runner call.
///
/// `None` rather than a partially-rewritten strategy: a recipe that runs `yarn install` and
/// `yarn umd` needs yarn, and rewriting half of it produces something that fails later and looks
/// like a different problem.
pub fn without_yarn(strategy: &Strategy, scripts: &BTreeMap<String, String>) -> Option<Strategy> {
    if scripts.is_empty() {
        return None;
    }
    let mut next = strategy.clone();
    let mut changed = false;

    let phases: Vec<&mut Vec<Step>> = match &mut next {
        Strategy::Flow(f) => vec![&mut f.src, &mut f.deps, &mut f.build],
        // A manual strategy is raw scripts, which is what a model emits. Same rewrite, different
        // shape.
        Strategy::Manual(m) => {
            for script in [&mut m.deps, &mut m.build] {
                let rewritten = rewrite(script.as_str(), scripts, 0)?;
                if rewritten != *script {
                    *script = rewritten;
                    changed = true;
                }
            }
            return changed.then_some(next);
        }
        _ => return None,
    };

    for steps in phases {
        for step in steps.iter_mut() {
            let StepBody::Runs(script) = &step.body else {
                continue;
            };
            let rewritten = rewrite(script, scripts, 0)?;
            if &rewritten != script {
                step.body = StepBody::Runs(rewritten);
                changed = true;
            }
        }
    }
    changed.then_some(next)
}

/// One shell fragment, with `yarn` taken out of it.
///
/// `None` where a `yarn` call is not a task-runner call, which is the whole safety property: this
/// must never turn `yarn install` into something that looks like it worked.
fn rewrite(cmd: &str, scripts: &BTreeMap<String, String>, depth: u8) -> Option<String> {
    if depth >= MAX_DEPTH {
        return None;
    }
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let mut out: Vec<String> = Vec::with_capacity(words.len());
    let mut i = 0usize;

    while i < words.len() {
        let w = words[i];
        // `yarn run x` and `yarn x` are the same call. Anything else — `install`, `add`, a flag —
        // is yarn doing something only yarn does.
        if w == "yarn" {
            let (name, skip) = match words.get(i + 1) {
                Some(&"run") => (words.get(i + 2).copied(), 3),
                Some(other) => (Some(*other), 2),
                None => (None, 1),
            };
            out.push(invoke(name?, scripts, depth)?);
            i += skip;
            continue;
        }
        // `npm run <s>` where `<s>` itself reaches yarn. Expanding it is what actually fixes
        // `prop-types`, whose strategy never mentions yarn — `build` does, two levels down.
        if w == "npm"
            && words.get(i + 1) == Some(&"run")
            && let Some(name) = words.get(i + 2)
            && reaches_yarn(name, scripts)
        {
            out.push(invoke(name, scripts, depth)?);
            i += 3;
            continue;
        }
        out.push(w.to_string());
        i += 1;
    }
    Some(out.join(" "))
}

/// How to run one named script without yarn.
///
/// **Not simply `npm run <name>`.** That is right only when the script's own body does not reach
/// yarn — `umd` is browserify and rewrites cleanly, while `build` is `yarn umd && yarn umd-min`
/// and `npm run build` would find yarn again one level down. A script that reaches yarn is
/// expanded into what it would have run.
fn invoke(name: &str, scripts: &BTreeMap<String, String>, depth: u8) -> Option<String> {
    let body = scripts.get(name)?;
    if !reaches_yarn(name, scripts) {
        return Some(format!("npm run {name}"));
    }
    // Parenthesised, because an expansion carrying `&&` into the middle of a larger command would
    // otherwise rebind what follows it.
    Some(format!("( {} )", rewrite(body, scripts, depth + 1)?))
}

/// Whether running this script would invoke yarn directly.
fn reaches_yarn(name: &str, scripts: &BTreeMap<String, String>) -> bool {
    scripts
        .get(name)
        .is_some_and(|b| b.split_whitespace().any(|t| t == "yarn"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `prop-types@15.8.1`, from the published artifact's own `package.json`.
    fn prop_types() -> BTreeMap<String, String> {
        [
            ("umd", "NODE_ENV=development browserify index.js -t loose-envify --standalone PropTypes -o prop-types.js"),
            ("umd-min", "NODE_ENV=production browserify index.js -t loose-envify -t uglifyify --standalone PropTypes -o prop-types.min.js"),
            ("build", "yarn umd && yarn umd-min"),
            ("prepublish", "not-in-publish || yarn build"),
            ("test", "npm run tests-only"),
            ("tests-only", "jest"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    fn a_yarn_task_runner_call_becomes_npm_run() {
        let s = prop_types();
        // `yarn build` is not `npm run build`: `build` is itself `yarn umd && yarn umd-min`, so
        // the rewrite has to go through it rather than hand yarn to npm.
        assert_eq!(
            rewrite("yarn build", &s, 0).as_deref(),
            Some("( npm run umd && npm run umd-min )")
        );
        assert_eq!(
            rewrite("yarn umd && yarn umd-min", &s, 0).as_deref(),
            Some("npm run umd && npm run umd-min")
        );
        // `yarn run x` is the same call spelled longer.
        assert_eq!(
            rewrite("yarn run umd", &s, 0).as_deref(),
            Some("npm run umd")
        );
    }

    /// The case that actually fires: the strategy never mentions yarn.
    #[test]
    fn npm_run_reaching_yarn_two_levels_down_is_expanded() {
        let s = prop_types();
        assert_eq!(
            rewrite("npm run build", &s, 0).as_deref(),
            Some("( npm run umd && npm run umd-min )"),
            "the strategy runs `npm run build`; `build` is what reaches yarn"
        );
    }

    /// **The safety property.** yarn resolving is not yarn running, and this must never make the
    /// first look like it worked.
    #[test]
    fn yarn_as_a_resolver_is_refused() {
        let s = prop_types();
        for cmd in [
            "yarn install",
            "yarn install --frozen-lockfile",
            "yarn add lodash",
            "yarn --version",
            "yarn",
        ] {
            assert_eq!(
                rewrite(cmd, &s, 0),
                None,
                "`{cmd}` is yarn doing something only yarn does"
            );
        }
    }

    #[test]
    fn a_script_that_does_not_exist_is_not_a_task_runner_call() {
        // `yarn frobnicate` where nothing declares `frobnicate` is not a call we can rewrite, and
        // guessing would turn a clear failure into a confusing one.
        assert_eq!(rewrite("yarn frobnicate", &prop_types(), 0), None);
    }

    #[test]
    fn a_command_with_no_yarn_in_it_is_returned_unchanged() {
        let s = prop_types();
        for cmd in ["npm run tests-only", "npm pack", "make all"] {
            assert_eq!(rewrite(cmd, &s, 0).as_deref(), Some(cmd));
        }
    }

    /// A package can declare a cycle. Following it for ever is not an option.
    #[test]
    fn a_cycle_between_scripts_terminates() {
        let s: BTreeMap<String, String> = [("a", "yarn b"), ("b", "yarn a")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // Both forms follow the cycle and both stop rather than recursing. `npm run a` is not a
        // fix here either: `a` reaches yarn, so it has to be expanded, and expanding it arrives
        // back at `a`.
        assert_eq!(rewrite("yarn a", &s, 0), None);
        assert_eq!(rewrite("npm run a", &s, 0), None);
    }

    #[test]
    fn a_strategy_is_rewritten_phase_by_phase() {
        use crate::{FlowStrategy, Location, StepBody};
        let flow = FlowStrategy {
            location: Location {
                repo: "https://example.invalid/x".into(),
                git_ref: "aa".into(),
                subdir: None,
            },
            src: vec![],
            deps: vec![],
            build: vec![
                Step {
                    body: StepBody::Runs("npm run build".into()),
                    needs: vec![],
                    when: None,
                },
                Step {
                    body: StepBody::Uses {
                        tool: "npm/build/pack".into(),
                        with: Default::default(),
                    },
                    needs: vec![],
                    when: None,
                },
            ],
            output_dir: Some(".".into()),
            output_path: Some("*.tgz".into()),
        };
        let before = Strategy::Flow(flow);
        let after = without_yarn(&before, &prop_types()).expect("something to rewrite");
        let Strategy::Flow(f) = &after else {
            panic!("shape changed")
        };
        assert_eq!(
            f.build[0].body,
            StepBody::Runs("( npm run umd && npm run umd-min )".into())
        );
        // The tool step is untouched: it never mentioned yarn.
        assert!(matches!(f.build[1].body, StepBody::Uses { .. }));
    }

    #[test]
    fn nothing_to_rewrite_is_none_rather_than_an_identical_strategy() {
        // The caller uses `Some` to mean "try this instead". Returning an unchanged strategy would
        // make the repair loop spend an iteration rebuilding exactly what just failed.
        use crate::{FlowStrategy, Location, StepBody};
        let flow = FlowStrategy {
            location: Location {
                repo: "https://example.invalid/x".into(),
                git_ref: "aa".into(),
                subdir: None,
            },
            src: vec![],
            deps: vec![],
            build: vec![Step {
                body: StepBody::Runs("npm pack".into()),
                needs: vec![],
                when: None,
            }],
            output_dir: None,
            output_path: None,
        };
        assert!(without_yarn(&Strategy::Flow(flow), &prop_types()).is_none());
    }
}
