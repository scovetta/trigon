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
        // shape — and inlined, since a manual strategy is never rendered.
        Strategy::Manual(m) => {
            for script in [&mut m.deps, &mut m.build] {
                let rewritten = rewrite(script.as_str(), scripts, 0, &mut Splice::Inline)?;
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
            let mut literal = step.literal.clone();
            let rewritten = rewrite(script, scripts, 0, &mut Splice::Literal(&mut literal))?;
            if &rewritten != script {
                step.body = StepBody::Runs(rewritten);
                step.literal = literal;
                changed = true;
            }
        }
    }
    changed.then_some(next)
}

/// Where the expansion of a script goes.
///
/// **A `runs` step is a template, and a script body is the repository's text.** Spliced into the
/// step, `"build": "echo {{ 7*7 }}"` in a checkout's `package.json` was rendered as the template it
/// looks like — `echo 49` — or failed the render on a name that is not defined, so the repository
/// under test chose what its own build recipe said. Into a template the expansion is a literal of
/// the step instead, which the template prints by name and never evaluates. A manual strategy is
/// raw shell that is never rendered, so there it is spliced in as it is.
enum Splice<'a> {
    Inline,
    Literal(&'a mut BTreeMap<String, String>),
}

/// One shell fragment, with `yarn` taken out of it.
///
/// `None` where a `yarn` call is not a task-runner call, which is the whole safety property: this
/// must never turn `yarn install` into something that looks like it worked.
///
/// **Line by line, and only the call is replaced.** Everything else is copied through as it was —
/// newlines, indentation, the spacing between words — because a step is shell, and a newline in it
/// ends a command. Split on whitespace and joined with spaces, a multi-line `runs: |` step became
/// one line, `cd pkg npm ci ( npm run umd && npm run umd-min )`, which `sh` refuses at the `(`: the
/// rung spent a build on a syntax error, and the failure was reported against the package. A step
/// with no yarn in it came back respaced, which read as a change. A call does not run on into the
/// next line either: `yarn` alone at the end of one is `yarn install`, as it is to the shell.
fn rewrite(
    cmd: &str,
    scripts: &BTreeMap<String, String>,
    depth: u8,
    splice: &mut Splice<'_>,
) -> Option<String> {
    if depth >= MAX_DEPTH {
        return None;
    }
    let mut out = String::with_capacity(cmd.len());
    for line in cmd.split_inclusive('\n') {
        let words = words_of(line);
        let word = |i: usize| words.get(i).map(|&(_, w)| w);
        // How far into `line` has been written to `out`.
        let mut copied = 0usize;
        let mut i = 0usize;

        while let Some(w) = word(i) {
            // `yarn run x` and `yarn x` are the same call. Anything else — `install`, `add`, a
            // flag — is yarn doing something only yarn does.
            let (name, take) = if w == "yarn" {
                match word(i + 1) {
                    Some("run") => (word(i + 2), 3),
                    Some(other) => (Some(other), 2),
                    None => (None, 1),
                }
            // `npm run <s>` where `<s>` itself reaches yarn. Expanding it is what actually fixes
            // `prop-types`, whose strategy never mentions yarn — `build` does, two levels down.
            } else if w == "npm"
                && word(i + 1) == Some("run")
                && let Some(name) = word(i + 2)
                && reaches_yarn(name, scripts)
            {
                (Some(name), 3)
            } else {
                i += 1;
                continue;
            };
            let replacement = invoke(name?, scripts, depth, splice)?;
            let (start, _) = words[i];
            let (last, last_word) = words[i + take - 1];
            out.push_str(&line[copied..start]);
            out.push_str(&replacement);
            copied = last + last_word.len();
            i += take;
        }
        out.push_str(&line[copied..]);
    }
    Some(out)
}

/// The words of one line, where `split_whitespace` would split it, each with the byte offset it
/// starts at, so a rewrite can replace a call and copy the text around it through untouched.
fn words_of(line: &str) -> Vec<(usize, &str)> {
    let mut words = Vec::new();
    let mut start = None;
    for (at, c) in line.char_indices() {
        match (c.is_whitespace(), start) {
            (true, Some(s)) => {
                words.push((s, &line[s..at]));
                start = None;
            }
            (false, None) => start = Some(at),
            _ => {}
        }
    }
    if let Some(s) = start {
        words.push((s, &line[s..]));
    }
    words
}

/// How to run one named script without yarn.
///
/// **Not simply `npm run <name>`.** That is right only when the script's own body does not reach
/// yarn — `umd` is browserify and rewrites cleanly, while `build` is `yarn umd && yarn umd-min`
/// and `npm run build` would find yarn again one level down. A script that reaches yarn is
/// expanded into what it would have run.
///
/// The name is a word of the fragment being rewritten, so `npm run <name>` is that fragment's own
/// text. The expansion is the script's body, which is the repository's, and goes where `splice`
/// says; what it expands to in turn is part of it, so everything below goes in with it.
fn invoke(
    name: &str,
    scripts: &BTreeMap<String, String>,
    depth: u8,
    splice: &mut Splice<'_>,
) -> Option<String> {
    let body = scripts.get(name)?;
    if !reaches_yarn(name, scripts) {
        return Some(format!("npm run {name}"));
    }
    let expanded = rewrite(body, scripts, depth + 1, &mut Splice::Inline)?;
    // Parenthesised, because an expansion carrying `&&` into the middle of a larger command would
    // otherwise rebind what follows it.
    Some(match splice {
        Splice::Inline => format!("( {expanded} )"),
        Splice::Literal(literal) => {
            format!("( {{{{ literal.{} }}}} )", key_for(name, expanded, literal))
        }
    })
}

/// The literal an expansion of `name` is kept under, added to `literal` if it is not there yet.
///
/// Named for the script, so a reviewer reading `( {{ literal.script_build }} )` knows what it
/// stands for — but spelled from ASCII letters, digits and `_` alone, because the name is the
/// repository's and the key is read in a template: `umd-min` would read as `umd - min`. The same
/// key again is the same expansion; one already taken by other text gets a number.
fn key_for(name: &str, expanded: String, literal: &mut BTreeMap<String, String>) -> String {
    let base: String = name
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => c,
            _ => '_',
        })
        .collect();
    let base = format!("script_{base}");
    let mut key = base.clone();
    for n in 2.. {
        match literal.get(&key) {
            None => {
                literal.insert(key.clone(), expanded);
                break;
            }
            Some(v) if *v == expanded => break,
            Some(_) => key = format!("{base}_{n}"),
        }
    }
    key
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

    /// A fragment rewritten as a manual strategy's is, with every expansion spliced in.
    fn inline(cmd: &str, scripts: &BTreeMap<String, String>) -> Option<String> {
        rewrite(cmd, scripts, 0, &mut Splice::Inline)
    }

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
            inline("yarn build", &s).as_deref(),
            Some("( npm run umd && npm run umd-min )")
        );
        assert_eq!(
            inline("yarn umd && yarn umd-min", &s).as_deref(),
            Some("npm run umd && npm run umd-min")
        );
        // `yarn run x` is the same call spelled longer.
        assert_eq!(inline("yarn run umd", &s).as_deref(), Some("npm run umd"));
    }

    /// The case that actually fires: the strategy never mentions yarn.
    #[test]
    fn npm_run_reaching_yarn_two_levels_down_is_expanded() {
        let s = prop_types();
        assert_eq!(
            inline("npm run build", &s).as_deref(),
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
                inline(cmd, &s),
                None,
                "`{cmd}` is yarn doing something only yarn does"
            );
        }
    }

    #[test]
    fn a_script_that_does_not_exist_is_not_a_task_runner_call() {
        // `yarn frobnicate` where nothing declares `frobnicate` is not a call we can rewrite, and
        // guessing would turn a clear failure into a confusing one.
        assert_eq!(inline("yarn frobnicate", &prop_types()), None);
    }

    #[test]
    fn a_command_with_no_yarn_in_it_is_returned_unchanged() {
        let s = prop_types();
        for cmd in ["npm run tests-only", "npm pack", "make all"] {
            assert_eq!(inline(cmd, &s).as_deref(), Some(cmd));
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
        assert_eq!(inline("yarn a", &s), None);
        assert_eq!(inline("npm run a", &s), None);
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
                    literal: BTreeMap::new(),
                },
                Step {
                    body: StepBody::Uses {
                        tool: "npm/build/pack".into(),
                        with: Default::default(),
                    },
                    needs: vec![],
                    when: None,
                    literal: BTreeMap::new(),
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
        // The expansion is the repository's text, so it is a literal of the step, which the
        // template prints by name.
        assert_eq!(
            f.build[0].body,
            StepBody::Runs("( {{ literal.script_build }} )".into())
        );
        assert_eq!(
            f.build[0].literal.get("script_build").map(String::as_str),
            Some("npm run umd && npm run umd-min")
        );
        // The tool step is untouched: it never mentioned yarn.
        assert!(matches!(f.build[1].body, StepBody::Uses { .. }));
        assert!(f.build[1].literal.is_empty());
        // And a second pass finds no yarn left, so the rung does not loop.
        assert!(without_yarn(&after, &prop_types()).is_none());
    }

    /// A flow strategy of one `runs` step, rewritten and rendered as the run renders it.
    fn rendered(runs: &str, scripts: &BTreeMap<String, String>) -> (Strategy, String) {
        let s = crate::from_yaml(&format!(
            "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
             \x20 subdir: pkg\nbuild:\n  - runs: '{runs}'\noutput_path: '*.tgz'\n"
        ))
        .expect("parses");
        let next = without_yarn(&s, scripts).expect("something to rewrite");
        let tools = crate::ToolRegistry::builtin().expect("registry");
        let built = crate::render(&next, &crate::Context::default(), &tools)
            .expect("renders")
            .build;
        (next, built)
    }

    /// **A script body is the repository's text, and never template source.** Spliced into the
    /// `runs` template, `{{ 7*7 }}` built as `49`, `{% if %}` failed the render and `{#` opened a
    /// comment that swallowed the rest of the step: the package under test was writing its own
    /// recipe. As a literal it reaches the build script byte for byte — and the fragment's own
    /// template around it still renders.
    #[test]
    fn a_script_body_reaches_the_build_as_written_and_is_never_evaluated() {
        let body = "yarn umd && echo {{ 7*7 }} {% if %} {#";
        let scripts: BTreeMap<String, String> = [("build", body), ("umd", "browserify x")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (_, built) = rendered("cd {{ location.subdir }} && npm run build", &scripts);
        assert_eq!(
            built,
            "cd pkg && ( npm run umd && echo {{ 7*7 }} {% if %} {# )"
        );
    }

    /// A key is spelled from the script's name and read in a template, so what the repository
    /// named a script cannot become template syntax; two names that spell one key keep two keys,
    /// and one script expanded twice keeps one.
    #[test]
    fn two_scripts_whose_names_spell_one_key_keep_two_and_one_script_keeps_one() {
        let scripts: BTreeMap<String, String> = [
            ("umd-min", "yarn x"),
            ("umd_min", "yarn y"),
            ("x", "echo x"),
            ("y", "echo y"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let (next, built) = rendered("npm run umd-min && yarn umd_min && yarn umd-min", &scripts);
        let Strategy::Flow(f) = &next else {
            panic!("shape changed")
        };
        assert_eq!(
            f.build[0].body,
            StepBody::Runs(
                "( {{ literal.script_umd_min }} ) && ( {{ literal.script_umd_min_2 }} ) && \
                 ( {{ literal.script_umd_min }} )"
                    .into()
            )
        );
        assert_eq!(f.build[0].literal.len(), 2, "{:?}", f.build[0].literal);
        assert_eq!(built, "( npm run x ) && ( npm run y ) && ( npm run x )");
    }

    /// Whether `sh` reads a script without a syntax error. `-n` parses and runs nothing.
    fn parses_as_shell(script: &str) -> Result<(), String> {
        let out = std::process::Command::new("sh")
            .args(["-n", "-c", script])
            .env_clear()
            .output()
            .expect("sh runs");
        match out.status.success() {
            true => Ok(()),
            false => Err(String::from_utf8_lossy(&out.stderr).into_owned()),
        }
    }

    /// **A step keeps its lines, and only the call is rewritten.** A `runs: |` step is shell, and
    /// a newline in it ends a command. Split on whitespace and joined with spaces, this step
    /// became `cd {{ location.subdir }} npm ci ( {{ literal.script_build }} )`, which `sh` refuses
    /// at the `(`: the rung spent a build on a syntax error, and the failure was the package's. A
    /// step with no yarn in it, beside one that has, is not touched at all, spacing included.
    #[test]
    fn a_multi_line_step_keeps_its_lines_and_only_the_call_is_rewritten() {
        let s = crate::from_yaml(
            "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
             \x20 subdir: pkg\nbuild:\n  - runs: |\n      cd {{ location.subdir }}\n      \
             npm ci\n      npm run build\n  - runs: |\n      echo  one\n\n        echo two\n\
             output_path: '*.tgz'\n",
        )
        .expect("parses");
        let next = without_yarn(&s, &prop_types()).expect("something to rewrite");
        let (Strategy::Flow(before), Strategy::Flow(f)) = (&s, &next) else {
            panic!("shape changed")
        };
        assert_eq!(
            f.build[0].body,
            StepBody::Runs(
                "cd {{ location.subdir }}\nnpm ci\n( {{ literal.script_build }} )\n".into()
            )
        );
        assert_eq!(f.build[1], before.build[1], "no yarn, so not touched");

        let tools = crate::ToolRegistry::builtin().expect("registry");
        let built = crate::render(&next, &crate::Context::default(), &tools)
            .expect("renders")
            .build;
        assert_eq!(
            built,
            "cd pkg\nnpm ci\n( npm run umd && npm run umd-min )\necho  one\n\n  echo two"
        );
        parses_as_shell(&built).unwrap_or_else(|e| panic!("{e}\n{built}"));

        // A call does not run on into the next line, as it would not for the shell: `yarn` alone
        // at the end of one is `yarn install`, which is not a task-runner call.
        assert_eq!(inline("yarn\nbuild", &prop_types()), None);
    }

    /// The same for a manual strategy's scripts, which are never rendered: each line is kept, and a
    /// strategy whose only multi-line script has no yarn in it has nothing to rewrite.
    #[test]
    fn a_multi_line_manual_script_keeps_its_lines() {
        let got = without_yarn(
            &manual("npm ci\n", "npm ci\nnpm run build\nnpm pack\n"),
            &prop_types(),
        )
        .expect("rewritten");
        let Strategy::Manual(m) = got else {
            panic!("shape changed")
        };
        assert_eq!(m.deps, "npm ci\n", "no yarn, so not touched");
        assert_eq!(
            m.build,
            "npm ci\n( npm run umd && npm run umd-min )\nnpm pack\n"
        );
        parses_as_shell(&m.build).unwrap_or_else(|e| panic!("{e}\n{}", m.build));

        assert!(
            without_yarn(&manual("npm ci\n", "npm ci\n  npm pack\n"), &prop_types()).is_none(),
            "only whitespace would have changed"
        );
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
                literal: BTreeMap::new(),
            }],
            output_dir: None,
            output_path: None,
        };
        assert!(without_yarn(&Strategy::Flow(flow), &prop_types()).is_none());
    }

    #[test]
    fn the_scripts_are_read_from_the_checkouts_manifest_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("trigon-yarn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // No manifest at all: nothing to rewrite with.
        assert!(scripts_from_checkout(&dir).is_empty());

        std::fs::write(dir.join("package.json"), "{ not json").unwrap();
        assert!(scripts_from_checkout(&dir).is_empty());

        std::fs::write(dir.join("package.json"), r#"{"name": "x"}"#).unwrap();
        assert!(scripts_from_checkout(&dir).is_empty());

        // A script that is not a string is not a command, and is dropped rather than guessed at.
        std::fs::write(
            dir.join("package.json"),
            r#"{"scripts": {"build": "yarn umd", "umd": "browserify x", "weird": 7}}"#,
        )
        .unwrap();
        let got = scripts_from_checkout(&dir);
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            [
                ("build".to_string(), "yarn umd".to_string()),
                ("umd".to_string(), "browserify x".to_string()),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn manual(deps: &str, build: &str) -> Strategy {
        Strategy::Manual(crate::ManualStrategy {
            location: crate::Location {
                repo: "https://example.invalid/x".into(),
                git_ref: "aa".into(),
                subdir: None,
            },
            deps: deps.into(),
            build: build.into(),
            output_dir: None,
            output_path: None,
        })
    }

    #[test]
    fn a_manual_strategy_is_rewritten_the_same_way_and_refused_the_same_way() {
        // Raw scripts are what a model emits, and the rewrite is the same rewrite.
        let got = without_yarn(&manual("npm ci", "yarn build"), &prop_types()).expect("rewritten");
        let Strategy::Manual(m) = got else {
            panic!("shape changed")
        };
        assert_eq!(m.deps, "npm ci");
        assert_eq!(m.build, "( npm run umd && npm run umd-min )");

        // Half a rewrite is worse than none: a recipe that still needs yarn to install fails
        // later and looks like a different problem.
        assert!(without_yarn(&manual("yarn install", "yarn build"), &prop_types()).is_none());
        // And nothing to rewrite is `None`, not the same strategy handed back.
        assert!(without_yarn(&manual("npm ci", "npm pack"), &prop_types()).is_none());
    }

    #[test]
    fn with_no_scripts_or_no_steps_there_is_nothing_to_rewrite() {
        assert!(without_yarn(&manual("", "yarn build"), &BTreeMap::new()).is_none());
        let hint = Strategy::LocationHint(crate::LocationHint {
            location: crate::Location::default(),
            note: None,
        });
        assert!(without_yarn(&hint, &prop_types()).is_none());
    }

    #[test]
    fn scripts_that_call_each_other_forever_are_refused_rather_than_followed() {
        let cycle: BTreeMap<String, String> = [("a", "yarn b"), ("b", "yarn a")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(inline("yarn a", &cycle), None);
    }
}
