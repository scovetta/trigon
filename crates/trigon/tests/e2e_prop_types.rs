//! The `prop-types@15.8.1` repair, end to end, against every answer the model actually gave.
//!
//! **Why this file exists.** The chain from a model's answer to a usable recipe broke in four
//! different places on four consecutive runs — the output budget, the wrapper, drift past the end
//! of the document, and the validation context — and each fix was verified against a unit test
//! shaped like the failure that had just been reported. That is how you fix four symptoms and ship
//! the fifth. So: every answer that has ever come back for this package is a fixture here, and the
//! assertion is about the *whole* path rather than any one step in it.
//!
//! The package is a good test because its divergence is real and understood. `prop-types` ships two
//! UMD bundles, `prop-types.js` and `prop-types.min.js`, built by a `build` script that modern npm
//! no longer runs: `prepublish` fires for `npm publish` and not for `npm pack`. A plain pack
//! therefore produces a tarball missing exactly those two members, which is what every run reports.
//!
//! These fixtures are **verbatim**. Several are corrupted — the model drifting into simulated
//! conversation, echoing the provider's own structured-output scaffolding, appending commentary to
//! a line of YAML. That is what arrived, and a salvage path is only worth anything against what
//! arrived.

use std::collections::BTreeMap;

use trigon_ai::parse_candidate;

/// Every recorded answer, newest run last.
const ANSWERS: &[(&str, &str)] = &[
    ("01", include_str!("fixtures/prop-types-answer-01.json")),
    ("02", include_str!("fixtures/prop-types-answer-02.json")),
    ("03", include_str!("fixtures/prop-types-answer-03.json")),
    ("04", include_str!("fixtures/prop-types-answer-04.json")),
    ("05", include_str!("fixtures/prop-types-answer-05.json")),
    ("06", include_str!("fixtures/prop-types-answer-06.json")),
    ("07", include_str!("fixtures/prop-types-answer-07.json")),
    ("08", include_str!("fixtures/prop-types-answer-08.json")),
];

/// `prop-types@15.8.1`'s own scripts, from the published artifact's `package.json`.
fn scripts() -> BTreeMap<String, String> {
    [
        ("umd", "NODE_ENV=development browserify index.js -t loose-envify --standalone PropTypes -o prop-types.js"),
        ("umd-min", "NODE_ENV=production browserify index.js -t loose-envify -t uglifyify --standalone PropTypes -o prop-types.min.js"),
        ("build", "yarn umd && yarn umd-min"),
        ("prepublish", "not-in-publish || yarn build"),
        ("lint", "eslint ."),
        ("test", "npm run tests-only"),
        ("tests-only", "jest"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// One shell fragment through the deterministic rung, via a one-step strategy, as the build script
/// it renders to.
///
/// `without_yarn` works on strategies rather than strings, because that is what the repair loop
/// hands it; this wraps a command in the smallest strategy that carries one. Rendered, because the
/// expansion of a script is the repository's text and is kept as a literal of the step, which the
/// step's template reads by name: what runs is the rendered script, not the template.
fn rewritten(cmd: &str, scripts: &BTreeMap<String, String>) -> Option<String> {
    use trigon_strategy::{FlowStrategy, Location, Step, StepBody, Strategy};
    let one = Strategy::Flow(FlowStrategy {
        location: Location {
            repo: "https://example.invalid/x".into(),
            git_ref: "aa".into(),
            subdir: None,
        },
        src: vec![],
        deps: vec![],
        build: vec![Step {
            body: StepBody::Runs(cmd.to_string()),
            needs: vec![],
            when: None,
            literal: BTreeMap::new(),
        }],
        output_dir: None,
        output_path: None,
    });
    let next = trigon_strategy::without_yarn(&one, scripts)?;
    let tools = trigon_strategy::ToolRegistry::builtin().expect("registry");
    let rendered = trigon_strategy::render(&next, &Default::default(), &tools)
        .unwrap_or_else(|e| panic!("the rewritten strategy does not render: {e}"));
    Some(rendered.build)
}

/// What the pipeline made of one answer.
#[derive(Debug)]
enum Got {
    /// A recipe came out, and it renders.
    Recipe(String),
    /// The answer was refused, with the reason a reader would see.
    Refused(String),
}

/// The real path: unwrap the answer, parse the recipe, render it the way the run will, and ask
/// whether there is anything to execute — which is exactly what `usable` does before accepting a
/// proposal.
fn pipeline(raw: &str) -> Got {
    let c = match parse_candidate(raw) {
        Ok(c) => c,
        Err(e) => return Got::Refused(format!("the answer did not parse: {e}")),
    };
    // The same call the run makes: the longest prefix that parses, because a model that stops
    // answering keeps generating and the parser is the only oracle for where it stopped.
    match trigon_strategy::from_yaml_longest_prefix(&c.strategy) {
        Ok((strategy, dropped)) => {
            let kept: String = c
                .strategy
                .lines()
                .take(c.strategy.lines().count() - dropped)
                .collect::<Vec<_>>()
                .join("\n");
            match renders(&strategy) {
                Ok(()) => Got::Recipe(kept),
                Err(e) => Got::Refused(e),
            }
        }
        Err(e) => Got::Refused(format!("not valid YAML: {e}")),
    }
}

/// Render and check executability, in the run's own context.
fn renders(s: &trigon_strategy::Strategy) -> Result<(), String> {
    let tools = trigon_strategy::ToolRegistry::builtin().map_err(|e| e.to_string())?;
    let loc = s.location().cloned().unwrap_or_default();
    let cx = trigon_strategy::Context {
        location: trigon_strategy::LocationCtx {
            repo: loc.repo,
            git_ref: loc.git_ref,
            subdir: loc.subdir.unwrap_or_default(),
        },
        env: trigon_strategy::EnvCtx {
            arch: "x86_64".into(),
            platform: "linux".into(),
            has_repo: true,
            // The run has a mirror. Validating without one rejects every recipe that pins the
            // published moment, which is every correct recipe for this package.
            timewarp_base: "timewarp:8129".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    trigon_strategy::render(s, &cx, &tools)
        .map_err(|e| e.to_string())
        .and_then(|i| i.executable().map_err(|e| e.to_string()))
        .map(|_| ())
}

/// **The headline.** Every answer either yields a recipe or is refused for a reason that names the
/// model's failure rather than ours.
///
/// Not "every answer yields a recipe": several of these are genuinely corrupt, and a salvage that
/// manufactured a recipe out of `那 Done.omit extra text.` would be worse than a refusal. What the
/// run may not do is report a *parse* failure while printing the model's diagnosis where the cause
/// belongs, which is what it did for four runs.
#[test]
fn every_recorded_answer_is_either_a_recipe_or_a_clean_refusal() {
    let mut recipes = 0;
    let mut refusals = Vec::new();
    for (name, raw) in ANSWERS {
        match pipeline(raw) {
            Got::Recipe(_) => recipes += 1,
            Got::Refused(why) => refusals.push((*name, why)),
        }
    }
    eprintln!("recipes: {recipes} of {}", ANSWERS.len());
    for (n, why) in &refusals {
        eprintln!("  {n} refused: {}", why.chars().take(120).collect::<String>());
    }
    assert!(
        recipes > 0,
        "not one of {} recorded answers produced a usable recipe. The model diagnosed this package \
         correctly every time; if nothing survives, the pipeline is the problem, not the answers.",
        ANSWERS.len()
    );

    // **A refusal must be about the answer, not about us.** Every one of these strings was a bug
    // in this repository, found by shipping it and having the next run report it:
    //
    //   "not valid YAML"        — drift past the end of the document went unparsed (§3.60, §3.62)
    //   "no mirror is configured" — the guard rendered in a context the build does not use (§3.63)
    //   "did not fit"           — the output budget was spent on reasoning (§3.59)
    //
    // A refusal naming an unregistered tool or an undeclared parameter is the model's mistake and
    // is allowed. One naming any of these is ours, and the run was never the model's to fail.
    for (name, why) in &refusals {
        for ours in [
            "not valid YAML",
            "no mirror is configured",
            "did not fit",
            "the answer did not parse",
        ] {
            assert!(
                !why.contains(ours),
                "{name} was refused with `{ours}`, which has been a defect in this repository \
                 every time it has appeared: {why}"
            );
        }
    }
}

/// The diagnosis survives even where the recipe does not.
///
/// It is the half a human can act on, and for four runs it was being printed as though it were the
/// error message — "the proposal did not parse as a strategy, twice. The model said: …" — which
/// made a correct diagnosis read as the cause of a failure.
#[test]
fn the_diagnosis_survives_every_answer() {
    for (name, raw) in ANSWERS {
        let c = parse_candidate(raw)
            .unwrap_or_else(|e| panic!("{name}: the answer did not parse at all: {e}"));
        assert!(
            c.diagnosis.len() > 40,
            "{name}: the diagnosis came through empty or truncated: {:?}",
            c.diagnosis
        );
    }
}

/// No recipe carries the model's drift into something that would be executed.
///
/// The recipes here become shell scripts inside a build container. Salvaging a document is only
/// safe if the salvage stops where the document does.
#[test]
fn no_salvaged_recipe_carries_drift() {
    const DRIFT: &[&str] = &[
        "SIEM",
        "System:",
        "Assistant:",
        "json_schema",
        "You must respond",
        "No new messages",
        "further instructions",
    ];
    for (name, raw) in ANSWERS {
        let Got::Recipe(recipe) = pipeline(raw) else {
            continue;
        };
        for needle in DRIFT {
            assert!(
                !recipe.contains(needle),
                "{name}: a salvaged recipe carries `{needle}`, which would reach a shell:\n{recipe}"
            );
        }
    }
}

/// The deterministic rung needs no model at all.
///
/// `yarn <script>` where `<script>` is a key in `package.json` is `npm run <script>`: same script,
/// same binaries, same pinned versions. This is the path that should fix `prop-types` without
/// spending a token, and it is asserted separately from the model's answers precisely so a bad day
/// at the provider cannot take it down with it.
#[test]
fn the_yarn_rewrite_needs_no_model() {
    let s = scripts();
    // What the model keeps proposing, and what the published package actually does.
    for (before, after) in [
        ("npm run build", "( npm run umd && npm run umd-min )"),
        ("yarn build", "( npm run umd && npm run umd-min )"),
        ("yarn umd && yarn umd-min", "npm run umd && npm run umd-min"),
    ] {
        assert_eq!(
            rewritten(before, &s).as_deref(),
            Some(after),
            "`{before}` should become `{after}` with no model involved"
        );
    }
    // And yarn doing something only yarn does is still refused.
    assert_eq!(
        rewritten("yarn install --frozen-lockfile", &s),
        None
    );
}

/// The repair has to be about the actual divergence.
///
/// `prop-types` is missing two UMD bundles. A recipe that parses, renders and runs but never builds
/// them would reproduce the same divergence for ever — and would look like progress at every step
/// before the comparison.
#[test]
fn every_salvaged_recipe_tries_to_build_the_missing_bundles() {
    for (name, raw) in ANSWERS {
        let Got::Recipe(recipe) = pipeline(raw) else {
            continue;
        };
        let mentions_the_work = ["browserify", "umd", "build"]
            .iter()
            .any(|needle| recipe.contains(needle));
        assert!(
            mentions_the_work,
            "{name}: the recipe never reaches the bundling step, so it rebuilds the same \
             divergence:\n{recipe}"
        );
    }
}
