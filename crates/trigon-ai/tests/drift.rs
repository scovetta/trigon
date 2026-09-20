//! A model that keeps generating past the end of its answer.
//!
//! Both fixtures are **verbatim answers from one real repair** of `prop-types@15.8.1`, recorded in
//! the run's transcript. In both, the model diagnosed the divergence correctly — the tarball's
//! missing members are UMD bundles built by a `prepublish` hook that modern npm no longer fires for
//! `npm pack` — and wrote a correct recipe. Then it kept going.
//!
//! The drift lands *inside* the JSON string value, so the JSON stays well-formed and every consumer
//! downstream sees it as part of the strategy. What the caller reported was
//! `not valid YAML: mapping values are not allowed in this context`, with the model's diagnosis
//! printed where the cause should have been — so the answer looked wrong when it was right.
//!
//! Kept as files rather than string literals because the whole point is that these are what
//! actually arrived, not what somebody thought would arrive.

use trigon_ai::parse_candidate;

const DRIFT_1: &str = include_str!("fixtures/prop-types-drift-1.json");
const DRIFT_2: &str = include_str!("fixtures/prop-types-drift-2.json");

#[test]
fn a_recipe_that_drifts_into_prose_still_parses_as_a_strategy() {
    for (name, raw) in [("first attempt", DRIFT_1), ("retry", DRIFT_2)] {
        let c = parse_candidate(raw).unwrap_or_else(|e| panic!("{name}: {e}"));

        // The diagnosis was right both times, which is the part worth not losing.
        assert!(
            c.diagnosis.contains("prepublish"),
            "{name}: the diagnosis should name the hook that did not fire: {}",
            c.diagnosis
        );

        // And the recipe now ends where the recipe ends.
        trigon_strategy::from_yaml(&c.strategy)
            .unwrap_or_else(|e| panic!("{name}: the salvaged strategy does not parse: {e}"));
    }
}

#[test]
fn the_drift_itself_is_not_in_the_strategy() {
    let c = parse_candidate(DRIFT_1).expect("parses");
    assert!(
        !c.strategy.contains("SIEM"),
        "the first answer's trailing line survived into the recipe:\n{}",
        c.strategy
    );

    let c = parse_candidate(DRIFT_2).expect("parses");
    for marker in ["System:", "Assistant:", "further instructions"] {
        assert!(
            !c.strategy.contains(marker),
            "the retry's trailing kilobyte survived into the recipe, including `{marker}`:\n{}",
            c.strategy
        );
    }
}

/// The recipe is cut, not merely made to parse.
///
/// A trailing line that happened to be valid YAML would be *executed*, so the boundary has to be
/// "where the document ends" rather than "where the parser stops complaining".
#[test]
fn the_recipe_kept_is_the_one_the_model_wrote() {
    let c = parse_candidate(DRIFT_1).expect("parses");
    let s = trigon_strategy::from_yaml(&c.strategy).expect("parses");
    let text = format!("{s:?}");
    assert!(
        text.contains("browserify"),
        "the build step the model proposed should survive the cut: {text}"
    );
    assert!(
        c.strategy.trim_end().ends_with("'*.tgz'"),
        "the recipe should end at its last field:\n{}",
        c.strategy
    );
}
