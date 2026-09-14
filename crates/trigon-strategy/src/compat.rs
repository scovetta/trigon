//! Reading the prior art's `build.yaml` documents.
//!
//! `google/oss-rebuild`'s `definitions/` directory is M1's DSL corpus: 53 overrides written for
//! packages where inference failed, which makes it the pathological tail rather than the common
//! path. Executing them validates the flow DSL, the template engine and the tool registry harder
//! than anything we would write ourselves, and it says nothing about the reproduction rate. Both
//! halves of that matter.
//!
//! Their format is not ours. It is an untagged one-of, where exactly one top-level key is set and
//! that key names a strategy type, so `pypi_pure_wheel_build` and `maven_build` are types there and
//! named flow templates here. Importing is therefore a lowering, not a parse:
//!
//! | Theirs | Ours |
//! |---|---|
//! | `flow` | `Strategy::Flow`, with `dir` renamed to `subdir` and `with` keys to snake_case |
//! | `pypi_pure_wheel_build` | a `Strategy::Flow` over `pypi/deps/basic` and `pypi/build/wheel` |
//! | `rebuild_location_hint` | `Strategy::LocationHint` |
//!
//! Anything else is refused by name. A shape we lower wrongly is worse than one we decline: it
//! produces a build that runs, does something other than what the definition asked for, and reports
//! a verdict about it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;

use crate::error::StrategyError;
use crate::model::{FlowStrategy, Location, LocationHint, Step, StepBody, Strategy};

/// A declarative, bounded stabilizer attached to one definition.
///
/// Carried through rather than executed. Dropping one silently would change the verdict for that
/// target: the definition says the comparison needs it, and a run without it reports a divergence
/// the author already explained. Executing them is a separate piece of work with its own bounds,
/// in `docs/04-strategies.md` §5.2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomStabilizer {
    /// The operation, as its key in the source document.
    pub kind: String,
    /// The mandatory prose justification. Their format requires it and so does ours.
    pub reason: String,
    /// The parameters, unlowered.
    pub config: BTreeMap<String, Value>,
}

/// What one of their documents lowers to.
#[derive(Clone, Debug, PartialEq)]
pub struct Imported {
    pub strategy: Strategy,
    pub custom_stabilizers: Vec<CustomStabilizer>,
}

/// Lower one `build.yaml`.
pub fn import(src: &str) -> Result<Imported, StrategyError> {
    let doc: Value = serde_yaml_ng::from_str(src)?;
    let Value::Mapping(map) = doc else {
        return Err(StrategyError::Invalid("expected a mapping".into()));
    };

    let mut custom_stabilizers = Vec::new();
    let mut chosen: Option<(String, &Value)> = None;
    for (k, v) in &map {
        let Some(k) = k.as_str() else { continue };
        if k == "custom_stabilizers" {
            custom_stabilizers = custom(v)?;
            continue;
        }
        if let Some((first, _)) = &chosen {
            return Err(StrategyError::Invalid(format!(
                "two strategy keys, `{first}` and `{k}`. Their format sets exactly one."
            )));
        }
        chosen = Some((k.to_string(), v));
    }

    let Some((kind, body)) = chosen else {
        return Err(StrategyError::Invalid(
            "no strategy key. Expected one of flow, pypi_pure_wheel_build, rebuild_location_hint"
                .into(),
        ));
    };

    let strategy = match kind.as_str() {
        "flow" => flow(body)?,
        "pypi_pure_wheel_build" => pypi_pure_wheel(body)?,
        "npm_custom_build" => npm_custom(body)?,
        "npm_pack_build" => npm_pack(body)?,
        "rebuild_location_hint" => Strategy::LocationHint(LocationHint {
            location: location(body.get("location").unwrap_or(&Value::Null))?,
            note: Some("imported from oss-rebuild definitions".into()),
        }),
        other => {
            return Err(StrategyError::Invalid(format!(
                "`{other}` is not lowered. It needs the {} tools, which are not ported yet. \
                 Refusing rather than guessing: a shape lowered wrongly builds something other \
                 than what the definition asked for and still reports a verdict.",
                ecosystem_of(other)
            )));
        }
    };

    Ok(Imported {
        strategy,
        custom_stabilizers,
    })
}

fn ecosystem_of(kind: &str) -> &'static str {
    match kind {
        k if k.starts_with("npm") => "npm",
        k if k.starts_with("maven") => "maven",
        k if k.starts_with("cratesio") => "crates.io",
        k if k.starts_with("gem") || k.starts_with("rubygems") => "rubygems",
        _ => "required",
    }
}

fn flow(body: &Value) -> Result<Strategy, StrategyError> {
    Ok(Strategy::Flow(FlowStrategy {
        location: location(body.get("location").unwrap_or(&Value::Null))?,
        src: steps(body.get("src"))?,
        deps: steps(body.get("deps"))?,
        build: steps(body.get("build"))?,
        output_dir: string(body.get("output_dir")),
        output_path: None,
    }))
}

/// `pypi_pure_wheel_build` is their pre-canned pure-wheel flow. Ours is the same flow, spelled out.
fn pypi_pure_wheel(body: &Value) -> Result<Strategy, StrategyError> {
    let loc = location(body.get("location").unwrap_or(&Value::Null))?;
    let dir = loc.subdir.clone().unwrap_or_else(|| ".".into());

    let requirements = match body.get("requirements") {
        Some(Value::Sequence(items)) => {
            let list: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
            serde_json::to_string(&list).unwrap_or_else(|_| "[]".into())
        }
        _ => "[]".into(),
    };

    let mut with = BTreeMap::from([
        ("venv".to_string(), crate::VENV.to_string()),
        ("requirements".to_string(), requirements),
    ]);
    if let Some(t) = string(body.get("registry_time")) {
        with.insert("registry_time".into(), t);
    }

    let output_dir = if dir == "." {
        "dist".to_string()
    } else {
        format!("{}/dist", dir.trim_end_matches('/'))
    };

    Ok(Strategy::Flow(FlowStrategy {
        location: loc,
        src: vec![uses("git-checkout", BTreeMap::new())],
        deps: vec![uses("pypi/deps/basic", with)],
        build: vec![uses(
            "pypi/build/wheel",
            BTreeMap::from([
                ("locator".to_string(), format!("{}/bin/", crate::VENV)),
                ("dir".to_string(), dir),
            ]),
        )],
        output_dir: Some(output_dir),
        output_path: None,
    }))
}

/// `npm_custom_build`: a package whose publish ran a script before packing.
fn npm_custom(body: &Value) -> Result<Strategy, StrategyError> {
    let loc = location(body.get("location").unwrap_or(&Value::Null))?;
    let mut deps = BTreeMap::from([
        ("node_version".to_string(), required(body, "node_version")?),
        ("npm_version".to_string(), required(body, "npm_version")?),
    ]);
    if let Some(t) = string(body.get("registry_time")) {
        deps.insert("registry_time".into(), t);
    }

    let mut build = BTreeMap::from([("npm_version".to_string(), required(body, "npm_version")?)]);
    for (theirs, ours) in [
        ("version_override", "version_override"),
        ("command", "command"),
    ] {
        if let Some(v) = string(body.get(theirs)) {
            build.insert(ours.into(), v);
        }
    }
    // Their booleans are optional and default false. Absent and false are the same build, so an
    // absent key is not carried through as the string "false".
    for (theirs, ours) in [
        ("keep_root", "keep_root"),
        ("prepack_remove_deps", "remove_deps"),
    ] {
        if body.get(theirs).and_then(Value::as_bool) == Some(true) {
            build.insert(ours.into(), "true".into());
        }
    }

    // The tarball rather than the directory: `npm pack` writes one, and naming the directory
    // copies the whole working tree instead.
    let output_path = tgz_glob(&loc);
    Ok(Strategy::Flow(FlowStrategy {
        location: loc,
        src: vec![uses("git-checkout", BTreeMap::new())],
        deps: vec![uses("npm/deps/custom", deps)],
        build: vec![uses("npm/build/custom", build)],
        output_dir: None,
        output_path: Some(output_path),
    }))
}

/// `npm_pack_build`: the plain case, `npm pack` with no publish script.
fn npm_pack(body: &Value) -> Result<Strategy, StrategyError> {
    let loc = location(body.get("location").unwrap_or(&Value::Null))?;
    let mut deps = BTreeMap::from([
        ("node_version".to_string(), required(body, "node_version")?),
        ("npm_version".to_string(), required(body, "npm_version")?),
    ]);
    if let Some(t) = string(body.get("registry_time")) {
        deps.insert("registry_time".into(), t);
    }
    let mut build = BTreeMap::from([("npm_version".to_string(), required(body, "npm_version")?)]);
    if let Some(v) = string(body.get("version_override")) {
        build.insert("version_override".into(), v);
    }
    let output_path = tgz_glob(&loc);
    Ok(Strategy::Flow(FlowStrategy {
        location: loc,
        src: vec![uses("git-checkout", BTreeMap::new())],
        deps: vec![uses("npm/deps/custom", deps)],
        build: vec![uses("npm/build/pack", build)],
        output_dir: None,
        output_path: Some(output_path),
    }))
}

/// A field the lowering cannot invent a default for.
fn required(body: &Value, key: &str) -> Result<String, StrategyError> {
    string(body.get(key)).filter(|s| !s.is_empty()).ok_or_else(|| {
        StrategyError::Invalid(format!(
            "`{key}` is required and absent. Guessing one would pin a toolchain the definition did \
             not ask for, which is a different build reported under this definition's name."
        ))
    })
}

fn tgz_glob(loc: &Location) -> String {
    match &loc.subdir {
        Some(d) => format!("{}/*.tgz", d.trim_end_matches('/')),
        None => "*.tgz".into(),
    }
}

fn uses(tool: &str, with: BTreeMap<String, String>) -> Step {
    Step {
        body: StepBody::Uses {
            tool: tool.to_string(),
            with,
        },
        needs: Vec::new(),
        when: None,
    }
}

fn location(v: &Value) -> Result<Location, StrategyError> {
    let repo = string(v.get("repo")).unwrap_or_default();
    if repo.is_empty() {
        return Err(StrategyError::Invalid("location has no repo".into()));
    }
    Ok(Location {
        repo,
        git_ref: string(v.get("ref")).unwrap_or_default(),
        // They call it `dir`; we call it `subdir`. An empty string means the repository root, and
        // carrying it through as `Some("")` would render `cd ` in a template.
        subdir: string(v.get("dir")).filter(|d| !d.is_empty() && d != "."),
    })
}

fn steps(v: Option<&Value>) -> Result<Vec<Step>, StrategyError> {
    let Some(Value::Sequence(items)) = v else {
        return Ok(Vec::new());
    };
    items.iter().map(step).collect()
}

fn step(v: &Value) -> Result<Step, StrategyError> {
    let runs = string(v.get("runs"));
    let tool = string(v.get("uses"));
    let needs: Vec<String> = match v.get("needs") {
        Some(Value::Sequence(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };

    let body = match (runs, tool) {
        (Some(r), None) => StepBody::Runs(r),
        (None, Some(t)) => {
            let mut with = BTreeMap::new();
            if let Some(Value::Mapping(m)) = v.get("with") {
                for (k, val) in m {
                    let (Some(k), Some(val)) = (k.as_str(), val.as_str()) else {
                        continue;
                    };
                    with.insert(snake_case(k), val.to_string());
                }
            }
            StepBody::Uses { tool: t, with }
        }
        (Some(_), Some(_)) => {
            return Err(StrategyError::Invalid(
                "step sets both `runs` and `uses`".into(),
            ));
        }
        (None, None) => {
            return Err(StrategyError::Invalid(
                "step sets neither `runs` nor `uses`".into(),
            ));
        }
    };
    Ok(Step {
        body,
        needs,
        when: None,
    })
}

/// Their tool parameters are camelCase; ours are snake_case.
///
/// Mechanical rather than a lookup table, so a parameter we have not seen still arrives with the
/// right spelling instead of silently missing.
fn snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn custom(v: &Value) -> Result<Vec<CustomStabilizer>, StrategyError> {
    let Value::Sequence(items) = v else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in items {
        let Value::Mapping(m) = item else { continue };
        let reason = m
            .get(Value::from("reason"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                StrategyError::Invalid(
                    "a custom stabilizer without a `reason` is not reviewable, and both formats \
                     require one"
                        .into(),
                )
            })?
            .trim()
            .to_string();
        for (k, cfg) in m {
            let Some(k) = k.as_str() else { continue };
            if k == "reason" {
                continue;
            }
            let mut config = BTreeMap::new();
            if let Value::Mapping(c) = cfg {
                for (ck, cv) in c {
                    if let Some(ck) = ck.as_str() {
                        config.insert(ck.to_string(), cv.clone());
                    }
                }
            }
            out.push(CustomStabilizer {
                kind: k.to_string(),
                reason: reason.clone(),
                config,
            });
        }
    }
    Ok(out)
}

fn string(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_owned)
}
