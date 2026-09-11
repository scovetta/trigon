//! `strategy_digest`: what the cache key and the attestation pin.
//!
//! Over a canonical serialization of the parsed value, never over the YAML bytes. The difference
//! is not cosmetic: editing a comment in a strategy would otherwise invalidate the cache for every
//! target using it, which at a hundred thousand targets is an expensive typo. Reordering two keys
//! in a mapping would do the same.
//!
//! Canonicalization is RFC 8785 (JCS), vendored rather than depended on, because it sits in the
//! signing path. The subset needed here is small: no floats appear in a strategy, which removes the
//! part of JCS that is genuinely hard, and a test asserts that.
//!
//! Tools hash in alongside the strategy. A strategy that uses `pypi/deps/basic` means whatever that
//! tool means today, so changing the tool has to invalidate the strategies that use it, or a cached
//! verdict outlives the recipe that produced it.

use sha2::{Digest as _, Sha256};

use crate::error::StrategyError;
use crate::model::{Step, StepBody, Strategy};
use crate::tool::ToolRegistry;

/// The digest of a strategy, together with the tools it reaches.
pub fn strategy_digest(s: &Strategy, tools: &ToolRegistry) -> Result<String, StrategyError> {
    let mut h = Sha256::new();
    h.update(b"trigon.strategy.v1\n");
    h.update(canonical(s)?.as_bytes());

    // Only the tools this strategy actually reaches, transitively. Hashing the whole registry would
    // make an unrelated tool's edit invalidate every cached verdict in the fleet.
    let mut reached = std::collections::BTreeSet::new();
    for step in steps_of(s) {
        collect_tools(step, tools, &mut reached);
    }
    for id in &reached {
        h.update(b"\ntool\n");
        h.update(id.as_bytes());
        h.update(b"\n");
        if let Some(t) = tools.get(id) {
            h.update(canonical_value(&serde_yaml_ng::to_value(t)?)?.as_bytes());
        }
    }
    Ok(hex(&h.finalize()))
}

fn steps_of(s: &Strategy) -> Vec<&Step> {
    match s {
        Strategy::Flow(f) => f
            .src
            .iter()
            .chain(f.deps.iter())
            .chain(f.build.iter())
            .collect(),
        _ => Vec::new(),
    }
}

fn collect_tools(step: &Step, tools: &ToolRegistry, out: &mut std::collections::BTreeSet<String>) {
    if let StepBody::Uses { tool, .. } = &step.body
        && out.insert(tool.clone())
        && let Some(t) = tools.get(tool)
    {
        for s in &t.steps {
            collect_tools(s, tools, out);
        }
    }
}

/// A strategy as canonical JSON.
pub fn canonical(s: &Strategy) -> Result<String, StrategyError> {
    canonical_value(&serde_yaml_ng::to_value(s)?)
}

fn canonical_value(v: &serde_yaml_ng::Value) -> Result<String, StrategyError> {
    // Canonicalization lives in `trigon-core` because the attestation layer needs the same one.
    // Two implementations of RFC 8785 is two ways to disagree about a signature.
    trigon_core::jcs::canonicalize(&to_json(v)?).map_err(|e| StrategyError::Invalid(e.to_string()))
}

/// YAML to JSON, refusing what JCS cannot canonicalize.
fn to_json(v: &serde_yaml_ng::Value) -> Result<serde_json::Value, StrategyError> {
    use serde_yaml_ng::Value;
    Ok(match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Number(n) => {
            if n.is_f64() {
                // JCS number formatting for floats is the hard part of the spec, and nothing in a
                // strategy needs one. Refusing beats emitting a form a second implementation would
                // render differently and then disagreeing about a signature.
                return Err(StrategyError::Invalid(format!(
                    "a strategy may not contain the floating-point value {n}: its canonical form \
                     is implementation-dependent, and this digest is signed"
                )));
            }
            match n.as_i64() {
                Some(i) => serde_json::Value::from(i),
                None => serde_json::Value::from(n.as_u64().unwrap_or(0)),
            }
        }
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Sequence(items) => {
            serde_json::Value::Array(items.iter().map(to_json).collect::<Result<Vec<_>, _>>()?)
        }
        Value::Mapping(m) => {
            let mut out = serde_json::Map::new();
            for (k, val) in m {
                let Value::String(k) = k else {
                    return Err(StrategyError::Invalid(
                        "a strategy mapping key must be a string".into(),
                    ));
                };
                out.insert(k.clone(), to_json(val)?);
            }
            serde_json::Value::Object(out)
        }
        Value::Tagged(t) => {
            return Err(StrategyError::Invalid(format!(
                "a strategy may not contain the YAML tag `{}`",
                t.tag
            )));
        }
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
