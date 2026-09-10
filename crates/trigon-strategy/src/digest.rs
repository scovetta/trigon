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
    let mut out = String::new();
    write_jcs(v, &mut out)?;
    Ok(out)
}

/// RFC 8785 for the subset a strategy document can contain.
fn write_jcs(v: &serde_yaml_ng::Value, out: &mut String) -> Result<(), StrategyError> {
    use serde_yaml_ng::Value;
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                // JCS number formatting for floats is the hard part of the spec, and nothing in a
                // strategy needs one. Refusing is better than serializing one a second
                // implementation would format differently and then disagreeing about a signature.
                return Err(StrategyError::Invalid(format!(
                    "a strategy may not contain the floating-point value {n}: its canonical form \
                     is implementation-dependent, and this digest is signed"
                )));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_json_string(s, out),
        Value::Sequence(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out)?;
            }
            out.push(']');
        }
        Value::Mapping(m) => {
            // JCS orders members by the UTF-16 code units of their keys. Every key we emit is
            // ASCII, where that coincides with byte order, and a non-ASCII key is refused rather
            // than ordered by a rule this implementation does not fully implement.
            let mut pairs: Vec<(String, &Value)> = Vec::with_capacity(m.len());
            for (k, val) in m {
                let Value::String(k) = k else {
                    return Err(StrategyError::Invalid(
                        "a strategy mapping key must be a string".into(),
                    ));
                };
                if !k.is_ascii() {
                    return Err(StrategyError::Invalid(format!(
                        "non-ASCII mapping key `{k}`: JCS orders keys by UTF-16 code unit, which \
                         this canonicalizer only implements for ASCII"
                    )));
                }
                pairs.push((k.clone(), val));
            }
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (k, val)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                write_jcs(val, out)?;
            }
            out.push('}');
        }
        Value::Tagged(t) => {
            return write_jcs(&t.value, out).map_err(|_| {
                StrategyError::Invalid(format!(
                    "a strategy may not contain the YAML tag `{}`",
                    t.tag
                ))
            });
        }
    }
    Ok(())
}

/// RFC 8785 string escaping: the two-character forms where they exist, `\u00xx` otherwise.
fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
