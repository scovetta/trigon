//! Two-pass deserialization, for the error message.
//!
//! The naive version, deriving `Deserialize` on the internally-tagged enum and wrapping it in
//! `serde_path_to_error`, does not work. Internal tagging buffers the whole document through
//! serde's private `Content` type before it dispatches, and the path is lost in the buffer: every
//! error comes back anchored at the document root. That is the same defect `docs/04` §2.2 predicts
//! for `flatten`, and it applies here for the same reason.
//!
//! So this reads `schema` and `kind` itself, then deserializes the variant's payload **directly**,
//! with no buffering in the way. The path survives:
//!
//! ```text
//! flow.deps[0].with.python: invalid type: integer `3`, expected a string
//! ```
//!
//! That line goes verbatim into a repair prompt, which is the entire argument for the dependency.
//! The enum keeps its derived `Deserialize` for nested use; it is just not what parses a document.

use serde::de::DeserializeOwned;
use serde_yaml_ng::Value;

use crate::error::StrategyError;
use crate::model::{CURRENT_SCHEMA, FlowStrategy, ManualStrategy, PrebuiltStrategy, Strategy};

const KINDS: &[&str] = &["location_hint", "flow", "manual", "prebuilt"];

/// Parse a strategy document.
pub fn from_yaml(src: &str) -> Result<Strategy, StrategyError> {
    let doc: Value = serde_yaml_ng::from_str(src)?;
    let Value::Mapping(mut map) = doc else {
        return Err(StrategyError::Invalid(
            "a strategy document is a mapping with a `kind`".into(),
        ));
    };

    // Absent and unreadable are different. `.and_then(as_u64).unwrap_or(CURRENT)` treated
    // `schema: "1"`, `schema: 1.5` and `schema: true` as "no schema given, assume the current one" —
    // so a document declaring a version this build cannot honour was rendered anyway, which is the
    // opposite of what a version field is for. Absent still means current; unreadable is an error.
    let schema = match map.remove(Value::from("schema")) {
        None => CURRENT_SCHEMA as u64,
        Some(v) => v.as_u64().ok_or_else(|| {
            StrategyError::Invalid(format!(
                "`schema` has to be a whole number, and this one is `{v:?}`. A document whose \
                 version cannot be read is not a document this build can promise to understand."
            ))
        })?,
    } as u32;
    if schema > CURRENT_SCHEMA {
        return Err(StrategyError::SchemaTooNew {
            found: schema,
            known: CURRENT_SCHEMA,
        });
    }

    let kind = match map.remove(Value::from("kind")) {
        None => return Err(StrategyError::MissingKind),
        Some(v) => match v.as_str().map(str::to_owned) {
            Some(k) => k,
            None => {
                return Err(StrategyError::Invalid(format!(
                    "`kind` must be one of {}, not {v:?}",
                    KINDS.join(", ")
                )));
            }
        },
    };

    let body = Value::Mapping(map);
    match kind.as_str() {
        "location_hint" => payload(body, "location_hint").map(Strategy::LocationHint),
        "flow" => payload::<FlowStrategy>(body, "flow").map(Strategy::Flow),
        "manual" => payload::<ManualStrategy>(body, "manual").map(Strategy::Manual),
        "prebuilt" => payload::<PrebuiltStrategy>(body, "prebuilt").map(Strategy::Prebuilt),
        other => Err(StrategyError::Invalid(format!(
            "unknown kind `{other}`. Known kinds: {}. An ecosystem-specific build such as \
             `pypi_pure_wheel_build` is a `flow` whose steps use a named tool, not a kind of its \
             own: see docs/04-strategies.md §2.1.",
            KINDS.join(", ")
        ))),
    }
}

/// Deserialize one variant's payload, prefixing the path with the kind it was found under.
fn payload<T: DeserializeOwned>(body: Value, kind: &str) -> Result<T, StrategyError> {
    serde_path_to_error::deserialize(body).map_err(|e| {
        let inner = e.path().to_string();
        let path = if inner.is_empty() || inner == "." {
            kind.to_string()
        } else {
            format!("{kind}.{inner}")
        };
        StrategyError::Field {
            path,
            message: e.into_inner().to_string(),
        }
    })
}

/// Serialize a strategy back to YAML, `schema` first.
pub fn to_yaml(s: &Strategy) -> Result<String, StrategyError> {
    let body = serde_yaml_ng::to_string(s)?;
    Ok(format!("schema: {CURRENT_SCHEMA}\n{body}"))
}
