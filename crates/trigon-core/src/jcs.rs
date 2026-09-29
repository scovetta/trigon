//! RFC 8785 canonical JSON.
//!
//! Vendored rather than depended on because it sits in the signing path: what a signature covers is
//! the canonical bytes, so a canonicalizer that disagreed with ours by one escape would make every
//! signature we ever produced unverifiable by anyone else. One implementation, here, used by both
//! the strategy digest and the attestation layer, because two of them is two ways to disagree.
//!
//! The subset is stated rather than silently partial. Floats are refused: their canonical form is
//! the genuinely hard part of the spec and nothing we sign contains one. So are integers beyond
//! ±(2^53 − 1), the range a double holds exactly: past it RFC 8785 writes the double nearest the
//! number, often a different integer, and writing the exact digits instead would disagree with
//! every conforming implementation. Non-ASCII object keys are refused because JCS orders keys by
//! UTF-16 code unit, and this implements that ordering only where it coincides with byte order.

use serde_json::Value;

/// The largest integer every JSON reader holds exactly: 2^53 − 1, JavaScript's
/// `Number.MAX_SAFE_INTEGER`. Its negation is the smallest.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, PartialEq, Eq)]
pub enum CanonError {
    /// A float, whose canonical form is implementation-dependent.
    Float(String),
    /// An integer beyond ±[`MAX_SAFE_INTEGER`], where RFC 8785 writes the nearest double.
    UnsafeInteger(String),
    /// A key this implementation will not claim to order correctly.
    NonAsciiKey(String),
}

impl std::fmt::Display for CanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonError::Float(n) => write!(
                f,
                "cannot canonicalize the floating-point value {n}: its form is \
                 implementation-dependent and this output is signed"
            ),
            CanonError::UnsafeInteger(n) => write!(
                f,
                "cannot canonicalize the integer {n}: past ±{MAX_SAFE_INTEGER} its form is the \
                 nearest double's rather than its own, and this output is signed"
            ),
            CanonError::NonAsciiKey(k) => write!(
                f,
                "cannot canonicalize the non-ASCII key `{k}`: JCS orders keys by UTF-16 code unit, \
                 which this implements only where that coincides with byte order"
            ),
        }
    }
}

impl std::error::Error for CanonError {}

/// The canonical form of a JSON value.
pub fn canonicalize(v: &Value) -> Result<String, CanonError> {
    let mut out = String::new();
    write(v, &mut out)?;
    Ok(out)
}

fn write(v: &Value, out: &mut String) -> Result<(), CanonError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(CanonError::Float(n.to_string()));
            }
            // Not a float, so a `u64` or an `i64`. Both signs, because `-(2^53)` is as far out
            // of reach as `2^53`.
            let magnitude = n.as_u64().or_else(|| n.as_i64().map(i64::unsigned_abs));
            if magnitude.is_none_or(|m| m > MAX_SAFE_INTEGER) {
                return Err(CanonError::UnsafeInteger(n.to_string()));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            for k in &keys {
                if !k.is_ascii() {
                    return Err(CanonError::NonAsciiKey((*k).clone()));
                }
            }
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 string escaping: the two-character forms where they exist, `\u00xx` otherwise.
fn write_string(s: &str, out: &mut String) {
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
