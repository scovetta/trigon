//! RFC 8785 canonicalization, which sits in the signing path.
//!
//! A signature covers the canonical bytes, so a canonicalizer that disagreed with another
//! implementation by one escape would make every signature we ever produced unverifiable by anyone
//! else. These are the cases where an implementation drifts.

use serde_json::json;
use trigon_core::jcs::{CanonError, canonicalize};

#[test]
fn object_keys_are_sorted_however_they_arrived() {
    let v = json!({"b": 1, "a": 2, "C": 3});
    assert_eq!(canonicalize(&v).unwrap(), r#"{"C":3,"a":2,"b":1}"#);
}

#[test]
fn arrays_keep_their_order() {
    // Sorting these would change what the document says, not just how it is spelled.
    let v = json!([3, 1, 2]);
    assert_eq!(canonicalize(&v).unwrap(), "[3,1,2]");
}

#[test]
fn there_is_no_insignificant_whitespace() {
    let v = json!({"a": [1, {"b": null}], "c": true});
    assert_eq!(
        canonicalize(&v).unwrap(),
        r#"{"a":[1,{"b":null}],"c":true}"#
    );
}

#[test]
fn control_characters_use_the_two_character_forms_where_they_exist() {
    // The classic drift: a newline emitted literally rather than as an escape. Both are valid JSON
    // and only one is canonical, and a verifier that chose the other computes a different digest.
    let v = json!({"s": "a\nb\tc\"d\\e"});
    assert_eq!(canonicalize(&v).unwrap(), r#"{"s":"a\nb\tc\"d\\e"}"#);
}

#[test]
fn a_control_character_with_no_short_form_becomes_a_u_escape() {
    let v = json!({"s": "\u{1}"});
    let expected = format!("{{\"s\":\"{}u0001\"}}", '\\');
    assert_eq!(canonicalize(&v).unwrap(), expected);
}

#[test]
fn non_ascii_string_values_pass_through_unescaped() {
    // JCS emits UTF-8; it does not escape above 0x1f.
    let v = json!({"s": "h\u{e9}llo"});
    assert_eq!(canonicalize(&v).unwrap(), "{\"s\":\"h\u{e9}llo\"}");
}

#[test]
fn a_float_is_refused_rather_than_formatted() {
    // Number formatting is the genuinely hard part of the spec and nothing we sign contains one.
    // Emitting a form another implementation renders differently is how a signature stops
    // verifying, silently, later.
    let e = canonicalize(&json!({"x": 1.5})).unwrap_err();
    assert!(matches!(e, CanonError::Float(_)));
    assert!(e.to_string().contains("signed"), "{e}");
}

#[test]
fn a_non_ascii_key_is_refused_rather_than_ordered_by_guess() {
    // JCS orders keys by UTF-16 code unit. This implements that only where it coincides with byte
    // order, and says so rather than sorting wrongly.
    let mut m = serde_json::Map::new();
    m.insert("h\u{e9}y".to_string(), json!(1));
    let e = canonicalize(&serde_json::Value::Object(m)).unwrap_err();
    assert!(matches!(e, CanonError::NonAsciiKey(_)));
    assert!(e.to_string().contains("UTF-16"), "{e}");
}

#[test]
fn integers_keep_their_exact_form() {
    let v = json!({"a": 0, "b": -1, "c": 9007199254740991i64});
    assert_eq!(
        canonicalize(&v).unwrap(),
        r#"{"a":0,"b":-1,"c":9007199254740991}"#
    );
}

#[test]
fn canonicalizing_is_idempotent() {
    // Because the output is parsed and re-canonicalized by anyone verifying it.
    let v = json!({"z": [1, {"y": "x"}], "a": "b"});
    let once = canonicalize(&v).unwrap();
    let twice = canonicalize(&serde_json::from_str(&once).unwrap()).unwrap();
    assert_eq!(once, twice);
}
