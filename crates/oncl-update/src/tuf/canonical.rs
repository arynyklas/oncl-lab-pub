//! Canonical JSON, the form TUF signatures are made over ("OLPC canonical JSON", the
//! `canonical_json` of `securesystemslib`; TUF specification section 4.1, "Metaformat"),
//! and the strict parser every metadata file is read with.
//!
//! The canonical form of a value:
//!
//! - an object is `{` its members sorted by key (bytewise on the UTF-8 of the key, which is
//!   also code point order) as `"key":value`, separated by `,`, `}`;
//! - an array is `[` its items separated by `,` `]`;
//! - no whitespace outside strings;
//! - a string is its UTF-8 in quotes with exactly two escapes, `\\` for a backslash and
//!   `\"` for a quote; every other character, control characters and newlines included,
//!   is written as it is;
//! - a number is a decimal integer; there are no floats (and no exponents): a value with a
//!   float is refused, not rounded;
//! - `true`, `false` and `null` as they are.
//!
//! The form is computed from an arbitrary [`serde_json::Value`], never from a typed struct:
//! a field this client does not know is still part of what was signed.
//!
//! [`parse`] reads a file into a [`Value`] and refuses what a signer and a verifier could
//! read differently: a key twice in one object (`serde_json` alone keeps the last), a float,
//! nesting deeper than [`MAX_DEPTH`], a file over the caller's limit, anything after the
//! value.

use std::cell::RefCell;
use std::fmt;

use serde::Deserializer;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use super::error::TufError;

/// The deepest nesting of arrays and objects, in files read and in values encoded. Metadata
/// is a handful of levels deep.
pub const MAX_DEPTH: usize = 32;

/// The canonical form of `value`.
///
/// # Errors
///
/// [`TufError::Float`] for a number that is not an integer of `i64` or `u64`;
/// [`TufError::TooDeep`] past [`MAX_DEPTH`].
pub fn to_vec(value: &Value) -> Result<Vec<u8>, TufError> {
    let mut out = Vec::new();
    write(value, &mut out, 0)?;
    Ok(out)
}

fn write(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), TufError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else {
                return Err(TufError::Float);
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            if depth >= MAX_DEPTH {
                return Err(TufError::TooDeep(MAX_DEPTH));
            }
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(item, out, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            if depth >= MAX_DEPTH {
                return Err(TufError::TooDeep(MAX_DEPTH));
            }
            let mut sorted: Vec<(&String, &Value)> = members.iter().collect();
            sorted.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (key, member)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write(member, out, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for &byte in s.as_bytes() {
        // Multi-byte UTF-8 sequences never contain the bytes of `"` or `\`.
        if byte == b'"' || byte == b'\\' {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out.push(b'"');
}

/// Reads `bytes` as one JSON value, strictly (see the module's description). `what` names
/// the file in errors.
///
/// # Errors
///
/// [`TufError::TooLarge`] if `bytes` is over `limit`; [`TufError::DuplicateKey`],
/// [`TufError::Float`], [`TufError::TooDeep`]; [`TufError::Json`] for anything else that
/// is not one JSON value.
pub fn parse(bytes: &[u8], limit: u64, what: &str) -> Result<Value, TufError> {
    if bytes.len() as u64 > limit {
        return Err(TufError::TooLarge {
            what: what.to_owned(),
            limit,
        });
    }
    let failure = RefCell::new(None);
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let read = Strict {
        depth: 0,
        failure: &failure,
    }
    .deserialize(&mut de)
    .and_then(|value| de.end().map(|()| value));
    match read {
        Ok(value) => Ok(value),
        Err(e) => Err(failure
            .into_inner()
            .unwrap_or_else(|| TufError::Json(format!("{what}: {e}")))),
    }
}

/// Reads a value, remembering which rule it broke: `serde_json::Error` carries only text.
#[derive(Clone, Copy)]
struct Strict<'a> {
    depth: usize,
    failure: &'a RefCell<Option<TufError>>,
}

impl Strict<'_> {
    fn fail<E: serde::de::Error>(&self, error: TufError) -> E {
        let message = error.to_string();
        *self.failure.borrow_mut() = Some(error);
        E::custom(message)
    }

    fn deeper(&self) -> Strict<'_> {
        Strict {
            depth: self.depth + 1,
            failure: self.failure,
        }
    }
}

impl<'de> DeserializeSeed<'de> for Strict<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Value, E> {
        Err(self.fail(TufError::Float))
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.fail(TufError::TooDeep(MAX_DEPTH)));
        }
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self.deeper())? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.fail(TufError::TooDeep(MAX_DEPTH)));
        }
        let mut members = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if members.contains_key(&key) {
                return Err(self.fail(TufError::DuplicateKey(key)));
            }
            let value = map.next_value_seed(self.deeper())?;
            members.insert(key, value);
        }
        Ok(Value::Object(members))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(value: &Value) -> String {
        String::from_utf8(to_vec(value).unwrap()).unwrap()
    }

    #[test]
    fn keys_are_sorted_and_there_is_no_whitespace() {
        let v = json!({"b": [1, {"z": null, "a": true}], "a": "x", "B": false, "": -3});
        assert_eq!(
            canon(&v),
            r#"{"":-3,"B":false,"a":"x","b":[1,{"a":true,"z":null}]}"#
        );
        // Bytewise on UTF-8: "é" (0xC3 0xA9) sorts after every ASCII key.
        assert_eq!(canon(&json!({"é": 1, "z": 2})), r#"{"z":2,"é":1}"#);
    }

    #[test]
    fn only_backslash_and_quote_are_escaped() {
        // A newline, a tab, a control character and a non-ASCII character stay as they are.
        let v = json!({"k": "a\"b\\c\nd\te\u{1}é\u{2028}"});
        assert_eq!(
            to_vec(&v).unwrap(),
            "{\"k\":\"a\\\"b\\\\c\nd\te\u{1}é\u{2028}\"}".as_bytes()
        );
    }

    #[test]
    fn integers_only() {
        assert_eq!(
            canon(&json!([0, -1, 9007199254740993_i64, u64::MAX])),
            "[0,-1,9007199254740993,18446744073709551615]"
        );
        let float = serde_json::Number::from_f64(1.5).unwrap();
        assert!(matches!(
            to_vec(&Value::Number(float)),
            Err(TufError::Float)
        ));
    }

    #[test]
    fn the_form_is_the_same_for_any_input_spelling() {
        let a = parse(br#"{ "b" : 1,  "a" : "\u00e9\/" }"#, 1000, "t").unwrap();
        let b = parse("{\"a\":\"é/\",\"b\":1}".as_bytes(), 1000, "t").unwrap();
        assert_eq!(to_vec(&a).unwrap(), to_vec(&b).unwrap());
        assert_eq!(canon(&a), "{\"a\":\"é/\",\"b\":1}");
    }

    #[test]
    fn duplicate_keys_are_refused_at_any_depth() {
        for text in [
            r#"{"a":1,"a":2}"#,
            r#"{"x":{"a":1,"b":2,"a":3}}"#,
            r#"[{"a":1,"a":1}]"#,
            // Equal after unescaping.
            r#"{"a":1,"\u0061":2}"#,
        ] {
            assert!(
                matches!(parse(text.as_bytes(), 1000, "t"), Err(TufError::DuplicateKey(k)) if k == "a"),
                "{text}"
            );
        }
        parse(br#"{"a":1,"b":{"a":2}}"#, 1000, "t").unwrap();
    }

    #[test]
    fn floats_are_refused() {
        for text in [
            "1.5",
            "[1.0]",
            r#"{"a":1e3}"#,
            "-0",
            "18446744073709551616",
            "[0.0]",
        ] {
            assert!(
                matches!(parse(text.as_bytes(), 1000, "t"), Err(TufError::Float)),
                "{text}"
            );
        }
        parse(
            b"[0, -9223372036854775808, 18446744073709551615]",
            1000,
            "t",
        )
        .unwrap();
    }

    #[test]
    fn depth_and_size_and_trailing_data_are_limited() {
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        parse(deep(MAX_DEPTH).as_bytes(), 1000, "t").unwrap();
        assert!(matches!(
            parse(deep(MAX_DEPTH + 1).as_bytes(), 1000, "t"),
            Err(TufError::TooDeep(MAX_DEPTH))
        ));
        let deep_obj = format!(
            "{}1{}",
            r#"{"a":"#.repeat(MAX_DEPTH + 1),
            "}".repeat(MAX_DEPTH + 1)
        );
        assert!(matches!(
            parse(deep_obj.as_bytes(), 1000, "t"),
            Err(TufError::TooDeep(_))
        ));
        // A body of exactly the limit is read, one byte more is refused.
        parse(b"[1,2]", 5, "t").unwrap();
        assert!(matches!(
            parse(b"[1,2] ", 5, "t"),
            Err(TufError::TooLarge { limit: 5, .. })
        ));
        for text in ["", "{} {}", "{}x", "{\"a\":1}}", "nul", "{'a':1}", "[1,]"] {
            assert!(
                matches!(parse(text.as_bytes(), 1000, "t"), Err(TufError::Json(_))),
                "{text:?}"
            );
        }
        assert!(matches!(
            parse(&[b'"', 0xff, b'"'], 1000, "t"),
            Err(TufError::Json(_))
        ));
    }

    #[test]
    fn deep_values_built_by_hand_are_not_encoded() {
        let mut v = json!(1);
        for _ in 0..=MAX_DEPTH {
            v = json!([v]);
        }
        assert!(matches!(to_vec(&v), Err(TufError::TooDeep(_))));
    }
}
