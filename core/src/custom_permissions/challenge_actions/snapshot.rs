//! Select signed fields without materializing unsigned snapshot metadata.
//!
//! Read signed fields directly from JSON tokens so their types remain unchanged
//! across serde_json feature configurations. Only the shallow shapes that signed
//! event fields can use are constructed; unsigned metadata is skipped.

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeMap, fmt};

pub(crate) fn signed_fields(raw: &str) -> Result<Value, serde_json::Error> {
    // Check the complete JSON grammar iteratively without interpreting numbers.
    // This also validates all delimiters used by the slice walk below.
    serde_json::from_str::<IgnoredAny>(raw)?;
    let mut input = raw.trim_start();
    if !input.starts_with('{') {
        return Ok(decode_final(input, 0));
    }
    input = &input[1..];
    let mut effective = BTreeMap::new();
    loop {
        input = input.trim_start();
        if input.starts_with('}') {
            break;
        }
        let name: String = take(&mut input)?;
        delimiter(&mut input, ':')?;
        let start = input;
        take::<IgnoredAny>(&mut input)?;
        if matches!(
            name.as_str(),
            "id" | "pubkey" | "sig" | "created_at" | "kind" | "content" | "tags"
        ) {
            // Retain only the last raw slice, before any value representation or
            // range checks. At most seven borrowed slices survive this pass.
            effective.insert(name, &start[..start.len() - input.len()]);
        }
        input = input.trim_start();
        if input.starts_with('}') {
            break;
        }
        delimiter(&mut input, ',')?;
    }
    let fields = effective
        .into_iter()
        .map(|(name, raw)| {
            let depth = if name == "tags" { 2 } else { 0 };
            (name, decode_final(raw, depth))
        })
        .collect();
    Ok(Value::Object(fields))
}

// Stream offsets let the syntax scanner delimit a value without constructing it
// or requiring serde_json features that affect other workspace deserializers.
fn take<'de, T: serde::Deserialize<'de>>(input: &mut &'de str) -> Result<T, serde_json::Error> {
    let mut stream = serde_json::Deserializer::from_str(input).into_iter::<T>();
    let value = stream
        .next()
        .ok_or_else(|| invalid_boundary("Missing JSON value"))??;
    *input = &input[stream.byte_offset()..];
    Ok(value)
}

fn delimiter(input: &mut &str, expected: char) -> Result<(), serde_json::Error> {
    *input = input
        .trim_start()
        .strip_prefix(expected)
        .ok_or_else(|| invalid_boundary("Invalid JSON delimiter"))?;
    Ok(())
}

fn invalid_boundary(message: &str) -> serde_json::Error {
    <serde_json::Error as serde::de::Error>::custom(message)
}

fn decode_final(raw: &str, array_depth: u8) -> Value {
    let mut decoder = serde_json::Deserializer::from_str(raw);
    // Grammar is already checked. An effective value that cannot be represented
    // (for example a non-finite number) cannot be a valid signed field. A null
    // sentinel makes it a shape failure, not a JSON syntax failure.
    Projection { array_depth }
        .deserialize(&mut decoder)
        .unwrap_or(Value::Null)
}

#[derive(Clone, Copy)]
struct Projection {
    array_depth: u8,
}

impl<'de> DeserializeSeed<'de> for Projection {
    type Value = Value;

    fn deserialize<D>(self, decoder: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Projection {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("JSON signed event fields")
    }

    fn visit_map<A>(self, mut object: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        // Objects cannot be a valid signed primitive or tag. Retain their
        // actual type, but skip their contents with the iterative scanner.
        while object.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        let fields = Map::new();
        Ok(Value::Object(fields))
    }

    fn visit_seq<A>(self, mut array: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        match self {
            Self { array_depth } if array_depth > 0 => {
                while let Some(value) = array.next_element_seed(Self {
                    array_depth: array_depth - 1,
                })? {
                    values.push(value);
                }
            }
            _ => {
                // A root array, primitive array, or third tag-array level is invalid.
                // Keep its array type without recursive descent.
                while array.next_element::<IgnoredAny>()?.is_some() {}
            }
        }
        Ok(Value::Array(values))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
    }
}
