//! Canonical-JSON codec (internal).
//!
//! Memberships and signed states are signed over — and tokens are
//! base64-encoded from — a *canonical* JSON encoding: object keys sorted recursively, with no
//! insignificant whitespace. Canonicalization makes the byte string
//! deterministic across re-serialization, which is what makes signing and
//! verification stable regardless of struct field or map iteration order.

use serde::Serialize;

use crate::error::{Error, Result};

/// Serialize `value` to canonical JSON bytes (sorted keys, compact).
///
/// This is the exact byte string that gets signed (memberships, heads) or
/// base64-encoded (tokens); both producer and verifier must agree on it byte-for-byte.
///
/// Routing through `serde_json::Value` is what canonicalizes: `serde_json`'s
/// object map is a `BTreeMap` (no `preserve_order` feature), so keys come out
/// sorted recursively regardless of struct field or input map order; `to_vec`
/// then emits with no insignificant whitespace.
pub(crate) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(Error::Encode)?;
    serde_json::to_vec(&value).map_err(Error::Encode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_is_compact() {
        let v = json!({"b": 1, "a": 2, "nested": {"y": 1, "x": 2}});
        assert_eq!(
            canonical_bytes(&v).unwrap(),
            br#"{"a":2,"b":1,"nested":{"x":2,"y":1}}"#.to_vec()
        );
    }

    #[test]
    fn invariant_to_input_key_order() {
        let a = json!({"x": 1, "y": 2});
        let b = json!({"y": 2, "x": 1});
        assert_eq!(canonical_bytes(&a).unwrap(), canonical_bytes(&b).unwrap());
    }
}
