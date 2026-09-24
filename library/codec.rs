//! Canonical-JSON codec, length-prefixed framing, and fixed-size hex ids
//! (all internal).
//!
//! Memberships and signed states are signed over — and tokens are
//! base64-encoded from — a *canonical* JSON encoding: object keys sorted recursively, with no
//! insignificant whitespace. Canonicalization makes the byte string
//! deterministic across re-serialization, which is what makes signing and
//! verification stable regardless of struct field or map iteration order.

use serde::Serialize;

use crate::error::{Error, Result};

/// The base64 every wires token and JOSE value uses: URL-safe alphabet, no
/// padding.
///
/// ```
/// use base64::Engine as _;
/// assert_eq!(library::B64.encode([0xfb, 0xff]), "-_8");
/// ```
pub const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Serialize `value` to canonical JSON bytes (sorted keys, compact).
///
/// This is the exact byte string that gets signed (memberships, signed states)
/// or base64-encoded (tokens); both producer and verifier must agree on it
/// byte-for-byte.
///
/// Routing through `serde_json::Value` is what canonicalizes: `serde_json`'s
/// object map is a `BTreeMap` (no `preserve_order` feature), so keys come out
/// sorted recursively regardless of struct field or input map order; `to_vec`
/// then emits with no insignificant whitespace.
pub(crate) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(Error::Encode)?;
    serde_json::to_vec(&value).map_err(Error::Encode)
}

/// Prefix `body` with its length as four big-endian bytes: the framing
/// every wires stream protocol (session, state sync, inbox) uses.
/// [`Error::BadFrame`] if the body is longer than a `u32` can say.
pub(crate) fn length_prefixed(body: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(body.len()).map_err(|_| Error::BadFrame)?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// The body length the prefix at the start of `buf` announces, once its four
/// bytes are there.
pub(crate) fn prefix_len(buf: &[u8]) -> Option<usize> {
    let prefix: [u8; 4] = buf.get(..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(prefix) as usize)
}

/// The body of the first whole frame in `buf`, and how many bytes the frame
/// used (prefix included); `None` until all of it has arrived.
pub(crate) fn split_frame(buf: &[u8]) -> Option<(&[u8], usize)> {
    let end = 4 + prefix_len(buf)?;
    Some((buf.get(4..end)?, end))
}

/// Declare a fixed-size byte id that travels as lowercase hex: the struct
/// (with `Copy`, `Eq`, `Hash`, `Debug` and string serde), `hex`,
/// `from_hex`, `Display`, and the `String` conversions serde goes through.
/// A wrong length is [`Error::BadLength`](crate::Error::BadLength).
macro_rules! hex_id {
    ($(#[$meta:meta])* $vis:vis struct $name:ident([u8; $n:literal]);) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        $vis struct $name([u8; $n]);

        impl $name {
            #[doc = concat!("Lowercase hex (", stringify!($n), " bytes, twice as many characters).")]
            pub fn hex(&self) -> String {
                hex::encode(self.0)
            }

            #[doc = concat!("Parse the hex of exactly ", stringify!($n), " bytes.")]
            pub fn from_hex(s: &str) -> $crate::error::Result<Self> {
                let bytes = hex::decode(s)?;
                let bytes = bytes
                    .try_into()
                    .map_err(|_| $crate::error::Error::BadLength)?;
                Ok(Self(bytes))
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::error::Error;
            fn try_from(s: String) -> $crate::error::Result<Self> {
                Self::from_hex(&s)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.hex()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.hex())
            }
        }
    };
}
pub(crate) use hex_id;

#[cfg(test)]
mod tests {
    use super::*;

    /// Fields declared out of key order, so a serializer that kept
    /// declaration order would emit `b` before `a` (and `y` before `x`).
    #[derive(Serialize)]
    struct Outer {
        b: u8,
        a: u8,
        nested: Inner,
    }

    #[derive(Serialize)]
    struct Inner {
        y: u8,
        x: u8,
    }

    #[test]
    fn sorts_keys_and_is_compact() {
        let v = Outer {
            b: 1,
            a: 2,
            nested: Inner { y: 1, x: 2 },
        };
        // Plain serde keeps declaration order; canonicalizing must not.
        assert_eq!(
            serde_json::to_vec(&v).unwrap(),
            br#"{"b":1,"a":2,"nested":{"y":1,"x":2}}"#.to_vec()
        );
        assert_eq!(
            canonical_bytes(&v).unwrap(),
            br#"{"a":2,"b":1,"nested":{"x":2,"y":1}}"#.to_vec()
        );
    }

    #[test]
    fn frames_split_where_they_were_joined() {
        let framed = length_prefixed(b"abc").unwrap();
        assert_eq!(framed, b"\0\0\0\x03abc");
        assert_eq!(prefix_len(&framed[..3]), None);
        assert_eq!(prefix_len(&framed), Some(3));
        assert_eq!(split_frame(&framed[..6]), None);
        let mut two = framed.clone();
        two.extend_from_slice(b"xyz");
        assert_eq!(split_frame(&two), Some((&b"abc"[..], 7)));
    }

    #[test]
    fn invariant_to_input_map_order() {
        // A HashMap iterates in an arbitrary order; a map built in the
        // reverse order must still encode to the same bytes.
        let forward: std::collections::HashMap<String, u32> =
            (0..64).map(|i| (format!("k{i}"), i)).collect();
        let reverse: std::collections::HashMap<String, u32> =
            (0..64).rev().map(|i| (format!("k{i}"), i)).collect();
        let bytes = canonical_bytes(&forward).unwrap();
        assert_eq!(bytes, canonical_bytes(&reverse).unwrap());
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with(r#"{"k0":0,"k1":1,"k10":10,"#), "{text}");
    }
}
