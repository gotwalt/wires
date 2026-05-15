use serde::{Deserialize, Serialize};
use snafu::{ResultExt, ensure};

use crate::error::{ContentMissingFieldSnafu, EncodeContentSnafu, ParseContentSnafu, Result};

/// Plaintext content body. After AEAD decryption (or for Public mode, directly),
/// this is what's inside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalContent {
    /// Dotted namespace type, e.g. "home.fridge.temp".
    #[serde(rename = "type")]
    pub type_: String,

    /// Natural-language summary, MUST be present and non-empty.
    pub text: String,

    /// Optional structured payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CanonicalContent {
    pub fn new(type_: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            type_: type_.into(),
            text: text.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.type_.is_empty(),
            ContentMissingFieldSnafu { field: "type" }
        );
        ensure!(
            !self.text.is_empty(),
            ContentMissingFieldSnafu { field: "text" }
        );
        Ok(())
    }

    /// Canonical JSON: keys sorted recursively, no insignificant whitespace.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let v: serde_json::Value = serde_json::to_value(self).context(EncodeContentSnafu)?;
        let canonical = canonicalize(&v);
        serde_json::to_vec(&canonical).context(EncodeContentSnafu)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let c: CanonicalContent = serde_json::from_slice(bytes).context(ParseContentSnafu)?;
        c.validate()?;
        Ok(c)
    }
}

fn canonicalize(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), canonicalize(&m[k]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize).collect())
        }
        _ => v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn requires_type_and_text() {
        let bad = CanonicalContent {
            type_: "".into(),
            text: "x".into(),
            data: None,
        };
        assert!(bad.validate().is_err());
        let bad = CanonicalContent {
            type_: "x".into(),
            text: "".into(),
            data: None,
        };
        assert!(bad.validate().is_err());
        let good = CanonicalContent::new("home.fridge.temp", "holding at 38F");
        good.validate().unwrap();
    }

    #[test]
    fn canonical_bytes_stable_across_key_order() {
        let a: serde_json::Value = json!({"type": "x", "text": "y", "data": {"b": 1, "a": 2}});
        let b: serde_json::Value = json!({"type": "x", "data": {"a": 2, "b": 1}, "text": "y"});
        let a_c: CanonicalContent = serde_json::from_value(a).unwrap();
        let b_c: CanonicalContent = serde_json::from_value(b).unwrap();
        assert_eq!(
            a_c.to_canonical_bytes().unwrap(),
            b_c.to_canonical_bytes().unwrap()
        );
    }

    #[test]
    fn roundtrip_through_canonical_bytes() {
        let c = CanonicalContent::new("home.fridge.temp", "holding at 38F")
            .with_data(json!({"value": 38, "unit": "F"}));
        let bytes = c.to_canonical_bytes().unwrap();
        let back = CanonicalContent::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn missing_data_field_optional() {
        let c = CanonicalContent::new("x", "y");
        let bytes = c.to_canonical_bytes().unwrap();
        // Should NOT contain "data" because skip_serializing_if
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("data"));
        let back = CanonicalContent::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back, c);
    }
}
