//! Channel view, variant, member metadata types. Spec §4.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    Agent,
    Api,
    Cli,
    Human,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_kind_serializes_snake_case() {
        let cases = [
            (MemberKind::Agent, "\"agent\""),
            (MemberKind::Api, "\"api\""),
            (MemberKind::Cli, "\"cli\""),
            (MemberKind::Human, "\"human\""),
            (MemberKind::Unknown, "\"unknown\""),
        ];
        for (v, expected) in cases {
            let s = serde_json::to_string(&v).unwrap();
            assert_eq!(s, expected);
            let parsed: MemberKind = serde_json::from_str(&s).unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn member_kind_rejects_unknown_string() {
        let r: serde_json::Result<MemberKind> = serde_json::from_str("\"bot\"");
        assert!(r.is_err(), "unknown variant should fail to parse");
    }
}
