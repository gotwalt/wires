//! Wire content schemas for the three channel reserved types. Spec §6.

use serde::{Deserialize, Serialize};

use crate::channel::types::MemberKind;
use crate::wire::Pubkey;

pub const TYPE_CREATE: &str = "__channel.create";
pub const TYPE_INVITE: &str = "__channel.invite";
pub const TYPE_MEMBER_META: &str = "__channel.member_meta";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCreate {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInvite {
    #[serde(with = "hex::serde")]
    pub agent: Pubkey,
    pub invited_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMemberMeta {
    pub kind: MemberKind,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub asserted_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_create_round_trips() {
        let v = ChannelCreate {
            name: "coordinate-grocery".to_string(),
            description: Some("weekly shop".to_string()),
            created_at: 1_700_000_000_000,
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: ChannelCreate = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn channel_create_without_description_omits_field() {
        let v = ChannelCreate {
            name: "x".to_string(),
            description: None,
            created_at: 1,
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("description"));
    }

    #[test]
    fn channel_invite_round_trips() {
        let v = ChannelInvite {
            agent: [9u8; 32],
            invited_at: 100,
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: ChannelInvite = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn member_meta_content_round_trips() {
        let v = ChannelMemberMeta {
            kind: MemberKind::Api,
            display_name: "gmail-bridge".to_string(),
            description: None,
            asserted_at: 42,
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: ChannelMemberMeta = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }
}
