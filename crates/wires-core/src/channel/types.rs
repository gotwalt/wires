//! Channel view, variant, member metadata types. Spec §4.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::wire::{Pubkey, TopicId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    Agent,
    Api,
    Cli,
    Human,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberMeta {
    pub kind: MemberKind,
    pub display_name: String,
    pub description: Option<String>,
    pub asserted_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelVariant {
    Named {
        name: String,
        description: Option<String>,
    },
    Dm {
        /// Sorted byte-lexicographically.
        participants: Vec<Pubkey>,
    },
}

#[derive(Debug, Clone)]
pub struct ChannelView {
    pub topic_id: TopicId,
    pub variant: ChannelVariant,
    /// Full members: have on-log `__channel.member_meta`.
    pub members: BTreeMap<Pubkey, MemberMeta>,
    /// Invited but not yet meta'd. Only populated for Named channels.
    pub pending: BTreeSet<Pubkey>,
    /// Some only for Named.
    pub created_at: Option<i64>,
    /// Some only for Named. Display/audit only — no policy role (spec §3).
    pub creator: Option<Pubkey>,
}

impl ChannelView {
    /// Construct an empty Named-variant view for `topic_id` before any log
    /// entries have been folded.
    pub fn empty_named(topic_id: TopicId) -> Self {
        Self {
            topic_id,
            variant: ChannelVariant::Named {
                name: String::new(),
                description: None,
            },
            members: BTreeMap::new(),
            pending: BTreeSet::new(),
            created_at: None,
            creator: None,
        }
    }

    /// Construct an empty DM view from a sorted participant list. Caller is
    /// responsible for verifying the participants match `topic_id` per the
    /// derivation in `derive::dm_topic_id`.
    pub fn empty_dm(topic_id: TopicId, participants: Vec<Pubkey>) -> Self {
        Self {
            topic_id,
            variant: ChannelVariant::Dm { participants },
            members: BTreeMap::new(),
            pending: BTreeSet::new(),
            created_at: None,
            creator: None,
        }
    }
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

    #[test]
    fn empty_named_has_empty_roster() {
        let v = ChannelView::empty_named([7u8; 32]);
        assert!(v.members.is_empty());
        assert!(v.pending.is_empty());
        assert_eq!(v.topic_id, [7u8; 32]);
        assert!(matches!(v.variant, ChannelVariant::Named { .. }));
    }

    #[test]
    fn empty_dm_carries_sorted_participants() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let v = ChannelView::empty_dm([0u8; 32], vec![alice, bob]);
        if let ChannelVariant::Dm { participants } = &v.variant {
            assert_eq!(participants, &vec![alice, bob]);
        } else {
            panic!("expected Dm variant");
        }
    }

    #[test]
    fn member_meta_round_trips() {
        let m = MemberMeta {
            kind: MemberKind::Agent,
            display_name: "kitchen-bot".to_string(),
            description: Some("monitors the fridge".to_string()),
            asserted_at: 1_000,
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: MemberMeta = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
    }
}
