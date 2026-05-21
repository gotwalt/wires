//! Channel-event replay-fold. Spec §7.
//!
//! The fold consumes an ordered iterator of `(sender, content_type, content_bytes)`
//! tuples produced by the substrate layer after envelope-verification and decrypt.
//! It is pure: same input sequence → same `ChannelView` regardless of how many
//! times you call it.

use crate::channel::schemas::{
    ChannelCreate, ChannelInvite, ChannelMemberMeta, TYPE_CREATE, TYPE_INVITE, TYPE_MEMBER_META,
};
use crate::channel::types::{ChannelVariant, ChannelView, MemberMeta};
use crate::wire::Pubkey;

/// One decoded channel-layer event the fold can consume. Sender comes from
/// the envelope; `content_type` and `data` come from `CanonicalContent`.
#[derive(Debug, Clone)]
pub struct Event {
    pub sender: Pubkey,
    pub content_type: String,
    /// The structured payload from `CanonicalContent::data`. None means the
    /// publisher omitted it (channel events without payloads are rejected at
    /// fold time by the per-rule decoders).
    pub data: Option<serde_json::Value>,
}

/// Fold `events` into `view`. Events arrive in substrate order: per-publisher
/// hash-chain ordered, ingest-order across publishers. Events that violate
/// state-machine rules are dropped silently — the fold does not return errors.
pub fn fold(view: &mut ChannelView, events: impl IntoIterator<Item = Event>) {
    for ev in events {
        apply(view, &ev);
    }
}

fn apply(view: &mut ChannelView, ev: &Event) {
    let is_meta = ev.content_type == TYPE_MEMBER_META;
    if !is_meta && !publisher_has_meta(view, &ev.sender) && ev.content_type != TYPE_CREATE {
        return;
    }
    match ev.content_type.as_str() {
        TYPE_CREATE => apply_create(view, ev),
        TYPE_INVITE => apply_invite(view, ev),
        TYPE_MEMBER_META => apply_member_meta(view, ev),
        _ => {}
    }
}

fn apply_create(view: &mut ChannelView, ev: &Event) {
    // Rule 2: DM topics reject __channel.create.
    if matches!(view.variant, ChannelVariant::Dm { .. }) {
        return;
    }
    // Rule 1: first create wins.
    if view.creator.is_some() {
        return;
    }
    let parsed: ChannelCreate = match ev
        .data
        .as_ref()
        .and_then(|d| serde_json::from_value(d.clone()).ok())
    {
        Some(v) => v,
        None => return, // missing or malformed payload — drop
    };
    view.variant = ChannelVariant::Named {
        name: parsed.name,
        description: parsed.description,
    };
    view.creator = Some(ev.sender);
    view.created_at = Some(parsed.created_at);
}

fn apply_invite(view: &mut ChannelView, ev: &Event) {
    // Rule 2: DM topics reject invites.
    if matches!(view.variant, ChannelVariant::Dm { .. }) {
        return;
    }
    // Rule 6: publisher must be a full member.
    if !view.members.contains_key(&ev.sender) {
        return;
    }
    let parsed: ChannelInvite = match ev
        .data
        .as_ref()
        .and_then(|d| serde_json::from_value(d.clone()).ok())
    {
        Some(v) => v,
        None => return,
    };
    if view.members.contains_key(&parsed.agent) || view.pending.contains(&parsed.agent) {
        return; // already in roster; no-op
    }
    view.pending.insert(parsed.agent);
}

fn apply_member_meta(view: &mut ChannelView, ev: &Event) {
    // Rule 4: self-only. The publisher's pubkey IS the subject; there is no
    // explicit subject field in the content. So self-only is satisfied by
    // construction — we apply the meta to `ev.sender` only.
    let parsed: ChannelMemberMeta = match ev
        .data
        .as_ref()
        .and_then(|d| serde_json::from_value(d.clone()).ok())
    {
        Some(v) => v,
        None => return,
    };
    let meta = MemberMeta {
        kind: parsed.kind,
        display_name: parsed.display_name,
        description: parsed.description,
        asserted_at: parsed.asserted_at,
    };
    // Rule 5: latest-wins (BTreeMap insert overwrites).
    view.members.insert(ev.sender, meta);
    // Promote from pending if applicable.
    view.pending.remove(&ev.sender);
}

/// Rule 3: returns true iff `sender` has already published a member_meta on
/// this view. `__channel.member_meta` itself is exempt — it is its own
/// admission ticket.
fn publisher_has_meta(view: &ChannelView, sender: &Pubkey) -> bool {
    view.members.contains_key(sender)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::types::MemberKind;

    fn ev(sender: Pubkey, type_: &str, content: &impl serde::Serialize) -> Event {
        Event {
            sender,
            content_type: type_.to_string(),
            data: Some(serde_json::to_value(content).unwrap()),
        }
    }

    #[test]
    fn empty_log_yields_empty_view() {
        let mut v = ChannelView::empty_named([1u8; 32]);
        fold(&mut v, std::iter::empty());
        assert!(v.members.is_empty());
        assert!(v.pending.is_empty());
        assert_eq!(v.created_at, None);
        assert_eq!(v.creator, None);
    }

    #[test]
    fn fold_is_idempotent_under_double_replay() {
        let mut v = ChannelView::empty_named([1u8; 32]);
        let events = vec![];
        fold(&mut v.clone(), events.clone());
        fold(&mut v, events);
        // Trivial for empty; later tasks add meaningful cases.
        assert_eq!(v.members.len(), 0);
    }

    #[test]
    fn first_channel_create_sets_name_and_creator() {
        let alice: Pubkey = [1u8; 32];
        let mut v = ChannelView::empty_named([7u8; 32]);
        fold(
            &mut v,
            [ev(
                alice,
                TYPE_CREATE,
                &ChannelCreate {
                    name: "coord".to_string(),
                    description: Some("d".to_string()),
                    created_at: 100,
                },
            )],
        );
        assert_eq!(v.creator, Some(alice));
        assert_eq!(v.created_at, Some(100));
        if let ChannelVariant::Named { name, description } = &v.variant {
            assert_eq!(name, "coord");
            assert_eq!(description.as_deref(), Some("d"));
        } else {
            panic!("expected Named variant");
        }
    }

    #[test]
    fn second_channel_create_is_ignored() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let mut v = ChannelView::empty_named([7u8; 32]);
        fold(
            &mut v,
            [
                ev(
                    alice,
                    TYPE_CREATE,
                    &ChannelCreate {
                        name: "first".to_string(),
                        description: None,
                        created_at: 100,
                    },
                ),
                ev(
                    bob,
                    TYPE_CREATE,
                    &ChannelCreate {
                        name: "second".to_string(),
                        description: None,
                        created_at: 200,
                    },
                ),
            ],
        );
        assert_eq!(v.creator, Some(alice));
        if let ChannelVariant::Named { name, .. } = &v.variant {
            assert_eq!(name, "first");
        } else {
            panic!("expected Named variant");
        }
    }

    #[test]
    fn channel_create_on_dm_topic_is_rejected() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let mut v = ChannelView::empty_dm([7u8; 32], vec![alice, bob]);
        fold(
            &mut v,
            [ev(
                alice,
                TYPE_CREATE,
                &ChannelCreate {
                    name: "x".to_string(),
                    description: None,
                    created_at: 1,
                },
            )],
        );
        assert_eq!(v.creator, None);
        if let ChannelVariant::Dm { .. } = v.variant {
            // good
        } else {
            panic!("expected Dm variant preserved");
        }
    }

    #[test]
    fn member_meta_self_publish_admits_into_members() {
        let alice: Pubkey = [1u8; 32];
        let mut v = ChannelView::empty_named([7u8; 32]);
        fold(
            &mut v,
            [ev(
                alice,
                TYPE_MEMBER_META,
                &ChannelMemberMeta {
                    kind: MemberKind::Agent,
                    display_name: "alice-bot".to_string(),
                    description: None,
                    asserted_at: 5,
                },
            )],
        );
        assert!(v.members.contains_key(&alice));
    }

    #[test]
    fn member_meta_latest_wins() {
        let alice: Pubkey = [1u8; 32];
        let mut v = ChannelView::empty_named([7u8; 32]);
        fold(
            &mut v,
            [
                ev(
                    alice,
                    TYPE_MEMBER_META,
                    &ChannelMemberMeta {
                        kind: MemberKind::Agent,
                        display_name: "old".to_string(),
                        description: None,
                        asserted_at: 5,
                    },
                ),
                ev(
                    alice,
                    TYPE_MEMBER_META,
                    &ChannelMemberMeta {
                        kind: MemberKind::Agent,
                        display_name: "new".to_string(),
                        description: None,
                        asserted_at: 10,
                    },
                ),
            ],
        );
        assert_eq!(v.members[&alice].display_name, "new");
    }

    #[test]
    fn pre_meta_events_from_publisher_are_dropped() {
        // alice tries to invite bob before publishing her own member_meta.
        // The invite should not be folded.
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let mut v = ChannelView::empty_named([7u8; 32]);
        fold(
            &mut v,
            [
                ev(
                    alice,
                    TYPE_CREATE,
                    &ChannelCreate {
                        name: "c".to_string(),
                        description: None,
                        created_at: 1,
                    },
                ),
                // No alice member_meta yet.
                ev(
                    alice,
                    TYPE_INVITE,
                    &ChannelInvite {
                        agent: bob,
                        invited_at: 2,
                    },
                ),
            ],
        );
        assert!(
            v.pending.is_empty(),
            "invite from unmeta'd publisher must be dropped"
        );
    }

    #[test]
    fn invite_from_full_member_places_agent_in_pending() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let mut v = ChannelView::empty_named([7u8; 32]);
        fold(
            &mut v,
            [
                ev(
                    alice,
                    TYPE_CREATE,
                    &ChannelCreate {
                        name: "c".to_string(),
                        description: None,
                        created_at: 1,
                    },
                ),
                ev(
                    alice,
                    TYPE_MEMBER_META,
                    &ChannelMemberMeta {
                        kind: MemberKind::Agent,
                        display_name: "alice".to_string(),
                        description: None,
                        asserted_at: 2,
                    },
                ),
                ev(
                    alice,
                    TYPE_INVITE,
                    &ChannelInvite {
                        agent: bob,
                        invited_at: 3,
                    },
                ),
            ],
        );
        assert!(v.pending.contains(&bob));
        assert!(!v.members.contains_key(&bob));
    }

    #[test]
    fn bob_publishing_meta_after_invite_moves_him_to_members() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let mut v = ChannelView::empty_named([7u8; 32]);
        fold(
            &mut v,
            [
                ev(
                    alice,
                    TYPE_CREATE,
                    &ChannelCreate {
                        name: "c".to_string(),
                        description: None,
                        created_at: 1,
                    },
                ),
                ev(
                    alice,
                    TYPE_MEMBER_META,
                    &ChannelMemberMeta {
                        kind: MemberKind::Agent,
                        display_name: "alice".to_string(),
                        description: None,
                        asserted_at: 2,
                    },
                ),
                ev(
                    alice,
                    TYPE_INVITE,
                    &ChannelInvite {
                        agent: bob,
                        invited_at: 3,
                    },
                ),
                ev(
                    bob,
                    TYPE_MEMBER_META,
                    &ChannelMemberMeta {
                        kind: MemberKind::Agent,
                        display_name: "bob".to_string(),
                        description: None,
                        asserted_at: 4,
                    },
                ),
            ],
        );
        assert!(!v.pending.contains(&bob));
        assert!(v.members.contains_key(&bob));
    }

    #[test]
    fn invite_on_dm_topic_rejected() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let carol: Pubkey = [3u8; 32];
        let mut v = ChannelView::empty_dm([7u8; 32], vec![alice, bob]);
        fold(
            &mut v,
            [
                ev(
                    alice,
                    TYPE_MEMBER_META,
                    &ChannelMemberMeta {
                        kind: MemberKind::Agent,
                        display_name: "alice".to_string(),
                        description: None,
                        asserted_at: 1,
                    },
                ),
                ev(
                    alice,
                    TYPE_INVITE,
                    &ChannelInvite {
                        agent: carol,
                        invited_at: 2,
                    },
                ),
            ],
        );
        assert!(v.pending.is_empty(), "DM topics reject invites");
    }

    #[test]
    fn duplicate_invite_is_noop() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let mut v = ChannelView::empty_named([7u8; 32]);
        fold(
            &mut v,
            [
                ev(
                    alice,
                    TYPE_CREATE,
                    &ChannelCreate {
                        name: "c".to_string(),
                        description: None,
                        created_at: 1,
                    },
                ),
                ev(
                    alice,
                    TYPE_MEMBER_META,
                    &ChannelMemberMeta {
                        kind: MemberKind::Agent,
                        display_name: "alice".to_string(),
                        description: None,
                        asserted_at: 2,
                    },
                ),
                ev(
                    alice,
                    TYPE_INVITE,
                    &ChannelInvite {
                        agent: bob,
                        invited_at: 3,
                    },
                ),
                ev(
                    alice,
                    TYPE_INVITE,
                    &ChannelInvite {
                        agent: bob,
                        invited_at: 5,
                    },
                ),
            ],
        );
        assert_eq!(v.pending.len(), 1);
    }
}
