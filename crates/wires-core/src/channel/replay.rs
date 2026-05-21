//! Channel-event replay-fold. Spec §7.
//!
//! The fold consumes an ordered iterator of `(sender, content_type, content_bytes)`
//! tuples produced by the substrate layer after envelope-verification and decrypt.
//! It is pure: same input sequence → same `ChannelView` regardless of how many
//! times you call it.

#[allow(unused_imports)]
use crate::channel::schemas::{
    ChannelCreate, ChannelInvite, ChannelMemberMeta, TYPE_CREATE, TYPE_INVITE, TYPE_MEMBER_META,
};
#[allow(unused_imports)]
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

#[allow(unused_variables)]
fn apply(_view: &mut ChannelView, _ev: &Event) {
    // Filled in by subsequent tasks. Placeholder for the rules.
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
