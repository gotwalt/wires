//! A caller's `view` subscription on `wires/directory-sub/2` (card 37).
//!
//! A long-running caller (`wires mcp`, one gateway session, `wires inbox
//! --wait`) follows its view instead of asking again: the directory sends
//! the whole view first, then, for every new head, a `view_update {head,
//! changed, removed}` computed against the view it sent last
//! ([`View::update_to`](library::View::update_to)), and a `fresh` beat when
//! only freshness moved. So a grant or a revocation reaches the caller in
//! the time the publish takes to arrive.
//!
//! The principal is the ID token the subscriber presented in its `hello`,
//! verified and admitted once, when the subscription opens, as a `view`
//! request is ([`Directory::admit`]): a subscriber the policy doesn't admit
//! is refused at the `hello`. The first frame is always the whole view,
//! whatever `have` the subscriber names: the directory stores nothing per
//! subscriber, so it can't know which view a `have` refers to. A subscriber
//! that can't apply an update subscribes again.
//!
//! A subscription takes a slot from the callers' own pool, apart from the
//! hosts' ([`Directory::view_slot`]: at most
//! [`MAX_VIEW_SUBSCRIPTIONS_PER_PERSON`](super::node::MAX_VIEW_SUBSCRIPTIONS_PER_PERSON)
//! for one person), and ends with `denied`:
//!
//! - when its ID token expires ([`SIGN_IN_EXPIRED`]): the client subscribes
//!   again with the token it holds then;
//! - when a head it adopts no longer admits the subscriber
//!   ([`library::check_admitted`]: its node or person banned, or no role
//!   matches any more), after a `view_update` that empties its view
//!   ([`NOT_ADMITTED`]);
//! - when a head stops listing this directory (it can no longer vouch), so
//!   the caller fails over.

use anyhow::Result;
use iroh::endpoint::{Connection, SendStream};
use library::{NodeId, Principal, SubFrame, View};

use super::node::{Directory, NOT_ADMITTED};
use super::wire;
use crate::host::gate::SIGN_IN_EXPIRED;
use crate::host::transport;

/// Serve one `view` subscription for `caller`, admitted as `principal` by
/// the token in its `hello`, on `send`, until the caller goes or the
/// directory stops; or with a terminal `denied` (see the module docs).
pub(crate) async fn serve(
    dir: &Directory,
    conn: &Connection,
    send: &mut SendStream,
    caller: NodeId,
    principal: Principal,
) -> Result<()> {
    let _slot = match dir.view_slot(&principal) {
        Ok(slot) => slot,
        Err(reason) => return deny(send, reason).await,
    };
    if dir.snapshot().is_none() {
        return deny(send, super::node::EMPTY.into()).await;
    }
    let expires = tokio::time::Instant::now() + expiry(&principal, crate::clock::now_unix());
    tracing::debug!(
        peer = %caller.hex(),
        who = %principal.name(),
        "directory: a view subscription"
    );
    let mut sent: Option<View> = None;
    let mut changes = dir.watch();
    loop {
        let snapshot = changes.borrow_and_update().clone();
        if let Some(c) = snapshot {
            let Some(fresh) = c.fresh.clone() else {
                // The head no longer lists this node: it vouches for nothing.
                return deny(send, "no longer a directory of this network".into()).await;
            };
            if let Err(e) = library::check_admitted(&c.held.policy, caller, &principal) {
                tracing::debug!(
                    peer = %caller.hex(),
                    who = %principal.name(),
                    "view subscription ended: {e}"
                );
                if let Some(before) = &sent {
                    let empty = View {
                        head: c.held.signed.head.clone(),
                        entries: Vec::new(),
                    };
                    let frame = SubFrame::ViewUpdate {
                        update: before.update_to(&empty),
                        fresh,
                    };
                    wire::write(send, &frame.encode()?).await?;
                }
                return deny(send, NOT_ADMITTED.into()).await;
            }
            let frame = match &sent {
                Some(view) if view.head.head.version >= c.held.version() => {
                    SubFrame::Fresh { fresh }
                }
                held => {
                    let view = c.held.signed.view_for(caller, Some(&principal), None);
                    let frame = match held {
                        Some(before) => SubFrame::ViewUpdate {
                            update: before.update_to(&view),
                            fresh,
                        },
                        None => SubFrame::View {
                            view: view.clone(),
                            fresh,
                        },
                    };
                    sent = Some(view);
                    frame
                }
            };
            wire::write(send, &frame.encode()?).await?;
        }
        tokio::select! {
            changed = changes.changed() => if changed.is_err() { return Ok(()); },
            _ = conn.closed() => return Ok(()),
            _ = tokio::time::sleep_until(expires) => {
                tracing::debug!(peer = %caller.hex(), "view subscription ended: the ID token expired");
                return deny(send, SIGN_IN_EXPIRED.into()).await;
            }
        }
    }
}

/// How long from `now` until `principal`'s ID token expires (its `exp`):
/// when the subscription it opened ends.
fn expiry(principal: &Principal, now: i64) -> std::time::Duration {
    std::time::Duration::from_secs(
        u64::try_from(principal.not_after.saturating_sub(now)).unwrap_or(0),
    )
}

/// End the subscription with a terminal `denied`.
async fn deny(send: &mut SendStream, reason: String) -> Result<()> {
    let frame = SubFrame::Denied {
        reason: transport::truncate_reason(reason),
    };
    wire::write(send, &frame.encode()?).await?;
    send.finish().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who(not_after: i64) -> Principal {
        Principal {
            issuer: "https://idp".into(),
            subject: "s".into(),
            email: Some("a@x.com".into()),
            org: None,
            groups: vec![],
            not_after,
        }
    }

    #[test]
    fn a_subscription_lasts_until_its_token_expires_and_no_longer() {
        assert_eq!(expiry(&who(1_000), 990), std::time::Duration::from_secs(10));
        assert_eq!(expiry(&who(1_000), 1_000), std::time::Duration::ZERO);
        assert_eq!(expiry(&who(1_000), 5_000), std::time::Duration::ZERO);
    }
}
