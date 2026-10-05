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
//! verified once, when the subscription opens, as a `view` request is
//! ([`Directory::admit`]): a subscriber with no token that verifies is
//! refused at the `hello`. One that signs in again subscribes again. The first frame is always the whole view, whatever `have` the
//! subscriber names: the directory stores nothing per subscriber, so it
//! can't know which view a `have` refers to. A subscriber that can't apply
//! an update subscribes again.
//!
//! Every view is cut under the newest head, bans included: a head that bans
//! the subscriber's node or person sends a `view_update` that empties its
//! view. A head that stops listing this directory (it can no longer vouch)
//! ends the stream with `denied`, so the caller fails over.

use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::{Connection, SendStream};
use library::{NodeId, Principal, SubFrame, View};

use super::node::Directory;
use super::wire;
use crate::host::transport;

/// Serve one `view` subscription for `caller`, verified as `principal` by
/// the token in its `hello`, on `send`, until the caller goes or the
/// directory stops; or with a terminal `denied` when the subscriber cap is
/// reached, or the head stops listing this directory.
pub(crate) async fn serve(
    dir: &Directory,
    conn: &Connection,
    send: &mut SendStream,
    caller: NodeId,
    principal: Principal,
) -> Result<()> {
    let Ok(_slot) = Arc::clone(&dir.subscribers).try_acquire_owned() else {
        return deny(
            send,
            format!(
                "this directory's subscriber cap ({}) is reached",
                dir.max_subscribers
            ),
        )
        .await;
    };
    if dir.snapshot().is_none() {
        return deny(send, super::node::EMPTY.into()).await;
    }
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
        }
    }
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
