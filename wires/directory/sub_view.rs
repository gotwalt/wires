//! A caller's `view` subscription on `wires/directory-sub/1` (card 37).
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
//! ([`Directory::principal`]); a subscriber that signs in again subscribes
//! again. The first frame is always the whole view, whatever `have` the
//! subscriber names: the directory stores nothing per subscriber, so it
//! can't know which view a `have` refers to. A subscriber that can't apply
//! an update subscribes again.

use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::{Connection, SendStream};
use library::{IdToken, NodeId, Principal, SubFrame, View};

use super::node::Directory;
use super::wire;
use crate::clock::now_unix;
use crate::host::transport;

/// Serve one `view` subscription for the admitted `caller` (which presented
/// `id_token` in its `hello`) on `send`, until the caller goes, the
/// directory stops, or the subscriber cap is reached (a terminal `denied`).
pub(crate) async fn serve(
    dir: &Directory,
    conn: &Connection,
    send: &mut SendStream,
    caller: NodeId,
    id_token: Option<&IdToken>,
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
    let principal: Option<Principal> = match dir.snapshot() {
        Some(c) => {
            dir.principal(caller, id_token, &c.held.policy, now_unix())
                .await
        }
        None => return deny(send, "this directory holds no policy yet".into()).await,
    };
    tracing::debug!(
        peer = %caller.hex(),
        who = principal.as_ref().map(Principal::name).as_deref().unwrap_or("-"),
        "directory: a view subscription"
    );
    let mut sent: Option<View> = None;
    let mut changes = dir.watch();
    loop {
        let snapshot = changes.borrow_and_update().clone();
        if let Some(c) = snapshot
            && let Some(fresh) = c.fresh.clone()
        {
            let frame = match &sent {
                Some(view) if view.head.head.version >= c.held.version() => {
                    SubFrame::Fresh { fresh }
                }
                held => {
                    let view = c.held.signed.view_for(principal.as_ref(), None);
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
