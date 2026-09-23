//! `wires advanced publish <topic>`: hand a message to the resident node if
//! there is one, else publish one-shot (spec §7.2).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Args;
use library::{NodeId, TopicPeer};

use super::context::{TopicArgs, TopicContext};
use super::local::{STORE_LOCK_WAIT, append_local, current_fabric_key, open_topic_store};
use super::peers::PeerBook;
use super::watch::deadline;
use super::{ipc, topics};
use crate::admin::keystore;
use crate::{init_logging, now_unix};

/// `publish` arguments: the shared topic arguments plus the message.
///
/// With no `--message`, stdin is read and **each line is published
/// separately** — so `tail -f log | wires advanced publish ops` is a live feed and not
/// one enormous message.
#[derive(Args)]
pub(crate) struct PublishArgs {
    #[command(flatten)]
    pub(crate) common: TopicArgs,
    /// The message text. Omit to publish one message per line of stdin.
    #[arg(long, short = 'm')]
    pub(crate) message: Option<String>,
}

/// How long a one-shot `wires advanced publish` waits for its first mesh neighbor before
/// giving up and storing the message locally.
///
/// A bound, not a sleep: the wait ends on the first
/// [`TopicEvent::NeighborUp`](crate::channel::topics::TopicEvent::NeighborUp), and this
/// is only how long "nobody is there" takes to establish.
pub(crate) const PUBLISH_NEIGHBOR_WAIT: Duration = Duration::from_secs(15);

/// How long a one-shot `wires advanced publish` stays up after broadcasting, so gossip
/// can actually put the bytes on the wire before the endpoint closes.
pub(crate) const PUBLISH_LINGER: Duration = Duration::from_secs(1);

/// How many times a streaming `wires advanced publish` retries one line before dropping
/// it and moving on to the next.
const PUBLISH_ATTEMPTS: usize = 3;

/// How long a streaming `wires advanced publish` waits before reconnecting to a tail that
/// just refused it or hung up.
const PUBLISH_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Where a `wires advanced publish` invocation's messages come from.
///
/// Streaming rather than collected, so `tail -f app.log | wires advanced publish ops`
/// publishes each line as it appears instead of waiting for an end of input
/// that never comes.
pub(crate) enum Messages {
    /// A single `--message`, once.
    One(Option<String>),
    /// One message per line of stdin.
    Stdin(tokio::io::Lines<tokio::io::BufReader<tokio::io::Stdin>>),
}

impl Messages {
    /// The next message, skipping blank lines; `None` at the end.
    pub(crate) async fn next(&mut self) -> anyhow::Result<Option<String>> {
        match self {
            Messages::One(text) => Ok(text.take()),
            Messages::Stdin(lines) => loop {
                match lines.next_line().await.context("reading stdin")? {
                    Some(line) if line.trim().is_empty() => continue,
                    other => return Ok(other),
                }
            },
        }
    }
}

/// `publish`: hand the message to the resident tail if there is one, else do it
/// one-shot (spec §7.2).
pub(crate) async fn publish_cmd(a: PublishArgs) -> anyhow::Result<()> {
    init_logging();
    let ks = Arc::new(keystore::Keystore::resolve()?);
    let home = keystore::home()?;
    let ctx = TopicContext::resolve(ks, home, &a.common)?;
    let messages = match a.message {
        Some(text) => Messages::One(Some(text)),
        None => {
            use tokio::io::AsyncBufReadExt as _;
            Messages::Stdin(tokio::io::BufReader::new(tokio::io::stdin()).lines())
        }
    };

    if let Some(client) = ipc::ControlClient::connect(&ctx.socket_path()).await? {
        return publish_through_tail(&ctx, client, messages).await;
    }
    publish_one_shot(&ctx, messages, PUBLISH_NEIGHBOR_WAIT, PUBLISH_LINGER).await
}

/// Stream every message through the resident tail, surviving a refusal.
///
/// `tail -f app.log | wires advanced publish ops` is the documented use, and it used to
/// end on the first error: a `{"err":…}` reply — which the tail sends for
/// something as ordinary as "no fabric key for the current commit yet", in the
/// window between a `roster commit` and the operator's `wires advanced import` — or the
/// socket closing because the tail was restarted. The pipe died permanently and
/// every subsequent line was silently never published.
///
/// So a failure retries the same line, reconnecting first (a closed socket is
/// the common case, and the tail may be back), and only after
/// [`PUBLISH_ATTEMPTS`] does it give up on *that line* and move to the next.
/// The command fails only if nothing at all got through.
pub(crate) async fn publish_through_tail(
    ctx: &TopicContext,
    client: ipc::ControlClient,
    mut messages: Messages,
) -> anyhow::Result<()> {
    let socket = ctx.socket_path();
    let mut client = Some(client);
    let (mut published, mut dropped) = (0usize, 0usize);
    while let Some(text) = messages.next().await? {
        match publish_line(&mut client, &socket, &text, PUBLISH_RETRY_DELAY).await {
            Ok(seq) => {
                tracing::info!(seq, "published through the resident tail");
                published += 1;
            }
            Err(e) => {
                dropped += 1;
                eprintln!(
                    "wires advanced publish: dropping a line after {PUBLISH_ATTEMPTS} attempts: {e:#}"
                );
            }
        }
    }
    match (published, dropped) {
        (0, 0) => eprintln!("wires advanced publish: nothing to publish"),
        (0, _) => anyhow::bail!("no message could be published through the resident tail"),
        (_, 0) => {}
        (_, n) => eprintln!("wires advanced publish: {n} line(s) were not published"),
    }
    Ok(())
}

/// Publish one line through the resident tail, reconnecting between attempts.
///
/// `client` is taken as a slot rather than a value because a failure discards
/// the connection: a `{"err":…}` reply leaves it usable and a closed socket does
/// not, and reconnecting costs less than telling those apart. The caller keeps
/// the slot across lines, so a healthy stream reconnects zero times.
async fn publish_line(
    client: &mut Option<ipc::ControlClient>,
    socket: &Path,
    text: &str,
    retry_delay: Duration,
) -> anyhow::Result<u64> {
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..PUBLISH_ATTEMPTS {
        if client.is_none() {
            if attempt > 0 {
                tokio::time::sleep(retry_delay).await;
            }
            *client = ipc::ControlClient::connect(socket).await.unwrap_or(None);
        }
        let Some(open) = client.as_mut() else {
            last = Some(anyhow::anyhow!(
                "no resident tail on {} to publish through",
                socket.display()
            ));
            continue;
        };
        match open.publish(text).await {
            Ok(seq) => return Ok(seq),
            Err(e) => {
                tracing::warn!(attempt = attempt + 1, "publish refused: {e:#}");
                *client = None;
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("the publish was never attempted")))
}

/// Publish without a resident tail: bind, admit, join, wait for one neighbor,
/// then seal/append/broadcast each message and linger.
///
/// With no reachable peer the messages are still appended locally and the
/// command exits 0 with a warning: the log is the authority, and the next tail
/// on this node replays them out (spec §7.2).
pub(crate) async fn publish_one_shot(
    ctx: &TopicContext,
    mut messages: Messages,
    wait: Duration,
    linger: Duration,
) -> anyhow::Result<()> {
    // The tail may be *starting*: it binds its control socket before it joins,
    // but a publish that arrived a moment earlier saw no socket and got here.
    // Waiting out the redb lock turns that race into a pause instead of a lost
    // message (or, in the other order, a dead resident node).
    let store = Arc::new(open_topic_store(&ctx.home, ctx.topic, STORE_LOCK_WAIT).await?);
    let node = topics::TopicNode::spawn(&ctx.node, ctx.node_config(Arc::clone(&store))).await?;

    let mut book = PeerBook::open(&ctx.home, ctx.topic);
    let mut changed = false;
    for peer in &ctx.ticket_peers {
        changed |= book.record(peer.clone());
    }
    if changed {
        book.save();
    }
    let bootstrap = book.list();
    let (sender, mut events) = node.join(ctx.topic, &bootstrap).await?;

    let neighbor = if bootstrap.is_empty() {
        // Nothing to wait *for*: this endpoint bound a moment ago on a random
        // port and no peer has been told about it, so the 15 seconds would buy
        // only a 15-second pause on every publish from a node that has never
        // been given a ticket.
        eprintln!(
            "wires advanced publish: no known peer on topic {:?} — storing locally (pass `--peer <ticket>`, \
             or keep a `wires watch` running)",
            ctx.name
        );
        None
    } else {
        wait_for_neighbor(&mut events, wait).await
    };
    match neighbor {
        Some(peer) => {
            tracing::info!(peer = %peer.hex(), "neighbor up; publishing");
            if book.record(TopicPeer::new(peer)) {
                book.save();
            }
        }
        None if !bootstrap.is_empty() => eprintln!(
            "wires advanced publish: no reachable peer on topic {:?} after {}s — the message is stored \
             locally and reaches the topic on the next catch-up",
            ctx.name,
            wait.as_secs()
        ),
        None => {}
    }

    let (version, key) = current_fabric_key(&ctx.keystore)?;
    let mut published = 0usize;
    while let Some(text) = messages.next().await? {
        let envelope = append_local(
            &store,
            &ctx.node,
            ctx.topic,
            version,
            &key,
            &text,
            now_unix(),
        )?;
        if neighbor.is_some()
            && let Err(e) = sender.broadcast(&envelope).await
        {
            // Warned, never fatal — the same rule the tail's publish path
            // follows, and for the same reason: the sequence is *already*
            // allocated and the message is already in the log, so aborting here
            // would drop every remaining line and invite a retry that
            // republishes this one under a fresh sequence (a duplicate line on
            // the topic, from a peer restart).
            tracing::warn!(
                seq = envelope.seq.0,
                "stored but not broadcast (replay will carry it): {e:#}"
            );
        }
        tracing::info!(seq = envelope.seq.0, "published");
        published += 1;
    }
    if published == 0 {
        eprintln!("wires advanced publish: nothing to publish");
    } else if neighbor.is_some() {
        // Gossip needs a moment to actually put the bytes on the wire; closing
        // the endpoint first would drop them.
        tokio::time::sleep(linger).await;
    }
    node.shutdown().await?;
    Ok(())
}

/// Wait up to `wait` for the first mesh neighbor, discarding other events.
async fn wait_for_neighbor(
    events: &mut tokio::sync::mpsc::Receiver<topics::TopicEvent>,
    wait: Duration,
) -> Option<NodeId> {
    let until = deadline(wait);
    loop {
        match tokio::time::timeout_at(until, events.recv()).await {
            Ok(Some(topics::TopicEvent::NeighborUp(peer))) => return Some(peer),
            // Nothing else here is worth waiting on: a one-shot publish neither
            // prints nor ingests.
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advanced::{Advanced, AdvancedArgs};
    use crate::testutil::provisioned;
    use crate::{Cli, Command};
    use clap::Parser;
    use library::NodeIdentity;

    #[test]
    fn publish_parses_the_documented_flags() {
        let cli =
            Cli::try_parse_from(["wires", "advanced", "publish", "ops", "-m", "ship it"]).unwrap();
        match cli.command {
            Command::Advanced(AdvancedArgs {
                cmd: Advanced::Publish(a),
            }) => {
                assert_eq!(a.common.topic, "ops");
                assert_eq!(a.message.as_deref(), Some("ship it"));
            }
            _ => panic!("expected publish"),
        }
        // No `--message` is the stdin form, not an error.
        let cli = Cli::try_parse_from(["wires", "advanced", "publish", "ops"]).unwrap();
        match cli.command {
            Command::Advanced(AdvancedArgs {
                cmd: Advanced::Publish(a),
            }) => assert!(a.message.is_none()),
            _ => panic!("expected publish"),
        }
    }

    #[tokio::test]
    async fn publish_reaches_a_minimal_tail_loop_over_the_control_socket() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = Arc::new(member.store());

        // The socket lives under a short scratch path on purpose: a unix socket
        // path is capped at ~104 bytes and Bazel's temp root is longer than
        // that. `socket_path`'s own shape is asserted in `ipc`'s suite.
        let scratch = ipc::ScratchDir::new("pub");
        let path = scratch.socket("p.sock");
        let socket = ipc::ControlSocket::bind(&path).await.unwrap();
        let (tx, mut requests) = tokio::sync::mpsc::channel(4);
        let server = socket.spawn(tx);

        // The tail loop, reduced to the part `wires advanced publish` talks to: the
        // single sequence allocator.
        let loop_store = Arc::clone(&store);
        let node = NodeIdentity::from_seed([2u8; 32]);
        let (topic, version, key) = (ctx.topic, member.version, member.key.clone());
        let tail = tokio::spawn(async move {
            while let Some(request) = requests.recv().await {
                let answer =
                    append_local(&loop_store, &node, topic, version, &key, &request.text, 5)
                        .map(|envelope| envelope.seq.0)
                        .map_err(|e| format!("{e:#}"));
                let _ = request.reply.send(answer);
            }
        });

        let mut client = ipc::ControlClient::connect(&path).await.unwrap().unwrap();
        assert_eq!(client.publish("hello").await.unwrap(), 0);
        assert_eq!(client.publish("again").await.unwrap(), 1);

        // The tail — not the publisher — allocated and stored them.
        let stored = store.read_backfill(10).unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].open(&member.key).unwrap(), b"hello");
        assert_eq!(stored[1].open(&member.key).unwrap(), b"again");
        assert_eq!(stored[1].prev_hash, stored[0].message_hash().unwrap());

        drop(client);
        server.abort();
        tail.abort();
    }

    /// A streaming publish survives a refusal and a tail restart.
    ///
    /// `tail -f app.log | wires advanced publish ops` used to end on the first error —
    /// and the tail answers `{"err":…}` for something as ordinary as "no fabric
    /// key for the current commit yet", in the window between a `roster commit`
    /// and the operator's `wires advanced import`. The pipe died permanently and every
    /// later line was silently never published.
    #[tokio::test]
    async fn a_streaming_publish_survives_a_refusal_and_a_reconnect() {
        let scratch = ipc::ScratchDir::new("retry");
        let path = scratch.socket("r.sock");

        // A "tail" that refuses the first line the way a keyless one does, then
        // answers normally.
        let socket = ipc::ControlSocket::bind(&path).await.unwrap();
        let (tx, mut requests) = tokio::sync::mpsc::channel(4);
        let server = socket.spawn(tx);
        let tail = tokio::spawn(async move {
            let mut seen = 0u64;
            while let Some(request) = requests.recv().await {
                let answer = if seen == 0 {
                    Err("no fabric key in the keyring".to_string())
                } else {
                    Ok(seen)
                };
                seen += 1;
                let _ = request.reply.send(answer);
            }
        });

        let mut client = ipc::ControlClient::connect(&path).await.unwrap();
        assert!(client.is_some(), "the fixture tail is listening");
        let seq = publish_line(&mut client, &path, "first", Duration::from_millis(10))
            .await
            .expect("a refusal must cost a retry, not the whole feed");
        assert_eq!(seq, 1, "the retry is what got through");
        let seq = publish_line(&mut client, &path, "second", Duration::from_millis(10))
            .await
            .expect("and the stream carries on");
        assert_eq!(seq, 2);

        // The tail goes away mid-stream: the line is reported, once, after its
        // attempts — never a silent stop.
        tail.abort();
        server.abort();
        std::fs::remove_file(&path).ok();
        let e = publish_line(&mut client, &path, "third", Duration::from_millis(10))
            .await
            .expect_err("with no tail there is nothing to publish through");
        assert!(format!("{e:#}").contains("no resident tail"), "{e:#}");
    }

    /// A publisher does not wait forever on a tail that never answers.
    #[tokio::test]
    async fn a_publish_gives_up_on_a_tail_that_never_answers() {
        let scratch = ipc::ScratchDir::new("mute");
        let path = scratch.socket("m.sock");
        let socket = ipc::ControlSocket::bind(&path).await.unwrap();
        // Bound and accepting, but nothing ever reads the request channel: the
        // shape of a tail wedged on a slow peer.
        let (tx, _requests) = tokio::sync::mpsc::channel(4);
        let server = socket.spawn(tx);

        let mut client = ipc::ControlClient::connect(&path).await.unwrap().unwrap();
        let e = client
            .publish_within("anyone there?", Duration::from_millis(50))
            .await
            .expect_err("a wedged tail must be reported, not waited on");
        assert!(format!("{e:#}").contains("did not answer"), "{e:#}");
        server.abort();
    }
}
