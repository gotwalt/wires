//! Frame I/O for the directory's two ALPNs, the one-request client
//! ([`ask`]) every other role uses, and the admin's [`publish`].
//!
//! The frames are [`library::directory`]'s. Nothing is sized from a peer's
//! length prefix: a buffer grows only as bytes arrive, and a prefix over the
//! limit is refused before a byte of body is read. Every request is at most
//! [`MAX_SMALL_DIRECTORY_FRAME`] ([`read_request`]); only a publish's
//! `items` may be larger ([`read_items`]), and a directory reads them only
//! after the publish's head checked out.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::Endpoint;
use library::{
    DIRECTORY_ALPN, DirectoryAnswer, DirectoryRequest, IdToken, MAX_DIRECTORY_FRAME,
    MAX_SMALL_DIRECTORY_FRAME, NodeId, SignedPolicy, SubFrame, SubRequest,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::host::transport;

/// How long one dial may take.
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one frame (a request, or the answer to one) may take.
pub(crate) const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// Write already-encoded frame bytes.
pub(crate) async fn write<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    w.write_all(bytes)
        .await
        .context("writing a directory frame")
}

/// The 4-byte length prefix, or `None` at a clean end of stream.
async fn read_prefix<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<[u8; 4]>> {
    let mut prefix = [0u8; 4];
    match r.read_exact(&mut prefix).await {
        Ok(_) => Ok(Some(prefix)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e).context("reading a directory frame"),
    }
}

/// Read `len` more body bytes onto `buf` (which holds the prefix and maybe
/// the body's first bytes), growing only as they arrive.
async fn read_rest<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>, len: usize) -> Result<()> {
    let rest = (4 + len).saturating_sub(buf.len()) as u64;
    (&mut *r)
        .take(rest)
        .read_to_end(buf)
        .await
        .context("reading a directory frame body")?;
    if buf.len() != 4 + len {
        bail!("truncated directory frame");
    }
    Ok(())
}

/// A frame type's decoder: the first whole frame in a buffer, if any.
type Decoder<T> = fn(&[u8]) -> library::Result<Option<(T, usize)>>;

/// Read one frame of at most `max` bytes and decode it with `decode`.
async fn read_capped<R, T>(r: &mut R, max: usize, decode: Decoder<T>) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
{
    let Some(prefix) = read_prefix(r).await? else {
        return Ok(None);
    };
    let len = u32::from_be_bytes(prefix) as usize;
    if len > max {
        bail!("a {len}-byte directory frame (at most {max})");
    }
    let mut buf = Vec::with_capacity(4 + len.min(MAX_SMALL_DIRECTORY_FRAME));
    buf.extend_from_slice(&prefix);
    read_rest(r, &mut buf, len).await?;
    match decode(&buf)? {
        Some((frame, _)) => Ok(Some(frame)),
        None => bail!("truncated directory frame"),
    }
}

/// Read one [`DirectoryRequest`] within [`FRAME_TIMEOUT`], at most
/// [`MAX_SMALL_DIRECTORY_FRAME`] (refused from the prefix alone).
pub(crate) async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<DirectoryRequest> {
    tokio::time::timeout(
        FRAME_TIMEOUT,
        read_capped(r, MAX_SMALL_DIRECTORY_FRAME, DirectoryRequest::decode),
    )
    .await
    .map_err(|_| anyhow!("no directory request within {FRAME_TIMEOUT:?}"))??
    .ok_or_else(|| anyhow!("the stream ended before a request"))
}

/// Read the `items` frame of a publish whose head checked out, within
/// [`FRAME_TIMEOUT`]: at most [`MAX_DIRECTORY_FRAME`], the one request that
/// may be that large.
pub(crate) async fn read_items<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<library::Item>> {
    let frame = tokio::time::timeout(
        FRAME_TIMEOUT,
        read_capped(r, MAX_DIRECTORY_FRAME, DirectoryRequest::decode),
    )
    .await
    .map_err(|_| anyhow!("no items within {FRAME_TIMEOUT:?}"))??
    .ok_or_else(|| anyhow!("the stream ended before the items"))?;
    match frame {
        DirectoryRequest::Items { items } => Ok(items),
        _ => bail!("a publish's head must be followed by its items"),
    }
}

/// Read the frame that opens a `wires/directory/2` stream, before its
/// sender is admitted, within `deadline`: at most
/// [`MAX_SMALL_DIRECTORY_FRAME`]. The caller checks it is a `hello`.
pub(crate) async fn read_hello<R: AsyncRead + Unpin>(
    r: &mut R,
    deadline: Duration,
) -> Result<DirectoryRequest> {
    tokio::time::timeout(
        deadline,
        read_capped(r, MAX_SMALL_DIRECTORY_FRAME, DirectoryRequest::decode),
    )
    .await
    .map_err(|_| anyhow!("no hello within {deadline:?}"))??
    .ok_or_else(|| anyhow!("the stream ended before a hello"))
}

/// Read one [`DirectoryAnswer`] within [`FRAME_TIMEOUT`].
pub(crate) async fn read_answer<R: AsyncRead + Unpin>(r: &mut R) -> Result<DirectoryAnswer> {
    tokio::time::timeout(
        FRAME_TIMEOUT,
        read_capped(r, MAX_DIRECTORY_FRAME, DirectoryAnswer::decode),
    )
    .await
    .map_err(|_| anyhow!("no directory answer within {FRAME_TIMEOUT:?}"))??
    .ok_or_else(|| anyhow!("the directory closed without an answer"))
}

/// Read one [`SubRequest`] within [`FRAME_TIMEOUT`] (at most
/// [`MAX_SMALL_DIRECTORY_FRAME`]).
pub(crate) async fn read_sub_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<SubRequest> {
    tokio::time::timeout(
        FRAME_TIMEOUT,
        read_capped(r, MAX_SMALL_DIRECTORY_FRAME, SubRequest::decode),
    )
    .await
    .map_err(|_| anyhow!("no subscription frame within {FRAME_TIMEOUT:?}"))??
    .ok_or_else(|| anyhow!("the stream ended before a subscription frame"))
}

/// Read the next [`SubFrame`], with no deadline (a subscription is quiet
/// between beats); `None` when the directory ends the stream.
pub(crate) async fn read_sub_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<SubFrame>> {
    read_capped(r, MAX_DIRECTORY_FRAME, SubFrame::decode).await
}

/// Dial directory `dir` by key, open with `hello` (our ID token, when we
/// act for a person), send `request`, and return its one answer.
pub(crate) async fn ask(
    endpoint: &Endpoint,
    dir: NodeId,
    id_token: Option<IdToken>,
    request: &DirectoryRequest,
) -> Result<DirectoryAnswer> {
    exchange(endpoint, dir, id_token, &[request.encode()?]).await
}

/// Publish `policy` to directory `dir`: `hello` (no token: the root's
/// signature is the whole check), `publish {head}`, then `items {items}`,
/// sent together; the directory reads the items only if the head checked
/// out, and answers once.
pub(crate) async fn publish(
    endpoint: &Endpoint,
    dir: NodeId,
    policy: &SignedPolicy,
) -> Result<DirectoryAnswer> {
    let head = DirectoryRequest::Publish {
        head: policy.head.clone(),
    }
    .encode()?;
    let items = DirectoryRequest::Items {
        items: policy.items.clone(),
    }
    .encode()?;
    exchange(endpoint, dir, None, &[head, items]).await
}

/// Dial `dir`, write `hello` then the already-encoded `frames`, and read
/// the one answer: the dial within [`DIAL_TIMEOUT`], everything after it
/// (the stream, the writes, the answer) within [`FRAME_TIMEOUT`], so one
/// exchange ([`ask`], [`publish`]) ends within 15 s whatever the directory
/// does.
async fn exchange(
    endpoint: &Endpoint,
    dir: NodeId,
    id_token: Option<IdToken>,
    frames: &[Vec<u8>],
) -> Result<DirectoryAnswer> {
    let addr = transport::endpoint_addr(&dir, &[], None)?;
    let conn = tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, DIRECTORY_ALPN))
        .await
        .map_err(|_| anyhow!("no answer within {DIAL_TIMEOUT:?}"))?
        .map_err(|e| anyhow!("dialing directory {}…: {e}", dir.short()))?;
    let hello = DirectoryRequest::Hello { id_token };
    let answer = tokio::time::timeout(FRAME_TIMEOUT, async {
        let (mut send, mut recv) = conn.open_bi().await.context("opening a stream")?;
        write(&mut send, &hello.encode()?).await?;
        for frame in frames {
            write(&mut send, frame).await?;
        }
        send.finish().ok();
        read_answer(&mut recv).await
    })
    .await
    .unwrap_or_else(|_| Err(anyhow!("no directory answer within {FRAME_TIMEOUT:?}")));
    conn.close(0u32.into(), b"done");
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_items_may_be_large() {
        // A 1 MiB request: refused from its prefix alone, whatever it is.
        let mut bytes = ((1usize << 20) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(br#"{"type":"items","items":[]}"#);
        let e = read_request(&mut bytes.as_slice()).await.unwrap_err();
        assert!(format!("{e:#}").contains("1048576-byte"), "{e:#}");
        // Over the hard limit, even items: refused from the prefix.
        let over = ((MAX_DIRECTORY_FRAME + 1) as u32).to_be_bytes();
        assert!(read_items(&mut over.as_slice()).await.is_err());
        // A small request reads back; items read back as items, and
        // anything else where items belong is refused.
        let hello = DirectoryRequest::Hello { id_token: None }.encode().unwrap();
        assert_eq!(
            read_request(&mut hello.as_slice()).await.unwrap(),
            DirectoryRequest::Hello { id_token: None }
        );
        let items = DirectoryRequest::Items { items: vec![] }.encode().unwrap();
        assert!(read_items(&mut items.as_slice()).await.unwrap().is_empty());
        assert!(read_items(&mut hello.as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn a_subscriber_sends_nothing_large() {
        let over = ((MAX_SMALL_DIRECTORY_FRAME + 1) as u32).to_be_bytes();
        assert!(read_sub_request(&mut over.as_slice()).await.is_err());
        // A clean end of stream is not a frame.
        assert!(read_sub_frame(&mut [].as_slice()).await.unwrap().is_none());
    }

    /// Takes a connection on the directory ALPN and then does nothing: never
    /// takes the stream, never reads, never answers.
    #[derive(Debug, Clone)]
    struct Silent;

    impl iroh::protocol::ProtocolHandler for Silent {
        async fn accept(
            &self,
            conn: iroh::endpoint::Connection,
        ) -> Result<(), iroh::protocol::AcceptError> {
            tokio::time::sleep(Duration::from_secs(120)).await;
            drop(conn);
            Ok(())
        }
    }

    /// An exchange with a directory that takes the connection and never
    /// answers ends within the dial and frame timeouts, even when its frames
    /// are too large to be buffered (the writes block): the admin's publish
    /// has a real bound (card 48).
    #[tokio::test]
    async fn a_directory_that_never_answers_is_given_up_on() {
        let book = iroh::address_lookup::memory::MemoryLookup::new();
        let bind = |who: library::NodeIdentity| {
            let book = book.clone();
            async move {
                Endpoint::builder(iroh::endpoint::presets::Minimal)
                    .secret_key(transport::secret_key(&who))
                    .address_lookup(book)
                    .bind()
                    .await
                    .unwrap()
            }
        };
        let dir = library::NodeIdentity::generate();
        let dir_id = dir.node_id();
        let silent = bind(dir).await;
        let socks: Vec<std::net::SocketAddr> = silent
            .bound_sockets()
            .into_iter()
            .map(crate::net::dialable)
            .collect();
        book.add_endpoint_info(transport::endpoint_addr(&dir_id, &socks, None).unwrap());
        let _router = iroh::protocol::Router::builder(silent)
            .accept(DIRECTORY_ALPN, Silent)
            .spawn();
        let me = bind(library::NodeIdentity::generate()).await;
        // Far more than any stream window: the writes can't all be buffered.
        let big = vec![0u8; 8 << 20];
        let started = std::time::Instant::now();
        let e = exchange(&me, dir_id, None, &[big]).await.unwrap_err();
        let took = started.elapsed();
        assert!(took >= FRAME_TIMEOUT, "{took:?}: {e:#}");
        assert!(
            took < DIAL_TIMEOUT + FRAME_TIMEOUT + Duration::from_secs(2),
            "{took:?}"
        );
        assert!(format!("{e:#}").contains("no directory answer"), "{e:#}");
        me.close().await;
    }
}
