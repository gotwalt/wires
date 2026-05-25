//! The pairing flow: issue a grant over the wire instead of by pasting node ids.
//!
//! A requester dials the operator on the pairing ALPN and announces the scope
//! it wants. The operator — who holds the root key — sees the requester's
//! **iroh-authenticated** node id, decides whether to consent, and on yes mints
//! a [`CapabilityTicket`] whose `subject` *is* that authenticated node id. So a
//! paired ticket is non-transferable by construction: the subject can only be
//! the node that actually paired.
//!
//! This is a UX wrapper around `grant` — the operator still supplies the target
//! and scope; pairing only collects (and authenticates) the subject.

use anyhow::{Context, Result, anyhow, bail};
use iroh::{Endpoint, EndpointAddr};
use library::{CapabilityTicket, Grant, NodeId, NodeIdentity, Scope};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::transport;

/// The custom ALPN for the pairing exchange.
pub const PAIR_ALPN: &[u8] = b"wires/pair/0";

/// Largest pairing message accepted, in bytes.
const MAX_MSG: usize = 64 * 1024;

/// What the operator will mint for a consented requester. The `subject` is not
/// here — it is the authenticated requester, filled in at pairing time.
pub struct PairTerms {
    /// The responder the issued ticket points at.
    pub target: NodeId,
    /// The scope granted (authoritative; the requester's ask is only advisory).
    pub scope: Scope,
    /// Grant expiry, unix seconds.
    pub not_after: i64,
    /// Direct address hints embedded in the issued ticket.
    pub addrs: Vec<std::net::SocketAddr>,
    /// Relay URL embedded in the issued ticket.
    pub relay_url: Option<String>,
}

/// Requester → operator: the scope being asked for (advisory).
#[derive(serde::Serialize, serde::Deserialize)]
struct PairRequest {
    scope: String,
}

/// Operator → requester: the issued ticket, or a denial.
#[derive(serde::Serialize, serde::Deserialize)]
enum PairResponse {
    Granted { ticket: String },
    Denied { reason: String },
}

// ---------------------------------------------------------------------------
// Operator side
// ---------------------------------------------------------------------------

/// Bind a pairing endpoint for `node` and accept requests (see [`pair_accept_on`]).
pub async fn pair_accept(
    node: NodeIdentity,
    root: NodeIdentity,
    terms: PairTerms,
    relay_url: Option<&str>,
    consent: impl Fn(NodeId, &str) -> bool,
    once: bool,
) -> Result<()> {
    let endpoint = transport::bind_with_alpn(&node, relay_url, PAIR_ALPN).await?;
    pair_accept_on(endpoint, root, terms, consent, once).await
}

/// Accept pairing requests on `endpoint`. For each, call `consent` with the
/// authenticated requester and its requested scope; on yes, mint and return a
/// ticket bound to that requester. Stops after one request if `once`.
pub async fn pair_accept_on(
    endpoint: Endpoint,
    root: NodeIdentity,
    terms: PairTerms,
    consent: impl Fn(NodeId, &str) -> bool,
    once: bool,
) -> Result<()> {
    eprintln!(
        "wires pair: operator {} on {:?} — waiting",
        transport::to_node_id(&endpoint.id()).hex(),
        endpoint.bound_sockets()
    );
    while let Some(incoming) = endpoint.accept().await {
        let conn = incoming.await.context("accepting pairing connection")?;
        let requester = transport::to_node_id(&conn.remote_id());
        let (mut send, mut recv) = conn.accept_bi().await.context("accepting bi-stream")?;
        let req: PairRequest = read_json(&mut recv).await?;

        let resp = if consent(requester, &req.scope) {
            let grant = Grant::mint(&root, requester, terms.scope.clone(), terms.not_after)?;
            let ticket = CapabilityTicket::new(terms.target, terms.scope.clone(), grant)
                .with_addrs(terms.addrs.clone())
                .with_relay_url(terms.relay_url.clone());
            eprintln!(
                "wires pair: granted {} to {}",
                terms.scope.as_str(),
                requester.hex()
            );
            PairResponse::Granted {
                ticket: ticket.encode()?,
            }
        } else {
            eprintln!("wires pair: declined {}", requester.hex());
            PairResponse::Denied {
                reason: "operator declined".to_string(),
            }
        };
        write_json(&mut send, &resp).await?;
        send.finish().ok();
        // Let the response flush; the requester closes once it has read it.
        // Bound the wait so a vanished requester can't pin the loop.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed()).await;
        if once {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Requester side
// ---------------------------------------------------------------------------

/// Bind a pairing endpoint for `node` and request a ticket (see [`pair_request_on`]).
pub async fn pair_request(
    node: NodeIdentity,
    operator: EndpointAddr,
    scope: Scope,
    relay_url: Option<&str>,
) -> Result<String> {
    let endpoint = transport::bind_with_alpn(&node, relay_url, PAIR_ALPN).await?;
    pair_request_on(endpoint, operator, scope).await
}

/// Dial `operator` on `endpoint`, announce `scope`, and return the issued
/// ticket text (or an error if the operator declined).
pub async fn pair_request_on(
    endpoint: Endpoint,
    operator: EndpointAddr,
    scope: Scope,
) -> Result<String> {
    let conn = endpoint
        .connect(operator, PAIR_ALPN)
        .await
        .map_err(|e| anyhow!("dialing operator: {e}"))?;
    let (mut send, mut recv) = conn.open_bi().await.context("opening bi-stream")?;
    write_json(
        &mut send,
        &PairRequest {
            scope: scope.as_str().to_string(),
        },
    )
    .await?;
    send.finish().ok();
    let resp = read_json::<_, PairResponse>(&mut recv).await?;
    // Gracefully close so our CONNECTION_CLOSE flushes to the operator, whose
    // flush-wait then returns without hitting the idle timeout.
    endpoint.close().await;
    match resp {
        PairResponse::Granted { ticket } => Ok(ticket),
        PairResponse::Denied { reason } => bail!("pairing denied: {reason}"),
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed JSON over a stream
// ---------------------------------------------------------------------------

async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("encoding pairing message")?;
    let len = u32::try_from(bytes.len()).map_err(|_| anyhow!("pairing message too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    Ok(())
}

async fn read_json<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .await
        .context("reading message length")?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_MSG {
        bail!("pairing message too large: {n}");
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .await
        .context("reading message body")?;
    serde_json::from_slice(&buf).context("decoding pairing message")
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{Crl, check_accept};

    async fn test_ep(id: &NodeIdentity) -> Endpoint {
        Endpoint::empty_builder()
            .secret_key(transport::secret_key(id))
            .alpns(vec![PAIR_ALPN.to_vec()])
            .bind()
            .await
            .unwrap()
    }

    fn localhost_socks(ep: &Endpoint) -> Vec<std::net::SocketAddr> {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
        ep.bound_sockets()
            .into_iter()
            .map(|sock| match sock {
                SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, v4.port()))
                }
                SocketAddr::V6(v6) if v6.ip().is_unspecified() => SocketAddr::V6(
                    SocketAddrV6::new(Ipv6Addr::LOCALHOST, v6.port(), v6.flowinfo(), v6.scope_id()),
                ),
                other => other,
            })
            .collect()
    }

    #[tokio::test]
    async fn pairing_issues_a_grant_bound_to_the_requester() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let root_id = root.node_id();
        let operator = NodeIdentity::from_seed([2u8; 32]);
        let requester = NodeIdentity::from_seed([3u8; 32]);
        let target = NodeIdentity::from_seed([4u8; 32]).node_id();

        let op_ep = test_ep(&operator).await;
        let op_addr =
            transport::endpoint_addr(&operator.node_id(), &localhost_socks(&op_ep), None).unwrap();
        let terms = PairTerms {
            target,
            scope: Scope::new("tools.rg"),
            not_after: i64::MAX,
            addrs: Vec::new(),
            relay_url: None,
        };
        let acc = tokio::spawn(pair_accept_on(op_ep, root, terms, |_, _| true, true));

        let req_ep = test_ep(&requester).await;
        // The requester *asks* for a different scope; the operator's terms are
        // authoritative, so the issued ticket carries the operator's scope.
        let text = pair_request_on(req_ep, op_addr, Scope::new("tools.requested"))
            .await
            .unwrap();
        let ticket = CapabilityTicket::decode(&text).unwrap();

        assert_eq!(ticket.grant.subject, requester.node_id());
        assert_eq!(ticket.target, target);
        assert_eq!(ticket.scope.as_str(), "tools.rg");
        assert!(check_accept(&ticket.grant, root_id, requester.node_id(), 0, &Crl::new()).is_ok());
        let _ = acc.await;
    }

    #[tokio::test]
    async fn declined_pairing_errors() {
        let root = NodeIdentity::from_seed([5u8; 32]);
        let operator = NodeIdentity::from_seed([6u8; 32]);
        let requester = NodeIdentity::from_seed([7u8; 32]);
        let target = NodeIdentity::from_seed([8u8; 32]).node_id();

        let op_ep = test_ep(&operator).await;
        let op_addr =
            transport::endpoint_addr(&operator.node_id(), &localhost_socks(&op_ep), None).unwrap();
        let terms = PairTerms {
            target,
            scope: Scope::new("tools.rg"),
            not_after: i64::MAX,
            addrs: Vec::new(),
            relay_url: None,
        };
        let acc = tokio::spawn(pair_accept_on(op_ep, root, terms, |_, _| false, true));

        let req_ep = test_ep(&requester).await;
        let result = pair_request_on(req_ep, op_addr, Scope::new("tools.rg")).await;
        assert!(result.is_err());
        let _ = acc.await;
    }

    #[tokio::test]
    async fn read_json_rejects_oversized_message() {
        // A length prefix beyond MAX_MSG must be refused without allocating it.
        let big = (MAX_MSG as u32 + 1).to_be_bytes();
        let mut cur = std::io::Cursor::new(big.to_vec());
        let parsed: Result<PairRequest> = read_json(&mut cur).await;
        assert!(parsed.is_err());
    }
}
