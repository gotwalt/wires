//! `wires login`: bind this node's key to the user's IdP identity (card 04).
//!
//! An ordinary OIDC authorization-code flow with PKCE and a loopback redirect
//! (`http://127.0.0.1:<port>/callback`, RFC 8252 §7.3), with one twist: the
//! request's `nonce` is [`OidcNonce::for_node`] of this node's key. The IdP
//! signs an ID token carrying that nonce, so the token alone proves "the
//! holder of node key *K* signed in as *alice@corp*" — to anyone who checks
//! the IdP's signature, with no wires-run attestor in the loop.
//!
//! Then:
//!
//! 1. the token is verified locally (the same [`KeyFetcher::verify`] a host
//!    runs), so a misconfigured client fails here and not at the host;
//! 2. it is stored in the keystore as [`ID_TOKEN_FILE`] (`0600`), plus
//!    [`REFRESH_TOKEN_FILE`] when the IdP granted one;
//! 3. nothing is published: `wires call` presents the stored token in its
//!    session `Hello` (and `wires inbox` in its fetch), and the host verifies
//!    it there.
//!
//! Configuration (flag, else environment): `--client-id` /
//! `WIRES_OIDC_CLIENT_ID` (required), `--client-secret` /
//! `WIRES_OIDC_CLIENT_SECRET` (Google "Desktop app" clients have a
//! non-confidential one), `--issuer` / `WIRES_OIDC_ISSUER` (default
//! `https://accounts.google.com`).
//!
//! The small HTTP/1.1 reader/writer here ([`read_request`],
//! [`write_response`]) serves only the loopback redirect (and the test
//! suite's mock issuer); it is not a general server.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use clap::Args;
use library::{Audience, B64, IdToken, IdentityClaim, Issuer, NodeId, OidcNonce, Principal};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::admin::keystore;
use crate::caller::jwks::{Discovery, KeyFetcher};

/// The default issuer: Google, the demo IdP.
pub(crate) const DEFAULT_ISSUER: &str = "https://accounts.google.com";

/// The raw ID token, in the keystore (mode `0600`).
pub(crate) const ID_TOKEN_FILE: &str = "idp-token.jwt";
/// The IdP refresh token, when one was granted (mode `0600`).
pub(crate) const REFRESH_TOKEN_FILE: &str = "idp-refresh-token";
/// How long the loopback listener waits for the browser to come back.
pub(crate) const CALLBACK_WAIT: Duration = Duration::from_secs(300);
/// The scopes requested: an ID token with the email claim, nothing more.
pub(crate) const SCOPES: &str = "openid email";
/// Largest HTTP request head + body the loopback server reads.
const MAX_REQUEST: usize = 64 * 1024;
/// How long the loopback listener keeps answering after the sign-in landed.
///
/// Browsers open more than one connection to a page they are loading (Safari
/// speculatively, others for `favicon.ico` or a retry). Closing the listener
/// the instant the code arrives leaves those finding nothing listening, and
/// the browser shows "Can't connect to the server" over a login that worked.
/// The login itself does not wait for this: it runs in the background while
/// the token exchange and the publish carry on.
pub(crate) const CALLBACK_LINGER: Duration = Duration::from_secs(3);
/// How long an answered loopback connection is drained before it is dropped.
///
/// Dropping a socket with unread request bytes makes the kernel send a reset
/// instead of a clean close, and a reset can make the browser discard the page
/// it was just sent. So the rest of the request is read and thrown away, until
/// the browser hangs up or this runs out.
const DRAIN_WAIT: Duration = Duration::from_secs(2);

/// `login` arguments.
#[derive(Args, Debug, Default)]
pub(crate) struct LoginArgs {
    /// Hex 32-byte seed of this node's key. Falls back to `$WIRES_NODE_SEED`,
    /// then `--node-seed-file`, then the keystore (`node.seed`).
    #[arg(long)]
    pub node_seed: Option<String>,
    /// Read the node key seed (hex) from this file.
    #[arg(long)]
    pub node_seed_file: Option<std::path::PathBuf>,
    /// OIDC issuer. Falls back to `$WIRES_OIDC_ISSUER`, then Google.
    #[arg(long)]
    pub issuer: Option<String>,
    /// OAuth client id. Falls back to `$WIRES_OIDC_CLIENT_ID`.
    #[arg(long)]
    pub client_id: Option<String>,
    /// OAuth client secret (non-confidential for Desktop-app clients). Falls
    /// back to `$WIRES_OIDC_CLIENT_SECRET`.
    #[arg(long)]
    pub client_secret: Option<String>,
    /// Use the stored refresh token instead of the browser when possible;
    /// falls back to the browser flow if the refreshed token is not bound to
    /// this node (Google omits `nonce` on refresh).
    #[arg(long, conflicts_with = "reuse")]
    pub refresh: bool,
    /// Re-verify the stored ID token without signing in.
    #[arg(long)]
    pub reuse: bool,
    /// Print the sign-in URL but do not try to open a browser.
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed loopback port for the redirect (default: any free port) — for
    /// `ssh -L <port>:127.0.0.1:<port>` when the browser is on another machine.
    #[arg(long, default_value_t = 0)]
    pub callback_port: u16,
}

/// An OAuth client registered with one issuer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OidcClient {
    /// The issuer the client is registered with.
    pub issuer: Issuer,
    /// The client id (also the token's expected `aud`).
    pub client_id: String,
    /// The client secret, when the IdP issues one (sent on token requests).
    pub client_secret: Option<String>,
}

impl OidcClient {
    /// Resolve from flags, else the `WIRES_OIDC_*` environment.
    fn resolve(a: &LoginArgs) -> Result<Self> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let client_id = a
            .client_id
            .clone()
            .or_else(|| env("WIRES_OIDC_CLIENT_ID"))
            .ok_or_else(|| {
                anyhow!(
                    "no OAuth client id: pass --client-id or set $WIRES_OIDC_CLIENT_ID (for \
                     Google, create a \"Desktop app\" OAuth client in the Cloud Console)"
                )
            })?;
        Ok(Self {
            issuer: Issuer::new(
                a.issuer
                    .clone()
                    .or_else(|| env("WIRES_OIDC_ISSUER"))
                    .unwrap_or_else(|| DEFAULT_ISSUER.to_string()),
            ),
            client_id,
            client_secret: a
                .client_secret
                .clone()
                .or_else(|| env("WIRES_OIDC_CLIENT_SECRET")),
        })
    }

    /// The single audience a token for this client must carry.
    fn audience(&self) -> Audience {
        Audience::new(self.client_id.clone())
    }
}

/// A PKCE verifier and its S256 challenge (RFC 7636).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pkce {
    /// The secret sent on the token request.
    pub verifier: String,
    /// `base64url(sha256(verifier))`, sent on the authorization request.
    pub challenge: String,
}

impl Pkce {
    /// A fresh random verifier (32 bytes → 43 characters).
    pub(crate) fn generate() -> Result<Self> {
        Ok(Self::from_verifier(random_token(32)?))
    }

    /// The challenge for a given verifier.
    pub(crate) fn from_verifier(verifier: String) -> Self {
        let challenge = B64.encode(ring::digest::digest(
            &ring::digest::SHA256,
            verifier.as_bytes(),
        ));
        Self {
            verifier,
            challenge,
        }
    }
}

/// `n` random bytes, base64url.
pub(crate) fn random_token(n: usize) -> Result<String> {
    use ring::rand::SecureRandom as _;
    let mut buf = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| anyhow!("the system RNG failed"))?;
    Ok(B64.encode(buf))
}

/// A completed login: the verified claim and what the IdP handed back.
#[derive(Clone, Debug)]
pub(crate) struct Login {
    /// The claim to publish.
    pub claim: IdentityClaim,
    /// Who the IdP says this node's holder is (verified locally).
    pub principal: Principal,
    /// The refresh token, when the IdP granted one.
    pub refresh_token: Option<String>,
}

/// The token endpoint's JSON reply (success or error form).
#[derive(Deserialize)]
struct TokenReply {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// The authorization URL the browser is sent to.
pub(crate) fn authorization_url(
    doc: &Discovery,
    client: &OidcClient,
    redirect: &Url,
    state: &str,
    nonce: &OidcNonce,
    pkce: &Pkce,
) -> Url {
    let mut url = doc.authorization_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", redirect.as_str())
        .append_pair("scope", SCOPES)
        .append_pair("state", state)
        .append_pair("nonce", nonce.as_str())
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256");
    url
}

/// Run the whole browser flow for `node` and verify the result.
///
/// `open` is handed the authorization URL — production opens a browser; the
/// tests drive the mock issuer with an HTTP client instead. `wait` bounds how
/// long the loopback listener waits for the redirect.
pub(crate) async fn run_flow(
    fetcher: &KeyFetcher,
    client: &OidcClient,
    node: NodeId,
    port: u16,
    open: impl FnOnce(&Url),
    wait: Duration,
) -> Result<Login> {
    let doc = fetcher.discover(&client.issuer).await?;
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("binding the loopback redirect listener on port {port}"))?;
    let port = listener.local_addr()?.port();
    let redirect = Url::parse(&format!("http://127.0.0.1:{port}/callback"))?;
    let state = random_token(16)?;
    let pkce = Pkce::generate()?;
    let url = authorization_url(
        &doc,
        client,
        &redirect,
        &state,
        &OidcNonce::for_node(&node),
        &pkce,
    );
    open(&url);
    let code = tokio::time::timeout(wait, await_callback(listener, &state, CALLBACK_LINGER))
        .await
        .map_err(|_| anyhow!("no sign-in came back within {}s", wait.as_secs()))??;
    exchange_code(fetcher, client, node, &code, &redirect, &pkce.verifier).await
}

/// Redeem an authorization `code` at `client`'s issuer (with the
/// `redirect` it was sent to and the PKCE `verifier`), then verify the ID
/// token as a claim for `node`.
///
/// `wires login` binds the token to the caller's own node; `wires gateway`
/// binds each web user's token to the gateway's node, which presents it.
pub(crate) async fn exchange_code(
    fetcher: &KeyFetcher,
    client: &OidcClient,
    node: NodeId,
    code: &str,
    redirect: &Url,
    verifier: &str,
) -> Result<Login> {
    let doc = fetcher.discover(&client.issuer).await?;
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect.as_str()),
        ("code_verifier", verifier),
    ];
    let reply = token_request(fetcher, &doc, client, &form).await?;
    finish(fetcher, client, node, reply).await
}

/// Exchange a stored refresh token for a new ID token and verify it.
pub(crate) async fn refresh(
    fetcher: &KeyFetcher,
    client: &OidcClient,
    node: NodeId,
    refresh_token: &str,
) -> Result<Login> {
    let doc = fetcher.discover(&client.issuer).await?;
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    let mut reply = token_request(fetcher, &doc, client, &form).await?;
    // Refresh responses usually omit the refresh token; keep the one we have.
    reply
        .refresh_token
        .get_or_insert_with(|| refresh_token.to_string());
    finish(fetcher, client, node, reply).await
}

/// Verify an already-held token (for `--reuse`).
pub(crate) async fn verify_held(
    fetcher: &KeyFetcher,
    client: &OidcClient,
    node: NodeId,
    id_token: IdToken,
) -> Result<Login> {
    finish(
        fetcher,
        client,
        node,
        TokenReply {
            id_token: Some(id_token.as_str().to_string()),
            refresh_token: None,
            error: None,
            error_description: None,
        },
    )
    .await
}

/// POST a form to the token endpoint and parse the reply.
async fn token_request(
    fetcher: &KeyFetcher,
    doc: &Discovery,
    client: &OidcClient,
    form: &[(&str, &str)],
) -> Result<TokenReply> {
    // Finished before the first await: the serializer isn't `Send`, and the
    // gateway runs this on a multi-threaded server.
    let body = {
        let mut body = url::form_urlencoded::Serializer::new(String::new());
        body.extend_pairs(form);
        body.append_pair("client_id", &client.client_id);
        if let Some(secret) = &client.client_secret {
            body.append_pair("client_secret", secret);
        }
        body.finish()
    };
    let resp = fetcher
        .http()
        .post(doc.token_endpoint.clone())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .body(body)
        .send()
        .await
        .with_context(|| format!("POST {}", doc.token_endpoint))?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    let reply: TokenReply = serde_json::from_slice(&bytes)
        .with_context(|| format!("token endpoint replied HTTP {status} with a non-JSON body"))?;
    if let Some(error) = &reply.error {
        bail!(
            "the IdP refused the token request: {error}{}",
            reply
                .error_description
                .as_deref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default()
        );
    }
    if !status.is_success() {
        bail!("token endpoint replied HTTP {status}");
    }
    Ok(reply)
}

/// Verify the reply's ID token as a claim for `node`, like any reader would.
async fn finish(
    fetcher: &KeyFetcher,
    client: &OidcClient,
    node: NodeId,
    reply: TokenReply,
) -> Result<Login> {
    let id_token = reply
        .id_token
        .ok_or_else(|| anyhow!("the IdP's reply has no id_token (is `openid` in the scope?)"))?;
    let claim = IdentityClaim {
        node,
        id_token: IdToken::new(id_token),
    };
    let principal = fetcher
        .verify(
            &claim,
            std::slice::from_ref(&client.issuer),
            &[client.audience()],
            crate::clock::now_unix(),
        )
        .await
        .map_err(|e| anyhow!("the IdP's ID token does not verify as a claim for this node: {e}"))?;
    Ok(Login {
        claim,
        principal,
        refresh_token: reply.refresh_token,
    })
}

/// Accept loopback connections until the redirect arrives; return its `code`.
///
/// Anything other than `GET /callback` (a browser's `favicon.ico`) gets a 404
/// and the wait continues. A wrong `state` is refused outright (RFC 6749
/// §10.12: a forged redirect), as is an `error=` redirect.
///
/// Every answered connection is closed gracefully ([`drain`]), and on success
/// the listener is handed to [`linger_signed_in`] for `linger`, so the
/// browser's other connections still find a server.
async fn await_callback(listener: TcpListener, state: &str, linger: Duration) -> Result<String> {
    let code = accept_callback(&listener, state).await?;
    tokio::spawn(linger_signed_in(listener, linger));
    Ok(code)
}

/// The "signed in" page, as [`accept_callback`] and [`linger_signed_in`] serve it.
const SIGNED_IN: &str = "wires: signed in. You can close this tab.";

/// [`await_callback`]'s accept loop.
async fn accept_callback(listener: &TcpListener, state: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let request = match read_request(&mut stream).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("ignoring a malformed loopback request: {e:#}");
                continue;
            }
        };
        let url = Url::parse(&format!("http://127.0.0.1{}", request.target))
            .unwrap_or_else(|_| Url::parse("http://127.0.0.1/").expect("static URL"));
        if request.method != "GET" || url.path() != "/callback" {
            let _ = write_response(&mut stream, 404, "text/plain", &[], b"not found").await;
            tokio::spawn(drain(stream));
            continue;
        }
        let param = |k: &str| {
            url.query_pairs()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.into_owned())
        };
        if let Some(error) = param("error") {
            let _ = page(&mut stream, 400, "Sign-in failed; see the terminal.").await;
            tokio::spawn(drain(stream));
            bail!(
                "the IdP returned an error: {error}{}",
                param("error_description")
                    .map(|d| format!(" ({d})"))
                    .unwrap_or_default()
            );
        }
        if param("state").as_deref() != Some(state) {
            let _ = page(&mut stream, 400, "State mismatch; sign-in refused.").await;
            tokio::spawn(drain(stream));
            bail!("the redirect's state does not match this login (a forged or stale redirect)");
        }
        let Some(code) = param("code") else {
            let _ = page(&mut stream, 400, "No authorization code.").await;
            tokio::spawn(drain(stream));
            bail!("the redirect carried no authorization code");
        };
        let _ = page(&mut stream, 200, SIGNED_IN).await;
        tokio::spawn(drain(stream));
        return Ok(code);
    }
}

/// Keep answering the loopback listener for `linger` after a successful
/// sign-in: `GET /callback` (whatever its query) gets the same "signed in"
/// page, anything else a 404. Then the listener closes.
///
/// Nothing here is trusted or acted on — the code has already been taken, and
/// a second redirect carrying another one is simply thanked and ignored.
async fn linger_signed_in(listener: TcpListener, linger: Duration) {
    let until = tokio::time::Instant::now() + linger;
    while let Ok(Ok((mut stream, _))) = tokio::time::timeout_at(until, listener.accept()).await {
        tokio::spawn(async move {
            let Ok(Ok(request)) = tokio::time::timeout(DRAIN_WAIT, read_request(&mut stream)).await
            else {
                return;
            };
            let path = request
                .target
                .split_once('?')
                .map_or(request.target.as_str(), |(path, _)| path);
            if request.method == "GET" && path == "/callback" {
                let _ = page(&mut stream, 200, SIGNED_IN).await;
            } else {
                let _ = write_response(&mut stream, 404, "text/plain", &[], b"not found").await;
            }
            drain(stream).await;
        });
    }
}

/// Close an answered connection gracefully: the response is written and the
/// write half shut down ([`write_response`] does both), so read and discard
/// whatever the client still sends — up to [`MAX_REQUEST`] bytes, for at most
/// [`DRAIN_WAIT`] — before dropping it. See [`DRAIN_WAIT`] for why.
async fn drain(mut stream: TcpStream) {
    let mut left = MAX_REQUEST;
    let mut sink = [0u8; 4096];
    let _ = tokio::time::timeout(DRAIN_WAIT, async {
        while left > 0 {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => left = left.saturating_sub(n),
            }
        }
    })
    .await;
}

/// A minimal HTML page.
async fn page(stream: &mut TcpStream, status: u16, text: &str) -> Result<()> {
    let body =
        format!("<!doctype html><meta charset=utf-8><title>wires login</title><p>{text}</p>");
    write_response(
        stream,
        status,
        "text/html; charset=utf-8",
        &[],
        body.as_bytes(),
    )
    .await
}

/// One parsed HTTP/1.1 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpRequest {
    /// `GET`, `POST`, …
    pub method: String,
    /// The request target (`/path?query`).
    pub target: String,
    /// The body (`Content-Length` bytes; empty without one).
    pub body: Vec<u8>,
}

/// Read one HTTP/1.1 request (head + `Content-Length` body), at most
/// [`MAX_REQUEST`] bytes.
pub(crate) async fn read_request<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<HttpRequest> {
    let mut buf = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() >= MAX_REQUEST {
            bail!("request head too large");
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed mid-request");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).context("request head is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(target)) = (first.next(), first.next()) else {
        bail!("bad request line");
    };
    let mut length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            length = v.trim().parse().context("bad Content-Length")?;
        }
    }
    if head_end + 4 + length > MAX_REQUEST {
        bail!("request body too large");
    }
    let (method, target) = (method.to_string(), target.to_string());
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < length {
        let mut chunk = vec![0u8; length - body.len()];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed mid-body");
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Ok(HttpRequest {
        method,
        target,
        body,
    })
}

/// Write one HTTP/1.1 response and close the exchange (`Connection: close`).
pub(crate) async fn write_response<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\nCache-Control: no-store\r\n",
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Index of the first occurrence of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Write `contents` to `path` with mode `0600`, atomically (temp + rename).
pub(crate) fn save_secret(path: &Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    std::io::Write::write_all(&mut file, contents.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Print the URL and (unless told not to) try the platform's browser opener.
fn open_browser(url: &Url, launch: bool) {
    eprintln!("wires login: sign in at\n\n  {url}\n");
    if !launch {
        return;
    }
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let spawned = std::process::Command::new(opener)
        .arg(url.as_str())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if spawned.is_err() {
        eprintln!("wires login: could not launch a browser ({opener}); open the URL yourself");
    }
}

/// `wires login`.
pub(crate) async fn login_cmd(a: LoginArgs) -> Result<()> {
    crate::init_logging();
    let ks = keystore::Keystore::resolve()?;
    let home = keystore::home()?;
    let node =
        keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?.node_id();
    let client = OidcClient::resolve(&a)?;
    let fetcher = KeyFetcher::new(Some(home.join("jwks")))?;
    let token_path = ks.path(ID_TOKEN_FILE);
    let refresh_path = ks.path(REFRESH_TOKEN_FILE);

    let launch = !a.no_browser;
    let interactive = || {
        run_flow(
            &fetcher,
            &client,
            node,
            a.callback_port,
            move |url| open_browser(url, launch),
            CALLBACK_WAIT,
        )
    };
    let login = if a.reuse {
        let held = std::fs::read_to_string(&token_path)
            .with_context(|| format!("no stored ID token at {}", token_path.display()))?;
        verify_held(&fetcher, &client, node, IdToken::new(held.trim())).await?
    } else if a.refresh {
        match std::fs::read_to_string(&refresh_path) {
            Ok(rt) => match refresh(&fetcher, &client, node, rt.trim()).await {
                Ok(login) => login,
                Err(e) => {
                    eprintln!(
                        "wires login: refresh did not yield a node-bound token ({e:#}); signing in again"
                    );
                    interactive().await?
                }
            },
            Err(_) => {
                eprintln!("wires login: no refresh token stored; signing in again");
                interactive().await?
            }
        }
    } else {
        interactive().await?
    };

    save_secret(&token_path, login.claim.id_token.as_str())?;
    if let Some(rt) = &login.refresh_token {
        save_secret(&refresh_path, rt)?;
    }
    eprintln!(
        "wires login: node {} is {} (token stored in {}, valid until unix {})",
        node.hex(),
        login.principal.name(),
        token_path.display(),
        login.principal.not_after
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller::mock_idp::MockIdp;
    use library::{IdTokenError, NodeIdentity};
    use proptest::prelude::*;

    const PATIENCE: Duration = Duration::from_secs(20);

    fn node() -> NodeId {
        NodeIdentity::from_seed([4; 32]).node_id()
    }

    #[test]
    fn pkce_matches_the_rfc_7636_appendix_b_vector() {
        let p = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into());
        assert_eq!(p.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn a_fresh_pkce_verifier_is_long_and_unique() {
        let (a, b) = (Pkce::generate().unwrap(), Pkce::generate().unwrap());
        assert_eq!(a.verifier.len(), 43);
        assert_ne!(a.verifier, b.verifier);
    }

    #[test]
    fn the_authorization_url_carries_every_binding_parameter() {
        let doc = Discovery {
            issuer: "https://idp.example".into(),
            authorization_endpoint: Url::parse("https://idp.example/auth?x=1").unwrap(),
            token_endpoint: Url::parse("https://idp.example/token").unwrap(),
            jwks_uri: Url::parse("https://idp.example/jwks").unwrap(),
        };
        let client = OidcClient {
            issuer: Issuer::new("https://idp.example"),
            client_id: "cid".into(),
            client_secret: None,
        };
        let redirect = Url::parse("http://127.0.0.1:5555/callback").unwrap();
        let pkce = Pkce::from_verifier("v".into());
        let nonce = OidcNonce::for_node(&node());
        let url = authorization_url(&doc, &client, &redirect, "st", &nonce, &pkce);
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["x"], "1");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], "cid");
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:5555/callback");
        assert_eq!(q["scope"], "openid email");
        assert_eq!(q["state"], "st");
        assert_eq!(q["nonce"], nonce.as_str());
        assert_eq!(q["code_challenge"], pkce.challenge);
        assert_eq!(q["code_challenge_method"], "S256");
    }

    #[tokio::test]
    async fn read_request_parses_head_and_body() {
        let raw = b"POST /token?a=b HTTP/1.1\r\nHost: x\r\ncontent-length: 5\r\n\r\nhello";
        let mut r = &raw[..];
        let req = read_request(&mut r).await.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/token?a=b");
        assert_eq!(req.body, b"hello");
        let mut short = &b"GET / HTTP/1.1\r\n"[..];
        assert!(read_request(&mut short).await.is_err());
    }

    proptest! {
        /// Any body round-trips through the reader, whatever its bytes.
        #[test]
        fn read_request_round_trips_bodies(body in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let mut raw = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
            raw.extend_from_slice(&body);
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let req = rt.block_on(async { read_request(&mut &raw[..]).await }).unwrap();
            prop_assert_eq!(req.body, body);
        }
    }

    #[test]
    fn secrets_are_written_0600() {
        let dir = crate::testutil::ScratchDir::new("sec");
        let path = dir.path().join(ID_TOKEN_FILE);
        save_secret(&path, "a").unwrap();
        save_secret(&path, "b").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "b");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// The whole flow, hermetically: discovery, loopback redirect, PKCE code
    /// exchange, local verification — with the browser replaced by an HTTP
    /// client that follows the mock's redirect.
    #[tokio::test]
    async fn the_login_flow_runs_end_to_end_against_a_mock_issuer() {
        let idp = MockIdp::start("alice@example.com").await;
        let fetcher = KeyFetcher::new(None).unwrap();
        let login = run_flow(&fetcher, &idp.client(), node(), 0, idp.browser(), PATIENCE)
            .await
            .unwrap();
        assert_eq!(login.claim.node, node());
        assert_eq!(login.principal.email.as_deref(), Some("alice@example.com"));
        assert_eq!(login.principal.issuer, idp.issuer.as_str());
        assert!(login.refresh_token.is_some());
        // The mock checked the PKCE verifier and saw the node-bound nonce.
        assert_eq!(
            idp.last_nonce().as_deref(),
            Some(OidcNonce::for_node(&node()).as_str())
        );
    }

    #[tokio::test]
    async fn a_refresh_that_keeps_the_nonce_yields_a_new_bound_token() {
        let idp = MockIdp::start("alice@example.com").await;
        let fetcher = KeyFetcher::new(None).unwrap();
        let first = run_flow(&fetcher, &idp.client(), node(), 0, idp.browser(), PATIENCE)
            .await
            .unwrap();
        let rt = first.refresh_token.clone().unwrap();
        let again = refresh(&fetcher, &idp.client(), node(), &rt).await.unwrap();
        assert_eq!(again.principal.email.as_deref(), Some("alice@example.com"));
        assert_eq!(again.refresh_token.as_deref(), Some(rt.as_str()));
    }

    #[tokio::test]
    async fn a_refresh_without_the_nonce_is_refused_like_googles() {
        let idp = MockIdp::start("alice@example.com").await;
        let fetcher = KeyFetcher::new(None).unwrap();
        let first = run_flow(&fetcher, &idp.client(), node(), 0, idp.browser(), PATIENCE)
            .await
            .unwrap();
        idp.set_nonce_on_refresh(false);
        let err = refresh(
            &fetcher,
            &idp.client(),
            node(),
            &first.refresh_token.unwrap(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("nonce"), "{err:#}");
    }

    #[tokio::test]
    async fn an_unregistered_client_is_refused_by_the_issuer() {
        let idp = MockIdp::start("alice@example.com").await;
        let fetcher = KeyFetcher::new(None).unwrap();
        let mut client = idp.client();
        client.client_id = "not-registered".into();
        let err = run_flow(&fetcher, &client, node(), 0, idp.browser(), PATIENCE)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("invalid_client"), "{err:#}");
    }

    /// Write `request` on a fresh loopback connection to `port` and read the
    /// whole reply — an error if the server reset the connection instead.
    async fn raw_exchange(port: u16, request: &[u8]) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
        stream.write_all(request).await?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await?;
        Ok(String::from_utf8_lossy(&reply).into_owned())
    }

    /// Card 11: a browser that sends more than the request head we parse (a
    /// pipelined or speculative tail) still gets the whole "signed in" page,
    /// not a reset — which Safari showed as "Can't connect to the server".
    #[tokio::test]
    async fn the_signed_in_page_survives_unread_request_bytes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let waiter = tokio::spawn(async move {
            await_callback(listener, "st", Duration::from_millis(200)).await
        });
        let mut request =
            b"GET /callback?code=c0de&state=st HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec();
        request.extend(std::iter::repeat_n(b'x', 32 * 1024));
        let reply = tokio::time::timeout(PATIENCE, raw_exchange(port, &request))
            .await
            .unwrap()
            .expect("a complete response, not a connection reset");
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
        assert!(reply.contains(SIGNED_IN), "{reply}");
        assert_eq!(waiter.await.unwrap().unwrap(), "c0de");
    }

    /// Card 11: after the code is taken, the listener still answers for the
    /// linger window — `/callback` with the same page, anything else 404 — and
    /// then closes.
    #[tokio::test]
    async fn the_listener_keeps_answering_briefly_after_sign_in() {
        let linger = Duration::from_millis(500);
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let waiter = tokio::spawn(async move { await_callback(listener, "st", linger).await });
        let first = raw_exchange(
            port,
            b"GET /callback?code=c0de&state=st HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await
        .unwrap();
        assert!(first.contains(SIGNED_IN), "{first}");
        assert_eq!(waiter.await.unwrap().unwrap(), "c0de");

        // The browser's second (speculative, or retried) connection.
        let again = raw_exchange(
            port,
            b"GET /callback?code=c0de&state=st HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await
        .unwrap();
        assert!(again.starts_with("HTTP/1.1 200 OK"), "{again}");
        assert!(again.contains(SIGNED_IN), "{again}");
        let favicon = raw_exchange(
            port,
            b"GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await
        .unwrap();
        assert!(favicon.starts_with("HTTP/1.1 404"), "{favicon}");

        // Closed once the linger window is over (polled: a loaded test run
        // can delay the linger task past the window by a little).
        tokio::time::sleep(linger).await;
        let closed = async {
            while TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(5), closed)
                .await
                .is_ok(),
            "the listener closes once the linger window is over"
        );
    }

    #[tokio::test]
    async fn a_forged_redirect_with_the_wrong_state_is_refused() {
        let idp = MockIdp::start("alice@example.com").await;
        let fetcher = KeyFetcher::new(None).unwrap();
        let err = run_flow(
            &fetcher,
            &idp.client(),
            node(),
            0,
            |url: &Url| {
                let redirect = url
                    .query_pairs()
                    .find(|(k, _)| k == "redirect_uri")
                    .unwrap()
                    .1
                    .into_owned();
                tokio::spawn(async move {
                    let forged = format!("{redirect}?code=stolen&state=wrong");
                    let _ = crate::caller::jwks::http_client()
                        .unwrap()
                        .get(forged)
                        .send()
                        .await;
                });
            },
            PATIENCE,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("state"), "{err:#}");
    }

    #[tokio::test]
    async fn an_idp_error_redirect_is_reported() {
        let idp = MockIdp::start("alice@example.com").await;
        let fetcher = KeyFetcher::new(None).unwrap();
        let err = run_flow(
            &fetcher,
            &idp.client(),
            node(),
            0,
            |url: &Url| {
                let redirect = url
                    .query_pairs()
                    .find(|(k, _)| k == "redirect_uri")
                    .unwrap()
                    .1
                    .into_owned();
                tokio::spawn(async move {
                    let denied = format!("{redirect}?error=access_denied");
                    let _ = crate::caller::jwks::http_client()
                        .unwrap()
                        .get(denied)
                        .send()
                        .await;
                });
            },
            PATIENCE,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("access_denied"), "{err:#}");
    }

    /// Keys rotate: a token signed under a `kid` the cache has never seen
    /// triggers exactly one refetch, and the on-disk cache serves a restarted
    /// reader without any fetch.
    #[tokio::test]
    async fn an_unknown_kid_refetches_and_the_disk_cache_serves_restarts() {
        let idp = MockIdp::start("alice@example.com").await;
        let dir = crate::testutil::ScratchDir::new("jwk");
        let cache = Some(dir.path().to_path_buf());
        let now = crate::clock::now_unix();
        let aud = [Audience::new(idp.client_id.clone())];
        let iss = [idp.issuer.clone()];

        let fetcher = KeyFetcher::new(cache.clone()).unwrap();
        let claim = IdentityClaim {
            node: node(),
            id_token: idp.mint(&OidcNonce::for_node(&node()), now + 600),
        };
        fetcher.verify(&claim, &iss, &aud, now).await.unwrap();
        assert_eq!(idp.jwks_fetches(), 1);

        // A restarted reader: served from disk.
        let restarted = KeyFetcher::new(cache.clone()).unwrap();
        restarted.verify(&claim, &iss, &aud, now).await.unwrap();
        assert_eq!(idp.jwks_fetches(), 1);

        // Rotation: a new kid forces one refetch, then verifies.
        idp.rotate_key();
        let rotated = IdentityClaim {
            node: node(),
            id_token: idp.mint(&OidcNonce::for_node(&node()), now + 600),
        };
        restarted.verify(&rotated, &iss, &aud, now).await.unwrap();
        assert_eq!(idp.jwks_fetches(), 2);

        // A bogus kid right after is not an amplifier: no further fetch.
        idp.rotate_key();
        let bogus = IdentityClaim {
            node: node(),
            id_token: idp.mint(&OidcNonce::for_node(&node()), now + 600),
        };
        let err = restarted.verify(&bogus, &iss, &aud, now).await.unwrap_err();
        assert!(matches!(
            err,
            crate::caller::jwks::VerifyError::Rejected(IdTokenError::UnknownKey { .. })
        ));
        assert_eq!(idp.jwks_fetches(), 2);
    }

    #[tokio::test]
    async fn an_expired_claim_still_names_its_principal() {
        let idp = MockIdp::start("alice@example.com").await;
        let fetcher = KeyFetcher::new(None).unwrap();
        let now = crate::clock::now_unix();
        let stale = IdentityClaim {
            node: node(),
            id_token: idp.mint(&OidcNonce::for_node(&node()), now - 3600),
        };
        let err = fetcher
            .verify(
                &stale,
                std::slice::from_ref(&idp.issuer),
                &[Audience::new(idp.client_id.clone())],
                now,
            )
            .await
            .unwrap_err();
        match err {
            crate::caller::jwks::VerifyError::Expired(p) => {
                assert_eq!(p.email.as_deref(), Some("alice@example.com"))
            }
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_untrusted_issuer_is_never_fetched() {
        let idp = MockIdp::start("alice@example.com").await;
        let fetcher = KeyFetcher::new(None).unwrap();
        let claim = IdentityClaim {
            node: node(),
            id_token: idp.mint(
                &OidcNonce::for_node(&node()),
                crate::clock::now_unix() + 600,
            ),
        };
        let err = fetcher
            .verify(
                &claim,
                &[Issuer::new("https://accounts.google.com")],
                &[Audience::new(idp.client_id.clone())],
                crate::clock::now_unix(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::caller::jwks::VerifyError::Untrusted(_)
        ));
        assert_eq!(idp.jwks_fetches(), 0);
    }
}
