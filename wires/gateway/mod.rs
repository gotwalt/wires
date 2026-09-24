//! The **gateway** role: `wires gateway`, the services you may call as a
//! remote MCP server, for clients that can only reach one over HTTPS
//! (Claude.ai's custom connectors, the MCP Inspector).
//!
//! It is a caller that acts for web users. The gateway is one member node;
//! each web user signs in with Google *through* it, and the gateway asks
//! Google for an ID token whose `nonce` is bound to the gateway's node key
//! (the same binding `wires login` makes for a caller's own node). Every call
//! then presents **that user's** ID token in the session handshake, so the
//! host verifies Google's signature for that user itself and records them
//! as the caller. The gateway holds nothing a host has to trust beyond its
//! membership: it can't name a user Google didn't sign in.
//!
//! What a web user sees is decided by the signed state, as for any caller:
//! the services a role **matching the user's IdP identity** admits
//! ([`web_grants`]). Every role needs a verified identity, so the gateway's
//! node alone admits nobody.
//!
//! - [`oauth`] — the OAuth 2.1 authorization server Claude.ai signs in to
//!   (metadata, `/authorize` → Google → `/token`), RFC 9728 / 8414 / 8707 /
//!   9207, PKCE S256.
//! - [`clients`] — client registration: Client ID Metadata Documents and
//!   stateless Dynamic Client Registration.
//! - [`sessions`] — authorizations in flight, codes, access tokens.
//! - [`mcp_http`] — the MCP endpoint: Streamable HTTP (2026-07-28, plus
//!   the legacy `initialize` era), over the same core as `wires mcp`.

pub mod clients;
pub mod mcp_http;
pub mod oauth;
pub mod sessions;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use axum::Router;
use axum::routing::{get, post};
use clap::Args;
use library::{Grant, IdToken, NodeId, Principal, State, role_admits};
use url::Url;

use crate::admin::keystore::{self, Keystore};
use crate::caller::call::{CredArgs, Credentials};
use crate::caller::jwks::KeyFetcher;
use crate::caller::login::{DEFAULT_ISSUER, OidcClient, random_token, save_secret};
use crate::caller::mcp::with_services;
use crate::caller::tools::ToolsConfig;
use crate::state::store;

use self::clients::{ClientKey, MetadataFetcher};
use self::sessions::Store;

/// The gateway's MAC key for DCR client ids, in the keystore (`0600`).
pub(crate) const CLIENT_KEY_FILE: &str = "gateway-client-key";
/// The gateway's issued sessions, in the keystore (`0600`).
pub(crate) const SESSIONS_FILE: &str = "gateway-sessions.json";
/// The one OAuth scope: run the services your identity allows.
pub(crate) const SCOPE: &str = "wires";

/// `wires gateway` arguments. Secrets resolve flag → environment → file.
#[derive(Args, Debug)]
pub struct GatewayArgs {
    /// The public origin clients reach this gateway at, e.g.
    /// `https://wires.positivesum.ai` (the OAuth issuer; the MCP endpoint is
    /// `<origin>/mcp`). Falls back to `$WIRES_GATEWAY_URL`.
    #[arg(long)]
    pub public_url: Option<String>,
    /// Where to listen for HTTP (TLS is the tunnel's or proxy's job).
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,
    /// The OAuth client id of a **Web application** client at the IdP, with
    /// `<public-url>/oauth/callback` as a redirect URI. Falls back to
    /// `$WIRES_GATEWAY_CLIENT_ID`. Hosts must trust it as an audience.
    #[arg(long)]
    pub client_id: Option<String>,
    /// Read the client secret from this file. Falls back to
    /// `$WIRES_GATEWAY_CLIENT_SECRET`.
    #[arg(long)]
    pub client_secret_file: Option<PathBuf>,
    /// The IdP (default Google). Falls back to `$WIRES_OIDC_ISSUER`.
    #[arg(long)]
    pub issuer: Option<String>,
    /// Also accept browser requests from this origin (repeatable). The
    /// public origin, `https://claude.ai` and `https://claude.com` are
    /// always accepted; requests with no `Origin` (server-side clients) are
    /// too.
    #[arg(long = "allow-origin")]
    pub allow_origins: Vec<String>,
    /// Rate-limit by the client address a fronting proxy reports
    /// (`CF-Connecting-IP`, else `X-Forwarded-For`) instead of the TCP peer.
    /// Only behind a proxy that sets them: clients can send them too.
    #[arg(long)]
    pub trust_proxy_header: bool,
    /// Dial hosts through this relay instead of n0's (as `wires call
    /// --relay-url`).
    #[arg(long)]
    pub relay_url: Option<String>,
}

/// The gateway's public URLs, all derived from its origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicUrls {
    /// The origin, no trailing slash: the OAuth issuer identifier.
    pub(crate) issuer: String,
}

impl PublicUrls {
    /// From a `--public-url`: `https` (or `http` on loopback, for tests),
    /// and nothing but an origin.
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let url = Url::parse(raw).with_context(|| format!("--public-url {raw}"))?;
        let loopback = crate::caller::jwks::is_loopback(&url);
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            bail!("--public-url must be https (got {raw})");
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            bail!("--public-url must be an origin only, like https://wires.example.com");
        }
        Ok(Self {
            issuer: url.origin().ascii_serialization(),
        })
    }

    /// The MCP endpoint, and the resource (RFC 8707) tokens are bound to.
    pub(crate) fn resource(&self) -> String {
        format!("{}/mcp", self.issuer)
    }

    /// The protected resource metadata for `/mcp` (RFC 9728 §3.1).
    pub(crate) fn resource_metadata(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource/mcp", self.issuer)
    }

    /// Where the IdP sends the user back.
    pub(crate) fn upstream_callback(&self) -> Url {
        Url::parse(&format!("{}/oauth/callback", self.issuer)).expect("valid origin")
    }

    /// An endpoint of the authorization server.
    pub(crate) fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.issuer)
    }
}

/// What the gateway reads and dials through: the live keystore in
/// production, a scripted one in tests.
pub(crate) trait Backend: Send + Sync + 'static {
    /// The caller used for one web user's calls.
    type Caller: crate::caller::call::Caller + Send + Sync;
    /// The signed state this gateway holds now (read per request, so a
    /// newer state applies at once).
    fn state(&self) -> Result<State>;
    /// A caller presenting `token` in every call's handshake.
    fn caller(&self, token: IdToken) -> Self::Caller;
}

/// The production [`Backend`]: this node's keystore, and one long-lived
/// endpoint every web user's calls dial from (one node key, one endpoint:
/// not one per call contending for the same relay slot).
pub(crate) struct Keystored {
    ks: Keystore,
    fabric: NodeId,
    endpoint: iroh::Endpoint,
    relay_url: Option<String>,
}

impl Backend for Keystored {
    type Caller = PresentingCaller;

    fn state(&self) -> Result<State> {
        Ok(store::read(&self.ks, self.fabric)?
            .context("the gateway holds no signed state: `wires join` it first")?
            .state)
    }

    fn caller(&self, token: IdToken) -> PresentingCaller {
        PresentingCaller {
            token,
            endpoint: self.endpoint.clone(),
            relay_url: self.relay_url.clone(),
        }
    }
}

/// Calls a service with this node's credentials over the gateway's shared
/// endpoint, presenting a web user's ID token instead of a stored one.
pub(crate) struct PresentingCaller {
    token: IdToken,
    endpoint: iroh::Endpoint,
    relay_url: Option<String>,
}

impl crate::caller::call::Caller for PresentingCaller {
    async fn call(
        &self,
        tool: &crate::caller::tools::RemoteTool,
        argv: library::Argv,
        stdin: Vec<u8>,
    ) -> Result<crate::caller::call::CallOutcome> {
        use crate::caller::call::{
            SERVICE_DIAL_TIMEOUT, ServiceDial, call_service_with, outcome, stored_state,
        };
        let ks = Keystore::resolve()?;
        let creds = Credentials::resolve(&CredArgs {
            relay_url: self.relay_url.clone(),
            ..CredArgs::default()
        })?
        .presenting(self.token.clone());
        let state = stored_state(&ks, &creds)?.context("the gateway holds no signed state")?;
        let dial = ServiceDial {
            endpoint: &self.endpoint,
            hints: crate::caller::pick::Hints::load(&ks),
            timeout: SERVICE_DIAL_TIMEOUT,
        };
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let result = call_service_with(
            &creds,
            &ks,
            &state,
            &library::ServiceName::from(tool.name.clone()),
            &dial,
            argv,
            std::io::Cursor::new(stdin),
            &mut stdout,
            &mut stderr,
            false,
        )
        .await;
        outcome(result, stdout, stderr)
    }
}

/// How often the gateway checks for a newer signed state (the pull itself
/// runs only when the stored one is stale).
const STATE_REFRESH: std::time::Duration = std::time::Duration::from_secs(600);

/// Requests per minute each client address may make to the unauthenticated
/// OAuth endpoints (`/register`, `/authorize…`, `/oauth/callback`, `/token`).
pub(crate) const OAUTH_PER_MINUTE: u32 = 60;
/// Most client addresses tracked; past this, idle ones go first, then the
/// oldest window (never a wholesale reset, which would free every client).
const MAX_TRACKED_ADDRS: usize = 10_000;
/// The window [`RateLimit`] counts over.
const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// A fixed-window request counter per client address.
pub(crate) struct RateLimit {
    per_minute: u32,
    seen: std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>,
}

impl RateLimit {
    /// A limit of `per_minute` requests per address.
    pub(crate) fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            seen: Default::default(),
        }
    }

    /// Count one request from `addr`; `false` if it is over the limit.
    pub(crate) fn allow(&self, addr: &str) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if seen.len() >= MAX_TRACKED_ADDRS && !seen.contains_key(addr) {
            seen.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
            while seen.len() >= MAX_TRACKED_ADDRS {
                let oldest = seen
                    .iter()
                    .min_by_key(|(_, (start, _))| *start)
                    .map(|(k, _)| k.clone())
                    .expect("non-empty");
                seen.remove(&oldest);
            }
        }
        let entry = seen.entry(addr.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.per_minute
    }
}

/// The rate-limit key for `ip`: the address, or its /64 for IPv6 (one
/// subscriber usually holds a whole /64).
pub(crate) fn addr_key(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// Who a request comes from, for rate limiting: the TCP peer, or with
/// `trust_proxy` (the gateway sits behind a proxy that sets them, e.g.
/// cloudflared) `CF-Connecting-IP`, else the first `X-Forwarded-For` hop.
/// Headers are never trusted otherwise: any client can send them.
pub(crate) fn client_addr(
    headers: &axum::http::HeaderMap,
    peer: Option<std::net::SocketAddr>,
    trust_proxy: bool,
) -> String {
    let from_header = || {
        headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
            .or_else(|| {
                headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.split(',').next())
                    .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
            })
    };
    let ip = if trust_proxy {
        from_header().or(peer.map(|p| p.ip()))
    } else {
        peer.map(|p| p.ip())
    };
    ip.map(addr_key).unwrap_or_else(|| "unknown".to_owned())
}

async fn limit_oauth<B: Backend>(
    axum::extract::State(gw): axum::extract::State<Arc<Gateway<B>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0);
    if gw
        .limiter
        .allow(&client_addr(req.headers(), peer, gw.trust_proxy))
    {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "60")],
            "too many requests",
        )
            .into_response()
    }
}

/// Everything a request handler needs.
pub(crate) struct Gateway<B> {
    /// Public URLs (issuer, resource).
    pub(crate) urls: PublicUrls,
    /// This gateway's node: the `nonce` every upstream sign-in is bound to.
    pub(crate) node: NodeId,
    /// The IdP client users sign in through.
    pub(crate) upstream: OidcClient,
    /// Discovery and ID-token verification for the IdP.
    pub(crate) fetcher: KeyFetcher,
    /// OAuth state.
    pub(crate) store: Store,
    /// DCR client ids.
    pub(crate) client_key: ClientKey,
    /// Client ID Metadata Documents.
    pub(crate) metadata: MetadataFetcher,
    /// Browser origins accepted on `/mcp`.
    pub(crate) origins: Vec<String>,
    /// The per-address limit on the OAuth endpoints.
    pub(crate) limiter: RateLimit,
    /// Take the client address from the proxy's headers, not the peer.
    pub(crate) trust_proxy: bool,
    /// State and dialing.
    pub(crate) backend: B,
}

impl<B: Backend> Gateway<B> {
    /// The services `principal` may call through this gateway, with the
    /// MCP tools they become, per the current signed state.
    pub(crate) fn tools_for(&self, principal: &Principal) -> Result<(Vec<Grant>, ToolsConfig)> {
        let state = self.backend.state()?;
        let grants = web_grants(&state, self.node, principal);
        let tools = with_services(ToolsConfig::default(), &state, &grants);
        Ok((grants, tools))
    }
}

/// The services a web user may call through the gateway node `gateway`:
/// those whose `allow` has a role whose matchers admit `principal`.
/// Nothing if the gateway itself isn't a member.
pub(crate) fn web_grants(state: &State, gateway: NodeId, principal: &Principal) -> Vec<Grant> {
    if !state.is_member(gateway) {
        return Vec::new();
    }
    state
        .services
        .iter()
        .filter_map(|(service, svc)| {
            svc.allow
                .iter()
                .find(|r| role_admits(state, r, Some(principal)))
                .map(|role| Grant {
                    service: service.clone(),
                    role: role.clone(),
                })
        })
        .collect()
}

/// The HTTP routes. The unauthenticated OAuth endpoints are rate-limited
/// per client address.
pub(crate) fn router<B: Backend>(gw: Arc<Gateway<B>>) -> Router {
    let oauth = Router::new()
        .route("/register", post(oauth::register::<B>))
        .route("/authorize", get(oauth::authorize::<B>))
        .route("/authorize/confirm", post(oauth::confirm::<B>))
        .route("/oauth/callback", get(oauth::callback::<B>))
        .route("/token", post(oauth::token::<B>))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&gw),
            limit_oauth::<B>,
        ));
    Router::new()
        .merge(oauth)
        .route("/", get(oauth::home::<B>))
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::resource_metadata::<B>),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(oauth::resource_metadata::<B>),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::server_metadata::<B>),
        )
        .route(
            "/mcp",
            post(mcp_http::post::<B>)
                .get(mcp_http::not_allowed)
                .delete(mcp_http::not_allowed),
        )
        .with_state(gw)
}

/// Read a secret: the file if given, else the environment.
fn secret(file: Option<&std::path::Path>, env: &str) -> Result<Option<String>> {
    if let Some(path) = file {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        return Ok(Some(text.trim().to_owned()));
    }
    Ok(std::env::var(env).ok().filter(|v| !v.is_empty()))
}

/// The DCR MAC key: from the keystore, created on first run.
fn client_key(ks: &Keystore) -> Result<ClientKey> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let path = ks.path(CLIENT_KEY_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let fresh = random_token(32)?;
            save_secret(&path, &fresh)?;
            fresh
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let bytes: [u8; 32] = b64
        .decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("{} is not a 32-byte key", path.display()))?;
    Ok(ClientKey::new(&bytes))
}

/// `wires gateway`: serve MCP over HTTP with OAuth, for web clients.
pub async fn gateway_cmd(a: GatewayArgs) -> Result<()> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let public = a
        .public_url
        .clone()
        .or_else(|| env("WIRES_GATEWAY_URL"))
        .ok_or_else(|| anyhow!("pass --public-url (or set $WIRES_GATEWAY_URL)"))?;
    let urls = PublicUrls::parse(&public)?;
    let client_id = a
        .client_id
        .clone()
        .or_else(|| env("WIRES_GATEWAY_CLIENT_ID"))
        .ok_or_else(|| {
            anyhow!(
                "pass --client-id (or set $WIRES_GATEWAY_CLIENT_ID): a Web application OAuth \
                 client whose redirect URI is {}",
                urls.upstream_callback()
            )
        })?;
    let upstream = OidcClient {
        issuer: library::Issuer::new(
            a.issuer
                .clone()
                .or_else(|| env("WIRES_OIDC_ISSUER"))
                .unwrap_or_else(|| DEFAULT_ISSUER.to_owned()),
        ),
        client_id,
        client_secret: secret(
            a.client_secret_file.as_deref(),
            "WIRES_GATEWAY_CLIENT_SECRET",
        )?,
    };
    let ks = Keystore::resolve()?;
    let node = keystore::node_identity_in(&ks)?.node_id();
    let membership = ks
        .read_membership()?
        .context("the gateway has no membership: `wires join <token>` it first")?;
    let backend = Keystored {
        ks: Keystore::resolve()?,
        fabric: membership.fabric,
        endpoint: crate::host::transport::bind(
            &keystore::node_identity_in(&ks)?,
            a.relay_url.as_deref(),
        )
        .await?,
        relay_url: a.relay_url.clone(),
    };
    let state = backend.state()?;
    if !state.is_member(node) {
        bail!(
            "this node ({}) is not a member of its signed state: the admin must invite it",
            node.hex()
        );
    }
    let mut origins = vec![
        urls.issuer.clone(),
        "https://claude.ai".to_owned(),
        "https://claude.com".to_owned(),
    ];
    origins.extend(a.allow_origins.iter().cloned());
    let gw = Arc::new(Gateway {
        node,
        upstream,
        fetcher: KeyFetcher::new(Some(ks.path("jwks")))?,
        store: Store::open(Some(ks.path(SESSIONS_FILE)), crate::now_unix())?,
        client_key: client_key(&ks)?,
        metadata: MetadataFetcher::new()?,
        origins,
        limiter: RateLimit::new(OAUTH_PER_MINUTE),
        trust_proxy: a.trust_proxy_header,
        backend,
        urls,
    });
    // A long-running caller: keep its state fresh without waiting for a
    // call to hand back a newer one (it would otherwise expire unnoticed).
    tokio::spawn(async {
        loop {
            tokio::time::sleep(STATE_REFRESH).await;
            crate::state::sync::refresh_cold().await;
        }
    });
    let listener = tokio::net::TcpListener::bind(a.listen)
        .await
        .with_context(|| format!("binding {}", a.listen))?;
    eprintln!(
        "wires gateway: node {}; MCP endpoint {} (listening on {})",
        node.hex(),
        gw.urls.resource(),
        a.listen
    );
    axum::serve(
        listener,
        router(gw).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use library::{Matcher, NodeIdentity, RoleName, Service, ServiceName, StateVersion};

    pub(crate) fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    pub(crate) fn principal(email: &str) -> Principal {
        Principal {
            issuer: "https://accounts.google.com".into(),
            subject: email.into(),
            email: Some(email.into()),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
            claims: Default::default(),
        }
    }

    /// Gateway 2, host 3. `orders-db` for `analyst` (alice, bob); `status` for
    /// `ops` (carol); `mixed` for `ops` then `analyst`. Matchers trust Google.
    pub(crate) fn state() -> State {
        state_for(library::GOOGLE_ISSUER)
    }

    /// [`state`] with its roles' matchers trusting `issuer`.
    pub(crate) fn state_for(issuer: &str) -> State {
        let mut s = State::new(node(1));
        s.version = StateVersion(1);
        s.not_after = i64::MAX;
        s.members.extend([node(2), node(3)]);
        s.hosts.insert(node(3));
        s.roles.insert(
            RoleName::new("analyst").unwrap(),
            ["alice@example.com", "bob@example.com"]
                .into_iter()
                .map(|e| Matcher {
                    email: Some(e.parse().unwrap()),
                    ..Matcher::new(issuer)
                })
                .collect(),
        );
        s.roles.insert(
            RoleName::new("ops").unwrap(),
            vec![Matcher {
                email: Some("carol@example.com".parse().unwrap()),
                ..Matcher::new(issuer)
            }],
        );
        let svc = |allow: Vec<RoleName>| Service {
            description: "d".into(),
            allow,
            hosts: vec![node(3)],
            readers: vec![],
        };
        let analyst = RoleName::new("analyst").unwrap();
        s.services.insert(
            ServiceName::new("orders-db").unwrap(),
            svc(vec![analyst.clone()]),
        );
        s.services.insert(
            ServiceName::new("status").unwrap(),
            svc(vec![RoleName::new("ops").unwrap()]),
        );
        s.services.insert(
            ServiceName::new("mixed").unwrap(),
            svc(vec![RoleName::new("ops").unwrap(), analyst]),
        );
        s
    }

    #[test]
    fn a_web_user_gets_the_services_whose_roles_match_them() {
        let names = |g: Vec<Grant>| -> Vec<(String, String)> {
            g.into_iter()
                .map(|g| (g.service.to_string(), g.role.as_str().to_owned()))
                .collect()
        };
        assert_eq!(
            names(web_grants(
                &state(),
                node(2),
                &principal("alice@example.com")
            )),
            [
                ("mixed".to_owned(), "analyst".to_owned()),
                ("orders-db".to_owned(), "analyst".to_owned())
            ]
        );
        assert!(web_grants(&state(), node(2), &principal("mallory@example.com")).is_empty());
        assert!(
            web_grants(&state(), node(9), &principal("alice@example.com")).is_empty(),
            "a gateway that isn't a member offers nothing"
        );
    }

    #[test]
    fn the_rate_limit_counts_per_address() {
        let l = RateLimit::new(3);
        assert!((0..3).all(|_| l.allow("a")));
        assert!(!l.allow("a"));
        assert!(l.allow("b"));
        let peer: Option<SocketAddr> = Some("198.51.100.7:4000".parse().unwrap());
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "10.0.0.1, 10.0.0.2".parse().unwrap());
        assert_eq!(
            client_addr(&h, peer, false),
            "198.51.100.7",
            "headers untrusted"
        );
        assert_eq!(client_addr(&h, peer, true), "10.0.0.1");
        h.insert("cf-connecting-ip", "203.0.113.9".parse().unwrap());
        assert_eq!(client_addr(&h, peer, true), "203.0.113.9");
        h.insert("cf-connecting-ip", "not an ip".parse().unwrap());
        assert_eq!(client_addr(&h, peer, true), "10.0.0.1");
        assert_eq!(
            client_addr(&axum::http::HeaderMap::new(), None, true),
            "unknown"
        );
        // One IPv6 subscriber (a /64) is one bucket.
        let a = client_addr(&h, Some("[2001:db8:1:2:aaaa::1]:1".parse().unwrap()), false);
        let b = client_addr(&h, Some("[2001:db8:1:2:bbbb::9]:1".parse().unwrap()), false);
        assert_eq!(a, b);
        assert_eq!(a, "2001:db8:1:2::/64");
    }

    #[test]
    fn a_full_table_evicts_rather_than_resets() {
        let l = RateLimit::new(1);
        assert!(l.allow("hog"));
        assert!(!l.allow("hog"));
        for i in 0..MAX_TRACKED_ADDRS {
            l.allow(&format!("fill-{i}"));
        }
        assert!(l.seen.lock().unwrap().len() <= MAX_TRACKED_ADDRS);
    }

    #[test]
    fn the_public_url_is_an_origin() {
        let u = PublicUrls::parse("https://wires.positivesum.ai").unwrap();
        assert_eq!(u.issuer, "https://wires.positivesum.ai");
        assert_eq!(u.resource(), "https://wires.positivesum.ai/mcp");
        assert_eq!(
            u.resource_metadata(),
            "https://wires.positivesum.ai/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            u.upstream_callback().as_str(),
            "https://wires.positivesum.ai/oauth/callback"
        );
        assert_eq!(
            PublicUrls::parse("https://wires.positivesum.ai/").unwrap(),
            u
        );
        assert!(PublicUrls::parse("http://127.0.0.1:8080").is_ok());
        for bad in [
            "http://wires.positivesum.ai",
            "https://wires.positivesum.ai/mcp",
            "https://wires.positivesum.ai/?x=1",
            "wires.positivesum.ai",
        ] {
            assert!(PublicUrls::parse(bad).is_err(), "{bad}");
        }
    }
}
