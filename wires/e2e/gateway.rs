//! `wires gateway`'s acceptance: a web MCP client (Claude.ai's shape) goes
//! from nothing to a tool call over real HTTP, against a mock Google.
//!
//! - [`a_web_client_signs_in_and_calls_as_its_user`]: the 401 challenge,
//!   both metadata documents, DCR, the consent page and its cookie, the
//!   Google leg (nonce bound to the gateway's node), the code with `state`
//!   and `iss`, PKCE at `/token`, then a modern `tools/list` / `tools/call`
//!   whose dialer is handed the user's own verifiable ID token, and a
//!   legacy `initialize` session on the same token.
//! - [`the_endpoint_enforces_the_transport_rules`]: `405`, `403` origin,
//!   `202` notification, `400` header mismatch, `404` unknown method,
//!   `401` for a bad token.
//! - [`a_user_the_state_admits_to_nothing_is_refused_at_sign_in`]
//! - [`a_code_is_single_use_and_bound_to_its_client`]
//!
//! The backend is scripted: the signed state is fixed in the test, and
//! "dialing" records the tool and token. That the host admits exactly such
//! a token is `services_host`'s job (a token nonce-bound to the dialing
//! node, verified against the host's trusted issuer).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use library::{IdToken, IdentityClaim, OidcNonce, State};
use reqwest::StatusCode;
use serde_json::{Value, json};
use url::Url;

use crate::caller::call::{CallOutcome, Caller};
use crate::caller::jwks::KeyFetcher;
use crate::caller::mock_idp::MockIdp;
use crate::caller::tools::RemoteTool;
use crate::gateway::clients::{ClientKey, MetadataFetcher};
use crate::gateway::sessions::Store;
use crate::gateway::tests::{node, state};
use crate::gateway::{Backend, Gateway, PublicUrls, router};

/// A form body (this reqwest is built without its `form` feature).
fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// Calls the scripted dialer saw: tool name and the token presented.
type Seen = Arc<Mutex<Vec<(String, IdToken)>>>;

struct Scripted {
    state: State,
    seen: Seen,
}

struct Recording {
    token: IdToken,
    seen: Seen,
}

impl Caller for Recording {
    async fn call(
        &self,
        tool: &RemoteTool,
        argv: library::Argv,
        _stdin: Vec<u8>,
    ) -> anyhow::Result<CallOutcome> {
        self.seen
            .lock()
            .unwrap()
            .push((tool.name.as_str().to_owned(), self.token.clone()));
        let argv: Vec<String> = argv.into();
        Ok(CallOutcome::Exited {
            exit: 0,
            stdout: format!("ran {}\n", argv.join(" ")).into_bytes(),
            stderr: vec![],
        })
    }
}

impl Backend for Scripted {
    type Caller = Recording;
    fn state(&self) -> anyhow::Result<State> {
        Ok(self.state.clone())
    }
    fn caller(&self, token: IdToken) -> Recording {
        Recording {
            token,
            seen: Arc::clone(&self.seen),
        }
    }
}

/// A gateway (node 2 of [`state`]) on a loopback port, signing users in at
/// `idp`.
struct Running {
    base: String,
    seen: Seen,
    http: reqwest::Client,
    _task: tokio::task::JoinHandle<()>,
}

const REDIRECT: &str = "http://127.0.0.1:9/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

impl Running {
    async fn start(idp: &MockIdp) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let seen: Seen = Arc::default();
        let gw = Arc::new(Gateway {
            urls: PublicUrls::parse(&base).unwrap(),
            node: node(2),
            upstream: idp.client(),
            fetcher: KeyFetcher::new(None).unwrap(),
            store: Store::open(None, crate::now_unix()).unwrap(),
            client_key: ClientKey::new(&[3; 32]),
            metadata: MetadataFetcher::new().unwrap(),
            origins: vec![base.clone(), "https://claude.ai".into()],
            backend: Scripted {
                state: state(),
                seen: Arc::clone(&seen),
            },
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, router(gw)).await.unwrap();
        });
        Self {
            base,
            seen,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            _task: task,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn register(&self) -> String {
        self.register_as("Test <Client>").await
    }

    async fn register_as(&self, name: &str) -> String {
        let r = self
            .http
            .post(self.url("/register"))
            .json(&json!({"redirect_uris":[REDIRECT],"client_name":name,
                          "token_endpoint_auth_method":"none","application_type":"native"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["token_endpoint_auth_method"], "none");
        body["client_id"].as_str().unwrap().to_owned()
    }

    /// Walk `/authorize` → consent → IdP → callback; the final redirect to
    /// the client, parsed.
    async fn authorize(&self, client_id: &str) -> HashMap<String, String> {
        let mut auth = Url::parse(&self.url("/authorize")).unwrap();
        auth.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", REDIRECT)
            .append_pair("state", "st-1")
            .append_pair("code_challenge", CHALLENGE)
            .append_pair("code_challenge_method", "S256")
            .append_pair("scope", "wires")
            .append_pair("resource", &self.url("/mcp"));
        let page = self.http.get(auth).send().await.unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()["x-frame-options"], "DENY");
        let cookie = page.headers()["set-cookie"].to_str().unwrap().to_owned();
        let cookie = cookie.split(';').next().unwrap().to_owned();
        let html = page.text().await.unwrap();
        assert!(
            html.contains("Test &lt;Client&gt;"),
            "escaped client name: {html}"
        );
        let id = html
            .split("name=\"id\" value=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap()
            .to_owned();

        // Without the cookie (another site pressing the button): refused.
        let forged = self
            .http
            .post(self.url("/authorize/confirm"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(&[("id", id.as_str())]))
            .send()
            .await
            .unwrap();
        assert_eq!(forged.status(), StatusCode::FORBIDDEN);

        let to_idp = self
            .http
            .post(self.url("/authorize/confirm"))
            .header("cookie", &cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(&[("id", id.as_str())]))
            .send()
            .await
            .unwrap();
        assert!(to_idp.status().is_redirection());
        let idp_url = to_idp.headers()["location"].to_str().unwrap().to_owned();
        let idp_q: HashMap<String, String> = Url::parse(&idp_url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        assert_eq!(idp_q["nonce"], OidcNonce::for_node(&node(2)).as_str());
        assert_eq!(idp_q["redirect_uri"], self.url("/oauth/callback"));

        let back = self.http.get(&idp_url).send().await.unwrap();
        let callback = back.headers()["location"].to_str().unwrap().to_owned();
        let to_client = self.http.get(&callback).send().await.unwrap();
        assert!(to_client.status().is_redirection());
        let loc = Url::parse(to_client.headers()["location"].to_str().unwrap()).unwrap();
        assert!(loc.as_str().starts_with(REDIRECT), "{loc}");
        loc.query_pairs().into_owned().collect()
    }

    async fn token(&self, client_id: &str, code: &str, verifier: &str) -> reqwest::Response {
        self.http
            .post(self.url("/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", client_id),
                ("redirect_uri", REDIRECT),
                ("code_verifier", verifier),
                ("resource", &self.url("/mcp")),
            ]))
            .send()
            .await
            .unwrap()
    }

    /// Sign in fully; the access token.
    async fn sign_in(&self) -> String {
        let client = self.register().await;
        let q = self.authorize(&client).await;
        let r = self.token(&client, &q["code"], VERIFIER).await;
        assert_eq!(r.status(), StatusCode::OK);
        let body: Value = r.json().await.unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    }

    /// A modern request with its mirrored headers.
    async fn modern(
        &self,
        token: &str,
        method: &str,
        name: Option<&str>,
        params: Value,
    ) -> reqwest::Response {
        let mut params = params;
        params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28"});
        let mut req = self
            .http
            .post(self.url("/mcp"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}));
        if let Some(n) = name {
            req = req.header("mcp-name", n);
        }
        req.send().await.unwrap()
    }
}

#[tokio::test]
async fn a_web_client_signs_in_and_calls_as_its_user() {
    let idp = MockIdp::start("alice@example.com").await;
    let gw = Running::start(&idp).await;

    // Unauthenticated: the challenge names the resource metadata.
    let r = gw
        .http
        .post(gw.url("/mcp"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let challenge = r.headers()["www-authenticate"].to_str().unwrap().to_owned();
    let prm_url = gw.url("/.well-known/oauth-protected-resource/mcp");
    assert!(
        challenge.contains(&format!("resource_metadata=\"{prm_url}\"")),
        "{challenge}"
    );

    let prm: Value = gw
        .http
        .get(&prm_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prm["resource"], gw.url("/mcp"));
    assert_eq!(prm["authorization_servers"], json!([gw.base]));
    let asm: Value = gw
        .http
        .get(gw.url("/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(asm["issuer"], gw.base);
    assert_eq!(asm["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(asm["client_id_metadata_document_supported"], json!(true));
    assert_eq!(
        asm["authorization_response_iss_parameter_supported"],
        json!(true)
    );

    let client = gw.register().await;
    let q = gw.authorize(&client).await;
    assert_eq!(q["state"], "st-1");
    assert_eq!(q["iss"], gw.base, "RFC 9207");
    let r = gw.token(&client, &q["code"], VERIFIER).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-store");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].as_i64().unwrap() > 0);
    assert!(body.get("refresh_token").is_none());
    let token = body["access_token"].as_str().unwrap().to_owned();

    // Modern: alice sees what `analyst` admits, never the `member` service.
    let r = gw.modern(&token, "tools/list", None, json!({})).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.headers().get("mcp-session-id").is_none());
    let list: Value = r.json().await.unwrap();
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["mixed", "orders-db"]);
    assert_eq!(list["result"]["resultType"], "complete");
    assert_eq!(list["result"]["cacheScope"], "private");

    let r = gw
        .modern(
            &token,
            "tools/call",
            Some("orders-db"),
            json!({"name":"orders-db","arguments":{"args":["select 1"]}}),
        )
        .await;
    assert_eq!(r.status(), StatusCode::OK);
    let call: Value = r.json().await.unwrap();
    assert_eq!(
        call["result"]["content"][0]["text"],
        "ran select 1\nexit: 0"
    );

    // The dialer was handed alice's own token, bound to the gateway's node:
    // exactly what a host verifies.
    let (tool, presented) = gw.seen.lock().unwrap()[0].clone();
    assert_eq!(tool, "orders-db");
    let fetcher = KeyFetcher::new(None).unwrap();
    let who = fetcher
        .verify(
            &IdentityClaim {
                node: node(2),
                id_token: presented,
            },
            std::slice::from_ref(&idp.issuer),
            &[library::Audience::new(idp.client_id.clone())],
            crate::now_unix(),
        )
        .await
        .unwrap();
    assert_eq!(who.email.as_deref(), Some("alice@example.com"));

    // A service alice's roles don't reach is not a tool.
    let r = gw
        .modern(
            &token,
            "tools/call",
            Some("status"),
            json!({"name":"status","arguments":{}}),
        )
        .await;
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32602);

    // Legacy, same token: initialize, then the agreed version in the header.
    let r = gw
        .http
        .post(gw.url("/mcp"))
        .bearer_auth(&token)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"0"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.headers().get("mcp-session-id").is_none(),
        "no sessions minted"
    );
    let init: Value = r.json().await.unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let r = gw
        .http
        .post(gw.url("/mcp"))
        .bearer_auth(&token)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    let r = gw
        .http
        .post(gw.url("/mcp"))
        .bearer_auth(&token)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    let list: Value = r.json().await.unwrap();
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 2);
    assert!(
        list["result"].get("resultType").is_none(),
        "legacy: unstamped"
    );
}

#[tokio::test]
async fn the_endpoint_enforces_the_transport_rules() {
    let idp = MockIdp::start("alice@example.com").await;
    let gw = Running::start(&idp).await;
    let token = gw.sign_in().await;

    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let r = gw
            .http
            .request(method, gw.url("/mcp"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
    let r = gw
        .http
        .post(gw.url("/mcp"))
        .bearer_auth(&token)
        .header("origin", "https://evil.example")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "DNS-rebinding guard");

    let r = gw
        .http
        .post(gw.url("/mcp"))
        .bearer_auth(&token)
        .header("origin", "https://claude.ai")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .json(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"orders-db","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32020);
    assert!(gw.seen.lock().unwrap().is_empty(), "nothing dialed");

    let r = gw.modern(&token, "resources/list", None, json!({})).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(r.json::<Value>().await.unwrap()["error"]["code"], -32601);

    let r = gw.modern(&token, "server/discover", None, json!({})).await;
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["result"]["supportedVersions"][0], "2026-07-28");

    let r = gw
        .modern("not-a-token", "tools/list", None, json!({}))
        .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(
        r.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("error=\"invalid_token\"")
    );
}

#[tokio::test]
async fn a_user_the_state_admits_to_nothing_is_refused_at_sign_in() {
    let idp = MockIdp::start("mallory@example.com").await;
    let gw = Running::start(&idp).await;
    let client = gw.register().await;
    let q = gw.authorize(&client).await;
    assert_eq!(q["error"], "access_denied");
    assert!(
        q["error_description"].contains("mallory@example.com"),
        "{q:?}"
    );
    assert_eq!(q["iss"], gw.base);
    assert!(!q.contains_key("code"));
}

#[tokio::test]
async fn a_code_is_single_use_and_bound_to_its_client() {
    let idp = MockIdp::start("alice@example.com").await;
    let gw = Running::start(&idp).await;
    let client = gw.register().await;

    let q = gw.authorize(&client).await;
    let wrong = gw.token(&client, &q["code"], &"x".repeat(43)).await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        wrong.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );
    let replay = gw.token(&client, &q["code"], VERIFIER).await;
    assert_eq!(
        replay.status(),
        StatusCode::BAD_REQUEST,
        "a failed redemption burns the code"
    );

    let other = gw.register_as("Another").await;
    assert_ne!(other, client);
    let q = gw.authorize(&client).await;
    let r = gw.token(&other, &q["code"], VERIFIER).await;
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "invalid_grant");

    // An unregistered redirect URI is never redirected to.
    let mut auth = Url::parse(&gw.url("/authorize")).unwrap();
    auth.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client)
        .append_pair("redirect_uri", "https://evil.example/cb")
        .append_pair("code_challenge", CHALLENGE)
        .append_pair("code_challenge_method", "S256");
    let r = gw.http.get(auth).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(r.headers().get("location").is_none());
}
