//! A hermetic OIDC issuer for the test suite (card 04).
//!
//! Serves, over plain HTTP on `127.0.0.1` (the one place [`crate::caller::jwks`]
//! allows `http`):
//!
//! - `GET /.well-known/openid-configuration` — discovery;
//! - `GET /jwks` — one ES256 key, `Cache-Control: max-age=300`, fetches counted;
//! - `GET /authorize` — records the request and 302s straight back to the
//!   `redirect_uri` with a code (no consent screen: the "user" is `email`, or
//!   the request's `login_hint` when it has one);
//! - `POST /token` — `authorization_code` (checks client id, redirect URI and
//!   the PKCE S256 verifier) and `refresh_token` grants, minting ES256 ID
//!   tokens with the recorded `nonce`.
//!
//! Signing keys are generated per instance with `ring`, and
//! [`MockIdp::rotate_key`] swaps in a new `kid` to exercise JWKS refetch.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use library::{B64, Issuer};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

use crate::caller::login::{Pkce, read_request, write_response};

/// The client id the mock accepts.
pub(crate) const MOCK_CLIENT_ID: &str = "wires-test-client";

/// One pending authorization, keyed by code.
struct Pending {
    client_id: String,
    redirect_uri: String,
    nonce: String,
    challenge: String,
    /// Who signs in: the request's `login_hint`, else the issuer's `email`.
    email: String,
}

/// Mutable issuer state.
struct State {
    issuer: String,
    email: String,
    /// PKCS#8 of the current signing key and its kid.
    key: Vec<u8>,
    kid: String,
    generation: usize,
    pending: HashMap<String, Pending>,
    /// refresh token → nonce of the original login.
    refresh: HashMap<String, String>,
    nonce_on_refresh: bool,
    jwks_fetches: usize,
    last_nonce: Option<String>,
    counter: usize,
}

impl State {
    fn new_key(&mut self) {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("keygen");
        self.key = doc.as_ref().to_vec();
        self.generation += 1;
        self.kid = format!("mock-{}", self.generation);
    }

    fn keypair(&self) -> EcdsaKeyPair {
        EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &self.key,
            &SystemRandom::new(),
        )
        .expect("pkcs8")
    }

    fn jwks(&self) -> serde_json::Value {
        let kp = self.keypair();
        let point = kp.public_key().as_ref();
        json!({"keys": [{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
            "kid": self.kid,
            "x": B64.encode(&point[1..33]),
            "y": B64.encode(&point[33..65]),
        }]})
    }

    /// An ES256 ID token for `self.email`, optionally with a nonce.
    fn mint(&self, nonce: Option<&str>, exp: i64) -> String {
        self.mint_as(&self.email, nonce, exp)
    }

    /// An ES256 ID token for `email`, optionally with a nonce.
    fn mint_as(&self, email: &str, nonce: Option<&str>, exp: i64) -> String {
        let header = json!({"alg": "ES256", "kid": self.kid, "typ": "JWT"});
        let mut claims = json!({
            "iss": self.issuer,
            "sub": format!("sub-{email}"),
            "aud": MOCK_CLIENT_ID,
            "exp": exp,
            "iat": exp - 3600,
            "email": email,
            "email_verified": true,
        });
        if let Some(n) = nonce {
            claims["nonce"] = n.into();
        }
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = self
            .keypair()
            .sign(&SystemRandom::new(), input.as_bytes())
            .expect("sign");
        format!("{input}.{}", B64.encode(sig.as_ref()))
    }
}

/// A running mock issuer; stops when dropped.
pub(crate) struct MockIdp {
    /// `http://127.0.0.1:<port>`.
    pub issuer: Issuer,
    /// The accepted client id ([`MOCK_CLIENT_ID`]).
    pub client_id: String,
    /// The issuer's state, for the tests' inspection hooks.
    #[cfg(test)]
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for MockIdp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockIdp {
    /// Bind on an ephemeral loopback port; every sign-in is `email`.
    pub(crate) async fn start(email: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let mut st = State {
            issuer: issuer.clone(),
            email: email.to_string(),
            key: Vec::new(),
            kid: String::new(),
            generation: 0,
            pending: HashMap::new(),
            refresh: HashMap::new(),
            nonce_on_refresh: true,
            jwks_fetches: 0,
            last_nonce: None,
            counter: 0,
        };
        st.new_key();
        let state = Arc::new(Mutex::new(st));
        let serving = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&serving);
                tokio::spawn(async move {
                    let Ok(req) = read_request(&mut stream).await else {
                        return;
                    };
                    let (status, ctype, headers, body) =
                        handle(&state, &req.method, &req.target, &req.body);
                    let headers: Vec<(&str, &str)> = headers
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    let _ =
                        write_response(&mut stream, status, ctype, &headers, body.as_bytes()).await;
                });
            }
        });
        Self {
            issuer: Issuer::new(issuer),
            client_id: MOCK_CLIENT_ID.to_string(),
            #[cfg(test)]
            state,
            task,
        }
    }
}

/// The hooks the `wires login` tests drive the issuer with.
#[cfg(test)]
impl MockIdp {
    /// The OAuth client registered with this issuer.
    pub(crate) fn client(&self) -> crate::caller::login::OidcClient {
        crate::caller::login::OidcClient {
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            client_secret: Some("not-so-secret".into()),
        }
    }

    /// A "browser": GET the authorization URL and follow the redirect back to
    /// the loopback listener, on a background task.
    pub(crate) fn browser(&self) -> impl FnOnce(&Url) + use<> {
        |url: &Url| {
            let url = url.clone();
            tokio::spawn(async move {
                let _ = crate::caller::jwks::http_client()
                    .unwrap()
                    .get(url)
                    .send()
                    .await;
            });
        }
    }

    /// Mint a token directly (bypassing the flow) with the current key.
    pub(crate) fn mint(&self, nonce: &library::OidcNonce, exp: i64) -> library::IdToken {
        library::IdToken::new(self.state.lock().unwrap().mint(Some(nonce.as_str()), exp))
    }

    /// Swap in a new signing key under a new `kid`.
    pub(crate) fn rotate_key(&self) {
        self.state.lock().unwrap().new_key();
    }

    /// How many times `/jwks` has been fetched.
    pub(crate) fn jwks_fetches(&self) -> usize {
        self.state.lock().unwrap().jwks_fetches
    }

    /// The nonce of the most recent authorization request.
    pub(crate) fn last_nonce(&self) -> Option<String> {
        self.state.lock().unwrap().last_nonce.clone()
    }

    /// Whether refreshed ID tokens carry the original nonce (Google's do not).
    pub(crate) fn set_nonce_on_refresh(&self, on: bool) {
        self.state.lock().unwrap().nonce_on_refresh = on;
    }
}

type Reply = (u16, &'static str, Vec<(String, String)>, String);

fn json_reply(status: u16, v: serde_json::Value) -> Reply {
    (status, "application/json", Vec::new(), v.to_string())
}

fn oauth_error(code: &str) -> Reply {
    json_reply(400, json!({"error": code}))
}

/// Route one request.
fn handle(state: &Mutex<State>, method: &str, target: &str, body: &[u8]) -> Reply {
    let mut st = state.lock().unwrap();
    let url = Url::parse(&format!("http://mock{target}")).unwrap();
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    match (method, url.path()) {
        ("GET", "/.well-known/openid-configuration") => json_reply(
            200,
            json!({
                "issuer": st.issuer,
                "authorization_endpoint": format!("{}/authorize", st.issuer),
                "token_endpoint": format!("{}/token", st.issuer),
                "jwks_uri": format!("{}/jwks", st.issuer),
            }),
        ),
        ("GET", "/jwks") => {
            st.jwks_fetches += 1;
            let (s, t, _, b) = json_reply(200, st.jwks());
            (
                s,
                t,
                vec![("Cache-Control".into(), "public, max-age=300".into())],
                b,
            )
        }
        ("GET", "/authorize") => {
            let get = |k: &str| query.get(k).cloned().unwrap_or_default();
            if get("client_id") != MOCK_CLIENT_ID {
                let redirect = get("redirect_uri");
                let loc = format!("{redirect}?error=invalid_client&state={}", get("state"));
                return (
                    302,
                    "text/plain",
                    vec![("Location".into(), loc)],
                    String::new(),
                );
            }
            st.counter += 1;
            let code = format!("code-{}", st.counter);
            st.last_nonce = Some(get("nonce"));
            // A test (or the demo) signs in as someone else by passing
            // `login_hint`, as a real IdP would pre-fill it.
            let email = Some(get("login_hint"))
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| st.email.clone());
            st.pending.insert(
                code.clone(),
                Pending {
                    client_id: get("client_id"),
                    redirect_uri: get("redirect_uri"),
                    nonce: get("nonce"),
                    challenge: get("code_challenge"),
                    email,
                },
            );
            let mut loc = Url::parse(&get("redirect_uri")).unwrap();
            loc.query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", &get("state"));
            (
                302,
                "text/plain",
                vec![("Location".into(), loc.to_string())],
                String::new(),
            )
        }
        ("POST", "/token") => {
            let form: HashMap<String, String> =
                url::form_urlencoded::parse(body).into_owned().collect();
            let get = |k: &str| form.get(k).cloned().unwrap_or_default();
            if get("client_id") != MOCK_CLIENT_ID {
                return oauth_error("invalid_client");
            }
            let exp = crate::clock::now_unix() + 3600;
            match get("grant_type").as_str() {
                "authorization_code" => {
                    let Some(p) = st.pending.remove(&get("code")) else {
                        return oauth_error("invalid_grant");
                    };
                    let pkce_ok =
                        Pkce::from_verifier(get("code_verifier")).challenge == p.challenge;
                    if p.client_id != get("client_id")
                        || p.redirect_uri != get("redirect_uri")
                        || !pkce_ok
                    {
                        return oauth_error("invalid_grant");
                    }
                    st.counter += 1;
                    let rt = format!("rt-{}", st.counter);
                    st.refresh.insert(rt.clone(), p.nonce.clone());
                    let id_token = st.mint_as(&p.email, Some(&p.nonce), exp);
                    json_reply(
                        200,
                        json!({"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
                               "id_token": id_token, "refresh_token": rt}),
                    )
                }
                "refresh_token" => {
                    let Some(nonce) = st.refresh.get(&get("refresh_token")).cloned() else {
                        return oauth_error("invalid_grant");
                    };
                    let nonce = st.nonce_on_refresh.then_some(nonce);
                    let id_token = st.mint(nonce.as_deref(), exp);
                    json_reply(
                        200,
                        json!({"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
                               "id_token": id_token}),
                    )
                }
                _ => oauth_error("unsupported_grant_type"),
            }
        }
        _ => (404, "text/plain", Vec::new(), "not found".into()),
    }
}
