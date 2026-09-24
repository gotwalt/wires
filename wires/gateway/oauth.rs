//! The gateway's OAuth 2.1 authorization server, as the MCP authorization
//! spec (2026-07-28) profiles it.
//!
//! 1. The MCP endpoint answers an unauthenticated request with `401` and
//!    `WWW-Authenticate: Bearer resource_metadata=…` ([`challenge`]).
//! 2. Protected resource metadata (RFC 9728) names this gateway as the
//!    authorization server; its metadata (RFC 8414) advertises PKCE S256
//!    only, Client ID Metadata Documents, DCR, and `iss` in responses.
//! 3. `/authorize` checks the client and its redirect URI, then shows a
//!    consent page naming the client. Continuing sends the browser to the
//!    IdP (Google) with `nonce` = hash of the gateway's node key.
//! 4. `/oauth/callback` redeems Google's code, verifies the ID token as a
//!    claim for the gateway's node, and refuses anyone the signed policy
//!    lets call nothing through the gateway. Otherwise it redirects to the
//!    client with a one-time code, its `state`, and `iss` (RFC 9207).
//! 5. `/token` redeems the code (client, redirect URI, PKCE verifier and
//!    resource must all match) for a bearer token bound to `/mcp`
//!    (RFC 8707) that expires with the Google ID token. No refresh tokens:
//!    see [`sessions`](super::sessions).

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use library::OidcNonce;
use serde_json::json;
use url::Url;

use super::clients::{Client, ClientError, RegistrationRequest, is_metadata_url};
use super::sessions::{Authorization, CODE_TTL_SECS, CodeGrant, PENDING_TTL_SECS, Session};
use super::{Backend, Gateway, PublicUrls, SCOPE};
use crate::caller::login::{Pkce, authorization_url, exchange_code, random_token};

/// The cookie binding a consent page to the browser that loaded it.
///
/// `__Host-`: browsers accept it only `Secure`, `Path=/` and without
/// `Domain`, so a sibling subdomain can't plant or shadow it.
const CONSENT_COOKIE: &str = "__Host-wires_authz";
/// The cookie binding the IdP's redirect back to the browser that consented:
/// without it, a copied IdP link would skip the consent page entirely.
const CALLBACK_COOKIE: &str = "__Host-wires_cb";

/// What [`CALLBACK_COOKIE`] holds for authorization `id`: a hash, so the
/// cookie alone never names a pending authorization.
fn callback_binding(id: &str) -> String {
    use base64::Engine as _;
    library::B64.encode(ring::digest::digest(
        &ring::digest::SHA256,
        format!("wires gateway callback v1:{id}").as_bytes(),
    ))
}

/// `; Secure` on an https gateway (a loopback test gateway is plain http).
fn secure_attr(urls: &PublicUrls) -> &'static str {
    if urls.issuer.starts_with("https://") {
        "; Secure"
    } else {
        ""
    }
}

type Gw<B> = State<Arc<Gateway<B>>>;

/// `WWW-Authenticate` for `/mcp` (RFC 6750 §3, RFC 9728 §5.1); `error` is
/// set when a token was presented and is no good.
pub(crate) fn challenge(urls: &PublicUrls, error: Option<&str>) -> HeaderValue {
    let mut v = format!(
        "Bearer resource_metadata=\"{}\", scope=\"{SCOPE}\"",
        urls.resource_metadata()
    );
    if let Some(e) = error {
        v.push_str(&format!(", error=\"{e}\""));
    }
    HeaderValue::from_str(&v).expect("ASCII header")
}

/// Whether `given` names this gateway's MCP endpoint (RFC 8707): its origin
/// (scheme and host compared case-insensitively) with path `/mcp` or none,
/// no query, no fragment.
pub(crate) fn resource_matches(urls: &PublicUrls, given: &str) -> bool {
    let Ok(u) = Url::parse(given) else {
        return false;
    };
    let path = u.path().trim_end_matches('/');
    u.origin().ascii_serialization() == urls.issuer
        && (path.is_empty() || path == "/mcp")
        && u.query().is_none()
        && u.fragment().is_none()
}

/// Whether `verifier` is a well-formed PKCE verifier (RFC 7636 §4.1) whose
/// S256 challenge is `challenge`.
pub(crate) fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        && Pkce::from_verifier(verifier.to_owned()).challenge == challenge
}

/// `GET /`: what this is and how to connect.
pub(crate) async fn home<B: Backend>(State(gw): Gw<B>) -> Html<String> {
    page(
        "wires gateway",
        &format!(
            "<p>This is a <a href=\"https://github.com/gotwalt/wires\">wires</a> gateway: the \
             services your identity may call, as a remote MCP server.</p>\
             <p>In Claude, add a custom connector with the URL <code>{}</code>, then sign in \
             with Google. Each call runs on the machine that hosts the service, which checks \
             who you are and records the call.</p>",
            esc(&gw.urls.resource())
        ),
    )
}

/// `GET /.well-known/oauth-protected-resource[/mcp]` (RFC 9728).
pub(crate) async fn resource_metadata<B: Backend>(State(gw): Gw<B>) -> Response {
    Json(json!({
        "resource": gw.urls.resource(),
        "authorization_servers": [gw.urls.issuer],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
        "resource_name": "wires",
        "resource_documentation": "https://github.com/gotwalt/wires",
    }))
    .into_response()
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
pub(crate) async fn server_metadata<B: Backend>(State(gw): Gw<B>) -> Response {
    let u = &gw.urls;
    Json(json!({
        "issuer": u.issuer,
        "authorization_endpoint": u.endpoint("/authorize"),
        "token_endpoint": u.endpoint("/token"),
        "registration_endpoint": u.endpoint("/register"),
        "scopes_supported": [SCOPE],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
        "service_documentation": "https://github.com/gotwalt/wires",
    }))
    .into_response()
}

/// `POST /register` (RFC 7591): the `client_id` is the registration.
pub(crate) async fn register<B: Backend>(State(gw): Gw<B>, body: axum::body::Bytes) -> Response {
    let req: RegistrationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &e.to_string(),
            );
        }
    };
    let now = crate::clock::now_unix();
    match gw.client_key.register(&req, now) {
        Ok(c) => (
            StatusCode::CREATED,
            no_store(),
            Json(json!({
                "client_id": c.id,
                "client_id_issued_at": now,
                "client_name": c.name,
                "redirect_uris": req.redirect_uris,
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            })),
        )
            .into_response(),
        Err(e) => oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", &e.0),
    }
}

/// Look up `client_id`: a metadata document URL, else a DCR id.
async fn client<B: Backend>(gw: &Gateway<B>, client_id: &str) -> Result<Client, ClientError> {
    if is_metadata_url(client_id) {
        gw.metadata.client(client_id).await
    } else {
        gw.client_key.registered(client_id)
    }
}

/// `GET /authorize`: check the request, then ask the user to continue.
///
/// Until the client and its redirect URI check out, errors are a page (never
/// a redirect to an unvalidated URI, OAuth 2.1 §4.1.2.1); after, they go
/// back to the client.
pub(crate) async fn authorize<B: Backend>(
    State(gw): Gw<B>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(client_id) = q.get("client_id") else {
        return error_page(StatusCode::BAD_REQUEST, "The request names no client_id.");
    };
    let client = match client(&gw, client_id).await {
        Ok(c) => c,
        Err(e) => return error_page(StatusCode::BAD_REQUEST, &format!("Unknown client: {e}.")),
    };
    let Some(redirect_uri) = q
        .get("redirect_uri")
        .and_then(|r| Url::parse(r).ok())
        .filter(|r| client.allows_redirect(r))
    else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "The redirect_uri is missing or not registered for this client.",
        );
    };
    let state = q.get("state").cloned();
    let back = |error: &str, description: &str| {
        to_client(
            &gw.urls,
            &redirect_uri,
            state.as_deref(),
            &[("error", error), ("error_description", description)],
        )
    };
    if q.get("response_type").map(String::as_str) != Some("code") {
        return back(
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    let Some(challenge) = q.get("code_challenge").filter(|c| c.len() == 43) else {
        return back(
            "invalid_request",
            "a PKCE code_challenge (S256) is required",
        );
    };
    if q.get("code_challenge_method").map(String::as_str) != Some("S256") {
        return back("invalid_request", "code_challenge_method must be S256");
    }
    if let Some(r) = q.get("resource")
        && !resource_matches(&gw.urls, r)
    {
        return back(
            "invalid_target",
            "this server issues tokens only for its own /mcp",
        );
    }
    let verifier = match random_token(32) {
        Ok(v) => v,
        Err(_) => return back("server_error", "no randomness"),
    };
    let authorization = Authorization {
        client_id: client.id.clone(),
        client_name: client.name.clone(),
        redirect_uri: redirect_uri.clone(),
        state: state.clone(),
        code_challenge: challenge.clone(),
        resource: gw.urls.resource(),
        upstream_verifier: verifier,
        login_hint: q.get("login_hint").map(|h| h.chars().take(256).collect()),
        created: crate::clock::now_unix(),
    };
    let id = match gw.store.begin(authorization) {
        Ok(id) => id,
        Err(_) => return back("server_error", "could not record the authorization"),
    };
    consent(&gw.urls, &client, &redirect_uri, &id)
}

/// The consent page: who is asking, where the grant goes, one button.
fn consent(urls: &PublicUrls, client: &Client, redirect: &Url, id: &str) -> Response {
    let secure = secure_attr(urls);
    let cookie = format!(
        "{CONSENT_COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={PENDING_TTL_SECS}{secure}"
    );
    let body = format!(
        "<p><strong>{}</strong>{} wants to run wires services as you.</p>\
         <p>You'll sign in with Google. Each call then runs on the machine that hosts the \
         service, which checks your identity against the admin-signed list of who may call \
         what, and records the call. Access ends when your sign-in expires (about an hour).</p>\
         <p class=\"dim\">Sign-in returns to {}</p>\
         <form method=\"post\" action=\"/authorize/confirm\">\
         <input type=\"hidden\" name=\"id\" value=\"{}\">\
         <button type=\"submit\">Continue with Google</button></form>",
        esc(&client.name),
        // A metadata-document client proves its URL's host; show it, since
        // the name is self-declared.
        if is_metadata_url(&client.id) {
            Url::parse(&client.id)
                .ok()
                .and_then(|u| u.host_str().map(|h| format!(" ({})", esc(h))))
                .unwrap_or_default()
        } else {
            String::new()
        },
        esc(redirect.host_str().unwrap_or("")),
        esc(id),
    );
    let mut resp = page("Connect to wires", &body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("ascii"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'; default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The value of cookie `name`, if the request carries it.
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// `POST /authorize/confirm`: the user pressed continue; off to the IdP.
///
/// The form's id must match the consent cookie (`SameSite=Strict`), so a
/// page elsewhere can't press the button for the user.
pub(crate) async fn confirm<B: Backend>(
    State(gw): Gw<B>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let id = f.get("id").map(String::as_str).unwrap_or_default();
    if id.is_empty() || cookie(&headers, CONSENT_COOKIE) != Some(id) {
        return error_page(
            StatusCode::FORBIDDEN,
            "This sign-in did not start in this browser. Start again from your MCP client.",
        );
    }
    let Some(a) = gw.store.pending(id, crate::clock::now_unix()) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "This sign-in has expired. Start again from your MCP client.",
        );
    };
    let doc = match gw.fetcher.discover(&gw.upstream.issuer).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("gateway: IdP discovery failed: {e:#}");
            return error_page(
                StatusCode::BAD_GATEWAY,
                "The identity provider is unreachable.",
            );
        }
    };
    let mut url = authorization_url(
        &doc,
        &gw.upstream,
        &gw.urls.upstream_callback(),
        id,
        &OidcNonce::for_node(&gw.node),
        &Pkce::from_verifier(a.upstream_verifier),
    );
    url.query_pairs_mut()
        .append_pair("prompt", "select_account");
    if let Some(hint) = &a.login_hint {
        url.query_pairs_mut().append_pair("login_hint", hint);
    }
    // `Lax`, not `Strict`: the IdP's redirect back is a cross-site
    // top-level navigation, which `Lax` still carries.
    let bind = format!(
        "{CALLBACK_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={PENDING_TTL_SECS}{}",
        callback_binding(id),
        secure_attr(&gw.urls)
    );
    let mut resp = Redirect::to(url.as_str()).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&bind).expect("ascii"),
    );
    resp
}

/// `GET /oauth/callback`: the IdP's answer. Verify, admit, hand the client
/// a code.
///
/// Only in the browser that pressed continue on the consent page: the
/// [`CALLBACK_COOKIE`] set there must match `state`. Otherwise an IdP link
/// copied out of someone else's authorization (theirs, with their redirect
/// URI) would sign the victim in to it with no consent page. A mismatch
/// leaves the authorization pending: it isn't the victim's to spend.
pub(crate) async fn callback<B: Backend>(
    State(gw): Gw<B>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let now = crate::clock::now_unix();
    let state = q.get("state").map(String::as_str).unwrap_or_default();
    if state.is_empty() || cookie(&headers, CALLBACK_COOKIE) != Some(&callback_binding(state)) {
        return error_page(
            StatusCode::FORBIDDEN,
            "This sign-in did not start in this browser. Start again from your MCP client.",
        );
    }
    let Some(a) = gw.store.finish(state, now) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "This sign-in has expired or was already used. Start again from your MCP client.",
        );
    };
    let back = |error: &str, description: &str| {
        to_client(
            &gw.urls,
            &a.redirect_uri,
            a.state.as_deref(),
            &[("error", error), ("error_description", description)],
        )
    };
    if let Some(e) = q.get("error") {
        return back("access_denied", &format!("the identity provider said: {e}"));
    }
    let Some(code) = q.get("code") else {
        return back("access_denied", "the identity provider sent no code");
    };
    let login = match exchange_code(
        &gw.fetcher,
        &gw.upstream,
        gw.node,
        code,
        &gw.urls.upstream_callback(),
        &a.upstream_verifier,
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("gateway: sign-in failed: {e:#}");
            return back("access_denied", "the sign-in did not verify");
        }
    };
    let who = login.principal.name();
    let session = Session {
        principal: login.principal,
        id_token: login.claim.id_token,
        client_id: a.client_id.clone(),
        resource: a.resource.clone(),
    };
    // Card 37: the user's view, cut by a directory for their own token.
    match gw.tools_for(&session).await {
        Ok((_, tools)) if tools.tools.is_empty() => {
            tracing::info!("gateway: {who} may call nothing here; refused");
            return back(
                "access_denied",
                "this account may call no services through this gateway",
            );
        }
        Ok((_, tools)) => {
            tracing::info!("gateway: {who} signed in ({} services)", tools.tools.len())
        }
        Err(e) => {
            tracing::warn!("gateway: no view for {who}: {e:#}");
            return back(
                "temporarily_unavailable",
                "the gateway could not get your services from a directory; try again",
            );
        }
    }
    let grant = CodeGrant {
        client_id: a.client_id.clone(),
        redirect_uri: a.redirect_uri.clone(),
        code_challenge: a.code_challenge.clone(),
        session,
        expires: now + CODE_TTL_SECS,
    };
    match gw.store.issue_code(grant) {
        Ok(code) => to_client(
            &gw.urls,
            &a.redirect_uri,
            a.state.as_deref(),
            &[("code", &code)],
        ),
        Err(_) => back("server_error", "could not issue a code"),
    }
}

/// `POST /token`: redeem a code for an access token.
pub(crate) async fn token<B: Backend>(
    State(gw): Gw<B>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let bad = |error: &str, d: &str| oauth_error(StatusCode::BAD_REQUEST, error, d);
    if f.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return bad(
            "unsupported_grant_type",
            "only authorization_code is supported",
        );
    }
    let now = crate::clock::now_unix();
    let Some(grant) = f.get("code").and_then(|c| gw.store.redeem_code(c, now)) else {
        return bad("invalid_grant", "the code is unknown, used or expired");
    };
    if f.get("client_id") != Some(&grant.client_id) {
        return bad("invalid_grant", "the code was issued to another client");
    }
    if f.get("redirect_uri").map(String::as_str) != Some(grant.redirect_uri.as_str()) {
        return bad(
            "invalid_grant",
            "redirect_uri does not match the authorization",
        );
    }
    let verifier = f
        .get("code_verifier")
        .map(String::as_str)
        .unwrap_or_default();
    if !pkce_ok(verifier, &grant.code_challenge) {
        return bad("invalid_grant", "the PKCE code_verifier does not match");
    }
    if let Some(r) = f.get("resource")
        && !resource_matches(&gw.urls, r)
    {
        return bad(
            "invalid_target",
            "this server issues tokens only for its own /mcp",
        );
    }
    let expires_in = grant.session.not_after() - now;
    if expires_in <= 0 {
        return bad("invalid_grant", "the sign-in behind this code has expired");
    }
    match gw.store.issue_token(grant.session, now) {
        Ok(token) => (
            no_store(),
            Json(json!({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "scope": SCOPE,
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!("gateway: could not persist a session: {e:#}");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not issue a token",
            )
        }
    }
}

/// Redirect to the client with `params`, its `state`, and `iss` (RFC 9207).
fn to_client(
    urls: &PublicUrls,
    uri: &Url,
    state: Option<&str>,
    params: &[(&str, &str)],
) -> Response {
    let mut u = uri.clone();
    {
        let mut q = u.query_pairs_mut();
        q.extend_pairs(params);
        if let Some(s) = state {
            q.append_pair("state", s);
        }
        q.append_pair("iss", &urls.issuer);
    }
    Redirect::to(u.as_str()).into_response()
}

fn no_store() -> [(header::HeaderName, &'static str); 2] {
    [
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
    ]
}

/// An OAuth JSON error (RFC 6749 §5.2).
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        no_store(),
        Json(json!({"error": error, "error_description": description})),
    )
        .into_response()
}

fn error_page(status: StatusCode, text: &str) -> Response {
    (
        status,
        page("wires gateway", &format!("<p>{}</p>", esc(text))),
    )
        .into_response()
}

/// A minimal page in the house style.
fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title><style>\
         :root{{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--dim:#666;--accent:#0b57d0}}\
         @media (prefers-color-scheme:dark){{:root{{--bg:#141414;--fg:#eee;--dim:#999;--accent:#8ab4f8}}}}\
         body{{background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;\
         max-width:34rem;margin:12vh auto;padding:0 16px}}h1{{font-size:1.3rem}}\
         .dim{{color:var(--dim);font-size:.9rem}}code{{font-size:.95em}}a{{color:var(--accent)}}\
         button{{font:inherit;padding:.6rem 1.1rem;border-radius:8px;border:0;\
         background:var(--accent);color:var(--bg);cursor:pointer}}\
         </style></head><body><h1>{}</h1>{body}</body></html>",
        esc(title),
        esc(title)
    ))
}

/// HTML-escape `s`.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn urls() -> PublicUrls {
        PublicUrls::parse("https://wires.positivesum.ai").unwrap()
    }

    #[test]
    fn the_resource_is_this_origin_and_mcp() {
        for ok in [
            "https://wires.positivesum.ai/mcp",
            "https://wires.positivesum.ai/mcp/",
            "https://wires.positivesum.ai",
            "https://wires.positivesum.ai/",
            "HTTPS://WIRES.positivesum.ai/mcp",
        ] {
            assert!(resource_matches(&urls(), ok), "{ok}");
        }
        for bad in [
            "https://other.example/mcp",
            "https://wires.positivesum.ai/other",
            "https://wires.positivesum.ai/mcp?x=1",
            "https://wires.positivesum.ai/mcp#f",
            "http://wires.positivesum.ai/mcp",
            "https://wires.positivesum.ai:8443/mcp",
            "wires.positivesum.ai",
        ] {
            assert!(!resource_matches(&urls(), bad), "{bad}");
        }
    }

    /// The verifier must be well-formed (RFC 7636 §4.1) as well as match.
    #[test]
    fn pkce_needs_a_well_formed_verifier_and_its_challenge() {
        use crate::caller::login::{RFC7636_CHALLENGE, RFC7636_VERIFIER};
        assert!(pkce_ok(RFC7636_VERIFIER, RFC7636_CHALLENGE));
        assert!(!pkce_ok(
            RFC7636_VERIFIER,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cX"
        ));
        let own = |v: &str| pkce_ok(v, &Pkce::from_verifier(v.into()).challenge);
        assert!(!own("short"), "under 43 characters");
        assert!(!own(&"a".repeat(129)), "over 128 characters");
        assert!(
            !own(&format!("{}+", &RFC7636_VERIFIER[1..])),
            "outside the alphabet"
        );
        assert!(own(&"a".repeat(43)) && own(&"~._-".repeat(32)));
    }

    #[test]
    fn the_challenge_points_at_the_metadata() {
        let h = challenge(&urls(), None);
        assert_eq!(
            h.to_str().unwrap(),
            "Bearer resource_metadata=\"https://wires.positivesum.ai/.well-known/oauth-protected-resource/mcp\", scope=\"wires\""
        );
        assert!(
            challenge(&urls(), Some("invalid_token"))
                .to_str()
                .unwrap()
                .ends_with(", error=\"invalid_token\"")
        );
    }

    #[test]
    fn a_redirect_to_the_client_carries_state_and_iss() {
        let uri = Url::parse("https://claude.ai/api/mcp/auth_callback").unwrap();
        let r = to_client(&urls(), &uri, Some("s&1"), &[("code", "abc")]);
        let loc = r.headers()[header::LOCATION].to_str().unwrap();
        let back = Url::parse(loc).unwrap();
        let q: HashMap<_, _> = back.query_pairs().into_owned().collect();
        assert_eq!(q["code"], "abc");
        assert_eq!(q["state"], "s&1");
        assert_eq!(q["iss"], "https://wires.positivesum.ai");
    }

    #[test]
    fn cookies_are_found_by_name() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; __Host-wires_authz=xyz; b=2"),
        );
        assert_eq!(cookie(&h, CONSENT_COOKIE), Some("xyz"));
        assert_eq!(cookie(&h, "c"), None);
    }

    #[test]
    fn pages_escape_what_they_show() {
        assert_eq!(esc("<b a=\"1\">&'"), "&lt;b a=&quot;1&quot;&gt;&amp;&#39;");
    }

    proptest! {
        /// A challenge admits only its own verifier.
        #[test]
        fn a_challenge_admits_no_other_verifier(
            a in "[A-Za-z0-9._~-]{43,64}",
            b in "[A-Za-z0-9._~-]{43,64}",
        ) {
            prop_assume!(a != b);
            prop_assert!(!pkce_ok(&b, &Pkce::from_verifier(a).challenge));
        }
    }
}
