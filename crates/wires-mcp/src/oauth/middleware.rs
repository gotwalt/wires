//! Bearer-token middleware for the /mcp route. Verifies signature + claims
//! offline, checks JTI against `revoked_jtis`, checks `client_id` against
//! `oauth_clients[].revoked`. On success, inserts the verified `Claims`
//! into the request extensions for downstream handlers.

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;

use crate::http::ServiceState;
use crate::token::{Claims, verify};

const WWW_AUTHENTICATE_HEADER: &str = "WWW-Authenticate";

pub async fn bearer(
    State(state): State<ServiceState>,
    mut req: Request,
    next: Next,
) -> Response {
    let header_val = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let token = match header_val.as_deref() {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim().to_string(),
        _ => {
            return challenge(&state, "missing or non-bearer Authorization header");
        }
    };
    let is_jti_revoked = |jti: &str| {
        matches!(state.store.get_revoked_jti(jti), Ok(Some(_)))
    };
    let claims = match verify(
        &state.signing_key.verifying_key(),
        &state.config.public_url,
        &state.config.public_url,
        is_jti_revoked,
        &token,
        Utc::now().timestamp(),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(error = %e, "bearer verify failed");
            return challenge(&state, "token verification failed");
        }
    };
    if let Ok(Some(client)) = state.store.get_oauth_client(&claims.client_id) {
        if client.revoked {
            return challenge(&state, "client revoked");
        }
    } else {
        return challenge(&state, "unknown client");
    }
    req.extensions_mut().insert(claims);
    next.run(req).await
}

fn challenge(state: &ServiceState, _detail: &str) -> Response {
    let prm = format!(
        "{}/.well-known/oauth-protected-resource",
        state.config.public_url.trim_end_matches('/')
    );
    let www = format!(
        "Bearer realm=\"mcp\", resource_metadata=\"{prm}\""
    );
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    resp.headers_mut().insert(
        WWW_AUTHENTICATE_HEADER,
        www.parse().expect("static header"),
    );
    resp
}

pub fn claims_from(req: &Request) -> Option<&Claims> {
    req.extensions().get::<Claims>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::http::ServiceState;
    use crate::store::{OauthClientRecord, Store};
    use crate::token::{MintInput, mint};
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let state = ServiceState {
            config: Arc::new(cfg),
            store,
            signing_key: Arc::new(SigningKey::from_bytes(&[1u8; 32])),
        };
        (tmp, state)
    }

    fn protected_app(state: ServiceState) -> Router {
        async fn handler() -> &'static str { "ok" }
        Router::new()
            .route("/mcp", get(handler))
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), bearer))
            .with_state(state)
    }

    fn register_client(state: &ServiceState, client_id: &str) {
        state.store.put_oauth_client(&OauthClientRecord {
            client_id: client_id.into(),
            client_name: "test".into(),
            redirect_uris: vec!["http://x".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
    }

    fn ts() -> i64 { chrono::Utc::now().timestamp() }

    #[tokio::test]
    async fn no_bearer_returns_401_with_www_authenticate() {
        let (_t, st) = state();
        let resp = protected_app(st)
            .oneshot(Request::get("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www = resp.headers().get("WWW-Authenticate").unwrap().to_str().unwrap();
        assert!(www.contains("Bearer"));
        assert!(www.contains("resource_metadata="));
    }

    #[tokio::test]
    async fn valid_bearer_proceeds() {
        let (_t, st) = state();
        register_client(&st, "c1");
        let token = mint(
            &st.signing_key,
            &MintInput {
                iss: &st.config.public_url,
                sub: &"a".repeat(64),
                aud: &st.config.public_url,
                now_s: ts(),
                ttl_s: 60,
                client_id: "c1",
            },
        ).unwrap();
        let resp = protected_app(st)
            .oneshot(
                Request::get("/mcp")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn revoked_client_returns_401() {
        let (_t, st) = state();
        st.store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "test".into(),
            redirect_uris: vec!["http://x".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: true,
        }).unwrap();
        let token = mint(
            &st.signing_key,
            &MintInput {
                iss: &st.config.public_url,
                sub: &"a".repeat(64),
                aud: &st.config.public_url,
                now_s: ts(),
                ttl_s: 60,
                client_id: "c1",
            },
        ).unwrap();
        let resp = protected_app(st)
            .oneshot(
                Request::get("/mcp")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
