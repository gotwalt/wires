//! JWKS endpoint. Advertises the EdDSA verifying key under `OKP`/`Ed25519`
//! per RFC 8037.

use axum::Json;
use axum::extract::State;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String, // "OKP"
    pub crv: String, // "Ed25519"
    pub kid: String,
    pub x: String, // base64url(pubkey)
    pub alg: String, // "EdDSA"
    #[serde(rename = "use")]
    pub use_: String, // "sig"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

pub fn jwk_for(sk: &SigningKey) -> Jwk {
    let vk = sk.verifying_key();
    Jwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        kid: crate::keys::kid_for(&vk),
        x: URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        alg: "EdDSA".into(),
        use_: "sig".into(),
    }
}

pub async fn handler(State(sk): State<Arc<SigningKey>>) -> Json<Jwks> {
    Json(Jwks {
        keys: vec![jwk_for(&sk)],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::http::{ServiceState, app};
    use crate::store::Store;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state(seed: [u8; 32]) -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let state = ServiceState {
            config: std::sync::Arc::new(cfg),
            store,
            signing_key: std::sync::Arc::new(SigningKey::from_bytes(&seed)),
        };
        (tmp, state)
    }

    #[tokio::test]
    async fn jwks_advertises_one_eddsa_key() {
        let (_t, st) = state([3u8; 32]);
        let expected_kid = crate::keys::kid_for(&st.signing_key.verifying_key());
        let resp = app(st)
            .oneshot(Request::get("/.well-known/jwks.json").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let jwks: Jwks = serde_json::from_slice(&body).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        let k = &jwks.keys[0];
        assert_eq!(k.kty, "OKP");
        assert_eq!(k.crv, "Ed25519");
        assert_eq!(k.alg, "EdDSA");
        assert_eq!(k.use_, "sig");
        assert_eq!(k.kid, expected_kid);
        assert!(!k.x.is_empty());
    }
}
