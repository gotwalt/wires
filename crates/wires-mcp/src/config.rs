use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wires_node::RetentionPolicy;

use crate::error::{InvalidRetentionSnafu, Result};

const DEFAULT_TTL_SECS: u64 = 3600;
const DEFAULT_MAX_BYTES_PER_USER: u64 = 52_428_800; // 50 MiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Public-facing base URL, e.g. `https://mcp.example.com`. Used as
    /// `iss` and `aud` on every issued JWT and as the canonical RFC 8707
    /// `resource` value. MUST NOT end with `/`.
    pub public_url: String,
    /// Socket the HTTPS service binds (TLS termination is upstream; v1 binds
    /// HTTP only and assumes a reverse proxy in production).
    pub bind: String,
    /// Filesystem root for gateway state (`~/.wires-mcp`).
    pub data_dir: PathBuf,
    /// Per-user retention. Defaults apply when the `[retention]` section is
    /// absent (1 h TTL, 50 MiB byte budget).
    #[serde(default)]
    pub retention: Option<RetentionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// TTL after which a stored message becomes eligible for eviction.
    /// Must be > 0.
    pub ttl_secs: u64,
    /// Byte budget across all of this user's topics. 0 = no budget cap.
    pub max_bytes_per_user: u64,
}

impl GatewayConfig {
    pub fn token_signing_path(&self) -> PathBuf {
        self.data_dir.join("token_signing.ed25519")
    }
    pub fn gateway_db_path(&self) -> PathBuf {
        self.data_dir.join("gateway.redb")
    }
    pub fn users_dir(&self) -> PathBuf {
        self.data_dir.join("users")
    }
    pub fn pending_pairs_dir(&self) -> PathBuf {
        self.data_dir.join("pending_pairs")
    }

    /// Resolve the effective `RetentionPolicy`: either the operator-supplied
    /// `[retention]` section (validated) or the workspace defaults.
    pub fn retention_policy(&self) -> Result<RetentionPolicy> {
        match &self.retention {
            None => Ok(RetentionPolicy {
                ttl: Duration::from_secs(DEFAULT_TTL_SECS),
                max_bytes_per_user: DEFAULT_MAX_BYTES_PER_USER,
            }),
            Some(c) => {
                if c.ttl_secs == 0 {
                    return InvalidRetentionSnafu {
                        detail: "ttl_secs must be > 0".to_string(),
                    }
                    .fail();
                }
                Ok(RetentionPolicy {
                    ttl: Duration::from_secs(c.ttl_secs),
                    max_bytes_per_user: c.max_bytes_per_user,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn paths_compose_from_data_dir() {
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:3000".into(),
            data_dir: PathBuf::from("/tmp/wires-mcp"),
            retention: None,
        };
        assert_eq!(
            cfg.token_signing_path(),
            Path::new("/tmp/wires-mcp/token_signing.ed25519")
        );
        assert_eq!(
            cfg.gateway_db_path(),
            Path::new("/tmp/wires-mcp/gateway.redb")
        );
        assert_eq!(cfg.users_dir(), Path::new("/tmp/wires-mcp/users"));
        assert_eq!(
            cfg.pending_pairs_dir(),
            Path::new("/tmp/wires-mcp/pending_pairs")
        );
    }

    #[test]
    fn toml_roundtrip() {
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:3000".into(),
            data_dir: PathBuf::from("/srv/wires-mcp"),
            retention: None,
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: GatewayConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.public_url, cfg.public_url);
        assert_eq!(back.bind, cfg.bind);
        assert_eq!(back.data_dir, cfg.data_dir);
    }

    #[test]
    fn retention_defaults_apply_when_section_absent() {
        let s = r#"
            public_url = "https://mcp.example.com"
            bind = "127.0.0.1:3000"
            data_dir = "/srv/wires-mcp"
        "#;
        let cfg: GatewayConfig = toml::from_str(s).unwrap();
        let policy = cfg.retention_policy().unwrap();
        assert_eq!(policy.ttl, std::time::Duration::from_secs(3600));
        assert_eq!(policy.max_bytes_per_user, 52_428_800);
    }

    #[test]
    fn retention_section_parses_both_fields() {
        let s = r#"
            public_url = "https://mcp.example.com"
            bind = "127.0.0.1:3000"
            data_dir = "/srv/wires-mcp"

            [retention]
            ttl_secs = 120
            max_bytes_per_user = 1024
        "#;
        let cfg: GatewayConfig = toml::from_str(s).unwrap();
        let policy = cfg.retention_policy().unwrap();
        assert_eq!(policy.ttl, std::time::Duration::from_secs(120));
        assert_eq!(policy.max_bytes_per_user, 1024);
    }

    #[test]
    fn retention_max_bytes_zero_disables_budget_but_keeps_ttl() {
        let s = r#"
            public_url = "https://mcp.example.com"
            bind = "127.0.0.1:3000"
            data_dir = "/srv/wires-mcp"

            [retention]
            ttl_secs = 60
            max_bytes_per_user = 0
        "#;
        let cfg: GatewayConfig = toml::from_str(s).unwrap();
        let policy = cfg.retention_policy().unwrap();
        assert_eq!(policy.ttl, std::time::Duration::from_secs(60));
        assert_eq!(policy.max_bytes_per_user, 0);
    }

    #[test]
    fn retention_ttl_zero_is_rejected() {
        let s = r#"
            public_url = "https://mcp.example.com"
            bind = "127.0.0.1:3000"
            data_dir = "/srv/wires-mcp"

            [retention]
            ttl_secs = 0
            max_bytes_per_user = 1024
        "#;
        let cfg: GatewayConfig = toml::from_str(s).unwrap();
        let err = cfg
            .retention_policy()
            .err()
            .expect("must reject ttl_secs = 0");
        assert!(matches!(
            err,
            crate::error::GatewayError::InvalidRetention { .. }
        ));
    }
}
