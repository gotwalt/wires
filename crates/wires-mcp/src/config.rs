use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
        };
        assert_eq!(cfg.token_signing_path(), Path::new("/tmp/wires-mcp/token_signing.ed25519"));
        assert_eq!(cfg.gateway_db_path(), Path::new("/tmp/wires-mcp/gateway.redb"));
        assert_eq!(cfg.users_dir(), Path::new("/tmp/wires-mcp/users"));
        assert_eq!(cfg.pending_pairs_dir(), Path::new("/tmp/wires-mcp/pending_pairs"));
    }

    #[test]
    fn toml_roundtrip() {
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:3000".into(),
            data_dir: PathBuf::from("/srv/wires-mcp"),
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: GatewayConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.public_url, cfg.public_url);
        assert_eq!(back.bind, cfg.bind);
        assert_eq!(back.data_dir, cfg.data_dir);
    }
}
