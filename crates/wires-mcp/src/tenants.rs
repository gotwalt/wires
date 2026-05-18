//! Holds the live set of per-OAuth-user `NodeRuntime`s, opens them lazily
//! from `<data_dir>/users/<root_pubkey_hex>/`, and closes them after an
//! idle TTL. Each `NodeRuntime` binds its own iroh endpoint (per-user
//! addressing — fine at v1 scale; see spec §7 for the v2 sharing note).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use snafu::ResultExt;
use wires_node::NodeConfig;
use wires_node::runtime::NodeRuntime;

use crate::error::{OpenRuntimeSnafu, Result, UnknownUserSnafu};

#[derive(Clone)]
pub struct TenantSupervisor {
    inner: Arc<tokio::sync::Mutex<Inner>>,
    users_dir: PathBuf,
    idle_ttl: Duration,
}

struct Inner {
    runtimes: HashMap<String, Slot>,
}

struct Slot {
    runtime: Arc<NodeRuntime>,
    last_touched: Instant,
}

impl TenantSupervisor {
    pub fn users_dir(&self) -> &Path {
        &self.users_dir
    }

    pub fn new(users_dir: PathBuf, idle_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(Inner {
                runtimes: HashMap::new(),
            })),
            users_dir,
            idle_ttl,
        }
    }

    pub async fn get_or_open(&self, sub: &str) -> Result<Arc<NodeRuntime>> {
        let dir = self.users_dir.join(sub);
        if !dir.exists() {
            return UnknownUserSnafu { sub: sub.to_string() }.fail();
        }
        let mut g = self.inner.lock().await;
        if let Some(slot) = g.runtimes.get_mut(sub) {
            slot.last_touched = Instant::now();
            return Ok(Arc::clone(&slot.runtime));
        }
        let cfg_path = dir.join("config.toml");
        let s = std::fs::read_to_string(&cfg_path).map_err(|e| crate::error::GatewayError::Io {
            source: e,
            location: snafu::location!(),
        })?;
        let mut cfg: NodeConfig = toml::from_str(&s).map_err(|e| crate::error::GatewayError::Io {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
            location: snafu::location!(),
        })?;
        cfg.data_dir = dir.clone();
        let runtime = NodeRuntime::open(cfg).await.context(OpenRuntimeSnafu)?;
        let runtime = Arc::new(runtime);
        g.runtimes.insert(
            sub.to_string(),
            Slot {
                runtime: Arc::clone(&runtime),
                last_touched: Instant::now(),
            },
        );
        Ok(runtime)
    }

    pub async fn bind(&self, sub: &str, source_dir: &std::path::Path) -> Result<Arc<NodeRuntime>> {
        if !source_dir.exists() {
            return Err(crate::error::GatewayError::Io {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "source dir missing"),
                location: snafu::location!(),
            });
        }
        std::fs::create_dir_all(&self.users_dir).map_err(|e| crate::error::GatewayError::Io {
            source: e,
            location: snafu::location!(),
        })?;
        let dest = self.users_dir.join(sub);
        std::fs::rename(source_dir, &dest).map_err(|e| crate::error::GatewayError::TempDataDirMove {
            source: e,
            location: snafu::location!(),
        })?;
        self.get_or_open(sub).await
    }

    pub async fn close(&self, sub: &str) {
        let mut g = self.inner.lock().await;
        g.runtimes.remove(sub);
    }

    pub async fn close_idle(&self) {
        let now = Instant::now();
        let mut g = self.inner.lock().await;
        let idle: Vec<String> = g
            .runtimes
            .iter()
            .filter(|(_, slot)| now.duration_since(slot.last_touched) > self.idle_ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in idle {
            g.runtimes.remove(&k);
        }
    }

    pub async fn is_open(&self, sub: &str) -> bool {
        self.inner.lock().await.runtimes.contains_key(sub)
    }

    pub fn spawn_gc(self, tick: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick);
            loop {
                interval.tick().await;
                self.close_idle().await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn get_or_open_errors_for_unknown_sub() {
        let tmp = TempDir::new().unwrap();
        let s = TenantSupervisor::new(tmp.path().to_path_buf(), Duration::from_secs(60));
        let err = s.get_or_open("nope").await.err().expect("expected error");
        assert!(matches!(err, crate::error::GatewayError::UnknownUser { .. }));
    }

    #[tokio::test]
    async fn bind_renames_then_opens() {
        let tmp = TempDir::new().unwrap();
        let users = tmp.path().join("users");
        std::fs::create_dir_all(&users).unwrap();
        let pending = tmp.path().join("pending").join("sess1");
        std::fs::create_dir_all(&pending).unwrap();
        let sub = "ab".repeat(32);
        let cfg = NodeConfig {
            data_dir: pending.clone(),
            root_pubkey_hex: sub.clone(),
            host: None,
        };
        std::fs::write(
            pending.join("config.toml"),
            toml::to_string_pretty(&cfg).unwrap(),
        ).unwrap();
        std::fs::write(pending.join("iroh.secret"), [7u8; 32]).unwrap();

        let sup = TenantSupervisor::new(users.clone(), Duration::from_secs(60));
        sup.bind(&sub, &pending).await.unwrap();

        assert!(users.join(&sub).exists());
        assert!(!pending.exists());
        assert!(sup.is_open(&sub).await);
    }

    #[tokio::test]
    async fn close_idle_drops_stale_slots() {
        let tmp = TempDir::new().unwrap();
        let users = tmp.path().join("users");
        std::fs::create_dir_all(&users).unwrap();
        let sub = "cd".repeat(32);
        let dir = users.join(&sub);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = NodeConfig {
            data_dir: dir.clone(),
            root_pubkey_hex: sub.clone(),
            host: None,
        };
        std::fs::write(dir.join("config.toml"), toml::to_string_pretty(&cfg).unwrap()).unwrap();
        std::fs::write(dir.join("iroh.secret"), [5u8; 32]).unwrap();

        let sup = TenantSupervisor::new(users.clone(), Duration::from_millis(50));
        let _ = sup.get_or_open(&sub).await.unwrap();
        assert!(sup.is_open(&sub).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
        sup.close_idle().await;
        assert!(!sup.is_open(&sub).await);
    }

    #[tokio::test]
    async fn spawn_gc_returns_a_join_handle_that_cancels() {
        let tmp = TempDir::new().unwrap();
        let sup = TenantSupervisor::new(tmp.path().to_path_buf(), Duration::from_millis(50));
        let h = sup.clone().spawn_gc(Duration::from_millis(10));
        h.abort();
    }
}
