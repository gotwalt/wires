# Wires CLI Hosted-Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `wires-cli` and `wires-node` first-class clients of the multi-tenant `wires-host` that landed on `main`. After this plan, an operator can: pair their root with a host, register topics, mint invite tokens, and use `wires publish` / `wires cat` with live gossip + host-backed replay; an invitee can `wires join <token>` and immediately participate. The CLI becomes the human-grokkable surface for validating the network's data flows ahead of the iOS app.

**Architecture:** Three layers, top-down. `wires-net` gains an HTTPS discovery fetcher, a peer-hint+discovery-fallback iterator, and convenience wrappers on `TenantClient` that hide the timestamp/nonce/sign dance. `wires-node` grows a `NodeRuntime` that owns the iroh `Endpoint`, gossip subscriptions, and replay client — `publish_and_broadcast`, `join_topic`, and `replay_from_host` are its public surface; the existing `Node` keeps its pure-storage role. `wires-cli` gains operator subcommands (`host pair`, `host topic-register`, `host status`, `host topic-unregister`), an invitee subcommand (`join`), an `InviteToken`-emitting `invite`, and auto-dialing `publish`/`cat`. `wires-ha` gains a one-line topic-register at startup when a host is configured. The dead `NodeConfig.bootstrap_peers: Vec<String>` field is removed outright.

**Tech Stack:** Rust 2024 stable; iroh 0.98 + iroh-gossip 0.98; redb 4; ed25519-dalek 2 + `rand_core::OsRng`; serde + serde_json + toml; reqwest 0.12 (rustls-tls + json) — new dep in `wires-net`; snafu; tempfile + tokio for tests.

**Spec:** Hosted-service design `docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md`. The host side is already implemented; this plan closes the client-side gap. The iOS companion spec is out of scope.

---

## File structure

```
crates/wires-net/
  Cargo.toml                            modify: add reqwest (real dep)
  src/discovery.rs                      NEW: fetch_endpoints(url) -> Vec<PeerHint>
  src/peer_hint.rs                      modify: drop TODOs; add first_reachable_with_discovery
  src/tenant.rs                         modify: add register_tenant/register_topic/unregister_topic/status convenience on TenantClient
  src/error.rs                          modify: DiscoveryFetch / TenantRpc error variants
  src/lib.rs                            modify: re-export discovery + new tenant helpers

crates/wires-node/src/
  config.rs                             modify: drop bootstrap_peers; add HostConfig
  runtime.rs                            NEW: NodeRuntime (Node + Endpoint + NetGlue + joined-topic registry)
  node.rs                               modify: drop bootstrap_peers from test fixtures
  lib.rs                                modify: re-export NodeRuntime + HostConfig

crates/wires-node/tests/
  acceptance.rs                         modify: drop bootstrap_peers
  acceptance_host_blindness.rs          modify: drop bootstrap_peers
  runtime_publish_subscribes.rs         NEW: NodeRuntime publish reaches a peer NodeRuntime

crates/wires-cli/src/
  main.rs                               modify: new subcommands + clap wiring
  cmd/mod.rs                            modify: register host + join modules
  cmd/init.rs                           modify: no bootstrap_peers; structured HostConfig=None
  cmd/host.rs                           NEW: pair, topic_register, topic_unregister, status
  cmd/invite.rs                         modify: emit InviteToken (base64)
  cmd/join.rs                           NEW: install cap + copy host info into config
  cmd/publish.rs                        modify: open NodeRuntime, broadcast
  cmd/cat.rs                            modify: open NodeRuntime, replay from host, then read + tail

crates/wires-ha/src/main.rs             modify: register topic at startup if host configured

crates/wires-host/tests/
  acceptance.rs                         modify: add acceptance #1 — two-clients-share-one-host end-to-end

docs/superpowers/plans/                 (this file)
README.md                               modify: rewrite quick-start around the hosted flow
CLAUDE.md                               modify: refresh data-dir layout (config.toml shape change)
```

---

## Phase 1 — `wires-node` config: drop `bootstrap_peers`

### Task 1: Replace `bootstrap_peers` with `host: Option<HostConfig>`

**Files:**
- Modify: `crates/wires-node/src/config.rs`
- Modify: `crates/wires-node/src/node.rs` (test fixtures at lines ~198, ~243, ~259)
- Modify: `crates/wires-node/tests/acceptance.rs` (line ~22)
- Modify: `crates/wires-node/tests/acceptance_host_blindness.rs` (lines ~27, ~35)
- Modify: `crates/wires-cli/src/cmd/init.rs` (line ~23)
- Modify: `crates/wires-node/src/lib.rs` (re-export `HostConfig`)

- [ ] **Step 1: Write the failing test**

Append the following test to the `tests` module in `crates/wires-node/src/config.rs`:

```rust
    #[test]
    fn host_config_round_trips_through_toml() {
        let cfg = NodeConfig {
            data_dir: PathBuf::from("/tmp/wires-test"),
            root_pubkey_hex: "deadbeef".into(),
            host: Some(HostConfig {
                peer_hints: vec![wires_net::PeerHint {
                    node_id: "ab".repeat(32),
                    addrs: vec!["127.0.0.1:11204".into()],
                    relay: None,
                }],
                discovery_url: Some("https://discovery.example/v1/bootstrap".into()),
            }),
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: NodeConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.root_pubkey_hex, "deadbeef");
        let h = back.host.expect("host must round-trip");
        assert_eq!(h.peer_hints.len(), 1);
        assert_eq!(
            h.discovery_url.as_deref(),
            Some("https://discovery.example/v1/bootstrap")
        );
    }

    #[test]
    fn legacy_config_without_host_deserializes() {
        // Older configs that omit `host` should default to None, not error.
        let s = r#"
            data_dir = "/tmp/wires-test"
            root_pubkey_hex = "deadbeef"
        "#;
        let cfg: NodeConfig = toml::from_str(s).unwrap();
        assert!(cfg.host.is_none());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wires-node config::tests::host_config_round_trips_through_toml`
Expected: FAIL — `host` field not found on `NodeConfig`, or `HostConfig` type not found.

- [ ] **Step 3: Rewrite `NodeConfig`**

Replace the contents of `crates/wires-node/src/config.rs` with:

```rust
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use wires_net::PeerHint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Filesystem root for persistent state (~/.wires by default).
    pub data_dir: PathBuf,
    /// Hex of the root pubkey for this household; needed to derive
    /// firehose/__caps topic ids.
    pub root_pubkey_hex: String,
    /// Optional host this agent has paired with. `None` for purely
    /// peer-to-peer operation (no persistent relay, no replay catch-up).
    #[serde(default)]
    pub host: Option<HostConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// Peer hints harvested from discovery or an invite token. Tried in order
    /// when bootstrapping gossip and when dialing the tenant/replay ALPNs.
    pub peer_hints: Vec<PeerHint>,
    /// Optional HTTPS service-discovery URL; consulted only if every entry in
    /// `peer_hints` is unreachable.
    #[serde(default)]
    pub discovery_url: Option<String>,
}

impl NodeConfig {
    pub fn firehose_topic_id(&self) -> [u8; 32] {
        derived_topic_id("wires.firehose.v1", &self.root_pubkey_hex)
    }
    pub fn caps_topic_id(&self) -> [u8; 32] {
        derived_topic_id("wires.caps.v1", &self.root_pubkey_hex)
    }
}

fn derived_topic_id(domain: &str, root_pubkey_hex: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    if let Ok(bytes) = hex::decode(root_pubkey_hex) {
        hasher.update(&bytes);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg(hex_pk: &str) -> NodeConfig {
        NodeConfig {
            data_dir: PathBuf::from("/tmp/wires-test"),
            root_pubkey_hex: hex_pk.to_string(),
            host: None,
        }
    }

    #[test]
    fn derived_ids_are_deterministic() {
        let c1 = cfg("deadbeef");
        let c2 = cfg("deadbeef");
        assert_eq!(c1.firehose_topic_id(), c2.firehose_topic_id());
        assert_eq!(c1.caps_topic_id(), c2.caps_topic_id());
    }

    #[test]
    fn firehose_and_caps_topic_ids_differ() {
        let c = cfg("deadbeef");
        assert_ne!(c.firehose_topic_id(), c.caps_topic_id());
    }

    #[test]
    fn different_root_yields_different_topic_ids() {
        let a = cfg("aa");
        let b = cfg("bb");
        assert_ne!(a.firehose_topic_id(), b.firehose_topic_id());
    }

    #[test]
    fn host_config_round_trips_through_toml() {
        let cfg = NodeConfig {
            data_dir: PathBuf::from("/tmp/wires-test"),
            root_pubkey_hex: "deadbeef".into(),
            host: Some(HostConfig {
                peer_hints: vec![wires_net::PeerHint {
                    node_id: "ab".repeat(32),
                    addrs: vec!["127.0.0.1:11204".into()],
                    relay: None,
                }],
                discovery_url: Some("https://discovery.example/v1/bootstrap".into()),
            }),
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: NodeConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.root_pubkey_hex, "deadbeef");
        let h = back.host.expect("host must round-trip");
        assert_eq!(h.peer_hints.len(), 1);
        assert_eq!(
            h.discovery_url.as_deref(),
            Some("https://discovery.example/v1/bootstrap")
        );
    }

    #[test]
    fn legacy_config_without_host_deserializes() {
        let s = r#"
            data_dir = "/tmp/wires-test"
            root_pubkey_hex = "deadbeef"
        "#;
        let cfg: NodeConfig = toml::from_str(s).unwrap();
        assert!(cfg.host.is_none());
    }
}
```

- [ ] **Step 4: Update `wires-node/src/lib.rs` exports**

In `crates/wires-node/src/lib.rs`, change the existing `pub use config::NodeConfig;` line to:

```rust
pub use config::{HostConfig, NodeConfig};
```

- [ ] **Step 5: Sweep `bootstrap_peers` from all callers**

In `crates/wires-node/src/node.rs`, search for every `bootstrap_peers: vec![]` and replace each with `host: None`. As of writing there are three (around lines 198, 243, 259, all in `mod tests`).

In `crates/wires-node/tests/acceptance.rs`, replace the same on line ~22:

```rust
// Before
let cfg = NodeConfig {
    data_dir: tmp.path().to_path_buf(),
    root_pubkey_hex: hex::encode(verifying.to_bytes()),
    bootstrap_peers: vec![],
};

// After
let cfg = NodeConfig {
    data_dir: tmp.path().to_path_buf(),
    root_pubkey_hex: hex::encode(verifying.to_bytes()),
    host: None,
};
```

In `crates/wires-node/tests/acceptance_host_blindness.rs`, repeat the same swap at both call sites (lines ~27 and ~35).

In `crates/wires-cli/src/cmd/init.rs`, change the `cfg` construction:

```rust
// Before
let cfg = NodeConfig {
    data_dir: data_dir.to_path_buf(),
    root_pubkey_hex: root_hex.clone(),
    bootstrap_peers: vec![],
};

// After
let cfg = NodeConfig {
    data_dir: data_dir.to_path_buf(),
    root_pubkey_hex: root_hex.clone(),
    host: None,
};
```

- [ ] **Step 6: Run the targeted tests**

Run: `cargo test -p wires-node config::tests`
Expected: PASS (5 tests).

- [ ] **Step 7: Run the workspace build to catch missed call sites**

Run: `cargo build --workspace`
Expected: build succeeds. If any other `bootstrap_peers: ...` literal turns up in error output, fix it (the field is gone). Search `git grep bootstrap_peers` to confirm zero hits before continuing.

- [ ] **Step 8: Commit**

```bash
git add crates/wires-node/src/config.rs crates/wires-node/src/lib.rs \
        crates/wires-node/src/node.rs \
        crates/wires-node/tests/acceptance.rs \
        crates/wires-node/tests/acceptance_host_blindness.rs \
        crates/wires-cli/src/cmd/init.rs
git commit -m "wires-node: drop dead bootstrap_peers, add HostConfig"
```

---

## Phase 2 — `wires-net` discovery + helpers

### Task 2: `discovery::fetch_endpoints`

**Files:**
- Modify: `crates/wires-net/Cargo.toml`
- Create: `crates/wires-net/src/discovery.rs`
- Modify: `crates/wires-net/src/lib.rs`
- Modify: `crates/wires-net/src/error.rs`

- [ ] **Step 1: Add reqwest dependency to `wires-net`**

In `crates/wires-net/Cargo.toml`, under `[dependencies]`, add:

```toml
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
```

- [ ] **Step 2: Extend `NetError` with `DiscoveryFetch`**

In `crates/wires-net/src/error.rs`, add a new variant inside the `NetError` enum (next to other `#[snafu(display(...))]` entries):

```rust
    #[snafu(display("Discovery fetch failed for {url}, at {location}"))]
    DiscoveryFetch {
        url: String,
        #[snafu(source)]
        source: reqwest::Error,
        #[snafu(implicit)]
        location: snafu::Location,
    },
```

- [ ] **Step 3: Write the failing test**

Create `crates/wires-net/src/discovery.rs` with the following content (test-only at first, to drive the API):

```rust
//! HTTPS service-discovery client. Spec §7 — fetches `/v1/bootstrap` and
//! converts the response into the `PeerHint` shape that `peer_hint` iterates.

use serde::Deserialize;
use snafu::ResultExt;

use crate::error::{DiscoveryFetchSnafu, Result};
use crate::invite::PeerHint;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryEndpoint {
    pub endpoint_id: String,
    #[serde(default)]
    pub relay: Option<String>,
    #[serde(default)]
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryResponse {
    pub version: u8,
    pub endpoints: Vec<DiscoveryEndpoint>,
    pub ttl_seconds: u32,
}

/// Fetch `url` and return its endpoints as `PeerHint`s. The response's
/// `endpoints[*]` map field-for-field onto `PeerHint`.
pub async fn fetch_endpoints(url: &str) -> Result<Vec<PeerHint>> {
    let resp = reqwest::get(url)
        .await
        .with_context(|_| DiscoveryFetchSnafu { url: url.to_string() })?;
    let payload: DiscoveryResponse = resp
        .json()
        .await
        .with_context(|_| DiscoveryFetchSnafu { url: url.to_string() })?;
    Ok(payload
        .endpoints
        .into_iter()
        .map(|e| PeerHint {
            node_id: e.endpoint_id,
            addrs: e.addrs,
            relay: e.relay,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_endpoints_decodes_minimal_response() {
        use axum::{Json, Router, routing::get};
        use serde_json::json;
        let app = Router::new().route(
            "/v1/bootstrap",
            get(|| async {
                Json(json!({
                    "version": 1,
                    "endpoints": [{
                        "endpoint_id": "abc",
                        "relay": null,
                        "addrs": ["127.0.0.1:11204"]
                    }],
                    "ttl_seconds": 300
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok(); });
        let url = format!("http://{addr}/v1/bootstrap");
        let hints = fetch_endpoints(&url).await.unwrap();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].node_id, "abc");
        assert_eq!(hints[0].addrs, vec!["127.0.0.1:11204".to_string()]);
    }
}
```

Add `axum = { version = "0.8", features = ["json"] }` to `[dev-dependencies]` in `crates/wires-net/Cargo.toml` (the test stands up a tiny in-process server; `serde_json` is already a regular dependency so it's visible in tests).

- [ ] **Step 4: Re-export `discovery` in `wires-net/src/lib.rs`**

Add to `crates/wires-net/src/lib.rs`:

```rust
pub mod discovery;
pub use discovery::{fetch_endpoints, DiscoveryEndpoint, DiscoveryResponse};
```

- [ ] **Step 5: Run the test**

Run: `cargo test -p wires-net discovery::tests::fetch_endpoints_decodes_minimal_response`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-net/Cargo.toml crates/wires-net/src/discovery.rs \
        crates/wires-net/src/error.rs crates/wires-net/src/lib.rs
git commit -m "wires-net: add HTTPS discovery::fetch_endpoints"
```

---

### Task 3: `peer_hint::first_reachable_with_discovery`

Replaces the unused TODOs with a proper retry-through-discovery path.

**Files:**
- Modify: `crates/wires-net/src/peer_hint.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/wires-net/src/peer_hint.rs` (replacing the placeholder test module):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::invite::PeerHint;
    use iroh::SecretKey;
    use iroh::endpoint::presets;

    #[tokio::test]
    async fn first_reachable_returns_none_for_no_hints_and_no_url() {
        let ep = iroh::Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let res = first_reachable_with_discovery(
            &ep,
            &[],
            None,
            b"/wires/tenant/0",
            std::time::Duration::from_millis(50),
        )
        .await;
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn first_reachable_falls_back_to_discovery_url() {
        use axum::{Json, Router, routing::get};
        use serde_json::json;
        // Boot a target endpoint we'll discover.
        let target_ep = iroh::Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .alpns(vec![b"/wires/test-alpn/0".to_vec()])
            .bind()
            .await
            .unwrap();
        let target_id_hex = hex::encode(target_ep.id().as_bytes());

        // Serve a discovery response pointing at it.
        let id_for_handler = target_id_hex.clone();
        let app = Router::new().route(
            "/v1/bootstrap",
            get(move || {
                let id = id_for_handler.clone();
                async move {
                    Json(json!({
                        "version": 1,
                        "endpoints": [{ "endpoint_id": id, "relay": null, "addrs": [] }],
                        "ttl_seconds": 300
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok(); });
        let url = format!("http://{addr}/v1/bootstrap");

        // Caller endpoint with no usable peer_hints.
        let caller_ep = iroh::Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let chosen = first_reachable_with_discovery(
            &caller_ep,
            &[],
            Some(&url),
            b"/wires/test-alpn/0",
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), target_ep.id());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-net peer_hint::tests::first_reachable_falls_back_to_discovery_url`
Expected: FAIL — `first_reachable_with_discovery` does not exist.

- [ ] **Step 3: Implement `first_reachable_with_discovery`**

In `crates/wires-net/src/peer_hint.rs`, drop the two `TODO:` lines from the module docstring and `first_reachable`'s docstring (they're being resolved by this task), then add this function below `first_reachable`:

```rust
/// Like [`first_reachable`], but if every entry in `peer_hints` fails AND
/// `discovery_url` is `Some`, fetches fresh hints from that URL and retries.
/// Spec §6 fallback path.
pub async fn first_reachable_with_discovery(
    endpoint: &iroh::Endpoint,
    peer_hints: &[crate::invite::PeerHint],
    discovery_url: Option<&str>,
    alpn: &[u8],
    per_hint_timeout: std::time::Duration,
) -> Option<iroh::EndpointId> {
    if let Some(id) = first_reachable(endpoint, peer_hints, alpn, per_hint_timeout).await {
        return Some(id);
    }
    let url = discovery_url?;
    let fresh = match crate::discovery::fetch_endpoints(url).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, url, "discovery fetch failed");
            return None;
        }
    };
    first_reachable(endpoint, &fresh, alpn, per_hint_timeout).await
}
```

- [ ] **Step 4: Run the new tests**

Run: `cargo test -p wires-net peer_hint::tests`
Expected: PASS (2 tests).

- [ ] **Step 5: Re-export the new helper**

In `crates/wires-net/src/lib.rs`, extend the existing `pub use peer_hint::...` line:

```rust
pub use peer_hint::{DialOutcome, first_reachable, first_reachable_with_discovery};
```

- [ ] **Step 6: Commit**

```bash
git add crates/wires-net/src/peer_hint.rs crates/wires-net/src/lib.rs
git commit -m "wires-net: peer_hint discovery-URL fallback (spec §6)"
```

---

### Task 4: `TenantClient::register_tenant` convenience wrapper

Pairing today requires the caller to construct timestamps, nonces, build signing bytes, sign, build the request, and call `TenantClient::send` — too much for a CLI subcommand to do inline. Wrap it.

**Files:**
- Modify: `crates/wires-net/src/tenant.rs`

- [ ] **Step 1: Add failing test**

Append a new test to the `tests` module at the bottom of `crates/wires-net/src/tenant.rs`:

```rust
    #[tokio::test]
    async fn register_tenant_helper_round_trips() {
        // Build a tiny TenantHandler that approves any well-signed register.
        use std::sync::Arc;
        struct Acc {
            host_id: [u8; 32],
            now: i64,
        }
        impl TenantHandler for Acc {
            fn handle_register(&self, req: TenantRegisterRequest) -> TenantResponse {
                // Verify the signature so we exercise the convenience function's signing.
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = register_signing_bytes(
                    &req.root_pubkey,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                TenantResponse::Register(TenantRegisterResponse {
                    ok: true,
                    host_endpoint_id: hex::encode(self.host_id),
                    server_time: self.now,
                    caps_topic_id: [9u8; 32],
                })
            }
            fn handle_topic_register(&self, _r: TopicRegisterRequest) -> TenantResponse {
                unreachable!()
            }
            fn handle_topic_unregister(&self, _r: TopicUnregisterRequest) -> TenantResponse {
                unreachable!()
            }
            fn handle_status(&self, _r: TenantStatusRequest) -> TenantResponse {
                unreachable!()
            }
        }
        let host_secret = iroh::SecretKey::generate();
        let host_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(host_secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let host_id: [u8; 32] = host_ep.id().as_bytes().to_owned();
        let handler = Arc::new(Acc {
            host_id,
            now: 42,
        });
        let _router = iroh::protocol::Router::builder(host_ep.clone())
            .accept(ALPN, TenantProtocol::new(handler))
            .spawn();

        let caller_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(iroh::SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let client = TenantClient::new(caller_ep);
        let root = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let resp = client
            .register_tenant(host_ep.id(), &root, &host_id, 1234)
            .await
            .unwrap();
        match resp {
            TenantResponse::Register(r) => {
                assert!(r.ok);
                assert_eq!(r.server_time, 42);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-net tenant::tests::register_tenant_helper_round_trips`
Expected: FAIL — `register_tenant` method does not exist on `TenantClient`.

- [ ] **Step 3: Implement the convenience helper**

In `crates/wires-net/src/tenant.rs`, add the following block right after the existing `impl TenantClient { ... pub async fn send ... }` block (anywhere inside `impl TenantClient`):

```rust
    /// Sign a `TenantRegisterRequest` with `root_signer` and dial `peer` to
    /// send it. `host_endpoint_id` must be the 32-byte ID of the host at
    /// `peer` (included in the signed bytes per spec §4.2). `timestamp_ms`
    /// should be the caller's current UNIX millis (the host accepts ±60s).
    pub async fn register_tenant(
        &self,
        peer: EndpointId,
        root_signer: &ed25519_dalek::SigningKey,
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<TenantResponse> {
        use ed25519_dalek::Signer as _;
        use rand_core::RngCore as _;
        let root_pubkey = root_signer.verifying_key().to_bytes();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let bytes =
            register_signing_bytes(&root_pubkey, timestamp_ms, &nonce, host_endpoint_id);
        let signature = root_signer.sign(&bytes).to_bytes();
        let req = TenantRequest::Register(TenantRegisterRequest {
            version: 1,
            root_pubkey,
            timestamp: timestamp_ms,
            nonce,
            signature,
        });
        self.send(peer, &req).await
    }
```

`rand_core` is already in `wires-net/Cargo.toml`'s `[dependencies]` — no change needed.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p wires-net tenant::tests::register_tenant_helper_round_trips`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/Cargo.toml crates/wires-net/src/tenant.rs
git commit -m "wires-net: TenantClient::register_tenant convenience"
```

---

### Task 5: `TenantClient::register_topic` / `unregister_topic` / `status`

Three more convenience wrappers in the same shape.

**Files:**
- Modify: `crates/wires-net/src/tenant.rs`

- [ ] **Step 1: Write the failing test**

Append to the `tests` module in `crates/wires-net/src/tenant.rs`:

```rust
    #[tokio::test]
    async fn topic_register_status_unregister_helpers_round_trip() {
        use std::sync::{Arc, Mutex};
        let topic = [0xAAu8; 32];

        #[derive(Default)]
        struct Acc {
            host_id: [u8; 32],
            registered: Mutex<Vec<[u8; 32]>>,
        }
        impl TenantHandler for Acc {
            fn handle_register(&self, _r: TenantRegisterRequest) -> TenantResponse {
                unreachable!()
            }
            fn handle_topic_register(&self, req: TopicRegisterRequest) -> TenantResponse {
                self.registered.lock().unwrap().push(req.topic_id);
                TenantResponse::TopicRegister(TopicRegisterResponse {
                    ok: true,
                    topic_id: req.topic_id,
                })
            }
            fn handle_topic_unregister(&self, req: TopicUnregisterRequest) -> TenantResponse {
                self.registered.lock().unwrap().retain(|t| t != &req.topic_id);
                TenantResponse::TopicUnregister(TopicUnregisterResponse {
                    ok: true,
                    topic_id: req.topic_id,
                })
            }
            fn handle_status(&self, _r: TenantStatusRequest) -> TenantResponse {
                TenantResponse::Status(TenantStatusResponse {
                    registered_at: 1,
                    topic_count: 1,
                    bytes_stored: 0,
                    retention_budget_bytes: 1 << 20,
                    oldest_retained_at: 0,
                    write_rate_limit_per_sec: 1000,
                    status: TenantStatusKind::Active,
                })
            }
        }

        let host_secret = iroh::SecretKey::generate();
        let host_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(host_secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let host_id: [u8; 32] = host_ep.id().as_bytes().to_owned();
        let handler = Arc::new(Acc { host_id, registered: Default::default() });
        let _router = iroh::protocol::Router::builder(host_ep.clone())
            .accept(ALPN, TenantProtocol::new(Arc::clone(&handler)))
            .spawn();

        let caller_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(iroh::SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let client = TenantClient::new(caller_ep);
        let root = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        // Register.
        let r = client
            .register_topic(host_ep.id(), &root, &topic, &host_id, 100)
            .await
            .unwrap();
        matches!(r, TenantResponse::TopicRegister(_));
        assert_eq!(handler.registered.lock().unwrap().clone(), vec![topic]);

        // Status.
        let s = client
            .tenant_status(host_ep.id(), &root, &host_id, 101)
            .await
            .unwrap();
        match s {
            TenantResponse::Status(s) => assert_eq!(s.write_rate_limit_per_sec, 1000),
            other => panic!("unexpected response: {other:?}"),
        }

        // Unregister.
        let u = client
            .unregister_topic(host_ep.id(), &root, &topic, &host_id, 102)
            .await
            .unwrap();
        matches!(u, TenantResponse::TopicUnregister(_));
        assert!(handler.registered.lock().unwrap().is_empty());
    }
```

- [ ] **Step 2: Verify the test fails**

Run: `cargo test -p wires-net tenant::tests::topic_register_status_unregister_helpers_round_trip`
Expected: FAIL — methods do not exist.

- [ ] **Step 3: Implement the three helpers**

In `crates/wires-net/src/tenant.rs`, append to `impl TenantClient`:

```rust
    pub async fn register_topic(
        &self,
        peer: EndpointId,
        root_signer: &ed25519_dalek::SigningKey,
        topic_id: &[u8; 32],
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<TenantResponse> {
        use ed25519_dalek::Signer as _;
        use rand_core::RngCore as _;
        let root_pubkey = root_signer.verifying_key().to_bytes();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let bytes = topic_register_signing_bytes(
            &root_pubkey,
            topic_id,
            timestamp_ms,
            &nonce,
            host_endpoint_id,
        );
        let signature = root_signer.sign(&bytes).to_bytes();
        let req = TenantRequest::TopicRegister(TopicRegisterRequest {
            version: 1,
            root_pubkey,
            topic_id: *topic_id,
            timestamp: timestamp_ms,
            nonce,
            signature,
        });
        self.send(peer, &req).await
    }

    pub async fn unregister_topic(
        &self,
        peer: EndpointId,
        root_signer: &ed25519_dalek::SigningKey,
        topic_id: &[u8; 32],
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<TenantResponse> {
        use ed25519_dalek::Signer as _;
        use rand_core::RngCore as _;
        let root_pubkey = root_signer.verifying_key().to_bytes();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let bytes = topic_unregister_signing_bytes(
            &root_pubkey,
            topic_id,
            timestamp_ms,
            &nonce,
            host_endpoint_id,
        );
        let signature = root_signer.sign(&bytes).to_bytes();
        let req = TenantRequest::TopicUnregister(TopicUnregisterRequest {
            version: 1,
            root_pubkey,
            topic_id: *topic_id,
            timestamp: timestamp_ms,
            nonce,
            signature,
        });
        self.send(peer, &req).await
    }

    pub async fn tenant_status(
        &self,
        peer: EndpointId,
        root_signer: &ed25519_dalek::SigningKey,
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<TenantResponse> {
        use ed25519_dalek::Signer as _;
        use rand_core::RngCore as _;
        let root_pubkey = root_signer.verifying_key().to_bytes();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let bytes = status_signing_bytes(&root_pubkey, timestamp_ms, &nonce, host_endpoint_id);
        let signature = root_signer.sign(&bytes).to_bytes();
        let req = TenantRequest::Status(TenantStatusRequest {
            version: 1,
            root_pubkey,
            timestamp: timestamp_ms,
            nonce,
            signature,
        });
        self.send(peer, &req).await
    }
```

- [ ] **Step 4: Run the new test**

Run: `cargo test -p wires-net tenant::tests::topic_register_status_unregister_helpers_round_trip`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/src/tenant.rs
git commit -m "wires-net: TenantClient topic-register/unregister/status helpers"
```

---

## Phase 3 — `wires-node` runtime

### Task 6: `NodeRuntime` skeleton + `open`

A thin owner over Node + Endpoint + NetGlue. Per-topic gossip handles are stashed in a `Mutex<HashMap<...>>` so `publish_and_broadcast` can find the handle for a topic without re-subscribing.

**Files:**
- Create: `crates/wires-node/src/runtime.rs`
- Modify: `crates/wires-node/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-node/src/runtime.rs` with this content (test-only at first, plus a stub):

```rust
//! `NodeRuntime` — owns an iroh Endpoint, gossip + replay glue, and a Node.
//! Provides the high-level `join_topic` / `publish_and_broadcast` /
//! `replay_from_host` surface used by `wires-cli` and `wires-ha`.

use std::collections::HashMap;
use std::sync::Arc;

use iroh::{Endpoint, SecretKey, endpoint::presets};
use parking_lot::Mutex;
use snafu::ResultExt;
use wires_net::{GossipHandle, load_or_create_secret};

use crate::config::NodeConfig;
use crate::error::{IoSnafu, NetSnafu, Result};
use crate::net_glue::NetGlue;
use crate::node::Node;

pub struct NodeRuntime {
    pub node: Arc<Node>,
    pub endpoint: Endpoint,
    pub glue: NetGlue,
    /// One gossip handle per joined topic.
    handles: Mutex<HashMap<[u8; 32], GossipHandle>>,
}

impl NodeRuntime {
    /// Open the underlying `Node`, load (or create) the per-data-dir iroh
    /// secret at `iroh.secret`, bind an Endpoint, and wire NetGlue.
    pub async fn open(config: NodeConfig) -> Result<Self> {
        let node = Arc::new(Node::open(config.clone())?);
        let secret_path = config.data_dir.join("iroh.secret");
        let secret = load_or_create_secret(&secret_path).context(NetSnafu)?;
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::from_bytes(&secret))
            .alpns(vec![wires_net::ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| std::io::Error::other(format!("endpoint bind: {e}")))
            .context(IoSnafu)?;
        let glue = NetGlue::new(endpoint.clone(), Arc::clone(&node.logs))
            .await
            .map_err(|e| std::io::Error::other(format!("net glue: {e}")))
            .context(IoSnafu)?;
        Ok(Self {
            node,
            endpoint,
            glue,
            handles: Mutex::new(HashMap::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn open_binds_an_endpoint_and_loads_a_node() {
        let tmp = TempDir::new().unwrap();
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: hex::encode([7u8; 32]),
            host: None,
        };
        let rt = NodeRuntime::open(cfg).await.unwrap();
        assert!(rt.endpoint.id().as_bytes().iter().any(|b| *b != 0));
        assert_eq!(rt.node.config.root_pubkey_hex.len(), 64);
    }
}
```

- [ ] **Step 2: Re-export `NodeRuntime`**

In `crates/wires-node/src/lib.rs`, add:

```rust
pub mod runtime;
pub use runtime::NodeRuntime;
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p wires-node runtime::tests::open_binds_an_endpoint_and_loads_a_node`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-node/src/runtime.rs crates/wires-node/src/lib.rs
git commit -m "wires-node: NodeRuntime skeleton + open"
```

---

### Task 7: `NodeRuntime::join_topic`

`join_topic(topic_id, bootstrap_peers)` subscribes via gossip, spawns the inbound-routing task into `node.handle_inbound`, and remembers the `GossipHandle` so a later `publish_and_broadcast` can find it.

**Files:**
- Modify: `crates/wires-node/src/runtime.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/wires-node/src/runtime.rs` `tests` module:

```rust
    #[tokio::test]
    async fn join_topic_registers_a_gossip_handle() {
        let tmp = TempDir::new().unwrap();
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: hex::encode([7u8; 32]),
            host: None,
        };
        let rt = NodeRuntime::open(cfg).await.unwrap();
        let topic = [1u8; 32];
        assert!(rt.join_topic(topic, vec![]).await.is_ok());
        // Second join is idempotent (returns the cached handle).
        assert!(rt.join_topic(topic, vec![]).await.is_ok());
        assert!(rt.has_joined(&topic));
    }
```

- [ ] **Step 2: Verify failure**

Run: `cargo test -p wires-node runtime::tests::join_topic_registers_a_gossip_handle`
Expected: FAIL — `join_topic` / `has_joined` not defined.

- [ ] **Step 3: Implement `join_topic`**

In `crates/wires-node/src/runtime.rs`, add inside `impl NodeRuntime`:

```rust
    /// Join `topic_id` on gossip (with optional `bootstrap` peer hints), and
    /// route inbound envelopes to `node.handle_inbound`. Idempotent: a second
    /// call returns the cached handle.
    pub async fn join_topic(
        &self,
        topic_id: [u8; 32],
        bootstrap: Vec<iroh::EndpointId>,
    ) -> Result<GossipHandle> {
        if let Some(h) = self.handles.lock().get(&topic_id) {
            return Ok(h.clone());
        }
        let handle = self
            .glue
            .subscribe_and_route(Arc::clone(&self.node), topic_id, bootstrap)
            .await?;
        self.handles.lock().insert(topic_id, handle.clone());
        Ok(handle)
    }

    /// Whether `topic_id` has been joined (debug/test helper).
    pub fn has_joined(&self, topic_id: &[u8; 32]) -> bool {
        self.handles.lock().contains_key(topic_id)
    }
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p wires-node runtime::tests::join_topic_registers_a_gossip_handle`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-node/src/runtime.rs
git commit -m "wires-node: NodeRuntime::join_topic"
```

---

### Task 8: `NodeRuntime::publish_and_broadcast`

Writes the message to the local log (`node.publish_standard`) and broadcasts the serialized envelope over gossip. The topic must already be joined.

**Files:**
- Modify: `crates/wires-node/src/runtime.rs`
- Create: `crates/wires-node/tests/runtime_publish_subscribes.rs`

- [ ] **Step 1: Write the failing integration test**

Create `crates/wires-node/tests/runtime_publish_subscribes.rs` with:

```rust
//! Two NodeRuntimes on the same machine join the same topic; one publishes,
//! the other observes the message via its broadcast event stream.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::cap::Right;
use wires_core::{CanonicalContent, Capability};
use wires_node::{NodeConfig, NodeRuntime};

#[tokio::test]
async fn runtime_publish_reaches_peer_runtime() {
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let topic = [0x42u8; 32];

    let alice_tmp = TempDir::new().unwrap();
    let bob_tmp = TempDir::new().unwrap();
    let alice_cfg = NodeConfig {
        data_dir: alice_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        host: None,
    };
    let bob_cfg = NodeConfig {
        data_dir: bob_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        host: None,
    };

    let alice = NodeRuntime::open(alice_cfg).await.unwrap();
    let bob = NodeRuntime::open(bob_cfg).await.unwrap();

    // Install matching epoch key on both nodes.
    let epoch_key = [0x99u8; 32];
    alice.node.install_epoch_key(topic, 0, epoch_key).unwrap();
    bob.node.install_epoch_key(topic, 0, epoch_key).unwrap();

    // Mint a cap for alice (so she can publish under the root) and install on both.
    let alice_pk = alice.node.ed_sk.verifying_key().to_bytes();
    let mut cap = Capability::new_unsigned(
        alice_pk,
        vec![hex::encode(topic)],
        vec![Right::Read, Right::Write],
        0,
        None,
    );
    cap.sign(&root).unwrap();
    alice.node.caps.upsert_grant(&cap).unwrap();
    bob.node.caps.upsert_grant(&cap).unwrap();

    // Alice and Bob both join the topic; Bob bootstraps from Alice.
    alice.join_topic(topic, vec![]).await.unwrap();
    bob.join_topic(topic, vec![alice.endpoint.id()]).await.unwrap();

    // Subscribe Bob's event stream before publishing.
    let mut bob_events = bob.node.subscribe();

    // Wait briefly for the gossip mesh to converge.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let content = CanonicalContent::new("agent.note", "hello bob");
    alice
        .publish_and_broadcast(topic, cap.cap_id.0, content)
        .await
        .unwrap();

    // Bob should observe the decrypted event within a short window.
    let event = tokio::time::timeout(Duration::from_secs(5), bob_events.recv())
        .await
        .expect("did not receive event in time")
        .unwrap();
    assert_eq!(event.topic_id, topic);
    let c = event.content.expect("decryption should succeed");
    assert_eq!(c.text, "hello bob");
}
```

- [ ] **Step 2: Verify failure**

Run: `cargo test -p wires-node --test runtime_publish_subscribes`
Expected: FAIL — `publish_and_broadcast` does not exist.

- [ ] **Step 3: Implement `publish_and_broadcast`**

In `crates/wires-node/src/runtime.rs`, add to `impl NodeRuntime`:

```rust
    /// Publish a `Standard`-mode message and broadcast the resulting envelope
    /// to every joined peer on this topic. The topic must already have been
    /// joined via `join_topic`.
    pub async fn publish_and_broadcast(
        &self,
        topic_id: [u8; 32],
        cap_id: [u8; 16],
        content: wires_core::CanonicalContent,
    ) -> Result<wires_core::WireMessage> {
        let handle = self
            .handles
            .lock()
            .get(&topic_id)
            .cloned()
            .ok_or_else(|| crate::error::NodeError::Config {
                message: format!(
                    "publish_and_broadcast called on un-joined topic {}",
                    hex::encode(topic_id)
                ),
                location: snafu::location!(),
            })?;
        let msg = self.node.publish_standard(topic_id, cap_id, content)?;
        let bytes = serde_json::to_vec(&msg).context(crate::error::SerdeSnafu)?;
        handle.broadcast(bytes).await.context(NetSnafu)?;
        Ok(msg)
    }
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p wires-node --test runtime_publish_subscribes -- --nocapture`
Expected: PASS (within ~10s). If it times out on a noisy CI, increase the sleep to 1s and timeout to 10s.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-node/src/runtime.rs crates/wires-node/tests/runtime_publish_subscribes.rs
git commit -m "wires-node: NodeRuntime::publish_and_broadcast"
```

---

### Task 9: `NodeRuntime::replay_from_host`

When a host is configured, `cat` should pull missing history via replay before reading the local log. This wraps `NetGlue::replay_from` and resolves the host's `EndpointId` from `HostConfig.peer_hints[0].node_id`.

**Files:**
- Modify: `crates/wires-node/src/runtime.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/wires-node/src/runtime.rs` `tests` module:

```rust
    #[tokio::test]
    async fn replay_from_host_errors_when_no_host_configured() {
        let tmp = TempDir::new().unwrap();
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: hex::encode([7u8; 32]),
            host: None,
        };
        let rt = NodeRuntime::open(cfg).await.unwrap();
        let topic = [9u8; 32];
        let err = rt.replay_from_host(topic).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no host configured"), "unexpected error: {msg}");
    }
```

- [ ] **Step 2: Verify failure**

Run: `cargo test -p wires-node runtime::tests::replay_from_host_errors_when_no_host_configured`
Expected: FAIL — method does not exist.

- [ ] **Step 3: Implement `replay_from_host`**

In `crates/wires-node/src/runtime.rs`, add to `impl NodeRuntime`:

```rust
    /// Pull missing history for `topic_id` from the configured host via the
    /// replay ALPN, and feed each delivered envelope to `node.handle_inbound`.
    /// Errors with a configuration error if no host is set or if no usable
    /// peer hint is reachable.
    pub async fn replay_from_host(&self, topic_id: [u8; 32]) -> Result<usize> {
        let host = self
            .node
            .config
            .host
            .as_ref()
            .ok_or_else(|| crate::error::NodeError::Config {
                message: "replay_from_host: no host configured".into(),
                location: snafu::location!(),
            })?;
        let peer = wires_net::first_reachable_with_discovery(
            &self.endpoint,
            &host.peer_hints,
            host.discovery_url.as_deref(),
            wires_net::ALPN,
            std::time::Duration::from_secs(5),
        )
        .await
        .ok_or_else(|| crate::error::NodeError::Config {
            message: "replay_from_host: no reachable peer hint".into(),
            location: snafu::location!(),
        })?;
        self.glue.replay_from(Arc::clone(&self.node), topic_id, peer).await
    }
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p wires-node runtime::tests::replay_from_host_errors_when_no_host_configured`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-node/src/runtime.rs
git commit -m "wires-node: NodeRuntime::replay_from_host"
```

---

## Phase 4 — `wires-cli` operator path

### Task 10: Add `host` subcommand scaffolding

Wires up clap with no-op handlers so subsequent tasks fill in real logic.

**Files:**
- Modify: `crates/wires-cli/src/main.rs`
- Create: `crates/wires-cli/src/cmd/host.rs`
- Modify: `crates/wires-cli/src/cmd/mod.rs`

- [ ] **Step 1: Add the `host` enum + dispatch in main.rs**

Edit `crates/wires-cli/src/main.rs`. Inside the `Cmd` enum, add a `Host` variant:

```rust
    /// Tenant control: pair with a host, register topics, view status.
    #[command(subcommand)]
    Host(HostCmd),
    /// Join an invite token: install the cap and store the inviter's host info.
    Join {
        /// Base64-encoded InviteToken (output of `wires invite`).
        token: String,
    },
```

After the existing `TopicCmd` enum, add:

```rust
#[derive(Subcommand)]
enum HostCmd {
    /// Pair with a host: fetch its endpoint from a discovery URL, register
    /// this tenant (signed by your local root key), persist the host info.
    Pair {
        #[arg(long)]
        discovery_url: String,
    },
    /// Register a topic with the paired host so it persists envelopes for it.
    TopicRegister { topic: String },
    /// Unregister a topic: the host stops persisting new envelopes (existing
    /// data is retained until eviction).
    TopicUnregister { topic: String },
    /// Print this tenant's status as the host reports it.
    Status,
}
```

In the `match cli.command { ... }` block, add arms that call into stubbed module functions:

```rust
        Cmd::Host(HostCmd::Pair { discovery_url }) => {
            cmd::host::pair(&data_dir, &discovery_url).await
        }
        Cmd::Host(HostCmd::TopicRegister { topic }) => {
            cmd::host::topic_register(&data_dir, &topic).await
        }
        Cmd::Host(HostCmd::TopicUnregister { topic }) => {
            cmd::host::topic_unregister(&data_dir, &topic).await
        }
        Cmd::Host(HostCmd::Status) => cmd::host::status(&data_dir).await,
        Cmd::Join { token } => cmd::join::run(&data_dir, &token).await,
```

- [ ] **Step 2: Add the new module files**

Create `crates/wires-cli/src/cmd/host.rs`:

```rust
//! `wires host *` subcommands. Each one loads the local root key from
//! `<data_dir>/root.ed25519`, opens a fresh iroh endpoint, dials a `TenantClient`,
//! and runs one request.

use std::path::Path;

pub async fn pair(
    _data_dir: &Path,
    _discovery_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host pair: not implemented yet".into())
}

pub async fn topic_register(
    _data_dir: &Path,
    _topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host topic-register: not implemented yet".into())
}

pub async fn topic_unregister(
    _data_dir: &Path,
    _topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host topic-unregister: not implemented yet".into())
}

pub async fn status(_data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host status: not implemented yet".into())
}
```

Create `crates/wires-cli/src/cmd/join.rs`:

```rust
//! `wires join <token>` — install an invite token: persist the cap and copy
//! the inviter's host hints into local config.

use std::path::Path;

pub async fn run(_data_dir: &Path, _token: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires join: not implemented yet".into())
}
```

In `crates/wires-cli/src/cmd/mod.rs`, register the new modules:

```rust
pub mod cat;
pub mod host;
pub mod init;
pub mod invite;
pub mod join;
pub mod publish;
pub mod revoke;
pub mod status;
pub mod topic;
```

- [ ] **Step 3: Verify it builds**

Run: `cargo build -p wires-cli`
Expected: build succeeds. (No tests at this stage — the actual flows arrive in following tasks.)

- [ ] **Step 4: Commit**

```bash
git add crates/wires-cli/src/main.rs crates/wires-cli/src/cmd/mod.rs \
        crates/wires-cli/src/cmd/host.rs crates/wires-cli/src/cmd/join.rs
git commit -m "wires-cli: scaffold host + join subcommands"
```

---

### Task 11: `wires host pair --discovery-url`

Implements the operator pairing flow: fetch discovery, dial the listed endpoint, send `TenantRegisterRequest` signed by the local root key, persist the new `HostConfig` into `config.toml`.

**Files:**
- Modify: `crates/wires-cli/src/cmd/host.rs`
- Create: `crates/wires-cli/tests/cli_host_pair.rs`

- [ ] **Step 1: Write the failing integration test**

Create `crates/wires-cli/tests/cli_host_pair.rs`:

```rust
//! Integration test: spin up a minimal tenant-only host process in-process,
//! point `wires host pair` at it via a discovery URL, and verify config.toml
//! is updated with the host's peer hint.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{Json, Router, routing::get};
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use rand_core::OsRng;
use serde_json::json;
use tempfile::TempDir;
use wires_host::http_discovery::{DiscoveryEndpoint, DiscoveryResponse, DiscoveryState};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol};

#[tokio::test]
async fn host_pair_persists_host_to_config() {
    // ---- spin up a tenant-aware host -----------------------------------
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![TENANT_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let host_eid: [u8; 32] = host_ep.id().as_bytes().to_owned();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention,
        host_endpoint_id: host_eid,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
        }),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    let discovery_state = Arc::new(DiscoveryState {
        response: DiscoveryResponse {
            version: 1,
            endpoints: vec![DiscoveryEndpoint {
                endpoint_id: hex::encode(host_eid),
                relay: None,
                addrs: vec![],
            }],
            ttl_seconds: 300,
        },
    });
    let app = wires_host::http_discovery::router(discovery_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok(); });

    // ---- run `wires init` then `wires host pair` -----------------------
    let agent_dir = TempDir::new().unwrap();
    // Mimic `wires init`: write root.ed25519 + a minimal config.toml.
    let root = SigningKey::generate(&mut OsRng);
    std::fs::write(agent_dir.path().join("root.ed25519"), root.to_bytes()).unwrap();
    let cfg = wires_node::NodeConfig {
        data_dir: agent_dir.path().to_path_buf(),
        root_pubkey_hex: hex::encode(root.verifying_key().to_bytes()),
        host: None,
    };
    std::fs::write(
        agent_dir.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();

    let url = format!("http://{addr}/v1/bootstrap");
    wires_cli::cmd::host::pair(agent_dir.path(), &url).await.unwrap();

    // ---- assert config.toml gained host fields -------------------------
    let after: wires_node::NodeConfig = toml::from_str(
        &std::fs::read_to_string(agent_dir.path().join("config.toml")).unwrap(),
    )
    .unwrap();
    let h = after.host.expect("host should be set after pair");
    assert_eq!(h.peer_hints.len(), 1);
    assert_eq!(h.peer_hints[0].node_id, hex::encode(host_eid));
    assert_eq!(h.discovery_url.as_deref(), Some(url.as_str()));

    // Tenant must be in the host's registry.
    let root_pubkey = root.verifying_key().to_bytes();
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}
```

Add a test-harness shim crate-local module so the test can call `pair` without going through `clap`. Create `crates/wires-cli/src/lib.rs`:

```rust
//! Library half of `wires-cli`. Exists so integration tests can drive
//! subcommand handlers without running the binary through a subprocess.

pub mod cmd;
```

And `crates/wires-cli/src/cmd/mod.rs` is already created — keep it.

Move the `mod cmd;` line out of `crates/wires-cli/src/main.rs` and replace with `use wires_cli::cmd;`. Add a `[lib]` entry to `crates/wires-cli/Cargo.toml`:

```toml
[lib]
name = "wires_cli"
path = "src/lib.rs"

[[bin]]
name = "wires"
path = "src/main.rs"
```

Integration tests can now call into the implementation directly as `wires_cli::cmd::host::pair(...)` etc. Drop the `wires_cli_test_harness::run_pair(...)` placeholder in the test code and use `wires_cli::cmd::host::pair(agent_dir.path(), &url).await.unwrap();` instead.

Add `[dev-dependencies]` to `crates/wires-cli/Cargo.toml`:

```toml
[dev-dependencies]
tempfile = { workspace = true }
tokio    = { workspace = true, features = ["macros", "rt-multi-thread"] }
wires-host = { workspace = true }
wires-net  = { workspace = true }
wires-node = { workspace = true }
rand_core  = { workspace = true }
ed25519-dalek = { workspace = true }
hex        = { workspace = true }
serde_json = { workspace = true }
toml       = { workspace = true }
axum       = "0.8"
iroh       = { workspace = true }
```

`wires-host` is not currently in `[workspace.dependencies]`. Add a line under the "Internal" comment in the top-level `Cargo.toml`:

```toml
wires-host   = { path = "crates/wires-host" }
```

so the new `[dev-dependencies]` block in `wires-cli/Cargo.toml` can reference `wires-host = { workspace = true }`.

- [ ] **Step 2: Verify failure**

Run: `cargo test -p wires-cli --test cli_host_pair`
Expected: FAIL — `pair` returns the "not implemented yet" error.

- [ ] **Step 3: Implement `pair`**

Replace the **entire contents** of `crates/wires-cli/src/cmd/host.rs` (which is currently just stubs) with:

```rust
//! `wires host *` subcommands. Each one loads the local root key from
//! `<data_dir>/root.ed25519`, opens a fresh iroh endpoint, dials a `TenantClient`,
//! and runs one request.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use wires_net::tenant::{TenantClient, TenantResponse};
use wires_net::{fetch_endpoints, load_or_create_secret};
use wires_node::{HostConfig, NodeConfig};

pub async fn pair(
    data_dir: &Path,
    discovery_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load existing config + root key.
    let cfg_path = data_dir.join("config.toml");
    let mut cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(&cfg_path)?)?;
    let root_bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    if root_bytes.len() != 32 {
        return Err("root.ed25519 must be 32 bytes — `wires invite` requires the local root.".into());
    }
    let root = SigningKey::from_bytes(&root_bytes.try_into().unwrap());

    // Fetch discovery; pick the first endpoint.
    let hints = fetch_endpoints(discovery_url).await?;
    let first = hints.first().ok_or("discovery returned no endpoints")?.clone();
    let host_eid_bytes: [u8; 32] = {
        let v = hex::decode(&first.node_id)?;
        if v.len() != 32 {
            return Err("discovery endpoint_id not 32-byte hex".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    };
    let host_eid = iroh::EndpointId::from_bytes(&host_eid_bytes)
        .map_err(|e| format!("bad endpoint id from discovery: {e}"))?;

    // Bind our own endpoint, register, persist.
    let secret_path = data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await?;
    let client = TenantClient::new(ep);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let resp = client.register_tenant(host_eid, &root, &host_eid_bytes, now).await?;
    match resp {
        TenantResponse::Register(r) if r.ok => {
            println!("Paired with host {} (server_time={})", r.host_endpoint_id, r.server_time);
        }
        TenantResponse::Error(e) => {
            return Err(format!("host rejected: {:?} — {}", e.code, e.message).into());
        }
        other => return Err(format!("unexpected response: {other:?}").into()),
    }
    cfg.host = Some(HostConfig {
        peer_hints: vec![first],
        discovery_url: Some(discovery_url.to_string()),
    });
    std::fs::write(&cfg_path, toml::to_string_pretty(&cfg)?)?;
    println!("Host info persisted to {}", cfg_path.display());
    Ok(())
}

pub async fn topic_register(
    _data_dir: &Path,
    _topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host topic-register: not implemented yet (Task 12)".into())
}

pub async fn topic_unregister(
    _data_dir: &Path,
    _topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host topic-unregister: not implemented yet (Task 12)".into())
}

pub async fn status(_data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host status: not implemented yet (Task 13)".into())
}
```

The remaining three stubs are filled in by Tasks 12 and 13.

- [ ] **Step 4: Run the test**

Run: `cargo test -p wires-cli --test cli_host_pair`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/wires-cli/Cargo.toml crates/wires-cli/src/lib.rs \
        crates/wires-cli/src/main.rs crates/wires-cli/src/cmd/host.rs \
        crates/wires-cli/tests/cli_host_pair.rs
git commit -m "wires-cli: implement wires host pair --discovery-url"
```

---

### Task 12: `wires host topic-register` + `wires host topic-unregister`

Once paired, the operator registers each topic the host should persist.

**Files:**
- Modify: `crates/wires-cli/src/cmd/host.rs`
- Create: `crates/wires-cli/tests/cli_host_topic_register.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-cli/tests/cli_host_topic_register.rs`:

```rust
//! After `wires host pair`, `wires host topic-register <hex>` enrolls a
//! topic with the host. Subsequent inbound envelopes for that topic should
//! be routed and persisted.

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::http_discovery::{DiscoveryEndpoint, DiscoveryResponse, DiscoveryState};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol};

#[tokio::test]
async fn topic_register_round_trip() {
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![TENANT_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let host_eid: [u8; 32] = host_ep.id().as_bytes().to_owned();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention,
        host_endpoint_id: host_eid,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
        }),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    let discovery_state = Arc::new(DiscoveryState {
        response: DiscoveryResponse {
            version: 1,
            endpoints: vec![DiscoveryEndpoint {
                endpoint_id: hex::encode(host_eid),
                relay: None,
                addrs: vec![],
            }],
            ttl_seconds: 300,
        },
    });
    let app = wires_host::http_discovery::router(discovery_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok(); });

    // Init + pair.
    let agent_dir = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    std::fs::write(agent_dir.path().join("root.ed25519"), root.to_bytes()).unwrap();
    let cfg = wires_node::NodeConfig {
        data_dir: agent_dir.path().to_path_buf(),
        root_pubkey_hex: hex::encode(root.verifying_key().to_bytes()),
        host: None,
    };
    std::fs::write(
        agent_dir.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    ).unwrap();
    wires_cli::cmd::host::pair(agent_dir.path(), &format!("http://{addr}/v1/bootstrap"))
        .await
        .unwrap();

    // Register a synthetic topic id.
    let topic = [0xCDu8; 32];
    wires_cli::cmd::host::topic_register(agent_dir.path(), &hex::encode(topic))
        .await
        .unwrap();
    let root_pubkey = root.verifying_key().to_bytes();
    assert_eq!(
        registry.lookup_topic_tenant(&topic).unwrap(),
        Some(root_pubkey)
    );

    // Unregister.
    wires_cli::cmd::host::topic_unregister(agent_dir.path(), &hex::encode(topic))
        .await
        .unwrap();
    assert!(registry.lookup_topic_tenant(&topic).unwrap().is_none());
}
```

(`TenantRegistry::lookup_topic_tenant(&topic_id) -> Result<Option<[u8;32]>>` is the existing read accessor that returns the topic→root mapping; verified against `crates/wires-host/src/tenant_registry.rs:112`.)

- [ ] **Step 2: Verify failure**

Run: `cargo test -p wires-cli --test cli_host_topic_register`
Expected: FAIL — `topic_register` still returns the "not implemented" error.

- [ ] **Step 3: Implement both subcommands**

In `crates/wires-cli/src/cmd/host.rs`, replace the stubs for `topic_register` and `topic_unregister` with:

```rust
async fn open_paired_client(
    data_dir: &Path,
) -> Result<
    (TenantClient, iroh::EndpointId, [u8; 32], SigningKey),
    Box<dyn std::error::Error>,
> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let host = cfg
        .host
        .as_ref()
        .ok_or("no host paired — run `wires host pair --discovery-url <URL>` first")?
        .clone();
    let first = host
        .peer_hints
        .first()
        .ok_or("paired host has no peer hints")?
        .clone();
    let host_eid_bytes: [u8; 32] = {
        let v = hex::decode(&first.node_id)?;
        if v.len() != 32 {
            return Err("host node_id not 32-byte hex".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    };
    let host_eid = iroh::EndpointId::from_bytes(&host_eid_bytes)
        .map_err(|e| format!("bad host endpoint id: {e}"))?;
    let root_bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    let root = SigningKey::from_bytes(&root_bytes.try_into().map_err(|_| "root.ed25519 not 32 bytes")?);
    let secret = load_or_create_secret(&data_dir.join("iroh.secret"))?;
    let ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await?;
    Ok((TenantClient::new(ep), host_eid, host_eid_bytes, root))
}

fn parse_topic(data_dir: &Path, topic: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if let Ok(bytes) = hex::decode(topic) {
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }
    let map_path = data_dir.join("topic_names.json");
    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(map_path)?)?;
    let hex_id = map
        .get(topic)
        .ok_or_else(|| format!("unknown topic '{topic}'"))?;
    let bytes = hex::decode(hex_id)?;
    if bytes.len() != 32 {
        return Err("topic_names.json entry is not 32-byte hex".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

pub async fn topic_register(
    data_dir: &Path,
    topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic_id = parse_topic(data_dir, topic)?;
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .register_topic(host_eid, &root, &topic_id, &host_eid_bytes, now_ms())
        .await?;
    match resp {
        TenantResponse::TopicRegister(r) if r.ok => {
            println!("Registered topic {}", hex::encode(r.topic_id));
            Ok(())
        }
        TenantResponse::Error(e) => Err(format!("host rejected: {:?} — {}", e.code, e.message).into()),
        other => Err(format!("unexpected response: {other:?}").into()),
    }
}

pub async fn topic_unregister(
    data_dir: &Path,
    topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic_id = parse_topic(data_dir, topic)?;
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .unregister_topic(host_eid, &root, &topic_id, &host_eid_bytes, now_ms())
        .await?;
    match resp {
        TenantResponse::TopicUnregister(r) if r.ok => {
            println!("Unregistered topic {}", hex::encode(r.topic_id));
            Ok(())
        }
        TenantResponse::Error(e) => Err(format!("host rejected: {:?} — {}", e.code, e.message).into()),
        other => Err(format!("unexpected response: {other:?}").into()),
    }
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p wires-cli --test cli_host_topic_register`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-cli/src/cmd/host.rs crates/wires-cli/tests/cli_host_topic_register.rs
git commit -m "wires-cli: implement wires host topic-register / topic-unregister"
```

---

### Task 13: `wires host status`

Wraps `TenantClient::tenant_status` and prints a human-readable summary.

**Files:**
- Modify: `crates/wires-cli/src/cmd/host.rs`

- [ ] **Step 1: Implement `status`**

In `crates/wires-cli/src/cmd/host.rs`, replace the `status` stub:

```rust
pub async fn status(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .tenant_status(host_eid, &root, &host_eid_bytes, now_ms())
        .await?;
    match resp {
        TenantResponse::Status(s) => {
            println!("Tenant status (as reported by host):");
            println!("  registered_at         : {}", s.registered_at);
            println!("  topic_count           : {}", s.topic_count);
            println!("  bytes_stored          : {}", s.bytes_stored);
            println!("  retention_budget      : {}", s.retention_budget_bytes);
            println!("  oldest_retained_at    : {}", s.oldest_retained_at);
            println!("  write_rate_limit_per_sec : {}", s.write_rate_limit_per_sec);
            println!("  status                : {:?}", s.status);
            Ok(())
        }
        TenantResponse::Error(e) => Err(format!("host rejected: {:?} — {}", e.code, e.message).into()),
        other => Err(format!("unexpected response: {other:?}").into()),
    }
}
```

- [ ] **Step 2: Smoke-test manually (no new dedicated test — `status` is a thin print on top of a tested helper)**

Run: `cargo build -p wires-cli`
Expected: build succeeds.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-cli/src/cmd/host.rs
git commit -m "wires-cli: implement wires host status"
```

---

## Phase 5 — `wires-cli` invitee path

### Task 14: Rewrite `wires invite` to emit `InviteToken`

Old behavior: prints `cap_id` hex. New behavior: builds an `InviteToken` (cap + peer_hints + discovery_url + expires + token_id), encodes as base64, prints. Requires `HostConfig` to be set (otherwise the invitee can't reach anything).

**Files:**
- Modify: `crates/wires-cli/src/cmd/invite.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-cli/tests/cli_invite_emits_token.rs`:

```rust
//! `wires invite` should print a base64 `InviteToken` that decodes back into
//! a cap whose grantor is the local root, with peer_hints copied from
//! HostConfig.

use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_net::{InviteToken, PeerHint};

static OUT: OnceLock<std::sync::Mutex<Vec<String>>> = OnceLock::new();

#[tokio::test]
async fn invite_emits_invitetoken() {
    // Synthesize a paired config and root key in a fresh data dir.
    let dir = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    std::fs::write(dir.path().join("root.ed25519"), root.to_bytes()).unwrap();
    let cfg = wires_node::NodeConfig {
        data_dir: dir.path().to_path_buf(),
        root_pubkey_hex: hex::encode(root.verifying_key().to_bytes()),
        host: Some(wires_node::HostConfig {
            peer_hints: vec![PeerHint {
                node_id: "ab".repeat(32),
                addrs: vec!["127.0.0.1:11204".into()],
                relay: None,
            }],
            discovery_url: Some("https://discovery.example/v1/bootstrap".into()),
        }),
    };
    std::fs::write(
        dir.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    // Pre-create the agent identity so `Node::open` can find it.
    let _ = wires_node::Node::open(cfg).unwrap();

    let invitee = SigningKey::generate(&mut OsRng);
    let token_str = wires_cli::cmd::invite::run_to_string(
        dir.path(),
        &hex::encode(invitee.verifying_key().to_bytes()),
        &["home.notes".to_string()],
        &["read".to_string(), "write".to_string()],
    )
    .await
    .unwrap();

    let decoded = InviteToken::decode(&token_str).unwrap();
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.cap.agent, invitee.verifying_key().to_bytes());
    assert_eq!(decoded.peer_hints.len(), 1);
    assert_eq!(decoded.peer_hints[0].node_id.len(), 64);
    assert_eq!(
        decoded.service_discovery_url.as_deref(),
        Some("https://discovery.example/v1/bootstrap")
    );
}
```

(`Capability::agent` is the grantee field per `crates/wires-core/src/cap.rs:31`. There is no separate `grantor` field on `Capability` — the root pubkey is verified out-of-band via `Capability::verify(&root_pk)`.)

- [ ] **Step 2: Verify failure**

Run: `cargo test -p wires-cli --test cli_invite_emits_token`
Expected: FAIL — `wires_cli::cmd::invite::run_to_string` does not exist.

- [ ] **Step 3: Rewrite `invite.rs`**

Replace the contents of `crates/wires-cli/src/cmd/invite.rs` with:

```rust
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::InviteToken;
use wires_node::{Node, NodeConfig};

/// Build an `InviteToken` and return its base64 form. Used both by the
/// `wires invite` CLI subcommand and by integration tests.
pub async fn run_to_string(
    data_dir: &Path,
    agent_pubkey: &str,
    topics: &[String],
    rights: &[String],
) -> Result<String, Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let host = cfg
        .host
        .as_ref()
        .ok_or("no host paired — run `wires host pair --discovery-url <URL>` before issuing invites")?
        .clone();
    let node = Node::open(cfg)?;

    let root_bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    if root_bytes.len() != 32 {
        return Err("root.ed25519 must be 32 bytes".into());
    }
    let root = SigningKey::from_bytes(&root_bytes.try_into().unwrap());

    let agent_bytes = hex::decode(agent_pubkey)?;
    if agent_bytes.len() != 32 {
        return Err("agent_pubkey must be 32 bytes (64 hex chars)".into());
    }
    let mut agent_pk = [0u8; 32];
    agent_pk.copy_from_slice(&agent_bytes);

    let rights_parsed: Vec<Right> = rights
        .iter()
        .map(|r| match r.as_str() {
            "read" => Ok(Right::Read),
            "write" => Ok(Right::Write),
            other => Err(format!("unknown right '{other}'")),
        })
        .collect::<Result<_, _>>()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let mut cap = Capability::new_unsigned(agent_pk, topics.to_vec(), rights_parsed, now, None);
    cap.sign(&root)?;
    node.caps.upsert_grant(&cap)?;

    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let token = InviteToken {
        version: 1,
        cap,
        peer_hints: host.peer_hints,
        service_discovery_url: host.discovery_url,
        expires: now + 7 * 24 * 60 * 60 * 1000, // 7d default
        token_id: hex::encode(nonce_bytes),
    };
    Ok(token.encode()?)
}

/// CLI entry point: print the cap_id (for self-cap publish flows) and the
/// invite token to stdout.
pub async fn run(
    data_dir: &Path,
    agent_pubkey: &str,
    topics: &[String],
    rights: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let token_str = run_to_string(data_dir, agent_pubkey, topics, rights).await?;
    let token = wires_net::InviteToken::decode(&token_str)?;
    println!("Minted capability:");
    println!("  cap_id : {}", hex::encode(token.cap.cap_id.0));
    println!("  agent  : {agent_pubkey}");
    println!("  topics : {topics:?}");
    println!("  rights : {rights:?}");
    println!();
    println!("Invite token (share with the invitee):");
    println!("{token_str}");
    Ok(())
}
```

(Verify the `Capability::new_unsigned` signature in `crates/wires-core/src/cap.rs` and adjust field/argument names if needed. The constructor's argument order and field name for `grantee` are what they are in `wires-core`; the test must match.)

- [ ] **Step 4: Run the test**

Run: `cargo test -p wires-cli --test cli_invite_emits_token`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-cli/src/cmd/invite.rs crates/wires-cli/tests/cli_invite_emits_token.rs
git commit -m "wires-cli: invite emits InviteToken (base64), not bare cap_id"
```

---

### Task 15: `wires join <token>`

Decodes the token, installs the cap into `caps.redb`, and writes the inviter's `host.peer_hints` + `host.discovery_url` into the invitee's `config.toml`. Also persists epoch keys if the invitee provides them via stdin (out of scope here; mention as a TODO in the doc-comment only — epoch-key distribution is a separate spec item).

**Files:**
- Modify: `crates/wires-cli/src/cmd/join.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-cli/tests/cli_join_installs_cap.rs`:

```rust
//! `wires join <token>` should install the cap into caps.redb and copy the
//! peer hints into config.toml.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::{InviteToken, PeerHint};
use wires_node::{Node, NodeConfig};

#[tokio::test]
async fn join_installs_cap_and_host_info() {
    // Inviter side: synthesize an InviteToken.
    let root = SigningKey::generate(&mut OsRng);
    let invitee = SigningKey::generate(&mut OsRng);
    let topic_name = "home.notes".to_string();

    let mut cap = Capability::new_unsigned(
        invitee.verifying_key().to_bytes(),
        vec![topic_name.clone()],
        vec![Right::Read, Right::Write],
        0,
        None,
    );
    cap.sign(&root).unwrap();
    let token = InviteToken {
        version: 1,
        cap: cap.clone(),
        peer_hints: vec![PeerHint {
            node_id: "ab".repeat(32),
            addrs: vec!["127.0.0.1:11204".into()],
            relay: None,
        }],
        service_discovery_url: Some("https://discovery.example/v1/bootstrap".into()),
        expires: i64::MAX,
        token_id: "tok-0".into(),
    };
    let encoded = token.encode().unwrap();

    // Invitee side: bare `wires init --root <hex>` simulated (no root.ed25519).
    let invitee_dir = TempDir::new().unwrap();
    let cfg = NodeConfig {
        data_dir: invitee_dir.path().to_path_buf(),
        root_pubkey_hex: hex::encode(root.verifying_key().to_bytes()),
        host: None,
    };
    std::fs::write(
        invitee_dir.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    // Pre-create the agent identity so Node::open works.
    let _ = Node::open(cfg).unwrap();

    wires_cli::cmd::join::run(invitee_dir.path(), &encoded)
        .await
        .unwrap();

    // Verify cap landed in caps.redb.
    let cfg_after: NodeConfig = toml::from_str(
        &std::fs::read_to_string(invitee_dir.path().join("config.toml")).unwrap(),
    )
    .unwrap();
    let node = Node::open(cfg_after.clone()).unwrap();
    assert!(node.caps.get(&cap.cap_id.0).unwrap().is_some());

    // Verify host info was persisted.
    let h = cfg_after.host.expect("host should be set after join");
    assert_eq!(h.peer_hints.len(), 1);
    assert_eq!(
        h.discovery_url.as_deref(),
        Some("https://discovery.example/v1/bootstrap")
    );
}
```

(`CapTable::get` takes a `&CapId` which is `&[u8; 16]`. `cap.cap_id` is a `CapIdRepr` (newtype wrapping `CapId`); pass the inner field as `&cap.cap_id.0`.)

- [ ] **Step 2: Verify failure**

Run: `cargo test -p wires-cli --test cli_join_installs_cap`
Expected: FAIL — `join::run` is still a stub.

- [ ] **Step 3: Implement `join`**

Replace `crates/wires-cli/src/cmd/join.rs` contents with:

```rust
use std::path::Path;

use wires_net::InviteToken;
use wires_node::{HostConfig, Node, NodeConfig};

pub async fn run(data_dir: &Path, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg_path = data_dir.join("config.toml");
    let mut cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(&cfg_path)?)?;

    let parsed = InviteToken::decode(token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    if parsed.expires <= now {
        return Err("invite token is expired".into());
    }

    // Verify cap signature against the local root pubkey. If verification
    // fails, the invite was signed by a different household's root.
    let root_bytes = hex::decode(&cfg.root_pubkey_hex)?;
    if root_bytes.len() != 32 {
        return Err("local config root_pubkey_hex is not 32 bytes".into());
    }
    let mut root_pk = [0u8; 32];
    root_pk.copy_from_slice(&root_bytes);
    parsed
        .cap
        .verify(&root_pk)
        .map_err(|e| format!("invite cap does not verify against local root: {e}"))?;

    // Install into the cap table.
    let node = Node::open(cfg.clone())?;
    node.caps.upsert_grant(&parsed.cap)?;

    // Persist host hints into config.
    cfg.host = Some(HostConfig {
        peer_hints: parsed.peer_hints,
        discovery_url: parsed.service_discovery_url,
    });
    std::fs::write(&cfg_path, toml::to_string_pretty(&cfg)?)?;

    println!("Joined: cap {} installed; host info persisted.", hex::encode(parsed.cap.cap_id.0));
    if !parsed.cap.topics.is_empty() {
        println!(
            "Note: epoch keys for {} topic(s) are not in the invite token; obtain them out-of-band before publishing.",
            parsed.cap.topics.len()
        );
    }
    Ok(())
}
```

(Adjust field accesses to match the real `Capability` shape: `parsed.cap.root_pubkey` may be named `grantor` or similar; use the actual field name.)

- [ ] **Step 4: Run the test**

Run: `cargo test -p wires-cli --test cli_join_installs_cap`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-cli/src/cmd/join.rs crates/wires-cli/tests/cli_join_installs_cap.rs
git commit -m "wires-cli: wires join <token> installs cap + host info"
```

---

## Phase 6 — `wires-cli` publish/cat auto-dial

### Task 16: `wires publish` via NodeRuntime

Currently `publish` writes locally only. Auto-dial via NodeRuntime so the message reaches peers and the host.

**Files:**
- Modify: `crates/wires-cli/src/cmd/publish.rs`

- [ ] **Step 1: Write the failing integration test**

Create `crates/wires-cli/tests/cli_publish_auto_dials.rs`:

```rust
//! After `wires init` + `wires host pair`, `wires publish` should both
//! write locally AND broadcast over gossip. We assert the second half by
//! standing up a second NodeRuntime subscribed to the topic and seeing the
//! event come through.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_node::{NodeConfig, NodeRuntime};

#[tokio::test]
async fn publish_broadcasts_via_gossip() {
    let topic = [0x55u8; 32];
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());

    // ---- subscriber NodeRuntime ----------------------------------------
    let sub_tmp = TempDir::new().unwrap();
    let sub_cfg = NodeConfig {
        data_dir: sub_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        host: None,
    };
    let sub = NodeRuntime::open(sub_cfg).await.unwrap();
    sub.node.install_epoch_key(topic, 0, [0x99u8; 32]).unwrap();
    sub.join_topic(topic, vec![]).await.unwrap();
    let mut sub_events = sub.node.subscribe();

    // ---- publisher dir, init + host config pointing at the subscriber ---
    let pub_tmp = TempDir::new().unwrap();
    std::fs::write(pub_tmp.path().join("root.ed25519"), root.to_bytes()).unwrap();
    // Open Node so identity files exist.
    let pub_node = wires_node::Node::open(NodeConfig {
        data_dir: pub_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        host: None,
    })
    .unwrap();
    pub_node.install_epoch_key(topic, 0, [0x99u8; 32]).unwrap();
    let pub_pk = pub_node.ed_sk.verifying_key().to_bytes();
    let mut cap = Capability::new_unsigned(
        pub_pk,
        vec![hex::encode(topic)],
        vec![Right::Read, Right::Write],
        0,
        None,
    );
    cap.sign(&root).unwrap();
    pub_node.caps.upsert_grant(&cap).unwrap();
    sub.node.caps.upsert_grant(&cap).unwrap();
    let cfg = NodeConfig {
        data_dir: pub_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex,
        host: Some(wires_node::HostConfig {
            peer_hints: vec![wires_net::PeerHint {
                node_id: hex::encode(sub.endpoint.id().as_bytes()),
                addrs: vec![],
                relay: None,
            }],
            discovery_url: None,
        }),
    };
    std::fs::write(
        pub_tmp.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();

    drop(pub_node); // release the redb lock before re-opening via the CLI helper

    // Wait briefly for gossip mesh to converge.
    tokio::time::sleep(Duration::from_millis(300)).await;

    wires_cli::cmd::publish::run(
        pub_tmp.path(),
        &hex::encode(topic),
        &hex::encode(cap.cap_id.0),
        "agent.note",
        "hi from publish",
        None,
    )
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(5), sub_events.recv())
        .await
        .expect("event did not arrive")
        .unwrap();
    assert_eq!(event.topic_id, topic);
    let c = event.content.expect("decryption should succeed");
    assert_eq!(c.text, "hi from publish");
    let _ = Arc::new(sub); // keep subscriber alive
}
```

- [ ] **Step 2: Verify failure**

Run: `cargo test -p wires-cli --test cli_publish_auto_dials`
Expected: FAIL — current `publish::run` does not broadcast.

- [ ] **Step 3: Rewrite `publish.rs`**

Replace `crates/wires-cli/src/cmd/publish.rs` with:

```rust
use std::path::Path;

use wires_core::CanonicalContent;
use wires_node::{NodeConfig, NodeRuntime};

pub async fn run(
    data_dir: &Path,
    topic: &str,
    cap: &str,
    type_: &str,
    text: &str,
    data: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let bootstrap = bootstrap_endpoints(&cfg)?;
    let runtime = NodeRuntime::open(cfg).await?;
    let topic_id = resolve_topic(data_dir, topic)?;
    let cap_id = decode_hex_16(cap)?;

    runtime.join_topic(topic_id, bootstrap).await?;

    let mut content = CanonicalContent::new(type_, text);
    if let Some(d) = data {
        content = content.with_data(serde_json::from_str(d)?);
    }
    let msg = runtime.publish_and_broadcast(topic_id, cap_id, content).await?;
    println!(
        "published seq={} sender={} timestamp={}",
        msg.seq,
        hex::encode(msg.sender),
        msg.timestamp
    );
    // Give gossip a moment to drain before exiting.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Ok(())
}

pub fn resolve_topic(data_dir: &Path, topic: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if let Ok(bytes) = hex::decode(topic)
        && bytes.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let map_path = data_dir.join("topic_names.json");
    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(map_path)?)?;
    let hex_id = map
        .get(topic)
        .ok_or_else(|| format!("unknown topic '{topic}'"))?;
    let bytes = hex::decode(hex_id)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_16(s: &str) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 16 {
        return Err("cap_id must be 16 bytes (32 hex chars)".into());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build a bootstrap list of `EndpointId`s from the optional `HostConfig`,
/// silently skipping unparseable hints (the caller logs).
fn bootstrap_endpoints(cfg: &NodeConfig) -> Result<Vec<iroh::EndpointId>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    if let Some(h) = &cfg.host {
        for hint in &h.peer_hints {
            let bytes = match hex::decode(&hint.node_id) {
                Ok(b) if b.len() == 32 => b,
                _ => continue,
            };
            let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
            if let Ok(id) = iroh::EndpointId::from_bytes(&arr) {
                out.push(id);
            }
        }
    }
    Ok(out)
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p wires-cli --test cli_publish_auto_dials -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-cli/src/cmd/publish.rs crates/wires-cli/tests/cli_publish_auto_dials.rs
git commit -m "wires-cli: publish auto-dials via NodeRuntime + gossip broadcast"
```

---

### Task 17: `wires cat` via NodeRuntime

`cat` should: open runtime, replay from host if configured, then read local log, then (if `--tail`) subscribe and stream events forever.

**Files:**
- Modify: `crates/wires-cli/src/cmd/cat.rs`

No dedicated unit test for `cat` — it's a thin pipe over `NodeRuntime::join_topic` + `replay_from_host` + `TopicLog::read_all` + `Node::handle_inbound` + `Node::subscribe`, all of which are tested upstream. End-to-end coverage of cat's behavior lives in the acceptance test added in Task 19 (publish via gossip, host persists, second client cat-replays from host).

- [ ] **Step 1: Implement `cat` via NodeRuntime**

Replace the contents of `crates/wires-cli/src/cmd/cat.rs` with:

```rust
use std::path::Path;

use chrono::TimeZone;
use wires_node::{DecryptedEvent, Inbound, NodeConfig, NodeRuntime};

use crate::cmd::publish::resolve_topic;

pub async fn run(
    data_dir: &Path,
    topic: &str,
    tail: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let topic_id = resolve_topic(data_dir, topic)?;
    let bootstrap = crate::cmd::publish_helpers::bootstrap_endpoints(&cfg)?;
    let host_configured = cfg.host.is_some();

    let runtime = NodeRuntime::open(cfg).await?;
    runtime.join_topic(topic_id, bootstrap).await?;
    if host_configured {
        match runtime.replay_from_host(topic_id).await {
            Ok(n) => eprintln!("(replay catch-up: {n} envelopes from host)"),
            Err(e) => eprintln!("(replay catch-up skipped: {e})"),
        }
    }

    // Print everything currently in the local log.
    let log = runtime.node.logs.get_or_open(&topic_id)?;
    for msg in log.read_all()? {
        let outcome = runtime.node.handle_inbound(msg.clone())?;
        let content = match outcome {
            Inbound::Accepted { content, .. } => content,
            _ => None,
        };
        print_event(&DecryptedEvent {
            topic_id,
            msg,
            content,
        });
    }

    if !tail {
        return Ok(());
    }

    let mut sub = runtime.node.subscribe();
    while let Ok(ev) = sub.recv().await {
        if ev.topic_id == topic_id {
            print_event(&ev);
        }
    }
    Ok(())
}

fn print_event(ev: &DecryptedEvent) {
    let ts = chrono::Utc
        .timestamp_millis_opt(ev.msg.timestamp)
        .single()
        .unwrap_or_default();
    let sender_short = &hex::encode(ev.msg.sender)[..8];
    match &ev.content {
        Some(c) => println!(
            "{} {} {} | {} :: {}",
            ts.format("%Y-%m-%d %H:%M:%S%.3f"),
            sender_short,
            ev.msg.seq,
            c.type_,
            c.text
        ),
        None => println!(
            "{} {} {} | <opaque>",
            ts.format("%Y-%m-%d %H:%M:%S%.3f"),
            sender_short,
            ev.msg.seq
        ),
    }
}
```

The `crate::cmd::publish_helpers::bootstrap_endpoints` reference needs a tiny refactor — extract the helper from `publish.rs` into a new sibling `publish_helpers.rs`:

Create `crates/wires-cli/src/cmd/publish_helpers.rs`:

```rust
use wires_node::NodeConfig;

pub fn bootstrap_endpoints(
    cfg: &NodeConfig,
) -> Result<Vec<iroh::EndpointId>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    if let Some(h) = &cfg.host {
        for hint in &h.peer_hints {
            let bytes = match hex::decode(&hint.node_id) {
                Ok(b) if b.len() == 32 => b,
                _ => continue,
            };
            let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
            if let Ok(id) = iroh::EndpointId::from_bytes(&arr) {
                out.push(id);
            }
        }
    }
    Ok(out)
}
```

Update `crates/wires-cli/src/cmd/publish.rs` to use it: replace the local `fn bootstrap_endpoints(...)` definition with `use crate::cmd::publish_helpers::bootstrap_endpoints;` at the top of the file (and delete the duplicated body).

Register the new module in `crates/wires-cli/src/cmd/mod.rs`:

```rust
pub mod publish_helpers;
```

- [ ] **Step 2: Build to confirm nothing's broken**

Run: `cargo build -p wires-cli`
Expected: build succeeds.

Run: `cargo test -p wires-cli`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-cli/src/cmd/cat.rs crates/wires-cli/src/cmd/publish.rs \
        crates/wires-cli/src/cmd/publish_helpers.rs crates/wires-cli/src/cmd/mod.rs
git commit -m "wires-cli: cat auto-dials, replays from host before printing"
```

---

## Phase 7 — `wires-ha` host-aware startup

### Task 18: `wires-ha` auto-registers its topic with the host

If the agent's config has a `HostConfig`, `wires-ha` should send a `TopicRegisterRequest` for its target topic at startup before publishing. Errors are non-fatal (peer-to-peer keeps working) but tracing-warned.

**Files:**
- Modify: `crates/wires-ha/src/main.rs`

- [ ] **Step 1: Add a call site**

After `tracing::info!(%endpoint_id, "wires-ha endpoint bound");` and before `NetGlue::new(...)`, insert:

```rust
    // If this agent is paired with a host, register the target topic so the
    // host actually persists what we publish.
    if let Some(host) = cfg.host.as_ref() {
        if let Some(first) = host.peer_hints.first() {
            match register_topic_best_effort(&endpoint, first, &topic_id).await {
                Ok(()) => tracing::info!(topic = %hex::encode(topic_id), "host topic-register OK"),
                Err(e) => tracing::warn!(error = %e, "host topic-register failed; continuing peer-to-peer"),
            }
        }
    }
```

(Place `let cfg` earlier — the existing flow already reads `cfg` from config.toml.)

Add the helper function at the bottom of `crates/wires-ha/src/main.rs`:

```rust
async fn register_topic_best_effort(
    endpoint: &Endpoint,
    hint: &wires_net::PeerHint,
    topic_id: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(&hint.node_id)?;
    if bytes.len() != 32 {
        return Err("host node_id not 32-byte hex".into());
    }
    let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
    let host_eid = iroh::EndpointId::from_bytes(&arr)?;

    // Read root key from the agent's data dir (same convention as the CLI).
    // Note: wires-ha is normally run by an agent the root holder has already
    // paired and onboarded, so root.ed25519 is present.
    // Skip if absent (a non-root agent still works peer-to-peer).
    let root_path = std::path::PathBuf::from(std::env::var("WIRES_HA_DATA_DIR").unwrap_or_default());
    let root_bytes = std::fs::read(root_path.join("root.ed25519"))?;
    if root_bytes.len() != 32 {
        return Err("root.ed25519 must be 32 bytes".into());
    }
    let root = ed25519_dalek::SigningKey::from_bytes(&root_bytes.try_into().unwrap());
    let client = wires_net::tenant::TenantClient::new(endpoint.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let resp = client
        .register_topic(host_eid, &root, topic_id, &arr, now)
        .await?;
    match resp {
        wires_net::tenant::TenantResponse::TopicRegister(r) if r.ok => Ok(()),
        other => Err(format!("host responded: {other:?}").into()),
    }
}
```

Reading `WIRES_HA_DATA_DIR` is a stopgap — pass `args.data_dir` directly. Simpler version: change the helper to take `data_dir: &Path` and pass it from the caller. Update both the call site and helper signature accordingly. (Keep this clean — env-var fishing is a smell.)

Final shape:

```rust
async fn register_topic_best_effort(
    endpoint: &Endpoint,
    hint: &wires_net::PeerHint,
    topic_id: &[u8; 32],
    data_dir: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(&hint.node_id)?;
    if bytes.len() != 32 {
        return Err("host node_id not 32-byte hex".into());
    }
    let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
    let host_eid = iroh::EndpointId::from_bytes(&arr)?;
    let root_bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    if root_bytes.len() != 32 {
        return Err("root.ed25519 must be 32 bytes".into());
    }
    let root = ed25519_dalek::SigningKey::from_bytes(&root_bytes.try_into().unwrap());
    let client = wires_net::tenant::TenantClient::new(endpoint.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let resp = client
        .register_topic(host_eid, &root, topic_id, &arr, now)
        .await?;
    match resp {
        wires_net::tenant::TenantResponse::TopicRegister(r) if r.ok => Ok(()),
        other => Err(format!("host responded: {other:?}").into()),
    }
}
```

And the call site:

```rust
            match register_topic_best_effort(&endpoint, first, &topic_id, &args.data_dir).await {
```

- [ ] **Step 2: Build the crate**

Run: `cargo build -p wires-ha`
Expected: build succeeds.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-ha/src/main.rs
git commit -m "wires-ha: register topic with host at startup when configured"
```

---

## Phase 8 — Acceptance + docs

### Task 19: End-to-end acceptance — two CLI clients share one host

Implements §11 acceptance #1 from the hosted-service spec.

**Files:**
- Modify: `crates/wires-host/tests/acceptance.rs`

- [ ] **Step 1: Add the new acceptance test**

Append to `crates/wires-host/tests/acceptance.rs`:

```rust
//! Acceptance #1: two distinct tenants (representing two CLI agents under
//! two different roots) on one host process. Each registers their own topic.
//! Each publishes via gossip. The host persists each into the correct
//! per-tenant directory. No cross-tenant content leakage.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey as DalekSk;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use tempfile::TempDir;
use tokio::sync::mpsc;
use wires_core::WireMessage;
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::routing::{Router as MsgRouter, WriteRateLimiter};
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantClient, TenantProtocol, TenantResponse};
use wires_net::{GossipNode, ALPN as REPLAY_ALPN};

#[tokio::test]
#[ignore]
async fn two_tenants_share_one_host_no_leakage() {
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000));
    let router_state = Arc::new(MsgRouter::new(
        Arc::clone(&registry),
        Arc::clone(&logs),
        Arc::clone(&retention),
        Arc::clone(&rate),
    ));

    // Host endpoint with the same ALPN set the production main.rs uses.
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![TENANT_ALPN.to_vec(), REPLAY_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let host_eid_bytes: [u8; 32] = host_ep.id().as_bytes().to_owned();

    // Gossip on the host + dynamic subscribe.
    let gossip = GossipNode::new(host_ep.clone()).await.unwrap();
    let (subscribe_tx, mut subscribe_rx) = mpsc::unbounded_channel::<[u8; 32]>();
    let gossip_clone = gossip.clone_for_subscribe();
    {
        let router_state = Arc::clone(&router_state);
        tokio::spawn(async move {
            while let Some(topic_id) = subscribe_rx.recv().await {
                let Ok((_h, mut rx)) = gossip_clone.join(topic_id, vec![]).await else { continue };
                let router_state = Arc::clone(&router_state);
                tokio::spawn(async move {
                    while let Some(bytes) = rx.recv().await {
                        let Ok(msg): Result<WireMessage, _> = serde_json::from_slice(&bytes) else { continue };
                        if wires_core::verify_envelope(&msg).is_err() {
                            continue;
                        }
                        let _ = router_state.route(&msg);
                    }
                });
            }
        });
    }

    // Tenant handler with the matching subscribe hook.
    let subscribe_tx_for_handler = subscribe_tx.clone();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention: Arc::clone(&retention),
        host_endpoint_id: host_eid_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
        }),
        on_topic_registered: Arc::new(move |_root, topic| {
            let _ = subscribe_tx_for_handler.send(topic);
        }),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _proto_router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // Two tenants: distinct roots, distinct topic ids.
    let root_a = DalekSk::generate(&mut rand_core::OsRng);
    let root_b = DalekSk::generate(&mut rand_core::OsRng);
    let topic_a = [0xAAu8; 32];
    let topic_b = [0xBBu8; 32];

    let now = || {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
    };
    // Tenant A registers.
    let caller_ep_a = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .bind()
        .await
        .unwrap();
    let client_a = TenantClient::new(caller_ep_a.clone());
    let r = client_a
        .register_tenant(host_ep.id(), &root_a, &host_eid_bytes, now())
        .await
        .unwrap();
    assert!(matches!(r, TenantResponse::Register(_)));
    let r = client_a
        .register_topic(host_ep.id(), &root_a, &topic_a, &host_eid_bytes, now())
        .await
        .unwrap();
    assert!(matches!(r, TenantResponse::TopicRegister(_)));

    // Tenant B registers.
    let caller_ep_b = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .bind()
        .await
        .unwrap();
    let client_b = TenantClient::new(caller_ep_b.clone());
    let _ = client_b
        .register_tenant(host_ep.id(), &root_b, &host_eid_bytes, now())
        .await
        .unwrap();
    let _ = client_b
        .register_topic(host_ep.id(), &root_b, &topic_b, &host_eid_bytes, now())
        .await
        .unwrap();

    // Open per-publisher gossip from each caller, joining the host as bootstrap.
    let gossip_a = GossipNode::new(caller_ep_a.clone()).await.unwrap();
    let gossip_b = GossipNode::new(caller_ep_b.clone()).await.unwrap();
    let (handle_a, _rx_a) = gossip_a
        .join(topic_a, vec![host_ep.id()])
        .await
        .unwrap();
    let (handle_b, _rx_b) = gossip_b
        .join(topic_b, vec![host_ep.id()])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Manufacture and broadcast a Standard envelope on each side (signed by
    // a freshly-generated cap holder for simplicity: re-use the root as the
    // sender for this single test).
    fn mk_envelope(
        topic: [u8; 32],
        sender_sk: &DalekSk,
        seq: u64,
        epoch_key: &[u8; 32],
    ) -> WireMessage {
        use wires_core::{CanonicalContent, MessageKind};
        let mut msg = WireMessage {
            topic_id: topic,
            epoch: 0,
            kind: MessageKind::Standard,
            sender: sender_sk.verifying_key().to_bytes(),
            cap_id: [0u8; 16],
            seq,
            prev_hash: [0u8; 32],
            timestamp: seq as i64 * 1000,
            payload_len: 0,
            signature: [0u8; 64],
            ciphertext: vec![],
        };
        // We're testing routing/persistence — not encryption — so we sign the
        // envelope over the canonical bytes and let the host's verify_envelope
        // succeed. Ciphertext stays empty.
        let _ = epoch_key;
        let bytes = msg.signing_bytes().expect("signing_bytes");
        use ed25519_dalek::Signer as _;
        msg.signature = sender_sk.sign(&bytes).to_bytes();
        msg
    }
    let msg_a = mk_envelope(topic_a, &root_a, 1, &[1u8; 32]);
    let msg_b = mk_envelope(topic_b, &root_b, 1, &[2u8; 32]);
    handle_a.broadcast(serde_json::to_vec(&msg_a).unwrap()).await.unwrap();
    handle_b.broadcast(serde_json::to_vec(&msg_b).unwrap()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Assert: on-disk per-tenant directories contain only their own log.
    let dir_a = host_tmp.path().join("tenants").join(hex::encode(root_a.verifying_key().to_bytes()));
    let dir_b = host_tmp.path().join("tenants").join(hex::encode(root_b.verifying_key().to_bytes()));
    let entries_a: Vec<_> = std::fs::read_dir(&dir_a).unwrap().flatten().collect();
    let entries_b: Vec<_> = std::fs::read_dir(&dir_b).unwrap().flatten().collect();
    let names_a: Vec<String> = entries_a.iter().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    let names_b: Vec<String> = entries_b.iter().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names_a.iter().any(|n| n.contains(&hex::encode(topic_a))), "{names_a:?}");
    assert!(names_b.iter().any(|n| n.contains(&hex::encode(topic_b))), "{names_b:?}");
    assert!(!names_a.iter().any(|n| n.contains(&hex::encode(topic_b))));
    assert!(!names_b.iter().any(|n| n.contains(&hex::encode(topic_a))));
}
```

(Signing uses `WireMessage::signing_bytes(&self) -> Result<Vec<u8>, CoreError>`. The closure constructs a `MessageKind::Standard` envelope with empty ciphertext — that's enough for the host's `verify_envelope` to succeed because the AAD/signature contract zeros `ciphertext` + `signature` + `payload_len` per CLAUDE.md invariant #1.)

- [ ] **Step 2: Run the new acceptance test**

Run: `cargo test -p wires-host --test acceptance two_tenants_share_one_host_no_leakage -- --ignored`
Expected: PASS within ~5 seconds.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/tests/acceptance.rs
git commit -m "wires-host: acceptance #1 — two tenants share one host (spec §11)"
```

---

### Task 20: Rewrite README around the hosted flow — multi-tab POC walkthrough

After the CLI changes land, the README's two-agents-on-one-machine quick-start is wrong (it uses long-gone shapes). Replace it with a comprehensive multi-terminal walkthrough that lets a developer observe the system end-to-end on their own machine: host setup, tenant pairing, topic registration, agent join, publish/tail, host status, and an explicit "observe the system" section showing where files land and what to look at.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the whole README body from `## Build` through `## Layout` inclusive**

Open `README.md`. Keep lines 1–12 (title, tagline, status paragraph) verbatim. Replace everything from `## Build` through the end of the `## Layout` section (i.e. everything up to but not including `## License`) with the following content. Leave the title block and the License section untouched.

````markdown
## Build

Requires stable Rust (tested on 1.95).

```bash
cargo build --release
```

Three binaries land in `target/release/`:

- **`wires`** — the agent/human CLI. One data directory per agent.
- **`wires-host`** — a multi-tenant blind relay/replay server. Holds no keys; persists ciphertext only for tenants and topics that have registered via the tenant control protocol.
- **`wires-ha`** — Home Assistant ingestion daemon. Subscribes to a HA WebSocket and publishes `state_changed` events onto a configured wires topic.

For the walkthrough below it's convenient to also `cargo install --path crates/wires-cli` and `cargo install --path crates/wires-host` so `wires` and `wires-host` are on your `$PATH`.

## Concepts in one paragraph each

- **Identity.** Every agent has an Ed25519 signing key and an X25519 secret. The root key for a household is a separate Ed25519 keypair held by the operator; capabilities are signed by it. `wires init` generates the agent identity; with no `--root` it also generates a local root key.
- **Capability.** A signed grant of `read` and/or `write` on a topic to a specific agent pubkey. Capabilities are the only way to publish, and they live in each agent's `caps.redb`.
- **Topic.** A 32-byte id with a per-epoch symmetric key. Messages on a topic are encrypted under the current epoch key. Topic names (e.g. `home.notes`) are a CLI-side convenience that maps to a random id at creation time.
- **Host.** A `wires-host` process is a blind multi-tenant relay: it persists ciphertext per tenant, serves replay, and routes by `topic_id → tenant`. It cannot decrypt anything.
- **Tenant.** A household paired with a host. Created via the `/wires/tenant/0` ALPN, signed by the root key. One tenant per root pubkey per host.

## Quick start: a local proof-of-concept in four terminals

This walks through running the full system on one machine. Open four terminal tabs. We use four data directories: `./host`, `./alice`, `./bob`, and (for observation) the host's data dir again.

### Tab 1 — `wires-host`

```bash
mkdir -p ./host
wires-host --data-dir ./host
# → wires-host: EndpointId = <HOST_ID>
# → wires-host: discovery listening at 0.0.0.0:8443 (public=http://0.0.0.0:8443)
# → wires-host: running. Press Ctrl-C to exit.
```

Leave it running for the rest of the walkthrough. Set `RUST_LOG=info` (or `debug`) before the command if you want to see routing decisions in real time.

### Tab 2 — Alice, the operator

Alice is the root-key holder for this household.

```bash
# 1. Initialize Alice's data dir. Generates a local root + agent identity.
wires --data-dir ./alice init
# → Generated local root pubkey: <ROOT_HEX>
# → Initialized at ./alice
# → Root pubkey: <ROOT_HEX>

# 2. Pair Alice's root with the host. Signs a TenantRegisterRequest with
#    ./alice/root.ed25519, dials the host at the EndpointId returned by
#    discovery, persists host info into ./alice/config.toml.
wires --data-dir ./alice host pair \
  --discovery-url http://127.0.0.1:8443/v1/bootstrap
# → Paired with host <HOST_ID> (server_time=<MILLIS>)
# → Host info persisted to ./alice/config.toml

# 3. Create a topic on Alice's side. Prints a 64-char topic id and the
#    epoch key (you'll share this manually with Bob — auto-distribution is
#    a future spec item).
wires --data-dir ./alice topic create home.notes
# → Created topic 'home.notes' with id <TOPIC_HEX>
# → Note: share epoch key <EPOCH_HEX> with peers manually.

# 4. Register the topic with the host so the host persists envelopes for it.
wires --data-dir ./alice host topic-register home.notes
# → Registered topic <TOPIC_HEX>

# 5. Check what the host reports for this tenant.
wires --data-dir ./alice host status
# → Tenant status (as reported by host):
# →   registered_at         : <MILLIS>
# →   topic_count           : 1
# →   bytes_stored          : 0
# →   retention_budget      : 1073741824
# →   write_rate_limit_per_sec : 1000
# →   status                : Active
```

### Tab 3 — Bob, an invited agent

Bob is a second agent under the same household. He shares Alice's root pubkey but has his own agent identity.

```bash
# 1. Initialize Bob, pinning him to Alice's root pubkey. No root.ed25519
#    is created; Bob cannot mint caps or pair with a host, only operate
#    under caps Alice grants him.
wires --data-dir ./bob init --root <ROOT_HEX>
# → Initialized at ./bob
# → Root pubkey: <ROOT_HEX>

# 2. Look up Bob's agent pubkey — Alice needs it to mint his invite.
wires --data-dir ./bob status
# → agent pubkey : <BOB_AGENT_HEX>
# → ...
```

### Tab 2 again — Alice mints invites

```bash
# 6. Mint an invite for Bob: cap + the host info Alice is paired with,
#    bundled into an InviteToken (base64).
wires --data-dir ./alice invite \
  --agent-pubkey <BOB_AGENT_HEX> \
  --topics home.notes \
  --rights read,write
# → Invite token (share with the invitee):
# → <BOB_TOKEN>

# 7. Also mint a self-cap so Alice can publish (the root pubkey is not an
#    automatic publisher; she still needs a cap pointing at her agent pk).
wires --data-dir ./alice status     # → "agent pubkey : <ALICE_AGENT_HEX>"
wires --data-dir ./alice invite \
  --agent-pubkey <ALICE_AGENT_HEX> \
  --topics home.notes \
  --rights read,write
# → Minted capability:
# →   cap_id : <ALICE_CAP_HEX>
# →   agent  : <ALICE_AGENT_HEX>
# →   topics : ["home.notes"]
# →   rights : ["read", "write"]
# →
# → Invite token (share with the invitee):
# → <ALICE_TOKEN>
#
# Note: `wires invite` always mints AND installs the cap into the inviter's
# caps.redb, so Alice doesn't need to `wires join` her own self-cap — she
# just uses <ALICE_CAP_HEX> directly in `wires publish` below.
```

### Tab 3 again — Bob joins and reads

```bash
# 3. Bob joins his invite token. Installs the cap into ./bob/caps.redb and
#    copies Alice's host info into ./bob/config.toml.
wires --data-dir ./bob join <BOB_TOKEN>
# → Joined: cap <BOB_CAP_HEX> installed; host info persisted.
# → Note: epoch keys for 1 topic(s) are not in the invite token; obtain
# →       them out-of-band before publishing.

# 4. Manual step (v1 only): copy the topic id + epoch key from Tab 2 step 3
#    into Bob's data dir. The simplest local hack is to copy the topic name
#    map and the epoch-key db file from Alice — they're keyed by topic_id:
cp ./alice/topic_names.json ./bob/topic_names.json
cp ./alice/keys_<TOPIC_HEX>.redb ./bob/keys_<TOPIC_HEX>.redb

# 5. Bob tails the topic. cat first replays any history the host has, then
#    streams live events from gossip.
wires --data-dir ./bob cat home.notes --tail
# → (replay catch-up: N envelopes from host)
# → [waits for live events]
```

### Tab 2 again — Alice publishes

```bash
# 8. Alice publishes. publish auto-dials the host (because config.toml has
#    `host`), broadcasts over gossip, and writes locally.
wires --data-dir ./alice publish \
  --topic home.notes \
  --cap <ALICE_CAP_HEX> \
  --type agent.note \
  "hello from alice"
# → published seq=0 sender=<ALICE_AGENT_HEX> timestamp=<MILLIS>
```

Within a second or two Bob's `cat --tail` in Tab 3 should print the message:

```
2026-05-14 23:42:01.234 <ALICE_AGENT_HEX_PREFIX> 0 | agent.note :: hello from alice
```

## Observing the system

### Where files live

```bash
ls ./host
# iroh.secret  tenants.redb  topic_index.redb  nonces.redb  tenants/

ls ./host/tenants
# <root_pubkey_hex>/        ← one directory per registered tenant

ls ./host/tenants/<ROOT_HEX>
# log_<TOPIC_HEX>.redb      ← per-topic ciphertext log
# ingest_<ROOT_HEX>.redb    ← per-tenant FIFO eviction index
```

The host has zero per-tenant secrets — no caps, no epoch keys. Verify with `ls`: you'll see only the four host-level redb files plus a per-tenant subdir of opaque ciphertext logs. The host literally cannot decrypt the content.

### Tenant status from the operator's side

```bash
wires --data-dir ./alice host status
```

Re-run after publishing a few messages — `bytes_stored` will grow, `topic_count` reflects registered topics, and `oldest_retained_at` advances forward as the retention budget evicts.

### Inspect on-disk per-tenant size

```bash
du -h ./host/tenants/<ROOT_HEX>
```

This is what a hosted-service operator would graph per tenant.

## Resilience: kill the host and watch replay catch up

1. In Tab 2, publish several more messages over a few seconds.
2. In Tab 1, `Ctrl-C` the host.
3. In Tab 2, publish a few more — these go peer-to-peer (Alice + Bob still see each other via gossip) but are NOT persisted by the host because it's down.
4. Restart Tab 1: `wires-host --data-dir ./host`. The host reloads its tenants.redb and topic_index.redb, re-subscribes to every previously-registered topic.
5. In a fresh Tab 4, run a "cold" Bob — copy `./bob` to `./bob2`, then `wires --data-dir ./bob2 cat home.notes`. The replay client pulls every message the host retains, and Bob2 sees everything published while the host was alive. Messages published while the host was down are visible to live Bob (via gossip) but not to cold Bob2 (because they were never persisted) — exactly the substrate's hash-chained "gap detection" property.

## Other useful commands

```bash
wires --data-dir ./alice host topic-unregister home.notes  # host stops persisting new envelopes
wires --data-dir ./alice revoke <CAP_HEX>                  # tomb a cap (substrate v1 — no gossip propagation yet)
wires --data-dir ./alice cat home.notes                    # no --tail: print local log and exit
```

## Networking notes

- Transport is [iroh](https://www.iroh.computer) (`0.98`). Discovery uses iroh's N0 preset by default.
- Gossip runs over iroh-gossip on the topic id directly.
- Replay (catching up after downtime) uses a custom QUIC stream on ALPN `/wires/replay/0`.
- Tenant control (registration + topic register/unregister + status) uses ALPN `/wires/tenant/0` with length-prefixed JSON frames.
- Service discovery is plain HTTPS at `GET /v1/bootstrap`, returning a list of host endpoints. Self-hosting operators can serve a static JSON file; the host serves its own by default (HTTP only — production wants a TLS terminator in front).

## Layout

```
crates/
  wires-core    pure types (WireMessage, Capability, content, sign/verify)
  wires-crypto  AEAD (chacha20-poly1305), sealed-box (x25519), public envelopes
  wires-store   redb-backed hash-chained logs, cap table, epoch keys, ingest index
  wires-net     iroh gossip + replay protocol + tenant control protocol + invite tokens + discovery
  wires-node    Node runtime (publish, inbound, sync, NetGlue, NodeRuntime)
  wires-cli     `wires` binary
  wires-host    `wires-host` multi-tenant relay (lib + bin: tenant registry, retention, routing, http discovery)
  wires-ha      `wires-ha` Home Assistant ingestion daemon
docs/superpowers/
  specs/        design docs (substrate, hosted-service, iOS companion)
  plans/        implementation plans
```
````

- [ ] **Step 2: Verify the README renders sensibly**

This is a docs change — no compile target — so verification is by reading. Render the README locally (any markdown viewer; GitHub-flavored is the target) and walk through the headings: Build, Concepts, Quick start (4 sub-sections, one per tab), Observing the system, Resilience demo, Other commands, Networking notes, Layout.

Confirm:
- Every `wires` command listed matches the CLI surface implemented in Tasks 11–17 (e.g. `wires host pair --discovery-url`, `wires host topic-register`, `wires invite ...`, `wires join <token>`, `wires publish ...`, `wires cat ...`).
- No reference to `--topic <hex>` on `wires-host` (it was removed pre-merge).
- No reference to `bootstrap_peers` (removed in Task 1).
- The `jq -r '.cap.cap_id'` snippet matches the `InviteToken` JSON shape from `wires-net::invite::InviteToken` (`cap.cap_id` is the base64-then-JSON path).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "README: multi-tab POC walkthrough for the hosted flow"
```

---

### Task 21: Refresh `CLAUDE.md` data-dir layout

`config.toml` now contains a `[host]` section. Capture that in the notes.

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLI agent data-dir block**

In `CLAUDE.md`, replace the CLI agent data-dir block with:

```
config.toml             NodeConfig (root_pubkey_hex, data_dir, optional host)
identity.ed25519        agent signing key (32 bytes raw)
identity.x25519         agent x25519 secret (32 bytes raw)
iroh.secret             iroh node secret (created on first NodeRuntime::open)
root.ed25519            local root key (only when `wires init` generated it)
topic_names.json        name → 32-byte topic_id map (CLI-side convenience)
caps.redb               CapTable
log_<topic-hex>.redb    per-topic hash-chained ciphertext log
keys_<topic-hex>.redb   per-topic epoch keys
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "CLAUDE.md: capture iroh.secret + host in CLI data-dir layout"
```

---

### Task 22: Workspace build + clippy + fmt + test

Final whole-workspace pass.

**Files:**
- None (verification only).

- [ ] **Step 1: Build everything**

Run: `cargo build --workspace`
Expected: clean build.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings. Fix any (most likely: unused imports introduced when rewriting `publish.rs` / `cat.rs`).

- [ ] **Step 3: Format**

Run: `cargo fmt --all`
Expected: no diff. If there is one, commit it as a separate `chore: cargo fmt` commit per the established pattern.

- [ ] **Step 4: Workspace tests (fast)**

Run: `cargo test --workspace`
Expected: PASS. Test count should grow by roughly:
- `wires-net`: +4 (discovery, peer_hint, tenant register/topic helpers)
- `wires-node`: +2 unit (config tests) + 1 integration (`runtime_publish_subscribes`)
- `wires-cli`: +4 integration (`cli_host_pair`, `cli_host_topic_register`, `cli_invite_emits_token`, `cli_join_installs_cap`).

- [ ] **Step 5: Acceptance pass**

Run: `cargo test --workspace -- --ignored`
Expected: PASS. New count: previous 7 + 1 new (`two_tenants_share_one_host_no_leakage`) = 8 ignored-acceptance tests.

- [ ] **Step 6: Commit any clippy/fmt cleanups**

```bash
git status
# Stage any fix-up edits, then:
git commit -m "chore: clippy + fmt"
```

---

## Out of scope (left for follow-up specs)

- iOS companion app revisions (the iOS spec is still stale — handled separately).
- `__cap.grant` gossip propagation (carrying caps over `__caps` topic rather than out-of-band invite tokens).
- `__topic.epoch_advance` distribution.
- Hosted-side admin tooling (tenant suspension UI, retention budget overrides).
- TLS for the discovery endpoint (currently HTTP-only by default; production needs a terminator).
- A `wires daemon` long-running mode (today `publish` short-circuits after a brief gossip drain; OK for the demo flows the user wants, less great for high-throughput agents).
- **Replace `wires publish`'s 500ms pre-broadcast sleep** (`crates/wires-cli/src/cmd/publish.rs`) with event-driven gossip-mesh readiness. The current timing-based wait works for the local POC but bakes a fixed latency into every CLI publish and risks flake under load. Right fix: a `joined()`-style helper on `GossipHandle` / `GossipTopic` (iroh-gossip 0.98 exposes a neighbor-up event stream) that returns once at least one peer is up. Affects publish; cat may benefit too.
- **iroh n0-preset endpoint cold-start latency.** Multiple integration tests during this plan hit transient cold-start failures (peer_hint discovery, cli_host_pair, others) that pass on retry. The pattern is that pkarr/DNS lookups for a brand-new endpoint take 5–30s. Mitigations in this branch: tests use `MemoryLookup` cross-registration and 10s `endpoint.online()` timeouts. Future work: investigate iroh's `pkarr` cache priming or `Endpoint::warm_up()` to bring this under control before any production deploy.
- **`wires-ha` requires `root.ed25519` on disk to do its best-effort `register_topic`.** This expands the daemon's blast radius (it's custodian of the household root, not just an agent identity). Replace with either operator-side pre-registration (`wires host topic-register` from a one-shot CLI invocation at deploy time) or pre-signed register blobs in config.
- **InviteToken does not bundle topic_names.json entries.** An invitee `wires join`s the token, but to `wires cat home.notes` they need a `topic_names.json` map. Today it's an out-of-band copy step (documented in README). Right fix: include the name→topic_id map in the token (small, additive change to `InviteToken`).
