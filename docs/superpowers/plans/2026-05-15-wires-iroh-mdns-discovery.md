# wires — local mDNS discovery for iroh endpoints — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add iroh's mDNS-based local discovery as a parallel address-lookup service on every on-LAN binary (CLI agents, `wires-ha`, all `wires-cli` dial commands) while leaving `wires-host` mDNS-free. Consolidate the six existing endpoint-bind call sites behind two named helpers in `wires-net::endpoint`.

**Architecture:** A new `wires-net::endpoint` module exposes `bind_lan` (LAN-co-located processes; enables `MdnsAddressLookup`) and `bind_cloud` (cloud infra; n0 pkarr/DNS only). A workspace-default `mdns` Cargo feature on `wires-net` propagates `iroh/address-lookup-mdns`; when disabled, the two helpers become identical and `swarm-discovery` drops from the dep graph. Three new `NetError` variants take iroh's concrete error types directly — no anyhow propagation.

**Tech Stack:** Rust edition 2024, iroh 0.98 (`address-lookup-mdns` feature → `swarm-discovery` 0.6.0-alpha.2), snafu errors, tokio runtime. Reference spec: `docs/superpowers/specs/2026-05-15-wires-iroh-mdns-discovery-design.md`.

---

## File map

**Created:**
- `crates/wires-net/src/endpoint.rs` — `bind_lan` + `bind_cloud` helpers
- `crates/wires-net/tests/bind_helpers.rs` — smoke tests for both helpers

**Modified:**
- `crates/wires-net/Cargo.toml` — add `[features]` block with `mdns` feature
- `crates/wires-net/src/error.rs` — add `EndpointBind` + two feature-gated variants
- `crates/wires-net/src/lib.rs` — declare module, re-export helpers
- `crates/wires-node/src/runtime.rs` — call `bind_lan`
- `crates/wires-host/src/main.rs` — call `bind_cloud`
- `crates/wires-ha/src/main.rs` — call `bind_lan`
- `crates/wires-cli/src/cmd/pair_listen.rs` — call `bind_lan`
- `crates/wires-cli/src/cmd/pair_approve.rs` — call `bind_lan`
- `crates/wires-cli/src/cmd/host.rs` — call `bind_lan`
- `CLAUDE.md` — update `wires-net` crate-layout row + cold-start note

**Unchanged (tests retain raw `Endpoint::builder` paths for determinism):**
- `crates/wires-net/tests/pair_protocol.rs`
- `crates/wires-net/src/peer_hint.rs` test module
- `crates/wires-net/src/tenant.rs` test module
- `crates/wires-cli/tests/cli_host_pair.rs`
- `crates/wires-cli/tests/cli_host_topic_register.rs`

---

### Task 1: Add the `mdns` Cargo feature to wires-net

**Files:**
- Modify: `crates/wires-net/Cargo.toml`

- [ ] **Step 1: Add the `[features]` block**

Insert the following two lines below the `[dev-dependencies]` section in `crates/wires-net/Cargo.toml` (creating a new `[features]` section):

```toml
[features]
default = ["mdns"]
mdns = ["iroh/address-lookup-mdns"]
```

The full additions, in context, append to the end of the file:

```toml
[dev-dependencies]
tempfile      = { workspace = true }
axum          = { version = "0.8", features = ["json"] }

[features]
default = ["mdns"]
mdns = ["iroh/address-lookup-mdns"]
```

- [ ] **Step 2: Verify the feature compiles with defaults**

Run: `cargo build -p wires-net`
Expected: clean build. `swarm-discovery` (0.6.0-alpha.2) is now in the dep graph.

- [ ] **Step 3: Verify the feature compiles without it**

Run: `cargo build -p wires-net --no-default-features`
Expected: clean build. `swarm-discovery` is NOT pulled in.

Verify with: `cargo tree -p wires-net --no-default-features | grep swarm-discovery`
Expected: empty output.

And: `cargo tree -p wires-net | grep swarm-discovery`
Expected: one line showing `swarm-discovery v0.6.0-alpha.2`.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-net/Cargo.toml
git commit -m "feat(wires-net): add mdns Cargo feature for iroh local discovery"
```

---

### Task 2: Add three new NetError variants

**Files:**
- Modify: `crates/wires-net/src/error.rs`

- [ ] **Step 1: Add the three new variants**

Open `crates/wires-net/src/error.rs`. The file currently defines `pub enum NetError` with several variants. Add these three new variants at the end of the enum, immediately before the closing brace (right after the last existing variant):

```rust
    #[snafu(display("iroh endpoint bind failed: {source}, at {location}"))]
    EndpointBind {
        source: iroh::endpoint::BindError,
        #[snafu(implicit)]
        location: Location,
    },
    #[cfg(feature = "mdns")]
    #[snafu(display("mDNS address-lookup setup failed: {source}, at {location}"))]
    MdnsSetup {
        source: iroh::address_lookup::AddressLookupBuilderError,
        #[snafu(implicit)]
        location: Location,
    },
    #[cfg(feature = "mdns")]
    #[snafu(display("endpoint address-lookup registry unavailable: {source}, at {location}"))]
    AddressLookup {
        source: iroh::address_lookup::Error,
        #[snafu(implicit)]
        location: Location,
    },
```

- [ ] **Step 2: Verify build with default features**

Run: `cargo build -p wires-net`
Expected: clean build. Three new variants and three `*Snafu` context selectors are generated.

- [ ] **Step 3: Verify build with feature off**

Run: `cargo build -p wires-net --no-default-features`
Expected: clean build. Only the `EndpointBind` variant compiles; `MdnsSetup` and `AddressLookup` are gated out.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-net/src/error.rs
git commit -m "feat(wires-net): add NetError variants for endpoint bind and mDNS setup"
```

---

### Task 3: Write failing tests for the bind helpers

**Files:**
- Create: `crates/wires-net/tests/bind_helpers.rs`

- [ ] **Step 1: Write the smoke tests**

Create `crates/wires-net/tests/bind_helpers.rs` with the following content:

```rust
//! Smoke tests for `wires_net::bind_lan` and `wires_net::bind_cloud`.
//!
//! These only verify that the helpers return a usable iroh `Endpoint` —
//! actual mDNS discovery between peers is not exercised here, because it
//! requires multicast and a second cooperating peer. The existing
//! `peer_hint.rs` and `pair_protocol.rs` integration tests cover the
//! cross-endpoint paths.

use iroh::SecretKey;

const TEST_ALPN: &[u8] = b"/wires/test-bind/0";

#[tokio::test]
async fn bind_lan_returns_a_usable_endpoint() {
    let sk = SecretKey::generate();
    let expected_id = sk.public();
    let ep = wires_net::bind_lan(sk, vec![TEST_ALPN.to_vec()])
        .await
        .expect("bind_lan should succeed on a fresh OS");
    assert_eq!(ep.id(), expected_id);
    ep.close().await;
}

#[tokio::test]
async fn bind_cloud_returns_a_usable_endpoint() {
    let sk = SecretKey::generate();
    let expected_id = sk.public();
    let ep = wires_net::bind_cloud(sk, vec![TEST_ALPN.to_vec()])
        .await
        .expect("bind_cloud should succeed on a fresh OS");
    assert_eq!(ep.id(), expected_id);
    ep.close().await;
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p wires-net --test bind_helpers`
Expected: COMPILATION FAILURE — `wires_net::bind_lan` and `wires_net::bind_cloud` do not exist yet. The compiler will say something like:
```
error[E0425]: cannot find function `bind_lan` in crate `wires_net`
```

This is the failing-test step. Do not commit yet.

---

### Task 4: Implement the bind helpers

**Files:**
- Create: `crates/wires-net/src/endpoint.rs`
- Modify: `crates/wires-net/src/lib.rs`

- [ ] **Step 1: Create the endpoint module**

Create `crates/wires-net/src/endpoint.rs` with the following content:

```rust
//! Endpoint bind helpers — one per deployment shape.
//!
//! [`bind_lan`] is for on-LAN agents (CLI runtimes, `wires-ha`, all
//! `wires-cli` dial commands). It registers iroh's `MdnsAddressLookup`
//! alongside the n0 pkarr/DNS resolver, so peers on the same LAN resolve in
//! milliseconds without an internet round-trip. Cross-LAN resolution still
//! works via n0.
//!
//! [`bind_cloud`] is for cloud-resident infrastructure (`wires-host`). It
//! skips mDNS entirely — multicast is useless in cloud environments, and the
//! host is reached by explicit `EndpointId` from the HTTPS `/v1/bootstrap`
//! response or from `PairGrant.host.peer_hints`.
//!
//! Both helpers use `iroh::endpoint::presets::N0` under the hood, so n0
//! pkarr/DNS discovery is always available.

use iroh::{Endpoint, SecretKey, endpoint::presets};
use snafu::ResultExt;

use crate::error::{EndpointBindSnafu, NetError};

/// Bind an endpoint for an on-LAN agent. Enables iroh's mDNS address lookup
/// (under the `mdns` Cargo feature, on by default) for fast LAN resolution.
pub async fn bind_lan(secret: SecretKey, alpns: Vec<Vec<u8>>) -> Result<Endpoint, NetError> {
    let ep = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(alpns)
        .bind()
        .await
        .context(EndpointBindSnafu)?;

    #[cfg(feature = "mdns")]
    {
        use iroh::address_lookup::MdnsAddressLookup;

        use crate::error::{AddressLookupSnafu, MdnsSetupSnafu};

        let mdns = MdnsAddressLookup::builder()
            .build(ep.id())
            .context(MdnsSetupSnafu)?;
        ep.address_lookup()
            .context(AddressLookupSnafu)?
            .add(mdns);
    }

    Ok(ep)
}

/// Bind an endpoint for cloud-resident infrastructure. Does NOT enable mDNS.
pub async fn bind_cloud(secret: SecretKey, alpns: Vec<Vec<u8>>) -> Result<Endpoint, NetError> {
    Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(alpns)
        .bind()
        .await
        .context(EndpointBindSnafu)
}
```

- [ ] **Step 2: Wire the module into the crate root and re-export the helpers**

Open `crates/wires-net/src/lib.rs`. Find the existing `pub mod discovery;` line (or similar `pub mod` declarations near the top of the file) and add `pub mod endpoint;` to the list. Add `bind_cloud`, `bind_lan` to the existing `pub use` block.

The relevant region of `lib.rs` currently reads (approximately):

```rust
pub mod discovery;
// ... other pub mod lines ...

pub use discovery::{DiscoveryEndpoint, DiscoveryResponse, fetch_endpoints};
// ... other re-exports ...
```

Add:

```rust
pub mod endpoint;

pub use endpoint::{bind_cloud, bind_lan};
```

Place `pub mod endpoint;` alphabetically among the other `pub mod` declarations, and the `pub use endpoint::...` line alphabetically among the other `pub use` lines.

- [ ] **Step 3: Run the bind-helper tests; verify pass**

Run: `cargo test -p wires-net --test bind_helpers`
Expected: both tests PASS. (The bind itself is local socket setup and does not depend on n0 DNS, so it returns within a second or two.)

- [ ] **Step 4: Also verify with the feature off**

Run: `cargo test -p wires-net --test bind_helpers --no-default-features`
Expected: both tests PASS. (With `mdns` off, `bind_lan` and `bind_cloud` are effectively identical.)

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/src/endpoint.rs crates/wires-net/src/lib.rs crates/wires-net/tests/bind_helpers.rs
git commit -m "feat(wires-net): add bind_lan and bind_cloud helpers with mDNS opt-in"
```

---

### Task 5: Migrate `wires-host/src/main.rs` to `bind_cloud`

**Files:**
- Modify: `crates/wires-host/src/main.rs:50-58`

- [ ] **Step 1: Replace the endpoint construction**

Open `crates/wires-host/src/main.rs`. The current block at lines 46–58 reads:

```rust
    // iroh identity ---------------------------------------------------------
    let secret_path = args.data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let iroh_sk = SecretKey::from_bytes(&secret);
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(iroh_sk)
        .alpns(vec![
            GOSSIP_ALPN.to_vec(),
            TENANT_ALPN.to_vec(),
            REPLAY_ALPN.to_vec(),
        ])
        .bind()
        .await?;
```

Replace it with:

```rust
    // iroh identity ---------------------------------------------------------
    let secret_path = args.data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let endpoint = wires_net::bind_cloud(
        SecretKey::from_bytes(&secret),
        vec![
            GOSSIP_ALPN.to_vec(),
            TENANT_ALPN.to_vec(),
            REPLAY_ALPN.to_vec(),
        ],
    )
    .await?;
```

- [ ] **Step 2: Remove the now-unused import**

At the top of the file, find the `use iroh::{Endpoint, SecretKey, endpoint::presets};` line and shrink it to `use iroh::SecretKey;` — `Endpoint` and `presets` are no longer referenced in this file.

- [ ] **Step 3: Build wires-host**

Run: `cargo build -p wires-host`
Expected: clean build.

- [ ] **Step 4: Run wires-host tests**

Run: `cargo test -p wires-host`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-host/src/main.rs
git commit -m "refactor(wires-host): use wires_net::bind_cloud (no mDNS in cloud)"
```

---

### Task 6: Migrate `wires-node/src/runtime.rs` to `bind_lan`

**Files:**
- Modify: `crates/wires-node/src/runtime.rs:8,30-44`

- [ ] **Step 1: Replace the endpoint construction inside `NodeRuntime::open`**

Open `crates/wires-node/src/runtime.rs`. The current `open` body at lines 30–44 reads:

```rust
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
```

Replace lines 30–40 (the `let endpoint = ...` block plus its `map_err`/`context` chain) with:

```rust
    pub async fn open(config: NodeConfig) -> Result<Self> {
        let node = Arc::new(Node::open(config.clone())?);
        let secret_path = config.data_dir.join("iroh.secret");
        let secret = load_or_create_secret(&secret_path).context(NetSnafu)?;
        let endpoint = wires_net::bind_lan(
            SecretKey::from_bytes(&secret),
            vec![wires_net::ALPN.to_vec()],
        )
        .await
        .context(NetSnafu)?;
```

- [ ] **Step 2: Trim the now-unused imports**

At line 8 the file imports `use iroh::{Endpoint, SecretKey, endpoint::presets};`. After the migration, only `SecretKey` is still referenced. Change to:

```rust
use iroh::{Endpoint, SecretKey};
```

Keep `Endpoint` — it's used in the `pub struct NodeRuntime` field at line 20 (`pub endpoint: Endpoint`). Drop `endpoint::presets`.

Also check whether `IoSnafu` is still imported and used elsewhere in the file. Run:

```bash
grep -n "IoSnafu" crates/wires-node/src/runtime.rs
```

If the only remaining reference was the one you just removed, also delete `IoSnafu` from the `use crate::error::{...}` line near the top of the file. (If `IoSnafu` is used elsewhere, leave the import alone.)

- [ ] **Step 3: Build wires-node**

Run: `cargo build -p wires-node`
Expected: clean build, no unused-import warnings.

- [ ] **Step 4: Run wires-node tests**

Run: `cargo test -p wires-node`
Expected: all tests pass (the `runtime_publish_subscribes` integration test now binds via `bind_lan`; it still uses `MemoryLookup` cross-registration so determinism is preserved).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-node/src/runtime.rs
git commit -m "refactor(wires-node): use wires_net::bind_lan in NodeRuntime::open"
```

---

### Task 7: Migrate `wires-ha/src/main.rs` to `bind_lan`

**Files:**
- Modify: `crates/wires-ha/src/main.rs:71-79`

- [ ] **Step 1: Replace the endpoint construction**

Open `crates/wires-ha/src/main.rs`. The current block at lines 71–79 reads:

```rust
    let secret = load_or_create_secret(&args.data_dir.join("iroh.secret"))?;
    let iroh_sk = SecretKey::from_bytes(&secret);
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(iroh_sk)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let endpoint_id = endpoint.id();
    tracing::info!(%endpoint_id, "wires-ha endpoint bound");
```

Replace with:

```rust
    let secret = load_or_create_secret(&args.data_dir.join("iroh.secret"))?;
    let endpoint = wires_net::bind_lan(
        SecretKey::from_bytes(&secret),
        vec![ALPN.to_vec()],
    )
    .await?;
    let endpoint_id = endpoint.id();
    tracing::info!(%endpoint_id, "wires-ha endpoint bound");
```

- [ ] **Step 2: Trim the imports**

Find the `use iroh::{Endpoint, SecretKey, endpoint::presets};` line near the top of the file. Drop `Endpoint` and `presets` if no longer used (they shouldn't be after this change). Result:

```rust
use iroh::SecretKey;
```

- [ ] **Step 3: Build wires-ha**

Run: `cargo build -p wires-ha`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-ha/src/main.rs
git commit -m "refactor(wires-ha): use wires_net::bind_lan for endpoint"
```

---

### Task 8: Migrate the three `wires-cli` dial commands to `bind_lan`

**Files:**
- Modify: `crates/wires-cli/src/cmd/pair_listen.rs:38-45`
- Modify: `crates/wires-cli/src/cmd/pair_approve.rs:109-116`
- Modify: `crates/wires-cli/src/cmd/host.rs:89-98`

- [ ] **Step 1: Migrate `pair_listen.rs`**

Open `crates/wires-cli/src/cmd/pair_listen.rs`. The current block at lines 37–45 reads:

```rust
    let secret = load_or_create_secret(&data_dir.join("iroh.secret")).context(NetSnafu)?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await
        .map_err(|e| CliError::Endpoint {
            message: format!("bind: {e}"),
            location: location!(),
        })?;
```

Replace with:

```rust
    let secret = load_or_create_secret(&data_dir.join("iroh.secret")).context(NetSnafu)?;
    let endpoint = wires_net::bind_lan(SecretKey::from_bytes(&secret), vec![])
        .await
        .context(NetSnafu)?;
```

Note: this site previously bound without any ALPNs (the iroh router is attached later by `run_listen`). `bind_lan` accepts an empty `Vec<Vec<u8>>` for the same effect.

Trim the imports at the top of the file: drop any `Endpoint`, `presets`, `location!` that are no longer referenced. Verify with:

```bash
cargo build -p wires-cli
```

If the compiler reports unused imports, remove them.

- [ ] **Step 2: Migrate `pair_approve.rs`**

Open `crates/wires-cli/src/cmd/pair_approve.rs`. The current block at lines 108–116 reads:

```rust
    let secret = load_or_create_secret(&data_dir.join("iroh.secret")).context(NetSnafu)?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await
        .map_err(|e| CliError::Endpoint {
            message: format!("bind: {e}"),
            location: location!(),
        })?;
```

Replace with:

```rust
    let secret = load_or_create_secret(&data_dir.join("iroh.secret")).context(NetSnafu)?;
    let endpoint = wires_net::bind_lan(SecretKey::from_bytes(&secret), vec![])
        .await
        .context(NetSnafu)?;
```

Trim unused imports — drop `Endpoint`, `presets`, `location!` if no longer referenced. Confirm with `cargo build -p wires-cli`.

- [ ] **Step 3: Migrate `host.rs`**

Open `crates/wires-cli/src/cmd/host.rs`. The current `bind_endpoint` helper at lines 89–98 reads:

```rust
async fn bind_endpoint(secret: [u8; 32]) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await
        .map_err(|e| CliError::Endpoint {
            message: format!("bind: {e}"),
            location: location!(),
        })
}
```

Replace the function body with a `bind_lan` call:

```rust
async fn bind_endpoint(secret: [u8; 32]) -> Result<Endpoint> {
    wires_net::bind_lan(SecretKey::from_bytes(&secret), vec![])
        .await
        .context(NetSnafu)
}
```

Add `use snafu::ResultExt;` and `use crate::error::NetSnafu;` if not already imported at the top of `host.rs`. Trim `Endpoint::builder` / `presets` / `location!` imports that are no longer used. Verify with `cargo build -p wires-cli`.

- [ ] **Step 4: Run wires-cli tests**

Run: `cargo test -p wires-cli`
Expected: all tests pass. The tests in `tests/cli_host_pair.rs` and `tests/cli_host_topic_register.rs` keep their own `Endpoint::builder` paths (they're not going through the CLI under test for endpoint construction); they should be unaffected.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-cli/src/cmd/pair_listen.rs \
        crates/wires-cli/src/cmd/pair_approve.rs \
        crates/wires-cli/src/cmd/host.rs
git commit -m "refactor(wires-cli): use wires_net::bind_lan in dial commands"
```

---

### Task 9: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the `wires-net` crate-layout row**

Open `CLAUDE.md` and find the table row that describes `wires-net`. It currently reads (with the long descriptive list of files inside the table cell):

```
| `wires-net` | iroh transport: `gossip.rs` wraps `iroh-gossip`; `replay.rs` is a custom QUIC protocol on `/wires/replay/0`; `tenant.rs` is the `/wires/tenant/0` control-plane (request/response types, `TenantClient`, `TenantProtocol`); `pair.rs` is the `/wires/pair/0` responder-driven pairing protocol (`PairRequest`, `PairGrantEnvelope`, `PairFrame`, `PairProtocol`, `PairClient`, `PairHandler`); `framing.rs` is the shared length-prefixed JSON helper; `discovery.rs` is the HTTPS `/v1/bootstrap` client; `peer_hint::first_reachable_with_discovery` is the join-time iterator with discovery-URL fallback. |
```

Append `endpoint.rs` to the file list. Change the trailing portion of the row to:

```
... `peer_hint::first_reachable_with_discovery` is the join-time iterator with discovery-URL fallback; `endpoint.rs` exposes `bind_lan` / `bind_cloud` helpers that consolidate every `Endpoint::builder(presets::N0)…bind()` call site and wire in iroh's mDNS local discovery for on-LAN binaries. |
```

- [ ] **Step 2: Add a cold-start note**

Find the "Note on cold-start flakiness" section under "Build and test". Append the following sentence to the end of that paragraph:

> mDNS is enabled by default in all on-LAN binaries via `wires-net`'s `mdns` feature; two test peers running on the same LAN may now resolve each other through mDNS faster than the documented n0 warm-up window. The defensive timeouts and `MemoryLookup` cross-registration in tests are still correct for non-LAN CI environments and for runs that disable the feature (`--no-default-features`).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude.md): note bind_lan/bind_cloud helpers and mdns default"
```

---

### Task 10: Workspace-wide verification

**Files:** none (verification only)

- [ ] **Step 1: Full workspace build with defaults**

Run: `cargo build --workspace`
Expected: clean build.

- [ ] **Step 2: Full workspace build with feature off**

Run: `cargo build --workspace --no-default-features`
Expected: clean build. (Other crates' default features are preserved because `--no-default-features` only suppresses the *root selected packages*' defaults. Pass `-p wires-net --no-default-features` for a more targeted check.)

Targeted check:

```bash
cargo build -p wires-net --no-default-features
cargo build -p wires-node                          # downstream still has mdns via wires-net default
cargo build -p wires-host                          # downstream still has mdns via wires-net default
cargo build -p wires-cli                           # downstream still has mdns via wires-net default
cargo build -p wires-ha                            # downstream still has mdns via wires-net default
```

Expected: all clean.

- [ ] **Step 3: Full workspace tests**

Run: `cargo test --workspace`
Expected: ~154 unit/integration tests pass. Cold-start latency may still apply on a freshly-booted machine; transient failures on the first run that pass on retry are still iroh warm-up per CLAUDE.md.

- [ ] **Step 4: Run the ignored acceptance scenarios**

Run: `cargo test --workspace -- --ignored`
Expected: 8 acceptance scenarios pass.

- [ ] **Step 5: Clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings. If any unused imports remain from the migration tasks (the `Endpoint`, `presets`, `location!`, `CliError::Endpoint` trimming), clean them up now.

- [ ] **Step 6: Format check**

Run: `cargo fmt --all --check`
Expected: exit 0. If not, run `cargo fmt --all` and commit:

```bash
git add -u
git commit -m "style: cargo fmt"
```

- [ ] **Step 7: Final verification commit (only if any fixes were needed)**

If steps 5–6 surfaced fixes, commit them as a single follow-up:

```bash
git add -u
git commit -m "chore: clippy/fmt cleanup after mDNS migration"
```

If everything was clean already, no additional commit is needed.

---

## Sanity-check matrix

After Task 10 passes, the following invariants from the spec must hold. Spot-check each one before declaring the work done:

| Invariant | How to verify |
|---|---|
| All six production endpoint sites use a `bind_*` helper. | `rg "Endpoint::builder" crates/wires-{node,host,ha,cli}/src \| grep -v tests/` returns empty. |
| `wires-host` is the only consumer of `bind_cloud`. | `rg "bind_cloud" crates/` shows uses only in `wires-host/src/main.rs` and in `wires-net` itself. |
| The `mdns` feature kill-switch works. | `cargo tree -p wires-net --no-default-features \| grep swarm-discovery` is empty; `cargo tree -p wires-net \| grep swarm-discovery` shows one line. |
| No new anyhow propagation. | `rg "anyhow" crates/wires-net/src/endpoint.rs` is empty. |
| The new `NetError` variants exist and are reachable. | `cargo doc -p wires-net --open` shows `EndpointBind`, `MdnsSetup`, `AddressLookup` on `NetError`. |
| Tests that historically used `MemoryLookup` still do. | `rg "MemoryLookup" crates/` matches at least the call sites in `wires-node/tests/runtime_publish_subscribes.rs` and `wires-cli/src/cmd/publish_helpers.rs`. |
