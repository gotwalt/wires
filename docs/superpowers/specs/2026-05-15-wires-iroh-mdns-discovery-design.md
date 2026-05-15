# wires — local mDNS discovery for iroh endpoints

**Status:** design, 2026-05-15. Augments the substrate spec §3 (transport) and the hosted-service spec §7 (discovery) without changing wire formats.

## 1. Motivation

Today every iroh endpoint in the workspace is built the same way:

```rust
Endpoint::builder(presets::N0).secret_key(sk).alpns(...).bind().await?
```

`presets::N0` registers iroh's n0-hosted pkarr/DNS resolver. To translate an `EndpointId` (a public key) into a reachable socket address, the local node has to ask the n0 fleet — even when the peer is sitting on the next desk over.

This costs us two things:

1. **Cold-start latency.** CLAUDE.md already calls it out: "The first run after a cold machine can take 5–30s as pkarr/DNS lookups warm up." Tests defend with 10s timeouts and `MemoryLookup` cross-registration. Real users hit this whenever a freshly opened CLI agent tries to publish.

2. **Internet dependency for household-local traffic.** The wires mission is an "E2E gossip substrate for a household's AI agents." A household running entirely on one LAN should not need outbound n0 connectivity to let two agents find each other.

Iroh 0.98 already ships a fix: an optional `address-lookup-mdns` Cargo feature that pulls in `swarm-discovery` and exposes `MdnsAddressLookup`. Registering it on an endpoint both advertises that endpoint's addresses on the LAN and consumes other endpoints' advertisements. It runs in parallel with n0 — whoever resolves first, wins. There is no wire-format change, no protocol change, no security-model change.

This spec defines how wires opts into it.

## 2. Scope of change

**Added:**

- `wires-net::endpoint` — a new module with two named bind helpers (`bind_lan`, `bind_cloud`) that consolidate the four-line `Endpoint::builder(...).bind()` incantation currently repeated at every site.
- A workspace-level `mdns` Cargo feature on `wires-net`, default-on, that propagates to `iroh/address-lookup-mdns`. When the feature is off, the two helpers are identical and `swarm-discovery` drops out of the dep graph.

**Changed:**

- Every production iroh endpoint construction is rewritten to call one of the two helpers. The choice of helper is per-binary and reflects deployment shape:
  - `wires-node`, `wires-ha`, all `wires-cli` dial commands → `bind_lan`
  - `wires-host` → `bind_cloud`

**Unchanged:**

- Wire formats: `WireMessage`, AEAD modes, capability surface, pairing protocols, replay protocol, tenant control protocol, HTTPS `/v1/bootstrap`. mDNS is a name-resolution layer; envelopes don't know it exists.
- `peer_hint::first_reachable_with_discovery` and the discovery-URL fallback. mDNS makes peer hints redundant on-LAN but doesn't replace them — agents not on the LAN keep using hints.
- Crate layering. `wires-net::endpoint` lives in `wires-net`, the layer that already owns iroh transport.

## 3. Helper surface

Two functions, one module:

```rust
// crates/wires-net/src/endpoint.rs

use iroh::{Endpoint, SecretKey, endpoint::presets};
use snafu::ResultExt;

use crate::error::{EndpointBindSnafu, NetError, Result};

/// Bind an endpoint for an on-LAN agent (`wires-node` runtimes, `wires-ha`,
/// all `wires-cli` dial commands). Enables iroh's mDNS address lookup so
/// peers on the same LAN resolve in milliseconds without round-tripping the
/// n0 pkarr/DNS fleet. Falls back to n0 transparently for off-LAN peers.
pub async fn bind_lan(secret: SecretKey, alpns: Vec<Vec<u8>>) -> Result<Endpoint> {
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

/// Bind an endpoint for cloud-hosted infrastructure (`wires-host`). Does NOT
/// register mDNS — multicast is useless and noisy in cloud environments, and
/// the host is reached by explicit `EndpointId` from the HTTPS `/v1/bootstrap`
/// response or from `PairGrant.host.peer_hints`.
pub async fn bind_cloud(secret: SecretKey, alpns: Vec<Vec<u8>>) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(alpns)
        .bind()
        .await
        .context(EndpointBindSnafu)
}
```

Re-exported from `wires-net::lib` as `wires_net::bind_lan` / `wires_net::bind_cloud`.

**No anyhow in the new code.** Three of the existing `NetError` variants (`Endpoint`, `GossipSubscribe`, `GossipPublish`, `ReplayRpc`, `TenantRegister`) wrap `Box<anyhow::Error>` for historical reasons — that boxing predates the project's current snafu discipline. Those variants are out of scope for this change but flagged in §10. The three new variants below use **concrete iroh error types** as their `source`, so anyhow never enters or leaves the helpers and the boundary is just `Result<Endpoint, NetError>`:

```rust
// crates/wires-net/src/error.rs (additions, alongside existing variants)

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum NetError {
    // ... existing variants unchanged ...

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
}
```

All three iroh error types are concrete `n0_error::stack_error` enums (`iroh/src/socket.rs:815` for `BindError`, `iroh/src/address_lookup.rs:257` and `:317` for the others), are `Send + Sync + 'static`, and implement `std::error::Error` — no trait adaptors or `Box<dyn>` wrapping needed.

## 4. Call-site migration

Every production call site collapses to a one-liner. The full enumeration:

| Site | Before | After |
|---|---|---|
| `wires-node/src/runtime.rs:34` (in `NodeRuntime::open`) | `Endpoint::builder(presets::N0).secret_key(...).alpns(...).bind().await?` | `wires_net::bind_lan(secret, alpns).await?` |
| `wires-ha/src/main.rs:73` | same | `wires_net::bind_lan(...)` |
| `wires-cli/src/cmd/pair_listen.rs:38` | same | `wires_net::bind_lan(...)` |
| `wires-cli/src/cmd/pair_approve.rs:109` | same | `wires_net::bind_lan(...)` |
| `wires-cli/src/cmd/host.rs:90` | same | `wires_net::bind_lan(...)` |
| `wires-host/src/main.rs:50` | same | `wires_net::bind_cloud(...)` |

The CLI's `cmd/host.rs` path dials a cloud-resident host and has no LAN counterpart in that specific RPC. It still binds with `bind_lan` because the operator's CLI is itself an on-LAN process — advertising on mDNS for the duration of the dial costs nothing and lets co-located household devices (e.g. a `pair-listen`ing agent) resolve the operator faster.

The pre-existing `wires_net::load_or_create_secret` helper that feeds the `SecretKey` is unchanged; both helpers take a `SecretKey` directly so callers retain control over secret loading.

**Tests are not part of the rewrite.** Existing endpoint construction in `wires-net/tests/pair_protocol.rs`, `wires-net/src/peer_hint.rs` test modules, `wires-cli/tests/cli_host_pair.rs`, `wires-cli/tests/cli_host_topic_register.rs`, and `wires-net/src/tenant.rs` test modules stays on the raw `Endpoint::builder` path. They use `MemoryLookup` cross-registration for determinism and we don't want to introduce LAN-wide multicast as a hidden test dependency on developer machines. Tests in `wires-node/tests/runtime_publish_subscribes.rs` go through `NodeRuntime::open`, so they'll pick up `bind_lan` automatically — that's fine, since they already cross-register addrs via `MemoryLookup` and mDNS just rides along.

## 5. Cargo plumbing

`crates/wires-net/Cargo.toml`:

```toml
[features]
default = ["mdns"]
mdns = ["iroh/address-lookup-mdns"]

[dependencies]
iroh = { workspace = true }   # the address-lookup-mdns feature is propagated, not declared here
```

`crates/wires-net/Cargo.toml` already declares `iroh = { workspace = true }`. The workspace `Cargo.toml` `[workspace.dependencies]` entry stays `iroh = "0.98"` with no features — features are pulled in by `wires-net`'s feature flag.

Downstream crates (`wires-node`, `wires-host`, `wires-ha`, `wires-cli`) consume `wires-net`'s default features and so get mDNS transitively. None of them needs a Cargo edit.

**Disabling.** `cargo build -p <bin> --no-default-features --features <whatever-else>` if a consumer ever needs an mDNS-free build. The off-switch is documented in CLAUDE.md.

## 6. Trust and threat model

mDNS broadcasts on the LAN:

- the endpoint's `EndpointId` (a public ed25519 key);
- the endpoint's reachable socket addresses;
- optionally a `RelayUrl` and `user_data`.

None of this changes the wires threat model. `EndpointId`s appear in every signed envelope already; LAN socket addresses leak no more than any other LAN service does; we set `user_data = None` and rely on iroh's default (no relay URL announced beyond what's already on the endpoint).

Specifically, all of these remain true:

- **Host blindness** is unaffected — the host has no caps and learns nothing new about the envelope contents.
- **Per-publisher hash chain** is unaffected — it's a property of the storage layer.
- **AEAD/sealed-box** are unaffected — mDNS does not touch payloads.
- **Capability mint/revoke** is unaffected — caps travel inside envelopes; mDNS only routes the QUIC handshake.

**Worth naming explicitly:** any peer on the same LAN now learns that there is *a* wires endpoint nearby, identified by its `EndpointId`. That `EndpointId` is the agent's ed25519 public key. An attacker on the LAN can already see the QUIC handshakes; mDNS makes the `EndpointId` slightly more discoverable but does not enable any new attack. Cap-based authorization remains the security boundary.

## 7. Interaction with peer hints and `peer_hint::first_reachable_with_discovery`

The peer-hint logic in `wires-net/src/peer_hint.rs` is unchanged. `first_reachable_with_discovery` still:

1. Iterates carried hints, attempting a transport open against each.
2. On exhaustion, fetches fresh hints from a discovery URL if one is available.

When mDNS is active and the peer is on-LAN, the very first hint succeeds in milliseconds because the underlying iroh endpoint already cached the LAN socket address from the multicast advertisement. When the peer is off-LAN, behavior matches today exactly.

Conversely, when mDNS has *already* resolved a peer's `EndpointId`, callers may pass an empty `bootstrap: Vec<EndpointId>` to `NodeRuntime::join_topic` and iroh will still dial successfully. This is a quality-of-life improvement, not a contract change — hints remain the off-LAN path of record.

## 8. Trade-offs and risks

| Concern | Mitigation |
|---|---|
| `swarm-discovery 0.6.0-alpha.2` is an alpha. | Feature-gated behind `wires-net`'s `mdns` feature, default-on but toggleable. iroh pins the alpha to an exact version, so we inherit a stable choice. |
| Multicast may be blocked on locked-down networks (some corp wifi, sandboxed containers). | Failure mode is purely additive: mDNS finds nothing, n0 still works. No code path is gated on mDNS success. |
| LAN scan reveals presence of a wires agent. | Already implied by any QUIC handshake on the LAN; `EndpointId` is public by design. No new attack surface. |
| Test machines on the same LAN now hear each other's `MdnsAddressLookup` broadcasts. | Tests that need determinism (e.g. `runtime_publish_subscribes`) already use `MemoryLookup` cross-registration for the intended peer set; extra mDNS noise is harmless. |
| `bind_cloud` site (`wires-host`) is the only one that opts out — easy to regress. | Codified in the helper choice at the call site, called out in CLAUDE.md, and validated in the spec self-review checklist below. |

## 9. CLAUDE.md updates required

Two short edits, made as part of the implementation plan:

1. Under "Crate layout" — `wires-net` row updated to mention `endpoint.rs` (the bind helpers) alongside the existing list (`gossip.rs`, `replay.rs`, `tenant.rs`, `pair.rs`, `framing.rs`, `discovery.rs`, `peer_hint.rs`).
2. Under "Build and test" / "Note on cold-start flakiness" — add a sentence noting that mDNS is enabled by default in agent binaries and that LAN-co-located test peers may resolve via mDNS faster than the documented n0 warm-up window. The cold-start timeout defenses stay; they're still correct for non-LAN test setups.

## 10. Out of scope

- **A LAN-only deployment mode** (n0 disabled, mDNS only). The augment model covers all current use cases; if a user runs in a fully air-gapped LAN, n0 lookups will fail silently and mDNS will still succeed. A future explicit `bind_lan_only` is straightforward to add but not required now.
- **Replacing `peer_hint` with mDNS-only resolution.** Hints remain authoritative for off-LAN peers and for the HTTPS bootstrap path.
- **Configurable mDNS service name, TTLs, or addr-filter rules.** Defaults from `MdnsAddressLookup::builder()` are appropriate for v1.
- **A discovery surface for the host on mDNS.** The host runs in the cloud (per §4) and is reached by HTTPS `/v1/bootstrap` + explicit `EndpointId`.
- **iOS companion.** Implementation will inherit `bind_lan` semantics if and when it adopts an iroh endpoint, but the iOS spec is on hold pending architectural revisions per CLAUDE.md.
- **De-anyhow-ing the existing `NetError` variants.** Five variants in `crates/wires-net/src/error.rs` (`Endpoint`, `GossipSubscribe`, `GossipPublish`, `ReplayRpc`, `TenantRegister`) still wrap `Box<anyhow::Error>`. That is a pre-existing inconsistency with the workspace's snafu discipline and should be cleaned up — but doing so requires re-typing the iroh / iroh-gossip error sources at each call site inside `gossip.rs` and `replay.rs`, which is unrelated to mDNS. Tracked as follow-up; this spec only commits to *not adding* new anyhow-shaped variants.
