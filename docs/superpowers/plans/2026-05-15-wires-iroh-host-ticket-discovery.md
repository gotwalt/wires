# Iroh-Native Host-Ticket Discovery — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the HTTPS `/v1/bootstrap` discovery surface with a `HostTicket` artifact (base64 + terminal QR) that operators distribute by QR/paste, and wire it through both `wires-host` and `wires-cli`.

**Architecture:** Add a `wires-net::ticket` module (peer of `pair.rs`) that owns the `HostTicket` type end-to-end (encode, decode, ANSI-QR render). `wires-host` prints the ticket on startup and exposes a `ticket` subcommand. `wires-cli host …` subcommands take `--ticket <STRING>` instead of `--discovery-url <URL>`. `PairGrant.HostInfo` keeps only `peer_hints` — `service_discovery_url` is removed because iroh pkarr/DNS + mDNS already provide live re-resolution given an `EndpointId`. After consumers migrate, the `wires-net::discovery` module, `wires-host::http_discovery` module, `reqwest`, and `axum` are deleted.

**Tech Stack:** Rust edition 2024 / stable 1.95, iroh 0.98, snafu, serde+serde_json, base64 0.22, hex 0.4 (already in tree); `qrcode = "0.14"` (new dep, terminal renderer only, default-features off).

**Spec:** `docs/superpowers/specs/2026-05-15-wires-iroh-host-ticket-discovery-design.md`

---

## File Map

| File | Action |
|---|---|
| `crates/wires-net/Cargo.toml` | Modify: add `qrcode`, remove `reqwest` (Task 1, 16) |
| `crates/wires-net/src/error.rs` | Modify: add `Ticket*` variants (Task 2); remove `DiscoveryFetch` (Task 16) |
| `crates/wires-net/src/ticket.rs` | Create (Task 3); extend (Tasks 4–6) |
| `crates/wires-net/src/lib.rs` | Modify: export `HostTicket`; drop `discovery::*` re-exports + `first_reachable_with_discovery` (Tasks 3, 14, 16) |
| `crates/wires-net/src/discovery.rs` | Delete (Task 16) |
| `crates/wires-net/src/peer_hint.rs` | Modify: delete `first_reachable_with_discovery` + its test (Task 14) |
| `crates/wires-net/src/pair/grant.rs` | Modify: drop `HostInfo.service_discovery_url` (Task 12) |
| `crates/wires-net/src/pair/request.rs` | Modify: add `PairRequest::render_qr_ansi` (Task 7) |
| `crates/wires-node/src/config.rs` | Modify: drop `HostConfig.discovery_url`; update test (Task 13) |
| `crates/wires-node/src/pair.rs` | Modify: drop `discovery_url` plumbing in `install_grant` (Task 12) |
| `crates/wires-cli/src/cmd/host.rs` | Modify: `pair()` takes ticket string (Task 11) |
| `crates/wires-cli/src/cmd/pair_approve.rs` | Modify: `HostInfo` construction (Task 12) |
| `crates/wires-cli/src/cmd/pair_listen.rs` | Modify: real QR render (Task 8) |
| `crates/wires-cli/src/main.rs` | Modify: `HostCmd::Pair` takes `--ticket`; dispatch update (Task 11) |
| `crates/wires-cli/tests/cli_host_pair.rs` | Rewrite: drop axum, use ticket (Task 11) |
| `crates/wires-cli/tests/cli_host_topic_register.rs` | Rewrite: drop axum, use ticket (Task 11) |
| `crates/wires-host/Cargo.toml` | Modify: remove `axum`, `tower`, `reqwest` (Task 17) |
| `crates/wires-host/src/lib.rs` | Modify: drop `pub mod http_discovery` (Task 17) |
| `crates/wires-host/src/main.rs` | Modify: add `ticket` subcommand + startup emission (Tasks 9, 10); drop axum boot (Task 17) |
| `crates/wires-host/src/http_discovery.rs` | Delete (Task 17) |
| `crates/wires-host/tests/acceptance.rs` | Rewrite: `end_to_end_register_via_host_ticket` (Task 15) |
| `CLAUDE.md` | Modify: crate-layout row + authoritative-docs row (Task 18) |

---

## Phase A — Add the `HostTicket` primitive

### Task 1: Add the `qrcode` dependency to `wires-net`

**Files:**
- Modify: `crates/wires-net/Cargo.toml`

- [ ] **Step 1: Add qrcode under `[dependencies]`**

Edit `crates/wires-net/Cargo.toml`. After the line `base64 = { workspace = true }`, add:

```toml
qrcode = { version = "0.14", default-features = false }
```

- [ ] **Step 2: Verify the workspace still builds**

Run: `cargo build -p wires-net`
Expected: clean build, qrcode pulled in.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-net/Cargo.toml Cargo.lock
git commit -m "feat(wires-net): add qrcode 0.14 dep for HostTicket terminal QR"
```

---

### Task 2: Add `Ticket*` snafu variants to `NetError`

**Files:**
- Modify: `crates/wires-net/src/error.rs`

- [ ] **Step 1: Append the variants**

Edit `crates/wires-net/src/error.rs`. Just before the closing `}` of the `pub enum NetError`, add these six variants (all follow the project's snafu convention: implicit `location: Location`, no `message` field, display ends with `, at {location}`):

```rust
    #[snafu(display("Ticket base64 decode failed, at {location}"))]
    TicketDecode {
        #[snafu(source)]
        source: base64::DecodeError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Ticket JSON parse failed, at {location}"))]
    TicketParse {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Ticket bounds: {what} exceeds limit {limit}, at {location}"))]
    TicketBounds {
        what: &'static str,
        limit: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Ticket unsupported version {version}, at {location}"))]
    TicketUnsupportedVersion {
        version: u8,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Ticket endpoint_id was not valid 32-byte hex, at {location}"))]
    TicketInvalidEndpointId {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Ticket QR rendering failed: {source}, at {location}"))]
    TicketQrRender {
        source: qrcode::types::QrError,
        #[snafu(implicit)]
        location: Location,
    },
```

- [ ] **Step 2: Confirm the crate compiles**

Run: `cargo build -p wires-net`
Expected: PASS. Unused-variant warnings are fine for now.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-net/src/error.rs
git commit -m "feat(wires-net): add Ticket* error variants for HostTicket flow"
```

---

### Task 3: Create `HostTicket` (type + encode + decode + tests)

**Files:**
- Create: `crates/wires-net/src/ticket.rs`
- Modify: `crates/wires-net/src/lib.rs`

- [ ] **Step 1: Write the new module**

Create `crates/wires-net/src/ticket.rs` with the content below. The file is intentionally test-first — the unit tests after the `impl` block exercise every documented bound.

```rust
//! Host discovery ticket — a self-contained, base64-encoded JSON artifact
//! distributed by the operator (QR scan, paste, AirDrop, etc.) that carries
//! everything a client needs to dial a `wires-host` over iroh.
//!
//! Replaces the v1 HTTPS `/v1/bootstrap` discovery flow. The ticket has no
//! signature — host trust in wires is availability-only (the receiver verifies
//! caps and decrypts on its end), and a hostile substituted ticket can only
//! DoS, not breach.
//!
//! See `docs/superpowers/specs/2026-05-15-wires-iroh-host-ticket-discovery-design.md`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, ensure};

use crate::error::{
    NetError, Result, TicketBoundsSnafu, TicketDecodeSnafu, TicketInvalidEndpointIdSnafu,
    TicketParseSnafu, TicketUnsupportedVersionSnafu,
};

pub const TICKET_VERSION: u8 = 1;
pub const MAX_TICKET_BYTES: usize = 1024;
pub const MAX_HINT_ADDRS: usize = 8;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostTicket {
    pub version: u8,
    /// Hex iroh EndpointId (matches `PairDial` / `PeerHint` convention).
    pub endpoint_id: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
    /// Unix ms after which `addrs`/`relay` are treated as zero-weight hints by
    /// the consumer. `endpoint_id` itself never expires.
    pub hint_expires_at: i64,
}

impl HostTicket {
    /// URL-safe base64 of canonical JSON.
    pub fn encode(&self) -> Result<String> {
        let json =
            serde_json::to_vec(self).map_err(|source| NetError::TicketParse {
                source,
                location: snafu::location!(),
            })?;
        ensure!(
            json.len() <= MAX_TICKET_BYTES,
            TicketBoundsSnafu {
                what: "encoded ticket",
                limit: MAX_TICKET_BYTES,
            }
        );
        Ok(URL_SAFE_NO_PAD.encode(&json))
    }

    /// Decode a URL-safe base64 string. Validates `version`, size, the
    /// `endpoint_id` hex shape, and `addrs.len()`.
    pub fn decode(s: &str) -> Result<Self> {
        ensure!(
            s.len() <= MAX_TICKET_BYTES * 2,
            TicketBoundsSnafu {
                what: "encoded ticket",
                limit: MAX_TICKET_BYTES,
            }
        );
        let bytes = URL_SAFE_NO_PAD.decode(s).context(TicketDecodeSnafu)?;
        ensure!(
            bytes.len() <= MAX_TICKET_BYTES,
            TicketBoundsSnafu {
                what: "decoded ticket",
                limit: MAX_TICKET_BYTES,
            }
        );
        let t: HostTicket = serde_json::from_slice(&bytes).context(TicketParseSnafu)?;
        t.check_bounds()?;
        Ok(t)
    }

    fn check_bounds(&self) -> Result<()> {
        ensure!(
            self.version == TICKET_VERSION,
            TicketUnsupportedVersionSnafu {
                version: self.version,
            }
        );
        ensure!(
            self.addrs.len() <= MAX_HINT_ADDRS,
            TicketBoundsSnafu {
                what: "addrs",
                limit: MAX_HINT_ADDRS,
            }
        );
        ensure!(
            self.endpoint_id.len() == 64,
            TicketInvalidEndpointIdSnafu
        );
        let bytes = hex::decode(&self.endpoint_id)
            .ok()
            .ok_or_else(|| NetError::TicketInvalidEndpointId {
                location: snafu::location!(),
            })?;
        ensure!(bytes.len() == 32, TicketInvalidEndpointIdSnafu);
        iroh::EndpointId::from_bytes(&bytes.as_slice().try_into().expect("len checked"))
            .ok()
            .ok_or_else(|| NetError::TicketInvalidEndpointId {
                location: snafu::location!(),
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HostTicket {
        HostTicket {
            version: TICKET_VERSION,
            endpoint_id: "ab".repeat(32),
            addrs: vec!["127.0.0.1:11204".into(), "192.0.2.5:11204".into()],
            relay: Some("https://relay.example/".into()),
            hint_expires_at: 1_700_000_000_000,
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let t = sample();
        let s = t.encode().unwrap();
        let back = HostTicket::decode(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn rejects_version_other_than_one() {
        let mut t = sample();
        t.version = 2;
        let s = t.encode().unwrap();
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(matches!(err, NetError::TicketUnsupportedVersion { .. }));
    }

    #[test]
    fn rejects_too_many_addrs() {
        let mut t = sample();
        t.addrs = (0..(MAX_HINT_ADDRS + 1))
            .map(|i| format!("127.0.0.{i}:11204"))
            .collect();
        let s = t.encode().unwrap();
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(
            matches!(err, NetError::TicketBounds { what, .. } if what == "addrs"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_non_hex_endpoint_id() {
        let mut t = sample();
        t.endpoint_id = "z".repeat(64);
        let s = t.encode().unwrap();
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(matches!(err, NetError::TicketInvalidEndpointId { .. }));
    }

    #[test]
    fn rejects_wrong_endpoint_id_length() {
        let mut t = sample();
        t.endpoint_id = "ab".repeat(31); // 62 hex chars
        let s = t.encode().unwrap();
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(matches!(err, NetError::TicketInvalidEndpointId { .. }));
    }

    #[test]
    fn rejects_oversize_token() {
        // Force a JSON > MAX_TICKET_BYTES via a big addrs list. Encode bypasses
        // the bound (we'd need to mutate after encode), so build base64 of an
        // oversize byte buffer directly.
        let big = vec![b'a'; MAX_TICKET_BYTES + 100];
        let s = URL_SAFE_NO_PAD.encode(&big);
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(
            matches!(err, NetError::TicketBounds { what, .. } if what == "decoded ticket"),
            "got {err:?}"
        );
    }

    #[test]
    fn hint_expires_at_in_past_still_decodes() {
        let mut t = sample();
        t.hint_expires_at = 0;
        let s = t.encode().unwrap();
        let back = HostTicket::decode(&s).unwrap();
        assert_eq!(back.hint_expires_at, 0);
    }
}
```

- [ ] **Step 2: Wire the module into the crate**

Edit `crates/wires-net/src/lib.rs`. Add `pub mod ticket;` alphabetically (between `tenant` and `time`) and a re-export. The two lines to add:

In the `pub mod` block:
```rust
pub mod ticket;
```

In the `pub use` block (after the `tenant::` block):
```rust
pub use ticket::{HostTicket, MAX_HINT_ADDRS, MAX_TICKET_BYTES, TICKET_VERSION};
```

- [ ] **Step 3: Run the new tests**

Run: `cargo test -p wires-net ticket::tests`
Expected: 7 tests, all PASS.

- [ ] **Step 4: Confirm the workspace still builds and existing tests pass**

Run: `cargo build --workspace && cargo test -p wires-net`
Expected: clean build; existing wires-net tests still pass.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/src/ticket.rs crates/wires-net/src/lib.rs
git commit -m "feat(wires-net): HostTicket type with encode/decode + bounds tests"
```

---

### Task 4: `HostTicket::from_endpoint` constructor

**Files:**
- Modify: `crates/wires-net/src/ticket.rs`

- [ ] **Step 1: Write the failing test**

Append inside `mod tests { ... }` in `crates/wires-net/src/ticket.rs`:

```rust
    #[tokio::test]
    async fn from_endpoint_roundtrips_endpoint_id() {
        use iroh::SecretKey;
        let ep = crate::bind_lan(SecretKey::generate(), vec![]).await.unwrap();
        let t = HostTicket::from_endpoint(&ep, std::time::Duration::from_secs(60)).unwrap();
        assert_eq!(t.endpoint_id, hex::encode(ep.id().as_bytes()));
        assert_eq!(t.version, TICKET_VERSION);
        assert!(t.hint_expires_at > 0, "hint_expires_at must be set");
        // Round-trip the encoded form.
        let s = t.encode().unwrap();
        let back = HostTicket::decode(&s).unwrap();
        assert_eq!(back.endpoint_id, t.endpoint_id);
    }
```

- [ ] **Step 2: Run the test — expect a compile failure**

Run: `cargo test -p wires-net ticket::tests::from_endpoint_roundtrips_endpoint_id`
Expected: FAIL — `from_endpoint` does not exist.

- [ ] **Step 3: Add the impl**

Append inside `impl HostTicket { ... }` in `crates/wires-net/src/ticket.rs` (after `decode`):

```rust
    /// Build a ticket from a live iroh `Endpoint`. Pulls `EndpointId`, direct
    /// socket addrs, and the optional relay url off `endpoint.addr()`.
    pub fn from_endpoint(
        endpoint: &iroh::Endpoint,
        hint_ttl: std::time::Duration,
    ) -> Result<Self> {
        let endpoint_id = hex::encode(endpoint.id().as_bytes());
        let endpoint_addr = endpoint.addr();
        let mut addrs: Vec<String> = Vec::new();
        let mut relay: Option<String> = None;
        for t in &endpoint_addr.addrs {
            match t {
                iroh::TransportAddr::Ip(sa) => addrs.push(sa.to_string()),
                iroh::TransportAddr::Relay(url) => relay = Some(url.to_string()),
                _ => {}
            }
        }
        // Cap addrs so we never exceed the wire bound.
        if addrs.len() > MAX_HINT_ADDRS {
            addrs.truncate(MAX_HINT_ADDRS);
        }
        let now_ms = crate::unix_now_ms();
        Ok(HostTicket {
            version: TICKET_VERSION,
            endpoint_id,
            addrs,
            relay,
            hint_expires_at: now_ms + hint_ttl.as_millis() as i64,
        })
    }
```

- [ ] **Step 4: Verify the test passes**

Run: `cargo test -p wires-net ticket::tests::from_endpoint_roundtrips_endpoint_id`
Expected: PASS. (Note: this test binds a real iroh endpoint; cold-start can take 5–30s. The CLAUDE.md note on `endpoint.online()` warm-up applies.)

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/src/ticket.rs
git commit -m "feat(wires-net): HostTicket::from_endpoint live-endpoint constructor"
```

---

### Task 5: `HostTicket::to_peer_hint` adapter

**Files:**
- Modify: `crates/wires-net/src/ticket.rs`

- [ ] **Step 1: Write the failing test**

Append inside `mod tests { ... }`:

```rust
    #[test]
    fn to_peer_hint_carries_fields() {
        let t = sample();
        let h = t.to_peer_hint();
        assert_eq!(h.node_id, t.endpoint_id);
        assert_eq!(h.addrs, t.addrs);
        assert_eq!(h.relay, t.relay);
    }
```

- [ ] **Step 2: Run the test — expect a compile failure**

Run: `cargo test -p wires-net ticket::tests::to_peer_hint_carries_fields`
Expected: FAIL — `to_peer_hint` does not exist.

- [ ] **Step 3: Add the impl**

Append inside `impl HostTicket { ... }`:

```rust
    /// `HostTicket` → `PeerHint`. Used by the CLI when dispatching
    /// `wires host …` subcommands: the `--ticket` value is decoded into a
    /// `HostTicket`, converted to a `PeerHint`, and handed to
    /// `peer_hint::first_reachable`.
    pub fn to_peer_hint(&self) -> crate::peer_hint::PeerHint {
        crate::peer_hint::PeerHint {
            node_id: self.endpoint_id.clone(),
            addrs: self.addrs.clone(),
            relay: self.relay.clone(),
        }
    }
```

- [ ] **Step 4: Verify the test passes**

Run: `cargo test -p wires-net ticket::tests::to_peer_hint_carries_fields`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/src/ticket.rs
git commit -m "feat(wires-net): HostTicket::to_peer_hint adapter"
```

---

### Task 6: `HostTicket::render_qr_ansi`

**Files:**
- Modify: `crates/wires-net/src/ticket.rs`

- [ ] **Step 1: Write the failing test**

Append inside `mod tests { ... }`:

```rust
    #[test]
    fn render_qr_ansi_produces_block_art() {
        let t = sample();
        let s = t.render_qr_ansi().unwrap();
        assert!(!s.is_empty(), "rendered QR must be non-empty");
        // Dense1x2 renderer uses half-block characters; sanity-check at least
        // one is present.
        assert!(
            s.chars().any(|c| c == '\u{2580}' || c == '\u{2584}' || c == '\u{2588}'),
            "rendered string should contain block art chars"
        );
    }
```

- [ ] **Step 2: Run the test — expect a compile failure**

Run: `cargo test -p wires-net ticket::tests::render_qr_ansi_produces_block_art`
Expected: FAIL — `render_qr_ansi` does not exist.

- [ ] **Step 3: Add the impl**

Append inside `impl HostTicket { ... }`:

```rust
    /// Render the encoded ticket as an ANSI half-block QR string. Caller
    /// writes it wherever it likes (typically stderr).
    pub fn render_qr_ansi(&self) -> Result<String> {
        let payload = self.encode()?;
        let code = qrcode::QrCode::new(payload.as_bytes())
            .map_err(|source| NetError::TicketQrRender {
                source,
                location: snafu::location!(),
            })?;
        let s = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();
        Ok(s)
    }
```

- [ ] **Step 4: Verify the test passes**

Run: `cargo test -p wires-net ticket::tests::render_qr_ansi_produces_block_art`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/src/ticket.rs
git commit -m "feat(wires-net): HostTicket::render_qr_ansi terminal QR"
```

---

### Task 7: `PairRequest::render_qr_ansi`

**Files:**
- Modify: `crates/wires-net/src/pair/request.rs`

- [ ] **Step 1: Write the failing test**

In `crates/wires-net/src/pair/request.rs`, inside the existing `mod tests { ... }` block, append:

```rust
    #[test]
    fn render_qr_ansi_produces_block_art() {
        let (req, _) = sample(1_700_000_000_000);
        let s = req.render_qr_ansi().unwrap();
        assert!(!s.is_empty());
        assert!(
            s.chars().any(|c| c == '\u{2580}' || c == '\u{2584}' || c == '\u{2588}'),
            "rendered string should contain block art chars"
        );
    }
```

- [ ] **Step 2: Run the test — expect a compile failure**

Run: `cargo test -p wires-net pair::request::tests::render_qr_ansi_produces_block_art`
Expected: FAIL — `render_qr_ansi` does not exist.

- [ ] **Step 3: Add the impl**

In `crates/wires-net/src/pair/request.rs`, inside `impl PairRequest { ... }`, append after the existing `decode` method:

```rust
    /// Render the encoded PairRequest token as an ANSI half-block QR string.
    /// Mirrors `HostTicket::render_qr_ansi`.
    pub fn render_qr_ansi(&self) -> Result<String> {
        let payload = self.encode()?;
        let code = qrcode::QrCode::new(payload.as_bytes()).map_err(|source| {
            crate::error::NetError::TicketQrRender {
                source,
                location: snafu::location!(),
            }
        })?;
        let s = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();
        Ok(s)
    }
```

- [ ] **Step 4: Verify the test passes**

Run: `cargo test -p wires-net pair::request::tests::render_qr_ansi_produces_block_art`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/src/pair/request.rs
git commit -m "feat(wires-net): PairRequest::render_qr_ansi terminal QR"
```

---

### Task 8: Use the real QR renderer in `wires pair-listen --qr`

**Files:**
- Modify: `crates/wires-cli/src/cmd/pair_listen.rs`

- [ ] **Step 1: Restructure the qr handling**

Replace lines 60–68 in `crates/wires-cli/src/cmd/pair_listen.rs`:

The current code:
```rust
    println!("Pair-listen window open for {} seconds.", ttl.as_secs());
    println!("Share this token with the operator:");
    println!("{}", started.request_token);
    if qr {
        println!(
            "(--qr requested; pipe the token to `qrencode -t ANSI256UTF8 -o-` for a terminal QR)"
        );
    }
    println!();
```

becomes:

```rust
    println!("Pair-listen window open for {} seconds.", ttl.as_secs());
    println!("Share this token with the operator:");
    println!("{}", started.request_token);
    if qr {
        let req = wires_net::pair::PairRequest::decode(&started.request_token).context(NetSnafu)?;
        let art = req.render_qr_ansi().context(NetSnafu)?;
        println!();
        print!("{art}");
    }
    println!();
```

- [ ] **Step 2: Verify the workspace builds**

Run: `cargo build -p wires-cli`
Expected: PASS.

- [ ] **Step 3: Smoke-test the change manually (optional but encouraged)**

Build and run, capturing stderr (where the QR lands when piped). This is an interactive sanity check, not part of the test suite — skip if running headless.

```bash
cargo build -p wires-cli
# In a real session, would be: wires init && wires pair-listen --role x --description y --request t:read --qr
```

- [ ] **Step 4: Commit**

```bash
git add crates/wires-cli/src/cmd/pair_listen.rs
git commit -m "feat(wires-cli): render real QR in pair-listen --qr"
```

---

## Phase B — Host-side ticket plumbing

### Task 9: Add `wires-host ticket` subcommand

**Files:**
- Modify: `crates/wires-host/src/main.rs`

- [ ] **Step 1: Introduce a clap Subcommand split**

The current `Args` struct uses a flat layout. Restructure so the binary has a default behavior (run the host) and an optional `ticket` subcommand. Replace the existing `Args` struct (currently lines 22–36) with:

```rust
#[derive(Parser)]
#[command(
    name = "wires-host",
    about = "Blind multi-tenant relay for the wires network"
)]
struct Args {
    #[arg(long, global = true)]
    data_dir: PathBuf,
    /// Public URL the (legacy) discovery service advertises. If omitted,
    /// defaults to `http://<discovery_addr>` (testing). Deleted in a later task.
    #[arg(long, global = true)]
    public_url: Option<String>,
    /// (Legacy) HTTPS discovery bind address. Deleted in a later task.
    #[arg(long, global = true, default_value = "0.0.0.0:8443")]
    discovery_addr: SocketAddr,

    /// TTL after which a ticket's addrs/relay are considered stale by
    /// consumers. The `endpoint_id` itself never expires.
    #[arg(long, global = true, default_value = "7d")]
    ticket_hint_ttl: humantime::Duration,
    /// Force-emit a terminal QR of the host ticket even if stderr is not a TTY.
    #[arg(long, global = true, conflicts_with = "no_qr")]
    qr: bool,
    /// Suppress terminal QR emission even if stderr is a TTY.
    #[arg(long, global = true)]
    no_qr: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Print the host's discovery ticket (base64 to stdout, optional QR to stderr) and exit.
    Ticket,
}
```

`humantime` is not currently in `wires-host`'s dependencies (it's only in `wires-cli`). Add it to `crates/wires-host/Cargo.toml` under `[dependencies]`:

```toml
humantime = "2"
```

- [ ] **Step 2: Implement the ticket subcommand**

Below the existing `main` declaration but inside the same file, modify `main` so that early after `Args::parse()` it dispatches the subcommand. Find the line:

```rust
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;
```

Just after `std::fs::create_dir_all(...)`, insert:

```rust
    if matches!(args.command, Some(Command::Ticket)) {
        run_ticket_subcommand(&args).await?;
        return Ok(());
    }
```

Then, at the bottom of the file (after `main`), add:

```rust
async fn run_ticket_subcommand(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::IsTerminal as _;

    let secret_path = args.data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let endpoint = wires_net::bind_cloud(SecretKey::from_bytes(&secret), vec![]).await?;
    let ticket = wires_net::HostTicket::from_endpoint(&endpoint, (*args.ticket_hint_ttl).into())?;
    let encoded = ticket.encode()?;
    println!("{encoded}");
    let show_qr = args.qr || (!args.no_qr && std::io::stderr().is_terminal());
    if show_qr {
        let art = ticket.render_qr_ansi()?;
        eprintln!();
        eprintln!("{art}");
    }
    Ok(())
}
```

- [ ] **Step 3: Verify the binary builds**

Run: `cargo build -p wires-host`
Expected: PASS.

- [ ] **Step 4: Smoke-test (no test harness yet)**

Run: `target/debug/wires-host --data-dir $(mktemp -d) --no-qr ticket | head -c 80; echo`
Expected: prints a base64 string (a HostTicket); exits 0; no QR (because --no-qr).

- [ ] **Step 5: Add an integration test**

Create `crates/wires-host/tests/ticket_subcommand.rs`:

```rust
//! Integration test: `wires-host ticket` prints a decodable ticket whose
//! endpoint_id matches the host's bound endpoint.

use std::process::Stdio;

use tempfile::TempDir;
use tokio::process::Command;
use wires_net::HostTicket;

#[tokio::test]
async fn ticket_subcommand_prints_decodable_ticket() {
    let tmp = TempDir::new().unwrap();
    let bin = env!("CARGO_BIN_EXE_wires-host");
    let output = Command::new(bin)
        .arg("--data-dir")
        .arg(tmp.path())
        .arg("--no-qr")
        .arg("ticket")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn wires-host");
    assert!(
        output.status.success(),
        "exit status: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let token = stdout.trim();
    let ticket = HostTicket::decode(token).expect("decode ticket");
    assert_eq!(ticket.endpoint_id.len(), 64);
    assert_eq!(ticket.version, wires_net::TICKET_VERSION);
}
```

- [ ] **Step 6: Run the integration test**

Run: `cargo test -p wires-host --test ticket_subcommand`
Expected: PASS. (First run may take 10–30s for iroh cold-start.)

- [ ] **Step 7: Commit**

```bash
git add crates/wires-host/src/main.rs crates/wires-host/Cargo.toml crates/wires-host/tests/ticket_subcommand.rs Cargo.lock
git commit -m "feat(wires-host): add ticket subcommand printing base64 + optional QR"
```

---

### Task 10: Emit the host ticket on startup

**Files:**
- Modify: `crates/wires-host/src/main.rs`

- [ ] **Step 1: Add the startup emission**

In `crates/wires-host/src/main.rs`, after the existing `println!("wires-host: EndpointId = {endpoint_id}");` line (which is line ~60 in the current source), add:

```rust
    // Emit the host ticket on every startup. Operators copy/scan; TTY runs
    // additionally get a QR rendered to stderr.
    {
        use std::io::IsTerminal as _;
        let ticket = wires_net::HostTicket::from_endpoint(&endpoint, (*args.ticket_hint_ttl).into())?;
        let encoded = ticket.encode()?;
        tracing::info!("host ticket: {encoded}");
        let show_qr = args.qr || (!args.no_qr && std::io::stderr().is_terminal());
        if show_qr {
            let art = ticket.render_qr_ansi()?;
            eprintln!();
            eprintln!("{art}");
        }
    }
```

- [ ] **Step 2: Verify the binary still builds**

Run: `cargo build -p wires-host`
Expected: PASS.

- [ ] **Step 3: Verify the entire test suite still passes**

Run: `cargo test -p wires-host`
Expected: all existing host tests pass plus the new ticket-subcommand test from Task 9.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-host/src/main.rs
git commit -m "feat(wires-host): emit host ticket on startup (INFO log + TTY QR)"
```

---

## Phase C — Migrate consumers off discovery_url

### Task 11: Swap `wires-cli host --discovery-url` → `--ticket` (atomic: CLI + 2 tests)

This task is intentionally larger because the CLI flag and the two integration tests that exercise it must move together. Otherwise the test crate won't compile.

**Files:**
- Modify: `crates/wires-cli/src/main.rs`
- Modify: `crates/wires-cli/src/cmd/host.rs`
- Modify: `crates/wires-cli/tests/cli_host_pair.rs` (rewrite)
- Modify: `crates/wires-cli/tests/cli_host_topic_register.rs` (rewrite)

- [ ] **Step 1: Update the clap surface in `wires-cli/src/main.rs`**

In `crates/wires-cli/src/main.rs`, find the `HostCmd::Pair` variant (lines 98–101):

```rust
    Pair {
        #[arg(long)]
        discovery_url: String,
    },
```

Replace with:

```rust
    Pair {
        /// HostTicket string (base64), or `@<path>` to read from a file.
        #[arg(long)]
        ticket: String,
    },
```

Then in `main()`, find the dispatch line (around line 134):

```rust
        Cmd::Host(HostCmd::Pair { discovery_url }) => {
            cmd::host::pair(&data_dir, &discovery_url).await
        }
```

Replace with:

```rust
        Cmd::Host(HostCmd::Pair { ticket }) => cmd::host::pair(&data_dir, &ticket).await,
```

- [ ] **Step 2: Rewrite `wires-cli/src/cmd/host.rs::pair()`**

Find the `pub async fn pair` function. Replace its full body and signature (currently lines 20–61) with:

```rust
pub async fn pair(data_dir: &Path, ticket_arg: &str) -> Result<()> {
    let cfg_path = data_dir.join("config.toml");
    let raw = std::fs::read_to_string(&cfg_path).context(IoSnafu)?;
    let mut cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let root = load_root_signing_key(data_dir).context(IoSnafu)?;

    let token = read_ticket_arg(ticket_arg)?;
    let ticket = wires_net::HostTicket::decode(&token).context(NetSnafu)?;
    let hint = ticket.to_peer_hint();
    let host_eid = endpoint_id_from_hex(&hint.node_id)
        .ok_or_else(|| invalid!("ticket carried an invalid endpoint_id"))?;
    let host_eid_bytes = *host_eid.as_bytes();

    let secret_path = data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path).context(NetSnafu)?;
    let ep = bind_endpoint(secret).await?;
    let client = TenantClient::new(ep);
    let resp = client
        .register_tenant(host_eid, &root, &host_eid_bytes, unix_now_ms())
        .await
        .context(NetSnafu)?;
    match resp {
        TenantResponse::Register(r) if r.ok => {
            println!(
                "Paired with host {} (server_time={})",
                r.host_endpoint_id, r.server_time
            );
        }
        TenantResponse::Error(e) => return Err(host_rejected(e)),
        other => return unexpected(other),
    }
    cfg.host = Some(HostConfig {
        peer_hints: vec![hint],
    });
    let toml_str = toml::to_string_pretty(&cfg).context(TomlSerializeSnafu)?;
    std::fs::write(&cfg_path, toml_str).context(IoSnafu)?;
    println!("Host info persisted to {}", cfg_path.display());
    Ok(())
}

/// Accept either a raw base64 ticket or `@<path>` to read from a file.
fn read_ticket_arg(arg: &str) -> Result<String> {
    if let Some(path) = arg.strip_prefix('@') {
        let s = std::fs::read_to_string(path).context(IoSnafu)?;
        Ok(s.trim().to_string())
    } else {
        Ok(arg.trim().to_string())
    }
}
```

Note: this references `HostConfig { peer_hints: ... }` without `discovery_url`. That field is removed in Task 13; for now the struct still has it. Replace the cfg.host = ... block with the *interim* form that still includes `discovery_url: None`:

```rust
    cfg.host = Some(HostConfig {
        peer_hints: vec![hint],
        discovery_url: None,
    });
```

(Task 13 will drop the `discovery_url: None` arm cleanly.)

Also update the imports at the top of the file. The current import:

```rust
use wires_net::{endpoint_id_from_hex, fetch_endpoints, load_or_create_secret, unix_now_ms};
```

becomes:

```rust
use wires_net::{endpoint_id_from_hex, load_or_create_secret, unix_now_ms};
```

(Drop `fetch_endpoints`; `wires_net::HostTicket` is referenced via full path inside `pair()`.)

Also remove the `discovery_url` argument hint from the error in `open_paired_client`. Change line 72 (in the current source):

```rust
            invalid!("no host paired — run `wires host pair --discovery-url <URL>` first")
```

to:

```rust
            invalid!("no host paired — run `wires host pair --ticket <STRING>` first")
```

- [ ] **Step 3: Rewrite `crates/wires-cli/tests/cli_host_pair.rs`**

Replace the entire file with:

```rust
//! Integration test: spin up a minimal tenant-only host in-process, build a
//! `HostTicket` from it, point `wires host pair` at it via `--ticket`, and
//! verify config.toml is updated with the host's peer hint.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use iroh::SecretKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol};
use wires_net::HostTicket;

#[tokio::test]
async fn host_pair_persists_host_to_config() {
    // ---- spin up a tenant-aware host -----------------------------------
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let host_ep = wires_net::bind_cloud(SecretKey::generate(), vec![TENANT_ALPN.to_vec()])
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
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
        }),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // ---- build the host ticket the operator would scan ------------------
    let ticket = HostTicket::from_endpoint(&host_ep, std::time::Duration::from_secs(60)).unwrap();
    let token = ticket.encode().unwrap();

    // ---- run `wires init` then `wires host pair --ticket <T>` ----------
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
    )
    .unwrap();

    wires_cli::cmd::host::pair(agent_dir.path(), &token).await.unwrap();

    // ---- assert config.toml gained host fields -------------------------
    let after: wires_node::NodeConfig =
        toml::from_str(&std::fs::read_to_string(agent_dir.path().join("config.toml")).unwrap())
            .unwrap();
    let h = after.host.expect("host should be set after pair");
    assert_eq!(h.peer_hints.len(), 1);
    assert_eq!(h.peer_hints[0].node_id, hex::encode(host_eid));

    // Tenant must be in the host's registry.
    let root_pubkey = root.verifying_key().to_bytes();
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}
```

- [ ] **Step 4: Rewrite `crates/wires-cli/tests/cli_host_topic_register.rs`**

Replace the entire file with:

```rust
//! After `wires host pair`, `wires host topic-register <hex>` enrolls a
//! topic with the host. Subsequent inbound envelopes for that topic should
//! be routed and persisted.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use iroh::SecretKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::HostTicket;
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol};

#[tokio::test]
async fn topic_register_round_trip() {
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let host_ep = wires_net::bind_cloud(SecretKey::generate(), vec![TENANT_ALPN.to_vec()])
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
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
        }),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // Build the host ticket the operator would scan.
    let ticket = HostTicket::from_endpoint(&host_ep, std::time::Duration::from_secs(60)).unwrap();
    let token = ticket.encode().unwrap();

    // Init + pair via ticket.
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
    )
    .unwrap();
    wires_cli::cmd::host::pair(agent_dir.path(), &token).await.unwrap();

    // Register a synthetic topic id (matches the pre-existing test's shape:
    // we call topic_register with a hex string, not a name created locally).
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

- [ ] **Step 5: Run the modified tests**

Run:
```
cargo test -p wires-cli --test cli_host_pair
cargo test -p wires-cli --test cli_host_topic_register
```
Expected: both PASS. If `cli_host_topic_register` fails because of stale `http_discovery` imports, delete them.

- [ ] **Step 6: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: all unit + integration tests pass. (`#[ignore]`-marked acceptance tests are still skipped at this point.)

- [ ] **Step 7: Commit**

```bash
git add crates/wires-cli/src/main.rs crates/wires-cli/src/cmd/host.rs crates/wires-cli/tests/cli_host_pair.rs crates/wires-cli/tests/cli_host_topic_register.rs
git commit -m "feat(wires-cli): host subcommands take --ticket (replaces --discovery-url)"
```

---

### Task 12: Remove `HostInfo.service_discovery_url`

**Files:**
- Modify: `crates/wires-net/src/pair/grant.rs`
- Modify: `crates/wires-cli/src/cmd/pair_approve.rs`
- Modify: `crates/wires-node/src/pair.rs`

- [ ] **Step 1: Drop the field from `HostInfo`**

In `crates/wires-net/src/pair/grant.rs`, find:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub peer_hints: Vec<PeerHint>,
    pub service_discovery_url: Option<String>,
}
```

Replace with:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub peer_hints: Vec<PeerHint>,
}
```

- [ ] **Step 2: Update the pair-approve construction**

In `crates/wires-cli/src/cmd/pair_approve.rs`, find:

```rust
        cfg.host.as_ref().map(|h| HostInfo {
            peer_hints: h.peer_hints.clone(),
            service_discovery_url: h.discovery_url.clone(),
        })
```

Replace with:

```rust
        cfg.host.as_ref().map(|h| HostInfo {
            peer_hints: h.peer_hints.clone(),
        })
```

- [ ] **Step 3: Update `install_grant` in `wires-node`**

In `crates/wires-node/src/pair.rs`, find:

```rust
    if let Some(host) = &grant.host {
        cfg.host = Some(HostConfig {
            peer_hints: host.peer_hints.clone(),
            discovery_url: host.service_discovery_url.clone(),
        });
    }
```

Replace with:

```rust
    if let Some(host) = &grant.host {
        cfg.host = Some(HostConfig {
            peer_hints: host.peer_hints.clone(),
            discovery_url: None,
        });
    }
```

(The `discovery_url: None` stub disappears in Task 13.)

- [ ] **Step 4: Verify workspace builds**

Run: `cargo build --workspace`
Expected: PASS.

- [ ] **Step 5: Verify the workspace test suite still passes**

Run: `cargo test --workspace`
Expected: all tests pass. There may be a `HostInfo`-shape test in `grant.rs` that no longer mentions `service_discovery_url` — verify the existing `seal_and_open_roundtrip`-style tests still pass.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-net/src/pair/grant.rs crates/wires-cli/src/cmd/pair_approve.rs crates/wires-node/src/pair.rs
git commit -m "feat(wires-net): drop service_discovery_url from PairGrant.HostInfo"
```

---

### Task 13: Remove `HostConfig.discovery_url`

**Files:**
- Modify: `crates/wires-node/src/config.rs`
- Modify: `crates/wires-cli/src/cmd/host.rs`
- Modify: `crates/wires-node/src/pair.rs`

- [ ] **Step 1: Drop the field**

In `crates/wires-node/src/config.rs`, find the `HostConfig` struct (lines 20–29 in the current source):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub peer_hints: Vec<PeerHint>,
    #[serde(default)]
    pub discovery_url: Option<String>,
}
```

Replace with:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub peer_hints: Vec<PeerHint>,
}
```

- [ ] **Step 2: Update the round-trip test in `config.rs`**

In the same file, find `host_config_round_trips_through_toml` (around line 99). Replace the test body so it no longer constructs or asserts on `discovery_url`:

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
            }),
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: NodeConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.root_pubkey_hex, "deadbeef");
        let h = back.host.expect("host must round-trip");
        assert_eq!(h.peer_hints.len(), 1);
    }
```

- [ ] **Step 3: Drop the `discovery_url: None` arms in callers**

In `crates/wires-cli/src/cmd/host.rs`, find:

```rust
    cfg.host = Some(HostConfig {
        peer_hints: vec![hint],
        discovery_url: None,
    });
```

Replace with:

```rust
    cfg.host = Some(HostConfig {
        peer_hints: vec![hint],
    });
```

In `crates/wires-node/src/pair.rs`, find the analogous block from Task 12:

```rust
    if let Some(host) = &grant.host {
        cfg.host = Some(HostConfig {
            peer_hints: host.peer_hints.clone(),
            discovery_url: None,
        });
    }
```

Replace with:

```rust
    if let Some(host) = &grant.host {
        cfg.host = Some(HostConfig {
            peer_hints: host.peer_hints.clone(),
        });
    }
```

- [ ] **Step 4: Verify workspace builds and tests pass**

Run: `cargo test --workspace`
Expected: PASS. The updated round-trip test should run clean.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-node/src/config.rs crates/wires-cli/src/cmd/host.rs crates/wires-node/src/pair.rs
git commit -m "feat(wires-node): drop HostConfig.discovery_url"
```

---

## Phase D — Delete the HTTPS surface

### Task 14: Delete `peer_hint::first_reachable_with_discovery`

**Files:**
- Modify: `crates/wires-net/src/peer_hint.rs`
- Modify: `crates/wires-net/src/lib.rs`

- [ ] **Step 1: Confirm there are no remaining callers**

Run:
```
rg "first_reachable_with_discovery" crates/
```
Expected: only the definition in `peer_hint.rs` and the re-export in `lib.rs`. If any other reference appears, fix that call site first.

- [ ] **Step 2: Delete the helper and its test**

In `crates/wires-net/src/peer_hint.rs`, delete:
- The `first_reachable_with_discovery` function (current source lines ~64–86).
- The `first_reachable_falls_back_to_discovery_url` test (current source lines ~127 onward to end of file).
- Update the `first_reachable_returns_none_for_no_hints_and_no_url` test name — rename to `first_reachable_returns_none_for_no_hints` and call `first_reachable` directly (the existing test currently invokes `first_reachable_with_discovery`; switch it).

Concretely the simpler form for the surviving test:

```rust
    #[tokio::test]
    async fn first_reachable_returns_none_for_no_hints() {
        let ep = iroh::Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let res = first_reachable(
            &ep,
            &[],
            b"/wires/tenant/0",
            std::time::Duration::from_millis(50),
        )
        .await;
        assert!(res.is_none());
    }
```

Drop the now-unused `NoopProto` definition if it's only used by the deleted test.

- [ ] **Step 3: Drop the re-export from `lib.rs`**

In `crates/wires-net/src/lib.rs`, change:

```rust
pub use peer_hint::{
    PeerHint, cap_id_from_hex, endpoint_id_from_hex, first_reachable,
    first_reachable_with_discovery,
};
```

to:

```rust
pub use peer_hint::{PeerHint, cap_id_from_hex, endpoint_id_from_hex, first_reachable};
```

- [ ] **Step 4: Verify workspace builds and tests pass**

Run: `cargo test --workspace`
Expected: PASS. `wires-net` peer_hint tests still pass; nothing else references the deleted helper.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/src/peer_hint.rs crates/wires-net/src/lib.rs
git commit -m "refactor(wires-net): drop first_reachable_with_discovery (iroh handles re-resolution)"
```

---

### Task 15: Rewrite `wires-host/tests/acceptance.rs::end_to_end_register_via_http_discovery`

**Files:**
- Modify: `crates/wires-host/tests/acceptance.rs`

- [ ] **Step 1: Read the existing acceptance test for shape**

Run: `sed -n '1,120p' crates/wires-host/tests/acceptance.rs`
Confirm the test's setup (spawn host, build discovery axum app, dial via reqwest).

- [ ] **Step 2: Rewrite the first acceptance test**

`acceptance.rs` contains **two** `#[ignore]` tests: `end_to_end_register_via_http_discovery` and `two_tenants_share_one_host_no_leakage`. Only the first uses `http_discovery`; the second is untouched.

Replace the *first* test (and the top-of-file imports it pulls in: `http_discovery::*`, `axum`, `reqwest`, `Signer`, `SigningKey`, `TenantOp`, `TenantClient`, `TenantRegisterRequest`, `TenantRequest`, `TenantResponse`, `signing_bytes`, `Endpoint`, `presets`, the `endpoint_id_bytes` helper if no longer used) with the new shape below. Keep the second test (`two_tenants_share_one_host_no_leakage`) and its imports (`DalekSk`, `Duration`, `mpsc`, `WireMessage`, `MsgRouter`, `WriteRateLimiter`, `REPLAY_ALPN`, `GossipNode`) verbatim.

The new test:

```rust
//! Acceptance scenario: end-to-end tenant register via a host ticket.

#[tokio::test]
#[ignore]
async fn end_to_end_register_via_host_ticket() {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use iroh::SecretKey;
    use rand_core::OsRng;
    use tempfile::TempDir;
    use wires_host::per_tenant_logs::PerTenantLogs;
    use wires_host::retention::Retention;
    use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
    use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol};
    use wires_net::HostTicket;

    // ---- host setup ----------------------------------------------------
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let host_ep = wires_net::bind_cloud(SecretKey::generate(), vec![TENANT_ALPN.to_vec()])
        .await
        .unwrap();
    let host_eid_bytes: [u8; 32] = host_ep.id().as_bytes().to_owned();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention,
        host_endpoint_id: host_eid_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
        }),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // ---- operator builds the ticket the iOS-app / CLI would scan -------
    let ticket = HostTicket::from_endpoint(&host_ep, std::time::Duration::from_secs(60)).unwrap();
    let token = ticket.encode().unwrap();

    // ---- fresh agent: init then pair -----------------------------------
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
    )
    .unwrap();

    wires_cli::cmd::host::pair(agent_dir.path(), &token).await.unwrap();

    // ---- assert tenant registered --------------------------------------
    let root_pubkey = root.verifying_key().to_bytes();
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}
```

Drop any axum / reqwest / http_discovery imports left over at the top of the file.

- [ ] **Step 3: Run the acceptance test**

Run: `cargo test -p wires-host --test acceptance -- --ignored end_to_end_register_via_host_ticket`
Expected: PASS. First run may take 10–30s for iroh cold-start.

- [ ] **Step 4: Run the rest of the acceptance suite**

Run: `cargo test -p wires-host -- --ignored`
Expected: all `#[ignore]` scenarios pass (acceptance.rs may contain other tests; they should be unaffected).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-host/tests/acceptance.rs
git commit -m "test(wires-host): rewrite acceptance to use host ticket, not /v1/bootstrap"
```

---

### Task 16: Delete `wires-net::discovery` module + `DiscoveryFetch` + `reqwest`

**Files:**
- Modify: `crates/wires-net/src/lib.rs`
- Delete: `crates/wires-net/src/discovery.rs`
- Modify: `crates/wires-net/src/error.rs`
- Modify: `crates/wires-net/Cargo.toml`

- [ ] **Step 1: Confirm there are no remaining callers**

Run:
```
rg "fetch_endpoints|DiscoveryEndpoint|DiscoveryResponse|wires_net::discovery|DiscoveryFetch" crates/
```
Expected: matches only inside `wires-net/src/discovery.rs`, `wires-net/src/lib.rs`, and `wires-net/src/error.rs`. Anywhere else is a missed migration.

- [ ] **Step 2: Delete the module**

Run: `git rm crates/wires-net/src/discovery.rs`

- [ ] **Step 3: Drop the `pub mod discovery;` and re-exports from `lib.rs`**

In `crates/wires-net/src/lib.rs`:

Delete line 1: `pub mod discovery;`
Delete line 13: `pub use discovery::{DiscoveryEndpoint, DiscoveryResponse, fetch_endpoints};`

- [ ] **Step 4: Drop the `DiscoveryFetch` variant**

In `crates/wires-net/src/error.rs`, delete the `DiscoveryFetch` variant (currently lines 50–57):

```rust
    #[snafu(display("Discovery fetch failed for {url}, at {location}"))]
    DiscoveryFetch {
        url: String,
        #[snafu(source)]
        source: reqwest::Error,
        #[snafu(implicit)]
        location: Location,
    },
```

- [ ] **Step 5: Drop `reqwest` from `wires-net/Cargo.toml`**

Edit `crates/wires-net/Cargo.toml`. Delete the line:

```toml
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
```

- [ ] **Step 6: Verify the workspace builds**

Run: `cargo build --workspace`
Expected: PASS.

- [ ] **Step 7: Verify the workspace tests pass**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/wires-net/src/lib.rs crates/wires-net/src/discovery.rs crates/wires-net/src/error.rs crates/wires-net/Cargo.toml Cargo.lock
git commit -m "refactor(wires-net): delete discovery module + reqwest dep"
```

---

### Task 17: Delete `wires-host::http_discovery` module and HTTPS boot

**Files:**
- Modify: `crates/wires-host/src/lib.rs`
- Delete: `crates/wires-host/src/http_discovery.rs`
- Modify: `crates/wires-host/src/main.rs`
- Modify: `crates/wires-host/Cargo.toml`

- [ ] **Step 1: Drop the module declaration**

In `crates/wires-host/src/lib.rs`, delete the line `pub mod http_discovery;`.

- [ ] **Step 2: Delete the module file**

Run: `git rm crates/wires-host/src/http_discovery.rs`

- [ ] **Step 3: Remove the HTTPS boot from main**

In `crates/wires-host/src/main.rs`:

- Delete the import line: `use wires_host::http_discovery::{self, DiscoveryEndpoint, DiscoveryResponse, DiscoveryState};`
- Delete the entire `// HTTPS discovery ---` block (currently lines ~159–181 in the current source) — from `let public_url = ...` through the `println!("wires-host: discovery listening at ...")` line and the `tokio::spawn` block. End the section with the existing `println!("wires-host: running. Press Ctrl-C to exit.");` and the `tokio::signal::ctrl_c().await?;` lines.
- Delete the `--discovery-addr` and `--public-url` Args fields (they are now unused). Also delete the `use std::net::SocketAddr;` import if SocketAddr is no longer referenced.

- [ ] **Step 4: Drop deps from `crates/wires-host/Cargo.toml`**

In `[dependencies]`, delete the `axum = "0.8"` line.
In `[dev-dependencies]`, delete `tower = { version = "0.5", features = ["util"] }` and `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }`.

- [ ] **Step 5: Verify build and tests**

Run: `cargo build -p wires-host && cargo test -p wires-host`
Expected: PASS.

Run: `cargo test --workspace`
Expected: PASS across the workspace.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-host/src/lib.rs crates/wires-host/src/http_discovery.rs crates/wires-host/src/main.rs crates/wires-host/Cargo.toml Cargo.lock
git commit -m "refactor(wires-host): delete http_discovery, axum, reqwest dev-dep"
```

---

## Phase E — Polish

### Task 18: Update `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the crate-layout row for `wires-net`**

In `CLAUDE.md`, locate the line in the "Crate layout" table for `wires-net`. The current line mentions `discovery.rs`. Replace any mention of `discovery.rs` with `ticket.rs` and ensure the row mentions: `gossip.rs`, `replay.rs`, `tenant.rs`, `pair.rs`, `ticket.rs`, `framing.rs`, `peer_hint.rs`, `endpoint.rs`.

- [ ] **Step 2: Update the crate-layout row for `wires-host`**

Same file, the `wires-host` row currently mentions `http_discovery`. Remove that mention.

- [ ] **Step 3: Update the "Hosted service v1" status sentence**

Find the sentence under "Status" → "Hosted service v1" describing `HTTPS service discovery at /v1/bootstrap`. Replace with: "host-ticket discovery (base64 + terminal QR; `wires-host ticket` and startup-time emission)."

- [ ] **Step 4: Add an entry to "Authoritative docs"**

Under "Authoritative docs", add a bullet near the other 2026-05-15 entries:

```markdown
- **Host-ticket discovery spec** — `docs/superpowers/specs/2026-05-15-wires-iroh-host-ticket-discovery-design.md`. Replaces HTTPS `/v1/bootstrap` with a base64 `HostTicket` + terminal QR. Drops `service_discovery_url` and `HostConfig.discovery_url`.
- **Host-ticket discovery plan** — `docs/superpowers/plans/2026-05-15-wires-iroh-host-ticket-discovery.md`.
```

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude.md): host-ticket discovery — update crate layout + docs index"
```

---

### Task 19: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full workspace build**

Run: `cargo build --workspace`
Expected: clean build, no warnings about unused imports or dead code.

- [ ] **Step 2: Full test suite**

Run: `cargo test --workspace`
Expected: ~154 unit/integration tests pass (current count) plus the new ticket tests; nothing skipped except `#[ignore]`s.

- [ ] **Step 3: Acceptance suite**

Run: `cargo test --workspace -- --ignored`
Expected: 8 acceptance scenarios from previous slices + the rewritten `end_to_end_register_via_host_ticket`, all PASS.

- [ ] **Step 4: Clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings.

- [ ] **Step 5: Format**

Run: `cargo fmt --all`
Expected: no diff. If there is a diff, commit it as a `style:` commit.

- [ ] **Step 6: Confirm dependency deletions actually happened**

Run:
```
rg '^reqwest\b|^axum\b' crates/wires-net/Cargo.toml crates/wires-host/Cargo.toml
```
Expected: no matches.

Run:
```
rg "fetch_endpoints|DiscoveryEndpoint|DiscoveryResponse|http_discovery|service_discovery_url|first_reachable_with_discovery|HostConfig.*discovery_url" crates/
```
Expected: no matches.

- [ ] **Step 7: Smoke-test the binary end-to-end (manual)**

In one terminal:
```
cargo run -p wires-host -- --data-dir $(mktemp -d) --no-qr
```
Wait for the `host ticket: <base64>` line in stderr/stdout. Copy the token.

In a second terminal:
```
TMP=$(mktemp -d)
cargo run -p wires-cli -- --data-dir "$TMP" init --new-root
cargo run -p wires-cli -- --data-dir "$TMP" host pair --ticket '<paste>'
```
Expected: "Paired with host <hex> (server_time=...)" on stdout.

This is a manual confirmation, not a CI test — record completion in the task list.

- [ ] **Step 8: No commit (this task is verification only)**

If `cargo fmt` produced changes in step 5, commit those:

```bash
git add -A
git commit -m "style: cargo fmt after host-ticket discovery migration"
```

Otherwise: skip.
