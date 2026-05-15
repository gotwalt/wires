# Responder-Driven Pairing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace today's inviter-driven `InviteToken` / `wires init --root` / `wires invite` / `wires join` flow with an OAuth-style responder-driven pairing — Bob declares a manifest, Alice consents and grants — implemented over a new `/wires/pair/0` iroh ALPN, with forward-secret sealed grants, single-use nonce binding, and crash-safe idempotent install.

**Architecture:** A new `wires-net::pair` module defines the wire types (`PairRequest`, `PairGrantEnvelope`, `PairFrame`) and a request/response protocol mirroring `wires-net::tenant`'s structure. `wires-node` implements `NodePairHandler` (verification + install) and exposes a `NodeRuntime::pair_listen` runtime entry. The CLI grows `wires pair-listen` (Bob) and `wires pair-approve` (Alice); `wires init` is reshaped to be household-agnostic; `wires invite` / `wires join` are deleted.

**Tech Stack:** Rust 2024 (toolchain 1.95, `resolver = "3"`), `iroh = "0.98"`, `chacha20poly1305 = "0.10"`, `ed25519-dalek = "2"`, `x25519-dalek = "2"`, `snafu` for errors, `redb = "4"` (transitively).

**Spec:** [`docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md`](../specs/2026-05-15-wires-responder-driven-pairing-design.md).

---

## File Structure

**Created:**

- `crates/wires-net/src/pair.rs` — wire types, sealed/signed envelope helpers, `PairFrame` framing, `PairProtocol` (iroh ProtocolHandler), `PairClient`, and the `PairHandler` trait. Single file mirrors the layout of `tenant.rs`.
- `crates/wires-cli/src/pair_pending.rs` — `PairPending` struct, JSON I/O, atomic create/delete with mode 0600.
- `crates/wires-cli/src/cmd/pair_listen.rs` — Bob's CLI entry point.
- `crates/wires-cli/src/cmd/pair_approve.rs` — Alice's CLI entry point.
- `crates/wires-node/src/pair.rs` — `install_grant` transactional helper and `NodePairHandler` (concrete `PairHandler` implementation that consumes a `Node` + data dir).

**Modified:**

- `crates/wires-net/src/lib.rs` — drop `invite`, add `pair`; update re-exports.
- `crates/wires-net/src/error.rs` — add pair-related error variants under `NetError`.
- `crates/wires-cli/src/lib.rs` — register `pair_pending` module.
- `crates/wires-cli/src/cmd/mod.rs` — drop `invite`, `join`; add `pair_listen`, `pair_approve`.
- `crates/wires-cli/src/cmd/init.rs` — remove `--root`, add `--new-root`, default to identity-only.
- `crates/wires-cli/src/cmd/topic.rs` — auto-mint self-cap on `topic create` when `root.ed25519` is present.
- `crates/wires-cli/src/main.rs` — clap subcommand changes (drop `Invite`/`Join`, add `PairListen`/`PairApprove`, retag `Init`).
- `crates/wires-node/src/lib.rs` — register `pair` module, re-export `NodePairHandler` and `pair_listen`.
- `crates/wires-node/src/runtime.rs` — `NodeRuntime::pair_listen` entry point.
- `README.md` — new walkthrough.
- `docs/superpowers/specs/2026-05-14-wires-substrate-design.md` — replace "invite token" wording in §2.6 (Bootstrapping) and §11 acceptance scenario with pair-listen / pair-approve.

**Deleted:**

- `crates/wires-net/src/invite.rs`
- `crates/wires-cli/src/cmd/invite.rs`
- `crates/wires-cli/src/cmd/join.rs`

---

## Task 1: `PairRequest` type with canonical JSON, signing, and size-bounded decode

**Files:**
- Create: `crates/wires-net/src/pair.rs`
- Modify: `crates/wires-net/src/lib.rs` (add `pub mod pair;`)

- [ ] **Step 1: Create the new module file with type declarations**

Write `crates/wires-net/src/pair.rs`:

```rust
//! Responder-driven pairing — ALPN `/wires/pair/0`.
//!
//! See `docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md`.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, ensure};

use crate::error::{NetError, PairBoundsSnafu, PairSignatureSnafu, Result, SerdeSnafu};

pub const ALPN: &[u8] = b"/wires/pair/0";

pub const MAX_FRAME_LEN: u32 = 64 * 1024;
pub const MAX_TOKEN_BYTES: usize = 4 * 1024;
pub const MAX_ROLE_LEN: usize = 32;
pub const MAX_DESCRIPTION_LEN: usize = 256;
pub const MAX_SCOPES: usize = 16;
pub const MAX_TOPIC_NAME_LEN: usize = 128;
pub const MIN_TTL_MS: i64 = 60_000;
pub const MAX_TTL_MS: i64 = 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub agent_pubkey: [u8; 32],
    #[serde(with = "hex::serde")]
    pub agent_x25519: [u8; 32],
    #[serde(with = "hex::serde")]
    pub ephemeral_x25519: [u8; 32],
    pub dial: PairDial,
    pub manifest: PairManifest,
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 32],
    pub issued_at: i64,
    pub expires: i64,
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairDial {
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairManifest {
    pub role: String,
    pub description: String,
    pub requested_scopes: Vec<RequestedScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedScope {
    pub topic_name: String,
    pub rights: Vec<wires_core::cap::Right>,
}
```

- [ ] **Step 2: Write the signing-bytes view (signature scope) and `sign`/`verify` methods**

Append to `crates/wires-net/src/pair.rs`:

```rust
impl PairRequest {
    /// Bytes that the agent ed25519 signs over — everything except `signature`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct View<'a> {
            version: u8,
            #[serde(with = "hex::serde")]
            agent_pubkey: &'a [u8; 32],
            #[serde(with = "hex::serde")]
            agent_x25519: &'a [u8; 32],
            #[serde(with = "hex::serde")]
            ephemeral_x25519: &'a [u8; 32],
            dial: &'a PairDial,
            manifest: &'a PairManifest,
            #[serde(with = "hex::serde")]
            nonce: &'a [u8; 32],
            issued_at: i64,
            expires: i64,
        }
        let v = View {
            version: self.version,
            agent_pubkey: &self.agent_pubkey,
            agent_x25519: &self.agent_x25519,
            ephemeral_x25519: &self.ephemeral_x25519,
            dial: &self.dial,
            manifest: &self.manifest,
            nonce: &self.nonce,
            issued_at: self.issued_at,
            expires: self.expires,
        };
        serde_json::to_vec(&v).context(SerdeSnafu)
    }

    pub fn sign(&mut self, agent_sk: &SigningKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        self.signature = agent_sk.sign(&bytes).to_bytes();
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.agent_pubkey)
            .ok()
            .ok_or_else(|| NetError::PairSignature {
                location: snafu::location!(),
            })?;
        let sig = Signature::from_bytes(&self.signature);
        let bytes = self.signing_bytes()?;
        ensure!(vk.verify(&bytes, &sig).is_ok(), PairSignatureSnafu);
        Ok(())
    }
}
```

- [ ] **Step 3: Implement size-bounded encode/decode**

Append to `crates/wires-net/src/pair.rs`:

```rust
impl PairRequest {
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context(SerdeSnafu)?;
        ensure!(
            json.len() <= MAX_TOKEN_BYTES,
            PairBoundsSnafu {
                what: "encoded token",
                limit: MAX_TOKEN_BYTES,
            }
        );
        Ok(crate::base64url::encode(&json))
    }

    pub fn decode(token: &str) -> Result<Self> {
        ensure!(
            token.len() <= MAX_TOKEN_BYTES * 2,
            PairBoundsSnafu {
                what: "encoded token",
                limit: MAX_TOKEN_BYTES,
            }
        );
        let bytes = crate::base64url::decode(token).map_err(|_| NetError::Serde {
            source: serde_json::from_str::<()>("\"bad base64\"").unwrap_err(),
            location: snafu::location!(),
        })?;
        let tok: PairRequest = serde_json::from_slice(&bytes).context(SerdeSnafu)?;
        tok.check_bounds()?;
        Ok(tok)
    }

    fn check_bounds(&self) -> Result<()> {
        ensure!(self.version == 1, PairBoundsSnafu { what: "version", limit: 1usize });
        ensure!(
            !self.manifest.role.is_empty() && self.manifest.role.len() <= MAX_ROLE_LEN,
            PairBoundsSnafu { what: "manifest.role", limit: MAX_ROLE_LEN }
        );
        ensure!(
            self.manifest.role.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            PairBoundsSnafu { what: "manifest.role chars", limit: 0usize }
        );
        ensure!(
            !self.manifest.description.is_empty()
                && self.manifest.description.len() <= MAX_DESCRIPTION_LEN,
            PairBoundsSnafu { what: "manifest.description", limit: MAX_DESCRIPTION_LEN }
        );
        ensure!(
            !self.manifest.requested_scopes.is_empty()
                && self.manifest.requested_scopes.len() <= MAX_SCOPES,
            PairBoundsSnafu { what: "manifest.requested_scopes", limit: MAX_SCOPES }
        );
        for scope in &self.manifest.requested_scopes {
            ensure!(
                !scope.topic_name.is_empty() && scope.topic_name.len() <= MAX_TOPIC_NAME_LEN,
                PairBoundsSnafu { what: "scope.topic_name", limit: MAX_TOPIC_NAME_LEN }
            );
        }
        let ttl = self.expires.saturating_sub(self.issued_at);
        ensure!(
            ttl >= MIN_TTL_MS && ttl <= MAX_TTL_MS,
            PairBoundsSnafu { what: "ttl", limit: MAX_TTL_MS as usize }
        );
        Ok(())
    }
}
```

- [ ] **Step 4: Reuse the existing base64url helper**

The deleted `invite.rs` defines `base64url_encode` / `base64url_decode`. Lift them into their own module so both pair.rs and future modules can use them.

Create `crates/wires-net/src/base64url.rs` and move the implementations from `crates/wires-net/src/invite.rs` (lines 60–110 in the current tree) verbatim, exposing them as:

```rust
pub fn encode(bytes: &[u8]) -> String { /* same body */ }
pub fn decode(s: &str) -> std::result::Result<Vec<u8>, ()> { /* same body */ }
```

Register the module in `crates/wires-net/src/lib.rs` by adding `pub mod base64url;` near the top (after `pub mod gossip;`).

- [ ] **Step 5: Add `pub mod pair;` to `crates/wires-net/src/lib.rs`**

Edit `crates/wires-net/src/lib.rs` and insert `pub mod pair;` between `pub mod invite;` and `pub mod peer_hint;` (keep `invite` for now — it's removed in Task 15). Add re-exports at the end:

```rust
pub use pair::{PairDial, PairManifest, PairRequest, RequestedScope};
```

- [ ] **Step 6: Add the new error variants to `crates/wires-net/src/error.rs`**

Append two variants to `NetError`:

```rust
    #[snafu(display("Pair request bounds: {what} exceeds limit {limit}, at {location}"))]
    PairBounds {
        what: &'static str,
        limit: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair signature verify failed, at {location}"))]
    PairSignature {
        #[snafu(implicit)]
        location: Location,
    },
```

- [ ] **Step 7: Write the failing tests**

Append to the bottom of `crates/wires-net/src/pair.rs`:

```rust
#[cfg(test)]
mod request_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn sample(now: i64) -> (PairRequest, SigningKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let mut req = PairRequest {
            version: 1,
            agent_pubkey: sk.verifying_key().to_bytes(),
            agent_x25519: [9u8; 32],
            ephemeral_x25519: [7u8; 32],
            dial: PairDial {
                node_id: "00".repeat(32),
                addrs: vec!["127.0.0.1:1234".into()],
                relay: None,
            },
            manifest: PairManifest {
                role: "chat-agent".into(),
                description: "Bob".into(),
                requested_scopes: vec![RequestedScope {
                    topic_name: "home.notes".into(),
                    rights: vec![wires_core::cap::Right::Read, wires_core::cap::Right::Write],
                }],
            },
            nonce: [3u8; 32],
            issued_at: now,
            expires: now + 5 * 60 * 1000,
            signature: [0u8; 64],
        };
        req.sign(&sk).unwrap();
        (req, sk)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let (req, _) = sample(1_700_000_000_000);
        let s = req.encode().unwrap();
        let back = PairRequest::decode(&s).unwrap();
        assert_eq!(back.agent_pubkey, req.agent_pubkey);
        assert_eq!(back.manifest.role, "chat-agent");
        assert_eq!(back.signature, req.signature);
    }

    #[test]
    fn signature_verifies() {
        let (req, _) = sample(1_700_000_000_000);
        req.verify().unwrap();
    }

    #[test]
    fn tampered_role_invalidates() {
        let (mut req, _) = sample(1_700_000_000_000);
        req.manifest.role = "evil-agent".into();
        assert!(req.verify().is_err());
    }

    #[test]
    fn tampered_pubkey_invalidates() {
        let (mut req, _) = sample(1_700_000_000_000);
        req.agent_pubkey = [0xff; 32];
        assert!(req.verify().is_err());
    }

    #[test]
    fn rejects_version_other_than_one() {
        let (mut req, _) = sample(1_700_000_000_000);
        req.version = 2;
        let s = req.encode().unwrap();
        assert!(PairRequest::decode(&s).is_err());
    }

    #[test]
    fn rejects_oversize_description() {
        let (mut req, sk) = sample(1_700_000_000_000);
        req.manifest.description = "x".repeat(MAX_DESCRIPTION_LEN + 1);
        req.sign(&sk).unwrap();
        let s = req.encode().unwrap();
        assert!(PairRequest::decode(&s).is_err());
    }

    #[test]
    fn rejects_ttl_below_min() {
        let now = 1_700_000_000_000;
        let (mut req, sk) = sample(now);
        req.expires = now + 1000;
        req.sign(&sk).unwrap();
        let s = req.encode().unwrap();
        assert!(PairRequest::decode(&s).is_err());
    }

    #[test]
    fn rejects_role_with_disallowed_chars() {
        let (mut req, sk) = sample(1_700_000_000_000);
        req.manifest.role = "chat agent".into();
        req.sign(&sk).unwrap();
        let s = req.encode().unwrap();
        assert!(PairRequest::decode(&s).is_err());
    }
}
```

- [ ] **Step 8: Run tests; verify all pass**

Run: `cargo test -p wires-net --lib pair::request_tests`
Expected: 8 passed; 0 failed.

- [ ] **Step 9: Commit**

```bash
git add crates/wires-net/src/pair.rs crates/wires-net/src/base64url.rs \
        crates/wires-net/src/lib.rs crates/wires-net/src/error.rs
git commit -m "$(cat <<'EOF'
feat(wires-net): PairRequest type with signed canonical JSON and bounded decode

Adds the first half of the responder-driven pairing wire format: PairRequest,
PairDial, PairManifest, RequestedScope, with ed25519 detached signing over
canonical JSON and strict size bounds enforced at decode (role, description,
scope count, topic name length, TTL window, total token bytes).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `PairGrant` + `PairGrantEnvelope` + sealed/signed crypto

**Files:**
- Modify: `crates/wires-net/src/pair.rs` (append)
- Modify: `crates/wires-net/src/error.rs`

- [ ] **Step 1: Add the inner-payload and envelope types**

Append to `crates/wires-net/src/pair.rs`:

```rust
use wires_core::Capability;
use crate::peer_hint::PeerHint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairGrant {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub root_pubkey: [u8; 32],
    pub cap: Capability,
    pub topic_keys: Vec<TopicEpochKey>,
    pub topic_names: Vec<TopicNameEntry>,
    pub host: Option<HostInfo>,
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 32],
    pub issued_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicEpochKey {
    #[serde(with = "hex::serde")]
    pub topic_id: [u8; 32],
    pub epoch: u32,
    #[serde(with = "hex::serde")]
    pub key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicNameEntry {
    #[serde(with = "hex::serde")]
    pub topic_id: [u8; 32],
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub peer_hints: Vec<PeerHint>,
    pub service_discovery_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairGrantEnvelope {
    #[serde(with = "hex::serde")]
    pub root_pubkey: [u8; 32],
    /// Sealed-box output: prepended-ephemeral-pubkey || ChaCha20-Poly1305(content).
    pub sealed_payload: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}
```

- [ ] **Step 2: Implement `seal_and_sign` / `open_and_verify` against `wires-crypto::sealed`**

The existing `wires_crypto::sealed::seal_to` internally generates a fresh ephemeral X25519 keypair and prepends the pubkey to the AEAD ciphertext. We reuse it; the envelope's `sealed_payload` carries the prepended ephemeral. The outer signature covers `root_pubkey || sealed_payload`.

The sealed-box API requires `topic_id`, `sender`, `seq`, `aad` for nonce derivation. We bind to the pairing nonce by using:
- `topic_id` = `grant.nonce` (the 32-byte pair nonce — uniquely scopes this seal),
- `sender` = `grant.root_pubkey`,
- `seq` = `0`,
- `aad` = `b"wires.pair.v1"` (domain separation).

Append to `crates/wires-net/src/pair.rs`:

```rust
const PAIR_SEAL_AAD: &[u8] = b"wires.pair.v1";

impl PairGrantEnvelope {
    /// Build an envelope from `grant`: seal `grant` to Bob's `recipient_ephemeral_x25519`,
    /// then sign over (root_pubkey || sealed_payload) with `root_sk`.
    pub fn seal_and_sign(
        grant: &PairGrant,
        recipient_ephemeral_x25519: &[u8; 32],
        root_sk: &SigningKey,
    ) -> Result<Self> {
        let content = serde_json::to_vec(grant).context(SerdeSnafu)?;
        let sealed_payload = wires_crypto::sealed::seal_to(
            recipient_ephemeral_x25519,
            &grant.nonce,
            &grant.root_pubkey,
            0,
            &content,
            PAIR_SEAL_AAD,
        )
        .map_err(|e| NetError::PairCrypto {
            source: Box::new(e),
            location: snafu::location!(),
        })?;

        let mut to_sign = Vec::with_capacity(32 + sealed_payload.len());
        to_sign.extend_from_slice(&grant.root_pubkey);
        to_sign.extend_from_slice(&sealed_payload);
        let signature = root_sk.sign(&to_sign).to_bytes();

        Ok(Self {
            root_pubkey: grant.root_pubkey,
            sealed_payload,
            signature,
        })
    }

    /// Verify the outer signature, then sealed-box-decrypt with `recipient_sk`.
    /// Caller verifies `nonce` and other inner-payload invariants after parsing.
    pub fn open_and_verify(
        &self,
        recipient_sk: &x25519_dalek::StaticSecret,
        expected_nonce: &[u8; 32],
    ) -> Result<PairGrant> {
        let vk = VerifyingKey::from_bytes(&self.root_pubkey)
            .ok()
            .ok_or_else(|| NetError::PairSignature {
                location: snafu::location!(),
            })?;
        let mut to_verify = Vec::with_capacity(32 + self.sealed_payload.len());
        to_verify.extend_from_slice(&self.root_pubkey);
        to_verify.extend_from_slice(&self.sealed_payload);
        let sig = Signature::from_bytes(&self.signature);
        ensure!(vk.verify(&to_verify, &sig).is_ok(), PairSignatureSnafu);

        let content = wires_crypto::sealed::open_sealed(
            recipient_sk,
            expected_nonce,
            &self.root_pubkey,
            0,
            &self.sealed_payload,
            PAIR_SEAL_AAD,
        )
        .map_err(|e| NetError::PairCrypto {
            source: Box::new(e),
            location: snafu::location!(),
        })?;
        let grant: PairGrant = serde_json::from_slice(&content).context(SerdeSnafu)?;
        Ok(grant)
    }
}
```

- [ ] **Step 3: Add the `PairCrypto` error variant**

Append to `crates/wires-net/src/error.rs`:

```rust
    #[snafu(display("Pair sealed-box failure, at {location}"))]
    PairCrypto {
        #[snafu(source(from(wires_crypto::error::CryptoError, Box::new)))]
        source: Box<wires_crypto::error::CryptoError>,
        #[snafu(implicit)]
        location: Location,
    },
```

If the source path differs (e.g. the error type is named `CryptoError` but in a different module), adjust the `from(...)` line accordingly. Run `cargo build -p wires-net` once after the edit; the compiler will pinpoint the correct path.

- [ ] **Step 4: Add re-exports**

In `crates/wires-net/src/lib.rs`, extend the pair re-export:

```rust
pub use pair::{
    HostInfo as PairHostInfo, PairDial, PairGrant, PairGrantEnvelope, PairManifest, PairRequest,
    RequestedScope, TopicEpochKey, TopicNameEntry,
};
```

(`HostInfo` is aliased to `PairHostInfo` at re-export to avoid colliding with other `HostInfo`-named types elsewhere in `wires-net`.)

- [ ] **Step 5: Write tests for round-trip and tamper-detection**

Append to `crates/wires-net/src/pair.rs`:

```rust
#[cfg(test)]
mod grant_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use wires_core::cap::Right;
    use x25519_dalek::{PublicKey as XPub, StaticSecret as XSk};

    fn sample_grant(root_pk: [u8; 32], cap: Capability, nonce: [u8; 32]) -> PairGrant {
        PairGrant {
            version: 1,
            root_pubkey: root_pk,
            cap,
            topic_keys: vec![TopicEpochKey {
                topic_id: [4u8; 32],
                epoch: 0,
                key: [5u8; 32],
            }],
            topic_names: vec![TopicNameEntry {
                topic_id: [4u8; 32],
                name: "home.notes".into(),
            }],
            host: None,
            nonce,
            issued_at: 1_700_000_000_000,
        }
    }

    fn signed_cap(root_sk: &SigningKey, bob_pk: [u8; 32]) -> Capability {
        let mut cap = Capability::new_unsigned(
            bob_pk,
            vec!["home.notes".into()],
            vec![Right::Read, Right::Write],
            1_700_000_000_000,
            None,
        );
        cap.sign(root_sk).unwrap();
        cap
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk = root_sk.verifying_key().to_bytes();
        let bob_ephemeral_sk = XSk::random_from_rng(OsRng);
        let bob_ephemeral_pk = XPub::from(&bob_ephemeral_sk).to_bytes();

        let nonce = [9u8; 32];
        let grant = sample_grant(root_pk, signed_cap(&root_sk, [7u8; 32]), nonce);

        let env = PairGrantEnvelope::seal_and_sign(&grant, &bob_ephemeral_pk, &root_sk).unwrap();
        let opened = env.open_and_verify(&bob_ephemeral_sk, &nonce).unwrap();
        assert_eq!(opened.nonce, nonce);
        assert_eq!(opened.cap.agent, [7u8; 32]);
    }

    #[test]
    fn tampered_signature_rejected() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk = root_sk.verifying_key().to_bytes();
        let bob_ephemeral_sk = XSk::random_from_rng(OsRng);
        let bob_ephemeral_pk = XPub::from(&bob_ephemeral_sk).to_bytes();
        let grant = sample_grant([0u8; 32], signed_cap(&root_sk, [7u8; 32]), [9u8; 32]);
        let mut env = PairGrantEnvelope::seal_and_sign(&grant, &bob_ephemeral_pk, &root_sk).unwrap();
        // mutate root_pubkey to break the signature scope
        env.root_pubkey = root_pk; // doesn't match what was signed (which was [0u8;32])
        assert!(env.open_and_verify(&bob_ephemeral_sk, &[9u8; 32]).is_err());
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk = root_sk.verifying_key().to_bytes();
        let bob_sk = XSk::random_from_rng(OsRng);
        let bob_pk = XPub::from(&bob_sk).to_bytes();
        let mallory_sk = XSk::random_from_rng(OsRng);

        let nonce = [9u8; 32];
        let grant = sample_grant(root_pk, signed_cap(&root_sk, [7u8; 32]), nonce);
        let env = PairGrantEnvelope::seal_and_sign(&grant, &bob_pk, &root_sk).unwrap();
        assert!(env.open_and_verify(&mallory_sk, &nonce).is_err());
    }

    #[test]
    fn wrong_nonce_aad_fails() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk = root_sk.verifying_key().to_bytes();
        let bob_sk = XSk::random_from_rng(OsRng);
        let bob_pk = XPub::from(&bob_sk).to_bytes();
        let grant = sample_grant(root_pk, signed_cap(&root_sk, [7u8; 32]), [9u8; 32]);
        let env = PairGrantEnvelope::seal_and_sign(&grant, &bob_pk, &root_sk).unwrap();
        assert!(env.open_and_verify(&bob_sk, &[8u8; 32]).is_err());
    }
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p wires-net --lib pair::grant_tests`
Expected: 4 passed; 0 failed.

- [ ] **Step 7: Commit**

```bash
git add crates/wires-net/src/pair.rs crates/wires-net/src/lib.rs crates/wires-net/src/error.rs
git commit -m "$(cat <<'EOF'
feat(wires-net): PairGrant + sealed-box envelope crypto

Adds PairGrant inner payload (cap, topic keys, topic names, host info, nonce
echo) and PairGrantEnvelope outer wire shape. Envelope crypto reuses
wires-crypto::sealed::seal_to with the pair nonce as topic_id and a
domain-separated AAD, then ed25519-signs (root_pubkey || sealed_payload)
with the root key. Tampering or wrong-recipient decryption fail closed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `PairFrame` + framing + reject codes

**Files:**
- Modify: `crates/wires-net/src/pair.rs`

- [ ] **Step 1: Add the frame types and reject codes**

Append to `crates/wires-net/src/pair.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairFrame {
    Grant(PairGrantEnvelope),
    Ack(PairAck),
    Reject(PairReject),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairAck {
    #[serde(with = "hex::serde")]
    pub installed_cap_id: [u8; 16],
    pub installed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairReject {
    pub code: PairRejectCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairRejectCode {
    NonceMismatch,
    NonceExpired,
    SignatureInvalid,
    SealUndecryptable,
    RootMismatch,
    CapInvalid,
    UnknownTopic,
    AlreadyPaired,
    InternalError,
}
```

- [ ] **Step 2: Write frame round-trip tests**

Append to `crates/wires-net/src/pair.rs`:

```rust
#[cfg(test)]
mod frame_tests {
    use super::*;

    #[test]
    fn grant_frame_roundtrip() {
        let env = PairGrantEnvelope {
            root_pubkey: [1u8; 32],
            sealed_payload: vec![0x10, 0x11, 0x12],
            signature: [2u8; 64],
        };
        let f = PairFrame::Grant(env);
        let j = serde_json::to_vec(&f).unwrap();
        let back: PairFrame = serde_json::from_slice(&j).unwrap();
        match back {
            PairFrame::Grant(e) => assert_eq!(e.sealed_payload, vec![0x10, 0x11, 0x12]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn ack_frame_roundtrip() {
        let f = PairFrame::Ack(PairAck { installed_cap_id: [9u8; 16], installed_at: 42 });
        let j = serde_json::to_vec(&f).unwrap();
        let back: PairFrame = serde_json::from_slice(&j).unwrap();
        assert!(matches!(back, PairFrame::Ack(_)));
    }

    #[test]
    fn reject_frame_carries_code_and_message() {
        let f = PairFrame::Reject(PairReject {
            code: PairRejectCode::NonceMismatch,
            message: "nonce".into(),
        });
        let j = serde_json::to_vec(&f).unwrap();
        let back: PairFrame = serde_json::from_slice(&j).unwrap();
        match back {
            PairFrame::Reject(r) => {
                assert_eq!(r.code, PairRejectCode::NonceMismatch);
                assert_eq!(r.message, "nonce");
            }
            _ => panic!("wrong variant"),
        }
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p wires-net --lib pair::frame_tests`
Expected: 3 passed; 0 failed.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-net/src/pair.rs
git commit -m "$(cat <<'EOF'
feat(wires-net): PairFrame + reject codes

Frame layer for the /wires/pair/0 protocol: one Grant frame from client,
one Ack-or-Reject from server. PairRejectCode enumerates the public
protocol-level failure surface.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `PairProtocol` server (iroh ProtocolHandler)

**Files:**
- Modify: `crates/wires-net/src/pair.rs`
- Reference: `crates/wires-net/src/tenant.rs` for the iroh `ProtocolHandler` boilerplate to mirror.

- [ ] **Step 1: Add the `PairHandler` trait and protocol struct**

Append to `crates/wires-net/src/pair.rs`:

```rust
use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

#[async_trait]
pub trait PairHandler: Send + Sync + 'static {
    async fn handle_grant(&self, envelope: PairGrantEnvelope) -> PairFrame;
}

/// iroh ProtocolHandler for `/wires/pair/0`. Reads one Grant, calls the handler,
/// writes back one Ack or Reject, closes the stream. Serializes concurrent
/// dials with an internal mutex so the handler observes one grant at a time.
#[derive(Clone)]
pub struct PairProtocol<H: PairHandler> {
    handler: Arc<H>,
    serializer: Arc<Mutex<()>>,
}

impl<H: PairHandler> PairProtocol<H> {
    pub fn new(handler: Arc<H>) -> Self {
        Self {
            handler,
            serializer: Arc::new(Mutex::new(())),
        }
    }
}
```

- [ ] **Step 2: Implement `iroh::protocol::ProtocolHandler`**

Mirror the pattern in `crates/wires-net/src/tenant.rs` (search for `impl iroh::protocol::ProtocolHandler` in that file and copy the structure). The body for `accept` reads:

```rust
impl<H: PairHandler> iroh::protocol::ProtocolHandler for PairProtocol<H> {
    fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), iroh::protocol::AcceptError>> + Send>>
    {
        let handler = self.handler.clone();
        let serializer = self.serializer.clone();
        Box::pin(async move {
            let (mut send, mut recv) = connection
                .accept_bi()
                .await
                .map_err(|e| iroh::protocol::AcceptError::from_err(e))?;
            let raw = crate::framing::read_frame(&mut recv, MAX_FRAME_LEN)
                .await
                .map_err(iroh::protocol::AcceptError::from_err)?;
            let frame: PairFrame = serde_json::from_slice(&raw)
                .map_err(iroh::protocol::AcceptError::from_err)?;
            let envelope = match frame {
                PairFrame::Grant(e) => e,
                _ => {
                    let reject = PairFrame::Reject(PairReject {
                        code: PairRejectCode::InternalError,
                        message: "expected Grant frame".into(),
                    });
                    let bytes = serde_json::to_vec(&reject)
                        .map_err(iroh::protocol::AcceptError::from_err)?;
                    crate::framing::write_frame(&mut send, &bytes)
                        .await
                        .map_err(iroh::protocol::AcceptError::from_err)?;
                    send.finish().ok();
                    return Ok(());
                }
            };
            let resp_frame = {
                let _g = serializer.lock().await;
                handler.handle_grant(envelope).await
            };
            let bytes = serde_json::to_vec(&resp_frame)
                .map_err(iroh::protocol::AcceptError::from_err)?;
            crate::framing::write_frame(&mut send, &bytes)
                .await
                .map_err(iroh::protocol::AcceptError::from_err)?;
            send.finish().ok();
            Ok(())
        })
    }
}
```

If `tenant.rs` shows a slightly different shape for the `AcceptError::from_err` calls, follow that file's exact pattern — `iroh` minor versions sometimes shift this API.

- [ ] **Step 3: Update Cargo.toml**

Add `async-trait = "0.1"` to `crates/wires-net/Cargo.toml` under `[dependencies]` if it isn't already there (tenant.rs uses the same).

- [ ] **Step 4: Write a stub-handler unit test that drives the protocol in-process**

Add an integration test at `crates/wires-net/tests/pair_protocol.rs`:

```rust
use std::sync::Arc;

use async_trait::async_trait;
use iroh::Endpoint;
use wires_net::pair::{
    ALPN, MAX_FRAME_LEN, PairAck, PairFrame, PairGrantEnvelope, PairHandler, PairProtocol,
    PairReject, PairRejectCode,
};

struct CannedAck;
#[async_trait]
impl PairHandler for CannedAck {
    async fn handle_grant(&self, _env: PairGrantEnvelope) -> PairFrame {
        PairFrame::Ack(PairAck {
            installed_cap_id: [0u8; 16],
            installed_at: 1,
        })
    }
}

struct CannedReject;
#[async_trait]
impl PairHandler for CannedReject {
    async fn handle_grant(&self, _env: PairGrantEnvelope) -> PairFrame {
        PairFrame::Reject(PairReject {
            code: PairRejectCode::NonceMismatch,
            message: "bad nonce".into(),
        })
    }
}

#[tokio::test]
async fn handler_returns_ack() {
    // Start a server with CannedAck, dial it from a client endpoint, send a
    // bogus Grant frame, observe the Ack come back.
    let server_ep = Endpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_addr = server_ep.node_addr().initialized().await;
    let proto = PairProtocol::new(Arc::new(CannedAck));
    let router = iroh::protocol::Router::builder(server_ep)
        .accept(ALPN, proto)
        .spawn();

    let client_ep = Endpoint::builder().bind().await.unwrap();
    let conn = client_ep.connect(server_addr, ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let env = PairGrantEnvelope {
        root_pubkey: [0u8; 32],
        sealed_payload: vec![0xaa],
        signature: [0u8; 64],
    };
    let bytes = serde_json::to_vec(&PairFrame::Grant(env)).unwrap();
    wires_net::framing::write_frame(&mut send, &bytes).await.unwrap();
    send.finish().ok();
    let raw = wires_net::framing::read_frame(&mut recv, MAX_FRAME_LEN).await.unwrap();
    let frame: PairFrame = serde_json::from_slice(&raw).unwrap();
    assert!(matches!(frame, PairFrame::Ack(_)));
    router.shutdown().await.ok();
}

#[tokio::test]
async fn handler_returns_reject() {
    let server_ep = Endpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_addr = server_ep.node_addr().initialized().await;
    let proto = PairProtocol::new(Arc::new(CannedReject));
    let router = iroh::protocol::Router::builder(server_ep)
        .accept(ALPN, proto)
        .spawn();

    let client_ep = Endpoint::builder().bind().await.unwrap();
    let conn = client_ep.connect(server_addr, ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let env = PairGrantEnvelope {
        root_pubkey: [0u8; 32],
        sealed_payload: vec![0xbb],
        signature: [0u8; 64],
    };
    let bytes = serde_json::to_vec(&PairFrame::Grant(env)).unwrap();
    wires_net::framing::write_frame(&mut send, &bytes).await.unwrap();
    send.finish().ok();
    let raw = wires_net::framing::read_frame(&mut recv, MAX_FRAME_LEN).await.unwrap();
    let frame: PairFrame = serde_json::from_slice(&raw).unwrap();
    match frame {
        PairFrame::Reject(r) => assert_eq!(r.code, PairRejectCode::NonceMismatch),
        _ => panic!("expected Reject"),
    }
    router.shutdown().await.ok();
}
```

If the exact iroh `Endpoint::builder()` / `Router::builder(...).accept(...).spawn()` shape differs from what tenant tests use, copy the working pattern from `crates/wires-net/tests/` (look for any test that already spawns a Router).

- [ ] **Step 5: Run tests**

Run: `cargo test -p wires-net --test pair_protocol`
Expected: 2 passed; 0 failed. (May take 5–15s on a cold machine due to iroh warm-up — see CLAUDE.md's note about cold-start flakiness.)

- [ ] **Step 6: Commit**

```bash
git add crates/wires-net/src/pair.rs crates/wires-net/tests/pair_protocol.rs crates/wires-net/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(wires-net): PairProtocol iroh ProtocolHandler for /wires/pair/0

Server-side handler trait (PairHandler) + iroh ProtocolHandler impl. One
Grant in, one Ack-or-Reject out, then close. A tokio Mutex serializes
concurrent dials so the handler observes grants one at a time.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `PairClient` for Alice's dial-and-send

**Files:**
- Modify: `crates/wires-net/src/pair.rs`

- [ ] **Step 1: Add `PairClient` and `deliver_grant`**

Append to `crates/wires-net/src/pair.rs`:

```rust
use iroh::endpoint::Endpoint;

#[derive(Clone)]
pub struct PairClient {
    endpoint: Endpoint,
}

impl PairClient {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Dial `dial.node_id`, send a Grant frame, await one Ack or Reject frame,
    /// then close. Maps `Reject` into `NetError::PairRejected`.
    pub async fn deliver_grant(
        &self,
        dial: &PairDial,
        envelope: PairGrantEnvelope,
    ) -> Result<PairAck> {
        let node_id_bytes = hex::decode(&dial.node_id).map_err(|_| NetError::PairDial {
            message: format!("invalid node_id hex: {}", dial.node_id),
            location: snafu::location!(),
        })?;
        let node_id_arr: [u8; 32] = node_id_bytes
            .try_into()
            .map_err(|_| NetError::PairDial {
                message: "node_id must be 32 bytes".into(),
                location: snafu::location!(),
            })?;
        let mut node_addr = iroh::NodeAddr::new(node_id_arr.into());
        for a in &dial.addrs {
            if let Ok(sa) = a.parse() {
                node_addr = node_addr.with_direct_addresses([sa]);
            }
        }
        if let Some(r) = &dial.relay {
            if let Ok(url) = r.parse() {
                node_addr = node_addr.with_relay_url(url);
            }
        }

        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.endpoint.connect(node_addr, ALPN),
        )
        .await
        .map_err(|_| NetError::PairDial {
            message: "dial timeout".into(),
            location: snafu::location!(),
        })?
        .map_err(|e| NetError::PairDial {
            message: format!("{e}"),
            location: snafu::location!(),
        })?;

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| NetError::PairStream {
            message: format!("open_bi: {e}"),
            location: snafu::location!(),
        })?;
        let bytes = serde_json::to_vec(&PairFrame::Grant(envelope)).context(SerdeSnafu)?;
        crate::framing::write_frame(&mut send, &bytes).await.map_err(|e| NetError::PairStream {
            message: format!("write_frame: {e}"),
            location: snafu::location!(),
        })?;
        send.finish().ok();
        let raw = crate::framing::read_frame(&mut recv, MAX_FRAME_LEN).await.map_err(|e| {
            NetError::PairStream {
                message: format!("read_frame: {e}"),
                location: snafu::location!(),
            }
        })?;
        let frame: PairFrame = serde_json::from_slice(&raw).context(SerdeSnafu)?;
        match frame {
            PairFrame::Ack(a) => Ok(a),
            PairFrame::Reject(r) => Err(NetError::PairRejected {
                code: r.code,
                message: r.message,
                location: snafu::location!(),
            }),
            PairFrame::Grant(_) => Err(NetError::PairStream {
                message: "server returned Grant frame".into(),
                location: snafu::location!(),
            }),
        }
    }
}
```

- [ ] **Step 2: Add the new error variants**

Append to `crates/wires-net/src/error.rs`:

```rust
    #[snafu(display("Pair dial failed: {message}, at {location}"))]
    PairDial {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair stream error: {message}, at {location}"))]
    PairStream {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair rejected by responder: {code:?}: {message}, at {location}"))]
    PairRejected {
        code: crate::pair::PairRejectCode,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
```

- [ ] **Step 3: Re-export `PairClient`, `PairAck`, `PairReject`, `PairRejectCode`**

Extend the pair re-export block in `crates/wires-net/src/lib.rs` to:

```rust
pub use pair::{
    ALPN as PAIR_ALPN, HostInfo as PairHostInfo, PairAck, PairClient, PairDial, PairFrame,
    PairGrant, PairGrantEnvelope, PairHandler, PairManifest, PairProtocol, PairReject,
    PairRejectCode, PairRequest, RequestedScope, TopicEpochKey, TopicNameEntry,
};
```

- [ ] **Step 4: Write an end-to-end integration test**

Append to `crates/wires-net/tests/pair_protocol.rs` an end-to-end test that uses `PairClient::deliver_grant` against the same `CannedAck`/`CannedReject` stubs:

```rust
use wires_net::pair::PairClient;

#[tokio::test]
async fn client_deliver_grant_returns_ack() {
    let server_ep = Endpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_addr = server_ep.node_addr().initialized().await;
    let proto = PairProtocol::new(Arc::new(CannedAck));
    let router = iroh::protocol::Router::builder(server_ep)
        .accept(ALPN, proto)
        .spawn();

    let client_ep = Endpoint::builder().bind().await.unwrap();
    let client = PairClient::new(client_ep);
    let dial = wires_net::pair::PairDial {
        node_id: hex::encode(server_addr.node_id.as_bytes()),
        addrs: server_addr
            .direct_addresses()
            .map(|a| a.to_string())
            .collect(),
        relay: server_addr.relay_url().map(|u| u.to_string()),
    };
    let env = PairGrantEnvelope {
        root_pubkey: [0u8; 32],
        sealed_payload: vec![0xab],
        signature: [0u8; 64],
    };
    let ack = client.deliver_grant(&dial, env).await.unwrap();
    assert_eq!(ack.installed_cap_id, [0u8; 16]);
    router.shutdown().await.ok();
}

#[tokio::test]
async fn client_surfaces_reject_as_error() {
    let server_ep = Endpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_addr = server_ep.node_addr().initialized().await;
    let proto = PairProtocol::new(Arc::new(CannedReject));
    let router = iroh::protocol::Router::builder(server_ep)
        .accept(ALPN, proto)
        .spawn();

    let client_ep = Endpoint::builder().bind().await.unwrap();
    let client = PairClient::new(client_ep);
    let dial = wires_net::pair::PairDial {
        node_id: hex::encode(server_addr.node_id.as_bytes()),
        addrs: server_addr
            .direct_addresses()
            .map(|a| a.to_string())
            .collect(),
        relay: server_addr.relay_url().map(|u| u.to_string()),
    };
    let env = PairGrantEnvelope {
        root_pubkey: [0u8; 32],
        sealed_payload: vec![0xcd],
        signature: [0u8; 64],
    };
    let err = client.deliver_grant(&dial, env).await.unwrap_err();
    assert!(format!("{err}").contains("NonceMismatch"));
    router.shutdown().await.ok();
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p wires-net --test pair_protocol`
Expected: 4 passed; 0 failed.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-net/src/pair.rs crates/wires-net/src/error.rs \
        crates/wires-net/src/lib.rs crates/wires-net/tests/pair_protocol.rs
git commit -m "$(cat <<'EOF'
feat(wires-net): PairClient dialer for /wires/pair/0

PairClient::deliver_grant resolves a PairDial into an iroh NodeAddr, opens
a stream, writes one Grant frame, awaits Ack or Reject. Reject maps to
NetError::PairRejected with the code + message. 30s dial timeout.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `pair_pending.json` I/O helper

**Files:**
- Create: `crates/wires-cli/src/pair_pending.rs`
- Modify: `crates/wires-cli/src/lib.rs`

- [ ] **Step 1: Add the module declaration**

Insert `pub mod pair_pending;` into `crates/wires-cli/src/lib.rs`.

- [ ] **Step 2: Write the type + I/O**

Create `crates/wires-cli/src/pair_pending.rs`:

```rust
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const FILE_NAME: &str = "pair_pending.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairPending {
    pub version: u8,
    pub nonce_hex: String,
    pub ephemeral_x25519_secret_hex: String,
    pub expires_unix_ms: i64,
    pub request_token: String,
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

pub fn save(data_dir: &Path, p: &PairPending) -> std::io::Result<()> {
    let s = serde_json::to_string_pretty(p).expect("PairPending serializes");
    write_secret(&path(data_dir), s.as_bytes())
}

pub fn load(data_dir: &Path) -> std::io::Result<Option<PairPending>> {
    let p = path(data_dir);
    if !p.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(&p)?;
    let parsed = serde_json::from_str(&s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(parsed))
}

pub fn delete(data_dir: &Path) -> std::io::Result<()> {
    let p = path(data_dir);
    if p.exists() {
        std::fs::remove_file(p)?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}
```

- [ ] **Step 3: Write tests**

Append to `crates/wires-cli/src/pair_pending.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn save_load_delete_roundtrip() {
        let td = TempDir::new().unwrap();
        let p = PairPending {
            version: 1,
            nonce_hex: "aa".repeat(32),
            ephemeral_x25519_secret_hex: "bb".repeat(32),
            expires_unix_ms: 1_700_000_300_000,
            request_token: "tok".into(),
        };
        save(td.path(), &p).unwrap();
        assert!(path(td.path()).exists());
        let back = load(td.path()).unwrap().expect("present");
        assert_eq!(back.nonce_hex, p.nonce_hex);
        delete(td.path()).unwrap();
        assert!(!path(td.path()).exists());
        assert!(load(td.path()).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn save_uses_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        save(
            td.path(),
            &PairPending {
                version: 1,
                nonce_hex: "00".repeat(32),
                ephemeral_x25519_secret_hex: "11".repeat(32),
                expires_unix_ms: 0,
                request_token: "".into(),
            },
        )
        .unwrap();
        let mode = std::fs::metadata(path(td.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
```

If `tempfile` is not yet in `crates/wires-cli/Cargo.toml`'s `[dev-dependencies]`, add `tempfile = "3"`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p wires-cli --lib pair_pending`
Expected: 2 passed; 0 failed.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-cli/src/pair_pending.rs crates/wires-cli/src/lib.rs crates/wires-cli/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(wires-cli): pair_pending.json I/O helper

Persists the in-flight pair-listen state (nonce, ephemeral X25519 secret,
expiry, original request token) at mode 0600 in the data dir. Allows
crash-recovery resume of an open pair-listen window.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `install_grant` transactional helper

**Files:**
- Create: `crates/wires-node/src/pair.rs`
- Modify: `crates/wires-node/src/lib.rs`

- [ ] **Step 1: Add the module + install function**

Create `crates/wires-node/src/pair.rs`:

```rust
//! Pair-grant installation logic. Verifies a decrypted PairGrant and writes
//! every artifact Bob needs to become a fully-onboarded household member.

use std::path::Path;

use snafu::{ResultExt, ensure};
use wires_core::Capability;
use wires_net::pair::{PairGrant, TopicNameEntry};

use crate::config::NodeConfig;
use crate::error::{
    AgentMismatchSnafu, BadCapSnafu, ConfigWriteSnafu, EpochKeySnafu, NodeError, Result,
    TopicNamesWriteSnafu, UpsertCapSnafu, UnknownTopicSnafu,
};
use crate::node::Node;

pub struct InstallOutcome {
    pub cap_id: [u8; 16],
}

pub fn install_grant(
    data_dir: &Path,
    node: &Node,
    self_agent_pubkey: &[u8; 32],
    grant: &PairGrant,
) -> Result<InstallOutcome> {
    // 1. Cap target sanity.
    ensure!(&grant.cap.agent == self_agent_pubkey, AgentMismatchSnafu);
    // 2. Cap signed by the claimed root.
    grant.cap.verify(&grant.root_pubkey).context(BadCapSnafu)?;
    // 3. Every topic_key references a topic that has a name entry.
    for tk in &grant.topic_keys {
        ensure!(
            grant.topic_names.iter().any(|n| n.topic_id == tk.topic_id),
            UnknownTopicSnafu { topic_id_hex: hex::encode(tk.topic_id) }
        );
    }

    // 4. config.toml — root pubkey + optional host info.
    let cfg_path = data_dir.join("config.toml");
    let mut cfg: NodeConfig = if cfg_path.exists() {
        toml::from_str(&std::fs::read_to_string(&cfg_path).context(ConfigWriteSnafu)?)
            .map_err(|e| NodeError::ConfigWrite {
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                location: snafu::location!(),
            })?
    } else {
        NodeConfig {
            data_dir: data_dir.to_path_buf(),
            root_pubkey_hex: String::new(),
            host: None,
        }
    };
    cfg.root_pubkey_hex = hex::encode(grant.root_pubkey);
    if let Some(host) = &grant.host {
        cfg.host = Some(crate::config::HostConfig {
            peer_hints: host.peer_hints.clone(),
            discovery_url: host.service_discovery_url.clone(),
        });
    }
    std::fs::write(
        &cfg_path,
        toml::to_string_pretty(&cfg).map_err(|e| NodeError::ConfigWrite {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            location: snafu::location!(),
        })?,
    )
    .context(ConfigWriteSnafu)?;

    // 5. topic_names.json — merge new entries.
    write_topic_names(data_dir, &grant.topic_names)?;

    // 6. Epoch keys.
    for tk in &grant.topic_keys {
        node.install_epoch_key(tk.topic_id, tk.epoch, tk.key)
            .context(EpochKeySnafu)?;
    }

    // 7. The cap itself, last so the invariant "keys ⟹ cap" never inverts.
    node.caps.upsert_grant(&grant.cap).context(UpsertCapSnafu)?;

    Ok(InstallOutcome {
        cap_id: grant.cap.cap_id.0,
    })
}

fn write_topic_names(data_dir: &Path, entries: &[TopicNameEntry]) -> Result<()> {
    let p = data_dir.join("topic_names.json");
    let mut map: std::collections::HashMap<String, String> = if p.exists() {
        serde_json::from_str(&std::fs::read_to_string(&p).context(TopicNamesWriteSnafu)?)
            .map_err(|e| NodeError::TopicNamesWrite {
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                location: snafu::location!(),
            })?
    } else {
        std::collections::HashMap::new()
    };
    for entry in entries {
        map.insert(entry.name.clone(), hex::encode(entry.topic_id));
    }
    std::fs::write(
        &p,
        serde_json::to_string_pretty(&map).expect("HashMap serializes"),
    )
    .context(TopicNamesWriteSnafu)?;
    Ok(())
}
```

- [ ] **Step 2: Add the corresponding error variants**

Append to `crates/wires-node/src/error.rs`:

```rust
    #[snafu(display("Pair-grant cap targets a different agent, at {location}"))]
    AgentMismatch {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair-grant cap failed root verification, at {location}"))]
    BadCap {
        #[snafu(source(from(wires_core::Error, Box::new)))]
        source: Box<wires_core::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair-grant references unknown topic_id {topic_id_hex}, at {location}"))]
    UnknownTopic {
        topic_id_hex: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to write config.toml: {source}, at {location}"))]
    ConfigWrite {
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to write topic_names.json: {source}, at {location}"))]
    TopicNamesWrite {
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to upsert cap: {source}, at {location}"))]
    UpsertCap {
        #[snafu(source(from(wires_store::Error, Box::new)))]
        source: Box<wires_store::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to install epoch key: {source}, at {location}"))]
    EpochKey {
        #[snafu(source(from(wires_store::Error, Box::new)))]
        source: Box<wires_store::Error>,
        #[snafu(implicit)]
        location: Location,
    },
```

Adjust source paths if `wires_core::Error` or `wires_store::Error` use different concrete names — `cargo build -p wires-node` will pinpoint mismatches.

- [ ] **Step 3: Register the new module**

Edit `crates/wires-node/src/lib.rs`: add `pub mod pair;` and re-export `pub use pair::{InstallOutcome, install_grant};`.

- [ ] **Step 4: Write integration tests**

Create `crates/wires-node/tests/pair_install.rs`:

```rust
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::cap::Right;
use wires_core::Capability;
use wires_net::pair::{HostInfo, PairGrant, TopicEpochKey, TopicNameEntry};
use wires_node::{Node, NodeConfig, install_grant};

fn fresh_node(td: &TempDir) -> (Node, SigningKey, [u8; 32]) {
    // wires init equivalent: write identity + minimal config
    let agent_sk = SigningKey::generate(&mut OsRng);
    let agent_pk = agent_sk.verifying_key().to_bytes();
    std::fs::write(td.path().join("identity.ed25519"), agent_sk.to_bytes()).unwrap();
    let xsk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    std::fs::write(td.path().join("identity.x25519"), xsk.to_bytes()).unwrap();
    let cfg = NodeConfig {
        data_dir: td.path().to_path_buf(),
        root_pubkey_hex: String::new(),
        host: None,
    };
    std::fs::write(td.path().join("config.toml"), toml::to_string_pretty(&cfg).unwrap()).unwrap();
    let node = Node::open(cfg).unwrap();
    (node, agent_sk, agent_pk)
}

fn make_signed_cap(root_sk: &SigningKey, agent_pk: [u8; 32]) -> Capability {
    let mut cap = Capability::new_unsigned(
        agent_pk,
        vec!["home.notes".into()],
        vec![Right::Read, Right::Write],
        1_700_000_000_000,
        None,
    );
    cap.sign(root_sk).unwrap();
    cap
}

#[test]
fn happy_path_installs_all_artifacts() {
    let td = TempDir::new().unwrap();
    let (node, _agent_sk, agent_pk) = fresh_node(&td);
    let root_sk = SigningKey::generate(&mut OsRng);
    let root_pk = root_sk.verifying_key().to_bytes();
    let topic_id = [42u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_pk,
        cap: make_signed_cap(&root_sk, agent_pk),
        topic_keys: vec![TopicEpochKey { topic_id, epoch: 0, key: [7u8; 32] }],
        topic_names: vec![TopicNameEntry { topic_id, name: "home.notes".into() }],
        host: None,
        nonce: [9u8; 32],
        issued_at: 1_700_000_000_000,
    };
    let out = install_grant(td.path(), &node, &agent_pk, &grant).unwrap();
    assert_eq!(out.cap_id, grant.cap.cap_id.0);
    // config.toml has root pubkey
    let cfg: NodeConfig = toml::from_str(
        &std::fs::read_to_string(td.path().join("config.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(cfg.root_pubkey_hex, hex::encode(root_pk));
    // topic_names.json has the entry
    let names: std::collections::HashMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(td.path().join("topic_names.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(names.get("home.notes"), Some(&hex::encode(topic_id)));
}

#[test]
fn rejects_cap_for_other_agent() {
    let td = TempDir::new().unwrap();
    let (node, _agent_sk, agent_pk) = fresh_node(&td);
    let root_sk = SigningKey::generate(&mut OsRng);
    let bogus_target = [0xfe; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: make_signed_cap(&root_sk, bogus_target),
        topic_keys: vec![],
        topic_names: vec![],
        host: None,
        nonce: [9u8; 32],
        issued_at: 1_700_000_000_000,
    };
    assert!(install_grant(td.path(), &node, &agent_pk, &grant).is_err());
}

#[test]
fn rejects_cap_signed_by_wrong_root() {
    let td = TempDir::new().unwrap();
    let (node, _, agent_pk) = fresh_node(&td);
    let real_root = SigningKey::generate(&mut OsRng);
    let imposter_root = SigningKey::generate(&mut OsRng);
    let grant = PairGrant {
        version: 1,
        root_pubkey: real_root.verifying_key().to_bytes(),
        cap: make_signed_cap(&imposter_root, agent_pk), // cap not signed by real_root
        topic_keys: vec![],
        topic_names: vec![],
        host: None,
        nonce: [9u8; 32],
        issued_at: 0,
    };
    assert!(install_grant(td.path(), &node, &agent_pk, &grant).is_err());
}

#[test]
fn idempotent_on_replay() {
    let td = TempDir::new().unwrap();
    let (node, _, agent_pk) = fresh_node(&td);
    let root_sk = SigningKey::generate(&mut OsRng);
    let topic_id = [42u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: make_signed_cap(&root_sk, agent_pk),
        topic_keys: vec![TopicEpochKey { topic_id, epoch: 0, key: [7u8; 32] }],
        topic_names: vec![TopicNameEntry { topic_id, name: "home.notes".into() }],
        host: None,
        nonce: [9u8; 32],
        issued_at: 0,
    };
    let a = install_grant(td.path(), &node, &agent_pk, &grant).unwrap();
    let b = install_grant(td.path(), &node, &agent_pk, &grant).unwrap();
    assert_eq!(a.cap_id, b.cap_id);
}
```

If `NodeConfig.host` doesn't exist as `Option<HostConfig>` in the codebase, replace the lookup with whatever exists today (it's mentioned in CLAUDE.md and used in the existing `wires host pair` flow — `crates/wires-cli/src/cmd/host.rs` is the place to copy the shape from).

- [ ] **Step 5: Run tests**

Run: `cargo test -p wires-node --test pair_install`
Expected: 4 passed; 0 failed.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-node/src/pair.rs crates/wires-node/src/error.rs \
        crates/wires-node/src/lib.rs crates/wires-node/tests/pair_install.rs
git commit -m "$(cat <<'EOF'
feat(wires-node): install_grant — transactional, idempotent pair install

Verifies a decrypted PairGrant (cap targets self, signed by claimed root,
every topic key has a name) then writes config.toml, topic_names.json,
epoch keys, and the cap in the prescribed order. Idempotent on replay.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `NodePairHandler` — wires verification → install → outcome

**Files:**
- Modify: `crates/wires-node/src/pair.rs`

- [ ] **Step 1: Add the handler type**

Append to `crates/wires-node/src/pair.rs`:

```rust
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};
use wires_net::pair::{
    PairAck, PairFrame, PairGrantEnvelope, PairHandler, PairReject, PairRejectCode,
};
use x25519_dalek::StaticSecret;

/// Outcome signaled to the outer pair-listen loop.
#[derive(Debug)]
pub enum PairOutcome {
    Paired { cap_id: [u8; 16] },
}

/// Concrete PairHandler that verifies a PairGrantEnvelope against the
/// in-memory pending pair state, installs the grant, and signals the loop.
pub struct NodePairHandler {
    inner: Arc<Mutex<HandlerState>>,
}

struct HandlerState {
    data_dir: PathBuf,
    node: Arc<Node>,
    self_agent_pubkey: [u8; 32],
    expected_nonce: [u8; 32],
    ephemeral_secret: StaticSecret,
    request_expires_ms: i64,
    outcome_tx: Option<oneshot::Sender<PairOutcome>>,
    completed: bool,
}

impl NodePairHandler {
    pub fn new(
        data_dir: PathBuf,
        node: Arc<Node>,
        self_agent_pubkey: [u8; 32],
        expected_nonce: [u8; 32],
        ephemeral_secret: StaticSecret,
        request_expires_ms: i64,
        outcome_tx: oneshot::Sender<PairOutcome>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HandlerState {
                data_dir,
                node,
                self_agent_pubkey,
                expected_nonce,
                ephemeral_secret,
                request_expires_ms,
                outcome_tx: Some(outcome_tx),
                completed: false,
            })),
        }
    }
}

#[async_trait]
impl PairHandler for NodePairHandler {
    async fn handle_grant(&self, envelope: PairGrantEnvelope) -> PairFrame {
        let mut state = self.inner.lock().await;
        if state.completed {
            return reject(PairRejectCode::AlreadyPaired, "already paired in this window");
        }

        let grant = match envelope.open_and_verify(&state.ephemeral_secret, &state.expected_nonce) {
            Ok(g) => g,
            Err(e) => {
                let s = format!("{e}");
                if s.contains("PairSignature") {
                    return reject(PairRejectCode::SignatureInvalid, "signature invalid");
                }
                if s.contains("PairCrypto") {
                    return reject(PairRejectCode::SealUndecryptable, "sealed payload undecryptable");
                }
                return reject(PairRejectCode::InternalError, &s);
            }
        };

        if grant.root_pubkey != envelope.root_pubkey {
            return reject(PairRejectCode::RootMismatch, "inner/outer root mismatch");
        }
        if grant.nonce != state.expected_nonce {
            return reject(PairRejectCode::NonceMismatch, "nonce mismatch");
        }
        if grant.issued_at > state.request_expires_ms {
            return reject(PairRejectCode::NonceExpired, "grant issued after request expired");
        }

        match install_grant(&state.data_dir, &state.node, &state.self_agent_pubkey, &grant) {
            Ok(out) => {
                // Delete pair_pending before sending Ack so a crash post-Ack still
                // leaves the data dir consistent.
                if let Err(e) = wires_cli::pair_pending::delete(&state.data_dir) {
                    return reject(
                        PairRejectCode::InternalError,
                        &format!("delete pair_pending: {e}"),
                    );
                }
                state.completed = true;
                if let Some(tx) = state.outcome_tx.take() {
                    let _ = tx.send(PairOutcome::Paired { cap_id: out.cap_id });
                }
                PairFrame::Ack(PairAck {
                    installed_cap_id: out.cap_id,
                    installed_at: now_ms(),
                })
            }
            Err(e) => {
                let s = format!("{e}");
                let code = if s.contains("AgentMismatch") || s.contains("BadCap") {
                    PairRejectCode::CapInvalid
                } else if s.contains("UnknownTopic") {
                    PairRejectCode::CapInvalid
                } else {
                    PairRejectCode::InternalError
                };
                reject(code, &s)
            }
        }
    }
}

fn reject(code: PairRejectCode, msg: &str) -> PairFrame {
    PairFrame::Reject(PairReject {
        code,
        message: msg.to_string(),
    })
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
```

Note: this references `wires_cli::pair_pending::delete`. Add `wires-cli` as a workspace dependency of `wires-node` if it isn't already — check `crates/wires-node/Cargo.toml`. If adding creates a circular dependency (wires-cli depends on wires-node), invert: move `pair_pending.rs` from wires-cli into wires-node and re-export from wires-cli.

Likely outcome: `pair_pending` should live in `wires-node`, since both the handler and the CLI need it. Move it there as part of this step: delete `crates/wires-cli/src/pair_pending.rs`, create `crates/wires-node/src/pair_pending.rs` with the same content, re-export via `crates/wires-node/src/lib.rs` (`pub mod pair_pending;`), and have `crates/wires-cli` reference it as `wires_node::pair_pending::*`.

- [ ] **Step 2: Re-export the handler**

In `crates/wires-node/src/lib.rs`, add to the pair re-exports:

```rust
pub use pair::{InstallOutcome, NodePairHandler, PairOutcome, install_grant};
pub mod pair_pending;
```

(Remove the old `pub mod pair_pending;` from `wires-cli/src/lib.rs` and the file from `crates/wires-cli/src/`.)

- [ ] **Step 3: Write integration tests for each reject code path**

Create `crates/wires-node/tests/pair_handler.rs`:

```rust
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use tokio::sync::oneshot;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::pair::{
    HostInfo, PairFrame, PairGrant, PairGrantEnvelope, PairHandler, PairRejectCode,
    TopicEpochKey, TopicNameEntry,
};
use wires_node::{Node, NodeConfig, NodePairHandler, PairOutcome};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSk};

fn fresh_node_handler(td: &TempDir, expected_nonce: [u8; 32]) -> (NodePairHandler, [u8; 32], XSk, [u8; 32], oneshot::Receiver<PairOutcome>) {
    let agent_sk = SigningKey::generate(&mut OsRng);
    let agent_pk = agent_sk.verifying_key().to_bytes();
    std::fs::write(td.path().join("identity.ed25519"), agent_sk.to_bytes()).unwrap();
    let xsk = XSk::random_from_rng(OsRng);
    std::fs::write(td.path().join("identity.x25519"), xsk.to_bytes()).unwrap();
    let cfg = NodeConfig {
        data_dir: td.path().to_path_buf(),
        root_pubkey_hex: String::new(),
        host: None,
    };
    std::fs::write(td.path().join("config.toml"), toml::to_string_pretty(&cfg).unwrap()).unwrap();
    let node = Arc::new(Node::open(cfg).unwrap());

    let ephemeral_sk = XSk::random_from_rng(OsRng);
    let ephemeral_pk = XPub::from(&ephemeral_sk).to_bytes();
    let (tx, rx) = oneshot::channel();
    let handler = NodePairHandler::new(
        td.path().to_path_buf(),
        node,
        agent_pk,
        expected_nonce,
        ephemeral_sk,
        i64::MAX,
        tx,
    );
    (handler, agent_pk, XSk::random_from_rng(OsRng), ephemeral_pk, rx)
}

fn signed_cap(root_sk: &SigningKey, agent_pk: [u8; 32]) -> Capability {
    let mut cap = Capability::new_unsigned(
        agent_pk,
        vec!["home.notes".into()],
        vec![Right::Read, Right::Write],
        1_700_000_000_000,
        None,
    );
    cap.sign(root_sk).unwrap();
    cap
}

#[tokio::test]
async fn happy_path_returns_ack_and_signals_outcome() {
    let td = TempDir::new().unwrap();
    let nonce = [3u8; 32];
    let (handler, agent_pk, _unused, ephemeral_pk, mut rx) = fresh_node_handler(&td, nonce);
    let root_sk = SigningKey::generate(&mut OsRng);
    let topic_id = [44u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: signed_cap(&root_sk, agent_pk),
        topic_keys: vec![TopicEpochKey { topic_id, epoch: 0, key: [8u8; 32] }],
        topic_names: vec![TopicNameEntry { topic_id, name: "home.notes".into() }],
        host: None,
        nonce,
        issued_at: 1_700_000_000_000,
    };
    let env = PairGrantEnvelope::seal_and_sign(&grant, &ephemeral_pk, &root_sk).unwrap();
    let frame = handler.handle_grant(env).await;
    assert!(matches!(frame, PairFrame::Ack(_)));
    let outcome = rx.try_recv().unwrap();
    assert!(matches!(outcome, PairOutcome::Paired { .. }));
}

#[tokio::test]
async fn nonce_mismatch_yields_reject() {
    let td = TempDir::new().unwrap();
    let (handler, agent_pk, _u, ephemeral_pk, _rx) = fresh_node_handler(&td, [3u8; 32]);
    let root_sk = SigningKey::generate(&mut OsRng);
    let mut grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: signed_cap(&root_sk, agent_pk),
        topic_keys: vec![],
        topic_names: vec![],
        host: None,
        nonce: [3u8; 32], // matches handler expected
        issued_at: 0,
    };
    grant.nonce = [4u8; 32]; // now mismatched
    let env = PairGrantEnvelope::seal_and_sign(&grant, &ephemeral_pk, &root_sk).unwrap();
    let frame = handler.handle_grant(env).await;
    // The seal nonce inside seal_to is based on grant.nonce, so opening with
    // the handler's expected nonce [3u8;32] will fail before we even reach
    // the nonce-check — that maps to SealUndecryptable.
    match frame {
        PairFrame::Reject(r) => {
            assert!(matches!(
                r.code,
                PairRejectCode::SealUndecryptable | PairRejectCode::NonceMismatch
            ));
        }
        _ => panic!("expected Reject"),
    }
}

#[tokio::test]
async fn wrong_recipient_yields_seal_undecryptable() {
    let td = TempDir::new().unwrap();
    let nonce = [3u8; 32];
    let (handler, agent_pk, _u, _ephemeral_pk, _rx) = fresh_node_handler(&td, nonce);
    let root_sk = SigningKey::generate(&mut OsRng);
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: signed_cap(&root_sk, agent_pk),
        topic_keys: vec![],
        topic_names: vec![],
        host: None,
        nonce,
        issued_at: 0,
    };
    // Seal to a key Bob doesn't have:
    let mallory_pk = XPub::from(&XSk::random_from_rng(OsRng)).to_bytes();
    let env = PairGrantEnvelope::seal_and_sign(&grant, &mallory_pk, &root_sk).unwrap();
    let frame = handler.handle_grant(env).await;
    match frame {
        PairFrame::Reject(r) => assert_eq!(r.code, PairRejectCode::SealUndecryptable),
        _ => panic!("expected Reject"),
    }
}

#[tokio::test]
async fn already_paired_after_first_success() {
    let td = TempDir::new().unwrap();
    let nonce = [3u8; 32];
    let (handler, agent_pk, _u, ephemeral_pk, _rx) = fresh_node_handler(&td, nonce);
    let root_sk = SigningKey::generate(&mut OsRng);
    let topic_id = [44u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: signed_cap(&root_sk, agent_pk),
        topic_keys: vec![TopicEpochKey { topic_id, epoch: 0, key: [8u8; 32] }],
        topic_names: vec![TopicNameEntry { topic_id, name: "home.notes".into() }],
        host: None,
        nonce,
        issued_at: 0,
    };
    let env = PairGrantEnvelope::seal_and_sign(&grant, &ephemeral_pk, &root_sk).unwrap();
    let first = handler.handle_grant(env.clone()).await;
    assert!(matches!(first, PairFrame::Ack(_)));
    let second = handler.handle_grant(env).await;
    match second {
        PairFrame::Reject(r) => assert_eq!(r.code, PairRejectCode::AlreadyPaired),
        _ => panic!("expected AlreadyPaired"),
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wires-node --test pair_handler`
Expected: 4 passed; 0 failed.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-node/src/pair.rs crates/wires-node/src/lib.rs \
        crates/wires-node/src/pair_pending.rs crates/wires-node/tests/pair_handler.rs
git rm crates/wires-cli/src/pair_pending.rs 2>/dev/null || true
git add crates/wires-cli/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(wires-node): NodePairHandler glues verify → install → outcome

Concrete PairHandler that opens the sealed envelope with Bob's ephemeral
secret, verifies the inner payload against the pending nonce + TTL,
delegates to install_grant, deletes pair_pending.json, and signals the
outer pair-listen loop via oneshot. Each failure path maps to its
documented PairRejectCode.

Also moves pair_pending from wires-cli to wires-node so both layers can
use it without a circular dep.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: `NodeRuntime::pair_listen` runtime entry point

**Files:**
- Modify: `crates/wires-node/src/runtime.rs`
- Modify: `crates/wires-node/src/pair.rs` (add `listen` orchestration)

- [ ] **Step 1: Add the orchestration function**

Append to `crates/wires-node/src/pair.rs`:

```rust
use ed25519_dalek::SigningKey;
use rand_core::RngCore;
use wires_net::pair::{
    ALPN as PAIR_ALPN, PairDial, PairManifest, PairProtocol, PairRequest, RequestedScope,
};

pub struct PairListenArgs {
    pub manifest: PairManifest,
    pub ttl: std::time::Duration,
}

pub struct PairListenStarted {
    pub request_token: String,
    pub outcome: oneshot::Receiver<PairOutcome>,
    pub router: iroh::protocol::Router,
}

/// Spin up a pair-listen window: register the protocol on the router,
/// persist pair_pending.json, return the encoded PairRequest token and a
/// oneshot receiver for the outcome. Caller awaits the receiver with a
/// TTL deadline.
pub async fn pair_listen(
    data_dir: std::path::PathBuf,
    node: Arc<Node>,
    agent_sk: SigningKey,
    agent_x25519: [u8; 32],
    endpoint: iroh::Endpoint,
    args: PairListenArgs,
) -> Result<PairListenStarted> {
    // If a prior window left pair_pending.json behind, resume with its state.
    let pending = crate::pair_pending::load(&data_dir).map_err(|source| NodeError::ConfigWrite {
        source,
        location: snafu::location!(),
    })?;
    let (nonce, ephemeral_sk, request_token, request_expires_ms) = if let Some(p) = pending {
        let nonce_arr = hex_to_arr32(&p.nonce_hex)?;
        let secret_arr = hex_to_arr32(&p.ephemeral_x25519_secret_hex)?;
        (
            nonce_arr,
            StaticSecret::from(secret_arr),
            p.request_token,
            p.expires_unix_ms,
        )
    } else {
        let mut nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let ephemeral_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let ephemeral_pk = XPub::from(&ephemeral_sk).to_bytes();
        let agent_pk = agent_sk.verifying_key().to_bytes();
        let now = now_ms();
        let expires = now + args.ttl.as_millis() as i64;
        let dial = PairDial {
            node_id: hex::encode(endpoint.node_id().as_bytes()),
            addrs: endpoint
                .bound_sockets()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            relay: endpoint.home_relay().get().map(|u| u.to_string()),
        };
        let mut req = PairRequest {
            version: 1,
            agent_pubkey: agent_pk,
            agent_x25519,
            ephemeral_x25519: ephemeral_pk,
            dial,
            manifest: args.manifest,
            nonce,
            issued_at: now,
            expires,
            signature: [0u8; 64],
        };
        req.sign(&agent_sk).map_err(|source| NodeError::PairListenSign {
            source: Box::new(source),
            location: snafu::location!(),
        })?;
        let token = req.encode().map_err(|source| NodeError::PairListenSign {
            source: Box::new(source),
            location: snafu::location!(),
        })?;
        crate::pair_pending::save(
            &data_dir,
            &crate::pair_pending::PairPending {
                version: 1,
                nonce_hex: hex::encode(nonce),
                ephemeral_x25519_secret_hex: hex::encode(ephemeral_sk.to_bytes()),
                expires_unix_ms: expires,
                request_token: token.clone(),
            },
        )
        .map_err(|source| NodeError::ConfigWrite {
            source,
            location: snafu::location!(),
        })?;
        (nonce, ephemeral_sk, token, expires)
    };

    let (outcome_tx, outcome_rx) = oneshot::channel();
    let handler = Arc::new(NodePairHandler::new(
        data_dir,
        node,
        agent_sk.verifying_key().to_bytes(),
        nonce,
        ephemeral_sk,
        request_expires_ms,
        outcome_tx,
    ));
    let protocol = PairProtocol::new(handler);
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(PAIR_ALPN, protocol)
        .spawn();
    Ok(PairListenStarted {
        request_token,
        outcome: outcome_rx,
        router,
    })
}

fn hex_to_arr32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|_| NodeError::ConfigWrite {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, "bad hex"),
        location: snafu::location!(),
    })?;
    bytes
        .try_into()
        .map_err(|_| NodeError::ConfigWrite {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong length"),
            location: snafu::location!(),
        })
}
```

- [ ] **Step 2: Add the `PairListenSign` error variant**

Append to `crates/wires-node/src/error.rs`:

```rust
    #[snafu(display("Pair-listen sign/encode failed: {source}, at {location}"))]
    PairListenSign {
        source: Box<wires_net::error::NetError>,
        #[snafu(implicit)]
        location: Location,
    },
```

- [ ] **Step 3: Re-export `pair_listen`**

In `crates/wires-node/src/lib.rs`, add `pair::pair_listen` and `pair::{PairListenArgs, PairListenStarted}` to the re-exports.

- [ ] **Step 4: Write a full-lifecycle integration test**

Create `crates/wires-node/tests/pair_listen.rs`:

```rust
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::cap::Right;
use wires_core::Capability;
use wires_net::pair::{
    HostInfo, PairClient, PairDial, PairGrant, PairGrantEnvelope, PairManifest, PairRequest,
    RequestedScope, TopicEpochKey, TopicNameEntry,
};
use wires_node::{Node, NodeConfig, PairListenArgs, PairOutcome, pair_listen};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSk};

#[tokio::test]
async fn full_lifecycle_alice_dial_bob_install() {
    // --- Bob side: init data dir, open Node, start pair_listen
    let td = TempDir::new().unwrap();
    let agent_sk = SigningKey::generate(&mut OsRng);
    std::fs::write(td.path().join("identity.ed25519"), agent_sk.to_bytes()).unwrap();
    let xsk = XSk::random_from_rng(OsRng);
    let agent_x25519 = XPub::from(&xsk).to_bytes();
    std::fs::write(td.path().join("identity.x25519"), xsk.to_bytes()).unwrap();
    let cfg = NodeConfig {
        data_dir: td.path().to_path_buf(),
        root_pubkey_hex: String::new(),
        host: None,
    };
    std::fs::write(td.path().join("config.toml"), toml::to_string_pretty(&cfg).unwrap()).unwrap();
    let node = Arc::new(Node::open(cfg).unwrap());

    let endpoint = iroh::Endpoint::builder().bind().await.unwrap();
    let started = pair_listen(
        td.path().to_path_buf(),
        node,
        agent_sk.clone(),
        agent_x25519,
        endpoint,
        PairListenArgs {
            manifest: PairManifest {
                role: "chat-agent".into(),
                description: "Bob".into(),
                requested_scopes: vec![RequestedScope {
                    topic_name: "home.notes".into(),
                    rights: vec![Right::Read, Right::Write],
                }],
            },
            ttl: std::time::Duration::from_secs(60),
        },
    )
    .await
    .unwrap();

    let request = PairRequest::decode(&started.request_token).unwrap();
    request.verify().unwrap();

    // --- Alice side: forge a PairGrant, seal, sign, dial, await ack
    let root_sk = SigningKey::generate(&mut OsRng);
    let mut cap = Capability::new_unsigned(
        request.agent_pubkey,
        vec!["home.notes".into()],
        vec![Right::Read, Right::Write],
        1_700_000_000_000,
        None,
    );
    cap.sign(&root_sk).unwrap();
    let topic_id = [44u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap,
        topic_keys: vec![TopicEpochKey { topic_id, epoch: 0, key: [8u8; 32] }],
        topic_names: vec![TopicNameEntry { topic_id, name: "home.notes".into() }],
        host: None,
        nonce: request.nonce,
        issued_at: 1_700_000_000_000,
    };
    let env = PairGrantEnvelope::seal_and_sign(&grant, &request.ephemeral_x25519, &root_sk).unwrap();

    let alice_ep = iroh::Endpoint::builder().bind().await.unwrap();
    let client = PairClient::new(alice_ep);
    let ack = client.deliver_grant(&request.dial, env).await.unwrap();
    assert_eq!(ack.installed_cap_id, grant.cap.cap_id.0);

    // Bob's pair_listen oneshot signaled.
    let outcome = started.outcome.await.unwrap();
    assert!(matches!(outcome, PairOutcome::Paired { .. }));

    // pair_pending.json is gone, config.toml has root pubkey.
    assert!(!td.path().join("pair_pending.json").exists());
    let cfg_back: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    assert_eq!(cfg_back.root_pubkey_hex, hex::encode(root_sk.verifying_key().to_bytes()));

    started.router.shutdown().await.ok();
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p wires-node --test pair_listen`
Expected: 1 passed; 0 failed.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-node/src/pair.rs crates/wires-node/src/error.rs \
        crates/wires-node/src/lib.rs crates/wires-node/tests/pair_listen.rs
git commit -m "$(cat <<'EOF'
feat(wires-node): pair_listen runtime entry point

pair_listen() generates (or resumes) a PairRequest, writes pair_pending,
mounts PairProtocol on the iroh Router with a NodePairHandler, and
returns the encoded token plus a oneshot receiver for the outcome.
Caller blocks on outcome with a TTL deadline.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Rewrite `wires init`

**Files:**
- Modify: `crates/wires-cli/src/main.rs`
- Modify: `crates/wires-cli/src/cmd/init.rs`

- [ ] **Step 1: Update the clap subcommand**

Replace the `Init` variant in `crates/wires-cli/src/main.rs`:

```rust
    /// Initialize identity (Ed25519 + X25519) in the data directory.
    Init {
        /// Generate a fresh local root key in addition to identity. Use this for
        /// the household operator (Alice). Mutually exclusive with all other
        /// init flags. Without this flag, `init` writes identity only.
        #[arg(long)]
        new_root: bool,
    },
```

And update the match arm in `main`:

```rust
        Cmd::Init { new_root } => cmd::init::run(&data_dir, new_root).await,
```

- [ ] **Step 2: Rewrite `cmd/init.rs`**

Replace `crates/wires-cli/src/cmd/init.rs`:

```rust
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use wires_node::{Node, NodeConfig};

pub async fn run(data_dir: &Path, new_root: bool) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(data_dir)?;
    let root_pubkey_hex = if new_root {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        std::fs::write(data_dir.join("root.ed25519"), sk.to_bytes())?;
        println!("Generated local root pubkey: {pk_hex}");
        pk_hex
    } else {
        String::new()
    };
    let cfg = NodeConfig {
        data_dir: data_dir.to_path_buf(),
        root_pubkey_hex: root_pubkey_hex.clone(),
        host: None,
    };
    std::fs::write(data_dir.join("config.toml"), toml::to_string_pretty(&cfg)?)?;
    let _node = Node::open(cfg)?;
    println!("Initialized at {}", data_dir.display());
    if root_pubkey_hex.is_empty() {
        println!("(no root pinned — pair with an operator via `wires pair-listen` to attach to a household)");
    } else {
        println!("Root pubkey: {root_pubkey_hex}");
    }
    Ok(())
}
```

- [ ] **Step 3: Decide what `Node::open` does with an empty `root_pubkey_hex`**

Inspect `crates/wires-node/src/node.rs` (`Node::open`). If it currently parses `root_pubkey_hex` and errors on a non-hex value or wrong length, allow an empty string to mean "not yet pinned". Concretely: change the `root_pubkey: Option<[u8; 32]>` field in `Node` (or wherever it's stored) to be `None` when `root_pubkey_hex.is_empty()`.

Search for the existing parse: `grep -n "root_pubkey_hex" crates/wires-node/src/`. Update the parse site to:

```rust
let root_pubkey = if cfg.root_pubkey_hex.is_empty() {
    None
} else {
    let bytes = hex::decode(&cfg.root_pubkey_hex).context(BadRootHexSnafu)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| /* wrong length */ ...)?;
    Some(arr)
};
```

Adjust any downstream code that previously assumed `Some(_)` — likely none of the substrate-message code paths run pre-pairing, so this should be a small change.

- [ ] **Step 4: Write a test**

Create `crates/wires-cli/tests/init.rs`:

```rust
use tempfile::TempDir;
use wires_node::NodeConfig;

#[tokio::test]
async fn init_writes_identity_only_by_default() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), false).await.unwrap();
    assert!(td.path().join("identity.ed25519").exists());
    assert!(td.path().join("identity.x25519").exists());
    assert!(!td.path().join("root.ed25519").exists());
    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    assert!(cfg.root_pubkey_hex.is_empty());
}

#[tokio::test]
async fn init_new_root_writes_root_key() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), true).await.unwrap();
    assert!(td.path().join("root.ed25519").exists());
    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    assert_eq!(cfg.root_pubkey_hex.len(), 64);
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p wires-cli --test init`
Expected: 2 passed; 0 failed.

Then run the full crate build to catch downstream breakage:

Run: `cargo build -p wires-cli`
Expected: clean build. Any remaining compile errors point to places that depend on the old `root: Option<String>` shape — fix them.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-cli/src/cmd/init.rs crates/wires-cli/src/main.rs \
        crates/wires-cli/tests/init.rs crates/wires-node/src/node.rs
git commit -m "$(cat <<'EOF'
refactor(wires-cli): wires init is identity-only by default

Removes the --root flag; replaces with --new-root for the operator path.
Plain `wires init` writes identity files and an unpinned config.toml
(root_pubkey_hex empty), ready for `wires pair-listen` to attach to a
household. Node::open tolerates an empty root_pubkey_hex.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: `wires topic create` auto-mints a self-cap

**Files:**
- Modify: `crates/wires-cli/src/cmd/topic.rs`

- [ ] **Step 1: Extend `cmd::topic::create`**

Replace `crates/wires-cli/src/cmd/topic.rs`:

```rust
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use wires_core::Capability;
use wires_core::cap::Right;
use wires_node::{Node, NodeConfig};

pub async fn create(data_dir: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Node::open(cfg)?;

    let mut topic_id = [0u8; 32];
    OsRng.fill_bytes(&mut topic_id);
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    node.install_epoch_key(topic_id, 0, epoch_key)?;

    let map_path = data_dir.join("topic_names.json");
    let mut map: std::collections::HashMap<String, String> = if map_path.exists() {
        serde_json::from_str(&std::fs::read_to_string(&map_path)?)?
    } else {
        std::collections::HashMap::new()
    };
    map.insert(name.to_string(), hex::encode(topic_id));
    std::fs::write(&map_path, serde_json::to_string_pretty(&map)?)?;

    println!("Created topic '{name}' with id {}", hex::encode(topic_id));
    println!(
        "Note: in v1, epoch keys are not distributed via gossip yet — share epoch key {} with peers manually.",
        hex::encode(epoch_key)
    );

    // Auto-mint a self-cap if this data dir holds a root key and no cap
    // exists for the local agent on this topic. Operator (Alice) workflow.
    let root_path = data_dir.join("root.ed25519");
    if root_path.exists() {
        let root_bytes = std::fs::read(&root_path)?;
        if root_bytes.len() != 32 {
            return Err("root.ed25519 must be 32 bytes".into());
        }
        let root_sk = SigningKey::from_bytes(&root_bytes.try_into().unwrap());
        let agent_pk = node.identity_pubkey();
        // If the agent already has a cap covering this topic name with both
        // rights, skip.
        if !node.caps.agent_has_cap_for(&agent_pk, name, Right::Write)? {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as i64;
            let mut cap = Capability::new_unsigned(
                agent_pk,
                vec![name.to_string()],
                vec![Right::Read, Right::Write],
                now,
                None,
            );
            cap.sign(&root_sk)?;
            node.caps.upsert_grant(&cap)?;
            println!("Minted self-cap: {}", hex::encode(cap.cap_id.0));
        }
    }

    Ok(())
}
```

This depends on two helpers that may not yet exist:

- `Node::identity_pubkey() -> [u8; 32]` — returns the ed25519 pubkey loaded from `identity.ed25519`.
- `CapTable::agent_has_cap_for(&self, agent_pk, topic_name, right) -> Result<bool>` — true if any installed cap allows that (agent, topic, right) tuple.

- [ ] **Step 2: Add `Node::identity_pubkey`**

Inspect `crates/wires-node/src/node.rs`. If the ed25519 signing key is already loaded into the `Node`, expose `identity_pubkey(&self) -> [u8; 32]` returning `self.identity_sk.verifying_key().to_bytes()`. If `Node` doesn't currently load the signing key, add it: `identity_sk: SigningKey` field plus a load in `Node::open`.

- [ ] **Step 3: Add `CapTable::agent_has_cap_for`**

In `crates/wires-store/src/caps.rs` (or wherever the `CapTable` lives), add:

```rust
pub fn agent_has_cap_for(
    &self,
    agent_pk: &[u8; 32],
    topic_name: &str,
    right: wires_core::cap::Right,
) -> Result<bool> {
    for cap in self.iter_active_for(agent_pk)? {
        if cap.allows(topic_name, right).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}
```

If `iter_active_for(...)` doesn't exist, use whatever iterator the existing code uses to scan the table.

- [ ] **Step 4: Write a test**

Create `crates/wires-cli/tests/topic_self_cap.rs`:

```rust
use tempfile::TempDir;
use wires_node::Node;
use wires_node::NodeConfig;

#[tokio::test]
async fn create_auto_mints_self_cap_when_root_present() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), true).await.unwrap(); // --new-root
    wires_cli::cmd::topic::create(td.path(), "home.notes").await.unwrap();

    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    let node = Node::open(cfg).unwrap();
    let agent_pk = node.identity_pubkey();
    assert!(node.caps.agent_has_cap_for(&agent_pk, "home.notes", wires_core::cap::Right::Write).unwrap());
}

#[tokio::test]
async fn create_skips_self_cap_when_no_root() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), false).await.unwrap(); // identity only
    // topic create on an unpinned dir should still succeed (creates a local
    // topic_id + epoch key) but skip cap-minting since there's no root.
    wires_cli::cmd::topic::create(td.path(), "home.notes").await.unwrap();
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p wires-cli --test topic_self_cap`
Expected: 2 passed; 0 failed.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-cli/src/cmd/topic.rs crates/wires-cli/tests/topic_self_cap.rs \
        crates/wires-node/src/node.rs crates/wires-store/src/caps.rs
git commit -m "$(cat <<'EOF'
feat(wires-cli): topic create auto-mints a self-cap when root is present

When the operator's data dir holds root.ed25519, `wires topic create`
mints and installs a read+write cap for the local agent on the new topic.
Eliminates the self-invite dance the README walkthrough used to require.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: `wires pair-listen` CLI command

**Files:**
- Create: `crates/wires-cli/src/cmd/pair_listen.rs`
- Modify: `crates/wires-cli/src/cmd/mod.rs`
- Modify: `crates/wires-cli/src/main.rs`

- [ ] **Step 1: Write the command implementation**

Create `crates/wires-cli/src/cmd/pair_listen.rs`:

```rust
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use wires_core::cap::Right;
use wires_net::pair::{PairManifest, RequestedScope};
use wires_node::{Node, NodeConfig, PairListenArgs, PairOutcome, pair_listen as run_listen};

pub async fn run(
    data_dir: &Path,
    role: String,
    description: String,
    requests: Vec<String>,
    ttl: Duration,
    qr: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let scopes = parse_requests(&requests)?;
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Arc::new(Node::open(cfg)?);
    let agent_sk_bytes = std::fs::read(data_dir.join("identity.ed25519"))?;
    if agent_sk_bytes.len() != 32 {
        return Err("identity.ed25519 must be 32 bytes".into());
    }
    let agent_sk = SigningKey::from_bytes(&agent_sk_bytes.try_into().unwrap());
    let agent_x25519_secret = std::fs::read(data_dir.join("identity.x25519"))?;
    if agent_x25519_secret.len() != 32 {
        return Err("identity.x25519 must be 32 bytes".into());
    }
    let agent_x25519_secret_arr: [u8; 32] = agent_x25519_secret.try_into().unwrap();
    let agent_x25519_pk =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(agent_x25519_secret_arr))
            .to_bytes();

    // Open a fresh iroh endpoint just for pair-listen. (NodeRuntime is heavier
    // and not needed here since we don't subscribe to gossip pre-pairing.)
    let secret_bytes = std::fs::read(data_dir.join("iroh.secret"))
        .unwrap_or_else(|_| wires_net::identity::load_or_create_secret(&data_dir.join("iroh.secret")).unwrap());
    let secret = iroh::SecretKey::from_bytes(
        &secret_bytes.try_into().map_err(|_| "iroh.secret must be 32 bytes")?,
    );
    let endpoint = iroh::Endpoint::builder()
        .secret_key(secret)
        .discovery_n0()
        .bind()
        .await?;
    // Wait for the endpoint to come online (avoid pkarr warm-up flakiness).
    tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await.ok();

    let started = run_listen(
        data_dir.to_path_buf(),
        node,
        agent_sk,
        agent_x25519_pk,
        endpoint,
        PairListenArgs {
            manifest: PairManifest {
                role,
                description,
                requested_scopes: scopes,
            },
            ttl,
        },
    )
    .await?;

    println!("Pair-listen window open for {} seconds.", ttl.as_secs());
    println!("Share this token with the operator:");
    println!("{}", started.request_token);
    if qr {
        print_qr(&started.request_token);
    }
    println!();
    println!("Waiting for pair-approve…");
    match tokio::time::timeout(ttl, started.outcome).await {
        Ok(Ok(PairOutcome::Paired { cap_id })) => {
            println!("Paired. Installed cap: {}", hex::encode(cap_id));
            started.router.shutdown().await.ok();
            Ok(())
        }
        Ok(Err(_)) => {
            started.router.shutdown().await.ok();
            Err("pair-listen handler closed without outcome".into())
        }
        Err(_) => {
            wires_node::pair_pending::delete(data_dir).ok();
            started.router.shutdown().await.ok();
            Err("pair-listen window expired".into())
        }
    }
}

fn parse_requests(reqs: &[String]) -> Result<Vec<RequestedScope>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for r in reqs {
        let (name, rights) = r
            .split_once(':')
            .ok_or_else(|| format!("--request '{r}' must be 'name:rights'"))?;
        let mut rs = Vec::new();
        for token in rights.split('+') {
            match token {
                "read" => rs.push(Right::Read),
                "write" => rs.push(Right::Write),
                other => return Err(format!("unknown right '{other}' in --request '{r}'").into()),
            }
        }
        out.push(RequestedScope {
            topic_name: name.to_string(),
            rights: rs,
        });
    }
    if out.is_empty() {
        return Err("--request <name:rights> is required at least once".into());
    }
    Ok(out)
}

fn print_qr(_token: &str) {
    // QR printing is optional; for v1 we don't pull in a QR crate. Print a
    // hint pointing the user at a terminal QR tool.
    println!("(--qr requested; pipe the token to `qrencode -t ANSI256UTF8 -o-` for a terminal QR)");
}
```

- [ ] **Step 2: Register the module**

Edit `crates/wires-cli/src/cmd/mod.rs`: add `pub mod pair_listen;` (alongside the existing modules).

- [ ] **Step 3: Add the clap subcommand**

In `crates/wires-cli/src/main.rs`, add to the `Cmd` enum:

```rust
    /// Start a pair-listen window; print a PairRequest token; wait for a
    /// pair-approve dial.
    PairListen {
        #[arg(long)]
        role: String,
        #[arg(long)]
        description: String,
        /// Topic-name + rights, e.g. "home.notes:read+write". Repeatable.
        #[arg(long = "request", required = true)]
        request: Vec<String>,
        /// Pair window TTL. Examples: "5m", "60s", "1h".
        #[arg(long, default_value = "5m")]
        ttl: humantime::Duration,
        #[arg(long)]
        qr: bool,
    },
```

And the match arm:

```rust
        Cmd::PairListen { role, description, request, ttl, qr } => {
            cmd::pair_listen::run(&data_dir, role, description, request, ttl.into(), qr).await
        }
```

Add `humantime = "2"` to `crates/wires-cli/Cargo.toml` under `[dependencies]` if absent.

- [ ] **Step 4: Run cargo build**

Run: `cargo build -p wires-cli`
Expected: clean build. Fix any field-name or path mismatches the compiler points out.

- [ ] **Step 5: Write a CLI-level smoke test**

Create `crates/wires-cli/tests/pair_listen_cli.rs`:

```rust
use tempfile::TempDir;
use wires_net::pair::PairRequest;

#[tokio::test]
async fn pair_listen_emits_a_valid_token() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), false).await.unwrap();
    // Spawn pair-listen in a task with a short TTL so it returns on timeout.
    let path = td.path().to_path_buf();
    let handle = tokio::spawn(async move {
        wires_cli::cmd::pair_listen::run(
            &path,
            "test".into(),
            "smoke".into(),
            vec!["home.notes:read+write".into()],
            std::time::Duration::from_secs(2),
            false,
        )
        .await
    });
    // Wait for the listen task to print the token, captured via pair_pending.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let pending =
        wires_node::pair_pending::load(td.path()).unwrap().expect("pair_pending exists");
    let req = PairRequest::decode(&pending.request_token).unwrap();
    req.verify().unwrap();
    assert_eq!(req.manifest.role, "test");
    let _ = handle.await; // task returns Err on TTL — fine
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p wires-cli --test pair_listen_cli`
Expected: 1 passed.

- [ ] **Step 7: Commit**

```bash
git add crates/wires-cli/src/cmd/pair_listen.rs crates/wires-cli/src/cmd/mod.rs \
        crates/wires-cli/src/main.rs crates/wires-cli/Cargo.toml \
        crates/wires-cli/tests/pair_listen_cli.rs
git commit -m "$(cat <<'EOF'
feat(wires-cli): wires pair-listen subcommand

Loads identity, opens an iroh endpoint, starts the pair-listen runtime
window with a parsed manifest (--role / --description / --request) and
prints the encoded PairRequest token. Blocks on the outcome oneshot up
to --ttl, deletes pair_pending on timeout.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: `wires pair-approve` CLI command

**Files:**
- Create: `crates/wires-cli/src/cmd/pair_approve.rs`
- Modify: `crates/wires-cli/src/cmd/mod.rs`
- Modify: `crates/wires-cli/src/main.rs`

- [ ] **Step 1: Write the command implementation**

Create `crates/wires-cli/src/cmd/pair_approve.rs`:

```rust
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;

use ed25519_dalek::SigningKey;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::pair::{
    HostInfo, PairClient, PairGrant, PairGrantEnvelope, PairRequest, RequestedScope, TopicEpochKey,
    TopicNameEntry,
};
use wires_node::{Node, NodeConfig};

pub async fn run(
    data_dir: &Path,
    token: &str,
    narrow_scopes: Vec<String>,
    narrow_topics: Option<Vec<String>>,
    no_host: bool,
    assume_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = PairRequest::decode(token)?;
    request.verify()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    if now >= request.expires {
        return Err("pair request has expired".into());
    }

    print_manifest(&request, now);
    if !assume_yes && !prompt_yes_no("Approve and grant? [y/N] ")? {
        return Err("rejected by operator".into());
    }

    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let host_info = if no_host {
        None
    } else {
        cfg.host.as_ref().map(|h| HostInfo {
            peer_hints: h.peer_hints.clone(),
            service_discovery_url: h.discovery_url.clone(),
        })
    };
    let node = Node::open(cfg)?;
    let root_bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    if root_bytes.len() != 32 {
        return Err("root.ed25519 must be 32 bytes".into());
    }
    let root_sk = SigningKey::from_bytes(&root_bytes.try_into().unwrap());
    let root_pk = root_sk.verifying_key().to_bytes();

    // Resolve & filter scopes.
    let name_map: HashMap<String, [u8; 32]> = load_topic_names(data_dir)?;
    let scopes = filter_scopes(&request.manifest.requested_scopes, &narrow_scopes, narrow_topics.as_deref())?;
    let mut topic_keys = Vec::new();
    let mut topic_names = Vec::new();
    let mut cap_topics: Vec<String> = Vec::new();
    let mut cap_rights: Vec<Right> = Vec::new();
    let mut seen_rights = std::collections::HashSet::new();
    for scope in &scopes {
        let topic_id = name_map
            .get(&scope.topic_name)
            .ok_or_else(|| format!("unknown topic '{}'", scope.topic_name))?;
        let epoch_key = node
            .epoch_key(*topic_id, 0)?
            .ok_or_else(|| format!("no epoch key for '{}'", scope.topic_name))?;
        topic_keys.push(TopicEpochKey { topic_id: *topic_id, epoch: 0, key: epoch_key });
        topic_names.push(TopicNameEntry { topic_id: *topic_id, name: scope.topic_name.clone() });
        cap_topics.push(scope.topic_name.clone());
        for r in &scope.rights {
            if seen_rights.insert(*r) {
                cap_rights.push(*r);
            }
        }
    }

    let mut cap = Capability::new_unsigned(request.agent_pubkey, cap_topics, cap_rights, now, None);
    cap.sign(&root_sk)?;
    let cap_id = cap.cap_id.0;
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_pk,
        cap,
        topic_keys,
        topic_names,
        host: host_info,
        nonce: request.nonce,
        issued_at: now,
    };
    let envelope = PairGrantEnvelope::seal_and_sign(&grant, &request.ephemeral_x25519, &root_sk)?;

    let endpoint = iroh::Endpoint::builder().discovery_n0().bind().await?;
    tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.online()).await.ok();
    let client = PairClient::new(endpoint);
    let ack = client.deliver_grant(&request.dial, envelope).await?;
    println!(
        "Paired: cap {} installed at {} on agent {}",
        hex::encode(cap_id),
        ack.installed_at,
        hex::encode(request.agent_pubkey),
    );
    Ok(())
}

fn print_manifest(req: &PairRequest, now_ms: i64) {
    println!("Pair request from agent {}", hex::encode(req.agent_pubkey));
    println!("  role        : {}", req.manifest.role);
    println!("  description : {}", req.manifest.description);
    println!("  requested   :");
    for s in &req.manifest.requested_scopes {
        let rs: Vec<&str> = s
            .rights
            .iter()
            .map(|r| match r {
                Right::Read => "read",
                Right::Write => "write",
            })
            .collect();
        println!("    {} : {}", s.topic_name, rs.join(", "));
    }
    println!("  issued_at   : {} (ms)", req.issued_at);
    let remaining_s = (req.expires - now_ms).max(0) / 1000;
    println!("  expires_at  : {} ({}s remaining)", req.expires, remaining_s);
    println!("  nonce       : {}...", &hex::encode(req.nonce)[..16]);
}

fn prompt_yes_no(prompt: &str) -> std::io::Result<bool> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(matches!(buf.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn load_topic_names(data_dir: &Path) -> Result<HashMap<String, [u8; 32]>, Box<dyn std::error::Error>> {
    let p = data_dir.join("topic_names.json");
    if !p.exists() {
        return Ok(HashMap::new());
    }
    let raw: HashMap<String, String> = serde_json::from_str(&std::fs::read_to_string(p)?)?;
    let mut out = HashMap::new();
    for (k, v) in raw {
        let bytes = hex::decode(&v)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| "topic_id must be 32 bytes")?;
        out.insert(k, arr);
    }
    Ok(out)
}

fn filter_scopes(
    requested: &[RequestedScope],
    narrow_scopes: &[String],
    narrow_topics: Option<&[String]>,
) -> Result<Vec<RequestedScope>, Box<dyn std::error::Error>> {
    // Apply --topics first (whitelist), then --scope per-topic narrowing.
    let mut base: Vec<RequestedScope> = match narrow_topics {
        Some(names) => requested
            .iter()
            .filter(|s| names.iter().any(|n| n == &s.topic_name))
            .cloned()
            .collect(),
        None => requested.to_vec(),
    };
    for spec in narrow_scopes {
        let (name, rights) = spec
            .split_once(':')
            .ok_or_else(|| format!("--scope '{spec}' must be 'name:rights'"))?;
        let mut rs = Vec::new();
        for t in rights.split('+') {
            match t {
                "read" => rs.push(Right::Read),
                "write" => rs.push(Right::Write),
                other => return Err(format!("unknown right '{other}' in --scope '{spec}'").into()),
            }
        }
        if let Some(s) = base.iter_mut().find(|s| s.topic_name == name) {
            // Narrow to the intersection of requested and operator-specified.
            s.rights.retain(|r| rs.contains(r));
        }
    }
    base.retain(|s| !s.rights.is_empty());
    if base.is_empty() {
        return Err("after narrowing, no scopes remain to grant".into());
    }
    Ok(base)
}
```

This depends on `Node::epoch_key(topic_id, epoch) -> Result<Option<[u8;32]>>`. If that method doesn't exist, add it to `crates/wires-node/src/node.rs` — it's a straightforward wrapper around the existing `keys_<topic>.redb` reader.

- [ ] **Step 2: Register the module + clap subcommand**

In `crates/wires-cli/src/cmd/mod.rs`: `pub mod pair_approve;`.

In `crates/wires-cli/src/main.rs`, add to `Cmd`:

```rust
    /// Decode and approve a PairRequest from Bob.
    PairApprove {
        /// Base64 PairRequest token.
        token: String,
        /// Narrow per-topic rights, e.g. `--scope home.notes:read`. Repeatable.
        #[arg(long = "scope")]
        scope: Vec<String>,
        /// Narrow to a subset of requested topic names. Repeatable.
        #[arg(long = "topics", value_delimiter = ',')]
        topics: Option<Vec<String>>,
        /// Omit host info from the grant.
        #[arg(long)]
        no_host: bool,
        /// Skip the interactive prompt.
        #[arg(long)]
        yes: bool,
    },
```

And the match arm:

```rust
        Cmd::PairApprove { token, scope, topics, no_host, yes } => {
            cmd::pair_approve::run(&data_dir, &token, scope, topics, no_host, yes).await
        }
```

- [ ] **Step 3: Add the end-to-end CLI acceptance test**

Create `crates/wires-cli/tests/pair_e2e.rs`:

```rust
use std::time::Duration;
use tempfile::TempDir;
use wires_node::pair_pending;

#[tokio::test]
#[ignore]
async fn alice_pairs_bob_end_to_end() {
    let alice_td = TempDir::new().unwrap();
    let bob_td = TempDir::new().unwrap();

    // Alice: init with new root, create topic.
    wires_cli::cmd::init::run(alice_td.path(), true).await.unwrap();
    wires_cli::cmd::topic::create(alice_td.path(), "home.notes").await.unwrap();

    // Bob: identity-only init.
    wires_cli::cmd::init::run(bob_td.path(), false).await.unwrap();

    // Bob: start pair-listen in a background task.
    let bob_path = bob_td.path().to_path_buf();
    let listen = tokio::spawn(async move {
        wires_cli::cmd::pair_listen::run(
            &bob_path,
            "chat-agent".into(),
            "Bob".into(),
            vec!["home.notes:read+write".into()],
            Duration::from_secs(30),
            false,
        )
        .await
    });

    // Wait for pair_pending.json to appear with a token.
    let mut token = None;
    for _ in 0..30 {
        if let Ok(Some(p)) = pair_pending::load(bob_td.path()) {
            token = Some(p.request_token);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let token = token.expect("Bob should have written pair_pending.json");

    // Alice: pair-approve (yes, default scopes, no host since no `wires host pair`).
    wires_cli::cmd::pair_approve::run(
        alice_td.path(),
        &token,
        vec![],
        None,
        true, // no_host
        true, // yes
    )
    .await
    .unwrap();

    // Bob's listen task should now resolve to Paired.
    let res = listen.await.unwrap();
    assert!(res.is_ok());
    assert!(!bob_td.path().join("pair_pending.json").exists());
    assert!(bob_td.path().join("caps.redb").exists());
}
```

`#[ignore]` because it spins up two real iroh endpoints; runs only with `cargo test -- --ignored`.

- [ ] **Step 4: Build and run**

Run: `cargo build -p wires-cli`
Expected: clean build.

Run: `cargo test -p wires-cli --test pair_e2e -- --ignored`
Expected: 1 passed (may take 10–30s on cold start).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-cli/src/cmd/pair_approve.rs crates/wires-cli/src/cmd/mod.rs \
        crates/wires-cli/src/main.rs crates/wires-cli/tests/pair_e2e.rs \
        crates/wires-node/src/node.rs
git commit -m "$(cat <<'EOF'
feat(wires-cli): wires pair-approve subcommand

Decodes a PairRequest token, prints the manifest for operator consent
(unless --yes), resolves requested topic names against topic_names.json,
narrows scopes per --scope / --topics, mints a root-signed Capability,
seals + signs the PairGrant, dials Bob's iroh endpoint, awaits Ack.
Ignored acceptance test walks the full Alice/Bob pairing.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Delete `InviteToken`, `wires invite`, `wires join`

**Files:**
- Delete: `crates/wires-net/src/invite.rs`
- Delete: `crates/wires-cli/src/cmd/invite.rs`
- Delete: `crates/wires-cli/src/cmd/join.rs`
- Modify: `crates/wires-net/src/lib.rs`
- Modify: `crates/wires-cli/src/cmd/mod.rs`
- Modify: `crates/wires-cli/src/main.rs`

- [ ] **Step 1: Delete the files**

```bash
git rm crates/wires-net/src/invite.rs crates/wires-cli/src/cmd/invite.rs crates/wires-cli/src/cmd/join.rs
```

- [ ] **Step 2: Remove the module declarations and re-exports**

Edit `crates/wires-net/src/lib.rs`:
- Remove the `pub mod invite;` line.
- Remove the `pub use invite::{InviteToken, PeerHint};` re-export.
- Re-export `PeerHint` from its actual home: `pub use peer_hint::PeerHint;` (peer_hint.rs already declares `PeerHint` per the existing tree — verify with `grep -n "pub struct PeerHint" crates/wires-net/src/peer_hint.rs`; if the struct lives in invite.rs today, move it to peer_hint.rs as part of this step).

Edit `crates/wires-cli/src/cmd/mod.rs`:
- Remove the `pub mod invite;` and `pub mod join;` lines.

Edit `crates/wires-cli/src/main.rs`:
- Remove the `Invite { … }` and `Join { … }` variants from the `Cmd` enum.
- Remove the corresponding match arms in `main`.

- [ ] **Step 3: Rebuild and resolve any stragglers**

Run: `cargo build --workspace`
Expected: clean build. If anything still references `InviteToken` or `wires_net::invite::*`, the compiler points to it — most likely an integration test or example. Update or delete.

In particular, check `crates/wires-net/src/peer_hint.rs` and any test under `crates/wires-net/tests/` that uses `InviteToken`. Adapt or delete.

- [ ] **Step 4: Run the full test suite to confirm nothing else broke**

Run: `cargo test --workspace`
Expected: all tests pass (the count drops by ~6 from invite.rs's tests being gone).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
chore: delete InviteToken, wires invite, wires join

Subsumed by the new responder-driven pairing flow (wires pair-listen +
wires pair-approve). No migration shim — this is a prototype.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: Update README walkthrough

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite the quick-start walkthrough**

Replace the section starting at `## Quick start: a local proof-of-concept in four terminals` through the end of `### Tab 3 again — Bob joins and reads` in `README.md` with the following:

````markdown
## Quick start: a local proof-of-concept in four terminals

This walks through running the full system on one machine. Open four terminal tabs. We use four data directories: `./host`, `./alice`, `./bob`, and (for observation) the host's data dir again.

### Tab 1 — `wires-host`

```bash
mkdir -p ./host
wires-host --data-dir ./host
# → wires-host: EndpointId = <HOST_ID>
# → wires-host: discovery listening at 0.0.0.0:8443
# → wires-host: running. Press Ctrl-C to exit.
```

Leave it running for the rest of the walkthrough.

### Tab 2 — Alice, the operator

```bash
# 1. Initialize Alice's data dir with a fresh local root.
wires --data-dir ./alice init --new-root
# → Generated local root pubkey: <ROOT_HEX>
# → Initialized at ./alice
# → Root pubkey: <ROOT_HEX>

# 2. Pair Alice's root with the host.
wires --data-dir ./alice host pair --discovery-url http://127.0.0.1:8443/v1/bootstrap

# 3. Create a topic. Auto-mints a self-cap because root.ed25519 is present.
wires --data-dir ./alice topic create home.notes
# → Created topic 'home.notes' with id <TOPIC_HEX>
# → Minted self-cap: <ALICE_CAP_HEX>

# 4. Register the topic with the host.
wires --data-dir ./alice host topic-register home.notes
```

### Tab 3 — Bob, an invited agent

```bash
# 1. Identity-only init. No root, no caps, no household awareness.
wires --data-dir ./bob init

# 2. Start a pair-listen window. Prints a PairRequest token and blocks.
wires --data-dir ./bob pair-listen \
  --role chat-agent \
  --description "Bob, a chat agent" \
  --request home.notes:read+write
# → Pair-listen window open for 300 seconds.
# → Share this token with the operator:
# → <BOB_TOKEN>
# → Waiting for pair-approve…
```

### Tab 2 again — Alice approves Bob

```bash
wires --data-dir ./alice pair-approve <BOB_TOKEN>
# → Pair request from agent <BOB_AGENT_HEX>
# →   role        : chat-agent
# →   description : Bob, a chat agent
# →   requested   :
# →     home.notes : read, write
# →   ...
# → Approve and grant? [y/N] y
# → Paired: cap <BOB_CAP_HEX> installed at <MILLIS> on agent <BOB_AGENT_HEX>
```

Bob's pair-listen exits with `Paired. Installed cap: <BOB_CAP_HEX>`.

### Tab 3 again — Bob reads and Alice publishes

```bash
# Bob tails the topic. Replay first, then live.
wires --data-dir ./bob cat home.notes --tail

# Alice publishes (Tab 2):
wires --data-dir ./alice publish \
  --topic home.notes \
  --cap <ALICE_CAP_HEX> \
  --type agent.note \
  "hello from alice"
```

Within a second or two Bob's tail prints the message.
````

- [ ] **Step 2: Update the "Concepts in one paragraph each" bullets if any reference invite tokens**

In `README.md`, search for "invite" and replace any mentions with the pair-listen flow. The "Capability" bullet should now read:

```markdown
- **Capability.** A signed grant of `read` and/or `write` on a topic to a specific agent pubkey. Capabilities are the only way to publish. Operators (root-key holders) mint them through `wires pair-approve` in response to a pair request from an agent. Caps live in each agent's `caps.redb`.
```

- [ ] **Step 3: Verify by reading the file**

```bash
grep -n "invite\|InviteToken" README.md
```

Expected: zero results (or only historic context if it must remain).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs(readme): walkthrough uses pair-listen / pair-approve

Replaces the InviteToken-based 4-tab walkthrough with the new
responder-driven pairing flow.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: Update substrate spec wording

**Files:**
- Modify: `docs/superpowers/specs/2026-05-14-wires-substrate-design.md`

- [ ] **Step 1: Adjust the Bootstrapping paragraph (§2.6)**

Open `docs/superpowers/specs/2026-05-14-wires-substrate-design.md` and find the paragraph starting "**Bootstrapping.** When a new agent comes online…". Replace with:

```markdown
**Bootstrapping.** When a new agent comes online, it needs (a) an iroh `NodeAddr` of at least one peer and (b) a capability. Both are conveyed by the responder-driven pairing flow defined in `docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md`: the agent declares its role and requested scopes via a signed `PairRequest` token (QR or paste); the operator consents and dials the agent over `/wires/pair/0` with a sealed, signed `PairGrant` containing the root pubkey, root-signed cap, per-topic epoch keys, and host info. The token's nonce makes pairing single-use; the QR scan is the trust-establishment act (TOFU on the root pubkey).
```

- [ ] **Step 2: Adjust the §11 acceptance scenario**

Find the scenario line "agent C bootstrapped from an invite token". Replace with:

```markdown
3. A third agent bootstrapped via `wires pair-listen` / `wires pair-approve` → receives full history (including all prior epoch keys), tails live.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-05-14-wires-substrate-design.md
git commit -m "$(cat <<'EOF'
docs(substrate-spec): point bootstrapping at responder-driven pairing spec

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 17: Update CLAUDE.md to reflect new shape

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Patch the wires-cli row in the crate-layout table**

In `CLAUDE.md`, find the `wires-cli` row in the crate layout table. Replace its description with:

```
| `wires-cli` | `wires` binary. Speaks the tenant control protocol (`wires host pair / topic-register / topic-unregister / status`), drives responder-driven pairing (`wires pair-listen` on Bob, `wires pair-approve` on Alice), and auto-dials gossip on `publish` / `cat`. |
```

- [ ] **Step 2: Patch the wires-net row**

Update the `wires-net` row to drop the `InviteToken` reference and add `pair.rs`:

```
| `wires-net` | iroh transport: `gossip.rs` wraps `iroh-gossip`; `replay.rs` is a custom QUIC protocol on `/wires/replay/0`; `tenant.rs` is the `/wires/tenant/0` control-plane; `pair.rs` is the `/wires/pair/0` responder-driven pairing protocol (PairRequest, PairGrantEnvelope, PairProtocol/PairClient); `framing.rs` is the shared length-prefixed JSON helper; `discovery.rs` is the HTTPS `/v1/bootstrap` client; `peer_hint::first_reachable_with_discovery` is the join-time iterator with discovery-URL fallback. |
```

- [ ] **Step 3: Add a status-line note about the new pairing flow**

Update the top "## Status" section to add a third bullet:

```
- **Responder-driven pairing v1** (this branch) — agents declare a manifest via `wires pair-listen`; the operator consents via `wires pair-approve` over `/wires/pair/0`. Replaces the deleted `InviteToken` flow.
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
docs(claude-md): reflect responder-driven pairing landed

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 18: Final sweep — clippy, fmt, full test suite

**Files:**
- Any files clippy/fmt touches.

- [ ] **Step 1: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: zero warnings. Fix anything that fires.

- [ ] **Step 2: Run fmt**

Run: `cargo fmt --all`
Expected: idempotent; commit any changes.

- [ ] **Step 3: Run the full test suite**

Run: `cargo test --workspace`
Expected: all green.

Run: `cargo test --workspace -- --ignored`
Expected: all green (slower; ~30s including iroh warm-up).

- [ ] **Step 4: Commit any fmt / clippy fixups**

If clippy or fmt made changes:

```bash
git add -A
git commit -m "$(cat <<'EOF'
chore: cargo clippy + cargo fmt sweep for responder-driven pairing

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

If nothing changed, skip this commit.

- [ ] **Step 5: Final verification**

Run: `cargo build --workspace --release`
Expected: clean release build of all three binaries (`wires`, `wires-host`, `wires-ha`).

Manual smoke check (optional but recommended):

```bash
# In one terminal:
./target/release/wires-host --data-dir /tmp/wires-host
# In another:
./target/release/wires --data-dir /tmp/wires-alice init --new-root
./target/release/wires --data-dir /tmp/wires-alice host pair --discovery-url http://127.0.0.1:8443/v1/bootstrap
./target/release/wires --data-dir /tmp/wires-alice topic create home.notes
./target/release/wires --data-dir /tmp/wires-alice host topic-register home.notes
# In a third:
./target/release/wires --data-dir /tmp/wires-bob init
./target/release/wires --data-dir /tmp/wires-bob pair-listen \
  --role chat-agent --description Bob --request home.notes:read+write
# Capture the token, then back in Alice's terminal:
./target/release/wires --data-dir /tmp/wires-alice pair-approve <TOKEN> --yes
```

Confirm Bob's pair-listen prints `Paired. Installed cap: ...` and exits 0.

---

## Self-review checklist (run after the plan lands)

- Spec §2 scope → Tasks 1–14 cover every replaced/added item; Task 14 deletes the legacy surface.
- Spec §3 PairRequest → Task 1 (fields, signing, bounds).
- Spec §4 PairGrant + envelope → Task 2 (types + crypto).
- Spec §5 ALPN / framing / handler / client → Tasks 3 (frame), 4 (server), 5 (client).
- Spec §6 persistence + invariants → Task 6 (pair_pending), Task 7 (install order + idempotence), Task 9 (resume on existing pending file).
- Spec §7 error handling → Task 8 (each reject code path tested), error variants added in Tasks 1/2/5/7/9.
- Spec §8 CLI surface → Tasks 10 (init), 11 (topic-self-cap), 12 (pair-listen), 13 (pair-approve), 14 (deletions).
- Spec §9 testing → unit tests inline in Tasks 1–3; integration tests in Tasks 4, 5, 7, 8, 9; acceptance in Task 13.
- Spec §10 out of scope → nothing implemented.
- README + CLAUDE.md → Tasks 15, 17.
- Substrate spec wording → Task 16.
