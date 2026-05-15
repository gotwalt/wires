# Wires iOS Companion Implementation Plan

**Status:** Draft, revised 2026-05-15 against the post-hosted-service / responder-driven-pairing substrate. The previous draft's tasks for `HostPairToken`, `EnrollmentToken`, and `wires-host show-pair-qr` are deleted; tasks for tenant-client wrappers, pair-client wrappers, and discovery wrappers replace them. The previous draft's iOS agent identity and chain-state plumbing are gone — iOS is no longer a gossip peer in v1.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the v1 iOS companion app described in `docs/superpowers/specs/2026-05-14-wires-ios-companion-design.md`: a SwiftUI + TCA app over a Rust `wires-uniffi` facade that custodies the household root key, registers with a hosted `wires-host` via discovery + `/wires/tenant/0`, registers topics on demand, and approves new agents via responder-driven pair (`/wires/pair/0`).

**Architecture:** Rust core reuses `wires-core`, `wires-crypto`, `wires-net` unchanged in behavior. One small substrate refactor lifts the existing `Capability::sign(&SigningKey)`-style signing sites onto a `wires_core::RootSigner` trait so the iOS Keychain can supply a callback-backed signer; a blanket impl for `SigningKey` keeps every existing caller working. A new `crates/wires-uniffi` exposes a narrow per-operation FFI via UniFFI 0.28+. iOS persists low-sensitivity state in SwiftData, secrets in Keychain. SwiftUI views are driven by Composable Architecture reducers with dependency-injected `WiresClient`, `HouseholdClient`, `KeychainClient`.

**Tech Stack:** Rust 2024 + UniFFI 0.28, iroh 0.98, Swift 5.10+, iOS 17 deployment target, swift-composable-architecture 1.16+, swift-snapshot-testing.

---

## File Structure

**New Rust files:**
- `crates/wires-core/src/signer.rs` — `RootSigner` trait + `SignError` + blanket impl for `&SigningKey`
- `crates/wires-uniffi/Cargo.toml` + `src/{lib,error,types,signer,parse,topic,tenant,pair,app}.rs` + `build.rs` + `uniffi.toml` + `uniffi-bindgen.rs`

**Modified Rust files:**
- `Cargo.toml` (workspace) — add `wires-uniffi` member
- `crates/wires-core/src/{lib,cap,error}.rs` — re-export `RootSigner`; refactor `Capability::sign` to accept `&dyn RootSigner`
- `crates/wires-net/src/pair/grant.rs` — refactor `PairGrantEnvelope::seal_and_sign` to accept `&dyn RootSigner`
- `crates/wires-net/src/tenant.rs` — refactor `signed_send` / `register_tenant` / `register_topic` / `unregister_topic` / `tenant_status` to accept `&dyn RootSigner`

**Build / packaging:**
- `scripts/build-ioskit.sh` — cross-compile + uniffi-bindgen + xcframework assembly
- `Wires/WiresKit/Package.swift` + `Sources/WiresKit/` + `Frameworks/wires.xcframework`

**iOS files (new under `Wires/Wires/`):**
- `App/WiresApp.swift` (replaces template), `App/AppFeature.swift`
- `Features/Bootstrap/{BootstrapFeature,BootstrapView,DiscoveryURLView,ConfirmHostView}.swift`
- `Features/Home/{HomeFeature,HomeView}.swift`
- `Features/AgentEnrollment/{AgentEnrollmentFeature,ApprovalFeature,AgentEnrollmentView}.swift`
- `Features/Scan/{ScanFeature,ScanView}.swift`
- `Dependencies/{Wires,Household,Keychain}Client.swift`
- `Models/{Household,TopicRecord,CapRecord}.swift`

**iOS files removed:** `Wires/Wires/{ContentView,Item}.swift`

**Tests (new):** `Wires/WiresTests/{Bootstrap,AgentEnrollment,Approval,Scan,Home,App}FeatureTests.swift`, `Wires/WiresUITests/SnapshotTests.swift`

---

## Phase 1 — `RootSigner` trait lift

### Task 1: `RootSigner` trait in `wires-core` with blanket impl

**Files:**
- Create: `crates/wires-core/src/signer.rs`
- Modify: `crates/wires-core/src/{cap,lib,error}.rs`

The trait lives in `wires-core` so every signing-site crate (core itself, plus `wires-net::tenant` and `wires-net::pair`) can adopt it without introducing a new dependency. A blanket impl for `&SigningKey` preserves every existing caller (CLI, host, node, tests) unchanged.

- [ ] **Step 1: Write the trait + blanket impl + tests**

Create `crates/wires-core/src/signer.rs`:

```rust
//! `RootSigner` — the household's root-of-trust signing abstraction. Implemented
//! by an in-process `SigningKey` for CLI/daemon use and by a callback-backed
//! adapter from `wires-uniffi` for iOS Keychain biometric signing.

use ed25519_dalek::{Signer as _, SigningKey};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
pub enum SignError {
    #[snafu(display("Root signer rejected the message: {message}, at {location}"))]
    Rejected {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub trait RootSigner {
    fn pubkey(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError>;
}

impl RootSigner for &SigningKey {
    fn pubkey(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
        Ok(<SigningKey as Signer<ed25519_dalek::Signature>>::sign(self, message).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn blanket_impl_signs_and_pubkey_matches() {
        let sk = SigningKey::generate(&mut OsRng);
        let s = &sk;
        assert_eq!(<&SigningKey as RootSigner>::pubkey(&s), sk.verifying_key().to_bytes());
        let sig = <&SigningKey as RootSigner>::sign(&s, b"hello").unwrap();
        assert_eq!(sig.len(), 64);
    }
}
```

- [ ] **Step 2: Register the module**

Add to `crates/wires-core/src/lib.rs`:

```rust
pub mod signer;
pub use signer::{RootSigner, SignError};
```

- [ ] **Step 3: Run test**

Run: `cargo test -p wires-core --lib signer`
Expected: PASS, 1 test.

- [ ] **Step 4: Refactor `Capability::sign` to accept `&dyn RootSigner`**

In `crates/wires-core/src/cap.rs`, replace:

```rust
    pub fn sign(&mut self, root_sk: &SigningKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        self.sig = root_sk.sign(&bytes).to_bytes();
        Ok(())
    }
```

with:

```rust
    pub fn sign(&mut self, root: &dyn crate::RootSigner) -> Result<()> {
        let bytes = self.signing_bytes()?;
        self.sig = root.sign(&bytes).map_err(|source| {
            crate::error::Error::CapSignerRejected {
                source,
                location: snafu::location!(),
            }
        })?;
        Ok(())
    }
```

Add a matching variant to `crates/wires-core/src/error.rs`:

```rust
    #[snafu(display("Root signer rejected the capability, at {location}"))]
    CapSignerRejected {
        source: crate::SignError,
        #[snafu(implicit)]
        location: snafu::Location,
    },
```

Existing callers (`cap.sign(&root_sk)` where `root_sk: &SigningKey`) keep compiling because the blanket impl `&SigningKey: RootSigner` makes `&root_sk` coerce to `&dyn RootSigner`. If any tests call `cap.sign(&root_sk)` and need explicit re-borrow, change to `cap.sign(&&root_sk)` — but rustc typically infers without help.

- [ ] **Step 5: Run all `wires-core` tests**

Run: `cargo test -p wires-core`
Expected: every previously passing test still passes. The new variant adds zero behavior changes.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-core/
git commit -m "wires-core: lift RootSigner trait; Capability::sign takes &dyn RootSigner"
```

### Task 2: Thread `RootSigner` through `wires-net`

**Files:**
- Modify: `crates/wires-net/src/pair/grant.rs`, `crates/wires-net/src/tenant.rs`

- [ ] **Step 1: Refactor `PairGrantEnvelope::seal_and_sign`**

In `crates/wires-net/src/pair/grant.rs`, replace the signature of `seal_and_sign` to take `&dyn wires_core::RootSigner`. Inline replacement:

```rust
    pub fn seal_and_sign(
        grant: &PairGrant,
        recipient_ephemeral_x25519: &[u8; 32],
        root: &dyn wires_core::RootSigner,
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
        .context(PairCryptoSnafu)?;

        let mut to_sign = Vec::with_capacity(32 + sealed_payload.len());
        to_sign.extend_from_slice(&grant.root_pubkey);
        to_sign.extend_from_slice(&sealed_payload);
        let signature = root.sign(&to_sign).map_err(|source| NetError::PairSignerRejected {
            source,
            location: snafu::location!(),
        })?;

        Ok(Self {
            root_pubkey: grant.root_pubkey,
            sealed_payload,
            signature,
        })
    }
```

Add `PairSignerRejected { source: wires_core::SignError, ... }` to `wires-net::error::NetError` (snafu pattern).

- [ ] **Step 2: Update grant.rs unit tests**

In the same file's `mod tests`, change every `PairGrantEnvelope::seal_and_sign(&grant, &..., &root_sk)` to `PairGrantEnvelope::seal_and_sign(&grant, &..., &&root_sk)` if the blanket impl needs the explicit double-borrow (or use `&root_sk` if rustc infers).

Run: `cargo test -p wires-net --lib pair::grant`
Expected: all PASS.

- [ ] **Step 3: Refactor `TenantClient::signed_send` and friends**

In `crates/wires-net/src/tenant.rs`, change every `&ed25519_dalek::SigningKey` parameter on the `TenantClient` impl block to `&dyn wires_core::RootSigner`. The body of `signed_send` already calls `root_signer.sign(&bytes)` and reads `root_signer.verifying_key().to_bytes()`. Replace:

```rust
        let root_pubkey = root_signer.verifying_key().to_bytes();
        // ...
        let signature = root_signer.sign(&bytes).to_bytes();
```

with:

```rust
        let root_pubkey = root_signer.pubkey();
        // ...
        let signature = root_signer.sign(&bytes).map_err(|source| NetError::TenantSignerRejected {
            source,
            location: snafu::location!(),
        })?;
```

Add `TenantSignerRejected` to `NetError` (same pattern as `PairSignerRejected`).

Update `register_tenant`, `register_topic`, `unregister_topic`, `tenant_status` to thread `&dyn RootSigner` instead of `&SigningKey`.

- [ ] **Step 4: Run net + downstream tests**

Run: `cargo test -p wires-net && cargo test -p wires-cli && cargo test -p wires-host && cargo test -p wires-node`
Expected: every previously passing test still passes.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/
git commit -m "wires-net: pair + tenant signing takes &dyn RootSigner"
```

---

## Phase 2 — `wires-uniffi` crate skeleton

### Task 3: Crate skeleton + UniFFI setup

**Files:**
- Create: `crates/wires-uniffi/Cargo.toml`, `build.rs`, `uniffi.toml`, `src/lib.rs`, `uniffi-bindgen.rs`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Add the crate to the workspace**

In root `Cargo.toml` under `[workspace] members`, add:

```toml
    "crates/wires-uniffi",
```

- [ ] **Step 2: Create `Cargo.toml`**

Create `crates/wires-uniffi/Cargo.toml`:

```toml
[package]
name = "wires-uniffi"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "wires_uniffi"
crate-type = ["staticlib", "cdylib", "lib"]

[[bin]]
name = "uniffi-bindgen"
path = "uniffi-bindgen.rs"

[dependencies]
wires-core   = { workspace = true }
wires-crypto = { workspace = true }
wires-net    = { workspace = true }
uniffi = { version = "0.28", features = ["tokio"] }
snafu = "0.8"
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true, features = ["rt-multi-thread", "macros", "sync"] }
async-trait = "0.1"
ed25519-dalek = "2"
rand_core = "0.6"
hex = "0.4"
iroh = "0.98"
parking_lot = "0.12"
uuid = { version = "1", features = ["v4"] }
tracing = "0.1"

[build-dependencies]
uniffi = { version = "0.28", features = ["build"] }
```

- [ ] **Step 3: Create the bindgen binary and config**

Create `crates/wires-uniffi/uniffi-bindgen.rs`:

```rust
fn main() {
    uniffi::uniffi_bindgen_main()
}
```

Create `crates/wires-uniffi/uniffi.toml`:

```toml
[bindings.swift]
module_name = "WiresKit"
ffi_module_name = "wires_uniffi"
generate_module_map = true
omit_argument_labels = false
```

Create `crates/wires-uniffi/build.rs`:

```rust
fn main() {
    // Proc-macro scaffolding via uniffi::setup_scaffolding! in lib.rs handles the
    // build. No .udl file is used.
}
```

Create `crates/wires-uniffi/src/lib.rs`:

```rust
uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
```

- [ ] **Step 4: Build and test**

Run: `cargo test -p wires-uniffi`
Expected: 1 test PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/wires-uniffi/
git commit -m "wires-uniffi: crate skeleton with UniFFI scaffolding"
```

### Task 4: `WiresError` enum

**Files:**
- Create: `crates/wires-uniffi/src/error.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Write the enum + a display test**

Create `crates/wires-uniffi/src/error.rs`:

```rust
use snafu::{Location, Snafu};
use wires_net::pair::PairRejectCode;
use wires_net::tenant::TenantErrorCode;

#[derive(Debug, Snafu, uniffi::Error)]
#[uniffi(flat_error)]
pub enum WiresError {
    #[snafu(display("Failed to fetch service discovery URL: {message}, at {location}"))]
    DiscoveryFetch { message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Discovery URL returned no endpoints, at {location}"))]
    DiscoveryEmpty { #[snafu(implicit)] location: Location },

    #[snafu(display("Tenant register stream failed: {message}, at {location}"))]
    TenantStream { message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Host rejected tenant register: {code:?}: {message}, at {location}"))]
    TenantRejected { code: TenantErrorCode, message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Topic register stream failed: {message}, at {location}"))]
    TopicRegisterStream { message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Host rejected topic register: {code:?}: {message}, at {location}"))]
    TopicRegisterRejected { code: TenantErrorCode, message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Pair request token is invalid: {message}, at {location}"))]
    InvalidPairRequest { message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Pair request has expired, at {location}"))]
    PairRequestExpired { #[snafu(implicit)] location: Location },

    #[snafu(display("Unknown pending pair handle, at {location}"))]
    UnknownPairHandle { #[snafu(implicit)] location: Location },

    #[snafu(display("Pair grant delivery failed: {message}, at {location}"))]
    PairDeliveryFailed { message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Agent rejected pair grant: {code:?}: {message}, at {location}"))]
    PairRejected { code: PairRejectCode, message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Root signer failed: {message}, at {location}"))]
    RootSignerFailed { message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Internal error: {message}, at {location}"))]
    Internal { message: String, #[snafu(implicit)] location: Location },
}

pub type WiresResult<T> = std::result::Result<T, WiresError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_ends_with_location() {
        let e = DiscoveryEmptySnafu.build();
        let s = format!("{e}");
        assert!(s.contains(", at"), "got: {s}");
    }
}
```

`TenantErrorCode` and `PairRejectCode` must be UniFFI-friendly. They are simple C-style enums in `wires-net`; UniFFI should pick them up via `#[uniffi::remote(Enum)]` declarations. We add those declarations at the top of `error.rs` once we know UniFFI 0.28's exact syntax — verify before commit. If `#[uniffi::remote]` is unavailable on these enums for any reason, fall back to a local mirror enum and `From` conversions.

- [ ] **Step 2: Wire into lib.rs**

Replace `crates/wires-uniffi/src/lib.rs`:

```rust
uniffi::setup_scaffolding!();

pub mod error;
pub use error::{WiresError, WiresResult};
```

- [ ] **Step 3: Run test**

Run: `cargo test -p wires-uniffi`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: WiresError enum"
```

### Task 5: UniFFI Records and Enums (no logic)

**Files:**
- Create: `crates/wires-uniffi/src/types.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Write the type surface with a construction test**

Create `crates/wires-uniffi/src/types.rs`:

```rust
#[derive(Debug, Clone, uniffi::Record)]
pub struct HostInfo {
    pub endpoint_id_hex: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
    pub discovery_url: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TenantRegistration {
    pub caps_topic_id_hex: String,
    pub host_endpoint_id_hex: String,
    pub server_time_ms: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PairRequestPreview {
    pub handle: PendingPairHandle,
    pub agent_pubkey_hex: String,
    pub role: String,
    pub description: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub requested_scopes: Vec<RequestedScopePreview>,
    pub dial_summary: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RequestedScopePreview {
    pub topic_name: String,
    pub rights: Vec<Right>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct GrantedScope {
    pub topic_id_hex: String,
    pub topic_name: String,
    pub rights: Vec<Right>,
    pub epochs: Vec<EpochKey>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EpochKey {
    pub epoch: u32,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct NewTopic {
    pub topic_id_hex: String,
    pub epoch_0_key: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PairAckRecord {
    pub installed_cap_id_hex: String,
    pub installed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Record)]
pub struct PendingPairHandle {
    pub id: String,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum Right {
    Read,
    Write,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structs_construct() {
        let _ = HostInfo {
            endpoint_id_hex: "00".repeat(32),
            addrs: vec!["1.2.3.4:5".into()],
            relay: None,
            discovery_url: "https://example/v1/bootstrap".into(),
        };
        let _ = Right::Read;
        let _ = PairAckRecord { installed_cap_id_hex: "".into(), installed_at_ms: 0 };
    }
}
```

- [ ] **Step 2: Register and run**

In `crates/wires-uniffi/src/lib.rs` add:

```rust
pub mod types;
pub use types::*;
```

Run: `cargo test -p wires-uniffi`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: FFI record/enum type surface"
```

### Task 6: `SwiftRootSigner` callback trait + `RootSigner` adapter

**Files:**
- Create: `crates/wires-uniffi/src/signer.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Write the adapter + test**

Create `crates/wires-uniffi/src/signer.rs`:

```rust
use std::sync::Arc;

use wires_core::{RootSigner, SignError, signer::RejectedSnafu};
use snafu::IntoError;

use crate::error::WiresError;

#[uniffi::export(with_foreign)]
pub trait SwiftRootSigner: Send + Sync {
    fn pubkey(&self) -> Vec<u8>;
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, WiresError>;
}

pub struct SwiftRootSignerAdapter {
    pub inner: Arc<dyn SwiftRootSigner>,
}

impl RootSigner for SwiftRootSignerAdapter {
    fn pubkey(&self) -> [u8; 32] {
        let v = self.inner.pubkey();
        let mut out = [0u8; 32];
        let n = v.len().min(32);
        out[..n].copy_from_slice(&v[..n]);
        out
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
        let sig = self
            .inner
            .sign(message.to_vec())
            .map_err(|e| RejectedSnafu { message: format!("{e}") }.build())?;
        if sig.len() != 64 {
            return Err(RejectedSnafu {
                message: format!("signer returned {} bytes, expected 64", sig.len()),
            }
            .build());
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use wires_core::Capability;

    struct FakeSwiftSigner(SigningKey);
    impl SwiftRootSigner for FakeSwiftSigner {
        fn pubkey(&self) -> Vec<u8> {
            self.0.verifying_key().to_bytes().to_vec()
        }
        fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, WiresError> {
            Ok(self.0.sign(&message).to_bytes().to_vec())
        }
    }

    #[test]
    fn adapter_signs_through_fake_swift_and_cap_verifies() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let swift: Arc<dyn SwiftRootSigner> = Arc::new(FakeSwiftSigner(sk));
        let adapter = SwiftRootSignerAdapter { inner: swift };
        assert_eq!(adapter.pubkey(), pk);

        let mut cap = Capability::new_unsigned(
            [7u8; 32],
            vec!["home.notes".into()],
            vec![wires_core::cap::Right::Read],
            1_700_000_000_000,
            None,
        );
        cap.sign(&adapter).unwrap();
        cap.verify(&pk).unwrap();
    }
}
```

- [ ] **Step 2: Register and run**

In `crates/wires-uniffi/src/lib.rs` add `pub mod signer;`.

Run: `cargo test -p wires-uniffi --lib signer`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: SwiftRootSigner callback trait + RootSigner adapter"
```

### Task 7: Pure helpers — pair-request parsing, topic generation

**Files:**
- Create: `crates/wires-uniffi/src/parse.rs`, `crates/wires-uniffi/src/topic.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Write `topic.rs` with a test**

Create `crates/wires-uniffi/src/topic.rs`:

```rust
use rand_core::{OsRng, RngCore};

use crate::types::NewTopic;

pub fn generate_topic_id_and_epoch0() -> NewTopic {
    let mut topic_id = [0u8; 32];
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut topic_id);
    OsRng.fill_bytes(&mut epoch_key);
    NewTopic {
        topic_id_hex: hex::encode(topic_id),
        epoch_0_key: epoch_key.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_nonzero_distinct() {
        let a = generate_topic_id_and_epoch0();
        let b = generate_topic_id_and_epoch0();
        assert_eq!(a.topic_id_hex.len(), 64);
        assert_eq!(a.epoch_0_key.len(), 32);
        assert_ne!(a.topic_id_hex, b.topic_id_hex);
        assert_ne!(a.epoch_0_key, b.epoch_0_key);
    }
}
```

- [ ] **Step 2: Write `parse.rs` with tests**

Create `crates/wires-uniffi/src/parse.rs`:

```rust
//! Pair-request decoding for the iOS app. Verifies the agent's ed25519
//! signature and converts the wire type into a Swift-friendly preview.

use uuid::Uuid;
use wires_net::pair::PairRequest;

use crate::error::{InvalidPairRequestSnafu, WiresError};
use crate::types::{PairRequestPreview, PendingPairHandle, RequestedScopePreview, Right};

/// Decoded request plus a fresh handle. Caller stores the raw `PairRequest`
/// (which carries the ephemeral X25519 pubkey, nonce, and dial info needed
/// later) keyed by `handle.id`.
pub struct ParsedRequest {
    pub handle: PendingPairHandle,
    pub request: PairRequest,
    pub preview: PairRequestPreview,
}

pub fn parse_pair_request(payload: &str) -> Result<ParsedRequest, WiresError> {
    let req: PairRequest = PairRequest::decode_and_verify(payload).map_err(|e| {
        InvalidPairRequestSnafu { message: format!("{e}") }.build()
    })?;
    let handle = PendingPairHandle { id: Uuid::new_v4().to_string() };
    let preview = PairRequestPreview {
        handle: handle.clone(),
        agent_pubkey_hex: hex::encode(req.agent_pubkey),
        role: req.manifest.role.clone(),
        description: req.manifest.description.clone(),
        issued_at_ms: req.issued_at,
        expires_at_ms: req.expires,
        requested_scopes: req
            .manifest
            .requested_scopes
            .iter()
            .map(|s| RequestedScopePreview {
                topic_name: s.topic_name.clone(),
                rights: s
                    .rights
                    .iter()
                    .map(|r| match r {
                        wires_core::cap::Right::Read => Right::Read,
                        wires_core::cap::Right::Write => Right::Write,
                    })
                    .collect(),
            })
            .collect(),
        dial_summary: format!("{} ({} addrs)", req.dial.node_id, req.dial.addrs.len()),
    };
    Ok(ParsedRequest { handle, request: req, preview })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use wires_net::pair::request::{PairDial, PairManifest, RequestedScope};

    fn signed_request() -> String {
        let sk = SigningKey::generate(&mut OsRng);
        let req = PairRequest::new_signed(
            &sk,
            [3u8; 32],
            [4u8; 32],
            PairDial { node_id: "deadbeef".repeat(8), addrs: vec![], relay: None },
            PairManifest {
                role: "email".into(),
                description: "Gmail".into(),
                requested_scopes: vec![RequestedScope {
                    topic_name: "mail.inbox".into(),
                    rights: vec![wires_core::cap::Right::Read, wires_core::cap::Right::Write],
                }],
            },
            300_000,
        )
        .unwrap();
        req.encode().unwrap()
    }

    #[test]
    fn parses_and_verifies() {
        let s = signed_request();
        let parsed = parse_pair_request(&s).unwrap();
        assert_eq!(parsed.preview.role, "email");
        assert_eq!(parsed.preview.requested_scopes.len(), 1);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_pair_request("nope").is_err());
    }
}
```

If `PairRequest::new_signed` / `decode_and_verify` / `encode` have different names in `wires-net::pair::request`, adjust to match. Find them via `grep -rn "pub fn .*PairRequest" crates/wires-net/`.

- [ ] **Step 3: Register and run**

In `crates/wires-uniffi/src/lib.rs` add:

```rust
pub mod parse;
pub mod topic;
```

Run: `cargo test -p wires-uniffi`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: pair-request parser + topic id/epoch generator"
```

### Task 8: Tenant flow — `fetch_discovery`, `register_with_hosted_service`, `register_topic`

**Files:**
- Create: `crates/wires-uniffi/src/tenant.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Implement the three operations against `wires_net`**

Create `crates/wires-uniffi/src/tenant.rs`:

```rust
//! Thin wrappers around wires-net::discovery and wires-net::tenant that the
//! iOS app drives. Stateless — each call binds (or reuses) an endpoint and
//! sends one request.

use std::sync::Arc;
use std::time::SystemTime;

use iroh::Endpoint;
use wires_net::peer_hint::endpoint_id_from_hex;
use wires_net::tenant::{TenantClient, TenantRequest, TenantResponse};

use crate::error::{
    DiscoveryEmptySnafu, DiscoveryFetchSnafu, InternalSnafu, TenantRejectedSnafu,
    TenantStreamSnafu, TopicRegisterRejectedSnafu, TopicRegisterStreamSnafu, WiresError,
};
use crate::signer::{SwiftRootSigner, SwiftRootSignerAdapter};
use crate::types::{HostInfo, TenantRegistration};

pub async fn fetch_discovery(url: &str) -> Result<HostInfo, WiresError> {
    let hints = wires_net::discovery::fetch_endpoints(url)
        .await
        .map_err(|e| DiscoveryFetchSnafu { message: format!("{e}") }.build())?;
    let first = hints.into_iter().next().ok_or_else(|| DiscoveryEmptySnafu.build())?;
    Ok(HostInfo {
        endpoint_id_hex: first.node_id,
        addrs: first.addrs,
        relay: first.relay,
        discovery_url: url.to_string(),
    })
}

pub async fn register_with_hosted_service(
    endpoint: Endpoint,
    root_signer: Arc<dyn SwiftRootSigner>,
    host: &HostInfo,
) -> Result<TenantRegistration, WiresError> {
    let peer = endpoint_id_from_hex(&host.endpoint_id_hex)
        .ok_or_else(|| InternalSnafu { message: "bad endpoint id".into() }.build())?;

    // Cache host as a reachable address before dialing.
    add_host_addr(&endpoint, host)?;

    let adapter = SwiftRootSignerAdapter { inner: root_signer };
    let host_endpoint_id_bytes = peer.as_bytes();
    let now = now_ms()?;

    let client = TenantClient::new(endpoint);
    let resp = client
        .register_tenant(peer, &adapter, host_endpoint_id_bytes, now)
        .await
        .map_err(|e| TenantStreamSnafu { message: format!("{e}") }.build())?;

    match resp {
        TenantResponse::Register(r) if r.ok => Ok(TenantRegistration {
            caps_topic_id_hex: hex::encode(r.caps_topic_id),
            host_endpoint_id_hex: r.host_endpoint_id,
            server_time_ms: r.server_time,
        }),
        TenantResponse::Error(err) => Err(TenantRejectedSnafu {
            code: err.code,
            message: err.message,
        }
        .build()),
        other => Err(InternalSnafu {
            message: format!("unexpected response: {other:?}"),
        }
        .build()),
    }
}

pub async fn register_topic(
    endpoint: Endpoint,
    root_signer: Arc<dyn SwiftRootSigner>,
    host: &HostInfo,
    topic_id: &[u8; 32],
) -> Result<(), WiresError> {
    let peer = endpoint_id_from_hex(&host.endpoint_id_hex)
        .ok_or_else(|| InternalSnafu { message: "bad endpoint id".into() }.build())?;
    add_host_addr(&endpoint, host)?;

    let adapter = SwiftRootSignerAdapter { inner: root_signer };
    let now = now_ms()?;

    let client = TenantClient::new(endpoint);
    let resp = client
        .register_topic(peer, &adapter, topic_id, peer.as_bytes(), now)
        .await
        .map_err(|e| TopicRegisterStreamSnafu { message: format!("{e}") }.build())?;

    match resp {
        TenantResponse::TopicRegister(r) if r.ok => Ok(()),
        TenantResponse::Error(err) => Err(TopicRegisterRejectedSnafu {
            code: err.code,
            message: err.message,
        }
        .build()),
        other => Err(InternalSnafu {
            message: format!("unexpected response: {other:?}"),
        }
        .build()),
    }
}

fn add_host_addr(endpoint: &Endpoint, host: &HostInfo) -> Result<(), WiresError> {
    let peer = endpoint_id_from_hex(&host.endpoint_id_hex)
        .ok_or_else(|| InternalSnafu { message: "bad endpoint id".into() }.build())?;
    let mut addr = iroh::EndpointAddr::new(peer);
    for a in &host.addrs {
        if let Ok(sa) = a.parse::<std::net::SocketAddr>() {
            addr = addr.with_ip_addr(sa);
        }
    }
    if let Some(r) = &host.relay
        && let Ok(url) = r.parse::<iroh::RelayUrl>()
    {
        addr = addr.with_relay_url(url);
    }
    endpoint
        .add_endpoint_addr(addr)
        .map_err(|e| InternalSnafu { message: format!("add_endpoint_addr: {e}") }.build())?;
    Ok(())
}

fn now_ms() -> Result<i64, WiresError> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?
        .as_millis() as i64)
}
```

Verify exact iroh 0.98 API names: `EndpointAddr`, `with_ip_addr`, `with_relay_url`, `add_endpoint_addr`. Memory note `reference_iroh_098_endpoint_api.md` records that iroh 0.98 uses `EndpointAddr`/`EndpointId` (not `NodeAddr`/`NodeId`). If a method name differs in 0.98, adjust to the current API.

- [ ] **Step 2: Register**

In `crates/wires-uniffi/src/lib.rs` add `pub mod tenant;`.

Run: `cargo build -p wires-uniffi`
Expected: builds.

- [ ] **Step 3: Commit (scaffold; integration test arrives with WiresApp)**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: fetch_discovery + register_with_hosted_service + register_topic wrappers"
```

### Task 9: Pair flow — `approve_pair_request`

**Files:**
- Create: `crates/wires-uniffi/src/pair.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Implement approve_pair_request against `wires_net::pair`**

Create `crates/wires-uniffi/src/pair.rs`:

```rust
//! Build, seal, sign, and deliver a `PairGrant` to a pending pair request.

use std::sync::Arc;
use std::time::SystemTime;

use iroh::Endpoint;
use wires_core::{Capability, cap::Right as CoreRight};
use wires_net::pair::grant::{HostInfo as PairHostInfo, PairGrant, TopicEpochKey, TopicNameEntry};
use wires_net::pair::request::PairRequest;
use wires_net::pair::{PairClient, PairGrantEnvelope};
use wires_net::peer_hint::PeerHint;

use crate::error::{
    InternalSnafu, PairDeliveryFailedSnafu, PairRejectedSnafu, PairRequestExpiredSnafu, WiresError,
};
use crate::signer::{SwiftRootSigner, SwiftRootSignerAdapter};
use crate::types::{GrantedScope, HostInfo, PairAckRecord, Right};

pub async fn approve_pair_request(
    endpoint: Endpoint,
    root_signer: Arc<dyn SwiftRootSigner>,
    request: &PairRequest,
    granted_scopes: Vec<GrantedScope>,
    host: HostInfo,
) -> Result<PairAckRecord, WiresError> {
    let now = now_ms()?;
    if now > request.expires {
        return Err(PairRequestExpiredSnafu.build());
    }

    let adapter = SwiftRootSignerAdapter { inner: root_signer.clone() };
    let root_pubkey = adapter.pubkey();

    // 1. Build the Capability covering every granted topic.
    let topic_names: Vec<String> = granted_scopes.iter().map(|g| g.topic_name.clone()).collect();
    let rights: Vec<CoreRight> = combined_rights(&granted_scopes);
    let mut cap = Capability::new_unsigned(
        request.agent_pubkey,
        topic_names.clone(),
        rights,
        now,
        None,
    );
    cap.sign(&adapter)
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?;

    // 2. Assemble the PairGrant.
    let topic_keys: Vec<TopicEpochKey> = granted_scopes
        .iter()
        .flat_map(|g| {
            let topic_id = decode_topic_id(&g.topic_id_hex);
            g.epochs.iter().map(move |e| {
                let mut key = [0u8; 32];
                let n = e.key.len().min(32);
                key[..n].copy_from_slice(&e.key[..n]);
                TopicEpochKey {
                    topic_id,
                    epoch: e.epoch,
                    key,
                }
            })
        })
        .collect();

    let topic_name_entries: Vec<TopicNameEntry> = granted_scopes
        .iter()
        .map(|g| TopicNameEntry {
            topic_id: decode_topic_id(&g.topic_id_hex),
            name: g.topic_name.clone(),
        })
        .collect();

    let grant = PairGrant {
        version: 1,
        root_pubkey,
        cap,
        topic_keys,
        topic_names: topic_name_entries,
        host: Some(PairHostInfo {
            peer_hints: vec![PeerHint {
                node_id: host.endpoint_id_hex,
                addrs: host.addrs,
                relay: host.relay,
            }],
            service_discovery_url: Some(host.discovery_url),
        }),
        nonce: request.nonce,
        issued_at: now,
    };

    // 3. Seal and sign.
    let envelope = PairGrantEnvelope::seal_and_sign(&grant, &request.ephemeral_x25519, &adapter)
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?;

    // 4. Deliver.
    let client = PairClient::new(endpoint);
    let ack = client
        .deliver_grant(&request.dial, envelope)
        .await
        .map_err(|e| map_pair_err(e))?;

    Ok(PairAckRecord {
        installed_cap_id_hex: hex::encode(ack.installed_cap_id),
        installed_at_ms: ack.installed_at,
    })
}

fn combined_rights(scopes: &[GrantedScope]) -> Vec<CoreRight> {
    let mut read = false;
    let mut write = false;
    for s in scopes {
        for r in &s.rights {
            match r {
                Right::Read => read = true,
                Right::Write => write = true,
            }
        }
    }
    let mut out = Vec::with_capacity(2);
    if read {
        out.push(CoreRight::Read);
    }
    if write {
        out.push(CoreRight::Write);
    }
    out
}

fn decode_topic_id(hex_s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(bytes) = hex::decode(hex_s) {
        let n = bytes.len().min(32);
        out[..n].copy_from_slice(&bytes[..n]);
    }
    out
}

fn map_pair_err(e: wires_net::error::NetError) -> WiresError {
    use wires_net::error::NetError;
    match e {
        NetError::PairRejected { code, message, .. } => PairRejectedSnafu { code, message }.build(),
        other => PairDeliveryFailedSnafu { message: format!("{other}") }.build(),
    }
}

fn now_ms() -> Result<i64, WiresError> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?
        .as_millis() as i64)
}
```

The `PairGrant.cap.topics` is per-cap (one cap covering all granted topics). The substrate's `Capability.topics` is `Vec<String>` of glob patterns. In v1 the iOS app passes the literal names — wildcard handling lives in the agent's cap-evaluation path, not here.

**Single-scope-per-cap design check.** v1 mints one cap covering all granted topics with the union of rights. If the operator requested per-topic read-only-vs-read-write divergence, the cap would over-grant. The UI surface in §3.2 step 3 forbids that — Approve combines rights *per cap*, and the operator narrows scopes individually before approve. Tests cover both shapes.

- [ ] **Step 2: Register**

In `crates/wires-uniffi/src/lib.rs` add `pub mod pair;`.

Run: `cargo build -p wires-uniffi`
Expected: builds.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: approve_pair_request — build, seal, sign, deliver"
```

### Task 10: `WiresApp` facade

**Files:**
- Create: `crates/wires-uniffi/src/app.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Implement WiresApp**

Create `crates/wires-uniffi/src/app.rs`:

```rust
use std::collections::HashMap;
use std::sync::Arc;

use iroh::{Endpoint, SecretKey};
use parking_lot::Mutex;
use tokio::runtime::Runtime;
use tokio::sync::OnceCell;
use wires_net::pair::request::PairRequest;

use crate::error::{InternalSnafu, UnknownPairHandleSnafu, WiresError};
use crate::parse;
use crate::pair;
use crate::signer::SwiftRootSigner;
use crate::tenant;
use crate::topic::generate_topic_id_and_epoch0 as gen_topic;
use crate::types::{
    GrantedScope, HostInfo, NewTopic, PairAckRecord, PairRequestPreview, PendingPairHandle,
    TenantRegistration,
};

struct PendingPair {
    request: PairRequest,
}

#[derive(uniffi::Object)]
pub struct WiresApp {
    rt: Runtime,
    iroh_secret: [u8; 32],
    root_signer: Arc<dyn SwiftRootSigner>,
    endpoint: OnceCell<Endpoint>,
    pending: Mutex<HashMap<String, PendingPair>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl WiresApp {
    #[uniffi::constructor]
    pub fn bootstrap(iroh_secret: Vec<u8>, root_signer: Arc<dyn SwiftRootSigner>) -> Arc<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let mut secret = [0u8; 32];
        let n = iroh_secret.len().min(32);
        secret[..n].copy_from_slice(&iroh_secret[..n]);
        Arc::new(Self {
            rt,
            iroh_secret: secret,
            root_signer,
            endpoint: OnceCell::new(),
            pending: Mutex::new(HashMap::new()),
        })
    }

    pub async fn fetch_discovery(&self, url: String) -> Result<HostInfo, WiresError> {
        tenant::fetch_discovery(&url).await
    }

    pub async fn register_with_hosted_service(
        &self,
        host: HostInfo,
    ) -> Result<TenantRegistration, WiresError> {
        let ep = self.endpoint().await?;
        tenant::register_with_hosted_service(ep, self.root_signer.clone(), &host).await
    }

    pub async fn register_topic(
        &self,
        host: HostInfo,
        topic_id: Vec<u8>,
    ) -> Result<(), WiresError> {
        if topic_id.len() != 32 {
            return Err(InternalSnafu { message: "topic_id must be 32 bytes".into() }.build());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&topic_id);
        let ep = self.endpoint().await?;
        tenant::register_topic(ep, self.root_signer.clone(), &host, &arr).await
    }

    pub fn parse_pair_request(&self, payload: String) -> Result<PairRequestPreview, WiresError> {
        let parsed = parse::parse_pair_request(&payload)?;
        let preview = parsed.preview.clone();
        self.pending
            .lock()
            .insert(parsed.handle.id.clone(), PendingPair { request: parsed.request });
        Ok(preview)
    }

    pub fn generate_topic_id_and_epoch0(&self) -> NewTopic {
        gen_topic()
    }

    pub async fn approve_pair_request(
        &self,
        handle: PendingPairHandle,
        granted_scopes: Vec<GrantedScope>,
        host: HostInfo,
    ) -> Result<PairAckRecord, WiresError> {
        let pending = self
            .pending
            .lock()
            .remove(&handle.id)
            .ok_or_else(|| UnknownPairHandleSnafu.build())?;
        let ep = self.endpoint().await?;
        pair::approve_pair_request(
            ep,
            self.root_signer.clone(),
            &pending.request,
            granted_scopes,
            host,
        )
        .await
    }

    pub fn discard_pair_request(&self, handle: PendingPairHandle) {
        self.pending.lock().remove(&handle.id);
    }
}

impl WiresApp {
    async fn endpoint(&self) -> Result<Endpoint, WiresError> {
        let ep = self
            .endpoint
            .get_or_try_init(|| async {
                let secret = SecretKey::from_bytes(&self.iroh_secret);
                wires_net::endpoint::bind_lan(secret, vec![])
                    .await
                    .map_err(|e| InternalSnafu { message: format!("bind_lan: {e}") }.build())
            })
            .await?;
        Ok(ep.clone())
    }
}
```

Confirm `Endpoint: Clone` in iroh 0.98 — if not, hold the endpoint behind `Arc<Endpoint>` and return `Arc<Endpoint>`. The wires-net helpers (`TenantClient::new`, `PairClient::new`) take ownership; we want them cloneable per call.

- [ ] **Step 2: Register and run all tests + build release**

In `crates/wires-uniffi/src/lib.rs` add:

```rust
pub mod app;
pub use app::WiresApp;
```

Run: `cargo test -p wires-uniffi`
Expected: all PASS.

Run: `cargo build -p wires-uniffi --release`
Expected: builds.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: WiresApp facade — bootstrap, discovery, register, parse, approve"
```

### Task 11: End-to-end Rust integration test against `wires-host` + a fake agent

**Files:**
- Create: `crates/wires-uniffi/tests/end_to_end.rs`

This test exercises the iOS-side path against real `wires-host` and a real `wires-node` running `pair::listen`. It is the strongest evidence that `WiresApp` composes correctly.

- [ ] **Step 1: Write the integration test**

Create `crates/wires-uniffi/tests/end_to_end.rs`:

```rust
//! Integration test: WiresApp drives a full bootstrap + approve against real
//! wires-host and wires-node processes (in-test, not subprocesses).

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tokio::time::timeout;
use wires_uniffi::{HostInfo, WiresApp, signer::SwiftRootSigner, types::EpochKey};

// In-process implementation of SwiftRootSigner using a stable SigningKey.
struct InProcessSigner(SigningKey);
impl SwiftRootSigner for InProcessSigner {
    fn pubkey(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, wires_uniffi::WiresError> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(&message).to_bytes().to_vec())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end_register_and_approve() {
    // 1. Spin up wires-host in-process with a temp data dir + an HTTP discovery
    //    endpoint serving /v1/bootstrap. (Use wires_host::run() if it exists,
    //    or compose the components directly.)
    // 2. Spin up a wires-node running pair::listen with a known PairRequest.
    // 3. Construct WiresApp with InProcessSigner.
    // 4. fetch_discovery(URL) -> HostInfo.
    // 5. register_with_hosted_service(host) -> TenantRegistration.
    // 6. generate_topic_id_and_epoch0() -> NewTopic.
    // 7. register_topic(host, new_topic.topic_id_bytes).
    // 8. parse_pair_request(token).
    // 9. approve_pair_request(handle, [GrantedScope { ... }], host).
    // 10. Assert PairAckRecord present.
    // 11. Assert host's tenants.redb shows the registered tenant + topic.
    // 12. Assert wires-node's caps.redb / keys_<topic>.redb show the
    //     installed cap + epoch key.

    // The exact composition uses wires_host::lib helpers and wires_node::pair
    // entry points already in place — fill in once verified by reading the
    // existing wires-host integration tests for reference.
    panic!("fill in body using wires_host + wires_node testing utilities");
}
```

- [ ] **Step 2: Run, expect placeholder failure, fill body in a follow-up commit**

Run: `cargo test -p wires-uniffi --test end_to_end -- --nocapture`
Expected: explicit `panic!`. Subagent dispatched on Task 11 must read `crates/wires-host/tests/` and `crates/wires-node/tests/` (e.g. acceptance harnesses) for the in-process composition pattern, then replace the placeholder with the real assertion body.

- [ ] **Step 3: Commit when end-to-end runs green**

```bash
git add crates/wires-uniffi/tests/
git commit -m "wires-uniffi: end-to-end test against wires-host + wires-node"
```

---

## Phase 3 — Build tooling and `WiresKit` package

### Task 12: `scripts/build-ioskit.sh` + WiresKit SwiftPM package

**Files:**
- Create: `scripts/build-ioskit.sh`, `Wires/WiresKit/Package.swift`, `Wires/WiresKit/.gitignore`

- [ ] **Step 1: Install iOS Rust targets (one-time per developer)**

Run:

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios-sim
```

- [ ] **Step 2: Write the build script**

Create `scripts/build-ioskit.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
TARGET_DIR="$ROOT/target"
KIT_DIR="$ROOT/Wires/WiresKit"
FRAMEWORK_DIR="$KIT_DIR/Frameworks"
SOURCES_DIR="$KIT_DIR/Sources/WiresKit"

mkdir -p "$FRAMEWORK_DIR" "$SOURCES_DIR"

echo "==> Building wires-uniffi for iOS targets"
for T in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios-sim; do
  cargo build --release --target "$T" -p wires-uniffi
done

echo "==> Lipo-ing simulator slices"
SIM_DIR="$TARGET_DIR/ios-sim-fat/release"
mkdir -p "$SIM_DIR"
lipo -create \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/libwires_uniffi.a" \
  "$TARGET_DIR/x86_64-apple-ios-sim/release/libwires_uniffi.a" \
  -output "$SIM_DIR/libwires_uniffi.a"

echo "==> Generating Swift bindings"
HEADERS_DIR="$TARGET_DIR/uniffi-headers"
rm -rf "$HEADERS_DIR"
mkdir -p "$HEADERS_DIR/include"
cargo run --release -p wires-uniffi --bin uniffi-bindgen -- \
  generate \
  --library "$TARGET_DIR/aarch64-apple-ios/release/libwires_uniffi.a" \
  --language swift \
  --out-dir "$HEADERS_DIR"

# Move headers + modulemap into a per-slice include dir.
mv "$HEADERS_DIR"/*.h "$HEADERS_DIR/include/" 2>/dev/null || true
mv "$HEADERS_DIR"/*.modulemap "$HEADERS_DIR/include/module.modulemap" 2>/dev/null || true

echo "==> Assembling xcframework"
rm -rf "$FRAMEWORK_DIR/wires.xcframework"
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/libwires_uniffi.a" \
  -headers "$HEADERS_DIR/include" \
  -library "$SIM_DIR/libwires_uniffi.a" \
  -headers "$HEADERS_DIR/include" \
  -output "$FRAMEWORK_DIR/wires.xcframework"

echo "==> Copying Swift bindings into WiresKit/Sources"
cp "$HEADERS_DIR"/*.swift "$SOURCES_DIR/"

echo "==> Done. Built $FRAMEWORK_DIR/wires.xcframework"
```

Run: `chmod +x scripts/build-ioskit.sh`.

- [ ] **Step 3: Create the WiresKit SwiftPM package**

Create `Wires/WiresKit/Package.swift`:

```swift
// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "WiresKit",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "WiresKit", targets: ["WiresKit"]),
    ],
    targets: [
        .binaryTarget(name: "wiresFFI", path: "Frameworks/wires.xcframework"),
        .target(name: "WiresKit", dependencies: ["wiresFFI"], path: "Sources/WiresKit"),
    ]
)
```

Create `Wires/WiresKit/.gitignore`:

```
Frameworks/wires.xcframework/
Sources/WiresKit/*.swift
```

(The xcframework and generated Swift are build artifacts; check the package definition into git but not the binary outputs.)

- [ ] **Step 4: Run the build script, confirm artifact**

Run: `scripts/build-ioskit.sh`
Expected: `Wires/WiresKit/Frameworks/wires.xcframework` exists and `Wires/WiresKit/Sources/WiresKit/wires_uniffi.swift` is non-empty.

- [ ] **Step 5: Commit (package definition + script, not artifacts)**

```bash
git add scripts/build-ioskit.sh Wires/WiresKit/Package.swift Wires/WiresKit/.gitignore
git commit -m "ios: WiresKit SwiftPM package + build-ioskit.sh xcframework build"
```

### Task 13: Xcode project updates

**Files:**
- Modify: `Wires/Wires.xcodeproj/...` (via Xcode UI or `xcodeproj` ruby gem if used in CI)
- Delete: `Wires/Wires/Item.swift`, `Wires/Wires/ContentView.swift`

- [ ] **Step 1: Open the project in Xcode**

```bash
open Wires/Wires.xcodeproj
```

- [ ] **Step 2: Bump deployment target**

Project → Wires (target) → General → Minimum Deployments → iOS 17.0.

- [ ] **Step 3: Add SwiftPM dependencies**

File → Add Package Dependencies…
- `https://github.com/pointfreeco/swift-composable-architecture` — exact version `1.16.0` or "Up to Next Major from 1.16.0".
- `https://github.com/pointfreeco/swift-snapshot-testing` — add to WiresTests target only.

Add the local package:
- File → Add Package Dependencies → Add Local… → select `Wires/WiresKit/`.

Link `ComposableArchitecture` and `WiresKit` into the Wires target's "Frameworks, Libraries, and Embedded Content".

- [ ] **Step 4: Remove template files**

Delete `Wires/Wires/Item.swift` and `Wires/Wires/ContentView.swift` from the project navigator. (We replace them in subsequent tasks.)

- [ ] **Step 5: Verify the project compiles (placeholder Swift entry point)**

Replace `Wires/Wires/WiresApp.swift` (the @main file) with a minimal placeholder that compiles:

```swift
import SwiftUI
import WiresKit
import ComposableArchitecture

@main
struct WiresApp: App {
    var body: some Scene {
        WindowGroup {
            Text("WiresKit loaded; build pipeline OK")
        }
    }
}
```

Build → ⌘B. Expected: green build.

- [ ] **Step 6: Commit**

```bash
git add Wires/
git commit -m "ios: Xcode project — deployment iOS 17, TCA + WiresKit deps, remove template files"
```

---

## Phase 4 — Swift dependencies

### Task 14: `HouseholdClient` (SwiftData)

**Files:**
- Create: `Wires/Wires/Models/{Household,TopicRecord,CapRecord}.swift`, `Wires/Wires/Dependencies/HouseholdClient.swift`

- [ ] **Step 1: Write the SwiftData models**

Create the three model files exactly matching the spec's §4 layout (Household, TopicRecord, CapRecord — no PendingPublish).

- [ ] **Step 2: Write the dependency client**

Create `Wires/Wires/Dependencies/HouseholdClient.swift` with the closure-based shape from the spec's §7, backed by a SwiftData `ModelContainer`. Provide:

- `liveValue` — backed by `ModelContainer(for: Household.self, TopicRecord.self, CapRecord.self)`. Use `@MainActor` for the persistent container access. Each closure opens a `ModelContext`, performs the operation, and closes.
- `testValue` — `unimplemented()` for each closure.
- `previewValue` — canned data: one Household with no caps.

- [ ] **Step 3: Write a minimal in-process round-trip test**

Create `Wires/WiresTests/HouseholdClientTests.swift`. Use an in-memory `ModelContainer`. Test:

- Save a Household, load it back, fields match.
- Save a TopicRecord, list returns it.
- Save a CapRecord, list returns it.

- [ ] **Step 4: Run and commit**

Build + test in Xcode (⌘U).
Expected: tests pass.

```bash
git add Wires/Wires/Models/ Wires/Wires/Dependencies/HouseholdClient.swift Wires/WiresTests/HouseholdClientTests.swift
git commit -m "ios: SwiftData models + HouseholdClient with round-trip tests"
```

### Task 15: `KeychainClient`

**Files:**
- Create: `Wires/Wires/Dependencies/KeychainClient.swift`, `Wires/WiresTests/KeychainClientTests.swift`

- [ ] **Step 1: Write the client**

Create `Wires/Wires/Dependencies/KeychainClient.swift` exposing:

```swift
enum KeychainAccessibility {
    case afterFirstUnlockThisDeviceOnly
    case afterFirstUnlockThisDeviceOnlyBiometricCurrentSet
}

enum KeychainError: Error {
    case notFound
    case biometricCancelled
    case biometricFailed
    case unexpectedStatus(OSStatus)
}

@DependencyClient struct KeychainClient {
    var getData: @Sendable (_ account: String) throws -> Data?
    var setData: @Sendable (_ account: String, _ value: Data, _ accessibility: KeychainAccessibility) throws -> Void
    var deleteData: @Sendable (_ account: String) throws -> Void
    var signWithBiometric: @Sendable (_ account: String, _ message: Data) async throws -> Data
}
```

`liveValue` uses `SecItemCopyMatching` / `SecItemAdd` / `SecItemDelete` with service = `"wires"`. Biometric variant uses `SecAccessControlCreateWithFlags(.privateKeyUsage, [.biometryCurrentSet])` and a `LAContext` for the sign operation. The biometric `signWithBiometric` flow:

1. Read the seed bytes with a `LAContext` whose `evaluatedPolicyDomainState` was already consumed in this call (Face ID prompts here).
2. Reconstruct `Curve25519.Signing.PrivateKey` from the seed.
3. Sign `message`. Zero the seed buffer before returning.

- [ ] **Step 2: Test the non-biometric path**

Create `Wires/WiresTests/KeychainClientTests.swift`. Test cases:

- `set + get` round-trips.
- `delete` removes the item; subsequent `get` returns `nil`.
- `get` of non-existent account returns `nil` (does not throw).
- Setting twice for the same account overwrites.

Biometric tests are manual / device-only and live in `WiresUITests`. Stubbed here.

- [ ] **Step 3: Run and commit**

```bash
git add Wires/Wires/Dependencies/KeychainClient.swift Wires/WiresTests/KeychainClientTests.swift
git commit -m "ios: KeychainClient with set/get/delete + biometric sign stub"
```

### Task 16: `WiresClient` live impl wraps `WiresApp`

**Files:**
- Create: `Wires/Wires/Dependencies/WiresClient.swift`, `Wires/WiresTests/WiresClientLiveTests.swift`

- [ ] **Step 1: Write the dependency client wrapping `WiresApp`**

Create `Wires/Wires/Dependencies/WiresClient.swift`:

```swift
import ComposableArchitecture
import Dependencies
import Foundation
import WiresKit

@DependencyClient struct WiresClient {
    var bootstrap: @Sendable (Data, any SwiftRootSigner) -> Void
    var fetchDiscovery: @Sendable (String) async throws -> HostInfo
    var registerWithHostedService: @Sendable (HostInfo) async throws -> TenantRegistration
    var registerTopic: @Sendable (HostInfo, Data) async throws -> Void
    var parsePairRequest: @Sendable (String) throws -> PairRequestPreview
    var generateTopicIdAndEpoch0: @Sendable () -> NewTopic
    var approvePairRequest: @Sendable (PendingPairHandle, [GrantedScope], HostInfo) async throws -> PairAckRecord
    var discardPairRequest: @Sendable (PendingPairHandle) -> Void
}
```

The `liveValue` constructs a `WiresApp` lazily (on first `bootstrap` call) and stores it in an actor-isolated holder. Subsequent calls dispatch to the same `WiresApp`. UniFFI's generated `WiresApp` is `Arc<>` on the Rust side and `Sendable` on Swift.

The `SwiftRootSigner` protocol comes from the UniFFI-generated header; the live `WiresClient` wraps a `KeychainBackedRootSigner` (defined in the same file or `Dependencies/RootSigner.swift`) that uses `KeychainClient.signWithBiometric` for `sign(_:)` and returns the cached pubkey for `pubkey()`.

`testValue` uses `unimplemented()` for every closure; `previewValue` returns canned data.

- [ ] **Step 2: Write a smoke test that constructs the live client**

Create `Wires/WiresTests/WiresClientLiveTests.swift`. Test that:

- Calling `parsePairRequest` on a known-invalid string returns an error (we know it does because UniFFI maps `InvalidPairRequest`).
- Calling `generateTopicIdAndEpoch0` returns a topic_id_hex of length 64 and a 32-byte epoch_0_key.

These are deterministic-without-network tests; the live network calls (fetchDiscovery, register…, approve…) are exercised in `end_to_end.rs` on the Rust side and in `BootstrapFeatureTests` / `AgentEnrollmentFeatureTests` via `testValue`.

- [ ] **Step 3: Run and commit**

```bash
git add Wires/Wires/Dependencies/WiresClient.swift Wires/WiresTests/WiresClientLiveTests.swift
git commit -m "ios: WiresClient — TCA wrapper around WiresApp"
```

---

## Phase 5 — Swift TCA features

### Task 17: `AppFeature` + root composition

**Files:**
- Modify: `Wires/Wires/WiresApp.swift`
- Create: `Wires/Wires/App/AppFeature.swift`

- [ ] **Step 1: Write `AppFeature`**

Create `Wires/Wires/App/AppFeature.swift`:

```swift
import ComposableArchitecture

@Reducer
struct AppFeature {
    @ObservableState
    enum State: Equatable {
        case launching
        case bootstrap(BootstrapFeature.State)
        case home(HomeFeature.State)
    }

    enum Action {
        case onAppear
        case householdLoaded(Household?)
        case bootstrap(BootstrapFeature.Action)
        case home(HomeFeature.Action)
    }

    @Dependency(\.householdClient) var household

    var body: some ReducerOf<Self> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                return .run { send in
                    let h = try? await household.loadHousehold()
                    await send(.householdLoaded(h))
                }
            case let .householdLoaded(h):
                if let h, h.tenantRegisteredAt != nil {
                    state = .home(HomeFeature.State(household: h))
                } else {
                    state = .bootstrap(BootstrapFeature.State())
                }
                return .none
            case .bootstrap, .home:
                return .none
            }
        }
        .ifCaseLet(\.bootstrap, action: \.bootstrap) { BootstrapFeature() }
        .ifCaseLet(\.home, action: \.home) { HomeFeature() }
    }
}
```

- [ ] **Step 2: Wire into `@main`**

Replace `Wires/Wires/WiresApp.swift`:

```swift
import ComposableArchitecture
import SwiftUI

@main
struct WiresApp: App {
    static let store = Store(initialState: AppFeature.State.launching) {
        AppFeature()
    }

    var body: some Scene {
        WindowGroup {
            AppView(store: Self.store)
        }
    }
}

struct AppView: View {
    let store: StoreOf<AppFeature>

    var body: some View {
        SwitchStore(store) { initialState in
            switch initialState {
            case .launching:
                ProgressView().task { store.send(.onAppear) }
            case .bootstrap:
                CaseLet(\AppFeature.State.bootstrap, action: AppFeature.Action.bootstrap) { childStore in
                    BootstrapView(store: childStore)
                }
            case .home:
                CaseLet(\AppFeature.State.home, action: AppFeature.Action.home) { childStore in
                    HomeView(store: childStore)
                }
            }
        }
    }
}
```

`BootstrapFeature` and `HomeFeature` don't exist yet — stub them with minimal `@Reducer struct` and `View` so the file compiles. Real bodies arrive in tasks 18–21.

- [ ] **Step 3: Build, commit**

Build (⌘B). Expected: green.

```bash
git add Wires/Wires/App/ Wires/Wires/WiresApp.swift
git commit -m "ios: AppFeature + root composition"
```

### Task 18: `BootstrapFeature` (discovery URL → confirm host → register → done)

**Files:**
- Create: `Wires/Wires/Features/Bootstrap/{BootstrapFeature,BootstrapView,DiscoveryURLView,ConfirmHostView}.swift`
- Create: `Wires/WiresTests/BootstrapFeatureTests.swift`

- [ ] **Step 1: Write the reducer**

Create `Wires/Wires/Features/Bootstrap/BootstrapFeature.swift`. State + actions for three steps: `discoveryUrl`, `confirmHost(HostInfo)`, `done(Household)`. Effects:

- `fetchDiscovery` → on success transition to confirmHost; on error stay on discoveryUrl with error.
- `registerWithHostedService` → on success construct Household, save via HouseholdClient, transition to done.
- "Continue" from done → emits `bootstrapCompleted` which the parent observes.

- [ ] **Step 2: Write the view files**

Three small SwiftUI views. The view file is a thin observation over `@Bindable var store: StoreOf<BootstrapFeature>`.

- [ ] **Step 3: Write TestStore tests covering the spec §10 cases**

In `BootstrapFeatureTests.swift`:

- Happy path: enter URL → confirm host → register → done.
- Bad discovery URL (`testValue` throws) → alert, stays on URL step.
- Empty endpoints (`testValue` returns DiscoveryEmpty) → alert.
- Tenant register fails → retry → succeeds.
- Tenant register receives `TenantErrorCode.BadSignature` → alert with code-specific copy.

Each test uses `withDependencies` to inject mock closures and asserts the exact action sequence with `TestStore`.

- [ ] **Step 4: Run + commit**

Build + test (⌘U).

```bash
git add Wires/Wires/Features/Bootstrap/ Wires/WiresTests/BootstrapFeatureTests.swift
git commit -m "ios: BootstrapFeature — discovery -> confirm -> register -> done"
```

### Task 19: `HomeFeature`

**Files:**
- Create: `Wires/Wires/Features/Home/{HomeFeature,HomeView}.swift`
- Create: `Wires/WiresTests/HomeFeatureTests.swift`

- [ ] **Step 1: Write the reducer**

Lists caps grouped by agent. Single "Approve agent" button that presents `AgentEnrollmentFeature` (stubbed for now; real body in task 21). Loads caps from `HouseholdClient.listCaps` on appear.

- [ ] **Step 2: Write the view**

A `List` over caps, sectioned by `agentPubkeyHex`. Section header shows `agentAlias` if present, else `agentPubkeyHex` truncated.

- [ ] **Step 3: Tests**

- `.onAppear` triggers `listCaps`; state populates.
- "Approve agent" tap presents `AgentEnrollmentFeature`.
- Empty state renders correctly.

- [ ] **Step 4: Commit**

```bash
git add Wires/Wires/Features/Home/ Wires/WiresTests/HomeFeatureTests.swift
git commit -m "ios: HomeFeature — caps list, approve-agent button"
```

### Task 20: `ScanFeature` (reusable QR scanner)

**Files:**
- Create: `Wires/Wires/Features/Scan/{ScanFeature,ScanView}.swift`
- Create: `Wires/WiresTests/ScanFeatureTests.swift`

- [ ] **Step 1: Write the reducer**

State: `cameraPermission: PermissionStatus`, `lastDecoded: String?`, `error: ScanError?`. Actions: `appeared`, `permissionResolved(PermissionStatus)`, `decoded(String)`, `decodeFailed(ScanError)`.

The reducer holds an init-time parser closure `(String) throws -> Payload` so the same reducer is reused for `PairRequest` parsing in agent-enrollment. The reducer emits `decodedPayload(Payload)` after the parser succeeds.

- [ ] **Step 2: Write the view**

`ScanView` wraps an AVFoundation `AVCaptureSession` with `AVCaptureMetadataOutput` for QR detection. Permission denied state shows an alert with "Open Settings" deep link.

- [ ] **Step 3: Tests**

- Permission-denied path emits the right action.
- Decoded payload propagates through the parser.
- Parser-throws decoded path emits `decodeFailed`.

- [ ] **Step 4: Commit**

```bash
git add Wires/Wires/Features/Scan/ Wires/WiresTests/ScanFeatureTests.swift
git commit -m "ios: ScanFeature — reusable QR scanner with parser closure"
```

### Task 21: `AgentEnrollmentFeature` + `ApprovalFeature`

**Files:**
- Create: `Wires/Wires/Features/AgentEnrollment/{AgentEnrollmentFeature,ApprovalFeature,AgentEnrollmentView}.swift`
- Create: `Wires/WiresTests/{AgentEnrollmentFeatureTests,ApprovalFeatureTests}.swift`

- [ ] **Step 1: `AgentEnrollmentFeature`**

A small two-state stack: `scan(ScanFeature.State)` → `approve(ApprovalFeature.State)`. The scan parser is `WiresClient.parsePairRequest`. On decode success, transitions to `approve` with the `PairRequestPreview`.

- [ ] **Step 2: `ApprovalFeature`**

State per the spec §3.2 step 3: per-scope grant/deny + rights toggles; per-new-topic create/skip. Approve action runs the effect chain:

1. For each granted scope: load epoch keys from KeychainClient; or generate + register a new topic for literal-name scopes with no `TopicRecord`. Call `WiresClient.registerTopic` for new topics.
2. Build `[GrantedScope]` from the resolved per-scope info.
3. Call `WiresClient.approvePairRequest(handle, grantedScopes, host)`.
4. On `Ok(ack)`: persist `CapRecord` via `HouseholdClient`, dismiss.
5. On error: render via `userMessage(for:)` and keep sheet open.

- [ ] **Step 3: Tests covering the spec §10 cases**

In `AgentEnrollmentFeatureTests.swift` and `ApprovalFeatureTests.swift`, write the eight scenarios listed in spec §10 (existing topic happy path, narrowed rights, new topic, deny one scope, expired pair request, topic-register fail with retry, pair-deliver reject, pair-deliver success persists exactly once).

- [ ] **Step 4: Commit**

```bash
git add Wires/Wires/Features/AgentEnrollment/ Wires/WiresTests/{AgentEnrollmentFeatureTests,ApprovalFeatureTests}.swift
git commit -m "ios: AgentEnrollmentFeature + ApprovalFeature — scan, approve, mint, deliver"
```

---

## Phase 6 — Snapshot tests + manual acceptance

### Task 22: UI snapshot tests

**Files:**
- Create: `Wires/WiresUITests/SnapshotTests.swift`

- [ ] **Step 1: Write the snapshot suite**

Using `swift-snapshot-testing`, one snapshot per state listed in the spec §10:

- Bootstrap: enter URL, confirm host, registering, done.
- Home: empty, populated.
- Approval sheet: pristine, partially-narrowed, all-denied, in-flight, success.

Each test renders the view with canned `previewValue` state and asserts the image matches a recorded baseline (committed to the repo).

- [ ] **Step 2: Record baselines once on a known-good build**

Run with the snapshot recording flag enabled in Xcode, then disable. Commit the baselines.

- [ ] **Step 3: Commit**

```bash
git add Wires/WiresUITests/
git commit -m "ios: UI snapshot test suite + recorded baselines"
```

### Task 23: Manual acceptance pre-release checklist

**Files:**
- Create: `docs/ios-acceptance.md`

- [ ] **Step 1: Write the checklist**

Document the four manual scenarios from spec §10 "End-to-end manual acceptance". Each entry: prerequisites, exact CLI commands to run on the host/agent machines, the iOS interaction, the expected observable result.

- [ ] **Step 2: Walk through the checklist on real hardware**

Document the run (date, build, observations) in a follow-up commit.

- [ ] **Step 3: Commit the doc**

```bash
git add docs/ios-acceptance.md
git commit -m "ios: manual acceptance pre-release checklist"
```

---

## Self-review notes

- **Spec coverage.** Each section of the spec is implemented by tasks above: §2 trust model → tasks 14/15 (Keychain/SwiftData); §3.1 bootstrap → task 18; §3.2 agent approval → tasks 20–21; §3.3 per-launch refresh → task 17 (AppFeature); §4 data model → task 14; §5 wire-side surface → tasks 1–2 (RootSigner lift only); §6 Rust FFI → tasks 3–11; §7 Swift architecture → tasks 17–21; §8 build → tasks 12–13; §9 errors → task 4 + per-feature alert handling in tasks 18/21; §10 testing → integrated into the corresponding tasks plus task 22.
- **Type consistency.** `PendingPairHandle`, `HostInfo`, `TenantRegistration`, `PairRequestPreview`, `PairAckRecord`, `GrantedScope`, `EpochKey`, `NewTopic`, `Right`, `TenantErrorCode`, `PairRejectCode` are all defined once (task 5) and referenced by exactly those names elsewhere. The Rust-side `WiresError` variants (task 4) name-match the Swift `WiresError` cases UniFFI generates.
- **Placeholder review.** Task 11's integration-test body is intentionally a `panic!` with a documented filler step ("read existing wires-host integration tests for the in-process composition pattern, then replace"). All other tasks contain complete code or exact commands.
- **Open verifications** (not blockers; resolved at task time): exact UniFFI 0.28 syntax for re-exporting `wires_net` enums via `#[uniffi::remote]`; iroh 0.98 `EndpointAddr` method names (`with_ip_addr` / `add_endpoint_addr`); whether `iroh::Endpoint: Clone` or needs `Arc<Endpoint>`; exact `PairRequest::decode_and_verify` / `new_signed` / `encode` method names. Each task notes the verification expected during implementation.
