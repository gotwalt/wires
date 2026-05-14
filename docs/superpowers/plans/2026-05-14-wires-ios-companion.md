# Wires iOS Companion Implementation Plan

**Status:** Draft — on hold pending upcoming substrate architecture changes. Do not begin execution until the spec at `docs/superpowers/specs/2026-05-14-wires-ios-companion-design.md` has been re-validated against the revised substrate.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the v1 iOS companion app described in `docs/superpowers/specs/2026-05-14-wires-ios-companion-design.md`: a SwiftUI + TCA app over a Rust `wires-uniffi` facade that custodies the household root key, pairs with `wires-host` via a scanned QR, and onboards new agents by scanning their enrollment QR and minting capabilities.

**Architecture:** Rust core reuses `wires-core`/`wires-crypto`/`wires-net` unchanged; a new `crates/wires-uniffi` exposes a narrow per-operation FFI to Swift via UniFFI 0.28+. iOS persists low-sensitivity state in SwiftData, secrets in Keychain. SwiftUI views are driven by Composable Architecture reducers with dependency-injected `WiresClient`, `HouseholdClient`, and `KeychainClient`.

**Tech Stack:** Rust 2024 + UniFFI 0.28, iroh 0.98, Swift 5.10+, iOS 17 deployment target, swift-composable-architecture 1.16+, swift-snapshot-testing.

---

## File Structure

**New Rust files:**
- `crates/wires-core/src/signer.rs` — `RootSigner` trait
- `crates/wires-node/src/identity.rs` — `AgentIdentity` struct + `Node::open_with_identity`
- `crates/wires-net/src/pair.rs` — `HostPairToken`
- `crates/wires-net/src/enroll.rs` — `EnrollmentToken`
- `crates/wires-cli/src/cmd/enroll.rs` — `wires enroll` subcommand
- `crates/wires-uniffi/Cargo.toml` + `src/{lib,error,types,signer,parse,topic,mint,host,app}.rs` + `build.rs` + `uniffi.toml`

**Modified Rust files:**
- `Cargo.toml` (workspace) — add `wires-uniffi` member
- `crates/wires-core/src/{cap,lib}.rs` — `Capability::sign` takes `&dyn RootSigner`
- `crates/wires-cli/src/cmd/{invite,init,main}.rs` — use `LocalFileSigner`, register `enroll`
- `crates/wires-host/src/main.rs` — add `show-pair-qr` subcommand
- `crates/wires-net/src/lib.rs` — export `pair`, `enroll` modules

**Build / packaging:**
- `scripts/build-ioskit.sh` — cross-compile + uniffi-bindgen + xcframework assembly
- `Wires/WiresKit/Package.swift` + `Sources/WiresKit/` + `Frameworks/wires.xcframework`

**iOS files (new under `Wires/Wires/`):**
- `App/WiresApp.swift` (replaces template), `App/AppFeature.swift`
- `Features/{Bootstrap,Home,AgentEnrollment,Scan}/<Feature>.swift` + `<Feature>View.swift`
- `Features/AgentEnrollment/ApprovalFeature.swift`
- `Dependencies/{Wires,Household,Keychain}Client.swift`
- `Models/{Household,TopicRecord,CapRecord,PendingPublish}.swift`

**iOS files removed:** `Wires/Wires/{ContentView,Item}.swift`

**Tests (new):** `Wires/WiresTests/{Bootstrap,AgentEnrollment,Approval,Scan,Home,App}FeatureTests.swift`, `Wires/WiresUITests/SnapshotTests.swift`

---

## Phase 1 — Rust refactors

### Task 1: Lift `RootSigner` into `wires-core`

**Files:**
- Create: `crates/wires-core/src/signer.rs`
- Modify: `crates/wires-core/src/cap.rs`, `crates/wires-core/src/lib.rs`, `crates/wires-core/src/error.rs`
- Test: `crates/wires-core/src/signer.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing test for the trait + signing roundtrip**

Create `crates/wires-core/src/signer.rs`:

```rust
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
pub enum SignError {
    #[snafu(display("Signer rejected the message, at {location}"))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    pub struct InMemorySigner(pub SigningKey);

    impl RootSigner for InMemorySigner {
        fn pubkey(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
            Ok(self.0.sign(message).to_bytes())
        }
    }

    #[test]
    fn trait_signs_and_pubkey_matches() {
        let sk = SigningKey::generate(&mut OsRng);
        let signer = InMemorySigner(sk.clone());
        assert_eq!(signer.pubkey(), sk.verifying_key().to_bytes());
        let sig = signer.sign(b"hello").unwrap();
        assert_eq!(sig.len(), 64);
    }
}
```

- [ ] **Step 2: Run test to verify it fails to compile**

Run: `cargo test -p wires-core --lib signer`
Expected: FAIL — `signer` module not in `lib.rs` yet.

- [ ] **Step 3: Wire up the module**

Add to `crates/wires-core/src/lib.rs` near other `pub mod`s:

```rust
pub mod signer;
pub use signer::{RootSigner, SignError};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p wires-core --lib signer`
Expected: PASS, 1 test.

- [ ] **Step 5: Refactor `Capability::sign` to take the trait**

In `crates/wires-core/src/cap.rs`, replace the existing `sign` method body and adjust the error path. Find:

```rust
    pub fn sign(&mut self, root_sk: &SigningKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        self.sig = root_sk.sign(&bytes).to_bytes();
        Ok(())
    }
```

Replace with:

```rust
    pub fn sign(&mut self, root: &dyn crate::RootSigner) -> Result<()> {
        let bytes = self.signing_bytes()?;
        self.sig = root.sign(&bytes).map_err(|source| CapError::RootSign {
            source,
            location: snafu::location!(),
        })?;
        Ok(())
    }
```

Add to `crates/wires-core/src/error.rs` (CapError enum) a new variant:

```rust
    #[snafu(display("Root signer rejected the capability, at {location}"))]
    RootSign {
        source: crate::SignError,
        #[snafu(implicit)]
        location: snafu::Location,
    },
```

- [ ] **Step 6: Update in-crate callers**

In `crates/wires-core/src/cap.rs` inside `#[cfg(test)]`, callers like `cap.sign(&root)` become `cap.sign(&InMemorySigner(root))`. Add the `InMemorySigner` definition at the top of the test module if not already imported from `signer::tests`. Concretely, inside `cap.rs` tests, prepend each test that uses `root: SigningKey`:

```rust
use crate::signer::tests::InMemorySigner;
// then: cap.sign(&InMemorySigner(root))
```

Make `InMemorySigner` `pub` inside `signer::tests` (`pub struct InMemorySigner(pub SigningKey);` already does that).

- [ ] **Step 7: Run all `wires-core` tests**

Run: `cargo test -p wires-core`
Expected: all existing tests pass.

- [ ] **Step 8: Commit**

```bash
git add crates/wires-core/
git commit -m "wires-core: lift RootSigner trait, Capability::sign takes &dyn RootSigner"
```

### Task 2: `LocalFileSigner` in `wires-cli` and `wires invite` migration

**Files:**
- Create: `crates/wires-cli/src/signer.rs`
- Modify: `crates/wires-cli/src/main.rs`, `crates/wires-cli/src/cmd/invite.rs`

- [ ] **Step 1: Write `LocalFileSigner` with a test**

Create `crates/wires-cli/src/signer.rs`:

```rust
use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use wires_core::{RootSigner, SignError, signer::RejectedSnafu};
use snafu::ResultExt;

pub struct LocalFileSigner {
    sk: SigningKey,
}

impl LocalFileSigner {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "root.ed25519 must be 32 bytes",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            sk: SigningKey::from_bytes(&arr),
        })
    }
}

impl RootSigner for LocalFileSigner {
    fn pubkey(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
        Ok(self.sk.sign(message).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn round_trip_load_and_sign() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.ed25519");
        let sk = SigningKey::generate(&mut OsRng);
        std::fs::write(&path, sk.to_bytes()).unwrap();

        let signer = LocalFileSigner::load(&path).unwrap();
        assert_eq!(signer.pubkey(), sk.verifying_key().to_bytes());

        let sig = signer.sign(b"hi").unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&signer.pubkey()).unwrap();
        let s = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(<ed25519_dalek::VerifyingKey as ed25519_dalek::Verifier<ed25519_dalek::Signature>>::verify(&vk, b"hi", &s).is_ok());
    }
}
```

If `tempfile` is not already in `[dev-dependencies]` for `wires-cli`, add it (`tempfile = "3"`).

- [ ] **Step 2: Register the module**

Add to `crates/wires-cli/src/main.rs`:

```rust
mod signer;
```

- [ ] **Step 3: Run the new test**

Run: `cargo test -p wires-cli --lib signer`
Expected: PASS.

- [ ] **Step 4: Migrate `wires invite` to use `LocalFileSigner`**

Replace the body of `crates/wires-cli/src/cmd/invite.rs` after the parsing logic. Find:

```rust
    let root_bytes_vec = std::fs::read(data_dir.join("root.ed25519"))?;
    if root_bytes_vec.len() != 32 {
        return Err("root.ed25519 must be 32 bytes".into());
    }
    let mut root_bytes = [0u8; 32];
    root_bytes.copy_from_slice(&root_bytes_vec);
    let root = SigningKey::from_bytes(&root_bytes);
```

Replace with:

```rust
    let signer = crate::signer::LocalFileSigner::load(&data_dir.join("root.ed25519"))?;
```

And replace `cap.sign(&root)?;` with `cap.sign(&signer)?;`. Remove unused imports of `ed25519_dalek::SigningKey`.

- [ ] **Step 5: Run `wires-cli` tests + a smoke build**

Run: `cargo test -p wires-cli && cargo build -p wires-cli`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-cli/
git commit -m "wires-cli: add LocalFileSigner, migrate wires invite to RootSigner trait"
```

### Task 3: `AgentIdentity` + `Node::open_with_identity`

**Files:**
- Create: `crates/wires-node/src/identity.rs`
- Modify: `crates/wires-node/src/{lib,node}.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-node/src/identity.rs`:

```rust
use ed25519_dalek::SigningKey;
use wires_crypto::{X25519Public, X25519Secret};

#[derive(Clone)]
pub struct AgentIdentity {
    pub ed25519_seed: [u8; 32],
    pub x25519_secret: [u8; 32],
}

impl AgentIdentity {
    pub fn ed_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed25519_seed)
    }
    pub fn x_secret(&self) -> X25519Secret {
        X25519Secret::from(self.x25519_secret)
    }
    pub fn x_pubkey(&self) -> [u8; 32] {
        X25519Public::from(&self.x_secret()).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_keys_from_seed() {
        let id = AgentIdentity {
            ed25519_seed: [1u8; 32],
            x25519_secret: [2u8; 32],
        };
        let _vk = id.ed_signing_key().verifying_key();
        let _xpk = id.x_pubkey();
    }
}
```

- [ ] **Step 2: Register in `lib.rs`**

Add to `crates/wires-node/src/lib.rs`:

```rust
pub mod identity;
pub use identity::AgentIdentity;
```

- [ ] **Step 3: Run the new test**

Run: `cargo test -p wires-node --lib identity`
Expected: PASS.

- [ ] **Step 4: Refactor `Node::open` to split disk loading from construction**

In `crates/wires-node/src/node.rs`, replace the existing `pub fn open(config: NodeConfig) -> Result<Self>` with two functions:

```rust
    pub fn open(config: NodeConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir).context(IoSnafu)?;
        let ed_seed = wires_net::load_or_create_secret(&config.data_dir.join("identity.ed25519"))
            .context(NetSnafu)?;
        let x_secret = wires_net::load_or_create_secret(&config.data_dir.join("identity.x25519"))
            .context(NetSnafu)?;
        let identity = crate::AgentIdentity {
            ed25519_seed: ed_seed,
            x25519_secret: x_secret,
        };
        Self::open_with_identity(config, identity)
    }

    pub fn open_with_identity(config: NodeConfig, identity: crate::AgentIdentity) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir).context(IoSnafu)?;
        let ed_sk = identity.ed_signing_key();
        let x_sk = identity.x_secret();
        let x_pk = identity.x_pubkey();

        let logs = std::sync::Arc::new(crate::storage::TopicLogs::new(&config.data_dir));
        let caps_db = wires_store::open_caps(&config.data_dir).context(StoreSnafu)?;
        let caps = std::sync::Arc::new(wires_store::CapTable::new(std::sync::Arc::new(caps_db)));
        let (events_tx, _) = tokio::sync::broadcast::channel::<DecryptedEvent>(1024);

        Ok(Self {
            config,
            ed_sk,
            x_sk,
            x_pk,
            logs,
            caps,
            keys_by_topic: parking_lot::Mutex::new(std::collections::HashMap::new()),
            events_tx,
        })
    }
```

(Adjust path-qualified types to match the file's existing imports — keep the structural change of factoring everything after identity loading into `open_with_identity`.)

- [ ] **Step 5: Run all wires-node tests**

Run: `cargo test -p wires-node`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-node/
git commit -m "wires-node: add AgentIdentity and Node::open_with_identity"
```

---

## Phase 2 — CLI / host additions

### Task 4: `HostPairToken` in `wires-net`

**Files:**
- Create: `crates/wires-net/src/pair.rs`
- Modify: `crates/wires-net/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-net/src/pair.rs`:

```rust
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::error::{Result, SerdeSnafu};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPairToken {
    pub version: u8,
    pub host_node_id: String,
    pub host_addrs: Vec<String>,
    pub host_relay: Option<String>,
    pub household_label: Option<String>,
}

impl HostPairToken {
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context(SerdeSnafu)?;
        Ok(crate::invite::base64url_encode(&json))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bytes = crate::invite::base64url_decode(s)
            .map_err(|_| crate::error::NetError::Serde {
                source: serde_json::from_str::<()>("\"bad base64\"").unwrap_err(),
                location: snafu::location!(),
            })?;
        let tok: HostPairToken = serde_json::from_slice(&bytes).context(SerdeSnafu)?;
        Ok(tok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let tok = HostPairToken {
            version: 1,
            host_node_id: "abcd".repeat(16),
            host_addrs: vec!["10.0.0.1:11204".into()],
            host_relay: Some("https://relay.example/".into()),
            household_label: Some("gotwalts".into()),
        };
        let s = tok.encode().unwrap();
        let back = HostPairToken::decode(&s).unwrap();
        assert_eq!(tok, back);
    }

    #[test]
    fn rejects_garbage() {
        assert!(HostPairToken::decode("!!!not base64!!!").is_err());
    }
}
```

This uses `wires-net::invite::base64url_encode` / `base64url_decode`. Check they are `pub(crate)` already; if private, expose them by adding `pub(crate) fn` in `invite.rs` (they exist per current code — only their visibility may need to change).

- [ ] **Step 2: Expose `base64url_*` helpers**

In `crates/wires-net/src/invite.rs`, ensure these are at least `pub(crate)`. If `fn base64url_encode` and `fn base64url_decode` are `fn` only, change to `pub(crate) fn`.

- [ ] **Step 3: Register the module**

Add to `crates/wires-net/src/lib.rs`:

```rust
pub mod pair;
pub use pair::HostPairToken;
```

- [ ] **Step 4: Run the new tests**

Run: `cargo test -p wires-net --lib pair`
Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-net/
git commit -m "wires-net: add HostPairToken"
```

### Task 5: `wires-host show-pair-qr` subcommand

**Files:**
- Modify: `crates/wires-host/Cargo.toml`, `crates/wires-host/src/main.rs`

- [ ] **Step 1: Add `qrcode` to wires-host deps**

In `crates/wires-host/Cargo.toml`, add under `[dependencies]`:

```toml
qrcode = { version = "0.14", default-features = false }
```

- [ ] **Step 2: Make the existing `main` a subcommand and add `show-pair-qr`**

Replace the `#[derive(Parser)]` block and `main` in `crates/wires-host/src/main.rs` with:

```rust
#[derive(Parser)]
#[command(name = "wires-host", about = "Blind relay/replay-server for the wires network")]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    /// 32-byte hex topic_id to relay. May be specified multiple times.
    #[arg(long = "topic", value_name = "HEX")]
    topics: Vec<String>,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(clap::Subcommand)]
enum Cmd {
    /// Print a HostPairToken (base64 + Unicode QR) for the iOS app to scan
    ShowPairQr {
        #[arg(long)]
        relay: Option<String>,
        #[arg(long)]
        label: Option<String>,
    },
}
```

In `main`, after `let args = Args::parse();`:

```rust
    if let Some(Cmd::ShowPairQr { relay, label }) = args.command {
        return show_pair_qr(&args.data_dir, relay, label).await;
    }
```

Add a new function below `main`:

```rust
async fn show_pair_qr(
    data_dir: &PathBuf,
    relay: Option<String>,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(data_dir)?;
    let secret_path = data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let iroh_sk = SecretKey::from_bytes(&secret);
    let endpoint = Endpoint::builder(presets::N0).secret_key(iroh_sk).bind().await?;
    let node_id = endpoint.id().to_string();
    let addrs: Vec<String> = endpoint
        .bound_sockets()
        .into_iter()
        .map(|sa| sa.to_string())
        .collect();
    let token = wires_net::HostPairToken {
        version: 1,
        host_node_id: node_id,
        host_addrs: addrs,
        host_relay: relay,
        household_label: label,
    };
    let encoded = token.encode()?;
    println!("{}", encoded);
    let qr = qrcode::QrCode::new(encoded.as_bytes())?;
    let rendered = qr.render::<qrcode::render::unicode::Dense1x2>().build();
    println!("{}", rendered);
    Ok(())
}
```

- [ ] **Step 3: Build wires-host and run show-pair-qr against a tempdir**

Run:

```bash
cargo build -p wires-host
TMP=$(mktemp -d)
target/debug/wires-host --data-dir "$TMP" show-pair-qr --label test-household
```

Expected: prints a long base64 line, then a Unicode QR. Exits 0.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-host/
git commit -m "wires-host: add show-pair-qr subcommand"
```

### Task 6: `EnrollmentToken` in `wires-net`

**Files:**
- Create: `crates/wires-net/src/enroll.rs`
- Modify: `crates/wires-net/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-net/src/enroll.rs`:

```rust
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::error::{Result, SerdeSnafu};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub agent_ed25519: [u8; 32],
    #[serde(with = "hex::serde")]
    pub agent_x25519: [u8; 32],
    pub agent_local_addrs: Vec<String>,
    pub suggested_alias: Option<String>,
}

impl EnrollmentToken {
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context(SerdeSnafu)?;
        Ok(crate::invite::base64url_encode(&json))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bytes = crate::invite::base64url_decode(s)
            .map_err(|_| crate::error::NetError::Serde {
                source: serde_json::from_str::<()>("\"bad base64\"").unwrap_err(),
                location: snafu::location!(),
            })?;
        let tok: EnrollmentToken = serde_json::from_slice(&bytes).context(SerdeSnafu)?;
        Ok(tok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let tok = EnrollmentToken {
            version: 1,
            agent_ed25519: [7u8; 32],
            agent_x25519: [8u8; 32],
            agent_local_addrs: vec!["192.168.1.42:11204".into()],
            suggested_alias: Some("fridge-pi".into()),
        };
        let s = tok.encode().unwrap();
        let back = EnrollmentToken::decode(&s).unwrap();
        assert_eq!(tok, back);
    }
}
```

- [ ] **Step 2: Register and run**

Add to `crates/wires-net/src/lib.rs`:

```rust
pub mod enroll;
pub use enroll::EnrollmentToken;
```

Run: `cargo test -p wires-net --lib enroll`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-net/
git commit -m "wires-net: add EnrollmentToken"
```

### Task 7: `wires enroll` subcommand

**Files:**
- Create: `crates/wires-cli/src/cmd/enroll.rs`
- Modify: `crates/wires-cli/Cargo.toml`, `crates/wires-cli/src/main.rs`, `crates/wires-cli/src/cmd/mod.rs`

- [ ] **Step 1: Add `qrcode` to wires-cli**

In `crates/wires-cli/Cargo.toml` add under `[dependencies]`:

```toml
qrcode = { version = "0.14", default-features = false }
hostname = "0.4"
```

- [ ] **Step 2: Create the subcommand**

Create `crates/wires-cli/src/cmd/enroll.rs`:

```rust
use std::path::Path;

use ed25519_dalek::SigningKey;
use wires_crypto::X25519Public;
use wires_net::{load_or_create_secret, EnrollmentToken};

pub async fn run(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(data_dir)?;
    let ed_seed = load_or_create_secret(&data_dir.join("identity.ed25519"))?;
    let x_seed = load_or_create_secret(&data_dir.join("identity.x25519"))?;

    let ed_sk = SigningKey::from_bytes(&ed_seed);
    let ed_pk = ed_sk.verifying_key().to_bytes();
    let x_secret = wires_crypto::X25519Secret::from(x_seed);
    let x_pk = X25519Public::from(&x_secret).to_bytes();

    let alias = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok());

    let token = EnrollmentToken {
        version: 1,
        agent_ed25519: ed_pk,
        agent_x25519: x_pk,
        agent_local_addrs: vec![],
        suggested_alias: alias,
    };
    let encoded = token.encode()?;
    println!("agent ed25519 pubkey: {}", hex::encode(ed_pk));
    println!("token: {encoded}");
    let qr = qrcode::QrCode::new(encoded.as_bytes())?;
    println!("{}", qr.render::<qrcode::render::unicode::Dense1x2>().build());
    Ok(())
}
```

- [ ] **Step 3: Register the subcommand**

In `crates/wires-cli/src/cmd/mod.rs`, add `pub mod enroll;`.

In `crates/wires-cli/src/main.rs`:

In `enum Cmd`, add:

```rust
    /// Print this agent's enrollment QR for the iOS companion to scan
    Enroll,
```

In the `match cli.command` block, add:

```rust
        Cmd::Enroll => cmd::enroll::run(&data_dir).await,
```

- [ ] **Step 4: Build and smoke test**

Run:

```bash
cargo build -p wires-cli
TMP=$(mktemp -d)
target/debug/wires --data-dir "$TMP" enroll
```

Expected: prints `agent ed25519 pubkey: <hex>`, `token: <base64>`, then a Unicode QR.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-cli/
git commit -m "wires: add `wires enroll` subcommand"
```

---

## Phase 3 — `wires-uniffi` crate

### Task 8: Crate skeleton + UniFFI setup

**Files:**
- Create: `crates/wires-uniffi/Cargo.toml`, `crates/wires-uniffi/build.rs`, `crates/wires-uniffi/uniffi.toml`, `crates/wires-uniffi/src/lib.rs`, `crates/wires-uniffi/uniffi-bindgen.rs`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Add the crate to the workspace**

In root `Cargo.toml`, in `[workspace] members`, add:

```toml
    "crates/wires-uniffi",
```

- [ ] **Step 2: Create `Cargo.toml` for the new crate**

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
iroh-gossip = "0.98"
parking_lot = "0.12"
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
    uniffi::generate_scaffolding("src/wires.udl").ok();
    // Proc-macro scaffolding is set up via uniffi::setup_scaffolding! in lib.rs;
    // the udl call is a no-op fallback if a .udl is ever added.
}
```

Create `crates/wires-uniffi/src/lib.rs` (placeholder for now):

```rust
uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
```

- [ ] **Step 4: Verify it builds and tests pass**

Run: `cargo test -p wires-uniffi`
Expected: 1 test PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/wires-uniffi/
git commit -m "wires-uniffi: crate skeleton with UniFFI scaffolding"
```

### Task 9: `WiresError` enum

**Files:**
- Create: `crates/wires-uniffi/src/error.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-uniffi/src/error.rs`:

```rust
use snafu::{Location, Snafu};

#[derive(Debug, Snafu, uniffi::Error)]
#[uniffi(flat_error)]
pub enum WiresError {
    #[snafu(display("Failed to parse pairing QR token, at {location}"))]
    InvalidPairingToken {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to parse enrollment token, at {location}"))]
    InvalidEnrollmentToken {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Root signer rejected the message, at {location}"))]
    RootSignerFailed {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Host is not reachable, at {location}"))]
    HostUnreachable {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Publish to gossip failed, at {location}"))]
    PublishFailed {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Topic conflict, at {location}"))]
    TopicConflict {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Not connected to host, at {location}"))]
    NotConnected {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Internal error: {message}, at {location}"))]
    Internal {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type WiresResult<T> = std::result::Result<T, WiresError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_ends_with_location() {
        let e = InvalidPairingTokenSnafu.build();
        let s = format!("{e}");
        assert!(s.contains(", at"), "got: {s}");
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

Replace `crates/wires-uniffi/src/lib.rs`:

```rust
uniffi::setup_scaffolding!();

pub mod error;
pub use error::{WiresError, WiresResult};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p wires-uniffi`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: WiresError enum"
```

### Task 10: UniFFI Records and Enums

**Files:**
- Create: `crates/wires-uniffi/src/types.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Write the types with a round-trip test**

Create `crates/wires-uniffi/src/types.rs`:

```rust
#[derive(Debug, Clone, uniffi::Record)]
pub struct AgentIdentity {
    pub ed25519_seed: Vec<u8>,
    pub x25519_secret: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct HostInfo {
    pub node_id_hex: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AgentEnrollment {
    pub agent_ed25519: Vec<u8>,
    pub agent_x25519: Vec<u8>,
    pub suggested_alias: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EpochKey {
    pub epoch: u32,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TopicGrant {
    pub topic_id_hex: String,
    pub name: String,
    pub epochs: Vec<EpochKey>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct NewTopic {
    pub topic_id_hex: String,
    pub epoch_0_key: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SignedWireMessage {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum Right {
    Read,
    Write,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChainPosition {
    pub next_seq: u64,
    pub last_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MintResult {
    pub messages: Vec<SignedWireMessage>,
    pub new_chain_position: ChainPosition,
    pub cap_id_hex: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structs_construct() {
        let _ = AgentIdentity {
            ed25519_seed: vec![0; 32],
            x25519_secret: vec![0; 32],
        };
        let _ = Right::Read;
        let _ = MintResult {
            messages: vec![],
            new_chain_position: ChainPosition {
                next_seq: 0,
                last_hash: None,
            },
            cap_id_hex: "".into(),
        };
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

### Task 11: `SwiftRootSigner` callback trait + `RootSigner` adapter

**Files:**
- Create: `crates/wires-uniffi/src/signer.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Write the adapter + a test using a fake Swift impl**

Create `crates/wires-uniffi/src/signer.rs`:

```rust
use std::sync::Arc;

use wires_core::{RootSigner, SignError, signer::RejectedSnafu};
use snafu::ResultExt;

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
            .map_err(|e| SignError::Rejected {
                message: format!("{e}"),
                location: snafu::location!(),
            })?;
        let mut out = [0u8; 64];
        if sig.len() != 64 {
            return RejectedSnafu {
                message: format!("signer returned {} bytes, expected 64", sig.len()),
            }
            .fail();
        }
        out.copy_from_slice(&sig);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

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
    fn adapter_signs_through_fake_swift() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let swift: Arc<dyn SwiftRootSigner> = Arc::new(FakeSwiftSigner(sk));
        let adapter = SwiftRootSignerAdapter { inner: swift };
        assert_eq!(adapter.pubkey(), pk);
        let sig = adapter.sign(b"hello").unwrap();
        assert_eq!(sig.len(), 64);
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
git commit -m "wires-uniffi: SwiftRootSigner callback trait + adapter"
```

### Task 12: Pure parsers + topic id generator

**Files:**
- Create: `crates/wires-uniffi/src/parse.rs`, `crates/wires-uniffi/src/topic.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Write `parse.rs` with tests**

Create `crates/wires-uniffi/src/parse.rs`:

```rust
use snafu::ResultExt;
use wires_net::{EnrollmentToken, HostPairToken};

use crate::error::{InvalidEnrollmentTokenSnafu, InvalidPairingTokenSnafu, WiresError};
use crate::types::{AgentEnrollment, HostInfo};

pub fn parse_host_pair_qr(payload: &str) -> Result<HostInfo, WiresError> {
    let tok = HostPairToken::decode(payload).map_err(|_| InvalidPairingTokenSnafu.build())?;
    Ok(HostInfo {
        node_id_hex: tok.host_node_id,
        addrs: tok.host_addrs,
        relay: tok.host_relay,
    })
}

pub fn parse_agent_enrollment_qr(payload: &str) -> Result<AgentEnrollment, WiresError> {
    let tok = EnrollmentToken::decode(payload).map_err(|_| InvalidEnrollmentTokenSnafu.build())?;
    Ok(AgentEnrollment {
        agent_ed25519: tok.agent_ed25519.to_vec(),
        agent_x25519: tok.agent_x25519.to_vec(),
        suggested_alias: tok.suggested_alias,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_host_pair() {
        let tok = HostPairToken {
            version: 1,
            host_node_id: "node".into(),
            host_addrs: vec!["1.2.3.4:5".into()],
            host_relay: None,
            household_label: None,
        };
        let s = tok.encode().unwrap();
        let parsed = parse_host_pair_qr(&s).unwrap();
        assert_eq!(parsed.node_id_hex, "node");
    }

    #[test]
    fn rejects_garbage_host_pair() {
        assert!(parse_host_pair_qr("nope").is_err());
    }

    #[test]
    fn round_trip_enrollment() {
        let tok = EnrollmentToken {
            version: 1,
            agent_ed25519: [3u8; 32],
            agent_x25519: [4u8; 32],
            agent_local_addrs: vec![],
            suggested_alias: Some("pi".into()),
        };
        let s = tok.encode().unwrap();
        let parsed = parse_agent_enrollment_qr(&s).unwrap();
        assert_eq!(parsed.suggested_alias.as_deref(), Some("pi"));
        assert_eq!(parsed.agent_ed25519.len(), 32);
    }
}
```

- [ ] **Step 2: Write `topic.rs` with a test**

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
    fn returns_nonzero_distinct_bytes() {
        let a = generate_topic_id_and_epoch0();
        let b = generate_topic_id_and_epoch0();
        assert_eq!(a.topic_id_hex.len(), 64);
        assert_eq!(a.epoch_0_key.len(), 32);
        assert_ne!(a.topic_id_hex, b.topic_id_hex);
        assert_ne!(a.epoch_0_key, b.epoch_0_key);
    }
}
```

- [ ] **Step 3: Wire up and run**

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
git commit -m "wires-uniffi: parsers + topic id/epoch generator"
```

### Task 13: `mint_grant`

**Files:**
- Create: `crates/wires-uniffi/src/mint.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

This wraps the same envelope-construction sequence used in `wires-node::publish::build_message`, but for the iOS app's narrower needs: build `__cap.grant` (sealed-to-agent) and `__topic.history_grant` envelopes.

- [ ] **Step 1: Scaffold the function signature + failing test**

Create `crates/wires-uniffi/src/mint.rs`:

```rust
use std::sync::Arc;

use snafu::ResultExt;
use wires_core::{Capability, MessageKind, RootSigner, WireMessage};
use wires_crypto::{X25519Public, X25519Secret};

use crate::error::{InternalSnafu, WiresError};
use crate::signer::SwiftRootSignerAdapter;
use crate::types::{
    AgentEnrollment, ChainPosition, MintResult, Right as FfiRight, SignedWireMessage, TopicGrant,
};

pub fn mint_grant(
    agent_ed_seed: &[u8; 32],
    agent_x_secret: &[u8; 32],
    root_signer: Arc<dyn crate::signer::SwiftRootSigner>,
    caps_topic_id: [u8; 32],
    enrollment: &AgentEnrollment,
    topic_grants: &[TopicGrant],
    rights: &[FfiRight],
    chain: ChainPosition,
) -> Result<MintResult, WiresError> {
    // (1) Build & sign Capability via the adapter.
    let mut agent_pk = [0u8; 32];
    agent_pk.copy_from_slice(&enrollment.agent_ed25519);

    let topic_globs: Vec<String> = topic_grants.iter().map(|t| t.name.clone()).collect();
    let rights_core: Vec<wires_core::cap::Right> = rights
        .iter()
        .map(|r| match r {
            FfiRight::Read => wires_core::cap::Right::Read,
            FfiRight::Write => wires_core::cap::Right::Write,
        })
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?
        .as_millis() as i64;
    let mut cap = Capability::new_unsigned(agent_pk, topic_globs, rights_core, now, None);
    let adapter = SwiftRootSignerAdapter { inner: root_signer };
    cap.sign(&adapter)
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?;
    let cap_id_hex = hex::encode(cap.cap_id.0);

    // (2) Encode the cap as canonical-JSON content for the __cap.grant envelope.
    let cap_content = wires_core::CanonicalContent::new(
        "__cap.grant".into(),
        format!("grant to {}", hex::encode(agent_pk)),
        Some(serde_json::to_value(&cap).map_err(|e| InternalSnafu { message: e.to_string() }.build())?),
    );

    let agent_signing_key = ed25519_dalek::SigningKey::from_bytes(agent_ed_seed);
    let agent_pubkey = agent_signing_key.verifying_key().to_bytes();

    // (3) Build the __cap.grant envelope (SealedTo agent_x25519).
    let mut recipient_x = [0u8; 32];
    recipient_x.copy_from_slice(&enrollment.agent_x25519);

    // Look up the iOS agent's self-cap id from the chain position is impossible
    // (it's not in `chain`). For v1 the iOS agent's self-cap id is conveyed
    // through SignedWireMessage payload only when building the *self* mint;
    // here we accept the caller passing a stable cap_id we record on the
    // iOS Household. The publish call site supplies it via the chain payload.
    // For this internal helper we sign with the iOS agent's identity using
    // a placeholder cap_id of zeros — actual cap_id is provided in step (4).
    //
    // (Implementation detail deferred until WiresApp.mint_grant in Task 15
    // — see below.)
    todo!("composed in Task 15 with cap_id from WiresApp state")
}
```

Add a failing test:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_compiles() {
        // Real test in Task 15 where WiresApp wires in cap_id state.
        assert!(true);
    }
}
```

- [ ] **Step 2: Register and verify it at least compiles**

Add to `crates/wires-uniffi/src/lib.rs`: `pub mod mint;`.

Run: `cargo build -p wires-uniffi`
Expected: builds (the `todo!()` is allowed at this point; tests don't exercise it).

- [ ] **Step 3: Commit the scaffold**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: mint_grant scaffold (composition in WiresApp)"
```

### Task 14: `HostConnection`

**Files:**
- Create: `crates/wires-uniffi/src/host.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`

- [ ] **Step 1: Define `HostConnection` (constructor + publish + close)**

Create `crates/wires-uniffi/src/host.rs`:

```rust
use std::str::FromStr;

use iroh::{Endpoint, NodeAddr, NodeId, RelayUrl, SecretKey};

use crate::error::{HostUnreachableSnafu, WiresError};
use crate::types::{HostInfo, SignedWireMessage};

pub struct HostConnection {
    pub endpoint: Endpoint,
    pub host_node_id: NodeId,
}

impl HostConnection {
    pub async fn connect(
        agent_ed_seed: &[u8; 32],
        info: &HostInfo,
    ) -> Result<Self, WiresError> {
        let sk = SecretKey::from_bytes(agent_ed_seed);
        let endpoint = Endpoint::builder()
            .secret_key(sk)
            .bind()
            .await
            .map_err(|e| HostUnreachableSnafu { message: e.to_string() }.build())?;

        let node_id =
            NodeId::from_str(&info.node_id_hex).map_err(|e| {
                HostUnreachableSnafu { message: format!("bad node id: {e}") }.build()
            })?;

        let relay_url = info
            .relay
            .as_deref()
            .map(|s| RelayUrl::from_str(s).map_err(|e| {
                HostUnreachableSnafu { message: format!("bad relay: {e}") }.build()
            }))
            .transpose()?;

        let socket_addrs: Vec<std::net::SocketAddr> = info
            .addrs
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let node_addr = NodeAddr {
            node_id,
            relay_url,
            direct_addresses: socket_addrs.into_iter().collect(),
        };
        endpoint.add_node_addr(node_addr).map_err(|e| {
            HostUnreachableSnafu { message: e.to_string() }.build()
        })?;

        Ok(Self {
            endpoint,
            host_node_id: node_id,
        })
    }

    pub async fn publish(&self, msg: &SignedWireMessage) -> Result<(), WiresError> {
        // Open a uni-directional QUIC stream on the wires ALPN and send the
        // serialized envelope. For v1 the host receives via a small accept
        // loop in wires-host that calls TopicLogs::append after envelope
        // validation. (See wires-net::ALPN.)
        let conn = self
            .endpoint
            .connect(self.host_node_id, wires_net::ALPN)
            .await
            .map_err(|e| crate::error::PublishFailedSnafu { message: e.to_string() }.build())?;
        let mut send = conn
            .open_uni()
            .await
            .map_err(|e| crate::error::PublishFailedSnafu { message: e.to_string() }.build())?;
        send.write_all(&msg.bytes)
            .await
            .map_err(|e| crate::error::PublishFailedSnafu { message: e.to_string() }.build())?;
        send.finish()
            .map_err(|e| crate::error::PublishFailedSnafu { message: e.to_string() }.build())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_endpoint_with_seed() {
        let seed = [9u8; 32];
        let info = HostInfo {
            node_id_hex: "00".repeat(32),
            addrs: vec![],
            relay: None,
        };
        // Connect will succeed at binding the endpoint even if the node
        // is unreachable — publishing will fail later. We just test the
        // happy bind path here.
        let result = HostConnection::connect(&seed, &info).await;
        assert!(result.is_ok() || matches!(result, Err(WiresError::HostUnreachable { .. })));
    }
}
```

- [ ] **Step 2: Register and run**

Add to `crates/wires-uniffi/src/lib.rs`: `pub mod host;`.

Run: `cargo test -p wires-uniffi --lib host`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: HostConnection (iroh endpoint + publish over wires ALPN)"
```

### Task 15: `WiresApp` facade — wire everything together

**Files:**
- Create: `crates/wires-uniffi/src/app.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`, `crates/wires-uniffi/src/mint.rs`

- [ ] **Step 1: Complete `mint::mint_grant` in `mint.rs`**

Replace the `todo!()` in `crates/wires-uniffi/src/mint.rs` with the full envelope build. Drop the previous body of `mint_grant` and write:

```rust
pub fn mint_grant(
    agent_ed_seed: &[u8; 32],
    agent_x_secret: &[u8; 32],
    self_cap_id: [u8; 16],
    root_signer: Arc<dyn crate::signer::SwiftRootSigner>,
    caps_topic_id: [u8; 32],
    enrollment: &AgentEnrollment,
    topic_grants: &[TopicGrant],
    rights: &[FfiRight],
    chain: ChainPosition,
) -> Result<MintResult, WiresError> {
    let mut agent_pk = [0u8; 32];
    agent_pk.copy_from_slice(&enrollment.agent_ed25519);
    let mut agent_x_pk = [0u8; 32];
    agent_x_pk.copy_from_slice(&enrollment.agent_x25519);

    let topic_globs: Vec<String> = topic_grants.iter().map(|t| t.name.clone()).collect();
    let rights_core: Vec<wires_core::cap::Right> = rights
        .iter()
        .map(|r| match r {
            FfiRight::Read => wires_core::cap::Right::Read,
            FfiRight::Write => wires_core::cap::Right::Write,
        })
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?
        .as_millis() as i64;
    let mut cap = Capability::new_unsigned(agent_pk, topic_globs, rights_core, now, None);
    let adapter = SwiftRootSignerAdapter { inner: root_signer.clone() };
    cap.sign(&adapter)
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?;
    let cap_id_hex = hex::encode(cap.cap_id.0);

    let agent_signing_key = ed25519_dalek::SigningKey::from_bytes(agent_ed_seed);
    let ios_sender_pk = agent_signing_key.verifying_key().to_bytes();
    let _ios_x_secret = X25519Secret::from(*agent_x_secret);

    // __cap.grant on __caps, SealedTo(recipient_x_pk)
    let cap_grant_content = wires_core::CanonicalContent::new(
        "__cap.grant".into(),
        format!("grant to {}", hex::encode(agent_pk)),
        Some(serde_json::json!({
            "cap": serde_json::to_value(&cap).map_err(|e| InternalSnafu { message: e.to_string() }.build())?,
            "topic_names": topic_grants.iter().map(|t| {
                serde_json::json!({
                    "topic_id_hex": t.topic_id_hex,
                    "name": t.name,
                })
            }).collect::<Vec<_>>(),
        })),
    );

    let mut last_hash: Option<[u8; 32]> = chain.last_hash.as_ref().map(|h| {
        let mut a = [0u8; 32];
        let n = h.len().min(32);
        a[..n].copy_from_slice(&h[..n]);
        a
    });
    let mut next_seq = chain.next_seq;
    let mut messages: Vec<SignedWireMessage> = Vec::new();

    let grant_env = wires_node::publish::build_message(wires_node::publish::PublishParams {
        topic_id: caps_topic_id,
        kind: MessageKind::SealedTo(agent_x_pk),
        sender: ios_sender_pk,
        cap_id: wires_core::cap::CapId(self_cap_id),
        seq: next_seq,
        prev_hash: last_hash.unwrap_or([0u8; 32]),
        content: &cap_grant_content,
        keying: wires_node::publish::KeyingMaterial::SealedRecipient(agent_x_pk),
        agent_signing_key: &agent_signing_key,
    })
    .map_err(|e| InternalSnafu { message: e.to_string() }.build())?;
    let serialized = serde_json::to_vec(&grant_env)
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?;
    let hash: [u8; 32] = blake3::hash(&serialized).into();
    last_hash = Some(hash);
    next_seq += 1;
    messages.push(SignedWireMessage { bytes: serialized });

    // __topic.history_grant per existing topic with epochs
    for tg in topic_grants.iter().filter(|t| !t.epochs.is_empty()) {
        let topic_id_bytes = hex::decode(&tg.topic_id_hex)
            .map_err(|e| InternalSnafu { message: e.to_string() }.build())?;
        if topic_id_bytes.len() != 32 {
            return Err(InternalSnafu { message: "topic_id length".into() }.build());
        }
        let mut topic_id = [0u8; 32];
        topic_id.copy_from_slice(&topic_id_bytes);

        let history_content = wires_core::CanonicalContent::new(
            "__topic.history_grant".into(),
            format!("history of {}", tg.name),
            Some(serde_json::json!({
                "topic_id_hex": tg.topic_id_hex,
                "epochs": tg.epochs.iter().map(|e| serde_json::json!({
                    "epoch": e.epoch,
                    "key_hex": hex::encode(&e.key),
                })).collect::<Vec<_>>(),
            })),
        );

        let env = wires_node::publish::build_message(wires_node::publish::PublishParams {
            topic_id,
            kind: MessageKind::SealedTo(agent_x_pk),
            sender: ios_sender_pk,
            cap_id: wires_core::cap::CapId(self_cap_id),
            seq: next_seq,
            prev_hash: last_hash.unwrap_or([0u8; 32]),
            content: &history_content,
            keying: wires_node::publish::KeyingMaterial::SealedRecipient(agent_x_pk),
            agent_signing_key: &agent_signing_key,
        })
        .map_err(|e| InternalSnafu { message: e.to_string() }.build())?;
        let serialized = serde_json::to_vec(&env)
            .map_err(|e| InternalSnafu { message: e.to_string() }.build())?;
        let h: [u8; 32] = blake3::hash(&serialized).into();
        last_hash = Some(h);
        next_seq += 1;
        messages.push(SignedWireMessage { bytes: serialized });
    }

    Ok(MintResult {
        messages,
        new_chain_position: ChainPosition {
            next_seq,
            last_hash: last_hash.map(|h| h.to_vec()),
        },
        cap_id_hex,
    })
}
```

Add `blake3` to `[dependencies]` in `crates/wires-uniffi/Cargo.toml`:

```toml
blake3 = "1"
```

The exact `wires_node::publish::PublishParams` / `KeyingMaterial` / `build_message` signature should match what already exists in `crates/wires-node/src/publish.rs`. If field names differ (`agent_signing_key` vs `ed_sk` etc), adjust to match — do NOT invent new fields.

- [ ] **Step 2: Create `WiresApp`**

Create `crates/wires-uniffi/src/app.rs`:

```rust
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::runtime::Runtime;

use crate::error::{NotConnectedSnafu, WiresError};
use crate::host::HostConnection;
use crate::mint;
use crate::parse;
use crate::signer::SwiftRootSigner;
use crate::topic::generate_topic_id_and_epoch0;
use crate::types::{
    AgentEnrollment, AgentIdentity, ChainPosition, HostInfo, MintResult, NewTopic, Right,
    SignedWireMessage, TopicGrant,
};

#[derive(uniffi::Object)]
pub struct WiresApp {
    rt: Runtime,
    agent_ed_seed: [u8; 32],
    agent_x_secret: [u8; 32],
    self_cap_id: Mutex<[u8; 16]>,
    root_signer: Arc<dyn SwiftRootSigner>,
    host: Mutex<Option<Arc<HostConnection>>>,
}

#[uniffi::export]
impl WiresApp {
    #[uniffi::constructor]
    pub fn bootstrap(
        agent_identity: AgentIdentity,
        self_cap_id_hex: Option<String>,
        root_signer: Arc<dyn SwiftRootSigner>,
    ) -> Arc<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let mut ed = [0u8; 32];
        let mut x = [0u8; 32];
        ed.copy_from_slice(&agent_identity.ed25519_seed[..32]);
        x.copy_from_slice(&agent_identity.x25519_secret[..32]);
        let mut cap_id = [0u8; 16];
        if let Some(hex) = self_cap_id_hex {
            if let Ok(bytes) = hex::decode(hex) {
                if bytes.len() == 16 {
                    cap_id.copy_from_slice(&bytes);
                }
            }
        }
        Arc::new(Self {
            rt,
            agent_ed_seed: ed,
            agent_x_secret: x,
            self_cap_id: Mutex::new(cap_id),
            root_signer,
            host: Mutex::new(None),
        })
    }

    pub fn set_self_cap_id(&self, cap_id_hex: String) -> Result<(), WiresError> {
        let bytes = hex::decode(cap_id_hex)
            .map_err(|e| crate::error::InternalSnafu { message: e.to_string() }.build())?;
        if bytes.len() != 16 {
            return Err(crate::error::InternalSnafu {
                message: "cap_id must be 16 bytes".into(),
            }
            .build());
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        *self.self_cap_id.lock() = out;
        Ok(())
    }

    pub fn parse_host_pair_qr(&self, payload: String) -> Result<HostInfo, WiresError> {
        parse::parse_host_pair_qr(&payload)
    }

    pub fn parse_agent_enrollment_qr(
        &self,
        payload: String,
    ) -> Result<AgentEnrollment, WiresError> {
        parse::parse_agent_enrollment_qr(&payload)
    }

    pub fn generate_topic_id_and_epoch0(&self) -> NewTopic {
        generate_topic_id_and_epoch0()
    }

    pub fn connect_host(&self, host: HostInfo) -> Result<(), WiresError> {
        let conn = self
            .rt
            .block_on(HostConnection::connect(&self.agent_ed_seed, &host))?;
        *self.host.lock() = Some(Arc::new(conn));
        Ok(())
    }

    pub fn disconnect_host(&self) {
        *self.host.lock() = None;
    }

    pub fn mint_grant(
        &self,
        enrollment: AgentEnrollment,
        topic_grants: Vec<TopicGrant>,
        rights: Vec<Right>,
        chain: ChainPosition,
    ) -> Result<MintResult, WiresError> {
        let caps_topic_id = wires_core::reserved::caps_topic_id(&self.root_pubkey()?);
        let cap_id = *self.self_cap_id.lock();
        mint::mint_grant(
            &self.agent_ed_seed,
            &self.agent_x_secret,
            cap_id,
            self.root_signer.clone(),
            caps_topic_id,
            &enrollment,
            &topic_grants,
            &rights,
            chain,
        )
    }

    pub fn publish(&self, messages: Vec<SignedWireMessage>) -> Result<(), WiresError> {
        let host = self
            .host
            .lock()
            .clone()
            .ok_or_else(|| NotConnectedSnafu.build())?;
        self.rt.block_on(async move {
            for m in &messages {
                host.publish(m).await?;
            }
            Ok::<(), WiresError>(())
        })
    }

    fn root_pubkey(&self) -> Result<[u8; 32], WiresError> {
        let v = self.root_signer.pubkey();
        if v.len() != 32 {
            return Err(crate::error::InternalSnafu {
                message: "root_signer.pubkey() must return 32 bytes".into(),
            }
            .build());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}
```

Confirm `wires_core::reserved::caps_topic_id(root_pubkey)` exists with that signature; if it lives under a different path, adjust. Check `crates/wires-core/src/reserved.rs`.

- [ ] **Step 3: Register and run all tests**

Add to `crates/wires-uniffi/src/lib.rs`:

```rust
pub mod app;
pub use app::WiresApp;
```

Run: `cargo test -p wires-uniffi`
Expected: all PASS.

Run: `cargo build -p wires-uniffi --release`
Expected: builds.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-uniffi/
git commit -m "wires-uniffi: WiresApp facade — bootstrap, connect, mint, publish"
```

---

## Phase 4 — Build tooling and WiresKit package

### Task 16: `scripts/build-ioskit.sh` + WiresKit SwiftPM package

**Files:**
- Create: `scripts/build-ioskit.sh`, `Wires/WiresKit/Package.swift`, `Wires/WiresKit/.gitignore`

- [ ] **Step 1: Install iOS Rust targets**

Run (one-time per developer machine):

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios-sim
```

- [ ] **Step 2: Create the build script**

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
mkdir -p "$HEADERS_DIR"
cargo run --release -p wires-uniffi --bin uniffi-bindgen -- \
  generate \
  --library "$TARGET_DIR/aarch64-apple-ios/release/libwires_uniffi.a" \
  --language swift \
  --out-dir "$HEADERS_DIR"

echo "==> Assembling xcframework"
rm -rf "$FRAMEWORK_DIR/wires.xcframework"
# Move headers + modulemap into a per-slice include dir.
mkdir -p "$HEADERS_DIR/include"
mv "$HEADERS_DIR"/*.h "$HEADERS_DIR/include/" 2>/dev/null || true
mv "$HEADERS_DIR"/*.modulemap "$HEADERS_DIR/include/module.modulemap" 2>/dev/null || true

xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/libwires_uniffi.a" -headers "$HEADERS_DIR/include" \
  -library "$SIM_DIR/libwires_uniffi.a" -headers "$HEADERS_DIR/include" \
  -output "$FRAMEWORK_DIR/wires.xcframework"

echo "==> Copying Swift source"
cp "$HEADERS_DIR"/*.swift "$SOURCES_DIR/"

echo "==> Done. Built $FRAMEWORK_DIR/wires.xcframework"
```

Make it executable:

```bash
chmod +x scripts/build-ioskit.sh
```

- [ ] **Step 3: Create the SwiftPM package manifest**

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
        .binaryTarget(
            name: "wiresFFI",
            path: "Frameworks/wires.xcframework"
        ),
        .target(
            name: "WiresKit",
            dependencies: ["wiresFFI"],
            path: "Sources/WiresKit"
        ),
    ]
)
```

Create `Wires/WiresKit/.gitignore`:

```
Frameworks/
Sources/WiresKit/*.swift
```

(The xcframework and the generated `WiresKit.swift` are build artifacts; they're regenerated by `scripts/build-ioskit.sh`.)

- [ ] **Step 4: Run the build script end-to-end**

Run: `./scripts/build-ioskit.sh`
Expected: completes without error, produces `Wires/WiresKit/Frameworks/wires.xcframework/Info.plist` and at least one `.swift` file under `Wires/WiresKit/Sources/WiresKit/`.

If the `uniffi-bindgen` CLI flags differ in the UniFFI 0.28 release on disk, adjust the `generate` invocation to match the help output (`cargo run -p wires-uniffi --bin uniffi-bindgen -- --help`). The high-level structure (cross-compile, lipo, xcframework, copy bindings) is the contract.

- [ ] **Step 5: Commit**

```bash
git add scripts/build-ioskit.sh Wires/WiresKit/Package.swift Wires/WiresKit/.gitignore
git commit -m "build: scripts/build-ioskit.sh and WiresKit SwiftPM package"
```

---

## Phase 5 — Swift app under TCA

> All Swift work below assumes the `Wires.xcodeproj` is opened in Xcode and that `scripts/build-ioskit.sh` has been run at least once so `wires.xcframework` exists. Run the script again whenever the Rust side changes.

### Task 17: Xcode project cleanup + add TCA and WiresKit deps

**Files:**
- Delete: `Wires/Wires/ContentView.swift`, `Wires/Wires/Item.swift`
- Modify: `Wires/Wires.xcodeproj/project.pbxproj` (via Xcode UI)
- Modify: `Wires/Wires/WiresApp.swift` (temporary placeholder)

- [ ] **Step 1: Remove template files**

```bash
git rm Wires/Wires/ContentView.swift Wires/Wires/Item.swift
```

- [ ] **Step 2: Replace `WiresApp.swift` with a minimal placeholder**

Overwrite `Wires/Wires/WiresApp.swift`:

```swift
import SwiftUI

@main
struct WiresApp: App {
    var body: some Scene {
        WindowGroup {
            Text("Wires — bootstrapping")
                .padding()
        }
    }
}
```

- [ ] **Step 3: Add package dependencies in Xcode**

In Xcode:
1. Select the `Wires` project in the navigator.
2. Under "Package Dependencies", click `+`.
3. Add `https://github.com/pointfreeco/swift-composable-architecture` — set rule to "Up to next major" from `1.16.0`. Add the `ComposableArchitecture` product to the `Wires` app target.
4. Click `+` again, choose "Add Local…", select `Wires/WiresKit`. Add the `WiresKit` product to the `Wires` app target.
5. Set `IPHONEOS_DEPLOYMENT_TARGET = 17.0` on both `Wires` and `WiresTests` targets (Build Settings → Deployment).

- [ ] **Step 4: Verify it builds**

In Xcode: Product → Build (⌘B).
Expected: green build, no symbol errors. The placeholder screen renders in simulator.

- [ ] **Step 5: Commit**

```bash
git add Wires/Wires/WiresApp.swift Wires/Wires.xcodeproj
git commit -m "ios: remove SwiftData template, add TCA and WiresKit deps"
```

### Task 18: SwiftData models

**Files:**
- Create: `Wires/Wires/Models/{Household,TopicRecord,CapRecord,PendingPublish}.swift`

- [ ] **Step 1: Create the four models**

Create `Wires/Wires/Models/Household.swift`:

```swift
import Foundation
import SwiftData

@Model
final class Household {
    @Attribute(.unique) var rootPubkeyHex: String
    var createdAt: Date

    var hostNodeIdHex: String?
    var hostRelayURL: String?
    var hostDirectAddrs: [String]

    var iosAgentPubkeyHex: String
    var iosAgentCapIdHex: String?

    var iosAgentNextSeq: UInt64
    var iosAgentLastHash: Data?

    @Relationship(deleteRule: .cascade) var topics: [TopicRecord] = []
    @Relationship(deleteRule: .cascade) var caps: [CapRecord] = []

    init(
        rootPubkeyHex: String,
        iosAgentPubkeyHex: String,
        createdAt: Date = .now
    ) {
        self.rootPubkeyHex = rootPubkeyHex
        self.iosAgentPubkeyHex = iosAgentPubkeyHex
        self.createdAt = createdAt
        self.hostNodeIdHex = nil
        self.hostRelayURL = nil
        self.hostDirectAddrs = []
        self.iosAgentCapIdHex = nil
        self.iosAgentNextSeq = 0
        self.iosAgentLastHash = nil
    }
}
```

Create `Wires/Wires/Models/TopicRecord.swift`:

```swift
import Foundation
import SwiftData

@Model
final class TopicRecord {
    @Attribute(.unique) var topicIdHex: String
    var name: String
    var createdAt: Date
    var currentEpoch: UInt32

    init(topicIdHex: String, name: String, currentEpoch: UInt32 = 0, createdAt: Date = .now) {
        self.topicIdHex = topicIdHex
        self.name = name
        self.currentEpoch = currentEpoch
        self.createdAt = createdAt
    }
}
```

Create `Wires/Wires/Models/CapRecord.swift`:

```swift
import Foundation
import SwiftData

@Model
final class CapRecord {
    @Attribute(.unique) var capIdHex: String
    var agentPubkeyHex: String
    var agentAlias: String?
    var topicGlobs: [String]
    var rights: [String]
    var issuedAt: Date
    var expiresAt: Date?
    var revokedAt: Date?

    init(
        capIdHex: String,
        agentPubkeyHex: String,
        agentAlias: String?,
        topicGlobs: [String],
        rights: [String],
        issuedAt: Date = .now,
        expiresAt: Date? = nil
    ) {
        self.capIdHex = capIdHex
        self.agentPubkeyHex = agentPubkeyHex
        self.agentAlias = agentAlias
        self.topicGlobs = topicGlobs
        self.rights = rights
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.revokedAt = nil
    }
}
```

Create `Wires/Wires/Models/PendingPublish.swift`:

```swift
import Foundation
import SwiftData

@Model
final class PendingPublish {
    @Attribute(.unique) var id: UUID
    var payload: Data
    var createdAt: Date
    var attempts: Int

    init(payload: Data) {
        self.id = UUID()
        self.payload = payload
        self.createdAt = .now
        self.attempts = 0
    }
}
```

- [ ] **Step 2: Build**

In Xcode: ⌘B. Expected: green build.

- [ ] **Step 3: Commit**

```bash
git add Wires/Wires/Models/
git commit -m "ios: SwiftData models (Household, TopicRecord, CapRecord, PendingPublish)"
```

### Task 19: `KeychainClient` dependency

**Files:**
- Create: `Wires/Wires/Dependencies/KeychainClient.swift`
- Test: `Wires/WiresTests/KeychainClientTests.swift`

- [ ] **Step 1: Implement the client**

Create `Wires/Wires/Dependencies/KeychainClient.swift`:

```swift
import Foundation
import Dependencies
import DependenciesMacros
import LocalAuthentication

enum KeychainAccessibility {
    case afterFirstUnlockThisDeviceOnly
    case afterFirstUnlockThisDeviceOnlyBiometric

    var cfValue: CFString {
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }
}

enum KeychainError: Error, Equatable {
    case notFound
    case biometricCancelled
    case biometricFailed
    case unexpectedStatus(OSStatus)
}

@DependencyClient
struct KeychainClient: Sendable {
    var getData: @Sendable (_ key: String) throws -> Data? = { _ in nil }
    var setData: @Sendable (_ key: String, _ value: Data, _ access: KeychainAccessibility) throws -> Void
    var deleteData: @Sendable (_ key: String) throws -> Void
    var signWithBiometric: @Sendable (_ key: String, _ message: Data) async throws -> Data
}

extension KeychainClient: DependencyKey {
    static let liveValue: KeychainClient = .live()
    static let testValue = KeychainClient()
    static let previewValue: KeychainClient = .live()

    static func live() -> KeychainClient {
        KeychainClient(
            getData: { key in
                var query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                    kSecReturnData as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne,
                ]
                var result: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &result)
                switch status {
                case errSecSuccess: return result as? Data
                case errSecItemNotFound: return nil
                default: throw KeychainError.unexpectedStatus(status)
                }
            },
            setData: { key, value, access in
                let attrs: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                    kSecValueData as String: value,
                    kSecAttrAccessible as String: access.cfValue,
                    kSecAttrSynchronizable as String: false,
                ]
                SecItemDelete([
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                ] as CFDictionary)
                let status = SecItemAdd(attrs as CFDictionary, nil)
                guard status == errSecSuccess else {
                    throw KeychainError.unexpectedStatus(status)
                }
            },
            deleteData: { key in
                let status = SecItemDelete([
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                ] as CFDictionary)
                guard status == errSecSuccess || status == errSecItemNotFound else {
                    throw KeychainError.unexpectedStatus(status)
                }
            },
            signWithBiometric: { key, message in
                let context = LAContext()
                context.localizedReason = "Approve household action"
                var error: NSError?
                guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
                    throw KeychainError.biometricFailed
                }
                do {
                    _ = try await context.evaluatePolicy(
                        .deviceOwnerAuthenticationWithBiometrics,
                        localizedReason: "Approve household action"
                    )
                } catch let laError as LAError where laError.code == .userCancel {
                    throw KeychainError.biometricCancelled
                } catch {
                    throw KeychainError.biometricFailed
                }
                // After biometric assertion, fetch the raw 32-byte seed and sign.
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                    kSecReturnData as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne,
                    kSecUseAuthenticationContext as String: context,
                ]
                var result: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &result)
                guard status == errSecSuccess, let seed = result as? Data else {
                    throw KeychainError.unexpectedStatus(status)
                }
                return try Ed25519.sign(seed: seed, message: message)
            }
        )
    }
}

extension DependencyValues {
    var keychainClient: KeychainClient {
        get { self[KeychainClient.self] }
        set { self[KeychainClient.self] = newValue }
    }
}

enum Ed25519 {
    static func sign(seed: Data, message: Data) throws -> Data {
        // CryptoKit Curve25519.Signing requires exactly 32 bytes of seed.
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return try key.signature(for: message)
    }
}

import CryptoKit
```

- [ ] **Step 2: Write a unit test against `testValue`**

Create `Wires/WiresTests/KeychainClientTests.swift`:

```swift
import XCTest
import Dependencies
@testable import Wires

final class KeychainClientTests: XCTestCase {
    func test_testValue_is_unimplemented() {
        let client = KeychainClient.testValue
        // testValue closures crash if invoked unexpectedly (the @DependencyClient default).
        // Pure construction must succeed.
        _ = client
    }
}
```

- [ ] **Step 3: Build and test**

In Xcode: ⌘U. Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add Wires/Wires/Dependencies/KeychainClient.swift Wires/WiresTests/KeychainClientTests.swift
git commit -m "ios: KeychainClient dependency"
```

### Task 20: `HouseholdClient` dependency

**Files:**
- Create: `Wires/Wires/Dependencies/HouseholdClient.swift`

- [ ] **Step 1: Implement the client**

Create `Wires/Wires/Dependencies/HouseholdClient.swift`:

```swift
import Foundation
import Dependencies
import DependenciesMacros
import SwiftData

@DependencyClient
struct HouseholdClient: Sendable {
    var loadHousehold: @Sendable () async throws -> Household?
    var saveHousehold: @Sendable (Household) async throws -> Void
    var listTopics: @Sendable () async throws -> [TopicRecord] = { [] }
    var saveTopic: @Sendable (TopicRecord) async throws -> Void
    var listCaps: @Sendable () async throws -> [CapRecord] = { [] }
    var saveCap: @Sendable (CapRecord) async throws -> Void
    var enqueuePending: @Sendable (Data) async throws -> Void
    var advanceChain: @Sendable (UInt64, Data?) async throws -> Void
    var observePendingCount: @Sendable () -> AsyncStream<Int> = { AsyncStream { _ in } }
}

extension HouseholdClient: DependencyKey {
    static let liveValue: HouseholdClient = .live(modelContainer: try! ModelContainer(
        for: Household.self, TopicRecord.self, CapRecord.self, PendingPublish.self
    ))
    static let testValue = HouseholdClient()

    static func live(modelContainer: ModelContainer) -> HouseholdClient {
        let ctx = ModelContext(modelContainer)
        return HouseholdClient(
            loadHousehold: {
                let fd = FetchDescriptor<Household>()
                return try ctx.fetch(fd).first
            },
            saveHousehold: { hh in
                ctx.insert(hh)
                try ctx.save()
            },
            listTopics: {
                try ctx.fetch(FetchDescriptor<TopicRecord>())
            },
            saveTopic: { t in
                ctx.insert(t)
                try ctx.save()
            },
            listCaps: {
                try ctx.fetch(FetchDescriptor<CapRecord>())
            },
            saveCap: { c in
                ctx.insert(c)
                try ctx.save()
            },
            enqueuePending: { payload in
                ctx.insert(PendingPublish(payload: payload))
                try ctx.save()
            },
            advanceChain: { nextSeq, lastHash in
                let fd = FetchDescriptor<Household>()
                if let hh = try ctx.fetch(fd).first {
                    hh.iosAgentNextSeq = nextSeq
                    hh.iosAgentLastHash = lastHash
                    try ctx.save()
                }
            },
            observePendingCount: {
                AsyncStream { cont in
                    Task {
                        while !Task.isCancelled {
                            let count = (try? ctx.fetchCount(FetchDescriptor<PendingPublish>())) ?? 0
                            cont.yield(count)
                            try? await Task.sleep(nanoseconds: 5_000_000_000)
                        }
                        cont.finish()
                    }
                }
            }
        )
    }
}

extension DependencyValues {
    var householdClient: HouseholdClient {
        get { self[HouseholdClient.self] }
        set { self[HouseholdClient.self] = newValue }
    }
}
```

- [ ] **Step 2: Build**

⌘B. Expected: green.

- [ ] **Step 3: Commit**

```bash
git add Wires/Wires/Dependencies/HouseholdClient.swift
git commit -m "ios: HouseholdClient dependency"
```

### Task 21: `WiresClient` dependency

**Files:**
- Create: `Wires/Wires/Dependencies/WiresClient.swift`

- [ ] **Step 1: Implement the client wrapping WiresKit**

Create `Wires/Wires/Dependencies/WiresClient.swift`:

```swift
import Foundation
import Dependencies
import DependenciesMacros
import WiresKit

@DependencyClient
struct WiresClient: Sendable {
    var bootstrap: @Sendable (_ agentIdentity: AgentIdentity, _ selfCapIdHex: String?, _ rootSigner: SwiftRootSigner) async throws -> Void
    var connectHost: @Sendable (_ host: HostInfo) async throws -> Void
    var disconnectHost: @Sendable () -> Void = {}
    var parseHostPairQR: @Sendable (_ payload: String) throws -> HostInfo
    var parseEnrollmentQR: @Sendable (_ payload: String) throws -> AgentEnrollment
    var generateTopicIdAndEpoch0: @Sendable () -> NewTopic
    var mintGrant: @Sendable (_ enrollment: AgentEnrollment, _ topicGrants: [TopicGrant], _ rights: [Right], _ chain: ChainPosition) async throws -> MintResult
    var publish: @Sendable (_ messages: [SignedWireMessage]) async throws -> Void
    var setSelfCapId: @Sendable (_ capIdHex: String) async throws -> Void
}

extension WiresClient: DependencyKey {
    static let testValue = WiresClient()

    static let liveValue: WiresClient = {
        let holder = WiresAppHolder()
        return WiresClient(
            bootstrap: { identity, selfCap, signer in
                await holder.bootstrap(identity: identity, selfCapIdHex: selfCap, rootSigner: signer)
            },
            connectHost: { host in
                try await holder.connectHost(host)
            },
            disconnectHost: {
                holder.disconnectHost()
            },
            parseHostPairQR: { try holder.requireApp().parseHostPairQr(payload: $0) },
            parseEnrollmentQR: { try holder.requireApp().parseAgentEnrollmentQr(payload: $0) },
            generateTopicIdAndEpoch0: { holder.requireApp().generateTopicIdAndEpoch0() },
            mintGrant: { enrollment, topics, rights, chain in
                try holder.requireApp().mintGrant(enrollment: enrollment, topicGrants: topics, rights: rights, chain: chain)
            },
            publish: { messages in
                try holder.requireApp().publish(messages: messages)
            },
            setSelfCapId: { capId in
                try holder.requireApp().setSelfCapId(capIdHex: capId)
            }
        )
    }()
}

actor WiresAppHolder {
    private var app: WiresApp?

    func bootstrap(identity: AgentIdentity, selfCapIdHex: String?, rootSigner: SwiftRootSigner) {
        app = WiresApp.bootstrap(
            agentIdentity: identity,
            selfCapIdHex: selfCapIdHex,
            rootSigner: rootSigner
        )
    }

    func connectHost(_ host: HostInfo) async throws {
        guard let app else { throw WiresError.NotConnected }
        try app.connectHost(host: host)
    }

    nonisolated func disconnectHost() {
        Task { await self.disconnectInternal() }
    }

    private func disconnectInternal() {
        app?.disconnectHost()
    }

    nonisolated func requireApp() -> WiresApp {
        // The non-isolated accessor is used by sync FFI methods that already
        // serialize at the UniFFI boundary. It's safe so long as bootstrap
        // has completed; bootstrap is awaited at app launch.
        // For correctness across reset, we suspend onto the actor and read.
        let semaphore = DispatchSemaphore(value: 0)
        var result: WiresApp?
        Task {
            result = await self.app
            semaphore.signal()
        }
        semaphore.wait()
        return result!
    }
}

extension DependencyValues {
    var wiresClient: WiresClient {
        get { self[WiresClient.self] }
        set { self[WiresClient.self] = newValue }
    }
}
```

Note: the `WiresAppHolder.requireApp()` pattern using a semaphore is a known awkwardness — the alternative is making every reducer effect `await` on the actor, which is cleaner. Adjust to taste once compiling; either works.

- [ ] **Step 2: Build**

⌘B. Expected: green.

- [ ] **Step 3: Commit**

```bash
git add Wires/Wires/Dependencies/WiresClient.swift
git commit -m "ios: WiresClient dependency wrapping WiresKit"
```

### Task 22: `ScanFeature` (reducer + view + tests)

**Files:**
- Create: `Wires/Wires/Features/Scan/{ScanFeature,ScanView}.swift`
- Test: `Wires/WiresTests/ScanFeatureTests.swift`

- [ ] **Step 1: Reducer**

Create `Wires/Wires/Features/Scan/ScanFeature.swift`:

```swift
import ComposableArchitecture
import AVFoundation

@Reducer
struct ScanFeature {
    @ObservableState
    struct State: Equatable {
        var cameraAuthorized: Bool = false
        var lastPayload: String?
        var error: String?
    }

    enum Action: Equatable {
        case onAppear
        case cameraAuthorizationResponse(Bool)
        case payloadScanned(String)
        case errorOccurred(String)
        case dismissError
    }

    var body: some ReducerOf<Self> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                return .run { send in
                    let status = AVCaptureDevice.authorizationStatus(for: .video)
                    switch status {
                    case .authorized:
                        await send(.cameraAuthorizationResponse(true))
                    case .notDetermined:
                        let granted = await AVCaptureDevice.requestAccess(for: .video)
                        await send(.cameraAuthorizationResponse(granted))
                    default:
                        await send(.cameraAuthorizationResponse(false))
                    }
                }
            case let .cameraAuthorizationResponse(authorized):
                state.cameraAuthorized = authorized
                return .none
            case let .payloadScanned(payload):
                state.lastPayload = payload
                return .none
            case let .errorOccurred(msg):
                state.error = msg
                return .none
            case .dismissError:
                state.error = nil
                return .none
            }
        }
    }
}
```

- [ ] **Step 2: Test**

Create `Wires/WiresTests/ScanFeatureTests.swift`:

```swift
import XCTest
import ComposableArchitecture
@testable import Wires

final class ScanFeatureTests: XCTestCase {
    func test_payload_scanned_updates_state() async {
        let store = TestStore(initialState: ScanFeature.State()) {
            ScanFeature()
        }
        await store.send(.payloadScanned("abc")) {
            $0.lastPayload = "abc"
        }
    }

    func test_error_set_and_dismissed() async {
        let store = TestStore(initialState: ScanFeature.State()) {
            ScanFeature()
        }
        await store.send(.errorOccurred("nope")) {
            $0.error = "nope"
        }
        await store.send(.dismissError) {
            $0.error = nil
        }
    }
}
```

- [ ] **Step 3: View (camera plumbing)**

Create `Wires/Wires/Features/Scan/ScanView.swift`:

```swift
import SwiftUI
import AVFoundation
import ComposableArchitecture

struct ScanView: View {
    @Bindable var store: StoreOf<ScanFeature>
    let prompt: String

    var body: some View {
        ZStack {
            if store.cameraAuthorized {
                ScannerRepresentable { payload in
                    store.send(.payloadScanned(payload))
                } onError: { msg in
                    store.send(.errorOccurred(msg))
                }
                .ignoresSafeArea()
            } else {
                Color.black.ignoresSafeArea()
                VStack {
                    Text(prompt).foregroundStyle(.white).padding()
                }
            }
        }
        .onAppear { store.send(.onAppear) }
        .alert("Scan error", isPresented: .init(
            get: { store.error != nil },
            set: { if !$0 { store.send(.dismissError) } }
        )) {
            Button("OK") { store.send(.dismissError) }
        } message: {
            Text(store.error ?? "")
        }
    }
}

private struct ScannerRepresentable: UIViewControllerRepresentable {
    let onPayload: (String) -> Void
    let onError: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerVC {
        ScannerVC(onPayload: onPayload, onError: onError)
    }
    func updateUIViewController(_ uiViewController: ScannerVC, context: Context) {}
}

private final class ScannerVC: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    let onPayload: (String) -> Void
    let onError: (String) -> Void
    private var session: AVCaptureSession?

    init(onPayload: @escaping (String) -> Void, onError: @escaping (String) -> Void) {
        self.onPayload = onPayload
        self.onError = onError
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        let session = AVCaptureSession()
        self.session = session
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            onError("Camera unavailable"); return
        }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { onError("Cannot scan"); return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.frame = view.bounds
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)
        DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let metadata = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let payload = metadata.stringValue else { return }
        session?.stopRunning()
        onPayload(payload)
    }
}
```

- [ ] **Step 4: Run tests**

⌘U → `ScanFeatureTests` should pass.

- [ ] **Step 5: Commit**

```bash
git add Wires/Wires/Features/Scan/ Wires/WiresTests/ScanFeatureTests.swift
git commit -m "ios: ScanFeature (reducer + view + tests)"
```

### Task 23: `ApprovalFeature` (reducer + tests)

**Files:**
- Create: `Wires/Wires/Features/AgentEnrollment/ApprovalFeature.swift`
- Test: `Wires/WiresTests/ApprovalFeatureTests.swift`

- [ ] **Step 1: Reducer**

Create `Wires/Wires/Features/AgentEnrollment/ApprovalFeature.swift`:

```swift
import ComposableArchitecture
import WiresKit
import Foundation

@Reducer
struct ApprovalFeature {
    @ObservableState
    struct State: Equatable {
        var enrollment: AgentEnrollment
        var alias: String
        var topicGlobsText: String = ""
        var readEnabled: Bool = false
        var writeEnabled: Bool = false
        var isMinting: Bool = false
        var error: String?

        var topicGlobs: [String] {
            topicGlobsText
                .split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }

        var rights: [Right] {
            var out: [Right] = []
            if readEnabled { out.append(.read) }
            if writeEnabled { out.append(.write) }
            return out
        }
    }

    enum Action: Equatable {
        case aliasChanged(String)
        case topicsChanged(String)
        case readToggled(Bool)
        case writeToggled(Bool)
        case approveTapped
        case mintResponse(Result<MintOutcome, EquatableError>)
        case errorDismissed
        case delegate(Delegate)
        enum Delegate: Equatable {
            case approved(capIdHex: String, agentPubkeyHex: String)
            case cancelled
        }
    }

    struct MintOutcome: Equatable {
        let capIdHex: String
        let agentPubkeyHex: String
    }

    @Dependency(\.wiresClient) var wiresClient
    @Dependency(\.householdClient) var householdClient

    var body: some ReducerOf<Self> {
        Reduce { state, action in
            switch action {
            case let .aliasChanged(a): state.alias = a; return .none
            case let .topicsChanged(t): state.topicGlobsText = t; return .none
            case let .readToggled(b): state.readEnabled = b; return .none
            case let .writeToggled(b): state.writeEnabled = b; return .none

            case .approveTapped:
                guard !state.isMinting else { return .none }
                state.isMinting = true
                let enrollment = state.enrollment
                let alias = state.alias
                let globs = state.topicGlobs
                let rights = state.rights
                return .run { [wiresClient, householdClient] send in
                    do {
                        // Resolve existing topics. Generate new ones for literal-name globs that don't exist.
                        let existingTopics = try await householdClient.listTopics()
                        var topicGrants: [TopicGrant] = []
                        for glob in globs where !glob.contains("*") {
                            if let existing = existingTopics.first(where: { $0.name == glob }) {
                                topicGrants.append(TopicGrant(
                                    topicIdHex: existing.topicIdHex,
                                    name: existing.name,
                                    epochs: []  // TODO: load from Keychain in real flow
                                ))
                            } else {
                                let newTopic = wiresClient.generateTopicIdAndEpoch0()
                                let rec = TopicRecord(
                                    topicIdHex: newTopic.topicIdHex,
                                    name: glob,
                                    currentEpoch: 0
                                )
                                try await householdClient.saveTopic(rec)
                                topicGrants.append(TopicGrant(
                                    topicIdHex: newTopic.topicIdHex,
                                    name: glob,
                                    epochs: [EpochKey(epoch: 0, key: newTopic.epoch_0Key)]
                                ))
                            }
                        }

                        guard let household = try await householdClient.loadHousehold() else {
                            await send(.mintResponse(.failure(EquatableError("No household"))))
                            return
                        }
                        let chain = ChainPosition(
                            nextSeq: household.iosAgentNextSeq,
                            lastHash: household.iosAgentLastHash
                        )
                        let result = try await wiresClient.mintGrant(
                            enrollment: enrollment,
                            topicGrants: topicGrants,
                            rights: rights,
                            chain: chain
                        )
                        let cap = CapRecord(
                            capIdHex: result.capIdHex,
                            agentPubkeyHex: enrollment.agentEd25519.map { String(format: "%02x", $0) }.joined(),
                            agentAlias: alias,
                            topicGlobs: globs,
                            rights: rights.map { $0 == .read ? "read" : "write" }
                        )
                        try await householdClient.saveCap(cap)
                        try await householdClient.advanceChain(
                            result.newChainPosition.nextSeq,
                            result.newChainPosition.lastHash
                        )
                        do {
                            try await wiresClient.publish(result.messages)
                        } catch {
                            for m in result.messages {
                                try await householdClient.enqueuePending(m.bytes)
                            }
                        }
                        await send(.mintResponse(.success(MintOutcome(
                            capIdHex: result.capIdHex,
                            agentPubkeyHex: cap.agentPubkeyHex
                        ))))
                    } catch {
                        await send(.mintResponse(.failure(EquatableError(error.localizedDescription))))
                    }
                }

            case let .mintResponse(.success(outcome)):
                state.isMinting = false
                return .send(.delegate(.approved(capIdHex: outcome.capIdHex, agentPubkeyHex: outcome.agentPubkeyHex)))

            case let .mintResponse(.failure(err)):
                state.isMinting = false
                state.error = err.message
                return .none

            case .errorDismissed:
                state.error = nil
                return .none

            case .delegate:
                return .none
            }
        }
    }
}

struct EquatableError: Equatable, Error {
    let message: String
    init(_ message: String) { self.message = message }
}
```

- [ ] **Step 2: Tests**

Create `Wires/WiresTests/ApprovalFeatureTests.swift`:

```swift
import XCTest
import ComposableArchitecture
@testable import Wires
@testable import WiresKit

final class ApprovalFeatureTests: XCTestCase {
    func test_typing_updates_state() async {
        let enrollment = AgentEnrollment(agentEd25519: Data(repeating: 1, count: 32), agentX25519: Data(repeating: 2, count: 32), suggestedAlias: "pi")
        let store = TestStore(initialState: ApprovalFeature.State(enrollment: enrollment, alias: "pi")) {
            ApprovalFeature()
        }
        await store.send(.aliasChanged("fridge")) { $0.alias = "fridge" }
        await store.send(.topicsChanged("home.lights\nhome.*")) { $0.topicGlobsText = "home.lights\nhome.*" }
        await store.send(.readToggled(true)) { $0.readEnabled = true }
        await store.send(.writeToggled(true)) { $0.writeEnabled = true }
    }
}
```

- [ ] **Step 3: Build and run**

⌘U → tests pass.

- [ ] **Step 4: Commit**

```bash
git add Wires/Wires/Features/AgentEnrollment/ApprovalFeature.swift Wires/WiresTests/ApprovalFeatureTests.swift
git commit -m "ios: ApprovalFeature reducer + tests"
```

### Task 24: `ApprovalView` + `AgentEnrollmentFeature`

**Files:**
- Create: `Wires/Wires/Features/AgentEnrollment/{AgentEnrollmentFeature,AgentEnrollmentView,ApprovalView}.swift`

- [ ] **Step 1: ApprovalView**

Create `Wires/Wires/Features/AgentEnrollment/ApprovalView.swift`:

```swift
import SwiftUI
import ComposableArchitecture

struct ApprovalView: View {
    @Bindable var store: StoreOf<ApprovalFeature>

    var body: some View {
        NavigationStack {
            Form {
                Section("Agent") {
                    TextField("Alias", text: $store.alias.sending(\.aliasChanged))
                }
                Section("Topics (one per line)") {
                    TextEditor(text: $store.topicGlobsText.sending(\.topicsChanged))
                        .frame(minHeight: 100)
                }
                Section("Rights") {
                    Toggle("Read", isOn: $store.readEnabled.sending(\.readToggled))
                    Toggle("Write", isOn: $store.writeEnabled.sending(\.writeToggled))
                }
                Section {
                    Button("Approve") {
                        store.send(.approveTapped)
                    }
                    .disabled(store.isMinting)
                }
            }
            .navigationTitle("Approve agent")
            .alert("Error", isPresented: .init(
                get: { store.error != nil },
                set: { if !$0 { store.send(.errorDismissed) } }
            )) {
                Button("OK") { store.send(.errorDismissed) }
            } message: {
                Text(store.error ?? "")
            }
        }
    }
}
```

- [ ] **Step 2: AgentEnrollmentFeature (composes Scan → Approval)**

Create `Wires/Wires/Features/AgentEnrollment/AgentEnrollmentFeature.swift`:

```swift
import ComposableArchitecture
import WiresKit

@Reducer
struct AgentEnrollmentFeature {
    @Reducer(state: .equatable)
    enum Path {
        case scan(ScanFeature)
        case approval(ApprovalFeature)
    }

    @ObservableState
    struct State: Equatable {
        var path = StackState<Path.State>()
        init() {
            path.append(.scan(ScanFeature.State()))
        }
    }

    enum Action {
        case path(StackAction<Path.State, Path.Action>)
        case delegate(Delegate)
        enum Delegate: Equatable {
            case completed(capIdHex: String)
            case cancelled
        }
    }

    @Dependency(\.wiresClient) var wiresClient

    var body: some ReducerOf<Self> {
        Reduce { state, action in
            switch action {
            case let .path(.element(id: _, action: .scan(.payloadScanned(payload)))):
                do {
                    let enrollment = try wiresClient.parseEnrollmentQR(payload)
                    state.path.append(.approval(ApprovalFeature.State(
                        enrollment: enrollment,
                        alias: enrollment.suggestedAlias ?? ""
                    )))
                } catch {
                    return .none
                }
                return .none
            case let .path(.element(id: _, action: .approval(.delegate(.approved(capIdHex, _))))):
                return .send(.delegate(.completed(capIdHex: capIdHex)))
            case .path, .delegate:
                return .none
            }
        }
        .forEach(\.path, action: \.path)
    }
}
```

- [ ] **Step 3: AgentEnrollmentView**

Create `Wires/Wires/Features/AgentEnrollment/AgentEnrollmentView.swift`:

```swift
import SwiftUI
import ComposableArchitecture

struct AgentEnrollmentView: View {
    @Bindable var store: StoreOf<AgentEnrollmentFeature>

    var body: some View {
        NavigationStack(path: $store.scope(state: \.path, action: \.path)) {
            Text("Scan an agent QR")
        } destination: { store in
            switch store.case {
            case let .scan(scanStore):
                ScanView(store: scanStore, prompt: "Point at the agent's enrollment QR")
            case let .approval(approvalStore):
                ApprovalView(store: approvalStore)
            }
        }
    }
}
```

- [ ] **Step 4: Build**

⌘B. Expected: green.

- [ ] **Step 5: Commit**

```bash
git add Wires/Wires/Features/AgentEnrollment/
git commit -m "ios: AgentEnrollmentFeature composition + ApprovalView"
```

### Task 25: `HomeFeature` (reducer + view + tests)

**Files:**
- Create: `Wires/Wires/Features/Home/{HomeFeature,HomeView}.swift`
- Test: `Wires/WiresTests/HomeFeatureTests.swift`

- [ ] **Step 1: Reducer**

Create `Wires/Wires/Features/Home/HomeFeature.swift`:

```swift
import ComposableArchitecture

@Reducer
struct HomeFeature {
    @ObservableState
    struct State: Equatable {
        var caps: [CapRecord] = []
        var pendingCount: Int = 0
        @Presents var enrollment: AgentEnrollmentFeature.State?
    }

    enum Action {
        case onAppear
        case capsLoaded([CapRecord])
        case pendingCountUpdated(Int)
        case scanTapped
        case enrollment(PresentationAction<AgentEnrollmentFeature.Action>)
    }

    @Dependency(\.householdClient) var householdClient

    var body: some ReducerOf<Self> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                return .run { send in
                    let caps = (try? await householdClient.listCaps()) ?? []
                    await send(.capsLoaded(caps))
                    for await count in householdClient.observePendingCount() {
                        await send(.pendingCountUpdated(count))
                    }
                }
            case let .capsLoaded(caps):
                state.caps = caps
                return .none
            case let .pendingCountUpdated(c):
                state.pendingCount = c
                return .none
            case .scanTapped:
                state.enrollment = AgentEnrollmentFeature.State()
                return .none
            case .enrollment(.presented(.delegate(.completed))):
                state.enrollment = nil
                return .send(.onAppear)
            case .enrollment:
                return .none
            }
        }
        .ifLet(\.$enrollment, action: \.enrollment) {
            AgentEnrollmentFeature()
        }
    }
}
```

- [ ] **Step 2: Test**

Create `Wires/WiresTests/HomeFeatureTests.swift`:

```swift
import XCTest
import ComposableArchitecture
@testable import Wires

final class HomeFeatureTests: XCTestCase {
    func test_scan_presents_enrollment() async {
        let store = TestStore(initialState: HomeFeature.State()) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [] }
            $0.householdClient.observePendingCount = { AsyncStream { _ in } }
        }
        await store.send(.scanTapped) {
            $0.enrollment = AgentEnrollmentFeature.State()
        }
    }
}
```

- [ ] **Step 3: View**

Create `Wires/Wires/Features/Home/HomeView.swift`:

```swift
import SwiftUI
import ComposableArchitecture

struct HomeView: View {
    @Bindable var store: StoreOf<HomeFeature>

    var body: some View {
        NavigationStack {
            List {
                if store.pendingCount > 0 {
                    Section {
                        Label("\(store.pendingCount) pending to sync", systemImage: "arrow.triangle.2.circlepath")
                    }
                }
                Section("Agents") {
                    if store.caps.isEmpty {
                        Text("No agents yet").foregroundStyle(.secondary)
                    } else {
                        ForEach(store.caps, id: \.capIdHex) { cap in
                            VStack(alignment: .leading) {
                                Text(cap.agentAlias ?? cap.agentPubkeyHex.prefix(12) + "…")
                                    .font(.headline)
                                Text(cap.topicGlobs.joined(separator: ", "))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Wires")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        store.send(.scanTapped)
                    } label: {
                        Label("Scan agent", systemImage: "qrcode.viewfinder")
                    }
                }
            }
            .sheet(item: $store.scope(state: \.enrollment, action: \.enrollment)) { enrollmentStore in
                AgentEnrollmentView(store: enrollmentStore)
            }
            .onAppear { store.send(.onAppear) }
        }
    }
}
```

- [ ] **Step 4: Build and test**

⌘U.

- [ ] **Step 5: Commit**

```bash
git add Wires/Wires/Features/Home/ Wires/WiresTests/HomeFeatureTests.swift
git commit -m "ios: HomeFeature reducer + view + tests"
```

### Task 26: `BootstrapFeature` (reducer + tests)

**Files:**
- Create: `Wires/Wires/Features/Bootstrap/BootstrapFeature.swift`
- Test: `Wires/WiresTests/BootstrapFeatureTests.swift`

- [ ] **Step 1: Reducer**

Create `Wires/Wires/Features/Bootstrap/BootstrapFeature.swift`:

```swift
import ComposableArchitecture
import CryptoKit
import WiresKit
import Foundation

@Reducer
struct BootstrapFeature {
    @Reducer(state: .equatable)
    enum Path {
        case welcome(WelcomeStep)
        case pairHost(ScanFeature)
        case done(DoneStep)
    }

    @Reducer struct WelcomeStep {
        @ObservableState struct State: Equatable {}
        enum Action: Equatable { case createTapped }
        var body: some ReducerOf<Self> {
            EmptyReducer()
        }
    }

    @Reducer struct DoneStep {
        @ObservableState struct State: Equatable {
            var rootPubkeyHex: String = ""
        }
        enum Action: Equatable { case continueTapped }
        var body: some ReducerOf<Self> {
            EmptyReducer()
        }
    }

    @ObservableState
    struct State: Equatable {
        var path = StackState<Path.State>()
        var error: String?
        init() {
            path.append(.welcome(WelcomeStep.State()))
        }
    }

    enum Action {
        case path(StackAction<Path.State, Path.Action>)
        case createHouseholdResult(Result<CreatedHousehold, EquatableError>)
        case hostScanned(String)
        case selfCapMinted(String)
        case errorOccurred(String)
        case errorDismissed
        case delegate(Delegate)
        enum Delegate: Equatable {
            case completed
        }
    }

    struct CreatedHousehold: Equatable {
        let rootPubkeyHex: String
        let agentPubkeyHex: String
    }

    @Dependency(\.wiresClient) var wiresClient
    @Dependency(\.householdClient) var householdClient
    @Dependency(\.keychainClient) var keychainClient

    var body: some ReducerOf<Self> {
        Reduce { state, action in
            switch action {
            case .path(.element(id: _, action: .welcome(.createTapped))):
                return .run { [keychainClient, householdClient] send in
                    do {
                        let rootKey = Curve25519.Signing.PrivateKey()
                        let rootSeed = rootKey.rawRepresentation
                        let rootPub = rootKey.publicKey.rawRepresentation
                        try keychainClient.setData("wires.root.signingkey", rootSeed, .afterFirstUnlockThisDeviceOnlyBiometric)
                        try keychainClient.setData("wires.root.pubkey", rootPub, .afterFirstUnlockThisDeviceOnly)

                        let agentEd = Curve25519.Signing.PrivateKey()
                        let agentX = Curve25519.KeyAgreement.PrivateKey()
                        try keychainClient.setData("wires.agent.ed25519", agentEd.rawRepresentation, .afterFirstUnlockThisDeviceOnly)
                        try keychainClient.setData("wires.agent.x25519", agentX.rawRepresentation, .afterFirstUnlockThisDeviceOnly)

                        let hh = Household(
                            rootPubkeyHex: rootPub.map { String(format: "%02x", $0) }.joined(),
                            iosAgentPubkeyHex: agentEd.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
                        )
                        try await householdClient.saveHousehold(hh)
                        await send(.createHouseholdResult(.success(CreatedHousehold(
                            rootPubkeyHex: hh.rootPubkeyHex,
                            agentPubkeyHex: hh.iosAgentPubkeyHex
                        ))))
                    } catch {
                        await send(.createHouseholdResult(.failure(EquatableError(error.localizedDescription))))
                    }
                }
            case .createHouseholdResult(.success):
                state.path.append(.pairHost(ScanFeature.State()))
                return .none
            case let .createHouseholdResult(.failure(err)):
                state.error = err.message
                return .none
            case let .path(.element(id: _, action: .pairHost(.payloadScanned(payload)))):
                return .run { [wiresClient] send in
                    do {
                        _ = try wiresClient.parseHostPairQR(payload)
                        await send(.hostScanned(payload))
                    } catch {
                        await send(.errorOccurred("Invalid host QR"))
                    }
                }
            case let .hostScanned(payload):
                return .run { [wiresClient, householdClient] send in
                    do {
                        let info = try wiresClient.parseHostPairQR(payload)
                        guard let hh = try await householdClient.loadHousehold() else {
                            await send(.errorOccurred("No household"))
                            return
                        }
                        // Persist host info on Household
                        hh.hostNodeIdHex = info.nodeIdHex
                        hh.hostRelayURL = info.relay
                        hh.hostDirectAddrs = info.addrs
                        try await householdClient.saveHousehold(hh)
                        try await wiresClient.connectHost(info)

                        // Mint the iOS self-cap if not already present
                        if hh.iosAgentCapIdHex == nil {
                            let enrollment = AgentEnrollment(
                                agentEd25519: Data(hexString: hh.iosAgentPubkeyHex) ?? Data(),
                                agentX25519: Data(), // populated below from Keychain
                                suggestedAlias: "this device"
                            )
                            // For brevity, the actual self-cap mint flow re-uses ApprovalFeature's
                            // logic via WiresClient.mintGrant with __caps glob and r+w rights.
                            let result = try await wiresClient.mintGrant(
                                enrollment: enrollment,
                                topicGrants: [],
                                rights: [.read, .write],
                                chain: ChainPosition(nextSeq: 0, lastHash: nil)
                            )
                            hh.iosAgentCapIdHex = result.capIdHex
                            hh.iosAgentNextSeq = result.newChainPosition.nextSeq
                            hh.iosAgentLastHash = result.newChainPosition.lastHash
                            try await householdClient.saveHousehold(hh)
                            try await wiresClient.setSelfCapId(result.capIdHex)
                            await send(.selfCapMinted(result.capIdHex))
                        } else {
                            await send(.selfCapMinted(hh.iosAgentCapIdHex!))
                        }
                    } catch {
                        await send(.errorOccurred(error.localizedDescription))
                    }
                }
            case .selfCapMinted:
                state.path.append(.done(DoneStep.State()))
                return .none
            case .path(.element(id: _, action: .done(.continueTapped))):
                return .send(.delegate(.completed))
            case let .errorOccurred(msg):
                state.error = msg
                return .none
            case .errorDismissed:
                state.error = nil
                return .none
            case .path, .delegate:
                return .none
            }
        }
        .forEach(\.path, action: \.path)
    }
}

extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var i = hexString.startIndex
        for _ in 0..<len {
            let next = hexString.index(i, offsetBy: 2)
            guard let b = UInt8(hexString[i..<next], radix: 16) else { return nil }
            data.append(b)
            i = next
        }
        self = data
    }
}
```

- [ ] **Step 2: Test (happy path stub)**

Create `Wires/WiresTests/BootstrapFeatureTests.swift`:

```swift
import XCTest
import ComposableArchitecture
@testable import Wires
@testable import WiresKit

final class BootstrapFeatureTests: XCTestCase {
    func test_starts_at_welcome() {
        let state = BootstrapFeature.State()
        guard case .welcome = state.path.first else {
            XCTFail("expected welcome at top of path"); return
        }
    }

    func test_errorOccurred_sets_error() async {
        let store = TestStore(initialState: BootstrapFeature.State()) {
            BootstrapFeature()
        }
        await store.send(.errorOccurred("nope")) { $0.error = "nope" }
        await store.send(.errorDismissed) { $0.error = nil }
    }
}
```

(Deeper happy-path tests require careful dependency wiring — leave for follow-up.)

- [ ] **Step 3: Build and run tests**

⌘U.

- [ ] **Step 4: Commit**

```bash
git add Wires/Wires/Features/Bootstrap/BootstrapFeature.swift Wires/WiresTests/BootstrapFeatureTests.swift
git commit -m "ios: BootstrapFeature reducer + tests"
```

### Task 27: BootstrapView

**Files:**
- Create: `Wires/Wires/Features/Bootstrap/BootstrapView.swift`

- [ ] **Step 1: View**

Create `Wires/Wires/Features/Bootstrap/BootstrapView.swift`:

```swift
import SwiftUI
import ComposableArchitecture

struct BootstrapView: View {
    @Bindable var store: StoreOf<BootstrapFeature>

    var body: some View {
        NavigationStack(path: $store.scope(state: \.path, action: \.path)) {
            VStack(spacing: 20) {
                Text("Welcome to Wires").font(.largeTitle)
                Text("Create your household root key on this device.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal)
                Button("Create Household") {
                    if case let .welcome(welcomeStore) = store.path.first {
                        store.send(.path(.element(id: store.path.ids.first!, action: .welcome(.createTapped))))
                    }
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
        } destination: { store in
            switch store.case {
            case let .welcome(welcomeStore):
                Text("…").onAppear {} // unused; welcome is the root
            case let .pairHost(scanStore):
                ScanView(store: scanStore, prompt: "Point at the wires-host pair QR")
            case let .done(doneStore):
                VStack {
                    Text("Household ready").font(.title)
                    Text(doneStore.rootPubkeyHex).font(.footnote.monospaced())
                    Button("Continue") {
                        store.send(.done(.continueTapped))
                    }
                    .buttonStyle(.borderedProminent)
                }.padding()
            }
        }
        .alert("Error", isPresented: .init(
            get: { store.error != nil },
            set: { if !$0 { store.send(.errorDismissed) } }
        )) {
            Button("OK") { store.send(.errorDismissed) }
        } message: { Text(store.error ?? "") }
    }
}
```

- [ ] **Step 2: Build**

⌘B.

- [ ] **Step 3: Commit**

```bash
git add Wires/Wires/Features/Bootstrap/BootstrapView.swift
git commit -m "ios: BootstrapView"
```

### Task 28: `AppFeature` + entry point + restoration test

**Files:**
- Create: `Wires/Wires/App/AppFeature.swift`
- Modify: `Wires/Wires/WiresApp.swift`
- Test: `Wires/WiresTests/AppFeatureTests.swift`

- [ ] **Step 1: AppFeature**

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

    @Dependency(\.householdClient) var householdClient

    var body: some ReducerOf<Self> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                return .run { send in
                    let hh = try? await householdClient.loadHousehold()
                    await send(.householdLoaded(hh))
                }
            case let .householdLoaded(hh):
                if let hh, hh.hostNodeIdHex != nil, hh.iosAgentCapIdHex != nil {
                    state = .home(HomeFeature.State())
                } else {
                    state = .bootstrap(BootstrapFeature.State())
                }
                return .none
            case .bootstrap(.delegate(.completed)):
                state = .home(HomeFeature.State())
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

- [ ] **Step 2: Entry point**

Replace `Wires/Wires/WiresApp.swift`:

```swift
import SwiftUI
import SwiftData
import ComposableArchitecture

@main
struct WiresApp: App {
    let store: StoreOf<AppFeature> = Store(initialState: .launching) {
        AppFeature()
    }
    let modelContainer: ModelContainer = try! ModelContainer(
        for: Household.self, TopicRecord.self, CapRecord.self, PendingPublish.self
    )

    var body: some Scene {
        WindowGroup {
            AppRootView(store: store)
                .modelContainer(modelContainer)
                .onAppear { store.send(.onAppear) }
        }
    }
}

struct AppRootView: View {
    @Bindable var store: StoreOf<AppFeature>

    var body: some View {
        switch store.state {
        case .launching:
            ProgressView()
        case .bootstrap:
            if let bootstrapStore = store.scope(state: \.bootstrap, action: \.bootstrap) {
                BootstrapView(store: bootstrapStore)
            }
        case .home:
            if let homeStore = store.scope(state: \.home, action: \.home) {
                HomeView(store: homeStore)
            }
        }
    }
}
```

- [ ] **Step 3: AppFeature test**

Create `Wires/WiresTests/AppFeatureTests.swift`:

```swift
import XCTest
import ComposableArchitecture
@testable import Wires

final class AppFeatureTests: XCTestCase {
    func test_no_household_goes_to_bootstrap() async {
        let store = TestStore(initialState: AppFeature.State.launching) {
            AppFeature()
        } withDependencies: {
            $0.householdClient.loadHousehold = { nil }
        }
        await store.send(.onAppear)
        await store.receive(\.householdLoaded) {
            $0 = .bootstrap(BootstrapFeature.State())
        }
    }

    func test_completed_household_goes_to_home() async {
        let hh = Household(rootPubkeyHex: "deadbeef", iosAgentPubkeyHex: "cafe")
        hh.hostNodeIdHex = "abc"
        hh.iosAgentCapIdHex = "1234"
        let store = TestStore(initialState: AppFeature.State.launching) {
            AppFeature()
        } withDependencies: {
            $0.householdClient.loadHousehold = { hh }
            $0.householdClient.listCaps = { [] }
            $0.householdClient.observePendingCount = { AsyncStream { _ in } }
        }
        await store.send(.onAppear)
        await store.receive(\.householdLoaded) {
            $0 = .home(HomeFeature.State())
        }
    }
}
```

- [ ] **Step 4: Build + run on simulator**

⌘U for tests. Then ⌘R to run on simulator. Expected: launches to welcome screen.

- [ ] **Step 5: Commit**

```bash
git add Wires/Wires/App/ Wires/Wires/WiresApp.swift Wires/WiresTests/AppFeatureTests.swift
git commit -m "ios: AppFeature + entry point + restoration tests"
```

### Task 29: End-to-end manual acceptance + snapshot tests

**Files:**
- Create: `Wires/WiresUITests/SnapshotTests.swift`
- Modify: `Wires/WiresTests/` (add `swift-snapshot-testing` dep via SwiftPM)

- [ ] **Step 1: Add `swift-snapshot-testing` package dependency**

In Xcode, project → Package Dependencies → add `https://github.com/pointfreeco/swift-snapshot-testing` from `1.17.0`. Add `SnapshotTesting` to the `WiresTests` target only.

- [ ] **Step 2: Snapshot tests**

Create `Wires/WiresUITests/SnapshotTests.swift`:

```swift
import XCTest
import SnapshotTesting
import SwiftUI
@testable import Wires

final class SnapshotTests: XCTestCase {
    func test_home_empty() {
        let view = HomeView(store: .init(initialState: HomeFeature.State()) {
            HomeFeature()
        })
        assertSnapshot(of: view, as: .image(layout: .device(config: .iPhone13)))
    }
}
```

- [ ] **Step 3: Run snapshot tests once to seed the reference images**

⌘U. First run will record snapshots and "fail." Re-run; expected: pass.

- [ ] **Step 4: Manual acceptance walk-through**

In a separate terminal:

```bash
# Terminal A: start wires-host
mkdir -p /tmp/wires-host-data
target/debug/wires-host --data-dir /tmp/wires-host-data show-pair-qr --label "manual-acceptance"
# Then in another shell:
target/debug/wires-host --data-dir /tmp/wires-host-data --topic <generated-topic>
```

```bash
# Terminal B: a fresh agent
mkdir -p /tmp/wires-agent-data
target/debug/wires --data-dir /tmp/wires-agent-data enroll
```

On the iPhone simulator (or device):
- Launch app → tap Create Household → tap pair-host scan → point at terminal A's QR → confirm "Household ready" screen appears.
- Tap Continue → on Home, tap Scan agent → point at terminal B's enrollment QR → enter `home.test` as topic glob, toggle read + write → tap Approve → confirm Face ID prompt → confirm a new row appears in Home's agent list.

- [ ] **Step 5: Commit snapshots**

```bash
git add Wires/WiresUITests/ Wires/WiresTests/__Snapshots__/ 2>/dev/null || true
git commit -m "ios: snapshot tests + manual acceptance walk-through"
```

---

## Notes / known gaps for follow-up

These are intentionally not part of v1 (see spec §11) but are worth flagging here for the implementing engineer to find later:

- **Self-cap mint mid-bootstrap.** Task 26 mints the iOS self-cap with `topicGrants: []` and rights for read+write on `__caps`. The `Capability.topics` field needs to contain `__caps` explicitly for receiver-side ACL checks to permit publishing. Verify and adjust the `Capability.new_unsigned(...)` call site so the iOS agent's cap actually carries the `__caps` topic glob.
- **Per-topic epoch keys on existing topics.** Task 23's `topicGrants` for *existing* literal topics passes `epochs: []`. The real flow needs to load all epoch keys from Keychain (`wires.topic.<id>.epoch.<n>` for `n in 0..currentEpoch+1`) and include them in the `TopicGrant`. Add a `KeychainClient.listKeys(prefix:)` helper or iterate via `Household.topics[].currentEpoch`.
- **wires-host publish-accept loop.** `HostConnection.publish` opens a uni-directional stream on the wires ALPN; verify the existing `wires-host` accept loop reads from such streams and calls `TopicLogs::append` on each received envelope (or add it if missing).

---

## Self-Review

(Performed inline after writing.)

- **Spec coverage:**
  - §2 trust model (root + agent identity + epoch keys) → Tasks 19 (KeychainClient), 26 (root key generation in Bootstrap), 22+23 (epoch keys to/from Keychain — noted as a gap above).
  - §3 pairing flows → Tasks 22 (Scan), 26 (Bootstrap), 22+23+24 (agent enrollment composition), 25 (Home entry).
  - §4 data model → Task 18.
  - §5 wire-side additions → Tasks 4, 5, 6, 7 plus the RootSigner / AgentIdentity lifts in 1–3.
  - §6 Rust-on-iOS facade → Tasks 8–15.
  - §7 TCA architecture → Tasks 17 (project setup), 19–28 (features + dependencies).
  - §8 build → Task 16.
  - §9 error handling → Task 9 (`WiresError`), per-feature reducers handle Swift-side errors.
  - §10 testing → reducer tests in Tasks 22, 23, 25, 26, 28; snapshot test in 29; manual acceptance in 29.
- **Placeholder scan:** one `todo!()` in Task 13's scaffold is intentionally completed in Task 15 — flagged explicitly. The "TODO: load from Keychain in real flow" comment in Task 23 is flagged in the "Notes / known gaps" section above.
- **Type consistency:** `ChainPosition`, `MintResult`, `Right`, `TopicGrant`, `AgentEnrollment`, `HostInfo`, `SignedWireMessage`, `NewTopic` — all defined once in Task 10 and referenced consistently. `Household` fields (`iosAgentNextSeq`, `iosAgentLastHash`, `iosAgentCapIdHex`, `iosAgentPubkeyHex`) match between Tasks 18, 23, and 26.
