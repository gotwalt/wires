# Wires — iOS Companion App Design

**Date:** 2026-05-14
**Status:** Draft — on hold pending upcoming substrate architecture changes. Reviewed and approved 2026-05-14 against the current substrate spec; revisit before implementing to confirm the trust model, capability shape, and `__caps` semantics still hold.
**Scope:** v1 of the iOS companion app. Pairs with [the substrate design](2026-05-14-wires-substrate-design.md), which defines the wire format, capability model, and host blindness contract this app participates in.

---

## 1. Mental model

The iOS app is the **root of trust** for a household's wires network. It custodies the Ed25519 root key that signs every capability, and it is where the operator approves new agents joining the network.

Architecturally it is a thin SwiftUI app over a Rust core. The Rust core (`crates/wires-uniffi`) is a narrow facade exposing only what the iOS app needs — QR parsing, signed-message construction, one iroh connection to the household's blind host. The existing `wires-core`, `wires-crypto`, and `wires-net` crates are reused unchanged. `wires-store` and `wires-node` are not used on iOS: there is no append-only log to maintain, no per-topic ciphertext store, no replay responder.

Persistence is split by sensitivity: SwiftData for low-sensitivity records (cap registry, topic registry, host info, pending publish queue), Keychain for secrets (root signing key, agent identity, topic epoch keys).

**v1 user-visible scope:**
- Generate household root key on first launch.
- Pair with the household's `wires-host` via a QR shown by `wires-host`.
- Onboard new agents by scanning their enrollment QR and approving topics + rights.

**Explicitly out of scope for v1:**
- Revoking capabilities (no Revoke UI). Revocation can only be performed by the root key, so this is an iOS feature when added.
- Tail / view feeds (read-only household activity view).
- Standalone "create topic" UI. Topic creation happens implicitly when a granted cap names a previously-unknown topic.
- Multi-device root key custody (e.g. iPhone + iPad). One device per household for v1.
- Backup / recovery of the root key. Lose the phone, lose the household.
- iCloud sync of any iOS-app state.

---

## 2. Trust model and key custody

### Root key

A single Ed25519 keypair, generated in CryptoKit at first launch and stored in iOS Keychain.

- Keychain accessibility: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
- Access control: `SecAccessControlCreateWithFlags(.privateKeyUsage, [.biometryCurrentSet])`. Every signing operation triggers Face ID / Touch ID via LocalAuthentication.
- `kSecAttrSynchronizable = false`. Key does not replicate to iCloud Keychain.
- `.afterFirstUnlockThisDeviceOnly` excludes the key from iCloud backups by definition.

**Why not Secure Enclave?** iOS Secure Enclave hardware only supports P-256 ECDSA. The wires protocol uses Ed25519 consistently across all signatures (envelope signing, agent identity, cap signing). Adding a second signature algorithm to the protocol surface to accommodate a single platform constraint was the alternative; we chose to keep Ed25519 uniform and accept the Keychain-with-biometric storage compromise.

**Security delta:** Both SE and Keychain-with-biometric gate signing on biometric assertion and prevent extraction via the normal Keychain API without that assertion. SE additionally guarantees the private key bytes never enter normal CPU memory; Keychain does not — the seed is briefly in process memory during signing. For a household-scale trust root the realistic threats (lost or stolen phone) are mitigated identically by both. Kernel compromise during an authorized sign window is the differential threat and is judged out-of-scope.

### Agent identity (the iOS app as a wires peer)

To publish capability events to the `__caps` topic, the iOS app must be a wires peer with its own agent identity. This identity is separate from the root key and is software Ed25519 + X25519 stored in Keychain.

- `wires.agent.ed25519` — 32-byte Ed25519 seed
- `wires.agent.x25519` — 32-byte X25519 secret
- Both with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, no biometric ACL (agent-identity signs every envelope; biometric prompting per envelope is not usable UX).
- Both `kSecAttrSynchronizable = false`.

The iOS app's agent pubkey is registered like any other agent in the household's `__caps` topic. The first cap minted by a new household is the iOS app's own cap, self-signed by the root, granting write on `__caps`. (See §3.1 step 4 for the bootstrap flow that mints this self-cap.)

### Topic epoch keys

The iOS app holds, for each topic the household has created, every epoch symmetric key (32 bytes, ChaCha20-Poly1305) ever issued. Required because `__topic.history_grant` events sealed to new agents must carry the full epoch-key history.

Storage: Keychain, one entry per (topic_id, epoch).
- Key: `wires.topic.<topic_id_hex>.epoch.<n>`
- Value: 32 raw bytes
- Same accessibility as the agent identity: `.afterFirstUnlockThisDeviceOnly`, no biometric ACL.

Topic epoch keys are placed in Keychain rather than SwiftData because SwiftData's store, while encrypted at rest while the device is locked, is plaintext while the device is unlocked. An attacker with a one-time unlocked-device backup can therefore extract a SwiftData store but not Keychain entries with `.afterFirstUnlockThisDeviceOnly`.

---

## 3. Pairing flows

Three flows: first-launch wizard, agent onboarding, and (implicit) per-launch reconnect.

### 3.1 First-launch wizard

Triggered when AppFeature observes no `Household` record in SwiftData.

**Step 1: Create household.** Single screen, single button "Create Household". On tap:
1. Generate Ed25519 root keypair in CryptoKit. Persist to Keychain at `wires.root.signingkey` with the biometric ACL described in §2. Cache root pubkey hex separately at `wires.root.pubkey` (no ACL, read freely).
2. Generate Ed25519 + X25519 agent identity. Persist to Keychain.
3. Insert a `Household` record into SwiftData: `rootPubkeyHex` set, `iosAgentPubkeyHex` set, `iosAgentNextSeq = 0`, `iosAgentLastHash = nil`, `iosAgentCapIdHex = nil`. Host fields nil — populated in step 2; cap fields nil — populated in step 4.
4. Advance to step 2.

**Step 2: Pair with host.** Camera-permission prompt (on first invocation), then live AVFoundation capture session scanning for QR codes. The operator runs `wires-host show-pair-qr` on their server; the rendered QR encodes a base64 `HostPairToken` (§5.1). On scan:
1. Decode and validate token (version check, NodeId hex parses, addresses well-formed).
2. Populate `Household.hostNodeIdHex`, `hostRelayURL`, `hostDirectAddrs`.
3. Call into Rust: `WiresApp.bootstrap(agentIdentity, rootSigner)` to construct the in-process state; then `WiresApp.connectHost(HostInfo)` to dial the host's iroh `NodeAddr`, open a QUIC connection, subscribe to `__caps` via iroh-gossip, and confirm the subscribe ACK lands within a 10s timeout.
4. If the iOS app's own agent identity has not yet been bound to a cap, mint and publish the self-cap now: a `Capability` granting the iOS agent `read+write` on `__caps`, signed by the root (with biometric prompt). The mint flow is described in §3.2 step 3.b; the only difference for the self-cap is that `enrollment` is constructed from the iOS app's own keys, not from a scanned QR.
5. Advance to step 3.

**Step 3: Done.** Confirmation screen with the household root pubkey hex (a long string the operator may want to save for verification). Tap "Continue" to enter the Home screen.

### 3.2 Agent onboarding

Triggered from Home by "Scan agent" button.

**Step 1: Agent prepares.** The new agent runs `wires enroll` (new CLI subcommand, §5.2). It:
1. Reads `data_dir/identity.ed25519` and `identity.x25519`; if absent, generates both and persists.
2. Prints an `EnrollmentToken` (base64) and a Unicode QR render of the same token to stdout.

The operator points the iOS camera at the QR.

**Step 2: Scan and approve.** On successful QR decode:
1. Push the `ApprovalFeature` screen (modal sheet). Pre-fill alias from `EnrollmentToken.suggested_alias` (editable). Empty topic-globs field. Read + write toggles both off by default; operator must explicitly enable.
2. Operator types topic globs one per line — e.g. `home.lights`, `home.*`, `mail.inbox`. Sets rights. Taps Approve.
3. **Approve action:**
   a. Resolve topic globs against the topic registry:
      - For each glob, find matching `TopicRecord`s in SwiftData. Collect their `topic_id`s and load all epoch keys from Keychain.
      - If the glob is a literal name (`home.lights`, no `*`) and no `TopicRecord` matches, this is a new topic. Call `WiresClient.generateTopicIdAndEpoch0()` to produce a fresh `(topic_id, epoch_0_key)`. Create a `TopicRecord` (currentEpoch = 0, name = the literal). Persist the epoch key to Keychain. Treat the new topic as a match for the glob.
      - If the glob contains a wildcard (`*` or `**`) and matches zero existing topics, no new topics are created — the glob is recorded in the cap and applies prospectively to any future matching topic.
   b. Build the message bundle. Read the current chain position (`iosAgentNextSeq`, `iosAgentLastHash`) and self-cap id (`iosAgentCapIdHex`) from the `Household` record. Call `WiresClient.mintGrant(enrollment, topicGrants, rights, chainPosition)`. Rust:
      - Constructs `Capability` with `agent = enrollment.agent_ed25519`, `topics = glob_strings`, `rights`, `issued = now`, `expires = None`, fresh random `cap_id`.
      - Signs the cap by invoking the `RootSigner` callback. Swift side triggers Face ID, signs the cap signing-bytes with the Keychain-resident root key, returns 64 bytes.
      - Constructs the `__cap.grant` `WireMessage` envelope: `topic_id = __caps`, kind `SealedTo(enrollment.agent_x25519)`, sender = iOS agent pubkey, cap_id = the iOS agent's self-cap, content = canonical-JSON-serialized `Capability` plus topic name metadata for each `topic_id` in `topicGrants`.
      - For each `topic_id` in `topicGrants` with non-empty `epoch_keys`, constructs a `__topic.history_grant` envelope on that topic, kind `SealedTo(enrollment.agent_x25519)`, content `{topic_id, epochs: [{epoch, key}, ...]}`.
      - Signs each envelope with the iOS agent ed25519. Encrypts each (sealed-box for `SealedTo`).
      - Returns `[SignedWireMessage]` (a UniFFI-friendly opaque type wrapping `Vec<u8>`).
   c. Persist the new `CapRecord` to SwiftData and advance the chain position on `Household` via `HouseholdClient.advanceChain(newChainPosition)`. Both writes happen in a single SwiftData transaction so a crash mid-write does not leave chain state and cap registry out of sync.
   d. Call `WiresClient.publish(messages)`. Rust gossips each envelope on its target topic via the existing `HostConnection`.
   e. On publish failure: write each message to SwiftData `PendingPublish`. Surface a pending-sync banner on Home. The chain position has already advanced — the envelopes are valid and durable; re-issuing them is safe (idempotent on hash).
4. Dismiss the sheet, return to Home with a brief confirmation.

**Epoch rotation note.** v1 does not rotate epochs on agent add (membership is monotonic without revoke). When revoke is added in v2, agent removal triggers `__topic.epoch_advance` events sealed to each *remaining* member. The plumbing for epoch state is already in place — only the trigger and the rotation pipeline are deferred.

### 3.3 Per-launch reconnect

On every app launch (after first):
1. AppFeature reads `Household` from SwiftData. Bootstrap completion is judged by `hostNodeIdHex != nil && iosAgentCapIdHex != nil`. Complete → home path; incomplete or absent → bootstrap path, resumed at the first incomplete step.
2. Load agent identity from Keychain.
3. Call `WiresApp.bootstrap(agentIdentity, rootSigner)` and `WiresApp.connectHost(hostInfo)`.
4. On `connectHost` failure (host offline, no network): proceed to Home in a degraded state. Drain `PendingPublish` queue when reachability resumes.

---

## 4. Data model

Four SwiftData `@Model` types, in `Wires/Wires/Models/`.

```swift
@Model final class Household {
    @Attribute(.unique) var rootPubkeyHex: String
    var createdAt: Date

    // Host pairing (populated at bootstrap step 2)
    var hostNodeIdHex: String?
    var hostRelayURL: String?
    var hostDirectAddrs: [String]

    // iOS agent's own self-cap, minted at bootstrap step 4
    var iosAgentPubkeyHex: String         // 32-byte ed25519 pubkey of this device's agent identity
    var iosAgentCapIdHex: String?         // nil until the self-cap is minted

    // iOS agent's per-publisher chain on __caps. Used by mint_grant to build envelopes.
    var iosAgentNextSeq: UInt64           // initialized to 0
    var iosAgentLastHash: Data?           // nil at seq=0; 32 bytes after each successful mint

    @Relationship(deleteRule: .cascade) var topics: [TopicRecord]
    @Relationship(deleteRule: .cascade) var caps: [CapRecord]
}

@Model final class TopicRecord {
    @Attribute(.unique) var topicIdHex: String
    var name: String
    var createdAt: Date
    var currentEpoch: UInt32
    // Epoch key bytes live in Keychain, not here. This record only asserts
    // that epochs 0..currentEpoch exist; the actual bytes are retrieved by
    // looking up wires.topic.<topicIdHex>.epoch.<n>.
}

@Model final class CapRecord {
    @Attribute(.unique) var capIdHex: String
    var agentPubkeyHex: String
    var agentAlias: String?
    var topicGlobs: [String]
    var rights: [String]
    var issuedAt: Date
    var expiresAt: Date?
    var revokedAt: Date?
}

@Model final class PendingPublish {
    @Attribute(.unique) var id: UUID
    var payload: Data
    var createdAt: Date
    var attempts: Int
}
```

**Keychain layout** (all `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAttrSynchronizable = false`):

| Key | Value | ACL |
|---|---|---|
| `wires.root.signingkey` | Raw 32-byte Ed25519 seed | `.biometryCurrentSet` |
| `wires.root.pubkey` | Raw 32-byte Ed25519 pubkey | None (read freely) |
| `wires.agent.ed25519` | Raw 32-byte Ed25519 seed | None |
| `wires.agent.x25519` | Raw 32-byte X25519 secret | None |
| `wires.topic.<id_hex>.epoch.<n>` | Raw 32-byte symmetric key | None |

---

## 5. Wire-side additions

Two additions outside the iOS app, and one small refactor.

### 5.1 `wires-host show-pair-qr`

New subcommand on the `wires-host` binary. Prints a base64 `HostPairToken` plus a Unicode QR render to stdout.

```rust
// crates/wires-net/src/pair.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPairToken {
    pub version: u8,                       // 1
    pub host_node_id: String,              // hex iroh EndpointId
    pub host_addrs: Vec<String>,           // direct addr hints, "ip:port"
    pub host_relay: Option<String>,        // relay url
    pub household_label: Option<String>,   // optional friendly name
}
```

Encoding: URL-safe base64 of canonical JSON, matching the pattern of `InviteToken` in the same crate. No secrets — the host NodeId is a public identifier and the addresses are public network locations.

### 5.2 `wires enroll`

New subcommand on the `wires` binary. Generates agent identity (if not already present), then prints an `EnrollmentToken` and a Unicode QR.

```rust
// crates/wires-net/src/enroll.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub version: u8,                       // 1
    pub agent_ed25519: [u8; 32],
    pub agent_x25519: [u8; 32],
    pub agent_local_addrs: Vec<String>,
    pub suggested_alias: Option<String>,   // derived from hostname
}
```

The enrollment token contains no secrets — `agent_ed25519` and `agent_x25519` are the agent's *public* keys. The matching private keys remain on the agent's machine.

The agent does not yet know the host NodeAddr at enrollment time. After approval the iOS app publishes the cap to `__caps`, but the agent cannot pick it up until it dials a peer. For v1 the agent operator configures the host separately (e.g. `wires set-host <node-addr>` or by hand-editing `config.toml`). The substrate spec's invite-bundles-peer-hint flow is preserved as the existing `wires invite` command and is unchanged by this work.

### 5.3 Lift `RootSigner` into `wires-core`

Currently `Capability::sign` takes `&SigningKey` directly:

```rust
// crates/wires-core/src/cap.rs (current)
impl Capability {
    pub fn sign(&mut self, root: &SigningKey) -> Result<(), CapError> { ... }
}
```

Refactor to a trait:

```rust
// crates/wires-core/src/cap.rs (new)
pub trait RootSigner {
    fn pubkey(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError>;
}

impl Capability {
    pub fn sign(&mut self, signer: &dyn RootSigner) -> Result<(), CapError> { ... }
}
```

Two impls:
- `LocalFileSigner` in `wires-cli` — wraps a `SigningKey` loaded from `root.ed25519`. Today's `wires invite` is migrated to use it. Behavior identical.
- `KeychainBiometricSigner` in `wires-uniffi` — wraps a `Box<dyn SwiftRootSigner>` callback. The Swift side reads the root key from Keychain (triggering Face ID), reconstructs `Curve25519.Signing.PrivateKey`, signs, zeros the seed buffer.

The same lift applies to the agent identity dependency in `Node::open`. Today `Node::open(cfg)` reads `identity.ed25519` and `identity.x25519` from disk via `cfg.data_dir`. We introduce:

```rust
// crates/wires-node/src/identity.rs (new)
pub struct AgentIdentity {
    pub ed25519_seed: [u8; 32],
    pub x25519_secret: [u8; 32],
}

impl Node {
    pub fn open_with_identity(cfg: NodeConfig, identity: AgentIdentity) -> Result<Self, NodeError> { ... }
    pub fn open(cfg: NodeConfig) -> Result<Self, NodeError> { /* loads identity from cfg.data_dir, calls open_with_identity */ }
}
```

The CLI keeps using `Node::open`. `wires-uniffi` uses `Node::open_with_identity`, but note that on iOS we do not actually use `Node::open` or `wires-node` at all (see §6); the lift exists so that the FFI's `WiresApp::bootstrap` can construct the relevant pieces of state without the disk-file dependency.

---

## 6. Rust-on-iOS shape: `wires-uniffi`

A new crate, `crates/wires-uniffi`, that depends on `wires-core`, `wires-crypto`, `wires-net`. It does **not** depend on `wires-store` or `wires-node` — those are designed for tailing/replay/log-keeping, which iOS does not do.

### Crate role

`wires-uniffi` is a thin facade. Its public API is a single `WiresApp` UniFFI object plus a small set of parsers and types. The bulk of the protocol logic remains in `wires-core` and `wires-crypto`, unchanged.

### Public FFI surface

```rust
#[derive(uniffi::Object)]
pub struct WiresApp {
    /* private: AgentIdentity, RootSigner box, optional HostConnection */
}

#[uniffi::export]
impl WiresApp {
    #[uniffi::constructor]
    pub fn bootstrap(
        agent_identity: AgentIdentity,
        root_signer: Box<dyn SwiftRootSigner>,
    ) -> Arc<Self> { ... }

    pub async fn connect_host(&self, host: HostInfo) -> Result<(), WiresError> { ... }
    pub fn disconnect_host(&self);

    pub fn parse_host_pair_qr(&self, payload: String) -> Result<HostInfo, WiresError>;
    pub fn parse_agent_enrollment_qr(&self, payload: String) -> Result<AgentEnrollment, WiresError>;

    pub fn generate_topic_id_and_epoch0(&self) -> NewTopic;

    pub fn mint_grant(
        &self,
        enrollment: AgentEnrollment,
        topic_grants: Vec<TopicGrant>,
        rights: Vec<Right>,
    ) -> Result<Vec<SignedWireMessage>, WiresError>;

    pub async fn publish(&self, messages: Vec<SignedWireMessage>) -> Result<(), WiresError>;
}

#[derive(uniffi::Record)]
pub struct AgentIdentity { pub ed25519_seed: Vec<u8>, pub x25519_secret: Vec<u8> }

#[derive(uniffi::Record)]
pub struct HostInfo { pub node_id_hex: String, pub addrs: Vec<String>, pub relay: Option<String> }

#[derive(uniffi::Record)]
pub struct AgentEnrollment { pub agent_ed25519: Vec<u8>, pub agent_x25519: Vec<u8>, pub suggested_alias: Option<String> }

#[derive(uniffi::Record)]
pub struct TopicGrant { pub topic_id_hex: String, pub name: String, pub epochs: Vec<EpochKey> }

#[derive(uniffi::Record)]
pub struct EpochKey { pub epoch: u32, pub key: Vec<u8> }

#[derive(uniffi::Record)]
pub struct NewTopic { pub topic_id_hex: String, pub epoch_0_key: Vec<u8> }

#[derive(uniffi::Record)]
pub struct SignedWireMessage { pub bytes: Vec<u8> }  // serialized WireMessage, opaque to Swift

#[derive(uniffi::Enum)]
pub enum Right { Read, Write }

pub trait SwiftRootSigner: Send + Sync {
    fn pubkey(&self) -> Vec<u8>;
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, WiresError>;
}
```

### Internal state

A single `tokio` runtime is owned by `WiresApp` (built once at `bootstrap`, dropped at `Drop`). The optional `HostConnection` owns an iroh `Endpoint`, a gossip subscription handle on `__caps`, and a small in-memory retry queue. No disk persistence inside the Rust core.

### What about the agent's own message-chain state?

The iOS app's agent identity publishes `__cap.grant` events. Each is a `WireMessage` on the `__caps` topic with `(sender = ios_agent, seq, prev_hash)`. Per the substrate spec, the per-publisher hash chain must be maintained or the host will reject as a chain fork.

On iOS the chain state is held in SwiftData on the `Household` record (`iosAgentNextSeq`, `iosAgentLastHash`; see §4). Before each `mint_grant`, Swift passes the current `ChainPosition` into the FFI; Rust uses it during envelope construction. The returned `MintResult` carries the post-mint `ChainPosition`, which Swift writes back transactionally alongside the new `CapRecord`. This is the only mutable wire-protocol state the iOS app maintains, and lifting it out of Rust into SwiftData keeps the Rust core stateless across crash boundaries.

This adds one parameter pair to `mint_grant`. Updated signature:

```rust
pub fn mint_grant(
    &self,
    enrollment: AgentEnrollment,
    topic_grants: Vec<TopicGrant>,
    rights: Vec<Right>,
    chain_position: ChainPosition,
) -> Result<MintResult, WiresError>;

#[derive(uniffi::Record)]
pub struct ChainPosition { pub next_seq: u64, pub last_hash: Option<Vec<u8>> }

#[derive(uniffi::Record)]
pub struct MintResult {
    pub messages: Vec<SignedWireMessage>,
    pub new_chain_position: ChainPosition,
    pub cap_id_hex: String,
}
```

---

## 7. Swift architecture under TCA

The iOS app uses [swift-composable-architecture](https://github.com/pointfreeco/swift-composable-architecture) (TCA, current 1.16+ release line). The reasons: many async flows (scan → parse → mint → publish → persist) each with multiple failure modes, an FFI boundary that fits naturally as a Dependency, and a strong testing story via `TestStore`.

### Features

One folder per feature under `Wires/Wires/Features/`, each containing a `Feature.swift` (reducer) and a `FeatureView.swift` (SwiftUI).

- **`AppFeature`** — root. `State` is an enum: `case bootstrap(BootstrapFeature.State)` or `case home(HomeFeature.State)`. Transitions on `bootstrapCompleted`. At launch, reads `Household` from SwiftData via `HouseholdClient`; absent → bootstrap, present → home.
- **`BootstrapFeature`** — three-screen wizard. Uses `StackState<Path.State>` with cases `welcome`, `pairHost(ScanFeature.State)`, `done`.
- **`HomeFeature`** — list of `CapRecord`s, "Scan agent" button, pending-publish banner. Presents `AgentEnrollmentFeature` via `@Presents`.
- **`AgentEnrollmentFeature`** — composes `ScanFeature` and `ApprovalFeature` via a small two-state stack.
- **`ScanFeature`** — reusable QR scanner reducer. State: camera permission, last decoded payload, error. Generic in payload shape via an init-time parser closure.
- **`ApprovalFeature`** — approval sheet. State: alias, topic-globs (one per line), read/write toggles. Approve action triggers the mint+publish effect chain.

### Dependencies

Under `Wires/Wires/Dependencies/`. Each is a `struct` of closures with `DependencyKey` conformance, plus `liveValue`, `testValue` (unimplemented), and `previewValue` (canned data).

```swift
@DependencyClient struct WiresClient {
    var bootstrap: @Sendable (AgentIdentity, any RootSignerCallback) async throws -> Void
    var connectHost: @Sendable (HostInfo) async throws -> Void
    var parseEnrollmentQR: @Sendable (String) throws -> AgentEnrollment
    var parseHostPairQR: @Sendable (String) throws -> HostInfo
    var generateTopicIdAndEpoch0: @Sendable () -> NewTopic
    var mintGrant: @Sendable (AgentEnrollment, [TopicGrant], [Right], ChainPosition) async throws -> MintResult
    var publish: @Sendable ([SignedWireMessage]) async throws -> Void
}

@DependencyClient struct HouseholdClient {
    var loadHousehold: @Sendable () async throws -> Household?
    var saveHousehold: @Sendable (Household) async throws -> Void
    var listTopics: @Sendable () async throws -> [TopicRecord]
    var saveTopic: @Sendable (TopicRecord) async throws -> Void
    var listCaps: @Sendable () async throws -> [CapRecord]
    var saveCap: @Sendable (CapRecord) async throws -> Void
    var enqueuePending: @Sendable (SignedWireMessage) async throws -> Void
    var advanceChain: @Sendable (ChainPosition) async throws -> Void
    var observePendingCount: @Sendable () -> AsyncStream<Int>
}

@DependencyClient struct KeychainClient {
    var getData: @Sendable (String) throws -> Data?
    var setData: @Sendable (String, Data, KeychainAccessibility) throws -> Void
    var deleteData: @Sendable (String) throws -> Void
    var signWithBiometric: @Sendable (String, Data) async throws -> Data
}
```

Reducers never touch `ModelContext` or `SecItem` APIs directly — all I/O goes through these clients. This is what makes reducers testable.

### Folder layout

```
Wires/
  Wires/
    App/
      WiresApp.swift              # @main, instantiates root Store
      AppFeature.swift
    Features/
      Bootstrap/
        BootstrapFeature.swift
        BootstrapView.swift
        PathReducers.swift
      Home/
        HomeFeature.swift
        HomeView.swift
      AgentEnrollment/
        AgentEnrollmentFeature.swift
        ApprovalFeature.swift
        AgentEnrollmentView.swift
      Scan/
        ScanFeature.swift
        ScanView.swift
    Dependencies/
      WiresClient.swift
      HouseholdClient.swift
      KeychainClient.swift
    Models/
      Household.swift
      TopicRecord.swift
      CapRecord.swift
      PendingPublish.swift
  WiresKit/                       # SwiftPM local package
    Package.swift
    Sources/WiresKit/             # UniFFI-generated Swift
    Frameworks/wires.xcframework  # built by scripts/build-ioskit.sh
  WiresTests/                     # TestStore-based reducer tests
  WiresUITests/                   # snapshot + UI tests
```

### Xcode project dependencies

- `swift-composable-architecture` from `https://github.com/pointfreeco/swift-composable-architecture`, pinned `from: "1.16.0"`.
- Local SwiftPM package at `path: "../WiresKit"`.
- `swift-snapshot-testing` from `https://github.com/pointfreeco/swift-snapshot-testing`, dev-only (test target).

---

## 8. Build and packaging

### `wires-uniffi` build

The crate is `crate-type = ["staticlib", "cdylib"]`. UniFFI is wired via `uniffi-bindgen` (matching the pattern in iroh-ffi, which is itself archived but serves as a reference). The build script `scripts/build-ioskit.sh`:

1. `cargo build --release --target aarch64-apple-ios -p wires-uniffi`
2. `cargo build --release --target aarch64-apple-ios-sim -p wires-uniffi`
3. `cargo build --release --target x86_64-apple-ios-sim -p wires-uniffi`
4. `lipo -create` the two simulator slices into a fat library
5. `xcodebuild -create-xcframework` combining the device library and the fat simulator library into `Wires/WiresKit/Frameworks/wires.xcframework`
6. `cargo run --bin wires-uniffi-bindgen` (or the appropriate uniffi-bindgen invocation) to emit `wires_uniffi.swift` and `wires_uniffi.h` into `Wires/WiresKit/Sources/WiresKit/`

The script is idempotent; CI runs it on a macOS runner before Xcode build.

### Xcode project

The `Wires.xcodeproj` is updated to:
- Add `Package.swift` references for swift-composable-architecture and the local `WiresKit` package.
- Update the `Wires` target's "Frameworks, Libraries, and Embedded Content" to include `ComposableArchitecture` and `WiresKit`.
- Bump deployment target to iOS 17 (TCA + SwiftData + `@Observable` macro require it).
- Replace the SwiftData/Item template scaffolding (`Item.swift`, default `ContentView`) with the new structure from §7.

---

## 9. Error handling

### Rust side: `WiresError`

A single UniFFI-modeled enum, defined in `wires-uniffi/src/error.rs` per the existing snafu pattern (every variant has `#[snafu(implicit)] location: Location`, display ends with `, at {location}`, no `message: String` field).

```rust
#[derive(Debug, Snafu, uniffi::Error)]
pub enum WiresError {
    #[snafu(display("Failed to parse pairing QR token, at {location}"))]
    InvalidPairingToken { #[snafu(implicit)] location: Location },

    #[snafu(display("Failed to parse enrollment token, at {location}"))]
    InvalidEnrollmentToken { #[snafu(implicit)] location: Location },

    #[snafu(display("Failed to sign with root key, at {location}"))]
    RootSignerFailed { source: SignError, #[snafu(implicit)] location: Location },

    #[snafu(display("Failed to connect to host, at {location}"))]
    HostUnreachable { source: NetError, #[snafu(implicit)] location: Location },

    #[snafu(display("Failed to publish to gossip topic, at {location}"))]
    PublishFailed { source: NetError, #[snafu(implicit)] location: Location },

    #[snafu(display("Topic name conflicts with existing topic_id, at {location}"))]
    TopicConflict { #[snafu(implicit)] location: Location },

    #[snafu(display("Not connected to host, at {location}"))]
    NotConnected { #[snafu(implicit)] location: Location },
}
```

UniFFI generates a matching Swift `enum WiresError: Error` with the same case names.

### Swift side

`WiresClient` and `HouseholdClient` calls in effects produce `WiresError` and `HouseholdError` respectively. Reducers translate via a `userMessage(for: any Error) -> String` helper. Each presenting feature has a `@Presents var destination: Destination.State?` with an `alert` case.

`KeychainClient` exposes its own small Swift enum:

```swift
enum KeychainError: Error {
    case notFound
    case biometricCancelled       // user dismissed Face ID — handled non-modal
    case biometricFailed
    case unexpectedStatus(OSStatus)
}
```

User-cancelled Face ID is silent: the reducer returns to the previous state without alerting. Other Keychain failures surface as alerts.

Publish failures inside `WiresClient.publish` are caught at the boundary: Swift catches `WiresError.PublishFailed`, enqueues each `SignedWireMessage` to `HouseholdClient.enqueuePending`, and reports success-with-pending. A background task in `AppFeature` observes `observePendingCount`, retries with exponential backoff when count > 0 and `connectHost` is alive.

---

## 10. Testing strategy

### Rust tests

- **`wires-core`** — existing tests stay; one new test asserts the `RootSigner` trait roundtrip: a mock signer signs, `Capability::verify_root` checks.
- **`wires-uniffi`** unit tests — parser roundtrips (token serialize/parse), malformed-input rejection, `generate_topic_id_and_epoch0` returns 32+32 bytes of nonzero entropy.
- **`wires-uniffi`** integration test — spins up a local iroh test endpoint as a stand-in for `wires-host`, calls `WiresApp.bootstrap` + `connect_host` + `mint_grant` + `publish`, verifies the host receives the envelope and `verify_envelope` passes.

### Swift reducer tests (`WiresTests/`, TCA `TestStore`)

- **`BootstrapFeatureTests`** — drives the wizard with mocked dependencies. Cases:
  - Happy path: create → pair scan → connect → self-cap mint → done. Asserts `mintGrant` is called exactly once with the iOS agent's own keys as the enrollment target, and that `Household.iosAgentCapIdHex` and `iosAgentNextSeq` are advanced.
  - Host scan returns malformed QR → alert, retry available.
  - Connect fails → alert, stays on pair-host step, no mint attempted.
  - Self-cap mint fails after successful connect → alert, leaves Household in a recoverable partial state (host info saved, cap nil); next launch retries the self-cap mint.
- **`AgentEnrollmentFeatureTests`** — scan → approval → mint → publish. Cases:
  - Happy path: existing topic.
  - Happy path: new topic name (asserts `generateTopicIdAndEpoch0` was called and a new `TopicRecord` saved).
  - Malformed enrollment QR.
  - User cancels at approval.
  - Mint succeeds, publish fails: assert `enqueuePending` called once per message.
  - Topic conflict: glob `home.lights` literal matches no existing topic but a different topic with the same name exists in registry → conflict error surfaced.
- **`ScanFeatureTests`** — permission denied path, malformed payload path, successful decode propagation.
- **`AppFeatureTests`** — restoration: nil household → bootstrap; populated → home; reads from `HouseholdClient.loadHousehold` exactly once at launch.

`TestStore` enforces that every emitted action is consumed by a `receive(...)` assertion, so unintended state changes fail the test.

### UI snapshot tests (`WiresUITests/`)

Using `swift-snapshot-testing`. One snapshot per major screen state:
- Bootstrap: welcome, scanning, paired, done.
- Home: empty, populated, with pending-publish banner.
- Approval sheet: pristine, partially filled, validation error.

### End-to-end manual acceptance

Not part of CI. Run before each release.

1. Fresh install on a real device → wizard runs → root key generated, Face ID enrolled, host paired with `wires-host` on a separate machine.
2. New agent (`wires enroll` on a third machine) produces QR → operator scans → approves with `home.test` topic + read+write → agent dials host → receives cap → can `wires publish` on `home.test`.
3. Kill app, relaunch → state restored, immediately ready to onboard another agent without re-bootstrap.
4. With `wires-host` offline, scan another agent, approve → pending banner appears. Bring host online → banner clears within retry interval. New agent receives cap.

---

## 11. Out of scope (each gets its own spec)

- **Revoke UI.** Listing existing caps, tapping to revoke. Requires the spec's `__cap.revoke` flow plus a tap-to-confirm-with-biometric path. Depends on this iOS spec.
- **Tail / view feeds.** Read-only "household activity" view. Requires the iOS app to subscribe to topics beyond `__caps`, decrypt with epoch keys, render. Substantial new work.
- **Root key backup and recovery.** Secret sharing, recovery phrase, or successor key designation. Depends on protocol-level `__cap.root_rotation` flow being designed and implemented.
- **Multi-device root custody.** Pairing iPhone + iPad as co-custodians of the same root key. Depends on a key-mirroring mechanism — likely via iCloud Keychain with synchronizable items, but the threat model needs rework.
- **Epoch rotation triggers.** Wired when revoke lands.
- **macOS / iPadOS variants.** Same SwiftUI + TCA + WiresKit code targets these, but layout, navigation, and Keychain accessibility nuances need their own pass.
