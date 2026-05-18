# iOS "Reset Household" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Ship a debug-build "Reset household" button on the Home screen that (1) tells the host to unregister this tenant, (2) wipes all local Keychain entries + SwiftData rows, (3) resets the in-memory `WiresApp` instance, and (4) returns the app to `.launching` so `prepareWiresApp` regenerates fresh keys. Required to make the iOS bootstrap → pair → done loop repeatable end-to-end against the same host.

**Architecture:** Three new UniFFI surface items (`UnregisterResult`, `WiresApp::unregister_with_hosted_service`, the Rust helper in `wires-uniffi::tenant`). Two new dependency-client methods on `WiresClient` (`unregisterTenant`, `reset`). One wipe method per existing client (`HouseholdClient.wipeAll`, `KeychainClient.wipeAllWiresAccounts`). One new TCA delegate action `.didReset` from `HomeFeature` to `AppFeature`. Confirmation via `AlertState`; soft-fails the host RPC and proceeds with local wipe if the host rejects.

**Tech Stack:** Rust 2024 / UniFFI 0.x (existing) for the FFI surface; TCA (ComposableArchitecture) + SwiftData + LocalAuthentication for the iOS side. No new dependencies on either side.

**Spec basis:** `memory/project_test_loop_needs_reset.md` describes the required effect chain. `memory/project_tenant_unregister_shipped_2026_05_18.md` documents the host-side primitive this consumes.

---

## File Map

| File | Action | Owner task |
|---|---|---|
| `crates/wires-uniffi/src/types.rs` | Modify: add `UnregisterResult` Record | Task A |
| `crates/wires-uniffi/src/tenant.rs` | Modify: add `unregister_with_hosted_service` helper | Task A |
| `crates/wires-uniffi/src/app.rs` | Modify: add `WiresApp::unregister_with_hosted_service` method | Task A |
| `scripts/build-ioskit.sh` (run) | Regenerates xcframework + Swift bindings | Task A |
| `Wires/Wires/Dependencies/WiresClient.swift` | Modify: add `unregisterTenant` + `reset` | Task B |
| `Wires/Wires/Dependencies/HouseholdClient.swift` | Modify: add `wipeAll` | Task C |
| `Wires/Wires/Dependencies/KeychainClient.swift` | Modify: add `wipeAllWiresAccounts` | Task C |
| `Wires/Wires/Features/Home/HomeFeature.swift` | Modify: alert + reset actions + effect | Task D |
| `Wires/Wires/Features/Home/HomeView.swift` | Modify: `#if DEBUG` toolbar button + `.alert` modifier | Task E |
| `Wires/Wires/App/AppFeature.swift` | Modify: observe `.home(.didReset)` → `.launching` + re-onAppear | Task F |
| `Wires/WiresTests/HomeFeatureTests.swift` | Modify: three new tests | Task G |

---

## Phase A — UniFFI surface

### Task A: Rust + Swift binding regen

**Files:**
- `crates/wires-uniffi/src/types.rs` (modify)
- `crates/wires-uniffi/src/tenant.rs` (modify)
- `crates/wires-uniffi/src/app.rs` (modify)
- Run `scripts/build-ioskit.sh`

- [ ] **Step 1: Add `UnregisterResult` Record**

In `crates/wires-uniffi/src/types.rs`, after `TenantRegistration` (line ~17):

```rust
#[derive(Debug, Clone, uniffi::Record)]
pub struct UnregisterResult {
    /// True iff the host had a tenant record to remove. False is a successful
    /// no-op (idempotent on retry).
    pub ok: bool,
    /// Number of topic_index entries the host dropped.
    pub topics_removed: u32,
}
```

- [ ] **Step 2: Add the `unregister_with_hosted_service` helper**

In `crates/wires-uniffi/src/tenant.rs`, after `register_with_hosted_service` (around line 62):

```rust
pub async fn unregister_with_hosted_service(
    endpoint: Endpoint,
    root_signer: Arc<dyn SwiftRootSigner>,
    host: &HostInfo,
) -> Result<UnregisterResult, WiresError> {
    let peer = decode_endpoint_id(&host.endpoint_id_hex)?;
    register_hint_addrs(&endpoint, host);

    let adapter = SwiftRootSignerAdapter {
        inner: root_signer,
    };
    let host_eid_bytes = *peer.as_bytes();
    let now = now_ms()?;

    let client = TenantClient::new(endpoint);
    let resp = client
        .unregister_tenant(peer, &adapter, &host_eid_bytes, now)
        .await
        .map_err(|e| {
            TenantStreamSnafu {
                message: format!("{e}"),
            }
            .build()
        })?;

    match resp {
        TenantResponse::Unregister(r) => Ok(UnregisterResult {
            ok: r.ok,
            topics_removed: r.topics_removed,
        }),
        TenantResponse::Error(err) => Err(TenantRejectedSnafu {
            code: err.code,
            message: err.message,
        }
        .build()),
        other => Err(InternalSnafu {
            message: format!("unexpected tenant response: {other:?}"),
        }
        .build()),
    }
}
```

Then update the imports in the same file to add `UnregisterResult` to the `use crate::types` import block.

- [ ] **Step 3: Add the `WiresApp` method**

In `crates/wires-uniffi/src/app.rs`, inside the `#[uniffi::export]` impl block after `register_with_hosted_service` (around line 65), add:

```rust
pub async fn unregister_with_hosted_service(
    &self,
    host: HostInfo,
) -> Result<UnregisterResult, WiresError> {
    let ep = self.endpoint().await?;
    tenant_flow::unregister_with_hosted_service(ep, self.root_signer.clone(), &host).await
}
```

Add `UnregisterResult` to the existing `use crate::types::{ ... }` import in `app.rs`.

- [ ] **Step 4: Verify Rust side builds + tests pass**

```
cargo build -p wires-uniffi
cargo test -p wires-uniffi
```

- [ ] **Step 5: Regenerate the Swift bindings**

```
scripts/build-ioskit.sh
```

This compiles for three iOS targets, lipo-merges sim slices, generates `Wires/WiresKit/Sources/WiresKit/wires_uniffi.swift`, and packages `wires.xcframework`. Takes ~3 min cold.

After it completes, verify the generated Swift file contains `func unregisterWithHostedService(host: HostInfo) async throws -> UnregisterResult`:

```
grep "unregisterWithHostedService" Wires/WiresKit/Sources/WiresKit/wires_uniffi.swift
```

- [ ] **Step 6: Commit**

```
git add crates/wires-uniffi/src/types.rs crates/wires-uniffi/src/tenant.rs crates/wires-uniffi/src/app.rs Wires/WiresKit/Sources/WiresKit/wires_uniffi.swift Wires/WiresKit/Frameworks/wires.xcframework
git commit -m "wires-uniffi: unregister_with_hosted_service + UnregisterResult"
```

(`wires.xcframework` is `.gitignore`d so the second `git add` is a no-op; the Swift binding is the load-bearing artifact.)

---

## Phase B — Swift dependency clients

### Task B: WiresClient.unregisterTenant + .reset

**Files:**
- `Wires/Wires/Dependencies/WiresClient.swift` (modify)

- [ ] **Step 1: Add the dependency-client closure**

In `WiresClient` struct (around line 20–32), add after `registerTopic`:

```swift
var unregisterTenant: @Sendable (_ host: HostInfo) async throws -> UnregisterResult
```

- [ ] **Step 2: Add the holder reset method**

In `WiresAppHolder` actor (around line 40–53), add a method that drops the cached instance:

```swift
func reset() {
    instance = nil
}
```

- [ ] **Step 3: Add the `reset` closure to `WiresClient`**

In the struct definition:

```swift
/// Drops the in-memory `WiresApp` instance so the next `bootstrap` call
/// creates a fresh one. Use after wiping local Keychain/SwiftData state to
/// guarantee the next session uses the newly-generated iroh secret + root
/// signer, not the cached one bound to the old keys.
var reset: @Sendable () async -> Void = {}
```

- [ ] **Step 4: Wire up the liveValue**

In `WiresClient.liveValue` (around line 56–94), add the two new closures:

```swift
unregisterTenant: { host in
    try await holder.require().unregisterWithHostedService(host: host)
},
reset: {
    await holder.reset()
},
```

- [ ] **Step 5: Verify the iOS app builds**

```
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
```

Expected: builds clean. Use this same command at every iOS-touching task.

- [ ] **Step 6: Commit**

```
git add Wires/Wires/Dependencies/WiresClient.swift
git commit -m "ios: WiresClient.unregisterTenant + .reset"
```

---

### Task C: HouseholdClient.wipeAll + KeychainClient.wipeAllWiresAccounts

**Files:**
- `Wires/Wires/Dependencies/HouseholdClient.swift` (modify)
- `Wires/Wires/Dependencies/KeychainClient.swift` (modify)

- [ ] **Step 1: Add `HouseholdClient.wipeAll` closure**

In the `@DependencyClient` struct (around line 16–30):

```swift
/// Delete every Household, TopicRecord, and CapRecord row.
var wipeAll: @Sendable () async throws -> Void
```

In `liveValue` (around line 38–55), add:

```swift
wipeAll: { try await store.wipeAll() },
```

In the `HouseholdStore` actor (the `@MainActor private final class HouseholdStore` at the bottom of the file), add:

```swift
func wipeAll() throws {
    let ctx = ModelContext(container)
    // Delete in dependency-free order. The schema has no cascades wired up,
    // so each entity is dropped independently.
    for h in try ctx.fetch(FetchDescriptor<Household>()) {
        ctx.delete(h)
    }
    for t in try ctx.fetch(FetchDescriptor<TopicRecord>()) {
        ctx.delete(t)
    }
    for c in try ctx.fetch(FetchDescriptor<CapRecord>()) {
        ctx.delete(c)
    }
    try ctx.save()
}
```

- [ ] **Step 2: Add `KeychainClient.wipeAllWiresAccounts`**

In `KeychainClient` struct (around line 26–36):

```swift
/// Drop every Keychain entry under the `"wires"` service in a single
/// `SecItemDelete` — covers root.signingkey, root.pubkey, iroh.secret, and
/// every `wires.topic.<id>.epoch.<n>` entry.
var wipeAllWiresAccounts: @Sendable () throws -> Void
```

In `liveValue` (around line 38–56), wire it:

```swift
wipeAllWiresAccounts: {
    try Self.deleteService(service: service)
},
```

In the implementation block (around line 121–132), add the static helper:

```swift
private static func deleteService(service: String) throws {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecUseDataProtectionKeychain: true,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
        throw KeychainError.unexpectedStatus(status)
    }
}
```

- [ ] **Step 3: Verify the iOS app builds**

Run the xcodebuild command from Task B Step 5.

- [ ] **Step 4: Commit**

```
git add Wires/Wires/Dependencies/HouseholdClient.swift Wires/Wires/Dependencies/KeychainClient.swift
git commit -m "ios: HouseholdClient.wipeAll + KeychainClient.wipeAllWiresAccounts"
```

---

## Phase C — TCA feature wiring

### Task D: HomeFeature reset action + confirmation alert

**Files:**
- `Wires/Wires/Features/Home/HomeFeature.swift` (modify)

- [ ] **Step 1: Add the alert state + new actions**

In `HomeFeature.State` (around line 8–15), add a `@Presents` alert:

```swift
@Presents var alert: AlertState<Action.Alert>?
```

In the `Action` enum (around line 36–42), add:

```swift
case resetHouseholdTapped
case alert(PresentationAction<Alert>)
case resetCompleted
case resetFailed(String)
case didReset

@CasePathable
enum Alert: Equatable {
    case confirmReset
}
```

- [ ] **Step 2: Add the dependency injections**

Below the existing `@Dependency(\.householdClient) var household`, add:

```swift
@Dependency(\.keychainClient) var keychain
@Dependency(\.wiresClient) var wires
```

- [ ] **Step 3: Wire the new action arms in `body`**

Inside the `Reduce` switch (after the existing `.nodeEnrollment` arms but before the closing of the switch), add:

```swift
case .resetHouseholdTapped:
    state.alert = AlertState {
        TextState("Reset household?")
    } actions: {
        ButtonState(role: .destructive, action: .confirmReset) {
            TextState("Reset")
        }
        ButtonState(role: .cancel) {
            TextState("Cancel")
        }
    } message: {
        TextState("Tells the host to drop this tenant, then wipes every local key and database row. The next launch behaves like a fresh install.")
    }
    return .none

case .alert(.presented(.confirmReset)):
    state.alert = nil
    let host = state.host
    let household = self.household
    let keychain = self.keychain
    let wires = self.wires
    return .run { send in
        // 1. Tell the host to unregister. Soft-fail: a host that's offline
        //    or already-forgotten shouldn't block a local reset.
        if let host {
            do {
                _ = try await wires.unregisterTenant(host)
            } catch {
                // Logged, not raised.
                print("[reset] host unregister failed: \(error)")
            }
        }
        // 2. Wipe SwiftData.
        do { try await household.wipeAll() }
        catch {
            await send(.resetFailed("wipe SwiftData: \(error)"))
            return
        }
        // 3. Wipe Keychain.
        do { try keychain.wipeAllWiresAccounts() }
        catch {
            await send(.resetFailed("wipe Keychain: \(error)"))
            return
        }
        // 4. Drop the cached WiresApp so the next bootstrap regenerates.
        await wires.reset()
        await send(.resetCompleted)
    }

case .alert:
    return .none

case .resetCompleted:
    return .send(.didReset)

case let .resetFailed(message):
    state.loadError = "Reset failed: \(message)"
    return .none

case .didReset:
    // AppFeature observes this delegate action and transitions to .launching.
    return .none
```

Don't remove or restructure existing arms.

- [ ] **Step 4: Attach the `.ifLet` for the alert presentation**

At the bottom of `body`, after the existing `.ifLet(\.$nodeEnrollment, ...)`, add:

```swift
.ifLet(\.$alert, action: \.alert)
```

- [ ] **Step 5: Verify the iOS app builds**

xcodebuild.

- [ ] **Step 6: Commit**

```
git add Wires/Wires/Features/Home/HomeFeature.swift
git commit -m "ios: HomeFeature — reset household action + confirmation alert"
```

---

### Task E: HomeView debug-only "Reset household" button

**Files:**
- `Wires/Wires/Features/Home/HomeView.swift` (modify)

- [ ] **Step 1: Add a debug toolbar item + alert modifier**

In `HomeView`, find the existing `.toolbar` modifier (or add one if missing) and inside add:

```swift
#if DEBUG
ToolbarItem(placement: .secondaryAction) {
    Button(role: .destructive) {
        store.send(.resetHouseholdTapped)
    } label: {
        Label("Reset household (debug)", systemImage: "trash")
    }
}
#endif
```

If the existing toolbar already has a primary action (the Approve node button), keep that as `.primaryAction` and this reset button as `.secondaryAction`. iOS surfaces secondary actions in the "•••" overflow menu so the destructive button isn't tap-accessible by accident.

Below the existing view body modifiers, attach the alert:

```swift
.alert($store.scope(state: \.alert, action: \.alert))
```

- [ ] **Step 2: Verify the iOS app builds**

xcodebuild.

- [ ] **Step 3: Commit**

```
git add Wires/Wires/Features/Home/HomeView.swift
git commit -m "ios: HomeView — debug-only Reset household toolbar button"
```

---

### Task F: AppFeature transitions back to .launching on reset

**Files:**
- `Wires/Wires/App/AppFeature.swift` (modify)

- [ ] **Step 1: Observe `.home(.didReset)`**

In the `Reduce` switch (around line 31–66), add an arm BEFORE the catch-all `case .bootstrap, .home:`:

```swift
case .home(.didReset):
    state = .launching
    return .send(.onAppear)
```

This:
1. Drops the Home state — UI immediately goes back to launching.
2. Re-runs `.onAppear`, which calls `prepareWiresApp` (idempotent: regenerates the keys since Keychain is empty), reloads household state (none → routes to bootstrap), and transitions to `.bootstrap`.

- [ ] **Step 2: Verify the iOS app builds**

xcodebuild.

- [ ] **Step 3: Commit**

```
git add Wires/Wires/App/AppFeature.swift
git commit -m "ios: AppFeature — return to .launching on home reset"
```

---

## Phase D — Tests + verification

### Task G: HomeFeatureTests for reset flow

**Files:**
- `Wires/WiresTests/HomeFeatureTests.swift` (modify)

- [ ] **Step 1: Read the existing test file to know its imports and helpers**

`HomeFeatureTests` already exists (per the memory snapshot, 6 tests). Skim it first, follow its dependency-override pattern.

- [ ] **Step 2: Add the three new tests**

Append to `HomeFeatureTests`:

```swift
@Test
func resetHouseholdTapped_presentsConfirmationAlert() async {
    let store = TestStore(initialState: HomeFeature.State(rootPubkeyHex: "deadbeef")) {
        HomeFeature()
    } withDependencies: {
        $0.householdClient.listCaps = { [] }
        $0.householdClient.loadHousehold = { nil }
        $0.householdClient.wipeAll = { }
        $0.keychainClient.wipeAllWiresAccounts = { }
        $0.wiresClient.unregisterTenant = { _ in
            UnregisterResult(ok: true, topicsRemoved: 0)
        }
        $0.wiresClient.reset = { }
    }
    await store.send(.resetHouseholdTapped) {
        $0.alert = AlertState {
            TextState("Reset household?")
        } actions: {
            ButtonState(role: .destructive, action: .confirmReset) {
                TextState("Reset")
            }
            ButtonState(role: .cancel) {
                TextState("Cancel")
            }
        } message: {
            TextState("Tells the host to drop this tenant, then wipes every local key and database row. The next launch behaves like a fresh install.")
        }
    }
}

@Test
func cancelAlert_dismissesWithoutAction() async {
    let store = TestStore(initialState: HomeFeature.State(rootPubkeyHex: "deadbeef")) {
        HomeFeature()
    } withDependencies: {
        $0.householdClient.listCaps = { [] }
        $0.householdClient.loadHousehold = { nil }
        $0.householdClient.wipeAll = { }
        $0.keychainClient.wipeAllWiresAccounts = { }
        $0.wiresClient.unregisterTenant = { _ in
            UnregisterResult(ok: true, topicsRemoved: 0)
        }
        $0.wiresClient.reset = { }
    }
    await store.send(.resetHouseholdTapped) {
        $0.alert = AlertState {
            TextState("Reset household?")
        } actions: {
            ButtonState(role: .destructive, action: .confirmReset) {
                TextState("Reset")
            }
            ButtonState(role: .cancel) {
                TextState("Cancel")
            }
        } message: {
            TextState("Tells the host to drop this tenant, then wipes every local key and database row. The next launch behaves like a fresh install.")
        }
    }
    await store.send(.alert(.dismiss)) {
        $0.alert = nil
    }
}

@Test
func confirmReset_runsEffectAndEmitsDidReset() async {
    let wipeAllCalled = LockIsolated(false)
    let wipeKeychainCalled = LockIsolated(false)
    let resetCalled = LockIsolated(false)
    let unregisterCalled = LockIsolated(false)

    let store = TestStore(
        initialState: HomeFeature.State(
            rootPubkeyHex: "deadbeef",
            host: HostInfo(
                endpointIdHex: String(repeating: "ab", count: 32),
                addrs: ["1.2.3.4:5"],
                relay: nil,
                hintExpiresAtMs: 0
            )
        )
    ) {
        HomeFeature()
    } withDependencies: {
        $0.householdClient.listCaps = { [] }
        $0.householdClient.loadHousehold = { nil }
        $0.householdClient.wipeAll = { wipeAllCalled.setValue(true) }
        $0.keychainClient.wipeAllWiresAccounts = { wipeKeychainCalled.setValue(true) }
        $0.wiresClient.unregisterTenant = { _ in
            unregisterCalled.setValue(true)
            return UnregisterResult(ok: true, topicsRemoved: 2)
        }
        $0.wiresClient.reset = { resetCalled.setValue(true) }
    }

    await store.send(.resetHouseholdTapped) {
        $0.alert = AlertState {
            TextState("Reset household?")
        } actions: {
            ButtonState(role: .destructive, action: .confirmReset) {
                TextState("Reset")
            }
            ButtonState(role: .cancel) {
                TextState("Cancel")
            }
        } message: {
            TextState("Tells the host to drop this tenant, then wipes every local key and database row. The next launch behaves like a fresh install.")
        }
    }
    await store.send(.alert(.presented(.confirmReset))) {
        $0.alert = nil
    }
    await store.receive(\.resetCompleted)
    await store.receive(\.didReset)

    #expect(unregisterCalled.value == true)
    #expect(wipeAllCalled.value == true)
    #expect(wipeKeychainCalled.value == true)
    #expect(resetCalled.value == true)
}
```

The exact form of test-store API (`@Test` macro vs `func` + `XCTest`, `#expect` vs `XCTAssert`) depends on what `HomeFeatureTests` already uses — match it. Look at the existing `approveNode_*` tests for the pattern.

- [ ] **Step 3: Run the tests**

xcodebuild test scheme.

- [ ] **Step 4: Commit**

```
git add Wires/WiresTests/HomeFeatureTests.swift
git commit -m "ios: HomeFeatureTests — reset household alert + effect"
```

---

### Task H: Workspace verification

- [ ] **Step 1: Rust workspace**

```
cargo build --workspace
cargo test --workspace -- --test-threads=1
cargo clippy --workspace -- -D warnings
```

- [ ] **Step 2: iOS build + tests**

```
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires -destination 'platform=iOS Simulator,name=iPhone 17 Pro' clean build test
```

- [ ] **Step 3: Optional manual smoke (if a real device is paired)**

1. Launch the app, bootstrap, register, approve a node. Verify caps appear on Home.
2. Tap the "•••" menu → Reset household → confirm. Should return to bootstrap screen.
3. Repeat the bootstrap loop with the SAME host (no `rm -rf` on the host data dir needed). Should succeed end-to-end.

---

## Notes for the implementer

- `UnregisterResult` deliberately mirrors the host's response. We don't need to distinguish "tenant was there" vs "already gone" on the UI — both are success from the operator's POV.
- The `Reset` button is `#if DEBUG`-gated. Production builds will compile it out. If you later want a user-facing "Sign out / leave household" path, lift this guard and rename — the underlying effect is correct.
- The `wires.reset()` call is the subtle one. Without it, the holder still references a `WiresApp` bound to the OLD `iroh_secret` and the OLD `root_signer`. After Keychain wipe, the next `prepareWiresApp` generates fresh keys, but the holder's existing `WiresApp` is unaffected and its `endpoint()` will reuse the old secret. Dropping the cached instance forces re-bootstrap with the new keys.
- AppFeature's `.home(.didReset)` arm fires `.onAppear` synchronously — that's fine: `prepareWiresApp` is idempotent and `loadHousehold` returns nil after the wipe, which routes to `.bootstrap`.
